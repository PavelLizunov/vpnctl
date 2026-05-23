use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context;

#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub db_path: PathBuf,
    pub addr: SocketAddr,
}

impl DaemonConfig {
    /// Resolve final config from CLI/env. Same default as the CLI uses for
    /// `--db` so a single inventory backs both.
    pub async fn resolve(db_flag: Option<PathBuf>, addr: SocketAddr) -> anyhow::Result<Self> {
        let db_path = match db_flag {
            Some(p) => p,
            None => {
                let dir = dirs_data_dir()
                    .ok_or_else(|| {
                        anyhow::anyhow!("cannot resolve XDG data dir; pass --db / VPNCTL_DB")
                    })?
                    .join("vpnctl");
                // Surface dir-creation errors immediately rather than letting
                // the next sqlx::open() fail with an opaque "unable to open
                // database file" hours later.
                tokio::fs::create_dir_all(&dir)
                    .await
                    .with_context(|| format!("create {}", dir.display()))?;
                dir.join("inv.db")
            }
        };
        Ok(Self { db_path, addr })
    }
}

/// Avoid pulling the whole `dirs` crate just for this one lookup.
fn dirs_data_dir() -> Option<PathBuf> {
    if let Some(x) = std::env::var_os("XDG_DATA_HOME") {
        return Some(PathBuf::from(x));
    }
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".local/share"))
}

/// **Refuse to start with admin UI exposed AND no auth configured.**
///
/// Pre-2026-05-22 footgun (B3 audit): if the operator forgot to set
/// `VPNCTLD_ADMIN_USER` / `VPNCTLD_ADMIN_PASSWORD` AND bound the
/// daemon to `0.0.0.0` (or any non-loopback interface), the admin UI
/// went up with NO authentication. The `BasicAuth::from_env() →
/// None` path in `app::router_admin` silently dropped the auth
/// middleware ON PURPOSE (useful for local smoke), but had no
/// safeguard against non-loopback binds.
///
/// This check makes the bug class loud at startup:
///
///   * Bind is loopback (127.0.0.0/8, ::1) — proceed regardless of
///     auth state. Local smoke remains friction-free.
///   * Bind is non-loopback AND BOTH env vars are set (non-empty) —
///     proceed.
///   * Bind is non-loopback AND auth missing/empty — `Err` with a
///     concrete remediation message naming both env vars.
///
/// **Override:** `VPNCTLD_ALLOW_INSECURE_NONLOCAL=1` skips the check.
/// Documented for the «I really know what I'm doing» case (e.g. behind
/// an mTLS reverse proxy that handles auth) but the doc-comment is
/// explicit: this is the only knob, no half-measures.
pub fn assert_auth_safe_for_addr(addr: SocketAddr) -> anyhow::Result<()> {
    let user_present = std::env::var("VPNCTLD_ADMIN_USER")
        .map(|s| !s.is_empty())
        .unwrap_or(false);
    let pw_present = std::env::var("VPNCTLD_ADMIN_PASSWORD")
        .map(|s| !s.is_empty())
        .unwrap_or(false);
    let insecure_override = std::env::var_os("VPNCTLD_ALLOW_INSECURE_NONLOCAL")
        .is_some_and(|v| v == "1" || v == "true");
    assert_auth_safe_for_addr_with(addr, user_present, pw_present, insecure_override)
}

/// Pure inner helper — same logic as [`assert_auth_safe_for_addr`] but
/// with every env read lifted to parameters. Lets tests exercise every
/// branch without touching the process environment (which under Rust
/// 2024 + workspace `unsafe_code = "forbid"` would require unsafe
/// blocks that aren't allowed in this crate).
pub fn assert_auth_safe_for_addr_with(
    addr: SocketAddr,
    user_present: bool,
    pw_present: bool,
    insecure_override: bool,
) -> anyhow::Result<()> {
    if addr.ip().is_loopback() {
        return Ok(());
    }
    if insecure_override {
        tracing::warn!(
            target = "vpnctld::startup",
            %addr,
            "VPNCTLD_ALLOW_INSECURE_NONLOCAL=1 set — skipping auth-on-bind safety check. \
             You're responsible for upstream authentication (mTLS proxy, etc)."
        );
        return Ok(());
    }
    if user_present && pw_present {
        return Ok(());
    }
    Err(anyhow::anyhow!(
        "vpnctld refuses to bind {addr} without admin auth. \
         Set BOTH VPNCTLD_ADMIN_USER and VPNCTLD_ADMIN_PASSWORD (non-empty), \
         OR bind to a loopback address (127.0.0.1 / ::1) for local-only use, \
         OR set VPNCTLD_ALLOW_INSECURE_NONLOCAL=1 if upstream auth handles it."
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn loopback_bind_is_always_safe_regardless_of_auth() {
        let addr: SocketAddr = "127.0.0.1:18402".parse().unwrap();
        assert!(assert_auth_safe_for_addr_with(addr, false, false, false).is_ok());
        let addr6: SocketAddr = "[::1]:18402".parse().unwrap();
        assert!(assert_auth_safe_for_addr_with(addr6, false, false, false).is_ok());
    }

    #[test]
    fn nonlocal_bind_without_auth_is_rejected() {
        let addr: SocketAddr = "0.0.0.0:18402".parse().unwrap();
        let err = assert_auth_safe_for_addr_with(addr, false, false, false)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("VPNCTLD_ADMIN_USER") && err.contains("VPNCTLD_ADMIN_PASSWORD"),
            "error must name both required env vars; got: {err}"
        );
    }

    #[test]
    fn nonlocal_bind_with_only_user_set_is_rejected() {
        // Both creds must be present — half-set is still a footgun.
        let addr: SocketAddr = "192.0.2.1:18402".parse().unwrap();
        assert!(assert_auth_safe_for_addr_with(addr, true, false, false).is_err());
        assert!(assert_auth_safe_for_addr_with(addr, false, true, false).is_err());
    }

    #[test]
    fn nonlocal_bind_with_both_creds_is_allowed() {
        let addr: SocketAddr = "192.0.2.1:18402".parse().unwrap();
        let res = assert_auth_safe_for_addr_with(addr, true, true, false);
        assert!(res.is_ok(), "non-local bind with both creds set must be ok");
    }

    #[test]
    fn nonlocal_bind_with_insecure_override_is_allowed() {
        let addr: SocketAddr = "0.0.0.0:18402".parse().unwrap();
        let res = assert_auth_safe_for_addr_with(addr, false, false, true);
        assert!(res.is_ok(), "override must bypass the check");
    }
}
