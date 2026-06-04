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
    let insecure_override = std::env::var_os("VPNCTLD_ALLOW_INSECURE_NONLOCAL")
        .is_some_and(|v| v == "1" || v == "true");
    // Classify the EFFECTIVE auth config with the SAME parser the
    // request-time builder (`BasicAuth::from_env`) uses. Pre-2026-06-04
    // this gate only checked the env strings were non-empty, so a
    // malformed `$argon2…` password sailed through here while
    // `BasicAuth::from_env()` returned `None` and the admin router
    // dropped its auth layer → admin UI served with NO auth (fail-open).
    let auth = crate::handlers::auth::classify_admin_auth_env();
    assert_auth_safe_for_addr_inner(addr, auth, insecure_override)
}

/// Pure inner helper — same logic as [`assert_auth_safe_for_addr`] but
/// with every env read lifted to parameters. Lets tests exercise every
/// branch without touching the process environment (which under Rust
/// 2024 + workspace `unsafe_code = "forbid"` would require unsafe
/// blocks that aren't allowed in this crate).
///
/// The presence-bool form can only express Configured vs Absent — it
/// carries no malformed-hash signal, so it routes through
/// [`assert_auth_safe_for_addr_inner`] with the corresponding verdict.
pub fn assert_auth_safe_for_addr_with(
    addr: SocketAddr,
    user_present: bool,
    pw_present: bool,
    insecure_override: bool,
) -> anyhow::Result<()> {
    use crate::handlers::auth::AdminAuthConfig;
    let auth = if user_present && pw_present {
        AdminAuthConfig::Configured
    } else {
        AdminAuthConfig::Absent
    };
    assert_auth_safe_for_addr_inner(addr, auth, insecure_override)
}

/// Core gate over the already-classified auth verdict. Composes the
/// bind-safety check (B3) with auth-validity:
///
///   * `Malformed` — ALWAYS fatal, regardless of bind address and NOT
///     rescued by the insecure override. The operator set a `$argon2…`
///     password that doesn't parse: they intended auth, so we refuse to
///     boot rather than silently run with none. This is the core of the
///     fail-open fix.
///   * loopback bind — proceed regardless of auth state (local smoke).
///   * insecure override — proceed (upstream handles auth).
///   * `Configured` — proceed.
///   * `Absent` on a non-loopback bind — refuse with a remediation
///     message naming both env vars.
pub(crate) fn assert_auth_safe_for_addr_inner(
    addr: SocketAddr,
    auth: crate::handlers::auth::AdminAuthConfig,
    insecure_override: bool,
) -> anyhow::Result<()> {
    use crate::handlers::auth::AdminAuthConfig;
    if matches!(auth, AdminAuthConfig::Malformed) {
        return Err(anyhow::anyhow!(
            "vpnctld refuses to start: VPNCTLD_ADMIN_PASSWORD begins with $argon2 \
             but is not a valid PHC hash. Admin auth would be DISABLED (fail-open). \
             Re-generate the hash via `vpnctl admin hash-password` and paste the \
             full $argon2id$… line into /etc/vpnctl/vpnctld.env, or set a plaintext \
             password."
        ));
    }
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
    if matches!(auth, AdminAuthConfig::Configured) {
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

    // ─── malformed-argon2 fail-open fix (2026-06-04) ─────────────────
    //
    // Regression net for the bug where the startup gate trusted the raw
    // env strings (non-empty → "auth present") while `BasicAuth::from_env`
    // returned `None` on a malformed `$argon2…` hash → admin router served
    // with no auth. The gate now classifies via the SAME parser; a
    // `Malformed` verdict is fatal everywhere.

    #[test]
    fn nonlocal_bind_with_malformed_argon2_is_rejected() {
        use crate::handlers::auth::AdminAuthConfig;
        let addr: SocketAddr = "0.0.0.0:18402".parse().unwrap();
        let err = assert_auth_safe_for_addr_inner(addr, AdminAuthConfig::Malformed, false)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("$argon2") && err.contains("fail-open"),
            "malformed-argon2 startup error must name the cause; got: {err}"
        );
    }

    #[test]
    fn malformed_argon2_is_fatal_even_on_loopback() {
        // A configured-but-broken password is an operator mistake worth
        // surfacing everywhere — loopback smoke does NOT excuse it (the
        // operator clearly intended auth). Otherwise a fat-fingered hash
        // on 127.0.0.1 would still serve the admin UI with no auth.
        use crate::handlers::auth::AdminAuthConfig;
        let addr: SocketAddr = "127.0.0.1:18402".parse().unwrap();
        assert!(assert_auth_safe_for_addr_inner(addr, AdminAuthConfig::Malformed, false).is_err());
        let addr6: SocketAddr = "[::1]:18402".parse().unwrap();
        assert!(assert_auth_safe_for_addr_inner(addr6, AdminAuthConfig::Malformed, false).is_err());
    }

    #[test]
    fn malformed_argon2_not_rescued_by_insecure_override() {
        // The override is an escape hatch for "upstream handles auth",
        // NOT for "my hash is broken". Malformed stays fatal.
        use crate::handlers::auth::AdminAuthConfig;
        let addr: SocketAddr = "0.0.0.0:18402".parse().unwrap();
        assert!(assert_auth_safe_for_addr_inner(addr, AdminAuthConfig::Malformed, true).is_err());
    }

    #[test]
    fn configured_auth_via_inner_allows_nonlocal_bind() {
        // Sanity: the enum surface still permits a properly-configured
        // non-loopback bind (mirrors `nonlocal_bind_with_both_creds_is_allowed`).
        use crate::handlers::auth::AdminAuthConfig;
        let addr: SocketAddr = "192.0.2.1:18402".parse().unwrap();
        assert!(assert_auth_safe_for_addr_inner(addr, AdminAuthConfig::Configured, false).is_ok());
    }
}
