use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context;

#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub db_path: PathBuf,
    pub addr: SocketAddr,
}

impl DaemonConfig {
    pub async fn resolve(db_flag: Option<PathBuf>, addr: SocketAddr) -> anyhow::Result<Self> {
        let db_path = match db_flag {
            Some(p) => p,
            None => {
                let dir = dirs_data_dir()
                    .ok_or_else(|| {
                        anyhow::anyhow!("cannot resolve XDG data dir; pass --db / VPNCTL_DB")
                    })?
                    .join("vpnctl");
                tokio::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(&dir)
                    .await
                    .with_context(|| format!("create {}", dir.display()))?;
                dir.join("inv.db")
            }
        };
        Ok(Self { db_path, addr })
    }
}

fn dirs_data_dir() -> Option<PathBuf> {
    if let Some(x) = std::env::var_os("XDG_DATA_HOME") {
        return Some(PathBuf::from(x));
    }
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".local/share"))
}

pub fn parse_positive_secs(var: &str, default: u64) -> u64 {
    classify_positive_secs(var, std::env::var(var).ok().as_deref(), default)
}

pub fn classify_positive_secs(var: &str, raw: Option<&str>, default: u64) -> u64 {
    match raw {
        None => default,
        Some(raw) => match raw.parse::<u64>() {
            Ok(n) if n > 0 => n,
            _ => {
                tracing::warn!(
                    target = "vpnctld::config",
                    var,
                    value = %raw,
                    default,
                    "{var}={raw:?} is not a positive integer; using default {default}s"
                );
                default
            }
        },
    }
}

pub fn assert_auth_safe_for_addr(addr: SocketAddr) -> anyhow::Result<()> {
    let insecure_override = std::env::var_os("VPNCTLD_ALLOW_INSECURE_NONLOCAL")
        .is_some_and(|v| v == "1" || v == "true");
    let auth = crate::handlers::auth::classify_admin_auth_env();
    assert_auth_safe_for_addr_inner(addr, auth, insecure_override)
}

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

pub(crate) fn assert_auth_safe_for_addr_inner(
    addr: SocketAddr,
    auth: crate::handlers::auth::AdminAuthConfig,
    insecure_override: bool,
) -> anyhow::Result<()> {
    use crate::handlers::auth::AdminAuthConfig;
    if matches!(auth, AdminAuthConfig::Malformed) {
        return Err(anyhow::anyhow!(
            "vpnctld refuses to start: VPNCTLD_ADMIN_PASSWORD begins with $argon2 \
             but is not a complete, supported Argon2 PHC hash. Admin auth would be DISABLED (fail-open). \
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
    fn hashless_argon2_is_rejected_at_startup_on_every_bind() {
        let auth = crate::handlers::auth::classify_admin_auth(
            Some("admin".into()),
            Some("$argon2id".into()),
        );
        for addr in ["127.0.0.1:18402", "0.0.0.0:18402"] {
            let err = assert_auth_safe_for_addr_inner(addr.parse().unwrap(), auth, true)
                .unwrap_err()
                .to_string();
            assert!(err.contains("complete, supported Argon2 PHC hash"));
        }
    }

    #[test]
    fn malformed_argon2_is_fatal_even_on_loopback() {
        use crate::handlers::auth::AdminAuthConfig;
        let addr: SocketAddr = "127.0.0.1:18402".parse().unwrap();
        assert!(assert_auth_safe_for_addr_inner(addr, AdminAuthConfig::Malformed, false).is_err());
        let addr6: SocketAddr = "[::1]:18402".parse().unwrap();
        assert!(assert_auth_safe_for_addr_inner(addr6, AdminAuthConfig::Malformed, false).is_err());
    }

    #[test]
    fn malformed_argon2_not_rescued_by_insecure_override() {
        use crate::handlers::auth::AdminAuthConfig;
        let addr: SocketAddr = "0.0.0.0:18402".parse().unwrap();
        assert!(assert_auth_safe_for_addr_inner(addr, AdminAuthConfig::Malformed, true).is_err());
    }

    #[test]
    fn configured_auth_via_inner_allows_nonlocal_bind() {
        use crate::handlers::auth::AdminAuthConfig;
        let addr: SocketAddr = "192.0.2.1:18402".parse().unwrap();
        assert!(assert_auth_safe_for_addr_inner(addr, AdminAuthConfig::Configured, false).is_ok());
    }

    #[test]
    fn classify_positive_secs_unset_returns_default() {
        assert_eq!(classify_positive_secs("X", None, 300), 300);
    }

    #[tokio::test]
    async fn interval_env_zero_falls_back_to_default_no_panic() {
        let got = classify_positive_secs("X", Some("0"), 300);
        assert_eq!(got, 300, "interval=0 must fall back to default, never 0");

        let _tick = tokio::time::interval(std::time::Duration::from_secs(got));
    }

    #[test]
    fn classify_positive_secs_garbage_falls_back_to_default() {
        assert_eq!(classify_positive_secs("X", Some("not-a-number"), 42), 42);
    }

    #[test]
    fn classify_positive_secs_valid_value_is_used() {
        assert_eq!(
            classify_positive_secs("X", Some("17"), 300),
            17,
            "a valid positive override must win over the default"
        );
    }
}
