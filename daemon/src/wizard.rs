use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct WizardSession {
    pub address: String,
    pub ssh_user: String,
    pub root_password: String,
    pub ssh_port: u16,
    pub created: Instant,
}

impl std::fmt::Debug for WizardSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WizardSession")
            .field("address", &self.address)
            .field("ssh_user", &self.ssh_user)
            .field("root_password", &"<redacted>")
            .field("ssh_port", &self.ssh_port)
            .field("created", &self.created)
            .finish()
    }
}

#[derive(Debug, Default)]
pub struct WizardStore {
    inner: Mutex<HashMap<String, WizardSession>>,
}

pub const SESSION_TTL: Duration = Duration::from_secs(600);

pub const COOKIE_NAME: &str = "vpnctl_wizard";

impl WizardStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(
        &self,
        address: String,
        ssh_user: String,
        root_password: String,
        ssh_port: u16,
    ) -> String {
        let id = vpnctl_crypto::gen_password(32)
            .unwrap_or_else(|_| format!("fallback-{}", Instant::now().elapsed().as_nanos()));
        let session = WizardSession {
            address,
            ssh_user,
            root_password,
            ssh_port,
            created: Instant::now(),
        };
        if let Ok(mut g) = self.inner.lock() {
            g.insert(id.clone(), session);
        }
        id
    }

    pub fn get(&self, id: &str) -> Option<WizardSession> {
        let Ok(mut g) = self.inner.lock() else {
            return None;
        };
        if let Some(s) = g.get(id) {
            if s.created.elapsed() > SESSION_TTL {
                g.remove(id);
                return None;
            }
        }
        g.get(id).cloned()
    }

    pub fn remove(&self, id: &str) {
        if let Ok(mut g) = self.inner.lock() {
            g.remove(id);
        }
    }

    pub fn sweep_expired(&self) -> usize {
        let Ok(mut g) = self.inner.lock() else {
            return 0;
        };
        let before = g.len();
        g.retain(|_, s| s.created.elapsed() <= SESSION_TTL);
        before - g.len()
    }

    pub fn len(&self) -> usize {
        self.inner.lock().map(|g| g.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[cfg(test)]
    fn insert_at(&self, id: &str, session: WizardSession) {
        if let Ok(mut g) = self.inner.lock() {
            g.insert(id.to_string(), session);
        }
    }
}

pub fn validate_address(input: &str) -> Result<&str, &'static str> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("address is empty");
    }
    if trimmed.len() > 255 {
        return Err("address is too long (>255 chars)");
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '_' | '-'))
    {
        return Err("address contains characters outside [A-Za-z0-9.:_-]");
    }
    Ok(trimmed)
}

pub fn validate_ssh_user(input: &str) -> Result<&str, &'static str> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("ssh_user is empty");
    }
    if trimmed.len() > 32 {
        return Err("ssh_user is too long (>32 chars)");
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
    {
        return Err("ssh_user contains characters outside [A-Za-z0-9_-]");
    }
    Ok(trimmed)
}

pub fn validate_password(input: &str) -> Result<&str, &'static str> {
    if input.is_empty() {
        return Err("password is empty");
    }
    if input.len() > 256 {
        return Err("password is too long (>256 chars)");
    }
    Ok(input)
}

pub fn validate_ssh_port(input: &str) -> std::result::Result<u16, &'static str> {
    let t = input.trim();
    if t.is_empty() {
        return Ok(22);
    }
    let n: u32 = t.parse().map_err(|_| "ssh_port is not a number")?;
    if n == 0 || n > 65535 {
        return Err("ssh_port out of range (1..=65535)");
    }
    Ok(n as u16)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn insert_then_get_roundtrips_payload() {
        let store = WizardStore::new();
        let id = store.insert("198.51.100.42".into(), "root".into(), "hunter2".into(), 22);
        let s = store.get(&id).expect("session must be retrievable");
        assert_eq!(s.address, "198.51.100.42");
        assert_eq!(s.root_password, "hunter2");
        assert_eq!(s.ssh_port, 22);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn wizard_session_debug_redacts_root_password() {
        let session = WizardSession {
            address: "198.51.100.42".into(),
            ssh_user: "root".into(),
            root_password: "PW_ROOT_MUST_NOT_LEAK".into(),
            ssh_port: 22,
            created: Instant::now(),
        };
        let dbg = format!("{session:?}");
        assert!(
            !dbg.contains("PW_ROOT_MUST_NOT_LEAK"),
            "Debug leaked root_password: {dbg}"
        );
        assert!(
            dbg.contains("<redacted>"),
            "expected redaction marker in Debug output: {dbg}"
        );
        assert!(
            dbg.contains("198.51.100.42"),
            "address must still print: {dbg}"
        );
    }

    #[test]
    fn insert_preserves_non_default_ssh_port() {
        let store = WizardStore::new();
        let id = store.insert("198.51.100.93".into(), "root".into(), "pw".into(), 2222);
        assert_eq!(store.get(&id).unwrap().ssh_port, 2222);
    }

    #[test]
    fn get_unknown_id_returns_none() {
        let store = WizardStore::new();
        assert!(store.get("nope").is_none());
    }

    #[test]
    fn remove_drops_session() {
        let store = WizardStore::new();
        let id = store.insert("a".into(), "root".into(), "b".into(), 22);
        store.remove(&id);
        assert!(store.get(&id).is_none());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn wizard_store_periodic_sweep_evicts_expired() {
        let store = WizardStore::new();

        let fresh = store.insert("fresh.example".into(), "root".into(), "fresh-pw".into(), 22);
        let stale_created = Instant::now()
            .checked_sub(SESSION_TTL + Duration::from_secs(1))
            .expect("test clock is far enough from boot to backdate by ~10 min");
        store.insert_at(
            "stale-id",
            WizardSession {
                address: "stale.example".into(),
                ssh_user: "root".into(),
                root_password: "stale-root-secret".into(),
                ssh_port: 2222,
                created: stale_created,
            },
        );
        assert_eq!(store.len(), 2, "both sessions present before sweep");

        let dropped = store.sweep_expired();

        assert_eq!(dropped, 1, "exactly the stale session is swept");
        assert_eq!(store.len(), 1, "fresh session survives the sweep");
        assert!(
            store.get("stale-id").is_none(),
            "stale session is gone after sweep"
        );
        assert!(
            store.get(&fresh).is_some(),
            "fresh session is still retrievable after sweep"
        );

        let leaked = store
            .inner
            .lock()
            .unwrap()
            .values()
            .any(|s| s.root_password == "stale-root-secret");
        assert!(
            !leaked,
            "swept session's root password is no longer retained"
        );
    }

    #[test]
    fn validate_ssh_port_defaults_blank_to_22() {
        assert_eq!(validate_ssh_port("").unwrap(), 22);
        assert_eq!(validate_ssh_port("   ").unwrap(), 22);
    }

    #[test]
    fn validate_ssh_port_accepts_in_range_values() {
        assert_eq!(validate_ssh_port("2222").unwrap(), 2222);
        assert_eq!(validate_ssh_port("1").unwrap(), 1);
        assert_eq!(validate_ssh_port("65535").unwrap(), 65535);
    }

    #[test]
    fn validate_ssh_port_rejects_zero_and_oob_and_garbage() {
        assert!(validate_ssh_port("0").is_err());
        assert!(validate_ssh_port("65536").is_err());
        assert!(validate_ssh_port("abc").is_err());
        assert!(validate_ssh_port("-1").is_err());
    }

    #[test]
    fn validate_address_accepts_ipv4_ipv6_and_hostname() {
        assert!(validate_address("192.0.2.1").is_ok());
        assert!(validate_address("2001:db8::1").is_ok());
        assert!(validate_address("vpn-de1.example.org").is_ok());
    }

    #[test]
    fn validate_address_rejects_empty_and_garbage() {
        assert!(validate_address("").is_err());
        assert!(validate_address("   ").is_err());
        assert!(validate_address("198.51.100.1; rm -rf /").is_err());
        assert!(validate_address("hostname with space").is_err());
    }

    #[test]
    fn validate_address_trims_whitespace() {
        assert_eq!(validate_address("  10.0.0.1  ").unwrap(), "10.0.0.1");
    }

    #[test]
    fn validate_ssh_user_accepts_common_hoster_accounts() {
        assert_eq!(validate_ssh_user("root").unwrap(), "root");
        assert_eq!(validate_ssh_user(" debian ").unwrap(), "debian");
        assert_eq!(validate_ssh_user("ubuntu-24_04").unwrap(), "ubuntu-24_04");
    }

    #[test]
    fn validate_ssh_user_rejects_empty_injection_and_oversize() {
        assert!(validate_ssh_user("").is_err());
        assert!(validate_ssh_user("debian; id").is_err());
        assert!(validate_ssh_user("-oProxyCommand=x").is_err());
        assert!(validate_ssh_user(&"a".repeat(33)).is_err());
    }

    #[test]
    fn validate_password_rejects_empty() {
        assert!(validate_password("").is_err());
    }

    #[test]
    fn validate_password_accepts_arbitrary_bytes_within_limit() {
        assert!(validate_password("p@$$ word with space").is_ok());
        assert!(validate_password(&"x".repeat(256)).is_ok());
        assert!(validate_password(&"x".repeat(257)).is_err());
    }
}
