//! Phase E — add-server wizard session store.
//!
//! The wizard collects the IP + root password on step 1, then streams
//! the bootstrap (key push → register → secrets → install → apply) on
//! step 2 (SSE) and finishes on the server's detail page — a 2-step
//! flow. (A step-3 «first-grant prompt» was planned but never built;
//! the UI copy stopped promising it 2026-06-04.) Between steps the
//! operator's input has to live somewhere; the choices are:
//!
//!   1. **Server-side in-memory store keyed by a random session id**
//!      (this module). Pros: secrets never leave the daemon process.
//!      Cons: state lost on restart — but the wizard is a 5-minute
//!      flow, not a multi-day one, so restart-loss is acceptable.
//!   2. HMAC-signed cookie carrying the secrets directly. Pros:
//!      stateless, restart-safe. Cons: root password sitting in the
//!      browser cookie jar even with HttpOnly+SameSite is a wider
//!      blast radius than a process-memory dict.
//!
//! We pick (1). The session id is 32 bytes of base64-url, set as an
//! HttpOnly + SameSite=Strict cookie scoped to `Path=/admin/servers/new`
//! so it never goes anywhere else in the admin UI.
//!
//! TTL is 10 minutes — long enough for a deliberate operator filling
//! out the form, short enough that an abandoned session times out
//! before the Tweaks panel does.
//!
//! Expiry is enforced two ways:
//!   * **Lazy purge on access** — `get()` drops the entry it's asked
//!     for if it has aged out. Cheap, but only fires for ids that are
//!     re-fetched.
//!   * **Periodic sweep** — `sweep_expired()` evicts ALL aged-out
//!     entries regardless of whether anyone ever asks for them again.
//!     This is the load-bearing one for the abandoned-session case:
//!     an operator who pastes a root password on step 1 then closes
//!     the tab leaves an id that is NEVER re-fetched, so lazy purge
//!     alone would retain the plaintext password until daemon
//!     restart. The sweep is wired into the existing rate-limit
//!     cleanup tick in `app.rs` (10-min cadence ≈ the TTL), so an
//!     abandoned session is gone within ~one TTL of going stale.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// One in-flight wizard session — the operator's step-1 input.
///
/// `root_password` is intentionally NOT hashed/encrypted at rest in
/// the store: the daemon is single-tenant on the homelab, and the
/// SSE step uses the password verbatim to bootstrap the new node.
/// Storing a hash would just mean the operator has to re-type before
/// step 2, defeating the wizard.
///
/// `ssh_port` covers the Cloudzy/non-22 case (DO Cloud Firewall pins
/// to 22 but other hosters move it; pasting "address: vpn.foo.com,
/// port: 2222" must work). 22 is the default when the form field is
/// blank — the most common case.
#[derive(Clone)]
pub struct WizardSession {
    pub address: String,
    pub root_password: String,
    pub ssh_port: u16,
    /// Wall-clock instant the session was created. Used by `get` to
    /// expire stale sessions on access.
    pub created: Instant,
}

// Hand-written so `root_password` never lands in logs / panics /
// anyhow chains via `{:?}`. Same `<redacted>` convention as the
// `User` Debug impl in `vpnctl-core` and the russh transport builders.
// The derived Debug was a loaded gun: any future `tracing::debug!(?session)`
// or `.context(format!("{session:?}"))` would have dumped the plaintext
// root password. Pinned by `wizard_session_debug_redacts_root_password`.
impl std::fmt::Debug for WizardSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WizardSession")
            .field("address", &self.address)
            .field("root_password", &"<redacted>")
            .field("ssh_port", &self.ssh_port)
            .field("created", &self.created)
            .finish()
    }
}

/// In-memory session store with lazy TTL expiry. Cloning is cheap
/// (Arc-wrapped at the call site).
#[derive(Debug, Default)]
pub struct WizardStore {
    inner: Mutex<HashMap<String, WizardSession>>,
}

/// Session lifetime. 10 minutes is the longest a sane operator should
/// take to read step 1 + paste credentials + click submit. After that
/// the assumption is they walked away and the session is stale.
pub const SESSION_TTL: Duration = Duration::from_secs(600);

/// Cookie name. Scoped via `Path=/admin/servers/new` so it never
/// leaks to other admin endpoints — the operator's session id has no
/// reason to ride along on `/admin/users` traffic.
pub const COOKIE_NAME: &str = "vpnctl_wizard";

impl WizardStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a fresh session and return its id. The id is 32 bytes of
    /// crypto random, base64-url encoded (43 ASCII chars). Collisions
    /// are statistically impossible at homelab scale.
    pub fn insert(&self, address: String, root_password: String, ssh_port: u16) -> String {
        let id = vpnctl_crypto::gen_password(32).unwrap_or_else(|_| {
            // gen_password's only failure mode is OS RNG starvation,
            // which on Linux means /dev/urandom is broken — at that
            // point the daemon has bigger problems. Fallback to a
            // timestamp-keyed id so we still respond, even if weakly:
            // the cookie is HttpOnly+SameSite=Strict so guessing it
            // requires admin-side access already.
            format!("fallback-{}", Instant::now().elapsed().as_nanos())
        });
        let session = WizardSession {
            address,
            root_password,
            ssh_port,
            created: Instant::now(),
        };
        if let Ok(mut g) = self.inner.lock() {
            g.insert(id.clone(), session);
        }
        id
    }

    /// Fetch a session by id, returning `Some` only if it exists AND
    /// hasn't expired. Expired entries are dropped on access (lazy
    /// purge) so the map doesn't grow unbounded.
    pub fn get(&self, id: &str) -> Option<WizardSession> {
        let Ok(mut g) = self.inner.lock() else {
            return None;
        };
        // Drop the expired one if present, then look up.
        if let Some(s) = g.get(id) {
            if s.created.elapsed() > SESSION_TTL {
                g.remove(id);
                return None;
            }
        }
        g.get(id).cloned()
    }

    /// Drop a session explicitly (e.g. after successful step-3
    /// completion or operator cancel). No-op if the id is unknown.
    pub fn remove(&self, id: &str) {
        if let Ok(mut g) = self.inner.lock() {
            g.remove(id);
        }
    }

    /// Evict every session older than [`SESSION_TTL`], returning the
    /// number dropped. Unlike the lazy purge in [`get`], this fires
    /// for ids that are NEVER re-fetched — the abandoned-wizard case
    /// where an operator pastes a root password on step 1 then closes
    /// the tab. Without it those entries (each holding a plaintext
    /// root password) would live until daemon restart, well past the
    /// TTL. Called on a timer from the rate-limit cleanup tick in
    /// `app.rs`. Sweeps under the same lock the rest of the store
    /// uses; on lock-poisoning it returns 0 (no panic — same
    /// convention as `get` / `remove` / `len`).
    pub fn sweep_expired(&self) -> usize {
        let Ok(mut g) = self.inner.lock() else {
            return 0;
        };
        let before = g.len();
        g.retain(|_, s| s.created.elapsed() <= SESSION_TTL);
        before - g.len()
    }

    /// Number of currently-stored sessions. Used by integration tests
    /// to assert the store side-effect of step-1 submit; in
    /// production the lazy TTL purge keeps this bounded so it's
    /// uninteresting to the hot path. Returns 0 on lock-poisoning
    /// rather than panicking — same convention as `get` / `remove`.
    pub fn len(&self) -> usize {
        self.inner.lock().map(|g| g.len()).unwrap_or(0)
    }

    /// Convenience predicate: `true` when no sessions are stored.
    /// Mirrors the standard `len` / `is_empty` pair (clippy nudges on
    /// `len() == 0` checks).
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Test-only: insert a session under `id` with a caller-supplied
    /// `created` instant. Lets the sweep test backdate `created` past
    /// the TTL deterministically (an [`Instant`] can't be moved into
    /// the past, and sleeping 10 real minutes in a unit test is a
    /// non-starter).
    #[cfg(test)]
    fn insert_at(&self, id: &str, session: WizardSession) {
        if let Ok(mut g) = self.inner.lock() {
            g.insert(id.to_string(), session);
        }
    }
}

/// Validate a server address (IP or hostname). Returns `Err` with a
/// short reason on rejection. The wizard's step 1 calls this BEFORE
/// stashing the input — invalid input never reaches the session store.
///
/// We don't try to parse as `IpAddr` because the operator should also
/// be able to type a hostname (`vpn-de1.example.org`). Charset gate
/// is the practical guard: anything matching `[A-Za-z0-9.:_-]` is a
/// reasonable IP/hostname candidate; anything else is either junk or
/// a shell-injection attempt and we bounce it.
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

/// Validate a root password. Returns `Err` on empty/oversize. We do
/// NOT validate complexity — operators who type weak passwords here
/// are bootstrapping the node, after which the wizard disables
/// password auth entirely.
pub fn validate_password(input: &str) -> Result<&str, &'static str> {
    if input.is_empty() {
        return Err("password is empty");
    }
    if input.len() > 256 {
        return Err("password is too long (>256 chars)");
    }
    Ok(input)
}

/// Parse + validate the optional SSH port. Empty string → default 22
/// (the most common case — DigitalOcean Cloud Firewall pins to 22).
/// Non-empty: must parse as 1..=65535. Anything else is operator
/// typo, surfaced with a short reason.
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
        let id = store.insert("198.51.100.42".into(), "hunter2".into(), 22);
        let s = store.get(&id).expect("session must be retrievable");
        assert_eq!(s.address, "198.51.100.42");
        assert_eq!(s.root_password, "hunter2");
        assert_eq!(s.ssh_port, 22);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn wizard_session_debug_redacts_root_password() {
        // Loaded-gun fix: a future `tracing::debug!(?session)` or
        // `format!("{session:?}")` in an anyhow chain must NOT dump the
        // plaintext root password. Same `<redacted>` convention as the
        // `User` Debug impl in vpnctl-core.
        let session = WizardSession {
            address: "198.51.100.42".into(),
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
        // The non-secret fields stay visible for diagnostics.
        assert!(
            dbg.contains("198.51.100.42"),
            "address must still print: {dbg}"
        );
    }

    #[test]
    fn insert_preserves_non_default_ssh_port() {
        // Cloudzy ships SSH on 2222 by default — the operator's
        // step-1 form field must round-trip through the session.
        let store = WizardStore::new();
        let id = store.insert("104.194.156.93".into(), "pw".into(), 2222);
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
        let id = store.insert("a".into(), "b".into(), 22);
        store.remove(&id);
        assert!(store.get(&id).is_none());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn wizard_store_periodic_sweep_evicts_expired() {
        // The abandoned-session case: an entry that is NEVER re-fetched
        // (operator closed the tab after pasting the root password)
        // must still be evicted by the timer sweep once it ages past
        // the TTL — lazy purge alone would retain the plaintext
        // password until restart.
        let store = WizardStore::new();

        // One fresh session (within TTL) + one backdated well past it.
        let fresh = store.insert("fresh.example".into(), "fresh-pw".into(), 22);
        let stale_created = Instant::now()
            .checked_sub(SESSION_TTL + Duration::from_secs(1))
            .expect("test clock is far enough from boot to backdate by ~10 min");
        store.insert_at(
            "stale-id",
            WizardSession {
                address: "stale.example".into(),
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

        // The stale session's plaintext secret must no longer be in
        // the map at all (the whole point of L1).
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
    fn validate_password_rejects_empty() {
        assert!(validate_password("").is_err());
    }

    #[test]
    fn validate_password_accepts_arbitrary_bytes_within_limit() {
        // Operators on minimal Debian VPSes get whatever the hoster
        // gives them; common formats include `Aa1!` plus whitespace,
        // unicode-quoted passwords from copy-paste, etc. We don't
        // judge — just length-cap.
        assert!(validate_password("p@$$ word with space").is_ok());
        assert!(validate_password(&"x".repeat(256)).is_ok());
        assert!(validate_password(&"x".repeat(257)).is_err());
    }
}
