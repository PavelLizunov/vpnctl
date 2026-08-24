#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::{IpAddr, Ipv4Addr};

use axum::http::{HeaderMap, HeaderValue};

use super::handler::resolve_sub_ips_with;

/// A trusted reverse proxy (stand-in for nginx). The `_with`
/// resolvers honour XFF / X-Real-IP only when the immediate peer is
/// in this list — same trust gate as `real_ip.rs`.
const TRUSTED_PROXY: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 207));
/// The third-party VICTIM whose IP a malicious client prepends to
/// leftmost-XFF hoping to get it banned for 24h.
const VICTIM_IP: &str = "198.51.100.77";
/// The attacker's TRUE immediate peer — what nginx writes into
/// `X-Real-IP` (overwriting any client-supplied value).
const ATTACKER_IP: &str = "203.0.113.9";

/// The CWE-345 fix, pinned at the exact seam `sub.rs` keys its
/// security decisions on. A request from a trusted proxy carries a
/// spoofed leftmost-XFF (the victim) but an honest `X-Real-IP` (the
/// attacker). The SECURITY IP — which feeds BOTH the rate-limit
/// bucket and `add_ban` — must be the attacker's true IP, so a third
/// party can NEVER be banned by header injection. The LOGGING IP
/// keeps the richer leftmost-XFF (observability semantics unchanged).
#[test]
fn security_ip_resists_leftmost_xff_spoof_logging_ip_keeps_it() {
    let mut h = HeaderMap::new();
    // nginx appends $remote_addr → leftmost is the client-supplied
    // (spoofed) victim; the trailing entry is the real peer.
    h.insert(
        "x-forwarded-for",
        HeaderValue::from_str(&format!("{VICTIM_IP}, {ATTACKER_IP}")).unwrap(),
    );
    // nginx OVERWRITES X-Real-IP with the true peer ($remote_addr).
    h.insert("x-real-ip", HeaderValue::from_static(ATTACKER_IP));

    let ips = resolve_sub_ips_with(&h, Some(TRUSTED_PROXY), &[TRUSTED_PROXY]);

    // Ban / rate-limit key = attacker's TRUE IP, never the victim.
    assert_eq!(
        ips.sec_ip.map(|i| i.to_string()).as_deref(),
        Some(ATTACKER_IP),
        "security IP (rate-limit bucket + 24h ban key) must be the spoof-proof \
         X-Real-IP, NOT the client-controlled leftmost-XFF — else a third party \
         gets banned via header injection (CWE-345)"
    );
    // The victim's IP must NOT be the thing that gets banned.
    assert_ne!(
        ips.sec_ip.map(|i| i.to_string()).as_deref(),
        Some(VICTIM_IP),
        "the spoofed victim IP must never become the ban/rate-limit key"
    );
    // Logging IP semantics preserved — still the leftmost-XFF.
    assert_eq!(
        ips.log_ip.map(|i| i.to_string()).as_deref(),
        Some(VICTIM_IP),
        "logging IP (sub_access_log) keeps the established richer leftmost-XFF \
         value per CLAUDE.md 'Known gaps' — only the security decision moved"
    );
}

/// No-XFF / no-X-Real-IP from a trusted proxy: both IPs fall back to
/// the raw peer. Guards that the split introduced no behaviour change
/// for ordinary direct requests.
#[test]
fn both_ips_fall_back_to_peer_when_no_headers() {
    let h = HeaderMap::new();
    let ips = resolve_sub_ips_with(&h, Some(TRUSTED_PROXY), &[TRUSTED_PROXY]);
    assert_eq!(ips.sec_ip, Some(TRUSTED_PROXY));
    assert_eq!(ips.log_ip, Some(TRUSTED_PROXY));
}

/// Untrusted immediate peer: every forwarding header is dropped on
/// the floor for BOTH IPs (an arbitrary external client can't spoof
/// either axis). This is the pre-existing spoof defense — the change
/// must not weaken it.
#[test]
fn untrusted_peer_ignores_all_forwarding_headers() {
    let untrusted = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1));
    let mut h = HeaderMap::new();
    h.insert(
        "x-forwarded-for",
        HeaderValue::from_str(&format!("{VICTIM_IP}, {ATTACKER_IP}")).unwrap(),
    );
    h.insert("x-real-ip", HeaderValue::from_static(ATTACKER_IP));
    // Trusted list does NOT contain `untrusted`.
    let ips = resolve_sub_ips_with(&h, Some(untrusted), &[TRUSTED_PROXY]);
    assert_eq!(
        ips.sec_ip,
        Some(untrusted),
        "untrusted peer's X-Real-IP must be ignored — raw peer is the key"
    );
    assert_eq!(
        ips.log_ip,
        Some(untrusted),
        "untrusted peer's XFF must be ignored for logging too"
    );
}

/// Missing ConnectInfo (oneshot test rigs, misconfigured make-service)
/// → both IPs are `None`, so the handler skips the per-IP ban + bucket
/// entirely (the `if let Some(addr)` guards). No panic, no key.
#[test]
fn no_peer_ip_yields_none_for_both() {
    let mut h = HeaderMap::new();
    h.insert("x-real-ip", HeaderValue::from_static(ATTACKER_IP));
    let ips = resolve_sub_ips_with(&h, None, &[TRUSTED_PROXY]);
    assert_eq!(ips.sec_ip, None);
    assert_eq!(ips.log_ip, None);
}
