#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::{IpAddr, Ipv4Addr};

use axum::http::{HeaderMap, HeaderValue};

use super::handler::resolve_sub_ips_with;

const TRUSTED_PROXY: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 207));
const VICTIM_IP: &str = "198.51.100.77";
const ATTACKER_IP: &str = "203.0.113.9";

#[test]
fn security_ip_resists_leftmost_xff_spoof_logging_ip_keeps_it() {
    let mut h = HeaderMap::new();
    h.insert(
        "x-forwarded-for",
        HeaderValue::from_str(&format!("{VICTIM_IP}, {ATTACKER_IP}")).unwrap(),
    );
    h.insert("x-real-ip", HeaderValue::from_static(ATTACKER_IP));

    let ips = resolve_sub_ips_with(&h, Some(TRUSTED_PROXY), &[TRUSTED_PROXY]);

    assert_eq!(
        ips.sec_ip.map(|i| i.to_string()).as_deref(),
        Some(ATTACKER_IP),
        "security IP (rate-limit bucket + 24h ban key) must be the spoof-proof \
         X-Real-IP, NOT the client-controlled leftmost-XFF — else a third party \
         gets banned via header injection (CWE-345)"
    );
    assert_ne!(
        ips.sec_ip.map(|i| i.to_string()).as_deref(),
        Some(VICTIM_IP),
        "the spoofed victim IP must never become the ban/rate-limit key"
    );
    assert_eq!(
        ips.log_ip.map(|i| i.to_string()).as_deref(),
        Some(VICTIM_IP),
        "logging IP (sub_access_log) keeps the established richer leftmost-XFF \
         value — only the security decision moved"
    );
}

#[test]
fn both_ips_fall_back_to_peer_when_no_headers() {
    let h = HeaderMap::new();
    let ips = resolve_sub_ips_with(&h, Some(TRUSTED_PROXY), &[TRUSTED_PROXY]);
    assert_eq!(ips.sec_ip, Some(TRUSTED_PROXY));
    assert_eq!(ips.log_ip, Some(TRUSTED_PROXY));
}

#[test]
fn untrusted_peer_ignores_all_forwarding_headers() {
    let untrusted = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1));
    let mut h = HeaderMap::new();
    h.insert(
        "x-forwarded-for",
        HeaderValue::from_str(&format!("{VICTIM_IP}, {ATTACKER_IP}")).unwrap(),
    );
    h.insert("x-real-ip", HeaderValue::from_static(ATTACKER_IP));
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

#[test]
fn no_peer_ip_yields_none_for_both() {
    let mut h = HeaderMap::new();
    h.insert("x-real-ip", HeaderValue::from_static(ATTACKER_IP));
    let ips = resolve_sub_ips_with(&h, None, &[TRUSTED_PROXY]);
    assert_eq!(ips.sec_ip, None);
    assert_eq!(ips.log_ip, None);
}
