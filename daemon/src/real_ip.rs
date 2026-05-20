//! Real-client-IP resolution from `X-Forwarded-For` when the
//! immediate peer is a trusted reverse proxy.
//!
//! ## Why this exists
//!
//! Post-Phase-5 nginx cutover (2026-05-19): EVERY production request
//! to `/api/v1/app/config/<device_id>` arrives at vpnctld with peer
//! IP = `192.168.0.207` (the nginx host on the LAN). Without this
//! module, vpnctld's two abuse-detection inputs collapse:
//!
//!   1. `sub_access_log.ip` — every row reads "192.168.0.207" → the
//!      operator's per-user distinct-IP counter on
//!      `/admin/users/<id>` is always 1, and the heavy-users tile +
//!      Layer-3 UA-fingerprint clustering get garbage input.
//!   2. `rate_limit::try_acquire_ip` — every external client shares
//!      ONE token bucket (keyed by nginx's loopback IP). A single
//!      abuser exhausts the bucket on behalf of all 33 production
//!      users. Phase Track-2's persistent-ban escalation also fires
//!      on nginx's IP, banning ALL legit clients for 24h.
//!
//! nginx already sets `X-Real-IP $remote_addr` and
//! `X-Forwarded-For $proxy_add_x_forwarded_for` on the proxy_pass
//! to vpnctld:18402 (verified in /home/user/wb-price-scheduler/nginx/nginx.conf
//! 2026-05-20). vpnctld just wasn't reading them.
//!
//! ## Trust gate
//!
//! Parsing `X-Forwarded-For` from ANY peer is a spoof surface: a
//! malicious external client could inject the header to pretend to
//! be someone else, bypassing rate-limit per-IP buckets. The trust
//! gate is "only parse the header when the immediate TCP peer is in
//! the trusted-proxy allowlist". The allowlist is sourced from the
//! `VPNCTLD_TRUSTED_PROXIES` env var (comma-separated `IpAddr`s);
//! when the var is unset, the LAN-deployment default
//! `192.168.0.207` (nginx host) is used. Setting it to the empty
//! string OR a value that fails to parse falls back to the default
//! (operator-typo-resilient).
//!
//! ## Header format
//!
//! `X-Forwarded-For` is a comma-separated list `<client>, <proxy1>,
//! <proxy2>` — leftmost is the original client, each subsequent IP
//! is a proxy in the chain. We take the leftmost, BUT trust it only
//! because the immediate peer is in our allowlist. If a hostile
//! actor controls one of the trusted proxies, they can spoof the
//! leftmost — that's a different threat model (the trusted proxy
//! itself is compromised) and out of scope here.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::OnceLock;

use axum::http::HeaderMap;

/// Lazy-init cache of the trusted-proxies list. Read once at first
/// resolve call, never re-read (matches the "config doesn't change
/// across daemon lifetime" model used by `BasicAuth::from_env`).
static TRUSTED_PROXIES: OnceLock<Vec<IpAddr>> = OnceLock::new();

/// Default LAN-deployment trust list: nginx host on 192.168.0.207.
/// Documented in CLAUDE.md infrastructure section.
const DEFAULT_TRUSTED_PROXY_LAN: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 207));

/// Read `VPNCTLD_TRUSTED_PROXIES` (comma-separated `IpAddr` list).
/// Unset OR empty after-trim OR no values parse cleanly → fall back
/// to the single-host default. The `filter(|v| !v.is_empty())` after
/// the parse means an operator typo (`VPNCTLD_TRUSTED_PROXIES="not.an.ip"`)
/// falls back rather than disabling header parsing entirely (which
/// would silently re-enable the post-Phase-5 collapse bug).
fn trusted_proxies() -> &'static [IpAddr] {
    TRUSTED_PROXIES.get_or_init(|| {
        std::env::var("VPNCTLD_TRUSTED_PROXIES")
            .ok()
            .map(|s| {
                s.split(',')
                    .filter_map(|x| x.trim().parse::<IpAddr>().ok())
                    .collect::<Vec<_>>()
            })
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| vec![DEFAULT_TRUSTED_PROXY_LAN])
    })
}

/// Resolve the "real" client IP for abuse-detection purposes.
///
/// * If `peer` is NOT in the trusted-proxy allowlist → return `peer`.
///   Any `X-Forwarded-For` header is ignored (spoof defense).
/// * If `peer` IS trusted → parse `X-Forwarded-For` and return the
///   leftmost IP that's a valid `IpAddr`. Missing/malformed/empty →
///   fall back to `peer` (same conservative behaviour as not-trusted).
///
/// Lowercase header lookup because axum normalises HTTP/1.1 header
/// names to lowercase per RFC 7230 §3.2.
pub fn resolve_real_ip(headers: &HeaderMap, peer: IpAddr) -> IpAddr {
    if !trusted_proxies().contains(&peer) {
        return peer;
    }
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
        .unwrap_or(peer)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};
    use std::net::Ipv4Addr;

    fn header(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_str(value).unwrap());
        h
    }

    fn peer(o: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 0, o))
    }

    #[test]
    fn untrusted_peer_returns_peer_ignoring_header() {
        // Untrusted peer attempting to spoof — header is dropped on the
        // floor, peer IP is returned verbatim.
        let h = header("1.2.3.4");
        let untrusted = peer(100); // not the nginx host
        let got = resolve_real_ip(&h, untrusted);
        assert_eq!(got, untrusted);
    }

    #[test]
    fn trusted_peer_extracts_leftmost_xff() {
        let h = header("203.0.113.7, 192.168.0.207");
        let trusted = DEFAULT_TRUSTED_PROXY_LAN;
        let got = resolve_real_ip(&h, trusted);
        assert_eq!(got, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)));
    }

    #[test]
    fn trusted_peer_no_header_falls_back_to_peer() {
        let h = HeaderMap::new();
        let trusted = DEFAULT_TRUSTED_PROXY_LAN;
        let got = resolve_real_ip(&h, trusted);
        assert_eq!(got, trusted);
    }

    #[test]
    fn trusted_peer_malformed_header_falls_back() {
        let h = header("not-an-ip, also-not");
        let trusted = DEFAULT_TRUSTED_PROXY_LAN;
        let got = resolve_real_ip(&h, trusted);
        assert_eq!(got, trusted);
    }

    #[test]
    fn trusted_peer_extracts_ipv6_xff() {
        let h = header("2001:db8::42, 192.168.0.207");
        let trusted = DEFAULT_TRUSTED_PROXY_LAN;
        let got = resolve_real_ip(&h, trusted);
        assert_eq!(got.to_string(), "2001:db8::42");
    }
}
