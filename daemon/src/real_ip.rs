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

/// Same trust-gate as `resolve_real_ip` applied to a different
/// header. Track-1.4 (migration 0020): if the immediate peer is in
/// `VPNCTLD_TRUSTED_PROXIES`, return the value of `header_name` —
/// after a SHAPE check that rejects obvious garbage. Otherwise
/// return None unconditionally (spoof defense — an untrusted peer
/// can claim any JA3 / JA4 it wants).
///
/// Shape check (tight allowlist): ASCII alphanumerics + the small
/// punctuation set `, . - _ :` that covers every JA3 (digits, `,`,
/// `-`) and JA4 (alnum, `_`) form we know about, plus generous room
/// for future `_xxx` / dotted-version suffixes. Max length 120.
/// This is intentionally STRICTER than "rejects HTML/log-line
/// breakers": the value flows into the admin HTML (maud escapes
/// anyway) and into journalctl JSON (the tight allowlist makes log
/// injection structurally impossible). Anything outside the
/// allowlist → None, conservative-by-default.
pub fn resolve_trusted_header(
    headers: &HeaderMap,
    peer: IpAddr,
    header_name: &str,
) -> Option<String> {
    if !trusted_proxies().contains(&peer) {
        return None;
    }
    let raw = headers.get(header_name)?.to_str().ok()?;
    if raw.is_empty() || raw.len() > 120 {
        return None;
    }
    if raw
        .bytes()
        .any(|b| !(b.is_ascii_alphanumeric() || matches!(b, b',' | b'.' | b'-' | b'_' | b':')))
    {
        return None;
    }
    Some(raw.to_string())
}

/// Convenience helper for Track-1.4 callers (sub.rs + vpn_router.rs)
/// that need both JA3 and JA4 chips from the same request. Returns
/// `(ja3, ja4)`, each gated independently through the trust list
/// and shape check via `resolve_trusted_header`. Centralising the
/// header names (`x-ssl-ja3` and `x-ssl-ja4`) in ONE place means a
/// future header rename (or a third fingerprint family like
/// `x-tls-version`) doesn't have to be touched in every handler.
pub fn collect_tls_fingerprints(
    headers: &HeaderMap,
    peer: IpAddr,
) -> (Option<String>, Option<String>) {
    (
        resolve_trusted_header(headers, peer, "x-ssl-ja3"),
        resolve_trusted_header(headers, peer, "x-ssl-ja4"),
    )
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

    // ── Track-1.4 — resolve_trusted_header (JA3 / JA4) ─────────────

    fn ja_header(name: &str, value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
        h
    }

    #[test]
    fn trusted_header_untrusted_peer_returns_none() {
        let h = ja_header("x-ssl-ja3", "769,49195-49199,0-23-65281,29-23-24,0");
        assert_eq!(
            resolve_trusted_header(&h, peer(100), "x-ssl-ja3"),
            None,
            "untrusted peer must not be able to spoof a JA3 header"
        );
    }

    #[test]
    fn trusted_header_trusted_peer_returns_value() {
        let h = ja_header("x-ssl-ja3", "abcdef0123456789abcdef0123456789");
        let got = resolve_trusted_header(&h, DEFAULT_TRUSTED_PROXY_LAN, "x-ssl-ja3");
        assert_eq!(got.as_deref(), Some("abcdef0123456789abcdef0123456789"));
    }

    #[test]
    fn trusted_header_rejects_oversized() {
        let big = "a".repeat(200);
        let h = ja_header("x-ssl-ja3", &big);
        assert_eq!(
            resolve_trusted_header(&h, DEFAULT_TRUSTED_PROXY_LAN, "x-ssl-ja3"),
            None,
            "≥121-char header must be rejected (log-bomb defense)"
        );
    }

    #[test]
    fn trusted_header_rejects_whitespace_and_quotes() {
        for bad in [
            "abc def",  // space
            "abc\tdef", // tab
            "abc<def",  // HTML-attr breaker
            "abc\"def", // quote
            "abc'def",  // apostrophe
        ] {
            let h = ja_header("x-ssl-ja3", bad);
            assert_eq!(
                resolve_trusted_header(&h, DEFAULT_TRUSTED_PROXY_LAN, "x-ssl-ja3"),
                None,
                "header value {bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn trusted_header_rejects_shell_and_log_metacharacters() {
        // Track-1.4 hardening: the shape check is a TIGHT allowlist
        // (alnum + `,._-:`), not just "rejects HTML breakers". Every
        // char below would parse as ASCII and pass the loose v1
        // check; the tight allowlist rejects them, making log/shell
        // injection structurally impossible if any future caller
        // shells out the value or writes it into a non-escaping log.
        for bad in [
            "abc;def",  // shell separator
            "abc$def",  // var expansion
            "abc`def",  // backtick
            "abc|def",  // pipe
            "abc&def",  // background
            "abc(def",  // subshell open
            "abc)def",  // subshell close
            "abc\\def", // backslash
            "abc=def",  // env-assign
            "abc/def",  // path separator (forbid — JA3/JA4 never contain /)
        ] {
            let h = ja_header("x-ssl-ja3", bad);
            assert_eq!(
                resolve_trusted_header(&h, DEFAULT_TRUSTED_PROXY_LAN, "x-ssl-ja3"),
                None,
                "header value {bad:?} must be rejected by the tight allowlist"
            );
        }
    }

    #[test]
    fn trusted_header_rejects_non_ascii() {
        let h = ja_header("x-ssl-ja3", "Дашборд");
        assert_eq!(
            resolve_trusted_header(&h, DEFAULT_TRUSTED_PROXY_LAN, "x-ssl-ja3"),
            None,
            "non-ASCII must be rejected"
        );
    }

    #[test]
    fn trusted_header_accepts_ja4_composite_shape() {
        // FoxIO JA4 shape: `t13d1516h2_8daaf6152771_b186095e22b6`.
        // Underscore + alphanumerics. Must pass the shape check.
        let h = ja_header("x-ssl-ja4", "t13d1516h2_8daaf6152771_b186095e22b6");
        let got = resolve_trusted_header(&h, DEFAULT_TRUSTED_PROXY_LAN, "x-ssl-ja4");
        assert_eq!(got.as_deref(), Some("t13d1516h2_8daaf6152771_b186095e22b6"));
    }

    // ── Track-1.4 — collect_tls_fingerprints convenience ───────────

    #[test]
    fn collect_tls_fingerprints_returns_both_when_trusted() {
        let mut h = HeaderMap::new();
        h.insert(
            "x-ssl-ja3",
            HeaderValue::from_static("769,49195-49199,0-23-65281,29-23-24,0"),
        );
        h.insert(
            "x-ssl-ja4",
            HeaderValue::from_static("t13d1516h2_8daaf6152771_b186095e22b6"),
        );
        let (ja3, ja4) = collect_tls_fingerprints(&h, DEFAULT_TRUSTED_PROXY_LAN);
        assert!(ja3.is_some(), "ja3 must be captured");
        assert!(ja4.is_some(), "ja4 must be captured");
    }

    #[test]
    fn collect_tls_fingerprints_untrusted_peer_returns_both_none() {
        let mut h = HeaderMap::new();
        h.insert("x-ssl-ja3", HeaderValue::from_static("abc123"));
        h.insert("x-ssl-ja4", HeaderValue::from_static("def456"));
        let (ja3, ja4) = collect_tls_fingerprints(&h, peer(100));
        assert_eq!(ja3, None, "untrusted peer must not be able to spoof JA3");
        assert_eq!(ja4, None, "untrusted peer must not be able to spoof JA4");
    }
}
