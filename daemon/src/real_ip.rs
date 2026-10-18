use std::net::IpAddr;
use std::sync::OnceLock;

use axum::http::HeaderMap;

static TRUSTED_PROXIES: OnceLock<Vec<IpAddr>> = OnceLock::new();

pub(crate) fn trusted_proxies() -> &'static [IpAddr] {
    TRUSTED_PROXIES.get_or_init(|| {
        std::env::var("VPNCTLD_TRUSTED_PROXIES")
            .ok()
            .map(|s| {
                s.split(',')
                    .filter_map(|x| x.trim().parse::<IpAddr>().ok())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    })
}

pub fn resolve_real_ip(headers: &HeaderMap, peer: IpAddr) -> IpAddr {
    resolve_real_ip_with(headers, peer, trusted_proxies())
}

pub fn resolve_real_ip_with(headers: &HeaderMap, peer: IpAddr, trusted: &[IpAddr]) -> IpAddr {
    if !trusted.contains(&peer) {
        return peer;
    }
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
        .unwrap_or(peer)
}

pub fn resolve_peer_real_ip(headers: &HeaderMap, peer: IpAddr) -> IpAddr {
    resolve_peer_real_ip_with(headers, peer, trusted_proxies())
}

pub fn resolve_peer_real_ip_with(headers: &HeaderMap, peer: IpAddr, trusted: &[IpAddr]) -> IpAddr {
    if !trusted.contains(&peer) {
        return peer;
    }
    headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
        .unwrap_or(peer)
}

pub fn resolve_trusted_header(
    headers: &HeaderMap,
    peer: IpAddr,
    header_name: &str,
) -> Option<String> {
    resolve_trusted_header_with(headers, peer, header_name, trusted_proxies())
}

pub fn resolve_trusted_header_with(
    headers: &HeaderMap,
    peer: IpAddr,
    header_name: &str,
    trusted: &[IpAddr],
) -> Option<String> {
    if !trusted.contains(&peer) {
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

pub fn collect_tls_fingerprints(
    headers: &HeaderMap,
    peer: IpAddr,
) -> (Option<String>, Option<String>) {
    collect_tls_fingerprints_with(headers, peer, trusted_proxies())
}

pub fn collect_tls_fingerprints_with(
    headers: &HeaderMap,
    peer: IpAddr,
    trusted: &[IpAddr],
) -> (Option<String>, Option<String>) {
    (
        resolve_trusted_header_with(headers, peer, "x-ssl-ja3", trusted),
        resolve_trusted_header_with(headers, peer, "x-ssl-ja4", trusted),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};
    use std::net::Ipv4Addr;

    const DEFAULT_TRUSTED_PROXY_LAN: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 207));

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
        let h = header("1.2.3.4");
        let untrusted = peer(100);
        let got = resolve_real_ip(&h, untrusted);
        assert_eq!(got, untrusted);
    }

    #[test]
    fn trusted_peer_extracts_leftmost_xff() {
        let h = header("203.0.113.7, 192.168.0.207");
        let trusted = DEFAULT_TRUSTED_PROXY_LAN;
        let got = resolve_real_ip_with(&h, trusted, &[trusted]);
        assert_eq!(got, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)));
    }

    #[test]
    fn trusted_peer_no_header_falls_back_to_peer() {
        let h = HeaderMap::new();
        let trusted = DEFAULT_TRUSTED_PROXY_LAN;
        let got = resolve_real_ip_with(&h, trusted, &[trusted]);
        assert_eq!(got, trusted);
    }

    #[test]
    fn trusted_peer_malformed_header_falls_back() {
        let h = header("not-an-ip, also-not");
        let trusted = DEFAULT_TRUSTED_PROXY_LAN;
        let got = resolve_real_ip_with(&h, trusted, &[trusted]);
        assert_eq!(got, trusted);
    }

    #[test]
    fn trusted_peer_extracts_ipv6_xff() {
        let h = header("2001:db8::42, 192.168.0.207");
        let trusted = DEFAULT_TRUSTED_PROXY_LAN;
        let got = resolve_real_ip_with(&h, trusted, &[trusted]);
        assert_eq!(got.to_string(), "2001:db8::42");
    }

    #[test]
    fn peer_real_ip_uses_x_real_ip_and_resists_xff_spoof() {
        let mut h = HeaderMap::new();
        h.insert(
            "x-forwarded-for",
            HeaderValue::from_static("104.194.156.93, 203.0.113.9"),
        );
        h.insert("x-real-ip", HeaderValue::from_static("203.0.113.9"));
        let trusted = DEFAULT_TRUSTED_PROXY_LAN;
        assert_eq!(
            resolve_real_ip_with(&h, trusted, &[trusted]).to_string(),
            "104.194.156.93"
        );
        assert_eq!(
            resolve_peer_real_ip_with(&h, trusted, &[trusted]).to_string(),
            "203.0.113.9"
        );
    }

    #[test]
    fn peer_real_ip_untrusted_peer_ignores_header() {
        let mut h = HeaderMap::new();
        h.insert("x-real-ip", HeaderValue::from_static("1.2.3.4"));
        let untrusted = peer(100);
        assert_eq!(resolve_peer_real_ip(&h, untrusted), untrusted);
    }

    #[test]
    fn peer_real_ip_no_header_falls_back_to_peer() {
        let h = HeaderMap::new();
        let trusted = DEFAULT_TRUSTED_PROXY_LAN;
        assert_eq!(resolve_peer_real_ip_with(&h, trusted, &[trusted]), trusted);
    }

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
        let trusted = DEFAULT_TRUSTED_PROXY_LAN;
        let got = resolve_trusted_header_with(&h, trusted, "x-ssl-ja3", &[trusted]);
        assert_eq!(got.as_deref(), Some("abcdef0123456789abcdef0123456789"));
    }

    #[test]
    fn trusted_header_rejects_oversized() {
        let big = "a".repeat(200);
        let h = ja_header("x-ssl-ja3", &big);
        let trusted = DEFAULT_TRUSTED_PROXY_LAN;
        assert_eq!(
            resolve_trusted_header_with(&h, trusted, "x-ssl-ja3", &[trusted]),
            None,
            "≥121-char header must be rejected (log-bomb defense)"
        );
    }

    #[test]
    fn trusted_header_rejects_whitespace_and_quotes() {
        let trusted = DEFAULT_TRUSTED_PROXY_LAN;
        for bad in ["abc def", "abc\tdef", "abc<def", "abc\"def", "abc'def"] {
            let h = ja_header("x-ssl-ja3", bad);
            assert_eq!(
                resolve_trusted_header_with(&h, trusted, "x-ssl-ja3", &[trusted]),
                None,
                "header value {bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn trusted_header_rejects_shell_and_log_metacharacters() {
        let trusted = DEFAULT_TRUSTED_PROXY_LAN;
        for bad in [
            "abc;def", "abc$def", "abc`def", "abc|def", "abc&def", "abc(def", "abc)def",
            "abc\\def", "abc=def", "abc/def",
        ] {
            let h = ja_header("x-ssl-ja3", bad);
            assert_eq!(
                resolve_trusted_header_with(&h, trusted, "x-ssl-ja3", &[trusted]),
                None,
                "header value {bad:?} must be rejected by the tight allowlist"
            );
        }
    }

    #[test]
    fn trusted_header_rejects_non_ascii() {
        let h = ja_header("x-ssl-ja3", "Дашборд");
        let trusted = DEFAULT_TRUSTED_PROXY_LAN;
        assert_eq!(
            resolve_trusted_header_with(&h, trusted, "x-ssl-ja3", &[trusted]),
            None,
            "non-ASCII must be rejected"
        );
    }

    #[test]
    fn trusted_header_accepts_ja4_composite_shape() {
        let h = ja_header("x-ssl-ja4", "t13d1516h2_8daaf6152771_b186095e22b6");
        let trusted = DEFAULT_TRUSTED_PROXY_LAN;
        let got = resolve_trusted_header_with(&h, trusted, "x-ssl-ja4", &[trusted]);
        assert_eq!(got.as_deref(), Some("t13d1516h2_8daaf6152771_b186095e22b6"));
    }

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
        let trusted = DEFAULT_TRUSTED_PROXY_LAN;
        let (ja3, ja4) = collect_tls_fingerprints_with(&h, trusted, &[trusted]);
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
