use std::net::IpAddr;
use std::sync::OnceLock;

use axum::http::HeaderMap;
use ipnet::IpNet;

static TRUSTED_PROXIES: OnceLock<Vec<IpNet>> = OnceLock::new();

fn parse_trusted_proxies(raw: &str) -> anyhow::Result<Vec<IpNet>> {
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    raw.split(',')
        .map(|entry| {
            let entry = entry.trim();
            entry
                .parse::<IpAddr>()
                .map(IpNet::from)
                .or_else(|_| entry.parse::<IpNet>())
                .map_err(|_| {
                    anyhow::anyhow!(
                        "vpnctld refuses to start: invalid VPNCTLD_TRUSTED_PROXIES entry {entry:?}; expected an IP address or CIDR range"
                    )
                })
        })
        .collect()
}

pub(crate) fn init_trusted_proxies() -> anyhow::Result<()> {
    let raw = match std::env::var("VPNCTLD_TRUSTED_PROXIES") {
        Ok(raw) => raw,
        Err(std::env::VarError::NotPresent) => String::new(),
        Err(std::env::VarError::NotUnicode(_)) => {
            anyhow::bail!("vpnctld refuses to start: VPNCTLD_TRUSTED_PROXIES is not valid Unicode");
        }
    };
    let proxies = parse_trusted_proxies(&raw)?;
    let _ = TRUSTED_PROXIES.set(proxies);
    Ok(())
}

fn trusted_proxies() -> &'static [IpNet] {
    TRUSTED_PROXIES.get().map_or(&[], Vec::as_slice)
}

pub(crate) fn is_trusted_proxy(peer: IpAddr) -> bool {
    trusted_proxies().iter().any(|net| net.contains(&peer))
}

pub fn resolve_real_ip(headers: &HeaderMap, peer: IpAddr) -> IpAddr {
    resolve_peer_real_ip(headers, peer)
}

pub fn resolve_real_ip_with(headers: &HeaderMap, peer: IpAddr, trusted: &[IpAddr]) -> IpAddr {
    resolve_peer_real_ip_with(headers, peer, trusted)
}

pub fn resolve_peer_real_ip(headers: &HeaderMap, peer: IpAddr) -> IpAddr {
    resolve_peer_real_ip_with_proxies(headers, peer, trusted_proxies())
}

fn resolve_peer_real_ip_with_proxies(
    headers: &HeaderMap,
    peer: IpAddr,
    proxies: &[IpNet],
) -> IpAddr {
    resolve_peer_real_ip_inner(headers, peer, proxies.iter().any(|net| net.contains(&peer)))
}

pub fn resolve_peer_real_ip_with(headers: &HeaderMap, peer: IpAddr, trusted: &[IpAddr]) -> IpAddr {
    resolve_peer_real_ip_inner(headers, peer, trusted.contains(&peer))
}

fn resolve_peer_real_ip_inner(headers: &HeaderMap, peer: IpAddr, trusted: bool) -> IpAddr {
    if !trusted {
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
    resolve_trusted_header_inner(headers, header_name, is_trusted_proxy(peer))
}

pub fn resolve_trusted_header_with(
    headers: &HeaderMap,
    peer: IpAddr,
    header_name: &str,
    trusted: &[IpAddr],
) -> Option<String> {
    resolve_trusted_header_inner(headers, header_name, trusted.contains(&peer))
}

fn resolve_trusted_header_inner(
    headers: &HeaderMap,
    header_name: &str,
    trusted: bool,
) -> Option<String> {
    if !trusted {
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
    (
        resolve_trusted_header(headers, peer, "x-ssl-ja3"),
        resolve_trusted_header(headers, peer, "x-ssl-ja4"),
    )
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
        h.insert("x-real-ip", HeaderValue::from_str(value).unwrap());
        h
    }

    fn peer(o: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 0, o))
    }

    #[test]
    fn trusted_proxies_parse_exact_ips_and_cidr_ranges() {
        let proxies = parse_trusted_proxies(
            " 127.0.0.1, ::1, 127.0.0.1/32, 10.0.0.0/8, ::1/128, 2001:db8::/32 ",
        )
        .unwrap();
        assert_eq!(proxies.len(), 6);
        for ip in ["127.0.0.1", "::1", "10.255.255.255", "2001:db8::42"] {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(proxies.iter().any(|net| net.contains(&ip)));
        }
        for ip in ["127.0.0.2", "11.0.0.1", "::2", "2001:db9::1"] {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(!proxies.iter().any(|net| net.contains(&ip)));
        }
        assert!(parse_trusted_proxies("").unwrap().is_empty());
        assert!(parse_trusted_proxies("  ").unwrap().is_empty());
    }

    #[test]
    fn trusted_proxies_reject_every_invalid_entry() {
        for bad in [
            "not-an-ip",
            "10.0.0.0/33",
            "::1/129",
            "10.0.0.0/-1",
            "10.0.0.0/8/24",
            "localhost",
            "",
        ] {
            let err = parse_trusted_proxies(&format!("127.0.0.1,{bad},::1"))
                .unwrap_err()
                .to_string();
            assert!(err.contains("VPNCTLD_TRUSTED_PROXIES"));
            assert!(err.contains(&format!("{bad:?}")), "{err}");
        }
        assert!(parse_trusted_proxies("127.0.0.1,").is_err());
        assert!(parse_trusted_proxies(",::1").is_err());
    }

    #[test]
    fn peer_real_ip_trusts_cidr_proxy_but_rejects_peers_outside_range() {
        let proxies = parse_trusted_proxies("10.0.0.0/8,2001:db8::/32").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("198.51.100.99"));
        headers.insert("x-real-ip", HeaderValue::from_static("203.0.113.9"));
        let client: IpAddr = "203.0.113.9".parse().unwrap();
        for ip in ["10.0.0.1", "10.255.255.255", "2001:db8::42"] {
            assert_eq!(
                resolve_peer_real_ip_with_proxies(&headers, ip.parse().unwrap(), &proxies),
                client
            );
        }
        for ip in ["11.0.0.1", "2001:db9::42"] {
            let ip: IpAddr = ip.parse().unwrap();
            assert_eq!(
                resolve_peer_real_ip_with_proxies(&headers, ip, &proxies),
                ip
            );
        }
    }

    #[test]
    fn untrusted_peer_returns_peer_ignoring_header() {
        let h = header("1.2.3.4");
        let untrusted = peer(100);
        let got = resolve_real_ip(&h, untrusted);
        assert_eq!(got, untrusted);
    }

    #[test]
    fn trusted_peer_extracts_x_real_ip() {
        let h = header("203.0.113.7");
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
    fn trusted_peer_extracts_ipv6_x_real_ip() {
        let h = header("2001:db8::42");
        let trusted = DEFAULT_TRUSTED_PROXY_LAN;
        let got = resolve_real_ip_with(&h, trusted, &[trusted]);
        assert_eq!(got.to_string(), "2001:db8::42");
    }

    #[test]
    fn peer_real_ip_uses_x_real_ip_and_resists_xff_spoof() {
        let mut h = HeaderMap::new();
        h.insert(
            "x-forwarded-for",
            HeaderValue::from_static("198.51.100.93, 203.0.113.9"),
        );
        h.insert("x-real-ip", HeaderValue::from_static("203.0.113.9"));
        let trusted = DEFAULT_TRUSTED_PROXY_LAN;
        assert_eq!(
            resolve_real_ip_with(&h, trusted, &[trusted]).to_string(),
            "203.0.113.9"
        );
        assert_eq!(
            resolve_peer_real_ip_with(&h, trusted, &[trusted]).to_string(),
            "203.0.113.9"
        );
    }

    #[test]
    fn logging_ip_never_falls_back_to_xff() {
        let trusted = DEFAULT_TRUSTED_PROXY_LAN;
        for real_ip in [None, Some("not-an-ip"), Some("203.0.113.9, 198.51.100.93")] {
            let mut h = HeaderMap::new();
            h.insert("x-forwarded-for", HeaderValue::from_static("198.51.100.93"));
            if let Some(value) = real_ip {
                h.insert("x-real-ip", HeaderValue::from_static(value));
            }
            assert_eq!(resolve_real_ip_with(&h, trusted, &[trusted]), trusted);
        }
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
