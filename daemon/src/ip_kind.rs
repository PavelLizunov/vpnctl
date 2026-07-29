//! IP-address classification helpers shared between the admin UI
//! render (which paints colour chips next to each row) and the
//! access-log writer (which fires `sub_access.suspicious_local_ip`
//! admin_alerts on non-public hits).
//!
//! Pavel 2026-05-21: «если видим 127.0.0.1 или любой из 192.168/10/
//! 172.16-31 (метка LAN) и 169.254.* то это инцедент, который
//! требует разбирательства». The writer-side alert hook + the
//! render-side chip both want the same classifier — keep one
//! source of truth here so a future net-class addition (say
//! `100.64.0.0/10` CGNAT) lands in both places at once.
//!
/// Bucket the IP belongs to. Used for:
/// - admin-UI chip colour + tooltip + label,
/// - the `sub_access.suspicious_local_ip` alert predicate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpKind {
    /// `127.0.0.0/8` — same-host loopback. Almost never seen on a
    /// production sub fetch. Strong investigation signal.
    Loopback,
    /// RFC 1918 private space: `10/8`, `172.16/12`, `192.168/16`.
    /// In our setup the only legitimate source of these is the
    /// nginx peer on `192.168.0.207` (which we read THROUGH via
    /// `X-Forwarded-For` — see `real_ip.rs`); a row with a LAN
    /// peer + no XFF resolution means the client really came
    /// from inside the homelab.
    LanRfc1918,
    /// `169.254.0.0/16` — DHCP-failure fallback. Should never
    /// appear in a healthy access log.
    LinkLocal,
    /// RFC 4193 `fc00::/7` unique-local IPv6 space.
    Ula,
    /// `0.0.0.0` / `::` cannot identify a real external client.
    Unspecified,
    /// Everything else — real public client.
    Public,
}

impl IpKind {
    /// True if this is a non-public bucket. Used as the «fire the
    /// suspicious-local-ip alert?» predicate, gated further by the
    /// UA allowlist in `access_log::run_writer`.
    pub fn is_lan_or_loopback(self) -> bool {
        self != IpKind::Public
    }

    /// Short label for admin UI chip + alert summary. EN-only by
    /// design — kept as a stable token so log greps work the same
    /// regardless of operator locale.
    pub fn label(self) -> &'static str {
        match self {
            IpKind::Loopback => "loopback",
            IpKind::LanRfc1918 => "lan-rfc1918",
            IpKind::LinkLocal => "link-local",
            IpKind::Ula => "ula",
            IpKind::Unspecified => "unspecified",
            IpKind::Public => "public",
        }
    }
}

/// Parse once with the standard library so IPv4 and IPv6 use the same rules.
pub fn classify_ip(ip: &str) -> IpKind {
    match ip.parse::<std::net::IpAddr>() {
        Ok(addr) if addr.is_loopback() => IpKind::Loopback,
        Ok(addr) if addr.is_unspecified() => IpKind::Unspecified,
        Ok(std::net::IpAddr::V4(addr)) if addr.is_private() => IpKind::LanRfc1918,
        Ok(std::net::IpAddr::V4(addr)) if addr.is_link_local() => IpKind::LinkLocal,
        Ok(std::net::IpAddr::V6(addr)) if addr.is_unicast_link_local() => IpKind::LinkLocal,
        Ok(std::net::IpAddr::V6(addr)) if addr.segments()[0] & 0xfe00 == 0xfc00 => IpKind::Ula,
        _ => IpKind::Public,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn classify_ip_buckets() {
        assert_eq!(classify_ip("127.0.0.1"), IpKind::Loopback);
        assert_eq!(classify_ip("127.1.2.3"), IpKind::Loopback);
        assert_eq!(classify_ip("10.0.0.1"), IpKind::LanRfc1918);
        assert_eq!(classify_ip("192.168.0.236"), IpKind::LanRfc1918);
        assert_eq!(classify_ip("172.16.5.1"), IpKind::LanRfc1918);
        assert_eq!(classify_ip("172.31.255.254"), IpKind::LanRfc1918);
        assert_eq!(classify_ip("172.15.0.1"), IpKind::Public);
        assert_eq!(classify_ip("172.32.0.1"), IpKind::Public);
        assert_eq!(classify_ip("169.254.0.1"), IpKind::LinkLocal);
        assert_eq!(classify_ip("::1"), IpKind::Loopback);
        assert_eq!(classify_ip("fe80::1"), IpKind::LinkLocal);
        assert_eq!(classify_ip("fc00::1"), IpKind::Ula);
        assert_eq!(classify_ip("fd12:3456::1"), IpKind::Ula);
        assert_eq!(classify_ip("::"), IpKind::Unspecified);
        assert_eq!(classify_ip("104.194.156.93"), IpKind::Public);
        assert_eq!(classify_ip("8.8.8.8"), IpKind::Public);
        assert_eq!(classify_ip("2001:4860:4860::8888"), IpKind::Public);
        assert_eq!(classify_ip("not-an-ip"), IpKind::Public);
    }

    #[test]
    fn is_lan_or_loopback_covers_all_three_buckets() {
        assert!(IpKind::Loopback.is_lan_or_loopback());
        assert!(IpKind::LanRfc1918.is_lan_or_loopback());
        assert!(IpKind::LinkLocal.is_lan_or_loopback());
        assert!(IpKind::Ula.is_lan_or_loopback());
        assert!(IpKind::Unspecified.is_lan_or_loopback());
        assert!(!IpKind::Public.is_lan_or_loopback());
    }
}
