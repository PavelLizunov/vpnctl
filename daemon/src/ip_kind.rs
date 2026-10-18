#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpKind {
    Loopback,
    LanRfc1918,
    LinkLocal,
    Ula,
    Unspecified,
    Public,
}

impl IpKind {
    pub fn is_lan_or_loopback(self) -> bool {
        self != IpKind::Public
    }

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
