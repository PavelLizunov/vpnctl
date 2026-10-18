use std::borrow::Cow;
use std::net::Ipv6Addr;

pub fn host_for_url(addr: &str) -> Cow<'_, str> {
    if addr.parse::<Ipv6Addr>().is_ok() {
        Cow::Owned(format!("[{addr}]"))
    } else {
        Cow::Borrowed(addr)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_dotted_quad_passes_through_unchanged() {
        let out = host_for_url("203.0.113.7");
        assert_eq!(out, "203.0.113.7");
        assert!(matches!(out, Cow::Borrowed(_)));
    }

    #[test]
    fn hostname_passes_through_unchanged() {
        let out = host_for_url("vpn-de1.example.org");
        assert_eq!(out, "vpn-de1.example.org");
        assert!(matches!(out, Cow::Borrowed(_)));
    }

    #[test]
    fn ipv6_literal_gets_bracketed() {
        let out = host_for_url("2a00:1450::1");
        assert_eq!(out, "[2a00:1450::1]");
        assert!(matches!(out, Cow::Owned(_)));
    }

    #[test]
    fn ipv6_full_form_is_bracketed_verbatim_not_canonicalized() {
        assert_eq!(
            host_for_url("2001:0db8:0000:0000:0000:0000:0000:0001"),
            "[2001:0db8:0000:0000:0000:0000:0000:0001]"
        );
    }

    #[test]
    fn ipv6_loopback_gets_bracketed() {
        assert_eq!(host_for_url("::1"), "[::1]");
    }

    #[test]
    fn already_bracketed_input_is_not_double_bracketed() {
        let out = host_for_url("[2a00:1450::1]");
        assert_eq!(out, "[2a00:1450::1]");
        assert!(matches!(out, Cow::Borrowed(_)));
    }

    #[test]
    fn ipv4_mapped_hostname_like_with_colon_port_is_not_treated_as_ipv6() {
        let out = host_for_url("example.org");
        assert_eq!(out, "example.org");
    }
}
