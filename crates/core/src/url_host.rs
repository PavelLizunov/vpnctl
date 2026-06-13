//! IPv6-safe URL host formatting shared across `Protocol::share_link`
//! builders in `vpnctl-protocols`.
//!
//! ## Why this lives in `vpnctl-core`
//!
//! `Server.address` is a free-form `String` that the daemon's
//! `validate_address` (UI label "IPv4, IPv6 or hostname") explicitly
//! permits to be a bare IPv6 literal (`2a00:1450::1`). Every
//! `share_link` builder in `vpnctl-protocols` interpolates that
//! address into the authority of a URI as `@{addr}:{port}` /
//! `{addr}:{port}` / a WireGuard `Endpoint = {addr}:{port}`. For an
//! IPv6 literal that produces an UNPARSEABLE URI —
//! `vless://uuid@2a00:1450::1:443?…` — because RFC 3986 §3.2.2
//! requires IPv6 literals in a URL host to be wrapped in square
//! brackets (`@[2a00:1450::1]:443`). The colons inside the address
//! are otherwise indistinguishable from the host:port separator.
//!
//! `vpnctl-protocols` already depends on `vpnctl-core` for the
//! `Server` / `User` / `RenderCtx` types, so this helper adds zero
//! new edges to the dependency graph — it just gives all seven
//! affected protocols one place to bracket the host.
//!
//! ## What this is NOT for
//!
//! This helper formats a **URL host** (authority / WireGuard
//! endpoint). It MUST NOT be applied to a TLS `sni=` value:
//! hysteria2 / anytls / trojan also emit `sni={addr}`, but an SNI is
//! a bare TLS server-name, not a URL host — a bracketed SNI would be
//! wrong. Only the authority host gets bracketed.

use std::borrow::Cow;
use std::net::Ipv6Addr;

/// Bracket an IPv6 literal for use as a URL host per RFC 3986 §3.2.2;
/// pass IPv4 addresses and hostnames through unchanged.
///
/// The input is a *raw* address (an unbracketed `Server.address`), so
/// only a bare IPv6 literal triggers the wrap. An IPv4 dotted-quad or
/// a hostname never parses as [`Ipv6Addr`], so it is returned borrowed
/// and byte-identical — this is what keeps the IPv4 share-link
/// byte-equality contract intact.
///
/// A value that is *already* bracketed (`[2a00::1]`) does NOT parse as
/// an [`Ipv6Addr`] either, so it is passed through unchanged rather
/// than double-bracketed. In practice `Server.address` is never
/// pre-bracketed (`validate_address` stores the bare literal), so this
/// is purely a defensive no-op, not a supported input shape.
///
/// ## Examples
///
/// ```
/// use vpnctl_core::url_host::host_for_url;
/// assert_eq!(host_for_url("203.0.113.7"), "203.0.113.7");
/// assert_eq!(host_for_url("vpn-de1.example.org"), "vpn-de1.example.org");
/// assert_eq!(host_for_url("2a00:1450::1"), "[2a00:1450::1]");
/// ```
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
        // The byte-equality contract: an IPv4 address must round-trip
        // byte-identical (and stay borrowed — no allocation).
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
        // The helper brackets the EXACT input bytes — it does NOT
        // re-compress / canonicalize the literal. Byte-stability is the
        // goal: whatever the operator typed as `Server.address` is what
        // appears (bracketed) in the link, so the link is reproducible.
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
        // Defensive: a pre-bracketed value does NOT parse as Ipv6Addr,
        // so it passes through rather than becoming `[[…]]`. This input
        // shape does not occur in practice (Server.address is bare).
        let out = host_for_url("[2a00:1450::1]");
        assert_eq!(out, "[2a00:1450::1]");
        assert!(matches!(out, Cow::Borrowed(_)));
    }

    #[test]
    fn ipv4_mapped_hostname_like_with_colon_port_is_not_treated_as_ipv6() {
        // A `host:port` string is not a bare address and must not
        // parse as Ipv6 — callers pass only the host, never host:port.
        let out = host_for_url("example.org");
        assert_eq!(out, "example.org");
    }
}
