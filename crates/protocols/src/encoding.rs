use percent_encoding::{AsciiSet, CONTROLS};

/// RFC 3986 percent-encoding set for URL userinfo (username/password before `@`).
/// Used by Hysteria2, AnyTLS, Trojan, Naive, TuicV5, and Shadowsocks2022.
pub(crate) const USERINFO: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'@')
    .add(b'/')
    .add(b':')
    .add(b'\\')
    .add(b'[')
    .add(b']');

/// RFC 3986 percent-encoding set for standard URL fragments (`#...`).
/// Used by Hysteria2, AnyTLS, Trojan, Naive, TuicV5, Shadowsocks2022, and WireGuard.
pub(crate) const FRAGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'`')
    .add(b'#')
    .add(b'?');

/// Strict percent-encoding set for VLESS URL fragments (`#...`) which additionally escapes `/`, `@`, `:`.
/// Used by VlessReality, VlessWs, and VlessXhttp.
pub(crate) const VLESS_FRAGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'<')
    .add(b'>')
    .add(b'`')
    .add(b'#')
    .add(b'?')
    .add(b'/')
    .add(b'@')
    .add(b':');

/// Strict set for percent-encoding values that land in a URL query string.
pub(crate) const QUERY: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'`')
    .add(b'#')
    .add(b'?')
    .add(b'+')
    .add(b'&')
    .add(b'=');

/// Characters that must never appear in domain names for reverse proxies (Caddy, etc.).
pub(crate) const DOMAIN_ILLEGAL: &[char] =
    &['\n', '\r', '\t', ' ', '/', '?', '#', '@', '\\', '{', '}'];
