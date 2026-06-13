#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! IPv6 share-link bracketing regression net (RFC 3986 §3.2.2).
//!
//! `Server.address` is a free-form string that the daemon's
//! `validate_address` explicitly permits to be a bare IPv6 literal
//! (UI label: "IPv4, IPv6 or hostname"). Every `share_link` builder
//! interpolates that address into a URL authority as `@{addr}:{port}`.
//! For an IPv6 literal that yields an UNPARSEABLE URI
//! (`vless://uuid@2a00:1450::1:443?…`) — RFC 3986 requires the literal
//! to be bracketed in the host position (`@[2a00:1450::1]:443`).
//!
//! These tests pin, per protocol:
//!   * the authority host is the BRACKETED literal `[<ipv6>]:<port>`,
//!   * the resulting URI host:port is unambiguously splittable, and
//!   * where a `sni=` param is present (hysteria2 / anytls / trojan)
//!     the SNI stays the BARE IPv6 — an SNI is a TLS server-name, not
//!     a URL host, so bracketing it would be wrong.
//!
//! Companion to `spec_share_link_byte_equality.rs`, which pins the
//! IPv4 output byte-for-byte (the helper only brackets when the input
//! parses as `Ipv6Addr`, so IPv4/hostname output is untouched).

use std::collections::HashMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;
use vpnctl_core::{KernelId, Protocol, RenderCtx, Server, ServerId, User, UserId};
use vpnctl_protocols::{
    ANYTLS_PORT, AnyTls, Hysteria2, SS_2022_PORT, Shadowsocks2022, TROJAN_PORT, Trojan, TuicV5,
    VlessReality, WireGuard, render_client_conf_public,
};

// A representative compressed IPv6 literal — the `::` is exactly the
// shape that would corrupt a naive `host:port` split.
const IP6: &str = "2a00:1450::1";
const IP6_BRACKETED: &str = "[2a00:1450::1]";
// A valid WireGuard test pubkey (44-char base64), reused from the
// wireguard spec test corpus.
const WG_PUBKEY: &str = "qXFvJL5KLmM3Of9hVo5GmJ4n0LB9rWYfV4ZE1XGZJks=";

// ── helpers ─────────────────────────────────────────────────────────────

fn srv_ipv6() -> Server {
    Server {
        id: ServerId("node-6".into()),
        address: IP6.into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

fn user(name: &str, pw: Option<&str>) -> User {
    User {
        id: UserId(name.into()),
        uuid: "00000000-0000-0000-0000-000000000001".into(),
        tuic_password: pw.map(str::to_string),
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    }
}

fn user_wg(name: &str, pubkey: &str) -> User {
    let mut u = user(name, None);
    u.wireguard_pubkey = Some(pubkey.into());
    u
}

fn ctx_with<'a>(server: &'a Server, secrets: &'a HashMap<String, String>) -> RenderCtx<'a> {
    RenderCtx::new(server, secrets)
}

/// Split a `scheme://[userinfo@]authority...` link's authority host
/// and assert it is the bracketed IPv6 literal `[<ipv6>]`, i.e. the
/// `:` chars inside the address did NOT leak into the host:port split.
/// Returns the `:port` tail (after the closing bracket) for further
/// assertion.
fn assert_bracketed_authority<'a>(link: &'a str, scheme_prefix: &str) -> &'a str {
    let after_scheme = link
        .strip_prefix(scheme_prefix)
        .unwrap_or_else(|| panic!("link does not start with {scheme_prefix:?}: {link}"));
    // Authority host begins after the last `@` of the userinfo (if any).
    let authority = match after_scheme.rsplit_once('@') {
        Some((_userinfo, rest)) => rest,
        None => after_scheme,
    };
    assert!(
        authority.starts_with(IP6_BRACKETED),
        "authority host must be the bracketed IPv6 literal, got: {authority}"
    );
    // The closing bracket delimits host from `:port` — split there.
    let tail = &authority[IP6_BRACKETED.len()..];
    assert!(
        tail.starts_with(':'),
        "bracketed host must be immediately followed by :port, got tail: {tail}"
    );
    tail
}

// ── VLESS ───────────────────────────────────────────────────────────────

#[test]
fn vless_ipv6_authority_is_bracketed() {
    let s = srv_ipv6();
    let mut secrets = HashMap::new();
    secrets.insert("vless.public_key".into(), "PUBKEY".into());
    secrets.insert("vless.short_id".into(), "deadbeef".into());
    let ctx = ctx_with(&s, &secrets);
    let link = VlessReality::new()
        .share_link(&ctx, &user("alice", None))
        .unwrap();
    let tail = assert_bracketed_authority(&link, "vless://");
    assert!(tail.starts_with(":443?"), "expected :443? got {tail}");
    // The sni= here is a fixed domain (www.microsoft.com), never the
    // address — so there is no bare-IPv6-sni concern for VLESS.
    assert!(link.contains("sni=www.microsoft.com"));
}

// ── TUIC ────────────────────────────────────────────────────────────────

#[test]
fn tuic_ipv6_authority_is_bracketed() {
    let s = srv_ipv6();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let link = TuicV5::new()
        .share_link(&ctx, &user("alice", Some("pw1")))
        .unwrap();
    let tail = assert_bracketed_authority(&link, "tuic://");
    assert!(tail.starts_with(":8443?"), "expected :8443? got {tail}");
}

// ── Shadowsocks 2022 ─────────────────────────────────────────────────────

#[test]
fn shadowsocks_ipv6_authority_is_bracketed() {
    let s = srv_ipv6();
    let mut secrets = HashMap::new();
    secrets.insert("ss2022.psk".into(), "PSK_BASE64".into());
    let ctx = ctx_with(&s, &secrets);
    let link = Shadowsocks2022::new()
        .share_link(&ctx, &user("alice", None))
        .unwrap();
    let tail = assert_bracketed_authority(&link, "ss://");
    assert!(
        tail.starts_with(&format!(":{SS_2022_PORT}/")),
        "expected :{SS_2022_PORT}/ got {tail}"
    );
}

// ── Hysteria2 (authority bracketed; sni stays BARE) ──────────────────────

#[test]
fn hysteria2_ipv6_authority_bracketed_but_sni_is_bare() {
    let s = srv_ipv6();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let link = Hysteria2::new()
        .share_link(&ctx, &user("alice", Some("pw1")))
        .unwrap();
    let tail = assert_bracketed_authority(&link, "hysteria2://");
    assert!(tail.starts_with(":8444/"), "expected :8444/ got {tail}");
    // CRITICAL: sni= is a TLS server-name, NOT a URL host — it MUST be
    // the bare IPv6 literal with NO brackets.
    assert!(
        link.contains(&format!("sni={IP6}&")),
        "sni must be the BARE IPv6 literal (no brackets): {link}"
    );
    assert!(
        !link.contains(&format!("sni={IP6_BRACKETED}")),
        "sni must NOT be bracketed: {link}"
    );
}

// ── AnyTLS (authority bracketed; sni stays BARE) ─────────────────────────

#[test]
fn anytls_ipv6_authority_bracketed_but_sni_is_bare() {
    let s = srv_ipv6();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let link = AnyTls::new()
        .share_link(&ctx, &user("alice", Some("pw1")))
        .unwrap();
    let tail = assert_bracketed_authority(&link, "anytls://");
    assert!(
        tail.starts_with(&format!(":{ANYTLS_PORT}/")),
        "expected :{ANYTLS_PORT}/ got {tail}"
    );
    assert!(
        link.contains(&format!("sni={IP6}&")),
        "sni must be the BARE IPv6 literal (no brackets): {link}"
    );
    assert!(!link.contains(&format!("sni={IP6_BRACKETED}")));
}

// ── Trojan (authority bracketed; sni stays BARE) ─────────────────────────

#[test]
fn trojan_ipv6_authority_bracketed_but_sni_is_bare() {
    let s = srv_ipv6();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let link = Trojan::new()
        .share_link(&ctx, &user("alice", Some("pw1")))
        .unwrap();
    let tail = assert_bracketed_authority(&link, "trojan://");
    assert!(
        tail.starts_with(&format!(":{TROJAN_PORT}?")),
        "expected :{TROJAN_PORT}? got {tail}"
    );
    assert!(
        link.contains(&format!("sni={IP6}&")),
        "sni must be the BARE IPv6 literal (no brackets): {link}"
    );
    assert!(!link.contains(&format!("sni={IP6_BRACKETED}")));
}

// ── WireGuard: sing-box outbound `endpoint` is bracketed ─────────────────

#[test]
fn wireguard_singbox_endpoint_ipv6_is_bracketed() {
    let s = srv_ipv6();
    let mut secrets = HashMap::new();
    secrets.insert("wireguard.server_public_key".into(), "SERVERPUB".into());
    let ctx = ctx_with(&s, &secrets);
    let cfg = WireGuard::new()
        .client_config(&ctx, &user_wg("alice", WG_PUBKEY))
        .unwrap();
    let endpoint = cfg
        .pointer("/peer/endpoint")
        .and_then(Value::as_str)
        .expect("client_config must carry peer.endpoint");
    assert_eq!(
        endpoint, "[2a00:1450::1]:51820",
        "sing-box wireguard endpoint must bracket the IPv6 host"
    );
}

// ── WireGuard: `.conf` `Endpoint =` is bracketed ─────────────────────────

#[test]
fn wireguard_conf_endpoint_ipv6_is_bracketed() {
    let s = srv_ipv6();
    let mut secrets = HashMap::new();
    secrets.insert("wireguard.server_public_key".into(), "SERVERPUB".into());
    let ctx = ctx_with(&s, &secrets);
    let conf = render_client_conf_public(&ctx, &user_wg("alice", WG_PUBKEY)).unwrap();
    assert!(
        conf.contains("Endpoint = [2a00:1450::1]:51820"),
        "WireGuard .conf Endpoint must bracket the IPv6 host:\n{conf}"
    );
    // And the share-link (base64 of the conf) must carry it too.
    let link = WireGuard::new()
        .share_link(&ctx, &user_wg("alice", WG_PUBKEY))
        .unwrap();
    let b64 = link
        .strip_prefix("wireguard://?conf=")
        .and_then(|s| s.split('#').next())
        .expect("wireguard share-link shape");
    let decoded = String::from_utf8(URL_SAFE_NO_PAD.decode(b64).unwrap()).unwrap();
    assert!(
        decoded.contains("Endpoint = [2a00:1450::1]:51820"),
        "decoded share-link .conf must bracket the IPv6 host:\n{decoded}"
    );
}
