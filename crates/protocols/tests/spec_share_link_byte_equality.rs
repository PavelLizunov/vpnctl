#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Byte-equality regression net for `Protocol::share_link`.
//!
//! These tests assert EXACT string equality between the impl's
//! `share_link()` output and a hand-derived expected value, for
//! the exact UUID / password / secrets configuration shipping with
//! the bash `vpn-control` legacy clients. If a future commit
//! changes the format string in `crates/protocols/src/*.rs`, every
//! existing client on a phone breaks silently — these tests fire
//! BEFORE that lands.

use std::collections::HashMap;

use vpnctl_core::{KernelId, Protocol, RenderCtx, Server, ServerId, User, UserId};
use vpnctl_protocols::{Hysteria2, TuicV5, VlessReality};

// ── helpers ─────────────────────────────────────────────────────────────

fn srv() -> Server {
    Server {
        id: ServerId("node-1".to_string()),
        address: "203.0.113.7".to_string(),
        ssh_port: 22,
        ssh_user: "root".to_string(),
        kernel: KernelId("sing-box".to_string()),
        enabled_protocols: vec![],
        trusted_host_fingerprint: None,
        hoster: "generic".to_string(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

fn user(name: &str, pw: Option<&str>) -> User {
    User {
        id: UserId(name.to_string()),
        uuid: "00000000-0000-0000-0000-000000000001".to_string(),
        tuic_password: pw.map(str::to_string),
        wireguard_pubkey: None,
        sub_token: None,
    }
}

fn ctx_with<'a>(server: &'a Server, secrets: &'a HashMap<String, String>) -> RenderCtx<'a> {
    RenderCtx::new(server, secrets)
}

fn vless_secrets() -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert(
        "vless.public_key".to_string(),
        "PUBKEY_TEST_BASE64URL".to_string(),
    );
    m.insert("vless.short_id".to_string(), "deadbeef".to_string());
    m
}

// ── VLESS ───────────────────────────────────────────────────────────────

#[test]
fn vless_happy_path_byte_equal() {
    let s = srv();
    let secrets = vless_secrets();
    let ctx = ctx_with(&s, &secrets);
    let u = user("alice", Some("pw-alice"));
    let link = VlessReality::new().share_link(&ctx, &u).unwrap();
    assert_eq!(
        link,
        "vless://00000000-0000-0000-0000-000000000001@203.0.113.7:443?type=tcp&security=reality&pbk=PUBKEY_TEST_BASE64URL&sid=deadbeef&sni=www.microsoft.com&fp=chrome#alice",
    );
}

#[test]
fn vless_fragment_percent_encodes_space_byte_equal() {
    // user.id "alice cool" — space is NOT in the FRAGMENT unreserved set,
    // so it MUST become %20. Everything else stays verbatim.
    let s = srv();
    let secrets = vless_secrets();
    let ctx = ctx_with(&s, &secrets);
    let u = user("alice cool", Some("pw-alice"));
    let link = VlessReality::new().share_link(&ctx, &u).unwrap();
    assert_eq!(
        link,
        "vless://00000000-0000-0000-0000-000000000001@203.0.113.7:443?type=tcp&security=reality&pbk=PUBKEY_TEST_BASE64URL&sid=deadbeef&sni=www.microsoft.com&fp=chrome#alice%20cool",
    );
}

#[test]
fn vless_missing_public_key_is_error() {
    let s = srv();
    let mut secrets = HashMap::new();
    // Only short_id present; public_key MUST be required → Err.
    secrets.insert("vless.short_id".to_string(), "deadbeef".to_string());
    let ctx = ctx_with(&s, &secrets);
    let u = user("alice", Some("pw-alice"));
    let res = VlessReality::new().share_link(&ctx, &u);
    assert!(
        res.is_err(),
        "expected Err when vless.public_key is absent; got {res:?}",
    );
}

// ── TUIC v5 ─────────────────────────────────────────────────────────────

#[test]
fn tuic_happy_path_byte_equal() {
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let u = user("alice", Some("pw-alice"));
    let link = TuicV5::new().share_link(&ctx, &u).unwrap();
    assert_eq!(
        link,
        "tuic://00000000-0000-0000-0000-000000000001:pw-alice@203.0.113.7:8443?congestion_control=bbr&alpn=h3&allow_insecure=1#alice",
    );
}

#[test]
fn tuic_userinfo_percent_encodes_colon_in_password_byte_equal() {
    // Password "pw:x" — `:` is structural in userinfo and MUST become %3A.
    // Fragment "alice" stays verbatim.
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let u = user("alice", Some("pw:x"));
    let link = TuicV5::new().share_link(&ctx, &u).unwrap();
    assert_eq!(
        link,
        "tuic://00000000-0000-0000-0000-000000000001:pw%3Ax@203.0.113.7:8443?congestion_control=bbr&alpn=h3&allow_insecure=1#alice",
    );
}

// ── Hysteria2 ───────────────────────────────────────────────────────────

#[test]
fn hysteria2_happy_path_byte_equal() {
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let u = user("alice", Some("pw-alice"));
    let link = Hysteria2::new().share_link(&ctx, &u).unwrap();
    assert_eq!(
        link,
        "hysteria2://pw-alice@203.0.113.7:8444/?sni=203.0.113.7&insecure=1#alice",
    );
}

#[test]
fn hysteria2_fragment_percent_encodes_hash_byte_equal() {
    // user.id "alice#1" — `#` is the URI fragment delimiter and MUST be %23
    // when it appears inside the fragment label itself.
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let u = user("alice#1", Some("pw-alice"));
    let link = Hysteria2::new().share_link(&ctx, &u).unwrap();
    assert_eq!(
        link,
        "hysteria2://pw-alice@203.0.113.7:8444/?sni=203.0.113.7&insecure=1#alice%231",
    );
}

#[test]
fn hysteria2_missing_password_is_error() {
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let u = user("alice", None);
    let res = Hysteria2::new().share_link(&ctx, &u);
    assert!(
        res.is_err(),
        "expected Err when tuic_password is absent; got {res:?}",
    );
}
