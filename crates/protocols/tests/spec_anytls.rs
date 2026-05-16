#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Independent spec tests for `vpnctl_protocols::AnyTls`.
//!
//! Written from the spec only — no peeking at the implementation.
//! If a test fails, the implementation is wrong — do NOT weaken the test.

use std::collections::HashMap;

use serde_json::Value;
use vpnctl_core::{KernelId, Protocol, ProtocolId, RenderCtx, Server, ServerId, User, UserId};
use vpnctl_protocols::{ANYTLS_PORT, AnyTls};

// ── helpers ─────────────────────────────────────────────────────────────

fn srv() -> Server {
    Server {
        id: ServerId("node-1".to_string()),
        address: "203.0.113.7".to_string(),
        ssh_port: 22,
        ssh_user: "root".to_string(),
        kernel: KernelId("sing-box".to_string()),
        enabled_protocols: vec![ProtocolId("anytls".to_string())],
        trusted_host_fingerprint: None,
        hoster: "generic".to_string(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

fn user(name: &str, pw: Option<&str>) -> User {
    User {
        id: UserId(name.to_string()),
        uuid: "uuid-1".to_string(),
        tuic_password: pw.map(str::to_string),
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
    }
}

fn ctx_with<'a>(server: &'a Server, secrets: &'a HashMap<String, String>) -> RenderCtx<'a> {
    RenderCtx::new(server, secrets)
}

// ── A1: id() + port constant ────────────────────────────────────────────

#[test]
fn a1_protocol_id_is_anytls() {
    assert_eq!(AnyTls::new().id(), ProtocolId("anytls".to_string()));
}

#[test]
fn a1_anytls_port_constant_is_8843() {
    assert_eq!(ANYTLS_PORT, 8843u16);
}

// ── A2: server_inbound ──────────────────────────────────────────────────

#[test]
fn a2_server_inbound_top_level_shape() {
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let users = [user("alice", Some("pw1"))];
    let v = AnyTls::new().server_inbound(&ctx, &users).unwrap();
    assert_eq!(v.get("type").and_then(Value::as_str), Some("anytls"));
    assert_eq!(v.get("tag").and_then(Value::as_str), Some("anytls-in"));
    assert_eq!(v.get("listen").and_then(Value::as_str), Some("::"));
    assert_eq!(
        v.get("listen_port").and_then(Value::as_u64),
        Some(u64::from(ANYTLS_PORT)),
    );
}

#[test]
fn a2_server_inbound_uses_default_cert_paths() {
    let s = srv();
    let secrets = HashMap::new(); // tuic.cert_path / tuic.key_path absent
    let ctx = ctx_with(&s, &secrets);
    let users = [user("alice", Some("pw1"))];
    let v = AnyTls::new().server_inbound(&ctx, &users).unwrap();
    assert_eq!(
        v.pointer("/tls/enabled").and_then(Value::as_bool),
        Some(true),
    );
    assert_eq!(
        v.pointer("/tls/certificate_path").and_then(Value::as_str),
        Some("/etc/sing-box/cert.pem"),
    );
    assert_eq!(
        v.pointer("/tls/key_path").and_then(Value::as_str),
        Some("/etc/sing-box/key.pem"),
    );
}

#[test]
fn a2_server_inbound_uses_secret_cert_paths_verbatim() {
    let s = srv();
    let mut secrets = HashMap::new();
    secrets.insert(
        "tuic.cert_path".to_string(),
        "/srv/keys/anytls.crt".to_string(),
    );
    secrets.insert(
        "tuic.key_path".to_string(),
        "/srv/keys/anytls.key".to_string(),
    );
    let ctx = ctx_with(&s, &secrets);
    let users = [user("alice", Some("pw1"))];
    let v = AnyTls::new().server_inbound(&ctx, &users).unwrap();
    assert_eq!(
        v.pointer("/tls/certificate_path").and_then(Value::as_str),
        Some("/srv/keys/anytls.crt"),
    );
    assert_eq!(
        v.pointer("/tls/key_path").and_then(Value::as_str),
        Some("/srv/keys/anytls.key"),
    );
}

#[test]
fn a2_server_inbound_users_one_per_user_with_name_and_password() {
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let users = [user("alice", Some("pw-A")), user("bob", Some("pw-B"))];
    let v = AnyTls::new().server_inbound(&ctx, &users).unwrap();
    let arr = v
        .get("users")
        .and_then(Value::as_array)
        .expect("users must be an array");
    assert_eq!(arr.len(), 2, "expected one entry per user; got {arr:?}");
    assert_eq!(arr[0].get("name").and_then(Value::as_str), Some("alice"));
    assert_eq!(arr[0].get("password").and_then(Value::as_str), Some("pw-A"));
    assert_eq!(arr[1].get("name").and_then(Value::as_str), Some("bob"));
    assert_eq!(arr[1].get("password").and_then(Value::as_str), Some("pw-B"));
}

#[test]
fn a2_server_inbound_skips_users_without_tuic_password() {
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let users = [
        user("alice", Some("pw-A")),
        user("nopw", None),
        user("bob", Some("pw-B")),
    ];
    let v = AnyTls::new().server_inbound(&ctx, &users).unwrap();
    let arr = v
        .get("users")
        .and_then(Value::as_array)
        .expect("users must be an array");
    assert_eq!(arr.len(), 2, "users without tuic_password must be skipped");
    let names: Vec<&str> = arr
        .iter()
        .filter_map(|u| u.get("name").and_then(Value::as_str))
        .collect();
    assert!(!names.contains(&"nopw"), "got names: {names:?}");
}

// ── A3: client_config ───────────────────────────────────────────────────

#[test]
fn a3_client_config_field_by_field() {
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let u = user("alice", Some("client-pw"));
    let v = AnyTls::new().client_config(&ctx, &u).unwrap();
    assert_eq!(v.get("type").and_then(Value::as_str), Some("anytls"));
    assert_eq!(v.get("tag").and_then(Value::as_str), Some("anytls-out"));
    assert_eq!(v.get("server").and_then(Value::as_str), Some("203.0.113.7"));
    assert_eq!(
        v.get("server_port").and_then(Value::as_u64),
        Some(u64::from(ANYTLS_PORT)),
    );
    assert_eq!(v.get("password").and_then(Value::as_str), Some("client-pw"),);
    assert_eq!(
        v.pointer("/tls/enabled").and_then(Value::as_bool),
        Some(true),
    );
    assert_eq!(
        v.pointer("/tls/insecure").and_then(Value::as_bool),
        Some(true),
    );
}

#[test]
fn a3_client_config_missing_password_returns_render_error() {
    // Post-review: AnyTLS now hard-errors on missing password
    // (consistent with share_link). Pin the new contract — minting
    // a config with empty password would just silently auth-fail
    // on the client.
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let u = user("alice", None);
    let err = AnyTls::new().client_config(&ctx, &u).unwrap_err();
    let msg = format!("{err:?}");
    assert!(
        msg.contains("Render") && msg.contains("alice"),
        "expected Render error naming user; got {msg}"
    );
}

// ── A4: share_link ──────────────────────────────────────────────────────

#[test]
fn a4_share_link_scheme_host_port_query_and_fragment() {
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let u = user("alice", Some("pw"));
    let link = AnyTls::new().share_link(&ctx, &u).unwrap();
    assert!(link.starts_with("anytls://"), "got link: {link}");
    assert!(
        link.contains(&format!("@{}:{}", s.address, ANYTLS_PORT)),
        "host:port must be @203.0.113.7:8843; got {link}"
    );
    assert!(
        link.contains(&format!("sni={}", s.address)),
        "share link must carry sni=<address>; got {link}",
    );
    assert!(
        link.contains("insecure=1"),
        "share link must carry insecure=1; got {link}",
    );
    let frag_idx = link.find('#').expect("share link must have '#' fragment");
    let fragment = &link[frag_idx + 1..];
    assert_eq!(fragment, "alice", "fragment must be user.id; got {link}");
}

#[test]
fn a4_share_link_password_percent_encodes_at_and_slash() {
    // Password "ab/cd@ef" — `/` and `@` are structural in USERINFO and MUST
    // be percent-encoded inside the auth segment.
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let u = user("alice", Some("ab/cd@ef"));
    let link = AnyTls::new().share_link(&ctx, &u).unwrap();

    let after_scheme = link
        .strip_prefix("anytls://")
        .expect("link must start with anytls://");
    let at_idx = after_scheme
        .rfind('@')
        .expect("share link must contain '@' between userinfo and host");
    let userinfo = &after_scheme[..at_idx];

    assert!(
        userinfo.contains("%40"),
        "raw '@' must be percent-encoded in password; userinfo = {userinfo:?}",
    );
    assert!(
        userinfo.contains("%2F") || userinfo.contains("%2f"),
        "raw '/' must be percent-encoded in password; userinfo = {userinfo:?}",
    );
    assert!(
        !userinfo.contains('@'),
        "raw '@' leaked into userinfo: {userinfo:?}",
    );
    assert!(
        !userinfo.contains('/'),
        "raw '/' leaked into userinfo: {userinfo:?}",
    );
}

#[test]
fn a4_share_link_user_without_password_returns_error() {
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let u = user("alice-no-pw", None);
    let res = AnyTls::new().share_link(&ctx, &u);
    let err = res.expect_err("expected Err for user without tuic_password");
    let msg = format!("{err}");
    assert!(
        msg.contains("alice-no-pw"),
        "error must mention the user id; got {msg:?}",
    );
}
