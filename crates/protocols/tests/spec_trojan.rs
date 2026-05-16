#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Spec tests for `vpnctl_protocols::Trojan` — independent of impl.

use std::collections::HashMap;

use serde_json::Value;
use vpnctl_core::{KernelId, Protocol, ProtocolId, RenderCtx, Server, ServerId, User, UserId};
use vpnctl_protocols::{TROJAN_PORT, Trojan};

fn srv() -> Server {
    Server {
        id: ServerId("node-1".into()),
        address: "203.0.113.7".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernel: KernelId("sing-box".into()),
        enabled_protocols: vec![ProtocolId("trojan".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

fn user(name: &str, pw: Option<&str>) -> User {
    User {
        id: UserId(name.into()),
        uuid: "uuid-1".into(),
        tuic_password: pw.map(str::to_string),
        wireguard_pubkey: None,
        sub_token: None,
    }
}

fn ctx_with<'a>(server: &'a Server, secrets: &'a HashMap<String, String>) -> RenderCtx<'a> {
    RenderCtx::new(server, secrets)
}

#[test]
fn tr1_id_is_trojan() {
    assert_eq!(Trojan::new().id(), ProtocolId("trojan".into()));
}

#[test]
fn tr1_port_constant_is_8643() {
    assert_eq!(TROJAN_PORT, 8643);
}

#[test]
fn tr2_server_inbound_shape() {
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let v = Trojan::new()
        .server_inbound(&ctx, &[user("alice", Some("pw"))])
        .unwrap();
    assert_eq!(v.get("type").and_then(Value::as_str), Some("trojan"));
    assert_eq!(v.get("tag").and_then(Value::as_str), Some("trojan-in"));
    assert_eq!(v.get("listen").and_then(Value::as_str), Some("::"));
    assert_eq!(v.get("listen_port").and_then(Value::as_u64), Some(8643));
    assert!(v.get("users").and_then(Value::as_array).is_some());
    assert_eq!(
        v.pointer("/tls/enabled").and_then(Value::as_bool),
        Some(true)
    );
}

#[test]
fn tr2_uses_default_cert_paths_when_secrets_absent() {
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let v = Trojan::new()
        .server_inbound(&ctx, &[user("alice", Some("pw"))])
        .unwrap();
    assert_eq!(
        v.pointer("/tls/certificate_path").and_then(Value::as_str),
        Some("/etc/sing-box/cert.pem")
    );
    assert_eq!(
        v.pointer("/tls/key_path").and_then(Value::as_str),
        Some("/etc/sing-box/key.pem")
    );
}

#[test]
fn tr2_overrides_cert_paths_via_tuic_secrets() {
    let s = srv();
    let mut secrets = HashMap::new();
    secrets.insert("tuic.cert_path".into(), "/srv/c.pem".into());
    secrets.insert("tuic.key_path".into(), "/srv/k.pem".into());
    let ctx = ctx_with(&s, &secrets);
    let v = Trojan::new()
        .server_inbound(&ctx, &[user("alice", Some("pw"))])
        .unwrap();
    assert_eq!(
        v.pointer("/tls/certificate_path").and_then(Value::as_str),
        Some("/srv/c.pem")
    );
    assert_eq!(
        v.pointer("/tls/key_path").and_then(Value::as_str),
        Some("/srv/k.pem")
    );
}

#[test]
fn tr2_skips_users_without_tuic_password() {
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let users = [
        user("alice", Some("pw-A")),
        user("nopw", None),
        user("bob", Some("pw-B")),
    ];
    let v = Trojan::new().server_inbound(&ctx, &users).unwrap();
    let arr = v.get("users").and_then(Value::as_array).unwrap();
    assert_eq!(arr.len(), 2);
    let names: Vec<&str> = arr
        .iter()
        .filter_map(|u| u.get("name").and_then(Value::as_str))
        .collect();
    assert!(!names.contains(&"nopw"));
}

#[test]
fn tr3_client_config_fields() {
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let v = Trojan::new()
        .client_config(&ctx, &user("alice", Some("client-pw")))
        .unwrap();
    assert_eq!(v.get("type").and_then(Value::as_str), Some("trojan"));
    assert_eq!(v.get("tag").and_then(Value::as_str), Some("trojan-out"));
    assert_eq!(v.get("server").and_then(Value::as_str), Some("203.0.113.7"));
    assert_eq!(v.get("server_port").and_then(Value::as_u64), Some(8643));
    assert_eq!(v.get("password").and_then(Value::as_str), Some("client-pw"));
    assert_eq!(
        v.pointer("/tls/insecure").and_then(Value::as_bool),
        Some(true)
    );
}

#[test]
fn tr4_share_link_uses_trojan_scheme_with_allowinsecure_camelcase() {
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let link = Trojan::new()
        .share_link(&ctx, &user("alice", Some("hunter2")))
        .unwrap();
    assert!(link.starts_with("trojan://hunter2@203.0.113.7:8643?"));
    assert!(link.contains("sni=203.0.113.7"));
    // Trojan uses `allowInsecure` (camelCase), NOT `insecure` — pin
    // against future drift that would break older Trojan clients.
    assert!(
        link.contains("allowInsecure=1"),
        "trojan link must use camelCase `allowInsecure`, got: {link}"
    );
    assert!(link.ends_with("#alice"));
}

#[test]
fn tr4_share_link_percent_encodes_special_chars_in_password() {
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let link = Trojan::new()
        .share_link(&ctx, &user("alice", Some("p@ss/word")))
        .unwrap();
    // `@` and `/` must be percent-encoded so the userinfo parser
    // doesn't split in the wrong place.
    assert!(link.contains("p%40ss%2Fword"));
    assert!(!link.contains("p@ss/word"));
}

#[test]
fn tr4_share_link_missing_password_returns_render_error() {
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let res = Trojan::new().share_link(&ctx, &user("nopw", None));
    let err = res.unwrap_err();
    let msg = format!("{err:?}");
    assert!(msg.contains("Render"));
    assert!(msg.contains("nopw"));
}
