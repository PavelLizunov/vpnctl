#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use vpnctl_core::{
    DpiRisk, KernelId, Protocol, ProtocolId, RenderCtx, Server, ServerId, User, UserId,
};
use vpnctl_protocols::{AnyTls, Hysteria2, Trojan};

fn srv() -> Server {
    Server {
        id: ServerId("node-1".to_string()),
        address: "203.0.113.7".to_string(),
        ssh_port: 22,
        ssh_user: "root".to_string(),
        kernels: vec![KernelId("sing-box".to_string())],
        enabled_protocols: vec![ProtocolId("hysteria2".to_string())],
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
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    }
}

fn ctx_with<'a>(server: &'a Server, secrets: &'a HashMap<String, String>) -> RenderCtx<'a> {
    RenderCtx::new(server, secrets)
}

#[test]
fn pinned_hysteria2_native_config_is_stable_and_uri_is_unavailable() {
    let server = srv();
    let user = user("alice", Some("pw1"));
    let protocol = Hysteria2::new();
    for obfs in [false, true] {
        let mut secrets = HashMap::new();
        if obfs {
            secrets.insert("hysteria2.obfs.password".into(), "obfs-pass".into());
        }
        let ctx = ctx_with(&server, &secrets);
        let mut expected = protocol.client_config(&ctx, &user).unwrap();
        assert_eq!(expected["tls"]["insecure"], false);
        assert!(
            expected["tls"]
                .get("certificate_public_key_sha256")
                .is_none()
        );
        let inbound = serde_json::to_vec(&protocol.server_inbound(&ctx, &[]).unwrap()).unwrap();
        secrets.insert("tls.cert_sha256".into(), "ab".repeat(32));
        secrets.insert(
            "observed.tls.cert_public_key_sha256".into(),
            "cd".repeat(32),
        );
        let ctx = ctx_with(&server, &secrets);
        assert!(matches!(
            protocol.share_link(&ctx, &user),
            Err(vpnctl_core::CoreError::ShareLinkUnavailable(_))
        ));
        expected["tls"]["certificate_public_key_sha256"] = json!([STANDARD.encode([0xcd; 32])]);
        assert_eq!(
            serde_json::to_vec(&protocol.client_config(&ctx, &user).unwrap()).unwrap(),
            serde_json::to_vec(&expected).unwrap()
        );
        assert_eq!(
            serde_json::to_vec(&protocol.server_inbound(&ctx, &[]).unwrap()).unwrap(),
            inbound
        );
    }
}

#[test]
fn certificate_pin_keeps_other_tls_protocol_links_and_json_byte_equal() {
    let server = srv();
    let user = user("alice", Some("pw1"));
    let mut secrets = HashMap::new();
    let protocols: [&dyn Protocol; 2] = [&Trojan::new(), &AnyTls::new()];
    for protocol in protocols {
        secrets.clear();
        let ctx = ctx_with(&server, &secrets);
        let link = protocol.share_link(&ctx, &user).unwrap().into_bytes();
        let client = serde_json::to_vec(&protocol.client_config(&ctx, &user).unwrap()).unwrap();
        secrets.insert("tls.cert_sha256".into(), "ab".repeat(32));
        let ctx = ctx_with(&server, &secrets);
        assert_eq!(protocol.share_link(&ctx, &user).unwrap().into_bytes(), link);
        assert_eq!(
            serde_json::to_vec(&protocol.client_config(&ctx, &user).unwrap()).unwrap(),
            client
        );
    }
}

#[test]
fn h1_protocol_id_is_hysteria2() {
    let p = Hysteria2::new();
    assert_eq!(p.id(), ProtocolId("hysteria2".to_string()));
}

#[test]
fn h2_server_inbound_top_level_type_is_hysteria2() {
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let users = [user("alice", Some("pw1"))];
    let v = Hysteria2::new().server_inbound(&ctx, &users).unwrap();
    assert_eq!(v.get("type").and_then(Value::as_str), Some("hysteria2"));
}

#[test]
fn h2_server_inbound_listen_port_is_8444() {
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let users = [user("alice", Some("pw1"))];
    let v = Hysteria2::new().server_inbound(&ctx, &users).unwrap();
    assert_eq!(v.get("listen_port").and_then(Value::as_u64), Some(8444));
}

#[test]
fn h2_server_inbound_tls_alpn_contains_h3() {
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let users = [user("alice", Some("pw1"))];
    let v = Hysteria2::new().server_inbound(&ctx, &users).unwrap();
    let alpn = v
        .pointer("/tls/alpn")
        .and_then(Value::as_array)
        .expect("tls.alpn must be an array");
    assert!(
        alpn.iter().any(|x| x.as_str() == Some("h3")),
        "tls.alpn must contain \"h3\"; got {alpn:?}"
    );
}

#[test]
fn h2_server_inbound_uses_default_cert_paths() {
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let users = [user("alice", Some("pw1"))];
    let v = Hysteria2::new().server_inbound(&ctx, &users).unwrap();
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
fn h2_server_inbound_uses_secret_cert_paths_verbatim() {
    let s = srv();
    let mut secrets = HashMap::new();
    secrets.insert("tuic.cert_path".to_string(), "/srv/keys/h2.crt".to_string());
    secrets.insert("tuic.key_path".to_string(), "/srv/keys/h2.key".to_string());
    let ctx = ctx_with(&s, &secrets);
    let users = [user("alice", Some("pw1"))];
    let v = Hysteria2::new().server_inbound(&ctx, &users).unwrap();
    assert_eq!(
        v.pointer("/tls/certificate_path").and_then(Value::as_str),
        Some("/srv/keys/h2.crt"),
    );
    assert_eq!(
        v.pointer("/tls/key_path").and_then(Value::as_str),
        Some("/srv/keys/h2.key"),
    );
}

#[test]
fn h2_server_inbound_users_one_per_user_with_name_and_password() {
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let users = [user("alice", Some("pw-A")), user("bob", Some("pw-B"))];
    let v = Hysteria2::new().server_inbound(&ctx, &users).unwrap();
    let arr = v
        .get("users")
        .and_then(Value::as_array)
        .expect("users must be an array");
    assert_eq!(arr.len(), 2, "expected one entry per user; got {arr:?}");
    let alice = &arr[0];
    let bob = &arr[1];
    assert_eq!(alice.get("name").and_then(Value::as_str), Some("alice"));
    assert_eq!(alice.get("password").and_then(Value::as_str), Some("pw-A"));
    assert_eq!(bob.get("name").and_then(Value::as_str), Some("bob"));
    assert_eq!(bob.get("password").and_then(Value::as_str), Some("pw-B"));
}

#[test]
fn h2_server_inbound_skips_users_without_tuic_password() {
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let users = [
        user("alice", Some("pw-A")),
        user("nopw", None),
        user("bob", Some("pw-B")),
    ];
    let v = Hysteria2::new().server_inbound(&ctx, &users).unwrap();
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

#[test]
fn h3_client_config_basic_fields() {
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let u = user("alice", Some("client-pw"));
    let v = Hysteria2::new().client_config(&ctx, &u).unwrap();
    assert_eq!(v.get("type").and_then(Value::as_str), Some("hysteria2"));
    assert_eq!(v.get("server").and_then(Value::as_str), Some("203.0.113.7"),);
    assert_eq!(v.get("server_port").and_then(Value::as_u64), Some(8444));
    assert_eq!(v.get("password").and_then(Value::as_str), Some("client-pw"),);
}

#[test]
fn h3_client_config_user_without_password_returns_error() {
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let u = user("alice", None);
    let err = Hysteria2::new().client_config(&ctx, &u).unwrap_err();
    let msg = format!("{err:?}");
    assert!(
        msg.contains("Render") && msg.contains("alice"),
        "expected Render error naming user; got {msg}"
    );
}

#[test]
fn h3_client_config_requires_tls_verification_and_h3_alpn() {
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let u = user("alice", Some("pw"));
    let v = Hysteria2::new().client_config(&ctx, &u).unwrap();
    assert_eq!(
        v.pointer("/tls/insecure").and_then(Value::as_bool),
        Some(false),
    );
    let alpn = v
        .pointer("/tls/alpn")
        .and_then(Value::as_array)
        .expect("tls.alpn must be an array");
    assert!(
        alpn.iter().any(|x| x.as_str() == Some("h3")),
        "client tls.alpn must contain \"h3\"; got {alpn:?}"
    );
}

#[test]
fn h7_no_realm_secrets_means_no_realm_key_in_inbound() {
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let users = [user("alice", Some("pw1"))];
    let v = Hysteria2::new().server_inbound(&ctx, &users).unwrap();
    assert!(
        v.get("realm").is_none(),
        "no realm secrets ⇒ no realm key (back-compat); got {v}"
    );
    assert_eq!(v.get("listen_port").and_then(Value::as_u64), Some(8444));
}

#[test]
fn h7_realm_emitted_when_server_url_present_with_defaults() {
    let s = srv();
    let mut secrets = HashMap::new();
    secrets.insert(
        "hysteria2.realm.server_url".into(),
        "https://realm.example.com".into(),
    );
    let ctx = ctx_with(&s, &secrets);
    let v = Hysteria2::new()
        .server_inbound(&ctx, &[user("alice", Some("pw1"))])
        .unwrap();
    let realm = v.get("realm").expect("realm block must be emitted");
    assert_eq!(
        realm.get("server_url").and_then(Value::as_str),
        Some("https://realm.example.com")
    );
    assert_eq!(
        realm.get("realm_id").and_then(Value::as_str),
        Some("node-1"),
        "realm_id must default to server.id when not configured"
    );
    assert_eq!(
        realm.get("token").and_then(Value::as_str),
        Some(""),
        "token must default to empty (anonymous register)"
    );
    assert_eq!(
        realm.get("stun_servers").and_then(Value::as_array),
        Some(&vec![]),
        "stun_servers must default to empty array (sing-box uses its default pool)"
    );
    assert_eq!(v.get("listen_port").and_then(Value::as_u64), Some(8444));
}

#[test]
fn h7_realm_id_and_token_overrides_apply() {
    let s = srv();
    let mut secrets = HashMap::new();
    secrets.insert(
        "hysteria2.realm.server_url".into(),
        "https://rendezvous.lan".into(),
    );
    secrets.insert("hysteria2.realm.realm_id".into(), "homelab-vpn".into());
    secrets.insert("hysteria2.realm.token".into(), "shh-secret".into());
    let ctx = ctx_with(&s, &secrets);
    let v = Hysteria2::new()
        .server_inbound(&ctx, &[user("alice", Some("pw1"))])
        .unwrap();
    let realm = v.get("realm").unwrap();
    assert_eq!(
        realm.get("realm_id").and_then(Value::as_str),
        Some("homelab-vpn")
    );
    assert_eq!(
        realm.get("token").and_then(Value::as_str),
        Some("shh-secret")
    );
}

#[test]
fn h7_stun_servers_csv_is_parsed_into_json_array() {
    let s = srv();
    let mut secrets = HashMap::new();
    secrets.insert(
        "hysteria2.realm.server_url".into(),
        "https://r.example".into(),
    );
    secrets.insert(
        "hysteria2.realm.stun_servers".into(),
        " stun.example.com:3478 , stun.cloudflare.com:3478 , ".into(),
    );
    let ctx = ctx_with(&s, &secrets);
    let v = Hysteria2::new()
        .server_inbound(&ctx, &[user("alice", Some("pw1"))])
        .unwrap();
    let arr = v["realm"]["stun_servers"].as_array().unwrap();
    assert_eq!(
        arr.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>(),
        vec!["stun.example.com:3478", "stun.cloudflare.com:3478"],
        "stun_servers must trim whitespace + drop empty entries"
    );
}

#[test]
fn h7_empty_server_url_does_not_activate_realm() {
    for empty in ["", "   ", "\t\n"] {
        let s = srv();
        let mut secrets = HashMap::new();
        secrets.insert("hysteria2.realm.server_url".into(), empty.into());
        let ctx = ctx_with(&s, &secrets);
        let v = Hysteria2::new()
            .server_inbound(&ctx, &[user("alice", Some("pw1"))])
            .unwrap();
        assert!(
            v.get("realm").is_none(),
            "empty/whitespace server_url={empty:?} must NOT activate realm; got {v}"
        );
    }
}

#[test]
fn h8_no_obfs_secret_means_no_obfs_key_anywhere() {
    let s = srv();
    let secrets = HashMap::from([("tls.cert_sha256".into(), "ab".repeat(32))]);
    let ctx = ctx_with(&s, &secrets);
    let u = user("alice", Some("pw1"));
    let inbound = Hysteria2::new()
        .server_inbound(&ctx, std::slice::from_ref(&u))
        .unwrap();
    let outbound = Hysteria2::new().client_config(&ctx, &u).unwrap();
    assert!(inbound.get("obfs").is_none(), "inbound back-compat");
    assert!(outbound.get("obfs").is_none(), "outbound back-compat");
}

#[test]
fn h8_inbound_renders_obfs_when_password_set() {
    let s = srv();
    let mut secrets = HashMap::new();
    secrets.insert("hysteria2.obfs.password".into(), "my-obfs-secret".into());
    let ctx = ctx_with(&s, &secrets);
    let v = Hysteria2::new()
        .server_inbound(&ctx, &[user("alice", Some("pw1"))])
        .unwrap();
    let obfs = v.get("obfs").expect("obfs block must be emitted");
    assert_eq!(
        obfs.get("type").and_then(Value::as_str),
        Some("salamander"),
        "obfs.type must be hardcoded to salamander (only supported kind)"
    );
    assert_eq!(
        obfs.get("password").and_then(Value::as_str),
        Some("my-obfs-secret")
    );
}

#[test]
fn h8_client_config_mirrors_server_obfs_password() {
    let s = srv();
    let mut secrets = HashMap::new();
    secrets.insert("hysteria2.obfs.password".into(), "shared-secret".into());
    let ctx = ctx_with(&s, &secrets);
    let v = Hysteria2::new()
        .client_config(&ctx, &user("alice", Some("pw1")))
        .unwrap();
    let obfs = v.get("obfs").expect("client config must mirror obfs");
    assert_eq!(obfs.get("type").and_then(Value::as_str), Some("salamander"));
    assert_eq!(
        obfs.get("password").and_then(Value::as_str),
        Some("shared-secret"),
        "client + server MUST share the obfs password (it's the QUIC-handshake key)"
    );
}

#[test]
fn h8_empty_obfs_password_does_not_activate_obfs() {
    for empty in ["", "   ", "\t\n"] {
        let s = srv();
        let mut secrets = HashMap::new();
        secrets.insert("hysteria2.obfs.password".into(), empty.into());
        let ctx = ctx_with(&s, &secrets);
        let v = Hysteria2::new()
            .server_inbound(&ctx, &[user("alice", Some("pw1"))])
            .unwrap();
        assert!(
            v.get("obfs").is_none(),
            "empty/whitespace obfs.password={empty:?} must NOT activate obfs; got {v}"
        );
    }
}

#[test]
fn h8_realm_and_obfs_can_coexist() {
    let s = srv();
    let mut secrets = HashMap::new();
    secrets.insert(
        "hysteria2.realm.server_url".into(),
        "https://r.example".into(),
    );
    secrets.insert("hysteria2.obfs.password".into(), "obfs-pw".into());
    let ctx = ctx_with(&s, &secrets);
    let v = Hysteria2::new()
        .server_inbound(&ctx, &[user("alice", Some("pw1"))])
        .unwrap();
    assert!(
        v.get("realm").is_some(),
        "realm block must coexist with obfs"
    );
    assert!(
        v.get("obfs").is_some(),
        "obfs block must coexist with realm"
    );
}

#[test]
fn h9_dpi_risk_stays_weak_but_tooltip_explains_conditional_obfs() {
    let risk = Hysteria2::new().dpi_risk();
    assert_eq!(
        risk,
        DpiRisk::Weak,
        "Hysteria2 must stay Weak: legacy/undeployed servers can lack the Salamander secret"
    );
    let tooltip = risk.tooltip();
    assert!(
        tooltip.contains("Salamander"),
        "Weak tooltip must name the Salamander obfs so operators know new servers ARE obfuscated; got: {tooltip}"
    );
    assert!(
        tooltip.contains("legacy"),
        "Weak tooltip must scope the fingerprint to legacy servers lacking the secret; got: {tooltip}"
    );
    assert!(
        !tooltip.contains("Hysteria2-without-obfs QUIC"),
        "Weak tooltip must not claim Hysteria2 has no obfuscation outright; got: {tooltip}"
    );
}
