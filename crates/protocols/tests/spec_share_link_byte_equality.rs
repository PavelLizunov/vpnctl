#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;

use vpnctl_core::{KernelId, Protocol, RenderCtx, Server, ServerId, User, UserId};
use vpnctl_protocols::{TuicV5, VlessReality};

fn srv() -> Server {
    Server {
        id: ServerId("node-1".to_string()),
        address: "203.0.113.7".to_string(),
        ssh_port: 22,
        ssh_user: "root".to_string(),
        kernels: vec![KernelId("sing-box".to_string())],
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
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
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
    m.insert(
        "vless.private_key".to_string(),
        "PRIVKEY_TEST_BASE64URL".to_string(),
    );
    m.insert("vless.short_id".to_string(), "deadbeef".to_string());
    m
}

#[test]
fn vless_packet_encoding_public_contract_is_xudp() {
    assert_eq!(vpnctl_protocols::VLESS_PACKET_ENCODING, "xudp");
}

#[test]
fn vless_happy_path_byte_equal_uses_robust_default_sni() {
    let s = srv();
    let secrets = vless_secrets();
    let ctx = ctx_with(&s, &secrets);
    let u = user("alice", Some("pw-alice"));
    let link = VlessReality::new().share_link(&ctx, &u).unwrap();
    assert_eq!(
        link,
        "vless://00000000-0000-0000-0000-000000000001@203.0.113.7:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=yahoo.com&fp=randomized&pbk=PUBKEY_TEST_BASE64URL&sid=deadbeef&type=tcp&packetEncoding=xudp#alice",
    );
}

#[test]
fn vless_explicit_microsoft_sni_byte_equal_with_bash_scripts() {
    let s = srv();
    let mut secrets = vless_secrets();
    secrets.insert("vless.sni".into(), "www.microsoft.com".into());
    let ctx = ctx_with(&s, &secrets);
    let u = user("alice", Some("pw-alice"));
    let link = VlessReality::new().share_link(&ctx, &u).unwrap();
    assert_eq!(
        link,
        "vless://00000000-0000-0000-0000-000000000001@203.0.113.7:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=randomized&pbk=PUBKEY_TEST_BASE64URL&sid=deadbeef&type=tcp&packetEncoding=xudp#alice",
    );
}

#[test]
fn vless_server_inbound_default_sni_matches_client_link_default() {
    let s = srv();
    let secrets = vless_secrets();
    let ctx = ctx_with(&s, &secrets);
    let u = user("alice", Some("pw-alice"));
    let inbound = VlessReality::new().server_inbound(&ctx, &[u]).unwrap();
    assert_eq!(
        inbound
            .pointer("/tls/server_name")
            .and_then(serde_json::Value::as_str),
        Some("yahoo.com"),
        "server_inbound default serverName must equal the client-link default SNI",
    );
    assert_eq!(
        inbound
            .pointer("/tls/reality/handshake/server")
            .and_then(serde_json::Value::as_str),
        Some("yahoo.com"),
        "server_inbound default REALITY handshake dest must equal the client-link default SNI",
    );
}

#[test]
fn vless_fragment_percent_encodes_space_byte_equal() {
    let s = srv();
    let secrets = vless_secrets();
    let ctx = ctx_with(&s, &secrets);
    let u = user("alice cool", Some("pw-alice"));
    let link = VlessReality::new().share_link(&ctx, &u).unwrap();
    assert_eq!(
        link,
        "vless://00000000-0000-0000-0000-000000000001@203.0.113.7:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=yahoo.com&fp=randomized&pbk=PUBKEY_TEST_BASE64URL&sid=deadbeef&type=tcp&packetEncoding=xudp#alice%20cool",
    );
}

#[test]
fn vless_server_inbound_user_carries_xtls_vision_flow() {
    let s = srv();
    let secrets = vless_secrets();
    let ctx = ctx_with(&s, &secrets);
    let u = user("alice", Some("pw-alice"));
    let inbound = VlessReality::new().server_inbound(&ctx, &[u]).unwrap();
    let first_user = inbound
        .pointer("/users/0")
        .expect("inbound must have at least one user");
    assert_eq!(
        first_user
            .pointer("/flow")
            .and_then(serde_json::Value::as_str),
        Some("xtls-rprx-vision"),
        "VLESS user record must carry xtls-rprx-vision flow (vps-is-01 import bug)",
    );
}

#[test]
fn vless_client_outbound_carries_xtls_vision_flow_and_xudp() {
    let s = srv();
    let secrets = vless_secrets();
    let ctx = ctx_with(&s, &secrets);
    let u = user("alice", Some("pw-alice"));
    let outbound = VlessReality::new().client_config(&ctx, &u).unwrap();
    assert_eq!(
        outbound
            .pointer("/flow")
            .and_then(serde_json::Value::as_str),
        Some("xtls-rprx-vision"),
        "VLESS outbound must carry xtls-rprx-vision flow at top level",
    );
    assert_eq!(
        outbound
            .pointer("/packet_encoding")
            .and_then(serde_json::Value::as_str),
        Some("xudp"),
        "VLESS outbound must explicitly enable XUDP for UDP applications",
    );
}

#[test]
fn vless_listen_port_secret_override_propagates_to_inbound_outbound_and_share_link() {
    let s = srv();
    let mut secrets = vless_secrets();
    secrets.insert("vless.listen_port".into(), "8443".into());
    let ctx = ctx_with(&s, &secrets);
    let u = user("alice", Some("pw-alice"));

    let inbound = VlessReality::new()
        .server_inbound(&ctx, std::slice::from_ref(&u))
        .unwrap();
    assert_eq!(
        inbound.pointer("/listen_port").and_then(|v| v.as_u64()),
        Some(8443),
        "server inbound must bind the overridden port"
    );

    let outbound = VlessReality::new().client_config(&ctx, &u).unwrap();
    assert_eq!(
        outbound.pointer("/server_port").and_then(|v| v.as_u64()),
        Some(8443),
        "client outbound must target the overridden port"
    );

    let link = VlessReality::new().share_link(&ctx, &u).unwrap();
    assert!(
        link.contains(":8443?"),
        "share-link must encode the overridden port; got: {link}"
    );
    assert!(
        !link.contains(":443?"),
        "share-link must NOT carry the default 443 when override is set; got: {link}"
    );
}

#[test]
fn vless_listen_port_default_443_when_secret_unset() {
    let s = srv();
    let secrets = vless_secrets();
    let ctx = ctx_with(&s, &secrets);
    let u = user("alice", Some("pw-alice"));

    let inbound = VlessReality::new()
        .server_inbound(&ctx, std::slice::from_ref(&u))
        .unwrap();
    assert_eq!(
        inbound.pointer("/listen_port").and_then(|v| v.as_u64()),
        Some(443)
    );
    let outbound = VlessReality::new().client_config(&ctx, &u).unwrap();
    assert_eq!(
        outbound.pointer("/server_port").and_then(|v| v.as_u64()),
        Some(443)
    );
    let link = VlessReality::new().share_link(&ctx, &u).unwrap();
    assert!(link.contains(":443?"), "default share-link must use :443");
}

#[test]
fn vless_listen_port_garbage_falls_back_to_443() {
    let s = srv();
    let mut secrets = vless_secrets();
    secrets.insert("vless.listen_port".into(), "abc".into());
    let ctx = ctx_with(&s, &secrets);
    let u = user("alice", Some("pw-alice"));
    let inbound = VlessReality::new().server_inbound(&ctx, &[u]).unwrap();
    assert_eq!(
        inbound.pointer("/listen_port").and_then(|v| v.as_u64()),
        Some(443),
        "garbage port secret must fall back to 443"
    );
}

#[test]
fn vless_missing_public_key_is_error() {
    let s = srv();
    let mut secrets = HashMap::new();
    secrets.insert("vless.short_id".to_string(), "deadbeef".to_string());
    let ctx = ctx_with(&s, &secrets);
    let u = user("alice", Some("pw-alice"));
    let res = VlessReality::new().share_link(&ctx, &u);
    assert!(
        res.is_err(),
        "expected Err when vless.public_key is absent; got {res:?}",
    );
}

#[test]
fn tuic_pinned_client_config_byte_equal() {
    let s = srv();
    let secrets = HashMap::from([
        ("tls.cert_sha256".into(), "ab".repeat(32)),
        (
            "observed.tls.cert_public_key_sha256".into(),
            "cd".repeat(32),
        ),
    ]);
    let ctx = ctx_with(&s, &secrets);
    let u = user("alice", Some("pw-alice"));
    let out = TuicV5::new().client_config(&ctx, &u).unwrap();
    let expected = serde_json::json!({
        "type": "tuic",
        "tag": "tuic-out",
        "server": "203.0.113.7",
        "server_port": 8443,
        "uuid": "00000000-0000-0000-0000-000000000001",
        "password": "pw-alice",
        "congestion_control": "bbr",
        "udp_relay_mode": "native",
        "tls": {
            "enabled": true,
            "insecure": false,
            "alpn": ["h3"],
            "certificate_public_key_sha256": ["zc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc0="]
        }
    });
    assert_eq!(out.to_string(), expected.to_string());
    assert!(TuicV5::new().share_link(&ctx, &u).is_err());
}

#[test]
fn tuic_client_config_missing_password_is_error() {
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let u = user("alice", None);
    let res = TuicV5::new().client_config(&ctx, &u);
    assert!(
        res.is_err(),
        "expected Err when tuic_password is absent; got {res:?}",
    );
    match res {
        Err(vpnctl_core::CoreError::Render(msg)) => {
            assert!(msg.contains("alice"));
            assert!(msg.contains("tuic_password"));
        }
        other => panic!("expected CoreError::Render, got {other:?}"),
    }
}

#[test]
fn vless_reality_listen_ports_is_tcp_443_default() {
    assert_eq!(VlessReality::new().listen_ports(), &[("tcp", 443)]);
}
