#![allow(clippy::expect_used)]

use std::collections::HashMap;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::json;
use vpnctl_core::{DpiRisk, Protocol, RenderCtx, Server, ServerId, User, UserId};
use vpnctl_protocols::Vmess;

const DOMAIN: &str = "vpn.example.test";
const ALICE_UUID: &str = "69fcc06e-70c5-4f78-9dec-38d5636b4115";
const BOB_UUID: &str = "a2568ff8-d30c-4513-ab96-781667ea15a2";
const CERTIFICATE_CHAIN: &str = concat!(
    "-----BEGIN CERTIFICATE-----\n",
    "ZmFrZS1sZWFm\n",
    "-----END CERTIFICATE-----\n",
    "-----BEGIN CERTIFICATE-----\n",
    "ZmFrZS1pbnRlcm1lZGlhdGU=\n",
    "-----END CERTIFICATE-----\n",
);
const LINK_JSON: &str = concat!(
    r#"{"add":"vpn.example.test","aid":"0","alpn":"http/1.1","host":"vpn.example.test","#,
    r#""id":"69fcc06e-70c5-4f78-9dec-38d5636b4115","net":"ws","path":"/vmess","#,
    r#""port":"443","ps":"spec-server VMess ~alice","scy":"aes-128-gcm","#,
    r#""sni":"vpn.example.test","tls":"tls","type":"none","v":"2"}"#,
);

fn server() -> Server {
    Server {
        id: ServerId("spec-server".into()),
        address: "192.0.2.10".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![],
        enabled_protocols: vec![],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

fn user(id: &str, uuid: &str, disabled: bool) -> User {
    User {
        id: UserId(id.into()),
        uuid: uuid.into(),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled,
    }
}

fn alice() -> User {
    user("alice", ALICE_UUID, false)
}

fn synthetic_key(label: &str) -> String {
    format!("-----BEGIN {label}-----\nZmFrZS1rZXk=\n-----END {label}-----\n")
}

fn client_settings() -> HashMap<String, String> {
    HashMap::from([("vmess.domain".into(), DOMAIN.into())])
}

fn server_settings() -> HashMap<String, String> {
    let mut settings = client_settings();
    settings.insert("vmess.certificate".into(), CERTIFICATE_CHAIN.into());
    settings.insert("vmess.key".into(), synthetic_key("PRIVATE KEY"));
    settings
}

#[test]
fn vmess_metadata_and_default_port() {
    assert_eq!(Vmess.id().0, "vmess");
    assert_eq!(Vmess.dpi_risk(), DpiRisk::Moderate);
    assert_eq!(Vmess.listen_ports(), &[("tcp", 443)]);
    assert_eq!(
        Vmess.effective_listen_ports(&client_settings()),
        [("tcp", 443)]
    );
    assert!(Vmess.appears_in_sing_box_sub());
    assert!(Vmess.appears_in_stock_sing_box_sub());
}

#[test]
fn inbound_contains_tls_websocket_and_unique_enabled_users() {
    let server = server();
    let settings = server_settings();
    let ctx = RenderCtx::new(&server, &settings);
    let users = [
        user("disabled", BOB_UUID, true),
        user("malformed", "invalid-uuid", false),
        alice(),
        user("duplicate", &ALICE_UUID.to_ascii_uppercase(), false),
        user("bob", BOB_UUID, false),
    ];

    Vmess.validate_server(&ctx).expect("valid VMess settings");
    let inbound = Vmess.server_inbound(&ctx, &users).expect("VMess inbound");
    assert_eq!(
        inbound,
        json!({
            "type": "vmess",
            "tag": "vmess-in",
            "listen": "::",
            "listen_port": 443,
            "users": [
                {"name": "alice", "uuid": ALICE_UUID, "alterId": 0},
                {"name": "bob", "uuid": BOB_UUID, "alterId": 0},
            ],
            "tls": {
                "enabled": true,
                "alpn": ["http/1.1"],
                "certificate": CERTIFICATE_CHAIN.lines().collect::<Vec<_>>(),
                "key": settings["vmess.key"].lines().collect::<Vec<_>>(),
            },
            "transport": {"type": "ws", "path": "/vmess"},
        })
    );
}

#[test]
fn server_accepts_supported_private_key_delimiters() {
    let server = server();
    let mut settings = server_settings();
    for label in ["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"] {
        let key = synthetic_key(label);
        settings.insert("vmess.key".into(), key.clone());
        let ctx = RenderCtx::new(&server, &settings);

        Vmess
            .validate_server(&ctx)
            .expect("supported PEM key label");
        let inbound = Vmess.server_inbound(&ctx, &[]).expect("VMess inbound");
        assert_eq!(
            inbound["tls"]["key"],
            json!(key.lines().collect::<Vec<_>>())
        );
    }
}

#[test]
fn server_rejects_missing_or_malformed_pem() {
    let server = server();
    let mismatched_key = synthetic_key("RSA PRIVATE KEY").replace("END RSA", "END EC");
    for (field, value) in [
        ("vmess.certificate", None),
        ("vmess.key", None),
        (
            "vmess.certificate",
            Some("-----BEGIN CERTIFICATE-----\nZmFrZQ==\n"),
        ),
        ("vmess.key", Some("ZmFrZS1rZXk=")),
        ("vmess.key", Some(CERTIFICATE_CHAIN)),
        ("vmess.key", Some(mismatched_key.as_str())),
    ] {
        let mut settings = server_settings();
        settings.remove(field);
        if let Some(value) = value {
            settings.insert(field.into(), value.into());
        }
        let ctx = RenderCtx::new(&server, &settings);

        assert!(Vmess.validate_server(&ctx).is_err(), "field {field}");
        assert!(Vmess.server_inbound(&ctx, &[]).is_err(), "field {field}");
    }
}

#[test]
fn client_config_matches_sing_box_json_bytes_without_server_tls_material() {
    let server = server();
    let settings = client_settings();
    let ctx = RenderCtx::new(&server, &settings);
    let outbound = Vmess.client_config(&ctx, &alice()).expect("VMess outbound");

    assert_eq!(
        serde_json::to_string(&outbound).expect("serialize outbound"),
        concat!(
            r#"{"alter_id":0,"security":"aes-128-gcm","server":"vpn.example.test","#,
            r#""server_port":443,"tag":"vmess-out","tls":{"alpn":["http/1.1"],"#,
            r#""enabled":true,"server_name":"vpn.example.test"},"transport":{"headers":{"#,
            r#""Host":"vpn.example.test"},"path":"/vmess","type":"ws"},"type":"vmess","#,
            r#""uuid":"69fcc06e-70c5-4f78-9dec-38d5636b4115"}"#,
        )
    );
}

#[test]
fn share_link_matches_v2ray_json_bytes_and_padded_standard_base64() {
    let server = server();
    let settings = client_settings();
    let ctx = RenderCtx::new(&server, &settings);
    let link = Vmess.share_link(&ctx, &alice()).expect("VMess share link");
    let encoded = link.strip_prefix("vmess://").expect("VMess link scheme");

    assert_eq!(encoded, STANDARD.encode(LINK_JSON));
    assert_eq!(
        STANDARD.decode(encoded).expect("decode VMess payload"),
        LINK_JSON.as_bytes()
    );
}

#[test]
fn custom_port_is_used_by_the_listener_and_both_client_formats() {
    let server = server();
    let mut settings = server_settings();
    for port in [1_u16, 8443, u16::MAX] {
        settings.insert("vmess.listen_port".into(), port.to_string());
        let ctx = RenderCtx::new(&server, &settings);
        Vmess.validate_server(&ctx).expect("valid VMess port");
        assert_eq!(Vmess.effective_listen_ports(&settings), [("tcp", port)]);
        assert_eq!(
            Vmess.server_inbound(&ctx, &[]).expect("VMess inbound")["listen_port"],
            port
        );
        assert_eq!(
            Vmess.client_config(&ctx, &alice()).expect("VMess outbound")["server_port"],
            port
        );
        let link = Vmess.share_link(&ctx, &alice()).expect("VMess share link");
        let encoded = link.strip_prefix("vmess://").expect("VMess link scheme");
        let bytes = STANDARD.decode(encoded).expect("decode VMess payload");
        let payload: serde_json::Value = serde_json::from_slice(&bytes).expect("VMess payload");
        assert_eq!(payload["port"], port.to_string());
    }
}

#[test]
fn rejects_invalid_ports_and_detects_ssh_port_conflicts() {
    let mut server = server();
    let mut settings = server_settings();
    for port in ["0", "65536", "-1", "https"] {
        settings.insert("vmess.listen_port".into(), port.into());
        let ctx = RenderCtx::new(&server, &settings);
        assert!(Vmess.validate_server(&ctx).is_err(), "port {port}");
        assert!(Vmess.server_inbound(&ctx, &[]).is_err(), "port {port}");
        assert!(Vmess.client_config(&ctx, &alice()).is_err(), "port {port}");
        assert!(Vmess.share_link(&ctx, &alice()).is_err(), "port {port}");
    }

    settings.insert("vmess.listen_port".into(), server.ssh_port.to_string());
    assert!(
        Vmess
            .validate_server(&RenderCtx::new(&server, &settings))
            .is_err()
    );
    settings.remove("vmess.listen_port");
    server.ssh_port = 443;
    assert!(
        Vmess
            .validate_server(&RenderCtx::new(&server, &settings))
            .is_err()
    );
}

#[test]
fn server_and_clients_require_a_valid_dns_hostname() {
    let server = server();
    for domain in [
        None,
        Some(""),
        Some("192.0.2.10"),
        Some("2001:db8::10"),
        Some("https://vpn.example.test"),
        Some("vpn.example.test:443"),
        Some("-vpn.example.test"),
        Some("vpn-.example.test"),
        Some("vpn_name.example.test"),
        Some("vpn..example.test"),
    ] {
        let mut settings = server_settings();
        settings.remove("vmess.domain");
        if let Some(domain) = domain {
            settings.insert("vmess.domain".into(), domain.into());
        }
        let ctx = RenderCtx::new(&server, &settings);
        assert!(Vmess.validate_server(&ctx).is_err(), "domain {domain:?}");
        assert!(
            Vmess.server_inbound(&ctx, &[]).is_err(),
            "domain {domain:?}"
        );
        assert!(
            Vmess.client_config(&ctx, &alice()).is_err(),
            "domain {domain:?}"
        );
        assert!(
            Vmess.share_link(&ctx, &alice()).is_err(),
            "domain {domain:?}"
        );
    }
}

#[test]
fn disabled_users_and_malformed_uuids_cannot_receive_client_config() {
    let server = server();
    let settings = client_settings();
    let ctx = RenderCtx::new(&server, &settings);
    for user in [
        user("disabled", ALICE_UUID, true),
        user("empty", "", false),
        user("malformed", "invalid-uuid", false),
    ] {
        assert!(
            Vmess.client_config(&ctx, &user).is_err(),
            "user {}",
            user.id.0
        );
        assert!(Vmess.share_link(&ctx, &user).is_err(), "user {}", user.id.0);
    }
}
