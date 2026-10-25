#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde_json::Value;
use vpnctl_core::{
    CoreError, KernelId, Protocol, ProtocolId, RenderCtx, Server, ServerId, User, UserId,
};
use vpnctl_protocols::{SS_2022_PORT, Shadowsocks2022};

fn srv() -> Server {
    Server {
        id: ServerId("node-1".to_string()),
        address: "203.0.113.7".to_string(),
        ssh_port: 22,
        ssh_user: "root".to_string(),
        kernels: vec![KernelId("sing-box".to_string())],
        enabled_protocols: vec![ProtocolId("shadowsocks-2022".to_string())],
        trusted_host_fingerprint: None,
        hoster: "generic".to_string(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

fn user(name: &str) -> User {
    User {
        id: UserId(name.to_string()),
        uuid: "00000000-0000-0000-0000-000000000001".to_string(),
        tuic_password: None,
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

const PSK: &str = "AAECAwQFBgcICQoLDA0ODw==";

fn secrets_with_psk() -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert("ss2022.psk".to_string(), PSK.to_string());
    m
}

#[test]
fn ss_id_is_shadowsocks_2022() {
    let p = Shadowsocks2022::new();
    assert_eq!(p.id(), ProtocolId("shadowsocks-2022".to_string()));
}

#[test]
fn ss_port_constant_is_8388() {
    assert_eq!(SS_2022_PORT, 8388_u16);
}

#[test]
fn ss_server_inbound_default_method() {
    let s = srv();
    let secrets = secrets_with_psk();
    let ctx = ctx_with(&s, &secrets);
    let v = Shadowsocks2022::new()
        .server_inbound(&ctx, &[user("alice"), user("bob")])
        .unwrap();
    assert_eq!(v.get("type").and_then(Value::as_str), Some("shadowsocks"));
    assert_eq!(v.get("tag").and_then(Value::as_str), Some("ss22-in"));
    assert_eq!(v.get("listen").and_then(Value::as_str), Some("::"));
    assert_eq!(
        v.get("listen_port").and_then(Value::as_u64),
        Some(u64::from(SS_2022_PORT))
    );
    assert_eq!(v.get("listen_port").and_then(Value::as_u64), Some(8388));
    assert_eq!(
        v.get("method").and_then(Value::as_str),
        Some("2022-blake3-aes-128-gcm")
    );
    assert_eq!(v.get("password").and_then(Value::as_str), Some(PSK));
    assert!(
        v.get("users").is_none(),
        "v0.4 single-user mode: no `users` array; got {v}"
    );
}

#[test]
fn ss_server_inbound_method_override_via_secret() {
    let s = srv();
    let mut secrets = secrets_with_psk();
    secrets.insert(
        "ss2022.method".into(),
        "2022-blake3-aes-256-gcm".to_string(),
    );
    secrets.insert("ss2022.psk".into(), B64.encode([0_u8; 32]));
    let ctx = ctx_with(&s, &secrets);
    let v = Shadowsocks2022::new()
        .server_inbound(&ctx, &[user("alice")])
        .unwrap();
    assert_eq!(
        v.get("method").and_then(Value::as_str),
        Some("2022-blake3-aes-256-gcm")
    );
}

#[test]
fn ss_server_inbound_users_argument_is_ignored() {
    let s = srv();
    let secrets = secrets_with_psk();
    let ctx = ctx_with(&s, &secrets);
    let p = Shadowsocks2022::new();
    let v_empty = p.server_inbound(&ctx, &[]).unwrap();
    let v_one = p.server_inbound(&ctx, &[user("alice")]).unwrap();
    let v_many = p
        .server_inbound(&ctx, &[user("a"), user("b"), user("c")])
        .unwrap();
    assert_eq!(v_empty, v_one, "users array must be ignored (empty vs one)");
    assert_eq!(v_one, v_many, "users array must be ignored (one vs many)");
}

#[test]
fn ss_server_inbound_missing_psk_returns_missing_secret() {
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let err = Shadowsocks2022::new()
        .server_inbound(&ctx, &[user("alice")])
        .unwrap_err();
    match err {
        CoreError::MissingSecret { server, key } => {
            assert_eq!(server, ServerId("node-1".to_string()));
            assert_eq!(key, "ss2022.psk");
        }
        other => panic!("expected MissingSecret {{ key: ss2022.psk }}, got {other:?}"),
    }
}

#[test]
fn ss_client_config_basic_fields() {
    let s = srv();
    let secrets = secrets_with_psk();
    let ctx = ctx_with(&s, &secrets);
    let v = Shadowsocks2022::new()
        .client_config(&ctx, &user("alice"))
        .unwrap();
    assert_eq!(v.get("type").and_then(Value::as_str), Some("shadowsocks"));
    assert_eq!(v.get("tag").and_then(Value::as_str), Some("ss22-out"));
    assert_eq!(v.get("server").and_then(Value::as_str), Some("203.0.113.7"));
    assert_eq!(
        v.get("server_port").and_then(Value::as_u64),
        Some(u64::from(SS_2022_PORT))
    );
    assert_eq!(
        v.get("method").and_then(Value::as_str),
        Some("2022-blake3-aes-128-gcm")
    );
    assert_eq!(v.get("password").and_then(Value::as_str), Some(PSK));
}

#[test]
fn ss_client_config_method_and_password_match_inbound() {
    let s = srv();
    let mut secrets = secrets_with_psk();
    secrets.insert(
        "ss2022.method".into(),
        "2022-blake3-chacha20-poly1305".to_string(),
    );
    secrets.insert("ss2022.psk".into(), B64.encode([0_u8; 32]));
    let ctx = ctx_with(&s, &secrets);
    let p = Shadowsocks2022::new();
    let inbound = p.server_inbound(&ctx, &[user("alice")]).unwrap();
    let outbound = p.client_config(&ctx, &user("alice")).unwrap();
    assert_eq!(
        inbound.get("method"),
        outbound.get("method"),
        "method must match between inbound and outbound"
    );
    assert_eq!(
        inbound.get("password"),
        outbound.get("password"),
        "password (PSK) must match between inbound and outbound"
    );
}

#[test]
fn ss_client_config_missing_psk_returns_missing_secret() {
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let err = Shadowsocks2022::new()
        .client_config(&ctx, &user("alice"))
        .unwrap_err();
    assert!(
        matches!(err, CoreError::MissingSecret { ref key, .. } if key == "ss2022.psk"),
        "expected MissingSecret(ss2022.psk), got {err:?}"
    );
}

#[test]
fn ss_client_config_user_argument_is_ignored() {
    let s = srv();
    let secrets = secrets_with_psk();
    let ctx = ctx_with(&s, &secrets);
    let p = Shadowsocks2022::new();
    let v1 = p.client_config(&ctx, &user("alice")).unwrap();
    let mut bob = user("bob");
    bob.uuid = "ffffffff-ffff-ffff-ffff-ffffffffffff".into();
    let v2 = p.client_config(&ctx, &bob).unwrap();
    assert_eq!(v1, v2, "client_config must ignore the User argument");
}

#[test]
fn ss_invalid_method_rejected_by_server_inbound() {
    let s = srv();
    let mut secrets = secrets_with_psk();
    secrets.insert("ss2022.method".into(), "aes-128-gcm".to_string());
    let ctx = ctx_with(&s, &secrets);
    let err = Shadowsocks2022::new()
        .server_inbound(&ctx, &[user("alice")])
        .unwrap_err();
    assert!(
        matches!(err, CoreError::Render(_)),
        "invalid method must be Render error, got {err:?}"
    );
}

#[test]
fn ss_invalid_method_rejected_by_client_config() {
    let s = srv();
    let mut secrets = secrets_with_psk();
    secrets.insert("ss2022.method".into(), "rc4-md5".to_string());
    let ctx = ctx_with(&s, &secrets);
    let err = Shadowsocks2022::new()
        .client_config(&ctx, &user("alice"))
        .unwrap_err();
    assert!(
        matches!(err, CoreError::Render(_)),
        "invalid method must be Render error, got {err:?}"
    );
}

#[test]
fn ss_invalid_method_rejected_by_share_link() {
    let s = srv();
    let mut secrets = secrets_with_psk();
    secrets.insert("ss2022.method".into(), "chacha20-ietf-poly1305".to_string());
    let ctx = ctx_with(&s, &secrets);
    let err = Shadowsocks2022::new()
        .share_link(&ctx, &user("alice"))
        .unwrap_err();
    assert!(
        matches!(err, CoreError::Render(_)),
        "invalid method must be Render error from share_link too, got {err:?}"
    );
}

#[test]
fn ss_all_three_valid_methods_accepted() {
    for method in [
        "2022-blake3-aes-128-gcm",
        "2022-blake3-aes-256-gcm",
        "2022-blake3-chacha20-poly1305",
    ] {
        let s = srv();
        let mut secrets = secrets_with_psk();
        secrets.insert("ss2022.method".into(), method.to_string());
        let bytes = if method == "2022-blake3-aes-128-gcm" {
            16
        } else {
            32
        };
        secrets.insert("ss2022.psk".into(), B64.encode(vec![0_u8; bytes]));
        let ctx = ctx_with(&s, &secrets);
        let v = Shadowsocks2022::new()
            .server_inbound(&ctx, &[user("alice")])
            .unwrap();
        assert_eq!(v.get("method").and_then(Value::as_str), Some(method));
        let protocol = Shadowsocks2022::new();
        assert!(protocol.client_config(&ctx, &user("alice")).is_ok());
        assert!(protocol.share_link(&ctx, &user("alice")).is_ok());
    }
}

#[test]
fn ss_share_link_missing_psk_returns_missing_secret() {
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let err = Shadowsocks2022::new()
        .share_link(&ctx, &user("alice"))
        .unwrap_err();
    assert!(
        matches!(err, CoreError::MissingSecret { ref key, .. } if key == "ss2022.psk"),
        "expected MissingSecret(ss2022.psk), got {err:?}"
    );
}

#[test]
fn ss_share_link_format_scheme_host_port_and_required_slash() {
    let s = srv();
    let secrets = secrets_with_psk();
    let ctx = ctx_with(&s, &secrets);
    let link = Shadowsocks2022::new()
        .share_link(&ctx, &user("alice"))
        .unwrap();

    assert!(
        link.starts_with("ss://"),
        "must start with ss:// scheme; got {link}"
    );
    assert!(
        link.contains("@203.0.113.7:8388"),
        "must contain @<host>:<port>; got {link}"
    );
    assert!(
        link.contains("203.0.113.7:8388/#"),
        "SIP002 requires `/` between port and `#`; got {link}"
    );
    assert!(link.contains('#'), "must contain a fragment; got {link}");
}

#[test]
fn ss_share_link_userinfo_is_plain_method_colon_password_not_base64() {
    let s = srv();
    let secrets = secrets_with_psk();
    let ctx = ctx_with(&s, &secrets);
    let link = Shadowsocks2022::new()
        .share_link(&ctx, &user("alice"))
        .unwrap();

    let after_scheme = link.strip_prefix("ss://").expect("ss://");
    let at_idx = after_scheme.rfind('@').expect("'@' between userinfo+host");
    let userinfo = &after_scheme[..at_idx];

    let (method_part, pw_part) = userinfo
        .split_once(':')
        .expect("userinfo must be method:password (literal ':')");
    assert_eq!(
        method_part, "2022-blake3-aes-128-gcm",
        "method must be the plain default; userinfo={userinfo}"
    );
    assert_eq!(
        pw_part, PSK,
        "PSK must appear verbatim in userinfo (no base64); userinfo={userinfo}"
    );
}

#[test]
fn ss_share_link_base64_slashes_are_percent_encoded() {
    let s = srv();
    let mut secrets = secrets_with_psk();
    secrets.insert("ss2022.psk".into(), B64.encode([255_u8; 16]));
    let ctx = ctx_with(&s, &secrets);
    let link = Shadowsocks2022::new()
        .share_link(&ctx, &user("alice"))
        .unwrap();
    assert_eq!(
        link,
        "ss://2022-blake3-aes-128-gcm:%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2Fw==@203.0.113.7:8388/#alice"
    );
}

#[test]
fn ss_share_link_tag_is_user_id_percent_encoded() {
    let s = srv();
    let secrets = secrets_with_psk();
    let ctx = ctx_with(&s, &secrets);
    let link = Shadowsocks2022::new()
        .share_link(&ctx, &user("alice cool#1"))
        .unwrap();

    let frag_idx = link.find('#').expect("must have '#'");
    let fragment = &link[frag_idx + 1..];

    assert!(fragment.contains("%20"), "space → %20; got {fragment}");
    assert!(fragment.contains("%23"), "'#' → %23; got {fragment}");
    assert!(!fragment.contains(' '), "raw space leaked: {fragment}");
    assert!(!fragment.contains('#'), "raw '#' leaked: {fragment}");
}

#[test]
fn ss_secret_specs_match_method_key_length() {
    let protocol = Shadowsocks2022::new();
    for (method, bytes) in [
        ("2022-blake3-aes-128-gcm", 16),
        ("2022-blake3-aes-256-gcm", 32),
        ("2022-blake3-chacha20-poly1305", 32),
    ] {
        let secrets = HashMap::from([("ss2022.method".into(), method.into())]);
        assert_eq!(
            protocol.server_secret_specs_for(&secrets).unwrap(),
            vec![vpnctl_core::ServerSecretSpec::Base64Key {
                key: "ss2022.psk",
                key_bytes: bytes,
            }]
        );
    }
    assert_eq!(
        protocol.server_secret_specs_for(&HashMap::new()).unwrap(),
        protocol.server_secret_specs()
    );
}

#[test]
fn ss_wrong_length_or_invalid_base64_is_rejected_by_every_renderer() {
    let server = srv();
    let protocol = Shadowsocks2022::new();
    for (method, required, wrong) in [
        ("2022-blake3-aes-128-gcm", 16, 32),
        ("2022-blake3-aes-256-gcm", 32, 16),
        ("2022-blake3-chacha20-poly1305", 32, 16),
    ] {
        for psk in [B64.encode(vec![0_u8; wrong]), "invalid!".into()] {
            let secrets = HashMap::from([
                ("ss2022.method".into(), method.into()),
                ("ss2022.psk".into(), psk),
            ]);
            let ctx = ctx_with(&server, &secrets);
            let errors = [
                protocol.server_inbound(&ctx, &[]).unwrap_err(),
                protocol.client_config(&ctx, &user("alice")).unwrap_err(),
                protocol.share_link(&ctx, &user("alice")).unwrap_err(),
            ];
            for error in errors {
                let message = error.to_string();
                assert!(message.contains("ss2022.psk"));
                assert!(message.contains(&format!("{required} bytes")));
                assert!(message.contains(method));
                assert!(!message.contains("invalid!"));
            }
        }
    }
}

#[test]
fn ss_aes128_share_link_and_config_bytes_are_unchanged() {
    let server = srv();
    let secrets = secrets_with_psk();
    let ctx = ctx_with(&server, &secrets);
    let protocol = Shadowsocks2022::new();
    assert_eq!(
        protocol
            .share_link(&ctx, &user("alice"))
            .unwrap()
            .as_bytes(),
        b"ss://2022-blake3-aes-128-gcm:AAECAwQFBgcICQoLDA0ODw==@203.0.113.7:8388/#alice"
    );
    assert_eq!(
        serde_json::to_vec(&protocol.client_config(&ctx, &user("alice")).unwrap()).unwrap(),
        br#"{"method":"2022-blake3-aes-128-gcm","password":"AAECAwQFBgcICQoLDA0ODw==","server":"203.0.113.7","server_port":8388,"tag":"ss22-out","type":"shadowsocks"}"#
    );
}
