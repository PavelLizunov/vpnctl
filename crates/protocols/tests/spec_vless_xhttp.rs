#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Spec tests for `vpnctl_protocols::VlessXhttp` (VLESS over Xray-core's
//! `xhttp` transport + REALITY, sharing the sibling `vless+reality`
//! protocol's keypair via `RenderCtx::secrets`). Written from the spec
//! only — no flow key anywhere is the single most safety-critical
//! contract here (xhttp framing is incompatible with XTLS-Vision at the
//! wire level). If a test fails, the impl is wrong — DO NOT weaken it.

use std::collections::HashMap;

use vpnctl_core::{
    CoreError, DpiRisk, KernelId, Protocol, ProtocolId, RenderCtx, Server, ServerId,
    ServerSecretSpec, User, UserId,
};
use vpnctl_protocols::{VLESS_XHTTP_PORT, VlessXhttp};

const PRIVATE_KEY: &str = "priv-key-abc123";
const PUBLIC_KEY: &str = "pub-key-xyz789";
const SHORT_ID: &str = "deadbeef";
const PATH_SECRET: &str = "Zq9_path-OK";

fn srv() -> Server {
    Server {
        id: ServerId("xhttp-node-1".into()),
        address: "203.0.113.42".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("xray".into())],
        enabled_protocols: vec![ProtocolId("vless+xhttp".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

fn user(name: &str) -> User {
    User {
        id: UserId(name.into()),
        uuid: format!("uuid-{name}"),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    }
}

/// Full happy-path secret set. Callers mutate / remove entries to
/// exercise failure + boundary branches.
fn secrets() -> HashMap<String, String> {
    let mut s = HashMap::new();
    s.insert("vless.private_key".into(), PRIVATE_KEY.into());
    s.insert("vless.public_key".into(), PUBLIC_KEY.into());
    s.insert("vless.short_id".into(), SHORT_ID.into());
    s.insert("vlessxhttp.path".into(), PATH_SECRET.into());
    s
}

fn missing_secret_key(err: &CoreError) -> Option<&str> {
    match err {
        CoreError::MissingSecret { key, .. } => Some(key.as_str()),
        _ => None,
    }
}

// ── trait-surface constants ─────────────────────────────────────────

#[test]
fn id_is_vless_plus_xhttp() {
    assert_eq!(VlessXhttp::new().id(), ProtocolId("vless+xhttp".into()));
}

#[test]
fn listen_ports_is_tcp_9443() {
    assert_eq!(VlessXhttp::new().listen_ports(), &[("tcp", 9443)]);
}

#[test]
fn port_constant_is_9443() {
    assert_eq!(VLESS_XHTTP_PORT, 9443);
}

#[test]
fn dpi_risk_is_strong() {
    assert_eq!(VlessXhttp::new().dpi_risk(), DpiRisk::Strong);
}

#[test]
fn server_secret_specs_is_exactly_vlessxhttp_path_password_and_nothing_vless_namespaced() {
    let specs = VlessXhttp::new().server_secret_specs();
    assert_eq!(
        specs,
        vec![ServerSecretSpec::Password {
            key: "vlessxhttp.path",
            entropy_bytes: 16,
        }]
    );
    // Regression guard: this protocol must NOT mint its own copy of the
    // REALITY keypair / short_id — it reuses the sibling `vless+reality`
    // protocol's secrets by reading them from RenderCtx, never declaring
    // them here.
    for spec in &specs {
        let key = match spec {
            ServerSecretSpec::Password { key, .. } => *key,
            ServerSecretSpec::Base64Key { key, .. } => *key,
            ServerSecretSpec::X25519Keypair {
                private_key,
                public_key,
            } => {
                assert!(
                    !private_key.starts_with("vless."),
                    "must not mint its own vless.* keypair: {private_key}"
                );
                assert!(
                    !public_key.starts_with("vless."),
                    "must not mint its own vless.* keypair: {public_key}"
                );
                continue;
            }
            ServerSecretSpec::WireguardKeypair { .. } => continue,
            ServerSecretSpec::ShortId { key } => *key,
        };
        assert!(
            !key.starts_with("vless."),
            "server_secret_specs must not declare a vless.*-namespaced key, got {key}"
        );
    }
}

// ── server_inbound (Xray-core wire schema) ──────────────────────────

#[test]
fn server_inbound_happy_path_full_shape() {
    let s = srv();
    let sec = secrets();
    let ctx = RenderCtx::new(&s, &sec);
    let v = VlessXhttp::new()
        .server_inbound(&ctx, &[user("alice"), user("bob")])
        .unwrap();

    assert_eq!(v["listen"].as_str(), Some("0.0.0.0"));
    assert_eq!(v["port"].as_u64(), Some(9443));
    assert_eq!(v["protocol"].as_str(), Some("vless"));

    let clients = v["settings"]["clients"]
        .as_array()
        .expect("clients must be an array");
    assert_eq!(clients.len(), 2);
    assert_eq!(clients[0]["id"].as_str(), Some("uuid-alice"));
    assert_eq!(clients[0]["email"].as_str(), Some("alice"));
    assert_eq!(clients[1]["id"].as_str(), Some("uuid-bob"));
    assert_eq!(clients[1]["email"].as_str(), Some("bob"));
    assert_eq!(v["settings"]["decryption"].as_str(), Some("none"));

    assert_eq!(v["streamSettings"]["network"].as_str(), Some("xhttp"));
    assert_eq!(v["streamSettings"]["security"].as_str(), Some("reality"));
    assert_eq!(
        v["streamSettings"]["xhttpSettings"]["path"].as_str(),
        Some(&*format!("/{PATH_SECRET}/"))
    );
    assert_eq!(
        v["streamSettings"]["xhttpSettings"]["mode"].as_str(),
        Some("auto")
    );

    let reality = &v["streamSettings"]["realitySettings"];
    assert_eq!(reality["dest"].as_str(), Some("yahoo.com:443"));
    assert_eq!(
        reality["serverNames"].as_array().unwrap().as_slice(),
        &[serde_json::Value::String("yahoo.com".into())]
    );
    assert_eq!(reality["privateKey"].as_str(), Some(PRIVATE_KEY));
    assert_eq!(
        reality["shortIds"].as_array().unwrap().as_slice(),
        &[serde_json::Value::String(SHORT_ID.into())]
    );
}

#[test]
fn server_inbound_zero_users_yields_empty_clients_array_not_null_or_error() {
    let s = srv();
    let sec = secrets();
    let ctx = RenderCtx::new(&s, &sec);
    let v = VlessXhttp::new().server_inbound(&ctx, &[]).unwrap();
    let clients = v["settings"]["clients"]
        .as_array()
        .expect("clients must still be an array with zero users");
    assert!(clients.is_empty());
}

#[test]
fn server_inbound_missing_private_key_is_missing_secret_error() {
    let s = srv();
    let mut sec = secrets();
    sec.remove("vless.private_key");
    let ctx = RenderCtx::new(&s, &sec);
    let err = VlessXhttp::new().server_inbound(&ctx, &[]).unwrap_err();
    assert_eq!(missing_secret_key(&err), Some("vless.private_key"));
}

#[test]
fn server_inbound_missing_short_id_is_missing_secret_error() {
    let s = srv();
    let mut sec = secrets();
    sec.remove("vless.short_id");
    let ctx = RenderCtx::new(&s, &sec);
    let err = VlessXhttp::new().server_inbound(&ctx, &[]).unwrap_err();
    assert_eq!(missing_secret_key(&err), Some("vless.short_id"));
}

#[test]
fn server_inbound_missing_path_secret_is_missing_secret_error() {
    let s = srv();
    let mut sec = secrets();
    sec.remove("vlessxhttp.path");
    let ctx = RenderCtx::new(&s, &sec);
    let err = VlessXhttp::new().server_inbound(&ctx, &[]).unwrap_err();
    assert_eq!(missing_secret_key(&err), Some("vlessxhttp.path"));
}

#[test]
fn server_inbound_path_secret_empty_or_illegal_char_is_render_error_not_panic() {
    for bad in ["", "has space", "has/slash", "has?question", "has#hash"] {
        let s = srv();
        let mut sec = secrets();
        sec.insert("vlessxhttp.path".into(), bad.into());
        let ctx = RenderCtx::new(&s, &sec);
        let err = VlessXhttp::new().server_inbound(&ctx, &[]).unwrap_err();
        assert!(
            matches!(err, CoreError::Render(_)),
            "path {bad:?} must reject with Render, got {err:?}"
        );
    }
}

#[test]
fn server_inbound_sni_and_mode_default_when_absent() {
    let s = srv();
    let mut sec = secrets();
    sec.remove("vless.sni");
    sec.remove("vlessxhttp.mode");
    let ctx = RenderCtx::new(&s, &sec);
    let v = VlessXhttp::new().server_inbound(&ctx, &[]).unwrap();
    assert_eq!(
        v["streamSettings"]["realitySettings"]["dest"].as_str(),
        Some("yahoo.com:443")
    );
    assert_eq!(
        v["streamSettings"]["realitySettings"]["serverNames"][0].as_str(),
        Some("yahoo.com")
    );
    assert_eq!(
        v["streamSettings"]["xhttpSettings"]["mode"].as_str(),
        Some("auto")
    );
}

#[test]
fn server_inbound_sni_and_mode_overridden_by_secrets() {
    let s = srv();
    let mut sec = secrets();
    sec.insert("vless.sni".into(), "cover.example.net".into());
    sec.insert("vlessxhttp.mode".into(), "stream-one".into());
    let ctx = RenderCtx::new(&s, &sec);
    let v = VlessXhttp::new().server_inbound(&ctx, &[]).unwrap();
    assert_eq!(
        v["streamSettings"]["realitySettings"]["dest"].as_str(),
        Some("cover.example.net:443")
    );
    assert_eq!(
        v["streamSettings"]["realitySettings"]["serverNames"][0].as_str(),
        Some("cover.example.net")
    );
    assert_eq!(
        v["streamSettings"]["xhttpSettings"]["mode"].as_str(),
        Some("stream-one")
    );
}

#[test]
fn server_inbound_never_contains_a_flow_key_anywhere() {
    let s = srv();
    let sec = secrets();
    let ctx = RenderCtx::new(&s, &sec);
    let v = VlessXhttp::new()
        .server_inbound(&ctx, &[user("alice"), user("bob")])
        .unwrap();
    let dumped = serde_json::to_string(&v).unwrap();
    assert!(
        !dumped.contains("\"flow\""),
        "server_inbound must never carry a flow key (xhttp is Vision-incompatible): {dumped}"
    );
    // Also walk each per-client object explicitly — a top-level string
    // search could in principle miss a key whose value happens to look
    // like the literal text `"flow"` while the key itself differs, so
    // this is a belt-and-braces structural check too.
    for client in v["settings"]["clients"].as_array().unwrap() {
        assert!(
            client.get("flow").is_none(),
            "client entry must not carry a flow key: {client}"
        );
    }
}

// ── client_config (sing-box-style outbound) ─────────────────────────

#[test]
fn client_config_happy_path_full_shape() {
    let s = srv();
    let sec = secrets();
    let ctx = RenderCtx::new(&s, &sec);
    let v = VlessXhttp::new()
        .client_config(&ctx, &user("alice"))
        .unwrap();

    assert_eq!(v["type"].as_str(), Some("vless"));
    assert_eq!(v["tag"].as_str(), Some("vless-xhttp-out"));
    assert_eq!(v["server"].as_str(), Some("203.0.113.42"));
    assert_eq!(v["server_port"].as_u64(), Some(9443));
    assert_eq!(v["uuid"].as_str(), Some("uuid-alice"));

    assert_eq!(v["tls"]["enabled"].as_bool(), Some(true));
    assert_eq!(v["tls"]["server_name"].as_str(), Some("yahoo.com"));
    assert_eq!(v["tls"]["utls"]["enabled"].as_bool(), Some(true));
    assert_eq!(v["tls"]["utls"]["fingerprint"].as_str(), Some("randomized"));
    assert_eq!(v["tls"]["reality"]["enabled"].as_bool(), Some(true));
    assert_eq!(v["tls"]["reality"]["public_key"].as_str(), Some(PUBLIC_KEY));
    assert_eq!(v["tls"]["reality"]["short_id"].as_str(), Some(SHORT_ID));

    assert_eq!(v["transport"]["type"].as_str(), Some("xhttp"));
    assert_eq!(
        v["transport"]["path"].as_str(),
        Some(&*format!("/{PATH_SECRET}/"))
    );
    assert_eq!(v["transport"]["mode"].as_str(), Some("auto"));
}

#[test]
fn client_config_missing_public_key_is_missing_secret_error() {
    let s = srv();
    let mut sec = secrets();
    sec.remove("vless.public_key");
    let ctx = RenderCtx::new(&s, &sec);
    let err = VlessXhttp::new()
        .client_config(&ctx, &user("alice"))
        .unwrap_err();
    assert_eq!(missing_secret_key(&err), Some("vless.public_key"));
}

#[test]
fn client_config_missing_short_id_is_missing_secret_error() {
    let s = srv();
    let mut sec = secrets();
    sec.remove("vless.short_id");
    let ctx = RenderCtx::new(&s, &sec);
    let err = VlessXhttp::new()
        .client_config(&ctx, &user("alice"))
        .unwrap_err();
    assert_eq!(missing_secret_key(&err), Some("vless.short_id"));
}

#[test]
fn client_config_missing_path_secret_is_missing_secret_error() {
    let s = srv();
    let mut sec = secrets();
    sec.remove("vlessxhttp.path");
    let ctx = RenderCtx::new(&s, &sec);
    let err = VlessXhttp::new()
        .client_config(&ctx, &user("alice"))
        .unwrap_err();
    assert_eq!(missing_secret_key(&err), Some("vlessxhttp.path"));
}

#[test]
fn client_config_path_secret_empty_or_illegal_char_is_render_error() {
    for bad in ["", "bad path", "bad/path"] {
        let s = srv();
        let mut sec = secrets();
        sec.insert("vlessxhttp.path".into(), bad.into());
        let ctx = RenderCtx::new(&s, &sec);
        let err = VlessXhttp::new()
            .client_config(&ctx, &user("alice"))
            .unwrap_err();
        assert!(
            matches!(err, CoreError::Render(_)),
            "path {bad:?} must reject with Render, got {err:?}"
        );
    }
}

#[test]
fn client_config_never_contains_a_flow_key_at_top_level() {
    let s = srv();
    let sec = secrets();
    let ctx = RenderCtx::new(&s, &sec);
    let v = VlessXhttp::new()
        .client_config(&ctx, &user("alice"))
        .unwrap();
    assert!(
        v.get("flow").is_none(),
        "xhttp client_config must not carry a top-level flow key: {v}"
    );
    let dumped = serde_json::to_string(&v).unwrap();
    assert!(
        !dumped.contains("\"flow\""),
        "xhttp client_config must not carry a flow key anywhere: {dumped}"
    );
}

// ── share_link (byte-exact) ──────────────────────────────────────────

#[test]
fn share_link_happy_path_byte_exact() {
    let s = srv();
    let sec = secrets();
    let ctx = RenderCtx::new(&s, &sec);
    let link = VlessXhttp::new().share_link(&ctx, &user("alice")).unwrap();
    let expected = format!(
        "vless://uuid-alice@203.0.113.42:9443?encryption=none&security=reality&sni=yahoo.com\
         &fp=randomized&pbk={PUBLIC_KEY}&sid={SHORT_ID}&type=xhttp&path=%2F{PATH_SECRET}%2F&mode=auto#alice"
    );
    assert_eq!(link, expected);
}

#[test]
fn share_link_never_contains_flow_param() {
    let s = srv();
    let sec = secrets();
    let ctx = RenderCtx::new(&s, &sec);
    let link = VlessXhttp::new().share_link(&ctx, &user("alice")).unwrap();
    assert!(
        !link.contains("flow="),
        "vless+xhttp share_link must never carry flow= (Vision-incompatible): {link}"
    );
}

#[test]
fn share_link_byte_stable_across_repeated_calls() {
    let s = srv();
    let sec = secrets();
    let ctx = RenderCtx::new(&s, &sec);
    let u = user("alice");
    let p = VlessXhttp::new();
    let a = p.share_link(&ctx, &u).unwrap();
    let b = p.share_link(&ctx, &u).unwrap();
    assert_eq!(a, b, "share_link must be byte-stable across repeated calls");
}

#[test]
fn share_link_ipv6_address_gets_bracketed_authority() {
    let mut s = srv();
    s.address = "2a00:1450::1".into();
    let sec = secrets();
    let ctx = RenderCtx::new(&s, &sec);
    let link = VlessXhttp::new().share_link(&ctx, &user("alice")).unwrap();
    assert!(
        link.starts_with("vless://uuid-alice@[2a00:1450::1]:9443?"),
        "IPv6 host must be bracketed in the authority: {link}"
    );
}

#[test]
fn share_link_ipv4_address_is_not_bracketed() {
    let s = srv();
    let sec = secrets();
    let ctx = RenderCtx::new(&s, &sec);
    let link = VlessXhttp::new().share_link(&ctx, &user("alice")).unwrap();
    assert!(
        link.starts_with("vless://uuid-alice@203.0.113.42:9443?"),
        "IPv4 host must not be bracketed: {link}"
    );
}

#[test]
fn share_link_fragment_percent_encodes_space_in_user_id() {
    let s = srv();
    let sec = secrets();
    let ctx = RenderCtx::new(&s, &sec);
    let link = VlessXhttp::new()
        .share_link(&ctx, &user("alice smith"))
        .unwrap();
    assert!(
        link.ends_with("#alice%20smith"),
        "space in user id must be percent-encoded in the fragment: {link}"
    );
    assert!(
        !link.contains("#alice smith"),
        "raw space must not appear in the fragment: {link}"
    );
}

#[test]
fn share_link_sni_and_mode_default_when_absent() {
    let s = srv();
    let mut sec = secrets();
    sec.remove("vless.sni");
    sec.remove("vlessxhttp.mode");
    let ctx = RenderCtx::new(&s, &sec);
    let link = VlessXhttp::new().share_link(&ctx, &user("alice")).unwrap();
    assert!(link.contains("sni=yahoo.com"), "got {link}");
    assert!(link.contains("mode=auto"), "got {link}");
}

#[test]
fn share_link_sni_and_mode_overridden_by_secrets() {
    let s = srv();
    let mut sec = secrets();
    sec.insert("vless.sni".into(), "cover.example.net".into());
    sec.insert("vlessxhttp.mode".into(), "packet-up".into());
    let ctx = RenderCtx::new(&s, &sec);
    let link = VlessXhttp::new().share_link(&ctx, &user("alice")).unwrap();
    assert!(link.contains("sni=cover.example.net"), "got {link}");
    assert!(link.contains("mode=packet-up"), "got {link}");
}

#[test]
fn share_link_missing_public_key_is_missing_secret_error() {
    let s = srv();
    let mut sec = secrets();
    sec.remove("vless.public_key");
    let ctx = RenderCtx::new(&s, &sec);
    let err = VlessXhttp::new()
        .share_link(&ctx, &user("alice"))
        .unwrap_err();
    assert_eq!(missing_secret_key(&err), Some("vless.public_key"));
}

#[test]
fn share_link_missing_path_secret_is_missing_secret_error() {
    let s = srv();
    let mut sec = secrets();
    sec.remove("vlessxhttp.path");
    let ctx = RenderCtx::new(&s, &sec);
    let err = VlessXhttp::new()
        .share_link(&ctx, &user("alice"))
        .unwrap_err();
    assert_eq!(missing_secret_key(&err), Some("vlessxhttp.path"));
}
