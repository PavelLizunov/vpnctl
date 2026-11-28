#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;

use serde_json::{Value, json};
use vpnctl_core::{KernelId, Protocol, ProtocolId, RenderCtx, Server, ServerId, User, UserId};
use vpnctl_protocols::Mieru;

const ALICE_UUID: &str = "69fcc06e-70c5-4f78-9dec-38d5636b4115";
const BOB_UUID: &str = "a2568ff8-d30c-4513-ab96-781667ea15a2";

fn srv() -> Server {
    Server {
        id: ServerId("node-1".into()),
        address: "203.0.113.7".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("mieru".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

fn user(id: &str, uuid: &str) -> User {
    User {
        id: UserId(id.into()),
        uuid: uuid.into(),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    }
}

fn disabled_user(id: &str, uuid: &str) -> User {
    let mut out = user(id, uuid);
    out.disabled = true;
    out
}

fn alice() -> User {
    user("alice", ALICE_UUID)
}

fn secrets(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
        .collect()
}

fn inbound(server: &Server, settings: &HashMap<String, String>, users: &[User]) -> Value {
    let ctx = RenderCtx::new(server, settings);
    Mieru
        .server_inbound(&ctx, users)
        .expect("Mieru inbound must render")
}

fn client(server: &Server, settings: &HashMap<String, String>, user: &User) -> Value {
    let ctx = RenderCtx::new(server, settings);
    Mieru
        .client_config(&ctx, user)
        .expect("Mieru outbound must render")
}

fn link(server: &Server, settings: &HashMap<String, String>, user: &User) -> String {
    let ctx = RenderCtx::new(server, settings);
    Mieru
        .share_link(&ctx, user)
        .expect("Mieru share link must render")
}

fn usernames(value: &Value) -> Vec<&str> {
    value
        .get("users")
        .and_then(Value::as_array)
        .expect("users must be an array")
        .iter()
        .map(|user| {
            user.get("username")
                .and_then(Value::as_str)
                .expect("user must have a username")
        })
        .collect()
}

#[test]
fn mi1_id_and_default_listener_are_tcp_8445() {
    let protocol = Mieru;
    assert_eq!(protocol.id(), ProtocolId("mieru".into()));
    assert_eq!(protocol.listen_ports(), &[("tcp", 8445)]);
    assert_eq!(
        protocol.effective_listen_ports(&HashMap::new()),
        vec![("tcp", 8445)]
    );
    assert!(
        !protocol.appears_in_sing_box_sub(),
        "legacy sing-box subscriptions must exclude Mieru"
    );
    assert!(
        !protocol.appears_in_stock_sing_box_sub(),
        "stock sing-box cannot render Mieru"
    );
}

#[test]
fn mi2_inbound_defaults_match_the_server_contract() {
    let server = srv();
    let settings = HashMap::new();
    let value = inbound(&server, &settings, &[alice(), user("bob", BOB_UUID)]);

    assert_eq!(value.get("type").and_then(Value::as_str), Some("mieru"));
    assert_eq!(value.get("tag").and_then(Value::as_str), Some("mieru-in"));
    assert_eq!(value.get("listen").and_then(Value::as_str), Some("::"));
    assert_eq!(value.get("listen_port").and_then(Value::as_u64), Some(8445));
    assert_eq!(value.get("transport").and_then(Value::as_str), Some("tcp"));
    assert_eq!(
        value.get("users"),
        Some(&json!([
            {"username": "alice", "password": ALICE_UUID},
            {"username": "bob", "password": BOB_UUID},
        ]))
    );
}

#[test]
fn mi2_inbound_honors_udp_transport_and_port() {
    let server = srv();
    let settings = secrets(&[("mieru.listen_port", "9445"), ("mieru.transport", "udp")]);
    let value = inbound(&server, &settings, &[alice()]);

    assert_eq!(value.get("listen_port").and_then(Value::as_u64), Some(9445));
    assert_eq!(value.get("transport").and_then(Value::as_str), Some("udp"));
    assert_eq!(Mieru.effective_listen_ports(&settings), vec![("udp", 9445)]);
}

#[test]
fn mi2_inbound_drops_disabled_invalid_empty_and_duplicate_users_but_keeps_colons() {
    let server = srv();
    let settings = HashMap::new();
    let users = [
        disabled_user("disabled", BOB_UUID),
        user("bad-uuid", "not-a-uuid"),
        user("", ALICE_UUID),
        user("alice:ops", BOB_UUID),
        alice(),
        user("alice", BOB_UUID),
        user("bob", BOB_UUID),
    ];
    let value = inbound(&server, &settings, &users);

    assert_eq!(usernames(&value), vec!["alice:ops", "alice", "bob"]);
    let rendered = value
        .get("users")
        .and_then(Value::as_array)
        .expect("users must be an array");
    assert_eq!(rendered.len(), 3);
    assert_eq!(
        rendered[0].get("password").and_then(Value::as_str),
        Some(BOB_UUID),
        "a colon is legal in a Mieru username"
    );
    assert_eq!(
        rendered[1].get("password").and_then(Value::as_str),
        Some(ALICE_UUID),
        "the first user with a duplicated name wins"
    );
}

#[test]
fn mi3_outbound_defaults_include_transport_multiplexing_and_handshake() {
    let server = srv();
    let settings = HashMap::new();
    let value = client(&server, &settings, &alice());

    assert_eq!(value.get("type").and_then(Value::as_str), Some("mieru"));
    assert_eq!(value.get("tag").and_then(Value::as_str), Some("mieru-out"));
    assert_eq!(
        value.get("server").and_then(Value::as_str),
        Some("203.0.113.7")
    );
    assert_eq!(value.get("server_port").and_then(Value::as_u64), Some(8445));
    assert_eq!(value.get("transport").and_then(Value::as_str), Some("tcp"));
    assert_eq!(value.get("username").and_then(Value::as_str), Some("alice"));
    assert_eq!(
        value.get("password").and_then(Value::as_str),
        Some(ALICE_UUID)
    );
    assert_eq!(
        value.get("multiplexing").and_then(Value::as_str),
        Some("middle")
    );
    assert_eq!(
        value.get("handshake_mode").and_then(Value::as_str),
        Some("standard")
    );
}

#[test]
fn mi3_outbound_honors_all_settings() {
    let server = srv();
    let settings = secrets(&[
        ("mieru.listen_port", "9445"),
        ("mieru.transport", "udp"),
        ("mieru.multiplexing", "high"),
        ("mieru.handshake_mode", "no_wait"),
    ]);
    let value = client(&server, &settings, &alice());

    assert_eq!(value.get("server_port").and_then(Value::as_u64), Some(9445));
    assert_eq!(value.get("transport").and_then(Value::as_str), Some("udp"));
    assert_eq!(
        value.get("multiplexing").and_then(Value::as_str),
        Some("high")
    );
    assert_eq!(
        value.get("handshake_mode").and_then(Value::as_str),
        Some("no_wait")
    );
}

#[test]
fn mi3_multiplexing_and_handshake_accept_only_documented_values() {
    let server = srv();

    for value in ["default", "off", "low", "middle", "high"] {
        let settings = secrets(&[("mieru.multiplexing", value)]);
        let rendered = client(&server, &settings, &alice());
        assert_eq!(
            rendered.get("multiplexing").and_then(Value::as_str),
            Some(value),
            "multiplexing={value:?} must be preserved"
        );
    }

    for value in ["default", "standard", "no_wait"] {
        let settings = secrets(&[("mieru.handshake_mode", value)]);
        let rendered = client(&server, &settings, &alice());
        assert_eq!(
            rendered.get("handshake_mode").and_then(Value::as_str),
            Some(value),
            "handshake_mode={value:?} must be preserved"
        );
    }

    for bad in ["bogus", "LOW", "medium", "max"] {
        let settings = secrets(&[("mieru.multiplexing", bad)]);
        let ctx = RenderCtx::new(&server, &settings);
        assert!(
            Mieru.client_config(&ctx, &alice()).is_err(),
            "multiplexing={bad:?} must be rejected"
        );
    }

    for bad in ["bogus", "STANDARD", "no-wait"] {
        let settings = secrets(&[("mieru.handshake_mode", bad)]);
        let ctx = RenderCtx::new(&server, &settings);
        assert!(
            Mieru.client_config(&ctx, &alice()).is_err(),
            "handshake_mode={bad:?} must be rejected"
        );
    }
}

#[test]
fn mi5_transport_and_port_are_strictly_validated() {
    let server = srv();

    for bad in ["sctp", "quic", ""] {
        let settings = secrets(&[("mieru.transport", bad)]);
        let ctx = RenderCtx::new(&server, &settings);
        assert!(
            Mieru.server_inbound(&ctx, &[alice()]).is_err(),
            "transport={bad:?} must be rejected"
        );
        assert!(
            Mieru.client_config(&ctx, &alice()).is_err(),
            "transport={bad:?} must be rejected"
        );
    }

    for bad in ["0", "65536", "-1", "abc", ""] {
        let settings = secrets(&[("mieru.listen_port", bad)]);
        let ctx = RenderCtx::new(&server, &settings);
        assert!(
            Mieru.server_inbound(&ctx, &[alice()]).is_err(),
            "listen_port={bad:?} must be rejected"
        );
        assert!(
            Mieru.client_config(&ctx, &alice()).is_err(),
            "listen_port={bad:?} must be rejected"
        );
        assert!(
            Mieru.share_link(&ctx, &alice()).is_err(),
            "listen_port={bad:?} must be rejected"
        );
    }

    for good in ["1", "65535"] {
        let settings = secrets(&[("mieru.listen_port", good)]);
        let port: u64 = good.parse().expect("test port must parse");
        let server_value = inbound(&server, &settings, &[alice()]);
        assert_eq!(
            server_value.get("listen_port").and_then(Value::as_u64),
            Some(port)
        );
        let client_value = client(&server, &settings, &alice());
        assert_eq!(
            client_value.get("server_port").and_then(Value::as_u64),
            Some(port)
        );
    }
}

#[test]
fn mi4_share_link_default_is_exact() {
    let server = srv();
    let settings = HashMap::new();
    let link = link(&server, &settings, &alice());

    assert_eq!(
        link,
        format!(
            "mieru://alice:{ALICE_UUID}@203.0.113.7:8445?transport=tcp&multiplexing=middle&handshake=standard#alice"
        )
    );
}

#[test]
fn mi4_share_link_reflects_options_and_percent_encodes_userinfo() {
    let server = srv();
    let settings = secrets(&[
        ("mieru.listen_port", "9445"),
        ("mieru.transport", "udp"),
        ("mieru.multiplexing", "off"),
        ("mieru.handshake_mode", "no_wait"),
    ]);
    let user = user("alice:ops", ALICE_UUID);
    let link = link(&server, &settings, &user);

    assert!(
        link.starts_with(&format!(
            "mieru://alice%3Aops:{ALICE_UUID}@203.0.113.7:9445?transport=udp&multiplexing=off&handshake=no_wait#"
        )),
        "colon in the username must be percent-encoded and options must be reflected; got {link}"
    );
    assert!(
        link.ends_with("#alice%3Aops") || link.ends_with("#alice:ops"),
        "the label must identify the user; got {link}"
    );
    assert!(
        !link.contains("alice:ops@"),
        "raw colon leaked into userinfo: {link}"
    );
}

#[test]
fn mi4_share_link_percent_encodes_a_space_in_the_label() {
    let server = srv();
    let settings = HashMap::new();
    let user = user("alice ops", ALICE_UUID);
    let link = link(&server, &settings, &user);

    assert!(
        link.starts_with(&format!(
            "mieru://alice%20ops:{ALICE_UUID}@203.0.113.7:8445?"
        )),
        "space in the username must be percent-encoded; got {link}"
    );
    assert!(
        link.ends_with("#alice%20ops"),
        "space in the label must be percent-encoded; got {link}"
    );
    assert!(!link.contains("alice ops"), "raw username leaked: {link}");
}

#[test]
fn mi6_ipv6_share_link_authority_is_bracketed() {
    let mut server = srv();
    server.address = "2a00:1450::1".into();
    let settings = HashMap::new();
    let link = link(&server, &settings, &alice());

    assert!(
        link.contains("@[2a00:1450::1]:8445?"),
        "IPv6 authority must be bracketed; got {link}"
    );
    let value = client(&server, &settings, &alice());
    assert_eq!(
        value.get("server").and_then(Value::as_str),
        Some("2a00:1450::1"),
        "the native outbound uses the bare address"
    );
}
