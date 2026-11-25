#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use vpnctl_core::{
    KernelId, Protocol, ProtocolId, RenderCtx, Server, ServerId, ServerSecretSpec, User, UserId,
};
use vpnctl_protocols::{
    TURNRELAY_DEFAULT_CONNECTIONS, TURNRELAY_DEFAULT_MODE, TURNRELAY_PORT, TurnRelay,
    is_valid_turnrelay_fingerprint, turnrelay_applied_digest,
};

const FINGERPRINT: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn server() -> Server {
    Server {
        id: ServerId("de".into()),
        address: "192.0.2.10".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("turnrelay".into())],
        enabled_protocols: vec![ProtocolId("turnrelay".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

fn user(disabled: bool) -> User {
    User {
        id: UserId("alice".into()),
        uuid: "11111111-1111-4111-8111-111111111111".into(),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled,
    }
}

fn base_secrets() -> HashMap<String, String> {
    let mut secrets = HashMap::new();
    secrets.insert(
        "turnrelay.turn_server".into(),
        "turn.example.org:3478".into(),
    );
    secrets.insert("turnrelay.turn_username".into(), "turn-user".into());
    secrets.insert("turnrelay.turn_password".into(), "turn-pass".into());
    secrets.insert("turnrelay.password".into(), "exit-secret".into());
    secrets
}

fn deployed(server: &Server, secrets: &mut HashMap<String, String>) {
    let digest = turnrelay_applied_digest(&RenderCtx::new(server, secrets)).unwrap();
    secrets.insert("observed.turnrelay.applied".into(), digest);
    secrets.insert("observed.turnrelay.cert_sha256".into(), FINGERPRINT.into());
}

fn deployed_secrets() -> HashMap<String, String> {
    let mut secrets = base_secrets();
    let server = server();
    deployed(&server, &mut secrets);
    secrets
}

#[test]
fn turnrelay_identity_ports_and_subscription_flags_are_locked() {
    let protocol = TurnRelay;
    assert_eq!(protocol.id(), ProtocolId("turnrelay".into()));
    assert_eq!(protocol.listen_ports(), &[("udp", 53492)]);
    assert_eq!(TURNRELAY_PORT, 53492);
    assert!(!protocol.appears_in_sing_box_sub());
    assert!(!protocol.appears_in_stock_sing_box_sub());
    assert_eq!(protocol.dpi_risk(), vpnctl_core::DpiRisk::Weak);
}

#[test]
fn turnrelay_declares_one_minted_exit_password() {
    assert_eq!(
        TurnRelay.server_secret_specs(),
        vec![ServerSecretSpec::Password {
            key: "turnrelay.password",
            entropy_bytes: 32,
        }]
    );
}

#[test]
fn server_inbound_defaults_match_the_locked_contract() {
    let server = server();
    let secrets = base_secrets();
    let inbound = TurnRelay
        .server_inbound(&RenderCtx::new(&server, &secrets), &[])
        .unwrap();
    assert_eq!(inbound["address"], "192.0.2.10");
    assert_eq!(inbound["listen_port"], 53492);
    assert_eq!(inbound["mode"], TURNRELAY_DEFAULT_MODE);
    assert_eq!(inbound["connections"], TURNRELAY_DEFAULT_CONNECTIONS);
    assert_eq!(inbound["udp"], true);
    assert_eq!(inbound["password"], "exit-secret");
    assert_eq!(
        inbound["applied"],
        turnrelay_applied_digest(&RenderCtx::new(&server, &secrets)).unwrap()
    );
}

#[test]
fn server_inbound_honors_every_override() {
    let server = server();
    let mut secrets = base_secrets();
    secrets.insert("turnrelay.listen_port".into(), "6000".into());
    secrets.insert("turnrelay.mode".into(), "srtp".into());
    secrets.insert("turnrelay.connections".into(), "9".into());
    secrets.insert("turnrelay.udp".into(), "false".into());
    let inbound = TurnRelay
        .server_inbound(&RenderCtx::new(&server, &secrets), &[])
        .unwrap();
    assert_eq!(inbound["listen_port"], 6000);
    assert_eq!(inbound["mode"], "srtp");
    assert_eq!(inbound["connections"], 9);
    assert_eq!(inbound["udp"], false);
}

#[test]
fn missing_required_secrets_are_missing_secret_errors() {
    let server = server();
    for key in [
        "turnrelay.turn_server",
        "turnrelay.turn_username",
        "turnrelay.turn_password",
        "turnrelay.password",
    ] {
        let mut secrets = base_secrets();
        secrets.remove(key);
        let error = TurnRelay
            .server_inbound(&RenderCtx::new(&server, &secrets), &[])
            .unwrap_err();
        assert!(
            matches!(error, vpnctl_core::CoreError::MissingSecret { .. }),
            "{key}: {error}"
        );
        assert!(error.to_string().contains(key), "{key}: {error}");
    }
}

#[test]
fn invalid_overrides_are_render_errors() {
    let server = server();
    for (key, value) in [
        ("turnrelay.listen_port", "0"),
        ("turnrelay.listen_port", "65536"),
        ("turnrelay.listen_port", "junk"),
        ("turnrelay.mode", "wrap"),
        ("turnrelay.connections", "0"),
        ("turnrelay.connections", "61"),
        ("turnrelay.connections", "x"),
        ("turnrelay.udp", "maybe"),
        ("turnrelay.turn_server", "turn.example.org"),
        ("turnrelay.turn_server", "turn.example.org:0"),
        ("turnrelay.turn_server", "[::1]"),
        ("turnrelay.turn_server", "::1:3478"),
        ("turnrelay.turn_username", ""),
        ("turnrelay.turn_password", ""),
    ] {
        let mut secrets = base_secrets();
        secrets.insert(key.into(), value.into());
        assert!(
            TurnRelay
                .server_inbound(&RenderCtx::new(&server, &secrets), &[])
                .is_err(),
            "{key}={value}"
        );
    }
}

#[test]
fn node_address_must_be_a_literal_ip_and_must_not_collide_with_ssh() {
    for address in ["de.example.com", "0.0.0.0", "::"] {
        let mut server = server();
        server.address = address.into();
        let secrets = base_secrets();
        assert!(
            TurnRelay
                .validate_server(&RenderCtx::new(&server, &secrets))
                .is_err(),
            "{address}"
        );
    }
    let mut server = server();
    server.ssh_port = 53492;
    let secrets = base_secrets();
    assert!(
        TurnRelay
            .validate_server(&RenderCtx::new(&server, &secrets))
            .is_err()
    );
}

#[test]
fn effective_listen_ports_track_override_and_fall_back_on_garbage() {
    let protocol = TurnRelay;
    assert_eq!(
        protocol.effective_listen_ports(&base_secrets()),
        vec![("udp", 53492)]
    );
    let mut secrets = base_secrets();
    secrets.insert("turnrelay.listen_port".into(), "6000".into());
    assert_eq!(
        protocol.effective_listen_ports(&secrets),
        vec![("udp", 6000)]
    );
    for bad in ["0", "", "junk", "65536"] {
        let mut secrets = base_secrets();
        secrets.insert("turnrelay.listen_port".into(), bad.into());
        assert_eq!(
            protocol.effective_listen_ports(&secrets),
            vec![("udp", 53492)],
            "{bad}"
        );
    }
}

#[test]
fn client_config_matches_the_locked_v1_profile() {
    let server = server();
    let secrets = deployed_secrets();
    let value = TurnRelay
        .client_config(&RenderCtx::new(&server, &secrets), &user(false))
        .unwrap();
    assert_eq!(
        value,
        serde_json::json!({
            "id": "turnrelay-de",
            "provider": "static",
            "server_type": "exit",
            "server": "192.0.2.10",
            "server_port": 53492,
            "turn_server": "turn.example.org:3478",
            "turn_username": "turn-user",
            "turn_password": "turn-pass",
            "password": "exit-secret",
            "server_fingerprint": FINGERPRINT,
            "connections": 2,
            "mode": "dtls",
            "udp": true,
        })
    );
}

#[test]
fn client_config_honors_overrides() {
    let server = server();
    let mut secrets = deployed_secrets();
    secrets.insert("turnrelay.listen_port".into(), "6000".into());
    secrets.insert("turnrelay.mode".into(), "srtp".into());
    secrets.insert("turnrelay.connections".into(), "7".into());
    secrets.insert("turnrelay.udp".into(), "false".into());
    deployed(&server, &mut secrets);
    let value = TurnRelay
        .client_config(&RenderCtx::new(&server, &secrets), &user(false))
        .unwrap();
    assert_eq!(value["server_port"], 6000);
    assert_eq!(value["mode"], "srtp");
    assert_eq!(value["connections"], 7);
    assert_eq!(value["udp"], false);
}

#[test]
fn client_config_is_unavailable_before_deploy_or_after_rotation() {
    let server = server();

    let mut undeployed = base_secrets();
    assert!(
        TurnRelay
            .client_config(&RenderCtx::new(&server, &undeployed), &user(false))
            .is_err()
    );

    undeployed = deployed_secrets();
    undeployed.remove("observed.turnrelay.cert_sha256");
    assert!(
        TurnRelay
            .client_config(&RenderCtx::new(&server, &undeployed), &user(false))
            .is_err()
    );

    let mut rotated = deployed_secrets();
    rotated.insert("turnrelay.password".into(), "rotated-exit".into());
    assert!(
        TurnRelay
            .client_config(&RenderCtx::new(&server, &rotated), &user(false))
            .is_err(),
        "a rotated exit password must invalidate the profile until redeploy"
    );

    let mut changed_turn = deployed_secrets();
    changed_turn.insert(
        "turnrelay.turn_server".into(),
        "other.example.org:3478".into(),
    );
    assert!(
        TurnRelay
            .client_config(&RenderCtx::new(&server, &changed_turn), &user(false))
            .is_err()
    );

    let mut disabled = deployed_secrets();
    disabled.insert("turnrelay.udp".into(), "false".into());
    assert!(
        TurnRelay
            .client_config(&RenderCtx::new(&server, &disabled), &user(false))
            .is_err()
    );
}

#[test]
fn fingerprint_shape_is_strict_lowercase_hex() {
    assert!(is_valid_turnrelay_fingerprint(FINGERPRINT));
    for bad in [
        FINGERPRINT.to_ascii_uppercase(),
        FINGERPRINT[..62].to_string(),
        "g".repeat(64),
        String::new(),
    ] {
        assert!(!is_valid_turnrelay_fingerprint(&bad), "{bad:?}");
        let server = server();
        let mut secrets = deployed_secrets();
        secrets.insert("observed.turnrelay.cert_sha256".into(), bad);
        assert!(
            TurnRelay
                .client_config(&RenderCtx::new(&server, &secrets), &user(false))
                .is_err()
        );
    }
}

#[test]
fn disabled_users_are_rejected() {
    let server = server();
    let secrets = deployed_secrets();
    assert!(
        TurnRelay
            .client_config(&RenderCtx::new(&server, &secrets), &user(true))
            .is_err()
    );
    assert!(
        TurnRelay
            .share_link(&RenderCtx::new(&server, &secrets), &user(true))
            .is_err()
    );
}

#[test]
fn share_link_is_url_safe_json_and_byte_stable() {
    let server = server();
    let secrets = deployed_secrets();
    let first = TurnRelay
        .share_link(&RenderCtx::new(&server, &secrets), &user(false))
        .unwrap();
    let second = TurnRelay
        .share_link(&RenderCtx::new(&server, &secrets), &user(false))
        .unwrap();
    assert_eq!(first, second);
    let rest = first.strip_prefix("turnrelay://").unwrap();
    let (payload, fragment) = rest.split_once('#').unwrap();
    assert_eq!(fragment, "de%20TurnRelay%20~alice");
    let profile: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
    assert_eq!(profile["id"], "turnrelay-de");
    assert_eq!(profile["server_fingerprint"], FINGERPRINT);
}

#[test]
fn no_base64_padding_or_plus_characters_leak_into_the_payload() {
    let server = server();
    let secrets = deployed_secrets();
    let link = TurnRelay
        .share_link(&RenderCtx::new(&server, &secrets), &user(false))
        .unwrap();
    let payload = link
        .strip_prefix("turnrelay://")
        .unwrap()
        .split_once('#')
        .unwrap()
        .0;
    assert!(!payload.contains('='));
    assert!(!payload.contains('+'));
    assert!(!payload.contains('/'));
}
