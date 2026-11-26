#![allow(clippy::unwrap_used)]

use std::collections::HashMap;

use serde_json::json;
use vpnctl_core::{DpiRisk, Protocol, RenderCtx, Server, ServerId, ServerSecretSpec};
use vpnctl_protocols::TurnRelayRelay;

const USERNAME: &str = "turnrelay_relay.username";
const PASSWORD: &str = "turnrelay_relay.password";
const PORT: &str = "turnrelay_relay.listen_port";
const REALM: &str = "turnrelay_relay.realm";
const EXITS: &str = "turnrelay_relay.allowed_exits";

fn server(address: &str) -> Server {
    Server {
        id: ServerId("entry".into()),
        address: address.into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![],
        enabled_protocols: vec![],
        trusted_host_fingerprint: None,
        hoster: "fixture".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

fn credentials() -> HashMap<String, String> {
    HashMap::from([
        (USERNAME.into(), "fixture-turnrelay-user".into()),
        (PASSWORD.into(), "fixture-turnrelay-password".into()),
    ])
}

#[test]
fn relay_metadata_exposes_both_ports_and_only_minted_server_credentials() {
    let relay = TurnRelayRelay;
    assert_eq!(relay.id().0, "turnrelay-relay");
    assert_eq!(relay.dpi_risk(), DpiRisk::Strong);
    assert!(!relay.appears_in_sing_box_sub());
    assert!(!relay.appears_in_stock_sing_box_sub());
    assert_eq!(relay.listen_ports(), &[("tcp", 53491), ("udp", 53491)]);
    assert_eq!(
        relay.server_secret_specs(),
        [
            ServerSecretSpec::Password {
                key: USERNAME,
                entropy_bytes: 12
            },
            ServerSecretSpec::Password {
                key: PASSWORD,
                entropy_bytes: 24
            },
        ]
    );
}

#[test]
fn relay_inbound_defaults_to_an_empty_allowlist() {
    let server = server("203.0.113.10");
    let secrets = credentials();
    let ctx = RenderCtx::new(&server, &secrets);
    assert_eq!(
        TurnRelayRelay.server_inbound(&ctx, &[]).unwrap(),
        json!({
            "address": "203.0.113.10",
            "listen_port": 53491,
            "username": "fixture-turnrelay-user",
            "password": "fixture-turnrelay-password",
            "realm": "turnrelay",
            "allowed_exits": "",
        })
    );
}

#[test]
fn relay_inbound_applies_realm_allowlist_and_both_port_boundaries() {
    let server = server("203.0.113.10");
    let mut secrets = credentials();
    secrets.insert(REALM.into(), "fixture-realm".into());
    secrets.insert(EXITS.into(), "192.0.2.1,198.51.100.2".into());
    for port in [1u16, 65535] {
        secrets.insert(PORT.into(), port.to_string());
        let ctx = RenderCtx::new(&server, &secrets);
        let rendered = TurnRelayRelay.server_inbound(&ctx, &[]).unwrap();
        assert_eq!(rendered["listen_port"], port);
        assert_eq!(rendered["realm"], "fixture-realm");
        assert_eq!(rendered["allowed_exits"], "192.0.2.1,198.51.100.2");
        assert_eq!(
            TurnRelayRelay.effective_listen_ports(&secrets),
            [("tcp", port), ("udp", port)]
        );
    }
}

#[test]
fn invalid_relay_settings_and_missing_credentials_fail_rendering() {
    for address in ["", "turn.example.org", "2001:db8::1", "192.0.2.256"] {
        assert!(
            TurnRelayRelay
                .server_inbound(&RenderCtx::new(&server(address), &credentials()), &[])
                .is_err(),
            "{address}"
        );
    }

    let server = server("203.0.113.10");
    for (key, input) in [
        (PORT, "0"),
        (PORT, "65536"),
        (PORT, "tcp"),
        (EXITS, "192.0.2.1,example.org"),
        (EXITS, "2001:db8::1"),
        (EXITS, ",192.0.2.1"),
        (EXITS, "192.0.2.1,"),
    ] {
        let mut secrets = credentials();
        secrets.insert(key.into(), input.into());
        assert!(
            TurnRelayRelay
                .server_inbound(&RenderCtx::new(&server, &secrets), &[])
                .is_err(),
            "{key}: {input}"
        );
    }

    for key in [USERNAME, PASSWORD] {
        let mut secrets = credentials();
        secrets.remove(key);
        assert!(
            TurnRelayRelay
                .server_inbound(&RenderCtx::new(&server, &secrets), &[])
                .is_err(),
            "{key} missing"
        );
        secrets.insert(key.into(), String::new());
        assert!(
            TurnRelayRelay
                .server_inbound(&RenderCtx::new(&server, &secrets), &[])
                .is_err(),
            "{key} empty"
        );
    }
}
