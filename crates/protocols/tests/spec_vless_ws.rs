#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Spec tests for `vpnctl_protocols::VlessWs` (vless + websocket over a
//! fronting TLS domain). Written from the spec only — envelope schema,
//! client outbound shape, share-link byte format. If a test fails, the
//! impl is wrong — DO NOT weaken the test.

use std::collections::HashMap;

use vpnctl_core::{
    DpiRisk, KernelId, Protocol, ProtocolId, RenderCtx, Server, ServerId, ServerSecretSpec, User,
    UserId,
};
use vpnctl_protocols::VlessWs;

const DOMAIN: &str = "edge.example.com";
const PATH_SECRET: &str = "Ab3xKp";

fn srv() -> Server {
    Server {
        id: ServerId("ws-node-1".into()),
        address: "203.0.113.9".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("vless-ws".into())],
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

/// Secrets map with everything present (happy path). Callers mutate /
/// remove entries to exercise the failure + boundary branches.
fn secrets() -> HashMap<String, String> {
    let mut s = HashMap::new();
    s.insert("vlessws.domain".into(), DOMAIN.into());
    s.insert("vlessws.path".into(), PATH_SECRET.into());
    s
}

// ── trait-surface constants ─────────────────────────────────────────

#[test]
fn id_is_vless_ws() {
    assert_eq!(VlessWs::new().id(), ProtocolId("vless-ws".into()));
}

#[test]
fn listen_ports_is_empty() {
    // No static port — must coexist with REALITY on :443.
    assert!(VlessWs::new().listen_ports().is_empty());
}

#[test]
fn dpi_risk_is_strong() {
    assert_eq!(VlessWs::new().dpi_risk(), DpiRisk::Strong);
}

#[test]
fn appears_in_sing_box_sub_is_true() {
    assert!(VlessWs::new().appears_in_sing_box_sub());
}

#[test]
fn server_secret_specs_is_exactly_vlessws_path_password() {
    let specs = VlessWs::new().server_secret_specs();
    assert_eq!(
        specs,
        vec![ServerSecretSpec::Password {
            key: "vlessws.path",
            entropy_bytes: 16,
        }]
    );
}

// ── server_inbound (envelope) ───────────────────────────────────────

#[test]
fn server_inbound_envelope_has_all_keys_and_values() {
    let s = srv();
    let mut sec = secrets();
    sec.insert("vlessws.acme_email".into(), "ops@example.com".into());
    let ctx = RenderCtx::new(&s, &sec);
    let v = VlessWs::new()
        .server_inbound(&ctx, &[user("alice"), user("bob")])
        .unwrap();

    assert_eq!(v["domain"].as_str(), Some(DOMAIN));
    assert_eq!(v["acme_email"].as_str(), Some("ops@example.com"));
    assert_eq!(v["front_port"].as_u64(), Some(8443));
    // path = "/" + secret
    assert_eq!(v["path"].as_str(), Some("/Ab3xKp"));

    let users = v["users"].as_array().expect("users must be an array");
    assert_eq!(users.len(), 2);
    assert_eq!(users[0]["uuid"].as_str(), Some("uuid-alice"));
    assert_eq!(users[0]["name"].as_str(), Some("alice"));
    assert_eq!(users[1]["uuid"].as_str(), Some("uuid-bob"));
    assert_eq!(users[1]["name"].as_str(), Some("bob"));
}

#[test]
fn server_inbound_acme_email_defaults_to_empty_string() {
    let s = srv();
    let sec = secrets(); // no acme_email
    let ctx = RenderCtx::new(&s, &sec);
    let v = VlessWs::new().server_inbound(&ctx, &[]).unwrap();
    assert_eq!(v["acme_email"].as_str(), Some(""));
}

#[test]
fn server_inbound_front_port_overridden_by_secret() {
    let s = srv();
    let mut sec = secrets();
    sec.insert("vlessws.listen_port".into(), "2087".into());
    let ctx = RenderCtx::new(&s, &sec);
    let v = VlessWs::new().server_inbound(&ctx, &[]).unwrap();
    assert_eq!(v["front_port"].as_u64(), Some(2087));
}

#[test]
fn server_inbound_front_port_zero_or_garbage_falls_back_to_default() {
    // zero and unparsable both round-trip to the 8443 default.
    for bad in ["0", "not-a-number"] {
        let s = srv();
        let mut sec = secrets();
        sec.insert("vlessws.listen_port".into(), bad.into());
        let ctx = RenderCtx::new(&s, &sec);
        let v = VlessWs::new().server_inbound(&ctx, &[]).unwrap();
        assert_eq!(v["front_port"].as_u64(), Some(8443), "input {bad:?}");
    }
}

#[test]
fn server_inbound_missing_or_empty_domain_is_err() {
    // Missing entirely, and present-but-empty, both reject.
    for set_empty in [false, true] {
        let s = srv();
        let mut sec = secrets();
        if set_empty {
            sec.insert("vlessws.domain".into(), String::new());
        } else {
            sec.remove("vlessws.domain");
        }
        let ctx = RenderCtx::new(&s, &sec);
        assert!(
            VlessWs::new().server_inbound(&ctx, &[]).is_err(),
            "set_empty={set_empty}"
        );
    }
}

#[test]
fn server_inbound_domain_with_forbidden_char_is_err() {
    // Any of newline/CR/tab/space//?#@\{} in the domain rejects.
    for bad in [
        "evil.com/path",
        "evil .com",
        "e@vil.com",
        "a?b",
        "x#y",
        "a{b}",
    ] {
        let s = srv();
        let mut sec = secrets();
        sec.insert("vlessws.domain".into(), (*bad).into());
        let ctx = RenderCtx::new(&s, &sec);
        assert!(
            VlessWs::new().server_inbound(&ctx, &[]).is_err(),
            "domain {bad:?} must be rejected"
        );
    }
}

#[test]
fn server_inbound_missing_or_malformed_path_secret_is_err() {
    // Missing, and present-but-containing a slash (not [A-Za-z0-9_-]+).
    let cases: [Option<&str>; 3] = [None, Some("foo/bar"), Some("")];
    for case in cases {
        let s = srv();
        let mut sec = secrets();
        match case {
            None => {
                sec.remove("vlessws.path");
            }
            Some(v) => {
                sec.insert("vlessws.path".into(), v.into());
            }
        }
        let ctx = RenderCtx::new(&s, &sec);
        assert!(
            VlessWs::new().server_inbound(&ctx, &[]).is_err(),
            "path {case:?} must be rejected"
        );
    }
}

// ── client_config (sing-box outbound) ───────────────────────────────

#[test]
fn client_config_has_expected_outbound_shape() {
    let s = srv();
    let sec = secrets();
    let ctx = RenderCtx::new(&s, &sec);
    let v = VlessWs::new().client_config(&ctx, &user("alice")).unwrap();

    assert_eq!(v["type"].as_str(), Some("vless"));
    // server is the fronting DOMAIN — never the raw server IP.
    assert_eq!(v["server"].as_str(), Some(DOMAIN));
    assert_ne!(v["server"].as_str(), Some("203.0.113.9"));
    assert_eq!(v["server_port"].as_u64(), Some(8443));
    assert_eq!(v["uuid"].as_str(), Some("uuid-alice"));
    // No flow key on the ws path.
    assert!(v.get("flow").is_none(), "ws outbound must not carry flow");

    // tls object: enabled + server_name=domain + utls chrome + NO reality.
    assert_eq!(v["tls"]["enabled"].as_bool(), Some(true));
    assert_eq!(v["tls"]["server_name"].as_str(), Some(DOMAIN));
    assert_eq!(v["tls"]["utls"]["fingerprint"].as_str(), Some("chrome"));
    assert!(
        v["tls"].get("reality").is_none(),
        "ws path must not carry a reality block"
    );

    // transport object: ws + path + Host header = domain.
    assert_eq!(v["transport"]["type"].as_str(), Some("ws"));
    assert_eq!(v["transport"]["path"].as_str(), Some("/Ab3xKp"));
    assert_eq!(v["transport"]["headers"]["Host"].as_str(), Some(DOMAIN));
}

#[test]
fn client_config_server_port_follows_listen_port_override() {
    let s = srv();
    let mut sec = secrets();
    sec.insert("vlessws.listen_port".into(), "2087".into());
    let ctx = RenderCtx::new(&s, &sec);
    let v = VlessWs::new().client_config(&ctx, &user("alice")).unwrap();
    assert_eq!(v["server_port"].as_u64(), Some(2087));
}

#[test]
fn client_config_missing_domain_or_path_is_err() {
    for missing in ["vlessws.domain", "vlessws.path"] {
        let s = srv();
        let mut sec = secrets();
        sec.remove(missing);
        let ctx = RenderCtx::new(&s, &sec);
        assert!(
            VlessWs::new().client_config(&ctx, &user("alice")).is_err(),
            "missing {missing} must Err"
        );
    }
}

// ── share_link (byte-exact) ─────────────────────────────────────────

#[test]
fn share_link_is_byte_exact() {
    let s = srv();
    let sec = secrets();
    let ctx = RenderCtx::new(&s, &sec);
    let link = VlessWs::new().share_link(&ctx, &user("alice")).unwrap();
    let expected = format!(
        "vless://uuid-alice@{DOMAIN}:8443?encryption=none&type=ws&security=tls\
         &sni={DOMAIN}&host={DOMAIN}&path=%2F{PATH_SECRET}&fp=chrome#alice"
    );
    assert_eq!(link, expected);
}

#[test]
fn share_link_uses_front_port_override() {
    let s = srv();
    let mut sec = secrets();
    sec.insert("vlessws.listen_port".into(), "2087".into());
    let ctx = RenderCtx::new(&s, &sec);
    let link = VlessWs::new().share_link(&ctx, &user("alice")).unwrap();
    assert!(
        link.starts_with(&format!("vless://uuid-alice@{DOMAIN}:2087?")),
        "front-port override must reach the host:port — got {link}"
    );
}

#[test]
fn share_link_byte_stable_across_runs() {
    let s = srv();
    let sec = secrets();
    let ctx = RenderCtx::new(&s, &sec);
    let u = user("alice");
    let a = VlessWs::new().share_link(&ctx, &u).unwrap();
    let b = VlessWs::new().share_link(&ctx, &u).unwrap();
    assert_eq!(a, b, "share_link must be byte-stable across runs");
}

#[test]
fn share_link_different_users_get_distinct_uuids_and_fragments() {
    let s = srv();
    let sec = secrets();
    let ctx = RenderCtx::new(&s, &sec);
    let a = VlessWs::new().share_link(&ctx, &user("alice")).unwrap();
    let b = VlessWs::new().share_link(&ctx, &user("bob")).unwrap();
    assert_ne!(a, b);
    assert!(a.contains("uuid-alice") && a.ends_with("#alice"));
    assert!(b.contains("uuid-bob") && b.ends_with("#bob"));
}

#[test]
fn share_link_missing_domain_or_path_is_err() {
    for missing in ["vlessws.domain", "vlessws.path"] {
        let s = srv();
        let mut sec = secrets();
        sec.remove(missing);
        let ctx = RenderCtx::new(&s, &sec);
        assert!(
            VlessWs::new().share_link(&ctx, &user("alice")).is_err(),
            "missing {missing} must Err"
        );
    }
}

// ── cross-method agreement: the SAME path secret feeds all three ────

#[test]
fn envelope_client_and_link_reference_the_same_path_secret() {
    let s = srv();
    let mut sec = secrets();
    sec.insert("vlessws.path".into(), "ZxQ_99".into());
    let ctx = RenderCtx::new(&s, &sec);
    let p = VlessWs::new();

    let env = p.server_inbound(&ctx, &[user("alice")]).unwrap();
    let cfg = p.client_config(&ctx, &user("alice")).unwrap();
    let link = p.share_link(&ctx, &user("alice")).unwrap();

    assert_eq!(env["path"].as_str(), Some("/ZxQ_99"));
    assert_eq!(cfg["transport"]["path"].as_str(), Some("/ZxQ_99"));
    assert!(link.contains("path=%2FZxQ_99"), "got {link}");
}
