#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Port-declaration spec for `vpnctl_protocols::VlessReality`.
//!
//! Pins the cdn-incident fix (2026-08-05): REALITY's default port is the
//! static 443, but a per-server `vless.listen_port` secret override moves
//! the REAL bind port — and `effective_listen_ports` (what the firewall
//! step, the port-conflict guard and the admin drift table read) MUST
//! track it. If a test fails, the impl is wrong — DO NOT weaken it.

use std::collections::HashMap;

use vpnctl_core::{KernelId, Protocol, ProtocolId, RenderCtx, Server, ServerId, User, UserId};
use vpnctl_protocols::VlessReality;

fn srv() -> Server {
    Server {
        id: ServerId("cdn".into()),
        address: "192.0.2.10".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("vless+reality".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

fn base_secrets() -> HashMap<String, String> {
    let mut s = HashMap::new();
    s.insert("vless.private_key".into(), "priv-key".into());
    s.insert("vless.public_key".into(), "pub-key".into());
    s.insert("vless.short_id".into(), "deadbeef".into());
    s
}

// ── static declaration ───────────────────────────────────────────────

#[test]
fn listen_ports_is_tcp_443() {
    assert_eq!(VlessReality::new().listen_ports(), &[("tcp", 443)]);
}

// ── effective (secret-aware) declaration ─────────────────────────────

#[test]
fn effective_listen_ports_defaults_to_443_without_override() {
    let ports = VlessReality::new().effective_listen_ports(&base_secrets());
    assert_eq!(ports, vec![("tcp", 443)]);
}

#[test]
fn effective_listen_ports_honours_the_override() {
    let mut s = base_secrets();
    s.insert("vless.listen_port".into(), "8443".into());
    let ports = VlessReality::new().effective_listen_ports(&s);
    assert_eq!(ports, vec![("tcp", 8443)]);
}

#[test]
fn effective_listen_ports_unparsable_override_falls_back_to_443() {
    for bad in ["", "not-a-port", "8443x", "-1", "65536"] {
        let mut s = base_secrets();
        s.insert("vless.listen_port".into(), bad.into());
        let ports = VlessReality::new().effective_listen_ports(&s);
        assert_eq!(ports, vec![("tcp", 443)], "bad override {bad:?}");
    }
}

// ── consistency with what sing-box actually binds ────────────────────

#[test]
fn server_inbound_listen_port_matches_effective_declaration() {
    // The drift table + firewall read `effective_listen_ports`; sing-box
    // binds whatever `server_inbound` renders. These two MUST agree for
    // every override value, otherwise the admin UI and ufw drift from
    // reality again (the exact cdn incident this file pins).
    for override_value in [None, Some("8443"), Some("10443")] {
        let mut s = base_secrets();
        if let Some(v) = override_value {
            s.insert("vless.listen_port".into(), v.into());
        }
        let server = srv();
        let ctx = RenderCtx::new(&server, &s);
        let inbound = VlessReality::new().server_inbound(&ctx, &[]).unwrap();
        let rendered_port = inbound["listen_port"].as_u64().unwrap() as u16;

        let declared = VlessReality::new().effective_listen_ports(&s);
        assert_eq!(declared.len(), 1);
        assert_eq!(
            declared[0],
            ("tcp", rendered_port),
            "override {override_value:?}: declaration diverges from rendered inbound"
        );
    }
}

#[test]
fn share_link_port_matches_effective_declaration() {
    // The client link carries the SAME override port — a client pointed
    // at 443 while the server binds 8443 can never connect.
    let mut s = base_secrets();
    s.insert("vless.listen_port".into(), "8443".into());
    let server = srv();
    let ctx = RenderCtx::new(&server, &s);
    let user = User {
        id: UserId("alice".into()),
        uuid: "uuid-alice".into(),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    };
    let link = VlessReality::new().share_link(&ctx, &user).unwrap();
    assert!(
        link.contains("@192.0.2.10:8443?"),
        "share_link must carry the override port: {link}"
    );
}
