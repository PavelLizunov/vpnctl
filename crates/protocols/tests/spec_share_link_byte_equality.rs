#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Byte-equality regression net for `Protocol::share_link`.
//!
//! These tests assert EXACT string equality between the impl's
//! `share_link()` output and a hand-derived expected value, for
//! the exact UUID / password / secrets configuration shipping with
//! the bash `vpn-control` legacy clients. If a future commit
//! changes the format string in `crates/protocols/src/*.rs`, every
//! existing client on a phone breaks silently — these tests fire
//! BEFORE that lands.

use std::collections::HashMap;

use vpnctl_core::{KernelId, Protocol, RenderCtx, Server, ServerId, User, UserId};
use vpnctl_protocols::{Hysteria2, TuicV5, VlessReality};

// ── helpers ─────────────────────────────────────────────────────────────

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
    // Added 2026-05-16 for the new server_inbound flow-pinning test:
    // share_link only consults public_key, but server_inbound requires
    // private_key. Adding both here is a strict super-set — every
    // existing share_link test still passes.
    m.insert(
        "vless.private_key".to_string(),
        "PRIVKEY_TEST_BASE64URL".to_string(),
    );
    m.insert("vless.short_id".to_string(), "deadbeef".to_string());
    m
}

// ── VLESS ───────────────────────────────────────────────────────────────

#[test]
fn vless_packet_encoding_public_contract_is_xudp() {
    assert_eq!(vpnctl_protocols::VLESS_PACKET_ENCODING, "xudp");
}

#[test]
fn vless_happy_path_byte_equal_uses_robust_default_sni() {
    // Pins the link LAYOUT (param ORDER + param SET — `encryption=none`
    // included; was missing in db3998c) against `scripts/get-vless.sh`
    // from the bash vpn-control project. This is the format regression
    // net: if a future commit reorders/drops a param or changes the
    // encoding, this fires before it lands.
    //
    // Three intentional deviations from the *literal* bash bytes:
    //   1. `fp` is `randomized`, not the bash `chrome` literal. RU DPI
    //      began fingerprinting the static Chrome uTLS ClientHello
    //      (2026-06-16) and resetting REALITY; `randomized` evades it.
    //      See `vless_reality.rs::REALITY_UTLS_FP`.
    //   2. `sni` is `yahoo.com` (DEFAULT_REALITY_SNI), not the bash
    //      `www.microsoft.com` literal. The microsoft dest is a FRAGILE
    //      REALITY upstream — its TLS "steal" only completes for the
    //      `randomized` fingerprint, so firefox/chrome clients got EOF
    //      (proven A/B from a RU network 2026-06-25). yahoo.com is
    //      robust to every fingerprint. The genuine "byte-identical to
    //      bash" contract — for a server that explicitly carries the
    //      legacy microsoft secret — is pinned separately in
    //      `vless_explicit_microsoft_sni_byte_equal_with_bash_scripts`.
    //   3. `packetEncoding=xudp` explicitly enables UDP relay for clients
    //      that otherwise import a TCP-only VLESS profile.
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
    // CLAUDE.md "Migration from bash — seamless preservation": the
    // contract is *same secret material → same bytes*. `vless.sni` IS
    // per-server secret material. A server that explicitly pins
    // `vless.sni=www.microsoft.com` (as the bash get-vless.sh deploys
    // baked in) must still render the legacy link BYTE-FOR-BYTE, so a
    // phone holding a cached bash `sni=www.microsoft.com` link keeps
    // working after the vpnctl cutover. `fp` deviates (randomized,
    // the 2026-06-16 DPI-evasion switch) and `packetEncoding=xudp` is
    // appended so UDP applications work after import.
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
    // The default SNI feeds BOTH the server's REALITY serverNames
    // allowlist (server_inbound → tls.server_name + reality.handshake.server)
    // AND the client surfaces (share_link / client_config). If these two
    // defaults ever diverge, a freshly-deployed server would advertise one
    // dest in its allowlist while handing clients a link for another →
    // REALITY rejects the SNI and every client breaks at the TLS steal.
    // Both server-side fields are pinned to the SAME literal the client
    // byte-equality tests assert (`yahoo.com` = DEFAULT_REALITY_SNI), so a
    // future edit that changes one default-SNI surface but not the others
    // fails here.
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
    // user.id "alice cool" — space is NOT in the FRAGMENT unreserved set,
    // so it MUST become %20. Everything else stays verbatim. Param
    // order matches `vless_happy_path_byte_equal_uses_robust_default_sni`
    // (default SNI = yahoo.com).
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
    // Spec: every user record in the sing-box vless inbound MUST set
    // `flow: "xtls-rprx-vision"` so REALITY handshakes succeed.
    // Empty / wrong flow → silent handshake failure for the client,
    // worst kind. Pinned to detect a regression to the old buggy
    // `flow: ""` immediately.
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
    // Mirror of the inbound check: outbound MUST also set flow at the
    // top level (sing-box outbound vless schema), or the client/server
    // flow mismatch causes handshake-reject.
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
    // Per-server port override (post-2026-05-26) — operator sets
    // `vless.listen_port` server-secret on a co-tenant host where
    // :443 is owned by a legacy 3x-ui. All three render surfaces
    // (server inbound, client outbound, share-link) must agree on
    // the alternate port, else clients hit one port + server binds
    // another → handshake never starts.
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
    // Symmetric guard: no override → default 443 in all three
    // surfaces. Pins the «backward-compat for fleet servers»
    // contract — every existing de/fi/is rendering stays byte-
    // identical post-feature.
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
    // Defensive: typo in the operator-pasted port (`"abc"`) must
    // NOT silently drop the inbound to port 0 — the renderer falls
    // back to the safe 443 default. Combined with the reserved-
    // ports guard, a typo on a co-tenant host fails-closed at
    // deploy time (443 collides with the reservation).
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
    // Only short_id present; public_key MUST be required → Err.
    secrets.insert("vless.short_id".to_string(), "deadbeef".to_string());
    let ctx = ctx_with(&s, &secrets);
    let u = user("alice", Some("pw-alice"));
    let res = VlessReality::new().share_link(&ctx, &u);
    assert!(
        res.is_err(),
        "expected Err when vless.public_key is absent; got {res:?}",
    );
}

// ── TUIC v5 ─────────────────────────────────────────────────────────────

#[test]
fn tuic_happy_path_byte_equal() {
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let u = user("alice", Some("pw-alice"));
    let link = TuicV5::new().share_link(&ctx, &u).unwrap();
    assert_eq!(
        link,
        "tuic://00000000-0000-0000-0000-000000000001:pw-alice@203.0.113.7:8443?congestion_control=bbr&alpn=h3&allow_insecure=1#alice",
    );
}

#[test]
fn tuic_userinfo_percent_encodes_colon_in_password_byte_equal() {
    // Password "pw:x" — `:` is structural in userinfo and MUST become %3A.
    // Fragment "alice" stays verbatim.
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let u = user("alice", Some("pw:x"));
    let link = TuicV5::new().share_link(&ctx, &u).unwrap();
    assert_eq!(
        link,
        "tuic://00000000-0000-0000-0000-000000000001:pw%3Ax@203.0.113.7:8443?congestion_control=bbr&alpn=h3&allow_insecure=1#alice",
    );
}

#[test]
fn tuic_percent_encodes_percent_sign_in_password_and_fragment_byte_equal() {
    // Password "pw%20" — `%` MUST be escaped to %25 to avoid ambiguous/malformed decoding.
    // Fragment "alice%1" — `%` MUST also become %25.
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let u = user("alice%1", Some("pw%20"));
    let link = TuicV5::new().share_link(&ctx, &u).unwrap();
    assert_eq!(
        link,
        "tuic://00000000-0000-0000-0000-000000000001:pw%2520@203.0.113.7:8443?congestion_control=bbr&alpn=h3&allow_insecure=1#alice%251",
    );
}

#[test]
fn tuic_missing_password_is_error() {
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let u = user("alice", None);
    let res = TuicV5::new().share_link(&ctx, &u);
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

// ── Hysteria2 ───────────────────────────────────────────────────────────

#[test]
fn hysteria2_happy_path_byte_equal() {
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let u = user("alice", Some("pw-alice"));
    let link = Hysteria2::new().share_link(&ctx, &u).unwrap();
    assert_eq!(
        link,
        "hysteria2://pw-alice@203.0.113.7:8444/?sni=203.0.113.7&insecure=1#alice",
    );
}

#[test]
fn hysteria2_fragment_percent_encodes_hash_byte_equal() {
    // user.id "alice#1" — `#` is the URI fragment delimiter and MUST be %23
    // when it appears inside the fragment label itself.
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let u = user("alice#1", Some("pw-alice"));
    let link = Hysteria2::new().share_link(&ctx, &u).unwrap();
    assert_eq!(
        link,
        "hysteria2://pw-alice@203.0.113.7:8444/?sni=203.0.113.7&insecure=1#alice%231",
    );
}

#[test]
fn hysteria2_missing_password_is_error() {
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let u = user("alice", None);
    let res = Hysteria2::new().share_link(&ctx, &u);
    assert!(
        res.is_err(),
        "expected Err when tuic_password is absent; got {res:?}",
    );
}

#[test]
fn vless_reality_listen_ports_is_tcp_443_default() {
    // Post cdn-incident (2026-08-05): REALITY declares its default cover
    // port so the firewall step, the port-conflict guard and the drift
    // table see it. The per-server `vless.listen_port` override is
    // resolved by `effective_listen_ports` (spec_vless_reality_ports.rs).
    assert_eq!(VlessReality::new().listen_ports(), &[("tcp", 443)]);
}
