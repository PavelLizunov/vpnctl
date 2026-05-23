#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Spec tests for `vpnctl_protocols::WireGuard`.
//! Written from the spec only (envelope schema, share-link format,
//! per-user contract). If a test fails, the impl is wrong — DO NOT
//! weaken the test.

use std::collections::HashMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;
use vpnctl_core::{KernelId, Protocol, ProtocolId, RenderCtx, Server, ServerId, User, UserId};
use vpnctl_protocols::{CLIENT_PRIVKEY_PLACEHOLDER, WIREGUARD_PORT, WireGuard};

const PUBKEY_A: &str = "qXFvJL5KLmM3Of9hVo5GmJ4n0LB9rWYfV4ZE1XGZJks=";
const PUBKEY_B: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaaa=";
const SERVER_PRIV: &str = "AAABBBCCCDDDEEEFFFGGGHHHIIIJJJKKKLLLMMMNNNn=";
const SERVER_PUB: &str = "ZZZAAABBBCCCDDDEEEFFFGGGHHHIIIJJJKKKLLLMMMm=";

fn srv() -> Server {
    Server {
        id: ServerId("wg-node-1".into()),
        address: "203.0.113.7".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("amneziawg".into())],
        enabled_protocols: vec![ProtocolId("wireguard".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

fn user(name: &str, pubkey: Option<&str>) -> User {
    User {
        id: UserId(name.into()),
        uuid: format!("uuid-{name}"),
        tuic_password: None,
        wireguard_pubkey: pubkey.map(str::to_string),
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    }
}

/// Same as `user` but the user was created via `--gen-wireguard`
/// (server-side keypair generation, both halves stored). Used by
/// the low-tech-UX spec tests that pin the
/// no-`<PASTE>`-placeholder contract.
fn user_with_keypair(name: &str, pubkey: &str, privkey: &str) -> User {
    User {
        id: UserId(name.into()),
        uuid: format!("uuid-{name}"),
        tuic_password: None,
        wireguard_pubkey: Some(pubkey.into()),
        wireguard_private: Some(privkey.into()),
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    }
}

fn server_secrets() -> HashMap<String, String> {
    let mut s = HashMap::new();
    s.insert("wireguard.server_private_key".into(), SERVER_PRIV.into());
    s.insert("wireguard.server_public_key".into(), SERVER_PUB.into());
    s
}

#[test]
fn wg_id_is_wireguard() {
    assert_eq!(WireGuard::new().id(), ProtocolId("wireguard".into()));
}

#[test]
fn wg_constants_match_spec() {
    assert_eq!(WIREGUARD_PORT, 51820);
    assert!(CLIENT_PRIVKEY_PLACEHOLDER.contains("PASTE"));
}

#[test]
fn wg_server_inbound_envelope_top_level_keys() {
    let s = srv();
    let secrets = server_secrets();
    let ctx = RenderCtx::new(&s, &secrets);
    let v = WireGuard::new().server_inbound(&ctx, &[]).unwrap();
    let obj = v.as_object().expect("envelope must be a JSON object");
    for k in [
        "type",
        "tag",
        "listen_port",
        "private_key",
        "address_cidr",
        "peers",
    ] {
        assert!(obj.contains_key(k), "envelope missing key '{k}': {v}");
    }
}

#[test]
fn wg_server_inbound_default_listen_port_is_51820() {
    let s = srv();
    let secrets = server_secrets();
    let ctx = RenderCtx::new(&s, &secrets);
    let v = WireGuard::new().server_inbound(&ctx, &[]).unwrap();
    assert_eq!(v.get("listen_port").and_then(Value::as_u64), Some(51820));
}

#[test]
fn wg_server_inbound_listen_port_overridden_by_secret() {
    let s = srv();
    let mut secrets = server_secrets();
    secrets.insert("wireguard.listen_port".into(), "12345".into());
    let ctx = RenderCtx::new(&s, &secrets);
    let v = WireGuard::new().server_inbound(&ctx, &[]).unwrap();
    assert_eq!(v.get("listen_port").and_then(Value::as_u64), Some(12345));
}

#[test]
fn wg_server_inbound_skips_users_without_pubkey() {
    let s = srv();
    let secrets = server_secrets();
    let ctx = RenderCtx::new(&s, &secrets);
    let users = [
        user("alice", Some(PUBKEY_A)),
        user("nopubkey", None),
        user("bob", Some(PUBKEY_B)),
    ];
    let v = WireGuard::new().server_inbound(&ctx, &users).unwrap();
    let peers = v.get("peers").and_then(Value::as_array).unwrap();
    assert_eq!(peers.len(), 2);
    let names: Vec<&str> = peers
        .iter()
        .filter_map(|p| p.get("name").and_then(Value::as_str))
        .collect();
    assert!(!names.contains(&"nopubkey"));
}

#[test]
fn wg_server_inbound_peer_allowed_ips_assigned_by_index() {
    let s = srv();
    let secrets = server_secrets();
    let ctx = RenderCtx::new(&s, &secrets);
    let users = [user("alice", Some(PUBKEY_A)), user("bob", Some(PUBKEY_B))];
    let v = WireGuard::new().server_inbound(&ctx, &users).unwrap();
    let peers = v.get("peers").and_then(Value::as_array).unwrap();
    assert_eq!(
        peers[0].get("allowed_ips").and_then(Value::as_str),
        Some("10.66.0.2/32")
    );
    assert_eq!(
        peers[1].get("allowed_ips").and_then(Value::as_str),
        Some("10.66.0.3/32")
    );
}

#[test]
fn wg_server_inbound_missing_private_key_returns_missing_secret_error() {
    let s = srv();
    let secrets = HashMap::new();
    let ctx = RenderCtx::new(&s, &secrets);
    let err = WireGuard::new().server_inbound(&ctx, &[]).unwrap_err();
    let msg = format!("{err:?}");
    assert!(
        msg.contains("MissingSecret") && msg.contains("wireguard.server_private_key"),
        "expected MissingSecret(wireguard.server_private_key); got {msg}"
    );
}

#[test]
fn wg_server_inbound_invalid_pubkey_format_returns_render_error() {
    let s = srv();
    let secrets = server_secrets();
    let ctx = RenderCtx::new(&s, &secrets);
    let users = [user("baduser", Some("not-base64-44-chars"))];
    let err = WireGuard::new().server_inbound(&ctx, &users).unwrap_err();
    let msg = format!("{err:?}");
    assert!(msg.contains("Render"), "expected Render error; got {msg}");
    assert!(
        msg.contains("baduser"),
        "msg should name the user; got {msg}"
    );
}

#[test]
fn wg_client_config_uses_placeholder_private_key_never_reads_inventory() {
    let s = srv();
    let secrets = server_secrets();
    let ctx = RenderCtx::new(&s, &secrets);
    let v = WireGuard::new()
        .client_config(&ctx, &user("alice", Some(PUBKEY_A)))
        .unwrap();
    let priv_key = v
        .pointer("/interface/private_key")
        .and_then(Value::as_str)
        .unwrap();
    assert_eq!(priv_key, CLIENT_PRIVKEY_PLACEHOLDER);
}

#[test]
fn wg_client_config_amneziawg_block_present_when_all_obfs_secrets_set() {
    let s = srv();
    let mut secrets = server_secrets();
    for k in [
        "amneziawg.jc",
        "amneziawg.jmin",
        "amneziawg.jmax",
        "amneziawg.s1",
        "amneziawg.s2",
        "amneziawg.h1",
        "amneziawg.h2",
        "amneziawg.h3",
        "amneziawg.h4",
    ] {
        secrets.insert(k.into(), "42".into());
    }
    let ctx = RenderCtx::new(&s, &secrets);
    let v = WireGuard::new()
        .client_config(&ctx, &user("alice", Some(PUBKEY_A)))
        .unwrap();
    assert!(
        v.pointer("/interface/amneziawg").is_some(),
        "amneziawg block must appear when all 9 obfs secrets set; got {v}"
    );
}

#[test]
fn wg_client_config_amneziawg_block_omitted_when_any_obfs_secret_missing() {
    let s = srv();
    let mut secrets = server_secrets();
    // Set 8 out of 9 — h4 missing.
    for k in [
        "amneziawg.jc",
        "amneziawg.jmin",
        "amneziawg.jmax",
        "amneziawg.s1",
        "amneziawg.s2",
        "amneziawg.h1",
        "amneziawg.h2",
        "amneziawg.h3",
    ] {
        secrets.insert(k.into(), "42".into());
    }
    let ctx = RenderCtx::new(&s, &secrets);
    let v = WireGuard::new()
        .client_config(&ctx, &user("alice", Some(PUBKEY_A)))
        .unwrap();
    assert!(
        v.pointer("/interface/amneziawg").is_none(),
        "all-or-nothing: missing h4 means no amneziawg block; got {v}"
    );
}

#[test]
fn wg_share_link_starts_with_wireguard_pseudo_uri() {
    let s = srv();
    let secrets = server_secrets();
    let ctx = RenderCtx::new(&s, &secrets);
    let link = WireGuard::new()
        .share_link(&ctx, &user("alice", Some(PUBKEY_A)))
        .unwrap();
    assert!(
        link.starts_with("wireguard://?conf="),
        "share_link must start with wireguard://?conf=; got {link}"
    );
    assert!(link.contains("#alice"), "fragment carries user id");
}

#[test]
fn wg_share_link_base64_payload_decodes_to_valid_ini() {
    let s = srv();
    let secrets = server_secrets();
    let ctx = RenderCtx::new(&s, &secrets);
    let link = WireGuard::new()
        .share_link(&ctx, &user("alice", Some(PUBKEY_A)))
        .unwrap();
    let after_conf = link
        .strip_prefix("wireguard://?conf=")
        .unwrap()
        .split('#')
        .next()
        .unwrap();
    let bytes = URL_SAFE_NO_PAD
        .decode(after_conf)
        .expect("conf decodes as base64url");
    let text = std::str::from_utf8(&bytes).unwrap();
    assert!(
        text.contains("[Interface]\n"),
        "decoded conf has [Interface]: {text}"
    );
    assert!(text.contains("[Peer]\n"), "decoded conf has [Peer]: {text}");
    // Server pubkey is what the client peer must use.
    assert!(
        text.contains(SERVER_PUB),
        "client conf must reference server's PUBLIC key"
    );
    // Client private key is a placeholder — never the server's private.
    assert!(text.contains(CLIENT_PRIVKEY_PLACEHOLDER));
    assert!(
        !text.contains(SERVER_PRIV),
        "server private key MUST NOT leak into client conf"
    );
}

#[test]
fn wg_share_link_user_without_pubkey_returns_render_error() {
    let s = srv();
    let secrets = server_secrets();
    let ctx = RenderCtx::new(&s, &secrets);
    let err = WireGuard::new()
        .share_link(&ctx, &user("nopubkey", None))
        .unwrap_err();
    let msg = format!("{err:?}");
    assert!(
        msg.contains("Render") && msg.contains("nopubkey"),
        "expected hard-error mentioning user; got {msg}"
    );
}

// ── Low-tech-UX contract (CLAUDE.md "users are low-tech"
//    one-action ceiling): when `wireguard_private` is set on the user
//    (i.e. created via `--gen-wireguard` / web `gen_wireguard` flow),
//    rendered configs must contain the REAL private key and NOT the
//    `<PASTE YOUR PRIVATE KEY HERE>` placeholder. The recipient
//    imports the artefact as-is in one action.

const CLIENT_PRIV_FOR_TEST: &str = "BBBaaaCCCdddEEEfffGGGhhhIIIjjjKKKlllMMMnnno=";

#[test]
fn wg_client_conf_uses_server_generated_private_verbatim() {
    let s = srv();
    let secrets = server_secrets();
    let ctx = RenderCtx::new(&s, &secrets);
    let u = user_with_keypair("alice", PUBKEY_A, CLIENT_PRIV_FOR_TEST);
    let link = WireGuard::new().share_link(&ctx, &u).unwrap();
    // share_link wraps a base64(.conf) payload — decode and inspect
    let b64 = link
        .strip_prefix("wireguard://?conf=")
        .and_then(|s| s.split('#').next())
        .expect("share_link must start with wireguard://?conf=");
    let bytes = URL_SAFE_NO_PAD.decode(b64).unwrap();
    let text = String::from_utf8(bytes).unwrap();
    assert!(
        text.contains(CLIENT_PRIV_FOR_TEST),
        "conf must embed server-generated private verbatim: {text}"
    );
    assert!(
        !text.contains(CLIENT_PRIVKEY_PLACEHOLDER),
        "conf must NOT have the <PASTE> placeholder when private is set"
    );
}

#[test]
fn wg_client_config_outbound_uses_server_generated_private_verbatim() {
    // Mirror of the above on the JSON outbound path that vpnctl
    // returns via `/sub/<token>`.
    let s = srv();
    let secrets = server_secrets();
    let ctx = RenderCtx::new(&s, &secrets);
    let u = user_with_keypair("alice", PUBKEY_A, CLIENT_PRIV_FOR_TEST);
    let out = WireGuard::new().client_config(&ctx, &u).unwrap();
    let priv_field = out
        .pointer("/interface/private_key")
        .and_then(serde_json::Value::as_str)
        .expect("private_key must be a string");
    assert_eq!(
        priv_field, CLIENT_PRIV_FOR_TEST,
        "outbound must embed user.wireguard_private verbatim, not placeholder"
    );
}

#[test]
fn wg_client_conf_keeps_placeholder_when_private_is_none() {
    // Operator-paranoid path (legacy `--wireguard-pubkey` only): no
    // private stored → conf still has `<PASTE>` so the operator knows
    // to do the editor step. This pins the FALLBACK contract.
    let s = srv();
    let secrets = server_secrets();
    let ctx = RenderCtx::new(&s, &secrets);
    let u = user("paranoid", Some(PUBKEY_A));
    let link = WireGuard::new().share_link(&ctx, &u).unwrap();
    let b64 = link
        .strip_prefix("wireguard://?conf=")
        .and_then(|s| s.split('#').next())
        .unwrap();
    let bytes = URL_SAFE_NO_PAD.decode(b64).unwrap();
    let text = String::from_utf8(bytes).unwrap();
    assert!(
        text.contains(CLIENT_PRIVKEY_PLACEHOLDER),
        "without server-generated private, placeholder MUST remain"
    );
}

#[test]
fn wg_share_link_byte_stable_across_runs() {
    let s = srv();
    let secrets = server_secrets();
    let ctx = RenderCtx::new(&s, &secrets);
    let u = user("alice", Some(PUBKEY_A));
    let a = WireGuard::new().share_link(&ctx, &u).unwrap();
    let b = WireGuard::new().share_link(&ctx, &u).unwrap();
    assert_eq!(a, b, "share_link must be byte-stable across runs");
}
