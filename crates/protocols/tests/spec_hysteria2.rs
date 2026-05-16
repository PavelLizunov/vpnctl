#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Independent spec tests for `vpnctl_protocols::Hysteria2`.
//!
//! These tests are written from the spec only (no peeking at the impl).
//! If a test fails, the implementation is wrong — do NOT weaken the test.

use std::collections::HashMap;

use serde_json::Value;
use vpnctl_core::{KernelId, Protocol, ProtocolId, RenderCtx, Server, ServerId, User, UserId};
use vpnctl_protocols::Hysteria2;

// ── helpers ─────────────────────────────────────────────────────────────

fn srv() -> Server {
    Server {
        id: ServerId("node-1".to_string()),
        address: "203.0.113.7".to_string(),
        ssh_port: 22,
        ssh_user: "root".to_string(),
        kernel: KernelId("sing-box".to_string()),
        enabled_protocols: vec![ProtocolId("hysteria2".to_string())],
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
    }
}

fn ctx_with<'a>(server: &'a Server, secrets: &'a HashMap<String, String>) -> RenderCtx<'a> {
    RenderCtx::new(server, secrets)
}

// ── H1: id() ────────────────────────────────────────────────────────────

#[test]
fn h1_protocol_id_is_hysteria2() {
    let p = Hysteria2::new();
    assert_eq!(p.id(), ProtocolId("hysteria2".to_string()));
}

// ── H2: server_inbound ──────────────────────────────────────────────────

#[test]
fn h2_server_inbound_top_level_type_is_hysteria2() {
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let users = [user("alice", Some("pw1"))];
    let v = Hysteria2::new().server_inbound(&ctx, &users).unwrap();
    assert_eq!(v.get("type").and_then(Value::as_str), Some("hysteria2"));
}

#[test]
fn h2_server_inbound_listen_port_is_8444() {
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let users = [user("alice", Some("pw1"))];
    let v = Hysteria2::new().server_inbound(&ctx, &users).unwrap();
    assert_eq!(v.get("listen_port").and_then(Value::as_u64), Some(8444));
}

#[test]
fn h2_server_inbound_tls_alpn_contains_h3() {
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let users = [user("alice", Some("pw1"))];
    let v = Hysteria2::new().server_inbound(&ctx, &users).unwrap();
    let alpn = v
        .pointer("/tls/alpn")
        .and_then(Value::as_array)
        .expect("tls.alpn must be an array");
    assert!(
        alpn.iter().any(|x| x.as_str() == Some("h3")),
        "tls.alpn must contain \"h3\"; got {alpn:?}"
    );
}

#[test]
fn h2_server_inbound_uses_default_cert_paths() {
    let s = srv();
    let secrets = HashMap::new(); // tuic.cert_path / tuic.key_path absent
    let ctx = ctx_with(&s, &secrets);
    let users = [user("alice", Some("pw1"))];
    let v = Hysteria2::new().server_inbound(&ctx, &users).unwrap();
    assert_eq!(
        v.pointer("/tls/certificate_path").and_then(Value::as_str),
        Some("/etc/sing-box/cert.pem"),
    );
    assert_eq!(
        v.pointer("/tls/key_path").and_then(Value::as_str),
        Some("/etc/sing-box/key.pem"),
    );
}

#[test]
fn h2_server_inbound_uses_secret_cert_paths_verbatim() {
    let s = srv();
    let mut secrets = HashMap::new();
    secrets.insert("tuic.cert_path".to_string(), "/srv/keys/h2.crt".to_string());
    secrets.insert("tuic.key_path".to_string(), "/srv/keys/h2.key".to_string());
    let ctx = ctx_with(&s, &secrets);
    let users = [user("alice", Some("pw1"))];
    let v = Hysteria2::new().server_inbound(&ctx, &users).unwrap();
    assert_eq!(
        v.pointer("/tls/certificate_path").and_then(Value::as_str),
        Some("/srv/keys/h2.crt"),
    );
    assert_eq!(
        v.pointer("/tls/key_path").and_then(Value::as_str),
        Some("/srv/keys/h2.key"),
    );
}

#[test]
fn h2_server_inbound_users_one_per_user_with_name_and_password() {
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let users = [user("alice", Some("pw-A")), user("bob", Some("pw-B"))];
    let v = Hysteria2::new().server_inbound(&ctx, &users).unwrap();
    let arr = v
        .get("users")
        .and_then(Value::as_array)
        .expect("users must be an array");
    assert_eq!(arr.len(), 2, "expected one entry per user; got {arr:?}");
    let alice = &arr[0];
    let bob = &arr[1];
    assert_eq!(alice.get("name").and_then(Value::as_str), Some("alice"));
    assert_eq!(alice.get("password").and_then(Value::as_str), Some("pw-A"));
    assert_eq!(bob.get("name").and_then(Value::as_str), Some("bob"));
    assert_eq!(bob.get("password").and_then(Value::as_str), Some("pw-B"));
}

#[test]
fn h2_server_inbound_skips_users_without_tuic_password() {
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let users = [
        user("alice", Some("pw-A")),
        user("nopw", None),
        user("bob", Some("pw-B")),
    ];
    let v = Hysteria2::new().server_inbound(&ctx, &users).unwrap();
    let arr = v
        .get("users")
        .and_then(Value::as_array)
        .expect("users must be an array");
    assert_eq!(arr.len(), 2, "users without tuic_password must be skipped");
    let names: Vec<&str> = arr
        .iter()
        .filter_map(|u| u.get("name").and_then(Value::as_str))
        .collect();
    assert!(!names.contains(&"nopw"), "got names: {names:?}");
}

// ── H3: client_config ───────────────────────────────────────────────────

#[test]
fn h3_client_config_basic_fields() {
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let u = user("alice", Some("client-pw"));
    let v = Hysteria2::new().client_config(&ctx, &u).unwrap();
    assert_eq!(v.get("type").and_then(Value::as_str), Some("hysteria2"));
    assert_eq!(v.get("server").and_then(Value::as_str), Some("203.0.113.7"),);
    assert_eq!(v.get("server_port").and_then(Value::as_u64), Some(8444));
    assert_eq!(v.get("password").and_then(Value::as_str), Some("client-pw"),);
}

#[test]
fn h3_client_config_password_defaults_to_empty_when_absent() {
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let u = user("alice", None);
    let v = Hysteria2::new().client_config(&ctx, &u).unwrap();
    assert_eq!(v.get("password").and_then(Value::as_str), Some(""));
}

#[test]
fn h3_client_config_tls_insecure_and_alpn() {
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let u = user("alice", Some("pw"));
    let v = Hysteria2::new().client_config(&ctx, &u).unwrap();
    assert_eq!(
        v.pointer("/tls/insecure").and_then(Value::as_bool),
        Some(true),
    );
    let alpn = v
        .pointer("/tls/alpn")
        .and_then(Value::as_array)
        .expect("tls.alpn must be an array");
    assert!(
        alpn.iter().any(|x| x.as_str() == Some("h3")),
        "client tls.alpn must contain \"h3\"; got {alpn:?}"
    );
}

// ── H4: share_link ──────────────────────────────────────────────────────

#[test]
fn h4_share_link_starts_with_hysteria2_scheme() {
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let u = user("alice", Some("pw"));
    let link = Hysteria2::new().share_link(&ctx, &u).unwrap();
    assert!(link.starts_with("hysteria2://"), "got link: {link}");
}

#[test]
fn h4_share_link_password_segment_percent_encodes_colon_and_at() {
    // Password "ab:cd@ef" — both `:` and `@` are structural in userinfo and
    // MUST be percent-encoded inside the password segment.
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let u = user("alice", Some("ab:cd@ef"));
    let link = Hysteria2::new().share_link(&ctx, &u).unwrap();

    // password sits between "//" and "@<host>" — extract that prefix.
    let after_scheme = link
        .strip_prefix("hysteria2://")
        .expect("link must start with hysteria2://");
    let at_idx = after_scheme
        .rfind('@')
        .expect("share link must contain '@' between userinfo and host");
    let userinfo = &after_scheme[..at_idx];

    assert!(
        userinfo.contains("%3A") || userinfo.contains("%3a"),
        "raw ':' must be percent-encoded in password; userinfo = {userinfo:?}",
    );
    assert!(
        userinfo.contains("%40"),
        "raw '@' must be percent-encoded in password; userinfo = {userinfo:?}",
    );
    // And the literal characters must NOT survive in the userinfo segment.
    assert!(
        !userinfo.contains('@'),
        "raw '@' leaked into userinfo: {userinfo:?}",
    );
}

#[test]
fn h4_share_link_fragment_percent_encodes_space_and_hash() {
    // user.id "alice cool#1" — space → %20, '#' → %23 in fragment.
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let u = user("alice cool#1", Some("pw"));
    let link = Hysteria2::new().share_link(&ctx, &u).unwrap();

    let frag_idx = link
        .find('#')
        .expect("share link must contain a '#' fragment separator");
    let fragment = &link[frag_idx + 1..];

    assert!(
        fragment.contains("%20"),
        "space must be %20 in fragment; got {fragment:?}",
    );
    assert!(
        fragment.contains("%23"),
        "'#' must be %23 in fragment; got {fragment:?}",
    );
    assert!(
        !fragment.contains(' '),
        "raw space leaked into fragment: {fragment:?}",
    );
    assert!(
        !fragment.contains('#'),
        "raw '#' leaked into fragment: {fragment:?}",
    );
}

#[test]
fn h4_share_link_contains_insecure_and_sni_query_params() {
    // Spec evolved per review-agent: official Hysteria2 URI scheme
    // (https://hysteria.network/docs/developers/URI-Scheme/) lists
    // `sni`, `obfs`, `obfs-password`, `pinSHA256`, `insecure` — NO
    // `alpn`. ALPN is negotiated at TLS handshake regardless. Stricter
    // parsers reject unknown URI params.
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let u = user("alice", Some("pw"));
    let link = Hysteria2::new().share_link(&ctx, &u).unwrap();
    assert!(
        link.contains("insecure=1"),
        "share link must carry insecure=1; got {link}",
    );
    assert!(
        link.contains(&format!("sni={}", s.address)),
        "share link must carry sni=<address>; got {link}",
    );
    assert!(
        !link.contains("alpn="),
        "share link must NOT carry alpn (not in official URI spec); got {link}",
    );
}

#[test]
fn h4_share_link_user_without_password_returns_error() {
    // Per review-agent: silent `unwrap_or_default()` was producing
    // `hysteria2://@host/...` which clients accept syntactically but
    // can't authenticate. Refuse to mint such links explicitly.
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let u = user("alice", None);
    let res = Hysteria2::new().share_link(&ctx, &u);
    assert!(
        res.is_err(),
        "expected Err for user without tuic_password, got {res:?}",
    );
}

// ── H7: Hysteria Realm (NAT-traversal) — optional realm block in inbound
//
// Activation rule (per impl docstring):
//   * `hysteria2.realm.server_url` set → realm block emitted with all
//     four keys; `realm_id` defaults to server.id, `token` to "",
//     `stun_servers` to [] (empty list = sing-box default pool).
//   * Absent → no realm key in JSON (back-compat: existing nodes
//     deployed before Realm support was added MUST not regress).
//
// `listen` and `listen_port` are kept regardless — sing-box accepts
// concurrent direct + realm transports.

#[test]
fn h7_no_realm_secrets_means_no_realm_key_in_inbound() {
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let users = [user("alice", Some("pw1"))];
    let v = Hysteria2::new().server_inbound(&ctx, &users).unwrap();
    assert!(
        v.get("realm").is_none(),
        "no realm secrets ⇒ no realm key (back-compat); got {v}"
    );
    // Direct-listen path must still be intact.
    assert_eq!(v.get("listen_port").and_then(Value::as_u64), Some(8444));
}

#[test]
fn h7_realm_emitted_when_server_url_present_with_defaults() {
    let s = srv();
    let mut secrets = HashMap::new();
    secrets.insert(
        "hysteria2.realm.server_url".into(),
        "https://realm.example.com".into(),
    );
    let ctx = ctx_with(&s, &secrets);
    let v = Hysteria2::new()
        .server_inbound(&ctx, &[user("alice", Some("pw1"))])
        .unwrap();
    let realm = v.get("realm").expect("realm block must be emitted");
    assert_eq!(
        realm.get("server_url").and_then(Value::as_str),
        Some("https://realm.example.com")
    );
    // Defaults: realm_id = server.id, token = "", stun_servers = [].
    assert_eq!(
        realm.get("realm_id").and_then(Value::as_str),
        Some("node-1"),
        "realm_id must default to server.id when not configured"
    );
    assert_eq!(
        realm.get("token").and_then(Value::as_str),
        Some(""),
        "token must default to empty (anonymous register)"
    );
    assert_eq!(
        realm.get("stun_servers").and_then(Value::as_array),
        Some(&vec![]),
        "stun_servers must default to empty array (sing-box uses its default pool)"
    );
    // Direct-listen path still present — concurrent transport.
    assert_eq!(v.get("listen_port").and_then(Value::as_u64), Some(8444));
}

#[test]
fn h7_realm_id_and_token_overrides_apply() {
    let s = srv();
    let mut secrets = HashMap::new();
    secrets.insert(
        "hysteria2.realm.server_url".into(),
        "https://rendezvous.lan".into(),
    );
    secrets.insert("hysteria2.realm.realm_id".into(), "homelab-vpn".into());
    secrets.insert("hysteria2.realm.token".into(), "shh-secret".into());
    let ctx = ctx_with(&s, &secrets);
    let v = Hysteria2::new()
        .server_inbound(&ctx, &[user("alice", Some("pw1"))])
        .unwrap();
    let realm = v.get("realm").unwrap();
    assert_eq!(
        realm.get("realm_id").and_then(Value::as_str),
        Some("homelab-vpn")
    );
    assert_eq!(
        realm.get("token").and_then(Value::as_str),
        Some("shh-secret")
    );
}

#[test]
fn h7_stun_servers_csv_is_parsed_into_json_array() {
    let s = srv();
    let mut secrets = HashMap::new();
    secrets.insert(
        "hysteria2.realm.server_url".into(),
        "https://r.example".into(),
    );
    // Whitespace + trailing comma must not produce empty entries.
    secrets.insert(
        "hysteria2.realm.stun_servers".into(),
        " stun.example.com:3478 , stun.cloudflare.com:3478 , ".into(),
    );
    let ctx = ctx_with(&s, &secrets);
    let v = Hysteria2::new()
        .server_inbound(&ctx, &[user("alice", Some("pw1"))])
        .unwrap();
    let arr = v["realm"]["stun_servers"].as_array().unwrap();
    assert_eq!(
        arr.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>(),
        vec!["stun.example.com:3478", "stun.cloudflare.com:3478"],
        "stun_servers must trim whitespace + drop empty entries"
    );
}

/// Empty / whitespace-only `server_url` MUST NOT activate the realm
/// block — otherwise sing-box rejects the config only at deploy-time
/// during `sing-box check`. We catch it at config-render. (Review-agent
/// finding on cd61838^..492fdeb burst.)
#[test]
fn h7_empty_server_url_does_not_activate_realm() {
    for empty in ["", "   ", "\t\n"] {
        let s = srv();
        let mut secrets = HashMap::new();
        secrets.insert("hysteria2.realm.server_url".into(), empty.into());
        let ctx = ctx_with(&s, &secrets);
        let v = Hysteria2::new()
            .server_inbound(&ctx, &[user("alice", Some("pw1"))])
            .unwrap();
        assert!(
            v.get("realm").is_none(),
            "empty/whitespace server_url={empty:?} must NOT activate realm; got {v}"
        );
    }
}

// ── H8: Salamander obfs (anti-DPI XOR scrambling) ───────────────────────
//
// Activation rule: emit the `obfs` block on BOTH server_inbound and
// client_config IFF `hysteria2.obfs.password` is set (and non-empty
// after trim). Type is hardcoded to `salamander` (only kind sing-box
// + upstream Hysteria 2 ship). Share-link encodes via the official
// `obfs=salamander&obfs-password=<pct-encoded>` query parameters.

#[test]
fn h8_no_obfs_secret_means_no_obfs_key_anywhere() {
    let s = srv();
    let secrets = HashMap::new();
    let ctx = ctx_with(&s, &secrets);
    let u = user("alice", Some("pw1"));
    let inbound = Hysteria2::new()
        .server_inbound(&ctx, std::slice::from_ref(&u))
        .unwrap();
    let outbound = Hysteria2::new().client_config(&ctx, &u).unwrap();
    let link = Hysteria2::new().share_link(&ctx, &u).unwrap();
    assert!(inbound.get("obfs").is_none(), "inbound back-compat");
    assert!(outbound.get("obfs").is_none(), "outbound back-compat");
    assert!(
        !link.contains("obfs="),
        "share_link back-compat must not carry &obfs= query; got: {link}"
    );
}

#[test]
fn h8_inbound_renders_obfs_when_password_set() {
    let s = srv();
    let mut secrets = HashMap::new();
    secrets.insert("hysteria2.obfs.password".into(), "my-obfs-secret".into());
    let ctx = ctx_with(&s, &secrets);
    let v = Hysteria2::new()
        .server_inbound(&ctx, &[user("alice", Some("pw1"))])
        .unwrap();
    let obfs = v.get("obfs").expect("obfs block must be emitted");
    assert_eq!(
        obfs.get("type").and_then(Value::as_str),
        Some("salamander"),
        "obfs.type must be hardcoded to salamander (only supported kind)"
    );
    assert_eq!(
        obfs.get("password").and_then(Value::as_str),
        Some("my-obfs-secret")
    );
}

#[test]
fn h8_client_config_mirrors_server_obfs_password() {
    let s = srv();
    let mut secrets = HashMap::new();
    secrets.insert("hysteria2.obfs.password".into(), "shared-secret".into());
    let ctx = ctx_with(&s, &secrets);
    let v = Hysteria2::new()
        .client_config(&ctx, &user("alice", Some("pw1")))
        .unwrap();
    let obfs = v.get("obfs").expect("client config must mirror obfs");
    assert_eq!(obfs.get("type").and_then(Value::as_str), Some("salamander"));
    assert_eq!(
        obfs.get("password").and_then(Value::as_str),
        Some("shared-secret"),
        "client + server MUST share the obfs password (it's the QUIC-handshake key)"
    );
}

#[test]
fn h8_share_link_obfs_query_format() {
    let s = srv();
    let mut secrets = HashMap::new();
    // Include a `+` and a space to verify percent-encoding (USERINFO set).
    secrets.insert("hysteria2.obfs.password".into(), "salt+pepper sea".into());
    let ctx = ctx_with(&s, &secrets);
    let link = Hysteria2::new()
        .share_link(&ctx, &user("alice", Some("pw1")))
        .unwrap();
    assert!(
        link.contains("&obfs=salamander&obfs-password="),
        "official URI scheme requires &obfs=salamander&obfs-password=; got: {link}"
    );
    // Spec: `obfs-password` (with hyphen), NOT `obfsParam` or `obfs_password`.
    assert!(
        !link.contains("obfsParam") && !link.contains("obfs_password"),
        "wrong query parameter name: {link}"
    );
    // Percent-encoding: space → %20 (NOT `+` per USERINFO set), `+` → %2B.
    assert!(
        link.contains("salt%2Bpepper%20sea"),
        "obfs-password must be percent-encoded with USERINFO charset; got: {link}"
    );
}

#[test]
fn h8_empty_obfs_password_does_not_activate_obfs() {
    for empty in ["", "   ", "\t\n"] {
        let s = srv();
        let mut secrets = HashMap::new();
        secrets.insert("hysteria2.obfs.password".into(), empty.into());
        let ctx = ctx_with(&s, &secrets);
        let v = Hysteria2::new()
            .server_inbound(&ctx, &[user("alice", Some("pw1"))])
            .unwrap();
        assert!(
            v.get("obfs").is_none(),
            "empty/whitespace obfs.password={empty:?} must NOT activate obfs; got {v}"
        );
    }
}

#[test]
fn h8_realm_and_obfs_can_coexist() {
    // The two anti-censorship layers compose: Realm (anti-IP-block)
    // + Salamander (anti-DPI-fingerprint). Must produce both blocks.
    let s = srv();
    let mut secrets = HashMap::new();
    secrets.insert(
        "hysteria2.realm.server_url".into(),
        "https://r.example".into(),
    );
    secrets.insert("hysteria2.obfs.password".into(), "obfs-pw".into());
    let ctx = ctx_with(&s, &secrets);
    let v = Hysteria2::new()
        .server_inbound(&ctx, &[user("alice", Some("pw1"))])
        .unwrap();
    assert!(
        v.get("realm").is_some(),
        "realm block must coexist with obfs"
    );
    assert!(
        v.get("obfs").is_some(),
        "obfs block must coexist with realm"
    );
}
