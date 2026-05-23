#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Independent spec tests for `vpnctl_protocols::Shadowsocks2022`.
//!
//! Written from the spec ONLY (no peeking at the impl). If a test fails,
//! the implementation is wrong (or the spec is ambiguous) — DO NOT weaken
//! the test to make it pass.

use std::collections::HashMap;

use serde_json::Value;
use vpnctl_core::{
    CoreError, KernelId, Protocol, ProtocolId, RenderCtx, Server, ServerId, User, UserId,
};
use vpnctl_protocols::{SS_2022_PORT, Shadowsocks2022};

// ── helpers ─────────────────────────────────────────────────────────────

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

/// Default-method PSK (32 bytes for AES-128 base64 → 24 chars; we use a
/// fixed string — the protocol code does NOT validate PSK length, only
/// reads it from secrets).
const PSK: &str = "Test1234567890abcdef0123";

fn secrets_with_psk() -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert("ss2022.psk".to_string(), PSK.to_string());
    m
}

// ── id ─────────────────────────────────────────────────────────────────

#[test]
fn ss_id_is_shadowsocks_2022() {
    let p = Shadowsocks2022::new();
    assert_eq!(p.id(), ProtocolId("shadowsocks-2022".to_string()));
}

#[test]
fn ss_port_constant_is_8388() {
    assert_eq!(SS_2022_PORT, 8388_u16);
}

// ── server_inbound ─────────────────────────────────────────────────────

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
    // v0.4 single-user mode: the inbound's `password` field IS the PSK,
    // so there must be NO `users` array.
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
    // v0.4 single-user mode: passing zero, one, or many users must
    // produce IDENTICAL JSON (the inbound's password is the PSK, and
    // there is no users array).
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
    let secrets = HashMap::new(); // no ss2022.psk
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

// ── client_config ──────────────────────────────────────────────────────

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
    // The override must propagate identically to inbound + outbound —
    // otherwise client cannot connect.
    let s = srv();
    let mut secrets = secrets_with_psk();
    secrets.insert(
        "ss2022.method".into(),
        "2022-blake3-chacha20-poly1305".to_string(),
    );
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
    // Single-user mode: outbound must be identical regardless of which
    // User struct is passed (different id, different uuid).
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

// ── invalid method ─────────────────────────────────────────────────────

#[test]
fn ss_invalid_method_rejected_by_server_inbound() {
    let s = srv();
    let mut secrets = secrets_with_psk();
    // Pre-2022 cipher — must be refused.
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
        let ctx = ctx_with(&s, &secrets);
        let v = Shadowsocks2022::new()
            .server_inbound(&ctx, &[user("alice")])
            .unwrap();
        assert_eq!(v.get("method").and_then(Value::as_str), Some(method));
    }
}

// ── share_link (SIP002) ────────────────────────────────────────────────

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

    // scheme
    assert!(
        link.starts_with("ss://"),
        "must start with ss:// scheme; got {link}"
    );
    // host + port
    assert!(
        link.contains("@203.0.113.7:8388"),
        "must contain @<host>:<port>; got {link}"
    );
    // SIP002 mandates the "/" between port and "#" — strict parsers
    // reject share links without it.
    assert!(
        link.contains("203.0.113.7:8388/#"),
        "SIP002 requires `/` between port and `#`; got {link}"
    );
    // fragment must exist (it carries the tag = user.id).
    assert!(link.contains('#'), "must contain a fragment; got {link}");
}

#[test]
fn ss_share_link_userinfo_is_plain_method_colon_password_not_base64() {
    // SIP002: for AEAD-2022 ciphers the userinfo is NOT base64-encoded;
    // it is the literal `method:password` (with percent-encoding for
    // structural chars). We encode our PSK with base64-friendly chars
    // so the test is unambiguous: literal substring must appear, base64
    // of the same payload must NOT.
    let s = srv();
    let secrets = secrets_with_psk();
    let ctx = ctx_with(&s, &secrets);
    let link = Shadowsocks2022::new()
        .share_link(&ctx, &user("alice"))
        .unwrap();

    let after_scheme = link.strip_prefix("ss://").expect("ss://");
    let at_idx = after_scheme.rfind('@').expect("'@' between userinfo+host");
    let userinfo = &after_scheme[..at_idx];

    // Must contain a single literal ':' between method and password.
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
fn ss_share_link_special_chars_in_psk_are_percent_encoded() {
    // Operator can rotate to any PSK string. If it contains '@' or '/'
    // or '#' or ':', SIP002 says the userinfo segment must percent-
    // encode them — otherwise the parser splits in the wrong place.
    let s = srv();
    let mut secrets = HashMap::new();
    secrets.insert("ss2022.psk".into(), "p@ss/wo#rd:1".to_string());
    let ctx = ctx_with(&s, &secrets);
    let link = Shadowsocks2022::new()
        .share_link(&ctx, &user("alice"))
        .unwrap();

    let after_scheme = link.strip_prefix("ss://").expect("ss://");
    let at_idx = after_scheme.rfind('@').expect("'@' separator");
    let userinfo = &after_scheme[..at_idx];

    // Method then ONE literal ':' separator then encoded password.
    let pw_part = userinfo
        .strip_prefix("2022-blake3-aes-128-gcm:")
        .expect("expected method then ':' then password; got {userinfo}");

    assert!(pw_part.contains("%40"), "'@' must be %40; pw={pw_part}");
    assert!(
        pw_part.contains("%2F") || pw_part.contains("%2f"),
        "'/' must be %2F; pw={pw_part}"
    );
    assert!(pw_part.contains("%23"), "'#' must be %23; pw={pw_part}");
    assert!(
        pw_part.contains("%3A") || pw_part.contains("%3a"),
        "'/' must be %3A; pw={pw_part}"
    );

    // Raw chars must NOT survive in the password segment — otherwise
    // the URL parser splits on them.
    assert!(!pw_part.contains('@'), "raw '@' leaked: {pw_part}");
    assert!(!pw_part.contains('/'), "raw '/' leaked: {pw_part}");
    assert!(!pw_part.contains('#'), "raw '#' leaked: {pw_part}");
    // After the method's ':' there must be no further raw ':'.
    assert!(
        !pw_part.contains(':'),
        "raw ':' leaked into password: {pw_part}"
    );
}

#[test]
fn ss_share_link_tag_is_user_id_percent_encoded() {
    // user.id "alice cool#1" — fragment-significant chars: '#' must be
    // %23, space must be %20.
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
