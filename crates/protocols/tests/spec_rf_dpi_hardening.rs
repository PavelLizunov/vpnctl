#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;

use serde_json::json;
use vpnctl_core::{KernelId, Protocol, RenderCtx, Server, ServerId, User, UserId};
use vpnctl_protocols::{
    DEFAULT_REALITY_FP, DEFAULT_REALITY_SNI, Hysteria2, NEW_SERVER_REALITY_FP,
    NEW_SERVER_REALITY_SNI, TuicV5, VALID_REALITY_FPS, VlessReality, VlessXhttp,
    is_valid_reality_fp, is_valid_reality_handshake_server, is_valid_reality_sni, reality_fp,
    reality_handshake_target, tls_server_name,
};

const TEST_PRIVKEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const TEST_PUBKEY: &str = "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE";
const TEST_SHORT_ID: &str = "0102030405060708";
const TEST_XHTTP_PATH: &str = "Zq9_path-OK";

fn fixture_server() -> Server {
    Server {
        id: ServerId("node-1".into()),
        address: "203.0.113.7".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

fn fixture_user() -> User {
    User {
        id: UserId("alice".into()),
        uuid: "00000000-0000-0000-0000-000000000001".into(),
        tuic_password: Some("pw-alice".into()),
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    }
}

fn secrets(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (String::from(*k), String::from(*v)))
        .collect()
}

fn vless_base_secrets() -> HashMap<String, String> {
    secrets(&[
        ("vless.private_key", TEST_PRIVKEY),
        ("vless.public_key", TEST_PUBKEY),
        ("vless.short_id", TEST_SHORT_ID),
    ])
}

fn vless_xhttp_base_secrets() -> HashMap<String, String> {
    let mut map = vless_base_secrets();
    map.insert(
        String::from("vlessxhttp.path"),
        String::from(TEST_XHTTP_PATH),
    );
    map
}

fn quic_base_secrets() -> HashMap<String, String> {
    let mut map = HashMap::new();
    map.insert(
        String::from("observed.tls.cert_public_key_sha256"),
        "cd".repeat(32),
    );
    map
}

#[test]
fn constants_match_spec_legacy_and_new_server_values() {
    assert_eq!(DEFAULT_REALITY_SNI, "yahoo.com");
    assert_eq!(NEW_SERVER_REALITY_SNI, "www.apple.com");
    assert_eq!(DEFAULT_REALITY_FP, "randomized");
    assert_eq!(NEW_SERVER_REALITY_FP, "chrome");

    let expected_fps: &[&str] = &[
        "chrome",
        "firefox",
        "safari",
        "ios",
        "android",
        "edge",
        "360",
        "qq",
        "random",
        "randomized",
    ];
    assert_eq!(VALID_REALITY_FPS, expected_fps);
    assert!(is_valid_reality_sni(DEFAULT_REALITY_SNI));
    assert!(is_valid_reality_sni(NEW_SERVER_REALITY_SNI));
    assert!(is_valid_reality_fp(DEFAULT_REALITY_FP));
    assert!(is_valid_reality_fp(NEW_SERVER_REALITY_FP));
}

#[test]
fn is_valid_reality_fp_accepts_every_member_of_valid_reality_fps() {
    assert_eq!(VALID_REALITY_FPS.len(), 10);
    for &fp in VALID_REALITY_FPS {
        assert!(is_valid_reality_fp(fp), "expected fp {fp:?} to be valid");
    }
}

#[test]
fn is_valid_reality_fp_rejects_unknown_case_mismatch_whitespace_and_empty() {
    let invalid_fps = [
        "",
        " ",
        "Chrome",
        "CHROME",
        "Randomized",
        " chrome",
        "chrome ",
        "chrome\n",
        "opera",
        "brave",
        "chrome&sni=evil.com",
    ];
    for fp in invalid_fps {
        assert!(!is_valid_reality_fp(fp), "expected fp {fp:?} to be invalid");
    }
}

#[test]
fn reality_fp_returns_valid_secret_or_falls_back_to_default() {
    assert_eq!(reality_fp(&HashMap::new()), DEFAULT_REALITY_FP);

    for &fp in VALID_REALITY_FPS {
        let sec = secrets(&[("vless.fp", fp)]);
        assert_eq!(reality_fp(&sec), fp);
    }

    for invalid in ["", "   ", "Chrome", "opera", "chrome&pbk=x"] {
        let sec = secrets(&[("vless.fp", invalid)]);
        assert_eq!(
            reality_fp(&sec),
            DEFAULT_REALITY_FP,
            "invalid vless.fp {invalid:?} must fall back to DEFAULT_REALITY_FP"
        );
    }
}

#[test]
fn is_valid_reality_sni_accepts_valid_ascii_hostnames() {
    let valid_hosts = [
        "yahoo.com",
        "www.apple.com",
        "a.b",
        "sub-1.edge-02.example.co.uk",
        "A1.Example-Host.ORG",
    ];
    for host in valid_hosts {
        assert!(
            is_valid_reality_sni(host),
            "expected {host:?} to be valid SNI"
        );
    }
}

#[test]
fn is_valid_reality_sni_enforces_label_and_total_length_boundaries() {
    let label_63 = "a".repeat(63);
    let label_64 = "a".repeat(64);
    assert!(is_valid_reality_sni(&format!("{label_63}.com")));
    assert!(!is_valid_reality_sni(&format!("{label_64}.com")));

    let l1 = "a".repeat(63);
    let l2 = "b".repeat(63);
    let l3 = "c".repeat(63);
    let l4_ok = "d".repeat(57);
    let l4_too_long = "d".repeat(58);

    let host_253 = format!("{l1}.{l2}.{l3}.{l4_ok}.com");
    assert_eq!(host_253.len(), 253);
    assert!(is_valid_reality_sni(&host_253));

    let host_254 = format!("{l1}.{l2}.{l3}.{l4_too_long}.com");
    assert_eq!(host_254.len(), 254);
    assert!(!is_valid_reality_sni(&host_254));

    assert!(!is_valid_reality_sni(""));
}

#[test]
fn is_valid_reality_sni_rejects_hyphens_dots_bad_chars_and_ip_literals() {
    let invalid_hosts = [
        "-example.com",
        "example-.com",
        "www.-example.com",
        "www.example-.com",
        "example.com-",
        "-.com",
        ".example.com",
        "example.com.",
        "example..com",
        ".",
        "my_host.example.com",
        " example.com",
        "example.com ",
        "exa mple.com",
        "example.com\n",
        "example.com:443",
        "https://example.com",
        "example.com/path",
        "пример.рф",
        "exämple.com",
        "127.0.0.1",
        "203.0.113.7",
        "0.0.0.0",
        "::1",
        "2001:db8::1",
        "[::1]",
    ];
    for host in invalid_hosts {
        assert!(
            !is_valid_reality_sni(host),
            "expected {host:?} to be invalid SNI"
        );
    }
}

#[test]
fn is_valid_reality_handshake_server_accepts_hostnames_and_ip_literals() {
    let valid_servers = [
        "yahoo.com",
        "www.apple.com",
        "decoy-1.internal.example",
        "127.0.0.1",
        "203.0.113.7",
        "0.0.0.0",
        "::1",
        "2001:db8::1",
        "fe80::1",
    ];
    for server in valid_servers {
        assert!(
            is_valid_reality_handshake_server(server),
            "expected handshake server {server:?} to be valid"
        );
    }
}

#[test]
fn is_valid_reality_handshake_server_rejects_invalid_hosts_ports_brackets_and_whitespace() {
    let label_64_host = format!("{}.com", "a".repeat(64));
    let invalid_servers = [
        "",
        "   ",
        "[::1]",
        "127.0.0.1:8443",
        "example.com:443",
        " 127.0.0.1",
        "127.0.0.1 ",
        " www.apple.com ",
        "-bad.example.com",
        "bad-.example.com",
        "bad..example.com",
        "bad_host.example.com",
        "2001:db8:::1",
        label_64_host.as_str(),
    ];
    for server in invalid_servers {
        assert!(
            !is_valid_reality_handshake_server(server),
            "expected handshake server {server:?} to be invalid"
        );
    }
}

#[test]
fn reality_handshake_target_defaults_to_sni_and_443_when_unset() {
    let empty = HashMap::new();
    assert_eq!(
        reality_handshake_target(&empty, "yahoo.com"),
        ("yahoo.com", 443)
    );
    assert_eq!(
        reality_handshake_target(&empty, "www.apple.com"),
        ("www.apple.com", 443)
    );
}

#[test]
fn reality_handshake_target_accepts_ipv4_ipv6_hostname_and_trims_whitespace() {
    let sec_ipv4 = secrets(&[
        ("vless.handshake_server", "127.0.0.1"),
        ("vless.handshake_port", "8443"),
    ]);
    assert_eq!(
        reality_handshake_target(&sec_ipv4, "www.apple.com"),
        ("127.0.0.1", 8443)
    );

    let sec_ipv6 = secrets(&[
        ("vless.handshake_server", "::1"),
        ("vless.handshake_port", "8443"),
    ]);
    assert_eq!(
        reality_handshake_target(&sec_ipv6, "www.apple.com"),
        ("::1", 8443)
    );

    let sec_host = secrets(&[
        ("vless.handshake_server", "decoy.example.com"),
        ("vless.handshake_port", "9443"),
    ]);
    assert_eq!(
        reality_handshake_target(&sec_host, "www.apple.com"),
        ("decoy.example.com", 9443)
    );

    let sec_trimmed = secrets(&[
        ("vless.handshake_server", "  127.0.0.1 \n"),
        ("vless.handshake_port", " \t8443\r\n "),
    ]);
    assert_eq!(
        reality_handshake_target(&sec_trimmed, "www.apple.com"),
        ("127.0.0.1", 8443)
    );

    let sec_trimmed_host = secrets(&[
        ("vless.handshake_server", "  decoy.example.com  "),
        ("vless.handshake_port", " 443 "),
    ]);
    assert_eq!(
        reality_handshake_target(&sec_trimmed_host, "www.apple.com"),
        ("decoy.example.com", 443)
    );
}

#[test]
fn reality_handshake_target_enforces_port_bounds_and_independent_fallbacks() {
    let sec_min_port = secrets(&[
        ("vless.handshake_server", "127.0.0.1"),
        ("vless.handshake_port", "1"),
    ]);
    assert_eq!(
        reality_handshake_target(&sec_min_port, "www.apple.com"),
        ("127.0.0.1", 1)
    );

    let sec_max_port = secrets(&[
        ("vless.handshake_server", "127.0.0.1"),
        ("vless.handshake_port", "65535"),
    ]);
    assert_eq!(
        reality_handshake_target(&sec_max_port, "www.apple.com"),
        ("127.0.0.1", 65535)
    );

    for bad_port in ["0", "65536", "-1", "abc", "8443x", "", "   "] {
        let sec = secrets(&[
            ("vless.handshake_server", "127.0.0.1"),
            ("vless.handshake_port", bad_port),
        ]);
        assert_eq!(
            reality_handshake_target(&sec, "www.apple.com"),
            ("127.0.0.1", 443),
            "invalid port {bad_port:?} must fall back to 443 while keeping valid server"
        );
    }

    for bad_server in ["", "   ", "-bad.example.com", "127.0.0.1:8443", "[::1]"] {
        let sec = secrets(&[
            ("vless.handshake_server", bad_server),
            ("vless.handshake_port", "8443"),
        ]);
        assert_eq!(
            reality_handshake_target(&sec, "www.apple.com"),
            ("www.apple.com", 8443),
            "invalid server {bad_server:?} must fall back to sni while keeping valid port"
        );
    }
}

#[test]
fn tls_server_name_returns_trimmed_valid_hostname_or_none_on_invalid_or_absent() {
    assert_eq!(tls_server_name(&HashMap::new()), None);

    let sec_valid = secrets(&[("tls.server_name", "cdn.example.com")]);
    assert_eq!(tls_server_name(&sec_valid), Some("cdn.example.com"));

    let sec_padded = secrets(&[("tls.server_name", " \tcdn.example.com\r\n ")]);
    assert_eq!(tls_server_name(&sec_padded), Some("cdn.example.com"));

    let label_64_host = format!("{}.com", "a".repeat(64));
    let invalid_names = [
        "",
        "   ",
        "127.0.0.1",
        "203.0.113.7",
        "::1",
        "2001:db8::1",
        "-bad.example.com",
        "bad-.example.com",
        "bad_host.example.com",
        "example.com:443",
        label_64_host.as_str(),
    ];
    for name in invalid_names {
        let sec = secrets(&[("tls.server_name", name)]);
        assert_eq!(
            tls_server_name(&sec),
            None,
            "invalid tls.server_name {name:?} must return None"
        );
    }
}

#[test]
fn vless_reality_legacy_secrets_preserve_byte_identical_defaults() {
    let proto = VlessReality::new();
    let server = fixture_server();
    let user = fixture_user();
    let users = std::slice::from_ref(&user);
    let sec = vless_base_secrets();
    let ctx = RenderCtx::new(&server, &sec);

    let inbound = proto.server_inbound(&ctx, users).unwrap();
    assert_eq!(inbound["tls"]["server_name"], json!(DEFAULT_REALITY_SNI));
    assert_eq!(
        inbound["tls"]["reality"]["handshake"]["server"],
        json!(DEFAULT_REALITY_SNI)
    );
    assert_eq!(
        inbound["tls"]["reality"]["handshake"]["server_port"],
        json!(443)
    );

    let client = proto.client_config(&ctx, &user).unwrap();
    assert_eq!(
        client["tls"]["utls"]["fingerprint"],
        json!(DEFAULT_REALITY_FP)
    );

    let link = proto.share_link(&ctx, &user).unwrap();
    let expected_legacy_link = concat!(
        "vless://00000000-0000-0000-0000-000000000001@203.0.113.7:443",
        "?encryption=none&flow=xtls-rprx-vision&security=reality",
        "&sni=yahoo.com&fp=randomized",
        "&pbk=EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE",
        "&sid=0102030405060708&type=tcp&packetEncoding=xudp#alice",
    );
    assert_eq!(link, expected_legacy_link);

    let mut fallback_sec = vless_base_secrets();
    fallback_sec.insert(String::from("vless.fp"), String::from("Chrome"));
    fallback_sec.insert(
        String::from("vless.handshake_server"),
        String::from("bad host"),
    );
    fallback_sec.insert(String::from("vless.handshake_port"), String::from("0"));
    fallback_sec.insert(String::from("tls.server_name"), String::from("127.0.0.1"));
    let fallback_ctx = RenderCtx::new(&server, &fallback_sec);

    let fallback_inbound = proto.server_inbound(&fallback_ctx, users).unwrap();
    let fallback_client = proto.client_config(&fallback_ctx, &user).unwrap();
    assert_eq!(
        serde_json::to_string(&fallback_inbound).unwrap(),
        serde_json::to_string(&inbound).unwrap()
    );
    assert_eq!(
        serde_json::to_string(&fallback_client).unwrap(),
        serde_json::to_string(&client).unwrap()
    );
    assert_eq!(
        proto.share_link(&fallback_ctx, &user).unwrap(),
        expected_legacy_link
    );
}

#[test]
fn vless_reality_uses_chrome_fp_in_client_config_and_share_link() {
    let proto = VlessReality::new();
    let server = fixture_server();
    let user = fixture_user();
    let mut sec = vless_base_secrets();
    sec.insert(
        String::from("vless.sni"),
        String::from(NEW_SERVER_REALITY_SNI),
    );
    sec.insert(
        String::from("vless.fp"),
        String::from(NEW_SERVER_REALITY_FP),
    );
    let ctx = RenderCtx::new(&server, &sec);

    let client = proto.client_config(&ctx, &user).unwrap();
    assert_eq!(client["tls"]["utls"]["fingerprint"], json!("chrome"));

    let link = proto.share_link(&ctx, &user).unwrap();
    let expected_link = concat!(
        "vless://00000000-0000-0000-0000-000000000001@203.0.113.7:443",
        "?encryption=none&flow=xtls-rprx-vision&security=reality",
        "&sni=www.apple.com&fp=chrome",
        "&pbk=EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE",
        "&sid=0102030405060708&type=tcp&packetEncoding=xudp#alice",
    );
    assert_eq!(link, expected_link);
}

#[test]
fn vless_reality_separate_handshake_target_loopback_and_hostname_preserves_sni() {
    let proto = VlessReality::new();
    let server = fixture_server();
    let user = fixture_user();
    let users = std::slice::from_ref(&user);

    let mut base_sec = vless_base_secrets();
    base_sec.insert(String::from("vless.sni"), String::from("www.apple.com"));
    base_sec.insert(String::from("vless.fp"), String::from("chrome"));
    let base_ctx = RenderCtx::new(&server, &base_sec);
    let base_client_json =
        serde_json::to_string(&proto.client_config(&base_ctx, &user).unwrap()).unwrap();
    let base_link = proto.share_link(&base_ctx, &user).unwrap();

    let mut ipv4_sec = base_sec.clone();
    ipv4_sec.insert(
        String::from("vless.handshake_server"),
        String::from("127.0.0.1"),
    );
    ipv4_sec.insert(String::from("vless.handshake_port"), String::from("8443"));
    let ipv4_ctx = RenderCtx::new(&server, &ipv4_sec);
    let ipv4_inbound = proto.server_inbound(&ipv4_ctx, users).unwrap();
    assert_eq!(ipv4_inbound["tls"]["server_name"], json!("www.apple.com"));
    assert_eq!(
        ipv4_inbound["tls"]["reality"]["handshake"]["server"],
        json!("127.0.0.1")
    );
    assert_eq!(
        ipv4_inbound["tls"]["reality"]["handshake"]["server_port"],
        json!(8443)
    );
    assert_eq!(
        serde_json::to_string(&proto.client_config(&ipv4_ctx, &user).unwrap()).unwrap(),
        base_client_json
    );
    assert_eq!(proto.share_link(&ipv4_ctx, &user).unwrap(), base_link);

    let mut host_sec = base_sec.clone();
    host_sec.insert(
        String::from("vless.handshake_server"),
        String::from("decoy.example.com"),
    );
    host_sec.insert(String::from("vless.handshake_port"), String::from("8443"));
    let host_ctx = RenderCtx::new(&server, &host_sec);
    let host_inbound = proto.server_inbound(&host_ctx, users).unwrap();
    assert_eq!(host_inbound["tls"]["server_name"], json!("www.apple.com"));
    assert_eq!(
        host_inbound["tls"]["reality"]["handshake"]["server"],
        json!("decoy.example.com")
    );
    assert_eq!(
        host_inbound["tls"]["reality"]["handshake"]["server_port"],
        json!(8443)
    );

    let mut trimmed_sec = base_sec;
    trimmed_sec.insert(
        String::from("vless.handshake_server"),
        String::from(" 127.0.0.1 "),
    );
    let trimmed_ctx = RenderCtx::new(&server, &trimmed_sec);
    let trimmed_inbound = proto.server_inbound(&trimmed_ctx, users).unwrap();
    assert_eq!(
        trimmed_inbound["tls"]["server_name"],
        json!("www.apple.com")
    );
    assert_eq!(
        trimmed_inbound["tls"]["reality"]["handshake"]["server"],
        json!("127.0.0.1")
    );
    assert_eq!(
        trimmed_inbound["tls"]["reality"]["handshake"]["server_port"],
        json!(443)
    );
}

#[test]
fn vless_xhttp_legacy_defaults_and_chrome_fp_in_client_and_share_link() {
    let proto = VlessXhttp::new();
    let server = fixture_server();
    let user = fixture_user();
    let users = std::slice::from_ref(&user);

    let legacy_sec = vless_xhttp_base_secrets();
    let legacy_ctx = RenderCtx::new(&server, &legacy_sec);
    let legacy_inbound = proto.server_inbound(&legacy_ctx, users).unwrap();
    let legacy_rs = &legacy_inbound["streamSettings"]["realitySettings"];
    assert_eq!(legacy_rs["serverNames"], json!(["yahoo.com"]));
    assert_eq!(legacy_rs["dest"], json!("yahoo.com:443"));

    let legacy_client = proto.client_config(&legacy_ctx, &user).unwrap();
    assert_eq!(
        legacy_client["tls"]["utls"]["fingerprint"],
        json!(DEFAULT_REALITY_FP)
    );
    let expected_legacy_link = concat!(
        "vless://00000000-0000-0000-0000-000000000001@203.0.113.7:9443",
        "?encryption=none&security=reality",
        "&sni=yahoo.com&fp=randomized",
        "&pbk=EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE",
        "&sid=0102030405060708&type=xhttp&path=%2FZq9_path-OK%2F&mode=auto#alice",
    );
    assert_eq!(
        proto.share_link(&legacy_ctx, &user).unwrap(),
        expected_legacy_link
    );

    let mut chrome_sec = vless_xhttp_base_secrets();
    chrome_sec.insert(
        String::from("vless.sni"),
        String::from(NEW_SERVER_REALITY_SNI),
    );
    chrome_sec.insert(
        String::from("vless.fp"),
        String::from(NEW_SERVER_REALITY_FP),
    );
    let chrome_ctx = RenderCtx::new(&server, &chrome_sec);
    let chrome_client = proto.client_config(&chrome_ctx, &user).unwrap();
    assert_eq!(chrome_client["tls"]["utls"]["fingerprint"], json!("chrome"));
    let expected_chrome_link = concat!(
        "vless://00000000-0000-0000-0000-000000000001@203.0.113.7:9443",
        "?encryption=none&security=reality",
        "&sni=www.apple.com&fp=chrome",
        "&pbk=EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE",
        "&sid=0102030405060708&type=xhttp&path=%2FZq9_path-OK%2F&mode=auto#alice",
    );
    assert_eq!(
        proto.share_link(&chrome_ctx, &user).unwrap(),
        expected_chrome_link
    );

    let mut bad_fp_sec = vless_xhttp_base_secrets();
    bad_fp_sec.insert(String::from("vless.fp"), String::from("Chrome"));
    let bad_fp_ctx = RenderCtx::new(&server, &bad_fp_sec);
    let bad_fp_client = proto.client_config(&bad_fp_ctx, &user).unwrap();
    assert_eq!(
        bad_fp_client["tls"]["utls"]["fingerprint"],
        json!(DEFAULT_REALITY_FP)
    );
    assert_eq!(
        proto.share_link(&bad_fp_ctx, &user).unwrap(),
        expected_legacy_link
    );
}

#[test]
fn vless_xhttp_separate_handshake_target_brackets_ipv6_and_preserves_server_names() {
    let proto = VlessXhttp::new();
    let server = fixture_server();
    let user = fixture_user();
    let users = std::slice::from_ref(&user);

    let mut base_sec = vless_xhttp_base_secrets();
    base_sec.insert(String::from("vless.sni"), String::from("www.apple.com"));

    let mut ipv6_sec = base_sec.clone();
    ipv6_sec.insert(String::from("vless.handshake_server"), String::from("::1"));
    ipv6_sec.insert(String::from("vless.handshake_port"), String::from("8443"));
    let ipv6_ctx = RenderCtx::new(&server, &ipv6_sec);
    let ipv6_inbound = proto.server_inbound(&ipv6_ctx, users).unwrap();
    let ipv6_rs = &ipv6_inbound["streamSettings"]["realitySettings"];
    assert_eq!(ipv6_rs["serverNames"], json!(["www.apple.com"]));
    assert_eq!(ipv6_rs["dest"], json!("[::1]:8443"));

    let mut ipv6_def_sec = base_sec.clone();
    ipv6_def_sec.insert(
        String::from("vless.handshake_server"),
        String::from("2001:db8::1"),
    );
    let ipv6_def_ctx = RenderCtx::new(&server, &ipv6_def_sec);
    let ipv6_def_inbound = proto.server_inbound(&ipv6_def_ctx, users).unwrap();
    let ipv6_def_rs = &ipv6_def_inbound["streamSettings"]["realitySettings"];
    assert_eq!(ipv6_def_rs["serverNames"], json!(["www.apple.com"]));
    assert_eq!(ipv6_def_rs["dest"], json!("[2001:db8::1]:443"));

    let mut ipv4_sec = base_sec.clone();
    ipv4_sec.insert(
        String::from("vless.handshake_server"),
        String::from("127.0.0.1"),
    );
    ipv4_sec.insert(String::from("vless.handshake_port"), String::from("8443"));
    let ipv4_ctx = RenderCtx::new(&server, &ipv4_sec);
    let ipv4_inbound = proto.server_inbound(&ipv4_ctx, users).unwrap();
    let ipv4_rs = &ipv4_inbound["streamSettings"]["realitySettings"];
    assert_eq!(ipv4_rs["serverNames"], json!(["www.apple.com"]));
    assert_eq!(ipv4_rs["dest"], json!("127.0.0.1:8443"));

    let mut host_sec = base_sec.clone();
    host_sec.insert(
        String::from("vless.handshake_server"),
        String::from("decoy.example.com"),
    );
    host_sec.insert(String::from("vless.handshake_port"), String::from("8443"));
    let host_ctx = RenderCtx::new(&server, &host_sec);
    let host_inbound = proto.server_inbound(&host_ctx, users).unwrap();
    let host_rs = &host_inbound["streamSettings"]["realitySettings"];
    assert_eq!(host_rs["serverNames"], json!(["www.apple.com"]));
    assert_eq!(host_rs["dest"], json!("decoy.example.com:8443"));

    let mut invalid_sec = base_sec;
    invalid_sec.insert(
        String::from("vless.handshake_server"),
        String::from("[::1]"),
    );
    invalid_sec.insert(String::from("vless.handshake_port"), String::from("0"));
    let invalid_ctx = RenderCtx::new(&server, &invalid_sec);
    let invalid_inbound = proto.server_inbound(&invalid_ctx, users).unwrap();
    let invalid_rs = &invalid_inbound["streamSettings"]["realitySettings"];
    assert_eq!(invalid_rs["serverNames"], json!(["www.apple.com"]));
    assert_eq!(invalid_rs["dest"], json!("www.apple.com:443"));
}

#[test]
fn tuic_v5_emits_valid_tls_server_name_and_omits_when_absent_or_invalid() {
    let proto = TuicV5::new();
    let server = fixture_server();
    let user = fixture_user();

    let base_sec = quic_base_secrets();
    let base_ctx = RenderCtx::new(&server, &base_sec);
    let base_client = proto.client_config(&base_ctx, &user).unwrap();
    assert!(
        base_client["tls"]
            .as_object()
            .unwrap()
            .get("server_name")
            .is_none()
    );
    let base_json = serde_json::to_string(&base_client).unwrap();

    let mut valid_sec = base_sec.clone();
    valid_sec.insert(
        String::from("tls.server_name"),
        String::from("tuic.example.com"),
    );
    let valid_ctx = RenderCtx::new(&server, &valid_sec);
    let valid_client = proto.client_config(&valid_ctx, &user).unwrap();
    assert_eq!(
        valid_client["tls"]["server_name"],
        json!("tuic.example.com")
    );

    let mut padded_sec = base_sec.clone();
    padded_sec.insert(
        String::from("tls.server_name"),
        String::from("  tuic.example.com\n "),
    );
    let padded_ctx = RenderCtx::new(&server, &padded_sec);
    let padded_client = proto.client_config(&padded_ctx, &user).unwrap();
    assert_eq!(
        padded_client["tls"]["server_name"],
        json!("tuic.example.com")
    );
    assert_eq!(
        serde_json::to_string(&padded_client).unwrap(),
        serde_json::to_string(&valid_client).unwrap()
    );

    let invalid_names = [
        "",
        "   ",
        "203.0.113.7",
        "::1",
        "-bad.example.com",
        "bad_host.example.com",
    ];
    for name in invalid_names {
        let mut sec = base_sec.clone();
        sec.insert(String::from("tls.server_name"), String::from(name));
        let ctx = RenderCtx::new(&server, &sec);
        let client = proto.client_config(&ctx, &user).unwrap();
        assert!(
            client["tls"]
                .as_object()
                .unwrap()
                .get("server_name")
                .is_none(),
            "invalid tls.server_name {name:?} must be omitted from TuicV5 client_config"
        );
        assert_eq!(
            serde_json::to_string(&client).unwrap(),
            base_json,
            "invalid tls.server_name {name:?} must preserve legacy TuicV5 bytes"
        );
    }
}

#[test]
fn hysteria2_emits_valid_tls_server_name_and_omits_when_absent_or_invalid() {
    let proto = Hysteria2::new();
    let server = fixture_server();
    let user = fixture_user();

    let base_sec = quic_base_secrets();
    let base_ctx = RenderCtx::new(&server, &base_sec);
    let base_client = proto.client_config(&base_ctx, &user).unwrap();
    assert!(
        base_client["tls"]
            .as_object()
            .unwrap()
            .get("server_name")
            .is_none()
    );
    assert_eq!(base_client["tls"]["enabled"], json!(true));
    assert_eq!(base_client["tls"]["insecure"], json!(false));
    assert_eq!(base_client["tls"]["alpn"], json!(["h3"]));
    let base_json = serde_json::to_string(&base_client).unwrap();

    let mut valid_sec = base_sec.clone();
    valid_sec.insert(
        String::from("tls.server_name"),
        String::from("hy2.example.com"),
    );
    let valid_ctx = RenderCtx::new(&server, &valid_sec);
    let valid_client = proto.client_config(&valid_ctx, &user).unwrap();
    assert_eq!(valid_client["tls"]["server_name"], json!("hy2.example.com"));
    assert_eq!(valid_client["tls"]["enabled"], json!(true));
    assert_eq!(valid_client["tls"]["insecure"], json!(false));
    assert_eq!(valid_client["tls"]["alpn"], json!(["h3"]));

    let mut padded_sec = base_sec.clone();
    padded_sec.insert(
        String::from("tls.server_name"),
        String::from(" \thy2.example.com\r\n "),
    );
    let padded_ctx = RenderCtx::new(&server, &padded_sec);
    let padded_client = proto.client_config(&padded_ctx, &user).unwrap();
    assert_eq!(
        padded_client["tls"]["server_name"],
        json!("hy2.example.com")
    );
    assert_eq!(
        serde_json::to_string(&padded_client).unwrap(),
        serde_json::to_string(&valid_client).unwrap()
    );

    let invalid_names = [
        "",
        "   ",
        "203.0.113.7",
        "::1",
        "-bad.example.com",
        "example.com:443",
    ];
    for name in invalid_names {
        let mut sec = base_sec.clone();
        sec.insert(String::from("tls.server_name"), String::from(name));
        let ctx = RenderCtx::new(&server, &sec);
        let client = proto.client_config(&ctx, &user).unwrap();
        assert!(
            client["tls"]
                .as_object()
                .unwrap()
                .get("server_name")
                .is_none(),
            "invalid tls.server_name {name:?} must be omitted from Hysteria2 client_config"
        );
        assert_eq!(
            serde_json::to_string(&client).unwrap(),
            base_json,
            "invalid tls.server_name {name:?} must preserve legacy Hysteria2 bytes"
        );
    }
}
