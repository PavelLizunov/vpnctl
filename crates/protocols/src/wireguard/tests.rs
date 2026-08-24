#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;
use vpnctl_core::{KernelId, Protocol, ProtocolId, RenderCtx, Server, ServerId, User, UserId};

use super::amnezia::{amnezia_share_link, awg_share_link, qcompress_zlib};
use super::helpers::{WIREGUARD_PORT, is_valid_wg_pubkey};
use super::protocol::WireGuard;

#[test]
fn pubkey_shape_check_accepts_valid_44_char_base64() {
    // Real-looking WG pubkey shape: 43 base64 + final '='.
    let k = "qXFvJL5KLmM3Of9hVo5GmJ4n0LB9rWYfV4ZE1XGZJks=";
    assert!(is_valid_wg_pubkey(k));
}

#[test]
fn pubkey_shape_check_rejects_wrong_length() {
    assert!(!is_valid_wg_pubkey("too-short="));
    assert!(!is_valid_wg_pubkey(&"x".repeat(43)));
    assert!(!is_valid_wg_pubkey(&"x".repeat(45)));
}

#[test]
fn pubkey_shape_check_requires_trailing_eq_pad() {
    // Right length, wrong padding.
    let k = "qXFvJL5KLmM3Of9hVo5GmJ4n0LB9rWYfV4ZE1XGZJksA";
    assert!(!is_valid_wg_pubkey(k));
}

#[test]
fn pubkey_shape_check_rejects_invalid_charset() {
    // Right length+padding but contains a `:` (not base64-alphabet).
    let k = "qXFvJL5KLmM3Of:hVo5GmJ4n0LB9rWYfV4ZE1XGZJks=";
    assert!(!is_valid_wg_pubkey(k));
}

#[test]
fn appears_in_sing_box_sub_is_false() {
    // CRITICAL: WireGuard's `client_config()` is an internal
    // `{ type: "wireguard", interface, peer }` object, NOT a valid
    // sing-box outbound. If the /sub handler doesn't skip it, the
    // whole envelope becomes unparseable and Hiddify / sing-box
    // drops every route (including the legit VLESS / TUIC ones).
    // Pin the trait override (same contract as wgturn / dns-tunnel).
    assert!(
        !WireGuard::new().appears_in_sing_box_sub(),
        "wireguard must opt OUT of the sing-box subscription"
    );
}

// ── AmneziaVPN deep-link tests ─────────────────────────────────
//
// Pin the byte-format invariants Amnezia's parser depends on:
//   * `vpn://` prefix exactly,
//   * base64-url (NO trailing `=` padding),
//   * qCompress envelope = 4-byte BE length + zlib stream,
//   * round-trip decoded JSON must contain a single container
//     `amnezia-wireguard` with the user's WG material accessible
//     under `containers[0].wireguard.last_config` (itself a
//     JSON-stringified object).

/// `effective_listen_ports` must resolve the per-server
/// `wireguard.listen_port` override with the SAME semantics as the
/// inbound renderer — guard/drift/firewall see the port wg-quick
/// actually binds (PR #139 review finding 2).
#[test]
fn effective_listen_ports_honours_override() {
    let p = WireGuard::new();
    assert_eq!(
        p.effective_listen_ports(&HashMap::new()),
        vec![("udp", WIREGUARD_PORT)]
    );
    let mut overridden = HashMap::new();
    overridden.insert("wireguard.listen_port".into(), "52820".into());
    assert_eq!(p.effective_listen_ports(&overridden), vec![("udp", 52820)]);
    // unparsable or zero → default (identical to the inbound renderer)
    for bad in ["junk", "0", "", "-1", "65536"] {
        let mut s = HashMap::new();
        s.insert("wireguard.listen_port".into(), bad.into());
        assert_eq!(
            p.effective_listen_ports(&s),
            vec![("udp", WIREGUARD_PORT)],
            "bad override {bad:?}"
        );
    }
}

fn fake_user() -> User {
    User {
        id: UserId("alex".into()),
        uuid: "11111111-1111-1111-1111-111111111111".into(),
        tuic_password: None,
        wireguard_pubkey: Some("qXFvJL5KLmM3Of9hVo5GmJ4n0LB9rWYfV4ZE1XGZJks=".into()),
        wireguard_private: Some("0000000000000000000000000000000000000000000=".into()),
        sub_token: Some("st".into()),
        vpn_router_device_id: None,
        disabled: false,
    }
}

fn fake_server() -> Server {
    Server {
        id: ServerId("vps1".into()),
        address: "198.51.100.42".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("wireguard".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

fn fake_secrets() -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert(
        "wireguard.server_public_key".into(),
        "Qhh7nQwL+0fH3iZ8VAEcvVNlEMU8r9SiH3LzAh6Kj3o=".into(),
    );
    m
}

#[test]
fn qcompress_zlib_emits_4byte_be_length_prefix() {
    let data = b"hello amnezia";
    let out = qcompress_zlib(data).unwrap();
    assert!(out.len() >= 4);
    let len_prefix = u32::from_be_bytes([out[0], out[1], out[2], out[3]]);
    assert_eq!(len_prefix as usize, data.len());
    // Zlib stream starts with 0x78 (CMF) — every qCompress output
    // does, regardless of level. Pin it so a future swap of the
    // backend (deflate-rs etc) that emits raw-deflate instead of
    // zlib silently breaks Amnezia parsing.
    assert_eq!(out[4], 0x78, "byte 4 must be zlib CMF magic 0x78");
}

/// Pin compression level 8 by comparing it to level 1 on the SAME
/// non-trivial payload (a JSON-like blob where the level actually
/// matters — pure repetition compresses identically at every
/// level via RLE). If a future refactor drops to `Compression::fast()`,
/// level-1 output will be ≥ level-8 output and this test fires.
#[test]
fn qcompress_zlib_uses_high_compression_level() {
    use flate2::Compression;
    use flate2::write::ZlibEncoder;
    use std::io::Write;

    // Mixed text — enough variation that the encoder's match finder
    // has work to do; level 8 (full lazy matching) beats level 1
    // (greedy) by several bytes on this shape.
    let payload = br#"{"containers":[{"container":"amnezia-wireguard","wireguard":{"port":"51820","transport_proto":"udp","subnet_address":"10.66.0.0","last_config":"{\"client_ip\":\"10.66.0.2\",\"hostName\":\"203.0.113.7\",\"port\":51820,\"persistent_keep_alive\":\"25\"}"}}],"defaultContainer":"amnezia-wireguard","description":"test-user","hostName":"203.0.113.7"}"#;

    let our = qcompress_zlib(payload).unwrap();

    // Reference: same payload, level 1 (Compression::fast()).
    let mut fast_out = Vec::new();
    fast_out.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    let mut enc = ZlibEncoder::new(&mut fast_out, Compression::fast());
    enc.write_all(payload).unwrap();
    enc.finish().unwrap();

    assert!(
        our.len() <= fast_out.len(),
        "qcompress_zlib (claimed level 8) produced {} bytes; level-1 reference produced {}. Level 8 must be at least as compact as level 1.",
        our.len(),
        fast_out.len()
    );
    // Also confirm a non-trivial savings (>= 4 bytes) so the
    // test catches "we switched to default(level=6)" — default
    // compression is within 1-2 bytes of fast() on this size.
    assert!(
        our.len() + 4 <= fast_out.len(),
        "level-8 output {} bytes vs level-1 {} — savings <4 bytes suggests level was dropped below 8",
        our.len(),
        fast_out.len()
    );
}

#[test]
fn amnezia_share_link_starts_with_vpn_prefix_and_is_base64url_no_pad() {
    let server = fake_server();
    let secrets = fake_secrets();
    let ctx = RenderCtx::new(&server, &secrets);
    let user = fake_user();
    let link = amnezia_share_link(&ctx, &user).unwrap();
    assert!(link.starts_with("vpn://"), "wrong scheme prefix: {link:?}");
    let payload = link.strip_prefix("vpn://").unwrap();
    assert!(
        !payload.ends_with('='),
        "Amnezia parser requires base64-url WITHOUT padding (OmitTrailingEquals): {payload:?}"
    );
    // base64url alphabet only — `+`/`/` would fail Amnezia's
    // `Base64UrlEncoding` decode.
    for c in payload.chars() {
        assert!(
            c.is_ascii_alphanumeric() || c == '-' || c == '_',
            "non-base64url char {c:?} in payload"
        );
    }
}

#[test]
fn amnezia_share_link_roundtrips_to_container_json_with_last_config() {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use flate2::read::ZlibDecoder;
    use std::io::Read;

    let server = fake_server();
    let secrets = fake_secrets();
    let ctx = RenderCtx::new(&server, &secrets);
    let user = fake_user();
    let link = amnezia_share_link(&ctx, &user).unwrap();
    let b64 = link.strip_prefix("vpn://").unwrap();
    let raw = URL_SAFE_NO_PAD.decode(b64).unwrap();
    assert!(
        raw.len() > 4,
        "envelope must include the 4-byte length prefix"
    );
    let _len_prefix = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let mut dec = ZlibDecoder::new(&raw[4..]);
    let mut json_bytes = Vec::new();
    dec.read_to_end(&mut json_bytes).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&json_bytes).unwrap();

    // Top-level shape Amnezia's importer reads.
    assert_eq!(v["defaultContainer"], "amnezia-wireguard");
    assert_eq!(v["hostName"], "198.51.100.42");
    assert_eq!(v["description"], "alex");
    assert!(v["containers"].is_array());
    let c0 = &v["containers"][0];
    assert_eq!(c0["container"], "amnezia-wireguard");
    let wg = &c0["wireguard"];
    assert_eq!(wg["transport_proto"], "udp");
    assert_eq!(wg["port"], "51820");
    // `last_config` is a JSON-stringified inner object — Amnezia
    // re-parses it from string. Pin both the stringification AND
    // the inner field names.
    let inner_str = wg["last_config"]
        .as_str()
        .expect("last_config must be a string");
    let inner: serde_json::Value = serde_json::from_str(inner_str).unwrap();
    assert_eq!(
        inner["client_pub_key"],
        user.wireguard_pubkey.as_deref().unwrap()
    );
    assert_eq!(
        inner["client_priv_key"],
        user.wireguard_private.as_deref().unwrap()
    );
    assert_eq!(
        inner["server_pub_key"],
        secrets["wireguard.server_public_key"]
    );
    assert_eq!(inner["client_ip"], "10.66.0.2");
    assert_eq!(inner["port"], 51820);
    assert_eq!(inner["hostName"], "198.51.100.42");
    assert_eq!(
        inner["allowed_ips"],
        serde_json::json!(["0.0.0.0/0", "::/0"])
    );
    // The `config` field carries the full .conf body (Interface+Peer).
    let conf = inner["config"]
        .as_str()
        .expect("inner config must be a string");
    assert!(conf.contains("[Interface]"));
    assert!(conf.contains("[Peer]"));
    assert!(conf.contains("Endpoint = 198.51.100.42:51820"));
}

#[test]
fn amnezia_share_link_errors_on_missing_user_wireguard_pubkey() {
    let server = fake_server();
    let secrets = fake_secrets();
    let ctx = RenderCtx::new(&server, &secrets);
    let mut user = fake_user();
    user.wireguard_pubkey = None;
    let err = amnezia_share_link(&ctx, &user).unwrap_err();
    assert!(
        format!("{err}").contains("no wireguard_pubkey"),
        "wrong error: {err}"
    );
}

#[test]
fn amnezia_share_link_errors_on_missing_server_pubkey_secret() {
    let server = fake_server();
    let secrets = HashMap::new(); // missing wireguard.server_public_key
    let ctx = RenderCtx::new(&server, &secrets);
    let user = fake_user();
    let err = amnezia_share_link(&ctx, &user).unwrap_err();
    assert!(
        format!("{err}").contains("wireguard.server_public_key"),
        "expected MissingSecret(wireguard.server_public_key), got: {err}"
    );
}

// ── awg:// share-link (Flow D — sing-box-lx client app) ────────

fn fake_secrets_awg() -> HashMap<String, String> {
    let mut m = fake_secrets(); // wireguard.server_public_key
    for (k, v) in [
        ("jc", "7"),
        ("jmin", "60"),
        ("jmax", "140"),
        ("s1", "30"),
        ("s2", "90"),
        ("h1", "1111111111"),
        ("h2", "2022222222"),
        ("h3", "333333333"),
        ("h4", "444444444"),
    ] {
        m.insert(format!("amneziawg.{k}"), v.into());
    }
    m
}

#[test]
fn awg_share_link_matches_operator_schema() {
    let server = fake_server();
    let secrets = fake_secrets_awg();
    let ctx = RenderCtx::new(&server, &secrets);
    let user = fake_user();
    let link = awg_share_link(&ctx, &user).unwrap();

    // scheme + userinfo(server pubkey) @ host:port
    assert!(link.starts_with("awg://"), "scheme: {link}");
    assert!(
        link.contains(&format!(
            "awg://{}@198.51.100.42:51820?",
            secrets["wireguard.server_public_key"]
        )),
        "userinfo/host/port wrong: {link}"
    );
    // client private key = the server-generated one
    assert!(link.contains(&format!(
        "private_key={}",
        user.wireguard_private.as_deref().unwrap()
    )));
    assert!(link.contains("address=10.66.0.2/32"));
    assert!(link.contains("keepalive=25"));
    // obfs verbatim from secrets
    assert!(link.contains("jc=7"));
    assert!(link.contains("jmin=60"));
    assert!(link.contains("jmax=140"));
    assert!(link.contains("s1=30"));
    assert!(link.contains("s2=90"));
    // s3/s4 ALWAYS 0 (1.x server — bidirectional, unused server-side)
    assert!(link.contains("s3=0"));
    assert!(link.contains("s4=0"));
    assert!(link.contains("h1=1111111111"));
    assert!(link.contains("h4=444444444"));
    // fragment = user id
    assert!(link.ends_with("#alex"), "fragment: {link}");
}

#[test]
fn awg_share_link_errors_without_server_generated_private_key() {
    let server = fake_server();
    let secrets = fake_secrets_awg();
    let ctx = RenderCtx::new(&server, &secrets);
    let mut user = fake_user();
    user.wireguard_private = None; // operator-provided-pubkey path
    let err = awg_share_link(&ctx, &user).unwrap_err();
    assert!(
        format!("{err}").contains("no server-generated wireguard private key"),
        "wrong error: {err}"
    );
}

#[test]
fn awg_share_link_errors_without_obfs_secrets() {
    // No amneziawg.* minted (e.g. a vanilla wg server) → hard error;
    // an awg:// link only makes sense for an AmneziaWG node.
    let server = fake_server();
    let secrets = fake_secrets(); // server pubkey only, no obfs
    let ctx = RenderCtx::new(&server, &secrets);
    let user = fake_user();
    let err = awg_share_link(&ctx, &user).unwrap_err();
    assert!(
        format!("{err}").contains("obfuscation params"),
        "wrong error: {err}"
    );
}

#[test]
fn awg_share_link_emits_base64_key_verbatim() {
    // The operator's schema places the standard-base64 private key RAW
    // in the query value; their sing-box-lx app parses values verbatim
    // (NOT application/x-www-form-urlencoded, under which `+` → space).
    // Pin verbatim emission of a key containing `+` and `/` so a future
    // percent-encoding change is a deliberate, test-breaking decision.
    let server = fake_server();
    let secrets = fake_secrets_awg();
    let ctx = RenderCtx::new(&server, &secrets);
    let mut user = fake_user();
    let key = "ab+CD/ef+GH/ijKLmnopQRSTuvwx0123456789ABCxz=";
    user.wireguard_private = Some(key.into());
    let link = awg_share_link(&ctx, &user).unwrap();
    assert!(
        link.contains(&format!("private_key={key}")),
        "private key must be emitted verbatim (raw +,/,= — not url-encoded): {link}"
    );
}
