#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;
use vpnctl_core::{KernelId, Protocol, ProtocolId, RenderCtx, Server, ServerId, User, UserId};

use super::amnezia::{amnezia_share_link, awg_share_link, qcompress_zlib};
use super::helpers::{WIREGUARD_PORT, is_valid_wg_pubkey};
use super::protocol::WireGuard;

#[test]
fn pubkey_shape_check_accepts_valid_44_char_base64() {
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
    let k = "qXFvJL5KLmM3Of9hVo5GmJ4n0LB9rWYfV4ZE1XGZJksA";
    assert!(!is_valid_wg_pubkey(k));
}

#[test]
fn pubkey_shape_check_rejects_invalid_charset() {
    let k = "qXFvJL5KLmM3Of:hVo5GmJ4n0LB9rWYfV4ZE1XGZJks=";
    assert!(!is_valid_wg_pubkey(k));
}

#[test]
fn appears_in_sing_box_sub_is_false() {
    assert!(
        !WireGuard::new().appears_in_sing_box_sub(),
        "wireguard must opt OUT of the sing-box subscription"
    );
}

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
    assert_eq!(out[4], 0x78, "byte 4 must be zlib CMF magic 0x78");
}

#[test]
fn qcompress_zlib_uses_high_compression_level() {
    use flate2::Compression;
    use flate2::write::ZlibEncoder;
    use std::io::Write;

    let payload = br#"{"containers":[{"container":"amnezia-wireguard","wireguard":{"port":"51820","transport_proto":"udp","subnet_address":"10.66.0.0","last_config":"{\"client_ip\":\"10.66.0.2\",\"hostName\":\"203.0.113.7\",\"port\":51820,\"persistent_keep_alive\":\"25\"}"}}],"defaultContainer":"amnezia-wireguard","description":"test-user","hostName":"203.0.113.7"}"#;

    let our = qcompress_zlib(payload).unwrap();

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

    assert_eq!(v["defaultContainer"], "amnezia-wireguard");
    assert_eq!(v["hostName"], "198.51.100.42");
    assert_eq!(v["description"], "alex");
    assert!(v["containers"].is_array());
    let c0 = &v["containers"][0];
    assert_eq!(c0["container"], "amnezia-wireguard");
    let wg = &c0["wireguard"];
    assert_eq!(wg["transport_proto"], "udp");
    assert_eq!(wg["port"], "51820");
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
    let secrets = HashMap::new();
    let ctx = RenderCtx::new(&server, &secrets);
    let user = fake_user();
    let err = amnezia_share_link(&ctx, &user).unwrap_err();
    assert!(
        format!("{err}").contains("wireguard.server_public_key"),
        "expected MissingSecret(wireguard.server_public_key), got: {err}"
    );
}

fn fake_secrets_awg() -> HashMap<String, String> {
    let mut m = fake_secrets();
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

fn assert_amnezia_export_byte_equal(
    server: &Server,
    secrets: &HashMap<String, String>,
    expected_params: &serde_json::Value,
    expected_ini_params: &str,
) {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let expected_conf = format!(
        concat!(
            "# vpnctl-rendered AmneziaWG client config.\n",
            "# Private key was server-generated for alex — import this file as-is.\n\n",
            "[Interface]\nPrivateKey = 0000000000000000000000000000000000000000000=\n",
            "Address = 10.66.0.2/32\nDNS = 1.1.1.1\n{}\n",
            "[Peer]\nPublicKey = Qhh7nQwL+0fH3iZ8VAEcvVNlEMU8r9SiH3LzAh6Kj3o=\n",
            "Endpoint = 198.51.100.42:51820\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n"
        ),
        expected_ini_params
    );
    let mut expected_last_config = serde_json::json!({
        "config": expected_conf,
        "hostName": "198.51.100.42",
        "port": 51820,
        "client_ip": "10.66.0.2",
        "client_priv_key": "0000000000000000000000000000000000000000000=",
        "client_pub_key": "qXFvJL5KLmM3Of9hVo5GmJ4n0LB9rWYfV4ZE1XGZJks=",
        "server_pub_key": "Qhh7nQwL+0fH3iZ8VAEcvVNlEMU8r9SiH3LzAh6Kj3o=",
        "allowed_ips": ["0.0.0.0/0", "::/0"],
        "persistent_keep_alive": "25",
    });
    expected_last_config
        .as_object_mut()
        .unwrap()
        .extend(expected_params.as_object().unwrap().clone());
    let expected_payload = serde_json::json!({
        "containers": [{
            "container": "amnezia-wireguard",
            "wireguard": {
                "port": "51820",
                "transport_proto": "udp",
                "subnet_address": "10.66.0.0",
                "last_config": serde_json::to_string(&expected_last_config).unwrap(),
            },
        }],
        "defaultContainer": "amnezia-wireguard",
        "description": "alex",
        "dns1": "1.1.1.1",
        "dns2": "1.0.0.1",
        "hostName": "198.51.100.42",
    });
    let expected_bytes = serde_json::to_vec(&expected_payload).unwrap();
    let expected_link = format!(
        "vpn://{}",
        URL_SAFE_NO_PAD.encode(qcompress_zlib(&expected_bytes).unwrap())
    );
    let ctx = RenderCtx::new(server, secrets);
    assert_eq!(
        amnezia_share_link(&ctx, &fake_user()).unwrap().as_bytes(),
        expected_link.as_bytes()
    );
}

#[test]
fn amnezia_plain_wireguard_export_byte_equal() {
    assert_amnezia_export_byte_equal(&fake_server(), &fake_secrets(), &serde_json::json!({}), "");
}

#[test]
fn amnezia_awg_export_byte_equal_with_complete_params() {
    assert_amnezia_export_byte_equal(
        &fake_server(),
        &fake_secrets_awg(),
        &serde_json::json!({
            "Jc": "7", "Jmin": "60", "Jmax": "140", "S1": "30", "S2": "90",
            "H1": "1111111111", "H2": "2022222222", "H3": "333333333", "H4": "444444444",
            "isObfuscationEnabled": true,
        }),
        concat!(
            "Jc = 7\nJmin = 60\nJmax = 140\nS1 = 30\nS2 = 90\n",
            "H1 = 1111111111\nH2 = 2022222222\nH3 = 333333333\nH4 = 444444444\n"
        ),
    );
}

#[test]
fn amnezia_awg_export_byte_equal_with_partial_params() {
    let mut secrets = fake_secrets();
    secrets.insert("amneziawg.h1".into(), "0012345".into());
    assert_amnezia_export_byte_equal(
        &fake_server(),
        &secrets,
        &serde_json::json!({
            "Jc": "4", "Jmin": "40", "Jmax": "70", "S1": "50", "S2": "100",
            "H1": "0012345", "H2": "2", "H3": "3", "H4": "4",
            "isObfuscationEnabled": true,
        }),
        "Jc = 4\nJmin = 40\nJmax = 70\nS1 = 50\nS2 = 100\nH1 = 0012345\nH2 = 2\nH3 = 3\nH4 = 4\n",
    );
}

#[test]
fn amnezia_awg_export_byte_equal_with_kernel_defaults() {
    let mut server = fake_server();
    server.kernels = vec![KernelId("amneziawg".into())];
    assert_amnezia_export_byte_equal(
        &server,
        &fake_secrets(),
        &serde_json::json!({
            "Jc": "4", "Jmin": "40", "Jmax": "70", "S1": "50", "S2": "100",
            "H1": "1", "H2": "2", "H3": "3", "H4": "4",
            "isObfuscationEnabled": true,
        }),
        "Jc = 4\nJmin = 40\nJmax = 70\nS1 = 50\nS2 = 100\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\n",
    );
}

#[test]
fn complete_awg_client_outputs_stay_byte_equal() {
    let server = fake_server();
    let secrets = fake_secrets_awg();
    let ctx = RenderCtx::new(&server, &secrets);
    let user = fake_user();
    let expected_link = concat!(
        "awg://Qhh7nQwL+0fH3iZ8VAEcvVNlEMU8r9SiH3LzAh6Kj3o=@198.51.100.42:51820?",
        "private_key=0000000000000000000000000000000000000000000=",
        "&address=10.66.0.2/32&keepalive=25&jc=7&jmin=60&jmax=140",
        "&s1=30&s2=90&s3=0&s4=0&h1=1111111111&h2=2022222222&h3=333333333&h4=444444444#alex"
    );
    assert_eq!(
        awg_share_link(&ctx, &user).unwrap().as_bytes(),
        expected_link.as_bytes()
    );
    let expected_conf = concat!(
        "# vpnctl-rendered AmneziaWG client config.\n",
        "# Private key was server-generated for alex — import this file as-is.\n\n",
        "[Interface]\nPrivateKey = 0000000000000000000000000000000000000000000=\n",
        "Address = 10.66.0.2/32\nDNS = 1.1.1.1\n",
        "Jc = 7\nJmin = 60\nJmax = 140\nS1 = 30\nS2 = 90\n",
        "H1 = 1111111111\nH2 = 2022222222\nH3 = 333333333\nH4 = 444444444\n\n",
        "[Peer]\nPublicKey = Qhh7nQwL+0fH3iZ8VAEcvVNlEMU8r9SiH3LzAh6Kj3o=\n",
        "Endpoint = 198.51.100.42:51820\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n"
    );
    assert_eq!(
        super::render::render_client_conf(&ctx, &user)
            .unwrap()
            .as_bytes(),
        expected_conf.as_bytes()
    );
    let expected_json = serde_json::json!({
        "type": "wireguard",
        "interface": {
            "private_key": "0000000000000000000000000000000000000000000=",
            "address_cidr": "10.66.0.2/32", "dns": ["1.1.1.1"],
            "amneziawg": {
                "jc": "7", "jmin": "60", "jmax": "140", "s1": "30", "s2": "90",
                "h1": "1111111111", "h2": "2022222222", "h3": "333333333", "h4": "444444444"
            }
        },
        "peer": {
            "public_key": "Qhh7nQwL+0fH3iZ8VAEcvVNlEMU8r9SiH3LzAh6Kj3o=",
            "endpoint": "198.51.100.42:51820", "allowed_ips": "0.0.0.0/0,::/0",
            "persistent_keepalive": 25
        }
    });
    assert_eq!(
        serde_json::to_vec(&WireGuard::new().client_config(&ctx, &user).unwrap()).unwrap(),
        serde_json::to_vec(&expected_json).unwrap()
    );
}

#[test]
fn awg_share_link_matches_operator_schema() {
    let server = fake_server();
    let secrets = fake_secrets_awg();
    let ctx = RenderCtx::new(&server, &secrets);
    let user = fake_user();
    let link = awg_share_link(&ctx, &user).unwrap();

    assert!(link.starts_with("awg://"), "scheme: {link}");
    assert!(
        link.contains(&format!(
            "awg://{}@198.51.100.42:51820?",
            secrets["wireguard.server_public_key"]
        )),
        "userinfo/host/port wrong: {link}"
    );
    assert!(link.contains(&format!(
        "private_key={}",
        user.wireguard_private.as_deref().unwrap()
    )));
    assert!(link.contains("address=10.66.0.2/32"));
    assert!(link.contains("keepalive=25"));
    assert!(link.contains("jc=7"));
    assert!(link.contains("jmin=60"));
    assert!(link.contains("jmax=140"));
    assert!(link.contains("s1=30"));
    assert!(link.contains("s2=90"));
    assert!(link.contains("s3=0"));
    assert!(link.contains("s4=0"));
    assert!(link.contains("h1=1111111111"));
    assert!(link.contains("h4=444444444"));
    assert!(link.ends_with("#alex"), "fragment: {link}");
}

#[test]
fn awg_share_link_errors_without_server_generated_private_key() {
    let server = fake_server();
    let secrets = fake_secrets_awg();
    let ctx = RenderCtx::new(&server, &secrets);
    let mut user = fake_user();
    user.wireguard_private = None;
    let err = awg_share_link(&ctx, &user).unwrap_err();
    assert!(
        format!("{err}").contains("no server-generated wireguard private key"),
        "wrong error: {err}"
    );
}

#[test]
fn awg_share_link_errors_without_obfs_secrets() {
    let server = fake_server();
    let secrets = fake_secrets();
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

#[test]
fn client_config_derives_peer_address_from_ctx_peers() {
    let server = fake_server();
    let secrets = fake_secrets();
    let mut u1 = fake_user();
    u1.id = UserId("alex".into());
    let mut u2 = fake_user();
    u2.id = UserId("brian".into());
    let mut u3 = fake_user();
    u3.id = UserId("clara".into());

    let peers = vec![u1.clone(), u2.clone(), u3.clone()];
    let ctx = RenderCtx::with_peers(&server, &secrets, &peers);
    let p = WireGuard::new();

    let cfg1 = p.client_config(&ctx, &u1).unwrap();
    assert_eq!(
        cfg1.pointer("/interface/address_cidr")
            .and_then(serde_json::Value::as_str),
        Some("10.66.0.2/32"),
        "1st peer gets 10.66.0.2/32"
    );

    let cfg2 = p.client_config(&ctx, &u2).unwrap();
    assert_eq!(
        cfg2.pointer("/interface/address_cidr")
            .and_then(serde_json::Value::as_str),
        Some("10.66.0.3/32"),
        "2nd peer gets 10.66.0.3/32"
    );

    let cfg3 = p.client_config(&ctx, &u3).unwrap();
    assert_eq!(
        cfg3.pointer("/interface/address_cidr")
            .and_then(serde_json::Value::as_str),
        Some("10.66.0.4/32"),
        "3rd peer gets 10.66.0.4/32"
    );
}

#[test]
fn client_config_missing_from_non_empty_peers_returns_error() {
    let server = fake_server();
    let secrets = fake_secrets();
    let u1 = fake_user();
    let mut u2 = fake_user();
    u2.id = UserId("stranger".into());

    let peers = [u1];
    let ctx = RenderCtx::with_peers(&server, &secrets, &peers);
    let err = WireGuard::new().client_config(&ctx, &u2).unwrap_err();
    assert!(
        matches!(err, vpnctl_core::CoreError::Render(_)),
        "expected CoreError::Render, got {err:?}"
    );
}

#[test]
fn client_config_empty_peers_fallback_returns_base_address() {
    let server = fake_server();
    let secrets = fake_secrets();
    let u = fake_user();
    let ctx = RenderCtx::new(&server, &secrets);
    let cfg = WireGuard::new().client_config(&ctx, &u).unwrap();
    assert_eq!(
        cfg.pointer("/interface/address_cidr")
            .and_then(serde_json::Value::as_str),
        Some("10.66.0.2/32")
    );
}
