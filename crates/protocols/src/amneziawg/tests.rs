use super::*;
use std::collections::HashMap;
use vpnctl_core::{Server, ServerId, UserId};

fn user(id: &str, prefix: u16) -> User {
    let mut key = [7; 32];
    key[..2].copy_from_slice(&prefix.to_be_bytes());
    User {
        id: UserId(id.into()),
        uuid: "test-uuid".into(),
        tuic_password: None,
        wireguard_pubkey: Some(STANDARD.encode(key)),
        wireguard_private: Some(STANDARD.encode([9; 32])),
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    }
}

fn server() -> Server {
    Server {
        id: ServerId("test".into()),
        address: "2001:db8::1".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![],
        enabled_protocols: vec![],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

fn secrets() -> HashMap<String, String> {
    let mut secrets = HashMap::new();
    for version in [V2, V3] {
        secrets.insert(version.private_key.into(), STANDARD.encode([3; 32]));
        secrets.insert(version.public_key.into(), STANDARD.encode([4; 32]));
        secrets.insert(version.profile_seed.into(), STANDARD.encode([5; 32]));
    }
    secrets.insert(HEADER_KEY.into(), STANDARD.encode([6; 32]));
    secrets
}

#[test]
fn deterministic_shared_profiles_and_native_conf_encodings() {
    let server = server();
    let secrets = secrets();
    let users = [user("alice", 256), user("bob", 512)];
    let ctx = RenderCtx::with_peers(&server, &secrets, &users);
    for version in [V2, V3] {
        let inbound = server_endpoint(version, &ctx, &users).unwrap();
        let outbound = client_endpoint(version, &ctx, &users[0]).unwrap();
        let conf = render_amnezia_conf(version.number, &ctx, &users[0]).unwrap();
        assert_eq!(inbound, server_endpoint(version, &ctx, &users).unwrap());
        assert_eq!(inbound["listen_port"], version.port);
        assert_eq!(outbound["address"], json!(peer_cidrs(version, 258)));
        assert_eq!(outbound["address"], inbound["peers"][0]["allowed_ips"]);
        assert_eq!(
            outbound["peers"][0]["allowed_ips"],
            json!(["0.0.0.0/0", "::/0"])
        );
        assert!(conf.contains("AllowedIPs = 0.0.0.0/0, ::/0\n"));
        assert!(outbound.get("listen_port").is_none());
        assert!(conf.contains(&format!("Endpoint = [2001:db8::1]:{}", version.port)));
        let mut previous_end = 0_u32;
        for name in ["h1", "h2", "h3", "h4"] {
            let (start, end) = inbound[name].as_str().unwrap().split_once('-').unwrap();
            let start: u32 = start.parse().unwrap();
            let end: u32 = end.parse().unwrap();
            assert!(previous_end < start && start < end);
            previous_end = end;
        }
        for (name, _, _) in parameters(version, &ctx).unwrap() {
            assert_eq!(inbound[name], outbound[name]);
        }
        if version.number == 3 {
            assert_eq!(inbound["header_protection_key"], "06".repeat(32));
            assert!(conf.contains(&format!(
                "HeaderProtectionKey = {}\n",
                STANDARD.encode([6; 32])
            )));
            assert!(conf.contains("RandomTrailers = on\nDisableCookies = on\n"));
            assert!(conf.contains("ContentPaddingAddition = 0-32\n"));
            assert!(conf.contains("AmneziaWG 3.1"));
            for name in ["s1", "s2", "s3", "s4"] {
                assert_eq!(inbound[name], inbound["s1"]);
            }
        } else {
            for name in [
                "header_protection_key",
                "random_trailers",
                "disable_cookies",
                "content_padding_addition",
            ] {
                assert!(inbound.get(name).is_none());
                assert!(outbound.get(name).is_none());
            }
            assert!(!conf.contains("HeaderProtectionKey"));
            assert!(!conf.contains("RandomTrailers"));
        }
        assert!(inbound.get("rekey_after_time").is_none());
        assert!(!conf.contains("RekeyAfterTime"));
    }
}

#[test]
fn addresses_survive_peer_reorder_removal_and_addition() {
    let server = server();
    let secrets = secrets();
    let alice = user("alice", 65535);
    let sets = [
        vec![alice.clone()],
        vec![user("bob", 42), alice.clone()],
        vec![alice.clone(), user("carol", 91)],
    ];
    for peers in sets {
        let ctx = RenderCtx::with_peers(&server, &secrets, &peers);
        for (version, expected) in [
            (V2, json!(["10.72.0.4/32", "fd72:72::4/128"])),
            (V3, json!(["10.73.0.4/32", "fd73:73::4/128"])),
        ] {
            assert_eq!(
                client_endpoint(version, &ctx, &alice).unwrap()["address"],
                expected
            );
        }
    }
}

#[test]
fn invalid_and_ambiguous_peers_fail_closed() {
    let server = server();
    let secrets = secrets();
    let alice = user("alice", 42);
    let mut duplicate_key = alice.clone();
    duplicate_key.id = UserId("other".into());
    let mut colliding = user("other", 42);
    colliding.wireguard_pubkey = Some(STANDARD.encode({
        let mut key = [8; 32];
        key[..2].copy_from_slice(&42_u16.to_be_bytes());
        key
    }));
    for peers in [
        vec![],
        vec![user("bob", 22)],
        vec![alice.clone(), alice.clone()],
        vec![alice.clone(), duplicate_key],
        vec![alice.clone(), colliding],
    ] {
        let ctx = RenderCtx::with_peers(&server, &secrets, &peers);
        assert!(client_endpoint(V2, &ctx, &alice).is_err());
        if peers.len() > 1 {
            assert!(server_endpoint(V2, &ctx, &peers).is_err());
        }
    }
    let mut disabled = alice.clone();
    disabled.disabled = true;
    disabled.wireguard_pubkey = None;
    let peers = [disabled.clone()];
    let ctx = RenderCtx::with_peers(&server, &secrets, &peers);
    assert!(
        server_endpoint(V3, &ctx, &peers).unwrap()["peers"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(client_endpoint(V3, &ctx, &disabled).is_err());
    let peers = [alice.clone()];
    let ctx = RenderCtx::with_peers(&server, &secrets, &peers);
    let mut no_private = alice.clone();
    no_private.wireguard_private = None;
    assert!(client_endpoint(V3, &ctx, &no_private).is_err());
    let mut no_public = alice.clone();
    no_public.wireguard_pubkey = None;
    assert!(client_endpoint(V3, &ctx, &no_public).is_err());
    assert!(render_amnezia_conf(1, &ctx, &alice).is_err());
    assert!(
        AmneziaWg2::new()
            .share_link(&ctx, &alice)
            .unwrap_err()
            .to_string()
            .contains(".conf")
    );
}

#[test]
fn strict_base64_rejects_noncanonical_and_zero_keys_without_echo() {
    for value in [
        STANDARD.encode([0; 32]),
        STANDARD.encode([1; 31]),
        STANDARD.encode([1; 33]),
        "SENSITIVE\nPrivateKey = injection".into(),
        format!("{}B=", "A".repeat(42)),
        "A".repeat(43),
    ] {
        let error = decode_32(&value, true).unwrap_err().to_string();
        assert!(!error.contains(&value));
    }
    assert!(decode_32(&STANDARD.encode([0; 32]), false).is_ok());
}

#[test]
fn all_public_renderers_reject_malformed_secret_material() {
    let server = server();
    let peers = [user("alice", 23)];
    for version in [V2, V3] {
        let protocol: &dyn Protocol = if version.number == 2 {
            &AmneziaWg2
        } else {
            &AmneziaWg3
        };
        assert_eq!(protocol.id().0, version.id);
        assert_eq!(protocol.listen_ports(), &[("udp", version.port)]);
        assert!(!protocol.appears_in_sing_box_sub());
        assert!(!protocol.appears_in_stock_sing_box_sub());
        assert_eq!(protocol.server_secret_specs(), secret_specs(version));
        for key in [version.public_key, version.profile_seed, HEADER_KEY] {
            if key == HEADER_KEY && version.number == 2 {
                continue;
            }
            let mut secrets = secrets();
            secrets.insert(key.into(), "DO_NOT_ECHO\nInjected = yes".into());
            let ctx = RenderCtx::with_peers(&server, &secrets, &peers);
            let results = [
                protocol.server_inbound(&ctx, &peers),
                protocol.client_config(&ctx, &peers[0]),
            ];
            for result in results {
                assert!(!result.unwrap_err().to_string().contains("DO_NOT_ECHO"));
            }
            assert!(
                !render_amnezia_conf(version.number, &ctx, &peers[0])
                    .unwrap_err()
                    .to_string()
                    .contains("DO_NOT_ECHO")
            );
        }
        let mut secrets = secrets();
        secrets.insert(version.private_key.into(), STANDARD.encode([0; 32]));
        let ctx = RenderCtx::with_peers(&server, &secrets, &peers);
        assert!(protocol.server_inbound(&ctx, &peers).is_err());
    }
    let mut server = server;
    server.address = "host\nPostUp = evil".into();
    let secrets = secrets();
    let ctx = RenderCtx::with_peers(&server, &secrets, &peers);
    assert!(AmneziaWg2.client_config(&ctx, &peers[0]).is_err());
    assert!(render_amnezia_conf(3, &ctx, &peers[0]).is_err());
}

#[test]
fn host_validation_blocks_conf_injection() {
    for host in [
        "203.0.113.1",
        "2001:db8::1",
        "vpn.example.org",
        "vpn.example.org.",
        "localhost",
    ] {
        assert!(validate_host(host).is_ok(), "{host}");
    }
    for host in [
        "",
        "host\n[Peer]",
        "host\r",
        "host\0",
        "host:51821",
        "https://host",
        "bad_host",
        "-host",
        "host..org",
        "999.1.1.1",
        "[2001:db8::1]",
        "host #comment",
    ] {
        assert!(validate_host(host).is_err(), "{host}");
    }
}

#[test]
fn many_seeds_preserve_padding_and_junk_constraints() {
    let server = server();
    for byte in 0..=255_u8 {
        let mut secrets = secrets();
        for version in [V2, V3] {
            let seed = std::array::from_fn::<_, 32, _>(|i| byte.wrapping_add(i as u8));
            secrets.insert(version.profile_seed.into(), STANDARD.encode(seed));
            let ctx = RenderCtx::new(&server, &secrets);
            let config = server_endpoint(version, &ctx, &[]).unwrap();
            assert_ne!(
                config["s1"].as_u64().unwrap() + 148,
                config["s2"].as_u64().unwrap() + 92
            );
            assert!(config["jmin"].as_u64().unwrap() <= config["jmax"].as_u64().unwrap());
            for name in ["s1", "s2", "s3", "s4"] {
                assert!(config[name].as_u64().unwrap() >= 12);
            }
        }
    }
}
