//! Implementation-blind acceptance tests for the supplied AWG 2.0 / 3.1 contract.
//! Synthetic keys are canonical base64, not cryptographically related keypairs:
//! checking the private/public relation is explicitly outside this contract.
//! AWG JSON options use exact flat endpoint keys. Interface addresses use /32
//! and /128 within version-specific IPv4 /16 and IPv6 /64 allocation pools.
//! These are renderer contract checks, not runtime import or leak validation.

#[allow(clippy::unwrap_used, clippy::expect_used)]
mod spec {
    use std::collections::{BTreeMap, BTreeSet, HashMap};

    use base64::Engine;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use serde_json::{Value, json};
    use vpnctl_core::{
        KernelId, Protocol, ProtocolId, RenderCtx, Server, ServerId, ServerSecretSpec, User, UserId,
    };
    use vpnctl_protocols::{AmneziaWg2, AmneziaWg3, render_amnezia_conf};

    fn protocol(version: u8) -> Box<dyn Protocol> {
        if version == 2 {
            Box::new(AmneziaWg2::new())
        } else {
            assert_eq!(version, 3, "test fixture supports only specified versions");
            Box::new(AmneziaWg3::new())
        }
    }

    fn server() -> Server {
        Server {
            id: ServerId("spec-awg-node".into()),
            address: "203.0.113.7".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![
                ProtocolId("amneziawg2".into()),
                ProtocolId("amneziawg3".into()),
            ],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        }
    }

    fn key(byte: u8) -> String {
        STANDARD.encode([byte; 32])
    }

    fn user(name: &str, prefix: u16, discriminator: u8) -> User {
        let mut public = [discriminator; 32];
        public[..2].copy_from_slice(&prefix.to_be_bytes());
        User {
            id: UserId(name.into()),
            uuid: format!("spec-uuid-{name}"),
            tuic_password: None,
            wireguard_pubkey: Some(STANDARD.encode(public)),
            wireguard_private: Some(key(discriminator.wrapping_add(70))),
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        }
    }

    fn secrets(version: u8) -> HashMap<String, String> {
        let mut result = HashMap::from([
            (format!("amneziawg{version}.server_private_key"), key(41)),
            (format!("amneziawg{version}.server_public_key"), key(42)),
            (format!("amneziawg{version}.profile_seed"), key(43)),
        ]);
        if version == 3 {
            result.insert("amneziawg3.header_protection_key".into(), key(44));
        }
        result
    }

    fn expected_addresses(version: u8, peer: &User) -> [String; 2] {
        let bytes = STANDARD
            .decode(peer.wireguard_pubkey.as_ref().unwrap())
            .unwrap();
        let host = u16::from_be_bytes([bytes[0], bytes[1]]) % 65533 + 2;
        [
            format!("10.{}.{}.{}/32", 70 + version, host >> 8, host & 255),
            format!("fd{}:{}::{host:x}/128", 70 + version, 70 + version),
        ]
    }

    fn normalized(name: &str) -> String {
        name.chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .flat_map(char::to_lowercase)
            .collect()
    }

    fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
        let endpoint = value.as_object().expect("endpoint must be a JSON object");
        assert!(
            endpoint.contains_key(name),
            "missing flat endpoint field: {name}"
        );
        &endpoint[name]
    }

    fn absent(value: &Value, names: &[&str]) {
        let endpoint = value.as_object().expect("endpoint must be a JSON object");
        for name in names {
            assert!(
                !endpoint.contains_key(*name),
                "field must be omitted: {name}"
            );
        }
    }

    fn scalar(value: &Value) -> String {
        value
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| value.to_string())
    }

    fn ini(conf: &str) -> BTreeMap<(String, String), String> {
        let mut result = BTreeMap::new();
        let mut section = String::new();
        let mut sections = Vec::new();
        for line in conf.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            if line.starts_with('[') && line.ends_with(']') {
                section = line[1..line.len() - 1].to_owned();
                sections.push(section.clone());
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .expect("non-comment INI line must be key=value");
            assert!(!section.is_empty(), "INI values must belong to a section");
            assert!(
                result
                    .insert((section.clone(), key.trim().into()), value.trim().into())
                    .is_none(),
                "duplicate INI key"
            );
        }
        assert_eq!(sections, ["Interface", "Peer"]);
        result
    }

    fn option<'a>(
        conf: &'a BTreeMap<(String, String), String>,
        section: &str,
        name: &str,
    ) -> &'a str {
        conf.get(&(section.into(), name.into()))
            .expect("required INI option missing")
    }

    fn awg_fields() -> [(&'static str, &'static str); 11] {
        [
            ("Jc", "jc"),
            ("Jmin", "jmin"),
            ("Jmax", "jmax"),
            ("S1", "s1"),
            ("S2", "s2"),
            ("S3", "s3"),
            ("S4", "s4"),
            ("H1", "h1"),
            ("H2", "h2"),
            ("H3", "h3"),
            ("H4", "h4"),
        ]
    }

    fn range(text: &str) -> (u64, u64) {
        let (start, end) = text.split_once('-').unwrap_or((text, text));
        let result = (
            start.parse().expect("range lower bound"),
            end.parse().expect("range upper bound"),
        );
        assert!(result.0 > 0 && result.0 <= result.1 && result.1 <= u64::from(u32::MAX));
        result
    }

    fn redacted_error<T: std::fmt::Debug>(result: vpnctl_core::Result<T>, forbidden: &[String]) {
        let error = result.expect_err("invalid input must return an error");
        let diagnostic = format!("{error}\n{error:?}");
        for value in forbidden {
            assert!(
                !diagnostic.contains(value),
                "error leaked supplied key material"
            );
            // A newline must not permit logging the same key with whitespace stripped.
            let trimmed = value.trim();
            if trimmed.len() >= 16 {
                assert!(
                    !diagnostic.contains(trimmed),
                    "error leaked normalized key material"
                );
            }
        }
    }

    fn malformed_keys() -> Vec<String> {
        let canonical = key(19);
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut noncanonical = canonical.as_bytes().to_vec();
        let index = alphabet
            .iter()
            .position(|c| *c == noncanonical[42])
            .unwrap();
        noncanonical[42] = alphabet[index + 1]; // Set nonzero unused padding bits.
        vec![
            "not-a-base64-key-secret-marker".into(),
            STANDARD.encode([5; 31]),
            STANDARD.encode([5; 33]),
            key(0),
            canonical.trim_end_matches('=').into(),
            URL_SAFE_NO_PAD.encode([255; 32]),
            String::from_utf8(noncanonical).unwrap(),
            format!("{canonical}\n"),
            format!(" {canonical}"),
            format!("{canonical}\nInjected = secret-marker"),
        ]
    }

    #[test]
    fn protocol_identity_visibility_and_explicit_dedicated_conf_error() {
        for version in [2, 3] {
            let protocol = protocol(version);
            assert_eq!(protocol.id(), ProtocolId(format!("amneziawg{version}")));
            assert!(!protocol.appears_in_sing_box_sub());
            assert!(!protocol.appears_in_stock_sing_box_sub());
            let server = server();
            let secrets = secrets(version);
            let peers = [user("alice", 258, 1)];
            let ctx = RenderCtx::with_peers(&server, &secrets, &peers);
            let error = protocol
                .share_link(&ctx, &peers[0])
                .unwrap_err()
                .to_string()
                .to_lowercase();
            assert!(
                error.contains("conf"),
                "share-link error must identify the required conf artifact"
            );
            assert!(
                error.contains("dedicated") || error.contains("amnezia"),
                "share-link error must identify a dedicated Amnezia client requirement"
            );
        }
    }

    #[test]
    fn secret_declarations_cover_only_the_version_namespace_with_existing_key_variants() {
        for version in [2, 3] {
            let specs = protocol(version).server_secret_specs();
            let mut declared = BTreeSet::new();
            for spec in &specs {
                match spec {
                    ServerSecretSpec::Base64Key { key, key_bytes } => {
                        assert_eq!(*key_bytes, 32, "AWG secret material must be 32 bytes");
                        assert!(
                            declared.insert((*key).to_owned()),
                            "duplicate secret declaration"
                        );
                    }
                    ServerSecretSpec::WireguardKeypair {
                        private_key,
                        public_key,
                    } => {
                        assert_eq!(
                            *private_key,
                            format!("amneziawg{version}.server_private_key")
                        );
                        assert_eq!(*public_key, format!("amneziawg{version}.server_public_key"));
                        assert!(
                            declared.insert((*private_key).to_owned()),
                            "duplicate private key declaration"
                        );
                        assert!(
                            declared.insert((*public_key).to_owned()),
                            "duplicate public key declaration"
                        );
                    }
                    other => assert!(
                        matches!(
                            other,
                            ServerSecretSpec::Base64Key { .. }
                                | ServerSecretSpec::WireguardKeypair { .. }
                        ),
                        "unsupported AWG secret declaration: {other:?}"
                    ),
                }
            }
            let expected: BTreeSet<_> = secrets(version).into_keys().collect();
            assert_eq!(
                declared, expected,
                "declare exactly the version's required secrets"
            );
        }
    }

    #[test]
    fn server_endpoint_schema_and_fixed_ports() {
        for version in [2, 3] {
            let server = server();
            let mut secrets = secrets(version);
            secrets.insert(format!("amneziawg{version}.listen_port"), "12345".into());
            let peers = [user("alice", 258, 1), user("bob", 1024, 2)];
            let ctx = RenderCtx::with_peers(&server, &secrets, &peers);
            let endpoint = protocol(version).server_inbound(&ctx, &peers).unwrap();
            assert_eq!(endpoint["type"], "wireguard");
            assert_eq!(endpoint["tag"], format!("awg{version}-in"));
            assert_eq!(endpoint["system"], false);
            assert_eq!(
                endpoint["address"],
                json!([
                    format!("10.{}.0.1/32", 70 + version),
                    format!("fd{}:{}::1/128", 70 + version, 70 + version),
                ])
            );
            assert_eq!(endpoint["listen_port"], 51819 + u64::from(version));
            assert_eq!(endpoint["mtu"], 1280);
            assert_eq!(endpoint["private_key"], key(41));
            let rendered = endpoint["peers"].as_array().unwrap();
            assert_eq!(rendered.len(), peers.len());
            for peer in &peers {
                let entry = rendered
                    .iter()
                    .find(|p| p["public_key"].as_str() == peer.wireguard_pubkey.as_deref())
                    .unwrap();
                assert_eq!(
                    entry["allowed_ips"],
                    json!(expected_addresses(version, peer))
                );
            }
            absent(&endpoint, &["rekey_after_time"]);
        }
    }

    #[test]
    fn profile_is_coherent_and_matches_server_client_and_conf() {
        for version in [2, 3] {
            let server = server();
            let secrets = secrets(version);
            let peers = [user("alice", 258, 1)];
            let ctx = RenderCtx::with_peers(&server, &secrets, &peers);
            let protocol = protocol(version);
            let endpoint = protocol.server_inbound(&ctx, &peers).unwrap();
            let client = protocol.client_config(&ctx, &peers[0]).unwrap();
            let text = render_amnezia_conf(version, &ctx, &peers[0]).unwrap();
            let conf = ini(&text);
            for (name, json_name) in awg_fields() {
                assert_eq!(
                    scalar(field(&endpoint, json_name)),
                    option(&conf, "Interface", name)
                );
                assert_eq!(field(&client, json_name), field(&endpoint, json_name));
            }
            let number = |name| option(&conf, "Interface", name).parse::<u64>().unwrap();
            for name in ["S1", "S2", "S3", "S4"] {
                assert!(number(name) >= 12);
            }
            assert_ne!(number("S1") + 148, number("S2") + 92);
            assert!(number("Jmin") <= number("Jmax"));
            let mut ranges: Vec<_> = ["H1", "H2", "H3", "H4"]
                .iter()
                .map(|name| range(option(&conf, "Interface", name)))
                .collect();
            ranges.sort_unstable();
            assert!(ranges.windows(2).all(|pair| pair[0].1 < pair[1].0));
            absent(&client, &["rekey_after_time"]);
            assert!(!normalized(&text).contains("rekeyaftertime"));
            let version_comment = if version == 3 { "3.1" } else { "2.0" };
            assert!(
                text.lines().any(|line| {
                    let line = line.trim();
                    (line.starts_with('#') || line.starts_with(';'))
                        && line.contains(version_comment)
                }),
                "conf comment must identify the actual AmneziaWG version"
            );
        }
    }

    #[test]
    fn version_three_only_options_and_header_hex_are_consistent() {
        for version in [2, 3] {
            let server = server();
            let secrets = secrets(version);
            let peers = [user("alice", 258, 1)];
            let ctx = RenderCtx::with_peers(&server, &secrets, &peers);
            let protocol = protocol(version);
            let server_endpoint = protocol.server_inbound(&ctx, &peers).unwrap();
            let client_endpoint = protocol.client_config(&ctx, &peers[0]).unwrap();
            for endpoint in [&server_endpoint, &client_endpoint] {
                if version == 3 {
                    assert_eq!(field(endpoint, "random_trailers"), &json!(true));
                    assert_eq!(field(endpoint, "disable_cookies"), &json!(true));
                    assert_eq!(field(endpoint, "content_padding_addition"), &json!("0-32"));
                    let hex = field(endpoint, "header_protection_key").as_str().unwrap();
                    assert_eq!(hex.len(), 64);
                    assert_eq!(hex.to_ascii_lowercase(), "2c".repeat(32));
                } else {
                    for name in [
                        "random_trailers",
                        "disable_cookies",
                        "content_padding_addition",
                        "header_protection_key",
                    ] {
                        absent(endpoint, &[name]);
                    }
                }
            }
            let text = render_amnezia_conf(version, &ctx, &peers[0]).unwrap();
            let conf = ini(&text);
            if version == 3 {
                // Native INI uses base64 key bytes and `on`; JSON uses hex and true.
                let encoded = option(&conf, "Interface", "HeaderProtectionKey");
                let decoded = STANDARD
                    .decode(encoded)
                    .expect("native header key must be base64");
                assert_eq!(decoded, vec![44; 32]);
                assert_eq!(
                    STANDARD.encode(&decoded),
                    encoded,
                    "header key must be canonical base64"
                );
                let hex: String = decoded
                    .iter()
                    .flat_map(|byte| {
                        let digits = b"0123456789abcdef";
                        [
                            char::from(digits[usize::from(byte >> 4)]),
                            char::from(digits[usize::from(byte & 15)]),
                        ]
                    })
                    .collect();
                for endpoint in [&server_endpoint, &client_endpoint] {
                    assert_eq!(
                        field(endpoint, "header_protection_key")
                            .as_str()
                            .unwrap()
                            .to_ascii_lowercase(),
                        hex
                    );
                    for (ini_name, json_name) in [
                        ("RandomTrailers", "random_trailers"),
                        ("DisableCookies", "disable_cookies"),
                    ] {
                        let enabled = option(&conf, "Interface", ini_name) == "on";
                        assert!(enabled, "native boolean must be on");
                        assert_eq!(field(endpoint, json_name).as_bool(), Some(enabled));
                    }
                }
                assert_eq!(option(&conf, "Interface", "ContentPaddingAddition"), "0-32");
            } else {
                for name in [
                    "HeaderProtectionKey",
                    "RandomTrailers",
                    "DisableCookies",
                    "ContentPaddingAddition",
                ] {
                    assert!(!conf.contains_key(&("Interface".into(), name.into())));
                }
            }
        }
    }

    #[test]
    fn conf_has_native_fields_and_brackets_ipv6_endpoints() {
        for version in [2, 3] {
            for (address, expected_host) in [
                ("203.0.113.7", "203.0.113.7"),
                ("vpn.example.test", "vpn.example.test"),
                ("2001:db8::7", "[2001:db8::7]"),
            ] {
                let mut server = server();
                server.address = address.into();
                let secrets = secrets(version);
                let peers = [user("alice", 258, 1)];
                let ctx = RenderCtx::with_peers(&server, &secrets, &peers);
                let text = render_amnezia_conf(version, &ctx, &peers[0]).unwrap();
                let conf = ini(&text);
                assert_eq!(
                    option(&conf, "Interface", "PrivateKey"),
                    peers[0].wireguard_private.as_ref().unwrap()
                );
                assert_eq!(
                    option(&conf, "Interface", "Address"),
                    expected_addresses(version, &peers[0]).join(", ")
                );
                assert_eq!(option(&conf, "Interface", "DNS"), "1.1.1.1");
                assert_eq!(option(&conf, "Interface", "MTU"), "1280");
                assert_eq!(option(&conf, "Peer", "PublicKey"), key(42));
                assert_eq!(option(&conf, "Peer", "AllowedIPs"), "0.0.0.0/0, ::/0");
                assert_eq!(option(&conf, "Peer", "PersistentKeepalive"), "25");
                assert_eq!(
                    option(&conf, "Peer", "Endpoint"),
                    format!("{expected_host}:{}", 51819 + u16::from(version))
                );
                assert!(
                    !text.contains(&key(41)),
                    "client artifact must not contain server private key"
                );
                assert!(
                    !text.contains(&key(43)),
                    "client artifact must not contain profile seed"
                );
            }
        }
    }

    #[test]
    fn addresses_follow_big_endian_formula_at_wrap_boundaries() {
        for version in [2, 3] {
            for prefix in [0, 1, 255, 256, 258, 65532, 65533, 65534, 65535] {
                let server = server();
                let secrets = secrets(version);
                let peers = [user("edge", prefix, 3)];
                let ctx = RenderCtx::with_peers(&server, &secrets, &peers);
                let endpoint = protocol(version).server_inbound(&ctx, &peers).unwrap();
                let expected = expected_addresses(version, &peers[0]);
                assert_eq!(endpoint["peers"][0]["allowed_ips"], json!(expected));
                let client = protocol(version).client_config(&ctx, &peers[0]).unwrap();
                assert_eq!(client["address"], json!(expected));
                let text = render_amnezia_conf(version, &ctx, &peers[0]).unwrap();
                assert_eq!(
                    option(&ini(&text), "Interface", "Address"),
                    expected.join(", ")
                );
            }
        }
    }

    #[test]
    fn other_grant_addition_removal_and_reordering_leave_client_bytes_unchanged() {
        for version in [2, 3] {
            let server = server();
            let secrets = secrets(version);
            let alice = user("alice", 258, 1);
            let bob = user("bob", 1024, 2);
            let carol = user("carol", 4096, 3);
            let populations = [
                vec![alice.clone()],
                vec![bob.clone(), alice.clone()],
                vec![alice.clone(), bob.clone(), carol.clone()],
                vec![carol, alice.clone(), bob],
            ];
            let mut confs = BTreeSet::new();
            let mut clients = BTreeSet::new();
            for peers in populations {
                let ctx = RenderCtx::with_peers(&server, &secrets, &peers);
                confs.insert(render_amnezia_conf(version, &ctx, &alice).unwrap());
                let protocol = protocol(version);
                clients.insert(protocol.client_config(&ctx, &alice).unwrap().to_string());
                let endpoint = protocol.server_inbound(&ctx, &peers).unwrap();
                let entry = endpoint["peers"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|p| p["public_key"].as_str() == alice.wireguard_pubkey.as_deref())
                    .unwrap();
                assert_eq!(
                    entry["allowed_ips"],
                    json!(expected_addresses(version, &alice))
                );
            }
            assert_eq!(confs.len(), 1);
            assert_eq!(clients.len(), 1);
        }
    }

    #[test]
    fn full_tunnel_rendering_includes_ipv6_even_with_ipv4_transport() {
        let server = server(); // IPv4 transport must not imply IPv4-only inner traffic.
        let peers = [user("alice", 258, 1)];
        for (version, server_addresses, client_addresses) in [
            (
                2,
                ["10.72.0.1/32", "fd72:72::1/128"],
                ["10.72.1.4/32", "fd72:72::104/128"],
            ),
            (
                3,
                ["10.73.0.1/32", "fd73:73::1/128"],
                ["10.73.1.4/32", "fd73:73::104/128"],
            ),
        ] {
            let secrets = secrets(version);
            let ctx = RenderCtx::with_peers(&server, &secrets, &peers);
            let protocol = protocol(version);
            let inbound = protocol.server_inbound(&ctx, &peers).unwrap();
            let client = protocol.client_config(&ctx, &peers[0]).unwrap();
            assert_eq!(inbound["address"], json!(server_addresses));
            assert_eq!(inbound["peers"][0]["allowed_ips"], json!(client_addresses));
            assert_eq!(client["address"], json!(client_addresses));
            assert_eq!(client["peers"][0]["address"], "203.0.113.7");
            assert_eq!(client["peers"].as_array().unwrap().len(), 1);
            assert_eq!(
                client["peers"][0]["allowed_ips"],
                json!(["0.0.0.0/0", "::/0"])
            );
            let text = render_amnezia_conf(version, &ctx, &peers[0]).unwrap();
            let conf = ini(&text);
            assert_eq!(
                option(&conf, "Interface", "Address"),
                client_addresses.join(", ")
            );
            assert_eq!(option(&conf, "Peer", "AllowedIPs"), "0.0.0.0/0, ::/0");
            // No generated route-removal hooks or policy table override may bypass ::/0.
            for name in ["PreUp", "PostUp", "PreDown", "PostDown", "Table"] {
                assert!(!conf.contains_key(&("Interface".into(), name.into())));
            }
        }
    }

    #[test]
    fn other_version_secrets_do_not_change_rendered_bytes() {
        let server = server();
        let peers = [user("alice", 258, 1)];
        for (version, other) in [(2, 3), (3, 2)] {
            let own_secrets = secrets(version);
            let ctx = RenderCtx::with_peers(&server, &own_secrets, &peers);
            let protocol = protocol(version);
            let inbound = protocol.server_inbound(&ctx, &peers).unwrap();
            let client = protocol.client_config(&ctx, &peers[0]).unwrap();
            let conf = render_amnezia_conf(version, &ctx, &peers[0]).unwrap();
            let mut combined = own_secrets.clone();
            combined.extend(
                secrets(other)
                    .into_keys()
                    .map(|key| (key, "invalid-other-version-secret".into())),
            );
            let ctx = RenderCtx::with_peers(&server, &combined, &peers);
            assert_eq!(protocol.server_inbound(&ctx, &peers).unwrap(), inbound);
            assert_eq!(protocol.client_config(&ctx, &peers[0]).unwrap(), client);
            assert_eq!(render_amnezia_conf(version, &ctx, &peers[0]).unwrap(), conf);
        }
    }

    #[test]
    fn unrelated_keyless_grants_do_not_block_or_renumber_healthy_clients() {
        for version in [2, 3] {
            let server = server();
            let secrets = secrets(version);
            let alice = user("alice", 258, 1);
            let bob = user("bob", 1024, 2);
            let mut keyless = bob.clone();
            keyless.wireguard_pubkey = None;
            keyless.wireguard_private = None;
            let protocol = protocol(version);
            let baseline = [alice.clone()];
            let ctx = RenderCtx::with_peers(&server, &secrets, &baseline);
            let healthy_client = protocol.client_config(&ctx, &alice).unwrap();
            let healthy_conf = render_amnezia_conf(version, &ctx, &alice).unwrap();
            let healthy_server = protocol.server_inbound(&ctx, &baseline).unwrap();
            for peers in [
                vec![keyless.clone(), alice.clone()],
                vec![alice.clone(), keyless.clone()],
                vec![bob.clone(), alice.clone()], // Key provisioning must not renumber Alice.
            ] {
                let ctx = RenderCtx::with_peers(&server, &secrets, &peers);
                let inbound = protocol.server_inbound(&ctx, &peers).unwrap();
                assert_eq!(
                    protocol.client_config(&ctx, &alice).unwrap(),
                    healthy_client
                );
                assert_eq!(
                    render_amnezia_conf(version, &ctx, &alice).unwrap(),
                    healthy_conf
                );
                let rendered = inbound["peers"].as_array().unwrap();
                let entry = rendered
                    .iter()
                    .find(|p| p["public_key"].as_str() == alice.wireguard_pubkey.as_deref())
                    .unwrap();
                assert_eq!(entry, &healthy_server["peers"][0]);
                if let Some(target) = peers.iter().find(|peer| peer.wireguard_pubkey.is_none()) {
                    assert_eq!(inbound, healthy_server);
                    assert!(
                        protocol
                            .client_config(&ctx, target)
                            .unwrap_err()
                            .to_string()
                            .contains("client is missing a public key")
                    );
                    assert!(
                        render_amnezia_conf(version, &ctx, target)
                            .unwrap_err()
                            .to_string()
                            .contains("client is missing a public key")
                    );
                    assert!(target.wireguard_pubkey.is_none());
                    assert!(target.wireguard_private.is_none());
                    assert!(!target.disabled);
                } else {
                    assert_eq!(rendered.len(), 2);
                    assert!(render_amnezia_conf(version, &ctx, &bob).is_ok());
                }
            }
        }
    }

    #[test]
    fn unrelated_present_malformed_keys_still_fail_closed() {
        for version in [2, 3] {
            let server = server();
            let secrets = secrets(version);
            for bad in malformed_keys().into_iter().chain([String::new()]) {
                let mut malformed = user("malformed", 1024, 2);
                malformed.wireguard_pubkey = Some(bad.clone());
                let peers = [user("alice", 258, 1), malformed];
                let ctx = RenderCtx::with_peers(&server, &secrets, &peers);
                let forbidden = [bad]
                    .into_iter()
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>();
                redacted_error(protocol(version).server_inbound(&ctx, &peers), &forbidden);
                redacted_error(protocol(version).client_config(&ctx, &peers[0]), &forbidden);
                redacted_error(render_amnezia_conf(version, &ctx, &peers[0]), &forbidden);
            }
        }
    }

    #[test]
    fn profile_seed_is_deterministic_and_materially_affects_profile() {
        for version in [2, 3] {
            let server = server();
            let peers = [user("alice", 258, 1)];
            let mut profiles = BTreeSet::new();
            for seed in [43, 61, 89] {
                let mut secrets = secrets(version);
                secrets.insert(format!("amneziawg{version}.profile_seed"), key(seed));
                let ctx = RenderCtx::with_peers(&server, &secrets, &peers);
                let first = render_amnezia_conf(version, &ctx, &peers[0]).unwrap();
                assert_eq!(
                    first,
                    render_amnezia_conf(version, &ctx, &peers[0]).unwrap()
                );
                let endpoint = protocol(version).server_inbound(&ctx, &peers).unwrap();
                assert_eq!(
                    endpoint,
                    protocol(version).server_inbound(&ctx, &peers).unwrap()
                );
                let profile: Vec<_> = awg_fields()
                    .iter()
                    .map(|(_, names)| scalar(field(&endpoint, names)))
                    .collect();
                profiles.insert(profile);
            }
            assert_eq!(profiles.len(), 3, "profile_seed must not be ignored");
        }
    }

    #[test]
    fn duplicate_keys_and_both_kinds_of_address_collisions_are_rejected() {
        for version in [2, 3] {
            let server = server();
            let secrets = secrets(version);
            for peers in [
                vec![user("alice", 258, 1), user("duplicate-key", 258, 1)],
                vec![user("alice", 258, 1), user("same-prefix", 258, 2)],
                vec![user("alice", 0, 1), user("modulo-collision", 65533, 2)],
            ] {
                let ctx = RenderCtx::with_peers(&server, &secrets, &peers);
                let protocol = protocol(version);
                assert!(protocol.server_inbound(&ctx, &peers).is_err());
                assert!(protocol.client_config(&ctx, &peers[0]).is_err());
                assert!(render_amnezia_conf(version, &ctx, &peers[0]).is_err());
            }
        }
    }

    #[test]
    fn disabled_peers_are_skipped_before_validation_and_disabled_clients_rejected() {
        for version in [2, 3] {
            let server = server();
            let secrets = secrets(version);
            let alice = user("alice", 258, 1);
            let mut disabled = user("disabled", 258, 1);
            disabled.disabled = true;
            let mut malformed = user("disabled-malformed", 258, 2);
            malformed.disabled = true;
            malformed.wireguard_pubkey = Some("invalid-disabled-key".into());
            let peers = [alice.clone(), disabled, malformed];
            let ctx = RenderCtx::with_peers(&server, &secrets, &peers);
            let protocol = protocol(version);
            let endpoint = protocol.server_inbound(&ctx, &peers).unwrap();
            assert_eq!(endpoint["peers"].as_array().unwrap().len(), 1);
            assert_eq!(
                endpoint["peers"][0]["public_key"].as_str(),
                alice.wireguard_pubkey.as_deref()
            );
            assert!(render_amnezia_conf(version, &ctx, &alice).is_ok());
            for disabled in &peers[1..] {
                assert!(protocol.client_config(&ctx, disabled).is_err());
                assert!(render_amnezia_conf(version, &ctx, disabled).is_err());
            }
        }
    }

    #[test]
    fn missing_or_mismatched_grant_and_missing_client_private_key_are_errors() {
        for version in [2, 3] {
            let server = server();
            let secrets = secrets(version);
            let alice = user("alice", 258, 1);
            let protocol = protocol(version);
            let empty = RenderCtx::new(&server, &secrets);
            assert!(protocol.client_config(&empty, &alice).is_err());
            assert!(render_amnezia_conf(version, &empty, &alice).is_err());
            for peers in [vec![], vec![user("other", 1024, 2)]] {
                let ctx = RenderCtx::with_peers(&server, &secrets, &peers);
                assert!(protocol.client_config(&ctx, &alice).is_err());
                assert!(render_amnezia_conf(version, &ctx, &alice).is_err());
            }
            let mut missing_private = alice.clone();
            missing_private.wireguard_private = None;
            let peers = [missing_private];
            let ctx = RenderCtx::with_peers(&server, &secrets, &peers);
            assert!(protocol.client_config(&ctx, &peers[0]).is_err());
            assert!(render_amnezia_conf(version, &ctx, &peers[0]).is_err());
        }
    }

    #[test]
    fn every_required_server_secret_is_required_on_both_render_paths() {
        for version in [2, 3] {
            let server = server();
            let peers = [user("alice", 258, 1)];
            let valid = secrets(version);
            for missing in valid.keys() {
                let mut secrets = valid.clone();
                secrets.remove(missing);
                let ctx = RenderCtx::with_peers(&server, &secrets, &peers);
                let protocol = protocol(version);
                assert!(
                    protocol.server_inbound(&ctx, &peers).is_err(),
                    "missing {missing}"
                );
                assert!(
                    protocol.client_config(&ctx, &peers[0]).is_err(),
                    "missing {missing}"
                );
                assert!(
                    render_amnezia_conf(version, &ctx, &peers[0]).is_err(),
                    "missing {missing}"
                );
            }
        }
    }

    #[test]
    fn server_secrets_require_canonical_nonzero_base64_32_and_redacted_errors() {
        for version in [2, 3] {
            let server = server();
            let peers = [user("alice", 258, 1)];
            let valid = secrets(version);
            for name in valid.keys() {
                for bad in malformed_keys() {
                    let mut secrets = valid.clone();
                    secrets.insert(name.clone(), bad.clone());
                    let ctx = RenderCtx::with_peers(&server, &secrets, &peers);
                    let mut forbidden: Vec<_> = valid.values().cloned().collect();
                    forbidden.push(bad);
                    redacted_error(protocol(version).server_inbound(&ctx, &peers), &forbidden);
                    redacted_error(protocol(version).client_config(&ctx, &peers[0]), &forbidden);
                    redacted_error(render_amnezia_conf(version, &ctx, &peers[0]), &forbidden);
                }
            }
        }
    }

    #[test]
    fn user_public_and_private_keys_are_strictly_validated_without_disclosure() {
        for version in [2, 3] {
            let server = server();
            let secrets = secrets(version);
            for bad in malformed_keys() {
                for corrupt_private in [false, true] {
                    let mut alice = user("alice", 258, 1);
                    if corrupt_private {
                        alice.wireguard_private = Some(bad.clone());
                    } else {
                        alice.wireguard_pubkey = Some(bad.clone());
                    }
                    let peers = [alice];
                    let ctx = RenderCtx::with_peers(&server, &secrets, &peers);
                    let forbidden = vec![bad.clone()];
                    if !corrupt_private {
                        redacted_error(protocol(version).server_inbound(&ctx, &peers), &forbidden);
                    }
                    redacted_error(protocol(version).client_config(&ctx, &peers[0]), &forbidden);
                    redacted_error(render_amnezia_conf(version, &ctx, &peers[0]), &forbidden);
                }
            }
            let mut alice = user("alice", 258, 1);
            alice.wireguard_pubkey = None;
            let peers = [alice];
            let ctx = RenderCtx::with_peers(&server, &secrets, &peers);
            assert!(protocol(version).client_config(&ctx, &peers[0]).is_err());
            assert!(render_amnezia_conf(version, &ctx, &peers[0]).is_err());
        }
    }

    #[test]
    fn unsupported_versions_are_rejected_instead_of_silently_downgraded() {
        let server = server();
        let mut secrets = secrets(2);
        secrets.extend(self::secrets(3));
        let peers = [user("alice", 258, 1)];
        let ctx = RenderCtx::with_peers(&server, &secrets, &peers);
        for version in [0, 1, 4, 255] {
            assert!(render_amnezia_conf(version, &ctx, &peers[0]).is_err());
        }
    }
}
