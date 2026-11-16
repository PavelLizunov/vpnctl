//! Independent contract tests for the separately signed telephony feed.

#[allow(clippy::unwrap_used, clippy::expect_used)]
mod contract {
    use std::collections::BTreeMap;

    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};
    use p256::pkcs8::DecodePrivateKey;
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use vpnctld::corp_policy::{
        PhonePayload, PhoneRule, PolicySigningKey, normalize_phone_value, seed_phone_rules,
        validate_phone_rules, verify_phone_envelope,
    };

    fn rule(kind: &str, value: &str, action: &str, comment: &str) -> PhoneRule {
        PhoneRule {
            kind: kind.into(),
            value: value.into(),
            action: action.into(),
            comment: comment.into(),
        }
    }

    fn payload(rules: Vec<PhoneRule>) -> PhonePayload {
        PhonePayload {
            schema: 1,
            kind: "telephony".into(),
            policy_id: "spec.phone-policy".into(),
            key_id: "spec_key-1".into(),
            revision: 1,
            published_at: 1,
            apply: "next_connection".into(),
            rules,
        }
    }

    fn keys(key: &PolicySigningKey) -> BTreeMap<String, String> {
        BTreeMap::from([("spec_key-1".into(), key.spki_base64().unwrap())])
    }

    // Independently sign exact bytes so parser rejection cannot be explained by
    // a signature failure or by validation in the production signing method.
    fn envelope(key: &PolicySigningKey, bytes: &[u8]) -> Vec<u8> {
        let der = key.export_pkcs8_der().unwrap();
        let signer = SigningKey::from_pkcs8_der(der.as_bytes()).unwrap();
        let signature: Signature = signer.sign(bytes);
        serde_json::to_vec(&json!({
            "payload": STANDARD.encode(bytes),
            "signature": STANDARD.encode(signature.to_bytes()),
        }))
        .unwrap()
    }

    fn assert_raw_rejected(key: &PolicySigningKey, raw: &[u8]) {
        assert!(
            verify_phone_envelope(&envelope(key, raw), "spec.phone-policy", &keys(key)).is_err()
        );
    }

    #[test]
    fn phone_normalization_accepts_urls_idna_and_canonical_literal_prefixes() {
        for (kind, input, expected) in [
            (
                "domain_suffix",
                " HTTPS://Example.COM./a?q=x ",
                "example.com",
            ),
            ("domain_suffix", "bücher.de", "xn--bcher-kva.de"),
            ("domain_suffix", "UISCOM.RU", "uiscom.ru"),
            ("ip_cidr", "195.211.120.35", "195.211.120.35/32"),
            ("ip_cidr", "192.0.2.0/24", "192.0.2.0/24"),
            ("ip_cidr", "198.51.100.35/24", "198.51.100.0/24"),
            ("ip_cidr", "2001:db8::1", "2001:db8::1/128"),
            ("ip_cidr", "2001:db8::1/32", "2001:db8::/32"),
            ("ip_cidr", "2001:db8::/32", "2001:db8::/32"),
            ("ip_cidr", "0.0.0.0/0", "0.0.0.0/0"),
            ("ip_cidr", "::/0", "::/0"),
        ] {
            assert_eq!(normalize_phone_value(kind, input).unwrap(), expected);
        }
        assert!(normalize_phone_value("domain_suffix", &"x".repeat(4097)).is_err());
    }

    #[test]
    fn normalization_rejects_non_dns_names_public_suffixes_and_invalid_cidrs() {
        for input in [
            "",
            "com",
            "co.uk",
            "github.io",
            "foo.ck",
            "127.0.0.1",
            "2130706433",
            "https://user@example.com",
            "example.com:443",
            "example.com/a",
            "*.example.com",
            "a..example.com",
            "a_b.example.com",
            "-a.example.com",
            "a-.example.com",
            "xn--.com",
            "example.com\\x",
            "example.com\n",
        ] {
            assert!(
                normalize_phone_value("domain_suffix", input).is_err(),
                "{input:?}"
            );
        }
        assert_eq!(
            normalize_phone_value("domain_suffix", "www.ck").unwrap(),
            "www.ck"
        );
        for input in [
            "192.0.2.0/33",
            "2001:db8::/129",
            "::ffff:192.0.2.1/128",
            "192.000.2.1/32",
            "192.0.2.0/-1",
            "example.com",
        ] {
            assert!(
                normalize_phone_value("ip_cidr", input).is_err(),
                "{input:?}"
            );
        }
        assert!(normalize_phone_value("unknown", "example.com").is_err());
    }

    #[test]
    fn four_phone_domains_are_editable_but_portal_relatives_are_forbidden() {
        for domain in ["uiscom.ru", "uiscom.co", "comagic.ru", "callbackhunter.com"] {
            for action in ["direct", "proxy"] {
                validate_phone_rules(&[rule("domain_suffix", domain, action, "")]).unwrap();
            }
        }
        for domain in [
            "admin.corp.ninitux.com",
            "corp.ninitux.com",
            "ninitux.com",
            "x.admin.corp.ninitux.com",
        ] {
            assert!(validate_phone_rules(&[rule("domain_suffix", domain, "direct", "")]).is_err());
        }
        validate_phone_rules(&[rule("domain_suffix", "other.corp.ninitux.com", "proxy", "")])
            .unwrap();
    }

    #[test]
    fn empty_rules_and_exact_five_defaults_are_valid() {
        validate_phone_rules(&[]).unwrap();
        let defaults = seed_phone_rules().unwrap();
        validate_phone_rules(&defaults).unwrap();
        assert_eq!(defaults.len(), 5);
        let actual: std::collections::BTreeSet<_> = defaults
            .iter()
            .map(|r| (r.kind.as_str(), r.value.as_str(), r.action.as_str()))
            .collect();
        let expected = std::collections::BTreeSet::from([
            ("domain_suffix", "uiscom.ru", "direct"),
            ("domain_suffix", "uiscom.co", "direct"),
            ("domain_suffix", "comagic.ru", "direct"),
            ("domain_suffix", "callbackhunter.com", "direct"),
            ("ip_cidr", "195.211.120.35/32", "direct"),
        ]);
        assert_eq!(actual, expected);
    }

    #[test]
    fn validation_requires_canonical_values_known_types_actions_and_bounded_comments() {
        // Input normalization masks host bits; authenticated wire validation
        // requires those network bits to have been canonicalized already.
        for r in [
            rule("domain_suffix", "Example.COM", "direct", ""),
            rule("domain_suffix", "https://example.com", "direct", ""),
            rule("ip_cidr", "192.0.2.1", "direct", ""),
            rule("ip_cidr", "198.51.100.35/24", "direct", ""),
            rule("ip_cidr", "2001:db8::1/32", "direct", ""),
            rule("ip_cidr", "2001:0db8:0:0::/32", "direct", ""),
            rule("unknown", "example.com", "direct", ""),
            rule("domain_suffix", "example.com", "DIRECT", ""),
            rule("domain_suffix", "example.com", "direct", "a\nb"),
            rule("domain_suffix", "example.com", "direct", "a\u{85}b"),
            rule("domain_suffix", "example.com", "direct", &"é".repeat(129)),
        ] {
            assert!(validate_phone_rules(&[r]).is_err());
        }
        validate_phone_rules(&[rule(
            "domain_suffix",
            "example.com",
            "direct",
            &"é".repeat(128),
        )])
        .unwrap();
        let rules: Vec<_> = (0..64)
            .map(|i| rule("domain_suffix", &format!("s{i}.example.com"), "direct", ""))
            .collect();
        validate_phone_rules(&rules).unwrap();
        let mut too_many = rules;
        too_many.push(rule("domain_suffix", "last.example.com", "direct", ""));
        assert!(validate_phone_rules(&too_many).is_err());
    }

    #[test]
    fn duplicates_and_opposite_intersections_are_rejected_for_both_address_types() {
        for (kind, parent, child) in [
            ("domain_suffix", "example.com", "child.example.com"),
            ("ip_cidr", "192.0.2.0/24", "192.0.2.128/25"),
            ("ip_cidr", "2001:db8::/32", "2001:db8:1::/48"),
        ] {
            assert!(
                validate_phone_rules(&[
                    rule(kind, parent, "direct", ""),
                    rule(kind, parent, "direct", "")
                ])
                .is_err()
            );
            for (a, b) in [(parent, child), (child, parent)] {
                assert!(
                    validate_phone_rules(&[
                        rule(kind, a, "direct", ""),
                        rule(kind, b, "proxy", "")
                    ])
                    .is_err()
                );
                validate_phone_rules(&[rule(kind, a, "direct", ""), rule(kind, b, "direct", "")])
                    .unwrap();
            }
        }
        validate_phone_rules(&[
            rule("domain_suffix", "example.com", "direct", ""),
            rule("domain_suffix", "otherexample.com", "proxy", ""),
            rule("ip_cidr", "192.0.2.0/24", "direct", ""),
            rule("ip_cidr", "192.0.3.0/24", "proxy", ""),
            rule("ip_cidr", "2001:db8::/32", "proxy", ""),
        ])
        .unwrap();
    }

    #[test]
    fn signing_roundtrips_exact_bytes_digest_empty_and_default_lists_and_both_timings() {
        let key = PolicySigningKey::generate().unwrap();
        for rules in [vec![], seed_phone_rules().unwrap()] {
            for apply in ["next_connection", "now"] {
                let mut p = payload(rules.clone());
                p.apply = apply.into();
                let signed = key.sign_phone(&p).unwrap();
                assert_eq!(signed.payload, p);
                assert_eq!(signed.payload_bytes, serde_json::to_vec(&p).unwrap());
                if p.rules.is_empty() {
                    assert_eq!(
                        String::from_utf8(signed.payload_bytes.clone()).unwrap(),
                        format!(
                            "{{\"schema\":1,\"kind\":\"telephony\",\"policy_id\":\"spec.phone-policy\",\"key_id\":\"spec_key-1\",\"revision\":1,\"published_at\":1,\"apply\":\"{apply}\",\"rules\":[]}}"
                        )
                    );
                }
                let digest: String = Sha256::digest(&signed.payload_bytes)
                    .iter()
                    .map(|b| format!("{b:02X}"))
                    .collect();
                assert_eq!(signed.payload_sha256, digest);
                let verified =
                    verify_phone_envelope(&signed.envelope, &p.policy_id, &keys(&key)).unwrap();
                assert_eq!(verified.payload, p);
                assert_eq!(verified.payload_bytes, signed.payload_bytes);
                assert_eq!(verified.envelope, signed.envelope);
                assert_eq!(verified.payload_sha256, signed.payload_sha256);
            }
        }
    }

    #[test]
    fn exported_synthetic_key_imports_and_verifies_without_changing_public_identity() {
        let key = PolicySigningKey::generate().unwrap();
        let der = key.export_pkcs8_der().unwrap();
        let imported = PolicySigningKey::from_pkcs8_der(der.as_bytes()).unwrap();
        assert_eq!(imported.spki_base64().unwrap(), key.spki_base64().unwrap());
        let signed = imported.sign_phone(&payload(vec![])).unwrap();
        verify_phone_envelope(&signed.envelope, "spec.phone-policy", &keys(&key)).unwrap();
        assert!(PolicySigningKey::from_pkcs8_der(&[]).is_err());
        assert!(PolicySigningKey::from_pkcs8_der(b"not a private key").is_err());
    }

    #[test]
    fn authenticated_payload_rejects_unknown_missing_duplicate_and_noninteger_fields() {
        let key = PolicySigningKey::generate().unwrap();
        let p = payload(vec![rule("domain_suffix", "example.com", "direct", "")]);
        let raw = serde_json::to_string(&p).unwrap();
        for bad in [
            raw.replacen("\"schema\":1", "\"schema\":1,\"schema\":1", 1),
            raw.replacen("\"schema\":1", "\"schema\":1.0", 1),
            raw.replacen("\"revision\":1", "\"revision\":1e0", 1),
            raw.replacen("\"published_at\":1", "\"published_at\":1.0", 1),
            raw.replacen("\"schema\":1,", "", 1),
            raw.replacen("\"schema\":1", "\"schema\":1,\"extra\":true", 1),
            raw.replacen(
                "\"type\":\"domain_suffix\"",
                "\"type\":\"domain_suffix\",\"extra\":1",
                1,
            ),
            raw.replacen("\"comment\":\"\"", "\"comment\":\"\",\"comment\":\"\"", 1),
            format!("{raw} null"),
            format!("{raw}//comment"),
            raw.replacen("\"schema\":1", "\"schema\":true", 1),
            raw.replacen(
                "\"schema\":1",
                "\"schema\":1,\"deep\":[[[[[[[[[0]]]]]]]]]",
                1,
            ),
            raw.replacen("\"comment\":\"\"", "\"comment\":\"\",", 1),
        ] {
            assert_ne!(bad, raw);
            assert_raw_rejected(&key, bad.as_bytes());
        }
        assert_raw_rejected(&key, b"\xff");
    }

    #[test]
    fn signing_and_verification_enforce_identity_schema_revision_time_and_apply_bounds() {
        let key = PolicySigningKey::generate().unwrap();
        let good = serde_json::to_value(payload(vec![])).unwrap();
        for (field, value) in [
            ("schema", json!(0)),
            ("schema", json!(2)),
            ("kind", json!("sites")),
            ("policy_id", json!("")),
            ("policy_id", json!("a/b")),
            ("key_id", json!("")),
            ("key_id", json!("é")),
            ("revision", json!(0)),
            ("revision", json!(9007199254740992_u64)),
            ("published_at", json!(0)),
            ("published_at", json!(253402300800_u64)),
            ("apply", json!("later")),
            ("policy_id", json!("a".repeat(65))),
            ("key_id", json!("a".repeat(65))),
        ] {
            let mut bad = good.clone();
            bad[field] = value;
            let typed: PhonePayload = serde_json::from_value(bad.clone()).unwrap();
            assert!(key.sign_phone(&typed).is_err(), "field {field}");
            assert_raw_rejected(&key, &serde_json::to_vec(&bad).unwrap());
        }
        let mut max = payload(vec![]);
        max.policy_id = "a".repeat(64);
        max.key_id = "b".repeat(64);
        max.revision = 9007199254740991;
        max.published_at = 253402300799;
        let signed = key.sign_phone(&max).unwrap();
        let selected = BTreeMap::from([(max.key_id.clone(), key.spki_base64().unwrap())]);
        verify_phone_envelope(&signed.envelope, &max.policy_id, &selected).unwrap();
    }

    #[test]
    fn signature_and_provisioned_identity_bind_exact_payload_bytes() {
        let key = PolicySigningKey::generate().unwrap();
        let signed = key.sign_phone(&payload(vec![])).unwrap();
        assert!(verify_phone_envelope(&signed.envelope, "other-policy", &keys(&key)).is_err());
        assert!(
            verify_phone_envelope(&signed.envelope, "spec.phone-policy", &BTreeMap::new()).is_err()
        );
        let other = PolicySigningKey::generate().unwrap();
        assert!(
            verify_phone_envelope(&signed.envelope, "spec.phone-policy", &keys(&other)).is_err()
        );
        for spki in [
            "".to_string(),
            "not-base64".to_string(),
            STANDARD.encode([0_u8; 257]),
        ] {
            let malformed = BTreeMap::from([("spec_key-1".into(), spki)]);
            assert!(
                verify_phone_envelope(&signed.envelope, "spec.phone-policy", &malformed).is_err()
            );
        }
        let mut e: Value = serde_json::from_slice(&signed.envelope).unwrap();
        let mut changed = signed.payload_bytes.clone();
        changed.push(b' ');
        e["payload"] = json!(STANDARD.encode(changed));
        assert!(
            verify_phone_envelope(
                &serde_json::to_vec(&e).unwrap(),
                "spec.phone-policy",
                &keys(&key)
            )
            .is_err()
        );
        let mut e: Value = serde_json::from_slice(&signed.envelope).unwrap();
        let mut signature = STANDARD.decode(e["signature"].as_str().unwrap()).unwrap();
        signature[0] ^= 1;
        e["signature"] = json!(STANDARD.encode(signature));
        assert!(
            verify_phone_envelope(
                &serde_json::to_vec(&e).unwrap(),
                "spec.phone-policy",
                &keys(&key)
            )
            .is_err()
        );
    }

    #[test]
    fn wire_rule_validation_is_not_bypassed_by_a_valid_signature() {
        let key = PolicySigningKey::generate().unwrap();
        for rules in [
            vec![rule("domain_suffix", "Example.COM", "direct", "")],
            vec![rule("ip_cidr", "192.0.2.1/24", "direct", "")],
            vec![rule("domain_suffix", "admin.corp.ninitux.com", "proxy", "")],
            vec![
                rule("domain_suffix", "example.com", "direct", ""),
                rule("domain_suffix", "child.example.com", "proxy", ""),
            ],
        ] {
            let p = payload(rules);
            assert!(key.sign_phone(&p).is_err());
            assert_raw_rejected(&key, &serde_json::to_vec(&p).unwrap());
        }
    }

    #[test]
    fn envelope_fields_and_base64_are_strict_and_bounded() {
        let key = PolicySigningKey::generate().unwrap();
        let signed = key.sign_phone(&payload(vec![])).unwrap();
        let valid: Value = serde_json::from_slice(&signed.envelope).unwrap();
        let p = valid["payload"].as_str().unwrap();
        let s = valid["signature"].as_str().unwrap();
        for raw in [
            format!("{{\"payload\":\"{p}\",\"signature\":\"{s}\",\"extra\":0}}"),
            format!("{{\"payload\":\"{p}\",\"payload\":\"{p}\",\"signature\":\"{s}\"}}"),
            format!("{{\"payload\":\"{p}\",\"signature\":\"{s}\",\"signature\":\"{s}\"}}"),
            format!("{{\"payload\":\"{p}\"}}"),
            format!(
                "{{\"payload\":\"{p}\",\"signature\":\"{}\"}}",
                s.trim_end_matches('=')
            ),
            format!("{{\"payload\":\" {p}\",\"signature\":\"{s}\"}}"),
            format!("{{\"payload\":\"\",\"signature\":\"{s}\"}}"),
            format!("{{\"payload\":42,\"signature\":\"{s}\"}}"),
            format!(
                "{}null",
                String::from_utf8(signed.envelope.clone()).unwrap()
            ),
        ] {
            assert!(
                verify_phone_envelope(raw.as_bytes(), "spec.phone-policy", &keys(&key)).is_err()
            );
        }
        assert!(verify_phone_envelope(&[], "spec.phone-policy", &keys(&key)).is_err());
        let mut exact = signed.envelope;
        exact.resize(65536, b' ');
        let result = verify_phone_envelope(&exact, "spec.phone-policy", &keys(&key)).unwrap();
        assert_eq!(result.envelope, exact);
        exact.push(b' ');
        assert!(verify_phone_envelope(&exact, "spec.phone-policy", &keys(&key)).is_err());
    }

    #[test]
    fn exact_signed_whitespace_is_preserved_and_payload_over_limit_is_rejected() {
        let key = PolicySigningKey::generate().unwrap();
        let mut raw = serde_json::to_vec(&payload(vec![])).unwrap();
        raw.extend_from_slice(b" \n\t");
        let signed = envelope(&key, &raw);
        let verified = verify_phone_envelope(&signed, "spec.phone-policy", &keys(&key)).unwrap();
        assert_eq!(verified.payload_bytes, raw);
        assert_eq!(verified.envelope, signed);
        // The envelope's 65536-byte limit independently prevents a payload at
        // 49152 bytes from being accepted, because base64 and envelope add bytes.
        raw.resize(49153, b' ');
        assert_raw_rejected(&key, &raw);
    }
}
