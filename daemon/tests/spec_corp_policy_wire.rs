// Independent tests derived from docs/specs/corp-policy-wire.md and public fixtures.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod spec {
    use std::collections::BTreeMap;

    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use p256::{
        ecdsa::{
            Signature, SigningKey, VerifyingKey,
            signature::{Signer, Verifier},
        },
        pkcs8::{DecodePrivateKey, DecodePublicKey},
    };
    use serde::Deserialize;
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use vpnctld::corp_policy::{
        PolicyPayload, PolicyRule, PolicySigningKey, normalize_site, seed_rules,
        validate_public_key, validate_rules, verify_envelope,
    };

    const MAX_REVISION: u64 = 9_007_199_254_740_991;
    const MAX_PUBLISHED_AT: u64 = 253_402_300_799;
    const PROTECTED: [&str; 5] = [
        "uiscom.ru",
        "uiscom.co",
        "comagic.ru",
        "callbackhunter.com",
        "admin.corp.ninitux.com",
    ];

    #[derive(Debug, Deserialize)]
    struct Fixture {
        policy_id: String,
        key_id: String,
        spki: String,
        cases: Vec<FixtureCase>,
    }

    #[derive(Debug, Deserialize)]
    struct FixtureCase {
        name: String,
        valid: bool,
        payload_utf8: String,
        payload_sha256: String,
        envelope: Value,
    }

    fn fixture() -> Fixture {
        serde_json::from_str(include_str!("../assets/corp-policy/v1.json")).unwrap()
    }

    fn rule(domain: &str, action: &str, comment: &str) -> PolicyRule {
        PolicyRule {
            domain: domain.to_owned(),
            action: action.to_owned(),
            comment: comment.to_owned(),
        }
    }

    fn payload() -> PolicyPayload {
        PolicyPayload {
            schema: 1,
            policy_id: "test-policy".to_owned(),
            key_id: "test-key".to_owned(),
            revision: 1,
            published_at: 1,
            apply: "next_connection".to_owned(),
            rules: Vec::new(),
        }
    }

    fn key_map(key: &PolicySigningKey) -> BTreeMap<String, String> {
        BTreeMap::from([("test-key".to_owned(), key.spki_base64().unwrap())])
    }

    fn raw_envelope(key: &PolicySigningKey, bytes: &[u8]) -> Vec<u8> {
        let der = key.export_pkcs8_der().unwrap();
        let signer = SigningKey::from_pkcs8_der(der.as_bytes()).unwrap();
        let signature: Signature = signer.sign(bytes);
        serde_json::to_vec(&json!({
            "payload": STANDARD.encode(bytes),
            "signature": STANDARD.encode(signature.to_bytes()),
        }))
        .unwrap()
    }

    fn assert_invalid_payload(key: &PolicySigningKey, invalid: &PolicyPayload) {
        assert!(key.sign(invalid).is_err(), "sign accepted {invalid:?}");
        let bytes = serde_json::to_vec(invalid).unwrap();
        assert!(
            verify_envelope(
                &raw_envelope(key, &bytes),
                &invalid.policy_id,
                &key_map(key)
            )
            .is_err(),
            "verify accepted {invalid:?}"
        );
    }

    fn assert_invalid_raw(key: &PolicySigningKey, bytes: &[u8]) {
        assert!(
            verify_envelope(&raw_envelope(key, bytes), "test-policy", &key_map(key)).is_err(),
            "accepted malformed payload {:?}",
            String::from_utf8_lossy(bytes)
        );
    }

    #[test]
    fn public_vectors_verify_exact_payload_envelope_and_uppercase_digest() {
        let fixture = fixture();
        let keys = BTreeMap::from([(fixture.key_id.clone(), fixture.spki.clone())]);
        for case in fixture.cases {
            let envelope = serde_json::to_vec(&case.envelope).unwrap();
            let result = verify_envelope(&envelope, &fixture.policy_id, &keys);
            if case.valid {
                let signed = result.unwrap();
                assert_eq!(
                    signed.payload_bytes,
                    case.payload_utf8.as_bytes(),
                    "{}",
                    case.name
                );
                assert_eq!(signed.envelope, envelope, "{}", case.name);
                assert_eq!(signed.payload_sha256, case.payload_sha256, "{}", case.name);
                assert_eq!(
                    signed.payload,
                    serde_json::from_str::<PolicyPayload>(&case.payload_utf8).unwrap()
                );
            } else {
                assert!(result.is_err(), "{}", case.name);
            }
        }
    }

    #[test]
    fn fixture_signature_is_interoperable_with_independent_p256_verification() {
        let fixture = fixture();
        let der = STANDARD.decode(&fixture.spki).unwrap();
        let public = VerifyingKey::from_public_key_der(&der).unwrap();
        for case in fixture.cases.into_iter().filter(|case| case.valid) {
            let signature = STANDARD
                .decode(case.envelope["signature"].as_str().unwrap())
                .unwrap();
            assert_eq!(signature.len(), 64);
            let signature = Signature::from_slice(&signature).unwrap();
            public
                .verify(case.payload_utf8.as_bytes(), &signature)
                .unwrap();
        }
    }

    #[test]
    fn signing_uses_exact_compact_field_order_p1363_and_both_apply_modes() {
        let key = PolicySigningKey::generate().unwrap();
        for apply in ["next_connection", "now"] {
            let mut input = payload();
            input.apply = apply.to_owned();
            input.rules = vec![rule("example.com", "direct", "Company site")];
            let signed = key.sign(&input).unwrap();
            let expected = format!(
                "{{\"schema\":1,\"policy_id\":\"test-policy\",\"key_id\":\"test-key\",\"revision\":1,\"published_at\":1,\"apply\":\"{apply}\",\"rules\":[{{\"domain\":\"example.com\",\"action\":\"direct\",\"comment\":\"Company site\"}}]}}"
            );
            assert_eq!(signed.payload_bytes, expected.as_bytes());
            assert_eq!(signed.payload, input);
            assert_eq!(
                signed.payload_sha256,
                format!("{:X}", Sha256::digest(expected.as_bytes()))
            );
            let envelope: Value = serde_json::from_slice(&signed.envelope).unwrap();
            assert_eq!(envelope.as_object().unwrap().len(), 2);
            assert_eq!(
                STANDARD
                    .decode(envelope["payload"].as_str().unwrap())
                    .unwrap(),
                signed.payload_bytes
            );
            let signature = STANDARD
                .decode(envelope["signature"].as_str().unwrap())
                .unwrap();
            assert_eq!(signature.len(), 64);
            let public = VerifyingKey::from_public_key_der(
                &STANDARD.decode(key.spki_base64().unwrap()).unwrap(),
            )
            .unwrap();
            public
                .verify(
                    &signed.payload_bytes,
                    &Signature::from_slice(&signature).unwrap(),
                )
                .unwrap();
            assert_eq!(
                verify_envelope(&signed.envelope, "test-policy", &key_map(&key)).unwrap(),
                signed
            );
            assert_eq!(key.sign(&input).unwrap().payload_bytes, expected.as_bytes());
        }
    }

    #[test]
    fn verify_preserves_noncanonical_json_whitespace_and_field_order() {
        let key = PolicySigningKey::generate().unwrap();
        let bytes = br#" { "rules": [], "apply": "now", "published_at": 1, "revision": 1, "key_id": "test-key", "policy_id": "test-policy", "schema": 1 } "#;
        let mut envelope = raw_envelope(&key, bytes);
        envelope.insert(0, b' ');
        envelope.push(b'\n');
        let signed = verify_envelope(&envelope, "test-policy", &key_map(&key)).unwrap();
        assert_eq!(signed.payload_bytes, bytes);
        assert_eq!(signed.envelope, envelope);
        assert_eq!(
            signed.payload_sha256,
            format!("{:X}", Sha256::digest(bytes))
        );
        assert_eq!(signed.payload.apply, "now");
    }

    #[test]
    fn key_export_import_preserves_identity_and_hides_private_material_in_debug() {
        let key = PolicySigningKey::generate().unwrap();
        let der = key.export_pkcs8_der().unwrap();
        let restored = PolicySigningKey::from_pkcs8_der(der.as_bytes()).unwrap();
        assert_eq!(restored.spki_base64().unwrap(), key.spki_base64().unwrap());
        validate_public_key(&key.spki_base64().unwrap()).unwrap();
        let signed = restored.sign(&payload()).unwrap();
        verify_envelope(&signed.envelope, "test-policy", &key_map(&key)).unwrap();
        let signer = SigningKey::from_pkcs8_der(der.as_bytes()).unwrap();
        let scalar = signer.to_bytes();
        for debug in [format!("{key:?}"), format!("{der:?}")] {
            for private in [
                STANDARD.encode(der.as_bytes()),
                STANDARD.encode(scalar),
                format!("{:?}", der.as_bytes()),
                format!("{:?}", scalar.as_slice()),
                scalar
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>(),
                scalar
                    .iter()
                    .map(|byte| format!("{byte:02X}"))
                    .collect::<String>(),
            ] {
                assert!(
                    !debug.contains(&private),
                    "Debug revealed private key material"
                );
            }
        }
        assert_ne!(
            PolicySigningKey::generate().unwrap().spki_base64().unwrap(),
            key.spki_base64().unwrap()
        );
    }

    #[test]
    fn private_key_import_rejects_empty_truncated_wrong_curve_and_non_der_data() {
        let key = PolicySigningKey::generate().unwrap();
        let der = key.export_pkcs8_der().unwrap();
        let mut wrong_curve = der.as_bytes().to_vec();
        let oid = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
        let offset = wrong_curve
            .windows(oid.len())
            .position(|window| window == oid)
            .unwrap();
        wrong_curve[offset + oid.len() - 1] = 8;
        for invalid in [
            Vec::new(),
            vec![0],
            b"not a PKCS8 key".to_vec(),
            der.as_bytes()[..der.as_bytes().len() - 1].to_vec(),
            STANDARD.decode(key.spki_base64().unwrap()).unwrap(),
            wrong_curve,
        ] {
            assert!(PolicySigningKey::from_pkcs8_der(&invalid).is_err());
        }
    }

    #[test]
    fn public_key_requires_canonical_base64_valid_p256_spki_and_bounded_der() {
        let fixture = fixture();
        validate_public_key(&fixture.spki).unwrap();
        let der = STANDARD.decode(&fixture.spki).unwrap();
        let mut wrong_curve = der.clone();
        let oid = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
        let offset = wrong_curve
            .windows(oid.len())
            .position(|window| window == oid)
            .unwrap();
        wrong_curve[offset + oid.len() - 1] = 8;
        let mut invalid_point = der.clone();
        let point = invalid_point.len() - 65;
        invalid_point[point..].fill(0);
        invalid_point[point] = 4;
        for invalid in [
            String::new(),
            fixture.spki.trim_end_matches('=').to_owned(),
            format!(" {}", fixture.spki),
            format!("{}\n", fixture.spki),
            fixture.spki.replace('+', "-").replace('/', "_"),
            STANDARD.encode(&der[..der.len() - 1]),
            STANDARD.encode(wrong_curve),
            STANDARD.encode(invalid_point),
            STANDARD.encode([0_u8; 257]),
            STANDARD.encode(der.iter().copied().chain([0]).collect::<Vec<_>>()),
        ] {
            assert!(
                validate_public_key(&invalid).is_err(),
                "accepted invalid public key shape"
            );
        }
    }

    #[test]
    fn verification_selects_only_the_exact_expected_policy_and_key_id() {
        let fixture = fixture();
        let case = &fixture.cases[0];
        let envelope = serde_json::to_vec(&case.envelope).unwrap();
        let correct = BTreeMap::from([(fixture.key_id.clone(), fixture.spki.clone())]);
        for expected in ["", "CORP-fixture", "corp-fixture.", "other-policy"] {
            assert!(verify_envelope(&envelope, expected, &correct).is_err());
        }
        let wrong_key = PolicySigningKey::generate().unwrap().spki_base64().unwrap();
        for keys in [
            BTreeMap::new(),
            BTreeMap::from([("FIXTURE-key".to_owned(), fixture.spki.clone())]),
            BTreeMap::from([("other-key".to_owned(), fixture.spki.clone())]),
            BTreeMap::from([
                (fixture.key_id.clone(), wrong_key),
                ("other-key".to_owned(), fixture.spki.clone()),
            ]),
            BTreeMap::from([(fixture.key_id.clone(), "invalid".to_owned())]),
        ] {
            assert!(verify_envelope(&envelope, &fixture.policy_id, &keys).is_err());
        }
        let mut with_unrelated_key = correct;
        with_unrelated_key.insert("unused-key".to_owned(), "invalid".to_owned());
        verify_envelope(&envelope, &fixture.policy_id, &with_unrelated_key).unwrap();
    }

    #[test]
    fn verification_rejects_changed_signed_bytes_and_non_p1363_signatures() {
        let fixture = fixture();
        let keys = BTreeMap::from([(fixture.key_id.clone(), fixture.spki.clone())]);
        let case = &fixture.cases[0];
        let signature = STANDARD
            .decode(case.envelope["signature"].as_str().unwrap())
            .unwrap();
        let mut changed = case.envelope.clone();
        changed["payload"] =
            json!(STANDARD.encode(case.payload_utf8.replace("Company site", "Changed site")));
        assert!(
            verify_envelope(
                &serde_json::to_vec(&changed).unwrap(),
                &fixture.policy_id,
                &keys
            )
            .is_err()
        );
        let mut flipped = signature.clone();
        flipped[0] ^= 1;
        let der_signature = Signature::from_slice(&signature).unwrap().to_der();
        for invalid in [
            Vec::new(),
            vec![0; 64],
            signature[..63].to_vec(),
            signature.iter().copied().chain([0]).collect(),
            flipped,
            der_signature.as_bytes().to_vec(),
        ] {
            let mut envelope = case.envelope.clone();
            envelope["signature"] = json!(STANDARD.encode(invalid));
            assert!(
                verify_envelope(
                    &serde_json::to_vec(&envelope).unwrap(),
                    &fixture.policy_id,
                    &keys
                )
                .is_err()
            );
        }
    }

    #[test]
    fn envelope_rejects_duplicate_unknown_missing_and_nonstring_fields() {
        let key = PolicySigningKey::generate().unwrap();
        let signed = key.sign(&payload()).unwrap();
        let value: Value = serde_json::from_slice(&signed.envelope).unwrap();
        let p = serde_json::to_string(&value["payload"]).unwrap();
        let s = serde_json::to_string(&value["signature"]).unwrap();
        let candidates = [
            format!("{{\"payload\":{p},\"payload\":{p},\"signature\":{s}}}"),
            format!("{{\"payload\":{p},\"signature\":{s},\"signature\":{s}}}"),
            format!("{{\"payload\":{p},\"signature\":{s},\"unknown\":true}}"),
            format!("{{\"payload\":{p}}}"),
            format!("{{\"signature\":{s}}}"),
            format!("{{\"payload\":null,\"signature\":{s}}}"),
            format!("{{\"payload\":{p},\"signature\":[]}}"),
            format!("{{\"payload\":{p},\"signature\":{s},}}"),
            format!("{{\"payload\":{p},\"signature\":{s}}} false"),
            format!("{{\"payload\":{p},\"signature\":{s}}} /*comment*/"),
            "[]".to_owned(),
            "null".to_owned(),
            "{}".to_owned(),
        ];
        for invalid in candidates {
            assert!(
                verify_envelope(invalid.as_bytes(), "test-policy", &key_map(&key)).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn envelope_requires_canonical_standard_base64_and_strict_utf8() {
        let fixture = fixture();
        let case = &fixture.cases[0];
        let keys = BTreeMap::from([(fixture.key_id.clone(), fixture.spki.clone())]);
        for field in ["payload", "signature"] {
            let original = case.envelope[field].as_str().unwrap();
            let last_data = original.len() - 3;
            let mut nonzero_pad_bits = original.as_bytes().to_vec();
            let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let value = alphabet
                .iter()
                .position(|&byte| byte == nonzero_pad_bits[last_data])
                .unwrap();
            nonzero_pad_bits[last_data] = alphabet[value + 1];
            for invalid in [
                String::new(),
                original.trim_end_matches('=').to_owned(),
                format!(" {original}"),
                format!("{original}\n"),
                format!("{original}="),
                String::from_utf8(nonzero_pad_bits).unwrap(),
            ] {
                let mut envelope = case.envelope.clone();
                envelope[field] = json!(invalid);
                assert!(
                    verify_envelope(
                        &serde_json::to_vec(&envelope).unwrap(),
                        &fixture.policy_id,
                        &keys
                    )
                    .is_err(),
                    "{field}"
                );
            }
        }
        let mut url_safe_signature = case.envelope.clone();
        url_safe_signature["signature"] = json!(
            case.envelope["signature"]
                .as_str()
                .unwrap()
                .replace('+', "-")
                .replace('/', "_")
        );
        assert!(
            verify_envelope(
                &serde_json::to_vec(&url_safe_signature).unwrap(),
                &fixture.policy_id,
                &keys
            )
            .is_err()
        );
        let mut invalid_utf8 = serde_json::to_vec(&case.envelope).unwrap();
        invalid_utf8.push(0xff);
        assert!(verify_envelope(&invalid_utf8, &fixture.policy_id, &keys).is_err());
        let key = PolicySigningKey::generate().unwrap();
        assert_invalid_raw(&key, &[0xff]);
        assert_invalid_raw(&key, b"");
    }

    #[test]
    fn correctly_signed_payload_rejects_every_duplicate_and_unknown_field() {
        let key = PolicySigningKey::generate().unwrap();
        let mut input = payload();
        input.rules = vec![rule("example.com", "direct", "site")];
        let value = serde_json::to_value(&input).unwrap();
        let text = serde_json::to_string(&value).unwrap();
        for field in [
            "schema",
            "policy_id",
            "key_id",
            "revision",
            "published_at",
            "apply",
            "rules",
        ] {
            let duplicate = format!("{{\"{field}\":{},{}", value[field], &text[1..]);
            assert_invalid_raw(&key, duplicate.as_bytes());
        }
        assert_invalid_raw(&key, format!("{{\"unknown\":1,{}", &text[1..]).as_bytes());
        for field in ["domain", "action", "comment"] {
            let original = serde_json::to_string(&value["rules"][0]).unwrap();
            let duplicate = format!(
                "{{\"{field}\":{},{}",
                value["rules"][0][field],
                &original[1..]
            );
            assert_invalid_raw(&key, text.replace(&original, &duplicate).as_bytes());
        }
        let mut extra_rule_field = value;
        extra_rule_field["rules"][0]["enabled"] = json!(true);
        assert_invalid_raw(&key, &serde_json::to_vec(&extra_rule_field).unwrap());
        let escaped_duplicate = text.replacen("{", "{\"schem\\u0061\":1,", 1);
        assert_invalid_raw(&key, escaped_duplicate.as_bytes());
    }

    #[test]
    fn correctly_signed_payload_rejects_missing_fields_and_invalid_json_types() {
        let key = PolicySigningKey::generate().unwrap();
        let mut input = payload();
        input.rules = vec![rule("example.com", "direct", "")];
        let value = serde_json::to_value(&input).unwrap();
        for field in [
            "schema",
            "policy_id",
            "key_id",
            "revision",
            "published_at",
            "apply",
            "rules",
        ] {
            let mut missing = value.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert_invalid_raw(&key, &serde_json::to_vec(&missing).unwrap());
            let mut wrong_type = value.clone();
            wrong_type[field] = Value::Null;
            assert_invalid_raw(&key, &serde_json::to_vec(&wrong_type).unwrap());
        }
        for field in ["domain", "action", "comment"] {
            let mut missing = value.clone();
            missing["rules"][0].as_object_mut().unwrap().remove(field);
            assert_invalid_raw(&key, &serde_json::to_vec(&missing).unwrap());
            let mut wrong_type = value.clone();
            wrong_type["rules"][0][field] = json!(false);
            assert_invalid_raw(&key, &serde_json::to_vec(&wrong_type).unwrap());
        }
        for (field, wrong) in [
            ("schema", json!("1")),
            ("revision", json!(true)),
            ("rules", json!({})),
            ("policy_id", json!(1)),
        ] {
            let mut invalid = value.clone();
            invalid[field] = wrong;
            assert_invalid_raw(&key, &serde_json::to_vec(&invalid).unwrap());
        }
    }

    #[test]
    fn integer_fields_reject_decimal_exponent_negative_and_overflow_tokens() {
        let key = PolicySigningKey::generate().unwrap();
        let bytes = serde_json::to_string(&payload()).unwrap();
        for field in ["schema", "revision", "published_at"] {
            for number in [
                "1.0",
                "1e0",
                "1E+0",
                "-1",
                "-0",
                "01",
                "18446744073709551616",
            ] {
                let invalid =
                    bytes.replace(&format!("\"{field}\":1"), &format!("\"{field}\":{number}"));
                assert_invalid_raw(&key, invalid.as_bytes());
            }
        }
    }

    #[test]
    fn payload_rejects_trailing_data_comments_commas_and_deep_json() {
        let key = PolicySigningKey::generate().unwrap();
        let text = serde_json::to_string(&payload()).unwrap();
        for invalid in [
            format!("{text}{{}}"),
            format!("{text} null"),
            format!("{text}// comment"),
            text.replacen("{", "{/*comment*/", 1),
            format!("{},}}", &text[..text.len() - 1]),
            format!(
                "{{\"unknown\":{}0{},{}",
                "[".repeat(9),
                "]".repeat(9),
                &text[1..]
            ),
            "[]".to_owned(),
            "null".to_owned(),
        ] {
            assert_invalid_raw(&key, invalid.as_bytes());
        }
    }

    #[test]
    fn signing_and_verification_enforce_integer_and_apply_boundaries() {
        let key = PolicySigningKey::generate().unwrap();
        for (revision, published_at) in [(1, 1), (MAX_REVISION, MAX_PUBLISHED_AT)] {
            for apply in ["now", "next_connection"] {
                let mut valid = payload();
                valid.revision = revision;
                valid.published_at = published_at;
                valid.apply = apply.to_owned();
                let signed = key.sign(&valid).unwrap();
                assert_eq!(
                    verify_envelope(&signed.envelope, "test-policy", &key_map(&key))
                        .unwrap()
                        .payload,
                    valid
                );
            }
        }
        for schema in [0, 2, u64::MAX] {
            let mut invalid = payload();
            invalid.schema = schema;
            assert_invalid_payload(&key, &invalid);
        }
        for revision in [0, MAX_REVISION + 1, u64::MAX] {
            let mut invalid = payload();
            invalid.revision = revision;
            assert_invalid_payload(&key, &invalid);
        }
        for published_at in [0, MAX_PUBLISHED_AT + 1, u64::MAX] {
            let mut invalid = payload();
            invalid.published_at = published_at;
            assert_invalid_payload(&key, &invalid);
        }
        for apply in ["", "NOW", "next-connection", "now ", "later"] {
            let mut invalid = payload();
            invalid.apply = apply.to_owned();
            assert_invalid_payload(&key, &invalid);
        }
    }

    #[test]
    fn policy_and_key_identifiers_enforce_ascii_alphabet_and_one_to_64_bytes() {
        let key = PolicySigningKey::generate().unwrap();
        for id in ["A".to_owned(), "Abc-_.09".to_owned(), "x".repeat(64)] {
            let mut valid = payload();
            valid.policy_id = id.clone();
            valid.key_id = id.clone();
            let signed = key.sign(&valid).unwrap();
            let keys = BTreeMap::from([(id.clone(), key.spki_base64().unwrap())]);
            assert_eq!(
                verify_envelope(&signed.envelope, &id, &keys)
                    .unwrap()
                    .payload,
                valid
            );
        }
        for id in [
            "".to_owned(),
            "x".repeat(65),
            "with space".to_owned(),
            "a/b".to_owned(),
            "é".to_owned(),
            "a\n".to_owned(),
        ] {
            for field in ["policy_id", "key_id"] {
                let mut invalid = payload();
                if field == "policy_id" {
                    invalid.policy_id = id.clone();
                } else {
                    invalid.key_id = id.clone();
                }
                assert!(key.sign(&invalid).is_err());
                let keys = BTreeMap::from([(invalid.key_id.clone(), key.spki_base64().unwrap())]);
                assert!(
                    verify_envelope(
                        &raw_envelope(&key, &serde_json::to_vec(&invalid).unwrap()),
                        &invalid.policy_id,
                        &keys
                    )
                    .is_err()
                );
            }
        }
    }

    fn payload_with_length(length: usize) -> PolicyPayload {
        let mut input = payload();
        input.rules = (0..180)
            .map(|i| rule(&format!("site-{i}.example.com"), "direct", ""))
            .collect();
        let baseline = serde_json::to_vec(&input).unwrap().len();
        let mut remaining = length.checked_sub(baseline).unwrap();
        for rule in &mut input.rules {
            let count = remaining.min(256);
            rule.comment = "a".repeat(count);
            remaining -= count;
        }
        assert_eq!(remaining, 0);
        assert_eq!(serde_json::to_vec(&input).unwrap().len(), length);
        input
    }

    #[test]
    fn signing_checks_final_envelope_size_as_well_as_payload_size() {
        let key = PolicySigningKey::generate().unwrap();
        let valid = payload_with_length(48_000);
        let signed = key.sign(&valid).unwrap();
        assert!(signed.envelope.len() <= 65_536);
        verify_envelope(&signed.envelope, "test-policy", &key_map(&key)).unwrap();
        for size in [49_100, 49_152, 49_153] {
            let oversized = payload_with_length(size);
            assert!(
                key.sign(&oversized).is_err(),
                "accepted payload of {size} bytes whose final envelope exceeds 65536"
            );
            assert_invalid_raw(&key, &serde_json::to_vec(&oversized).unwrap());
        }
    }

    #[test]
    fn verification_accepts_exact_envelope_limit_and_rejects_empty_or_larger() {
        let key = PolicySigningKey::generate().unwrap();
        let mut envelope = key.sign(&payload()).unwrap().envelope;
        envelope.resize(65_536, b' ');
        let signed = verify_envelope(&envelope, "test-policy", &key_map(&key)).unwrap();
        assert_eq!(signed.envelope, envelope);
        envelope.push(b' ');
        assert!(verify_envelope(&envelope, "test-policy", &key_map(&key)).is_err());
        assert!(verify_envelope(b"", "test-policy", &key_map(&key)).is_err());
    }

    #[test]
    fn domain_fixture_matches_normalization_and_pinned_psl_rules() {
        let fixture: Value =
            serde_json::from_str(include_str!("../assets/corp-policy/domains.json")).unwrap();
        for case in fixture["normalization"].as_array().unwrap() {
            let input = case["input"].as_str().unwrap();
            match case["expected"].as_str() {
                Some(expected) => assert_eq!(normalize_site(input).unwrap(), expected, "{input}"),
                None => assert!(normalize_site(input).is_err(), "{input}"),
            }
        }
    }

    #[test]
    fn normalization_accepts_url_hostname_and_trims_spaces_but_not_control_characters() {
        for (input, expected) in [
            ("  EXAMPLE.COM.  ", "example.com"),
            ("http://Example.COM:8080/path?q=1#part", "example.com"),
            ("https://example.com./path", "example.com"),
            ("https://bücher.example:443/path", "xn--bcher-kva.example"),
            ("xn--bcher-kva.example", "xn--bcher-kva.example"),
        ] {
            assert_eq!(normalize_site(input).unwrap(), expected);
        }
        for input in [
            "",
            "   ",
            "example",
            "example.com/path",
            "example.com?query",
            "example.com#fragment",
            "https://@example.com",
            "https://:password@example.com",
            "https://user:password@example.com",
            "http://127.1/",
            "https://2130706433/",
            "https://0x7f000001/",
            "https://[::1]/",
            "0177.0.0.1",
            "example.com\\path",
            "https://example.com\\path",
            "site-.example",
            "^example.com$",
            "/example.com/",
            "example.*",
            "xn--a.example",
            ".example.com",
            "example.com\n",
            "\texample.com",
            "exam\u{0000}ple.com",
            "example.com\u{0085}",
        ] {
            assert!(normalize_site(input).is_err(), "{input:?}");
        }
    }

    #[test]
    fn normalization_enforces_utf16_input_and_ascii_domain_length_boundaries() {
        let exact = format!("{}example.com", " ".repeat(4096 - "example.com".len()));
        assert_eq!(normalize_site(&exact).unwrap(), "example.com");
        assert!(normalize_site(&format!(" {exact}")).is_err());
        let prefix = "https://example.com/";
        let remaining = 4096 - prefix.encode_utf16().count();
        let exact = format!(
            "{prefix}{}{}",
            "😀".repeat(remaining / 2),
            "a".repeat(remaining % 2)
        );
        assert_eq!(exact.encode_utf16().count(), 4096);
        assert_eq!(normalize_site(&exact).unwrap(), "example.com");
        assert!(normalize_site(&format!("{exact}a")).is_err());
        let max_label = format!("{}.example.com", "a".repeat(63));
        assert_eq!(normalize_site(&max_label).unwrap(), max_label);
        assert!(normalize_site(&format!("{}.example.com", "a".repeat(64))).is_err());
        let max_domain = format!(
            "{}.{}.{}.{}.com",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(57)
        );
        assert_eq!(max_domain.len(), 253);
        assert_eq!(normalize_site(&max_domain).unwrap(), max_domain);
        assert!(normalize_site(&format!("a{max_domain}")).is_err());
        let too_long_domain = max_domain.replacen(&"d".repeat(57), &"d".repeat(58), 1);
        assert_eq!(too_long_domain.len(), 254);
        assert!(normalize_site(&too_long_domain).is_err());
    }

    #[test]
    fn rules_require_wire_domains_already_normalized_and_valid_directions() {
        validate_rules(&[]).unwrap();
        validate_rules(&[rule("xn--bcher-kva.example", "direct", "")]).unwrap();
        for domain in [
            "EXAMPLE.com",
            "example.com.",
            " example.com",
            "bücher.example",
            "https://example.com",
            "co.uk",
            "github.io",
            "a.ck",
            "example..com",
            "127.0.0.1",
        ] {
            assert!(
                validate_rules(&[rule(domain, "direct", "")]).is_err(),
                "{domain}"
            );
        }
        for action in ["", "DIRECT", "Proxy", "block", "direct "] {
            assert!(
                validate_rules(&[rule("example.com", action, "")]).is_err(),
                "{action}"
            );
        }
    }

    #[test]
    fn rules_reject_duplicates_and_opposite_suffix_intersections_in_both_orders() {
        for action in ["direct", "proxy"] {
            let parent = rule("example.com", action, "parent");
            let child = rule("a.example.com", action, "child");
            validate_rules(&[parent.clone(), child.clone()]).unwrap();
            validate_rules(&[child, parent.clone()]).unwrap();
            assert!(validate_rules(&[parent.clone(), parent]).is_err());
        }
        let parent = rule("example.com", "direct", "");
        let child = rule("a.example.com", "proxy", "");
        assert!(validate_rules(&[parent.clone(), child.clone()]).is_err());
        assert!(validate_rules(&[child, parent]).is_err());
        assert!(
            validate_rules(&[
                rule("example.com", "direct", ""),
                rule("example.com", "proxy", "")
            ])
            .is_err()
        );
        validate_rules(&[
            rule("example.com", "direct", ""),
            rule("notexample.com", "proxy", ""),
            rule("example.com.example.org", "proxy", ""),
        ])
        .unwrap();
    }

    #[test]
    fn editable_rules_exclude_all_protected_suffixes_and_ancestors() {
        for protected in PROTECTED {
            assert_eq!(normalize_site(protected).unwrap(), protected);
            for domain in [protected.to_owned(), format!("sub.{protected}")] {
                for action in ["direct", "proxy"] {
                    assert!(
                        validate_rules(&[rule(&domain, action, "")]).is_err(),
                        "{domain}"
                    );
                }
            }
        }
        for ancestor in ["corp.ninitux.com", "ninitux.com"] {
            assert!(validate_rules(&[rule(ancestor, "direct", "")]).is_err());
        }
        for neighbor in [
            "notuiscom.ru",
            "notcomagic.ru",
            "notcallbackhunter.com",
            "notadmin.corp.ninitux.com",
            "admin.corp.ninitux.com.example.org",
        ] {
            validate_rules(&[rule(neighbor, "proxy", "")]).unwrap();
        }
    }

    #[test]
    fn rule_count_and_utf8_comment_limits_are_inclusive() {
        let mut rules: Vec<_> = (0..512)
            .map(|i| rule(&format!("site-{i}.example.com"), "direct", ""))
            .collect();
        validate_rules(&rules).unwrap();
        rules.push(rule("site-512.example.com", "direct", ""));
        assert!(validate_rules(&rules).is_err());
        for comment in ["a".repeat(256), "é".repeat(128), "😀".repeat(64)] {
            assert_eq!(comment.len(), 256);
            validate_rules(&[rule("example.com", "direct", &comment)]).unwrap();
            assert!(
                validate_rules(&[rule("example.com", "direct", &format!("{comment}a"))]).is_err()
            );
        }
        for control in ['\0', '\n', '\r', '\t', '\u{007f}', '\u{0085}'] {
            assert!(
                validate_rules(&[rule("example.com", "direct", &format!("a{control}b"))]).is_err()
            );
        }
    }

    #[test]
    fn signing_and_verification_validate_editable_rules_before_acceptance() {
        let key = PolicySigningKey::generate().unwrap();
        for rules in [
            vec![rule("uiscom.ru", "direct", "")],
            vec![rule("EXAMPLE.COM", "direct", "")],
            vec![
                rule("example.com", "direct", ""),
                rule("a.example.com", "proxy", ""),
            ],
            vec![rule("example.com", "direct", &"a".repeat(257))],
            (0..513)
                .map(|i| rule(&format!("s{i}.example.com"), "direct", ""))
                .collect(),
        ] {
            let mut invalid = payload();
            invalid.rules = rules;
            assert_invalid_payload(&key, &invalid);
        }
    }

    #[test]
    fn seed_is_exact_editable_business_domains_in_source_order_and_can_be_signed() {
        let source: Vec<Value> =
            serde_json::from_str(include_str!("../assets/corp-policy/business-rules.json"))
                .unwrap();
        let expected: Vec<PolicyRule> = source
            .iter()
            .filter(|entry| {
                entry["enabled"] == true
                    && entry["type"] == "domain_suffix"
                    && !PROTECTED.contains(&entry["value"].as_str().unwrap())
            })
            .map(|entry| {
                rule(
                    entry["value"].as_str().unwrap(),
                    entry["action"].as_str().unwrap(),
                    entry["comment"].as_str().unwrap(),
                )
            })
            .collect();
        let seeded = seed_rules().unwrap();
        assert_eq!(seeded, expected);
        assert_eq!(seeded.len(), 32);
        assert_eq!(seeded.first().unwrap().domain, "dns-shop.ru");
        assert_eq!(seeded.last().unwrap().domain, "pinterest.ru");
        validate_rules(&seeded).unwrap();
        let key = PolicySigningKey::generate().unwrap();
        let mut input = payload();
        input.rules = seeded;
        let signed = key.sign(&input).unwrap();
        assert_eq!(
            verify_envelope(&signed.envelope, "test-policy", &key_map(&key))
                .unwrap()
                .payload,
            input
        );
    }
}
