//! Implementation-blind contract tests using only the public crypto API.
#![allow(clippy::unwrap_used)]

use base64::{Engine as _, engine::general_purpose::STANDARD};
use vpnctl_crypto::{gen_wireguard_keypair, wireguard_keypair_matches};
use x25519_dalek::{PublicKey, StaticSecret};

fn independent_pair(bytes: [u8; 32]) -> (String, String) {
    let secret = StaticSecret::from(bytes);
    let public = PublicKey::from(&secret);
    (STANDARD.encode(bytes), STANDARD.encode(public.as_bytes()))
}

fn malformed_encodings(key: &str) -> Vec<(&'static str, String)> {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut noncanonical = key.as_bytes().to_vec();
    let last = alphabet
        .iter()
        .position(|&byte| byte == noncanonical[42])
        .unwrap();
    // A 32-byte encoding has two unused low bits in its final sextet.
    // Changing just those bits must be rejected, not decoded as the same key.
    noncanonical[42] = alphabet[last | 1];

    let mut cases = vec![
        ("empty", String::new()),
        ("missing padding", key.trim_end_matches('=').to_owned()),
        ("excess padding", format!("{key}=")),
        ("embedded padding", format!("{}={}", &key[..20], &key[21..])),
        ("nonzero pad bits", String::from_utf8(noncanonical).unwrap()),
        ("31 bytes", STANDARD.encode([1_u8; 31])),
        ("33 bytes", STANDARD.encode([1_u8; 33])),
        ("leading space", format!(" {key}")),
        ("trailing space", format!("{key} ")),
        ("trailing newline", format!("{key}\n")),
        ("trailing CRLF", format!("{key}\r\n")),
        (
            "embedded newline",
            format!("{}\n{}", &key[..20], &key[20..]),
        ),
        ("invalid ASCII", format!("!{}", &key[1..])),
        ("URL-safe dash", format!("-{}", &key[1..])),
        ("URL-safe underscore", format!("_{}", &key[1..])),
        ("Unicode", format!("é{}", &key[1..])),
        ("NUL", format!("{key}\0")),
    ];
    let url_safe = key.replace('+', "-").replace('/', "_");
    if url_safe != key {
        cases.push(("URL-safe alphabet", url_safe));
    }
    cases
}

#[test]
fn accepts_canonical_generated_and_independently_derived_pairs() {
    for (private, public) in [gen_wireguard_keypair(), independent_pair([0xfb; 32])] {
        for key in [&private, &public] {
            assert_eq!(key.len(), 44);
            assert!(key.ends_with('='));
            let decoded = STANDARD.decode(key).unwrap();
            assert_eq!(decoded.len(), 32);
            // Boolean assertions deliberately avoid printing key material.
            assert!(STANDARD.encode(decoded) == *key);
        }
        assert!(wireguard_keypair_matches(&private, &public));
    }
}

#[test]
fn rejects_crossed_independently_generated_pairs() {
    let (private_a, public_a) = gen_wireguard_keypair();
    let (private_b, public_b) = gen_wireguard_keypair();
    assert!(public_a != public_b, "independent generation collided");
    assert!(wireguard_keypair_matches(&private_a, &public_a));
    assert!(wireguard_keypair_matches(&private_b, &public_b));
    assert!(!wireguard_keypair_matches(&private_a, &public_b));
    assert!(!wireguard_keypair_matches(&private_b, &public_a));
}

#[test]
fn rejects_malformed_and_noncanonical_private_or_public_encodings() {
    let (private, public) = independent_pair([0xfb; 32]);
    assert!(private.contains('+') && private.contains('/'));
    assert!(wireguard_keypair_matches(&private, &public));

    for (case, invalid) in malformed_encodings(&private) {
        assert!(
            !wireguard_keypair_matches(&invalid, &public),
            "accepted invalid private encoding: {case}"
        );
    }
    for (case, invalid) in malformed_encodings(&public) {
        assert!(
            !wireguard_keypair_matches(&private, &invalid),
            "accepted invalid public encoding: {case}"
        );
    }
    assert!(!wireguard_keypair_matches("", ""));
}

#[test]
fn rejects_zero_keys_even_when_zero_private_derives_the_supplied_public() {
    let (zero, derived_public) = independent_pair([0; 32]);
    let (private, public) = independent_pair([0xfb; 32]);
    assert!(!wireguard_keypair_matches(&zero, &derived_public));
    assert!(!wireguard_keypair_matches(&zero, &public));
    assert!(!wireguard_keypair_matches(&private, &zero));
    assert!(!wireguard_keypair_matches(&zero, &zero));
}

#[test]
fn repeated_checks_are_deterministic_and_preserve_supplied_identity() {
    let (private, public) = gen_wireguard_keypair();
    let (_, other_public) = gen_wireguard_keypair();
    let original_private = private.clone();
    let original_public = public.clone();
    assert!(public != other_public, "independent generation collided");

    for _ in 0..32 {
        let matched: bool = wireguard_keypair_matches(&private, &public);
        let mismatched: bool = wireguard_keypair_matches(&private, &other_public);
        let malformed: bool = wireguard_keypair_matches("invalid", &public);
        assert!(matched);
        assert!(!mismatched);
        assert!(!malformed);
        assert!(private == original_private);
        assert!(public == original_public);
    }
}
