//! Spec tests for `extract_all_sha256_tokens`.
//!
//! Independent of the implementation — pins the contract that the
//! multi-key parse path (full `ssh-keyscan | ssh-keygen -lf -` dump
//! for a host) relies on. A failing test means the impl drifted or
//! the spec is ambiguous; don't weaken the test to make it pass.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use vpnctl_host_fingerprint::extract_all_sha256_tokens;

// ─── empty / no-token inputs ─────────────────────────────────────

#[test]
fn empty_input_returns_empty_vec() {
    assert_eq!(extract_all_sha256_tokens(""), Vec::<String>::new());
}

#[test]
fn input_with_no_sha256_token_returns_empty_vec() {
    // An MD5-style ssh-keygen line carries no `SHA256:` token.
    let line = "256 MD5:1f:0a:7e:9c:33:aa:bc:de:01:23:45:67:89:ab:cd:ef host (ED25519)";
    assert_eq!(extract_all_sha256_tokens(line), Vec::<String>::new());
}

#[test]
fn whitespace_only_input_returns_empty_vec() {
    assert_eq!(
        extract_all_sha256_tokens("   \n\t  \n"),
        Vec::<String>::new()
    );
}

// ─── single key ──────────────────────────────────────────────────

#[test]
fn single_key_line_returns_one_token() {
    let line = "256 SHA256:Jl4XlKj9/e2igS3EoZmKshf5x6UqkWRjqoEavJaizp4 213.155.9.39 (ED25519)";
    assert_eq!(
        extract_all_sha256_tokens(line),
        vec!["SHA256:Jl4XlKj9/e2igS3EoZmKshf5x6UqkWRjqoEavJaizp4".to_string()],
    );
}

#[test]
fn returned_token_has_no_trailing_algo_or_whitespace() {
    let line = "256 SHA256:Jl4XlKj9/e2igS3EoZmKshf5x6UqkWRjqoEavJaizp4 213.155.9.39 (ED25519)";
    let out = extract_all_sha256_tokens(line);
    assert_eq!(out.len(), 1);
    let tok = &out[0];
    assert!(tok.starts_with("SHA256:"));
    assert!(
        !tok.contains(' '),
        "token must not carry surrounding whitespace: {tok:?}"
    );
    assert!(
        !tok.contains("(ED25519)"),
        "token must not carry the trailing algo: {tok:?}"
    );
    assert!(
        !tok.contains(')'),
        "token must not carry the trailing paren: {tok:?}"
    );
}

// ─── the verbatim two-key real-world example ─────────────────────

#[test]
fn two_key_real_world_example_returns_both_in_order() {
    let dump = "256 SHA256:Jl4XlKj9/e2igS3EoZmKshf5x6UqkWRjqoEavJaizp4 213.155.9.39 (ED25519)\n\
                3072 SHA256:szQm1QS8dN6awI29eG1hLbKah/156RmJV1EpNFqlNwc 213.155.9.39 (RSA)\n";
    assert_eq!(
        extract_all_sha256_tokens(dump),
        vec![
            "SHA256:Jl4XlKj9/e2igS3EoZmKshf5x6UqkWRjqoEavJaizp4".to_string(),
            "SHA256:szQm1QS8dN6awI29eG1hLbKah/156RmJV1EpNFqlNwc".to_string(),
        ],
    );
}

// ─── three-key dump (ed25519 + rsa + ecdsa) ──────────────────────

#[test]
fn three_key_dump_returns_three_tokens_preserving_order() {
    let dump = "256 SHA256:Jl4XlKj9/e2igS3EoZmKshf5x6UqkWRjqoEavJaizp4 10.0.0.1 (ED25519)\n\
                3072 SHA256:szQm1QS8dN6awI29eG1hLbKah/156RmJV1EpNFqlNwc 10.0.0.1 (RSA)\n\
                256 SHA256:abcdEFGHijklMNOPqrstUVWXyz0123456789AbCdEfGh 10.0.0.1 (ECDSA)\n";
    assert_eq!(
        extract_all_sha256_tokens(dump),
        vec![
            "SHA256:Jl4XlKj9/e2igS3EoZmKshf5x6UqkWRjqoEavJaizp4".to_string(),
            "SHA256:szQm1QS8dN6awI29eG1hLbKah/156RmJV1EpNFqlNwc".to_string(),
            "SHA256:abcdEFGHijklMNOPqrstUVWXyz0123456789AbCdEfGh".to_string(),
        ],
    );
}

// ─── does NOT validate base64 shape ──────────────────────────────

#[test]
fn does_not_validate_shape_short_token_returned_verbatim() {
    // Shape validation is a different function's job; any token
    // starting with `SHA256:` is returned as-is.
    let line = "256 SHA256:short comment (ED25519)";
    assert_eq!(
        extract_all_sha256_tokens(line),
        vec!["SHA256:short".to_string()]
    );
}

#[test]
fn token_must_start_with_prefix_substring_match_does_not_count() {
    // A token where `SHA256:` is not at the start is NOT a match;
    // only tokens that START with the literal prefix are returned.
    let line = "256 NOTSHA256:Jl4XlKj9 host (ED25519)";
    assert_eq!(extract_all_sha256_tokens(line), Vec::<String>::new());
}
