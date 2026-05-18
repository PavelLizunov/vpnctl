//! Spec tests for `vpnctl-host-fingerprint`.
//!
//! These tests pin the contract that the three former call-sites
//! (CLI `vpnctl server set-fingerprint`, daemon
//! `POST /admin/servers/{id}/set-fingerprint`, daemon wizard
//! `ssh_keyscan_fingerprint`) rely on. If a test starts failing,
//! check whether the implementation drifted OR the spec was
//! ambiguous; don't weaken a test to make it pass.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use vpnctl_host_fingerprint::{
    Error, build_keyscan_args, extract_sha256_token, pick_key_line, validate_shape,
};

// ─── validate_shape ──────────────────────────────────────────────

#[test]
fn validate_accepts_canonical_unpadded_sha256() {
    // Exactly 43 base64 chars unpadded, standard alphabet.
    assert!(validate_shape(
        "SHA256:+cuHezsjR805tS/zcSG25H1InN2OHqpzIJlTmCDctS4"
    ));
}

#[test]
fn validate_accepts_padded_sha256() {
    // 44 chars with trailing `=` — some emitters keep the pad byte.
    assert!(validate_shape(
        "SHA256:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ="
    ));
}

#[test]
fn validate_accepts_url_safe_alphabet() {
    // URL-safe base64: `-` and `_` instead of `+` and `/`.
    // Real-world: GitHub UI copy-button output, jq one-liners.
    assert!(validate_shape(
        "SHA256:-cuHezsjR805tS_zcSG25H1InN2OHqpzIJlTmCDctS4"
    ));
}

#[test]
fn validate_rejects_md5_prefix() {
    assert!(!validate_shape(
        "MD5:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99"
    ));
}

#[test]
fn validate_rejects_no_prefix() {
    // 43 chars but missing the SHA256: prefix.
    assert!(!validate_shape(
        "+cuHezsjR805tS/zcSG25H1InN2OHqpzIJlTmCDctS4"
    ));
}

#[test]
fn validate_rejects_empty_body() {
    assert!(!validate_shape("SHA256:"));
}

#[test]
fn validate_rejects_too_short_body() {
    // 42 chars — SHA-256 is exactly 32 bytes → 43 base64 chars
    // unpadded; anything shorter is structurally wrong.
    let body: String = "A".repeat(42);
    assert!(!validate_shape(&format!("SHA256:{body}")));
}

#[test]
fn validate_rejects_too_long_body() {
    // 45 chars — beyond the longest possible representation.
    let body: String = "A".repeat(45);
    assert!(!validate_shape(&format!("SHA256:{body}")));
}

#[test]
fn validate_rejects_invalid_chars() {
    // Whitespace, `:`, `!`, etc. are not in either base64 alphabet.
    assert!(!validate_shape(
        "SHA256:!!cuHezsjR805tS/zcSG25H1InN2OHqpzIJlTmCDctS4"
    ));
    assert!(!validate_shape(
        "SHA256: cuHezsjR805tS/zcSG25H1InN2OHqpzIJlTmCDctS4"
    ));
}

#[test]
fn validate_rejects_empty_string() {
    assert!(!validate_shape(""));
}

#[test]
fn validate_rejects_just_prefix_with_extra_colon() {
    assert!(!validate_shape("SHA256::"));
}

// ─── pick_key_line ───────────────────────────────────────────────

#[test]
fn pick_prefers_ed25519_over_rsa() {
    // Real ssh-keyscan output (whitespace + 2 keys, ed25519 second).
    let out = "\
example.com ssh-rsa AAAAB3NzaC1yc2EAAAA...rsa-body-here
example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...ed25519-body
";
    let chosen = pick_key_line(out).unwrap();
    assert!(chosen.contains("ssh-ed25519"));
    assert!(!chosen.contains("ssh-rsa"));
}

#[test]
fn pick_falls_back_to_rsa_when_ed25519_absent() {
    let out = "\
example.com ssh-rsa AAAAB3NzaC1yc2EAAAA...rsa-body
";
    let chosen = pick_key_line(out).unwrap();
    assert!(chosen.contains("ssh-rsa"));
}

#[test]
fn pick_uses_positional_algo_match_not_substring() {
    // Regression for a real DNS-legal pathology: hostname literally
    // containing `ssh-ed25519` on a line that's actually rsa. The old
    // substring-based picker would falsely promote the rsa line and we
    // would silently pin the wrong fingerprint. The fix is positional:
    // look at the second whitespace token (the algo).
    let out = "\
ssh-ed25519.example.com ssh-rsa AAAAB3NzaC1yc2EAAAA...rsa-body
real.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...ed25519-body
";
    let chosen = pick_key_line(out).unwrap();
    assert!(
        chosen.starts_with("real.example.com"),
        "expected real ed25519 line, got: {chosen}"
    );
    assert!(chosen.contains(" ssh-ed25519 "));
}

#[test]
fn pick_skips_comment_lines() {
    let out = "\
# example.com:22 SSH-2.0-OpenSSH_9.2p1
# host hash bytes...
example.com ssh-ed25519 AAAA...key-body
";
    let chosen = pick_key_line(out).unwrap();
    assert!(chosen.contains("ssh-ed25519"));
    assert!(!chosen.starts_with('#'));
}

#[test]
fn pick_returns_none_on_only_comments() {
    let out = "\
# nothing useful
# but a header
";
    assert!(pick_key_line(out).is_none());
}

#[test]
fn pick_returns_none_on_empty_input() {
    assert!(pick_key_line("").is_none());
}

// ─── extract_sha256_token ────────────────────────────────────────

#[test]
fn extract_pulls_sha256_from_canonical_ssh_keygen_output() {
    // Format: `<bits> SHA256:<body> <comment> (<ALGO>)`.
    let out = "256 SHA256:+cuHezsjR805tS/zcSG25H1InN2OHqpzIJlTmCDctS4 root@host (ED25519)\n";
    assert_eq!(
        extract_sha256_token(out),
        Some("SHA256:+cuHezsjR805tS/zcSG25H1InN2OHqpzIJlTmCDctS4".to_string())
    );
}

#[test]
fn extract_handles_extra_whitespace() {
    let out = "   256    SHA256:abcXYZ012   weird-comment   (ED25519)  \n";
    assert_eq!(
        extract_sha256_token(out),
        Some("SHA256:abcXYZ012".to_string())
    );
}

#[test]
fn extract_returns_none_when_no_sha256_token() {
    let out = "256 MD5:aa:bb:cc root@host (RSA)\n";
    assert!(extract_sha256_token(out).is_none());
}

#[test]
fn extract_returns_none_on_empty_input() {
    assert!(extract_sha256_token("").is_none());
}

// ─── Error Display contract ──────────────────────────────────────

#[test]
fn error_display_mentions_host_and_port_on_keyscan_failed() {
    let e = Error::KeyscanFailed {
        host: "example.com".to_string(),
        port: 2222,
        code: Some(1),
        stderr: "Connection refused".to_string(),
    };
    let msg = e.to_string();
    assert!(
        msg.contains("example.com"),
        "expected host in error: {msg}"
    );
    assert!(msg.contains("2222"), "expected port in error: {msg}");
    assert!(
        msg.contains("Connection refused"),
        "expected stderr in error: {msg}"
    );
}

// ─── build_keyscan_args (security-contract pin) ──────────────────

#[test]
fn keyscan_args_include_double_dash_before_host() {
    // The `--` separator is the load-bearing defense against
    // flag-injection via an attacker-controlled (or typo'd) inventory
    // address starting with `-`. Without it, `ssh-keyscan -fsomething`
    // reads attacker-controlled file. This test fails immediately if a
    // future refactor reorders or drops the separator.
    let args = build_keyscan_args("2222", "-fmalicious");
    let dash_dash_pos = args
        .iter()
        .position(|&a| a == "--")
        .expect("ssh-keyscan argv MUST include `--`");
    let host_pos = args
        .iter()
        .position(|&a| a == "-fmalicious")
        .expect("host must be passed as an argv element");
    assert!(
        dash_dash_pos < host_pos,
        "`--` must come BEFORE host in argv: got args={args:?}"
    );
    // Belt-and-braces: `--` must be IMMEDIATELY before host.
    assert_eq!(
        host_pos,
        dash_dash_pos + 1,
        "`--` must be immediately before host: got args={args:?}"
    );
}

#[test]
fn keyscan_args_request_ed25519_first_with_rsa_fallback() {
    let args = build_keyscan_args("22", "example.com");
    let t_pos = args
        .iter()
        .position(|&a| a == "-t")
        .expect("argv must request explicit key types via -t");
    assert_eq!(
        args.get(t_pos + 1),
        Some(&"ed25519,rsa"),
        "key types must be ed25519,rsa (ed25519 first) — got {args:?}"
    );
}

#[test]
fn keyscan_args_set_connect_timeout() {
    let args = build_keyscan_args("22", "example.com");
    let t_pos = args
        .iter()
        .position(|&a| a == "-T")
        .expect("argv must include connect timeout flag -T");
    assert_eq!(
        args.get(t_pos + 1),
        Some(&"10"),
        "connect timeout must be 10s — got {args:?}"
    );
}

#[test]
fn error_display_quotes_output_on_no_fingerprint_token() {
    let e = Error::NoFingerprintToken {
        output: "256 garbage root@host".to_string(),
    };
    let msg = e.to_string();
    assert!(msg.contains("garbage"), "expected output in error: {msg}");
}
