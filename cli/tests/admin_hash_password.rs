use std::process::Command;

use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordVerifier},
};

#[test]
#[allow(clippy::unwrap_used, clippy::expect_used)]
fn hash_password_round_trip_verifies_with_same_plaintext() {
    let output = Command::new(env!("CARGO_BIN_EXE_vpnctl"))
        .args(["admin", "hash-password", "--password", "hunter2"])
        .output()
        .expect("run hash-password command");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let phc = String::from_utf8(output.stdout).unwrap();
    let parsed = PasswordHash::new(phc.trim()).unwrap();
    assert_eq!(parsed.algorithm.as_str(), "argon2id");
    Argon2::default()
        .verify_password(b"hunter2", &parsed)
        .expect("must verify the original plaintext");
    Argon2::default()
        .verify_password(b"wrong-pw", &parsed)
        .expect_err("must reject a different plaintext");
}

#[test]
#[allow(clippy::unwrap_used, clippy::expect_used)]
fn hash_password_rejects_empty_plaintext() {
    let output = Command::new(env!("CARGO_BIN_EXE_vpnctl"))
        .args(["admin", "hash-password", "--password", ""])
        .output()
        .expect("run hash-password command");
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("empty password"));
}
