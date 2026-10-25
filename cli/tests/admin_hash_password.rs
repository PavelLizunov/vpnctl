use std::io::Write;
use std::process::{Command, Stdio};

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

#[test]
#[allow(clippy::unwrap_used, clippy::expect_used)]
fn hash_password_from_stdin_round_trip_verifies_without_line_ending() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_vpnctl"))
        .args(["admin", "hash-password"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run hash-password command");
    child.stdin.take().unwrap().write_all(b"hunter2\n").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let phc = String::from_utf8(output.stdout).unwrap();
    let parsed = PasswordHash::new(phc.trim()).unwrap();
    assert_eq!(parsed.algorithm.as_str(), "argon2id");
    Argon2::default()
        .verify_password(b"hunter2", &parsed)
        .expect("must verify the stdin password without the line ending");
}
