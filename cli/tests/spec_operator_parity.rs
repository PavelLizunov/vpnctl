#![cfg(unix)]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const MISSING_USER: &str = "spec-parity-missing-user";
const MISSING_SERVER: &str = "spec-parity-missing-server";
const MISSING_PROTOCOL: &str = "spec-parity-missing-protocol";

struct TempDir(PathBuf);

impl TempDir {
    fn new(test_name: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must be after the Unix epoch")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("vpnctl-{test_name}-{}-{nonce}", std::process::id()));
        fs::create_dir(&path).expect("create isolated test directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn vpnctl<I, S>(test_name: &str, args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let temp = TempDir::new(test_name);
    command(&temp, args).output().expect("run vpnctl")
}

fn command<I, S>(temp: &TempDir, args: I) -> Command
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let db = temp.path().join("inventory.db");
    let mut command = Command::new(env!("CARGO_BIN_EXE_vpnctl"));
    command
        .args(args)
        .current_dir(temp.path())
        .env("VPNCTL_DB", &db)
        .env("VPNCTL_DB_PATH", &db)
        .env("VPNCTL_INVENTORY_DB", &db);
    command
}

fn text(output: &Output) -> String {
    format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn assert_help(args: &[&str]) {
    let output = vpnctl("help", args);
    assert!(output.status.success(), "{}", text(&output));
    let combined = text(&output).to_lowercase();
    assert!(combined.contains("usage"), "{}", text(&output));
}

fn assert_cli_rejected(args: &[&str], expected: &[&str]) {
    let output = vpnctl("rejected", args);
    assert!(!output.status.success(), "command unexpectedly succeeded");
    let combined = text(&output).to_lowercase();
    assert!(
        expected.iter().any(|needle| combined.contains(needle)),
        "expected one of {expected:?}; {}",
        text(&output)
    );
}

#[test]
fn operator_parity_commands_are_registered() {
    for args in [
        &["user", "disable", "--help"][..],
        &["user", "enable", "--help"],
        &["user", "traffic-limit", "--help"],
        &["user", "regen-wireguard", "--help"],
        &["user", "wireguard-conf", "--help"],
        &["server", "protocol-hide", "--help"],
        &["server", "protocol-unhide", "--help"],
        &["grant-protocol-disable", "--help"],
        &["grant-protocol-enable", "--help"],
    ] {
        assert_help(args);
    }
}

#[test]
fn traffic_limit_requires_a_mode_and_enforces_the_gib_range() {
    assert_cli_rejected(
        &["user", "traffic-limit", MISSING_USER],
        &["limit-gib", "clear", "required"],
    );

    assert_cli_rejected(
        &[
            "user",
            "traffic-limit",
            MISSING_USER,
            "--limit-gib",
            "1",
            "--clear",
        ],
        &["cannot be used", "conflict", "exclusive"],
    );
}

#[test]
fn traffic_limit_accepts_both_range_boundaries_before_entity_lookup() {
    for limit in ["1", "100"] {
        let output = vpnctl(
            "traffic-limit-boundary",
            ["user", "traffic-limit", MISSING_USER, "--limit-gib", limit],
        );
        assert!(
            !output.status.success(),
            "missing user unexpectedly succeeded"
        );
        let combined = text(&output).to_lowercase();
        assert!(
            !combined.contains("invalid value") && !combined.contains("out of range"),
            "valid boundary {limit} was rejected by argument validation; {}",
            text(&output)
        );
    }
}

#[test]
fn regen_wireguard_exposes_explicit_confirmation_and_defaults_to_dry_run() {
    let help = vpnctl("regen-help", ["user", "regen-wireguard", "--help"]);
    assert!(help.status.success(), "{}", text(&help));
    let help_text = text(&help).to_lowercase();
    assert!(help_text.contains("--yes"), "{}", text(&help));
    assert!(
        help_text.contains("dry-run") || help_text.contains("dry run"),
        "regen without --yes must be documented as a dry-run; {}",
        text(&help)
    );

    let dry_run = vpnctl("regen-dry-run", ["user", "regen-wireguard", MISSING_USER]);
    assert!(
        dry_run.status.success(),
        "dry-run must not require inventory mutation: {}",
        text(&dry_run)
    );
    let combined = text(&dry_run).to_lowercase();
    assert!(
        !combined.contains("--yes") || combined.contains("dry"),
        "regen without --yes was rejected as an unconfirmed mutation instead of running dry; {}",
        text(&dry_run)
    );
}

#[test]
fn missing_entities_are_reported_as_errors() {
    for args in [
        &["user", "disable", MISSING_USER][..],
        &["user", "enable", MISSING_USER],
        &["user", "wireguard-conf", MISSING_USER, MISSING_SERVER],
        &["server", "protocol-hide", MISSING_SERVER, MISSING_PROTOCOL],
        &[
            "server",
            "protocol-unhide",
            MISSING_SERVER,
            MISSING_PROTOCOL,
        ],
        &[
            "grant-protocol-disable",
            MISSING_USER,
            MISSING_SERVER,
            MISSING_PROTOCOL,
        ],
        &[
            "grant-protocol-enable",
            MISSING_USER,
            MISSING_SERVER,
            MISSING_PROTOCOL,
        ],
    ] {
        let output = vpnctl("missing-entity", args);
        assert!(
            !output.status.success(),
            "{:?} unexpectedly succeeded",
            args
        );
        let combined = text(&output).to_lowercase();
        assert!(
            combined.contains("not found")
                || combined.contains("missing")
                || combined.contains("unknown"),
            "missing entity was not identified; {}",
            text(&output)
        );
    }
}
