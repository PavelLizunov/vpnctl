//! Static + functional regression net for the operational packaging
//! artifacts under `scripts/`. These run in the ordinary `cargo test`
//! CI job on every platform (the static checks just read files); the
//! functional `deploy.sh` exercise runs only where a `bash` is available
//! (Linux CI, macOS, Git-Bash) and is skipped elsewhere.
//!
//! Invariants guarded here:
//!   * `vpnctl-backup.service` keeps `ProtectSystem=strict` but grants
//!     write access to the exact durable dir `/var/lib/vpnctl/backups`
//!     (where the script writes the final encrypted bundle) while the
//!     rest of `/var/lib/vpnctl` stays read-only.
//!   * `deploy.sh` installs the daemon AND the CLI from the same revision,
//!     atomically (temp file + rename), so a failed copy can never leave a
//!     partial executable nor a stale `/usr/local/bin/vpnctl`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::Command;

fn scripts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../scripts")
}

fn read_script(name: &str) -> String {
    let path = scripts_dir().join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// The value of a systemd `Key=val1 val2 …` line, split on whitespace.
fn systemd_list(unit: &str, key: &str) -> Vec<String> {
    unit.lines()
        .filter_map(|line| {
            let line = line.trim();
            line.strip_prefix(&format!("{key}=")).map(|rest| {
                rest.split_whitespace()
                    .map(String::from)
                    .collect::<Vec<_>>()
            })
        })
        .flatten()
        .collect()
}

#[test]
fn backup_unit_stays_strict_but_can_write_backups_dir() {
    let unit = read_script("vpnctl-backup.service");

    // The hardening must remain in force …
    assert!(
        unit.lines().any(|l| l.trim() == "ProtectSystem=strict"),
        "vpnctl-backup.service must keep ProtectSystem=strict"
    );

    // … while the exact durable deliverable dir is writable …
    let rw = systemd_list(&unit, "ReadWritePaths");
    assert!(
        rw.iter().any(|p| p == "/var/lib/vpnctl/backups"),
        "ReadWritePaths must grant /var/lib/vpnctl/backups (the script writes \
         the final encrypted bundle there); got {rw:?}"
    );

    // … and the rest of the state tree stays read-only. The inv.db lives
    // directly under /var/lib/vpnctl, which must remain in ReadOnlyPaths;
    // systemd resolves the overlap by most-specific-path, so only the
    // backups subdir is writable.
    let ro = systemd_list(&unit, "ReadOnlyPaths");
    assert!(
        ro.iter().any(|p| p == "/var/lib/vpnctl"),
        "ReadOnlyPaths must still cover /var/lib/vpnctl; got {ro:?}"
    );
}

#[test]
fn deploy_script_installs_both_binaries_atomically() {
    let script = read_script("deploy.sh");

    // Daemon and CLI destinations are both the live production paths …
    assert!(
        script.contains("/opt/vpnctl/vpnctld"),
        "deploy.sh must target the daemon path /opt/vpnctl/vpnctld"
    );
    assert!(
        script.contains("/usr/local/bin/vpnctl"),
        "deploy.sh must target the CLI path /usr/local/bin/vpnctl \
         (the stale-CLI bug it exists to fix)"
    );

    // … installed via a temp-file + atomic rename, never an in-place copy
    // that could be caught half-written.
    assert!(
        script.contains("mktemp"),
        "deploy.sh must stage each binary in a temp file first"
    );
    assert!(
        script.contains("mv -f"),
        "deploy.sh must rename the staged binary into place atomically"
    );

    // Both sources are validated before either install, so a missing CLI
    // binary can never leave a half-upgraded host.
    let daemon_check = script.find("daemon binary not found");
    let cli_check = script.find("cli binary not found");
    let first_install = script.find("install_atomic \"$DAEMON_SRC\"");
    assert!(
        daemon_check.is_some() && cli_check.is_some() && first_install.is_some(),
        "deploy.sh must validate both sources and install the daemon"
    );
    assert!(
        daemon_check.unwrap() < first_install.unwrap()
            && cli_check.unwrap() < first_install.unwrap(),
        "both source checks must precede the first install"
    );

    // Build mode: with no arguments the script builds daemon + CLI from the
    // SAME checkout, exporting the provenance SHA BEFORE cargo build so the
    // binaries embed it (vpnctl_core::build_version reads VPNCTL_BUILD_SHA
    // at compile time; no git at application runtime).
    let sha_export = script.find("export VPNCTL_BUILD_SHA");
    let cargo_build = script.find("cargo build --release");
    assert!(
        sha_export.is_some() && cargo_build.is_some(),
        "deploy.sh must export VPNCTL_BUILD_SHA and run cargo build"
    );
    assert!(
        sha_export.unwrap() < cargo_build.unwrap(),
        "VPNCTL_BUILD_SHA must be exported before cargo build so the SHA is \
         baked into the binaries"
    );

    // … and both product binaries come from that one build (same revision).
    let build_line = script[cargo_build.unwrap()..]
        .lines()
        .next()
        .unwrap_or_default();
    assert!(
        build_line.contains("-p vpnctld") && build_line.contains("-p vpnctl"),
        "cargo build must produce both the daemon and the CLI: {build_line:?}"
    );
}

/// True when a usable `bash` is on PATH.
fn bash_available() -> bool {
    Command::new("bash")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Forward-slash form of a path, so a Windows manifest dir works under
/// Git-Bash too.
fn bash_path(p: &Path) -> String {
    p.display().to_string().replace('\\', "/")
}

#[test]
fn deploy_script_functional_both_binaries_land() {
    if !bash_available() {
        eprintln!("skip: no bash on PATH (functional deploy.sh check)");
        return;
    }
    let dir = tempfile::TempDir::new().unwrap();
    let root = dir.path();

    let daemon_src = root.join("vpnctld.src");
    let cli_src = root.join("vpnctl.src");
    std::fs::write(&daemon_src, b"DAEMON_FROM_REV_X").unwrap();
    std::fs::write(&cli_src, b"CLI_FROM_REV_X").unwrap();

    let daemon_dst = root.join("opt").join("vpnctld");
    let cli_dst = root.join("bin").join("vpnctl");

    let script = scripts_dir().join("deploy.sh");
    let status = Command::new("bash")
        .arg(bash_path(&script))
        .arg(bash_path(&daemon_src))
        .arg(bash_path(&cli_src))
        .env("VPNCTL_DAEMON_DST", bash_path(&daemon_dst))
        .env("VPNCTL_CLI_DST", bash_path(&cli_dst))
        .env("VPNCTL_INSTALL_OWNER", "") // unprivileged: skip chown
        .status()
        .expect("spawn bash deploy.sh");
    assert!(status.success(), "deploy.sh must exit 0 on a valid pair");

    assert_eq!(
        std::fs::read(&daemon_dst).unwrap(),
        b"DAEMON_FROM_REV_X",
        "daemon binary must land at the daemon destination"
    );
    assert_eq!(
        std::fs::read(&cli_dst).unwrap(),
        b"CLI_FROM_REV_X",
        "CLI binary must land at the CLI destination"
    );

    // No staged temp litter may survive a successful install.
    for parent in [daemon_dst.parent().unwrap(), cli_dst.parent().unwrap()] {
        let leftovers: Vec<_> = std::fs::read_dir(parent)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with('.'))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp litter left in {parent:?}: {leftovers:?}"
        );
    }
}

#[test]
fn deploy_script_missing_cli_never_half_upgrades() {
    if !bash_available() {
        eprintln!("skip: no bash on PATH (functional deploy.sh check)");
        return;
    }
    let dir = tempfile::TempDir::new().unwrap();
    let root = dir.path();

    // Pre-existing "old" binaries at both live paths.
    let daemon_dst = root.join("opt").join("vpnctld");
    let cli_dst = root.join("bin").join("vpnctl");
    std::fs::create_dir_all(daemon_dst.parent().unwrap()).unwrap();
    std::fs::create_dir_all(cli_dst.parent().unwrap()).unwrap();
    std::fs::write(&daemon_dst, b"OLD_DAEMON").unwrap();
    std::fs::write(&cli_dst, b"OLD_CLI").unwrap();

    // Valid daemon source, but the CLI source is missing.
    let daemon_src = root.join("vpnctld.src");
    std::fs::write(&daemon_src, b"NEW_DAEMON").unwrap();
    let cli_src = root.join("does-not-exist");

    let script = scripts_dir().join("deploy.sh");
    let status = Command::new("bash")
        .arg(bash_path(&script))
        .arg(bash_path(&daemon_src))
        .arg(bash_path(&cli_src))
        .env("VPNCTL_DAEMON_DST", bash_path(&daemon_dst))
        .env("VPNCTL_CLI_DST", bash_path(&cli_dst))
        .env("VPNCTL_INSTALL_OWNER", "")
        .status()
        .expect("spawn bash deploy.sh");
    assert!(
        !status.success(),
        "deploy.sh must fail on a missing CLI source"
    );

    // The exact regression: the daemon must NOT have been swapped when the
    // CLI source is absent — no half-upgraded host, no stale-CLI window.
    assert_eq!(
        std::fs::read(&daemon_dst).unwrap(),
        b"OLD_DAEMON",
        "daemon must stay untouched when the CLI source is missing"
    );
    assert_eq!(std::fs::read(&cli_dst).unwrap(), b"OLD_CLI");
}
