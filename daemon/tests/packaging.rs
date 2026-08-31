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
//!   * `deploy.sh` installs daemon, CLI, and both managed node artifacts from
//!     the same revision, atomically per path (temp file + rename).

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
fn deploy_script_installs_revision_coupled_artifacts_atomically() {
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
    assert!(
        script.contains("/opt/vpnctl/node-artifacts/sing-box")
            && script.contains("/opt/vpnctl/node-artifacts/singbox-stats-helper"),
        "deploy.sh must install both managed node artifacts"
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

    // Every source is validated before the first install.
    let checks = [
        script.find("daemon binary not found"),
        script.find("cli binary not found"),
        script.find("sing-box artifact not found"),
        script.find("stats helper not found"),
    ];
    let first_stage = script
        .find("for i in \"${!SOURCES[@]}\"")
        .expect("stage loop");
    assert!(
        checks.iter().all(Option::is_some),
        "deploy.sh must validate all four sources"
    );
    assert!(
        checks
            .into_iter()
            .flatten()
            .all(|check| check < first_stage),
        "all source checks must precede staging"
    );
    assert!(
        script.contains(
            "DESTINATIONS=(\"$SING_BOX_DST\" \"$STATS_HELPER_DST\" \"$CLI_DST\" \"$DAEMON_DST\")"
        ),
        "node artifacts must land before the daemon compatibility switch"
    );
    assert!(
        script.contains("trap rollback EXIT HUP INT TERM")
            && script.contains("VPNCTL_FAIL_AFTER_SWAP"),
        "deploy.sh must rollback interrupted multi-artifact swaps"
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
    assert!(
        script.contains("tools/singbox-attr-patch/build.sh")
            && script.contains("tools/singbox-stats-helper/build.sh"),
        "build mode must produce both managed node artifacts"
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
fn deploy_script_functional_all_artifacts_land() {
    if !bash_available() {
        eprintln!("skip: no bash on PATH (functional deploy.sh check)");
        return;
    }
    let dir = tempfile::TempDir::new().unwrap();
    let root = dir.path();

    let sources = [
        (root.join("vpnctld.src"), b"DAEMON_FROM_REV_X".as_slice()),
        (root.join("vpnctl.src"), b"CLI_FROM_REV_X".as_slice()),
        (root.join("sing-box.src"), b"SING_BOX_FROM_REV_X".as_slice()),
        (
            root.join("stats-helper.src"),
            b"HELPER_FROM_REV_X".as_slice(),
        ),
    ];
    for (path, content) in &sources {
        std::fs::write(path, content).unwrap();
    }
    let destinations = [
        root.join("opt").join("vpnctld"),
        root.join("bin").join("vpnctl"),
        root.join("artifacts").join("sing-box"),
        root.join("artifacts").join("singbox-stats-helper"),
    ];

    let script = scripts_dir().join("deploy.sh");
    let status = Command::new("bash")
        .arg(bash_path(&script))
        .args(sources.iter().map(|(path, _)| bash_path(path)))
        .env("VPNCTL_DAEMON_DST", bash_path(&destinations[0]))
        .env("VPNCTL_CLI_DST", bash_path(&destinations[1]))
        .env("VPNCTL_SING_BOX_ARTIFACT", bash_path(&destinations[2]))
        .env("VPNCTL_STATS_HELPER_ARTIFACT", bash_path(&destinations[3]))
        .env("VPNCTL_INSTALL_OWNER", "")
        .status()
        .expect("spawn bash deploy.sh");
    assert!(
        status.success(),
        "deploy.sh must exit 0 on four valid artifacts"
    );

    for ((_, expected), destination) in sources.iter().zip(&destinations) {
        assert_eq!(std::fs::read(destination).unwrap(), *expected);
    }
    for parent in destinations.iter().filter_map(|path| path.parent()) {
        let leftovers: Vec<_> = std::fs::read_dir(parent)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with('.'))
            .collect();
        assert!(leftovers.is_empty(), "temp litter left in {parent:?}");
    }
}

#[test]
fn deploy_script_rolls_back_every_injected_swap_failure() {
    if !bash_available() {
        eprintln!("skip: no bash on PATH (functional deploy.sh check)");
        return;
    }
    let script = scripts_dir().join("deploy.sh");
    for fail_after in 1..=4 {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path();
        let sources: Vec<_> = (0..4).map(|i| root.join(format!("new-{i}"))).collect();
        let destinations: Vec<_> = (0..4).map(|i| root.join(format!("live-{i}"))).collect();
        for source in &sources {
            std::fs::write(source, b"NEW").unwrap();
        }
        for destination in &destinations {
            std::fs::write(destination, b"OLD").unwrap();
        }
        let status = Command::new("bash")
            .arg(bash_path(&script))
            .args(sources.iter().map(|path| bash_path(path)))
            .env("VPNCTL_DAEMON_DST", bash_path(&destinations[0]))
            .env("VPNCTL_CLI_DST", bash_path(&destinations[1]))
            .env("VPNCTL_SING_BOX_ARTIFACT", bash_path(&destinations[2]))
            .env("VPNCTL_STATS_HELPER_ARTIFACT", bash_path(&destinations[3]))
            .env("VPNCTL_FAIL_AFTER_SWAP", fail_after.to_string())
            .env("VPNCTL_INSTALL_OWNER", "")
            .status()
            .unwrap();
        assert!(!status.success(), "failure {fail_after} must abort");
        for destination in &destinations {
            assert_eq!(std::fs::read(destination).unwrap(), b"OLD");
        }
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
    let sing_box_src = root.join("sing-box.src");
    let helper_src = root.join("stats-helper.src");
    std::fs::write(&sing_box_src, b"NODE_SING_BOX").unwrap();
    std::fs::write(&helper_src, b"NODE_HELPER").unwrap();

    let script = scripts_dir().join("deploy.sh");
    let status = Command::new("bash")
        .arg(bash_path(&script))
        .arg(bash_path(&daemon_src))
        .arg(bash_path(&cli_src))
        .arg(bash_path(&sing_box_src))
        .arg(bash_path(&helper_src))
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
