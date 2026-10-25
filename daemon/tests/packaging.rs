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

    assert!(
        unit.lines().any(|l| l.trim() == "ProtectSystem=strict"),
        "vpnctl-backup.service must keep ProtectSystem=strict"
    );

    let rw = systemd_list(&unit, "ReadWritePaths");
    assert!(
        rw.iter().any(|p| p == "/var/lib/vpnctl/backups"),
        "ReadWritePaths must grant /var/lib/vpnctl/backups (the script writes \
         the final encrypted bundle there); got {rw:?}"
    );

    let ro = systemd_list(&unit, "ReadOnlyPaths");
    assert!(
        ro.iter().any(|p| p == "/var/lib/vpnctl"),
        "ReadOnlyPaths must still cover /var/lib/vpnctl; got {ro:?}"
    );
}

#[test]
fn deploy_script_installs_revision_coupled_artifacts_atomically() {
    let script = read_script("deploy.sh");

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

    assert!(
        script.contains("mktemp"),
        "deploy.sh must stage each binary in a temp file first"
    );
    assert!(
        script.contains("mv -f"),
        "deploy.sh must rename the staged binary into place atomically"
    );

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

fn bash_available() -> bool {
    Command::new("bash")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

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
        .env("VPNCTL_SKIP_ASSETS", "1")
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
            .env("VPNCTL_SKIP_ASSETS", "1")
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

    let daemon_dst = root.join("opt").join("vpnctld");
    let cli_dst = root.join("bin").join("vpnctl");
    std::fs::create_dir_all(daemon_dst.parent().unwrap()).unwrap();
    std::fs::create_dir_all(cli_dst.parent().unwrap()).unwrap();
    std::fs::write(&daemon_dst, b"OLD_DAEMON").unwrap();
    std::fs::write(&cli_dst, b"OLD_CLI").unwrap();

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
        .env("VPNCTL_SKIP_ASSETS", "1")
        .status()
        .expect("spawn bash deploy.sh");
    assert!(
        !status.success(),
        "deploy.sh must fail on a missing CLI source"
    );

    assert_eq!(
        std::fs::read(&daemon_dst).unwrap(),
        b"OLD_DAEMON",
        "daemon must stay untouched when the CLI source is missing"
    );
    assert_eq!(std::fs::read(&cli_dst).unwrap(), b"OLD_CLI");
}

fn run_deploy_with_assets(root: &Path, fail_after_assets: bool) -> std::process::ExitStatus {
    let sources: Vec<_> = (0..4).map(|i| root.join(format!("new-{i}"))).collect();
    let destinations: Vec<_> = (0..4).map(|i| root.join(format!("live-{i}"))).collect();
    for source in &sources {
        std::fs::write(source, b"NEW").unwrap();
    }
    for destination in &destinations {
        std::fs::write(destination, b"OLD").unwrap();
    }
    let mut cmd = Command::new("bash");
    cmd.arg(bash_path(&scripts_dir().join("deploy.sh")))
        .args(sources.iter().map(|path| bash_path(path)))
        .env("VPNCTL_DAEMON_DST", bash_path(&destinations[0]))
        .env("VPNCTL_CLI_DST", bash_path(&destinations[1]))
        .env("VPNCTL_SING_BOX_ARTIFACT", bash_path(&destinations[2]))
        .env("VPNCTL_STATS_HELPER_ARTIFACT", bash_path(&destinations[3]))
        .env("VPNCTL_ASSETS_SRC", bash_path(&root.join("assets-new")))
        .env("VPNCTL_ASSETS_DST", bash_path(&root.join("assets")))
        .env("VPNCTL_INSTALL_OWNER", "");
    if fail_after_assets {
        cmd.env("VPNCTL_FAIL_AFTER_ASSETS", "1");
    }
    cmd.status().unwrap()
}

fn seed_assets(root: &Path) {
    std::fs::create_dir_all(root.join("assets")).unwrap();
    std::fs::write(root.join("assets/admin.js"), b"OLD_JS").unwrap();
    std::fs::write(root.join("assets/stale.css"), b"OLD_CSS").unwrap();
    std::fs::create_dir_all(root.join("assets-new")).unwrap();
    std::fs::write(root.join("assets-new/admin.js"), b"NEW_JS").unwrap();
}

#[test]
fn deploy_script_ships_admin_assets_from_the_same_revision() {
    if !bash_available() {
        eprintln!("skip: no bash on PATH (functional deploy.sh check)");
        return;
    }
    let dir = tempfile::TempDir::new().unwrap();
    let root = dir.path();
    seed_assets(root);
    assert!(run_deploy_with_assets(root, false).success());
    assert_eq!(
        std::fs::read(root.join("assets/admin.js")).unwrap(),
        b"NEW_JS"
    );
    assert!(
        !root.join("assets/stale.css").exists(),
        "assets must be replaced as a set, not merged"
    );
    let litter: Vec<_> = std::fs::read_dir(root)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.contains(".stage.") || name.contains(".rollback."))
        .collect();
    assert!(litter.is_empty(), "temp litter left: {litter:?}");
}

#[test]
fn deploy_script_rolls_back_assets_with_binaries() {
    if !bash_available() {
        eprintln!("skip: no bash on PATH (functional deploy.sh check)");
        return;
    }
    let dir = tempfile::TempDir::new().unwrap();
    let root = dir.path();
    seed_assets(root);
    assert!(!run_deploy_with_assets(root, true).success());
    assert_eq!(
        std::fs::read(root.join("assets/admin.js")).unwrap(),
        b"OLD_JS"
    );
    assert_eq!(
        std::fs::read(root.join("assets/stale.css")).unwrap(),
        b"OLD_CSS"
    );
    for i in 0..4 {
        assert_eq!(
            std::fs::read(root.join(format!("live-{i}"))).unwrap(),
            b"OLD"
        );
    }
}

#[test]
fn deploy_script_refuses_prebuilt_artifacts_without_assets() {
    if !bash_available() {
        eprintln!("skip: no bash on PATH (functional deploy.sh check)");
        return;
    }
    let dir = tempfile::TempDir::new().unwrap();
    let root = dir.path();
    let sources: Vec<_> = (0..4).map(|i| root.join(format!("new-{i}"))).collect();
    let destinations: Vec<_> = (0..4).map(|i| root.join(format!("live-{i}"))).collect();
    for (source, destination) in sources.iter().zip(&destinations) {
        std::fs::write(source, b"NEW").unwrap();
        std::fs::write(destination, b"OLD").unwrap();
    }
    let status = Command::new("bash")
        .arg(bash_path(&scripts_dir().join("deploy.sh")))
        .args(sources.iter().map(|path| bash_path(path)))
        .env("VPNCTL_DAEMON_DST", bash_path(&destinations[0]))
        .env("VPNCTL_CLI_DST", bash_path(&destinations[1]))
        .env("VPNCTL_SING_BOX_ARTIFACT", bash_path(&destinations[2]))
        .env("VPNCTL_STATS_HELPER_ARTIFACT", bash_path(&destinations[3]))
        .env("VPNCTL_ASSETS_DST", bash_path(&root.join("assets")))
        .env_remove("VPNCTL_ASSETS_SRC")
        .env_remove("VPNCTL_SKIP_ASSETS")
        .env("VPNCTL_INSTALL_OWNER", "")
        .status()
        .unwrap();
    assert!(
        !status.success(),
        "new binaries with the previous admin.js would break every SSE button"
    );
    for destination in &destinations {
        assert_eq!(std::fs::read(destination).unwrap(), b"OLD");
    }
}

fn deploy_test_command(root: &Path) -> Command {
    for i in 0..4 {
        std::fs::write(root.join(format!("new-{i}")), b"NEW").unwrap();
        std::fs::write(root.join(format!("live-{i}")), b"OLD").unwrap();
    }
    let mut cmd = Command::new("bash");
    cmd.env("VPNCTL_DAEMON_DST", root.join("live-0"))
        .env("VPNCTL_CLI_DST", root.join("live-1"))
        .env("VPNCTL_SING_BOX_ARTIFACT", root.join("live-2"))
        .env("VPNCTL_STATS_HELPER_ARTIFACT", root.join("live-3"))
        .env("VPNCTL_DEPLOY_LOCK", root.join("deploy.lock"))
        .env("VPNCTL_INSTALL_OWNER", "")
        .env("VPNCTL_SKIP_ASSETS", "1")
        .env_remove("VPNCTL_ASSETS_SRC")
        .env_remove("VPNCTL_FAIL_AFTER_SWAP")
        .env("VPNCTL_ASSETS_DST", root.join("assets"));
    cmd
}

#[test]
fn deploy_script_waits_for_inter_run_lock_before_staging() {
    if !bash_available() {
        return;
    }
    let dir = tempfile::TempDir::new().unwrap();
    let root = dir.path();
    let mut cmd = deploy_test_command(root);
    let output = cmd
        .arg("-c")
        .arg(
            r#"
set -euo pipefail
flock() {
    if [ "${2:-}" = 9 ]; then : > "$TEST_LOCK_ATTEMPT"; fi
    command flock "$@"
}
export -f flock
exec 8>"$VPNCTL_DEPLOY_LOCK"
command flock -x 8
bash "$@" 8>&- &
pid=$!
trap 'kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true' EXIT
for ((i=0; i<500; i++)); do
    [ ! -e "$TEST_LOCK_ATTEMPT" ] || break
    sleep 0.01
done
[ -e "$TEST_LOCK_ATTEMPT" ]
kill -0 "$pid"
[ "$(cat "$VPNCTL_DAEMON_DST")" = OLD ]
[ "$(cat "$VPNCTL_SING_BOX_ARTIFACT")" = OLD ]
[ -z "$(find "$TEST_ROOT" -name '*.stage.*' -o -name '*.rollback.*')" ]
command flock -u 8
wait "$pid"
trap - EXIT
"#,
        )
        .arg("test-deploy-lock")
        .arg(bash_path(&scripts_dir().join("deploy.sh")))
        .args((0..4).map(|i| root.join(format!("new-{i}"))))
        .env("TEST_ROOT", root)
        .env("TEST_LOCK_ATTEMPT", root.join("attempt"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    for i in 0..4 {
        assert_eq!(
            std::fs::read(root.join(format!("live-{i}"))).unwrap(),
            b"NEW"
        );
    }
}

#[test]
fn deploy_script_rolls_back_signals_on_both_sides_of_rename() {
    if !bash_available() {
        return;
    }
    for timing in ["before", "after"] {
        for existed in [false, true] {
            let dir = tempfile::TempDir::new().unwrap();
            let root = dir.path();
            let mut cmd = deploy_test_command(root);
            if !existed {
                for i in 0..4 {
                    std::fs::remove_file(root.join(format!("live-{i}"))).unwrap();
                }
            }
            let output = cmd
                .arg("-c")
                .arg(
                    r#"
set -euo pipefail
mv() {
    case "${2:-}" in
        *.stage.*)
            if [ "$TEST_SIGNAL_TIMING" = after ]; then command mv "$@"; fi
            kill -TERM "$$"
            return 143
            ;;
    esac
    command mv "$@"
}
export -f mv
exec bash "$@"
"#,
                )
                .arg("test-deploy-signal")
                .arg(bash_path(&scripts_dir().join("deploy.sh")))
                .args((0..4).map(|i| root.join(format!("new-{i}"))))
                .env("TEST_SIGNAL_TIMING", timing)
                .output()
                .unwrap();
            assert!(
                !output.status.success(),
                "{timing} must interrupt the install"
            );
            for i in 0..4 {
                let destination = root.join(format!("live-{i}"));
                if existed {
                    assert_eq!(std::fs::read(destination).unwrap(), b"OLD", "{timing}");
                } else {
                    assert!(!destination.exists(), "{timing}: {destination:?}");
                }
            }
            assert!(std::fs::read_dir(root).unwrap().all(|entry| {
                let name = entry.unwrap().file_name().to_string_lossy().into_owned();
                !name.contains(".stage.") && !name.contains(".rollback.")
            }));
        }
    }
}
