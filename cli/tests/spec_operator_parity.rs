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

async fn setup_granted_server(
    temp: &TempDir,
    protocols: &[&str],
) -> vpnctl_inventory::SqliteInventory {
    use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
    let inv = vpnctl_inventory::SqliteInventory::open(&temp.path().join("inventory.db"))
        .await
        .unwrap();
    inv.add_server(&Server {
        id: ServerId("node".into()),
        address: "203.0.113.10".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: protocols
            .iter()
            .map(|id| ProtocolId((*id).into()))
            .collect(),
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();
    inv.add_user(&User {
        id: UserId("alice".into()),
        uuid: "uuid-alice".into(),
        tuic_password: Some("test-password".into()),
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    })
    .await
    .unwrap();
    inv.grant(&UserId("alice".into()), &ServerId("node".into()))
        .await
        .unwrap();
    inv
}

#[tokio::test]
async fn user_disable_enable_reports_only_pending_granted_deploys() {
    use vpnctl_core::{ServerId, UserId};
    let temp = TempDir::new("pending-deploys");
    let inv = setup_granted_server(&temp, &["trojan"]).await;
    let mut second = inv
        .get_server(&ServerId("node".into()))
        .await
        .unwrap()
        .unwrap();
    second.id = ServerId("second".into());
    second.address = "203.0.113.11".into();
    inv.add_server(&second).await.unwrap();
    inv.grant(&UserId("alice".into()), &second.id)
        .await
        .unwrap();
    let mut unrelated = second.clone();
    unrelated.id = ServerId("unrelated".into());
    unrelated.address = "203.0.113.12".into();
    inv.add_server(&unrelated).await.unwrap();

    for (action, disabled) in [("disable", true), ("enable", false)] {
        let help = command(&temp, ["user", action, "--help"]).output().unwrap();
        assert!(help.status.success(), "{}", text(&help));
        assert!(text(&help).contains("Deploy the listed servers"));
        assert!(text(&help).contains("--deploy"));
        let output = command(&temp, ["user", action, "alice"]).output().unwrap();
        assert!(output.status.success(), "{}", text(&output));
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains("in inventory"), "{stdout}");
        assert!(
            stdout.contains("Node access changes require deploy"),
            "{stdout}"
        );
        assert!(stdout.lines().any(|line| line == "  vpnctl deploy node"));
        assert!(stdout.lines().any(|line| line == "  vpnctl deploy second"));
        assert!(!stdout.contains("vpnctl deploy unrelated"));
        assert_eq!(
            inv.get_user(&UserId("alice".into()))
                .await
                .unwrap()
                .unwrap()
                .disabled,
            disabled
        );
        let audit_count = inv.recent_audit(100).await.unwrap().len();
        let retry = command(&temp, ["user", action, "alice"]).output().unwrap();
        assert!(retry.status.success(), "{}", text(&retry));
        assert!(text(&retry).contains("vpnctl deploy node"));
        assert_eq!(inv.recent_audit(100).await.unwrap().len(), audit_count);

        inv.audit("cli", "server.deploy", Some("node"), None)
            .await
            .unwrap();
        let retry = command(&temp, ["user", action, "alice"]).output().unwrap();
        assert!(retry.status.success(), "{}", text(&retry));
        assert!(!text(&retry).contains("vpnctl deploy node"));
        assert!(text(&retry).contains("vpnctl deploy second"));
        inv.audit("cli", "server.deploy", Some("second"), None)
            .await
            .unwrap();
        let deployed = command(&temp, ["user", action, "alice"]).output().unwrap();
        assert!(deployed.status.success(), "{}", text(&deployed));
        assert!(!text(&deployed).contains("vpnctl deploy"));
    }
}

#[tokio::test]
async fn user_disable_enable_deploys_only_pending_granted_servers_and_reports_failures() {
    use vpnctl_core::{ServerId, UserId};

    let temp = TempDir::new("user-immediate-deploy");
    // Unsupported protocols fail validation before any SSH connection.
    let inv = setup_granted_server(&temp, &[MISSING_PROTOCOL]).await;
    let uid = UserId("alice".into());
    let template = inv
        .get_server(&ServerId("node".into()))
        .await
        .unwrap()
        .unwrap();
    for (id, address, granted) in [
        ("second", "203.0.113.11", true),
        ("applied", "203.0.113.12", true),
        ("unrelated", "203.0.113.13", false),
    ] {
        let mut server = template.clone();
        server.id = ServerId(id.into());
        server.address = address.into();
        inv.add_server(&server).await.unwrap();
        if granted {
            inv.grant(&uid, &server.id).await.unwrap();
        }
    }

    for (action, disabled) in [("disable", true), ("enable", false)] {
        let audit_count = inv.recent_audit(100).await.unwrap().len();
        let saved = command(&temp, ["user", action, "alice", "--deploy"])
            .env("VPNCTLD_NODE_LOCK_DIR", temp.path().join("locks"))
            .output()
            .unwrap();
        assert!(!saved.status.success(), "{}", text(&saved));
        assert!(text(&saved).contains(MISSING_PROTOCOL), "{}", text(&saved));
        assert_eq!(inv.recent_audit(100).await.unwrap().len(), audit_count + 1);
        inv.audit("cli", "server.deploy", Some("applied"), None)
            .await
            .unwrap();
        let audit_count = inv.recent_audit(100).await.unwrap().len();

        let output = command(&temp, ["user", action, "alice", "--deploy"])
            .env("VPNCTLD_NODE_LOCK_DIR", temp.path().join("locks"))
            .output()
            .unwrap();
        assert!(!output.status.success(), "{}", text(&output));
        let stdout = String::from_utf8(output.stdout).unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains(MISSING_PROTOCOL), "{stderr}");
        for id in ["node", "second"] {
            assert!(
                stdout.contains(&format!("  vpnctl deploy {id}\n")),
                "{stdout}"
            );
            assert!(stderr.contains(&format!("{id}:")), "{stderr}");
        }
        for id in ["applied", "unrelated"] {
            assert!(!stdout.contains(&format!("vpnctl deploy {id}")), "{stdout}");
            assert!(!stderr.contains(&format!("{id}:")), "{stderr}");
        }
        assert_eq!(
            inv.get_user(&uid).await.unwrap().unwrap().disabled,
            disabled
        );
        assert_eq!(inv.recent_audit(100).await.unwrap().len(), audit_count);

        for id in ["node", "second"] {
            inv.audit("cli", "server.deploy", Some(id), None)
                .await
                .unwrap();
        }
        let audit_count = inv.recent_audit(100).await.unwrap().len();
        let applied = command(&temp, ["user", action, "alice", "--deploy"])
            .output()
            .unwrap();
        assert!(applied.status.success(), "{}", text(&applied));
        assert!(!text(&applied).contains("vpnctl deploy"));
        assert_eq!(inv.recent_audit(100).await.unwrap().len(), audit_count);
    }
}

fn prepare_failing_ssh(temp: &TempDir) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let bin = temp.path().join("bin");
    fs::create_dir(&bin).unwrap();
    let fingerprint = format!("SHA256:{}", "A".repeat(43));
    for (name, script) in [
        ("ssh", "#!/bin/bash\nexit 1\n".to_string()),
        (
            "ssh-keyscan",
            "#!/bin/bash\nprintf '%s\\n' 'node.example ssh-ed25519 AAAATEST'\n".to_string(),
        ),
        (
            "ssh-keygen",
            format!(
                "#!/bin/bash\ncat >/dev/null\nprintf '%s\\n' '256 {fingerprint} node.example (ED25519)'\n"
            ),
        ),
    ] {
        let path = bin.join(name);
        fs::write(&path, script).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let key = temp.path().join("id_test");
    fs::write(&key, "test key placeholder").unwrap();
    key
}

fn ssh_command<I, S>(temp: &TempDir, args: I) -> Command
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut command = command(temp, args);
    command
        .env(
            "PATH",
            format!("{}:/usr/bin:/bin", temp.path().join("bin").display()),
        )
        .env("VPNCTLD_NODE_LOCK_DIR", temp.path().join("locks"));
    command
}

#[tokio::test]
async fn update_kernels_json_stdout_contains_only_json() {
    let temp = TempDir::new("update-json");
    let _inv = setup_granted_server(&temp, &["trojan"]).await;
    let key = prepare_failing_ssh(&temp);
    let output = ssh_command(
        &temp,
        [
            "update-kernels",
            "node",
            "--key",
            key.to_str().unwrap(),
            "--output",
            "json",
        ],
    )
    .output()
    .unwrap();
    assert!(!output.status.success(), "mock SSH failure must propagate");
    let payload: serde_json::Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("stdout is not JSON: {error}; {}", text(&output)));
    assert_eq!(payload[0]["server"], "node");
    assert_eq!(payload[0]["kernels"][0]["kernel"], "sing-box");
    assert!(payload[0]["kernels"][0]["error"].is_string());
    let stderr = String::from_utf8(output.stderr).unwrap();
    for progress in [
        "→ connecting",
        "TOFU: stored host fingerprint",
        "→ upgrading",
    ] {
        assert!(stderr.contains(progress), "{stderr}");
    }
}

#[tokio::test]
async fn tofu_save_is_audited_for_deploy_and_update_kernels() {
    for action in ["deploy", "update-kernels"] {
        let temp = TempDir::new("tofu-audit");
        let inv = setup_granted_server(&temp, &["trojan"]).await;
        let key = prepare_failing_ssh(&temp);
        let run = || {
            ssh_command(&temp, [action, "node", "--key", key.to_str().unwrap()])
                .output()
                .unwrap()
        };
        let output = run();
        assert!(!output.status.success(), "mock SSH failure must propagate");
        let fingerprint = format!("SHA256:{}", "A".repeat(43));
        assert_eq!(
            inv.get_server(&vpnctl_core::ServerId("node".into()))
                .await
                .unwrap()
                .unwrap()
                .trusted_host_fingerprint
                .as_deref(),
            Some(fingerprint.as_str())
        );
        let output = run();
        assert!(!output.status.success(), "mock SSH failure must propagate");
        let audits = inv.recent_audit(100).await.unwrap();
        let pins: Vec<_> = audits
            .iter()
            .filter(|row| row.action == "server.fingerprint.set")
            .collect();
        assert_eq!(pins.len(), 1, "{action} must audit the first pin only");
        assert_eq!(pins[0].actor, "cli");
        assert_eq!(pins[0].target.as_deref(), Some("node"));
        assert_eq!(
            pins[0].payload,
            Some(serde_json::json!({
                "fingerprint": fingerprint,
                "previous": null,
                "source": "ssh-keyscan",
            }))
        );
    }
}

#[tokio::test]
async fn subscription_generation_errors_exit_nonzero() {
    let temp = TempDir::new("sub-error");
    let _inv = setup_granted_server(&temp, &["vless+reality"]).await;
    for flags in [&[][..], &["--output", "json"][..]] {
        let output = command(
            &temp,
            ["sub", "alice"].into_iter().chain(flags.iter().copied()),
        )
        .output()
        .unwrap();
        assert!(!output.status.success(), "{}", text(&output));
        assert!(
            output.stdout.is_empty(),
            "must not emit a partial subscription"
        );
        assert!(text(&output).contains("cannot build link for node/vless+reality"));
    }
}

#[tokio::test]
async fn successful_subscription_output_stays_byte_equal() {
    let temp = TempDir::new("sub-bytes");
    let _inv = setup_granted_server(&temp, &["trojan"]).await;
    let link = "trojan://test-password@203.0.113.10:8643?sni=203.0.113.10&allowInsecure=1#alice";
    let output = command(&temp, ["sub", "alice"]).output().unwrap();
    assert!(output.status.success(), "{}", text(&output));
    assert_eq!(
        output.stdout,
        format!("# node via trojan\n{link}\n\n").as_bytes()
    );
    let output = command(&temp, ["sub", "alice", "--output", "json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", text(&output));
    assert_eq!(
        output.stdout,
        format!("[{{\"server\":\"node\",\"protocol\":\"trojan\",\"link\":\"{link}\"}}]\n")
            .as_bytes()
    );
}
