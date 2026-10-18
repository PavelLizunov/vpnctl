#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::guards::*;
use super::scripts::*;
use super::*;
use serde_json::Value;
use std::collections::HashMap;
use vpnctl_core::{Server, ServerId, UserId};

fn dummy_ctx<'a>(server: &'a Server, secrets: &'a HashMap<String, String>) -> RenderCtx<'a> {
    RenderCtx::new(server, secrets)
}

fn dummy_server() -> Server {
    Server {
        id: ServerId("srv".into()),
        address: "10.0.0.1".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

#[test]
fn render_config_includes_clash_api_on_loopback() {
    let s = dummy_server();
    let secrets = HashMap::new();
    let ctx = dummy_ctx(&s, &secrets);
    let bytes = SingBox::new().render_config(&ctx, &[], &[]).unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        v["experimental"]["clash_api"]["external_controller"],
        Value::String("127.0.0.1:9090".into()),
        "clash_api must bind to 127.0.0.1:9090 (loopback only — no external exposure)"
    );
}

#[test]
fn render_config_counts_every_user_on_loopback_v2ray_api() {
    let s = dummy_server();
    let secrets = HashMap::new();
    let ctx = dummy_ctx(&s, &secrets);
    let users = [User {
        id: UserId("alice".into()),
        uuid: "00000000-0000-0000-0000-000000000001".into(),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    }];
    let bytes = SingBox::new().render_config(&ctx, &users, &[]).unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    let api = &v["experimental"]["v2ray_api"];
    assert_eq!(api["listen"], "127.0.0.1:10085");
    assert_eq!(api["stats"]["enabled"], true);
    assert_eq!(api["stats"]["users"], serde_json::json!(["alice"]));
}

#[test]
fn managed_install_requires_v2ray_api_and_blocks_apt_clobber() {
    let uploaded_sing_box = "/tmp/vpnctl-sing-box.123.1";
    let uploaded_helper = "/tmp/vpnctl-singbox-stats-helper.123.1";
    let script = install_managed_artifacts_script(uploaded_sing_box, uploaded_helper);
    let cleanup = cleanup_remote_artifacts_script(uploaded_sing_box, uploaded_helper);
    assert!(script.contains("with_v2ray_api"));
    assert!(script.contains("apt-mark hold sing-box"));
    assert!(script.contains("sing-box.vpnctl-stock"));
    assert!(script.contains("sing-box.vpnctl-prev"));
    assert!(script.contains("singbox-stats-helper.prev"));
    assert!(script.contains("trap rollback EXIT HUP INT TERM"));
    assert!(script.contains("trap cleanup_on_signal HUP INT TERM"));
    assert!(script.contains("trap - EXIT HUP INT TERM"));
    assert!(
        script.contains("set +e"),
        "rollback must attempt both restores"
    );
    assert!(script.contains("sing-box.rollback-new"));
    assert!(script.contains("$LIVE_HELPER.rollback-new"));
    assert!(script.contains("systemctl is-active --quiet sing-box"));
    assert!(script.contains("install -m 0755 \"$UPLOADED_SB\" \"$MANAGED_SB\""));
    assert!(script.contains("trap cleanup_stages EXIT"));
    assert!(script.contains("exec 9>/run/lock/vpnctl-singbox-install.lock"));
    assert!(
        script.find("flock -w 300 9") < script.find("cp -a /usr/bin/sing-box"),
        "the node-local lock must cover every shared backup and live path"
    );
    assert!(script.contains("UPLOADED_SB=/tmp/vpnctl-sing-box.123.1"));
    assert!(script.contains("UPLOADED_HELPER=/tmp/vpnctl-singbox-stats-helper.123.1"));
    assert!(cleanup.contains(uploaded_sing_box));
    assert!(cleanup.contains(uploaded_helper));
    assert!(
        script.find("install -m 0755 \"$UPLOADED_SB\" \"$MANAGED_SB\"")
            < script.find("\"$MANAGED_SB\" version"),
        "the uploaded binary must move off noexec /tmp before execution"
    );
    assert!(
        script.contains("cmp -s"),
        "unchanged binaries must be a no-op"
    );
}

#[test]
fn sing_box_vpnctl_release_artifacts_and_sha256_constants_are_pinned() {
    use super::scripts::{
        SING_BOX_AMD64_SHA256, SING_BOX_ARM64_SHA256, SING_BOX_ARMV7_SHA256,
        SING_BOX_VPNCTL_VERSION,
    };
    assert_eq!(SING_BOX_VPNCTL_VERSION, "1.14.0-vpnctl.5");
    assert_eq!(
        SING_BOX_AMD64_SHA256,
        "5f98eacc95b9ed9c1d53592605d812d9d2cb8c496fa95723cfb7c5f9447fe46e"
    );
    assert_eq!(
        SING_BOX_ARM64_SHA256,
        "4d3390860d406b19f53ac0be699d4b39668972abf7276539ca95df6a97ef38fa"
    );
    assert_eq!(
        SING_BOX_ARMV7_SHA256,
        "bed4d3825242b7f75daab85eb920a228fa33733fc06a89a06e0bfcb76cca9a71"
    );
}

#[test]
fn resolve_sing_box_artifact_path_resolves_expected_arch_defaults_and_overrides() {
    use super::arch::resolve_sing_box_artifact_path;
    use std::path::PathBuf;

    assert_eq!(
        resolve_sing_box_artifact_path("x86_64"),
        PathBuf::from("/opt/vpnctl/node-artifacts/sing-box")
    );
    assert_eq!(
        resolve_sing_box_artifact_path("amd64"),
        PathBuf::from("/opt/vpnctl/node-artifacts/sing-box")
    );

    assert_eq!(
        resolve_sing_box_artifact_path("aarch64"),
        PathBuf::from("/opt/vpnctl/node-artifacts/sing-box-arm64")
    );
    assert_eq!(
        resolve_sing_box_artifact_path("arm64"),
        PathBuf::from("/opt/vpnctl/node-artifacts/sing-box-arm64")
    );

    assert_eq!(
        resolve_sing_box_artifact_path("armv7l"),
        PathBuf::from("/opt/vpnctl/node-artifacts/sing-box-armv7")
    );
    assert_eq!(
        resolve_sing_box_artifact_path("armv7"),
        PathBuf::from("/opt/vpnctl/node-artifacts/sing-box-armv7")
    );
    assert_eq!(
        resolve_sing_box_artifact_path("armhf"),
        PathBuf::from("/opt/vpnctl/node-artifacts/sing-box-armv7")
    );
}

#[test]
fn managed_upload_paths_are_unique_and_shell_safe() {
    let first = remote_artifact_paths();
    let second = remote_artifact_paths();
    assert_ne!(first, second);
    for path in [first.0, first.1, second.0, second.1] {
        assert!(path.starts_with("/tmp/vpnctl-"));
        assert!(
            path.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'.'))
        );
    }
}

#[test]
fn setup_script_provisions_shared_tls_cert() {
    let s = SING_BOX_SETUP_SCRIPT.as_str();
    assert!(s.contains("/etc/sing-box/cert.pem"), "cert path missing");
    assert!(s.contains("/etc/sing-box/key.pem"), "key path missing");
    assert!(
        s.contains("openssl req -x509"),
        "self-signed cert generation missing"
    );
    assert!(
        s.contains("[ ! -f /etc/sing-box/cert.pem ]"),
        "cert generation must be guarded on absence (idempotent)"
    );
    assert!(
        s.contains("chmod 600 /etc/sing-box/key.pem"),
        "private key must be mode 0600"
    );
}

#[test]
fn setup_script_installs_and_configures_fail2ban() {
    let s = SING_BOX_SETUP_SCRIPT.as_str();
    assert!(
        s.contains("--no-install-recommends fail2ban python3-systemd"),
        "fail2ban and python3-systemd package install missing"
    );
    assert!(
        s.contains("python3-systemd"),
        "python3-systemd package install missing"
    );
    assert!(
        s.contains("/etc/fail2ban/jail.local"),
        "jail.local provisioning missing"
    );
    assert!(
        s.contains("backend  = systemd"),
        "fail2ban must use the systemd backend on Debian 12+"
    );
    assert!(s.contains("[sshd]"), "sshd jail missing");
    assert!(s.contains("enabled  = true"), "sshd jail must be enabled");
    assert!(
        s.contains("port     = ${F2B_SSH_PORT}"),
        "jail must bind the detected sshd port"
    );
    assert!(
        s.contains("systemctl is-active fail2ban") && s.contains("exit 1"),
        "must fail the deploy on a fail2ban crash-loop"
    );
    assert!(
        s.contains("command -v fail2ban-client"),
        "final assertion must verify fail2ban-client present"
    );
}

#[test]
fn setup_script_package_detection_uses_exact_dpkg_query_status() {
    let s = SING_BOX_SETUP_SCRIPT.as_str();
    assert!(
        s.contains(r#"dpkg-query -W -f='${Status}' fail2ban"#),
        "fail2ban gate must check fail2ban status via dpkg-query: {s}"
    );
    assert!(
        s.contains(r#"dpkg-query -W -f='${Status}' python3-systemd"#),
        "fail2ban gate must check python3-systemd status via dpkg-query: {s}"
    );
    assert!(
        s.contains("\"install ok installed\""),
        "gate must require exact 'install ok installed' status: {s}"
    );
    assert!(
        !s.contains("command -v fail2ban-client >/dev/null 2>&1 ||"),
        "bare command -v fail2ban-client gate must be gone: {s}"
    );
    assert!(
        !s.contains("dpkg -s python3-systemd"),
        "bare dpkg -s python3-systemd check must be gone: {s}"
    );
    assert!(
            s.contains(r#"[ "$(dpkg-query -W -f='${Status}' fail2ban 2>/dev/null || true)" != "install ok installed" ]"#)
                && s.contains(r#"[ "$(dpkg-query -W -f='${Status}' python3-systemd 2>/dev/null || true)" != "install ok installed" ]"#),
            "gate must check both fail2ban and python3-systemd status against 'install ok installed': {s}"
        );

    let gate_block = s
        .lines()
        .skip_while(|line| !line.contains("dpkg-query -W -f='${Status}' fail2ban"))
        .take(2)
        .collect::<Vec<_>>()
        .join("\n");

    let run_gate = |f2b_status: &str, py3_status: &str| -> String {
        let test_script = format!(
            r#"
                dpkg-query() {{
                    pkg="$3"
                    if [ "$pkg" = "fail2ban" ]; then
                        if [ -n "{f2b_status}" ]; then echo -n "{f2b_status}"; return 0; else return 1; fi
                    elif [ "$pkg" = "python3-systemd" ]; then
                        if [ -n "{py3_status}" ]; then echo -n "{py3_status}"; return 0; else return 1; fi
                    fi
                    return 1
                }}
                {gate_block}
                    echo "TRIGGERED"
                else
                    echo "SKIPPED"
                fi
                "#
        );
        let out = std::process::Command::new("bash")
            .arg("-c")
            .arg(&test_script)
            .output()
            .expect("failed to execute bash for gate evaluation test");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };

    assert_eq!(
        run_gate("install ok installed", "install ok installed"),
        "SKIPPED",
        "both installed ok must skip apt"
    );
    assert_eq!(
        run_gate("install ok installed", ""),
        "TRIGGERED",
        "partial-installed state (fail2ban installed, python3-systemd missing) must trigger install"
    );
    assert_eq!(
        run_gate("", ""),
        "TRIGGERED",
        "fresh state (both missing) must trigger install"
    );
    assert_eq!(
        run_gate("", "install ok installed"),
        "TRIGGERED",
        "fail2ban missing state must trigger install"
    );
    assert_eq!(
        run_gate("install ok half-installed", "install ok installed"),
        "TRIGGERED",
        "half-installed fail2ban must trigger install"
    );
    assert_eq!(
        run_gate("deinstall ok config-files", "install ok installed"),
        "TRIGGERED",
        "config-files fail2ban must trigger install"
    );
    assert_eq!(
        run_gate("install ok installed", "install ok half-configured"),
        "TRIGGERED",
        "half-configured python3-systemd must trigger install"
    );
}

#[test]
fn planted_reversal_package_detection_gate() {
    let conjunctive_gate = r#"
            if [ "$(dpkg-query -W -f='${Status}' fail2ban 2>/dev/null || true)" != "install ok installed" ] \
                && [ "$(dpkg-query -W -f='${Status}' python3-systemd 2>/dev/null || true)" != "install ok installed" ]; then
        "#;
    let test_script = format!(
        r#"
            dpkg-query() {{
                pkg="$3"
                if [ "$pkg" = "fail2ban" ]; then echo -n "install ok installed"; return 0; fi
                if [ "$pkg" = "python3-systemd" ]; then return 1; fi
                return 1
            }}
            {conjunctive_gate}
                echo "TRIGGERED"
            else
                echo "SKIPPED"
            fi
            "#
    );
    let out = std::process::Command::new("bash")
        .arg("-c")
        .arg(&test_script)
        .output()
        .unwrap();
    let result = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert_eq!(
        result, "SKIPPED",
        "planted conjunction must produce SKIPPED on partial install (reversal proof)"
    );

    let equality_gate = r#"
            if [ "$(dpkg-query -W -f='${Status}' fail2ban 2>/dev/null || true)" = "install ok installed" ] \
                || [ "$(dpkg-query -W -f='${Status}' python3-systemd 2>/dev/null || true)" = "install ok installed" ]; then
        "#;
    let test_script = format!(
        r#"
            dpkg-query() {{
                echo -n "install ok installed"; return 0;
            }}
            {equality_gate}
                echo "TRIGGERED"
            else
                echo "SKIPPED"
            fi
            "#
    );
    let out = std::process::Command::new("bash")
        .arg("-c")
        .arg(&test_script)
        .output()
        .unwrap();
    let result = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert_eq!(
        result, "TRIGGERED",
        "planted equality must produce TRIGGERED on fully installed node (reversal proof)"
    );
}

#[test]
fn setup_script_provisions_gpg_keyring_atomically_with_validation_and_cleanup() {
    let s = SING_BOX_SETUP_SCRIPT.as_str();

    assert!(
        s.contains("install -d -m 0755 /usr/share/keyrings"),
        "keyrings dir creation missing: {s}"
    );

    assert!(
        s.contains(r#"KEYRING_TMP="/usr/share/keyrings/sagernet.gpg.tmp"#),
        "temp file must be under /usr/share/keyrings: {s}"
    );

    assert!(
        s.contains(r#"trap 'rm -f "$KEYRING_TMP"' EXIT"#),
        "cleanup trap for KEYRING_TMP missing: {s}"
    );

    assert!(
        s.contains(r#"curl -fsSL https://sing-box.app/gpg.key"#)
            && s.contains(r#"gpg --dearmor --yes -o "$KEYRING_TMP""#),
        "gpg dearmor must write to KEYRING_TMP: {s}"
    );
    assert!(
        !s.contains("gpg --dearmor --yes -o /usr/share/keyrings/sagernet.gpg"),
        "must not directly dearmor into live keyring: {s}"
    );

    assert!(
        s.contains(r#"test -s "$KEYRING_TMP""#),
        "must validate KEYRING_TMP is non-empty: {s}"
    );

    assert!(
        s.contains(
            r#"gpg --no-default-keyring --keyring "$KEYRING_TMP" --list-keys >/dev/null 2>&1"#
        ),
        "must validate KEYRING_TMP parses as a valid keyring: {s}"
    );

    assert!(
        s.contains(r#"chmod 0644 "$KEYRING_TMP""#),
        "must chmod 0644 KEYRING_TMP: {s}"
    );

    assert!(
        s.contains(r#"mv "$KEYRING_TMP" /usr/share/keyrings/sagernet.gpg"#),
        "must atomically move KEYRING_TMP over live keyring: {s}"
    );

    assert!(
        s.contains("trap - EXIT"),
        "must disarm trap after successful atomic move: {s}"
    );

    let trap_pos = s
        .find(r#"trap 'rm -f "$KEYRING_TMP"' EXIT"#)
        .expect("trap pos");
    let curl_pos = s
        .find("curl -fsSL https://sing-box.app/gpg.key")
        .expect("curl pos");
    let test_s_pos = s.find(r#"test -s "$KEYRING_TMP""#).expect("test -s pos");
    let gpg_val_pos = s
        .find(r#"gpg --no-default-keyring --keyring "$KEYRING_TMP" --list-keys"#)
        .expect("gpg val pos");
    let chmod_pos = s.find(r#"chmod 0644 "$KEYRING_TMP""#).expect("chmod pos");
    let mv_pos = s
        .find(r#"mv "$KEYRING_TMP" /usr/share/keyrings/sagernet.gpg"#)
        .expect("mv pos");
    let untrap_pos = s.find("trap - EXIT").expect("untrap pos");

    assert!(trap_pos < curl_pos, "trap must be set BEFORE download");
    assert!(
        curl_pos < test_s_pos,
        "download must come before non-empty test"
    );
    assert!(
        test_s_pos < gpg_val_pos,
        "non-empty test must come before gpg parse test"
    );
    assert!(
        gpg_val_pos < chmod_pos,
        "gpg parse validation must come before chmod"
    );
    assert!(chmod_pos < mv_pos, "chmod must come before atomic mv");
    assert!(mv_pos < untrap_pos, "atomic mv must come before untrap");
}

#[test]
fn planted_reversal_gpg_keyring_transactional_failure_modes() {
    let temp_dir = std::env::temp_dir().join(format!("vpnctl-test-keyring-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&temp_dir).unwrap();

    let live_keyring = temp_dir.join("sagernet.gpg");
    std::fs::write(&live_keyring, b"original-valid-keyring").unwrap();
    let gnupg_home = temp_dir.join("gnupg");
    std::fs::create_dir_all(&gnupg_home).unwrap();
    std::fs::set_permissions(
        &gnupg_home,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();

    let script_empty = format!(
        r#"
            set -eu
            KEYRING_TMP="{temp_dir}/sagernet.gpg.tmp.$$"
            trap 'rm -f "$KEYRING_TMP"' EXIT
            touch "$KEYRING_TMP" # simulate empty download
            test -s "$KEYRING_TMP"
            gpg --no-default-keyring --keyring "$KEYRING_TMP" --list-keys >/dev/null 2>&1
            chmod 0644 "$KEYRING_TMP"
            mv "$KEYRING_TMP" "{live}"
            trap - EXIT
            "#,
        temp_dir = temp_dir.display(),
        live = live_keyring.display()
    );

    let out = std::process::Command::new("sh")
        .env("GNUPGHOME", &gnupg_home)
        .arg("-c")
        .arg(&script_empty)
        .output()
        .unwrap();

    assert!(!out.status.success(), "empty file must fail execution");
    assert_eq!(
        std::fs::read(&live_keyring).unwrap(),
        b"original-valid-keyring",
        "live keyring must remain untouched on empty download failure"
    );

    let leftover_tmp = std::fs::read_dir(&temp_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .any(|e| e.file_name().to_string_lossy().contains(".tmp"));
    assert!(
        !leftover_tmp,
        "cleanup trap must remove temporary file on failure"
    );

    let script_corrupt = format!(
        r#"
            set -eu
            KEYRING_TMP="{temp_dir}/sagernet.gpg.tmp.$$"
            trap 'rm -f "$KEYRING_TMP"' EXIT
            echo "corrupt non-keyring data" > "$KEYRING_TMP"
            test -s "$KEYRING_TMP"
            gpg --no-default-keyring --keyring "$KEYRING_TMP" --list-keys >/dev/null 2>&1
            chmod 0644 "$KEYRING_TMP"
            mv "$KEYRING_TMP" "{live}"
            trap - EXIT
            "#,
        temp_dir = temp_dir.display(),
        live = live_keyring.display()
    );

    let out = std::process::Command::new("sh")
        .env("GNUPGHOME", &gnupg_home)
        .arg("-c")
        .arg(&script_corrupt)
        .output()
        .unwrap();

    assert!(
        !out.status.success(),
        "corrupt keyring parse must fail execution"
    );
    assert_eq!(
        std::fs::read(&live_keyring).unwrap(),
        b"original-valid-keyring",
        "live keyring must remain untouched on corrupt keyring parse failure"
    );

    let leftover_tmp = std::fs::read_dir(&temp_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .any(|e| e.file_name().to_string_lossy().contains(".tmp"));
    assert!(
        !leftover_tmp,
        "cleanup trap must remove temporary file on failure"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn firewall_open_script_opens_each_port_idempotently_guarded() {
    let script = firewall_open_script(&[("tcp", 443), ("udp", 8443), ("udp", 8444), ("udp", 8444)])
        .expect("non-empty ports yield a script");
    assert!(
        script.contains("command -v ufw"),
        "must guard on ufw presence: {script}"
    );
    for line in [
        "ufw allow 443/tcp",
        "ufw allow 8443/udp",
        "ufw allow 8444/udp",
    ] {
        assert!(script.contains(line), "missing `{line}` in: {script}");
    }
    assert_eq!(
        script.matches("ufw allow 8444/udp").count(),
        1,
        "duplicate ports must collapse: {script}"
    );
    assert!(
        script.contains("|| true"),
        "must not fail on an existing rule: {script}"
    );
}

#[test]
fn firewall_open_script_empty_ports_is_none() {
    assert!(
        firewall_open_script(&[]).is_none(),
        "no declared ports => no firewall step"
    );
}

#[test]
fn setup_script_retains_install_log_and_logrotate_steps() {
    let s = SING_BOX_SETUP_SCRIPT.as_str();
    assert!(
        s.contains("apt-get install -y sing-box"),
        "sing-box install"
    );
    assert!(
        s.contains("install -o sing-box -g sing-box -m 0640 /dev/null /var/log/sing-box.log"),
        "log-file pre-create"
    );
    assert!(
            s.contains("[ -f /var/log/sing-box.log ] || install -o sing-box -g sing-box -m 0640 /dev/null /var/log/sing-box.log"),
            "log-file pre-create MUST be conditional (only-if-absent) — an unconditional `install /dev/null` re-create orphans sing-box's open log fd on every ensure_installed/update-kernels, breaking attribution"
        );
    assert!(
        s.contains("/etc/logrotate.d/sing-box"),
        "logrotate fragment"
    );
    assert!(s.contains("set -eu"), "fail-fast shell flags");
}

#[test]
fn sing_box_setup_script_gates_install_on_min_version() {
    let s = SING_BOX_SETUP_SCRIPT.as_str();
    assert!(
            s.contains(r#"[ "$(dpkg-query -W -f='${Status}' sing-box 2>/dev/null || true)" != "install ok installed" ]"#),
            "gate must require exact dpkg-query status 'install ok installed' for sing-box: {s}"
        );
    assert!(
        s.contains("[ ! -x /usr/bin/sing-box ]"),
        "gate must check for /usr/bin/sing-box executable: {s}"
    );
    assert!(
        s.contains(
            "CUR=$(/usr/bin/sing-box version 2>/dev/null | awk '/version/{print $3; exit}')"
        ),
        "version read must explicitly target /usr/bin/sing-box: {s}"
    );
    assert!(
        s.contains("dpkg --compare-versions"),
        "install must be gated on a dpkg version comparison, not bare presence: {s}"
    );
    assert!(
        s.contains(SING_BOX_MIN_VERSION),
        "the SING_BOX_MIN_VERSION floor ({SING_BOX_MIN_VERSION}) must appear in the rendered script: {s}"
    );
    assert!(
        s.contains(&format!("ge \"{SING_BOX_MIN_VERSION}\"")),
        "the floor must be the `ge` operand of the version compare: {s}"
    );
    assert!(
        !s.contains("if ! command -v sing-box"),
        "the bare-presence-only install gate must be gone: {s}"
    );
    assert!(
        s.contains(r#"if [ "$NEED" = 1 ]; then"#),
        "apt install must be reached via the version-aware NEED gate: {s}"
    );
    assert!(
        s.contains("REINSTALL=1") && s.contains("apt-get install -y --reinstall sing-box"),
        "missing canonical binary must force package reinstall: {s}"
    );
    assert!(
        s.contains("https://sing-box.app/gpg.key")
            && s.contains(r#"gpg --dearmor --yes -o "$KEYRING_TMP""#)
            && s.contains("deb.sagernet.org")
            && s.contains("apt-get install -y sing-box"),
        "SagerNet repo setup + apt install must be retained inside the gate: {s}"
    );
    assert!(
        s.contains("test -x /usr/bin/sing-box  # final assertion"),
        "the final `test -x /usr/bin/sing-box` assertion must remain: {s}"
    );
}

#[test]
fn sing_box_setup_script_gate_evaluation() {
    let s = SING_BOX_SETUP_SCRIPT.as_str();
    assert!(s.contains("dpkg-query -W -f='${Status}' sing-box"));

    let gate_block = s
        .lines()
        .skip_while(|line| !line.contains("dpkg-query -W -f='${Status}' sing-box"))
        .take_while(|line| !line.trim().starts_with("if [ \"$NEED\" = 1 ]"))
        .collect::<Vec<_>>()
        .join("\n");

    let run_gate = |pkg_status: &str, usr_bin_exists: bool, usr_bin_ver: &str| -> String {
        let temp_dir =
            std::env::temp_dir().join(format!("vpnctl-test-gate-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let mock_bin = temp_dir.join("sing-box");
        if usr_bin_exists {
            let script = format!(
                "#!/bin/sh\nif [ \"$1\" = \"version\" ]; then echo \"sing-box version {usr_bin_ver}\"; exit 0; fi\nexit 0\n"
            );
            std::fs::write(&mock_bin, script).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&mock_bin, std::fs::Permissions::from_mode(0o755))
                    .unwrap();
            }
        } else {
            let _ = std::fs::remove_file(&mock_bin);
        }

        let mut gate_code = gate_block.clone();
        gate_code = gate_code.replace("/usr/bin/sing-box", &mock_bin.to_string_lossy());

        let test_script = format!(
            r#"
                dpkg() {{
                    if [ "$1" = "--compare-versions" ]; then
                        v1="$2"
                        op="$3"
                        v2="$4"
                        if [ "$v1" = "$v2" ]; then return 0; fi
                        awk -v v1="$v1" -v v2="$v2" 'BEGIN {{
                            n1 = split(v1, a1, /[.-]/);
                            n2 = split(v2, a2, /[.-]/);
                            n = (n1 > n2 ? n1 : n2);
                            for (i = 1; i <= n; i++) {{
                                d1 = (i <= n1 ? a1[i] + 0 : 0);
                                d2 = (i <= n2 ? a2[i] + 0 : 0);
                                if (d1 > d2) exit 0;
                                if (d1 < d2) exit 1;
                            }}
                            exit 0;
                        }}'
                        return $?
                    fi
                    return 1
                }}
                dpkg-query() {{
                    for arg in "$@"; do
                        if [ "$arg" = "sing-box" ]; then
                            if [ -n "{pkg_status}" ]; then echo -n "{pkg_status}"; return 0; else return 1; fi
                        fi
                    done
                    return 1
                }}
                NEED=0
                {gate_code}
                if [ "$NEED" = 1 ]; then
                    echo "TRIGGERED"
                else
                    echo "SKIPPED"
                fi
                "#,
            pkg_status = pkg_status,
            gate_code = gate_code,
        );

        let out = std::process::Command::new("bash")
            .arg("-c")
            .arg(&test_script)
            .output()
            .expect("failed to execute gate evaluation");
        let _ = std::fs::remove_dir_all(&temp_dir);
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };

    assert_eq!(
        run_gate("install ok installed", true, SING_BOX_MIN_VERSION),
        "SKIPPED",
        "installed package at min version must skip apt"
    );
    assert_eq!(
        run_gate("install ok installed", true, "1.15.0"),
        "SKIPPED",
        "installed package above min version must skip apt"
    );

    assert_eq!(
        run_gate("", true, "1.15.0"),
        "TRIGGERED",
        "unregistered package state must trigger apt even if executable exists"
    );

    assert_eq!(
        run_gate("install ok installed", false, ""),
        "TRIGGERED",
        "missing /usr/bin/sing-box must trigger apt"
    );

    assert_eq!(
        run_gate("install ok installed", true, "1.13.7"),
        "TRIGGERED",
        "installed package below floor version must trigger apt upgrade"
    );

    assert_eq!(
        run_gate("install ok half-installed", true, "1.15.0"),
        "TRIGGERED",
        "half-installed package state must trigger apt"
    );
    assert_eq!(
        run_gate("deinstall ok config-files", true, "1.15.0"),
        "TRIGGERED",
        "config-files package state must trigger apt"
    );
}

#[test]
fn sing_box_setup_script_verifies_floor_after_install() {
    let s = SING_BOX_SETUP_SCRIPT.as_str();
    assert!(
        s.matches("dpkg --compare-versions").count() >= 2,
        "must re-compare the installed version against the floor AFTER apt install: {s}"
    );
    assert!(
        s.matches(&format!("ge \"{SING_BOX_MIN_VERSION}\"")).count() >= 2,
        "the post-install re-check must compare against the same floor: {s}"
    );
    let apt_at = s
        .find("apt-get install -y sing-box")
        .expect("apt install of sing-box must be present");
    let tail = &s[apt_at..];
    assert!(
        tail.contains("dpkg --compare-versions"),
        "the floor re-check must come AFTER the apt install: {s}"
    );
    assert!(
        tail.contains("exit 1"),
        "a failed post-install floor check must abort the deploy with exit 1: {s}"
    );
    assert!(
        tail.contains("/usr/bin/sing-box version"),
        "the re-check must specifically test /usr/bin/sing-box: {s}"
    );
    assert!(
        s.contains("floor unreachable from this repo"),
        "the abort diagnostic must explain the floor-unreachable cause: {s}"
    );
}

#[test]
fn logrotate_fragment_uses_copytruncate_without_create() {
    let s = SING_BOX_SETUP_SCRIPT.as_str();
    let start = s
        .find("/var/log/sing-box.log {")
        .expect("logrotate heredoc opening brace not found");
    let fragment = &s[start..];
    let end = fragment
        .find('}')
        .expect("logrotate heredoc closing brace not found");
    let fragment = &fragment[..end];
    assert!(
        fragment.contains("copytruncate"),
        "logrotate fragment must use copytruncate: {fragment}"
    );
    assert!(
        fragment.contains("compressoptions -1") && !fragment.contains("delaycompress"),
        "an immediate rotation must reclaim space without expensive default compression: {fragment}"
    );
    assert!(
        !fragment.contains("create "),
        "logrotate fragment must NOT carry a `create` directive (orphans sing-box's fd): {fragment}"
    );
}

#[test]
fn logrotate_fragment_uses_root_su_and_visible_errors() {
    let s = SING_BOX_SETUP_SCRIPT.as_str();
    let start = s
        .find("/var/log/sing-box.log {")
        .expect("logrotate heredoc opening brace not found");
    let fragment = &s[start..];
    let end = fragment
        .find('}')
        .expect("logrotate heredoc closing brace not found");
    let fragment = &fragment[..end];
    assert!(
        fragment.contains("su root root") && !fragment.contains("su sing-box"),
        "logrotate must satisfy group-writable /var/log without dropping privileges: {fragment}"
    );
    assert!(
        s.contains("logrotate -d /etc/logrotate.conf >/dev/null\n"),
        "must validate the global logrotate.conf include graph: {s}"
    );
    assert!(
        s.contains("logrotate /etc/logrotate.d/sing-box\n"),
        "deploy must immediately rotate an already-oversized log: {s}"
    );
    assert!(
        !s.contains("logrotate -d /etc/logrotate.conf >/dev/null 2>&1"),
        "validation must NOT suppress stderr: {s}"
    );
    assert!(
        s.contains("rm -f /etc/logrotate.d/sing-box.bak"),
        "must clean stale .bak backups from the parsed logrotate dir: {s}"
    );
    assert!(
        s.contains("sing-box.bak.*"),
        "must clean dateext-style sing-box.bak.<date> duplicates: {s}"
    );
    assert!(
        s.contains("sing-box.dpkg-old"),
        "must clean dpkg conffile backups: {s}"
    );
}

#[test]
fn render_config_keeps_existing_top_level_keys() {
    let s = dummy_server();
    let secrets = HashMap::new();
    let ctx = dummy_ctx(&s, &secrets);
    let bytes = SingBox::new().render_config(&ctx, &[], &[]).unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert!(v["log"].is_object(), "log block missing");
    assert!(v["inbounds"].is_array(), "inbounds array missing");
    let out = v["outbounds"].as_array().unwrap();
    assert_eq!(out.len(), 2, "outbounds should be [direct, block]");
    assert_eq!(out[0]["type"], "direct");
    assert_eq!(out[1]["type"], "block");
}

fn make_config(uuids: &[&str]) -> Vec<u8> {
    let users: Vec<Value> = uuids
        .iter()
        .map(|u| {
            serde_json::json!({
                "name": "u",
                "uuid": u,
                "flow": "xtls-rprx-vision",
            })
        })
        .collect();
    let cfg = serde_json::json!({
        "inbounds": [
            { "type": "vless", "users": users }
        ]
    });
    serde_json::to_vec(&cfg).unwrap()
}

#[test]
fn extract_user_uuids_finds_every_uuid_across_inbounds() {
    let cfg = serde_json::json!({
        "inbounds": [
            { "type": "vless", "users": [
                {"uuid": "aaa", "name": "a"},
                {"uuid": "bbb", "name": "b"},
            ]},
            { "type": "tuic", "users": [{"uuid": "ccc", "password": "x"}] },
            { "type": "trojan", "users": [{"password": "no-uuid-here"}] },
        ]
    });
    let bytes = serde_json::to_vec(&cfg).unwrap();
    let got = extract_user_uuids(&bytes).unwrap();
    let expected: std::collections::HashSet<String> = ["aaa", "bbb", "ccc"]
        .into_iter()
        .map(String::from)
        .collect();
    assert_eq!(got, expected);
}

#[test]
fn extract_user_uuids_returns_empty_on_no_inbounds() {
    let bytes = b"{}".to_vec();
    let got = extract_user_uuids(&bytes).unwrap();
    assert!(got.is_empty());
}

#[test]
fn extract_user_uuids_returns_err_on_invalid_json() {
    let bytes = b"not json".to_vec();
    assert!(extract_user_uuids(&bytes).is_err());
}

#[test]
fn live_config_user_uuids_returns_sorted_set() {
    let cfg = serde_json::json!({
        "inbounds": [
            { "type": "vless", "users": [
                {"uuid": "ccc"},
                {"uuid": "aaa"},
                {"uuid": "bbb"},
            ]},
        ]
    });
    let bytes = serde_json::to_vec(&cfg).unwrap();
    let got = live_config_user_uuids(&bytes);
    let order: Vec<&String> = got.iter().collect();
    assert_eq!(order, vec!["aaa", "bbb", "ccc"]);
}

#[test]
fn live_config_user_uuids_empty_on_unparseable_bytes() {
    assert!(live_config_user_uuids(b"not json").is_empty());
    assert!(live_config_user_uuids(b"{}").is_empty());
}

#[test]
fn user_uuid_diff_empty_when_new_is_superset() {
    let old = make_config(&["a", "b"]);
    let new = make_config(&["a", "b", "c"]);
    assert!(user_uuid_diff(&old, &new).unwrap().is_empty());
}

#[test]
fn user_uuid_diff_lists_only_removed_uuids() {
    let old = make_config(&["a", "b", "c"]);
    let new = make_config(&["a", "c"]);
    let lost = user_uuid_diff(&old, &new).unwrap();
    assert_eq!(lost.len(), 1, "lost: {lost:?}");
    assert!(lost.contains("b"));
}

#[test]
fn user_uuid_diff_lists_the_pavel_2026_05_19_case() {
    let live = make_config(&[
        "af6f36aa-2a51-45c7-82dd-5cd362ed970b",
        "b25684c3-90d6-454a-a911-4e0abba568b0",
    ]);
    let rendered = make_config(&["af6f36aa-2a51-45c7-82dd-5cd362ed970b"]);
    let lost = user_uuid_diff(&live, &rendered).unwrap();
    assert_eq!(lost.len(), 1);
    assert!(lost.contains("b25684c3-90d6-454a-a911-4e0abba568b0"));
}

#[test]
fn user_uuid_diff_empty_when_old_has_no_users() {
    let old = b"{\"inbounds\":[]}".to_vec();
    let new = make_config(&["a", "b"]);
    assert!(user_uuid_diff(&old, &new).unwrap().is_empty());
}

fn cfg_with_inbound_ports(ports: &[u16]) -> Vec<u8> {
    let inbounds: Vec<serde_json::Value> = ports
        .iter()
        .map(|p| serde_json::json!({"type": "vless", "listen_port": p}))
        .collect();
    serde_json::to_vec(&serde_json::json!({"inbounds": inbounds})).unwrap()
}

#[test]
fn reserved_ports_empty_list_is_noop() {
    let cfg = cfg_with_inbound_ports(&[443, 8443]);
    assert!(validate_config_excludes_ports(&cfg, &[]).is_ok());
}

#[test]
fn reserved_ports_disjoint_passes() {
    let cfg = cfg_with_inbound_ports(&[8443, 2083]);
    assert!(validate_config_excludes_ports(&cfg, &[443]).is_ok());
}

#[test]
fn reserved_ports_intersection_blocks() {
    let cfg = cfg_with_inbound_ports(&[443, 8443]);
    let err = validate_config_excludes_ports(&cfg, &[443])
        .expect_err("reserved-port collision must error");
    let msg = err.to_string();
    assert!(msg.contains("443"), "error must mention port 443: {msg}");
}

#[test]
fn reserved_ports_multiple_collisions_listed() {
    let cfg = cfg_with_inbound_ports(&[443, 2053, 2096, 8443]);
    let err = validate_config_excludes_ports(&cfg, &[443, 2053, 2096])
        .expect_err("multi-port collision must error");
    let msg = err.to_string();
    assert!(msg.contains("[443, 2053, 2096]"), "msg = {msg}");
}

#[test]
fn reserved_ports_malformed_config_fails_closed() {
    let err = validate_config_excludes_ports(b"not-json", &[443])
        .expect_err("malformed config with non-empty reserved list must fail closed");
    let msg = err.to_string();
    assert!(msg.contains("parse"), "msg = {msg}");
}

#[test]
fn reserved_ports_no_inbounds_array_is_safe() {
    let cfg = serde_json::to_vec(&serde_json::json!({"outbounds": []})).unwrap();
    assert!(validate_config_excludes_ports(&cfg, &[443]).is_ok());
}

#[test]
fn reserved_ports_listen_port_missing_is_safe() {
    let cfg = serde_json::to_vec(&serde_json::json!({
        "inbounds": [{"type": "vless"}, {"type": "tuic", "listen_port": 8443}]
    }))
    .unwrap();
    assert!(validate_config_excludes_ports(&cfg, &[443]).is_ok());
}

#[test]
fn reserved_ports_listen_port_non_u16_skipped() {
    let cfg = serde_json::to_vec(&serde_json::json!({
        "inbounds": [{"listen_port": 999_999}, {"listen_port": 443}]
    }))
    .unwrap();
    let err = validate_config_excludes_ports(&cfg, &[443]).expect_err("443 collides");
    assert!(err.to_string().contains("443"));
}

#[test]
fn apply_script_snapshots_live_config_before_swap() {
    let s = sing_box_apply_script();
    let cp = s
        .find("cp -a /etc/sing-box/config.json /etc/sing-box/config.json.bak")
        .expect("snapshot cp -a to .bak missing");
    let mv = s
        .find("mv /etc/sing-box/config.json.new /etc/sing-box/config.json")
        .expect("atomic swap mv missing");
    assert!(cp < mv, "snapshot must come BEFORE the atomic swap");
    assert!(
        s.contains("if [ -f /etc/sing-box/config.json ]; then"),
        "snapshot must be guarded on the live config existing: {s}"
    );
}

#[test]
fn apply_script_restores_bak_on_is_active_failure() {
    let s = sing_box_apply_script();
    let journal = s
        .find("journalctl -u sing-box")
        .expect("diagnostics dump missing");
    let restore = s
        .find("mv /etc/sing-box/config.json.bak /etc/sing-box/config.json")
        .expect("restore mv from .bak missing");
    let exit1 = s.rfind("exit 1").expect("failure exit missing");
    assert!(
        journal < restore && restore < exit1,
        "restore must run on the failure branch, after diagnostics, before exit 1"
    );
    let restart_after_restore = s[restore..exit1].contains("systemctl reload-or-restart sing-box");
    assert!(
        restart_after_restore,
        "restore branch must reload-or-restart back to the good config"
    );
    assert!(
        s[restore..exit1].contains("sing-box.vpnctl-prev")
            && s[restore..exit1].contains("singbox-stats-helper.prev")
            && s[restore..exit1].contains("sing-box.rollback-new")
            && s[restore..exit1].contains("singbox-stats-helper.rollback-new"),
        "a Stats health failure must atomically restore the previous managed pair"
    );
    assert!(
        s[restore..exit1].contains("|| true"),
        "restore steps must be `|| true`-guarded so the branch always reaches exit 1"
    );
}

#[test]
fn apply_script_cleans_up_bak_on_success() {
    let s = sing_box_apply_script();
    assert!(
        s.contains("rm -f /etc/sing-box/config.json.bak"),
        "success path must clean up the .bak snapshot: {s}"
    );
    assert!(
        s.contains("singbox-stats-helper --timeout 2s"),
        "success requires the loopback Stats API, not only systemd active"
    );
}

#[tokio::test]
async fn open_firewall_uses_effective_listen_ports() {
    #[derive(Debug, Default)]
    struct Recording {
        scripts: std::sync::Mutex<Vec<String>>,
    }
    #[async_trait::async_trait]
    impl vpnctl_core::SshTransport for Recording {
        async fn exec(&self, cmd: &str) -> vpnctl_core::Result<String> {
            self.scripts.lock().unwrap().push(cmd.to_string());
            Ok(String::new())
        }
        async fn exec_unprivileged(&self, cmd: &str) -> vpnctl_core::Result<String> {
            self.exec(cmd).await
        }
        async fn upload(&self, _path: &str, _content: &[u8]) -> vpnctl_core::Result<()> {
            Ok(())
        }
        async fn read_file(&self, _path: &str) -> vpnctl_core::Result<Vec<u8>> {
            Ok(Vec::new())
        }
    }

    let s = dummy_server();
    let mut secrets = HashMap::new();
    secrets.insert("vless.listen_port".to_string(), "8443".to_string());
    let ctx = dummy_ctx(&s, &secrets);
    let ssh = Recording::default();
    let reality = vpnctl_protocols::VlessReality::new();
    let protocols: Vec<&dyn vpnctl_core::Protocol> = vec![&reality];

    SingBox::new()
        .open_firewall(&ssh, &ctx, &protocols)
        .await
        .unwrap();

    let scripts = ssh.scripts.lock().unwrap();
    assert_eq!(scripts.len(), 1, "exactly one ufw script expected");
    let script = &scripts[0];
    assert!(
        script.contains("ufw allow 8443/tcp"),
        "override port must be opened: {script}"
    );
    assert!(
        !script.contains(" 443/tcp"),
        "static default must NOT be opened once overridden: {script}"
    );
}

#[test]
fn is_artifact_up_to_date_detects_matching_and_mismatching_node_state() {
    use super::is_artifact_up_to_date;

    let sb = "5f98eacc95b9ed9c1d53592605d812d9d2cb8c496fa95723cfb7c5f9447fe46e";
    let sh = "adfcc59728309f6e5bda548d402b3284fe97bdd9216b04933d1b97b4a2531ddc";

    let valid_output = format!(
        "{sb}  /usr/bin/sing-box\n{sh}  /usr/local/libexec/vpnctl/singbox-stats-helper\nactive\n"
    );
    assert!(
        is_artifact_up_to_date(&valid_output, sb, sh),
        "must be up to date when both checksums match and service is active"
    );

    let mismatched_sb = format!(
        "different_sha  /usr/bin/sing-box\n{sh}  /usr/local/libexec/vpnctl/singbox-stats-helper\nactive\n"
    );
    assert!(
        !is_artifact_up_to_date(&mismatched_sb, sb, sh),
        "must not be up to date when sing-box binary sha differs"
    );

    let mismatched_sh = format!(
        "{sb}  /usr/bin/sing-box\ndifferent_sh  /usr/local/libexec/vpnctl/singbox-stats-helper\nactive\n"
    );
    assert!(
        !is_artifact_up_to_date(&mismatched_sh, sb, sh),
        "must not be up to date when stats-helper sha differs"
    );

    let inactive_service = format!(
        "{sb}  /usr/bin/sing-box\n{sh}  /usr/local/libexec/vpnctl/singbox-stats-helper\ninactive\n"
    );
    assert!(
        !is_artifact_up_to_date(&inactive_service, sb, sh),
        "must not be up to date when service is inactive"
    );

    assert!(
        !is_artifact_up_to_date("", sb, sh),
        "empty output must fail safely"
    );
    assert!(
        !is_artifact_up_to_date("error: command not found", sb, sh),
        "error output must fail safely"
    );
}
