#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use std::collections::HashMap;
use vpnctl_core::{Server, ServerId, UserId};
use vpnctl_protocols::WireGuard;

fn dummy_server() -> Server {
    Server {
        id: ServerId("awg-node-1".into()),
        address: "203.0.113.7".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("amneziawg".into())],
        enabled_protocols: vec![ProtocolId("wireguard".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

fn user_with_pubkey(name: &str, pubkey: Option<&str>) -> User {
    User {
        id: UserId(name.into()),
        uuid: format!("uuid-{name}"),
        tuic_password: None,
        wireguard_pubkey: pubkey.map(str::to_string),
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    }
}

const PUBKEY_A: &str = "qXFvJL5KLmM3Of9hVo5GmJ4n0LB9rWYfV4ZE1XGZJks=";
const PUBKEY_B: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaaa=";

fn server_secrets() -> HashMap<String, String> {
    let mut s = HashMap::new();
    s.insert(
        "wireguard.server_private_key".into(),
        "AAABBBCCCDDDEEEFFFGGGHHHIIIJJJKKKLLLMMMNNNn=".into(),
    );
    s
}

#[test]
fn id_returns_amneziawg() {
    assert_eq!(AmneziaWg::new().id(), KernelId("amneziawg".into()));
}

#[test]
fn supported_protocols_only_wireguard() {
    assert_eq!(
        AmneziaWg::new().supported_protocols(),
        vec![ProtocolId("wireguard".into())]
    );
}

#[test]
fn render_config_missing_protocol_returns_render_error() {
    let s = dummy_server();
    let secrets = server_secrets();
    let ctx = RenderCtx::new(&s, &secrets);
    let err = AmneziaWg::new().render_config(&ctx, &[], &[]).unwrap_err();
    match err {
        CoreError::Render(msg) => {
            assert!(
                msg.contains("wireguard"),
                "msg should mention wireguard: {msg}"
            );
        }
        other => panic!("expected Render error, got {other:?}"),
    }
}

#[test]
fn render_config_emits_warning_header_and_interface_block() {
    let s = dummy_server();
    let secrets = server_secrets();
    let ctx = RenderCtx::new(&s, &secrets);
    let wg = WireGuard::new();
    let bytes = AmneziaWg::new()
        .render_config(&ctx, &[], &[&wg as &dyn Protocol])
        .unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    assert!(
        text.starts_with("# Rendered by vpnctl"),
        "must lead with do-not-edit warning"
    );
    assert!(text.contains("[Interface]\n"));
    assert!(text.contains("PrivateKey = AAABBBCCCDDDEEEFFFGGGHHHIIIJJJKKKLLLMMMNNNn="));
    assert!(text.contains("ListenPort = 51820"));
    assert!(text.contains("Address = 10.66.0.1/24"));
}

#[test]
fn render_config_includes_all_nine_amnezia_obfuscation_keys_with_defaults() {
    let s = dummy_server();
    let secrets = server_secrets();
    let ctx = RenderCtx::new(&s, &secrets);
    let wg = WireGuard::new();
    let bytes = AmneziaWg::new()
        .render_config(&ctx, &[], &[&wg as &dyn Protocol])
        .unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    for (key, default) in vpnctl_core::amneziawg::DEFAULT_AMNEZIA_PARAMS {
        let expected = format!("{key} = {default}\n");
        assert!(
            text.contains(&expected),
            "missing default obfuscation key: {expected:?}"
        );
    }
}

#[test]
fn partial_and_empty_awg_params_match_all_client_renderers() {
    let server = dummy_server();
    let wg = WireGuard::new();
    let mut user = user_with_pubkey("alice", Some(PUBKEY_A));
    user.wireguard_private = Some("0000000000000000000000000000000000000000000=".into());
    let defaults = [
        ("Jc", "4"),
        ("Jmin", "40"),
        ("Jmax", "70"),
        ("S1", "50"),
        ("S2", "100"),
        ("H1", "1"),
        ("H2", "2"),
        ("H3", "3"),
        ("H4", "4"),
    ];
    for supplied in [None, Some("Jc"), Some("H1")] {
        let mut secrets = server_secrets();
        secrets.insert("wireguard.server_public_key".into(), PUBKEY_B.into());
        if let Some(key) = supplied {
            secrets.insert(
                format!("amneziawg.{}", key.to_ascii_lowercase()),
                "123".into(),
            );
        }
        let ctx = RenderCtx::new(&server, &secrets);
        let server_bytes = AmneziaWg::new().render_config(&ctx, &[], &[&wg]).unwrap();
        let server_conf = std::str::from_utf8(&server_bytes).unwrap();
        let client_conf = vpnctl_protocols::render_client_conf_public(&ctx, &user).unwrap();
        let client_json = wg.client_config(&ctx, &user).unwrap();
        let link = vpnctl_protocols::awg_share_link(&ctx, &user).unwrap();
        for (key, default) in defaults {
            let value = if supplied == Some(key) {
                "123"
            } else {
                default
            };
            let line = format!("{key} = {value}\n");
            assert!(server_conf.contains(&line), "server: {line}");
            assert!(client_conf.contains(&line), "client: {line}");
            let lower = key.to_ascii_lowercase();
            assert_eq!(client_json["interface"]["amneziawg"][lower.as_str()], value);
            assert!(link.contains(&format!("&{lower}={value}")));
        }
    }
}

#[test]
fn render_config_overrides_obfs_params_via_secrets() {
    let s = dummy_server();
    let mut secrets = server_secrets();
    secrets.insert("amneziawg.jc".into(), "9".into());
    secrets.insert("amneziawg.h1".into(), "1234567890".into());
    let ctx = RenderCtx::new(&s, &secrets);
    let wg = WireGuard::new();
    let bytes = AmneziaWg::new()
        .render_config(&ctx, &[], &[&wg as &dyn Protocol])
        .unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    assert!(text.contains("Jc = 9\n"));
    assert!(text.contains("H1 = 1234567890\n"));
    assert!(text.contains("Jmin = 40\n"));
}

#[test]
fn render_config_emits_one_peer_block_per_user_with_pubkey() {
    let s = dummy_server();
    let secrets = server_secrets();
    let ctx = RenderCtx::new(&s, &secrets);
    let wg = WireGuard::new();
    let users = [
        user_with_pubkey("alice", Some(PUBKEY_A)),
        user_with_pubkey("bob", Some(PUBKEY_B)),
    ];
    let bytes = AmneziaWg::new()
        .render_config(&ctx, &users, &[&wg as &dyn Protocol])
        .unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    assert_eq!(
        text.matches("[Peer]\n").count(),
        2,
        "expected 2 [Peer] blocks; got conf:\n{text}"
    );
    assert!(text.contains(&format!("PublicKey = {PUBKEY_A}\n")));
    assert!(text.contains(&format!("PublicKey = {PUBKEY_B}\n")));
    assert!(text.contains("# user: alice"));
    assert!(text.contains("# user: bob"));
    assert!(text.contains("AllowedIPs = 10.66.0.2/32\n"));
    assert!(text.contains("AllowedIPs = 10.66.0.3/32\n"));
}

#[test]
fn render_config_skips_users_without_pubkey() {
    let s = dummy_server();
    let secrets = server_secrets();
    let ctx = RenderCtx::new(&s, &secrets);
    let wg = WireGuard::new();
    let users = [
        user_with_pubkey("alice", Some(PUBKEY_A)),
        user_with_pubkey("nopubkey", None),
        user_with_pubkey("bob", Some(PUBKEY_B)),
    ];
    let bytes = AmneziaWg::new()
        .render_config(&ctx, &users, &[&wg as &dyn Protocol])
        .unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    assert_eq!(text.matches("[Peer]\n").count(), 2);
    assert!(!text.contains("# user: nopubkey"));
}

#[test]
fn render_config_uses_lf_only_no_crlf() {
    let s = dummy_server();
    let secrets = server_secrets();
    let ctx = RenderCtx::new(&s, &secrets);
    let wg = WireGuard::new();
    let bytes = AmneziaWg::new()
        .render_config(
            &ctx,
            &[user_with_pubkey("alice", Some(PUBKEY_A))],
            &[&wg as &dyn Protocol],
        )
        .unwrap();
    assert_eq!(
        bytes.iter().filter(|&&b| b == b'\r').count(),
        0,
        "no CRLF allowed in INI output"
    );
}

#[test]
fn render_config_byte_stable_across_runs() {
    let s = dummy_server();
    let secrets = server_secrets();
    let ctx = RenderCtx::new(&s, &secrets);
    let wg = WireGuard::new();
    let users = [
        user_with_pubkey("alice", Some(PUBKEY_A)),
        user_with_pubkey("bob", Some(PUBKEY_B)),
    ];
    let a = AmneziaWg::new()
        .render_config(&ctx, &users, &[&wg as &dyn Protocol])
        .unwrap();
    let b = AmneziaWg::new()
        .render_config(&ctx, &users, &[&wg as &dyn Protocol])
        .unwrap();
    assert_eq!(a, b, "render_config must be byte-stable across runs");
}

#[test]
fn amneziawg_setup_gates_install_on_min_version() {
    let s = AMNEZIAWG_SETUP_SCRIPT.as_str();
    assert!(
        s.contains("dpkg --compare-versions"),
        "install must be gated on a dpkg version comparison, not bare presence: {s}"
    );
    assert!(
        s.contains("dpkg-query -W -f='${Version}' amneziawg-tools"),
        "the floor must compare against the dpkg amneziawg-tools package version: {s}"
    );
    assert!(
        s.contains(AMNEZIAWG_MIN_VERSION),
        "the AMNEZIAWG_MIN_VERSION floor ({AMNEZIAWG_MIN_VERSION}) must appear in the rendered script: {s}"
    );
    assert!(
        s.contains(&format!("ge \"{AMNEZIAWG_MIN_VERSION}\"")),
        "the floor must be the `ge` operand of the version compare: {s}"
    );
    assert!(
        !s.contains("if ! command -v awg-quick >/dev/null; then"),
        "the bare-presence-only install gate must be gone: {s}"
    );
    assert!(
        s.contains(r#"if [ "$NEED" = 1 ]; then"#),
        "apt install must be reached via the version-aware NEED gate: {s}"
    );
    assert!(
        s.contains("75C9DD72C799870E310542E24166F2C257290828")
            && s.contains("ppa.launchpadcontent.net/amnezia/ppa/ubuntu")
            && s.contains("apt-get install -y amneziawg amneziawg-tools"),
        "PPA keyring/repo setup + apt install must be retained inside the gate: {s}"
    );
    assert!(s.contains("set -eu"), "fail-fast shell flags: {s}");
    assert!(
        s.contains("command -v awg-quick")
            && s.contains("command -v awg")
            && s.contains("WARNING: amneziawg DKMS module built for newer kernel"),
        "post-install assertions + kernel-mismatch detection must remain: {s}"
    );
}

#[test]
fn apply_config_validates_via_conf_named_temp_not_conf_new() {
    let s = awg_apply_script();
    assert!(
        !s.contains("awg-quick strip /etc/amnezia/amneziawg/awg0.conf.new"),
        "must NOT validate the .conf.new temp file directly: {s}"
    );
    assert!(
        s.contains(r#"cp /etc/amnezia/amneziawg/awg0.conf.new "$_awgval/awg0.conf""#)
            && s.contains(r#"awg-quick strip "$_awgval/awg0.conf""#),
        "must validate a temp copy named awg0.conf: {s}"
    );
    assert!(
        s.contains("mv /etc/amnezia/amneziawg/awg0.conf.new /etc/amnezia/amneziawg/awg0.conf")
            && s.contains("systemctl reload-or-restart awg-quick@awg0"),
        "atomic install + service restart must remain: {s}"
    );
    assert!(s.contains("set -eu"), "fail-fast shell flags: {s}");
}

#[test]
fn apply_script_snapshots_before_swap_and_rolls_back_on_failure() {
    let s = awg_apply_script();
    let cp = s
        .find("cp -a /etc/amnezia/amneziawg/awg0.conf /etc/amnezia/amneziawg/awg0.conf.bak")
        .expect("snapshot cp -a to .bak missing");
    let mv = s
        .find("mv /etc/amnezia/amneziawg/awg0.conf.new /etc/amnezia/amneziawg/awg0.conf")
        .expect("atomic swap mv missing");
    assert!(cp < mv, "snapshot must precede the swap");
    assert!(
        s.contains("if [ -f /etc/amnezia/amneziawg/awg0.conf ]; then"),
        "snapshot must be guarded on the live config existing: {s}"
    );
    assert!(
        s.contains("rolling back to previous awg0 config"),
        "must roll back on activation failure: {s}"
    );
    assert!(
        s.contains("mv /etc/amnezia/amneziawg/awg0.conf.bak /etc/amnezia/amneziawg/awg0.conf"),
        "rollback must restore the .bak: {s}"
    );
    assert!(
        s.contains("rm -f /etc/amnezia/amneziawg/awg0.conf.bak"),
        "success path must remove the transient .bak: {s}"
    );
    assert!(
        s.contains("journalctl -u awg-quick@awg0"),
        "must dump diagnostics on failure: {s}"
    );
}

#[test]
fn apply_script_first_deploy_failure_removes_config_and_disables() {
    let s = awg_apply_script();
    assert!(
        s.contains("HAD_PREV=0"),
        "must track whether a previous config existed: {s}"
    );
    assert!(
        s.contains("HAD_PREV=1"),
        "must set HAD_PREV=1 when snapshotting: {s}"
    );
    assert!(
        s.contains("no previous config — removing failed deploy"),
        "must handle first-deploy failure: {s}"
    );
    let stop = s
        .find("systemctl stop awg-quick@awg0")
        .expect("must stop the service on first-deploy failure");
    let disable = s
        .find("systemctl disable awg-quick@awg0")
        .expect("must disable the service on first-deploy failure");
    let rm_conf = s
        .find("rm -f /etc/amnezia/amneziawg/awg0.conf\n")
        .expect("must remove the rejected config on first-deploy failure");
    assert!(
        stop < disable && disable < rm_conf,
        "ordering: stop → disable → remove config"
    );
}

#[test]
fn apply_script_validates_egress_iface_charset() {
    let s = awg_apply_script();
    assert!(
        s.contains("*[!a-zA-Z0-9._-]*"),
        "must reject iface names outside the conservative charset: {s}"
    );
    let validate = s
        .find("egress interface name failed validation")
        .expect("must fail closed on malformed iface name");
    let sed = s.find("sed -i").expect("sed interpolation");
    assert!(
        validate < sed,
        "iface validation must precede sed interpolation"
    );
}

#[test]
fn apply_script_command_ordering_validate_snapshot_swap_restart() {
    let s = awg_apply_script();
    let validate = s.find("awg-quick strip").expect("validate step");
    let snapshot = s.find("cp -a").expect("snapshot step");
    let swap = s
        .find("mv /etc/amnezia/amneziawg/awg0.conf.new")
        .expect("swap step");
    let restart = s
        .find("systemctl reload-or-restart awg-quick@awg0")
        .expect("restart step");
    assert!(
        validate < snapshot && snapshot < swap && swap < restart,
        "ordering must be: validate → snapshot → swap → restart"
    );
}

#[test]
fn apply_script_detects_egress_iface_and_persists_ip_forward() {
    let s = awg_apply_script();
    assert!(
        s.contains("ip -o -4 route show to default"),
        "must detect the default egress interface: {s}"
    );
    assert!(
        s.contains("EGRESS=${EGRESS:-eth0}"),
        "must fall back to eth0: {s}"
    );
    assert!(
        s.contains(&format!(
            "sed -i \"s/{EGRESS_IFACE_PLACEHOLDER}/$EGRESS/g\""
        )),
        "must replace the placeholder with the detected interface: {s}"
    );
    assert!(
        s.contains("sysctl -w net.ipv4.ip_forward=1"),
        "must activate IPv4 forwarding: {s}"
    );
    assert!(
        s.contains("/etc/sysctl.d/99-vpnctl-forward.conf"),
        "must persist IPv4 forwarding across reboots: {s}"
    );
}

#[test]
fn render_config_uses_egress_placeholder_not_hardcoded_eth0() {
    let s = dummy_server();
    let secrets = server_secrets();
    let ctx = RenderCtx::new(&s, &secrets);
    let wg = WireGuard::new();
    let bytes = AmneziaWg::new()
        .render_config(&ctx, &[], &[&wg as &dyn Protocol])
        .unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    assert!(
        text.contains(&format!("-o {EGRESS_IFACE_PLACEHOLDER} -j MASQUERADE")),
        "PostUp/PostDown must use the egress placeholder: {text}"
    );
    assert!(
        !text.contains("-o eth0 -j MASQUERADE"),
        "must NOT hardcode eth0 in the rendered config: {text}"
    );
    let placeholder_count = text
        .matches(&format!("-o {EGRESS_IFACE_PLACEHOLDER} -j MASQUERADE"))
        .count();
    assert_eq!(
        placeholder_count, 2,
        "both PostUp and PostDown must reference the placeholder: {text}"
    );
}

#[test]
fn apply_script_failed_reload_rolls_back_without_leaking_keys() {
    let dir = tempfile::TempDir::new().unwrap();
    let root = dir.path();
    let bin = root.join("bin");
    let conf_dir = root.join("etc/amnezia/amneziawg");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir_all(&conf_dir).unwrap();
    std::fs::write(conf_dir.join("awg0.conf"), "OLD\n").unwrap();
    std::fs::write(
        conf_dir.join("awg0.conf.new"),
        "[Interface]\nPrivateKey = fixture-private-key\n[Peer]\nPresharedKey = fixture-preshared-key\n",
    )
    .unwrap();
    // reload fails while the old interface keeps reporting active.
    let stubs = [
        (
            "systemctl",
            "case \"$1\" in reload-or-restart) exit 1;; is-active) echo active;; esac; exit 0",
        ),
        ("awg-quick", "cat \"$2\""),
        ("ip", "exit 0"),
        ("sysctl", "exit 0"),
        ("chown", "exit 0"),
        ("journalctl", "exit 0"),
        ("sleep", "exit 0"),
    ];
    for (name, body) in stubs {
        let path = bin.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
        std::fs::set_permissions(&path, perms).unwrap();
    }
    let script = awg_apply_script().replace("/etc/", &format!("{}/etc/", root.display()));
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let out = std::process::Command::new("sh")
        .arg("-c")
        .arg(&script)
        .env("PATH", path)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    for secret in [
        "PrivateKey",
        "PresharedKey",
        "fixture-private-key",
        "fixture-preshared-key",
    ] {
        assert!(
            !stderr.contains(secret),
            "diagnostics leaked {secret}: {stderr}"
        );
    }
    assert!(stderr.contains("did not become active"));
    assert_eq!(
        std::fs::read_to_string(conf_dir.join("awg0.conf")).unwrap(),
        "OLD\n",
        "a failed reload must restore the previous config"
    );
}

#[test]
fn apply_script_restart_failure_reaches_rollback() {
    let s = awg_apply_script();
    let restart = s
        .find("systemctl reload-or-restart awg-quick@awg0")
        .expect("restart step");
    let line = s[restart..].lines().next().unwrap_or_default();
    assert!(
        line.trim_end().ends_with("|| restart_rc=$?"),
        "under set -eu a failed restart must not skip the .bak rollback: {line}"
    );
}

#[test]
fn apply_script_validation_failure_removes_staging_and_validation_copy() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let conf_dir = root.join("etc/amnezia/amneziawg");
    std::fs::create_dir_all(&conf_dir).unwrap();
    std::fs::write(conf_dir.join("awg0.conf"), "OLD").unwrap();
    std::fs::write(conf_dir.join("awg0.conf.new"), "fixture-secret").unwrap();
    let script = awg_apply_script().replace("/etc/", &format!("{}/etc/", root.display()));
    let mocks = r#"
        ip() { :; }
        sysctl() { :; }
        mktemp() { command mktemp -d "$TEST_ROOT/validate.XXXXXX"; }
        awg-quick() {
            [ "$(stat -c %a "$(dirname "$2")")" = 700 ] || exit 2
            [ "$(stat -c %a "$2")" = 600 ] || exit 2
            return 1
        }
    "#;
    let out = std::process::Command::new("sh")
        .args(["-c", &format!("{mocks}\n{script}")])
        .env("TEST_ROOT", root)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(!conf_dir.join("awg0.conf.new").exists());
    assert_eq!(
        std::fs::read_to_string(conf_dir.join("awg0.conf")).unwrap(),
        "OLD"
    );
    assert!(!std::fs::read_dir(root).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("validate.")
    }));
}
