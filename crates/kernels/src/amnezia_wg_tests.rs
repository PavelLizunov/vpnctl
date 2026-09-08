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

/// Sample valid base64 WG pubkey shape (44 chars, ends '=').
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
    // /24 default address.
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
    for (key, default) in DEFAULT_AMNEZIA_PARAMS {
        let expected = format!("{key} = {default}\n");
        assert!(
            text.contains(&expected),
            "missing default obfuscation key: {expected:?}"
        );
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
    // Defaults for non-overridden keys still present.
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
    // Per-peer comment carries the user id (operator-readable).
    assert!(text.contains("# user: alice"));
    assert!(text.contains("# user: bob"));
    // /32 per peer, indexed.
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

/// The AmneziaWG install must be gated on a MINIMUM VERSION, not on
/// bare presence. Before this gate, `if ! command -v awg-quick`
/// wrapped the apt install directly, so once ANY `awg-quick` was on
/// PATH `vpnctl deploy` never upgraded `amneziawg`/`amneziawg-tools`
/// (latent fleet skew, same class as sing-box #27). Mirrors
/// `sing_box::sing_box_setup_script_gates_install_on_min_version`.
#[test]
fn amneziawg_setup_gates_install_on_min_version() {
    let s = AMNEZIAWG_SETUP_SCRIPT.as_str();
    // The version comparison is present and uses the node's dpkg.
    assert!(
        s.contains("dpkg --compare-versions"),
        "install must be gated on a dpkg version comparison, not bare presence: {s}"
    );
    // The comparison reads the dpkg package version (no brittle
    // `awg --version` banner parsing).
    assert!(
        s.contains("dpkg-query -W -f='${Version}' amneziawg-tools"),
        "the floor must compare against the dpkg amneziawg-tools package version: {s}"
    );
    // The declared floor is injected literally (no hard-coded copy).
    assert!(
        s.contains(AMNEZIAWG_MIN_VERSION),
        "the AMNEZIAWG_MIN_VERSION floor ({AMNEZIAWG_MIN_VERSION}) must appear in the rendered script: {s}"
    );
    // …and it is the right-hand side of the `ge` comparison.
    assert!(
        s.contains(&format!("ge \"{AMNEZIAWG_MIN_VERSION}\"")),
        "the floor must be the `ge` operand of the version compare: {s}"
    );
    // The bare-presence-only gate is GONE: the old wording wrapped
    // the apt install directly in `if ! command -v awg-quick …; then`.
    // Its absence proves the apt path is no longer skipped whenever
    // any awg-quick is on PATH.
    assert!(
        !s.contains("if ! command -v awg-quick >/dev/null; then"),
        "the bare-presence-only install gate must be gone: {s}"
    );
    // The apt install is now reached via the version-aware NEED gate.
    assert!(
        s.contains(r#"if [ "$NEED" = 1 ]; then"#),
        "apt install must be reached via the version-aware NEED gate: {s}"
    );
    // The PPA repo/key setup and the package install are retained
    // inside the gate (the bootstrap is otherwise UNCHANGED).
    assert!(
        s.contains("75C9DD72C799870E310542E24166F2C257290828")
            && s.contains("ppa.launchpadcontent.net/amnezia/ppa/ubuntu")
            && s.contains("apt-get install -y amneziawg amneziawg-tools"),
        "PPA keyring/repo setup + apt install must be retained inside the gate: {s}"
    );
    // Fail-fast shell flags survive the refactor.
    assert!(s.contains("set -eu"), "fail-fast shell flags: {s}");
    // The post-install assertions and the DKMS/kernel-mismatch
    // detection are untouched by the gate change.
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
    // REGRESSION (de 2026-06-27, first live amneziawg deploy): the
    // original code ran `awg-quick strip .../awg0.conf.new`, which
    // awg-quick rejects ("must be a valid interface name, followed by
    // .conf"), failing the deploy before the config was installed. The
    // validated path MUST end in `<iface>.conf`, never `.conf.new`.
    assert!(
        !s.contains("awg-quick strip /etc/amnezia/amneziawg/awg0.conf.new"),
        "must NOT validate the .conf.new temp file directly: {s}"
    );
    // Validation runs on a temp copy NAMED awg0.conf (a path with a
    // slash → awg-quick treats it as a file, not a bare iface name).
    assert!(
        s.contains(r#"cp /etc/amnezia/amneziawg/awg0.conf.new "$_awgval/awg0.conf""#)
            && s.contains(r#"awg-quick strip "$_awgval/awg0.conf""#),
        "must validate a temp copy named awg0.conf: {s}"
    );
    // Only after validation is the real temp atomically installed and
    // the service (re)started + polled active.
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
    // Snapshot precedes the mv swap.
    let cp = s
        .find("cp -a /etc/amnezia/amneziawg/awg0.conf /etc/amnezia/amneziawg/awg0.conf.bak")
        .expect("snapshot cp -a to .bak missing");
    let mv = s
        .find("mv /etc/amnezia/amneziawg/awg0.conf.new /etc/amnezia/amneziawg/awg0.conf")
        .expect("atomic swap mv missing");
    assert!(cp < mv, "snapshot must precede the swap");
    // Snapshot is guarded on existence (first deploy has no live config).
    assert!(
        s.contains("if [ -f /etc/amnezia/amneziawg/awg0.conf ]; then"),
        "snapshot must be guarded on the live config existing: {s}"
    );
    // Rollback restores the .bak and restarts the service.
    assert!(
        s.contains("rolling back to previous awg0 config"),
        "must roll back on activation failure: {s}"
    );
    assert!(
        s.contains("mv /etc/amnezia/amneziawg/awg0.conf.bak /etc/amnezia/amneziawg/awg0.conf"),
        "rollback must restore the .bak: {s}"
    );
    // Success path removes the .bak.
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
    // Detects the default egress interface via a safe fixed pipeline.
    assert!(
        s.contains("ip -o -4 route show to default"),
        "must detect the default egress interface: {s}"
    );
    // Falls back to eth0 when no default route exists.
    assert!(
        s.contains("EGRESS=${EGRESS:-eth0}"),
        "must fall back to eth0: {s}"
    );
    // Replaces the placeholder in the staged config.
    assert!(
        s.contains(&format!(
            "sed -i \"s/{EGRESS_IFACE_PLACEHOLDER}/$EGRESS/g\""
        )),
        "must replace the placeholder with the detected interface: {s}"
    );
    // Persists + activates IPv4 forwarding.
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
    // PostUp/PostDown use the placeholder, not a hardcoded interface.
    assert!(
        text.contains(&format!("-o {EGRESS_IFACE_PLACEHOLDER} -j MASQUERADE")),
        "PostUp/PostDown must use the egress placeholder: {text}"
    );
    assert!(
        !text.contains("-o eth0 -j MASQUERADE"),
        "must NOT hardcode eth0 in the rendered config: {text}"
    );
    // PostUp and PostDown are symmetric (same interface token).
    let placeholder_count = text
        .matches(&format!("-o {EGRESS_IFACE_PLACEHOLDER} -j MASQUERADE"))
        .count();
    assert_eq!(
        placeholder_count, 2,
        "both PostUp and PostDown must reference the placeholder: {text}"
    );
}
