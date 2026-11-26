use std::collections::HashMap;

use vpnctl_core::{
    Kernel, KernelId, Protocol, ProtocolId, RenderCtx, Server, ServerId, User, UserId,
};
use vpnctl_protocols::{Dnstt, TurnRelay, turnrelay_applied_digest};

use super::{PROBE, TurnRelayKernel, artifact_path};

fn server() -> Server {
    Server {
        id: ServerId("de".into()),
        address: "192.0.2.10".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("turnrelay".into())],
        enabled_protocols: vec![ProtocolId("turnrelay".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

fn secrets() -> HashMap<String, String> {
    let mut secrets = HashMap::new();
    secrets.insert(
        "turnrelay.turn_server".into(),
        "turn.example.org:3478".into(),
    );
    secrets.insert("turnrelay.turn_username".into(), "user".into());
    secrets.insert("turnrelay.turn_password".into(), "pass".into());
    secrets.insert("turnrelay.password".into(), "exit-secret".into());
    secrets
}

fn rendered(secrets: &HashMap<String, String>) -> String {
    let server = server();
    let ctx = RenderCtx::new(&server, secrets);
    let protocol = TurnRelay;
    String::from_utf8(
        TurnRelayKernel
            .render_config(&ctx, &[], &[&protocol as &dyn Protocol])
            .unwrap(),
    )
    .unwrap()
}

#[test]
fn kernel_identity_and_units_are_stable() {
    let kernel = TurnRelayKernel;
    assert_eq!(kernel.id(), KernelId("turnrelay".into()));
    assert_eq!(
        kernel.supported_protocols(),
        vec![ProtocolId("turnrelay".into())]
    );
    assert_eq!(kernel.service_units(), &["vpnctl-turnrelay.service"]);
}

#[test]
fn artifact_names_cover_supported_architectures() {
    for (arch, expected) in [
        ("x86_64", "turnrelay-server-amd64"),
        ("aarch64", "turnrelay-server-arm64"),
        ("armv7l", "turnrelay-server-armv7"),
    ] {
        assert_eq!(
            artifact_path(arch, "turnrelay-server").unwrap(),
            std::path::PathBuf::from(format!("/opt/vpnctl/node-artifacts/{expected}"))
        );
    }
    assert!(artifact_path("riscv64", "turnrelay-server").is_err());
}

#[test]
fn render_config_uses_defaults_and_embeds_the_unit() {
    let secrets = secrets();
    let server = server();
    let ctx = RenderCtx::new(&server, &secrets);
    let applied = turnrelay_applied_digest(&ctx).unwrap();
    let script = rendered(&secrets);
    assert!(script.contains("turnrelay_listen='0.0.0.0:53492'"));
    assert!(script.contains("turnrelay_port='53492'"));
    assert!(script.contains("turnrelay_mode='dtls'"));
    assert!(script.contains("turnrelay_password='exit-secret'"));
    assert!(script.contains(&format!("turnrelay_applied='{applied}'")));
    assert!(script.contains("vpnctl-turnrelay.service"));
    assert!(script.contains("TURNRELAY_PASSWORD=%s"));
    assert!(script.contains("/var/lib/vpnctl-turnrelay/cert.pem"));
}

#[test]
fn render_config_honors_port_mode_connections_and_udp_overrides() {
    let mut secrets = secrets();
    secrets.insert("turnrelay.listen_port".into(), "6000".into());
    secrets.insert("turnrelay.mode".into(), "srtp".into());
    secrets.insert("turnrelay.connections".into(), "12".into());
    secrets.insert("turnrelay.udp".into(), "false".into());
    let script = rendered(&secrets);
    assert!(script.contains("turnrelay_listen='0.0.0.0:6000'"));
    assert!(script.contains("turnrelay_mode='srtp'"));
    let server = server();
    let ctx = RenderCtx::new(&server, &secrets);
    let inbound = TurnRelay.server_inbound(&ctx, &[]).unwrap();
    assert_eq!(inbound["connections"], 12);
    assert_eq!(inbound["udp"], false);
}

#[test]
fn render_config_rejects_wrong_protocol_and_arity() {
    let server = server();
    let secrets = secrets();
    let ctx = RenderCtx::new(&server, &secrets);
    assert!(
        TurnRelayKernel
            .render_config(&ctx, &[], &[&Dnstt as &dyn Protocol])
            .is_err()
    );
    assert!(TurnRelayKernel.render_config(&ctx, &[], &[]).is_err());
    assert!(
        TurnRelayKernel
            .render_config(
                &ctx,
                &[],
                &[&TurnRelay as &dyn Protocol, &TurnRelay as &dyn Protocol]
            )
            .is_err()
    );
}

#[test]
fn validate_server_support_requires_a_literal_routable_ip() {
    let kernel = TurnRelayKernel;
    assert!(kernel.validate_server_support(&server()).is_ok());
    for address in ["de.example.com", "0.0.0.0", "ff02::1"] {
        let mut server = server();
        server.address = address.into();
        assert!(
            kernel.validate_server_support(&server).is_err(),
            "{address}"
        );
    }
}

#[tokio::test]
async fn deployed_secrets_report_pinned_certificate_and_applied_digest() {
    let server = server();
    let secrets = secrets();
    let ctx = RenderCtx::new(&server, &secrets);
    let ssh = vpnctl_ssh::MockTransport::new();
    ssh.expect(PROBE, "active\n");
    ssh.expect(
        "set -eu; test -s /var/lib/vpnctl-turnrelay/cert.pem; openssl x509 -in /var/lib/vpnctl-turnrelay/cert.pem -outform DER | sha256sum | cut -d' ' -f1",
        &format!("{}\n", "ab".repeat(32)),
    );
    let observed = TurnRelayKernel
        .deployed_server_secrets(&ssh, &ctx)
        .await
        .unwrap();
    assert_eq!(observed[0].0, "observed.turnrelay.cert_sha256");
    assert_eq!(observed[0].1, "ab".repeat(32));
    assert_eq!(observed[1].0, "observed.turnrelay.applied");
    assert_eq!(observed[1].1, turnrelay_applied_digest(&ctx).unwrap());
}

#[tokio::test]
async fn deployed_secrets_fail_when_inactive_or_fingerprint_is_invalid() {
    let server = server();
    let secrets = secrets();
    let ctx = RenderCtx::new(&server, &secrets);
    let inactive = vpnctl_ssh::MockTransport::new();
    inactive.expect(PROBE, "inactive\n");
    assert!(
        TurnRelayKernel
            .deployed_server_secrets(&inactive, &ctx)
            .await
            .is_err()
    );

    let invalid = vpnctl_ssh::MockTransport::new();
    invalid.expect(PROBE, "active\n");
    invalid.expect(
        "set -eu; test -s /var/lib/vpnctl-turnrelay/cert.pem; openssl x509 -in /var/lib/vpnctl-turnrelay/cert.pem -outform DER | sha256sum | cut -d' ' -f1",
        "not-a-fingerprint\n",
    );
    assert!(
        TurnRelayKernel
            .deployed_server_secrets(&invalid, &ctx)
            .await
            .is_err()
    );
}

#[test]
fn no_user_material_is_required_for_server_rendering() {
    let server = server();
    let secrets = secrets();
    let users = [User {
        id: UserId("alice".into()),
        uuid: "11111111-1111-4111-8111-111111111111".into(),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    }];
    assert!(
        TurnRelayKernel
            .render_config(
                &RenderCtx::new(&server, &secrets),
                &users,
                &[&TurnRelay as &dyn Protocol]
            )
            .is_ok()
    );
}

#[test]
fn exit_uses_strong_tier_and_scopes_ufw_to_ipv4_turn_provider() {
    assert_eq!(TurnRelay.dpi_risk(), vpnctl_core::DpiRisk::Strong);
    let mut secrets = secrets();
    secrets.insert("turnrelay.turn_server".into(), "192.0.2.12:53491".into());
    let script = rendered(&secrets);
    assert!(script.contains("turnrelay_relay_ip='192.0.2.12'"));
    assert!(script.contains("ufw allow proto udp from"));
    assert!(!script.contains("command -v nft"));
    assert!(script.contains("command -v openssl"));
}

#[tokio::test]
async fn managed_entry_renders_both_listeners_and_stops_when_disabled() {
    use crate::{TurnRelayRelayKernel, build_registry, reconcile_disabled_kernels};
    use vpnctl_protocols::TurnRelayRelay;
    let mut server = server();
    server.kernels = vec![KernelId("turnrelay-relay".into())];
    let mut secrets = HashMap::from([
        ("turnrelay_relay.username".into(), "fixture-user".into()),
        ("turnrelay_relay.password".into(), "fixture-pass".into()),
    ]);
    let protocol = TurnRelayRelay;
    let kernel = TurnRelayRelayKernel;
    assert_eq!(protocol.listen_ports(), &[("tcp", 53491), ("udp", 53491)]);
    assert!(!protocol.appears_in_sing_box_sub());
    assert!(!protocol.appears_in_stock_sing_box_sub());
    let ctx = RenderCtx::new(&server, &secrets);
    let script = String::from_utf8(kernel.render_config(&ctx, &[], &[&protocol]).unwrap()).unwrap();
    assert!(script.contains("RELAY_PORT=53491\n"));
    assert!(script.contains("EXIT_IPS=\n"));
    assert!(script.contains("install -m 0600"));
    assert!(script.contains("ss -H -lntp"));
    assert!(script.contains("ss -H -lnup"));
    assert!(script.contains("elif command -v iptables"));
    assert!(!script.contains("command -v nft"));
    secrets.insert("turnrelay_relay.listen_port".into(), "61000".into());
    assert_eq!(
        protocol.effective_listen_ports(&secrets),
        vec![("tcp", 61000), ("udp", 61000)]
    );

    let ssh = vpnctl_ssh::MockTransport::new();
    ssh.expect("set -eu\nstate=$(systemctl show --property=LoadState --value -- 'vpnctl-turnrelay-relay.service') || [ \"$state\" = not-found ]\nif [ \"$state\" != not-found ]; then systemctl disable --now -- 'vpnctl-turnrelay-relay.service'; fi\n", "");
    server.enabled_protocols.clear();
    reconcile_disabled_kernels(&build_registry().unwrap(), &server, &[], &ssh)
        .await
        .unwrap();
}

#[test]
fn managed_entry_applies_and_rolls_back_without_firewall_tools() {
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::process::Command;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let path = root.join("bin");
    fs::create_dir(&path).unwrap();
    for name in [
        "flock", "mktemp", "mkdir", "rm", "cp", "install", "mv", "grep", "sleep",
    ] {
        let binary = std::env::split_paths(&std::env::var_os("PATH").unwrap())
            .map(|dir| dir.join(name))
            .find(|file| file.is_file())
            .unwrap();
        symlink(binary, path.join(name)).unwrap();
    }
    for (name, body) in [
        ("systemctl", "case \"$1\" in show) echo 123;; esac"),
        (
            "systemd-analyze",
            "test \"${SIMULATE_VERIFY_FAILURE:-0}\" = 0",
        ),
        ("ss", "echo 'users:((\"turnrelay-relay\",pid=123,fd=3))'"),
    ] {
        let script = path.join(name);
        fs::write(&script, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(script, fs::Permissions::from_mode(0o755)).unwrap();
    }

    for dir in [
        "etc/vpnctl-turnrelay",
        "etc/systemd/system",
        "usr/local/libexec/vpnctl-turnrelay",
    ] {
        fs::create_dir_all(root.join(dir)).unwrap();
    }
    let binary = root.join("usr/local/libexec/vpnctl-turnrelay/turnrelay-relay");
    let candidate = binary.with_extension("candidate");
    let env = root.join("etc/vpnctl-turnrelay/relay.env");
    let apply = include_str!("../turnrelay_relay/apply.sh")
        .replace("/etc/", &format!("{}/etc/", root.display()))
        .replace("/usr/local/", &format!("{}/usr/local/", root.display()));
    let run = |port: u16, verify_failure: bool| {
        let command = format!(
            "relay_port={port}\nrelay_env='RELAY_PORT={port}\n'\nrelay_unit='fixture'\n{apply}"
        );
        Command::new("/bin/sh")
            .args(["-c", &command])
            .env("PATH", &path)
            .env(
                "SIMULATE_VERIFY_FAILURE",
                if verify_failure { "1" } else { "0" },
            )
            .output()
            .unwrap()
    };

    fs::write(&candidate, "first binary").unwrap();
    let result = run(53491, false);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        fs::metadata(&env).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(fs::read_to_string(&env).unwrap(), "RELAY_PORT=53491\n");

    fs::write(&candidate, "second binary").unwrap();
    assert!(!run(54491, true).status.success());
    assert_eq!(fs::read_to_string(&env).unwrap(), "RELAY_PORT=53491\n");
    assert_eq!(fs::read_to_string(&binary).unwrap(), "first binary");
}
