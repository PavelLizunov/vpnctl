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
            artifact_path(arch).unwrap(),
            std::path::PathBuf::from(format!("/opt/vpnctl/node-artifacts/{expected}"))
        );
    }
    assert!(artifact_path("riscv64").is_err());
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
