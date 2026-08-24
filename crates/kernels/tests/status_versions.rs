#![allow(clippy::expect_used)]

use vpnctl_core::{Kernel, KernelVersionPolicy};
use vpnctl_kernels::{AmneziaWg, Caddy, DnsTunnel, SingBox, Xray};
use vpnctl_ssh::MockTransport;

type StatusCase<'a> = (Box<dyn Kernel>, Vec<&'a str>, &'a str, &'a str);
type ActiveCase<'a> = (Box<dyn Kernel>, Vec<&'a str>);

#[tokio::test]
async fn every_current_kernel_reports_an_active_installed_version() {
    let cases: Vec<StatusCase<'_>> = vec![
        (
            Box::new(SingBox::new()),
            vec!["systemctl is-active sing-box 2>/dev/null || true"],
            "sing-box version 2>/dev/null | awk '/version/{print $3; exit}'",
            "1.13.18",
        ),
        (
            Box::new(AmneziaWg::new()),
            vec!["systemctl is-active awg-quick@awg0 2>/dev/null || true"],
            "dpkg-query -W -f='${Version}' amneziawg-tools 2>/dev/null",
            "1.0.20210913-1",
        ),
        (
            Box::new(Caddy::new()),
            vec!["systemctl is-active caddy 2>/dev/null || true"],
            "/usr/local/bin/caddy version 2>/dev/null | awk '{print $1; exit}'",
            "v2.11.4",
        ),
        (
            Box::new(DnsTunnel::new()),
            vec![
                "systemctl is-active dns-tunnel 2>/dev/null || true",
                "systemctl is-active dns-tunnel-singbox 2>/dev/null || true",
            ],
            "slipstream-server --version 2>/dev/null | awk '{print $NF; exit}'",
            "v0.1.0",
        ),
        (
            Box::new(Xray::new()),
            vec!["systemctl is-active xray 2>/dev/null || true"],
            "xray version 2>/dev/null | awk 'NR==1 {print $2}'",
            "26.3.27",
        ),
    ];

    for (kernel, active_commands, version_command, expected_version) in cases {
        let ssh = MockTransport::new();
        for command in active_commands {
            ssh.expect(command, "active\n");
        }
        ssh.expect(version_command, &format!(" {expected_version} \n"));

        let status = kernel.status(&ssh).await.expect("kernel status");
        assert!(status.active, "{} should be active", kernel.id());
        assert_eq!(status.version.as_deref(), Some(expected_version));
    }
}

#[tokio::test]
async fn every_current_kernel_reports_inactive_without_turning_it_into_transport_error() {
    let cases: Vec<ActiveCase<'_>> = vec![
        (
            Box::new(SingBox::new()),
            vec!["systemctl is-active sing-box 2>/dev/null || true"],
        ),
        (
            Box::new(AmneziaWg::new()),
            vec!["systemctl is-active awg-quick@awg0 2>/dev/null || true"],
        ),
        (
            Box::new(Caddy::new()),
            vec!["systemctl is-active caddy 2>/dev/null || true"],
        ),
        (
            Box::new(DnsTunnel::new()),
            vec![
                "systemctl is-active dns-tunnel 2>/dev/null || true",
                "systemctl is-active dns-tunnel-singbox 2>/dev/null || true",
            ],
        ),
        (
            Box::new(Xray::new()),
            vec!["systemctl is-active xray 2>/dev/null || true"],
        ),
    ];

    for (kernel, active_commands) in cases {
        let ssh = MockTransport::new();
        for command in active_commands {
            ssh.expect(command, "inactive\n");
        }
        let status = kernel.status(&ssh).await.expect("inactive is a status");
        assert!(!status.active, "{} must report inactive", kernel.id());
    }
}

#[test]
fn every_current_kernel_exposes_its_managed_floor_or_pin() {
    let cases: Vec<(Box<dyn Kernel>, KernelVersionPolicy, &str)> = vec![
        (
            Box::new(SingBox::new()),
            KernelVersionPolicy::Floor,
            "1.13.18",
        ),
        (
            Box::new(AmneziaWg::new()),
            KernelVersionPolicy::Floor,
            "1.0.20210913",
        ),
        (Box::new(Caddy::new()), KernelVersionPolicy::Pin, "v2.11.4"),
        (
            Box::new(DnsTunnel::new()),
            KernelVersionPolicy::Pin,
            "v0.1.0",
        ),
        (Box::new(Xray::new()), KernelVersionPolicy::Pin, "v26.3.27"),
    ];

    for (kernel, expected_policy, expected_value) in cases {
        let requirement = kernel
            .version_requirement()
            .expect("all current kernels are managed");
        assert_eq!(requirement.policy, expected_policy, "{}", kernel.id());
        assert_eq!(requirement.value, expected_value, "{}", kernel.id());
    }
}
