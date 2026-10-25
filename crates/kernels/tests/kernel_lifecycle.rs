#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use vpnctl_core::{CoreError, KernelId, Registry, Result, Server, ServerId, SshTransport};
    use vpnctl_kernels::{AmneziaWg, Caddy, SingBox, Xray, reconcile_disabled_kernels};

    #[derive(Debug, Default)]
    struct RecordingTransport {
        scripts: Mutex<Vec<String>>,
        fail: bool,
    }

    #[async_trait]
    impl SshTransport for RecordingTransport {
        async fn exec(&self, cmd: &str) -> Result<String> {
            self.scripts.lock().unwrap().push(cmd.to_string());
            if self.fail {
                return Err(CoreError::Transport("shutdown failed".into()));
            }
            Ok(String::new())
        }

        async fn exec_unprivileged(&self, cmd: &str) -> Result<String> {
            self.exec(cmd).await
        }

        async fn upload(&self, _: &str, _: &[u8]) -> Result<()> {
            panic!("reconciliation must not upload files")
        }

        async fn read_file(&self, _: &str) -> Result<Vec<u8>> {
            panic!("reconciliation must not read files")
        }
    }

    fn registry() -> Registry {
        let mut registry = Registry::new();
        registry.register_kernel(Box::new(SingBox::new())).unwrap();
        registry
            .register_kernel(Box::new(AmneziaWg::new()))
            .unwrap();
        registry.register_kernel(Box::new(Caddy::new())).unwrap();
        registry.register_kernel(Box::new(Xray::new())).unwrap();
        registry
    }

    fn server(kernels: Vec<KernelId>) -> Server {
        Server {
            id: ServerId("lifecycle".into()),
            address: "198.51.100.42".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels,
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        }
    }

    fn run_script(script: &str, state: &str, fail_disable: bool) -> (bool, String) {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let systemctl = dir.path().join("systemctl");
        std::fs::write(
            &systemctl,
            r#"#!/bin/sh
case "$1" in
    show)
        printf '%s\n' "$VPNCTL_UNIT_STATE"
        [ -n "$VPNCTL_UNIT_STATE" ] && [ "$VPNCTL_UNIT_STATE" != not-found ] ;;
    disable)
        printf '%s\n' "$*" >> "$VPNCTL_CALLS"
        [ "$VPNCTL_FAIL_DISABLE" != 1 ] ;;
    *) exit 99 ;;
esac
"#,
        )
        .unwrap();
        std::fs::set_permissions(&systemctl, std::fs::Permissions::from_mode(0o700)).unwrap();
        let calls = dir.path().join("calls");
        let output = std::process::Command::new("sh")
            .args(["-c", script])
            .env("PATH", format!("{}:/usr/bin:/bin", dir.path().display()))
            .env("VPNCTL_UNIT_STATE", state)
            .env("VPNCTL_FAIL_DISABLE", if fail_disable { "1" } else { "0" })
            .env("VPNCTL_CALLS", &calls)
            .output()
            .unwrap();
        (
            output.status.success(),
            std::fs::read_to_string(calls).unwrap_or_default(),
        )
    }

    #[tokio::test]
    async fn removed_kernels_stop_and_disable_all_owned_units() {
        let registry = registry();
        for (removed, units) in [
            ("sing-box", vec!["sing-box.service"]),
            ("amneziawg", vec!["awg-quick@awg0.service"]),
            ("caddy", vec!["caddy.service", "caddy-vlessws.service"]),
            ("xray", vec!["xray.service"]),
        ] {
            let server = server(
                registry
                    .kernel_ids()
                    .into_iter()
                    .filter(|kid| kid.0 != removed)
                    .collect(),
            );
            let ssh = RecordingTransport::default();
            reconcile_disabled_kernels(&registry, &server, &registry.kernel_ids(), &ssh)
                .await
                .unwrap();
            let scripts = ssh.scripts.lock().unwrap();
            assert_eq!(scripts.len(), 1);
            let (success, calls) = run_script(&scripts[0], "loaded", false);
            assert!(success);
            assert_eq!(
                calls,
                units
                    .iter()
                    .map(|unit| format!("disable --now -- {unit}\n"))
                    .collect::<String>()
            );
            let (success, calls) = run_script(&scripts[0], "not-found", false);
            assert!(success, "absent units must be a no-op");
            assert!(calls.is_empty());
            assert!(!run_script(&scripts[0], "loaded", true).0);
            assert!(
                !run_script(&scripts[0], "", false).0,
                "probe errors must fail"
            );
        }
    }

    #[tokio::test]
    async fn all_enabled_kernels_need_no_shutdown_call() {
        let registry = registry();
        let ssh = RecordingTransport::default();
        reconcile_disabled_kernels(
            &registry,
            &server(registry.kernel_ids()),
            &registry.kernel_ids(),
            &ssh,
        )
        .await
        .unwrap();
        assert!(ssh.scripts.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn never_retired_kernels_leave_node_services_alone() {
        let registry = registry();
        let ssh = RecordingTransport::default();
        reconcile_disabled_kernels(
            &registry,
            &server(vec![KernelId("sing-box".into())]),
            &[],
            &ssh,
        )
        .await
        .unwrap();
        assert!(
            ssh.scripts.lock().unwrap().is_empty(),
            "kernels vpnctl never managed here must not have their units stopped"
        );
    }

    #[tokio::test]
    async fn shutdown_transport_errors_fail_reconciliation() {
        let registry = registry();
        let ssh = RecordingTransport {
            fail: true,
            ..Default::default()
        };
        let result = reconcile_disabled_kernels(
            &registry,
            &server(vec![KernelId("sing-box".into())]),
            &[KernelId("xray".into())],
            &ssh,
        )
        .await;
        assert!(result.unwrap_err().to_string().contains("shutdown failed"));
    }
}
