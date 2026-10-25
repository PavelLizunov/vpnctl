#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use vpnctl_core::{
        CoreError, KernelId, Registry, RenderCtx, Result, Server, ServerId, SshTransport,
    };
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

    #[tokio::test]
    async fn apply_snapshot_failure_preserves_live_config_and_previous_backup() {
        use std::os::unix::fs::PermissionsExt;

        let registry = registry();
        for (id, config_path, staging_path) in [
            (
                "amneziawg",
                "/etc/amnezia/amneziawg/awg0.conf",
                "/etc/amnezia/amneziawg/awg0.conf.new",
            ),
            (
                "sing-box",
                "/etc/sing-box/config.json",
                "/etc/sing-box/config.json.new",
            ),
            (
                "xray",
                "/usr/local/etc/xray/config.json",
                "/usr/local/etc/xray/config.staging.json",
            ),
        ] {
            let ssh = vpnctl_ssh::MockTransport::new();
            registry
                .kernel(&KernelId(id.into()))
                .unwrap()
                .apply_config(&ssh, b"{}")
                .await
                .unwrap();
            let script = ssh.executed_commands().unwrap().pop().unwrap();
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path();
            let live = root.join(config_path.trim_start_matches('/'));
            let staging = root.join(staging_path.trim_start_matches('/'));
            let backup = live.with_file_name(format!(
                "{}.bak",
                live.file_name().unwrap().to_str().unwrap()
            ));
            std::fs::create_dir_all(live.parent().unwrap()).unwrap();
            std::fs::create_dir_all(root.join("etc/sysctl.d")).unwrap();
            std::fs::write(&live, "OLD\n").unwrap();
            std::fs::write(&staging, "NEW\n").unwrap();
            std::fs::write(&backup, "PREVIOUS BACKUP\n").unwrap();
            let bin = root.join("bin");
            std::fs::create_dir_all(&bin).unwrap();
            for (name, body) in [
                (
                    "cp",
                    "if [ \"$1\" = -a ]; then echo partial > \"$3\"; exit 1; fi\n/bin/cp \"$@\"",
                ),
                ("systemctl", "echo called >> \"$VPNCTL_CALLS\"; exit 1"),
                ("awg-quick", "exit 0"),
                ("ip", "exit 0"),
                ("sysctl", "exit 0"),
                ("chown", "exit 0"),
                ("journalctl", "exit 0"),
                ("sleep", "exit 0"),
                ("sing-box", "exit 0"),
                ("xray", "exit 0"),
            ] {
                let path = bin.join(name);
                std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            let script = script
                .replace("/usr/bin/sing-box", &bin.join("sing-box").to_string_lossy())
                .replace(
                    std::path::Path::new(config_path)
                        .parent()
                        .unwrap()
                        .to_str()
                        .unwrap(),
                    &live.parent().unwrap().to_string_lossy(),
                )
                .replace(
                    "/etc/sysctl.d",
                    &root.join("etc/sysctl.d").to_string_lossy(),
                );
            let calls = root.join("calls");
            let output = std::process::Command::new("sh")
                .args(["-c", &script])
                .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
                .env("VPNCTL_CALLS", &calls)
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(1), "{id}: {output:?}");
            assert_eq!(std::fs::read_to_string(&live).unwrap(), "OLD\n", "{id}");
            assert!(
                !staging.exists(),
                "{id}: the EXIT trap removes the staged file"
            );
            assert_eq!(
                std::fs::read_to_string(&backup).unwrap(),
                "PREVIOUS BACKUP\n",
                "{id}"
            );
            assert_eq!(
                std::fs::read_to_string(live.with_file_name(format!(
                    "{}.bak.new",
                    live.file_name().unwrap().to_str().unwrap()
                )))
                .unwrap(),
                "partial\n",
                "{id}: the stub must have reached the snapshot copy",
            );
            assert!(
                !calls.exists(),
                "{id}: snapshot failure must abort before service changes"
            );
        }
    }

    #[tokio::test]
    async fn all_kernels_propagate_firewall_errors_and_skip_absent_or_inactive_ufw() {
        let registry = registry();
        let server = server(vec![]);
        let secrets = std::collections::HashMap::new();
        let ctx = RenderCtx::new(&server, &secrets);
        let protocol = vpnctl_protocols::VlessReality::new();
        for id in registry.kernel_ids() {
            let kernel = registry.kernel(&id).unwrap();
            let failing = RecordingTransport {
                fail: true,
                ..Default::default()
            };
            assert!(
                kernel
                    .open_firewall(&failing, &ctx, &[&protocol])
                    .await
                    .is_err(),
                "{id}"
            );
            let ssh = RecordingTransport::default();
            kernel
                .open_firewall(&ssh, &ctx, &[&protocol])
                .await
                .unwrap();
            let script = ssh.scripts.lock().unwrap().pop().unwrap();
            for (present, active, fail_allow) in [
                (false, false, true),
                (true, false, true),
                (true, true, false),
                (true, true, true),
            ] {
                let dir = tempfile::tempdir().unwrap();
                let calls = dir.path().join("calls");
                let mocks = r#"
                    command() { return "$VPNCTL_UFW_ABSENT"; }
                    ufw() {
                        case "$1" in
                            status) echo "Status: $VPNCTL_UFW_STATE" ;;
                            allow) echo "$*" >> "$VPNCTL_CALLS"; return "$VPNCTL_FAIL_ALLOW" ;;
                            *) return 99 ;;
                        esac
                    }
                "#;
                let output = std::process::Command::new("sh")
                    .args(["-c", &format!("{mocks}\n{script}")])
                    .env("VPNCTL_UFW_ABSENT", if present { "0" } else { "1" })
                    .env(
                        "VPNCTL_UFW_STATE",
                        if active { "active" } else { "inactive" },
                    )
                    .env("VPNCTL_FAIL_ALLOW", if fail_allow { "1" } else { "0" })
                    .env("VPNCTL_CALLS", &calls)
                    .output()
                    .unwrap();
                assert_eq!(
                    output.status.success(),
                    !(present && active && fail_allow),
                    "{id}: {output:?}"
                );
                assert_eq!(calls.exists(), present && active, "{id}");
            }
        }
    }
}
