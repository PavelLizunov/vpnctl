#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::fs::PermissionsExt;
use vpnctl_core::{CoreError, Kernel, Result, SshTransport};

#[derive(Debug)]
struct LocalUpload {
    fail_upload: bool,
}

#[async_trait::async_trait]
impl SshTransport for LocalUpload {
    async fn exec(&self, cmd: &str) -> Result<String> {
        // Exercise real file modes without requiring root ownership in tests.
        let cmd = cmd
            .replace("-o root -g root ", "")
            .replace("chown root ", "true ");
        let output = std::process::Command::new("bash")
            .args(["-c", &cmd])
            .output()?;
        if !output.status.success() {
            return Err(CoreError::Transport("fixture apply failure".into()));
        }
        Ok(String::new())
    }

    async fn exec_unprivileged(&self, cmd: &str) -> Result<String> {
        self.exec(cmd).await
    }

    async fn upload(&self, path: &str, content: &[u8]) -> Result<()> {
        let parent = std::path::Path::new(path).parent().unwrap();
        assert_eq!(std::fs::metadata(parent)?.permissions().mode() & 0o022, 0);
        assert!(!std::fs::symlink_metadata(path)?.file_type().is_symlink());
        assert_eq!(std::fs::metadata(path)?.permissions().mode() & 0o777, 0o600);
        std::fs::write(path, content)?;
        assert_eq!(std::fs::metadata(path)?.permissions().mode() & 0o777, 0o600);
        if self.fail_upload {
            return Err(CoreError::Transport("fixture upload failure".into()));
        }
        Ok(())
    }

    async fn read_file(&self, _: &str) -> Result<Vec<u8>> {
        Err(CoreError::Transport("fixture has no live config".into()))
    }
}

#[tokio::test]
async fn staging_is_private_during_upload_and_removed_on_upload_or_apply_failure() {
    for (fail_upload, script) in [(false, "true"), (true, "true"), (false, "false")] {
        let dir = tempfile::tempdir().unwrap();
        let staged = dir.path().join("config.new");
        // A stale world-readable staging file must also be replaced securely.
        std::fs::write(&staged, "stale").unwrap();
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o644)).unwrap();
        let ssh = LocalUpload { fail_upload };
        let result =
            super::apply_staged_config(&ssh, staged.to_str().unwrap(), b"fixture-secret", script)
                .await;
        if fail_upload || script == "false" {
            assert!(result.is_err());
            assert!(!staged.exists());
        } else {
            result.unwrap();
            assert_eq!(std::fs::read(&staged).unwrap(), b"fixture-secret");
        }
    }
}

#[tokio::test]
async fn every_kernel_precreates_private_staging_before_apply() {
    let cases: Vec<(Box<dyn Kernel>, &str)> = vec![
        (
            Box::new(crate::SingBox::new()),
            "/etc/sing-box/config.json.new",
        ),
        (
            Box::new(crate::Xray::new()),
            "/usr/local/etc/xray/config.staging.json",
        ),
        (
            Box::new(crate::AmneziaWg::new()),
            "/etc/amnezia/amneziawg/awg0.conf.new",
        ),
        (Box::new(crate::Caddy::new()), "/etc/caddy/Caddyfile.new"),
    ];
    for (kernel, path) in cases {
        let ssh = vpnctl_ssh::MockTransport::new();
        kernel.apply_config(&ssh, b"fixture-secret").await.unwrap();
        let commands = ssh.executed_commands().unwrap();
        let parent = std::path::Path::new(path)
            .parent()
            .unwrap()
            .to_str()
            .unwrap();
        assert!(commands[0].contains(&format!(
            "test ! -L '{parent}'\nchown root '{parent}'\nchmod go-w '{parent}'"
        )));
        assert!(commands[0].ends_with(&format!(
            "rm -f -- '{path}'\ninstall -o root -g root -m 0600 /dev/null '{path}'"
        )));
        assert_eq!(ssh.uploaded(path), Some(b"fixture-secret".to_vec()));
    }
}

#[tokio::test]
async fn staging_replaces_untrusted_links_only_after_protecting_directory() {
    for hard_link in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join("config");
        std::fs::create_dir(&config_dir).unwrap();
        std::fs::set_permissions(&config_dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, "PRESERVE").unwrap();
        let staged = config_dir.join("config.new");
        if hard_link {
            std::fs::hard_link(&victim, &staged).unwrap();
        } else {
            std::os::unix::fs::symlink(&victim, &staged).unwrap();
        }
        let ssh = LocalUpload { fail_upload: false };
        super::apply_staged_config(&ssh, staged.to_str().unwrap(), b"NEW", "true")
            .await
            .unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"PRESERVE");
        assert_eq!(std::fs::read(&staged).unwrap(), b"NEW");
        assert_eq!(
            std::fs::metadata(&config_dir).unwrap().permissions().mode() & 0o022,
            0
        );
    }
}

#[tokio::test]
async fn staging_rejects_symlinked_directory_before_touching_target() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    std::fs::create_dir(&target).unwrap();
    let config_dir = dir.path().join("config");
    std::os::unix::fs::symlink(&target, &config_dir).unwrap();
    let victim = target.join("config.new");
    std::fs::write(&victim, "PRESERVE").unwrap();
    let ssh = LocalUpload { fail_upload: false };
    assert!(
        super::apply_staged_config(
            &ssh,
            config_dir.join("config.new").to_str().unwrap(),
            b"NEW",
            "true",
        )
        .await
        .is_err()
    );
    assert_eq!(std::fs::read(victim).unwrap(), b"PRESERVE");
}

pub(super) fn assert_validation_failure_removes_staging(
    script: &str,
    staging_path: &str,
    live_path: &str,
    validator: &str,
) {
    let dir = tempfile::tempdir().unwrap();
    let staged = dir.path().join("config.new");
    let live = dir.path().join("config");
    std::fs::write(&staged, "fixture-secret").unwrap();
    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&live, "OLD").unwrap();
    let script = script
        .replace(staging_path, staged.to_str().unwrap())
        .replace(live_path, live.to_str().unwrap())
        .replace(validator, "false");
    let output = std::process::Command::new("bash")
        .args(["-c", &script])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!staged.exists());
    assert_eq!(std::fs::read_to_string(live).unwrap(), "OLD");
}
