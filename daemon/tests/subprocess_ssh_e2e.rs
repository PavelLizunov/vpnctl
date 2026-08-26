//! End-to-end integration tests for production `SubprocessSshTransport`
//! against a real OpenSSH server running in a Docker container.
//!
//! Exercises:
//! - Root login: `exec`, `upload`, `read_file`
//! - Non-root login with passwordless sudo (`sudo -n`): `exec`, `upload`, `read_file`, `exec_unprivileged`
//! - Strict host key verification (`StrictHostKeyChecking=accept-new` + `known_hosts` pinning & mismatch detection)
//!
//! Gated by `#[ignore]` because it requires Docker. Run with:
//!
//! ```sh
//! cargo test -p vpnctld --test subprocess_ssh_e2e -- --ignored --nocapture
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use tempfile::TempDir;
use testcontainers::core::{ContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerRequest, GenericImage, ImageExt};
use vpnctl_core::SshTransport;
use vpnctld::ssh_subprocess::SubprocessSshTransport;

const TEST_USER: &str = "vpnctltest";
const SSHD_INTERNAL_PORT: u16 = 2222;

/// Generate a fresh Ed25519 keypair via `ssh-keygen`. Returns (priv_path, pub_str).
fn fresh_keypair(dir: &TempDir, name: &str) -> (PathBuf, String) {
    let priv_path = dir.path().join(name);
    let status = Command::new("ssh-keygen")
        .arg("-t")
        .arg("ed25519")
        .arg("-N")
        .arg("") // no passphrase
        .arg("-q")
        .arg("-f")
        .arg(&priv_path)
        .arg("-C")
        .arg("vpnctl-subprocess-e2e-test")
        .status()
        .expect("ssh-keygen invocation");
    assert!(status.success(), "ssh-keygen failed: {status:?}");
    let pub_str = std::fs::read_to_string(priv_path.with_extension("pub"))
        .expect("read pubkey")
        .trim()
        .to_string();
    (priv_path, pub_str)
}

/// Helper to build a linuxserver openssh-server container with sudo support.
fn make_sshd_image(
    user_name: &str,
    pub_key: &str,
    sudo_access: bool,
) -> ContainerRequest<GenericImage> {
    let mut image: ContainerRequest<GenericImage> =
        GenericImage::new("lscr.io/linuxserver/openssh-server", "latest")
            .with_exposed_port(ContainerPort::Tcp(SSHD_INTERNAL_PORT))
            .with_wait_for(WaitFor::message_on_stdout("[ls.io-init] done."))
            .with_env_var("PUID", if user_name == "root" { "0" } else { "1000" })
            .with_env_var("PGID", if user_name == "root" { "0" } else { "1000" })
            .with_env_var("USER_NAME", user_name)
            .with_env_var("PASSWORD_ACCESS", "false");

    if !pub_key.is_empty() {
        image = image.with_env_var("PUBLIC_KEY", pub_key);
    }
    if sudo_access {
        image = image.with_env_var("SUDO_ACCESS", "true");
    } else {
        image = image.with_env_var("SUDO_ACCESS", "false");
    }

    image
}

#[tokio::test]
#[ignore = "requires Docker daemon; run with --ignored"]
async fn subprocess_ssh_root_roundtrip() {
    let tmp = TempDir::new().expect("tmpdir");
    let (priv_path, pub_str) = fresh_keypair(&tmp, "id_root");
    let known_hosts_path = tmp.path().join("known_hosts");

    // linuxserver/openssh-server running with root login or user configured as root
    let image = make_sshd_image("root", &pub_str, false);
    let container = image.start().await.expect("start sshd container");
    let host_port = container
        .get_host_port_ipv4(SSHD_INTERNAL_PORT)
        .await
        .expect("port mapping");

    let transport = SubprocessSshTransport::new("127.0.0.1", "root", priv_path)
        .port(host_port)
        .known_hosts(known_hosts_path)
        .timeout(Duration::from_secs(30));

    // ── 1. exec check ──────────────────────────────────────────────────
    let uname = transport.exec("uname -s").await.expect("uname");
    assert_eq!(uname.trim(), "Linux", "uname output: {uname:?}");

    let id_out = transport.exec("id -u").await.expect("id -u");
    assert_eq!(id_out.trim(), "0", "root id must be 0");

    let whoami_out = transport.exec("whoami").await.expect("whoami");
    assert_eq!(whoami_out.trim(), "root", "whoami must be root");

    // ── 2. stderr and non-zero exit propagation ────────────────────────
    let err = transport.exec("ls /non-existent-file-path-12345").await;
    assert!(err.is_err(), "expected non-zero exit error, got {err:?}");

    // ── 3. upload and read_file binary payload roundtrip ───────────────
    let remote_path = "/tmp/vpnctl-root-e2e-payload.bin";
    let payload: Vec<u8> = (0u8..=255).cycle().take(8192).collect();

    transport
        .upload(remote_path, &payload)
        .await
        .expect("upload payload");
    let read_back = transport
        .read_file(remote_path)
        .await
        .expect("read_file payload");
    assert_eq!(read_back.len(), payload.len(), "size mismatch");
    assert_eq!(read_back, payload, "content mismatch");

    // ── 4. cleanup ─────────────────────────────────────────────────────
    let _ = transport.exec(&format!("rm -f {remote_path}")).await;
}

#[tokio::test]
#[ignore = "requires Docker daemon; run with --ignored"]
async fn subprocess_ssh_non_root_passwordless_sudo_roundtrip() {
    let tmp = TempDir::new().expect("tmpdir");
    let (priv_path, pub_str) = fresh_keypair(&tmp, "id_user");
    let known_hosts_path = tmp.path().join("known_hosts");

    let image = make_sshd_image(TEST_USER, &pub_str, true);
    let container = image.start().await.expect("start sshd container");
    let host_port = container
        .get_host_port_ipv4(SSHD_INTERNAL_PORT)
        .await
        .expect("port mapping");

    let transport = SubprocessSshTransport::new("127.0.0.1", TEST_USER, priv_path)
        .port(host_port)
        .known_hosts(known_hosts_path)
        .timeout(Duration::from_secs(30));

    // ── 1. privileged exec (automatically wrapped with sudo -n) ────────
    let id_out = transport.exec("id -u").await.expect("sudo id -u");
    assert_eq!(id_out.trim(), "0", "privileged id -u must return root (0)");

    let whoami_out = transport.exec("whoami").await.expect("sudo whoami");
    assert_eq!(
        whoami_out.trim(),
        "root",
        "privileged whoami must return root"
    );

    // ── 2. unprivileged exec (runs directly as login user) ─────────────
    let unpriv_user = transport
        .exec_unprivileged("whoami")
        .await
        .expect("unprivileged whoami");
    assert_eq!(
        unpriv_user.trim(),
        TEST_USER,
        "exec_unprivileged must return {TEST_USER}"
    );

    // ── 3. privileged upload and read_file in root-owned location ──────
    // /etc is owned by root and writable only by root.
    let remote_path = "/etc/vpnctl-sudo-e2e-payload.bin";
    let payload: Vec<u8> = (0u8..=255).rev().cycle().take(4096).collect();

    transport
        .upload(remote_path, &payload)
        .await
        .expect("upload to /etc via sudo");

    let read_back = transport
        .read_file(remote_path)
        .await
        .expect("read_file from /etc via sudo");
    assert_eq!(read_back.len(), payload.len(), "size mismatch");
    assert_eq!(read_back, payload, "content mismatch");

    // ── 4. stderr and non-zero exit propagation under sudo ─────────────
    let err = transport.exec("cat /non-existent-path-sudo-test").await;
    assert!(err.is_err(), "expected error on non-zero exit under sudo");

    // ── 5. cleanup ─────────────────────────────────────────────────────
    let _ = transport.exec(&format!("rm -f {remote_path}")).await;
}

#[tokio::test]
#[ignore = "requires Docker daemon; run with --ignored"]
async fn subprocess_ssh_strict_host_key_verification() {
    let tmp = TempDir::new().expect("tmpdir");
    let (priv_path, pub_str) = fresh_keypair(&tmp, "id_shk");
    let known_hosts_path = tmp.path().join("known_hosts");

    let image = make_sshd_image(TEST_USER, &pub_str, true);
    let container = image.start().await.expect("start sshd container");
    let host_port = container
        .get_host_port_ipv4(SSHD_INTERNAL_PORT)
        .await
        .expect("port mapping");

    // Initial state: known_hosts does not exist
    assert!(
        !known_hosts_path.exists(),
        "known_hosts should not exist initially"
    );

    let transport = SubprocessSshTransport::new("127.0.0.1", TEST_USER, priv_path.clone())
        .port(host_port)
        .known_hosts(known_hosts_path.clone())
        .timeout(Duration::from_secs(30));

    // ── 1. First connect: TOFU (accept-new) records host key ──────────
    let uname = transport
        .exec("uname -s")
        .await
        .expect("first connect with accept-new must succeed");
    assert_eq!(uname.trim(), "Linux");
    assert!(
        known_hosts_path.exists(),
        "known_hosts must be populated after first connect"
    );

    let known_hosts_content = std::fs::read_to_string(&known_hosts_path).expect("read known_hosts");
    assert!(
        known_hosts_content.contains(&format!("[127.0.0.1]:{host_port}")),
        "known_hosts must pin the host and port"
    );

    // ── 2. Second connect: strictly verifies against pinned key ───────
    let uname2 = transport
        .exec("uname -s")
        .await
        .expect("subsequent connect with matching known_hosts must succeed");
    assert_eq!(uname2.trim(), "Linux");

    // ── 3. Host key mismatch: strict checking rejects changed key ─────
    // Corrupt the known_hosts with a mismatched host key for this host:port
    let bogus_entry = format!(
        "[127.0.0.1]:{host_port} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBogusKeyMismatchedFingerprint1234567890abcdef\n"
    );
    std::fs::write(&known_hosts_path, bogus_entry).expect("write bogus known_hosts");

    let mismatch_err = transport.exec("uname -s").await;
    assert!(
        mismatch_err.is_err(),
        "mismatched host key in known_hosts must fail connection"
    );
    let err_str = format!("{mismatch_err:?}");
    assert!(
        err_str.contains("exit=") || err_str.contains("Host key verification failed"),
        "error should indicate host verification failure: {err_str}"
    );
}
