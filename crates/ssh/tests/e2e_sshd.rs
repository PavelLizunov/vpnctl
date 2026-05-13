//! End-to-end test for `RusshTransport` against a real OpenSSH server in
//! a Docker container.
//!
//! Gated by `#[ignore]` because it needs Docker. Run locally with:
//!
//! ```
//! cargo test -p vpnctl-ssh --test e2e_sshd -- --ignored
//! ```
//!
//! In CI a dedicated job runs this on `ubuntu-latest` (Docker is preinstalled).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;
use std::time::Duration;

use tempfile::TempDir;
use testcontainers::core::{ContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt};

use vpnctl_core::SshTransport;
use vpnctl_ssh::RusshTransportBuilder;

const TEST_USER: &str = "vpnctltest";
const SSHD_INTERNAL_PORT: u16 = 2222;

/// Generate a fresh Ed25519 keypair via the system `ssh-keygen` (avoids
/// `rand_core` version incompatibility between rand 0.9 and the older
/// trait re-exported through `russh::keys`). Returns (priv-key path,
/// pub-key OpenSSH string).
fn fresh_keypair(dir: &TempDir) -> (std::path::PathBuf, String) {
    let priv_path = dir.path().join("id_ed25519");
    let status = Command::new("ssh-keygen")
        .arg("-t").arg("ed25519")
        .arg("-N").arg("")  // no passphrase
        .arg("-q")
        .arg("-f").arg(&priv_path)
        .arg("-C").arg("vpnctl-e2e-test")
        .status()
        .expect("ssh-keygen invocation");
    assert!(status.success(), "ssh-keygen failed: {status:?}");
    let pub_str = std::fs::read_to_string(priv_path.with_extension("pub"))
        .expect("read pubkey")
        .trim()
        .to_string();
    (priv_path, pub_str)
}

#[tokio::test]
#[ignore = "requires Docker daemon; run with --ignored"]
async fn ssh_transport_full_roundtrip_against_real_sshd() {
    let tmp = TempDir::new().expect("tmpdir");
    let (priv_path, pub_str) = fresh_keypair(&tmp);

    // linuxserver/openssh-server reads PUBLIC_KEY env and writes it to
    // ~/.ssh/authorized_keys for USER_NAME on container start.
    let image = GenericImage::new("lscr.io/linuxserver/openssh-server", "latest")
        .with_exposed_port(ContainerPort::Tcp(SSHD_INTERNAL_PORT))
        .with_wait_for(WaitFor::message_on_stdout("[ls.io-init] done."))
        .with_env_var("PUID", "1000")
        .with_env_var("PGID", "1000")
        .with_env_var("USER_NAME", TEST_USER)
        .with_env_var("PUBLIC_KEY", &pub_str)
        .with_env_var("PASSWORD_ACCESS", "false")
        .with_env_var("SUDO_ACCESS", "false");

    let container = image.start().await.expect("start sshd container");
    let host_port = container
        .get_host_port_ipv4(SSHD_INTERNAL_PORT)
        .await
        .expect("port mapping");

    // The container marks "init done" before sshd is fully accepting in some
    // racy cases. Build a transport with retries via the operation timeout.
    let transport = RusshTransportBuilder::new("127.0.0.1", TEST_USER, priv_path)
        .port(host_port)
        .timeout(Duration::from_secs(30))
        .connect()
        .await
        .expect("connect");

    // ── basic exec ─────────────────────────────────────────────────────
    let uname = transport.exec("uname -s").await.expect("uname");
    assert_eq!(uname.trim(), "Linux", "uname output: {uname:?}");

    // ── stdout vs stderr separation + non-zero exit ─────────────────────
    let err = transport.exec("ls /this-file-does-not-exist").await;
    assert!(err.is_err(), "expected non-zero exit, got {err:?}");

    // ── upload + read round-trip with binary-ish payload ────────────────
    let path = "/tmp/vpnctl-e2e-roundtrip.bin";
    let payload: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
    transport.upload(path, &payload).await.expect("upload");
    let got = transport.read_file(path).await.expect("read");
    assert_eq!(got.len(), payload.len(), "size mismatch");
    assert_eq!(got, payload, "byte-by-byte mismatch");

    // ── observed host fingerprint is SHA256:... ─────────────────────────
    let fp = transport.observed_host_fingerprint().await;
    assert!(
        fp.as_deref().is_some_and(|s| s.starts_with("SHA256:")),
        "expected SHA256:..., got {fp:?}"
    );

    // cleanup is best-effort; the container will be torn down anyway.
    let _ = transport.exec(&format!("rm -f {path}")).await;
}
