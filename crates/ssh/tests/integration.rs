//! Integration tests for `RusshTransport`. Запускаются **только** через
//! `cargo test -- --ignored`, потому что ходят в реальный SSH-сервер.
//!
//! По умолчанию используется хост `192.168.0.207` (Forgejo host в нашем LAN)
//! и SSH-ключ `~/.ssh/id_ed25519` (`claude-chat`). Перекрыть можно через env:
//!   VPNCTL_TEST_HOST=192.168.0.207
//!   VPNCTL_TEST_USER=user
//!   VPNCTL_TEST_KEY=/home/appuser/.ssh/id_ed25519

use std::env;
use std::path::PathBuf;
use std::time::Duration;
use vpnctl_core::SshTransport;
use vpnctl_ssh::RusshTransportBuilder;

fn cfg() -> (String, String, PathBuf) {
    let host = env::var("VPNCTL_TEST_HOST").unwrap_or_else(|_| "192.168.0.207".into());
    let user = env::var("VPNCTL_TEST_USER").unwrap_or_else(|_| "user".into());
    let key = env::var("VPNCTL_TEST_KEY")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = env::var("HOME").unwrap_or_else(|_| "/home/appuser".into());
            PathBuf::from(home).join(".ssh/id_ed25519")
        });
    (host, user, key)
}

#[tokio::test]
#[ignore = "requires live SSH server; run with --ignored"]
async fn connect_and_exec_uname() {
    let (host, user, key) = cfg();
    let t = RusshTransportBuilder::new(host, user, key)
        .port(22)
        .timeout(Duration::from_secs(15))
        .connect()
        .await
        .expect_err_or_pass("connect");
    let out = t.exec("uname -s").await.expect_err_or_pass("uname");
    assert!(out.trim() == "Linux", "expected Linux, got {out:?}");
}

#[tokio::test]
#[ignore = "requires live SSH server; run with --ignored"]
async fn upload_then_read() {
    let (host, user, key) = cfg();
    let t = RusshTransportBuilder::new(host, user, key)
        .port(22)
        .connect()
        .await
        .expect_err_or_pass("connect");

    let path = "/tmp/vpnctl-test-roundtrip.txt";
    let payload = b"hello-from-rust\n";

    t.upload(path, payload).await.expect_err_or_pass("upload");
    let got = t.read_file(path).await.expect_err_or_pass("read");
    assert_eq!(got, payload);

    // cleanup
    let _ = t.exec(&format!("rm -f {path}")).await;
}

#[tokio::test]
#[ignore = "requires live SSH server; run with --ignored"]
async fn exec_nonzero_exit_is_error() {
    let (host, user, key) = cfg();
    let t = RusshTransportBuilder::new(host, user, key)
        .port(22)
        .connect()
        .await
        .expect_err_or_pass("connect");
    let err = t.exec("ls /nonexistent-vpnctl-path").await;
    assert!(err.is_err(), "expected error, got {err:?}");
}

#[tokio::test]
#[ignore = "requires live SSH server; run with --ignored"]
async fn host_fingerprint_observed() {
    let (host, user, key) = cfg();
    let t = RusshTransportBuilder::new(host, user, key)
        .port(22)
        .connect()
        .await
        .expect_err_or_pass("connect");
    let fp = t.observed_host_fingerprint().await;
    assert!(fp.as_deref().is_some_and(|s| s.starts_with("SHA256:")),
            "expected SHA256:... fingerprint, got {fp:?}");
}

// Helper: integration tests legitimately panic on setup failure.
// We can't `.unwrap()` because workspace lints forbid it; this helper
// converts unexpected errors to descriptive panics.
trait ResultExt<T> {
    fn expect_err_or_pass(self, what: &str) -> T;
}
impl<T, E: std::fmt::Debug> ResultExt<T> for std::result::Result<T, E> {
    #[allow(clippy::panic)]
    fn expect_err_or_pass(self, what: &str) -> T {
        match self {
            Ok(v) => v,
            Err(e) => panic!("integration test '{what}' failed: {e:?}"),
        }
    }
}
