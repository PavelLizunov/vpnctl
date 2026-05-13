//! Spec tests for the **password fallback** behaviour of
//! `RusshTransportBuilder::password()`.
//!
//! Independent: only the public API spec was given; the impl was not
//! read. Tests must NOT be weakened to make the impl pass.
//!
//! ```
//! cargo test -p vpnctl-ssh --test spec_password_auth -- --ignored
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::{Command, Stdio};
use std::time::Duration;

use tempfile::TempDir;
use testcontainers::core::{ContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerRequest, GenericImage, ImageExt};

use vpnctl_core::{CoreError, SshTransport};
use vpnctl_ssh::RusshTransportBuilder;

const TEST_USER: &str = "vpnctltest";
const TEST_PASSWORD: &str = "Sup3rSecretP@ssword-spec-987";
const WRONG_PASSWORD: &str = "definitely-not-the-right-pw-zzzz";
const SSHD_INTERNAL_PORT: u16 = 2222;

/// Generate a fresh Ed25519 keypair via `ssh-keygen`. Returns
/// (private key path, OpenSSH public key string). Mirrors `e2e_sshd.rs`.
fn fresh_keypair(dir: &TempDir, name: &str) -> (std::path::PathBuf, String) {
    let priv_path = dir.path().join(name);
    let status = Command::new("ssh-keygen")
        .arg("-t")
        .arg("ed25519")
        .arg("-N")
        .arg("")
        .arg("-q")
        .arg("-f")
        .arg(&priv_path)
        .arg("-C")
        .arg("vpnctl-spec-pw-test")
        .status()
        .expect("ssh-keygen invocation");
    assert!(status.success(), "ssh-keygen failed: {status:?}");
    let pub_str = std::fs::read_to_string(priv_path.with_extension("pub"))
        .expect("read pubkey")
        .trim()
        .to_string();
    (priv_path, pub_str)
}

/// Build a `linuxserver/openssh-server` image. `authorized_pub == ""`
/// installs no key; non-empty installs that pubkey for `TEST_USER`.
fn make_sshd_image(authorized_pub: &str, password_access: bool) -> ContainerRequest<GenericImage> {
    let mut img: ContainerRequest<GenericImage> =
        GenericImage::new("lscr.io/linuxserver/openssh-server", "latest")
            .with_exposed_port(ContainerPort::Tcp(SSHD_INTERNAL_PORT))
            .with_wait_for(WaitFor::message_on_stdout("[ls.io-init] done."))
            .with_env_var("PUID", "1000")
            .with_env_var("PGID", "1000")
            .with_env_var("USER_NAME", TEST_USER)
            .with_env_var("SUDO_ACCESS", "false");
    if !authorized_pub.is_empty() {
        img = img.with_env_var("PUBLIC_KEY", authorized_pub);
    }
    if password_access {
        img = img
            .with_env_var("PASSWORD_ACCESS", "true")
            .with_env_var("USER_PASSWORD", TEST_PASSWORD);
    } else {
        img = img.with_env_var("PASSWORD_ACCESS", "false");
    }
    img
}

// ─── Tests ──────────────────────────────────────────────────────────────

/// Rule 1: with ONLY a valid password and any (bad) key, `connect()`
/// succeeds — pubkey fails first on a fresh server, password wins.
#[tokio::test]
#[ignore = "requires Docker"]
async fn password_only_fresh_server_succeeds() {
    let tmp = TempDir::new().expect("tmpdir");
    let (bad_priv, _) = fresh_keypair(&tmp, "id_bad");

    let container = make_sshd_image("", true)
        .start()
        .await
        .expect("start sshd container");
    let host_port = container
        .get_host_port_ipv4(SSHD_INTERNAL_PORT)
        .await
        .expect("port mapping");

    let transport = RusshTransportBuilder::new("127.0.0.1", TEST_USER, bad_priv)
        .port(host_port)
        .password(TEST_PASSWORD)
        .timeout(Duration::from_secs(30))
        .connect()
        .await
        .expect("password fallback should succeed");

    let out = transport.exec("echo hi").await.expect("exec echo hi");
    assert_eq!(out.trim(), "hi");
}

/// Rule 2: valid pubkey installed AND wrong password → `connect()` succeeds
/// because the pubkey path short-circuits; the wrong password is never tried.
#[tokio::test]
#[ignore = "requires Docker"]
async fn pubkey_succeeds_short_circuits_wrong_password() {
    let tmp = TempDir::new().expect("tmpdir");
    let (good_priv, good_pub) = fresh_keypair(&tmp, "id_good");

    // Server password is set to the REAL password. If pubkey did NOT
    // short-circuit and the impl tried WRONG_PASSWORD, sshd would reject
    // it and connect() would error. Success ⇒ wrong password never sent.
    let container = make_sshd_image(&good_pub, true)
        .start()
        .await
        .expect("start sshd container");
    let host_port = container
        .get_host_port_ipv4(SSHD_INTERNAL_PORT)
        .await
        .expect("port mapping");

    let transport = RusshTransportBuilder::new("127.0.0.1", TEST_USER, good_priv)
        .port(host_port)
        .password(WRONG_PASSWORD)
        .timeout(Duration::from_secs(30))
        .connect()
        .await
        .expect("pubkey should win, wrong password never tried");

    let out = transport.exec("echo ok").await.expect("exec");
    assert_eq!(out.trim(), "ok");
}

/// Rule 3: wrong key + wrong password → `Err(CoreError::Transport(_))`,
/// and the error message must mention BOTH paths failed.
#[tokio::test]
#[ignore = "requires Docker"]
async fn wrong_pubkey_and_wrong_password_errors_mentions_both() {
    let tmp = TempDir::new().expect("tmpdir");
    let (bad_priv, _) = fresh_keypair(&tmp, "id_bad");

    // Server has the REAL password set; we pass WRONG_PASSWORD → both
    // pubkey and password authentication must fail.
    let container = make_sshd_image("", true)
        .start()
        .await
        .expect("start sshd container");
    let host_port = container
        .get_host_port_ipv4(SSHD_INTERNAL_PORT)
        .await
        .expect("port mapping");

    let res = RusshTransportBuilder::new("127.0.0.1", TEST_USER, bad_priv)
        .port(host_port)
        .password(WRONG_PASSWORD)
        .timeout(Duration::from_secs(30))
        .connect()
        .await;

    let err = match res {
        Ok(_) => panic!("expected auth failure, got Ok"),
        Err(e) => e,
    };
    match &err {
        CoreError::Transport(msg) => {
            let lower = msg.to_lowercase();
            let mentions_pubkey = lower.contains("pubkey")
                || lower.contains("public key")
                || lower.contains("publickey")
                || lower.contains("key");
            let mentions_password = lower.contains("password");
            assert!(
                mentions_pubkey && mentions_password,
                "Transport error must mention BOTH pubkey and password \
                 failures, got: {msg:?}"
            );
        }
        other => panic!("expected CoreError::Transport, got {other:?}"),
    }
}

// ─── Rule 4: password is not logged ────────────────────────────────────
//
// Implementation strategy (no `unsafe`, no extra dev-deps):
// the workspace forbids `unsafe`, so we cannot dup2 stderr in-process.
// Instead, we re-exec the test binary as a child process to run only
// the worker test (which actually dials sshd and sends the password).
// The parent collects the child's combined stdout+stderr and asserts
// the literal password never appears. RUST_LOG=trace is set on the
// child so any tracing-subscriber the impl might initialise emits at
// max verbosity.
//
// The worker test uses an env-var trip-wire so that, when invoked
// normally by `cargo test`, it short-circuits to a tautology (we don't
// want it to require Docker on its own — the controller test sets the
// env var only for the spawned child).

const LEAK_WORKER_ENV: &str = "VPNCTL_PW_LEAK_WORKER";
const LEAK_WORKER_PORT: &str = "VPNCTL_PW_LEAK_PORT";
const LEAK_WORKER_KEY: &str = "VPNCTL_PW_LEAK_KEY";

/// Worker driven by `password_is_not_logged_to_stderr`. When the env
/// var is unset, this is a no-op pass. When set, it dials sshd at the
/// port given via env, sends `TEST_PASSWORD`, runs `echo hi`, then
/// exits the process (so the test binary doesn't continue running other
/// tests in the child).
#[tokio::test]
#[ignore = "requires Docker"]
async fn password_leak_worker_internal_do_not_invoke_directly() {
    if std::env::var(LEAK_WORKER_ENV).is_err() {
        // Not running in the controlled child — pass silently.
        return;
    }
    let port: u16 = std::env::var(LEAK_WORKER_PORT)
        .expect("LEAK_WORKER_PORT")
        .parse()
        .expect("port parse");
    let key = std::path::PathBuf::from(std::env::var(LEAK_WORKER_KEY).expect("LEAK_WORKER_KEY"));

    let t = RusshTransportBuilder::new("127.0.0.1", TEST_USER, key)
        .port(port)
        .password(TEST_PASSWORD)
        .timeout(Duration::from_secs(30))
        .connect()
        .await
        .expect("connect");
    let _ = t.exec("echo hi").await.expect("exec");

    // Exit immediately so the test harness in the child stops here.
    // (If we let it return Ok, the harness might still write summary
    // lines, which won't contain the password but would clutter output.)
    std::process::exit(0);
}

#[tokio::test]
#[ignore = "requires Docker"]
async fn password_is_not_logged_to_stderr() {
    let tmp = TempDir::new().expect("tmpdir");
    let (bad_priv, _) = fresh_keypair(&tmp, "id_bad");

    let container = make_sshd_image("", true)
        .start()
        .await
        .expect("start sshd container");
    let host_port = container
        .get_host_port_ipv4(SSHD_INTERNAL_PORT)
        .await
        .expect("port mapping");

    // Re-exec this binary, asking the test harness to run only the
    // worker test by exact name. The worker reads env vars, performs
    // the connect, and exits.
    let exe = std::env::current_exe().expect("current_exe");
    let output = Command::new(&exe)
        .arg("--exact")
        .arg("--ignored")
        .arg("--nocapture")
        .arg("--test-threads=1")
        .arg("password_leak_worker_internal_do_not_invoke_directly")
        .env(LEAK_WORKER_ENV, "1")
        .env(LEAK_WORKER_PORT, host_port.to_string())
        .env(LEAK_WORKER_KEY, bad_priv.as_os_str())
        .env("RUST_LOG", "trace")
        .env("RUST_BACKTRACE", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn child test binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    drop(container);

    // Sanity: the worker really ran (it exits with code 0 via
    // process::exit). If it exited non-zero, the connect/exec failed
    // and the leak check is meaningless — surface that as a failure.
    assert!(
        output.status.success(),
        "worker child failed (status {:?}); combined output:\n{combined}",
        output.status
    );

    assert!(
        !combined.contains(TEST_PASSWORD),
        "password leaked to child process output! combined output:\n{combined}"
    );
}

/// Rule 5: after a successful password-fallback connect, `exec("echo hi")`
/// returns the same output as via the pubkey path.
#[tokio::test]
#[ignore = "requires Docker"]
async fn exec_after_password_fallback_behaves_like_pubkey_path() {
    let tmp = TempDir::new().expect("tmpdir");

    // Run A: password-fallback connect.
    let (bad_priv, _) = fresh_keypair(&tmp, "id_bad");
    let cont_a = make_sshd_image("", true).start().await.expect("start A");
    let port_a = cont_a
        .get_host_port_ipv4(SSHD_INTERNAL_PORT)
        .await
        .expect("port A");
    let t_a = RusshTransportBuilder::new("127.0.0.1", TEST_USER, bad_priv)
        .port(port_a)
        .password(TEST_PASSWORD)
        .timeout(Duration::from_secs(30))
        .connect()
        .await
        .expect("A connect");
    let out_a = t_a.exec("echo hi").await.expect("A exec");

    // Run B: pubkey-only connect.
    let (good_priv, good_pub) = fresh_keypair(&tmp, "id_good");
    let cont_b = make_sshd_image(&good_pub, false)
        .start()
        .await
        .expect("start B");
    let port_b = cont_b
        .get_host_port_ipv4(SSHD_INTERNAL_PORT)
        .await
        .expect("port B");
    let t_b = RusshTransportBuilder::new("127.0.0.1", TEST_USER, good_priv)
        .port(port_b)
        .timeout(Duration::from_secs(30))
        .connect()
        .await
        .expect("B connect");
    let out_b = t_b.exec("echo hi").await.expect("B exec");

    assert_eq!(
        out_a, out_b,
        "exec output differs between password-fallback and pubkey paths: \
         {out_a:?} vs {out_b:?}"
    );
    assert_eq!(out_a.trim(), "hi");
}
