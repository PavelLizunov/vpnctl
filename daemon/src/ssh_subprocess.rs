//! `SubprocessSshTransport` — implements `vpnctl_core::SshTransport`
//! by shelling out to the system `/usr/bin/ssh` binary instead of
//! linking the Rust `russh` client.
//!
//! # Why this exists
//!
//! Rust SSH stacks pull modern glibc syscalls (`russh` ⇒ glibc 2.38
//! via async crypto; `tokio::process` ⇒ glibc 2.39 via `pidfd_*`).
//! The bookworm production host ships glibc 2.36, so binaries pulling
//! either crash at startup with `version 'GLIBC_2.XX' not found`. Path
//! C — wrap the system `ssh` binary — sidesteps both glibc bumps
//! because the system binary is bookworm-native.
//!
//! # Implementation choices
//!
//! * `std::process::Command` (NOT `tokio::process::Command`) for the
//!   reason above. We run the blocking spawn inside
//!   `tokio::task::spawn_blocking` so the async runtime doesn't
//!   stall. Per-call cost: ~one thread-pool hop (~10 µs) — invisible
//!   at the cadences we use (5-min polls, on-demand deploys).
//! * `tokio::fs` would also pull `fs` feature into tokio; we use
//!   `std::fs` for the deploy-key file ops, again via
//!   `spawn_blocking` for the directory create.
//!
//! # Key management
//!
//! Caller passes a private-key path (typically
//! `/var/lib/vpnctl/.ssh/id_ed25519`). The transport never touches the
//! key file contents — it just hands the path to `ssh -i <path>` and
//! lets the system binary do all the crypto. `ensure_deploy_key()`
//! (below) auto-generates the keypair on first daemon start via the
//! system `ssh-keygen`.
//!
//! # Security
//!
//! * `StrictHostKeyChecking=accept-new` for first connect (TOFU);
//!   `BatchMode=yes` so any prompt aborts instead of hanging. After
//!   first connect the host key is pinned in
//!   `/var/lib/vpnctl/.ssh/known_hosts`.
//! * Per-call `-o ConnectTimeout=10` + `-o ServerAliveInterval=15`
//!   so a half-dead node fails fast instead of hanging the daemon
//!   task for tcp-default timeout (~minutes).
//! * `upload()` pipes base64 over `ssh`'s stdin — bytes never enter
//!   the shell command argv, never executed as a script.
//! * Single-quote in a remote path is rejected upfront rather than
//!   shell-escaped — vpnctld never generates such paths.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64_STANDARD;
use vpnctl_core::{CoreError, Result, SshTransport};

/// Default host-keys file. Per-vpnctld-process, not per-host —
/// `ssh` appends new fingerprints (TOFU) and verifies on subsequent
/// connects. Living under the same dir as the deploy key keeps a
/// single "this is vpnctld's SSH identity" surface.
const DEFAULT_KNOWN_HOSTS: &str = "/var/lib/vpnctl/.ssh/known_hosts";

/// One transport instance per (host, port, user, key_path). Cheap to
/// clone — every field is a small `String` or `PathBuf`.
#[derive(Clone, Debug)]
pub struct SubprocessSshTransport {
    /// Destination IP or hostname.
    host: String,
    /// SSH user (typically `root` for nodes vpnctld manages).
    user: String,
    /// TCP port the destination's sshd listens on.
    port: u16,
    /// Identity key path passed to `ssh -i`. Must be readable by the
    /// vpnctld process owner (typically `user:user 0600` on the
    /// homelab).
    key_path: PathBuf,
    /// `known_hosts` file. Defaults to `/var/lib/vpnctl/.ssh/known_hosts`.
    known_hosts: PathBuf,
}

impl SubprocessSshTransport {
    /// Construct a transport for one destination. Does NOT validate
    /// connectivity — the first `exec()` will do that and surface
    /// `CoreError::Transport` if the destination is unreachable, key
    /// is rejected, etc.
    pub fn new(host: impl Into<String>, user: impl Into<String>, key_path: PathBuf) -> Self {
        Self {
            host: host.into(),
            user: user.into(),
            port: 22,
            key_path,
            known_hosts: PathBuf::from(DEFAULT_KNOWN_HOSTS),
        }
    }

    /// Override the default SSH port (e.g. Cloudzy's `2222`).
    pub fn port(mut self, p: u16) -> Self {
        self.port = p;
        self
    }

    /// Override the known_hosts file. Most callers stick with the
    /// default — tests use this to point at a tempdir.
    pub fn known_hosts(mut self, path: PathBuf) -> Self {
        self.known_hosts = path;
        self
    }

    /// Build the canonical `ssh` argv for this transport, ending with
    /// the remote command. Split into its own function so tests can
    /// assert the produced argv without running `ssh`.
    pub fn build_ssh_args(&self, remote_cmd: &str) -> Vec<String> {
        let mut args: Vec<String> = vec![
            "-i".into(),
            self.key_path.to_string_lossy().into_owned(),
            "-p".into(),
            self.port.to_string(),
            "-o".into(),
            "BatchMode=yes".into(),
        ];
        args.extend(ssh_safety_opts(&self.known_hosts));
        // POSIX getopt separator — every token after `--` is treated
        // as positional regardless of leading dash. Defensive: today
        // `self.user` is hardcoded `"root"` and `self.host` is the
        // inventory address (validated). A future refactor letting
        // operator-controlled `ssh_user` reach here (e.g. supporting
        // non-root probes for hardened hosts) would silently
        // re-introduce a flag-injection path without this guard.
        // Same defense as host-fingerprint's `build_keyscan_args`.
        args.push("--".into());
        args.push(format!("{}@{}", self.user, self.host));
        args.push(remote_cmd.to_string());
        args
    }

    /// Spawn `ssh` (blocking, under `spawn_blocking`), optionally
    /// piping `stdin_bytes`, return stdout-or-error. Wrapping
    /// `std::process::Command` in `spawn_blocking` keeps the async
    /// runtime free; the cost (~one task hop, microseconds) is
    /// negligible against the SSH round-trip itself.
    async fn run(&self, remote_cmd: String, stdin_bytes: Option<Vec<u8>>) -> Result<Vec<u8>> {
        let args = self.build_ssh_args(&remote_cmd);
        let host = self.host.clone();
        let user = self.user.clone();
        let port = self.port;
        let handle = tokio::task::spawn_blocking(move || {
            let mut cmd = Command::new("ssh");
            cmd.args(&args);
            if stdin_bytes.is_some() {
                cmd.stdin(Stdio::piped());
            } else {
                cmd.stdin(Stdio::null());
            }
            cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
            let mut child = cmd.spawn().map_err(|e| {
                CoreError::Transport(format!("spawning ssh {user}@{host}:{port}: {e}"))
            })?;
            if let (Some(bytes), Some(mut sin)) = (stdin_bytes, child.stdin.take()) {
                use std::io::Write;
                sin.write_all(&bytes).map_err(|e| {
                    CoreError::Transport(format!("ssh stdin write {user}@{host}: {e}"))
                })?;
                drop(sin); // EOF → ssh proceeds
            }
            let output = child
                .wait_with_output()
                .map_err(|e| CoreError::Transport(format!("ssh wait {user}@{host}: {e}")))?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(CoreError::Transport(format!(
                    "ssh {user}@{host}:{port} exit={:?} stderr={}",
                    output.status.code(),
                    stderr.trim()
                )));
            }
            Ok(output.stdout)
        });
        handle
            .await
            .map_err(|e| CoreError::Transport(format!("spawn_blocking JoinError: {e}")))?
    }
}

#[async_trait]
impl SshTransport for SubprocessSshTransport {
    async fn exec(&self, cmd: &str) -> Result<String> {
        let bytes = self.run(cmd.to_string(), None).await?;
        String::from_utf8(bytes).map_err(|e| {
            CoreError::Transport(format!(
                "ssh {}@{}:{} non-UTF-8 stdout: {e}",
                self.user, self.host, self.port
            ))
        })
    }

    /// Upload binary content to a remote path via base64 over
    /// `ssh` stdin → remote `base64 -d > '<path>'`. The bytes
    /// never enter the argv, only the path does (and that's
    /// single-quoted server-side; `'` in path is rejected upfront).
    async fn upload(&self, path: &str, content: &[u8]) -> Result<()> {
        if path.contains('\'') {
            return Err(CoreError::Transport(format!(
                "upload: path with single quote not supported: {path:?}"
            )));
        }
        let b64 = B64_STANDARD.encode(content);
        let remote_cmd = format!("set -eu; base64 -d > '{path}'");
        self.run(remote_cmd, Some(b64.into_bytes())).await?;
        Ok(())
    }

    async fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        if path.contains('\'') {
            return Err(CoreError::Transport(format!(
                "read_file: path with single quote not supported: {path:?}"
            )));
        }
        let remote_cmd = format!("base64 < '{path}'");
        let bytes = self.run(remote_cmd, None).await?;
        let b64 = String::from_utf8(bytes).map_err(|e| {
            CoreError::Transport(format!(
                "read_file {}@{}:{path} non-UTF-8: {e}",
                self.user, self.host
            ))
        })?;
        B64_STANDARD
            .decode(b64.trim().replace('\n', ""))
            .map_err(|e| {
                CoreError::Transport(format!(
                    "read_file {}@{}:{path} base64 decode failed: {e}",
                    self.user, self.host
                ))
            })
    }
}

/// The five `-o` SSH options that both the daemon's pubkey-auth
/// transport and the wizard's sshpass-mediated password-auth path
/// share. Extracted so a future hardening tweak (raising
/// `ServerAliveCountMax`, switching `StrictHostKeyChecking` to
/// `yes` after the first connect, etc.) lands in exactly one place.
///
/// The options are, in order:
///   * `StrictHostKeyChecking=accept-new` — first-connect accepts,
///     subsequent connects verify against the pinned host key.
///   * `UserKnownHostsFile=<path>` — daemon-owned per-process known
///     hosts file, so we don't mutate the operator's `~/.ssh/`.
///   * `ConnectTimeout=10` — cap on the TCP connect; default is
///     OS-dependent and can sit for minutes on a black-holed route.
///   * `ServerAliveInterval=15` + `ServerAliveCountMax=2` — caller
///     side sends keepalive every 15 s and gives up after 2 missed
///     replies (~30 s of silence kills the connection). Without this,
///     a half-open connection across a stateful NAT can hang the
///     transport's `wait_with_output` until the OS gives up (~2 h
///     by default).
///
/// Each option is emitted as a separate `-o` flag so the argv shape
/// matches a hand-typed `ssh -o KEY=VAL` invocation; `ssh` does NOT
/// accept `-o KEY1=VAL1 KEY2=VAL2`.
pub fn ssh_safety_opts(known_hosts: &std::path::Path) -> Vec<String> {
    vec![
        "-o".into(),
        "StrictHostKeyChecking=accept-new".into(),
        "-o".into(),
        format!("UserKnownHostsFile={}", known_hosts.display()),
        "-o".into(),
        "ConnectTimeout=10".into(),
        "-o".into(),
        "ServerAliveInterval=15".into(),
        "-o".into(),
        "ServerAliveCountMax=2".into(),
    ]
}

/// Ensure vpnctld has a deploy key at `path`. If absent, generates a
/// fresh ed25519 keypair via the system `ssh-keygen` (no Rust crypto
/// deps; the system binary is bookworm-native, glibc 2.36).
///
/// The parent directory is created with mode 0700; the key itself
/// gets the default ssh-keygen mode (0600). Returns immediately if
/// the key already exists — idempotent, safe to call on every
/// daemon startup.
///
/// **Public key surfacing:** call `read_public_key(path)` after this
/// to get the `<ssh-ed25519 …>` text the operator pastes into each
/// node's `~/.ssh/authorized_keys`. The admin UI's Settings page
/// renders that text behind a one-click copy area.
pub async fn ensure_deploy_key(path: &Path) -> std::io::Result<()> {
    let owned = path.to_path_buf();
    tokio::task::spawn_blocking(move || ensure_deploy_key_sync(&owned))
        .await
        .map_err(|e| std::io::Error::other(format!("spawn_blocking JoinError: {e}")))?
}

fn ensure_deploy_key_sync(path: &Path) -> std::io::Result<()> {
    if path.exists() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(parent)?.permissions();
            perms.set_mode(0o700);
            std::fs::set_permissions(parent, perms)?;
        }
    }
    let status = Command::new("ssh-keygen")
        .args([
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "vpnctld-deploy",
            "-f",
            &path.to_string_lossy(),
        ])
        .status()?;
    if !status.success() {
        return Err(std::io::Error::other(format!(
            "ssh-keygen for {} failed: exit={:?}",
            path.display(),
            status.code()
        )));
    }
    Ok(())
}

/// Read the public-key file (`<path>.pub`) so the admin UI can
/// surface it for the operator to copy into each node's
/// `authorized_keys`. Sync read — small file, not worth async.
pub fn read_public_key(private_path: &Path) -> std::io::Result<String> {
    let pub_path = private_path.with_extension("pub");
    let raw = std::fs::read_to_string(&pub_path)?;
    Ok(raw.trim_end().to_string())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn make_transport() -> SubprocessSshTransport {
        SubprocessSshTransport::new("203.0.113.7", "root", PathBuf::from("/tmp/test-key"))
            .port(2222)
    }

    #[test]
    fn ssh_args_contain_identity_port_user_host_and_remote_cmd() {
        let t = make_transport();
        let args = t.build_ssh_args("uname -a");
        let i_pos = args.iter().position(|a| a == "-i").expect("identity flag");
        assert_eq!(args[i_pos + 1], "/tmp/test-key");
        let p_pos = args.iter().position(|a| a == "-p").expect("port flag");
        assert_eq!(args[p_pos + 1], "2222");
        let user_host = args
            .iter()
            .position(|a| a == "root@203.0.113.7")
            .expect("user@host");
        let cmd_pos = args
            .iter()
            .position(|a| a == "uname -a")
            .expect("remote cmd");
        assert!(user_host < cmd_pos);
    }

    #[test]
    fn ssh_args_include_safety_options() {
        let args = make_transport().build_ssh_args("ls");
        let joined = args.join(" ");
        for needle in [
            "BatchMode=yes",
            "StrictHostKeyChecking=accept-new",
            "UserKnownHostsFile=",
            "ConnectTimeout=10",
            "ServerAliveInterval=15",
            "ServerAliveCountMax=2",
        ] {
            assert!(joined.contains(needle), "missing {needle:?}: {joined}");
        }
    }

    #[tokio::test]
    async fn upload_rejects_path_with_single_quote() {
        let err = make_transport()
            .upload("/tmp/foo'bar", b"x")
            .await
            .unwrap_err();
        assert!(format!("{err:?}").contains("single quote"));
    }

    #[tokio::test]
    async fn read_file_rejects_path_with_single_quote() {
        let err = make_transport()
            .read_file("/tmp/foo'bar")
            .await
            .unwrap_err();
        assert!(format!("{err:?}").contains("single quote"));
    }

    #[tokio::test]
    async fn ensure_deploy_key_creates_key_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("id_ed25519");
        assert!(!key.exists());
        ensure_deploy_key(&key).await.unwrap();
        assert!(key.exists());
        let pub_txt = read_public_key(&key).unwrap();
        assert!(pub_txt.starts_with("ssh-ed25519 "));
        assert!(pub_txt.contains("vpnctld-deploy"));
    }

    #[tokio::test]
    async fn ensure_deploy_key_idempotent_on_existing() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("id_ed25519");
        ensure_deploy_key(&key).await.unwrap();
        let first = std::fs::read_to_string(key.with_extension("pub")).unwrap();
        ensure_deploy_key(&key).await.unwrap();
        let second = std::fs::read_to_string(key.with_extension("pub")).unwrap();
        assert_eq!(first, second);
    }
}
