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
use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64_STANDARD;
use vpnctl_core::{CoreError, Result, SshTransport};

/// Default host-keys file. Per-vpnctld-process, not per-host —
/// `ssh` appends new fingerprints (TOFU) and verifies on subsequent
/// connects. Living under the same dir as the deploy key keeps a
/// single "this is vpnctld's SSH identity" surface.
const DEFAULT_KNOWN_HOSTS: &str = "/var/lib/vpnctl/.ssh/known_hosts";

/// Hard wall-clock cap on a single SSH invocation (seconds).
///
/// `ConnectTimeout` + `ServerAlive*` bound the TCP connect and a
/// silently-dead link, but a LIVE connection whose REMOTE COMMAND hangs
/// (apt waiting on a dpkg lock, a wedged `systemctl`, a stuck
/// `sing-box check`) would otherwise block the `spawn_blocking` thread
/// until the OS gives up — effectively forever. The HTTP `TimeoutLayer`
/// doesn't save us: SSE deploys run in a detached task, and even for a
/// plain request cancelling the future never reaps the child process.
///
/// 300 s is generous on purpose: the slowest legitimate op is the
/// add-server `apt-get install sing-box` step (download + deps, up to
/// ~a minute on a slow mirror), so the default leaves 3–5× headroom and
/// only ever fires on a genuine hang. Override per-deployment with
/// `VPNCTLD_SSH_TIMEOUT_SECS` (clamped to 10..=3600).
const DEFAULT_SSH_TIMEOUT_SECS: u64 = 300;

/// Resolve the hard SSH timeout from `VPNCTLD_SSH_TIMEOUT_SECS`,
/// clamped to a sane range, falling back to [`DEFAULT_SSH_TIMEOUT_SECS`].
fn default_ssh_timeout() -> Duration {
    let secs = std::env::var("VPNCTLD_SSH_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|s| (10..=3600).contains(s))
        .unwrap_or(DEFAULT_SSH_TIMEOUT_SECS);
    Duration::from_secs(secs)
}

/// One transport instance per (host, port, user, key_path). Cheap to
/// clone — every field is a small `String` or `PathBuf`.
#[derive(Clone, Debug)]
pub struct SubprocessSshTransport {
    /// Destination IP or hostname.
    host: String,
    /// SSH management user. Non-root users are elevated through `sudo -n`
    /// for every managed-node operation.
    user: String,
    /// TCP port the destination's sshd listens on.
    port: u16,
    /// Identity key path passed to `ssh -i`. Must be readable by the
    /// vpnctld process owner (typically `user:user 0600` on the
    /// homelab).
    key_path: PathBuf,
    /// `known_hosts` file. Defaults to `/var/lib/vpnctl/.ssh/known_hosts`.
    known_hosts: PathBuf,
    /// Hard wall-clock cap on each invocation; on expiry the child `ssh`
    /// process is killed and `run` returns `Transport(... timed out ...)`.
    /// See [`DEFAULT_SSH_TIMEOUT_SECS`].
    timeout: Duration,
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
            timeout: default_ssh_timeout(),
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

    /// Override the hard wall-clock timeout (default
    /// [`DEFAULT_SSH_TIMEOUT_SECS`], env-overridable via
    /// `VPNCTLD_SSH_TIMEOUT_SECS`). A short-lived probe/status caller may
    /// dial this down so a wedged node fails fast instead of pinning a
    /// thread for the full default.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn privileged_command(&self, command: &str) -> String {
        if self.user == "root" {
            command.to_string()
        } else {
            format!(
                "sudo -n sh -c {}",
                vpnctl_core::shell::single_quote(command)
            )
        }
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
    /// Run `remote_cmd` over SSH with `stdin_bytes` piped to its
    /// stdin. Public wrapper around the private [`Self::run`] so
    /// callers outside the `SshTransport` trait (e.g.
    /// `alert_sink::TelegramSink` via-server mode) can send the
    /// Telegram URL via stdin instead of embedding the token-bearing
    /// URL into the remote shell command (which would land in
    /// `ps` on the remote server, visible to other tenants on a
    /// shared VPS).
    ///
    /// `remote_cmd` is the shell command the remote `bash -c` runs;
    /// `stdin_bytes` is fed to its stdin. Returns the command's
    /// stdout as raw bytes (caller decodes).
    ///
    /// Security audit 2026-05-18 round 2 finding — extracted to keep
    /// secrets out of argv.
    pub async fn exec_with_stdin(&self, remote_cmd: &str, stdin_bytes: Vec<u8>) -> Result<Vec<u8>> {
        self.run(remote_cmd.to_string(), Some(stdin_bytes)).await
    }

    /// Execute a command as the SSH login itself, without the managed-node
    /// sudo wrapper. Used only for per-user home operations such as installing
    /// vpnctld's deploy key into that user's `~/.ssh/authorized_keys`.
    pub async fn exec_unprivileged(&self, remote_cmd: &str) -> Result<String> {
        let bytes = self.run(remote_cmd.to_string(), None).await?;
        String::from_utf8(bytes).map_err(|e| {
            CoreError::Transport(format!(
                "ssh {}@{}:{} non-UTF-8 stdout: {e}",
                self.user, self.host, self.port
            ))
        })
    }

    async fn run(&self, remote_cmd: String, stdin_bytes: Option<Vec<u8>>) -> Result<Vec<u8>> {
        let args = self.build_ssh_args(&remote_cmd);
        let label = format!("{}@{}:{}", self.user, self.host, self.port);
        let timeout = self.timeout;
        let handle = tokio::task::spawn_blocking(move || {
            let mut cmd = Command::new("ssh");
            cmd.args(&args);
            run_child_with_timeout(cmd, stdin_bytes, timeout, &label)
        });
        handle
            .await
            .map_err(|e| CoreError::Transport(format!("spawn_blocking JoinError: {e}")))?
    }
}

/// Spawn `cmd`, feed `stdin_bytes` (if any), drain stdout/stderr, and
/// wait for exit — but no longer than `timeout`. On expiry the child is
/// **killed and reaped** and a `Transport` timeout error is returned;
/// this is the hard wall-clock bound that `ConnectTimeout`/`ServerAlive*`
/// can't provide for a live-connection-but-hung remote command.
///
/// Blocking by design (called inside `spawn_blocking`). `label` is the
/// `user@host:port` shown in error messages. Pulled out of [`Self::run`]
/// so the deadline/kill logic is unit-testable with cheap local commands
/// (`sleep`, `cat`, `sh -c …`) instead of a live SSH server.
///
/// stdout/stderr are drained on dedicated threads spawned BEFORE stdin is
/// written, so a chatty remote command can't dead-lock by filling the
/// ~64 KiB pipe buffer while we poll for the deadline (without readers a
/// verbose `apt-get` would block on write, never exit, and look like a
/// hang).
fn run_child_with_timeout(
    mut cmd: Command,
    stdin_bytes: Option<Vec<u8>>,
    timeout: Duration,
    label: &str,
) -> Result<Vec<u8>> {
    use std::io::{Read, Write};
    #[cfg(unix)]
    use std::os::unix::process::CommandExt;

    let deadline = Instant::now() + timeout;

    if stdin_bytes.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    #[cfg(unix)]
    cmd.process_group(0);

    let mut child = cmd
        .spawn()
        .map_err(|e| CoreError::Transport(format!("spawning ssh {label}: {e}")))?;

    let pid = child.id();
    let kill_and_reap = |child: &mut std::process::Child| {
        #[cfg(unix)]
        let _ = Command::new("kill")
            .args(["-s", "KILL", "--", &format!("-{pid}")])
            .status();
        let _ = child.kill();
        let _ = child.wait();
    };

    // Drain pipes on threads spawned up front (before writing stdin) so
    // neither direction can dead-lock on a full pipe buffer.
    let mut out_pipe = child.stdout.take();
    let mut err_pipe = child.stderr.take();
    let out_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(p) = out_pipe.as_mut() {
            let _ = p.read_to_end(&mut buf);
        }
        buf
    });
    let err_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(p) = err_pipe.as_mut() {
            let _ = p.read_to_end(&mut buf);
        }
        buf
    });

    let mut in_writer = if let (Some(bytes), Some(mut sin)) = (stdin_bytes, child.stdin.take()) {
        Some(std::thread::spawn(move || {
            let res = sin.write_all(&bytes);
            drop(sin);
            res
        }))
    } else {
        None
    };

    // Poll for exit until the deadline. 10 ms cadence: low latency, negligible CPU.
    let status = loop {
        if Instant::now() >= deadline {
            kill_and_reap(&mut child);
            let _ = out_reader.join();
            let _ = err_reader.join();
            if let Some(w) = in_writer {
                let _ = w.join();
            }
            return Err(CoreError::Transport(format!(
                "ssh {label} timed out after {timeout:?} (remote command killed)"
            )));
        }

        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if let Some(ref w) = in_writer {
                    if w.is_finished() {
                        if let Some(w) = in_writer.take() {
                            match w.join() {
                                Ok(Err(e)) => {
                                    kill_and_reap(&mut child);
                                    let _ = out_reader.join();
                                    let _ = err_reader.join();
                                    return Err(CoreError::Transport(format!(
                                        "ssh stdin write {label}: {e}"
                                    )));
                                }
                                Err(_) => {
                                    kill_and_reap(&mut child);
                                    let _ = out_reader.join();
                                    let _ = err_reader.join();
                                    return Err(CoreError::Transport(format!(
                                        "ssh stdin write {label}: writer thread panicked"
                                    )));
                                }
                                Ok(Ok(())) => {}
                            }
                        }
                    }
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                kill_and_reap(&mut child);
                let _ = out_reader.join();
                let _ = err_reader.join();
                if let Some(w) = in_writer {
                    let _ = w.join();
                }
                return Err(CoreError::Transport(format!("ssh wait {label}: {e}")));
            }
        }
    };

    let stdout = out_reader.join().unwrap_or_default();
    let stderr = err_reader.join().unwrap_or_default();

    if let Some(w) = in_writer {
        match w.join() {
            Ok(Err(e)) => {
                if !status.success() {
                    let stderr = String::from_utf8_lossy(&stderr);
                    return Err(CoreError::Transport(format!(
                        "ssh {label} exit={:?} stderr={}",
                        status.code(),
                        stderr.trim()
                    )));
                }
                return Err(CoreError::Transport(format!(
                    "ssh stdin write {label}: {e}"
                )));
            }
            Err(_) => {
                return Err(CoreError::Transport(format!(
                    "ssh stdin write {label}: writer thread panicked"
                )));
            }
            Ok(Ok(())) => {}
        }
    }

    if !status.success() {
        let stderr = String::from_utf8_lossy(&stderr);
        return Err(CoreError::Transport(format!(
            "ssh {label} exit={:?} stderr={}",
            status.code(),
            stderr.trim()
        )));
    }
    Ok(stdout)
}

#[async_trait]
impl SshTransport for SubprocessSshTransport {
    async fn exec(&self, cmd: &str) -> Result<String> {
        let bytes = self.run(self.privileged_command(cmd), None).await?;
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
        let remote_cmd = self.privileged_command(&format!("set -eu; base64 -d > '{path}'"));
        self.run(remote_cmd, Some(b64.into_bytes())).await?;
        Ok(())
    }

    async fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        if path.contains('\'') {
            return Err(CoreError::Transport(format!(
                "read_file: path with single quote not supported: {path:?}"
            )));
        }
        let remote_cmd = self.privileged_command(&format!("base64 < '{path}'"));
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

/// Resolve the public-key path (`<private_path>.pub`) corresponding to
/// a private key.
///
/// Appends `.pub` to the complete path rather than replacing the extension
/// (`with_extension`), so dotted private keys (e.g. `id.key`) correctly
/// resolve to `id.key.pub` matching OpenSSH / `ssh-keygen` conventions.
pub(crate) fn public_key_path(private_path: &Path) -> PathBuf {
    let mut pub_path = private_path.as_os_str().to_os_string();
    pub_path.push(".pub");
    PathBuf::from(pub_path)
}

/// Read the public-key file (`<path>.pub`) so the admin UI can
/// surface it for the operator to copy into each node's
/// `authorized_keys`. Sync read — small file, not worth async.
pub fn read_public_key(private_path: &Path) -> std::io::Result<String> {
    let pub_path = public_key_path(private_path);
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
    fn root_commands_are_not_wrapped_in_sudo() {
        assert_eq!(make_transport().privileged_command("id -u"), "id -u");
    }

    #[test]
    fn non_root_commands_use_passwordless_sudo_with_shell_quoting() {
        let t =
            SubprocessSshTransport::new("203.0.113.7", "debian", PathBuf::from("/tmp/test-key"));
        assert_eq!(
            t.privileged_command("printf '%s' \"$HOME\""),
            "sudo -n sh -c 'printf '\\''%s'\\'' \"$HOME\"'"
        );
    }

    #[test]
    fn unprivileged_command_is_not_wrapped_in_sudo() {
        let t =
            SubprocessSshTransport::new("203.0.113.7", "debian", PathBuf::from("/tmp/test-key"));
        let args = t.build_ssh_args("mkdir -p ~/.ssh");
        assert_eq!(args.last().map(String::as_str), Some("mkdir -p ~/.ssh"));
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

    // ─── hard wall-clock timeout (run_child_with_timeout) ────────────
    // Exercised with cheap local commands instead of a live SSH server;
    // the kill/deadline/drain logic is identical regardless of the binary.

    #[test]
    fn child_completes_before_timeout_returns_stdout() {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "printf hello"]);
        let out = run_child_with_timeout(cmd, None, Duration::from_secs(10), "test").unwrap();
        assert_eq!(out, b"hello");
    }

    #[test]
    fn child_nonzero_exit_is_transport_error_with_stderr() {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "printf oops >&2; exit 3"]);
        let err = run_child_with_timeout(cmd, None, Duration::from_secs(10), "test").unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("exit=Some(3)"), "got: {msg}");
        assert!(msg.contains("oops"), "got: {msg}");
    }

    #[test]
    fn child_stdin_is_piped_to_command() {
        // `cat` echoes stdin to stdout — proves the stdin pipe is wired
        // and the reader threads collect what the command emits.
        let cmd = Command::new("cat");
        let out = run_child_with_timeout(
            cmd,
            Some(b"piped-in".to_vec()),
            Duration::from_secs(10),
            "t",
        )
        .unwrap();
        assert_eq!(out, b"piped-in");
    }

    #[test]
    fn child_stdin_write_error_kills_and_reaps_the_child() {
        // Pins the CLEANUP, not just the error surfacing. The child closes
        // its stdin (`exec 0<&-`) so our 2 MiB write hits a broken pipe,
        // then sleeps and would `touch` a sentinel. The fix kills + reaps
        // the child on the stdin-write error, so the sentinel never appears.
        // A revert to the early-`?` return (no kill) leaves the child
        // sleeping → it touches the sentinel → this test fails. (Asserting
        // only "returns an error" couldn't catch the regression: a child
        // that exits at once returns the same error on the buggy path too.)
        let dir = tempfile::tempdir().unwrap();
        let sentinel = dir.path().join("child-survived");
        let sentinel_s = sentinel.to_string_lossy().into_owned();
        let mut cmd = Command::new("sh");
        cmd.arg("-c")
            .arg(format!("exec 0<&-; sleep 1; touch '{sentinel_s}'"));
        let big = vec![b'x'; 2 * 1024 * 1024]; // ≫ pipe buffer → broken pipe

        let res = run_child_with_timeout(cmd, Some(big), Duration::from_secs(10), "t");
        assert!(
            res.is_err(),
            "broken-pipe stdin write must surface an error"
        );
        assert!(
            format!("{:?}", res.unwrap_err()).contains("stdin write"),
            "error must identify the stdin-write failure"
        );
        // A killed child never reaches the touch; give a SURVIVING child
        // well past its 1 s sleep to prove it was actually reaped.
        std::thread::sleep(Duration::from_secs(2));
        assert!(
            !sentinel.exists(),
            "child must be killed on stdin-write error, not left running to completion"
        );
    }

    #[test]
    fn child_timeout_kills_hung_command_promptly() {
        // `sleep 30` would otherwise block the wait for 30s. The 200 ms
        // hard timeout must kill it and return an error in well under that
        // — the core fix: an infinite remote hang becomes a bounded error.
        let mut cmd = Command::new("sleep");
        cmd.arg("30");
        let start = Instant::now();
        let err = run_child_with_timeout(cmd, None, Duration::from_millis(200), "root@node:22")
            .unwrap_err();
        let elapsed = start.elapsed();
        assert!(format!("{err:?}").contains("timed out"), "got: {err:?}");
        assert!(
            elapsed < Duration::from_secs(5),
            "child not killed promptly: {elapsed:?}"
        );
    }

    #[test]
    fn child_large_output_does_not_deadlock() {
        // 200 KiB > the ~64 KiB pipe buffer. Without draining stdout on a
        // dedicated thread the child would block on write, never exit, and
        // trip the timeout. With the reader threads it completes fast.
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "head -c 200000 /dev/zero"]);
        let out = run_child_with_timeout(cmd, None, Duration::from_secs(10), "test").unwrap();
        assert_eq!(out.len(), 200_000);
    }

    #[test]
    fn child_accepts_pipe_never_reads_large_stdin_timeout_kills_and_reaps() {
        // The child process opens stdin as a pipe (Stdio::piped()) but never reads
        // from it, while we attempt to write 2 MiB (> 64 KiB pipe buffer).
        // Without the deadline covering stdin write, the writer would block indefinitely.
        // The hard timeout must fire, kill and reap the child quickly, and ensure
        // no orphan process is left running.
        let dir = tempfile::tempdir().unwrap();
        let sentinel = dir.path().join("child-survived");
        let sentinel_s = sentinel.to_string_lossy().into_owned();
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(format!("sleep 2; touch '{sentinel_s}'"));
        let big = vec![b'x'; 2 * 1024 * 1024]; // ≫ 64 KiB pipe buffer

        let start = Instant::now();
        let res =
            run_child_with_timeout(cmd, Some(big), Duration::from_millis(200), "root@node:22");
        let elapsed = start.elapsed();

        assert!(
            res.is_err(),
            "hung child with unread large stdin must time out"
        );
        let err_msg = format!("{:?}", res.unwrap_err());
        assert!(
            err_msg.contains("timed out"),
            "error must indicate timeout, got: {err_msg}"
        );
        assert!(
            elapsed < Duration::from_secs(1),
            "child not killed promptly on stdin pipe block: {elapsed:?}"
        );

        // Wait well past the child's sleep to verify it was reaped and not left running
        std::thread::sleep(Duration::from_millis(2500));
        assert!(
            !sentinel.exists(),
            "child must be killed on timeout, not left running to touch sentinel"
        );
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
        let first = read_public_key(&key).unwrap();
        ensure_deploy_key(&key).await.unwrap();
        let second = read_public_key(&key).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn read_public_key_no_extension() {
        let dir = tempfile::tempdir().unwrap();
        let priv_key = dir.path().join("id_ed25519");
        let pub_key = dir.path().join("id_ed25519.pub");
        std::fs::write(&pub_key, "ssh-ed25519 AAAAC3NzaC1yc2E test@node\n").unwrap();

        let content = read_public_key(&priv_key).unwrap();
        assert_eq!(content, "ssh-ed25519 AAAAC3NzaC1yc2E test@node");
    }

    #[test]
    fn read_public_key_dotted_path() {
        let dir = tempfile::tempdir().unwrap();
        let priv_key = dir.path().join("id.key");
        let pub_key = dir.path().join("id.key.pub");
        let wrong_pub = dir.path().join("id.pub");
        std::fs::write(&pub_key, "ssh-ed25519 AAAAC3NzaC1yc2E test@node\n").unwrap();
        std::fs::write(&wrong_pub, "wrong key content\n").unwrap();

        let content = read_public_key(&priv_key).unwrap();
        assert_eq!(content, "ssh-ed25519 AAAAC3NzaC1yc2E test@node");
    }

    #[test]
    fn public_key_path_appends_pub_for_standard_and_dotted_paths() {
        assert_eq!(
            public_key_path(Path::new("/etc/vpnctl/id_ed25519")),
            PathBuf::from("/etc/vpnctl/id_ed25519.pub")
        );
        assert_eq!(
            public_key_path(Path::new("/var/lib/vpnctl/id.key")),
            PathBuf::from("/var/lib/vpnctl/id.key.pub")
        );
        assert_eq!(
            public_key_path(Path::new("custom.deploy.key")),
            PathBuf::from("custom.deploy.key.pub")
        );
    }

    #[tokio::test]
    async fn ensure_deploy_key_creates_key_with_dotted_path() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("id.key.custom");
        assert!(!key.exists());
        ensure_deploy_key(&key).await.unwrap();
        assert!(key.exists());
        let pub_txt = read_public_key(&key).unwrap();
        assert!(pub_txt.starts_with("ssh-ed25519 "));
        assert!(pub_txt.contains("vpnctld-deploy"));
    }
}
