//! `SubprocessSshTransport` — implements `vpnctl_core::SshTransport`
//! by shelling out to the system `/usr/bin/ssh` binary instead of
//! linking the Rust `russh` client.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64_STANDARD;
use tempfile::TempDir;
use vpnctl_core::{CoreError, PinnedJumpRoute, Result, SshTransport};

/// Default host-keys file. Per-vpnctld-process, not per-host.
const DEFAULT_KNOWN_HOSTS: &str = "/var/lib/vpnctl/.ssh/known_hosts";

/// Hard wall-clock cap on a single SSH invocation (seconds).
const DEFAULT_SSH_TIMEOUT_SECS: u64 = 300;

fn default_ssh_timeout() -> Duration {
    let secs = std::env::var("VPNCTLD_SSH_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|s| (10..=3600).contains(s))
        .unwrap_or(DEFAULT_SSH_TIMEOUT_SECS);
    Duration::from_secs(secs)
}

/// One transport instance per (host, port, user, key_path, optional jump_host).
#[derive(Clone, Debug)]
pub struct SubprocessSshTransport {
    /// Destination IP or hostname.
    host: String,
    /// SSH management user.
    user: String,
    /// TCP port the destination's sshd listens on.
    port: u16,
    /// Optional fully pinned SSH jump route (ProxyJump).
    jump: Option<PinnedJumpRoute>,
    /// Inventory-authoritative pin for a direct target.
    target_fingerprint: Option<String>,
    /// Identity key path passed to `ssh -i`.
    key_path: PathBuf,
    /// `known_hosts` file.
    known_hosts: PathBuf,
    /// Hard wall-clock cap on each invocation.
    timeout: Duration,
}

impl SubprocessSshTransport {
    pub fn new(host: impl Into<String>, user: impl Into<String>, key_path: PathBuf) -> Self {
        Self {
            host: host.into(),
            user: user.into(),
            port: 22,
            jump: None,
            target_fingerprint: None,
            key_path,
            known_hosts: PathBuf::from(DEFAULT_KNOWN_HOSTS),
            timeout: default_ssh_timeout(),
        }
    }

    pub fn port(mut self, p: u16) -> Self {
        self.port = p;
        self
    }

    pub fn with_jump(mut self, jump: Option<PinnedJumpRoute>) -> Self {
        self.jump = jump;
        self
    }

    pub fn jump_route(&self) -> Option<&PinnedJumpRoute> {
        self.jump.as_ref()
    }

    pub fn trusted_fingerprint(mut self, fingerprint: Option<String>) -> Self {
        self.target_fingerprint = fingerprint;
        self
    }

    pub fn known_hosts(mut self, path: PathBuf) -> Self {
        self.known_hosts = path;
        self
    }

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

    /// Build argv for an ordinary direct connection. Pinned jump routes use
    /// [`prepare_pinned_jump`] instead and can never fall back to this path.
    fn build_direct_ssh_args(&self, remote_cmd: &str) -> Vec<String> {
        let mut args: Vec<String> = vec![
            "-i".into(),
            self.key_path.to_string_lossy().into_owned(),
            "-p".into(),
            self.port.to_string(),
            "-o".into(),
            "BatchMode=yes".into(),
        ];
        args.extend(ssh_safety_opts(&self.known_hosts, false));
        args.push("--".into());
        args.push(format!("{}@{}", self.user, self.host));
        args.push(remote_cmd.to_string());
        args
    }

    pub async fn exec_with_stdin(&self, remote_cmd: &str, stdin_bytes: Vec<u8>) -> Result<Vec<u8>> {
        self.run(remote_cmd.to_string(), Some(stdin_bytes)).await
    }

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
        let transport = self.clone();
        let label = format!("{}@{}:{}", self.user, self.host, self.port);
        let handle = tokio::task::spawn_blocking(move || {
            if transport.jump.is_some() {
                let prepared = prepare_pinned_jump(&transport)?;
                let mut cmd = Command::new("ssh");
                cmd.args(prepared.final_args(&remote_cmd));
                run_child_with_timeout(cmd, stdin_bytes, transport.timeout, &label)
            } else if transport.target_fingerprint.is_some() {
                let prepared = prepare_pinned_direct(&transport)?;
                let mut cmd = Command::new("ssh");
                cmd.args(prepared.final_args(&remote_cmd));
                run_child_with_timeout(cmd, stdin_bytes, transport.timeout, &label)
            } else {
                let mut cmd = Command::new("ssh");
                cmd.args(transport.build_direct_ssh_args(&remote_cmd));
                run_child_with_timeout(cmd, stdin_bytes, transport.timeout, &label)
            }
        });
        handle
            .await
            .map_err(|e| CoreError::Transport(format!("spawn_blocking JoinError: {e}")))?
    }
}

const JUMP_ALIAS: &str = "vpnctl-pinned-jump";
const TARGET_ALIAS: &str = "vpnctl-pinned-target";

struct PreparedJump {
    _dir: TempDir,
    config: PathBuf,
}

impl PreparedJump {
    fn final_args(&self, remote_cmd: &str) -> Vec<String> {
        vec![
            "-F".into(),
            self.config.to_string_lossy().into_owned(),
            "--".into(),
            TARGET_ALIAS.into(),
            remote_cmd.into(),
        ]
    }
}

fn prepare_pinned_direct(transport: &SubprocessSshTransport) -> Result<PreparedJump> {
    let expected = transport
        .target_fingerprint
        .as_deref()
        .ok_or_else(|| CoreError::Transport("direct target fingerprint is missing".into()))?;
    let expected = vpnctl_host_fingerprint::canonicalize_sha256(expected)
        .ok_or_else(|| CoreError::Transport("direct target fingerprint is malformed".into()))?;
    validate_endpoint(
        "target host",
        &transport.host,
        "target user",
        &transport.user,
        transport.port,
    )?;
    let identity_path = identity_path_for_config(&transport.key_path)?;
    let scan = run_keyscan(&transport.host, transport.port)?;
    let key = matching_raw_key(&scan, &expected)?.ok_or_else(|| {
        CoreError::Transport(format!(
            "target host {}:{} did not present its inventory-pinned host key",
            transport.host, transport.port
        ))
    })?;
    let dir = tempfile::Builder::new()
        .prefix("vpnctl-pinned-ssh-")
        .tempdir()
        .map_err(|e| {
            CoreError::Transport(format!("creating private SSH staging directory: {e}"))
        })?;
    let known_hosts = dir.path().join("known_hosts");
    let config = dir.path().join("ssh_config");
    std::fs::write(&known_hosts, known_hosts_entry(TARGET_ALIAS, &key)?)
        .map_err(|e| CoreError::Transport(format!("writing direct known_hosts: {e}")))?;
    let body = format!(
        "Host {TARGET_ALIAS}\n    HostName {}\n    User {}\n    Port {}\n    IdentityFile {}\n    IdentitiesOnly yes\n    BatchMode yes\n    StrictHostKeyChecking yes\n    UserKnownHostsFile {}\n    GlobalKnownHostsFile /dev/null\n    UpdateHostKeys no\n    HostKeyAlias {TARGET_ALIAS}\n",
        transport.host,
        transport.user,
        transport.port,
        config_quote(&identity_path.to_string_lossy()),
        known_hosts.display(),
    );
    std::fs::write(&config, body)
        .map_err(|e| CoreError::Transport(format!("writing direct ssh_config: {e}")))?;
    Ok(PreparedJump { _dir: dir, config })
}

fn validate_endpoint(
    host_label: &str,
    host: &str,
    user_label: &str,
    user: &str,
    port: u16,
) -> Result<()> {
    if host.is_empty()
        || !host.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':' | b'%' | b'[' | b']')
        })
    {
        return Err(CoreError::Transport(format!("invalid {host_label}")));
    }
    if user.is_empty()
        || !user
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        return Err(CoreError::Transport(format!("invalid {user_label}")));
    }
    if port == 0 {
        return Err(CoreError::Transport("SSH port must be non-zero".into()));
    }
    Ok(())
}

fn identity_path_for_config(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| CoreError::Transport(format!("resolving current directory: {e}")))?
            .join(path)
    };
    let raw = absolute
        .to_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| CoreError::Transport("identity path is empty or non-UTF-8".into()))?;
    if raw.chars().any(char::is_control) || raw.contains('%') {
        return Err(CoreError::Transport(
            "identity path must contain no control characters or '%' tokens".into(),
        ));
    }
    Ok(absolute)
}

fn prepare_pinned_jump(transport: &SubprocessSshTransport) -> Result<PreparedJump> {
    let route = transport
        .jump
        .as_ref()
        .ok_or_else(|| CoreError::Transport("pinned jump route is missing".into()))?;
    validate_pinned_jump(transport, route)?;
    let mut normalized = transport.clone();
    normalized.key_path = identity_path_for_config(&transport.key_path)?;

    let jump_scan = run_keyscan(&route.host, route.port)?;
    let jump_key = matching_raw_key(&jump_scan, &route.jump_fingerprint)?.ok_or_else(|| {
        CoreError::Transport(format!(
            "jump host {}:{} did not present its pinned host key",
            route.host, route.port
        ))
    })?;

    let dir = tempfile::Builder::new()
        .prefix("vpnctl-pinned-ssh-")
        .tempdir()
        .map_err(|e| {
            CoreError::Transport(format!("creating private SSH staging directory: {e}"))
        })?;
    let known_hosts = dir.path().join("known_hosts");
    let config = dir.path().join("ssh_config");
    std::fs::write(&known_hosts, known_hosts_entry(JUMP_ALIAS, &jump_key)?)
        .map_err(|e| CoreError::Transport(format!("writing staged known_hosts: {e}")))?;
    std::fs::write(
        &config,
        render_ssh_config(&normalized, route, &known_hosts, false),
    )
    .map_err(|e| CoreError::Transport(format!("writing staged ssh_config: {e}")))?;

    let target_port = transport.port.to_string();
    let remote_scan = format!(
        "ssh-keyscan {}",
        vpnctl_host_fingerprint::build_keyscan_args(&target_port, &transport.host).join(" ")
    );
    let stage_args = vec![
        "-F".to_string(),
        config.to_string_lossy().into_owned(),
        "--".to_string(),
        JUMP_ALIAS.to_string(),
        remote_scan,
    ];
    let mut stage = Command::new("ssh");
    stage.args(stage_args);
    let target_scan = run_child_with_timeout(
        stage,
        None,
        transport.timeout,
        &format!("pinned jump scan via {}:{}", route.host, route.port),
    )?;
    let target_key =
        matching_raw_key(&target_scan, &route.target_fingerprint)?.ok_or_else(|| {
            CoreError::Transport(format!(
                "target host {}:{} did not present its pinned host key",
                transport.host, transport.port
            ))
        })?;

    let entries = format!(
        "{}{}",
        known_hosts_entry(JUMP_ALIAS, &jump_key)?,
        known_hosts_entry(TARGET_ALIAS, &target_key)?
    );
    std::fs::write(&known_hosts, entries)
        .map_err(|e| CoreError::Transport(format!("writing final known_hosts: {e}")))?;
    std::fs::write(
        &config,
        render_ssh_config(&normalized, route, &known_hosts, true),
    )
    .map_err(|e| CoreError::Transport(format!("writing final ssh_config: {e}")))?;

    Ok(PreparedJump { _dir: dir, config })
}

fn validate_pinned_jump(transport: &SubprocessSshTransport, route: &PinnedJumpRoute) -> Result<()> {
    for (label, value) in [
        ("target host", transport.host.as_str()),
        ("jump host", route.host.as_str()),
    ] {
        if value.is_empty()
            || !value.bytes().all(|b| {
                b.is_ascii_alphanumeric()
                    || matches!(b, b'.' | b'-' | b'_' | b':' | b'%' | b'[' | b']')
            })
        {
            return Err(CoreError::Transport(format!("invalid {label}")));
        }
    }
    for (label, value) in [
        ("target user", transport.user.as_str()),
        ("jump user", route.user.as_str()),
    ] {
        if value.is_empty()
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        {
            return Err(CoreError::Transport(format!("invalid {label}")));
        }
    }
    if transport.port == 0 || route.port == 0 {
        return Err(CoreError::Transport("SSH ports must be non-zero".into()));
    }
    for (label, fingerprint) in [
        ("jump", route.jump_fingerprint.as_str()),
        ("target", route.target_fingerprint.as_str()),
    ] {
        if vpnctl_host_fingerprint::canonicalize_sha256(fingerprint).as_deref() != Some(fingerprint)
        {
            return Err(CoreError::Transport(format!(
                "{label} fingerprint is not canonical SHA256"
            )));
        }
    }
    identity_path_for_config(&transport.key_path)?;
    Ok(())
}

fn run_keyscan(host: &str, port: u16) -> Result<Vec<u8>> {
    let port = port.to_string();
    let output = Command::new("ssh-keyscan")
        .args(vpnctl_host_fingerprint::build_keyscan_args(&port, host))
        .stdin(Stdio::null())
        .output()
        .map_err(|e| CoreError::Transport(format!("spawning ssh-keyscan for pinned host: {e}")))?;
    if !output.status.success() {
        return Err(CoreError::Transport(format!(
            "ssh-keyscan for pinned host failed: exit={:?}",
            output.status.code()
        )));
    }
    if output.stdout.is_empty() {
        return Err(CoreError::Transport(
            "ssh-keyscan for pinned host returned no keys".into(),
        ));
    }
    Ok(output.stdout)
}

fn matching_raw_key(scan: &[u8], expected: &str) -> Result<Option<String>> {
    use std::io::Write;

    let mut child = Command::new("ssh-keygen")
        .args(["-lf", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| CoreError::Transport(format!("spawning ssh-keygen for pinned host: {e}")))?;
    child
        .stdin
        .take()
        .ok_or_else(|| CoreError::Transport("ssh-keygen stdin pipe unavailable".into()))?
        .write_all(scan)
        .map_err(|e| CoreError::Transport(format!("writing ssh-keygen input: {e}")))?;
    let output = child
        .wait_with_output()
        .map_err(|e| CoreError::Transport(format!("waiting for ssh-keygen: {e}")))?;
    if !output.status.success() {
        return Err(CoreError::Transport(format!(
            "ssh-keygen fingerprinting failed: exit={:?}",
            output.status.code()
        )));
    }
    let fingerprints = vpnctl_host_fingerprint::extract_all_sha256_tokens(
        &String::from_utf8_lossy(&output.stdout),
    );
    select_matching_raw_key(&String::from_utf8_lossy(scan), &fingerprints, expected)
}

fn select_matching_raw_key(
    scan: &str,
    fingerprints: &[String],
    expected: &str,
) -> Result<Option<String>> {
    let lines: Vec<&str> = scan
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    if lines.len() != fingerprints.len() {
        return Err(CoreError::Transport(
            "ssh-keyscan keys did not align with ssh-keygen fingerprints".into(),
        ));
    }
    Ok(lines
        .into_iter()
        .zip(fingerprints)
        .find(|(_, fingerprint)| vpnctl_host_fingerprint::fingerprints_match(expected, fingerprint))
        .map(|(line, _)| line.to_string()))
}

fn known_hosts_entry(alias: &str, raw_key: &str) -> Result<String> {
    let (_, key) = raw_key.split_once(char::is_whitespace).ok_or_else(|| {
        CoreError::Transport("ssh-keyscan returned a malformed host key line".into())
    })?;
    Ok(format!("{alias} {}\n", key.trim_start()))
}

fn render_ssh_config(
    transport: &SubprocessSshTransport,
    route: &PinnedJumpRoute,
    known_hosts: &Path,
    include_target: bool,
) -> String {
    let identity = config_quote(&transport.key_path.to_string_lossy());
    let known_hosts = config_quote(&known_hosts.to_string_lossy());
    let common = format!(
        "  IdentityFile {identity}\n  IdentitiesOnly yes\n  BatchMode yes\n  StrictHostKeyChecking yes\n  UserKnownHostsFile {known_hosts}\n  GlobalKnownHostsFile /dev/null\n  UpdateHostKeys no\n  ConnectTimeout 10\n  ServerAliveInterval 15\n  ServerAliveCountMax 2\n"
    );
    let mut config = format!(
        "Host {JUMP_ALIAS}\n  HostName {}\n  User {}\n  Port {}\n  HostKeyAlias {JUMP_ALIAS}\n{common}",
        route.host, route.user, route.port
    );
    if include_target {
        config.push_str(&format!(
            "Host {TARGET_ALIAS}\n  HostName {}\n  User {}\n  Port {}\n  HostKeyAlias {TARGET_ALIAS}\n  ProxyJump {JUMP_ALIAS}\n{common}",
            transport.host, transport.user, transport.port
        ));
    }
    config
}

fn config_quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

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

    async fn exec_unprivileged(&self, cmd: &str) -> Result<String> {
        SubprocessSshTransport::exec_unprivileged(self, cmd).await
    }

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

pub fn ssh_safety_opts(known_hosts: &std::path::Path, require_pinned: bool) -> Vec<String> {
    vec![
        "-o".into(),
        if require_pinned {
            "StrictHostKeyChecking=yes".into()
        } else {
            "StrictHostKeyChecking=accept-new".into()
        },
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

pub fn public_key_path(private_path: &Path) -> PathBuf {
    let mut pub_path = private_path.as_os_str().to_os_string();
    pub_path.push(".pub");
    PathBuf::from(pub_path)
}

pub fn read_public_key(private_path: &Path) -> std::io::Result<String> {
    let pub_path = public_key_path(private_path);
    let raw = std::fs::read_to_string(&pub_path)?;
    Ok(raw.trim_end().to_string())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const FP_A: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const FP_B: &str = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

    fn make_transport() -> SubprocessSshTransport {
        SubprocessSshTransport::new("203.0.113.7", "root", PathBuf::from("/tmp/test-key"))
            .port(2222)
    }

    fn route() -> PinnedJumpRoute {
        PinnedJumpRoute {
            host: "198.51.100.4".into(),
            user: "bastion".into(),
            port: 2200,
            jump_fingerprint: FP_A.into(),
            target_fingerprint: FP_B.into(),
        }
    }

    #[test]
    fn direct_ssh_args_retain_existing_tofu_behavior() {
        let args = make_transport().build_direct_ssh_args("uname -a");
        let joined = args.join(" ");
        assert!(joined.contains("-i /tmp/test-key -p 2222"));
        assert!(joined.contains("StrictHostKeyChecking=accept-new"));
        assert_eq!(args[args.len() - 2], "root@203.0.113.7");
        assert_eq!(args.last().map(String::as_str), Some("uname -a"));
    }

    #[test]
    fn pinned_route_validation_rejects_unsafe_or_unpinned_fields() {
        let transport = make_transport();
        assert!(validate_pinned_jump(&transport, &route()).is_ok());

        let mut invalid = route();
        invalid.host = "bad;host".into();
        assert!(validate_pinned_jump(&transport, &invalid).is_err());

        let mut invalid = route();
        invalid.target_fingerprint = "SHA256:short".into();
        assert!(validate_pinned_jump(&transport, &invalid).is_err());

        let mut invalid = route();
        invalid.port = 0;
        assert!(validate_pinned_jump(&transport, &invalid).is_err());
    }

    #[test]
    fn exact_raw_key_is_retained_for_matching_fingerprint() {
        let scan = "host ssh-ed25519 EXACT-RAW-A\nhost ssh-rsa EXACT-RAW-B\n";
        let fingerprints = vec![FP_A.into(), FP_B.into()];
        assert_eq!(
            select_matching_raw_key(scan, &fingerprints, FP_B).unwrap(),
            Some("host ssh-rsa EXACT-RAW-B".into())
        );
    }

    #[test]
    fn generated_config_pins_both_aliases_and_proxyjump() {
        let transport = make_transport();
        let config = render_ssh_config(
            &transport,
            &route(),
            Path::new("/tmp/private/known_hosts"),
            true,
        );
        for required in [
            "Host vpnctl-pinned-jump",
            "HostKeyAlias vpnctl-pinned-jump",
            "Host vpnctl-pinned-target",
            "HostKeyAlias vpnctl-pinned-target",
            "ProxyJump vpnctl-pinned-jump",
            "StrictHostKeyChecking yes",
            "GlobalKnownHostsFile /dev/null",
            "UpdateHostKeys no",
            "UserKnownHostsFile \"/tmp/private/known_hosts\"",
        ] {
            assert!(config.contains(required), "missing {required:?}: {config}");
        }
        assert!(!config.contains("accept-new"));
    }

    #[test]
    fn final_jump_args_use_only_private_config_and_target_alias() {
        let dir = TempDir::new().unwrap();
        let prepared = PreparedJump {
            config: dir.path().join("ssh_config"),
            _dir: dir,
        };
        let args = prepared.final_args("uname -a");
        assert_eq!(args[0], "-F");
        assert_eq!(args[2..], ["--", TARGET_ALIAS, "uname -a"]);
        assert!(!args.iter().any(|arg| arg == "-J" || arg == "-i"));
    }

    #[test]
    fn known_hosts_entry_replaces_only_scanned_host_token() {
        assert_eq!(
            known_hosts_entry(TARGET_ALIAS, "[10.0.0.1]:22 ssh-ed25519 RAWKEY").unwrap(),
            "vpnctl-pinned-target ssh-ed25519 RAWKEY\n"
        );
    }

    #[test]
    fn root_and_non_root_privileged_commands_are_preserved() {
        assert_eq!(make_transport().privileged_command("id -u"), "id -u");
        let transport =
            SubprocessSshTransport::new("203.0.113.7", "debian", PathBuf::from("/tmp/test-key"));
        assert_eq!(
            transport.privileged_command("printf '%s' \"$HOME\""),
            "sudo -n sh -c 'printf '\\''%s'\\'' \"$HOME\"'"
        );
    }
}
