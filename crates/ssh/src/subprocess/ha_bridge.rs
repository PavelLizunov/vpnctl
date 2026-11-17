use std::io::Read;
use std::path::Path;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64_STANDARD;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use vpnctl_core::{CoreError, PinnedJumpRoute, Result};

use super::SubprocessSshTransport;

const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;
const MAX_TIMEOUT_MS: u64 = 3_600_000;
static KNOWN_HOSTS_UPDATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    host: String,
    user: String,
    port: u16,
    jump: Option<PinnedJumpRoute>,
    target_fingerprint: Option<String>,
    timeout_ms: u64,
    known_hosts_b64: Option<String>,
    operation: Operation,
    remote_cmd: String,
    stdin_b64: Option<String>,
    password: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Operation {
    Exec,
    ExecPassword,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    ok: bool,
    stdout_b64: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    known_hosts_b64: Option<String>,
}

fn transport_error(message: impl Into<String>) -> CoreError {
    CoreError::Transport(format!("HA executor: {}", message.into()))
}

fn encode_frame(value: &impl Serialize) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value)
        .map_err(|e| transport_error(format!("encoding JSON frame: {e}")))?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(transport_error("JSON frame exceeds 64 MiB"));
    }
    Ok(bytes)
}

fn decode_bytes(value: &str, field: &str) -> Result<Vec<u8>> {
    B64_STANDARD
        .decode(value)
        .map_err(|_| transport_error(format!("invalid base64 in {field}")))
}

fn read_known_hosts(path: &Path) -> Result<Option<Vec<u8>>> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(transport_error(format!("reading known_hosts: {e}"))),
    };
    let mut bytes = Vec::new();
    file.take((MAX_FRAME_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| transport_error(format!("reading known_hosts: {e}")))?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(transport_error("known_hosts exceeds 64 MiB"));
    }
    Ok(Some(bytes))
}

fn write_known_hosts(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut staged = tempfile::NamedTempFile::new_in(parent)
        .map_err(|e| transport_error(format!("staging known_hosts update: {e}")))?;
    staged
        .write_all(bytes)
        .and_then(|()| staged.as_file().sync_all())
        .map_err(|e| transport_error(format!("writing known_hosts update: {e}")))?;
    staged
        .persist(path)
        .map_err(|e| transport_error(format!("installing known_hosts update: {e}")))?;
    Ok(())
}

fn apply_known_hosts_update(path: &Path, original: Option<&[u8]>, updated: &[u8]) -> Result<()> {
    let _guard = KNOWN_HOSTS_UPDATE
        .lock()
        .map_err(|_| transport_error("known_hosts update lock is poisoned"))?;
    let current = read_known_hosts(path)?;
    if current.as_deref() == original {
        return write_known_hosts(path, updated);
    }
    let appended = updated
        .strip_prefix(original.unwrap_or_default())
        .ok_or_else(|| transport_error("conflicting concurrent known_hosts rewrite"))?;
    let mut merged = current.unwrap_or_default();
    if !merged.is_empty() && !merged.ends_with(b"\n") && !appended.is_empty() {
        merged.push(b'\n');
    }
    merged.extend_from_slice(appended);
    if merged.len() > MAX_FRAME_BYTES {
        return Err(transport_error("merged known_hosts exceeds 64 MiB"));
    }
    write_known_hosts(path, &merged)
}

pub(super) async fn execute(
    transport: &SubprocessSshTransport,
    socket: &Path,
    remote_cmd: &str,
    stdin: Option<Vec<u8>>,
    password: Option<&str>,
) -> Result<Vec<u8>> {
    let timeout_ms = u64::try_from(transport.timeout.as_millis())
        .ok()
        .filter(|value| (1..=MAX_TIMEOUT_MS).contains(value))
        .ok_or_else(|| transport_error("timeout_ms must be in 1..=3600000"))?;
    let known_hosts = read_known_hosts(&transport.known_hosts)?;
    let request = Request {
        host: transport.host.clone(),
        user: transport.user.clone(),
        port: transport.port,
        jump: transport.jump.clone(),
        target_fingerprint: transport.target_fingerprint.clone(),
        timeout_ms,
        known_hosts_b64: known_hosts.as_ref().map(|bytes| B64_STANDARD.encode(bytes)),
        operation: if password.is_some() {
            Operation::ExecPassword
        } else {
            Operation::Exec
        },
        remote_cmd: remote_cmd.to_string(),
        stdin_b64: stdin.map(|bytes| B64_STANDARD.encode(bytes)),
        password: password.map(str::to_string),
    };
    let frame = encode_frame(&request)?;
    // Pinned jump setup can execute a scan and then the command, each bounded
    // by the transport timeout, plus two locally bounded key scans.
    let deadline = Duration::from_millis(timeout_ms * 2 + 90_000);
    let response = tokio::time::timeout(deadline, exchange(socket, &frame))
        .await
        .map_err(|_| transport_error("socket deadline exceeded; outcome unknown, never retry"))??;
    let response: Response = serde_json::from_slice(&response)
        .map_err(|e| transport_error(format!("invalid response JSON: {e}")))?;
    if !response.ok {
        return Err(transport_error(response.error.unwrap_or_else(|| {
            "request failed without an error description".into()
        })));
    }
    if response.error.is_some() {
        return Err(transport_error("success response contains an error"));
    }
    let stdout = decode_bytes(&response.stdout_b64, "stdout_b64")?;
    if let Some(updated) = response.known_hosts_b64 {
        apply_known_hosts_update(
            &transport.known_hosts,
            known_hosts.as_deref(),
            &decode_bytes(&updated, "known_hosts_b64")?,
        )?;
    }
    Ok(stdout)
}

async fn exchange(socket: &Path, request: &[u8]) -> Result<Vec<u8>> {
    let mut stream = UnixStream::connect(socket)
        .await
        .map_err(|e| transport_error(format!("connecting private socket: {e}")))?;
    stream
        .write_all(request)
        .await
        .map_err(|e| transport_error(format!("sending request; outcome unknown: {e}")))?;
    stream
        .write_all(b"\n")
        .await
        .map_err(|e| transport_error(format!("sending request delimiter; outcome unknown: {e}")))?;
    stream
        .shutdown()
        .await
        .map_err(|e| transport_error(format!("closing request; outcome unknown: {e}")))?;
    read_frame(&mut stream).await
}

async fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>> {
    let mut frame = Vec::new();
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let count = stream
            .read(&mut buffer)
            .await
            .map_err(|e| transport_error(format!("receiving response; outcome unknown: {e}")))?;
        if count == 0 {
            return Err(transport_error(
                "socket closed before response delimiter; outcome unknown",
            ));
        }
        let end = buffer[..count].iter().position(|byte| *byte == b'\n');
        let length = end.unwrap_or(count);
        if frame.len() + length > MAX_FRAME_BYTES {
            return Err(transport_error("response exceeds 64 MiB; outcome unknown"));
        }
        frame.extend_from_slice(&buffer[..length]);
        if let Some(end) = end {
            if end + 1 != count {
                return Err(transport_error("unexpected data after response delimiter"));
            }
            return Ok(frame);
        }
    }
}

/// Execute one bounded HA transport request on the independent witness.
///
/// Input is a single JSON request, at most 64 MiB, using flat transport fields
/// (`host`, `user`, `port`, optional `jump` and `target_fingerprint`, `timeout_ms`,
/// optional `known_hosts_b64`) and an `exec` or `exec_password` operation with
/// `remote_cmd`, optional `stdin_b64` and optional `password`. Timeout is
/// 1..=3_600_000 milliseconds. Password operations require a password and reject
/// stdin; ordinary operations reject passwords. Unknown top-level fields are rejected.
///
/// The deploy key comes exclusively from `VPNCTLD_DEPLOY_KEY`. Invocation while
/// `VPNCTLD_HA_EXECUTOR_SOCKET` is present is rejected before any dispatch. The
/// helper stages known_hosts privately and uses the ordinary pinned/TOFU SSH
/// paths exactly once. It never retries. Output is JSON with `ok`, `stdout_b64`,
/// optional `error`, and successful changed `known_hosts_b64`. Invalid requests
/// return an error; a dispatched transport failure returns `ok: false`.
pub async fn handle_ha_execute_request(bytes: &[u8]) -> Result<Vec<u8>> {
    if std::env::var_os("VPNCTLD_HA_EXECUTOR_SOCKET").is_some() {
        return Err(transport_error(
            "helper invocation in broker mode is forbidden",
        ));
    }
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(transport_error("request exceeds 64 MiB"));
    }
    let request: Request = serde_json::from_slice(bytes)
        .map_err(|e| transport_error(format!("invalid request JSON: {e}")))?;
    if !(1..=MAX_TIMEOUT_MS).contains(&request.timeout_ms) {
        return Err(transport_error("timeout_ms must be in 1..=3600000"));
    }
    if request.user.starts_with('-') {
        return Err(transport_error("target user cannot begin with a dash"));
    }
    super::validate_endpoint(
        "target host",
        &request.host,
        "target user",
        &request.user,
        request.port,
    )?;
    match request.operation {
        Operation::Exec if request.password.is_some() => {
            return Err(transport_error("exec cannot contain a password"));
        }
        Operation::ExecPassword if request.password.is_none() || request.stdin_b64.is_some() => {
            return Err(transport_error(
                "exec_password requires a password and forbids stdin",
            ));
        }
        _ => {}
    }
    let deploy_key = std::env::var_os("VPNCTLD_DEPLOY_KEY")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| transport_error("VPNCTLD_DEPLOY_KEY is required on the witness"))?;
    let known_hosts = request
        .known_hosts_b64
        .as_deref()
        .map(|value| decode_bytes(value, "known_hosts_b64"))
        .transpose()?
        .unwrap_or_default();
    let stdin = request
        .stdin_b64
        .as_deref()
        .map(|value| decode_bytes(value, "stdin_b64"))
        .transpose()?;
    use std::os::unix::fs::PermissionsExt;

    let staging = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .prefix("vpnctl-ha-execute-")
        .tempdir()
        .map_err(|e| transport_error(format!("creating private staging: {e}")))?;
    let known_hosts_path = staging.path().join("known_hosts");
    write_known_hosts(&known_hosts_path, &known_hosts)?;
    let transport = SubprocessSshTransport::new(request.host, request.user, deploy_key.into())
        .port(request.port)
        .with_jump(request.jump)
        .trusted_fingerprint(request.target_fingerprint)
        .known_hosts(known_hosts_path.clone())
        .timeout(Duration::from_millis(request.timeout_ms));
    let output = match request.operation {
        Operation::Exec => transport.run_local(request.remote_cmd, stdin).await,
        Operation::ExecPassword => {
            transport
                .exec_password_local_bytes(
                    request.password.as_deref().unwrap_or_default(),
                    &request.remote_cmd,
                )
                .await
        }
    };
    let response = match output {
        Ok(stdout) => {
            let updated = read_known_hosts(&known_hosts_path)?.unwrap_or_default();
            Response {
                ok: true,
                stdout_b64: B64_STANDARD.encode(stdout),
                error: None,
                known_hosts_b64: (updated != known_hosts).then(|| B64_STANDARD.encode(updated)),
            }
        }
        Err(error) => Response {
            ok: false,
            stdout_b64: String::new(),
            error: Some(error.to_string()),
            known_hosts_b64: None,
        },
    };
    encode_frame(&response)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use tokio::net::UnixListener;
    use vpnctl_core::SshTransport;

    fn transport(dir: &Path) -> SubprocessSshTransport {
        SubprocessSshTransport::new("203.0.113.19", "operator", dir.join("unselected-key"))
            .port(2202)
            .known_hosts(dir.join("known_hosts"))
            .timeout(Duration::from_millis(5))
    }

    #[tokio::test]
    async fn password_helper_keeps_binary_stdout_and_public_string_behavior() {
        const OUTPUT: &[u8] = b"\0\xffraw\x80\n";
        if let Some(dir) = std::env::var_os("VPNCTL_TEST_HA_PASSWORD_DIR") {
            let dir = Path::new(&dir);
            let request = Request {
                host: "203.0.113.19".into(),
                user: "root".into(),
                port: 2222,
                jump: None,
                target_fingerprint: None,
                timeout_ms: 1000,
                known_hosts_b64: None,
                operation: Operation::ExecPassword,
                remote_cmd: "placeholder command".into(),
                stdin_b64: None,
                password: Some("placeholder-password".into()),
            };
            let response = handle_ha_execute_request(&encode_frame(&request).unwrap())
                .await
                .unwrap();
            let response: Response = serde_json::from_slice(&response).unwrap();
            assert!(response.ok);
            assert_eq!(B64_STANDARD.decode(response.stdout_b64).unwrap(), OUTPUT);
            assert_eq!(std::fs::read(dir.join("calls")).unwrap(), b"call\n");
            let transport = transport(dir).timeout(Duration::from_secs(1));
            assert_eq!(
                transport
                    .exec_password("placeholder-password", "placeholder command")
                    .await
                    .unwrap(),
                String::from_utf8_lossy(OUTPUT)
            );
            assert_eq!(std::fs::read(dir.join("calls")).unwrap(), b"call\ncall\n");
            return;
        }
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let sshpass = dir.path().join("sshpass");
        std::fs::write(
            &sshpass,
            "#!/bin/sh\nprintf '\\000\\377raw\\200\\n'\nprintf 'call\\n' >> \"$VPNCTL_TEST_HA_PASSWORD_CALLS\"\n",
        ).unwrap();
        std::fs::set_permissions(&sshpass, std::fs::Permissions::from_mode(0o700)).unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "subprocess::ha_bridge::tests::password_helper_keeps_binary_stdout_and_public_string_behavior",
                "--nocapture",
            ])
            .env("VPNCTL_TEST_HA_PASSWORD_DIR", dir.path())
            .env("VPNCTL_TEST_HA_PASSWORD_CALLS", dir.path().join("calls"))
            .env("VPNCTLD_DEPLOY_KEY", dir.path().join("unselected-key"))
            .env("PATH", dir.path())
            .env_remove("VPNCTLD_HA_EXECUTOR_SOCKET")
            .env_remove("VPNCTLD_HA_KNOWN_HOSTS")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn concurrent_known_hosts_additions_survive_and_conflicting_rewrites_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        std::fs::write(&path, b"original\n").unwrap();
        apply_known_hosts_update(&path, Some(b"original\n"), b"original\nfirst\n").unwrap();
        apply_known_hosts_update(&path, Some(b"original\n"), b"original\nsecond\n").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"original\nfirst\nsecond\n");
        let error =
            apply_known_hosts_update(&path, Some(b"original\n"), b"replacement\n").unwrap_err();
        assert!(error.to_string().contains("conflicting concurrent"));
        assert_eq!(std::fs::read(&path).unwrap(), b"original\nfirst\nsecond\n");
    }

    #[tokio::test]
    async fn broker_routes_every_public_transport_operation() {
        if let Some(dir) = std::env::var_os("VPNCTL_HA_ROUTE_TEST_DIR") {
            let transport = transport(Path::new(&dir));
            assert_eq!(transport.exec("privileged").await.unwrap(), "reply");
            assert_eq!(
                transport
                    .exec_with_stdin("stdin", b"\0\xff".to_vec())
                    .await
                    .unwrap(),
                b"reply"
            );
            assert_eq!(transport.exec_unprivileged("plain").await.unwrap(), "reply");
            assert_eq!(
                SshTransport::exec_unprivileged(&transport, "trait plain")
                    .await
                    .unwrap(),
                "reply"
            );
            transport.upload("/placeholder", b"\0\xff").await.unwrap();
            assert_eq!(
                transport.read_file("/placeholder").await.unwrap(),
                b"\0\xff"
            );
            assert_eq!(
                transport
                    .exec_password("placeholder-password", "bootstrap")
                    .await
                    .unwrap(),
                "reply"
            );
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("executor.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        // A child test process provides isolated environment state; no unsafe
        // process-wide environment mutation can race the rest of the suite.
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "subprocess::ha_bridge::tests::broker_routes_every_public_transport_operation",
                "--nocapture",
            ])
            .env("VPNCTL_HA_ROUTE_TEST_DIR", dir.path())
            .env("VPNCTLD_HA_EXECUTOR_SOCKET", &socket)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        for index in 0..7 {
            let (mut peer, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
                .await
                .unwrap()
                .unwrap();
            let request: Request =
                serde_json::from_slice(&read_frame(&mut peer).await.unwrap()).unwrap();
            match index {
                0 => assert_eq!(request.remote_cmd, "sudo -n sh -c 'privileged'"),
                1 => {
                    assert_eq!(request.remote_cmd, "stdin");
                    assert_eq!(request.stdin_b64.as_deref(), Some("AP8="));
                }
                2 => assert_eq!(request.remote_cmd, "plain"),
                3 => assert_eq!(request.remote_cmd, "trait plain"),
                4 => {
                    assert!(request.remote_cmd.starts_with("sudo -n sh -c "));
                    assert_eq!(request.stdin_b64.as_deref(), Some("QVA4PQ=="));
                }
                5 => assert!(request.remote_cmd.contains("base64 < ")),
                6 => {
                    assert!(matches!(request.operation, Operation::ExecPassword));
                    assert_eq!(request.password.as_deref(), Some("placeholder-password"));
                }
                _ => unreachable!(),
            }
            let stdout = if index == 5 {
                b"AP8=".as_slice()
            } else {
                b"reply".as_slice()
            };
            let response = Response {
                ok: true,
                stdout_b64: B64_STANDARD.encode(stdout),
                error: None,
                known_hosts_b64: None,
            };
            peer.write_all(&encode_frame(&response).unwrap())
                .await
                .unwrap();
            peer.write_all(b"\n").await.unwrap();
        }
        let output = tokio::task::spawn_blocking(move || child.wait_with_output())
            .await
            .unwrap()
            .unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[tokio::test]
    async fn broker_preserves_bytes_transport_pins_and_changed_known_hosts() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("executor.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        std::fs::write(dir.path().join("known_hosts"), b"old host entry\n").unwrap();
        let broker = tokio::spawn(async move {
            let (mut peer, _) = listener.accept().await.unwrap();
            let bytes = read_frame(&mut peer).await.unwrap();
            let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert!(value.get("key_path").is_none());
            assert_eq!(value["host"], "203.0.113.19");
            assert_eq!(value["user"], "operator");
            assert_eq!(value["port"], 2202);
            assert_eq!(value["operation"], "exec");
            assert_eq!(value["remote_cmd"], "already privileged command");
            assert_eq!(value["target_fingerprint"], "test-inventory-pin");
            assert_eq!(value["jump"]["host"], "198.51.100.8");
            assert_eq!(value["timeout_ms"], 5);
            assert_eq!(value["stdin_b64"], B64_STANDARD.encode(b"\0\xffinput"));
            assert_eq!(
                value["known_hosts_b64"],
                B64_STANDARD.encode(b"old host entry\n")
            );
            let response = Response {
                ok: true,
                stdout_b64: B64_STANDARD.encode(b"\0\xffoutput"),
                error: None,
                known_hosts_b64: Some(B64_STANDARD.encode(b"old host entry\nnew host entry\n")),
            };
            peer.write_all(&encode_frame(&response).unwrap())
                .await
                .unwrap();
            peer.write_all(b"\n").await.unwrap();
        });
        let transport = transport(dir.path())
            .trusted_fingerprint(Some("test-inventory-pin".into()))
            .with_jump(Some(PinnedJumpRoute {
                host: "198.51.100.8".into(),
                user: "jump".into(),
                port: 2222,
                jump_fingerprint: "test-jump-pin".into(),
                target_fingerprint: "test-target-pin".into(),
            }));
        let output = execute(
            &transport,
            &socket,
            "already privileged command",
            Some(b"\0\xffinput".to_vec()),
            None,
        )
        .await
        .unwrap();
        broker.await.unwrap();
        assert_eq!(output, b"\0\xffoutput");
        assert_eq!(
            std::fs::read(&transport.known_hosts).unwrap(),
            b"old host entry\nnew host entry\n"
        );
    }

    #[tokio::test]
    async fn failed_password_request_never_applies_known_hosts_or_retries() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("executor.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let broker = tokio::spawn(async move {
            let (mut peer, _) = listener.accept().await.unwrap();
            let request: Request =
                serde_json::from_slice(&read_frame(&mut peer).await.unwrap()).unwrap();
            assert!(matches!(request.operation, Operation::ExecPassword));
            assert_eq!(request.password.as_deref(), Some("placeholder-password"));
            assert!(request.stdin_b64.is_none());
            let response = Response {
                ok: false,
                stdout_b64: String::new(),
                error: Some("dispatch outcome unknown: job-placeholder".into()),
                known_hosts_b64: Some(B64_STANDARD.encode(b"must not be installed")),
            };
            peer.write_all(&encode_frame(&response).unwrap())
                .await
                .unwrap();
            peer.write_all(b"\n").await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(50), listener.accept())
                    .await
                    .is_err()
            );
        });
        let transport = transport(dir.path());
        let error = execute(
            &transport,
            &socket,
            "id",
            None,
            Some("placeholder-password"),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("job-placeholder"));
        assert!(!transport.known_hosts.exists());
        broker.await.unwrap();
    }

    #[tokio::test]
    async fn missing_socket_is_an_error_without_direct_transport_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let error = execute(
            &transport(dir.path()),
            &dir.path().join("absent.sock"),
            "id",
            None,
            None,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("connecting private socket"));
    }

    #[tokio::test]
    async fn unterminated_response_is_uncertain_instead_of_success() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        server
            .write_all(br#"{"ok":true,"stdout_b64":""}"#)
            .await
            .unwrap();
        server.shutdown().await.unwrap();
        let error = read_frame(&mut client).await.unwrap_err();
        assert!(error.to_string().contains("outcome unknown"));
    }

    #[tokio::test]
    async fn frame_exactly_at_limit_is_accepted_but_one_more_byte_is_rejected() {
        for length in [MAX_FRAME_BYTES, MAX_FRAME_BYTES + 1] {
            let (mut client, mut server) = UnixStream::pair().unwrap();
            let writer = tokio::spawn(async move {
                let bytes = vec![b'x'; length];
                if server.write_all(&bytes).await.is_ok() {
                    let _ = server.write_all(b"\n").await;
                }
            });
            let result = read_frame(&mut client).await;
            drop(client);
            writer.await.unwrap();
            if length == MAX_FRAME_BYTES {
                assert_eq!(result.unwrap().len(), length);
            } else {
                assert!(result.unwrap_err().to_string().contains("exceeds 64 MiB"));
            }
        }
    }
}
