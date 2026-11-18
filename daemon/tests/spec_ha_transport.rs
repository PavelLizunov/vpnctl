#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use tempfile::TempDir;

    const BINARY_STDOUT: &[u8] = b"\0\xffha\x80\n";
    const BINARY_STDIN: &[u8] = b"\0input\xff\n";

    struct Fixture {
        root: TempDir,
        key: PathBuf,
        known_host: String,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().expect("temporary test directory");
            let key = root.path().join("executor_key");
            let generated = Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                .arg(&key)
                .output()
                .expect("generate an isolated test key");
            assert!(generated.status.success(), "ssh-keygen failed");
            let public_key =
                fs::read_to_string(key.with_extension("pub")).expect("test public key");
            let mut public_fields = public_key.split_whitespace();
            let kind = public_fields.next().expect("public key kind");
            let material = public_fields.next().expect("public key material");
            let known_host = format!("127.0.0.1 {kind} {material}\n");

            let ssh = root.path().join("ssh");
            fs::write(
                &ssh,
                r#"#!/usr/bin/python3
import json, os, pathlib, stat, sys
root = pathlib.Path(os.environ['SPEC_HA_FIXTURE_ROOT'])
with (root / 'calls').open('ab') as calls:
    calls.write(b'called\n')
args = sys.argv[1:]
known_hosts = next((arg.split('=', 1)[1] for arg in args
                    if arg.startswith('UserKnownHostsFile=')), None)
metadata = {'args': args, 'known_hosts': known_hosts}
if known_hosts is not None:
    metadata['directory_mode'] = stat.S_IMODE(os.stat(os.path.dirname(known_hosts)).st_mode)
    pathlib.Path(known_hosts).write_bytes(os.environ['SPEC_HA_KNOWN_HOST'].encode())
(root / 'ssh_metadata.json').write_text(json.dumps(metadata))
(root / 'stdin').write_bytes(sys.stdin.buffer.read())
sys.stdout.buffer.write(b'\x00\xffha\x80\n')
sys.stdout.buffer.flush()
if os.environ.get('SPEC_HA_SSH_FAIL') == 'yes':
    sys.stderr.write('isolated transport failure\n')
    sys.exit(17)
"#,
            )
            .expect("fake ssh executable");
            fs::set_permissions(&ssh, fs::Permissions::from_mode(0o700))
                .expect("executable fixture permissions");
            let sshpass = root.path().join("sshpass");
            fs::write(
            &sshpass,
            "#!/usr/bin/python3\nimport os, sys\nassert sys.argv[1] == '-e'\nos.execvp(sys.argv[2], sys.argv[2:])\n",
        )
        .expect("password transport wrapper fixture");
            fs::set_permissions(&sshpass, fs::Permissions::from_mode(0o700))
                .expect("password wrapper executable permissions");
            Self {
                root,
                key,
                known_host,
            }
        }

        fn command(&self, executable: impl AsRef<Path>) -> Command {
            let mut command = Command::new(executable.as_ref());
            let path = std::env::join_paths(std::iter::once(self.root.path().to_owned()).chain(
                std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()),
            ))
            .expect("fixture PATH");
            command
                .current_dir(self.root.path())
                .env("PATH", path)
                .env("VPNCTLD_DEPLOY_KEY", &self.key)
                .env("SPEC_HA_FIXTURE_ROOT", self.root.path())
                .env("SPEC_HA_KNOWN_HOST", &self.known_host)
                .env_remove("VPNCTLD_HA_EXECUTOR_SOCKET")
                .env_remove("SPEC_HA_SSH_FAIL");
            command
        }

        fn run_handler(&self, request: &[u8], settings: &[(&str, Option<&str>)]) -> Value {
            let request_path = self.root.path().join("request.json");
            let result_path = self.root.path().join("result.json");
            fs::write(&request_path, request).expect("child request");
            let mut child =
                self.command(std::env::current_exe().expect("integration test executable"));
            child
                .args(["--exact", "tests::ha_transport_child", "--nocapture"])
                .env("SPEC_HA_REQUEST", request_path)
                .env("SPEC_HA_RESULT", &result_path);
            for (name, value) in settings {
                if let Some(value) = value {
                    child.env(name, value);
                } else {
                    child.env_remove(name);
                }
            }
            let output = child.output().expect("isolated handler process");
            assert!(
                output.status.success(),
                "handler child failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            serde_json::from_slice(&fs::read(result_path).expect("handler result"))
                .expect("result envelope")
        }

        fn assert_rejected(&self, request: &[u8], settings: &[(&str, Option<&str>)]) {
            let result = self.run_handler(request, settings);
            if !result["rejected"].is_string() {
                let returned = response(&result);
                assert_eq!(
                    returned["ok"],
                    false,
                    "accepted request {}: {returned}",
                    String::from_utf8_lossy(&request[..request.len().min(1024)])
                );
                assert_eq!(returned["stdout_b64"], "");
                assert!(returned["error"].is_string());
            }
            assert_eq!(self.calls(), 0, "invalid request dispatched SSH");
        }

        fn calls(&self) -> usize {
            fs::read(self.root.path().join("calls"))
                .unwrap_or_default()
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
                .count()
        }
    }

    fn valid_request() -> Value {
        json!({
            "host": "127.0.0.1",
            "user": "root",
            "port": 22,
            "timeout_ms": 10_000,
            "operation": "exec",
            "remote_cmd": "printf isolated-spec-test",
            "jump": null,
            "target_fingerprint": null,
            "known_hosts_b64": null,
            "stdin_b64": STANDARD.encode(BINARY_STDIN),
            "password": null
        })
    }

    fn response(envelope: &Value) -> Value {
        let encoded = envelope["returned"]
            .as_str()
            .unwrap_or_else(|| panic!("handler rejected request: {envelope}"));
        serde_json::from_slice(&STANDARD.decode(encoded).expect("returned bytes"))
            .expect("JSON transport response")
    }

    // Child-only environment settings keep the parent test process race-free and
    // avoid unsafe Rust 2024 environment mutation.
    #[tokio::test]
    async fn ha_transport_child() {
        let Some(request_path) = std::env::var_os("SPEC_HA_REQUEST") else {
            return;
        };
        let request = fs::read(request_path).expect("child request bytes");
        let result = vpnctl_ssh::subprocess::handle_ha_execute_request(&request).await;
        let envelope = match result {
            Ok(bytes) => json!({"returned": STANDARD.encode(bytes)}),
            Err(error) => json!({"rejected": error.to_string()}),
        };
        fs::write(
            std::env::var_os("SPEC_HA_RESULT").expect("child result path"),
            serde_json::to_vec(&envelope).expect("result serialization"),
        )
        .expect("write child result");
    }

    #[test]
    fn malformed_frames_and_missing_required_fields_are_rejected_before_dispatch() {
        let fixture = Fixture::new();
        for bytes in [b"".as_slice(), b"{", b"null", b"[]", b"true", b"{}"] {
            fixture.assert_rejected(bytes, &[]);
        }
        for field in [
            "host",
            "user",
            "port",
            "timeout_ms",
            "operation",
            "remote_cmd",
        ] {
            let mut request = valid_request();
            request
                .as_object_mut()
                .expect("request object")
                .remove(field);
            fixture.assert_rejected(&serde_json::to_vec(&request).expect("request JSON"), &[]);
        }
        let mut request = valid_request();
        request["remote_cmd"] = json!("x".repeat(64 * 1024 * 1024));
        fixture.assert_rejected(&serde_json::to_vec(&request).expect("oversize JSON"), &[]);
    }

    #[test]
    fn unknown_fields_and_caller_supplied_key_paths_are_rejected() {
        let fixture = Fixture::new();
        for field in [
            "unknown",
            "key",
            "private_key",
            "deploy_key",
            "key_path",
            "known_hosts_path",
            "identity_file",
        ] {
            let mut request = valid_request();
            request[field] = json!("/tmp/caller-controlled");
            fixture.assert_rejected(&serde_json::to_vec(&request).expect("request JSON"), &[]);
        }
    }

    #[test]
    fn invalid_timeouts_endpoints_types_and_base64_are_rejected() {
        let fixture = Fixture::new();
        for (field, invalid_values) in [
            (
                "timeout_ms",
                vec![json!(0), json!(3_600_001), json!(-1), json!("1")],
            ),
            (
                "port",
                vec![json!(0), json!(65_536), json!(-1), json!("22")],
            ),
            (
                "host",
                vec![
                    json!(""),
                    json!("-oProxyCommand=bad"),
                    json!("host\nnext"),
                    json!(false),
                ],
            ),
            (
                "user",
                vec![
                    json!(""),
                    json!("-lroot"),
                    json!("root\nnext"),
                    json!(false),
                ],
            ),
            ("remote_cmd", vec![json!(null), json!(42)]),
            (
                "stdin_b64",
                vec![json!("*not-base64*"), json!("-_8="), json!(17)],
            ),
            (
                "known_hosts_b64",
                vec![json!("*not-base64*"), json!("-_8="), json!(17)],
            ),
        ] {
            for value in invalid_values {
                let mut request = valid_request();
                request[field] = value;
                fixture.assert_rejected(&serde_json::to_vec(&request).expect("request JSON"), &[]);
            }
        }
    }

    #[test]
    fn invalid_jump_endpoints_are_rejected_before_dispatch() {
        let fixture = Fixture::new();
        let jump = json!({
            "host": "127.0.0.2",
            "user": "root",
            "port": 22,
            "jump_fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "target_fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        });
        for (field, value) in [
            ("host", json!("")),
            ("host", json!("-oProxyCommand=bad")),
            ("host", json!("jump\nnext")),
            ("user", json!("")),
            ("user", json!("-lroot")),
            ("user", json!("root\nnext")),
            ("port", json!(0)),
            ("port", json!(65_536)),
        ] {
            let mut request = valid_request();
            request["jump"] = jump.clone();
            request["jump"][field] = value;
            fixture.assert_rejected(&serde_json::to_vec(&request).expect("request JSON"), &[]);
        }
    }

    #[test]
    fn password_and_stdin_operation_combinations_fail_closed() {
        let fixture = Fixture::new();
        for password in [json!("password"), json!("")] {
            let mut request = valid_request();
            request["password"] = password;
            fixture.assert_rejected(&serde_json::to_vec(&request).expect("request JSON"), &[]);
        }
        for password in [None, Some(Value::Null)] {
            let mut request = valid_request();
            request["operation"] = json!("exec_password");
            request["stdin_b64"] = Value::Null;
            if let Some(password) = password {
                request["password"] = password;
            } else {
                request
                    .as_object_mut()
                    .expect("request object")
                    .remove("password");
            }
            fixture.assert_rejected(&serde_json::to_vec(&request).expect("request JSON"), &[]);
        }
        for stdin in ["", "YQ=="] {
            let mut request = valid_request();
            request["operation"] = json!("exec_password");
            request["password"] = json!("password");
            request["stdin_b64"] = json!(stdin);
            fixture.assert_rejected(&serde_json::to_vec(&request).expect("request JSON"), &[]);
        }
        let mut request = valid_request();
        request["operation"] = json!("upload");
        fixture.assert_rejected(&serde_json::to_vec(&request).expect("request JSON"), &[]);
    }

    #[test]
    fn recursive_ha_invocation_and_missing_executor_identity_never_dispatch() {
        let fixture = Fixture::new();
        let bytes = serde_json::to_vec(&valid_request()).expect("request JSON");
        for socket in ["", "/tmp/recursive-ha.sock"] {
            fixture.assert_rejected(&bytes, &[("VPNCTLD_HA_EXECUTOR_SOCKET", Some(socket))]);
        }
        fixture.assert_rejected(&bytes, &[("VPNCTLD_DEPLOY_KEY", None)]);
        fixture.assert_rejected(&bytes, &[("VPNCTLD_DEPLOY_KEY", Some(""))]);
    }

    #[test]
    fn valid_timeout_boundaries_dispatch_once_and_preserve_binary_bytes_and_trust() {
        for timeout_ms in [1, 3_600_000] {
            let fixture = Fixture::new();
            let mut request = valid_request();
            request["timeout_ms"] = json!(timeout_ms);
            // One millisecond is a valid parsing boundary; actual dispatch success
            // has a realistic deadline in the separate success case below.
            if timeout_ms == 1 {
                let result =
                    fixture.run_handler(&serde_json::to_vec(&request).expect("request JSON"), &[]);
                assert!(
                    result["returned"].is_string(),
                    "valid boundary rejected: {result}"
                );
                continue;
            }
            let result = response(
                &fixture.run_handler(&serde_json::to_vec(&request).expect("request JSON"), &[]),
            );
            assert_eq!(result["ok"], true);
            assert_eq!(
                STANDARD
                    .decode(result["stdout_b64"].as_str().expect("stdout base64"))
                    .expect("stdout"),
                BINARY_STDOUT
            );
            assert_eq!(fixture.calls(), 1);
            assert_eq!(
                fs::read(fixture.root.path().join("stdin")).expect("SSH stdin"),
                BINARY_STDIN
            );
            let known_hosts = STANDARD
                .decode(
                    result["known_hosts_b64"]
                        .as_str()
                        .expect("changed trust bytes"),
                )
                .expect("known_hosts base64");
            assert_eq!(known_hosts, fixture.known_host.as_bytes());
            let metadata: Value = serde_json::from_slice(
                &fs::read(fixture.root.path().join("ssh_metadata.json")).expect("SSH metadata"),
            )
            .expect("metadata JSON");
            assert_eq!(
                metadata["directory_mode"], 0o700,
                "trust directory is not private"
            );
        }
    }

    #[test]
    fn dispatch_failure_returns_empty_stdout_and_is_never_replayed() {
        let fixture = Fixture::new();
        let result = response(&fixture.run_handler(
            &serde_json::to_vec(&valid_request()).expect("request JSON"),
            &[("SPEC_HA_SSH_FAIL", Some("yes"))],
        ));
        assert_eq!(result["ok"], false);
        assert_eq!(result["stdout_b64"], "");
        assert!(result["error"].is_string());
        assert_eq!(
            fixture.calls(),
            1,
            "uncertain execution must not be replayed"
        );
    }

    #[test]
    fn password_operation_with_no_stdin_dispatches_once() {
        let fixture = Fixture::new();
        let mut request = valid_request();
        request["operation"] = json!("exec_password");
        request["password"] = json!("isolated-spec-password");
        request["stdin_b64"] = Value::Null;
        let result = response(
            &fixture.run_handler(&serde_json::to_vec(&request).expect("request JSON"), &[]),
        );
        assert_eq!(result["ok"], true, "password response: {result}");
        assert_eq!(
            STANDARD
                .decode(result["stdout_b64"].as_str().expect("stdout base64"))
                .expect("stdout"),
            BINARY_STDOUT
        );
        assert_eq!(fixture.calls(), 1);
    }

    #[test]
    fn hidden_execute_flag_emits_one_json_response_without_application_startup() {
        let fixture = Fixture::new();
        let mut command = fixture.command(env!("CARGO_BIN_EXE_vpnctld"));
        command
            .arg("--ha-execute")
            .env("VPNCTLD_BIND", "invalid-bind-address")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("hidden execute mode");
        child
            .stdin
            .take()
            .expect("helper stdin")
            .write_all(&serde_json::to_vec(&valid_request()).expect("request JSON"))
            .expect("write helper request");
        let output = child.wait_with_output().expect("helper output");
        assert!(
            output.status.success(),
            "helper failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty(), "helper initialized logging");
        assert_eq!(output.stdout.last(), Some(&b'\n'));
        assert_eq!(
            output.stdout.iter().filter(|byte| **byte == b'\n').count(),
            1
        );
        let result: Value = serde_json::from_slice(&output.stdout).expect("single JSON response");
        assert_eq!(result["ok"], true);
        assert_eq!(
            STANDARD
                .decode(result["stdout_b64"].as_str().expect("stdout base64"))
                .expect("stdout"),
            BINARY_STDOUT
        );
        assert_eq!(fixture.calls(), 1);
    }

    #[test]
    fn embedded_migrations_are_complete_and_strictly_ordered_without_a_database() {
        let migrations = vpnctl_inventory::embedded_migration_checksums();
        assert!(
            !migrations.is_empty(),
            "schema must contain embedded migrations"
        );
        assert!(migrations.windows(2).all(|pair| pair[0].0 < pair[1].0));
        for (version, checksum) in migrations {
            assert!(version > 0, "migration version must be positive");
            assert_eq!(
                checksum.len(),
                48,
                "complete SQLx SHA384 checksum required for migration {version}"
            );
        }
    }

    #[test]
    fn artifact_metadata_matches_executable_and_the_complete_ordered_schema() {
        let root = tempfile::tempdir().expect("empty working directory");
        let output = Command::new(env!("CARGO_BIN_EXE_vpnctld"))
            .arg("--ha-artifact")
            .current_dir(root.path())
            .env("VPNCTLD_BIND", "invalid-bind-address")
            .env(
                "VPNCTLD_HA_EXECUTOR_SOCKET",
                "/nonexistent/spec-only-ha.sock",
            )
            .env_remove("VPNCTLD_DEPLOY_KEY")
            .output()
            .expect("artifact command");
        assert!(
            output.status.success(),
            "metadata initialized application state: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty(), "metadata initialized logging");
        assert_eq!(output.stdout.last(), Some(&b'\n'));
        assert_eq!(
            output.stdout.iter().filter(|byte| **byte == b'\n').count(),
            1
        );
        let artifact: Value =
            serde_json::from_slice(&output.stdout).expect("one artifact JSON object");
        let migrations = vpnctl_inventory::embedded_migration_checksums();
        let records: Vec<Value> = migrations
            .iter()
            .map(|(version, checksum)| json!({"version": version, "checksum_hex": hex(checksum)}))
            .collect();
        assert_eq!(artifact["migrations"], json!(records));
        assert_eq!(
            artifact["schema"],
            json!(
                migrations
                    .iter()
                    .map(|(version, _)| *version)
                    .max()
                    .expect("embedded schema")
            )
        );
        let canonical = migrations
            .iter()
            .map(|(version, checksum)| format!("{version}:{}\n", hex(checksum)))
            .collect::<String>();
        assert_eq!(
            artifact["migrations_sha256"],
            hex(&Sha256::digest(canonical.as_bytes()))
        );
        let executable = fs::read(env!("CARGO_BIN_EXE_vpnctld")).expect("actual helper executable");
        assert_eq!(
            artifact["executable_sha256"],
            hex(&Sha256::digest(executable))
        );
        assert_eq!(
            artifact["build_sha"],
            option_env!("VPNCTL_BUILD_SHA").unwrap_or("unknown")
        );
        assert!(
            fs::read_dir(root.path())
                .expect("working directory")
                .next()
                .is_none(),
            "artifact created application files"
        );
    }

    #[test]
    fn hidden_helper_flags_are_mutually_exclusive() {
        let root = tempfile::tempdir().expect("empty working directory");
        let output = Command::new(env!("CARGO_BIN_EXE_vpnctld"))
            .args(["--ha-execute", "--ha-artifact"])
            .current_dir(root.path())
            .stdin(Stdio::null())
            .output()
            .expect("incompatible helper flags");
        assert!(!output.status.success());
        assert!(
            output.stdout.is_empty(),
            "incompatible flags must not execute either helper"
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
