//! Independent executable-level assertions from docs/specs/controller-ha.md.
//! The handler runs in a fresh process so fixture environment changes never
//! affect another test or a real SSH transport.

#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use serde_json::{Value, json};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new(case: &str, mode: &str, ssh_present: bool) -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "vpnctl-spec-ha-outcome-{}-{unique}-{case}",
                std::process::id()
            ));
            fs::create_dir_all(root.join("bin")).unwrap();
            let fixture = Self { root };
            if ssh_present {
                fixture.script(
                    "ssh",
                    &format!("#!/bin/sh\nprintf 'dispatch\\n' >> \"$SPEC_INVOCATIONS\"\n{mode}\n"),
                );
            }
            fixture.script("sshpass", "#!/bin/sh\nshift 2\nexec \"$@\"\n");
            fixture.script(
            "ssh-keyscan",
            "#!/bin/sh\nprintf 'spec.invalid ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBERERERERERERERERERERERERERERERERERERERERER\\n'\n",
        );
            fixture.script(
            "ssh-keygen",
            "#!/bin/sh\nprintf '256 SHA256:ERERERERERERERERERERERERERERERERERERERERERE spec (ED25519)\\n'\n",
        );
            fixture
        }

        fn script(&self, name: &str, content: &str) {
            let path = self.root.join("bin").join(name);
            fs::write(&path, content).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }

        fn run(&self, request: &[u8]) -> Value {
            let input = self.root.join("request.json");
            let output = self.root.join("response.json");
            fs::write(&input, request).unwrap();
            let result = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "tests::spec_helper_child",
                    "--nocapture",
                ])
                .env_clear()
                .env("PATH", self.root.join("bin"))
                .env("HOME", &self.root)
                .env("VPNCTLD_DEPLOY_KEY", "spec-private-key-nonempty")
                .env("SPEC_REQUEST", input)
                .env("SPEC_RESPONSE", &output)
                .env("SPEC_INVOCATIONS", self.root.join("invocations"))
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "isolated child failed: {}\n{}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
            serde_json::from_slice(&fs::read(output).unwrap()).unwrap()
        }

        fn dispatches(&self) -> usize {
            fs::read_to_string(self.root.join("invocations"))
                .unwrap_or_default()
                .lines()
                .count()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn request() -> Value {
        json!({
            "host": "spec.invalid",
            "user": "root",
            "port": 22,
            "timeout_ms": 1000,
            "operation": "exec",
            "remote_cmd": "printf spec-output",
            "jump": null,
            "target_fingerprint": null,
            "known_hosts_b64": "",
            "stdin_b64": null,
            "password": null
        })
    }

    fn response(result: &Value) -> &Value {
        assert_eq!(result["handler_ok"], true, "handler rejected: {result}");
        &result["response"]
    }

    fn assert_terminal_rejection(result: &Value) {
        if result["handler_ok"] == true {
            let body = response(result);
            assert_eq!(body["ok"], false, "{body}");
            assert_eq!(body["outcome"], "rejected", "{body}");
            assert_eq!(body["stdout_b64"], "", "{body}");
        }
    }

    #[test]
    fn ssh_exit_zero_through_254_is_completed_and_never_retried() {
        for exit_code in [0, 1, 254] {
            let fixture = Fixture::new(
                &format!("exit-{exit_code}"),
                &format!("printf spec-output\nexit {exit_code}"),
                true,
            );
            let result = fixture.run(&serde_json::to_vec(&request()).unwrap());
            let body = response(&result);
            assert_eq!(body["outcome"], "completed", "exit {exit_code}: {body}");
            assert_eq!(body["exit_code"], exit_code, "{body}");
            assert_eq!(body["ok"], exit_code == 0, "{body}");
            if exit_code == 0 {
                assert_eq!(body["stdout_b64"], "c3BlYy1vdXRwdXQ=", "{body}");
            } else {
                assert_eq!(body["stdout_b64"], "", "{body}");
                assert!(body["error"].is_string(), "{body}");
            }
            assert_eq!(fixture.dispatches(), 1, "exit {exit_code} retried");
        }
    }

    #[test]
    fn ssh_255_timeout_and_signal_are_uncertain_and_never_retried() {
        for (name, script) in [
            ("exit-255", "exit 255"),
            ("timeout", "exec /bin/sleep 5"),
            ("signal", "kill -TERM $$"),
        ] {
            let fixture = Fixture::new(name, script, true);
            let mut input = request();
            input["timeout_ms"] = json!(100);
            let result = fixture.run(&serde_json::to_vec(&input).unwrap());
            let body = response(&result);
            assert_eq!(body["ok"], false, "{name}: {body}");
            assert_eq!(body["outcome"], "uncertain", "{name}: {body}");
            assert_eq!(body["stdout_b64"], "", "{body}");
            assert_eq!(fixture.dispatches(), 1, "{name} retried");
        }
    }

    #[test]
    fn missing_ssh_is_proven_predispatch_rejection() {
        let fixture = Fixture::new("missing-ssh", "", false);
        let result = fixture.run(&serde_json::to_vec(&request()).unwrap());
        let body = response(&result);
        assert_eq!(body["ok"], false, "{body}");
        assert_eq!(body["outcome"], "rejected", "{body}");
        assert_eq!(body["stdout_b64"], "", "{body}");
        assert_eq!(fixture.dispatches(), 0);
    }

    #[test]
    fn malformed_protocol_never_dispatches() {
        let mut malformed = Vec::new();
        malformed.push(b"{".to_vec());
        for (field, value) in [
            ("operation", json!("shell")),
            ("timeout_ms", json!(0)),
            ("timeout_ms", json!(3_600_001)),
            ("port", json!(0)),
            ("host", json!("")),
            ("user", json!("")),
            ("stdin_b64", json!("%%%")),
            ("known_hosts_b64", json!("%%%")),
            ("unexpected", json!(true)),
            ("password", json!("forbidden-on-exec")),
        ] {
            let mut input = request();
            input[field] = value;
            malformed.push(serde_json::to_vec(&input).unwrap());
        }
        let mut no_password = request();
        no_password["operation"] = json!("exec_password");
        malformed.push(serde_json::to_vec(&no_password).unwrap());
        for (index, input) in malformed.iter().enumerate() {
            let fixture = Fixture::new(&format!("invalid-{index}"), "exit 0", true);
            let result = fixture.run(input);
            assert_terminal_rejection(&result);
            assert_eq!(fixture.dispatches(), 0, "malformed request {index}");
        }
    }

    #[tokio::test]
    #[ignore = "only invoked by the parent fixture with an isolated environment"]
    async fn spec_helper_child() {
        let input = fs::read(std::env::var_os("SPEC_REQUEST").unwrap()).unwrap();
        let result = vpnctl_ssh::subprocess::handle_ha_execute_request(&input).await;
        let report = match result {
            Ok(bytes) => json!({
                "handler_ok": true,
                "response": serde_json::from_slice::<Value>(&bytes).unwrap()
            }),
            Err(_) => json!({"handler_ok": false}),
        };
        fs::write(
            Path::new(&std::env::var_os("SPEC_RESPONSE").unwrap()),
            serde_json::to_vec(&report).unwrap(),
        )
        .unwrap();
    }
}
