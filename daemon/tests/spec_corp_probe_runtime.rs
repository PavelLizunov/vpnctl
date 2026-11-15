//! Independent executable/socket/TLS contract tests; no implementation access.
#![cfg(target_os = "linux")]

#[allow(clippy::unwrap_used, clippy::expect_used)]
mod spec {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use rustls::{RootCertStore, pki_types::CertificateDer};
    use serde_json::{Value, json};
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        path::{Path, PathBuf},
        process::{Command, Stdio},
        sync::Arc,
        time::{Duration, Instant},
    };
    use tempfile::TempDir;
    use tokio::{
        io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
        net::{UnixListener, unix::OwnedReadHalf, unix::OwnedWriteHalf},
        task::JoinHandle,
        time::timeout,
    };
    use vpnctld::{
        corp_egress::{ProbeError, ProbeRequest, ProbeRunner},
        corp_probe_runtime::{RunnerConfig, SingBoxRunner},
    };

    const WORK: Duration = Duration::from_secs(5);
    const CLEANUP: Duration = Duration::from_secs(2);
    const EVENT: Duration = Duration::from_secs(9);

    fn token() -> String {
        URL_SAFE_NO_PAD.encode([17_u8; 32])
    }

    fn outbound() -> Value {
        json!({
            "type": "vless", "tag": "selected-exactly", "server": "vpn.example.invalid",
            "server_port": 443, "uuid": "3fc6c68e-a08a-4cba-b8ae-e9028921f04e",
            "tls": {"enabled": true, "server_name": "vpn.example.invalid"},
            "transport": {"type": "http", "path": "/selected-path"}
        })
    }

    fn request(value: Value) -> ProbeRequest {
        ProbeRequest {
            outbound: value,
            token: token().into(),
        }
    }

    fn private(path: &Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn openssl(dir: &Path, args: &[&str]) {
        let status = Command::new("/usr/bin/openssl")
            .current_dir(dir)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("CI requires /usr/bin/openssl for local TLS fixture generation");
        assert!(status.success(), "TLS fixture generation failed");
    }

    struct Fixture {
        _dir: TempDir,
        root: PathBuf,
        work: PathBuf,
        executable: PathBuf,
        listener: UnixListener,
    }

    impl Fixture {
        fn new(mode: &str, certificate: &str) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path().to_path_buf();
            private(&root, 0o700);
            let work = root.join("work");
            fs::create_dir(&work).unwrap();
            private(&work, 0o700);
            openssl(
                &root,
                &[
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-days",
                    "1",
                    "-subj",
                    "/CN=Corp fixture CA",
                    "-keyout",
                    "ca.key",
                    "-out",
                    "ca.pem",
                    "-addext",
                    "basicConstraints=critical,CA:TRUE",
                    "-addext",
                    "keyUsage=critical,keyCertSign,cRLSign",
                ],
            );
            openssl(
                &root,
                &["x509", "-in", "ca.pem", "-outform", "DER", "-out", "ca.der"],
            );
            let hostname = if certificate == "wrong_host" {
                "wrong.example.invalid"
            } else {
                "admin.corp.ninitux.com"
            };
            fs::write(root.join("leaf.ext"), format!("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:{hostname}\n")).unwrap();
            openssl(
                &root,
                &[
                    "req",
                    "-new",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-subj",
                    "/CN=Corp fixture",
                    "-keyout",
                    "leaf.key",
                    "-out",
                    "leaf.csr",
                ],
            );
            if certificate == "untrusted" {
                openssl(
                    &root,
                    &[
                        "x509", "-req", "-in", "leaf.csr", "-signkey", "leaf.key", "-days", "1",
                        "-extfile", "leaf.ext", "-out", "leaf.pem",
                    ],
                );
            } else {
                openssl(
                    &root,
                    &[
                        "x509",
                        "-req",
                        "-in",
                        "leaf.csr",
                        "-CA",
                        "ca.pem",
                        "-CAkey",
                        "ca.key",
                        "-CAcreateserial",
                        "-days",
                        "1",
                        "-extfile",
                        "leaf.ext",
                        "-out",
                        "leaf.pem",
                    ],
                );
            }
            private(&root.join("ca.key"), 0o600);
            private(&root.join("leaf.key"), 0o600);
            let event_path = root.join("events.sock");
            let listener = UnixListener::bind(&event_path).unwrap();
            let executable = root.join("managed-helper");
            let settings = format!(
                "#!/usr/bin/python3\nMODE = {}\nEVENT_PATH = {}\nCERT_PATH = {}\nKEY_PATH = {}\nFOREIGN_PATH = {}\n",
                json!(mode),
                json!(event_path),
                json!(root.join("leaf.pem")),
                json!(root.join("leaf.key")),
                json!(root.join("foreign.sock"))
            );
            fs::write(
                &executable,
                settings + include_str!("fixtures/corp-probe/runner.py"),
            )
            .unwrap();
            private(&executable, 0o700);
            Self {
                _dir: dir,
                root,
                work,
                executable,
                listener,
            }
        }

        fn config(&self) -> RunnerConfig {
            let mut tls_roots = RootCertStore::empty();
            tls_roots
                .add(CertificateDer::from(
                    fs::read(self.root.join("ca.der")).unwrap(),
                ))
                .unwrap();
            RunnerConfig {
                executable: self.executable.clone(),
                work_root: self.work.clone(),
                tls_roots,
                work_timeout: WORK,
                cleanup_timeout: CLEANUP,
            }
        }

        fn runner(&self) -> Arc<SingBoxRunner> {
            Arc::new(SingBoxRunner::new(self.config()).unwrap())
        }

        async fn accept(&self) -> Events {
            let (stream, _) = timeout(EVENT, self.listener.accept())
                .await
                .unwrap()
                .unwrap();
            let (read, write) = stream.into_split();
            Events {
                read: BufReader::new(read),
                write,
            }
        }

        async fn start(&self, runner: &Arc<SingBoxRunner>) -> Session {
            let owned = Arc::clone(runner);
            let task = tokio::spawn(async move { owned.run(request(outbound())).await });
            let mut events = self.accept().await;
            let config = events.next().await;
            assert_eq!(config["kind"], "config");
            Session {
                task,
                events,
                config,
            }
        }

        fn assert_clean(&self, config: &Value) {
            assert_eq!(
                fs::read_dir(&self.work).unwrap().count(),
                0,
                "private task directory must be removed"
            );
            let pid = config["pid"].as_u64().unwrap();
            assert!(
                !Path::new(&format!("/proc/{pid}")).exists(),
                "direct child must have exited and been reaped before completion"
            );
        }
    }

    struct Events {
        read: BufReader<OwnedReadHalf>,
        write: OwnedWriteHalf,
    }

    impl Events {
        async fn next(&mut self) -> Value {
            let mut line = String::new();
            let size = timeout(EVENT, self.read.read_line(&mut line))
                .await
                .unwrap()
                .unwrap();
            assert!(size > 0, "helper exited before expected event");
            serde_json::from_str(&line).unwrap()
        }

        async fn until(&mut self, kind: &str) -> Value {
            loop {
                let event = self.next().await;
                assert_ne!(
                    event["kind"], "helper_error",
                    "fixture protocol assertion failed: {event}"
                );
                if event["kind"] == kind {
                    return event;
                }
            }
        }
    }

    struct Session {
        task: JoinHandle<Result<(), ProbeError>>,
        events: Events,
        config: Value,
    }

    struct ForeignChild(std::process::Child);

    impl Drop for ForeignChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    struct RestorePrivateMode(PathBuf);

    impl Drop for RestorePrivateMode {
        fn drop(&mut self) {
            let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700));
        }
    }

    async fn result(task: JoinHandle<Result<(), ProbeError>>) -> Result<(), ProbeError> {
        timeout(EVENT, task).await.unwrap().unwrap()
    }

    fn assert_private_config(fixture: &Fixture, captured: &Value) {
        let config = &captured["config"];
        assert_eq!(config["outbounds"], json!([outbound()]));
        assert_eq!(config["route"]["final"], "selected-exactly");
        assert_eq!(config["log"]["disabled"], true);
        assert_eq!(config["inbounds"].as_array().unwrap().len(), 1);
        assert_eq!(config["inbounds"][0]["listen"], "127.0.0.1");
        assert_eq!(captured["config_mode"], 0o600);
        assert_eq!(captured["dir_mode"], 0o700);
        assert_eq!(
            captured["stdio"],
            json!(["/dev/null", "/dev/null", "/dev/null"])
        );
        let cwd = Path::new(captured["cwd"].as_str().unwrap());
        assert_eq!(cwd.parent(), Some(fixture.work.as_path()));
        let argv = captured["argv"].as_array().unwrap();
        assert_eq!(argv.len(), 4);
        assert_eq!(&argv[1..3], &[json!("run"), json!("-c")]);
        assert_eq!(
            Path::new(argv[3].as_str().unwrap()),
            cwd.join("config.json")
        );
        let user = &config["inbounds"][0]["users"][0];
        let username = user["username"].as_str().unwrap();
        let password = user["password"].as_str().unwrap();
        assert!(username.len() >= 32 && password.len() >= 32);
        assert_ne!(username, password);
        let encoded = config.to_string();
        assert!(
            !encoded.contains(&token()),
            "challenge must never enter config"
        );
        let env = captured["env"].as_array().unwrap();
        assert!(
            env.iter()
                .all(|entry| entry.as_str().unwrap().starts_with("PATH=")),
            "only fixed minimal PATH may enter child environment"
        );
        let public_process = format!("{}{}", captured["argv"], captured["env"]);
        for secret in [
            token(),
            username.into(),
            password.into(),
            outbound()["uuid"].as_str().unwrap().into(),
        ] {
            assert!(!public_process.contains(&secret));
        }
        assert!(config.get("experimental").is_none_or(
            |value| value.get("clash_api").is_none() && value.get("v2ray_api").is_none()
        ));
        assert!(
            config.get("dns").is_some(),
            "VPN host requires local bootstrap DNS"
        );
    }

    #[tokio::test]
    async fn verified_https_uses_exact_outbound_private_files_and_cleans_before_success() {
        let fixture = Fixture::new("valid", "valid");
        let config = fixture.config();
        assert_eq!(format!("{config:?}"), "RunnerConfig { .. }");
        assert_eq!(format!("{config:#?}"), "RunnerConfig { .. }");
        let runner = fixture.runner();
        assert_eq!(format!("{runner:?}"), "SingBoxRunner { .. }");
        assert_eq!(format!("{runner:#?}"), "SingBoxRunner { .. }");
        assert!(runner.available());
        assert_eq!(
            fs::read_dir(&fixture.work).unwrap().count(),
            0,
            "new must have no process or task-directory side effect"
        );
        let mut session = fixture.start(&runner).await;
        assert_private_config(&fixture, &session.config);
        assert_eq!(session.events.until("request").await["token"], token());
        assert_eq!(result(session.task).await, Ok(()));
        fixture.assert_clean(&session.config);
        assert!(runner.available());
        let next = fixture.start(&runner).await;
        assert_ne!(
            session.config["config"]["inbounds"][0]["users"],
            next.config["config"]["inbounds"][0]["users"],
            "each attempt requires independent random SOCKS credentials"
        );
        assert_eq!(result(next.task).await, Ok(()));
        fixture.assert_clean(&next.config);
    }

    #[tokio::test]
    async fn bounded_socks_addresses_and_absent_zero_length_are_accepted() {
        for mode in ["domain", "ipv6", "absent_length"] {
            let fixture = Fixture::new(mode, "valid");
            let runner = fixture.runner();
            let session = fixture.start(&runner).await;
            assert_eq!(result(session.task).await, Ok(()), "mode {mode}");
            fixture.assert_clean(&session.config);
        }
    }

    #[tokio::test]
    async fn pending_kernel_accept_retains_one_stream_without_socks_until_child_owns_it() {
        let fixture = Fixture::new("delayed_accept", "valid");
        let runner = fixture.runner();
        let mut session = fixture.start(&runner).await;
        let pending = session.events.until("pending_accept").await;
        assert_eq!(pending["inode"], 0);
        assert_eq!(pending["queued_bytes"], 0);
        assert_eq!(pending["connections"], 1);
        assert!(
            !session.task.is_finished(),
            "pending accept must not reject a valid retained connection"
        );
        assert_eq!(runner.run(request(outbound())).await, Err(ProbeError::Busy));
        session.events.write.write_all(b"inspect\n").await.unwrap();
        let checked = session.events.until("pending_accept_checked").await;
        assert_eq!(
            checked["remote"], pending["remote"],
            "the same client TCP tuple must remain established"
        );
        assert_eq!(
            checked["queued_bytes"], 0,
            "no SOCKS bytes may precede ownership proof"
        );
        assert_eq!(checked["connections"], 1);
        assert!(!session.task.is_finished());
        session.events.write.write_all(b"release\n").await.unwrap();
        assert_eq!(session.events.until("request").await["token"], token());
        assert_eq!(result(session.task).await, Ok(()));
        fixture.assert_clean(&session.config);
    }

    #[tokio::test]
    async fn pending_kernel_accept_without_release_expires_and_cleans_the_owned_child() {
        let fixture = Fixture::new("delayed_accept", "valid");
        let mut config = fixture.config();
        config.work_timeout = Duration::from_secs(1);
        let runner = Arc::new(SingBoxRunner::new(config).unwrap());
        let started = Instant::now();
        let mut session = fixture.start(&runner).await;
        let pending = session.events.until("pending_accept").await;
        assert_eq!(pending["inode"], 0);
        assert_eq!(pending["queued_bytes"], 0);
        assert!(!session.task.is_finished());
        assert!(result(session.task).await.is_err());
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "unaccepted connection must obey the absolute work and cleanup budgets"
        );
        fixture.assert_clean(&session.config);
        assert!(
            runner.available(),
            "a clean pending-accept timeout must not poison the runtime"
        );
    }

    #[tokio::test]
    async fn socks_tls_http_failures_never_certify_and_always_reap() {
        for (mode, certificate) in [
            ("early_exit", "valid"),
            ("no_auth", "valid"),
            ("refused_method", "valid"),
            ("auth_failure", "valid"),
            ("wrong_socks", "valid"),
            ("connect_denied", "valid"),
            ("valid", "wrong_host"),
            ("valid", "untrusted"),
            ("wrong_echo", "valid"),
            ("missing_echo", "valid"),
            ("duplicate_echo", "valid"),
            ("redirect", "valid"),
            ("large_headers", "valid"),
            ("many_headers", "valid"),
            ("transfer_encoding", "valid"),
            ("nonzero_length", "valid"),
            ("duplicate_length", "valid"),
            ("body", "valid"),
        ] {
            let fixture = Fixture::new(mode, certificate);
            let runner = fixture.runner();
            let session = fixture.start(&runner).await;
            assert!(
                result(session.task).await.is_err(),
                "mode {mode}, certificate {certificate}"
            );
            fixture.assert_clean(&session.config);
            assert!(
                runner.available(),
                "ordinary transcript failure must not poison a clean runner"
            );
        }
    }

    #[tokio::test]
    async fn constructor_rejects_unsafe_paths_roots_and_timeout_boundaries() {
        let fixture = Fixture::new("valid", "valid");
        for change in 0..10 {
            let mut config = fixture.config();
            match change {
                0 => config.work_timeout = Duration::ZERO,
                1 => config.cleanup_timeout = Duration::ZERO,
                2 => config.work_timeout = Duration::from_secs(15) + Duration::from_nanos(1),
                3 => config.cleanup_timeout = Duration::from_secs(2) + Duration::from_nanos(1),
                4 => config.tls_roots = RootCertStore::empty(),
                5 => config.executable = PathBuf::from("relative-helper"),
                6 => config.work_root = PathBuf::from("relative-work"),
                7 => config.executable = fixture.root.join("missing"),
                8 => config.work_root = fixture.root.join("missing"),
                9 => config.executable = fixture.work.clone(),
                _ => unreachable!(),
            }
            assert!(
                SingBoxRunner::new(config).is_err(),
                "unsafe constructor case {change}"
            );
        }
        for mode in [0o600, 0o720, 0o702] {
            private(&fixture.executable, mode);
            assert!(SingBoxRunner::new(fixture.config()).is_err());
        }
        private(&fixture.executable, 0o700);
        for mode in [0o755, 0o770, 0o777] {
            private(&fixture.work, mode);
            assert!(SingBoxRunner::new(fixture.config()).is_err());
        }
        private(&fixture.work, 0o700);
        let link = fixture.root.join("helper-link");
        symlink(&fixture.executable, &link).unwrap();
        let mut config = fixture.config();
        config.executable = link;
        assert!(SingBoxRunner::new(config).is_err());
        let link = fixture.root.join("work-link");
        symlink(&fixture.work, &link).unwrap();
        let mut config = fixture.config();
        config.work_root = link;
        assert!(SingBoxRunner::new(config).is_err());
        let intermediate = fixture.root.join("ancestor-link");
        symlink(&fixture.root, &intermediate).unwrap();
        let mut config = fixture.config();
        config.executable = intermediate.join("managed-helper");
        assert!(
            SingBoxRunner::new(config).is_err(),
            "executable ancestors must reject symlinks"
        );
        let mut config = fixture.config();
        config.work_root = intermediate.join("work");
        assert!(
            SingBoxRunner::new(config).is_err(),
            "work-root ancestors must reject symlinks"
        );
        private(&fixture.root, 0o770);
        assert!(SingBoxRunner::new(fixture.config()).is_err());
        private(&fixture.root, 0o700);
        let mut config = fixture.config();
        config.work_timeout = Duration::from_secs(15);
        config.cleanup_timeout = Duration::from_secs(2);
        assert!(
            SingBoxRunner::new(config).is_ok(),
            "inclusive maximum durations are valid"
        );
    }

    #[tokio::test]
    async fn malformed_requests_are_rejected_before_launch() {
        let fixture = Fixture::new("valid", "valid");
        let runner = fixture.runner();
        let mut bad = vec![Value::Null, json!([]), json!({}), json!({"type": "direct"})];
        for field in ["tag", "server", "server_port", "uuid", "tls"] {
            let mut value = outbound();
            value.as_object_mut().unwrap().remove(field);
            bad.push(value);
        }
        for (field, invalid) in [
            ("tag", json!("")),
            ("server", json!("")),
            ("server_port", json!(0)),
            ("server_port", json!(65536)),
            ("uuid", json!("not-a-uuid")),
            ("detour", json!("elsewhere")),
            ("detour", Value::Null),
            ("tls", json!({"enabled": false})),
        ] {
            let mut value = outbound();
            value[field] = invalid;
            bad.push(value);
        }
        let mut oversized = outbound();
        oversized["padding"] = json!("x".repeat(65536));
        bad.push(oversized);
        for value in bad {
            assert!(runner.run(request(value)).await.is_err());
        }
        for invalid in [
            "".to_owned(),
            "a".repeat(43),
            format!("{}=", token()),
            URL_SAFE_NO_PAD.encode([17_u8; 31]),
            URL_SAFE_NO_PAD.encode([17_u8; 33]),
        ] {
            assert!(
                runner
                    .run(ProbeRequest {
                        outbound: outbound(),
                        token: invalid.into()
                    })
                    .await
                    .is_err()
            );
        }
        assert_eq!(fs::read_dir(&fixture.work).unwrap().count(), 0);
        // A queued event is direct evidence that an invalid input launched a child.
        assert!(
            timeout(Duration::from_millis(30), fixture.listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn executable_and_ancestor_trust_are_revalidated_at_run_time() {
        for mutation in [
            "writable_executable",
            "writable_ancestor",
            "symlink",
            "missing",
        ] {
            let fixture = Fixture::new("valid", "valid");
            let runner = fixture.runner();
            match mutation {
                "writable_executable" => private(&fixture.executable, 0o722),
                "writable_ancestor" => private(&fixture.root, 0o770),
                "symlink" => {
                    let original = fixture.root.join("original");
                    fs::rename(&fixture.executable, &original).unwrap();
                    symlink(original, &fixture.executable).unwrap();
                }
                "missing" => fs::remove_file(&fixture.executable).unwrap(),
                _ => unreachable!(),
            }
            assert!(
                !runner.available(),
                "unsafe runtime must become unavailable: {mutation}"
            );
            assert!(runner.run(request(outbound())).await.is_err());
            private(&fixture.root, 0o700);
            assert_eq!(fs::read_dir(&fixture.work).unwrap().count(), 0);
        }
    }

    #[tokio::test]
    async fn failed_exec_removes_task_files_without_poisoning_clean_state() {
        let fixture = Fixture::new("valid", "valid");
        fs::write(
            &fixture.executable,
            "#!/nonexistent/corp-fixture-interpreter\n",
        )
        .unwrap();
        let runner = fixture.runner();
        assert!(runner.run(request(outbound())).await.is_err());
        assert_eq!(fs::read_dir(&fixture.work).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn stalled_socket_obeys_total_work_budget_and_finishes_cleanup() {
        let fixture = Fixture::new("stall", "valid");
        let mut config = fixture.config();
        config.work_timeout = Duration::from_secs(1);
        let runner = Arc::new(SingBoxRunner::new(config).unwrap());
        let started = Instant::now();
        let mut session = fixture.start(&runner).await;
        session.events.until("accepted").await;
        assert_eq!(runner.run(request(outbound())).await, Err(ProbeError::Busy));
        assert!(result(session.task).await.is_err());
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "work deadline plus cleanup budget must remain bounded"
        );
        fixture.assert_clean(&session.config);
        assert!(runner.available());
    }

    #[tokio::test]
    async fn progress_on_each_read_does_not_renew_the_absolute_work_deadline() {
        let fixture = Fixture::new("trickle", "valid");
        let mut config = fixture.config();
        config.work_timeout = Duration::from_secs(1);
        let runner = Arc::new(SingBoxRunner::new(config).unwrap());
        let started = Instant::now();
        let mut session = fixture.start(&runner).await;
        session.events.until("request").await;
        let mut control = session.events.write;
        let traffic = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(100));
            for _ in 0..60 {
                interval.tick().await;
                if control.write_all(b"x").await.is_err() {
                    break;
                }
            }
        });
        let outcome = result(session.task).await;
        traffic.abort();
        assert!(outcome.is_err());
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "receiving bytes must not renew the absolute one-second work budget"
        );
        fixture.assert_clean(&session.config);
    }

    #[tokio::test]
    async fn caller_cancellation_retains_busy_gate_until_owned_helper_cleanup() {
        let fixture = Fixture::new("controlled", "valid");
        let runner = fixture.runner();
        let mut session = fixture.start(&runner).await;
        session.events.until("accepted").await;
        session.task.abort();
        assert!(session.task.await.unwrap_err().is_cancelled());
        assert_eq!(runner.run(request(outbound())).await, Err(ProbeError::Busy));
        assert!(runner.available(), "busy alone is not unavailable");
        session.events.write.write_all(b"continue\n").await.unwrap();
        assert_eq!(session.events.until("request").await["token"], token());
        // EOF on the event channel proves child exit; bounded yielding observes
        // task-directory removal and gate release rather than sleeping as proof.
        let mut line = String::new();
        loop {
            line.clear();
            if timeout(EVENT, session.events.read.read_line(&mut line))
                .await
                .unwrap()
                .unwrap()
                == 0
            {
                break;
            }
        }
        timeout(EVENT, async {
            loop {
                if fs::read_dir(&fixture.work).unwrap().count() == 0 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        fixture.assert_clean(&session.config);
        let owned = Arc::clone(&runner);
        let task = tokio::spawn(async move {
            loop {
                match owned.run(request(outbound())).await {
                    Err(ProbeError::Busy) => tokio::task::yield_now().await,
                    outcome => break outcome,
                }
            }
        });
        let mut next_events = fixture.accept().await;
        let next_config = next_events.next().await;
        let next = Session {
            task,
            events: next_events,
            config: next_config,
        };
        let mut events = next.events;
        events.until("accepted").await;
        events.write.write_all(b"continue\n").await.unwrap();
        assert_eq!(result(next.task).await, Ok(()));
        fixture.assert_clean(&next.config);
    }

    #[tokio::test]
    async fn cleanup_failure_retains_cleanup_ownership_and_permanently_poisons_runner() {
        let status = fs::read_to_string("/proc/self/status").unwrap();
        let effective_uid = status
            .lines()
            .find_map(|line| {
                line.strip_prefix("Uid:")
                    .and_then(|uids| uids.split_whitespace().nth(1))
            })
            .unwrap()
            .parse::<u32>()
            .unwrap();
        assert_ne!(
            effective_uid, 0,
            "cleanup-permission fixture requires the standard nonroot GitHub ubuntu test user; root bypasses directory permissions"
        );
        let fixture = Fixture::new("controlled", "valid");
        let runner = fixture.runner();
        let mut session = fixture.start(&runner).await;
        session.events.until("accepted").await;
        // Remove only the ability to unlink the task directory from its parent.
        // The retained child's files/socket and HTTP exchange remain usable.
        let _restore = RestorePrivateMode(fixture.work.clone());
        private(&fixture.work, 0o500);
        session.events.write.write_all(b"continue\n").await.unwrap();
        assert_eq!(session.events.until("request").await["token"], token());
        assert_eq!(result(session.task).await, Err(ProbeError::CleanupFailed));
        assert!(!runner.available());
        private(&fixture.work, 0o700);
        // Trust is valid again, but poison is a separate permanent state.
        assert!(!runner.available());
        assert_eq!(
            runner.run(request(outbound())).await,
            Err(ProbeError::Unavailable)
        );
        timeout(EVENT, async {
            loop {
                if fs::read_dir(&fixture.work).unwrap().count() == 0 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("retained cleanup owner must remove its directory after permissions are restored");
        fixture.assert_clean(&session.config);
        assert!(!runner.available());
    }

    #[tokio::test]
    async fn namespace_tcp_table_without_child_fd_ownership_never_receives_credentials() {
        let fixture = Fixture::new("foreign", "valid");
        // This process is spawned by the test, never by the managed helper.
        // Its socket therefore appears in the child's namespace-wide tcp table
        // but cannot appear in the child's own /proc/<pid>/fd links.
        let script = format!(
            r#"
import json, socket
control = socket.socket(socket.AF_UNIX)
control.connect({event_path})
def event(kind, **fields):
    control.sendall((json.dumps(dict(kind=kind, **fields)) + "\n").encode())
listener = socket.socket(socket.AF_UNIX)
listener.bind({foreign_path})
listener.listen(1)
event("foreign_ready")
relay, _ = listener.accept()
port = b""
while not port.endswith(b"\n"):
    port += relay.recv(1)
tcp = socket.socket()
tcp.bind(("127.0.0.1", int(port)))
tcp.listen(1)
stream, _ = tcp.accept()
greeting = stream.recv(3)
credentials = b""
if greeting:
    stream.sendall(b"\x05\x02")
    credentials = stream.recv(1024)
event("foreign_finished", received_credentials=bool(credentials))
relay.sendall(b"x")
while control.recv(1):
    pass
"#,
            event_path = json!(fixture.root.join("events.sock")),
            foreign_path = json!(fixture.root.join("foreign.sock"))
        );
        let _foreign = ForeignChild(
            Command::new("/usr/bin/python3")
                .args(["-c", &script])
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let mut foreign_events = fixture.accept().await;
        assert_eq!(foreign_events.next().await["kind"], "foreign_ready");
        let runner = fixture.runner();
        let session = fixture.start(&runner).await;
        assert!(result(session.task).await.is_err());
        assert_eq!(
            foreign_events.until("foreign_finished").await["received_credentials"],
            false
        );
        fixture.assert_clean(&session.config);
    }
}
