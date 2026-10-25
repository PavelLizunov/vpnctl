#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod spec {
    use super::super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path as FsPath, PathBuf};
    use std::process::Command;
    use std::sync::Arc;

    use axum::http::StatusCode;
    use tempfile::TempDir;
    use vpnctl_core::{Registry, Server, ServerId};
    use vpnctl_inventory::SqliteInventory;

    const CASE_ENV: &str = "VPNCTL_EXISTING_KEY_SPEC_CASE";
    const HOST: &str = "203.0.113.71";
    const JUMP: &str = "203.0.113.72";
    const OLD_USER: &str = "old-login";

    fn executable(path: &FsPath, text: &str) {
        fs::write(path, text).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn run_case(case: &str) {
        let dir = TempDir::new().unwrap();
        let bin = dir.path().join("bin");
        fs::create_dir(&bin).unwrap();
        for name in ["deploy", "host"] {
            let output = Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                .arg(dir.path().join(name))
                .output()
                .expect("offline ssh-keygen must be available for isolated fixtures");
            assert!(output.status.success(), "fixture key generation failed");
        }
        executable(
            &bin.join("ssh"),
            r#"#!/bin/sh
input=$(/bin/cat)
{
  printf '\nSSH-BEGIN\n'
  printf '%s\n' "$@"
  printf 'STDIN-BEGIN\n%s\nSSH-END\n' "$input"
} >> "$VPNCTL_SPEC_DIR/transport.log"
previous=
for arg in "$@"; do
  case "$arg" in
    UserKnownHostsFile=*)
      case "$VPNCTL_EXISTING_KEY_SPEC_CASE" in
        wizard_missing_known_hosts) ;;
        wizard_*)
          known_hosts=${arg#UserKnownHostsFile=}
          read -r kind key rest < "$VPNCTL_SPEC_DIR/host.pub"
          host='[203.0.113.71]:2222'
          case "$VPNCTL_EXISTING_KEY_SPEC_CASE" in
            wizard_root_*|wizard_key_changed) host=203.0.113.71 ;;
            wizard_ssh_443) host='[203.0.113.71]:443' ;;
          esac
          printf '%s %s %s\n' "$host" "$kind" "$key" > "$known_hosts"
          case "$VPNCTL_EXISTING_KEY_SPEC_CASE" in
            wizard_ambiguous_known_hosts)
              read -r kind key rest < "$VPNCTL_SPEC_DIR/deploy.pub"
              printf '%s %s %s\n' "$host" "$kind" "$key" >> "$known_hosts" ;;
            wizard_hashed_*) ssh-keygen -H -f "$known_hosts" >/dev/null 2>&1 ;;
          esac ;;
      esac ;;
  esac
  if [ "$previous" = '-F' ]; then
    /bin/cat "$arg" >> "$VPNCTL_SPEC_DIR/transport.log"
    while read -r keyword value rest; do
      if [ "$keyword" = IdentityFile ]; then
        value=${value#\"}; value=${value%\"}
        case "$*" in
          *PubkeyAuthentication=no*) ;;
          *) [ -f "$value" ] || exit 255 ;;
        esac
      fi
    done < "$arg"
  fi
  previous=$arg
done
case "$* $input" in
  *ssh-keyscan*)
    read -r kind key rest < "$VPNCTL_SPEC_DIR/host.pub"
    printf '203.0.113.71 %s %s\n' "$kind" "$key"
    printf '[203.0.113.71]:2222 %s %s\n' "$kind" "$key"
    exit 0 ;;
esac
case "$VPNCTL_EXISTING_KEY_SPEC_CASE" in
  timeout) exec /bin/sleep 30 ;;
  password_timeout)
    printf '%s\n' "$$" > "$VPNCTL_SPEC_DIR/ssh.pid"
    exec /bin/sleep 30 ;;
  deploy_cancel)
    : > "$VPNCTL_SPEC_DIR/ssh-started"
    while [ ! -f "$VPNCTL_SPEC_DIR/ssh-release" ]; do /bin/sleep 0.02; done ;;
  key_failure) printf 'Permission denied (publickey). SPEC_SECRET_MUST_NOT_LEAK\n' >&2; exit 255 ;;
  sudo_failure)
    case "$* $input" in
      *'sudo -n sh -c'*) printf 'sudo: a password is required SPEC_SECRET_MUST_NOT_LEAK\n' >&2; exit 1 ;;
    esac ;;
esac
printf '0\n'
"#,
        );
        executable(
            &bin.join("ssh-keyscan"),
            r#"#!/bin/sh
printf 'KEYSCAN\n' >> "$VPNCTL_SPEC_DIR/keyscan.log"
keyfile=host.pub
case "$VPNCTL_EXISTING_KEY_SPEC_CASE" in
  wizard_*pin_mismatch) keyfile=deploy.pub ;;
  wizard_key_changed)
    [ "$(wc -l < "$VPNCTL_SPEC_DIR/keyscan.log")" -lt 2 ] || keyfile=deploy.pub ;;
esac
read -r kind key rest < "$VPNCTL_SPEC_DIR/$keyfile"
printf '203.0.113.71 %s %s\n' "$kind" "$key"
printf '[203.0.113.71]:2222 %s %s\n' "$kind" "$key"
printf '203.0.113.72 %s %s\n' "$kind" "$key"
"#,
        );
        executable(
            &bin.join("sshpass"),
            r#"#!/bin/sh
case "$VPNCTL_EXISTING_KEY_SPEC_CASE" in
  password_*|wizard_*)
    printf 'called\n' >> "$VPNCTL_SPEC_DIR/sshpass-called"
    [ "$1" = -e ] || exit 99
    shift
    exec "$@" ;;
  *) printf '%s\n' "$0" >> "$VPNCTL_SPEC_DIR/forbidden.log"; exit 99 ;;
esac
"#,
        );
        for name in ["scp", "sftp", "rsync"] {
            executable(
                &bin.join(name),
                "#!/bin/sh\nprintf '%s\\n' \"$0\" >> \"$VPNCTL_SPEC_DIR/forbidden.log\"\nexit 99\n",
            );
        }
        let module = module_path!().split_once("::").unwrap().1;
        let mut child = Command::new(std::env::current_exe().unwrap());
        child
            .args([
                "--exact",
                &format!("{module}::isolated_child"),
                "--nocapture",
            ])
            .env(CASE_ENV, case)
            .env("VPNCTL_SPEC_DIR", dir.path())
            .env("VPNCTLD_DEPLOY_KEY", dir.path().join("deploy"))
            .env("VPNCTLD_SSH_TIMEOUT_SECS", "10")
            .env_remove("VPNCTLD_REFERENCE_SSH_KEY")
            .env_remove("SSH_AUTH_SOCK")
            .env("HOME", dir.path())
            .env("TMPDIR", dir.path())
            .env("XDG_CONFIG_HOME", dir.path())
            .env("PATH", format!("{}:/usr/bin:/bin", bin.display()));
        if case == "password_reference_pin_failure" {
            child.env("VPNCTLD_REFERENCE_SSH_KEY", dir.path().join("deploy"));
        }
        let output = child.output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "case {case} must execute exactly one passing child:\n{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn wizard_pins_first_login_key_for_every_later_connection() {
        run_case("wizard_root_pin_match");
        run_case("wizard_hashed_pin_match");
    }

    #[test]
    fn wizard_keyscan_mismatch_stops_before_second_password_login() {
        run_case("wizard_root_pin_mismatch");
        run_case("wizard_nonroot_pin_mismatch");
    }

    #[test]
    fn wizard_key_auth_keeps_first_login_pin() {
        run_case("wizard_key_changed");
    }

    #[test]
    fn wizard_missing_accepted_key_stops_before_second_password_login() {
        run_case("wizard_missing_known_hosts");
    }

    #[test]
    fn wizard_with_several_accepted_keys_pins_the_presented_one() {
        run_case("wizard_ambiguous_known_hosts");
    }

    #[test]
    fn wizard_ssh_443_skips_reality_before_registration_with_visible_note() {
        run_case("wizard_ssh_443");
    }

    #[test]
    fn existing_key_accepts_nonroot_without_password_or_reference_key() {
        run_case("success");
    }

    #[test]
    fn existing_key_preserves_jump_and_host_pinning() {
        run_case("jump");
    }

    #[test]
    fn repeated_success_reverifies_but_does_not_audit_a_noop() {
        run_case("repeat");
    }

    #[test]
    fn failed_key_leaves_login_and_audit_unchanged() {
        run_case("key_failure");
    }

    #[test]
    fn failed_noninteractive_sudo_leaves_login_and_audit_unchanged() {
        run_case("sudo_failure");
    }

    #[test]
    fn host_pin_mismatch_leaves_login_and_audit_unchanged() {
        run_case("pin_failure");
    }

    #[test]
    fn timeout_leaves_login_and_audit_unchanged() {
        run_case("timeout");
    }

    #[test]
    fn absent_trusted_pin_is_rejected_before_ssh() {
        run_case("missing_pin");
    }

    #[test]
    fn missing_daemon_key_does_not_fallback_or_change_login() {
        run_case("missing_key");
    }

    #[test]
    fn invalid_users_are_rejected_before_any_ssh_or_keyscan() {
        run_case("invalid_users");
    }

    #[test]
    fn invalid_auth_method_is_rejected_before_any_ssh_or_keyscan() {
        run_case("invalid_method");
    }

    #[test]
    fn accepted_username_length_boundary_is_not_truncated() {
        run_case("user_boundary");
    }

    #[test]
    fn default_password_mode_still_requires_password_without_reference_key() {
        run_case("legacy_empty_password");
    }

    #[test]
    fn unknown_server_is_not_created_or_contacted() {
        run_case("unknown_server");
    }

    #[test]
    fn password_push_uses_inventory_pin_without_shared_known_hosts() {
        run_case("password_pin");
    }

    #[test]
    fn password_push_rejects_mismatched_pin_before_sending_password() {
        run_case("password_pin_failure");
    }

    #[test]
    fn reference_key_fallback_does_not_bypass_password_host_pin() {
        run_case("password_reference_pin_failure");
    }

    #[test]
    fn password_first_contact_retains_tofu() {
        run_case("password_tofu");
    }

    #[test]
    fn password_command_timeout_kills_child() {
        run_case("password_timeout");
    }

    #[test]
    fn cancelled_deploy_keeps_guard_until_ssh_finishes() {
        run_case("deploy_cancel");
    }

    fn read_log(root: &FsPath, name: &str) -> String {
        match fs::read_to_string(root.join(name)) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => panic!("cannot read fixture log: {error}"),
        }
    }

    fn assert_no_connection(root: &FsPath) {
        assert!(read_log(root, "transport.log").is_empty());
        assert!(read_log(root, "keyscan.log").is_empty());
        assert!(read_log(root, "forbidden.log").is_empty());
    }

    fn assert_verification_only(root: &FsPath) {
        assert!(
            read_log(root, "forbidden.log").is_empty(),
            "verification must not invoke password authentication/file transfer"
        );
        let log = read_log(root, "transport.log");
        for forbidden in [
            "authorized_keys",
            "ssh-copy-id",
            "apt-get",
            "systemctl",
            "docker run",
            "useradd",
            "usermod",
            "chmod",
            "chown",
            "tee ",
            ">>",
        ] {
            assert!(
                !log.contains(forbidden),
                "existing-key mode must only verify, found {forbidden:?}: {log}"
            );
        }
    }

    fn assert_transport(root: &FsPath, requested_user: &str, jump: bool) {
        let log = read_log(root, "transport.log");
        assert!(!log.is_empty(), "success cannot be synthesized without SSH");
        assert!(log.contains(HOST), "SSH must target the selected server");
        assert!(log.contains("2222"), "custom SSH port must survive");
        assert!(
            log.contains(&format!("{requested_user}@{HOST}"))
                || log.contains(&format!("\n{requested_user}\n"))
                || log.lines().any(|line| {
                    line.split_whitespace().collect::<Vec<_>>() == ["User", requested_user]
                }),
            "SSH must use submitted login, not old/root login: {log}"
        );
        assert!(!log.contains(&format!("{OLD_USER}@")));
        assert!(!log.contains(&format!("root@{HOST}")));
        assert!(
            log.contains(root.join("deploy").to_str().unwrap()),
            "daemon's own deploy identity must be selected explicitly: {log}"
        );
        for option in ["IdentitiesOnly", "BatchMode"] {
            assert!(
                log.contains(&format!("{option}=yes"))
                    || log.lines().any(|line| {
                        line.split_whitespace().collect::<Vec<_>>() == [option, "yes"]
                    }),
                "own-key verification requires {option}=yes: {log}"
            );
            assert!(
                !log.contains(&format!("{option}=no"))
                    && !log.lines().any(|line| {
                        line.split_whitespace().collect::<Vec<_>>() == [option, "no"]
                    }),
                "own-key verification must not disable {option}: {log}"
            );
        }
        assert!(
            log.contains("StrictHostKeyChecking=yes")
                || log.lines().any(|line| {
                    line.split_whitespace().collect::<Vec<_>>() == ["StrictHostKeyChecking", "yes"]
                }),
            "must preserve strict host-key checking: {log}"
        );
        assert!(
            log.contains("UserKnownHostsFile=")
                || log
                    .lines()
                    .any(|line| { line.split_whitespace().next() == Some("UserKnownHostsFile") })
        );
        assert!(!log.contains("StrictHostKeyChecking=no"));
        assert!(
            log.contains("sudo -n sh -c"),
            "nonroot must prove the exact sudo -n sh -c capability, not sudo true/id: {log}"
        );
        if jump {
            assert!(log.contains(JUMP), "configured jump must survive: {log}");
        }
        assert_verification_only(root);
    }

    async fn login(state: &AppState) -> String {
        state
            .inv
            .get_server(&ServerId("existing-key-spec".into()))
            .await
            .unwrap()
            .unwrap()
            .ssh_user
    }

    async fn call(state: &AppState, id: &str, form: &str) -> Response {
        server_push_deploy_key(Path(id.to_owned()), State(state.clone()), form.to_owned()).await
    }

    fn assert_success(response: &Response) {
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get("location").unwrap(),
            "/admin/servers/existing-key-spec/setup#push-deploy-key"
        );
    }

    #[test]
    fn isolated_child() {
        let Ok(case) = std::env::var(CASE_ENV) else {
            return;
        };
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let root = PathBuf::from(std::env::var("VPNCTL_SPEC_DIR").unwrap());
                assert_eq!(
                    std::env::var_os("VPNCTLD_REFERENCE_SSH_KEY").is_some(),
                    case == "password_reference_pin_failure"
                );
                let inv = SqliteInventory::open(&root.join("inventory.db"))
                    .await
                    .unwrap();
                let mut registry = Registry::new();
                if case == "wizard_ssh_443" {
                    registry = crate::app::build_registry().unwrap();
                }
                if case == "deploy_cancel" {
                    registry
                        .register_kernel(Box::new(vpnctl_kernels::Xray::new()))
                        .unwrap();
                }
                let (state, _writer) =
                    crate::app::make_app_state_for_tests(inv, Arc::new(registry));
                let fingerprint = Command::new("ssh-keygen")
                    .args(["-lf"])
                    .arg(root.join(
                        if matches!(
                            case.as_str(),
                            "pin_failure"
                                | "password_pin_failure"
                                | "password_reference_pin_failure"
                        ) {
                            "deploy.pub"
                        } else {
                            "host.pub"
                        },
                    ))
                    .output()
                    .unwrap();
                assert!(fingerprint.status.success());
                let fingerprint = String::from_utf8(fingerprint.stdout)
                    .unwrap()
                    .split_whitespace()
                    .nth(1)
                    .unwrap()
                    .to_owned();
                if case.starts_with("wizard_") {
                    use crate::wizard_bootstrap::{BootstrapEvent, BootstrapPlan, run_bootstrap};
                    use tokio_stream::StreamExt;

                    let root_login =
                        case.starts_with("wizard_root_") || case == "wizard_key_changed";
                    let events: Vec<_> = run_bootstrap(
                        BootstrapPlan {
                            server_id: "wizard-spec".into(),
                            address: HOST.into(),
                            ssh_user: if root_login { "root" } else { "debian" }.into(),
                            ssh_port: if case == "wizard_ssh_443" {
                                443
                            } else if root_login {
                                22
                            } else {
                                2222
                            },
                            root_password: "SPEC_PASSWORD".into(),
                            deploy_key_path: root.join("deploy"),
                            known_hosts_path: root.join("known_hosts"),
                        },
                        state.inv.clone(),
                        std::sync::Arc::clone(&state.registry),
                    )
                    .collect()
                    .await;
                    let password_calls = read_log(&root, "sshpass-called").lines().count();
                    let log = read_log(&root, "transport.log");
                    assert_eq!(log.matches("StrictHostKeyChecking=accept-new").count(), 1);
                    let stored = state
                        .inv
                        .get_server(&ServerId("wizard-spec".into()))
                        .await
                        .unwrap();
                    if case.ends_with("pin_mismatch")
                        || matches!(case.as_str(), "wizard_missing_known_hosts")
                    {
                        assert_eq!(password_calls, 1, "must not send password again");
                        assert!(!log.contains("authorized_keys"));
                        assert!(stored.is_none());
                        assert!(matches!(events.last(), Some(BootstrapEvent::Error { .. })));
                    } else if case == "wizard_key_changed" {
                        assert_eq!(password_calls, 2);
                        assert!(stored.is_none());
                        assert!(matches!(
                            events.last(),
                            Some(BootstrapEvent::Error {
                                phase: "verify-key",
                                ..
                            })
                        ));
                    } else {
                        assert_eq!(password_calls, if root_login { 2 } else { 3 });
                        assert_eq!(
                            stored.as_ref().unwrap().trusted_host_fingerprint,
                            Some(fingerprint)
                        );
                        assert!(log.contains("StrictHostKeyChecking yes"));
                        if case == "wizard_ssh_443" {
                            assert!(
                                !stored
                                    .unwrap()
                                    .enabled_protocols
                                    .iter()
                                    .any(|p| p.0 == "vless+reality")
                            );
                            assert!(events.iter().any(|event| matches!(
                                event,
                                BootstrapEvent::Step { phase: "register", message }
                                    if message.contains("vless+reality was skipped")
                                        && message.contains("443 is used by SSH")
                            )));
                        } else {
                            assert!(matches!(events.last(), Some(BootstrapEvent::Ok { .. })));
                        }
                    }
                    return;
                }
                let jump = case == "jump";
                let mut server = Server {
                    id: ServerId("existing-key-spec".into()),
                    address: HOST.into(),
                    ssh_port: 2222,
                    ssh_user: OLD_USER.into(),
                    kernels: if case == "deploy_cancel" {
                        vec![vpnctl_core::KernelId("xray".into())]
                    } else {
                        vec![]
                    },
                    enabled_protocols: vec![],
                    trusted_host_fingerprint: if matches!(
                        case.as_str(),
                        "missing_pin" | "password_tofu"
                    ) {
                        None
                    } else {
                        Some(fingerprint.clone())
                    },
                    hoster: "generic".into(),
                    jump_via: None,
                    usage_coefficient: 1.0,
                };
                if jump {
                    let mut gateway = server.clone();
                    gateway.id = ServerId("existing-key-jump".into());
                    gateway.address = JUMP.into();
                    gateway.ssh_port = 22;
                    gateway.ssh_user = "jump-user".into();
                    state.inv.add_server(&gateway).await.unwrap();
                    server.jump_via = Some(gateway.id);
                }
                state.inv.add_server(&server).await.unwrap();
                let audit_before = state.inv.recent_audit(100).await.unwrap().len();
                let id = "existing-key-spec";
                if case == "deploy_cancel" {
                    let request_state = state.clone();
                    let request = tokio::spawn(async move {
                        server_deploy(State(request_state), Path("existing-key-spec".into())).await
                    });
                    tokio::time::timeout(std::time::Duration::from_secs(5), async {
                        while !root.join("ssh-started").exists() {
                            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                        }
                    })
                    .await
                    .unwrap();
                    request.abort();
                    assert!(request.await.unwrap_err().is_cancelled());
                    let guard_retained =
                        crate::wizard_bootstrap::DeployGuard::try_acquire(id).is_none();
                    // Release SSH before asserting so a regression cannot hang runtime shutdown.
                    if !guard_retained {
                        fs::write(root.join("ssh-release"), "").unwrap();
                    }
                    assert!(
                        guard_retained,
                        "cancelling the handler released the deploy guard"
                    );
                    let second = server_deploy(State(state.clone()), Path(id.into())).await;
                    fs::write(root.join("ssh-release"), "").unwrap();
                    assert_eq!(second.status(), StatusCode::CONFLICT);
                    tokio::time::timeout(std::time::Duration::from_secs(5), async {
                        loop {
                            if let Some(guard) =
                                crate::wizard_bootstrap::DeployGuard::try_acquire(id)
                            {
                                drop(guard);
                                break;
                            }
                            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                        }
                    })
                    .await
                    .unwrap();
                    return;
                }
                if case.starts_with("password_") {
                    // Exercise both the ordinary password path and reference-key fallback.
                    let started = std::time::Instant::now();
                    let response =
                        call(&state, id, "ssh_user=debian&root_password=SPEC_PASSWORD").await;
                    let log = read_log(&root, "transport.log");
                    if case.ends_with("pin_failure") {
                        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
                        assert!(!root.join("sshpass-called").exists());
                        assert!(log.is_empty(), "host pin mismatch must prevent remote work");
                    } else if case == "password_timeout" {
                        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
                        assert!(started.elapsed() < std::time::Duration::from_secs(20));
                        let pid = fs::read_to_string(root.join("ssh.pid")).unwrap();
                        assert!(!PathBuf::from(format!("/proc/{}", pid.trim())).exists());
                        let body = axum::body::to_bytes(response.into_body(), 1_048_576)
                            .await
                            .unwrap();
                        assert!(String::from_utf8_lossy(&body).contains("timed out"));
                    } else {
                        assert_success(&response);
                        assert!(root.join("sshpass-called").exists());
                        if case == "password_tofu" {
                            assert!(log.contains("StrictHostKeyChecking=accept-new"));
                        } else {
                            assert!(log.contains("StrictHostKeyChecking yes"));
                            assert!(log.contains("BatchMode=no"));
                            assert!(!log.contains("accept-new"));
                        }
                    }
                    return;
                }
                if case == "invalid_users" {
                    for user in [
                        "",
                        "a%20b",
                        "a%09b",
                        "a%0Ab",
                        "a%0Db",
                        "a%00b",
                        "a%3Bb",
                        "a%24%28id%29",
                        "a%60id%60",
                        "a%2Fb",
                        "a%40b",
                        "a%27b",
                        "a%22b",
                        "abcdefghijklmnopqrstuvwxyz1234567",
                    ] {
                        let response = call(
                            &state,
                            id,
                            &format!("auth_method=deploy-key&ssh_user={user}"),
                        )
                        .await;
                        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "user {user:?}");
                        assert_no_connection(&root);
                        assert_eq!(login(&state).await, OLD_USER);
                        assert_eq!(
                            state.inv.recent_audit(100).await.unwrap().len(),
                            audit_before
                        );
                    }
                    return;
                }
                if case == "invalid_method" || case == "legacy_empty_password" {
                    let forms: &[&str] = if case == "invalid_method" {
                        &[
                            "auth_method=not-a-method&ssh_user=debian",
                            "auth_method=DEPLOY-KEY&ssh_user=debian",
                            "auth_method=deploy-key%3Bid&ssh_user=debian",
                        ]
                    } else {
                        &["root_password=", "ssh_user=debian&root_password="]
                    };
                    for form in forms {
                        let response = call(&state, id, form).await;
                        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "form {form}");
                        assert_no_connection(&root);
                        assert_eq!(login(&state).await, OLD_USER);
                        assert_eq!(
                            state.inv.recent_audit(100).await.unwrap().len(),
                            audit_before
                        );
                    }
                    return;
                }
                if case == "unknown_server" {
                    let response = call(
                        &state,
                        "does-not-exist",
                        "auth_method=deploy-key&ssh_user=debian",
                    )
                    .await;
                    assert_eq!(response.status(), StatusCode::NOT_FOUND);
                    assert_no_connection(&root);
                    assert_eq!(state.inv.list_servers().await.unwrap().len(), 1);
                    assert_eq!(
                        state.inv.recent_audit(100).await.unwrap().len(),
                        audit_before
                    );
                    return;
                }
                if case == "missing_key" {
                    fs::remove_file(root.join("deploy")).unwrap();
                    fs::remove_file(root.join("deploy.pub")).unwrap();
                }
                let user = if case == "user_boundary" {
                    "abcdefghijklmnopqrstuvwxyz123456"
                } else {
                    "debian"
                };
                let form = format!("auth_method=deploy-key&ssh_user={user}");
                let started = std::time::Instant::now();
                let response = call(&state, id, &form).await;
                if case == "timeout" {
                    assert!(
                        started.elapsed() < std::time::Duration::from_secs(25),
                        "the handler must time out instead of waiting for fake ssh to finish"
                    );
                    assert!(!read_log(&root, "transport.log").is_empty());
                }
                if matches!(
                    case.as_str(),
                    "key_failure"
                        | "sudo_failure"
                        | "pin_failure"
                        | "missing_key"
                        | "missing_pin"
                        | "timeout"
                ) {
                    assert!(
                        response.status().is_client_error() || response.status().is_server_error(),
                        "operational failure must not return success/redirect: {}",
                        response.status()
                    );
                    assert_eq!(login(&state).await, OLD_USER);
                    assert_eq!(
                        state.inv.recent_audit(100).await.unwrap().len(),
                        audit_before
                    );
                    assert_verification_only(&root);
                    if case == "sudo_failure" {
                        assert!(read_log(&root, "transport.log").contains("sudo -n sh -c"));
                    }
                    if case == "key_failure" {
                        assert!(!read_log(&root, "transport.log").is_empty());
                    }
                    if case == "missing_pin" {
                        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
                        assert_no_connection(&root);
                    }
                    if case == "pin_failure" {
                        assert!(
                            read_log(&root, "transport.log").is_empty(),
                            "mismatched pin must abort before login or remote command"
                        );
                    }
                    let body = axum::body::to_bytes(response.into_body(), 1_048_576)
                        .await
                        .unwrap();
                    assert!(
                        !String::from_utf8_lossy(&body).contains("SPEC_SECRET_MUST_NOT_LEAK"),
                        "raw SSH stderr must not leak potentially secret remote diagnostics"
                    );
                    return;
                }
                assert_success(&response);
                assert_eq!(login(&state).await, user);
                assert_transport(&root, user, jump);
                let audits = state.inv.recent_audit(100).await.unwrap();
                assert_eq!(
                    audits.len(),
                    audit_before + 1,
                    "exactly one login mutation audit"
                );
                assert_eq!(audits[0].target.as_deref(), Some(id));
                let persisted = state.inv.get_server(&server.id).await.unwrap().unwrap();
                assert_eq!(persisted.address, server.address);
                assert_eq!(persisted.ssh_port, server.ssh_port);
                assert_eq!(persisted.jump_via, server.jump_via);
                assert_eq!(
                    persisted.trusted_host_fingerprint,
                    server.trusted_host_fingerprint
                );
                assert_eq!(persisted.kernels, server.kernels);
                assert_eq!(persisted.enabled_protocols, server.enabled_protocols);
                if case == "repeat" {
                    let first_log = read_log(&root, "transport.log");
                    let response = call(&state, id, &form).await;
                    assert_success(&response);
                    assert_eq!(login(&state).await, user);
                    assert_eq!(
                        state.inv.recent_audit(100).await.unwrap().len(),
                        audits.len()
                    );
                    assert!(
                        read_log(&root, "transport.log").len() > first_log.len(),
                        "a no-op login must still reverify current access"
                    );
                    assert_transport(&root, user, false);
                }
            });
    }
}
