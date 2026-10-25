#![allow(clippy::expect_used)]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

use vpnctl_core::SshTransport;
use vpnctl_ssh::SubprocessSshTransport;

const WORKER_ENV: &str = "VPNCTL_PRIVILEGE_TEST_WORKER";

fn with_fake_ssh(test_name: &str) -> bool {
    if std::env::var(WORKER_ENV).as_deref() == Ok(test_name) {
        return true;
    }

    let tmp = tempfile::TempDir::new().expect("tmpdir");
    let ssh = tmp.path().join("ssh");
    std::fs::write(
        &ssh,
        "#!/bin/sh\nfor arg do :; done\nprintf '%s' \"$arg\"\n",
    )
    .expect("write fake ssh");
    std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o700))
        .expect("make fake ssh executable");

    // Override PATH only in a child so parallel tests keep their environment.
    let output = Command::new(std::env::current_exe().expect("test binary"))
        .args(["--exact", test_name, "--nocapture"])
        .env(WORKER_ENV, test_name)
        .env("PATH", tmp.path())
        .output()
        .expect("run transport test with fake ssh");
    assert!(
        output.status.success(),
        "transport worker failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
    false
}

#[tokio::test]
async fn root_transport_wire_command_is_unchanged() {
    if !with_fake_ssh("root_transport_wire_command_is_unchanged") {
        return;
    }
    let transport = SubprocessSshTransport::new("example.invalid", "root", PathBuf::from("key"));
    let command = "printf '%s\\n' \"$HOME\"; id -u";

    assert_eq!(transport.exec(command).await.expect("root exec"), command);
}

#[tokio::test]
async fn non_root_privileged_wire_command_uses_noninteractive_sudo_and_posix_quoting() {
    if !with_fake_ssh("non_root_privileged_wire_command_uses_noninteractive_sudo_and_posix_quoting")
    {
        return;
    }
    let transport =
        SubprocessSshTransport::new("example.invalid", "operator", PathBuf::from("key"));
    let command = "printf '%s' 'a b'; echo $HOME; echo `id`; printf '\\n'";

    assert_eq!(
        transport.exec(command).await.expect("privileged exec"),
        r"sudo -n sh -c 'printf '\''%s'\'' '\''a b'\''; echo $HOME; echo `id`; printf '\''\n'\'''"
    );
}

#[tokio::test]
async fn non_root_unprivileged_wire_command_is_unchanged() {
    if !with_fake_ssh("non_root_unprivileged_wire_command_is_unchanged") {
        return;
    }
    let transport =
        SubprocessSshTransport::new("example.invalid", "operator", PathBuf::from("key"));
    let command = "mkdir -p ~/.ssh && printf login-user";

    assert_eq!(
        SshTransport::exec_unprivileged(&transport, command)
            .await
            .expect("login-user exec"),
        command
    );
}
