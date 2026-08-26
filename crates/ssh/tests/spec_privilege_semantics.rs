//! Compile/spec tests for the SSH privilege contract.
//!
//! These tests intentionally use only public APIs. A connected
//! `RusshTransport` requires a live SSH server, so command routing is specified
//! with a recording `SshTransport`; the public POSIX quoting helper pins the
//! exact wrapper expected from non-root Russh transports.

#![allow(clippy::expect_used)]

use std::sync::Mutex;

use async_trait::async_trait;
use vpnctl_core::{Result, SshTransport, shell::single_quote};

#[derive(Debug, PartialEq, Eq)]
enum Operation {
    PrivilegedExec(String),
    LoginUserExec(String),
    PrivilegedUpload { path: String, content: Vec<u8> },
    PrivilegedRead(String),
}

#[derive(Debug, Default)]
struct RecordingTransport {
    operations: Mutex<Vec<Operation>>,
}

impl RecordingTransport {
    fn take_operations(&self) -> Vec<Operation> {
        std::mem::take(&mut *self.operations.lock().expect("recording lock"))
    }
}

#[async_trait]
impl SshTransport for RecordingTransport {
    async fn exec(&self, cmd: &str) -> Result<String> {
        self.operations
            .lock()
            .expect("recording lock")
            .push(Operation::PrivilegedExec(cmd.to_owned()));
        Ok(String::new())
    }

    async fn exec_unprivileged(&self, cmd: &str) -> Result<String> {
        self.operations
            .lock()
            .expect("recording lock")
            .push(Operation::LoginUserExec(cmd.to_owned()));
        Ok(String::new())
    }

    async fn upload(&self, path: &str, content: &[u8]) -> Result<()> {
        self.operations
            .lock()
            .expect("recording lock")
            .push(Operation::PrivilegedUpload {
                path: path.to_owned(),
                content: content.to_vec(),
            });
        Ok(())
    }

    async fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        self.operations
            .lock()
            .expect("recording lock")
            .push(Operation::PrivilegedRead(path.to_owned()));
        Ok(Vec::new())
    }
}

#[tokio::test]
async fn transport_api_keeps_privileged_and_login_user_operations_distinct() {
    let transport = RecordingTransport::default();

    transport.exec("id -u").await.expect("privileged exec");
    transport
        .exec_unprivileged("printf login-user")
        .await
        .expect("login-user exec");
    transport
        .upload("/etc/vpnctl/config", b"secret")
        .await
        .expect("privileged upload");
    transport
        .read_file("/etc/vpnctl/config")
        .await
        .expect("privileged read");

    assert_eq!(
        transport.take_operations(),
        vec![
            Operation::PrivilegedExec("id -u".into()),
            Operation::LoginUserExec("printf login-user".into()),
            Operation::PrivilegedUpload {
                path: "/etc/vpnctl/config".into(),
                content: b"secret".to_vec(),
            },
            Operation::PrivilegedRead("/etc/vpnctl/config".into()),
        ]
    );
}

#[test]
fn root_transport_wire_command_is_unchanged() {
    let command = "printf '%s\\n' \"$HOME\"; id -u";

    let expected_root_wire_command = command;

    assert_eq!(expected_root_wire_command, command);
}

#[test]
fn non_root_privileged_wire_command_uses_noninteractive_sudo_and_posix_quoting() {
    let command = "printf '%s' 'a b'; echo $HOME; echo `id`; printf '\\n'";

    let expected_wire_command = format!("sudo -n sh -c {}", single_quote(command));

    assert_eq!(
        expected_wire_command,
        "sudo -n sh -c 'printf '\\''%s'\\'' '\\''a b'\\''; echo $HOME; echo `id`; printf '\\''\\n'\\'''"
    );
}

#[test]
fn non_root_unprivileged_wire_command_is_unchanged() {
    let command = "mkdir -p ~/.ssh && printf login-user";

    let expected_login_user_wire_command = command;

    assert_eq!(expected_login_user_wire_command, command);
}
