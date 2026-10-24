use std::process::{Command, Stdio};

use crate::ssh_subprocess::ssh_safety_opts;

pub fn find_available_server_id(
    existing: &std::collections::HashSet<String>,
    base: &str,
) -> std::result::Result<String, String> {
    if !existing.contains(base) {
        return Ok(base.to_string());
    }
    for n in 2u32..=1000u32 {
        let candidate = format!("{base}-{n}");
        if !existing.contains(&candidate) {
            return Ok(candidate);
        }
    }
    Err(format!(
        "all id slots 2..1000 taken for base '{base}' — operator should delete stale servers first"
    ))
}

pub(super) fn redact_password(stderr: &str, password: &str) -> String {
    let trimmed = stderr.trim();
    if password.is_empty() || !trimmed.contains(password) {
        return trimmed.to_string();
    }
    trimmed.replace(password, "<redacted>")
}

/// Idempotent deploy-key push. A last line without its trailing LF gets one
/// first, so the new key is never glued onto an existing key.
pub fn authorized_key_push_cmd(pubkey: &str) -> String {
    format!(
        "set -eu; \
         mkdir -p ~/.ssh && chmod 0700 ~/.ssh; \
         touch ~/.ssh/authorized_keys && chmod 0600 ~/.ssh/authorized_keys; \
         if ! grep -qxF {pk_q} ~/.ssh/authorized_keys; then \
         if [ -s ~/.ssh/authorized_keys ] && [ -n \"$(tail -c 1 ~/.ssh/authorized_keys)\" ]; then \
         echo >> ~/.ssh/authorized_keys; fi; \
         printf '%s\\n' {pk_q} >> ~/.ssh/authorized_keys; fi; \
         echo done",
        pk_q = vpnctl_core::shell::single_quote(pubkey),
    )
}

pub fn derive_server_id(address: &str) -> String {
    address
        .chars()
        .map(|c| if c == ':' { '-' } else { c })
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        .collect()
}

pub async fn ssh_password_run(
    host: &str,
    port: u16,
    user: &str,
    password: &str,
    known_hosts: &std::path::Path,
    remote_cmd: &str,
) -> std::result::Result<String, String> {
    let pw = password.to_string();
    let host = host.to_string();
    let user = user.to_string();
    let cmd_owned = remote_cmd.to_string();
    let port_s = port.to_string();
    let userhost = format!("{user}@{host}");

    let mut args: Vec<String> = vec![
        "-e".into(),
        "ssh".into(),
        "-o".into(),
        "PreferredAuthentications=password".into(),
        "-o".into(),
        "PubkeyAuthentication=no".into(),
    ];
    args.extend(ssh_safety_opts(known_hosts, false));
    args.push("-p".into());
    args.push(port_s);
    args.push("--".into());
    args.push(userhost);
    args.push(cmd_owned);

    let pw_for_redact = pw.clone();
    tokio::task::spawn_blocking(move || {
        let mut cmd = Command::new("sshpass");
        cmd.env("SSHPASS", &pw)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let output = cmd.output().map_err(|e| {
            format!(
                "vpnctld cannot run sshpass on its own host ({e}); this is a daemon \
                 installation problem, not the node's IP or password — the vpnctld host \
                 needs the sshpass package"
            )
        })?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!(
                "sshpass exit={:?} stderr={}",
                output.status.code(),
                redact_password(&stderr, &pw_for_redact)
            ));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    })
    .await
    .map_err(|e| format!("spawn_blocking JoinError: {e}"))?
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod authorized_key_tests {
    use super::authorized_key_push_cmd;

    fn run_push(home: &std::path::Path, key: &str) {
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(authorized_key_push_cmd(key))
            .env("HOME", home)
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
    }

    #[test]
    fn push_keeps_last_key_without_trailing_newline_intact() {
        let dir = tempfile::TempDir::new().unwrap();
        let ssh = dir.path().join(".ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        let ak = ssh.join("authorized_keys");
        std::fs::write(&ak, "ssh-ed25519 AAAAexisting").unwrap();
        let new_key = "ssh-ed25519 AAAAdeploy vpnctl";
        run_push(dir.path(), new_key);
        run_push(dir.path(), new_key);
        assert_eq!(
            std::fs::read_to_string(&ak).unwrap(),
            "ssh-ed25519 AAAAexisting\nssh-ed25519 AAAAdeploy vpnctl\n"
        );
    }

    #[test]
    fn push_creates_file_when_absent() {
        let dir = tempfile::TempDir::new().unwrap();
        run_push(dir.path(), "ssh-ed25519 AAAAdeploy");
        assert_eq!(
            std::fs::read_to_string(dir.path().join(".ssh/authorized_keys")).unwrap(),
            "ssh-ed25519 AAAAdeploy\n"
        );
    }
}
