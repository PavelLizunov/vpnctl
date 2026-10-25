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
    trusted_fingerprint: Option<&str>,
    remote_cmd: &str,
) -> std::result::Result<String, String> {
    crate::ssh_subprocess::SubprocessSshTransport::new(
        host,
        user,
        std::path::PathBuf::from("/dev/null"),
    )
    .port(port)
    .known_hosts(known_hosts.to_path_buf())
    .trusted_fingerprint(trusted_fingerprint.map(str::to_string))
    .exec_password(password, remote_cmd)
    .await
    .map_err(|e| {
        if let vpnctl_core::CoreError::Transport(message) = &e {
            if message.starts_with("spawning ssh ") {
                return format!(
                    "vpnctld cannot run sshpass on its own host ({}); this is a daemon \
                     installation problem — the vpnctld host needs the sshpass package",
                    redact_password(message, password)
                );
            }
        }
        redact_password(&e.to_string(), password)
    })
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
