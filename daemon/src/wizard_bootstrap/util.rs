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
