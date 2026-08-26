use std::process::{Command, Stdio};

use crate::ssh_subprocess::ssh_safety_opts;

/// Pick a free server id given the set of existing ids and a base
/// name derived from the operator's address input. Returns the base
/// unchanged if it's free; otherwise appends `-2`, `-3`, … until a
/// free slot is found. Bounded to avoid an infinite loop on a
/// pathological inventory.
///
/// Pure function with no I/O — testable in isolation; the SSE handler
/// fetches `inv.list_servers()` once and passes the id set in.
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

/// Replace any occurrence of `password` in the sshpass/ssh stderr
/// stream with a redaction placeholder, then trim. Defensive — the
/// stock OpenSSH client does NOT echo the password and sshpass
/// intercepts the prompt without echoing either, so this should
/// never fire in practice. If it ever does (LogLevel=DEBUG on a
/// nonstandard sshd config, future sshpass version change), the
/// password won't end up in the SSE stream visible to the browser DOM
/// or in the daemon's tracing log.
pub(super) fn redact_password(stderr: &str, password: &str) -> String {
    let trimmed = stderr.trim();
    if password.is_empty() || !trimmed.contains(password) {
        return trimmed.to_string();
    }
    trimmed.replace(password, "<redacted>")
}

/// Derive a server id from an address. The wizard step-1 form
/// intentionally has no separate "id" field — operators shouldn't
/// have to name things (one-action ceiling). The id has to satisfy
/// the inventory's allowed alphabet (alphanumeric + `.` + `_` + `-`)
/// and the server-detail URL's path-encoding.
///
/// Strategy: replace `:` (IPv6 separator) with `-` so the result is
/// `[A-Za-z0-9.-]`. If the address is already alphanumeric+dots, it
/// passes through unchanged (so `198.51.100.42` stays
/// `198.51.100.42`). Caller is responsible for collision detection.
pub fn derive_server_id(address: &str) -> String {
    address
        .chars()
        .map(|c| if c == ':' { '-' } else { c })
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        .collect()
}

/// Run a remote command via `sshpass -e ssh` (password auth). Returns
/// the remote's stdout on success or a `String` error message on
/// any non-zero exit / spawn failure.
///
/// `BatchMode=no` is implicit (sshpass injects the password by
/// answering the prompt that BatchMode would otherwise suppress).
/// `accept-new` for first connect, after which the host key is pinned
/// in the daemon's known_hosts.
///
/// Password lives in the `SSHPASS` env var (sshpass's `-e` flag) so
/// it never appears in argv — `ps auxe` wouldn't expose it (only
/// `/proc/PID/environ`, which is root-only on Linux).
///
/// Public so the post-Phase-E «push deploy key to an existing
/// inventory server» button (`/admin/servers/{id}/push-deploy-key`)
/// can reuse it without re-implementing the sshpass dance — same
/// safety contract, same `--` separator defenses, same known_hosts
/// file.
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

    // Build argv BEFORE moving into spawn_blocking — `ssh_safety_opts`
    // borrows `known_hosts: &Path` which is not `'static`, so the
    // safety-opts block must be materialised here (owned Strings) and
    // captured by move.
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
    // POSIX getopt separator — same defense as `build_ssh_args` /
    // `build_keyscan_args`. Today `userhost` starts with «root@…»
    // (literal `r`) so no dash, but a future refactor allowing
    // non-root users from inventory would re-open flag-injection
    // without this guard.
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
            format!("spawning sshpass: {e} (is sshpass installed on the daemon host?)")
        })?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // redact_password defends against the (theoretical) case
            // where ssh/sshpass echoes the password literal into
            // stderr — the SSE event payload is visible in the
            // operator's browser DOM, so anything that ends up here
            // ends up in JS land.
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
