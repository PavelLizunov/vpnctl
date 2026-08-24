//! Pluggable alert push-transport. Phase G chunk 3.
//!
//! Phase G chunk 2 fires `admin_alerts` rows that show up on
//! `/admin/alerts` (pull). This module adds the **push** half — when
//! an alert fires, the operator gets notified out-of-band (Telegram
//! message today; ntfy.sh / journald-bridge later).
//!
//! ## Trait + implementations
//!
//! * [`AlertSink`] — the trait. One async method that takes the
//!   alert's kind / severity / summary and «delivers» it however the
//!   impl wants. Implementations are infallible-at-the-system-boundary
//!   in the sense that a delivery error is logged + swallowed (the
//!   alert is already persisted in `admin_alerts`; the push is a
//!   best-effort notification, not a primary record).
//! * [`NullSink`] — the no-op default used when the operator hasn't
//!   configured a transport. `send_text` returns `Ok(())` without
//!   touching the network.
//! * [`TelegramSink`] — POSTs to `api.telegram.org/bot<token>/
//!   sendMessage` via the system `curl` binary (no new HTTPS-client
//!   workspace dep — matches the Path C pattern from
//!   `daemon::ssh_subprocess`). Honours an optional outbound proxy
//!   via the `VPNCTLD_HTTPS_PROXY` env var so РФ-blocked endpoints
//!   can route through the homelab proxy on 192.168.0.142:18080.
//!
//! ## Why curl-subprocess, not reqwest
//!
//! Adding `reqwest` would pull `hyper` + `rustls` (or the system's
//! `openssl-sys`, which is forbidden by `deny.toml`). Both surfaces
//! expand the daemon's syscall footprint and risk pulling a glibc
//! ≥2.38 dependency that the bookworm host can't satisfy (Path C
//! lesson learned in 2026-05-16's crash-loop incident — see
//! CLAUDE.md). `curl` is bookworm-native, statically tested, and
//! already used implicitly by the kernel-install path in
//! `crates/kernels/src/sing_box.rs`.
//!
//! ## Via-server proxy mode (РФ workaround)
//!
//! When the daemon host can't reach `api.telegram.org` directly (РФ
//! network blocks, corporate NAT) the operator can route the call
//! through an inventory server by setting
//! `notification_settings.proxy_via_server_id`. The sink then SSHes
//! to that server using the existing deploy key and runs `curl`
//! THERE — the daemon doesn't need outbound HTTPS itself, only
//! outbound SSH to the inventory server (which it has anyway for
//! probes + deploys). The token + body still travel encrypted —
//! the bot-token URL is built locally and shell-quoted into the
//! remote command, the SSH tunnel encrypts in transit, the remote
//! curl establishes its own TLS to api.telegram.org from the
//! server's network. No long-lived tunnels, no proxy daemon on
//! the server.
//!
//! ## Why fire-and-forget at the caller (not here)
//!
//! `send_text` takes `&self` + returns `Result<(), Error>` so callers
//! can decide their own concurrency policy. The probe-poller spawns
//! the call to avoid blocking the next server's tick by ≤10s (curl's
//! configured connect timeout); a future synchronous test-send
//! handler awaits the same call directly to surface success/failure
//! to the operator. Neither concern belongs in the sink itself.

use std::process::{Command, Stdio};

use crate::ssh_subprocess::SubprocessSshTransport;
use vpnctl_core::shell::single_quote;

/// One sink transport. Implementors deliver alerts to wherever the
/// operator wants to be notified. Delivery errors are returned via
/// the `Result` so the caller can decide whether to surface them
/// (test-send handler) or swallow them (production fire-and-forget).
#[async_trait::async_trait]
pub trait AlertSink: Send + Sync {
    /// Send one alert. `text` is the ALREADY-RENDERED message body
    /// (localized + pretty — `alert_text::to_telegram_html` produces the
    /// Telegram HTML; the caller picks the locale). `kind` / `severity`
    /// are kept for transport-specific routing + log lines. `silent`
    /// asks the transport to deliver without a notification buzz
    /// (info / recovery alerts) where it supports it.
    ///
    /// Returns the transport's message id (Telegram `message_id` as a
    /// string) when it has one, so a later recovery can edit that message
    /// in place. `None` for transports without an editable-message
    /// concept (NullSink) or when the id couldn't be parsed.
    async fn send_text(
        &self,
        kind: &str,
        severity: &str,
        text: &str,
        silent: bool,
    ) -> Result<Option<String>, AlertSinkError>;

    /// Edit a previously-sent message in place — used by edit-on-recover
    /// to flip the original 🔴 alert message to 🟢 instead of sending a
    /// second message. `message_id` is the value `send_text` returned.
    /// No-op for transports that can't edit (NullSink).
    async fn edit_text(&self, message_id: &str, text: &str) -> Result<(), AlertSinkError>;

    /// Short identifier for log lines («telegram», «null»). Doesn't
    /// leak secrets — token-bearing transports omit the value.
    fn name(&self) -> &'static str;
}

/// Errors a sink may return. Operator-facing strings should be
/// suitable for showing in a 502 page; details (curl exit code,
/// stderr first line) live in the variant payload.
#[derive(Debug, thiserror::Error)]
pub enum AlertSinkError {
    /// Subprocess (`curl`) failed to spawn. Bookworm should always
    /// have curl pre-installed, but homelab cases (stripped container,
    /// path mangling) can hit this.
    #[error("alert-sink: spawning {tool} failed: {source}")]
    Spawn {
        tool: &'static str,
        #[source]
        source: std::io::Error,
    },

    /// Subprocess exited non-zero. The `stderr` is the first ~200
    /// chars of curl's stderr (truncated to avoid log spam).
    #[error("alert-sink: {tool} exited {code:?}: {stderr}")]
    NonZeroExit {
        tool: &'static str,
        code: Option<i32>,
        stderr: String,
    },

    /// Caller passed an empty / NULL token or chat_id. Indicates a
    /// caller-side bug — a properly configured sink should always
    /// have both halves; the partial-config UI surface should never
    /// produce a `TelegramSink` at all.
    #[error("alert-sink: misconfigured (token or chat_id empty)")]
    Misconfigured,
}

/// Classify a raw SSH transport error string into an actionable
/// operator-facing message. The default «SSH transport failed: …»
/// is correct but generic; the most common failure modes deserve
/// specific remediation steps.
///
/// Public so tests can pin the classifications.
pub fn classify_ssh_failure(stderr: &str) -> String {
    if stderr.contains("Permission denied (publickey") {
        format!(
            "deploy SSH key not authorised on the proxy server. \
             Open the server detail page → «Deploy SSH key — push to this server» \
             section → click «push deploy key» (uses VPNCTLD_REFERENCE_SSH_KEY \
             if set, or asks for root password). \
             Raw error: {stderr}"
        )
    } else if stderr.contains("Connection refused") {
        format!(
            "SSH connection refused — the server's sshd isn't listening on the \
             configured port. Check the server's `ssh_port` on /admin/servers/<id> \
             matches what's actually open. Raw error: {stderr}"
        )
    } else if stderr.contains("Connection timed out") || stderr.contains("Connection timeout") {
        format!(
            "SSH connection timed out — proxy server unreachable from the daemon. \
             Likely causes: server is down, firewall blocking the daemon's outbound, \
             wrong address on /admin/servers/<id>. Raw error: {stderr}"
        )
    } else if stderr.contains("Host key verification failed") {
        format!(
            "SSH host-key mismatch — the server's host key changed since the daemon \
             first connected. Verify the new fingerprint via console then update on \
             /admin/servers/<id> (Trusted host fingerprint section). Raw error: {stderr}"
        )
    } else {
        format!(
            "SSH transport failed: {stderr} \
             (deploy key authorised on the proxy server? \
             server reachable on its SSH port?)"
        )
    }
}

/// No-op sink. `send_text` returns `Ok(())` without I/O. Used when
/// the operator hasn't configured a transport — the alert still
/// lands in `admin_alerts` (Phase G chunk 2), just no push.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullSink;

#[async_trait::async_trait]
impl AlertSink for NullSink {
    async fn send_text(
        &self,
        _kind: &str,
        _severity: &str,
        _text: &str,
        _silent: bool,
    ) -> Result<Option<String>, AlertSinkError> {
        Ok(None)
    }

    async fn edit_text(&self, _message_id: &str, _text: &str) -> Result<(), AlertSinkError> {
        Ok(())
    }

    fn name(&self) -> &'static str {
        "null"
    }
}

/// Telegram bot transport. Posts to `api.telegram.org/bot<token>/
/// sendMessage` either:
///   * directly from the daemon host's network (default), optionally
///     through an HTTP proxy specified via `VPNCTLD_HTTPS_PROXY`, or
///   * through an inventory server via SSH-then-curl (when the
///     daemon host can't reach api.telegram.org but a VPN server
///     can). The server's TLS to api.telegram.org is direct from
///     the server's network; the daemon only needs outbound SSH.
///
/// The two egress modes are mutually exclusive — `via_ssh` wins
/// when set; the `proxy` field is ignored in that case (it would
/// be a property of the remote curl, not the local one).
///
/// Manual `Debug` (not derived) because `SubprocessSshTransport`
/// doesn't itself impl Debug and we don't want to add a workspace-
/// wide derive for it just to support this struct. Token is redacted
/// in the Debug output by design.
pub struct TelegramSink {
    token: String,
    chat_id: String,
    proxy: Option<String>,
    /// When `Some(...)`, the sink runs `curl` ON the remote server
    /// via SSH (uses the daemon's deploy key). When `None`, runs
    /// `curl` locally.
    via_ssh: Option<SubprocessSshTransport>,
}

impl std::fmt::Debug for TelegramSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TelegramSink")
            .field("token", &format!("•••• ({} chars)", self.token.len()))
            .field("chat_id", &self.chat_id)
            .field("proxy", &self.proxy)
            .field(
                "via_ssh",
                &self.via_ssh.as_ref().map(|_| "<SubprocessSshTransport>"),
            )
            .finish()
    }
}

impl TelegramSink {
    /// Construct. Empty `token` or `chat_id` returns `Err` rather
    /// than building a sink that will fail on every send — saves the
    /// caller a partial-config check.
    ///
    /// `proxy` is an explicit `Option<String>` parameter (not read
    /// from env) so tests can pin both code paths without touching
    /// process env state — `unsafe_code` is `forbid` workspace-wide,
    /// which rules out `std::env::set_var` in tests (edition 2024
    /// soundness fix). Production callers read the env var once and
    /// pass it in:
    /// ```text
    /// let proxy = std::env::var("VPNCTLD_HTTPS_PROXY").ok().filter(|s| !s.is_empty());
    /// TelegramSink::new(token, chat_id, proxy)?
    /// ```
    pub fn new(
        token: String,
        chat_id: String,
        proxy: Option<String>,
    ) -> Result<Self, AlertSinkError> {
        if token.is_empty() || chat_id.is_empty() {
            return Err(AlertSinkError::Misconfigured);
        }
        Ok(Self {
            token,
            chat_id,
            proxy: proxy.filter(|s| !s.is_empty()),
            via_ssh: None,
        })
    }

    /// Switch this sink to via-server proxy mode. The SSH transport
    /// is the daemon's normal deploy-key one pointed at an inventory
    /// server; `send_text` will run `curl` THERE instead of locally.
    /// Chainable.
    pub fn with_via_ssh(mut self, ssh: SubprocessSshTransport) -> Self {
        self.via_ssh = Some(ssh);
        self
    }

    /// Convenience constructor that reads `VPNCTLD_HTTPS_PROXY` from
    /// the env. Use in production wiring; tests call `new` directly
    /// to avoid env-state pollution.
    pub fn from_env(token: String, chat_id: String) -> Result<Self, AlertSinkError> {
        let proxy = std::env::var("VPNCTLD_HTTPS_PROXY").ok();
        Self::new(token, chat_id, proxy)
    }

    /// Redact the bot token in an arbitrary error/log string.
    /// Defense-in-depth: even with `-K -` stdin config, some curl
    /// failure modes echo the URL into stderr — and our error path
    /// surfaces that stderr into operator-readable places
    /// (settings_telegram_test's 502 response + audit_log row).
    ///
    /// Mirrors `wizard_bootstrap::redact_password` for the password
    /// path. Replaces every literal occurrence of the token with
    /// `••••<last4>` so the operator still sees which credential
    /// failed but the secret bytes don't leak. Empty-token guard
    /// is defensive — constructor rejects empty tokens, so this
    /// branch should be unreachable in practice.
    ///
    /// Bug-hunt agent finding 2026-05-18.
    fn redact_token(&self, s: &str) -> String {
        if self.token.is_empty() {
            return s.to_string();
        }
        let last4: &str = self
            .token
            .get(self.token.len().saturating_sub(4)..)
            .unwrap_or("");
        s.replace(&self.token, &format!("••••{last4}"))
    }

    /// Build the *remote* shell command that runs `curl` on the
    /// inventory server, reading the token-bearing URL from stdin
    /// via `curl -K -` (config-from-stdin). The body literal still
    /// goes in argv via `--data` (not a secret — it's just chat_id
    /// + alert text).
    ///
    /// **Security:** before this refactor the token-bearing URL was
    /// part of the remote shell command — visible to other tenants
    /// on a shared VPS via `ps auxf` for the duration of the curl
    /// call. With `-K -`, the URL travels via the SSH stdin
    /// channel (encrypted in transit) and is consumed by curl
    /// internally; never lands in argv. Security audit
    /// 2026-05-18 round 2 fix.
    ///
    /// Returns `(remote_cmd, stdin_bytes)` so caller pipes them
    /// together via `SubprocessSshTransport::exec_with_stdin`.
    pub fn build_remote_curl_invocation(&self, method: &str, body_json: &str) -> (String, Vec<u8>) {
        let cmd = format!(
            "curl -sS --connect-timeout 10 --max-time 20 -X POST \
             -H 'Content-Type: application/json' --data {body} -K -",
            body = single_quote(body_json),
        );
        // curl config-file syntax: one option per line, `url = "..."`.
        // Token never appears on the remote shell argv. `method` is a
        // fixed internal literal (sendMessage / editMessageText), never
        // operator input — no injection surface.
        let stdin = format!(
            "url = \"https://api.telegram.org/bot{}/{method}\"\n",
            self.token
        )
        .into_bytes();
        (cmd, stdin)
    }

    /// Construct the curl argv for the LOCAL path + the stdin bytes
    /// to feed via `-K -`. Public so a test can pin the invariants
    /// (`-K -` present; URL in stdin not argv; token never in any
    /// argv element).
    pub fn build_curl_local_invocation(
        &self,
        method: &str,
        body_json: &str,
    ) -> (Vec<String>, Vec<u8>) {
        let mut args: Vec<String> = vec![
            "-sS".into(),
            "--connect-timeout".into(),
            "10".into(),
            "--max-time".into(),
            "20".into(),
            "-X".into(),
            "POST".into(),
            "-H".into(),
            "Content-Type: application/json".into(),
            "--data".into(),
            body_json.into(),
        ];
        if let Some(p) = &self.proxy {
            args.push("--proxy".into());
            args.push(p.clone());
        }
        // Read URL (containing the secret token) from stdin via
        // curl's `-K` (config file) reading from `-` (stdin).
        // Defense against `/proc/<pid>/cmdline` leak on the daemon
        // host (same-user processes can read it).
        args.push("-K".into());
        args.push("-".into());
        let stdin = format!(
            "url = \"https://api.telegram.org/bot{}/{method}\"\n",
            self.token
        )
        .into_bytes();
        (args, stdin)
    }

    /// Shared Bot API transport: POST `body_json` to `method`
    /// (`sendMessage` / `editMessageText`) via the via-ssh relay or local
    /// curl, parse the response, enforce Telegram's `ok:true`, and return
    /// the `result` object. Token never lands in argv (URL via `-K -`
    /// stdin); response is byte-capped (64 KiB) + char-boundary trimmed.
    async fn call(
        &self,
        method: &str,
        body_json: &str,
    ) -> Result<serde_json::Value, AlertSinkError> {
        let response_body: String = if let Some(ssh) = &self.via_ssh {
            let (remote_cmd, stdin) = self.build_remote_curl_invocation(method, body_json);
            let bytes = ssh.exec_with_stdin(&remote_cmd, stdin).await.map_err(|e| {
                // Redact token before surfacing stderr — some curl failure
                // modes echo the token-bearing URL.
                let redacted = self.redact_token(&e.to_string());
                AlertSinkError::NonZeroExit {
                    tool: "ssh-then-curl",
                    code: None,
                    stderr: classify_ssh_failure(&redacted),
                }
            })?;
            String::from_utf8_lossy(&bytes).into_owned()
        } else {
            let (args, stdin) = self.build_curl_local_invocation(method, body_json);
            let res = tokio::task::spawn_blocking(move || {
                use std::io::Write;
                let mut child = Command::new("curl")
                    .args(&args)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()?;
                if let Some(mut sin) = child.stdin.take() {
                    sin.write_all(&stdin)?;
                    drop(sin); // EOF → curl proceeds
                } else {
                    return Err::<std::process::Output, std::io::Error>(std::io::Error::other(
                        "curl stdin pipe missing (Stdio::piped was ignored?)",
                    ));
                }
                child.wait_with_output()
            })
            .await
            .map_err(|e| AlertSinkError::Spawn {
                tool: "curl",
                source: std::io::Error::other(format!("tokio spawn_blocking JoinError: {e}")),
            })?
            .map_err(|e| AlertSinkError::Spawn {
                tool: "curl",
                source: e,
            })?;

            if !res.status.success() {
                let stderr = String::from_utf8_lossy(&res.stderr);
                let truncated: String = stderr.chars().take(200).collect();
                return Err(AlertSinkError::NonZeroExit {
                    tool: "curl",
                    code: res.status.code(),
                    stderr: self.redact_token(&truncated),
                });
            }
            String::from_utf8_lossy(&res.stdout).into_owned()
        };

        // Telegram returns HTTP 200 even on logical errors with body
        // `{"ok":false,...}`. Parse structurally + cap at 64 KiB
        // (char-boundary trim — non-ASCII descriptions would panic a raw
        // byte slice).
        const MAX_RESPONSE_BYTES: usize = 64 * 1024;
        let trimmed: String = if response_body.len() > MAX_RESPONSE_BYTES {
            tracing::warn!(
                target = "vpnctld::alert_sink",
                got_bytes = response_body.len(),
                cap = MAX_RESPONSE_BYTES,
                "Telegram response body exceeded cap; truncating"
            );
            response_body.chars().take(MAX_RESPONSE_BYTES).collect()
        } else {
            response_body.clone()
        };
        let parsed: serde_json::Value =
            serde_json::from_str(&trimmed).unwrap_or(serde_json::Value::Null);
        let ok_field = parsed.get("ok").and_then(serde_json::Value::as_bool);
        if ok_field != Some(true) {
            let truncated: String = response_body.chars().take(200).collect();
            return Err(AlertSinkError::NonZeroExit {
                tool: "telegram-api",
                code: Some(200),
                stderr: format!("logical error from api.telegram.org: {truncated}"),
            });
        }
        Ok(parsed
            .get("result")
            .cloned()
            .unwrap_or(serde_json::Value::Null))
    }
}

#[async_trait::async_trait]
impl AlertSink for TelegramSink {
    async fn send_text(
        &self,
        _kind: &str,
        _severity: &str,
        text: &str,
        silent: bool,
    ) -> Result<Option<String>, AlertSinkError> {
        // `text` arrives pre-rendered as Telegram HTML (localized) from
        // `alert_text::to_telegram_html`. Modern send fields:
        //   parse_mode=HTML            → <b>/<code> styling
        //   disable_web_page_preview   → no link unfurl card
        //   disable_notification       → silent for info/recovery
        let body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": true,
            "disable_notification": silent,
        })
        .to_string();
        let result = self.call("sendMessage", &body).await?;
        // `result.message_id` is an integer; stringify for the
        // admin_alerts TEXT column + the edit-on-recover lookup.
        Ok(result
            .get("message_id")
            .and_then(serde_json::Value::as_i64)
            .map(|id| id.to_string()))
    }

    async fn edit_text(&self, message_id: &str, text: &str) -> Result<(), AlertSinkError> {
        // editMessageText wants message_id as an integer. A non-numeric
        // stored id (shouldn't happen — we write it from an i64) is a
        // hard error rather than a silently-malformed request.
        let mid: i64 = message_id
            .parse()
            .map_err(|_| AlertSinkError::NonZeroExit {
                tool: "telegram-api",
                code: None,
                stderr: format!("non-numeric message_id {message_id:?}; cannot edit"),
            })?;
        // No disable_notification on edits — editing never re-notifies.
        let body = serde_json::json!({
            "chat_id": self.chat_id,
            "message_id": mid,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": true,
        })
        .to_string();
        self.call("editMessageText", &body).await?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        if self.via_ssh.is_some() {
            "telegram-via-ssh"
        } else {
            "telegram"
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn null_sink_is_noop_and_returns_ok() {
        let s = NullSink;
        s.send_text("k", "info", "hi", false).await.unwrap();
        assert_eq!(s.name(), "null");
    }

    #[test]
    fn telegram_sink_rejects_empty_token() {
        assert!(matches!(
            TelegramSink::new(String::new(), "123".into(), None),
            Err(AlertSinkError::Misconfigured)
        ));
    }

    #[test]
    fn telegram_sink_rejects_empty_chat_id() {
        assert!(matches!(
            TelegramSink::new("1234567890:ABCDEF".into(), String::new(), None),
            Err(AlertSinkError::Misconfigured)
        ));
    }

    #[test]
    fn telegram_sink_constructs_with_both_halves() {
        let s = TelegramSink::new("1234567890:ABCDEF".into(), "987".into(), None).unwrap();
        assert_eq!(s.name(), "telegram");
    }

    // ─── Token-via-stdin contract (security-audit 2026-05-18) ───
    //
    // Tests below pin that NEITHER local nor via-ssh path puts the
    // bot token in argv. The token MUST travel via curl's `-K -`
    // config-from-stdin so `ps auxf` / `/proc/<pid>/cmdline` can't
    // leak it to same-user processes (local) or other VPS tenants
    // (via-ssh).

    #[test]
    fn local_invocation_argv_contains_no_token() {
        let s = TelegramSink::new("SECRETTOKEN".into(), "CHAT".into(), None).unwrap();
        let (args, stdin) = s.build_curl_local_invocation("sendMessage", r#"{"x":1}"#);
        let joined = args.join(" ");
        assert!(
            !joined.contains("SECRETTOKEN"),
            "token MUST NOT appear in argv: {joined}"
        );
        let stdin_str = std::str::from_utf8(&stdin).unwrap();
        assert!(
            stdin_str.contains("SECRETTOKEN"),
            "token MUST appear in stdin config: {stdin_str:?}"
        );
        // POST + content-type still in argv (those are public).
        assert!(args.iter().any(|a| a == "POST"));
        assert!(args.iter().any(|a| a == "Content-Type: application/json"));
        // `-K -` switches curl to read config from stdin.
        let k_pos = args
            .iter()
            .position(|a| a == "-K")
            .expect("must include -K");
        assert_eq!(
            args.get(k_pos + 1).map(String::as_str),
            Some("-"),
            "argv MUST have `-K -` (config from stdin)"
        );
    }

    #[test]
    fn local_invocation_stdin_is_curl_config_url_line() {
        let s = TelegramSink::new("TOK123".into(), "987".into(), None).unwrap();
        let (_args, stdin) = s.build_curl_local_invocation("sendMessage", "{}");
        let stdin_str = std::str::from_utf8(&stdin).unwrap();
        // Format: `url = "<URL>"` followed by `\n`. Single line.
        assert_eq!(
            stdin_str, "url = \"https://api.telegram.org/botTOK123/sendMessage\"\n",
            "stdin must be valid curl config syntax"
        );
    }

    #[test]
    fn remote_invocation_does_not_embed_token_in_shell_command() {
        let s = TelegramSink::new("SECRETTOKEN".into(), "CHAT".into(), None).unwrap();
        let (cmd, stdin) = s.build_remote_curl_invocation("sendMessage", r#"{"x":1}"#);
        assert!(
            !cmd.contains("SECRETTOKEN"),
            "token MUST NOT appear in the remote shell command \
             (would be visible via ps on the proxy server): {cmd}"
        );
        let stdin_str = std::str::from_utf8(&stdin).unwrap();
        assert!(
            stdin_str.contains("SECRETTOKEN"),
            "token MUST appear in stdin config piped to remote curl"
        );
        // Remote cmd has `-K -` and body-literal in argv (body is
        // not a secret).
        assert!(cmd.contains(" -K -"), "must use config-from-stdin: {cmd}");
        assert!(
            cmd.contains(r#"--data '{"x":1}'"#),
            "body must remain in argv as single-quoted literal: {cmd}"
        );
    }

    #[test]
    fn local_invocation_edit_message_text_builds_valid_url_and_data() {
        let s = TelegramSink::new("TOK123".into(), "987".into(), None).unwrap();
        let (_args, stdin) = s.build_curl_local_invocation(
            "editMessageText",
            r#"{"chat_id":"987","message_id":42,"text":"recovered"}"#,
        );
        let stdin_str = std::str::from_utf8(&stdin).unwrap();
        assert_eq!(
            stdin_str, "url = \"https://api.telegram.org/botTOK123/editMessageText\"\n",
            "stdin must target editMessageText endpoint"
        );
    }

    #[tokio::test]
    async fn edit_text_rejects_non_numeric_message_id_synchronously() {
        let s = TelegramSink::new("TOK123".into(), "987".into(), None).unwrap();
        let err = s.edit_text("not-a-number", "text").await.unwrap_err();
        match err {
            AlertSinkError::NonZeroExit { stderr, .. } => {
                assert!(stderr.contains("non-numeric message_id"));
            }
            other => panic!("expected NonZeroExit, got {other:?}"),
        }
    }

    #[test]
    fn local_invocation_includes_proxy_when_set() {
        let s = TelegramSink::new(
            "TOK".into(),
            "CHAT".into(),
            Some("http://192.168.0.142:18080".into()),
        )
        .unwrap();
        let (args, _stdin) = s.build_curl_local_invocation("sendMessage", "{}");
        assert!(args.iter().any(|a| a == "--proxy"));
        assert!(args.iter().any(|a| a == "http://192.168.0.142:18080"));
    }

    #[test]
    fn local_invocation_omits_proxy_when_none() {
        let s = TelegramSink::new("TOK".into(), "CHAT".into(), None).unwrap();
        let (args, _stdin) = s.build_curl_local_invocation("sendMessage", "{}");
        assert!(!args.iter().any(|a| a == "--proxy"));
    }

    #[test]
    fn redact_token_replaces_with_last4_marker() {
        // Bug-hunt 2026-05-18: defense-in-depth against curl/ssh
        // stderr leaking the URL (which contains the token).
        let s = TelegramSink::new("SECRETtoken12abcd".into(), "CHAT".into(), None).unwrap();
        let leaked = "curl error: https://api.telegram.org/botSECRETtoken12abcd/sendMessage failed";
        let safe = s.redact_token(leaked);
        assert!(
            !safe.contains("SECRETtoken12abcd"),
            "token must be replaced: {safe}"
        );
        assert!(
            safe.contains("••••abcd"),
            "must include last4 marker: {safe}"
        );
        // Untouched parts survive.
        assert!(safe.contains("curl error:"));
        assert!(safe.contains("api.telegram.org"));
    }

    #[test]
    fn redact_token_handles_short_token_gracefully() {
        let s = TelegramSink::new("abc".into(), "CHAT".into(), None).unwrap();
        let safe = s.redact_token("curl: abc fail");
        // last4 of "abc" is just "abc" (whole token).
        assert!(!safe.contains("abc fail") || safe.contains("••••abc"));
    }

    #[test]
    fn new_treats_empty_proxy_as_none() {
        // Operator passing an env var set to "" should not produce a
        // `--proxy ""` argv element — filter at construction time.
        let s = TelegramSink::new("TOK".into(), "CHAT".into(), Some(String::new())).unwrap();
        let (args, _stdin) = s.build_curl_local_invocation("sendMessage", "{}");
        assert!(!args.iter().any(|a| a == "--proxy"));
    }

    #[test]
    fn debug_redacts_token_length_only() {
        let s = TelegramSink::new("12345SECRETtoken67890".into(), "CHAT".into(), None).unwrap();
        let dbg = format!("{s:?}");
        assert!(
            !dbg.contains("SECRET"),
            "token bytes must NOT appear in Debug"
        );
        assert!(dbg.contains("••••"), "must include redaction marker");
        assert!(dbg.contains("21 chars"), "must include token length");
    }

    #[test]
    fn classify_ssh_failure_recognises_permission_denied() {
        let raw = "ssh transport error: ssh root@1.2.3.4:22 exit=Some(255) \
                   stderr=root@1.2.3.4: Permission denied (publickey,password).";
        let msg = classify_ssh_failure(raw);
        assert!(
            msg.contains("deploy SSH key not authorised"),
            "must classify permission-denied: {msg}"
        );
        // Operator-facing remediation MUST point at the web UI (the
        // «push deploy key» button on the server detail page) — NOT
        // ask the operator to manually ssh + edit authorized_keys.
        // Per Pavel's «не должен просить меня сделать что-то вручную
        // на серверах» directive 2026-05-18.
        assert!(
            msg.contains("push deploy key"),
            "must point operator at the «push deploy key» button: {msg}"
        );
        assert!(
            !msg.contains("echo '<paste>'") && !msg.contains(">> ~/.ssh/authorized_keys"),
            "MUST NOT include manual `echo … >> authorized_keys` instructions: {msg}"
        );
        assert!(
            msg.contains(raw),
            "must preserve raw stderr for full context"
        );
    }

    #[test]
    fn classify_ssh_failure_recognises_connection_refused() {
        let msg = classify_ssh_failure("Connection refused");
        assert!(msg.contains("sshd isn't listening"));
        assert!(msg.contains("ssh_port"));
    }

    #[test]
    fn classify_ssh_failure_recognises_timeout() {
        let msg = classify_ssh_failure("ssh: connect to host 1.2.3.4: Connection timed out");
        assert!(msg.contains("server unreachable"));
    }

    #[test]
    fn classify_ssh_failure_recognises_host_key_mismatch() {
        let msg = classify_ssh_failure(
            "@@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@@\n\
             Host key verification failed.",
        );
        assert!(msg.contains("host-key mismatch"));
        assert!(msg.contains("Trusted host fingerprint"));
    }

    #[test]
    fn classify_ssh_failure_falls_through_to_generic_for_unknown() {
        let msg = classify_ssh_failure("some completely novel weirdness");
        // Default phrasing preserved.
        assert!(msg.contains("SSH transport failed"));
        assert!(msg.contains("some completely novel weirdness"));
    }

    #[test]
    fn name_reflects_via_ssh_mode() {
        let direct = TelegramSink::new("TOK".into(), "CHAT".into(), None).unwrap();
        assert_eq!(direct.name(), "telegram");
        // Construct a sink in via-ssh mode by chaining the helper.
        // We don't actually open the SSH connection in the test —
        // the transport is just held as a value.
        let ssh = SubprocessSshTransport::new(
            String::from("203.0.113.7"),
            String::from("root"),
            std::path::PathBuf::from("/dev/null"),
        );
        let proxied = direct.with_via_ssh(ssh);
        assert_eq!(proxied.name(), "telegram-via-ssh");
    }
}
