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
use vpnctl_core::{SshTransport, shell::single_quote};

/// One sink transport. Implementors deliver alerts to wherever the
/// operator wants to be notified. Delivery errors are returned via
/// the `Result` so the caller can decide whether to surface them
/// (test-send handler) or swallow them (production fire-and-forget).
#[async_trait::async_trait]
pub trait AlertSink: Send + Sync {
    /// Send one alert as a free-text message. Implementations format
    /// the three inputs however suits the transport (Telegram does
    /// plain text + emoji severity prefix; ntfy.sh would use title
    /// + body; journald would write a structured tracing event).
    async fn send_text(
        &self,
        kind: &str,
        severity: &str,
        summary: &str,
    ) -> Result<(), AlertSinkError>;

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

/// Format the per-alert message body the way Telegram chat (and any
/// future text-shaped sink) will render it. Standalone free fn so
/// every sink can share the same triage prefix without duplicating
/// the severity → emoji table.
///
/// **Severity → emoji table** — chosen for fast triage in the chat:
///   * `critical` → 🟥 (red square — actionable, daemon may have
///     lost contact)
///   * `warning`  → ⚠️ (yellow triangle — operator should look soon)
///   * `info`     → 🔵 (blue circle — informational, e.g. test-send)
///   * (anything else) → ▪ (neutral marker — defensive default)
pub fn format_alert_message(kind: &str, severity: &str, summary: &str) -> String {
    let prefix = match severity {
        "critical" => "🟥",
        "warning" => "⚠️",
        "info" => "🔵",
        _ => "▪",
    };
    format!("{prefix} vpnctld · {severity} · {kind}\n\n{summary}")
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
        _summary: &str,
    ) -> Result<(), AlertSinkError> {
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

    /// Build the *remote* shell command that runs `curl` on the
    /// inventory server. Single-quotes the URL + body so the remote
    /// shell sees them as opaque tokens — relies on
    /// `vpnctl_core::shell::single_quote`'s POSIX escape rules
    /// (already pinned by 8 spec tests in `crates/core/src/shell.rs`).
    ///
    /// Public so a test can assert that:
    ///   * the URL is single-quoted (so a token containing shell
    ///     metacharacters can't escape),
    ///   * the body is `--data` followed by a quoted JSON literal,
    ///   * the same connect/max timeouts as the local path apply,
    ///   * a `--` separator sits between the flag block and the URL
    ///     (defense against a future refactor that puts the URL
    ///     earlier).
    pub fn build_remote_curl_command(&self, body_json: &str) -> String {
        let url = format!("https://api.telegram.org/bot{}/sendMessage", self.token);
        format!(
            "curl -sS --connect-timeout 10 --max-time 20 -X POST \
             -H 'Content-Type: application/json' --data {body} -- {url}",
            body = single_quote(body_json),
            url = single_quote(&url),
        )
    }

    /// Construct the curl argv. Public so a test can pin the
    /// invariants (proxy-flag-before-url; `-X POST`; the
    /// Content-Type header is correct; we never pass the bare token
    /// without the `bot` prefix; etc).
    pub fn build_curl_args(&self, body_json: &str) -> Vec<String> {
        let mut args: Vec<String> = vec![
            // Quiet mode — no progress bars in our logs.
            "-sS".into(),
            // 10s connect timeout, 20s total — fits inside the
            // node-probe tick budget. A Telegram outage shouldn't
            // freeze the daemon.
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
        // POSIX getopt separator before the URL — defends against
        // the (extremely unlikely) future where `token` starts with
        // `-`. BotFather tokens never do, but the invariant is
        // cheap to maintain.
        args.push("--".into());
        args.push(format!(
            "https://api.telegram.org/bot{}/sendMessage",
            self.token
        ));
        args
    }
}

#[async_trait::async_trait]
impl AlertSink for TelegramSink {
    async fn send_text(
        &self,
        kind: &str,
        severity: &str,
        summary: &str,
    ) -> Result<(), AlertSinkError> {
        let text = format_alert_message(kind, severity, summary);
        // chat_id can be either an integer (e.g. 123456789) or a
        // string (`@channel_name`). serde_json's `json!` macro
        // encodes whichever-shape we give it; we stringify both
        // because Telegram accepts string-form for both. Simplifies
        // the schema.
        let body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": text,
        })
        .to_string();

        // Two egress paths. Both end up parsing the same response
        // JSON (Telegram always returns 200 + body); only the
        // transport differs.
        let response_body: String = if let Some(ssh) = &self.via_ssh {
            // Via-server path: SSH to inventory server, run curl
            // THERE. The remote command is built via
            // `build_remote_curl_command` which single-quotes the
            // URL + body so the remote shell sees them as opaque
            // tokens regardless of metacharacters.
            let remote_cmd = self.build_remote_curl_command(&body);
            ssh.exec(&remote_cmd)
                .await
                .map_err(|e| AlertSinkError::NonZeroExit {
                    tool: "ssh-then-curl",
                    code: None,
                    stderr: classify_ssh_failure(&e.to_string()),
                })?
        } else {
            // Local path: spawn curl directly.
            let args = self.build_curl_args(&body);
            let res = tokio::task::spawn_blocking(move || {
                Command::new("curl")
                    .args(&args)
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .output()
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
                    stderr: truncated,
                });
            }
            String::from_utf8_lossy(&res.stdout).into_owned()
        };

        // Telegram returns HTTP 200 even on logical errors (chat
        // not found, bot blocked) with body `{"ok":false,
        // "error_code":..., "description":"..."}`. Parse the JSON
        // structurally — a `contains("\"ok\":true")` substring check
        // would false-positive on a description like
        // `{"ok":false,"description":"... \"ok\":true ..."}` since
        // Telegram echoes operator-supplied chat names into
        // `description` (review-agent finding from chunk 3 part 2).
        //
        // **Response body cap (64 KiB)** — defense against an
        // upstream that streams arbitrarily-large JSON. curl
        // already caps at `--max-time 20`, but a fat pipe could
        // still deliver hundreds of MB in that window; serde_json
        // would happily parse the whole thing into a `Value` tree
        // and OOM the daemon. Telegram's real responses are tiny
        // (sub-KiB); 64 KiB is generous + bounds memory.
        // Security-audit 2026-05-18 finding.
        const MAX_RESPONSE_BYTES: usize = 64 * 1024;
        let trimmed: &str = if response_body.len() > MAX_RESPONSE_BYTES {
            tracing::warn!(
                target = "vpnctld::alert_sink",
                got_bytes = response_body.len(),
                cap = MAX_RESPONSE_BYTES,
                "Telegram response body exceeded cap; truncating"
            );
            &response_body[..MAX_RESPONSE_BYTES]
        } else {
            &response_body
        };
        let parsed: serde_json::Value =
            serde_json::from_str(trimmed).unwrap_or(serde_json::Value::Null);
        let ok_field = parsed.get("ok").and_then(serde_json::Value::as_bool);
        if ok_field != Some(true) {
            let truncated: String = response_body.chars().take(200).collect();
            return Err(AlertSinkError::NonZeroExit {
                tool: "telegram-api",
                code: Some(200),
                stderr: format!("logical error from api.telegram.org: {truncated}"),
            });
        }

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
        s.send_text("k", "info", "hi").await.unwrap();
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

    #[test]
    fn format_alert_message_prefixes_severity_with_emoji() {
        let m = format_alert_message("server.unreachable", "warning", "3 fails");
        assert!(
            m.starts_with("⚠️ vpnctld · warning · server.unreachable"),
            "got: {m:?}"
        );
        assert!(m.contains("3 fails"));

        let m = format_alert_message("server.fail2ban.banned_self", "critical", "boom");
        assert!(m.starts_with("🟥"), "got: {m:?}");
    }

    #[test]
    fn format_alert_message_uses_neutral_marker_for_unknown_severity() {
        let m = format_alert_message("kind", "🤷", "summary");
        assert!(
            m.starts_with("▪"),
            "unknown severity → neutral marker: {m:?}"
        );
    }

    #[test]
    fn build_curl_args_includes_post_and_content_type() {
        let s = TelegramSink::new("TOK".into(), "CHAT".into(), None).unwrap();
        let args = s.build_curl_args(r#"{"x":1}"#);
        let joined = args.join(" ");
        assert!(args.iter().any(|a| a == "POST"), "must POST");
        assert!(
            args.iter().any(|a| a == "Content-Type: application/json"),
            "must set content-type"
        );
        // Body literal must reach curl --data.
        assert!(joined.contains(r#"{"x":1}"#));
    }

    #[test]
    fn build_curl_args_includes_double_dash_before_url() {
        // POSIX getopt separator defense — pin so a future refactor
        // doesn't accidentally allow a `--proxy http://evil/` to be
        // interpreted as a flag if the URL ever moves earlier in
        // the argv.
        let s = TelegramSink::new("TOK".into(), "CHAT".into(), None).unwrap();
        let args = s.build_curl_args("{}");
        let dash_pos = args
            .iter()
            .position(|a| a == "--")
            .expect("must include `--`");
        let url_pos = args
            .iter()
            .position(|a| a.starts_with("https://api.telegram.org/"))
            .expect("must include the URL");
        assert_eq!(url_pos, dash_pos + 1, "url MUST immediately follow `--`");
    }

    #[test]
    fn build_curl_args_includes_proxy_when_set() {
        // Explicit proxy param — no env-pollution; `new()` takes
        // `Option<String>` directly because edition-2024 `unsafe_code`
        // forbid rules out `std::env::set_var` in tests.
        let s = TelegramSink::new(
            "TOK".into(),
            "CHAT".into(),
            Some("http://192.168.0.142:18080".into()),
        )
        .unwrap();
        let args = s.build_curl_args("{}");
        assert!(args.iter().any(|a| a == "--proxy"));
        assert!(args.iter().any(|a| a == "http://192.168.0.142:18080"));
    }

    #[test]
    fn build_curl_args_omits_proxy_when_none() {
        let s = TelegramSink::new("TOK".into(), "CHAT".into(), None).unwrap();
        let args = s.build_curl_args("{}");
        assert!(!args.iter().any(|a| a == "--proxy"));
    }

    #[test]
    fn new_treats_empty_proxy_as_none() {
        // Operator passing an env var set to "" should not produce a
        // `--proxy ""` argv element — filter at construction time.
        let s = TelegramSink::new("TOK".into(), "CHAT".into(), Some(String::new())).unwrap();
        let args = s.build_curl_args("{}");
        assert!(!args.iter().any(|a| a == "--proxy"));
    }

    #[test]
    fn build_remote_curl_command_quotes_url_and_body() {
        // Via-server proxy mode: the curl invocation is built as a
        // single shell-string for SSH to execute remotely. Both the
        // URL (contains the bot token) and the body (contains the
        // operator's alert text, may include any UTF-8) must be
        // wrapped in POSIX single-quotes so the remote shell sees
        // them as opaque tokens.
        let s = TelegramSink::new("TOK".into(), "CHAT".into(), None).unwrap();
        let cmd = s.build_remote_curl_command(r#"{"x":1}"#);
        // Body literal must appear as `--data '<body>'`.
        assert!(
            cmd.contains(r#"--data '{"x":1}'"#),
            "body must be `--data` then single-quoted JSON: {cmd}"
        );
        // URL must appear as `'https://api.telegram.org/...'`.
        assert!(
            cmd.contains("'https://api.telegram.org/botTOK/sendMessage'"),
            "URL must be single-quoted: {cmd}"
        );
        // `--` separator before URL — defense for a future refactor
        // that reorders the args.
        let dash_idx = cmd
            .find(" -- ")
            .expect("must include ` -- ` flag separator");
        let url_idx = cmd.find("'https://").expect("must include URL");
        assert!(dash_idx < url_idx, "`--` must come before URL");
        // Same timeouts as the local path.
        assert!(cmd.contains("--connect-timeout 10"));
        assert!(cmd.contains("--max-time 20"));
        assert!(cmd.contains("-X POST"));
    }

    #[test]
    fn build_remote_curl_command_escapes_single_quote_in_body() {
        // Defense: if the operator's alert text contains a `'`, the
        // POSIX-single-quote escape from `vpnctl_core::shell::
        // single_quote` (`'a'\''b'`) must survive into the command
        // so the remote shell reassembles the original byte sequence.
        let s = TelegramSink::new("TOK".into(), "CHAT".into(), None).unwrap();
        // JSON literal with an embedded `'` in the text field.
        let body = r#"{"text":"can't reach you"}"#;
        let cmd = s.build_remote_curl_command(body);
        // Expected single-quote pattern: original `'` becomes `'\''`.
        // Raw string handles the literal backslash + double-quote
        // bytes; the assertion is byte-equality against the
        // expected single_quote output.
        let expected_quoted = r#"'{"text":"can'\''t reach you"}'"#;
        assert!(
            cmd.contains(expected_quoted),
            "embedded `'` must be escaped via close-escape-reopen trick\n\
             expected substring: {expected_quoted}\n\
             actual cmd:         {cmd}"
        );
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
