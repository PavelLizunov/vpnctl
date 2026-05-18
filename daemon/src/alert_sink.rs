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
//! ## Why fire-and-forget at the caller (not here)
//!
//! `send_text` takes `&self` + returns `Result<(), Error>` so callers
//! can decide their own concurrency policy. The probe-poller spawns
//! the call to avoid blocking the next server's tick by ≤10s (curl's
//! configured connect timeout); a future synchronous test-send
//! handler awaits the same call directly to surface success/failure
//! to the operator. Neither concern belongs in the sink itself.

use std::process::{Command, Stdio};

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
/// sendMessage` via the system `curl`. Reads the optional
/// `VPNCTLD_HTTPS_PROXY` env var on construction so РФ-blocked
/// outbound can route through the homelab gost→xray proxy at
/// `http://192.168.0.142:18080`.
#[derive(Debug, Clone)]
pub struct TelegramSink {
    token: String,
    chat_id: String,
    proxy: Option<String>,
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
        })
    }

    /// Convenience constructor that reads `VPNCTLD_HTTPS_PROXY` from
    /// the env. Use in production wiring; tests call `new` directly
    /// to avoid env-state pollution.
    pub fn from_env(token: String, chat_id: String) -> Result<Self, AlertSinkError> {
        let proxy = std::env::var("VPNCTLD_HTTPS_PROXY").ok();
        Self::new(token, chat_id, proxy)
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
        let args = self.build_curl_args(&body);

        // `spawn_blocking` so curl's blocking I/O doesn't pin a
        // tokio worker. The curl process itself uses its own I/O
        // path; we just wait_with_output.
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

        // Telegram returns HTTP 200 even on logical errors (chat
        // not found, bot blocked) with body `{"ok":false,
        // "error_code":..., "description":"..."}`. Parse the JSON
        // structurally — a `contains("\"ok\":true")` substring check
        // would false-positive on a description like
        // `{"ok":false,"description":"... \"ok\":true ..."}` since
        // Telegram echoes operator-supplied chat names into
        // `description` (review-agent finding).
        let body_text = String::from_utf8_lossy(&res.stdout);
        let parsed: serde_json::Value =
            serde_json::from_str(&body_text).unwrap_or(serde_json::Value::Null);
        let ok_field = parsed.get("ok").and_then(serde_json::Value::as_bool);
        if ok_field != Some(true) {
            let truncated: String = body_text.chars().take(200).collect();
            return Err(AlertSinkError::NonZeroExit {
                tool: "telegram-api",
                code: Some(200),
                stderr: format!("logical error from api.telegram.org: {truncated}"),
            });
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "telegram"
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
}
