use std::process::{Command, Stdio};

use crate::ssh_subprocess::SubprocessSshTransport;
use vpnctl_core::shell::single_quote;

#[allow(clippy::double_must_use)]
#[async_trait::async_trait]
pub trait AlertSink: Send + Sync {
    async fn send_text(
        &self,
        kind: &str,
        severity: &str,
        text: &str,
        silent: bool,
    ) -> Result<Option<String>, AlertSinkError>;

    async fn edit_text(&self, message_id: &str, text: &str) -> Result<(), AlertSinkError>;

    fn name(&self) -> &'static str;
}

#[derive(Debug, thiserror::Error)]
pub enum AlertSinkError {
    #[error("alert-sink: spawning {tool} failed: {source}")]
    Spawn {
        tool: &'static str,
        #[source]
        source: std::io::Error,
    },

    #[error("alert-sink: {tool} exited {code:?}: {stderr}")]
    NonZeroExit {
        tool: &'static str,
        code: Option<i32>,
        stderr: String,
    },

    #[error("alert-sink: misconfigured (invalid bot token or chat_id)")]
    Misconfigured,
}

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

pub struct TelegramSink {
    token: String,
    chat_id: String,
    proxy: Option<String>,
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

pub(crate) fn valid_telegram_bot_token(token: &str) -> bool {
    let Some((bot_id, auth)) = token.split_once(':') else {
        return false;
    };
    token.len() >= 20
        && !bot_id.is_empty()
        && bot_id.bytes().all(|c| c.is_ascii_digit())
        && !auth.is_empty()
        && auth
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

pub(crate) fn valid_telegram_chat_id(chat_id: &str) -> bool {
    let numeric = chat_id.strip_prefix('-').unwrap_or(chat_id);
    (!numeric.is_empty() && numeric.bytes().all(|c| c.is_ascii_digit()))
        || chat_id.strip_prefix('@').is_some_and(|channel| {
            !channel.is_empty()
                && channel
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'_')
        })
}

impl TelegramSink {
    pub fn new(
        token: String,
        chat_id: String,
        proxy: Option<String>,
    ) -> Result<Self, AlertSinkError> {
        if !valid_telegram_bot_token(&token) || !valid_telegram_chat_id(&chat_id) {
            return Err(AlertSinkError::Misconfigured);
        }
        Ok(Self {
            token,
            chat_id,
            proxy: proxy.filter(|s| !s.is_empty()),
            via_ssh: None,
        })
    }

    pub fn with_via_ssh(mut self, ssh: SubprocessSshTransport) -> Self {
        self.via_ssh = Some(ssh);
        self
    }

    pub fn from_env(token: String, chat_id: String) -> Result<Self, AlertSinkError> {
        let proxy = std::env::var("VPNCTLD_HTTPS_PROXY").ok();
        Self::new(token, chat_id, proxy)
    }

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

    fn curl_config(&self, method: &str) -> Vec<u8> {
        let url = format!("https://api.telegram.org/bot{}/{method}", self.token)
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\r', "\\r")
            .replace('\n', "\\n");
        format!("url = \"{url}\"\n").into_bytes()
    }

    pub fn build_remote_curl_invocation(&self, method: &str, body_json: &str) -> (String, Vec<u8>) {
        let cmd = format!(
            "curl -sS --connect-timeout 10 --max-time 20 -X POST \
             -H 'Content-Type: application/json' --data {body} -K -",
            body = single_quote(body_json),
        );
        let stdin = self.curl_config(method);
        (cmd, stdin)
    }

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
        args.push("-K".into());
        args.push("-".into());
        let stdin = self.curl_config(method);
        (args, stdin)
    }

    async fn call(
        &self,
        method: &str,
        body_json: &str,
    ) -> Result<serde_json::Value, AlertSinkError> {
        let response_body: String = if let Some(ssh) = &self.via_ssh {
            let (remote_cmd, stdin) = self.build_remote_curl_invocation(method, body_json);
            let bytes = ssh.exec_with_stdin(&remote_cmd, stdin).await.map_err(|e| {
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
                    drop(sin);
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
        let body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": true,
            "disable_notification": silent,
        })
        .to_string();
        let result = self.call("sendMessage", &body).await?;
        Ok(result
            .get("message_id")
            .and_then(serde_json::Value::as_i64)
            .map(|id| id.to_string()))
    }

    async fn edit_text(&self, message_id: &str, text: &str) -> Result<(), AlertSinkError> {
        let mid: i64 = message_id
            .parse()
            .map_err(|_| AlertSinkError::NonZeroExit {
                tool: "telegram-api",
                code: None,
                stderr: format!("non-numeric message_id {message_id:?}; cannot edit"),
            })?;
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
            TelegramSink::new("1234567890:ABCDEFghijklmn".into(), String::new(), None),
            Err(AlertSinkError::Misconfigured)
        ));
    }

    #[test]
    fn telegram_sink_constructs_with_both_halves() {
        let s = TelegramSink::new("1234567890:ABCDEFghijklmn".into(), "987".into(), None).unwrap();
        assert_eq!(s.name(), "telegram");
    }

    #[test]
    fn telegram_sink_rejects_malformed_credentials() {
        for token in [
            "123456:AAAAAAAAAAAAAAAAAAAA\"\nnext\noutput = \"/tmp/key\"",
            "123456:AAAAAAAAAA\"AAAAAAAAAA",
            "123456:AAAAAAAAAA\rAAAAAAAAAA",
            "123456:AAAAAAAAAA\nAAAAAAAAAA",
            "123456:AAAAAAAAAA\\AAAAAAAAAA",
            "123456:AAAAAAAAAA/AAAAAAAAAA",
            "123456:AAAAAAAAAA:AAAAAAAAAA",
            "abcdef:AAAAAAAAAAAAAAAAAAAA",
        ] {
            assert!(matches!(
                TelegramSink::new(token.into(), "987".into(), None),
                Err(AlertSinkError::Misconfigured)
            ));
        }
        for chat_id in [
            "987\"\noutput = \"/tmp/key\"",
            "98\r7",
            "98\n7",
            "-",
            "@",
            "CHAT",
        ] {
            assert!(matches!(
                TelegramSink::new("123456:AAAAAAAAAAAAAAAAAAAA".into(), chat_id.into(), None),
                Err(AlertSinkError::Misconfigured)
            ));
        }
        for chat_id in ["987", "-100123", "@test_channel"] {
            assert!(
                TelegramSink::new("123456:Abc_012-DEFghijklmnop".into(), chat_id.into(), None)
                    .is_ok()
            );
        }
    }

    #[test]
    fn curl_config_escapes_method_without_adding_directives() {
        let sink =
            TelegramSink::new("123456:AAAAAAAAAAAAAAAAAAAA".into(), "987".into(), None).unwrap();
        let method = "sendMessage\"\r\nnext\noutput = \"/tmp/key\"\\";
        let (_, local) = sink.build_curl_local_invocation(method, "{}");
        let (_, remote) = sink.build_remote_curl_invocation(method, "{}");
        assert_eq!(local, remote);
        let config = String::from_utf8(local).unwrap();
        assert_eq!(config.lines().count(), 1);
        assert_eq!(config.matches('\r').count(), 0);
        assert_eq!(config.matches('\n').count(), 1);
        assert!(config.contains(r#"sendMessage\"\r\nnext\noutput = \"/tmp/key\"\\"#));
    }

    #[test]
    fn local_invocation_argv_contains_no_token() {
        let s = TelegramSink::new(
            "1234567890:SECRETTOKEN".into(),
            "@test_channel".into(),
            None,
        )
        .unwrap();
        let (args, stdin) = s.build_curl_local_invocation("sendMessage", r#"{"x":1}"#);
        let joined = args.join(" ");
        assert!(
            !joined.contains("1234567890:SECRETTOKEN"),
            "token MUST NOT appear in argv: {joined}"
        );
        let stdin_str = std::str::from_utf8(&stdin).unwrap();
        assert!(
            stdin_str.contains("1234567890:SECRETTOKEN"),
            "token MUST appear in stdin config: {stdin_str:?}"
        );
        assert!(args.iter().any(|a| a == "POST"));
        assert!(args.iter().any(|a| a == "Content-Type: application/json"));
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
        let s = TelegramSink::new("1234567890:FAKETOK123".into(), "987".into(), None).unwrap();
        let (_args, stdin) = s.build_curl_local_invocation("sendMessage", "{}");
        let stdin_str = std::str::from_utf8(&stdin).unwrap();
        assert_eq!(
            stdin_str, "url = \"https://api.telegram.org/bot1234567890:FAKETOK123/sendMessage\"\n",
            "stdin must be valid curl config syntax"
        );
    }

    #[test]
    fn remote_invocation_does_not_embed_token_in_shell_command() {
        let s = TelegramSink::new(
            "1234567890:SECRETTOKEN".into(),
            "@test_channel".into(),
            None,
        )
        .unwrap();
        let (cmd, stdin) = s.build_remote_curl_invocation("sendMessage", r#"{"x":1}"#);
        assert!(
            !cmd.contains("1234567890:SECRETTOKEN"),
            "token MUST NOT appear in the remote shell command \
             (would be visible via ps on the proxy server): {cmd}"
        );
        let stdin_str = std::str::from_utf8(&stdin).unwrap();
        assert!(
            stdin_str.contains("1234567890:SECRETTOKEN"),
            "token MUST appear in stdin config piped to remote curl"
        );
        assert!(cmd.contains(" -K -"), "must use config-from-stdin: {cmd}");
        assert!(
            cmd.contains(r#"--data '{"x":1}'"#),
            "body must remain in argv as single-quoted literal: {cmd}"
        );
    }

    #[test]
    fn local_invocation_edit_message_text_builds_valid_url_and_data() {
        let s = TelegramSink::new("1234567890:FAKETOK123".into(), "987".into(), None).unwrap();
        let (_args, stdin) = s.build_curl_local_invocation(
            "editMessageText",
            r#"{"chat_id":"987","message_id":42,"text":"recovered"}"#,
        );
        let stdin_str = std::str::from_utf8(&stdin).unwrap();
        assert_eq!(
            stdin_str,
            "url = \"https://api.telegram.org/bot1234567890:FAKETOK123/editMessageText\"\n",
            "stdin must target editMessageText endpoint"
        );
    }

    #[tokio::test]
    async fn edit_text_rejects_non_numeric_message_id_synchronously() {
        let s = TelegramSink::new("1234567890:FAKETOK123".into(), "987".into(), None).unwrap();
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
            "1234567890:FAKETOKEN".into(),
            "@test_channel".into(),
            Some("http://192.168.0.142:18080".into()),
        )
        .unwrap();
        let (args, _stdin) = s.build_curl_local_invocation("sendMessage", "{}");
        assert!(args.iter().any(|a| a == "--proxy"));
        assert!(args.iter().any(|a| a == "http://192.168.0.142:18080"));
    }

    #[test]
    fn local_invocation_omits_proxy_when_none() {
        let s =
            TelegramSink::new("1234567890:FAKETOKEN".into(), "@test_channel".into(), None).unwrap();
        let (args, _stdin) = s.build_curl_local_invocation("sendMessage", "{}");
        assert!(!args.iter().any(|a| a == "--proxy"));
    }

    #[test]
    fn redact_token_replaces_with_last4_marker() {
        let s = TelegramSink::new(
            "1234567890:SECRETtoken12abcd".into(),
            "@test_channel".into(),
            None,
        )
        .unwrap();
        let leaked = "curl error: https://api.telegram.org/bot1234567890:SECRETtoken12abcd/sendMessage failed";
        let safe = s.redact_token(leaked);
        assert!(
            !safe.contains("1234567890:SECRETtoken12abcd"),
            "token must be replaced: {safe}"
        );
        assert!(
            safe.contains("••••abcd"),
            "must include last4 marker: {safe}"
        );
        assert!(safe.contains("curl error:"));
        assert!(safe.contains("api.telegram.org"));
    }

    #[test]
    fn telegram_sink_rejects_short_token() {
        assert!(matches!(
            TelegramSink::new("123:abc".into(), "987".into(), None),
            Err(AlertSinkError::Misconfigured)
        ));
    }

    #[test]
    fn new_treats_empty_proxy_as_none() {
        let s = TelegramSink::new(
            "1234567890:FAKETOKEN".into(),
            "@test_channel".into(),
            Some(String::new()),
        )
        .unwrap();
        let (args, _stdin) = s.build_curl_local_invocation("sendMessage", "{}");
        assert!(!args.iter().any(|a| a == "--proxy"));
    }

    #[test]
    fn debug_redacts_token_length_only() {
        let s = TelegramSink::new(
            "1234567890:SECRETtoken67890".into(),
            "@test_channel".into(),
            None,
        )
        .unwrap();
        let dbg = format!("{s:?}");
        assert!(
            !dbg.contains("SECRET"),
            "token bytes must NOT appear in Debug"
        );
        assert!(dbg.contains("••••"), "must include redaction marker");
        assert!(
            dbg.contains(&format!("{} chars", s.token.len())),
            "must include token length"
        );
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
        assert!(msg.contains("SSH transport failed"));
        assert!(msg.contains("some completely novel weirdness"));
    }

    #[test]
    fn name_reflects_via_ssh_mode() {
        let direct =
            TelegramSink::new("1234567890:FAKETOKEN".into(), "@test_channel".into(), None).unwrap();
        assert_eq!(direct.name(), "telegram");
        let ssh = SubprocessSshTransport::new(
            String::from("203.0.113.7"),
            String::from("root"),
            std::path::PathBuf::from("/dev/null"),
        );
        let proxied = direct.with_via_ssh(ssh);
        assert_eq!(proxied.name(), "telegram-via-ssh");
    }
}
