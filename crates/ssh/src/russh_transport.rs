//! Реальный SSH-транспорт поверх [`russh`].
//!
//! Дизайн:
//!
//! - `RusshTransportBuilder` — типобезопасная конфигурация (адрес, порт, юзер,
//!   путь к ключу, fingerprint host key).
//! - `RusshTransport::connect(...)` (через builder) — устанавливает сессию,
//!   проверяет fingerprint, авторизуется ключом.
//! - `impl SshTransport` — `exec` / `upload` / `read_file`, каждая операция
//!   обёрнута в `tokio::time::timeout`.
//! - Host key verification: либо `trusted_fingerprint` задан и должен совпасть,
//!   либо `None` → TOFU (доверяем при первом коннекте). Реальный отпечаток
//!   сохраняется в `observed_host_fingerprint()` — слой выше (`inventory`)
//!   записывает его в БД.

use async_trait::async_trait;
use russh::client::{self, Handler};
use russh::keys::ssh_key::{HashAlg, PublicKey};
use russh::keys::{PrivateKeyWithHashAlg, load_secret_key};
use russh::{ChannelMsg, Disconnect};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::timeout;
use vpnctl_core::{CoreError, Result, SshTransport};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

// ────────────────────────────────────────────────────────────────────────────
// Host-key verification handler
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct VerifyHandler {
    trusted_fingerprint: Option<String>,
    observed_fingerprint: Arc<AsyncMutex<Option<String>>>,
}

impl Handler for VerifyHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> std::result::Result<bool, Self::Error> {
        let fp = server_public_key.fingerprint(HashAlg::Sha256).to_string();
        // Сохраняем для inspect()-after-connect.
        *self.observed_fingerprint.lock().await = Some(fp.clone());

        match &self.trusted_fingerprint {
            Some(expected) if expected == &fp => Ok(true),
            Some(_) => Err(russh::Error::UnknownKey),
            None => Ok(true), // TOFU
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Builder
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct RusshTransportBuilder {
    address: String,
    port: u16,
    user: String,
    key_path: PathBuf,
    key_passphrase: Option<String>,
    trusted_fingerprint: Option<String>,
    op_timeout: Duration,
}

impl RusshTransportBuilder {
    pub fn new(
        address: impl Into<String>,
        user: impl Into<String>,
        key_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            address: address.into(),
            port: 22,
            user: user.into(),
            key_path: key_path.into(),
            key_passphrase: None,
            trusted_fingerprint: None,
            op_timeout: DEFAULT_TIMEOUT,
        }
    }

    pub fn port(mut self, p: u16) -> Self {
        self.port = p;
        self
    }

    pub fn passphrase(mut self, p: impl Into<String>) -> Self {
        self.key_passphrase = Some(p.into());
        self
    }

    /// Установить ожидаемый fingerprint host key (`SHA256:...`). Если не задан —
    /// TOFU: первый коннект доверяет любому, реальный отпечаток доступен через
    /// `RusshTransport::observed_host_fingerprint()` для сохранения в inventory.
    pub fn trusted_fingerprint(mut self, fp: impl Into<String>) -> Self {
        self.trusted_fingerprint = Some(fp.into());
        self
    }

    pub fn timeout(mut self, d: Duration) -> Self {
        self.op_timeout = d;
        self
    }

    pub async fn connect(self) -> Result<RusshTransport> {
        let key = load_secret_key(&self.key_path, self.key_passphrase.as_deref())
            .map_err(|e| CoreError::Transport(format!("load key {:?}: {e}", self.key_path)))?;

        let observed = Arc::new(AsyncMutex::new(None));
        let handler = VerifyHandler {
            trusted_fingerprint: self.trusted_fingerprint.clone(),
            observed_fingerprint: Arc::clone(&observed),
        };

        let config = Arc::new(client::Config::default());

        let mut handle = timeout(
            self.op_timeout,
            client::connect(config, (self.address.as_str(), self.port), handler),
        )
        .await
        .map_err(|_| CoreError::Transport("connect timed out".into()))?
        .map_err(|e| CoreError::Transport(format!("connect: {e}")))?;

        // `best_supported_rsa_hash` returns Result<Option<Option<HashAlg>>>:
        // outer Option = "negotiation result known", inner = "RSA hash needed (RSA key)".
        // For Ed25519 keys, the inner Option will be None — that's fine.
        let best_hash = handle
            .best_supported_rsa_hash()
            .await
            .map_err(|e| CoreError::Transport(format!("rsa hash negotiation: {e}")))?
            .flatten();
        let pk = PrivateKeyWithHashAlg::new(Arc::new(key), best_hash);

        let auth = handle
            .authenticate_publickey(&self.user, pk)
            .await
            .map_err(|e| CoreError::Transport(format!("auth: {e}")))?;
        if !auth.success() {
            return Err(CoreError::Transport(format!(
                "auth failed for user {}",
                self.user
            )));
        }

        tracing::info!(
            target = "vpnctl::ssh",
            "connected to {}:{} as {}",
            self.address,
            self.port,
            self.user
        );

        Ok(RusshTransport {
            handle: AsyncMutex::new(handle),
            address: self.address,
            op_timeout: self.op_timeout,
            observed_fingerprint: observed,
        })
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Transport
// ────────────────────────────────────────────────────────────────────────────

pub struct RusshTransport {
    /// `client::Handle` методы берут `&self`, но `russh::client::Handle` не
    /// `Sync`, поэтому всё равно сериализуем через async-мьютекс. Прямой
    /// concurrent multiplexing каналов добавим, если станет узким местом.
    handle: AsyncMutex<client::Handle<VerifyHandler>>,
    address: String,
    op_timeout: Duration,
    observed_fingerprint: Arc<AsyncMutex<Option<String>>>,
}

impl std::fmt::Debug for RusshTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RusshTransport")
            .field("address", &self.address)
            .field("op_timeout", &self.op_timeout)
            .finish_non_exhaustive()
    }
}

impl RusshTransport {
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Fingerprint host key который мы реально получили при коннекте — TOFU
    /// слой выше использует это, чтобы сохранить в inventory.
    pub async fn observed_host_fingerprint(&self) -> Option<String> {
        self.observed_fingerprint.lock().await.clone()
    }

    pub async fn disconnect(&self) -> Result<()> {
        let session = self.handle.lock().await;
        session
            .disconnect(Disconnect::ByApplication, "", "")
            .await
            .map_err(|e| CoreError::Transport(format!("disconnect: {e}")))?;
        Ok(())
    }
}

#[async_trait]
impl SshTransport for RusshTransport {
    async fn exec(&self, cmd: &str) -> Result<String> {
        let session = self.handle.lock().await;
        let mut channel = session
            .channel_open_session()
            .await
            .map_err(|e| CoreError::Transport(format!("open session: {e}")))?;

        let cmd_owned = cmd.to_string();
        timeout(self.op_timeout, async move {
            channel
                .exec(true, cmd_owned.as_bytes())
                .await
                .map_err(|e| CoreError::Transport(format!("exec: {e}")))?;

            let mut stdout: Vec<u8> = Vec::new();
            let mut stderr: Vec<u8> = Vec::new();
            let mut exit: Option<u32> = None;

            // Drain to end-of-stream — never break early. Some servers send
            // Close before ExitStatus (observed with `tee`/`cat` consuming stdin).
            while let Some(msg) = channel.wait().await {
                match msg {
                    ChannelMsg::Data { ref data } => stdout.extend_from_slice(data),
                    ChannelMsg::ExtendedData { ref data, ext: 1 } => {
                        stderr.extend_from_slice(data);
                    }
                    ChannelMsg::ExitStatus { exit_status } => exit = Some(exit_status),
                    _ => {}
                }
            }

            match exit {
                Some(0) => Ok(String::from_utf8_lossy(&stdout).into_owned()),
                Some(code) => Err(CoreError::Transport(format!(
                    "exec exit={code}: {}",
                    String::from_utf8_lossy(&stderr).trim()
                ))),
                None => Err(CoreError::Transport("exec: no exit status".into())),
            }
        })
        .await
        .map_err(|_| CoreError::Transport(format!("exec timed out: {cmd}")))?
    }

    async fn upload(&self, path: &str, content: &[u8]) -> Result<()> {
        let session = self.handle.lock().await;
        let mut channel = session
            .channel_open_session()
            .await
            .map_err(|e| CoreError::Transport(format!("open session: {e}")))?;

        let quoted = shell_quote(path);
        let cmd = format!("tee {quoted} >/dev/null");
        let payload = content.to_vec();

        timeout(self.op_timeout, async move {
            channel
                .exec(true, cmd.as_bytes())
                .await
                .map_err(|e| CoreError::Transport(format!("exec tee: {e}")))?;
            channel
                .data(&payload[..])
                .await
                .map_err(|e| CoreError::Transport(format!("send data: {e}")))?;
            channel
                .eof()
                .await
                .map_err(|e| CoreError::Transport(format!("eof: {e}")))?;

            // NB: do **not** break on `Eof | Close` here — for commands that
            // consume stdin (like `tee`), the server may send Close before
            // ExitStatus. We drain until the channel iterator returns None.
            let mut exit: Option<u32> = None;
            let mut stderr: Vec<u8> = Vec::new();
            while let Some(msg) = channel.wait().await {
                match msg {
                    ChannelMsg::ExtendedData { ref data, ext: 1 } => {
                        stderr.extend_from_slice(data);
                    }
                    ChannelMsg::ExitStatus { exit_status } => exit = Some(exit_status),
                    _ => {}
                }
            }

            match exit {
                Some(0) => Ok(()),
                Some(code) => Err(CoreError::Transport(format!(
                    "upload exit={code}: {}",
                    String::from_utf8_lossy(&stderr).trim()
                ))),
                None => Err(CoreError::Transport("upload: no exit status".into())),
            }
        })
        .await
        .map_err(|_| CoreError::Transport(format!("upload timed out: {path}")))?
    }

    async fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        let session = self.handle.lock().await;
        let mut channel = session
            .channel_open_session()
            .await
            .map_err(|e| CoreError::Transport(format!("open session: {e}")))?;

        let quoted = shell_quote(path);
        let cmd = format!("cat {quoted}");

        timeout(self.op_timeout, async move {
            channel
                .exec(true, cmd.as_bytes())
                .await
                .map_err(|e| CoreError::Transport(format!("exec cat: {e}")))?;

            let mut buf: Vec<u8> = Vec::new();
            let mut stderr: Vec<u8> = Vec::new();
            let mut exit: Option<u32> = None;

            while let Some(msg) = channel.wait().await {
                match msg {
                    ChannelMsg::Data { ref data } => buf.extend_from_slice(data),
                    ChannelMsg::ExtendedData { ref data, ext: 1 } => {
                        stderr.extend_from_slice(data);
                    }
                    ChannelMsg::ExitStatus { exit_status } => exit = Some(exit_status),
                    _ => {}
                }
            }

            match exit {
                Some(0) => Ok(buf),
                Some(code) => Err(CoreError::Transport(format!(
                    "read exit={code}: {}",
                    String::from_utf8_lossy(&stderr).trim()
                ))),
                None => Err(CoreError::Transport("read: no exit status".into())),
            }
        })
        .await
        .map_err(|_| CoreError::Transport(format!("read timed out: {path}")))?
    }
}

/// POSIX-safe quoting: wrap in single quotes, escape embedded `'` as `'\''`.
fn shell_quote(s: &str) -> String {
    let escaped = s.replace('\'', r"'\''");
    format!("'{escaped}'")
}

#[cfg(test)]
mod tests {
    use super::shell_quote;

    #[test]
    fn quote_simple() {
        assert_eq!(
            shell_quote("/etc/sing-box/config.json"),
            "'/etc/sing-box/config.json'"
        );
    }

    #[test]
    fn quote_with_apostrophe() {
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
    }

    #[test]
    fn quote_with_spaces() {
        assert_eq!(shell_quote("/tmp/my file"), "'/tmp/my file'");
    }
}
