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
use zeroize::Zeroizing;

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
            Some(expected) if vpnctl_host_fingerprint::fingerprints_match(expected, &fp) => {
                Ok(true)
            }
            Some(_) => Err(russh::Error::UnknownKey),
            None => Ok(true), // TOFU
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Builder
// ────────────────────────────────────────────────────────────────────────────

pub struct RusshTransportBuilder {
    address: String,
    port: u16,
    user: String,
    key_path: PathBuf,
    /// Wrapped in `Zeroizing` so it gets memset(0) on drop and never appears
    /// in `{:?}` output (custom Debug below redacts it).
    key_passphrase: Option<Zeroizing<String>>,
    /// Опциональный password-fallback. Используется ТОЛЬКО если pubkey-auth
    /// не прошёл (например, во время `vpnctl bootstrap` — наш ключ ещё не
    /// добавлен на ноду). В обычном `deploy` остаётся `None` и лишний
    /// network round-trip не делается.
    password: Option<Zeroizing<String>>,
    trusted_fingerprint: Option<String>,
    op_timeout: Duration,
}

// Manual Debug — DERIVED Debug would print the wrapped String contents
// (Zeroizing implements Deref). Redact secret-bearing fields explicitly.
impl std::fmt::Debug for RusshTransportBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RusshTransportBuilder")
            .field("address", &self.address)
            .field("port", &self.port)
            .field("user", &self.user)
            .field("key_path", &self.key_path)
            .field(
                "key_passphrase",
                &self.key_passphrase.as_ref().map(|_| "<redacted>"),
            )
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("trusted_fingerprint", &self.trusted_fingerprint)
            .field("op_timeout", &self.op_timeout)
            .finish()
    }
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
            password: None,
            trusted_fingerprint: None,
            op_timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Установить password как fallback для первого подключения. Pubkey-auth
    /// пытается первой; если ключа на сервере ещё нет — auth откатывается на
    /// password. Используется в `vpnctl bootstrap` при провижне новой ноды.
    /// Хранится в `Zeroizing<String>` — memset(0) при drop.
    pub fn password(mut self, p: impl Into<String>) -> Self {
        self.password = Some(Zeroizing::new(p.into()));
        self
    }

    pub fn port(mut self, p: u16) -> Self {
        self.port = p;
        self
    }

    pub fn passphrase(mut self, p: impl Into<String>) -> Self {
        self.key_passphrase = Some(Zeroizing::new(p.into()));
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
        let passphrase_str = self.key_passphrase.as_deref().map(|s| s.as_str());
        let key = load_secret_key(&self.key_path, passphrase_str)
            .map_err(|e| CoreError::Transport(format!("load key {:?}: {e}", self.key_path)))?;

        let observed = Arc::new(AsyncMutex::new(None));
        let handler = VerifyHandler {
            trusted_fingerprint: self.trusted_fingerprint.clone(),
            observed_fingerprint: Arc::clone(&observed),
        };

        let config = Arc::new(client::Config::default());
        let address = self.address.clone();
        let port = self.port;
        let user = self.user.clone();
        let password = self.password.clone();
        let op_timeout = self.op_timeout;

        let handle = timeout(op_timeout, async move {
            let mut handle = client::connect(config, (address.as_str(), port), handler)
                .await
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
                .authenticate_publickey(&user, pk)
                .await
                .map_err(|e| CoreError::Transport(format!("auth (pubkey): {e}")))?;
            if !auth.success() {
                // Pubkey не принят — это нормально на первый bootstrap-коннект.
                // Если builder задал `password()`, пробуем password-fallback.
                if let Some(pw) = password.as_deref() {
                    tracing::warn!(
                        target = "vpnctl::ssh",
                        "pubkey auth failed for {}, trying password fallback",
                        user
                    );
                    let auth = handle
                        .authenticate_password(&user, pw)
                        .await
                        .map_err(|e| CoreError::Transport(format!("auth (password): {e}")))?;
                    if !auth.success() {
                        return Err(CoreError::Transport(format!(
                            "auth failed for user {} (both pubkey and password)",
                            user
                        )));
                    }
                } else {
                    return Err(CoreError::Transport(format!(
                        "pubkey auth failed for user {} (no password fallback configured)",
                        user
                    )));
                }
            }

            Ok(handle)
        })
        .await
        .map_err(|_| CoreError::Transport("connect timed out".into()))??;

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
        let cmd_owned = cmd.to_string();
        timeout(self.op_timeout, async move {
            let mut channel = session
                .channel_open_session()
                .await
                .map_err(|e| CoreError::Transport(format!("open session: {e}")))?;

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
        let quoted = shell_quote(path);
        let cmd = format!("tee {quoted} >/dev/null");
        let payload = content.to_vec();

        timeout(self.op_timeout, async move {
            let mut channel = session
                .channel_open_session()
                .await
                .map_err(|e| CoreError::Transport(format!("open session: {e}")))?;

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
        let quoted = shell_quote(path);
        let cmd = format!("cat {quoted}");

        timeout(self.op_timeout, async move {
            let mut channel = session
                .channel_open_session()
                .await
                .map_err(|e| CoreError::Transport(format!("open session: {e}")))?;

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

// `shell_quote` moved to `vpnctl_core::shell::single_quote`
// (2026-05-18) — was triplicated; consolidated for parity.
use vpnctl_core::shell::single_quote as shell_quote;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    const SAMPLE_PUBKEY_A: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL7MjcaRD4KtDbHYhu6KPY44nClRcIHQ1EQ9HRrEcORy test@vpnctl";
    const SAMPLE_PUBKEY_B: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA other@vpnctl";

    #[tokio::test]
    async fn verify_handler_accepts_canonical_unpadded_fingerprint() {
        let pk = PublicKey::from_openssh(SAMPLE_PUBKEY_A).expect("parse pubkey");
        let canonical_fp = pk.fingerprint(HashAlg::Sha256).to_string();
        let observed = Arc::new(AsyncMutex::new(None));
        let mut handler = VerifyHandler {
            trusted_fingerprint: Some(canonical_fp.clone()),
            observed_fingerprint: Arc::clone(&observed),
        };

        let res = handler.check_server_key(&pk).await;
        assert!(res.is_ok());
        assert_eq!(*observed.lock().await, Some(canonical_fp));
    }

    #[tokio::test]
    async fn verify_handler_accepts_padded_fingerprint() {
        let pk = PublicKey::from_openssh(SAMPLE_PUBKEY_A).expect("parse pubkey");
        let canonical_fp = pk.fingerprint(HashAlg::Sha256).to_string();
        let padded_fp = format!("{canonical_fp}=");
        let observed = Arc::new(AsyncMutex::new(None));
        let mut handler = VerifyHandler {
            trusted_fingerprint: Some(padded_fp),
            observed_fingerprint: Arc::clone(&observed),
        };

        let res = handler.check_server_key(&pk).await;
        assert!(res.is_ok());
        assert_eq!(*observed.lock().await, Some(canonical_fp));
    }

    #[tokio::test]
    async fn verify_handler_accepts_url_safe_and_url_safe_padded_fingerprint() {
        let pk = PublicKey::from_openssh(SAMPLE_PUBKEY_A).expect("parse pubkey");
        let canonical_fp = pk.fingerprint(HashAlg::Sha256).to_string();
        let url_safe_fp = canonical_fp.replace('+', "-").replace('/', "_");
        let url_safe_padded_fp = format!("{url_safe_fp}=");
        let observed = Arc::new(AsyncMutex::new(None));

        let mut handler1 = VerifyHandler {
            trusted_fingerprint: Some(url_safe_fp),
            observed_fingerprint: Arc::clone(&observed),
        };
        assert!(handler1.check_server_key(&pk).await.is_ok());

        let mut handler2 = VerifyHandler {
            trusted_fingerprint: Some(url_safe_padded_fp),
            observed_fingerprint: Arc::clone(&observed),
        };
        assert!(handler2.check_server_key(&pk).await.is_ok());
    }

    #[tokio::test]
    async fn verify_handler_rejects_mismatched_key_fingerprint() {
        let pk_a = PublicKey::from_openssh(SAMPLE_PUBKEY_A).expect("parse pubkey a");
        let pk_b = PublicKey::from_openssh(SAMPLE_PUBKEY_B).expect("parse pubkey b");
        let canonical_fp_b = pk_b.fingerprint(HashAlg::Sha256).to_string();
        let observed = Arc::new(AsyncMutex::new(None));
        let mut handler = VerifyHandler {
            trusted_fingerprint: Some(canonical_fp_b),
            observed_fingerprint: Arc::clone(&observed),
        };

        let res = handler.check_server_key(&pk_a).await;
        assert!(matches!(res, Err(russh::Error::UnknownKey)));
    }

    #[tokio::test]
    async fn verify_handler_rejects_malformed_fingerprint() {
        let pk = PublicKey::from_openssh(SAMPLE_PUBKEY_A).expect("parse pubkey");
        let observed = Arc::new(AsyncMutex::new(None));
        let mut handler = VerifyHandler {
            trusted_fingerprint: Some("SHA256:not-valid-base64!".to_string()),
            observed_fingerprint: Arc::clone(&observed),
        };

        let res = handler.check_server_key(&pk).await;
        assert!(matches!(res, Err(russh::Error::UnknownKey)));
    }

    #[tokio::test]
    async fn verify_handler_tofu_records_and_accepts() {
        let pk = PublicKey::from_openssh(SAMPLE_PUBKEY_A).expect("parse pubkey");
        let canonical_fp = pk.fingerprint(HashAlg::Sha256).to_string();
        let observed = Arc::new(AsyncMutex::new(None));
        let mut handler = VerifyHandler {
            trusted_fingerprint: None,
            observed_fingerprint: Arc::clone(&observed),
        };

        let res = handler.check_server_key(&pk).await;
        assert!(res.is_ok());
        assert_eq!(*observed.lock().await, Some(canonical_fp));
    }

    fn make_test_key(dir: &tempfile::TempDir) -> std::path::PathBuf {
        let priv_path = dir.path().join("id_ed25519");
        let status = std::process::Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-N", "", "-q", "-f"])
            .arg(&priv_path)
            .status()
            .expect("ssh-keygen invocation");
        assert!(status.success());
        priv_path
    }

    #[tokio::test]
    async fn connect_timeout_on_tcp_tarpit() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            if let Ok((_sock, _)) = listener.accept().await {
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });

        let tmp = tempfile::tempdir().unwrap();
        let key_path = make_test_key(&tmp);

        let start = std::time::Instant::now();
        let res = RusshTransportBuilder::new("127.0.0.1", "testuser", key_path)
            .port(port)
            .timeout(Duration::from_millis(100))
            .connect()
            .await;

        let elapsed = start.elapsed();
        assert!(elapsed < Duration::from_secs(3), "took {elapsed:?}");
        match res {
            Err(CoreError::Transport(msg)) => {
                assert!(
                    msg.contains("timed out"),
                    "expected timeout error, got {msg}"
                );
            }
            other => panic!("expected CoreError::Transport(timed out), got {other:?}"),
        }
    }

    use russh::server::Server;

    #[derive(Clone)]
    struct StalledAuthServer {
        stall_pubkey: bool,
        stall_password: bool,
    }

    impl russh::server::Server for StalledAuthServer {
        type Handler = StalledAuthHandler;

        fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self::Handler {
            StalledAuthHandler {
                stall_pubkey: self.stall_pubkey,
                stall_password: self.stall_password,
            }
        }
    }

    struct StalledAuthHandler {
        stall_pubkey: bool,
        stall_password: bool,
    }

    impl russh::server::Handler for StalledAuthHandler {
        type Error = russh::Error;

        async fn auth_publickey(
            &mut self,
            _user: &str,
            _publickey: &PublicKey,
        ) -> std::result::Result<russh::server::Auth, Self::Error> {
            if self.stall_pubkey {
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
            Ok(russh::server::Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            })
        }

        async fn auth_password(
            &mut self,
            _user: &str,
            _password: &str,
        ) -> std::result::Result<russh::server::Auth, Self::Error> {
            if self.stall_password {
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
            Ok(russh::server::Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            })
        }
    }

    async fn spawn_stalled_server(
        server_key_path: &std::path::Path,
        stall_pubkey: bool,
        stall_password: bool,
    ) -> u16 {
        let server_key = load_secret_key(server_key_path, None).expect("load server key");
        let mut config = russh::server::Config::default();
        config.keys.push(server_key);
        let config = Arc::new(config);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let mut server = StalledAuthServer {
            stall_pubkey,
            stall_password,
        };

        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let config = Arc::clone(&config);
                let handler = server.new_client(stream.peer_addr().ok());
                tokio::spawn(async move {
                    let _ = russh::server::run_stream(config, stream, handler).await;
                });
            }
        });

        // Give the listener a moment to bind and accept
        tokio::time::sleep(Duration::from_millis(20)).await;
        port
    }

    #[tokio::test]
    async fn connect_timeout_on_stalled_pubkey_auth() {
        let tmp = tempfile::tempdir().unwrap();
        let server_key_path = tmp.path().join("server_key");
        let status = std::process::Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-N", "", "-q", "-f"])
            .arg(&server_key_path)
            .status()
            .expect("ssh-keygen server key");
        assert!(status.success());

        let client_key_path = make_test_key(&tmp);
        let port = spawn_stalled_server(&server_key_path, true, false).await;

        let start = std::time::Instant::now();
        let res = RusshTransportBuilder::new("127.0.0.1", "testuser", client_key_path)
            .port(port)
            .timeout(Duration::from_millis(150))
            .connect()
            .await;

        let elapsed = start.elapsed();
        assert!(elapsed < Duration::from_secs(3), "took {elapsed:?}");
        match res {
            Err(CoreError::Transport(msg)) => {
                assert!(
                    msg.contains("timed out"),
                    "expected timeout error, got {msg}"
                );
            }
            other => panic!("expected CoreError::Transport(timed out), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn connect_timeout_on_stalled_password_auth() {
        let tmp = tempfile::tempdir().unwrap();
        let server_key_path = tmp.path().join("server_key");
        let status = std::process::Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-N", "", "-q", "-f"])
            .arg(&server_key_path)
            .status()
            .expect("ssh-keygen server key");
        assert!(status.success());

        let client_key_path = make_test_key(&tmp);
        let port = spawn_stalled_server(&server_key_path, false, true).await;

        let start = std::time::Instant::now();
        let res = RusshTransportBuilder::new("127.0.0.1", "testuser", client_key_path)
            .port(port)
            .password("some-fallback-password")
            .timeout(Duration::from_millis(150))
            .connect()
            .await;

        let elapsed = start.elapsed();
        assert!(elapsed < Duration::from_secs(3), "took {elapsed:?}");
        match res {
            Err(CoreError::Transport(msg)) => {
                assert!(
                    msg.contains("timed out"),
                    "expected timeout error, got {msg}"
                );
            }
            other => panic!("expected CoreError::Transport(timed out), got {other:?}"),
        }
    }

    #[derive(Clone)]
    struct StalledChannelServer {
        stall_channel_open: bool,
    }

    impl russh::server::Server for StalledChannelServer {
        type Handler = StalledChannelHandler;

        fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self::Handler {
            StalledChannelHandler {
                stall_channel_open: self.stall_channel_open,
            }
        }
    }

    struct StalledChannelHandler {
        stall_channel_open: bool,
    }

    impl russh::server::Handler for StalledChannelHandler {
        type Error = russh::Error;

        async fn auth_publickey(
            &mut self,
            _user: &str,
            _publickey: &PublicKey,
        ) -> std::result::Result<russh::server::Auth, Self::Error> {
            Ok(russh::server::Auth::Accept)
        }

        async fn channel_open_session(
            &mut self,
            _channel: russh::Channel<russh::server::Msg>,
            _session: &mut russh::server::Session,
        ) -> std::result::Result<bool, Self::Error> {
            if self.stall_channel_open {
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
            Ok(true)
        }
    }

    async fn spawn_stalled_channel_server(
        server_key_path: &std::path::Path,
        stall_channel_open: bool,
    ) -> u16 {
        let server_key = load_secret_key(server_key_path, None).expect("load server key");
        let mut config = russh::server::Config::default();
        config.keys.push(server_key);
        let config = Arc::new(config);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let mut server = StalledChannelServer { stall_channel_open };

        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let config = Arc::clone(&config);
                let handler = server.new_client(stream.peer_addr().ok());
                tokio::spawn(async move {
                    let _ = russh::server::run_stream(config, stream, handler).await;
                });
            }
        });

        tokio::time::sleep(Duration::from_millis(20)).await;
        port
    }

    #[tokio::test]
    async fn exec_timeout_on_stalled_channel_open() {
        let tmp = tempfile::tempdir().unwrap();
        let server_key_path = tmp.path().join("server_key");
        let status = std::process::Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-N", "", "-q", "-f"])
            .arg(&server_key_path)
            .status()
            .expect("ssh-keygen server key");
        assert!(status.success());

        let client_key_path = make_test_key(&tmp);
        let port = spawn_stalled_channel_server(&server_key_path, true).await;

        let transport = RusshTransportBuilder::new("127.0.0.1", "testuser", client_key_path)
            .port(port)
            .timeout(Duration::from_millis(150))
            .connect()
            .await
            .expect("connect succeeds");

        let start = std::time::Instant::now();
        let res = transport.exec("uname -s").await;
        let elapsed = start.elapsed();

        assert!(elapsed < Duration::from_secs(3), "took {elapsed:?}");
        match res {
            Err(CoreError::Transport(msg)) => {
                assert!(
                    msg.contains("exec timed out: uname -s"),
                    "expected exec timeout error, got: {msg}"
                );
            }
            other => panic!("expected CoreError::Transport(timed out), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn upload_timeout_on_stalled_channel_open() {
        let tmp = tempfile::tempdir().unwrap();
        let server_key_path = tmp.path().join("server_key");
        let status = std::process::Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-N", "", "-q", "-f"])
            .arg(&server_key_path)
            .status()
            .expect("ssh-keygen server key");
        assert!(status.success());

        let client_key_path = make_test_key(&tmp);
        let port = spawn_stalled_channel_server(&server_key_path, true).await;

        let transport = RusshTransportBuilder::new("127.0.0.1", "testuser", client_key_path)
            .port(port)
            .timeout(Duration::from_millis(150))
            .connect()
            .await
            .expect("connect succeeds");

        let start = std::time::Instant::now();
        let res = transport.upload("/tmp/stalled.txt", b"hello").await;
        let elapsed = start.elapsed();

        assert!(elapsed < Duration::from_secs(3), "took {elapsed:?}");
        match res {
            Err(CoreError::Transport(msg)) => {
                assert!(
                    msg.contains("upload timed out: /tmp/stalled.txt"),
                    "expected upload timeout error, got: {msg}"
                );
            }
            other => panic!("expected CoreError::Transport(timed out), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn read_file_timeout_on_stalled_channel_open() {
        let tmp = tempfile::tempdir().unwrap();
        let server_key_path = tmp.path().join("server_key");
        let status = std::process::Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-N", "", "-q", "-f"])
            .arg(&server_key_path)
            .status()
            .expect("ssh-keygen server key");
        assert!(status.success());

        let client_key_path = make_test_key(&tmp);
        let port = spawn_stalled_channel_server(&server_key_path, true).await;

        let transport = RusshTransportBuilder::new("127.0.0.1", "testuser", client_key_path)
            .port(port)
            .timeout(Duration::from_millis(150))
            .connect()
            .await
            .expect("connect succeeds");

        let start = std::time::Instant::now();
        let res = transport.read_file("/tmp/stalled.txt").await;
        let elapsed = start.elapsed();

        assert!(elapsed < Duration::from_secs(3), "took {elapsed:?}");
        match res {
            Err(CoreError::Transport(msg)) => {
                assert!(
                    msg.contains("read timed out: /tmp/stalled.txt"),
                    "expected read timeout error, got: {msg}"
                );
            }
            other => panic!("expected CoreError::Transport(timed out), got {other:?}"),
        }
    }
}
