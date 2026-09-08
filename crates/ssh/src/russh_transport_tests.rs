#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;

const SAMPLE_PUBKEY_A: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL7MjcaRD4KtDbHYhu6KPY44nClRcIHQ1EQ9HRrEcORy test@vpnctl";
const SAMPLE_PUBKEY_B: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA other@vpnctl";

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

async fn make_test_transport(user: &str) -> RusshTransport {
    let tmp = tempfile::tempdir().unwrap();
    let server_key_path = tmp.path().join("server_key");
    let status = std::process::Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-q", "-f"])
        .arg(&server_key_path)
        .status()
        .expect("ssh-keygen server key");
    assert!(status.success());

    let client_key_path = make_test_key(&tmp);
    let port = spawn_stalled_channel_server(&server_key_path, false).await;

    RusshTransportBuilder::new("127.0.0.1", user, client_key_path)
        .port(port)
        .timeout(Duration::from_secs(5))
        .connect()
        .await
        .expect("connect succeeds")
}

#[tokio::test]
async fn root_commands_are_not_wrapped_in_sudo() {
    let t = make_test_transport("root").await;
    assert_eq!(t.user(), "root");
    assert_eq!(t.privileged_command("id -u"), "id -u");
    assert_eq!(
        t.privileged_command("printf '%s' \"$HOME\""),
        "printf '%s' \"$HOME\""
    );
}

#[tokio::test]
async fn non_root_commands_use_passwordless_sudo_with_shell_quoting() {
    let t = make_test_transport("debian").await;
    assert_eq!(t.user(), "debian");
    assert_eq!(t.privileged_command("id -u"), "sudo -n sh -c 'id -u'");
    assert_eq!(
        t.privileged_command("printf '%s' \"$HOME\""),
        "sudo -n sh -c 'printf '\\''%s'\\'' \"$HOME\"'"
    );
}

#[tokio::test]
async fn root_upload_and_read_file_commands_are_not_wrapped_in_sudo() {
    let t = make_test_transport("root").await;
    let upload_cmd = format!("tee {} >/dev/null", shell_quote("/etc/vpnctl/config.json"));
    let read_cmd = format!("cat {}", shell_quote("/etc/vpnctl/config.json"));
    assert_eq!(
        t.privileged_command(&upload_cmd),
        "tee '/etc/vpnctl/config.json' >/dev/null"
    );
    assert_eq!(
        t.privileged_command(&read_cmd),
        "cat '/etc/vpnctl/config.json'"
    );
}

#[tokio::test]
async fn non_root_upload_and_read_file_commands_use_passwordless_sudo_with_shell_quoting() {
    let t = make_test_transport("debian").await;
    let upload_cmd = format!("tee {} >/dev/null", shell_quote("/etc/vpnctl/config.json"));
    let read_cmd = format!("cat {}", shell_quote("/etc/vpnctl/config.json"));
    assert_eq!(
        t.privileged_command(&upload_cmd),
        "sudo -n sh -c 'tee '\\''/etc/vpnctl/config.json'\\'' >/dev/null'"
    );
    assert_eq!(
        t.privileged_command(&read_cmd),
        "sudo -n sh -c 'cat '\\''/etc/vpnctl/config.json'\\'''"
    );
}
