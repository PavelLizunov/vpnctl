//! Private, owned sing-box process and retained-socket Corp observation.
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nix::sys::signal::{Signal, killpg};
use nix::sys::wait::{Id, WaitPidFlag, WaitStatus, waitid};
use nix::unistd::{Pid, getegid, geteuid, getgroups};
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use serde_json::{Value, json};
use tokio::sync::{Semaphore, oneshot};
use zeroize::Zeroizing;

use crate::corp_egress::{ProbeError, ProbeRequest, ProbeRunner};

const HOST: &str = "admin.corp.ninitux.com";
const MAX_PROC: u64 = 4 * 1024 * 1024;

pub struct RunnerConfig {
    pub executable: PathBuf,
    pub work_root: PathBuf,
    pub tls_roots: RootCertStore,
    pub work_timeout: Duration,
    pub cleanup_timeout: Duration,
}
impl std::fmt::Debug for RunnerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RunnerConfig { .. }")
    }
}
pub struct SingBoxRunner {
    config: Arc<RunnerConfig>,
    gate: Arc<Semaphore>,
    poison: Arc<AtomicBool>,
}
impl std::fmt::Debug for SingBoxRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SingBoxRunner { .. }")
    }
}
impl SingBoxRunner {
    pub fn new(config: RunnerConfig) -> Result<Self, ProbeError> {
        if config.work_timeout.is_zero()
            || config.work_timeout > Duration::from_secs(15)
            || config.cleanup_timeout.is_zero()
            || config.cleanup_timeout > Duration::from_secs(2)
            || config.tls_roots.is_empty()
        {
            return Err(ProbeError::Unavailable);
        }
        trust(&config)?;
        Ok(Self {
            config: Arc::new(config),
            gate: Arc::new(Semaphore::new(1)),
            poison: Arc::new(AtomicBool::new(false)),
        })
    }
    pub fn production() -> Result<Self, ProbeError> {
        let root = PathBuf::from("/var/lib/vpnctl/corp-probes");
        // Validate the existing ancestry before creating a private leaf.
        trusted_ancestors(&root)?;
        match fs::DirBuilder::new().mode(0o700).create(&root) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(ProbeError::Unavailable),
        }
        let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self::new(RunnerConfig {
            executable: PathBuf::from("/opt/vpnctl/node-artifacts/sing-box"),
            work_root: root,
            tls_roots: roots,
            work_timeout: Duration::from_secs(15),
            cleanup_timeout: Duration::from_secs(2),
        })
    }
}
#[async_trait::async_trait]
impl ProbeRunner for SingBoxRunner {
    fn available(&self) -> bool {
        !self.poison.load(Ordering::SeqCst) && trust(&self.config).is_ok()
    }
    async fn run(&self, request: ProbeRequest) -> Result<(), ProbeError> {
        if !self.available() {
            return Err(ProbeError::Unavailable);
        }
        let permit = Arc::clone(&self.gate)
            .try_acquire_owned()
            .map_err(|_| ProbeError::Busy)?;
        if !self.available() {
            return Err(ProbeError::Unavailable);
        }
        let deadline = Instant::now() + self.config.work_timeout;
        let acknowledgement = deadline + self.config.cleanup_timeout;
        let config = Arc::clone(&self.config);
        let poison = Arc::clone(&self.poison);
        let (sender, receiver) = oneshot::channel();
        drop(tokio::task::spawn_blocking(move || {
            let mut owner = Owner::new(Arc::clone(&poison));
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if poison.load(Ordering::SeqCst) {
                    return Err(ProbeError::Unavailable);
                }
                execute(&config, &request, deadline, &mut owner)
            }));
            let result = match outcome {
                Ok(result) => result,
                Err(_) => {
                    poison.store(true, Ordering::SeqCst);
                    Err(ProbeError::CleanupFailed)
                }
            };
            let cleanup_deadline = Instant::now() + config.cleanup_timeout;
            if owner.cleanup_until(cleanup_deadline) {
                // Acknowledgement follows directory removal and socket close.
                owner.socket.take();
                let result = if Instant::now() >= acknowledgement || poison.load(Ordering::SeqCst) {
                    poison.store(true, Ordering::SeqCst);
                    Err(ProbeError::CleanupFailed)
                } else {
                    result
                };
                drop(permit);
                let _ = sender.send(result);
            } else {
                poison.store(true, Ordering::SeqCst);
                let _ = sender.send(Err(ProbeError::CleanupFailed));
                // The same blocking owner retains the gate and all resources.
                owner.reap_until_complete();
            }
        }));
        match tokio::time::timeout_at(tokio::time::Instant::from_std(acknowledgement), receiver)
            .await
        {
            Ok(Ok(result)) if Instant::now() < acknowledgement => result,
            _ => {
                self.poison.store(true, Ordering::SeqCst);
                Err(ProbeError::CleanupFailed)
            }
        }
    }
}

fn safe_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
}
fn trusted_owner(meta: &fs::Metadata) -> bool {
    meta.uid() == 0 || meta.uid() == geteuid().as_raw()
}
fn trusted_ancestors(path: &Path) -> Result<(), ProbeError> {
    if !safe_absolute(path) {
        return Err(ProbeError::Unavailable);
    }
    let parent = path.parent().ok_or(ProbeError::Unavailable)?;
    for ancestor in parent.ancestors() {
        let meta = fs::symlink_metadata(ancestor).map_err(|_| ProbeError::Unavailable)?;
        let sticky_root = meta.uid() == 0 && meta.mode() & 0o1000 != 0;
        if !meta.is_dir() || !trusted_owner(&meta) || (meta.mode() & 0o022 != 0 && !sticky_root) {
            return Err(ProbeError::Unavailable);
        }
    }
    Ok(())
}
fn executable_by_owner(meta: &fs::Metadata) -> Result<bool, ProbeError> {
    let uid = geteuid().as_raw();
    if uid == 0 {
        return Ok(meta.mode() & 0o111 != 0);
    }
    if meta.uid() == uid {
        return Ok(meta.mode() & 0o100 != 0);
    }
    let group = meta.gid() == getegid().as_raw()
        || getgroups()
            .map_err(|_| ProbeError::Unavailable)?
            .iter()
            .any(|gid| gid.as_raw() == meta.gid());
    Ok(meta.mode() & if group { 0o010 } else { 0o001 } != 0)
}
fn trust(config: &RunnerConfig) -> Result<(), ProbeError> {
    trusted_ancestors(&config.executable)?;
    trusted_ancestors(&config.work_root)?;
    let executable =
        fs::symlink_metadata(&config.executable).map_err(|_| ProbeError::Unavailable)?;
    let root = fs::symlink_metadata(&config.work_root).map_err(|_| ProbeError::Unavailable)?;
    if !executable.is_file()
        || !trusted_owner(&executable)
        || executable.mode() & 0o022 != 0
        || !executable_by_owner(&executable)?
        || !root.is_dir()
        || !trusted_owner(&root)
        || root.permissions().mode() & 0o777 != 0o700
    {
        return Err(ProbeError::Unavailable);
    }
    Ok(())
}
fn valid_uuid(uuid: &str) -> bool {
    uuid.len() == 36
        && uuid.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}
struct BoundedJson {
    bytes: Zeroizing<Vec<u8>>,
    limit: usize,
}
impl Write for BoundedJson {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "probe size"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn serialize_bounded(value: &Value, limit: usize) -> Result<Zeroizing<Vec<u8>>, ProbeError> {
    let mut writer = BoundedJson {
        bytes: Zeroizing::new(Vec::new()),
        limit,
    };
    serde_json::to_writer(&mut writer, value).map_err(|_| ProbeError::Failed)?;
    Ok(writer.bytes)
}
fn validate(request: &ProbeRequest) -> Result<(), ProbeError> {
    if request.token.len() != 43 {
        return Err(ProbeError::Failed);
    }
    let token = URL_SAFE_NO_PAD
        .decode(request.token.as_bytes())
        .map_err(|_| ProbeError::Failed)?;
    let outbound = &request.outbound;
    let server_valid = outbound
        .get("server")
        .and_then(Value::as_str)
        .is_some_and(|server| {
            server.parse::<std::net::IpAddr>().is_ok()
                || url::Host::parse(server).is_ok_and(
                    |host| matches!(host, url::Host::Domain(domain) if !domain.is_empty()),
                )
        });
    let valid_text = |key| {
        outbound.get(key).and_then(Value::as_str).is_some_and(|s| {
            !s.is_empty()
                && s.len() <= 253
                && !s.chars().any(char::is_control)
                && !s.chars().any(char::is_whitespace)
        })
    };
    if token.len() != 32
        || URL_SAFE_NO_PAD.encode(&token) != request.token.as_str()
        || serialize_bounded(outbound, 65536).is_err()
        || !outbound.is_object()
        || outbound.get("type").and_then(Value::as_str) != Some("vless")
        || !valid_text("tag")
        || !valid_text("server")
        || !server_valid
        || !outbound
            .get("server_port")
            .and_then(Value::as_u64)
            .is_some_and(|p| (1..=65535).contains(&p))
        || !outbound
            .get("uuid")
            .and_then(Value::as_str)
            .is_some_and(valid_uuid)
        || outbound.pointer("/tls/enabled").and_then(Value::as_bool) != Some(true)
        || outbound.get("detour").is_some()
    {
        return Err(ProbeError::Failed);
    }
    Ok(())
}
fn random_secret() -> Result<Zeroizing<String>, ProbeError> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(bytes.as_mut()).map_err(|_| ProbeError::Failed)?;
    Ok(Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes.as_ref())))
}

struct Owner {
    child: Option<Child>,
    directory: Option<tempfile::TempDir>,
    socket: Option<TcpStream>,
    poison: Arc<AtomicBool>,
    cleanup_failed: bool,
    ownership_lost: bool,
}
impl Owner {
    fn new(poison: Arc<AtomicBool>) -> Self {
        Self {
            child: None,
            directory: None,
            socket: None,
            poison,
            cleanup_failed: false,
            ownership_lost: false,
        }
    }
    fn cleanup_error(&mut self) -> bool {
        self.cleanup_failed = true;
        self.poison.store(true, Ordering::SeqCst);
        false
    }
    fn cleanup_step(&mut self) -> bool {
        // Once wait ownership is uncertain, no cached numeric identifier is safe.
        // Retain all resources in this owner; only service shutdown can dispose
        // of this quarantine without a previously captured stable process handle.
        if self.ownership_lost {
            return self.cleanup_error();
        }
        if let Some(child) = self.child.as_mut() {
            let Ok(pid) = i32::try_from(child.id()) else {
                return self.cleanup_error();
            };
            // The leader is still owned and unreaped when the group is signalled.
            match killpg(Pid::from_raw(pid), Signal::SIGKILL) {
                Ok(()) | Err(nix::errno::Errno::ESRCH) => {}
                Err(_) => return self.cleanup_error(),
            }
            match child.try_wait() {
                Ok(Some(_)) => {
                    self.child.take();
                }
                Ok(None) => return false,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => return false,
                Err(_) => {
                    self.ownership_lost = true;
                    return self.cleanup_error();
                }
            }
        }
        if let Some(directory) = self.directory.as_ref() {
            match fs::remove_dir_all(directory.path()) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(_) => return self.cleanup_error(),
            }
            self.directory.take();
        }
        true
    }
    fn cleanup_until(&mut self, deadline: Instant) -> bool {
        loop {
            if self.cleanup_step() {
                return !self.cleanup_failed;
            }
            if self.cleanup_failed || Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    fn reap_until_complete(&mut self) {
        while !self.cleanup_step() {
            std::thread::sleep(Duration::from_millis(25));
        }
        self.socket.take();
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        if self.child.is_some() || self.directory.is_some() {
            self.poison.store(true, Ordering::SeqCst);
            self.reap_until_complete();
        }
    }
}
fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "probe deadline"))
}
fn check_deadline(deadline: Instant) -> Result<(), ProbeError> {
    remaining(deadline)
        .map(|_| ())
        .map_err(|_| ProbeError::Failed)
}
fn execute(
    config: &RunnerConfig,
    request: &ProbeRequest,
    deadline: Instant,
    owner: &mut Owner,
) -> Result<(), ProbeError> {
    validate(request)?;
    check_deadline(deadline)?;
    trust(config)?;
    let username = random_secret()?;
    let password = random_secret()?;
    let directory = tempfile::Builder::new()
        .prefix("probe-")
        .tempdir_in(&config.work_root)
        .map_err(|_| ProbeError::Failed)?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .map_err(|_| ProbeError::Failed)?;
    owner.directory = Some(directory);
    let directory = owner.directory.as_ref().ok_or(ProbeError::Failed)?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|_| ProbeError::Failed)?;
    let address = listener.local_addr().map_err(|_| ProbeError::Failed)?;
    let cfg = json!({
        "log": {"disabled": true},
        "dns": {"servers": [{"type": "local", "tag": "bootstrap"}], "final": "bootstrap"},
        "inbounds": [{"type": "socks", "tag": "probe", "listen": "127.0.0.1", "listen_port": address.port(),
            "users": [{"username": username.as_str(), "password": password.as_str()}]}],
        "outbounds": [request.outbound],
        "route": {"final": request.outbound["tag"], "default_domain_resolver": "bootstrap"}
    });
    let serialized = serialize_bounded(&cfg, 131072)?;
    let path = directory.path().join("config.json");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|_| ProbeError::Failed)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| ProbeError::Failed)?;
    file.write_all(&serialized)
        .map_err(|_| ProbeError::Failed)?;
    drop(file);
    check_deadline(deadline)?;
    trust(config)?;
    drop(listener);
    owner.child = Some(
        Command::new(&config.executable)
            .arg("run")
            .arg("-c")
            .arg(&path)
            .current_dir(directory.path())
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .map_err(|_| ProbeError::Failed)?,
    );
    let child = owner.child.as_ref().ok_or(ProbeError::Failed)?;
    let pid = i32::try_from(child.id()).map_err(|_| ProbeError::Failed)?;
    loop {
        check_deadline(deadline)?;
        alive(pid, &mut owner.ownership_lost)?;
        match TcpStream::connect_timeout(
            &address,
            remaining(deadline).map_err(|_| ProbeError::Failed)?,
        ) {
            Ok(stream) => {
                owner.socket = Some(stream);
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                std::thread::sleep(
                    Duration::from_millis(5)
                        .min(remaining(deadline).map_err(|_| ProbeError::Failed)?),
                );
            }
            Err(_) => return Err(ProbeError::Failed),
        }
    }
    let socket = owner.socket.as_mut().ok_or(ProbeError::Failed)?;
    prove_ownership(pid, socket, deadline, &mut owner.ownership_lost)?;
    let mut io = DeadlineStream {
        stream: socket,
        deadline,
    };
    socks(&mut io, username.as_bytes(), password.as_bytes()).map_err(|_| ProbeError::Failed)?;
    https(config, &mut io, request.token.as_str(), deadline)
}
fn alive(pid: i32, ownership_lost: &mut bool) -> Result<(), ProbeError> {
    match waitid(
        Id::Pid(Pid::from_raw(pid)),
        WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT,
    ) {
        Ok(WaitStatus::StillAlive) => Ok(()),
        Ok(_) | Err(nix::errno::Errno::EINTR) => Err(ProbeError::Failed),
        Err(_) => {
            *ownership_lost = true;
            Err(ProbeError::CleanupFailed)
        }
    }
}
fn bounded_proc(path: &Path) -> Result<String, ProbeError> {
    let file = File::open(path).map_err(|_| ProbeError::Failed)?;
    let mut bytes = Vec::new();
    file.take(MAX_PROC + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ProbeError::Failed)?;
    if bytes.len() as u64 > MAX_PROC {
        return Err(ProbeError::Failed);
    }
    String::from_utf8(bytes).map_err(|_| ProbeError::Failed)
}
fn proc_tuple(address: SocketAddr) -> Result<String, ProbeError> {
    let SocketAddr::V4(v4) = address else {
        return Err(ProbeError::Failed);
    };
    Ok(format!(
        "{:08X}:{:04X}",
        u32::from_le_bytes(v4.ip().octets()),
        v4.port()
    ))
}
fn valid_proc_tuple(tuple: &str) -> bool {
    let Some((ip, port)) = tuple.split_once(':') else {
        return false;
    };
    ip.len() == 8
        && port.len() == 4
        && u32::from_str_radix(ip, 16).is_ok()
        && u16::from_str_radix(port, 16).is_ok()
}
fn prove_ownership(
    pid: i32,
    stream: &TcpStream,
    deadline: Instant,
    ownership_lost: &mut bool,
) -> Result<(), ProbeError> {
    loop {
        check_deadline(deadline)?;
        if ownership_snapshot(pid, stream, deadline, ownership_lost)? {
            return Ok(());
        }
        std::thread::sleep(
            Duration::from_millis(5).min(remaining(deadline).map_err(|_| ProbeError::Failed)?),
        );
    }
}
fn ownership_snapshot(
    pid: i32,
    stream: &TcpStream,
    deadline: Instant,
    ownership_lost: &mut bool,
) -> Result<bool, ProbeError> {
    alive(pid, ownership_lost)?;
    let local = proc_tuple(stream.peer_addr().map_err(|_| ProbeError::Failed)?)?;
    let remote = proc_tuple(stream.local_addr().map_err(|_| ProbeError::Failed)?)?;
    let table = bounded_proc(&PathBuf::from(format!("/proc/{pid}/net/tcp")))?;
    let mut lines = table.lines();
    let header: Vec<_> = lines
        .next()
        .ok_or(ProbeError::Failed)?
        .split_ascii_whitespace()
        .collect();
    if !header.starts_with(&["sl", "local_address", "rem_address", "st"]) {
        return Err(ProbeError::Failed);
    }
    let mut inodes = HashSet::new();
    for line in lines {
        check_deadline(deadline)?;
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        if fields.len() < 10
            || !valid_proc_tuple(fields[1])
            || !valid_proc_tuple(fields[2])
            || fields[3].len() != 2
            || u8::from_str_radix(fields[3], 16).is_err()
            || fields[9].parse::<u64>().is_err()
        {
            return Err(ProbeError::Failed);
        }
        if fields[1] == local && fields[2] == remote && fields[3] == "01" {
            let inode = fields[9].parse::<u64>().map_err(|_| ProbeError::Failed)?;
            if inode == 0 {
                return Err(ProbeError::Failed);
            }
            inodes.insert(format!("socket:[{inode}]"));
        }
    }
    if inodes.is_empty() {
        alive(pid, ownership_lost)?;
        return Ok(false);
    }
    let entries = fs::read_dir(format!("/proc/{pid}/fd")).map_err(|_| ProbeError::Failed)?;
    let mut found = false;
    for (count, entry) in entries.enumerate() {
        check_deadline(deadline)?;
        if count >= 16384 {
            return Err(ProbeError::Failed);
        }
        let entry = entry.map_err(|_| ProbeError::Failed)?;
        let link = match fs::read_link(entry.path()) {
            Ok(link) => link,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(_) => return Err(ProbeError::Failed),
        };
        if link.to_str().is_some_and(|s| inodes.contains(s)) {
            found = true;
        }
    }
    alive(pid, ownership_lost)?;
    Ok(found)
}
struct DeadlineStream<'a> {
    stream: &'a mut TcpStream,
    deadline: Instant,
}
impl Read for DeadlineStream<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.stream
            .set_read_timeout(Some(remaining(self.deadline)?))?;
        self.stream.read(buffer)
    }
}
impl Write for DeadlineStream<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.stream
            .set_write_timeout(Some(remaining(self.deadline)?))?;
        self.stream.write(buffer)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream
            .set_write_timeout(Some(remaining(self.deadline)?))?;
        self.stream.flush()
    }
}
fn socks(stream: &mut DeadlineStream<'_>, username: &[u8], password: &[u8]) -> io::Result<()> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "probe transcript");
    stream.write_all(&[5, 1, 2])?;
    let mut selection = [0; 2];
    stream.read_exact(&mut selection)?;
    if selection != [5, 2] {
        return Err(invalid());
    }
    let mut auth = Zeroizing::new(Vec::new());
    auth.extend_from_slice(&[1, u8::try_from(username.len()).map_err(|_| invalid())?]);
    auth.extend_from_slice(username);
    auth.push(u8::try_from(password.len()).map_err(|_| invalid())?);
    auth.extend_from_slice(password);
    stream.write_all(&auth)?;
    stream.read_exact(&mut selection)?;
    if selection != [1, 0] {
        return Err(invalid());
    }
    let mut connect = vec![5, 1, 0, 3, u8::try_from(HOST.len()).map_err(|_| invalid())?];
    connect.extend_from_slice(HOST.as_bytes());
    connect.extend_from_slice(&443u16.to_be_bytes());
    stream.write_all(&connect)?;
    let mut reply = [0; 4];
    stream.read_exact(&mut reply)?;
    if reply[..3] != [5, 0, 0] {
        return Err(invalid());
    }
    let size = match reply[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut size = [0];
            stream.read_exact(&mut size)?;
            if size[0] == 0 {
                return Err(invalid());
            }
            usize::from(size[0])
        }
        _ => return Err(invalid()),
    };
    let mut address = vec![0; size + 2];
    stream.read_exact(&mut address)
}
fn https(
    config: &RunnerConfig,
    stream: &mut DeadlineStream<'_>,
    token: &str,
    deadline: Instant,
) -> Result<(), ProbeError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls_config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| ProbeError::Failed)?
        .with_root_certificates(config.tls_roots.clone())
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let name = rustls::pki_types::ServerName::try_from(HOST).map_err(|_| ProbeError::Failed)?;
    let mut connection =
        ClientConnection::new(Arc::new(tls_config), name).map_err(|_| ProbeError::Failed)?;
    let mut tls = rustls::Stream::new(&mut connection, stream);
    let request = Zeroizing::new(format!(
        "POST /api/v1/corp/egress-observation HTTP/1.1\r\nHost: {HOST}\r\nAuthorization: Bearer {token}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    ));
    tls.write_all(request.as_bytes())
        .map_err(|_| ProbeError::Failed)?;
    tls.flush().map_err(|_| ProbeError::Failed)?;
    let mut bytes = Zeroizing::new(Vec::new());
    loop {
        check_deadline(deadline)?;
        let mut buffer = [0; 1024];
        let read = tls.read(&mut buffer).map_err(|_| ProbeError::Failed)?;
        if read == 0 {
            return Err(ProbeError::Failed);
        }
        bytes.extend_from_slice(&buffer[..read]);
        if bytes.len() > 8192 {
            return Err(ProbeError::Failed);
        }
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut response = httparse::Response::new(&mut headers);
        match response.parse(&bytes).map_err(|_| ProbeError::Failed)? {
            httparse::Status::Partial => continue,
            httparse::Status::Complete(end) => {
                if end != bytes.len() || response.version != Some(1) || response.code != Some(204) {
                    return Err(ProbeError::Failed);
                }
                let mut echo = 0;
                let mut length = 0;
                for header in response.headers {
                    if header.name.eq_ignore_ascii_case("x-corp-probe") {
                        echo += 1;
                        if header.value != token.as_bytes() {
                            return Err(ProbeError::Failed);
                        }
                    }
                    if header.name.eq_ignore_ascii_case("transfer-encoding") {
                        return Err(ProbeError::Failed);
                    }
                    if header.name.eq_ignore_ascii_case("content-length") {
                        length += 1;
                        if header.value != b"0" {
                            return Err(ProbeError::Failed);
                        }
                    }
                }
                if echo != 1 || length > 1 {
                    return Err(ProbeError::Failed);
                }
                // rustls may already hold plaintext beyond this read's slice.
                check_deadline(deadline)?;
                match tls.conn.reader().read(&mut buffer) {
                    Ok(0) => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    _ => return Err(ProbeError::Failed),
                }
                return Ok(());
            }
        }
    }
}
