//! `vpnctl-core` — фундамент: типы, идентификаторы, ошибки и два главных трейта.
//!
//! Архитектурный принцип: разделяем «что бежит на сервере» (`Kernel`) и
//! «какой формат пакетов мы предъявляем клиенту» (`Protocol`).
//! Это позволяет добавлять новое ядро (например, wgturn) **не трогая**
//! existing inventory / cli / ssh / crypto-слои.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

//
// ── Identifiers ─────────────────────────────────────────────────────────
//

/// Стабильный строковый id (типа `"sing-box"`, `"wgturn"`).
/// Нельзя перепутать с другим `Id` благодаря newtype-обёртке.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KernelId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProtocolId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ServerId(pub String);

macro_rules! impl_display_for_id {
    ($($t:ty),+ $(,)?) => {
        $(impl fmt::Display for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        })+
    };
}
impl_display_for_id!(KernelId, ProtocolId, ServerId, UserId);

//
// ── Error type ──────────────────────────────────────────────────────────
//

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("kernel `{kernel}` does not support protocol `{protocol}`")]
    UnsupportedProtocol {
        kernel: KernelId,
        protocol: ProtocolId,
    },
    #[error("kernel `{0}` is already registered")]
    DuplicateKernel(KernelId),
    #[error("protocol `{0}` is already registered")]
    DuplicateProtocol(ProtocolId),
    #[error("missing required secret `{key}` for server `{server}`")]
    MissingSecret { server: ServerId, key: String },
    #[error("ssh transport error: {0}")]
    Transport(String),
    #[error("config render error: {0}")]
    Render(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, CoreError>;

//
// ── Domain entities ─────────────────────────────────────────────────────
//

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Server {
    pub id: ServerId,
    pub address: String,
    pub ssh_port: u16,
    pub ssh_user: String,
    pub kernel: KernelId,
    /// Какие протоколы мы хотим поднять на этом сервере.
    pub enabled_protocols: Vec<ProtocolId>,
    /// SHA256-fingerprint SSH host key, который мы доверяем.
    /// На первый коннект может быть `None` (TOFU — записывается после auth).
    #[serde(default)]
    pub trusted_host_fingerprint: Option<String>,
    /// Имя хостера (ключ в `vpnctl-hosters`): "digitalocean" / "cloudzy" / "generic".
    #[serde(default = "default_hoster")]
    pub hoster: String,
    /// SSH-jump host (ProxyJump). `None` — прямое подключение. ProxyJump
    /// в SSH-транспорте появится в v0.3, но поле резервируем заранее.
    #[serde(default)]
    pub jump_via: Option<ServerId>,
    /// Множитель учёта трафика (Marzban-style). Резерв для будущих лимитов.
    #[serde(default = "default_usage_coefficient")]
    pub usage_coefficient: f64,
}

fn default_hoster() -> String {
    "generic".to_string()
}
fn default_usage_coefficient() -> f64 {
    1.0
}

#[derive(Clone, Serialize, Deserialize)]
pub struct User {
    pub id: UserId,
    pub uuid: String,
    pub tuic_password: Option<String>,
    pub wireguard_pubkey: Option<String>,
    /// Opaque token for `vpnctld /sub/<token>` lookup. Populated by
    /// `inventory::add_user` if `None`. Field is `Option` so JSON snapshots
    /// from before v0.4 still deserialise.
    #[serde(default)]
    pub sub_token: Option<String>,
}

// Manual Debug: derived would print sub_token / tuic_password verbatim,
// which leaks credential-equivalents into logs / panics / anyhow chains.
impl fmt::Debug for User {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("User")
            .field("id", &self.id)
            .field("uuid", &self.uuid)
            .field(
                "tuic_password",
                &self.tuic_password.as_ref().map(|_| "<redacted>"),
            )
            .field("wireguard_pubkey", &self.wireguard_pubkey)
            .field("sub_token", &self.sub_token.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Минимальный SSH-контракт: что-нибудь, что умеет дёрнуть команду.
/// Реальная impl — в `vpnctl-ssh` поверх `russh`. В тестах — мок.
#[async_trait]
pub trait SshTransport: fmt::Debug + Send + Sync {
    async fn exec(&self, cmd: &str) -> Result<String>;
    async fn upload(&self, path: &str, content: &[u8]) -> Result<()>;
    async fn read_file(&self, path: &str) -> Result<Vec<u8>>;
}

/// Контекст рендеринга — то, что `Kernel`/`Protocol` нужно для генерации
/// конфига. **Все секреты per-server приходят из `secrets`** (загружается
/// из БД через `inventory::sqlite::SqliteInventory::list_server_secrets`).
/// Это ключевой архитектурный приём: реализации `Protocol` остаются
/// **stateless** — они не хранят REALITY-ключи, TUIC-сертификаты и т.п.,
/// а читают их из контекста по конвенциональным именам.
///
/// Конвенция ключей:
///
/// - `vless.private_key`, `vless.public_key`, `vless.short_id`, `vless.sni`
/// - `tuic.cert_path`, `tuic.key_path`
/// - (новые протоколы добавляют свой namespace)
#[derive(Debug)]
pub struct RenderCtx<'a> {
    pub server: &'a Server,
    pub secrets: &'a HashMap<String, String>,
}

impl<'a> RenderCtx<'a> {
    pub fn new(server: &'a Server, secrets: &'a HashMap<String, String>) -> Self {
        Self { server, secrets }
    }

    /// Достать секрет или вернуть `MissingSecret` ошибку.
    pub fn require(&self, key: &str) -> Result<&str> {
        self.secrets
            .get(key)
            .map(String::as_str)
            .ok_or_else(|| CoreError::MissingSecret {
                server: self.server.id.clone(),
                key: key.to_string(),
            })
    }

    /// Достать секрет или дефолт.
    pub fn or_default<'b>(&'b self, key: &str, default: &'b str) -> &'b str {
        self.secrets.get(key).map(String::as_str).unwrap_or(default)
    }
}

//
// ── Kernel: что крутится на сервере ─────────────────────────────────────
//

#[async_trait]
pub trait Kernel: fmt::Debug + Send + Sync {
    fn id(&self) -> KernelId;

    /// Список протоколов, которые это ядро вообще способно поднять.
    fn supported_protocols(&self) -> Vec<ProtocolId>;

    /// Проверка готовности (есть ли пакет в репо, есть ли systemd-юнит).
    async fn ensure_installed(&self, ssh: &dyn SshTransport) -> Result<()>;

    /// Сгенерировать серверный конфиг. `ctx` несёт сервер и его секреты,
    /// `users` — все пользователи с грантом на этот сервер, `protocols` —
    /// набор включённых протоколов (в порядке, в котором они должны
    /// появиться в inbound'ах).
    fn render_config(
        &self,
        ctx: &RenderCtx<'_>,
        users: &[User],
        protocols: &[&dyn Protocol],
    ) -> Result<Vec<u8>>;

    /// Залить новый конфиг + перезагрузить.
    async fn apply_config(&self, ssh: &dyn SshTransport, config: &[u8]) -> Result<()>;

    async fn restart(&self, ssh: &dyn SshTransport) -> Result<()>;
    async fn status(&self, ssh: &dyn SshTransport) -> Result<KernelStatus>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelStatus {
    pub active: bool,
    pub version: Option<String>,
    pub uptime_seconds: Option<u64>,
}

//
// ── Protocol: что предъявляем клиенту ───────────────────────────────────
//

/// Протоколы — **stateless**. Ключи и прочие секреты приходят через
/// `RenderCtx::secrets`. Это позволяет инстанциировать `Protocol` один раз в
/// `Registry` (без знания ключей), а ключи на каждый деплой брать из
/// inventory.
pub trait Protocol: fmt::Debug + Send + Sync {
    fn id(&self) -> ProtocolId;

    /// Кусочек серверного inbound — например `{ "type": "vless", ... }`
    /// для sing-box. Ядро потом склеит inbound'ы вместе.
    fn server_inbound(&self, ctx: &RenderCtx<'_>, users: &[User]) -> Result<serde_json::Value>;

    /// Полный клиентский конфиг (sing-box / wireguard / etc).
    fn client_config(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<serde_json::Value>;

    /// Share-link (`vless://...`, `tuic://...`, `wg://...`, и т.д.).
    fn share_link(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<String>;
}

//
// ── Registry: модули регистрируют себя здесь ────────────────────────────
//
// Чтобы добавить wgturn, не трогая CLI и inventory, делаем централизованный
// реестр. CLI ходит сюда: «дай мне Kernel по id».
//

#[derive(Debug, Default)]
pub struct Registry {
    kernels: Vec<Box<dyn Kernel>>,
    protocols: Vec<Box<dyn Protocol>>,
}

impl Registry {
    pub fn new() -> Self {
        Self {
            kernels: Vec::new(),
            protocols: Vec::new(),
        }
    }

    /// Зарегистрировать ядро. Возвращает ошибку, если ядро с таким `id` уже
    /// зарегистрировано (предотвращает silent inconsistency).
    pub fn register_kernel(&mut self, k: Box<dyn Kernel>) -> Result<()> {
        let id = k.id();
        if self.kernels.iter().any(|existing| existing.id() == id) {
            return Err(CoreError::DuplicateKernel(id));
        }
        self.kernels.push(k);
        Ok(())
    }

    /// Зарегистрировать протокол. Возвращает ошибку при дубликате.
    pub fn register_protocol(&mut self, p: Box<dyn Protocol>) -> Result<()> {
        let id = p.id();
        if self.protocols.iter().any(|existing| existing.id() == id) {
            return Err(CoreError::DuplicateProtocol(id));
        }
        self.protocols.push(p);
        Ok(())
    }

    pub fn kernel(&self, id: &KernelId) -> Option<&dyn Kernel> {
        self.kernels
            .iter()
            .find(|k| &k.id() == id)
            .map(|k| k.as_ref())
    }

    pub fn protocol(&self, id: &ProtocolId) -> Option<&dyn Protocol> {
        self.protocols
            .iter()
            .find(|p| &p.id() == id)
            .map(|p| p.as_ref())
    }

    pub fn validate_server(&self, server: &Server) -> Result<()> {
        let kernel = self
            .kernel(&server.kernel)
            .ok_or_else(|| CoreError::Render(format!("unknown kernel {}", server.kernel)))?;
        let supported = kernel.supported_protocols();
        for proto in &server.enabled_protocols {
            if !supported.contains(proto) {
                return Err(CoreError::UnsupportedProtocol {
                    kernel: server.kernel.clone(),
                    protocol: proto.clone(),
                });
            }
        }
        Ok(())
    }
}
