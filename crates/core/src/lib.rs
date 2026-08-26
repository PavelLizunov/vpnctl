//! `vpnctl-core` — фундамент: типы, идентификаторы, ошибки и два главных трейта.
//!
//! Архитектурный принцип: разделяем «что бежит на сервере» (`Kernel`) и
//! «какой формат пакетов мы предъявляем клиенту» (`Protocol`).
//! Это позволяет добавлять новое ядро (например, caddy) **не трогая**
//! existing inventory / cli / ssh / crypto-слои.

pub mod humanize;
pub mod shell;
pub mod url_host;
pub mod version;

pub use version::build_version;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

//
// ── Identifiers ─────────────────────────────────────────────────────────
//

/// Стабильный строковый id (типа `"sing-box"`, `"caddy"`).
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
    /// Какие ядра крутятся на этом сервере. Чаще всего один (исторически
    /// поле было `kernel: KernelId`), но один физический VPS может
    /// одновременно держать несколько демонов на разных портах
    /// (sing-box на 443/TCP + amneziawg на 51820/UDP). Каждое ядро
    /// independent: own systemd unit, own config file, own `ensure_installed`
    /// / `apply_config` cycle. Deploy итерирует `kernels` и запускает
    /// каждое с теми `enabled_protocols` которые это ядро supports.
    /// Renamed 2026-05-16 from singular `kernel`.
    pub kernels: Vec<KernelId>,
    /// Какие протоколы мы хотим поднять на этом сервере.
    pub enabled_protocols: Vec<ProtocolId>,
    /// SHA256-fingerprint SSH host key, который мы доверяем.
    /// На первый коннект может быть `None` (TOFU — записывается после auth).
    #[serde(default)]
    pub trusted_host_fingerprint: Option<String>,
    /// Имя хостера (Hoster key): "digitalocean" / "cloudzy" / "generic".
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
    /// SECRET. `Serialize` is `skip` so any `serde_json::to_string(&user)`
    /// path (CLI `--output json`, future REST API, audit log payload)
    /// CANNOT leak this value. The DB layer reads/writes the column
    /// directly, NOT through the derived `Serialize`. (Review-agent
    /// finding on the wg-keygen commit: previously the derive was
    /// the leak surface for `wireguard_private` — closing both at
    /// once for consistency.)
    #[serde(skip_serializing, default)]
    pub tuic_password: Option<String>,
    pub wireguard_pubkey: Option<String>,
    /// Server-generated Curve25519 private key for WireGuard /
    /// AmneziaWG, standard-base64 encoded (44 chars ending `=`).
    /// Set ONLY when the user was created via
    /// `vpnctl user add --gen-wireguard` (or the web equivalent);
    /// stays `None` for the operator-provided `--wireguard-pubkey`
    /// path. Renders into `[Interface] PrivateKey = …` in client
    /// `.conf` so the low-tech user can import a single artefact
    /// (per CLAUDE.md "users are assumed maximally low-tech").
    ///
    /// SECRET — `Serialize` is `skip` for the same reason as
    /// `tuic_password`. Live transport is `/sub/<token>` only.
    #[serde(skip_serializing, default)]
    pub wireguard_private: Option<String>,
    /// Opaque token for `vpnctld /sub/<token>` lookup. Populated by
    /// `inventory::add_user` if `None`. Field is `Option` so JSON snapshots
    /// from before v0.4 still deserialise. SECRET — `Serialize` is
    /// `skip` (token = bearer credential equivalent).
    #[serde(skip_serializing, default)]
    pub sub_token: Option<String>,
    /// 32-lowercase-hex device identifier used by the ninitux-compat
    /// endpoint `GET /api/v1/app/config/{device_id}` (Phase 3 merge,
    /// migration `0017_users_vpn_router_device_id.sql`). Pinned per
    /// user via `SqliteInventory::set_vpn_router_device_id`. When
    /// `Some(...)`, the operator can hand the user the production
    /// URL `https://ninitux.com/api/v1/app/config/<device_id>`
    /// directly — no token rotation needed. When `None`, the user
    /// has no ninitux-style endpoint (legacy `/sub/<token>` path
    /// still works regardless).
    ///
    /// **BEARER CREDENTIAL — `Serialize` is `skip`.** Anyone who
    /// knows the device_id can fetch the user's full VPN config
    /// (VLESS URIs with UUIDs, TUIC passwords) via the public
    /// `/api/v1/app/config/<device_id>` endpoint. Treat with the
    /// same care as `sub_token`. The pre-Phase-3 doc-comment
    /// called this a "device fingerprint, not a credential" —
    /// review-agent 2026-05-19 correctly pointed out that's
    /// wrong: knowing it == being able to fetch credentials.
    /// Live transport is the admin UI (operator-facing only,
    /// behind basic-auth) + the `/api/v1/app/config/` endpoint
    /// (the bearer-credential surface) and the audit_log (admin-
    /// gated). NEVER appears in `serde_json::to_string(&user)`
    /// output (CLI `--output json`, future REST API, audit
    /// payloads) — pinned by `user_debug_redacts_all_secret_fields`.
    #[serde(skip_serializing, default)]
    pub vpn_router_device_id: Option<String>,
    /// Soft-suspend flag (audit B1.user, migration 0026). When
    /// `true`, the subscription pipeline (`/sub/<token>` and
    /// `/api/v1/app/config/<device_id>`) renders an EMPTY config
    /// for this user — no protocols visible, no URIs emitted —
    /// while every secret (UUID, sub_token, WG keypair, TUIC pw)
    /// and every grant stays intact. Flipping back to `false`
    /// restores access byte-for-byte; flipping to `true` again
    /// is a one-click pause.
    ///
    /// **Default false** on every existing row (migration default).
    /// Serializable (no security reason to hide it — the operator
    /// who can see the user already knows). Web UI surfaces it as
    /// the «disable / enable user» button on the user-detail page.
    #[serde(default)]
    pub disabled: bool,
}

impl User {
    /// Return a clone of `self` with `uuid` replaced by `new_uuid`. Used
    /// at every share-link / sing-box rendering call-site to apply the
    /// per-(user, server) UUID override stored in `grants.client_uuid`
    /// (Phase 1 of the ninitux merge — see migration
    /// `0016_grants_per_server_uuid.sql` in `vpnctl-inventory`).
    ///
    /// The user's GLOBAL identity (`User::id`, sub_token lookups, audit
    /// targets) stays pinned to the original `User`; this helper only
    /// produces a per-server VIEW for protocol rendering. When
    /// `new_uuid` equals the existing `uuid` the original is cloned
    /// unchanged — safe to call unconditionally; callers don't need to
    /// short-circuit identity overrides.
    #[must_use]
    pub fn with_per_server_uuid(&self, new_uuid: &str) -> Self {
        let mut out = self.clone();
        out.uuid = new_uuid.to_string();
        out
    }
}

// Manual Debug: derived would print sub_token / tuic_password /
// wireguard_private verbatim, which leaks credential-equivalents
// into logs / panics / anyhow chains. Companion to `#[serde(skip_serializing)]`
// on those three fields — both Debug and Serialize paths are now
// covered. Pinned by `user_debug_redacts_all_secret_fields` test.
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
            .field(
                "wireguard_private",
                &self.wireguard_private.as_ref().map(|_| "<redacted>"),
            )
            .field("sub_token", &self.sub_token.as_ref().map(|_| "<redacted>"))
            .field(
                "vpn_router_device_id",
                &self.vpn_router_device_id.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod user_secret_redaction {
    use super::*;

    fn loaded_user() -> User {
        User {
            id: UserId("alice".into()),
            uuid: "uuid-public-not-secret".into(),
            tuic_password: Some("PW_TUIC_MUST_NOT_LEAK".into()),
            wireguard_pubkey: Some("PUBKEY_OK_TO_PRINT_44CHARS_ENDING_EQ_VALUEAA=".into()),
            wireguard_private: Some("PRIV_WG_MUST_NOT_LEAK".into()),
            sub_token: Some("SUB_TOKEN_MUST_NOT_LEAK".into()),
            // 32-hex bearer credential — knowing this string lets a
            // probe fetch the user's full VPN config via
            // /api/v1/app/config/<id>. Treated like sub_token: must
            // not leak via Debug, JSON serialisation, or any
            // logging path. Distinctive byte sequence so any future
            // refactor that bypasses the redaction surfaces here.
            vpn_router_device_id: Some("DEVICE_ID_MUST_NOT_LEAK_a92b915".into()),
            disabled: false,
        }
    }

    #[test]
    fn user_debug_redacts_all_secret_fields() {
        let dbg = format!("{:?}", loaded_user());
        for forbidden in [
            "PW_TUIC_MUST_NOT_LEAK",
            "PRIV_WG_MUST_NOT_LEAK",
            "SUB_TOKEN_MUST_NOT_LEAK",
            "DEVICE_ID_MUST_NOT_LEAK",
        ] {
            assert!(!dbg.contains(forbidden), "Debug leaked {forbidden}: {dbg}");
        }
        assert!(
            dbg.contains("<redacted>"),
            "expected redaction marker: {dbg}"
        );
        // Non-secret fields should still be visible.
        assert!(dbg.contains("alice"));
        assert!(dbg.contains("PUBKEY_OK_TO_PRINT"));
    }

    #[test]
    fn user_serialize_skips_all_secret_fields() {
        let json = serde_json::to_string(&loaded_user()).unwrap();
        for forbidden in [
            "PW_TUIC_MUST_NOT_LEAK",
            "PRIV_WG_MUST_NOT_LEAK",
            "SUB_TOKEN_MUST_NOT_LEAK",
            "DEVICE_ID_MUST_NOT_LEAK",
            "tuic_password",
            "wireguard_private",
            "sub_token",
            "vpn_router_device_id",
        ] {
            assert!(
                !json.contains(forbidden),
                "Serialize leaked {forbidden}: {json}"
            );
        }
        // Non-secret fields should round-trip.
        assert!(json.contains("alice"));
        assert!(json.contains("PUBKEY_OK_TO_PRINT"));
    }
}

/// Минимальный SSH-контракт: что-нибудь, что умеет дёрнуть команду.
/// Реальная impl — в `vpnctl-ssh` поверх `russh`. В тестах — мок.
#[async_trait]
pub trait SshTransport: fmt::Debug + Send + Sync {
    /// Execute a managed-node command with the transport's privileged semantics.
    async fn exec(&self, cmd: &str) -> Result<String>;
    /// Execute as the SSH login user. Home/key bootstrap operations use this
    /// path so a non-root login does not accidentally target `/root`.
    async fn exec_unprivileged(&self, cmd: &str) -> Result<String>;
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
    /// Все юзеры с грантом на этот сервер, в стабильном `ORDER BY id`
    /// порядке (то же, что `users_for_server` отдаёт inventory).
    /// Нужно для протоколов, у которых per-user state зависит от
    /// порядкового номера юзера на сервере — конкретно WireGuard
    /// раздаёт `10.66.0.<2+index>/32`, иначе все клиенты
    /// сталкиваются на 10.66.0.2 и второй пакет уходит в чёрную дыру
    /// (review-agent 2026-05-17).
    ///
    /// Пустой slice — допустим: вызывает legacy fallback (octet=2 для
    /// первого пользователя). Использовать `with_peers(..)` в любом
    /// контексте, где нужны корректные адреса.
    pub peers: &'a [User],
}

impl<'a> RenderCtx<'a> {
    /// Build a `RenderCtx` without the peer list — share_link will
    /// fall back to legacy single-user addressing (10.66.0.2). Safe
    /// only if you know the server has at most one WG user; new code
    /// should prefer `with_peers`.
    pub fn new(server: &'a Server, secrets: &'a HashMap<String, String>) -> Self {
        Self {
            server,
            secrets,
            peers: &[],
        }
    }

    /// Build a `RenderCtx` carrying the full granted-users list for
    /// the server. WireGuard's `share_link` reads `peers` to find the
    /// target user's index and emit the right `/32` per-user CIDR.
    pub fn with_peers(
        server: &'a Server,
        secrets: &'a HashMap<String, String>,
        peers: &'a [User],
    ) -> Self {
        Self {
            server,
            secrets,
            peers,
        }
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

    /// Version target managed by [`Kernel::ensure_installed`]. `None`
    /// means the kernel has no machine-comparable managed version.
    fn version_requirement(&self) -> Option<KernelVersionRequirement> {
        None
    }

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

    /// Открыть хост-фаервол под порты, которые биндят включённые
    /// `protocols` — источник правды `Protocol::effective_listen_ports()`
    /// (тот же набор, что у cross-protocol port-conflict guard'а), т.е.
    /// с учётом пер-серверных оверрайдов портов из `ctx.secrets`. Чтобы
    /// свежий `deploy` был доступен СРАЗУ, без ручного `ufw allow`
    /// (иначе смысл автоматизации теряется).
    ///
    /// DEFAULT — no-op: ядра без управляемого хост-фаервола, или
    /// управляющие им инлайн (amneziawg через wg-quick PostUp
    /// iptables), наследуют пустую реализацию.
    ///
    /// Контракт — **best-effort**: невозможность открыть фаервол (нет
    /// `ufw`; cloud-firewall хост вроде DigitalOcean, где ingress правит
    /// апстрим-firewall, а не локальный ufw) НЕ должна валить deploy —
    /// конфиг к этому моменту уже применён. Вызывающий логирует ошибку и
    /// продолжает.
    async fn open_firewall(
        &self,
        _ssh: &dyn SshTransport,
        _ctx: &RenderCtx<'_>,
        _protocols: &[&dyn Protocol],
    ) -> Result<()> {
        Ok(())
    }

    async fn restart(&self, ssh: &dyn SshTransport) -> Result<()>;
    async fn status(&self, ssh: &dyn SshTransport) -> Result<KernelStatus>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelStatus {
    pub active: bool,
    pub version: Option<String>,
    pub uptime_seconds: Option<u64>,
}

/// How [`Kernel::ensure_installed`] interprets its managed version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelVersionPolicy {
    /// Installed versions at or above the value are accepted.
    Floor,
    /// The installed build must match the value exactly.
    Pin,
}

/// Registry-owned version metadata rendered by the admin UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelVersionRequirement {
    pub policy: KernelVersionPolicy,
    pub value: &'static str,
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

    /// What `(proto, port)` tuples this protocol's `server_inbound`
    /// is expected to listen on. Default empty so existing protocols
    /// without listening-side semantics (or where the port is
    /// runtime-configurable via secrets) don't have to opt in.
    ///
    /// **Used by:** `daemon::handlers::admin::server_detail` drift
    /// detection — compares this declaration against the live
    /// `node_probe` output and highlights mismatch.
    ///
    /// Implementations return `&'static [(&'static str, u16)]`
    /// (compile-time constants); no runtime cost. Adding a new
    /// protocol that wants drift coverage is one method override
    /// here — no daemon edits needed. (Caught by review-agent
    /// against the prior burst: hardcoding the map in admin.rs
    /// violated the kernel/protocol orthogonality invariant.)
    fn listen_ports(&self) -> &'static [(&'static str, u16)] {
        &[]
    }

    /// Effective `(proto, port)` tuples this protocol's inbound will bind
    /// on a SPECIFIC server, taking that server's secrets into account.
    /// Defaults to the static [`listen_ports`](Self::listen_ports);
    /// protocols whose port is runtime-configurable via a per-server secret
    /// (today: VLESS+REALITY's `vless.listen_port` co-tenant override)
    /// override this so the firewall step, the cross-protocol port-conflict
    /// guard and the admin drift table all see the REAL port instead of the
    /// compile-time default. Consumers that have server context MUST call
    /// this rather than `listen_ports`.
    fn effective_listen_ports(
        &self,
        _secrets: &HashMap<String, String>,
    ) -> Vec<(&'static str, u16)> {
        self.listen_ports().to_vec()
    }

    /// Does this protocol's `client_config` produce a sing-box-
    /// compatible outbound JSON object? Default `true` — almost every
    /// protocol in this crate today does (VLESS / TUIC / Hysteria2 /
    /// Trojan / AnyTLS / Shadowsocks-2022 / WireGuard). The `/sub/<token>`
    /// endpoint assembles a sing-box `outbounds` array and serves it
    /// to Hiddify / sing-box clients; **any outbound with an
    /// unrecognised `type` makes the entire config invalid** and the
    /// client either refuses to start OR silently drops the route.
    ///
    /// Protocols that ARE NOT sing-box-native (e.g. wireguard —
    /// delivered via dedicated client configs / share links
    /// rather than the sing-box sub) MUST override this to
    /// `false`. The sub handler then skips them when assembling the
    /// sing-box config, but they still appear in the per-protocol
    /// share-links section of the admin UI.
    fn appears_in_sing_box_sub(&self) -> bool {
        true
    }

    /// How well this protocol resists DPI / active-probing in
    /// censorship environments (RU/IR/CN ASNs in 2026). Used by the
    /// admin UI to render a coloured risk chip next to each enabled
    /// protocol, downscale the font of `Weak` rows, and surface an
    /// explainer tooltip — operator decides whether to keep the
    /// protocol on, `hide` it (NM-10), or hard-disable it.
    ///
    /// Default is `Moderate` — every protocol's `server_inbound` is
    /// some flavour of obfuscated TLS / QUIC, so a moderate default
    /// reflects "not trivially fingerprintable, but not certified
    /// best-of-breed either". Implementations that have a clearer
    /// position (REALITY's `dest:` active-probe forwarding; raw
    /// WireGuard's fixed 4-byte handshake type tag; Shadowsocks-2022's
    /// high-entropy first byte) override.
    ///
    /// NM-12 (Pavel 2026-05-20): «давай начнём с того что ты уберёшь
    /// чтото плохие протоколы и пометишь их в ui как плохие и можешь
    /// даже шрифт меньше сделать у них». This is the trait-level
    /// substrate for that UI work — the admin templates read
    /// `Registry::protocol(pid).map(|p| p.dpi_risk())` and render
    /// accordingly. Adding a new protocol that wants risk coverage is
    /// one method override here; no admin / inventory edits needed.
    fn dpi_risk(&self) -> DpiRisk {
        DpiRisk::Moderate
    }

    /// Server-side secrets this protocol needs minted before
    /// `server_inbound` can render. Default empty — protocols whose
    /// secrets are per-user (Trojan / AnyTLS user passwords) or
    /// generated node-side at deploy time (TUIC / Hysteria2 self-signed
    /// cert) need no pre-mint.
    ///
    /// **Used by:** `daemon::wizard_bootstrap::bootstrap_server_secrets`,
    /// which iterates a server's enabled protocols, collects these
    /// specs, and generates + persists any declared key that's absent —
    /// idempotently (a present key is never regenerated, so existing
    /// clients keep working). Adding a secret-bearing protocol is one
    /// override here; no daemon edits.
    ///
    /// Closes the orthogonality TODO that let `shadowsocks-2022` ship
    /// without its `ss2022.psk` ever getting minted by the wizard — the
    /// `kg` deploy 2026-05-30 failed at render with
    /// `MissingSecret { key: "ss2022.psk" }` because the minter
    /// hardcoded only vless / wireguard / hysteria2.
    fn server_secret_specs(&self) -> Vec<ServerSecretSpec> {
        Vec::new()
    }
}

/// A server-side secret a [`Protocol`] declares it needs minted before
/// its inbound can render. The bootstrap secret-minter
/// (`daemon::wizard_bootstrap::bootstrap_server_secrets`) generates +
/// persists any declared key that's absent.
///
/// Declarative (the protocol says WHAT, the minter does HOW) on
/// purpose: the crypto primitives stay centralised in the daemon
/// (which already depends on `vpnctl-crypto`), so the `protocols`
/// crate needs no crypto dependency and the byte-shape of every
/// generated secret has one source of truth. Adding a protocol that
/// needs an EXISTING kind is a one-line spec in its own file with zero
/// daemon edits (the orthogonality invariant); a genuinely new KIND
/// (rare) adds one match arm in the minter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerSecretSpec {
    /// One random URL-safe-base64 password carrying `entropy_bytes` of
    /// entropy (minted via `vpnctl_crypto::gen_password`). For secrets
    /// consumed as an OPAQUE STRING (e.g. Hysteria2 Salamander obfs
    /// password) — NOT base64-decoded by the node daemon.
    Password {
        key: &'static str,
        entropy_bytes: usize,
    },
    /// Random raw key of `key_bytes`, encoded as STANDARD (padded)
    /// base64 (minted via `vpnctl_crypto::gen_base64_key`). For secrets
    /// the node daemon base64-DECODES back to raw key material — e.g. a
    /// Shadowsocks-2022 PSK (sing-box uses Go `base64.StdEncoding`, so a
    /// url-safe / unpadded string would fail to decode and reject the
    /// whole node config). Distinct from `Password` precisely because
    /// the encoding contract differs.
    Base64Key { key: &'static str, key_bytes: usize },
    /// x25519 keypair (REALITY) persisted as two keys
    /// (`vpnctl_crypto::gen_x25519_keypair`).
    X25519Keypair {
        private_key: &'static str,
        public_key: &'static str,
    },
    /// WireGuard (Curve25519) server keypair persisted as two keys
    /// (`vpnctl_crypto::gen_wireguard_keypair`).
    WireguardKeypair {
        private_key: &'static str,
        public_key: &'static str,
    },
    /// REALITY `short_id` — random 8-byte hex
    /// (`vpnctl_crypto::gen_short_id`).
    ShortId { key: &'static str },
}

/// DPI / active-probing resilience tier. Stored only in the registry
/// (compile-time const per protocol impl); never persisted.
///
/// - `Strong` — well-camouflaged: REALITY (TLS handshake to a real
///   upstream, active-probe defence via `dest:` forwarding), Naive
///   (Caddy with probe-resistant forwardproxy).
/// - `Moderate` — recognisable on careful active probing but not
///   trivially fingerprintable: TUIC v5, Hysteria2, AnyTLS, Trojan.
/// - `Weak` — known DPI-fingerprintable in 2026 RU/IR/CN:
///   Shadowsocks-2022 (high-entropy random from byte 0), raw
///   WireGuard (fixed `0x01 0x00 0x00 0x00` handshake initiation tag
///   trivially matched by TSPU / GFW).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DpiRisk {
    Strong,
    Moderate,
    Weak,
}

impl DpiRisk {
    /// Short label for the admin UI chip (≤10 chars to fit the
    /// existing row layout).
    pub fn label(self) -> &'static str {
        match self {
            DpiRisk::Strong => "DPI: strong",
            DpiRisk::Moderate => "DPI: moderate",
            DpiRisk::Weak => "DPI: weak",
        }
    }

    /// One-sentence explainer for the UI tooltip — surfaces the
    /// specific fingerprint or defence so the operator knows why
    /// the protocol earned its tier.
    pub fn tooltip(self) -> &'static str {
        match self {
            DpiRisk::Strong => {
                "Active-probe-resistant: TLS handshake to a real upstream / no fixed wire signature. Recommended."
            }
            DpiRisk::Moderate => {
                "Recognisable on careful active probing (QUIC version, AEAD-on-port-N) but not trivially blocked. Useful as a fallback."
            }
            DpiRisk::Weak => {
                "Trivially fingerprintable in RU/IR/CN 2026 (Shadowsocks high-entropy first byte, raw WireGuard 0x01 handshake tag, Trojan-without-fallback self-signed cert, Hysteria2 on legacy servers that lack the Salamander obfs secret — re-deploy mints it). Consider hiding via NM-10."
            }
        }
    }

    /// CSS variable name for the chip's border + text colour. Single
    /// source of truth — the admin UI's chip rendering calls these
    /// instead of repeating the `match` arms inline. Adding a future
    /// tier (e.g. `Critical`) is a one-spot edit. Review-agent NM-12
    /// flagged the original 4× duplication.
    ///
    /// The `var(--name, #hex)` fallback is the literal colour because
    /// `admin.css` doesn't (yet) define `--acc-good` / `--acc-bad` in
    /// `:root` — a theme that wants to override the palette can add
    /// them and these chips re-tint automatically.
    pub fn border_css(self) -> &'static str {
        match self {
            DpiRisk::Strong => "var(--acc-good, #2c5f2d)",
            DpiRisk::Moderate => "var(--rule)",
            DpiRisk::Weak => "var(--acc-bad, #97233f)",
        }
    }

    /// Text colour for the chip. Strong + Weak use the same value as
    /// their border (high-contrast "ok"/"bad" badge); Moderate uses
    /// `--mute` so the chip recedes into the dotted rule.
    pub fn text_css(self) -> &'static str {
        match self {
            DpiRisk::Strong => "var(--acc-good, #2c5f2d)",
            DpiRisk::Moderate => "var(--mute)",
            DpiRisk::Weak => "var(--acc-bad, #97233f)",
        }
    }
}

//
// ── Registry: модули регистрируют себя здесь ────────────────────────────
//
// Чтобы добавлять ядра и протоколы, не трогая CLI и inventory, делаем централизованный
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

    /// Every registered protocol id, in registration order. Used by
    /// the admin UI to render the full set of available protocols
    /// (e.g. checkbox list on the server-detail page) so the operator
    /// doesn't have to remember which protocol strings the registry
    /// accepts. Cheap clone — only ~7 short strings.
    pub fn protocol_ids(&self) -> Vec<ProtocolId> {
        self.protocols.iter().map(|p| p.id()).collect()
    }

    /// Every registered kernel id (analogous to `protocol_ids`).
    pub fn kernel_ids(&self) -> Vec<KernelId> {
        self.kernels.iter().map(|k| k.id()).collect()
    }

    /// Map kernel-id → protocols that kernel can run. Used by UI
    /// to grey-out incompatible protocols before submission
    /// (e.g. `wireguard` only under `amneziawg`, not under
    /// `sing-box`). One row per kernel, in registration order.
    pub fn kernel_protocol_matrix(&self) -> Vec<(KernelId, Vec<ProtocolId>)> {
        self.kernels
            .iter()
            .map(|k| (k.id(), k.supported_protocols()))
            .collect()
    }

    /// Kernel/protocol SUPPORT validation only (no port-conflict gate).
    /// For server-CREATE paths (`bootstrap`, `server add`) where no
    /// secrets exist yet: the port-conflict guard is secret-aware
    /// (`vless.listen_port` etc.), and the operator can't set the secret
    /// until the server row exists — validating ports here would reject
    /// exactly the naive+reality topology this guard exists to enable.
    /// The deploy path runs the full [`validate_server`] with real
    /// secrets; that is the authoritative gate.
    pub fn validate_server_support(&self, server: &Server) -> Result<()> {
        if server.kernels.is_empty() {
            return Err(CoreError::Render(format!(
                "server '{}' has no kernels assigned — assign at least one (sing-box, amneziawg, …)",
                server.id
            )));
        }
        // Resolve every declared kernel id. Unknown kernel = config error.
        let mut resolved = Vec::with_capacity(server.kernels.len());
        for kid in &server.kernels {
            let k = self
                .kernel(kid)
                .ok_or_else(|| CoreError::Render(format!("unknown kernel {kid}")))?;
            resolved.push((kid.clone(), k.supported_protocols()));
        }
        // Each declared protocol must be supported by AT LEAST ONE of the
        // server's kernels. Weaker than single-kernel "kernel must support
        // every protocol" — that one becomes physically impossible for
        // mixed deployments (sing-box does VLESS, amneziawg does WG;
        // neither supports the other). The new rule: every protocol has
        // SOMEONE to render it.
        for proto in &server.enabled_protocols {
            if !resolved.iter().any(|(_, sup)| sup.contains(proto)) {
                return Err(CoreError::UnsupportedProtocol {
                    // Attribute the error to the first kernel as the
                    // canonical "I'm the one who can't run this"
                    // displayed in the message. For exhaustive
                    // diagnostics the caller can re-walk `server.kernels`.
                    kernel: server.kernels[0].clone(),
                    protocol: proto.clone(),
                });
            }
        }
        Ok(())
    }

    pub fn validate_server(
        &self,
        server: &Server,
        secrets: &HashMap<String, String>,
    ) -> Result<()> {
        self.validate_server_support(server)?;

        // Cross-protocol port-conflict guard: two enabled protocols that
        // bind the same (transport, port) on one host collide at runtime
        // — e.g. naive's Caddy on tcp/443 vs VLESS+REALITY's sing-box on
        // tcp/443. Catch it here, before any SSH session, instead of
        // discovering it as a crash-looping second daemon.
        //
        // `effective_listen_ports(secrets)` (not the static `listen_ports`)
        // so a per-server override moves the protocol's declared port in
        // lockstep — `vless.listen_port=8443` frees tcp/443 for naive on
        // the same node, and a second protocol squatting 8443 (including
        // vless-ws's front port) is caught here (cdn incident 2026-08-05).
        let mut bound: HashMap<(&str, u16), &ProtocolId> = HashMap::new();
        for pid in &server.enabled_protocols {
            let Some(proto) = self.protocol(pid) else {
                continue;
            };
            for (transport, port) in proto.effective_listen_ports(secrets) {
                if let Some(prev) = bound.insert((transport, port), pid) {
                    return Err(CoreError::Render(format!(
                        "port conflict on {transport}/{port}: protocols '{prev}' and \
                         '{pid}' both bind it on server '{}'. Move one of them to a \
                         different port via its per-server `*.listen_port` secret \
                         (vless.listen_port, vlessws.listen_port, wireguard.listen_port) \
                         or to a dedicated node.",
                        server.id
                    )));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod validate_server_port_conflict {
    use super::*;
    use async_trait::async_trait;

    #[derive(Debug)]
    struct FakeProto {
        id: &'static str,
        ports: &'static [(&'static str, u16)],
    }
    impl Protocol for FakeProto {
        fn id(&self) -> ProtocolId {
            ProtocolId(self.id.to_string())
        }
        fn server_inbound(&self, _: &RenderCtx<'_>, _: &[User]) -> Result<serde_json::Value> {
            Ok(serde_json::Value::Null)
        }
        fn client_config(&self, _: &RenderCtx<'_>, _: &User) -> Result<serde_json::Value> {
            Ok(serde_json::Value::Null)
        }
        fn share_link(&self, _: &RenderCtx<'_>, _: &User) -> Result<String> {
            Ok(String::new())
        }
        fn listen_ports(&self) -> &'static [(&'static str, u16)] {
            self.ports
        }
    }

    #[derive(Debug)]
    struct FakeKernel {
        supports: Vec<&'static str>,
    }
    #[async_trait]
    impl Kernel for FakeKernel {
        fn id(&self) -> KernelId {
            KernelId("fake".to_string())
        }
        fn supported_protocols(&self) -> Vec<ProtocolId> {
            self.supports
                .iter()
                .map(|s| ProtocolId(s.to_string()))
                .collect()
        }
        async fn ensure_installed(&self, _: &dyn SshTransport) -> Result<()> {
            Ok(())
        }
        fn render_config(
            &self,
            _: &RenderCtx<'_>,
            _: &[User],
            _: &[&dyn Protocol],
        ) -> Result<Vec<u8>> {
            Ok(Vec::new())
        }
        async fn apply_config(&self, _: &dyn SshTransport, _: &[u8]) -> Result<()> {
            Ok(())
        }
        async fn restart(&self, _: &dyn SshTransport) -> Result<()> {
            Ok(())
        }
        async fn status(&self, _: &dyn SshTransport) -> Result<KernelStatus> {
            Ok(KernelStatus {
                active: false,
                version: None,
                uptime_seconds: None,
            })
        }
    }

    fn registry(protos: Vec<(&'static str, &'static [(&'static str, u16)])>) -> Registry {
        let mut r = Registry::new();
        let supports: Vec<&'static str> = protos.iter().map(|(id, _)| *id).collect();
        r.register_kernel(Box::new(FakeKernel { supports }))
            .unwrap();
        for (id, ports) in protos {
            r.register_protocol(Box::new(FakeProto { id, ports }))
                .unwrap();
        }
        r
    }

    fn server(protos: &[&'static str]) -> Server {
        Server {
            id: ServerId("s1".into()),
            address: "1.2.3.4".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("fake".into())],
            enabled_protocols: protos.iter().map(|p| ProtocolId(p.to_string())).collect(),
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        }
    }

    fn no_secrets() -> HashMap<String, String> {
        HashMap::new()
    }

    #[test]
    fn same_transport_and_port_conflicts() {
        let reg = registry(vec![("vless", &[("tcp", 443)]), ("naive", &[("tcp", 443)])]);
        let err = reg
            .validate_server(&server(&["vless", "naive"]), &no_secrets())
            .unwrap_err();
        match err {
            CoreError::Render(m) => {
                assert!(m.contains("port conflict"), "msg: {m}");
                assert!(m.contains("443"), "msg: {m}");
                assert!(m.contains("vless") && m.contains("naive"), "msg: {m}");
            }
            other => panic!("expected Render, got {other:?}"),
        }
    }

    #[test]
    fn distinct_ports_ok() {
        let reg = registry(vec![("vless", &[("tcp", 443)]), ("tuic", &[("udp", 8443)])]);
        assert!(
            reg.validate_server(&server(&["vless", "tuic"]), &no_secrets())
                .is_ok()
        );
    }

    #[test]
    fn same_port_different_transport_ok() {
        // tcp/443 and udp/443 are distinct sockets — not a conflict.
        let reg = registry(vec![("a", &[("tcp", 443)]), ("b", &[("udp", 443)])]);
        assert!(
            reg.validate_server(&server(&["a", "b"]), &no_secrets())
                .is_ok()
        );
    }

    #[test]
    fn protocol_without_declared_ports_never_conflicts() {
        let reg = registry(vec![("vless", &[("tcp", 443)]), ("portless", &[])]);
        assert!(
            reg.validate_server(&server(&["vless", "portless"]), &no_secrets())
                .is_ok()
        );
    }

    /// A protocol whose `effective_listen_ports` honours a secret override
    /// moves its declared port for the guard too: with the override set the
    /// naive-on-443 conflict disappears…
    #[test]
    fn secret_override_frees_default_port() {
        #[derive(Debug)]
        struct OverridableVless;
        impl Protocol for OverridableVless {
            fn id(&self) -> ProtocolId {
                ProtocolId("vless".to_string())
            }
            fn server_inbound(&self, _: &RenderCtx<'_>, _: &[User]) -> Result<serde_json::Value> {
                Ok(serde_json::Value::Null)
            }
            fn client_config(&self, _: &RenderCtx<'_>, _: &User) -> Result<serde_json::Value> {
                Ok(serde_json::Value::Null)
            }
            fn share_link(&self, _: &RenderCtx<'_>, _: &User) -> Result<String> {
                Ok(String::new())
            }
            fn listen_ports(&self) -> &'static [(&'static str, u16)] {
                &[("tcp", 443)]
            }
            fn effective_listen_ports(
                &self,
                secrets: &HashMap<String, String>,
            ) -> Vec<(&'static str, u16)> {
                let port: u16 = secrets
                    .get("vless.listen_port")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(443);
                vec![("tcp", port)]
            }
        }
        let mut reg = Registry::new();
        reg.register_kernel(Box::new(FakeKernel {
            supports: vec!["vless", "naive"],
        }))
        .unwrap();
        reg.register_protocol(Box::new(OverridableVless)).unwrap();
        reg.register_protocol(Box::new(FakeProto {
            id: "naive",
            ports: &[("tcp", 443)],
        }))
        .unwrap();

        // Without the override: naive + vless both claim tcp/443.
        assert!(
            reg.validate_server(&server(&["vless", "naive"]), &no_secrets())
                .is_err()
        );

        // With vless.listen_port=8443 the conflict is resolved…
        let mut overridden = no_secrets();
        overridden.insert("vless.listen_port".into(), "8443".into());
        assert!(
            reg.validate_server(&server(&["vless", "naive"]), &overridden)
                .is_ok()
        );

        // …but a third protocol squatting the override port conflicts.
        reg.register_protocol(Box::new(FakeProto {
            id: "squat",
            ports: &[("tcp", 8443)],
        }))
        .unwrap();
        let reg2 = {
            let mut r = Registry::new();
            r.register_kernel(Box::new(FakeKernel {
                supports: vec!["vless", "naive", "squat"],
            }))
            .unwrap();
            r.register_protocol(Box::new(OverridableVless)).unwrap();
            r.register_protocol(Box::new(FakeProto {
                id: "naive",
                ports: &[("tcp", 443)],
            }))
            .unwrap();
            r.register_protocol(Box::new(FakeProto {
                id: "squat",
                ports: &[("tcp", 8443)],
            }))
            .unwrap();
            r
        };
        let err = reg2
            .validate_server(&server(&["vless", "naive", "squat"]), &overridden)
            .unwrap_err();
        match err {
            CoreError::Render(m) => assert!(m.contains("8443"), "msg: {m}"),
            other => panic!("expected Render, got {other:?}"),
        }
    }

    /// PR #139 review finding 1: a protocol that declares NO static port
    /// but binds a secret-driven one (the vless-ws shape — caddy front on
    /// `vlessws.listen_port`, default 8443) must still be visible to the
    /// guard through `effective_listen_ports`. Its default front port
    /// EQUALS reality's canonical override port 8443, so the cdn-incident
    /// remedy (reality → 8443) silently recreated the outage on a
    /// vless-ws co-resident node unless the guard sees both sides.
    #[test]
    fn secret_driven_front_port_conflicts_with_reality_override() {
        // vless-ws shape: no static declaration, effective port from a
        // secret with a non-443 default.
        #[derive(Debug)]
        struct WsLike;
        impl Protocol for WsLike {
            fn id(&self) -> ProtocolId {
                ProtocolId("ws".to_string())
            }
            fn server_inbound(&self, _: &RenderCtx<'_>, _: &[User]) -> Result<serde_json::Value> {
                Ok(serde_json::Value::Null)
            }
            fn client_config(&self, _: &RenderCtx<'_>, _: &User) -> Result<serde_json::Value> {
                Ok(serde_json::Value::Null)
            }
            fn share_link(&self, _: &RenderCtx<'_>, _: &User) -> Result<String> {
                Ok(String::new())
            }
            fn effective_listen_ports(
                &self,
                secrets: &HashMap<String, String>,
            ) -> Vec<(&'static str, u16)> {
                let port: u16 = secrets
                    .get("front.listen_port")
                    .and_then(|s| s.parse().ok())
                    .filter(|&p| p != 0)
                    .unwrap_or(8443);
                vec![("tcp", port)]
            }
        }
        // reality shape: default 443, `vless.listen_port` override.
        #[derive(Debug)]
        struct RealityLike;
        impl Protocol for RealityLike {
            fn id(&self) -> ProtocolId {
                ProtocolId("reality".to_string())
            }
            fn server_inbound(&self, _: &RenderCtx<'_>, _: &[User]) -> Result<serde_json::Value> {
                Ok(serde_json::Value::Null)
            }
            fn client_config(&self, _: &RenderCtx<'_>, _: &User) -> Result<serde_json::Value> {
                Ok(serde_json::Value::Null)
            }
            fn share_link(&self, _: &RenderCtx<'_>, _: &User) -> Result<String> {
                Ok(String::new())
            }
            fn listen_ports(&self) -> &'static [(&'static str, u16)] {
                &[("tcp", 443)]
            }
            fn effective_listen_ports(
                &self,
                secrets: &HashMap<String, String>,
            ) -> Vec<(&'static str, u16)> {
                let port: u16 = secrets
                    .get("vless.listen_port")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(443);
                vec![("tcp", port)]
            }
        }

        let reg = {
            let mut r = Registry::new();
            r.register_kernel(Box::new(FakeKernel {
                supports: vec!["ws", "reality"],
            }))
            .unwrap();
            r.register_protocol(Box::new(WsLike)).unwrap();
            r.register_protocol(Box::new(RealityLike)).unwrap();
            r
        };

        // reality's canonical remedy port == ws's default front port →
        // the exact outage combination MUST be rejected pre-SSH.
        let mut clash = no_secrets();
        clash.insert("vless.listen_port".into(), "8443".into());
        let err = reg
            .validate_server(&server(&["ws", "reality"]), &clash)
            .unwrap_err();
        match err {
            CoreError::Render(m) => assert!(m.contains("8443"), "msg: {m}"),
            other => panic!("expected Render, got {other:?}"),
        }

        // defaults (ws 8443 / reality 443) cohabit fine…
        assert!(
            reg.validate_server(&server(&["ws", "reality"]), &no_secrets())
                .is_ok()
        );

        // …as does ws moved off the override port.
        let mut apart = no_secrets();
        apart.insert("vless.listen_port".into(), "8443".into());
        apart.insert("front.listen_port".into(), "2087".into());
        assert!(
            reg.validate_server(&server(&["ws", "reality"]), &apart)
                .is_ok()
        );
    }

    /// PR #139 review finding 5: server-CREATE paths have no secrets yet
    /// (the override secret needs the server row to exist first), so they
    /// validate support only — a naive+realty create must not abort on a
    /// port conflict the operator is about to resolve via the secret; the
    /// deploy-time gate (with real secrets) stays authoritative.
    #[test]
    fn support_only_validation_skips_port_gate() {
        let reg = registry(vec![("vless", &[("tcp", 443)]), ("naive", &[("tcp", 443)])]);
        assert!(
            reg.validate_server_support(&server(&["vless", "naive"]))
                .is_ok()
        );
        // …while the full gate still rejects the same combination.
        assert!(
            reg.validate_server(&server(&["vless", "naive"]), &no_secrets())
                .is_err()
        );
        // support errors still fire on the support-only path.
        assert!(reg.validate_server_support(&server(&["ghost"])).is_err());
    }
}
