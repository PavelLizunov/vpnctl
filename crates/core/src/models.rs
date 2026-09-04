use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

use crate::error::{CoreError, Result};
use crate::id::{KernelId, ProtocolId, ServerId, UserId};

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
    /// SSH-jump host (ProxyJump). `None` — прямое подключение.
    #[serde(default)]
    pub jump_via: Option<ServerId>,
    /// Множитель учёта трафика (Marzban-style). Резерв для будущих лимитов.
    #[serde(default = "default_usage_coefficient")]
    pub usage_coefficient: f64,
}

/// Fully pinned route for a one-hop system OpenSSH ProxyJump connection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedJumpRoute {
    pub host: String,
    pub user: String,
    pub port: u16,
    /// Canonical SHA-256 fingerprint of the jump host key.
    pub jump_fingerprint: String,
    /// Canonical SHA-256 fingerprint of the final target host key.
    pub target_fingerprint: String,
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
