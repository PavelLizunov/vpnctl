use serde_json::json;
use vpnctl_core::{Protocol, ProtocolId, RenderCtx, Result, User};

/// VLESS + REALITY на TCP:443.
///
/// **Stateless**: ключи REALITY и SNI приходят через [`RenderCtx::secrets`]
/// — это позволяет одной инстанции жить в `Registry` и работать с любым
/// сервером, секреты которого хранятся в `inventory::server_secrets`.
///
/// Конвенция ключей:
///
/// - `vless.private_key` (required) — REALITY x25519 private (base64-url-no-pad)
/// - `vless.public_key`  (required) — REALITY x25519 public  (base64-url-no-pad)
/// - `vless.short_id`    (required) — REALITY short ID (8 hex)
/// - `vless.sni`         (optional, default `www.microsoft.com`)
#[derive(Debug, Default)]
pub struct VlessReality;

impl VlessReality {
    pub fn new() -> Self {
        Self
    }
}

impl Protocol for VlessReality {
    fn id(&self) -> ProtocolId {
        ProtocolId("vless+reality".to_string())
    }

    fn server_inbound(&self, ctx: &RenderCtx<'_>, users: &[User]) -> Result<serde_json::Value> {
        let private_key = ctx.require("vless.private_key")?;
        let short_id = ctx.require("vless.short_id")?;
        let sni = ctx.or_default("vless.sni", "www.microsoft.com");

        let users_json: Vec<_> = users
            .iter()
            .map(|u| json!({ "uuid": u.uuid, "name": u.id.0, "flow": "" }))
            .collect();

        Ok(json!({
            "type": "vless",
            "tag": "vless-in",
            "listen": "::",
            "listen_port": 443,
            "users": users_json,
            "tls": {
                "enabled": true,
                "server_name": sni,
                "reality": {
                    "enabled": true,
                    "handshake": { "server": sni, "server_port": 443 },
                    "private_key": private_key,
                    "short_id": [short_id]
                }
            }
        }))
    }

    fn client_config(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<serde_json::Value> {
        let public_key = ctx.require("vless.public_key")?;
        let short_id = ctx.require("vless.short_id")?;
        let sni = ctx.or_default("vless.sni", "www.microsoft.com");

        Ok(json!({
            "type": "vless",
            "tag": "vless-out",
            "server": ctx.server.address,
            "server_port": 443,
            "uuid": user.uuid,
            "tls": {
                "enabled": true,
                "server_name": sni,
                "utls": { "enabled": true, "fingerprint": "chrome" },
                "reality": {
                    "enabled": true,
                    "public_key": public_key,
                    "short_id": short_id
                }
            }
        }))
    }

    fn share_link(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<String> {
        let public_key = ctx.require("vless.public_key")?;
        let short_id = ctx.require("vless.short_id")?;
        let sni = ctx.or_default("vless.sni", "www.microsoft.com");
        Ok(format!(
            "vless://{uuid}@{addr}:443?type=tcp&security=reality&pbk={pbk}&sid={sid}&sni={sni}&fp=chrome#{name}",
            uuid = user.uuid,
            addr = ctx.server.address,
            pbk = public_key,
            sid = short_id,
            sni = sni,
            name = user.id.0,
        ))
    }
}
