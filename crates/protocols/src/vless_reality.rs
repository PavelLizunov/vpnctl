use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use serde_json::json;
use vpnctl_core::{Protocol, ProtocolId, RenderCtx, Result, User};

/// Set of bytes that must be percent-encoded in URL fragments (RFC 3986):
/// everything that controls URL parsing, plus space/`#`/`?` which would
/// otherwise truncate or open a new component.
const FRAGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'<')
    .add(b'>')
    .add(b'`')
    .add(b'#')
    .add(b'?')
    .add(b'/')
    .add(b'@')
    .add(b':');

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

    fn listen_ports(&self) -> &'static [(&'static str, u16)] {
        &[("tcp", 443)]
    }

    fn dpi_risk(&self) -> vpnctl_core::DpiRisk {
        // REALITY serves a real TLS handshake to a real upstream
        // (`dest:` SNI, default www.microsoft.com); any probe that
        // doesn't carry valid VLESS-flow auth gets transparently
        // forwarded to Microsoft, so DPI sees authentic www.microsoft.com
        // HTML and cannot distinguish our server from a real visitor.
        // This is the gold-standard 2026 anti-probing posture.
        vpnctl_core::DpiRisk::Strong
    }

    fn server_inbound(&self, ctx: &RenderCtx<'_>, users: &[User]) -> Result<serde_json::Value> {
        let private_key = ctx.require("vless.private_key")?;
        let short_id = ctx.require("vless.short_id")?;
        let sni = ctx.or_default("vless.sni", "www.microsoft.com");
        // Per-server listen port override (post-2026-05-26). Default
        // 443 is the gold-standard cover (looks like real HTTPS),
        // but on a co-tenant host where :443 is owned by a legacy
        // 3x-ui Docker container, vpnctl needs to bind elsewhere.
        // Operator sets `vless.listen_port` server-secret to e.g.
        // `8443`; invalid values fall through to 443 so a typo
        // never silently drops the inbound to port 0.
        let listen_port: u16 = ctx
            .secrets
            .get("vless.listen_port")
            .and_then(|s| s.parse().ok())
            .unwrap_or(443);

        // XTLS-Vision sub-protocol is the **required** flow for VLESS +
        // REALITY in modern sing-box (≥ 1.4): without it the client
        // either gets a 400-style handshake reject ("flow not match") or
        // falls back to plain TLS proxying, defeating the REALITY
        // anti-DPI cover. Pinned to a string so a typo here surfaces in
        // `vless_server_inbound_user_carries_xtls_vision_flow` — caught
        // during vps-is-01 import (the bash-vpn-control deploys all set
        // `xtls-rprx-vision` and migrated clients would handshake-fail
        // without it).
        let users_json: Vec<_> = users
            .iter()
            .map(|u| {
                json!({
                    "uuid": u.uuid,
                    "name": u.id.0,
                    "flow": "xtls-rprx-vision",
                })
            })
            .collect();

        Ok(json!({
            "type": "vless",
            "tag": "vless-in",
            "listen": "::",
            "listen_port": listen_port,
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
        let server_port: u16 = ctx
            .secrets
            .get("vless.listen_port")
            .and_then(|s| s.parse().ok())
            .unwrap_or(443);

        // Mirror the server's `xtls-rprx-vision` flow — server REJECTS
        // sessions whose flow doesn't match the user-record's flow.
        // In sing-box outbound the `flow` field sits at the top level
        // next to `uuid` (per https://sing-box.sagernet.org/configuration/outbound/vless/).
        Ok(json!({
            "type": "vless",
            "tag": "vless-out",
            "server": ctx.server.address,
            "server_port": server_port,
            "uuid": user.uuid,
            "flow": "xtls-rprx-vision",
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
        let port: u16 = ctx
            .secrets
            .get("vless.listen_port")
            .and_then(|s| s.parse().ok())
            .unwrap_or(443);
        // user.id.0 lands in the URL fragment (`#name`) where chars like
        // `#`, ` `, `/` would corrupt the link or open a new component.
        // Percent-encode defensively even though server/CLI validate ids.
        let name = utf8_percent_encode(&user.id.0, FRAGMENT);
        // Parameter order + included params are pinned to match the
        // legacy bash `vpn-control/scripts/get-vless.sh` byte-for-byte:
        //   `?encryption=none&flow=xtls-rprx-vision&security=reality&sni=...&fp=chrome&pbk=...&sid=...&type=tcp`
        // (caught by Pavel's methodology check on db3998c — comparison
        // against the actual bash script showed mine was missing
        // `encryption=none` AND used a different param order, both
        // breaking the "Migration from bash — seamless preservation"
        // requirement in CLAUDE.md). The seven query params are pinned
        // verbatim in `vless_happy_path_byte_equal`.
        //
        // The `:443` in the link is the default — when `vless.listen_port`
        // is set on the server-secrets (3x-ui-coexistence case), the
        // alternate port substitutes in. Byte-equality test stays green
        // because it uses the default secrets (no listen_port override).
        Ok(format!(
            "vless://{uuid}@{addr}:{port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni={sni}&fp=chrome&pbk={pbk}&sid={sid}&type=tcp#{name}",
            uuid = user.uuid,
            addr = ctx.server.address,
            pbk = public_key,
            sid = short_id,
            sni = sni,
            name = name,
        ))
    }
}
