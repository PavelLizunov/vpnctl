use crate::encoding::VLESS_FRAGMENT as FRAGMENT;
use percent_encoding::utf8_percent_encode;
use serde_json::json;
use vpnctl_core::url_host::host_for_url;
use vpnctl_core::{CoreError, Protocol, ProtocolId, RenderCtx, Result, User};

use crate::vless_reality::{DEFAULT_REALITY_SNI, REALITY_UTLS_FP};

pub const VLESS_XHTTP_PORT: u16 = 9443;

const DEFAULT_XHTTP_MODE: &str = "auto";

#[derive(Debug, Default)]
pub struct VlessXhttp;

impl VlessXhttp {
    pub fn new() -> Self {
        Self
    }
}

fn checked_path<'a>(ctx: &'a RenderCtx<'_>) -> Result<&'a str> {
    let path = ctx.require("vlessxhttp.path")?;
    if path.is_empty()
        || !path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(CoreError::Render(format!(
            "vlessxhttp.path must be a non-empty [A-Za-z0-9_-] string (url-safe-base64 \
             minted by bootstrap); got {path:?}"
        )));
    }
    Ok(path)
}

fn checked_mode<'a>(ctx: &'a RenderCtx<'_>) -> Result<&'a str> {
    let mode = ctx.or_default("vlessxhttp.mode", DEFAULT_XHTTP_MODE);
    match mode {
        "auto" | "packet-up" | "stream-up" | "stream-one" => Ok(mode),
        _ => Err(CoreError::Render(format!(
            "vlessxhttp.mode must be one of auto/packet-up/stream-up/stream-one \
             (Xray-core's known xhttp transport modes); got {mode:?}"
        ))),
    }
}

impl Protocol for VlessXhttp {
    fn id(&self) -> ProtocolId {
        ProtocolId("vless+xhttp".to_string())
    }

    fn listen_ports(&self) -> &'static [(&'static str, u16)] {
        &[("tcp", VLESS_XHTTP_PORT)]
    }

    fn appears_in_stock_sing_box_sub(&self) -> bool {
        false
    }

    fn dpi_risk(&self) -> vpnctl_core::DpiRisk {
        vpnctl_core::DpiRisk::Strong
    }

    fn server_secret_specs(&self) -> Vec<vpnctl_core::ServerSecretSpec> {
        use vpnctl_core::ServerSecretSpec::{Password, ShortId, X25519Keypair};
        vec![
            X25519Keypair {
                private_key: "vless.private_key",
                public_key: "vless.public_key",
            },
            ShortId {
                key: "vless.short_id",
            },
            Password {
                key: "vlessxhttp.path",
                entropy_bytes: 16,
            },
        ]
    }

    fn server_inbound(&self, ctx: &RenderCtx<'_>, users: &[User]) -> Result<serde_json::Value> {
        let private_key = ctx.require("vless.private_key")?;
        let short_id = ctx.require("vless.short_id")?;
        let sni = ctx.or_default("vless.sni", DEFAULT_REALITY_SNI);
        let path = checked_path(ctx)?;
        let mode = checked_mode(ctx)?;

        let clients_json: Vec<_> = users
            .iter()
            .map(|u| json!({ "id": u.uuid, "email": u.id.0 }))
            .collect();

        Ok(json!({
            "listen": "::",
            "port": VLESS_XHTTP_PORT,
            "protocol": "vless",
            "settings": {
                "clients": clients_json,
                "decryption": "none"
            },
            "streamSettings": {
                "network": "xhttp",
                "security": "reality",
                "xhttpSettings": {
                    "path": format!("/{path}/"),
                    "mode": mode
                },
                "realitySettings": {
                    "dest": format!("{sni}:443"),
                    "serverNames": [sni],
                    "privateKey": private_key,
                    "shortIds": [short_id]
                }
            }
        }))
    }

    fn client_config(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<serde_json::Value> {
        let public_key = ctx.require("vless.public_key")?;
        let short_id = ctx.require("vless.short_id")?;
        let sni = ctx.or_default("vless.sni", DEFAULT_REALITY_SNI);
        let path = checked_path(ctx)?;
        let mode = checked_mode(ctx)?;

        Ok(json!({
            "type": "vless",
            "tag": "vless-xhttp-out",
            "server": ctx.server.address,
            "server_port": VLESS_XHTTP_PORT,
            "uuid": user.uuid,
            "tls": {
                "enabled": true,
                "server_name": sni,
                "utls": { "enabled": true, "fingerprint": REALITY_UTLS_FP },
                "reality": {
                    "enabled": true,
                    "public_key": public_key,
                    "short_id": short_id
                }
            },
            "transport": {
                "type": "xhttp",
                "path": format!("/{path}/"),
                "mode": mode
            }
        }))
    }

    fn share_link(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<String> {
        let public_key = ctx.require("vless.public_key")?;
        let short_id = ctx.require("vless.short_id")?;
        let sni = ctx.or_default("vless.sni", DEFAULT_REALITY_SNI);
        let path = checked_path(ctx)?;
        let mode = checked_mode(ctx)?;
        let name = utf8_percent_encode(&user.id.0, FRAGMENT);

        Ok(format!(
            "vless://{uuid}@{addr}:{port}?encryption=none&security=reality&sni={sni}&fp={fp}&pbk={pbk}&sid={sid}&type=xhttp&path=%2F{path}%2F&mode={mode}#{name}",
            uuid = user.uuid,
            addr = host_for_url(&ctx.server.address),
            port = VLESS_XHTTP_PORT,
            fp = REALITY_UTLS_FP,
            pbk = public_key,
            sid = short_id,
            sni = sni,
            path = path,
            mode = mode,
            name = name,
        ))
    }
}
