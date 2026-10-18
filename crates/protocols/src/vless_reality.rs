use crate::encoding::VLESS_FRAGMENT as FRAGMENT;
use percent_encoding::utf8_percent_encode;
use serde_json::json;
use vpnctl_core::url_host::host_for_url;
use vpnctl_core::{Protocol, ProtocolId, RenderCtx, Result, User};

pub(crate) const REALITY_UTLS_FP: &str = "randomized";

pub const DEFAULT_REALITY_SNI: &str = "yahoo.com";

pub const VLESS_PACKET_ENCODING: &str = "xudp";

#[derive(Debug, Default)]
pub struct VlessReality;

impl VlessReality {
    pub fn new() -> Self {
        Self
    }
}

pub fn listen_port(secrets: &std::collections::HashMap<String, String>) -> u16 {
    secrets
        .get("vless.listen_port")
        .and_then(|s| s.parse::<u16>().ok())
        .filter(|&p| p != 0)
        .unwrap_or(443)
}

impl Protocol for VlessReality {
    fn id(&self) -> ProtocolId {
        ProtocolId("vless+reality".to_string())
    }

    fn dpi_risk(&self) -> vpnctl_core::DpiRisk {
        vpnctl_core::DpiRisk::Strong
    }

    fn server_secret_specs(&self) -> Vec<vpnctl_core::ServerSecretSpec> {
        use vpnctl_core::ServerSecretSpec::{ShortId, X25519Keypair};
        vec![
            X25519Keypair {
                private_key: "vless.private_key",
                public_key: "vless.public_key",
            },
            ShortId {
                key: "vless.short_id",
            },
        ]
    }

    fn listen_ports(&self) -> &'static [(&'static str, u16)] {
        &[("tcp", 443)]
    }

    fn effective_listen_ports(
        &self,
        secrets: &std::collections::HashMap<String, String>,
    ) -> Vec<(&'static str, u16)> {
        vec![("tcp", listen_port(secrets))]
    }

    fn server_inbound(&self, ctx: &RenderCtx<'_>, users: &[User]) -> Result<serde_json::Value> {
        let private_key = ctx.require("vless.private_key")?;
        let short_id = ctx.require("vless.short_id")?;
        let sni = ctx.or_default("vless.sni", DEFAULT_REALITY_SNI);
        let listen_port: u16 = listen_port(ctx.secrets);

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
        let sni = ctx.or_default("vless.sni", DEFAULT_REALITY_SNI);
        let server_port: u16 = listen_port(ctx.secrets);

        Ok(json!({
            "type": "vless",
            "tag": "vless-out",
            "server": ctx.server.address,
            "server_port": server_port,
            "uuid": user.uuid,
            "flow": "xtls-rprx-vision",
            "packet_encoding": VLESS_PACKET_ENCODING,
            "tls": {
                "enabled": true,
                "server_name": sni,
                "utls": { "enabled": true, "fingerprint": REALITY_UTLS_FP },
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
        let sni = ctx.or_default("vless.sni", DEFAULT_REALITY_SNI);
        let port: u16 = listen_port(ctx.secrets);
        let name = utf8_percent_encode(&user.id.0, FRAGMENT);
        Ok(format!(
            "vless://{uuid}@{addr}:{port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni={sni}&fp={fp}&pbk={pbk}&sid={sid}&type=tcp&packetEncoding={packet_encoding}#{name}",
            uuid = user.uuid,
            addr = host_for_url(&ctx.server.address),
            fp = REALITY_UTLS_FP,
            pbk = public_key,
            sid = short_id,
            sni = sni,
            name = name,
            packet_encoding = VLESS_PACKET_ENCODING,
        ))
    }
}
