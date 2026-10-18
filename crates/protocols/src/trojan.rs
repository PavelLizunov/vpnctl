use crate::encoding::{FRAGMENT, USERINFO};
use percent_encoding::utf8_percent_encode;
use serde_json::json;
use vpnctl_core::url_host::host_for_url;
use vpnctl_core::{CoreError, Protocol, ProtocolId, RenderCtx, Result, User};

#[derive(Debug, Default)]
pub struct Trojan;

impl Trojan {
    pub fn new() -> Self {
        Self
    }
}

pub const TROJAN_PORT: u16 = 8643;

impl Protocol for Trojan {
    fn id(&self) -> ProtocolId {
        ProtocolId("trojan".to_string())
    }

    fn listen_ports(&self) -> &'static [(&'static str, u16)] {
        &[("tcp", TROJAN_PORT)]
    }

    fn dpi_risk(&self) -> vpnctl_core::DpiRisk {
        vpnctl_core::DpiRisk::Weak
    }

    fn server_inbound(&self, ctx: &RenderCtx<'_>, users: &[User]) -> Result<serde_json::Value> {
        let cert_path = ctx.or_default("tuic.cert_path", "/etc/sing-box/cert.pem");
        let key_path = ctx.or_default("tuic.key_path", "/etc/sing-box/key.pem");

        let users_json: Vec<_> = users
            .iter()
            .filter_map(|u| {
                u.tuic_password
                    .as_ref()
                    .map(|pw| json!({ "name": u.id.0, "password": pw }))
            })
            .collect();

        Ok(json!({
            "type": "trojan",
            "tag": "trojan-in",
            "listen": "::",
            "listen_port": TROJAN_PORT,
            "users": users_json,
            "tls": {
                "enabled": true,
                "certificate_path": cert_path,
                "key_path": key_path,
            }
        }))
    }

    fn client_config(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<serde_json::Value> {
        let pw = user.tuic_password.as_deref().ok_or_else(|| {
            CoreError::Render(format!(
                "user '{}' has no tuic_password — cannot mint a Trojan client config",
                user.id.0
            ))
        })?;
        Ok(json!({
            "type": "trojan",
            "tag": "trojan-out",
            "server": ctx.server.address,
            "server_port": TROJAN_PORT,
            "password": pw,
            "tls": { "enabled": true, "insecure": true }
        }))
    }

    fn share_link(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<String> {
        let raw_pw = user.tuic_password.as_deref().ok_or_else(|| {
            CoreError::Render(format!(
                "user '{}' has no tuic_password — cannot mint a Trojan link",
                user.id.0
            ))
        })?;
        let pw = utf8_percent_encode(raw_pw, USERINFO);
        let name = utf8_percent_encode(&user.id.0, FRAGMENT);
        Ok(format!(
            "trojan://{pw}@{host}:{port}?sni={sni}&allowInsecure=1#{name}",
            pw = pw,
            host = host_for_url(&ctx.server.address),
            sni = ctx.server.address,
            port = TROJAN_PORT,
            name = name,
        ))
    }
}
