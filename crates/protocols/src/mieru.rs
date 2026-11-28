use std::collections::HashMap;

use percent_encoding::utf8_percent_encode;
use serde_json::{Value, json};
use vpnctl_core::{CoreError, DpiRisk, Protocol, ProtocolId, RenderCtx, Result, User};

use crate::encoding::FRAGMENT;
use crate::username_password::{inbound_users, listen_port, setting, userinfo, validate_user};
use vpnctl_core::url_host::host_for_url;

pub const MIERU_PORT: u16 = 8445;

#[derive(Debug, Default)]
pub struct Mieru;

struct Settings<'a> {
    port: u16,
    transport: &'static str,
    multiplexing: &'a str,
    handshake_mode: &'a str,
}

impl<'a> Settings<'a> {
    fn parse(secrets: &'a HashMap<String, String>) -> Result<Self> {
        let transport = setting(secrets, "mieru.transport", "tcp", &["tcp", "udp"])?;
        Ok(Self {
            port: listen_port(secrets, "mieru.listen_port", MIERU_PORT)?,
            transport: if transport == "tcp" { "tcp" } else { "udp" },
            multiplexing: setting(
                secrets,
                "mieru.multiplexing",
                "middle",
                &["default", "off", "low", "middle", "high"],
            )?,
            handshake_mode: setting(
                secrets,
                "mieru.handshake_mode",
                "standard",
                &["default", "standard", "no_wait"],
            )?,
        })
    }

    fn for_server(ctx: &RenderCtx<'a>) -> Result<Self> {
        let settings = Self::parse(ctx.secrets)?;
        if settings.transport == "tcp" && settings.port == ctx.server.ssh_port {
            return Err(CoreError::Render(
                "Mieru TCP port conflicts with SSH".into(),
            ));
        }
        Ok(settings)
    }
}

impl Protocol for Mieru {
    fn id(&self) -> ProtocolId {
        ProtocolId("mieru".into())
    }

    fn listen_ports(&self) -> &'static [(&'static str, u16)] {
        &[("tcp", MIERU_PORT)]
    }

    fn effective_listen_ports(
        &self,
        secrets: &HashMap<String, String>,
    ) -> Vec<(&'static str, u16)> {
        Settings::parse(secrets)
            .map(|settings| vec![(settings.transport, settings.port)])
            .unwrap_or_default()
    }

    fn validate_server(&self, ctx: &RenderCtx<'_>) -> Result<()> {
        Settings::for_server(ctx).map(|_| ())
    }

    fn dpi_risk(&self) -> DpiRisk {
        DpiRisk::Moderate
    }

    fn requires_inbound_users(&self) -> bool {
        true
    }

    fn appears_in_sing_box_sub(&self) -> bool {
        false
    }

    fn server_inbound(&self, ctx: &RenderCtx<'_>, users: &[User]) -> Result<Value> {
        let settings = Settings::for_server(ctx)?;
        Ok(json!({
            "type": "mieru",
            "tag": "mieru-in",
            "listen": "::",
            "listen_port": settings.port,
            "transport": settings.transport,
            "users": inbound_users(users, "Mieru", true),
        }))
    }

    fn client_config(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<Value> {
        validate_user(user, "Mieru", true)?;
        let settings = Settings::for_server(ctx)?;
        Ok(json!({
            "type": "mieru",
            "tag": "mieru-out",
            "server": ctx.server.address,
            "server_port": settings.port,
            "transport": settings.transport,
            "username": user.id.0,
            "password": user.uuid,
            "multiplexing": settings.multiplexing,
            "handshake_mode": settings.handshake_mode,
        }))
    }

    fn share_link(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<String> {
        validate_user(user, "Mieru", true)?;
        let settings = Settings::for_server(ctx)?;
        let userinfo = userinfo(user);
        let host = host_for_url(&ctx.server.address);
        let fragment = utf8_percent_encode(&user.id.0, FRAGMENT);
        Ok(format!(
            "mieru://{userinfo}@{host}:{}?transport={}&multiplexing={}&handshake={}#{fragment}",
            settings.port, settings.transport, settings.multiplexing, settings.handshake_mode,
        ))
    }
}
