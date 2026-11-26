//! Managed TURN entry. Clients receive its credentials through the exit profile.
use std::{collections::HashMap, net::Ipv4Addr};

use serde_json::{Value, json};
use vpnctl_core::{
    CoreError, DpiRisk, Protocol, ProtocolId, RenderCtx, Result, ServerSecretSpec, User,
};

pub const TURNRELAY_RELAY_PORT: u16 = 53491;
const LISTEN_PORT: &str = "turnrelay_relay.listen_port";
const USERNAME: &str = "turnrelay_relay.username";
const PASSWORD: &str = "turnrelay_relay.password";

#[derive(Debug, Default)]
pub struct TurnRelayRelay;

fn listen_port(secrets: &HashMap<String, String>) -> Result<u16> {
    match secrets.get(LISTEN_PORT).map(String::as_str).unwrap_or("") {
        "" => Ok(TURNRELAY_RELAY_PORT),
        port => port.parse().ok().filter(|port| *port > 0).ok_or_else(|| {
            CoreError::Render("invalid TurnRelay entry port (expected 1..=65535)".into())
        }),
    }
}

fn env_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn entry_settings<'a>(ctx: &RenderCtx<'a>) -> Result<(Ipv4Addr, u16, &'a str, &'a str)> {
    let ip = ctx
        .server
        .address
        .parse::<Ipv4Addr>()
        .ok()
        .filter(|ip| !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast())
        .ok_or_else(|| {
            CoreError::Render("TurnRelay entry needs a unicast IPv4 node address".into())
        })?;
    let port = listen_port(ctx.secrets)?;
    if port == ctx.server.ssh_port {
        return Err(CoreError::Render(
            "TurnRelay entry port conflicts with SSH".into(),
        ));
    }
    let realm = ctx
        .secrets
        .get("turnrelay_relay.realm")
        .map_or("turnrelay", String::as_str);
    if !env_token(realm) {
        return Err(CoreError::Render("invalid TurnRelay entry realm".into()));
    }
    let exits = ctx
        .secrets
        .get("turnrelay_relay.allowed_exits")
        .map_or("", String::as_str);
    if !exits.is_empty()
        && !exits
            .split(',')
            .all(|ip| ip.trim().parse::<Ipv4Addr>().is_ok())
    {
        return Err(CoreError::Render(
            "invalid TurnRelay exit allowlist (expected IPv4 addresses)".into(),
        ));
    }
    Ok((ip, port, realm, exits))
}

fn credential<'a>(ctx: &RenderCtx<'a>, key: &str) -> Result<&'a str> {
    ctx.secrets
        .get(key)
        .map(String::as_str)
        .filter(|value| env_token(value))
        .ok_or_else(|| CoreError::MissingSecret {
            server: ctx.server.id.clone(),
            key: key.into(),
        })
}

impl Protocol for TurnRelayRelay {
    fn id(&self) -> ProtocolId {
        ProtocolId("turnrelay-relay".into())
    }

    fn listen_ports(&self) -> &'static [(&'static str, u16)] {
        &[("tcp", TURNRELAY_RELAY_PORT), ("udp", TURNRELAY_RELAY_PORT)]
    }

    fn effective_listen_ports(
        &self,
        secrets: &HashMap<String, String>,
    ) -> Vec<(&'static str, u16)> {
        let port = listen_port(secrets).unwrap_or(TURNRELAY_RELAY_PORT);
        vec![("tcp", port), ("udp", port)]
    }

    fn appears_in_sing_box_sub(&self) -> bool {
        false
    }

    fn dpi_risk(&self) -> DpiRisk {
        DpiRisk::Strong
    }

    fn validate_server(&self, ctx: &RenderCtx<'_>) -> Result<()> {
        entry_settings(ctx).map(|_| ())
    }

    fn server_secret_specs(&self) -> Vec<ServerSecretSpec> {
        vec![
            ServerSecretSpec::Password {
                key: USERNAME,
                entropy_bytes: 12,
            },
            ServerSecretSpec::Password {
                key: PASSWORD,
                entropy_bytes: 24,
            },
        ]
    }

    fn server_inbound(&self, ctx: &RenderCtx<'_>, _users: &[User]) -> Result<Value> {
        let (ip, port, realm, exits) = entry_settings(ctx)?;
        Ok(json!({
            "address": ip,
            "listen_port": port,
            "username": credential(ctx, USERNAME)?,
            "password": credential(ctx, PASSWORD)?,
            "realm": realm,
            "allowed_exits": exits,
        }))
    }

    fn client_config(&self, _ctx: &RenderCtx<'_>, _user: &User) -> Result<Value> {
        Err(CoreError::ShareLinkUnavailable(self.id().0))
    }

    fn share_link(&self, _ctx: &RenderCtx<'_>, _user: &User) -> Result<String> {
        Err(CoreError::ShareLinkUnavailable(self.id().0))
    }
}
