use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use percent_encoding::utf8_percent_encode;
use serde_json::json;
use std::collections::HashMap;
use vpnctl_core::url_host::host_for_url;
use vpnctl_core::{CoreError, Protocol, ProtocolId, RenderCtx, Result, User};

use super::amnezia::amneziawg_block;
use super::helpers::{
    CLIENT_PRIVKEY_PLACEHOLDER, DEFAULT_SERVER_CIDR, FRAGMENT, WIREGUARD_PORT, is_valid_wg_pubkey,
    listen_port, peer_octet_for,
};
use super::render::render_client_conf;

#[derive(Debug, Default)]
pub struct WireGuard;

impl WireGuard {
    pub fn new() -> Self {
        Self
    }
}

impl Protocol for WireGuard {
    fn id(&self) -> ProtocolId {
        ProtocolId("wireguard".to_string())
    }

    fn listen_ports(&self) -> &'static [(&'static str, u16)] {
        &[("udp", WIREGUARD_PORT)]
    }

    fn effective_listen_ports(
        &self,
        secrets: &HashMap<String, String>,
    ) -> Vec<(&'static str, u16)> {
        vec![("udp", listen_port(secrets))]
    }

    fn dpi_risk(&self) -> vpnctl_core::DpiRisk {
        vpnctl_core::DpiRisk::Weak
    }

    fn appears_in_sing_box_sub(&self) -> bool {
        false
    }

    fn server_secret_specs(&self) -> Vec<vpnctl_core::ServerSecretSpec> {
        vec![vpnctl_core::ServerSecretSpec::WireguardKeypair {
            private_key: "wireguard.server_private_key",
            public_key: "wireguard.server_public_key",
        }]
    }

    fn server_inbound(&self, ctx: &RenderCtx<'_>, users: &[User]) -> Result<serde_json::Value> {
        let private_key = ctx.require("wireguard.server_private_key")?;
        let listen_port: u16 = listen_port(ctx.secrets);
        let address_cidr = ctx
            .secrets
            .get("wireguard.server_address_cidr")
            .map(String::as_str)
            .unwrap_or(DEFAULT_SERVER_CIDR);

        let mut peers: Vec<serde_json::Value> = Vec::with_capacity(users.len());
        for (idx, u) in users.iter().enumerate() {
            let Some(pubkey) = u.wireguard_pubkey.as_deref() else {
                continue;
            };
            if !is_valid_wg_pubkey(pubkey) {
                return Err(CoreError::Render(format!(
                    "user '{}' has malformed wireguard pubkey (must be 44 base64 chars ending '='): {pubkey:?}",
                    u.id.0
                )));
            }
            let peer_octet = if ctx.wg_octets.is_some() {
                peer_octet_for(ctx, u)?
            } else {
                let octet = 2_u16.saturating_add(u16::try_from(idx).unwrap_or(u16::MAX));
                if octet > 254 {
                    return Err(CoreError::Render(format!(
                        "wireguard /24 has only 253 peer slots; user '{}' would overflow at index {idx}",
                        u.id.0
                    )));
                }
                octet
            };
            peers.push(json!({
                "name": u.id.0,
                "public_key": pubkey,
                "allowed_ips": format!("10.66.0.{peer_octet}/32"),
            }));
        }

        Ok(json!({
            "type": "wireguard",
            "tag": "wg-in",
            "listen_port": listen_port,
            "private_key": private_key,
            "address_cidr": address_cidr,
            "peers": peers,
        }))
    }

    fn client_config(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<serde_json::Value> {
        let server_pub = ctx.require("wireguard.server_public_key")?;
        let listen_port: u16 = listen_port(ctx.secrets);

        let peer_octet = peer_octet_for(ctx, user)?;
        let client_cidr = format!("10.66.0.{peer_octet}/32");

        let amnezia = amneziawg_block(ctx);

        if user.wireguard_private.is_some() && user.wireguard_pubkey.is_none() {
            return Err(CoreError::Render(format!(
                "user '{}' has wireguard_private set but no wireguard_pubkey \
                 — the server [Peer] block can't authenticate this client; \
                 fix the inventory row before re-running",
                user.id.0
            )));
        }
        let client_private = user
            .wireguard_private
            .as_deref()
            .unwrap_or(CLIENT_PRIVKEY_PLACEHOLDER);
        let mut interface = json!({
            "private_key": client_private,
            "address_cidr": client_cidr,
            "dns": ["1.1.1.1"],
        });
        if let Some(a) = amnezia
            && let Some(map) = interface.as_object_mut()
        {
            map.insert("amneziawg".to_string(), a);
        }

        Ok(json!({
            "type": "wireguard",
            "interface": interface,
            "peer": {
                "public_key": server_pub,
                "endpoint": format!("{}:{listen_port}", host_for_url(&ctx.server.address)),
                "allowed_ips": "0.0.0.0/0,::/0",
                "persistent_keepalive": 25,
            },
        }))
    }

    fn share_link(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<String> {
        let pubkey = user.wireguard_pubkey.as_deref().ok_or_else(|| {
            CoreError::Render(format!(
                "user '{}' has no wireguard_pubkey — cannot mint a WireGuard share link",
                user.id.0
            ))
        })?;
        if !is_valid_wg_pubkey(pubkey) {
            return Err(CoreError::Render(format!(
                "user '{}' has malformed wireguard pubkey: {pubkey:?}",
                user.id.0
            )));
        }
        let conf = render_client_conf(ctx, user)?;
        let conf_b64 = URL_SAFE_NO_PAD.encode(conf.as_bytes());
        let tag = utf8_percent_encode(&user.id.0, FRAGMENT);
        Ok(format!("wireguard://?conf={conf_b64}#{tag}"))
    }
}
