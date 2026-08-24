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
    listen_port,
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
        // SAME resolution as the inbound renderer (the shared
        // `listen_port` helper): guard/firewall/drift see the port
        // wg-quick ACTUALLY binds — otherwise an overridden node shows
        // «declared but NOT listening» forever (PR #139 review).
        vec![("udp", listen_port(secrets))]
    }

    fn dpi_risk(&self) -> vpnctl_core::DpiRisk {
        // Raw WireGuard's handshake initiation message is ALWAYS a
        // 148-byte UDP datagram that begins with `0x01 0x00 0x00 0x00`
        // (message_type=1 + 3 zero bytes for reserved). This is a
        // hard-coded constant in the WG protocol spec — it CANNOT be
        // changed without breaking the wire format. TSPU exploited
        // this since 2023 and now drops bare WireGuard 100% in RU
        // residential ASNs; GFW (CN) the same. The IR DPI blocks it
        // on similar grounds. Use `amneziawg` (kernel-level junk-packet injection)
        // when WG-style transport is needed in a hostile environment.
        vpnctl_core::DpiRisk::Weak
    }

    fn appears_in_sing_box_sub(&self) -> bool {
        // `client_config()` emits an INTERNAL `{ type: "wireguard",
        // interface: {...}, peer: {...} }` object — the shape consumed
        // by the wg-quick / AmneziaWG renderers, NOT a valid sing-box
        // outbound (sing-box's wireguard outbound is a flat object with
        // `server` / `server_port` / `private_key` / `peer_public_key`).
        // If this slips into the /sub envelope, sing-box / Hiddify sees
        // an unknown outbound shape and drops EVERY route (including the
        // working VLESS / TUIC ones). WireGuard is delivered via its own
        // `wg://` share link + `.conf` download. Hard `false`.
        false
    }

    fn server_secret_specs(&self) -> Vec<vpnctl_core::ServerSecretSpec> {
        // Server-side Curve25519 keypair. The per-user pair lives in
        // the `users` table (a different bootstrap path — user_create).
        vec![vpnctl_core::ServerSecretSpec::WireguardKeypair {
            private_key: "wireguard.server_private_key",
            public_key: "wireguard.server_public_key",
        }]
    }

    fn server_inbound(&self, ctx: &RenderCtx<'_>, users: &[User]) -> Result<serde_json::Value> {
        // Server-side material — required.
        let private_key = ctx.require("wireguard.server_private_key")?;
        let listen_port: u16 = listen_port(ctx.secrets);
        let address_cidr = ctx
            .secrets
            .get("wireguard.server_address_cidr")
            .map(String::as_str)
            .unwrap_or(DEFAULT_SERVER_CIDR);

        // Per-user peers. Skip users without a pubkey (partial
        // provisioning is allowed — same convention as Hysteria2's
        // missing tuic_password). Reject MALFORMED pubkeys hard so a
        // typo doesn't reach the kernel module and kill the deploy.
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
            // /32 per peer — each user gets exactly one tunnel address.
            // 10.66.0.2 .. 10.66.0.255. Past 254 users we'd overflow;
            // homelab scale comfortably under that.
            let peer_octet = 2_u16.saturating_add(u16::try_from(idx).unwrap_or(u16::MAX));
            if peer_octet > 254 {
                return Err(CoreError::Render(format!(
                    "wireguard /24 has only 253 peer slots; user '{}' would overflow at index {idx}",
                    u.id.0
                )));
            }
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
        // Server-side public key (NOT private) is what the client peer
        // needs in its [Peer] PublicKey field.
        let server_pub = ctx.require("wireguard.server_public_key")?;
        let listen_port: u16 = listen_port(ctx.secrets);

        // Where THIS user lands in the /24. We can't know the index
        // without the full users slice; use the user's pubkey as a
        // tagging marker the kernel can cross-reference if it has the
        // full peer list. Default to `.2/32` so a single-user
        // standalone client doesn't need extra context.
        // (For multi-user accuracy use `server_inbound`'s per-peer
        // allowed_ips; client_config is per-user only and lacks the
        // index.)
        let client_cidr = "10.66.0.2/32";

        // AmneziaWG sub-block. Emitted ONLY if the server has the
        // obfuscation params set — vanilla WireGuard servers don't,
        // and a vanilla WireGuard client given an `amneziawg` block
        // would just ignore it (per spec: unknown keys are skipped).
        // Still, omit when not set so the rendered conf stays minimal.
        let amnezia = amneziawg_block(ctx);

        // Server-generated private (low-tech UX) takes precedence;
        // operator-provided-pubkey path keeps the legacy placeholder.
        // See `render_client_conf` for the same fallback chain.
        //
        // Invariant guard: if private is set, the matching public MUST
        // also be set — the server's [Peer] block won't authenticate
        // a client whose pubkey isn't in the server's user list.
        // This pair is enforced by all write paths (CLI + web both
        // set both halves atomically), but a direct-SQL operator could
        // hand-set only one — fail loud here rather than ship a
        // silently-broken tunnel. (Review-agent finding on wg-keygen.)
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
        if let Some(a) = amnezia.clone()
            && let Some(map) = interface.as_object_mut()
        {
            map.insert("amneziawg".to_string(), a);
        }

        let _ = user; // single-user client_config doesn't differentiate

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
        // Hard-error on missing pubkey — operator asked for a link
        // that can't possibly authenticate. Mirror Hysteria2's split.
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
        // Build a real .conf file body, base64url-no-pad it, embed
        // in a stable wireguard:// pseudo-URI. The client (AmneziaVPN
        // app) base64-decodes the `conf` query-param and treats as a
        // real config file.
        let conf = render_client_conf(ctx, user)?;
        let conf_b64 = URL_SAFE_NO_PAD.encode(conf.as_bytes());
        let tag = utf8_percent_encode(&user.id.0, FRAGMENT);
        Ok(format!("wireguard://?conf={conf_b64}#{tag}"))
    }
}
