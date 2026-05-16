//! WireGuard protocol — wire format clients consume. The Kernel that
//! actually runs WireGuard on the node (today: AmneziaWG with anti-DPI
//! obfuscation; future: vanilla `wg-quick`) reads this module's
//! `server_inbound()` envelope and transforms it into its native
//! config format (INI for wg-quick / amneziawg-tools, JSON for
//! sing-box's hypothetical `wireguard` inbound).
//!
//! # Envelope schema (the trait-impedance fix)
//!
//! `Protocol::server_inbound` returns `serde_json::Value`. AmneziaWG
//! renders INI, not JSON — so we'd hit a trait-impedance problem if
//! the Protocol returned a sing-box-flavoured JSON config. Instead,
//! this module returns a STABLE ENVELOPE that any Kernel can
//! deserialise into a typed struct and transform.
//!
//! Envelope shape (JSON, byte-stable across runs — uses BTreeMap
//! ordering for the `peers` field if applicable; users vec is iterated
//! in caller-provided order which is `inv.users_for_server`'s
//! lex-sorted-by-id order):
//!
//! ```json
//! {
//!   "type": "wireguard",
//!   "tag": "wg-in",
//!   "listen_port": 51820,
//!   "private_key": "<base64 server private key>",
//!   "address_cidr": "10.66.0.1/24",
//!   "peers": [
//!     { "name": "alex", "public_key": "<base64 user pubkey>", "allowed_ips": "10.66.0.2/32" }
//!   ]
//! }
//! ```
//!
//! Per-peer `allowed_ips` is computed deterministically from the
//! peer's index in the `users` slice: `10.66.0.<2 + index>/32`. This
//! is stable across re-renders provided callers pass users in the
//! same order each time (which `inv.users_for_server` does — it
//! `ORDER BY id`s).
//!
//! # Per-user contract
//!
//! Users with `wireguard_pubkey == None` are SKIPPED (not an error)
//! in `server_inbound` so a partially-provisioned node still deploys.
//! Same user → `share_link` is a HARD ERROR (the operator is asking
//! for something that can't possibly work). Same split as Hysteria2's
//! `tuic_password` handling.
//!
//! Pubkey validation: 44 chars, base64 (`[A-Za-z0-9+/]{43}=`). Reject
//! malformed early so a typo doesn't reach `awg setconf` and crash
//! the kernel module.
//!
//! # Client config
//!
//! `client_config` returns an envelope SUITABLE for transformation
//! into a client `.conf` file. The CLIENT private key is emitted as
//! a placeholder (`"<PASTE YOUR PRIVATE KEY HERE>"`) — vpnctl never
//! sees it. The operator (or AmneziaVPN's import flow) substitutes
//! it. Standard self-hosted-WireGuard UX.
//!
//! # Share link
//!
//! `wireguard://?conf=<base64url(.conf bytes)>#<user-id>`. Not an
//! IETF-blessed URI; chosen for stability + universal QR encoding.
//! AmneziaVPN clients accept it. Vanilla WireGuard mobile apps don't,
//! but the user-detail page already shows the raw conf alongside the
//! QR (operator can paste manually).
//!
//! Stateless, like every other Protocol in this crate.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use serde_json::json;
use vpnctl_core::{CoreError, Protocol, ProtocolId, RenderCtx, Result, User};

#[derive(Debug, Default)]
pub struct WireGuard;

impl WireGuard {
    pub fn new() -> Self {
        Self
    }
}

/// UDP port WireGuard listens on. Public so kernels + tests can format
/// endpoints without duplicating the literal.
pub const WIREGUARD_PORT: u16 = 51820;

/// Default tunnel-side server CIDR. `/24` gives 254 peer slots — more
/// than enough for a single-operator homelab.
const DEFAULT_SERVER_CIDR: &str = "10.66.0.1/24";

/// Placeholder substituted by the client's import flow / operator.
/// vpnctl deliberately never holds the client private key — the
/// peer-side keypair is generated on the device.
pub const CLIENT_PRIVKEY_PLACEHOLDER: &str = "<PASTE YOUR PRIVATE KEY HERE>";

/// Validate a base64-encoded WireGuard public key. WG keys are exactly
/// 32 bytes → 44 chars of standard-base64 with `=` padding (last char).
/// We don't decode — just shape-check, since the kernel module will
/// reject a wrong-length or malformed key with a clear error message
/// at apply time anyway.
///
/// **Public so the CLI + web user-create handlers can share the SAME
/// validator** (caught by review-agent: previously each call site had
/// its own ad-hoc reimplementation — silent drift risk).
pub fn is_valid_wg_pubkey(s: &str) -> bool {
    if s.len() != 44 {
        return false;
    }
    if !s.ends_with('=') {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
}

/// Fragment-only escape set for the user-id tag in `share_link`'s
/// `#name` portion. Identical to the FRAGMENT set used elsewhere in
/// this crate.
const FRAGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'`')
    .add(b'#')
    .add(b'?');

impl Protocol for WireGuard {
    fn id(&self) -> ProtocolId {
        ProtocolId("wireguard".to_string())
    }

    fn listen_ports(&self) -> &'static [(&'static str, u16)] {
        &[("udp", WIREGUARD_PORT)]
    }

    fn server_inbound(&self, ctx: &RenderCtx<'_>, users: &[User]) -> Result<serde_json::Value> {
        // Server-side material — required.
        let private_key = ctx.require("wireguard.server_private_key")?;
        let listen_port: u16 = ctx
            .secrets
            .get("wireguard.listen_port")
            .and_then(|s| s.parse().ok())
            .unwrap_or(WIREGUARD_PORT);
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
        let listen_port: u16 = ctx
            .secrets
            .get("wireguard.listen_port")
            .and_then(|s| s.parse().ok())
            .unwrap_or(WIREGUARD_PORT);

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
                "endpoint": format!("{}:{listen_port}", ctx.server.address),
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

/// Optional `amneziawg` sub-object — populated when the server has
/// the obfuscation secrets set. Returns `None` when ANY of the
/// required obfs params is missing (we don't half-render — either
/// the full obfuscation profile or none of it, otherwise the client
/// would silently fail to handshake).
///
/// All 9 keys are required together because AmneziaWG's protocol
/// expects them as a coherent set (the H1-H4 magic constants must
/// match between client and server, missing any breaks the
/// handshake).
fn amneziawg_block(ctx: &RenderCtx<'_>) -> Option<serde_json::Value> {
    let keys = [
        "amneziawg.jc",
        "amneziawg.jmin",
        "amneziawg.jmax",
        "amneziawg.s1",
        "amneziawg.s2",
        "amneziawg.h1",
        "amneziawg.h2",
        "amneziawg.h3",
        "amneziawg.h4",
    ];
    // All-or-nothing: if any missing, skip the whole block.
    for k in &keys {
        ctx.secrets.get(*k)?;
    }
    Some(json!({
        "jc":   ctx.secrets.get("amneziawg.jc"),
        "jmin": ctx.secrets.get("amneziawg.jmin"),
        "jmax": ctx.secrets.get("amneziawg.jmax"),
        "s1":   ctx.secrets.get("amneziawg.s1"),
        "s2":   ctx.secrets.get("amneziawg.s2"),
        "h1":   ctx.secrets.get("amneziawg.h1"),
        "h2":   ctx.secrets.get("amneziawg.h2"),
        "h3":   ctx.secrets.get("amneziawg.h3"),
        "h4":   ctx.secrets.get("amneziawg.h4"),
    }))
}

/// Render the actual `.conf` text the share-link encodes. INI-format,
/// LF newlines, opens with a "do-not-edit" warning. Mirrors the conf
/// the AmneziaWG kernel writes server-side — same obfuscation block,
/// peer's keys swapped for client perspective.
///
/// **Private-key sourcing** (per CLAUDE.md "users are low-tech" rule):
///   * `user.wireguard_private` set (= server-generated via
///     `--gen-wireguard`) → conf is ready-to-import, single-action UX;
///     no editor step needed.
///   * `user.wireguard_private` is `None` (= operator-provided pubkey
///     only) → falls back to the legacy `<PASTE YOUR PRIVATE KEY HERE>`
///     placeholder + the comment block instructing the operator to
///     swap in the client-side privkey before forwarding to the user.
fn render_client_conf(ctx: &RenderCtx<'_>, user: &User) -> Result<String> {
    let server_pub = ctx.require("wireguard.server_public_key")?;
    let listen_port: u16 = ctx
        .secrets
        .get("wireguard.listen_port")
        .and_then(|s| s.parse().ok())
        .unwrap_or(WIREGUARD_PORT);

    let mut out = String::with_capacity(512);
    out.push_str("# vpnctl-rendered AmneziaWG client config.\n");
    if user.wireguard_private.is_some() {
        out.push_str("# Private key was server-generated for ");
        out.push_str(&user.id.0);
        out.push_str(" — import this file as-is.\n\n");
    } else {
        out.push_str("# Replace <PASTE YOUR PRIVATE KEY HERE> with the privkey for ");
        out.push_str(&user.id.0);
        out.push('\n');
        out.push_str("# generated locally via `awg genkey`.\n\n");
    }

    out.push_str("[Interface]\n");
    out.push_str("PrivateKey = ");
    out.push_str(
        user.wireguard_private
            .as_deref()
            .unwrap_or(CLIENT_PRIVKEY_PLACEHOLDER),
    );
    out.push('\n');
    out.push_str("Address = 10.66.0.2/32\n");
    out.push_str("DNS = 1.1.1.1\n");
    // AmneziaWG params (only if the server set them — same all-or-nothing
    // contract as the JSON envelope).
    if let Some(amnezia) = amneziawg_block(ctx) {
        let m = amnezia
            .as_object()
            .ok_or_else(|| CoreError::Render("amneziawg block must be a JSON object".into()))?;
        for (key, ini_key) in [
            ("jc", "Jc"),
            ("jmin", "Jmin"),
            ("jmax", "Jmax"),
            ("s1", "S1"),
            ("s2", "S2"),
            ("h1", "H1"),
            ("h2", "H2"),
            ("h3", "H3"),
            ("h4", "H4"),
        ] {
            if let Some(v) = m.get(key).and_then(|x| x.as_str()) {
                out.push_str(ini_key);
                out.push_str(" = ");
                out.push_str(v);
                out.push('\n');
            }
        }
    }
    out.push('\n');

    out.push_str("[Peer]\n");
    out.push_str("PublicKey = ");
    out.push_str(server_pub);
    out.push('\n');
    out.push_str("Endpoint = ");
    out.push_str(&ctx.server.address);
    out.push(':');
    out.push_str(&listen_port.to_string());
    out.push('\n');
    out.push_str("AllowedIPs = 0.0.0.0/0, ::/0\n");
    out.push_str("PersistentKeepalive = 25\n");
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pubkey_shape_check_accepts_valid_44_char_base64() {
        // Real-looking WG pubkey shape: 43 base64 + final '='.
        let k = "qXFvJL5KLmM3Of9hVo5GmJ4n0LB9rWYfV4ZE1XGZJks=";
        assert!(is_valid_wg_pubkey(k));
    }

    #[test]
    fn pubkey_shape_check_rejects_wrong_length() {
        assert!(!is_valid_wg_pubkey("too-short="));
        assert!(!is_valid_wg_pubkey(&"x".repeat(43)));
        assert!(!is_valid_wg_pubkey(&"x".repeat(45)));
    }

    #[test]
    fn pubkey_shape_check_requires_trailing_eq_pad() {
        // Right length, wrong padding.
        let k = "qXFvJL5KLmM3Of9hVo5GmJ4n0LB9rWYfV4ZE1XGZJksA";
        assert!(!is_valid_wg_pubkey(k));
    }

    #[test]
    fn pubkey_shape_check_rejects_invalid_charset() {
        // Right length+padding but contains a `:` (not base64-alphabet).
        let k = "qXFvJL5KLmM3Of:hVo5GmJ4n0LB9rWYfV4ZE1XGZJks=";
        assert!(!is_valid_wg_pubkey(k));
    }
}
