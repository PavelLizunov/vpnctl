use vpnctl_core::url_host::host_for_url;
use vpnctl_core::{CoreError, RenderCtx, Result, User};

use super::amnezia::amneziawg_block;
use super::helpers::{CLIENT_PRIVKEY_PLACEHOLDER, listen_port, peer_octet_for};

/// Public wrapper around the same `.conf` renderer used internally
/// by `share_link` and `amnezia_share_link`. Exposed so the daemon's
/// `.conf` download handler can serve a drag-drop-ready file
/// without going through a `share_link` plus base64-decode dance.
///
/// Returns the full INI body (Interface + Peer sections + AmneziaWG
/// obfs lines when secrets are set). Same error contract as
/// `share_link`: missing `wireguard.server_public_key` returns
/// `MissingSecret`.
pub fn render_client_conf_public(ctx: &RenderCtx<'_>, user: &User) -> Result<String> {
    render_client_conf(ctx, user)
}

/// Render the actual `.conf` text the share-link encodes. INI-format,
/// LF newlines, opens with a "do-not-edit" warning. Mirrors the conf
/// the AmneziaWG kernel writes server-side — same obfuscation block,
/// peer's keys swapped for client perspective.
///
/// **Private-key sourcing** (per CLAUDE.md "users are low-tech" rule):
///
/// - `user.wireguard_private` set (= server-generated via
///   `--gen-wireguard`) → conf is ready-to-import, single-action UX;
///   no editor step needed.
/// - `user.wireguard_private` is `None` (= operator-provided pubkey
///   only) → falls back to the legacy `<PASTE YOUR PRIVATE KEY HERE>`
///   placeholder + the comment block instructing the operator to
///   swap in the client-side privkey before forwarding to the user.
pub(crate) fn render_client_conf(ctx: &RenderCtx<'_>, user: &User) -> Result<String> {
    let server_pub = ctx.require("wireguard.server_public_key")?;
    let listen_port: u16 = listen_port(ctx.secrets);
    let peer_octet = peer_octet_for(ctx, user)?;

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
    out.push_str("Address = 10.66.0.");
    out.push_str(&peer_octet.to_string());
    out.push_str("/32\n");
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
    out.push_str(&host_for_url(&ctx.server.address));
    out.push(':');
    out.push_str(&listen_port.to_string());
    out.push('\n');
    out.push_str("AllowedIPs = 0.0.0.0/0, ::/0\n");
    out.push_str("PersistentKeepalive = 25\n");
    Ok(out)
}
