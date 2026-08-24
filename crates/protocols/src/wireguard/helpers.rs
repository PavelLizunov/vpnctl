use percent_encoding::{AsciiSet, CONTROLS};
use std::collections::HashMap;
use vpnctl_core::{RenderCtx, Result, User};

/// UDP port WireGuard listens on. Public so kernels + tests can format
/// endpoints without duplicating the literal.
pub const WIREGUARD_PORT: u16 = 51820;

/// Effective WireGuard bind port for a server: per-server
/// `wireguard.listen_port` secret, falling back to [`WIREGUARD_PORT`] on
/// absence, a typo, or an explicit zero (same zero-filter policy as
/// `vless_reality::listen_port` and `vless_ws::front_port` — a
/// parsed-but-zero port would bind an ephemeral socket and emit `:0`
/// endpoints). **Single source of truth** — every renderer and
/// `effective_listen_ports` resolve through it, so wg-quick's `ListenPort`,
/// the client endpoints, the firewall/guard declaration and the drift
/// table cannot diverge.
pub(crate) fn listen_port(secrets: &HashMap<String, String>) -> u16 {
    secrets
        .get("wireguard.listen_port")
        .and_then(|s| s.parse::<u16>().ok())
        .filter(|&p| p != 0)
        .unwrap_or(WIREGUARD_PORT)
}

/// Default tunnel-side server CIDR. `/24` gives 254 peer slots — more
/// than enough for a single-operator homelab.
pub(crate) const DEFAULT_SERVER_CIDR: &str = "10.66.0.1/24";

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
pub(crate) const FRAGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'`')
    .add(b'#')
    .add(b'?');

/// Compute the per-user `/32` octet for the target user on this
/// server. Thin wrapper around the shared `wg_addressing` helper.
///
/// Semantics (per `wg_addressing::peer_octet_in_slash24`):
///   * `ctx.peers` empty → `Ok(2)` legacy single-user fallback
///     (kept for byte-equality with pre-2026-05-17 clients holding
///     a `.conf` rendered without `with_peers`).
///   * `ctx.peers` populated + user found → `Ok(2 + idx)`.
///   * `ctx.peers` populated + user MISSING → `Err(Render)` —
///     tightened contract from the pre-extraction version that
///     silently returned 2; the caller built `RenderCtx` for the
///     wrong server.
pub(crate) fn peer_octet_for(ctx: &RenderCtx<'_>, user: &User) -> Result<u16> {
    crate::wg_addressing::peer_octet_in_slash24(ctx, user, 2)
}
