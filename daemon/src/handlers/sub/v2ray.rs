use base64::Engine;
use vpnctl_core::{RenderCtx, User, UserId};

use super::handler::SubError;
use crate::app::AppState;

/// 2026-05-23 quickfix (Pavel: «через V2raytun наш QR не работает»).
/// V2Ray-family clients (v2rayN, v2rayNG, v2rayTun, Shadowrocket,
/// Streisand, Quantumult, …) expect the classic «base64-encoded
/// line-separated raw URIs» subscription format. They CAN'T parse
/// sing-box JSON. The ninitux endpoint already does this via
/// `vpn_router::is_vpn_client_ua` content-negotiation; mirroring
/// the same dispatch here means the legacy `/sub/<token>` URL
/// works for both V2Ray-family clients AND sing-box/Hiddify.
///
/// **Returns:** the base64 subscription body for the resolved user.
/// Takes an ALREADY-RESOLVED `&User` (not a token) — the handler runs
/// the per-token ban + rate-limit gates on the resolved user BEFORE
/// dispatching here, so this path can no longer skip those defenses
/// (the original bug). Disabled users get an empty body.
pub(super) async fn render_v2ray_subscription(
    state: &AppState,
    user: &User,
    ua: Option<&str>,
) -> Result<(UserId, String), SubError> {
    let user_id = user.id.clone();
    // Disabled-user check — same semantics as the JSON path: empty
    // body. V2Ray clients tolerate an empty subscription as
    // «nothing to import», which is the right surface.
    if user.disabled {
        tracing::info!(
            target = "vpnctld::sub",
            user = %user_id.0,
            "user is disabled — returning empty v2ray sub"
        );
        return Ok((user_id, String::new()));
    }
    let servers = state
        .inv
        .servers_for_user(&user.id)
        .await
        .map_err(|e| SubError::Internal(format!("inventory: {e}")))?;
    // Whether THIS client can parse the sing-box-only transports
    // (Hysteria2 / TUIC / AnyTLS). V2Ray/Xray-core clients (V2rayTun,
    // v2rayN/NG) can't, and a leading `hysteria2://` entry breaks their
    // whole import — so they get VLESS-family only. Unknown/sing-box UAs
    // stay permissive. 2026-06-16 fix.
    let client_singbox = ua
        .map(crate::handlers::vpn_router::client_supports_singbox_transports)
        .unwrap_or(true);
    // Split by capability so VLESS-family (universally parsed) is always
    // emitted FIRST — a client that chokes on a trailing sing-box entry
    // has, by then, already imported the configs everyone supports.
    let mut core_links: Vec<String> = Vec::new();
    let mut singbox_links: Vec<String> = Vec::new();
    for server in &servers {
        // Auto-suppress (migration 0030): skip a server the health
        // monitor flagged unreachable (per-server opt-in); auto-restores
        // on recovery. DB error → don't suppress (keep it in the sub).
        if state
            .inv
            .is_server_auto_suppressed(&server.id)
            .await
            .unwrap_or(false)
        {
            continue;
        }
        let secrets = state
            .inv
            .list_server_secrets(&server.id)
            .await
            .map_err(|e| SubError::Internal(format!("inventory: {e}")))?;
        let ctx = RenderCtx::new(server, &secrets);
        let per_server_user = state
            .inv
            .user_with_per_server_uuid(user, &server.id)
            .await
            .map_err(|e| SubError::Internal(format!("inventory: {e}")))?;
        let visible_protocols = state
            .inv
            .visible_protocols_for_subscription(&user.id, &server.id)
            .await
            .map_err(|e| SubError::Internal(format!("inventory: {e}")))?;
        let visible_set: std::collections::HashSet<&vpnctl_core::ProtocolId> =
            visible_protocols.iter().collect();
        for pid in &server.enabled_protocols {
            if !visible_set.contains(pid) {
                continue;
            }
            let Some(proto) = state.registry.protocol(pid) else {
                continue;
            };
            match proto.share_link(&ctx, &per_server_user) {
                Ok(link) => {
                    // V2Ray-family clients only understand a subset of
                    // share-link schemes. WireGuard's `wireguard://?conf=…`
                    // would be silently dropped at best, crash the parser at
                    // worst — so neither bucket takes it. The sing-box-only transports go
                    // to `singbox_links` and are emitted only to clients
                    // that can parse them (see `client_singbox`).
                    if link.starts_with("vless://")
                        || link.starts_with("vmess://")
                        || link.starts_with("trojan://")
                        || link.starts_with("ss://")
                        || link.starts_with("ssr://")
                    {
                        core_links.push(link);
                    } else if link.starts_with("hysteria2://")
                        || link.starts_with("hy2://")
                        || link.starts_with("tuic://")
                        || link.starts_with("anytls://")
                    {
                        singbox_links.push(link);
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        target = "vpnctld::sub",
                        server = %server.id,
                        protocol = %pid,
                        error = %e,
                        "share_link failed for v2ray sub; skipping"
                    );
                }
            }
        }
    }
    // VLESS-family first; append the sing-box transports only for
    // clients that can parse them.
    if client_singbox {
        core_links.extend(singbox_links);
    }
    let joined = core_links.join("\n");
    let body = base64::engine::general_purpose::STANDARD.encode(joined.as_bytes());
    Ok((user_id, body))
}
