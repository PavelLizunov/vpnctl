use base64::Engine;
use vpnctl_core::{RenderCtx, User, UserId};

use super::handler::SubError;
use crate::app::AppState;

pub(super) async fn render_v2ray_subscription(
    state: &AppState,
    user: &User,
    ua: Option<&str>,
) -> Result<(UserId, String), SubError> {
    let user_id = user.id.clone();
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
        .subscription_servers_for_user(&user.id)
        .await
        .map_err(|e| SubError::Internal(format!("inventory: {e}")))?;
    let client_singbox = ua
        .map(crate::handlers::vpn_router::client_supports_singbox_transports)
        .unwrap_or(true);
    let mut core_links: Vec<String> = Vec::new();
    let mut singbox_links: Vec<String> = Vec::new();
    for server in &servers {
        if state
            .inv
            .is_server_auto_suppressed(&server.id)
            .await
            .unwrap_or(false)
        {
            continue;
        }
        if state
            .inv
            .client_detour_via(&server.id)
            .await
            .map_err(|e| SubError::Internal(format!("inventory: {e}")))?
            .is_some()
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
    if client_singbox {
        core_links.extend(singbox_links);
    }
    let joined = core_links.join("\n");
    let body = base64::engine::general_purpose::STANDARD.encode(joined.as_bytes());
    Ok((user_id, body))
}
