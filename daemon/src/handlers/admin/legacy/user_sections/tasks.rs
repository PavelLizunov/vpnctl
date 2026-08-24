use std::sync::Arc;

use crate::AppState;

/// Background, best-effort redeploy of `servers` after an inventory
/// mutation that changes node membership (grant / revoke / disable /
/// enable / delete) so the change lands on the nodes WITHOUT a manual
/// «Deploy all». Mirrors that button, scoped to the affected servers.
/// Without this, a grant only writes inv.db: the sub URI appears
/// instantly but the UUID never reaches the node's `users[]`, so the
/// REALITY handshake succeeds, VLESS-auth rejects, and the client is
/// silently forwarded to the cover dest — «connects but no internet»
/// (HANDOFF 2026-07-08 §4.1). `servers` must be captured by the caller
/// at the right moment — for a DELETE, BEFORE the cascade drops the
/// grants. Empty → no-op. `subject` labels the audit row: user id for
/// user-scoped triggers, server id for server-side bulk grant/revoke.
/// NOTE: apply_config restarts sing-box, so other users on a node see
/// a brief blip — inherent to any config change.
pub(crate) fn spawn_user_servers_redeploy(
    state: &AppState,
    servers: Vec<vpnctl_core::Server>,
    subject: String,
    trigger: &'static str,
) {
    if servers.is_empty() {
        return;
    }
    let inv = state.inv.clone();
    let registry = Arc::clone(&state.registry);
    let key_path = crate::app::deploy_key_path();
    let server_ids: Vec<String> = servers.iter().map(|s| s.id.0.clone()).collect();
    // Server-side bulk triggers target a SERVER; keep them out of the
    // `user.*` audit namespace so user-timeline filters don't surface
    // server-targeted rows (review 2026-07-08).
    let action: &'static str = if trigger.starts_with("server.") {
        "server.autodeploy"
    } else {
        "user.autodeploy"
    };
    tokio::spawn(async move {
        let errors = crate::wizard_bootstrap::redeploy_servers_collect_errors(
            servers,
            inv.clone(),
            registry,
            key_path,
        )
        .await;
        if errors.is_empty() {
            tracing::info!(
                target = "vpnctld::admin",
                subject = %subject,
                trigger,
                "auto-deploy applied (config re-rendered + sing-box reloaded)"
            );
        } else {
            tracing::warn!(
                target = "vpnctld::admin",
                subject = %subject,
                trigger,
                errors = ?errors,
                "auto-deploy: some servers failed to apply — retry via Deploy all"
            );
        }
        let _ = inv
            .audit(
                "admin",
                action,
                Some(&subject),
                Some(&serde_json::json!({
                    "trigger": trigger,
                    "servers": server_ids,
                    "ok": errors.is_empty(),
                    "errors": errors,
                })),
            )
            .await;
    });
}
