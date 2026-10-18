use std::sync::Arc;

use crate::AppState;

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
    let action: &'static str = if trigger.starts_with("server.") {
        "server.autodeploy"
    } else {
        "user.autodeploy"
    };
    let completion =
        crate::wizard_bootstrap::queue_servers_redeploy(servers, &inv, &registry, &key_path);
    tokio::spawn(async move {
        let errors = completion.await;
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
