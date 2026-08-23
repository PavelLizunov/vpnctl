use vpnctl_core::Server;
use vpnctl_inventory::SqliteInventory;

/// Write the DISTINCT `kernel.update` audit row for an SSE kernel-update
/// pass. Kept separate from `server.deploy` (NM-13 dot-convention naming)
/// so the audit timeline distinguishes a binary-only kernel upgrade from
/// a full config re-deploy. Payload: the kernels touched, their
/// before/after versions, any ssh errors, and `via:\"sse\"`. Audit failure
/// is non-fatal (logged) — the update already happened.
#[allow(clippy::too_many_arguments)]
pub(super) async fn write_update_kernels_audit(
    inv: &SqliteInventory,
    server: &Server,
    kernels_touched: &[String],
    versions_before: &[serde_json::Value],
    versions_after: &[serde_json::Value],
    ssh_errors: &[String],
    ssh_skip_reason: Option<&'static str>,
) {
    if let Err(e) = inv
        .audit(
            "admin",
            "kernel.update",
            Some(&server.id.0),
            Some(&serde_json::json!({
                "kernels": kernels_touched,
                "versions_before": versions_before,
                "versions_after": versions_after,
                "ssh_errors": ssh_errors,
                "ssh_skip_reason": ssh_skip_reason,
                "via": "sse",
            })),
        )
        .await
    {
        tracing::warn!(
            target = "vpnctld::update_kernels",
            server = %server.id.0,
            error = %e,
            "audit write failed for kernel.update (sse)"
        );
    }
}

pub(crate) fn deploy_audit_action(
    ssh_errors: &[String],
    configs_applied: usize,
    ssh_skip_reason: Option<&str>,
    inputs_changed: bool,
) -> &'static str {
    if ssh_skip_reason.is_some() {
        "server.deploy.skipped"
    } else if !ssh_errors.is_empty() {
        "server.deploy.failed"
    } else if inputs_changed {
        "server.deploy.stale"
    } else if configs_applied == 0 {
        "server.deploy.skipped"
    } else {
        "server.deploy"
    }
}

/// Write the deploy-attempt audit row for an SSE re-deploy. Only a
/// fully successful pass that applied at least one config uses the canonical
/// `server.deploy` action consumed by pending-deploy detection. Same
/// payload shape as the synchronous `server_deploy` handler
/// (`bootstrapped`, `kernels`, `protocols`, `ssh_kernels_pushed`,
/// `ssh_errors`, `ssh_config_bytes_total`, `ssh_skip_reason`) plus
/// `via:\"sse\"`. Shared between the skip-reason early-exit and the
/// normal completion so both paths leave an identical timeline entry.
/// Audit failure is non-fatal (logged) — the deploy already happened.
#[allow(clippy::too_many_arguments)]
pub(super) async fn write_deploy_audit(
    inv: &SqliteInventory,
    server: &Server,
    bootstrapped: &[&'static str],
    ssh_kernels_pushed: &[String],
    ssh_errors: &[String],
    total_config_bytes: usize,
    configs_applied: usize,
    ssh_skip_reason: Option<&'static str>,
    inputs_changed: bool,
    expected_revision: &str,
) -> &'static str {
    let mut action =
        deploy_audit_action(ssh_errors, configs_applied, ssh_skip_reason, inputs_changed);
    let payload = serde_json::json!({
        "bootstrapped": bootstrapped,
        "kernels": server.kernels.iter().map(|k| &k.0).collect::<Vec<_>>(),
        "protocols": server.enabled_protocols.iter().map(|p| &p.0).collect::<Vec<_>>(),
        "ssh_kernels_pushed": ssh_kernels_pushed,
        "ssh_errors": ssh_errors,
        "ssh_config_bytes_total": total_config_bytes,
        "configs_applied": configs_applied,
        "ssh_skip_reason": ssh_skip_reason,
        "inputs_changed": inputs_changed,
        "via": "sse",
    });
    let result = if action == "server.deploy" {
        inv.audit_deploy_if_revision("admin", &server.id, expected_revision, &payload)
            .await
            .map(|matches| {
                if !matches {
                    action = "server.deploy.stale";
                }
            })
    } else {
        inv.audit("admin", action, Some(&server.id.0), Some(&payload))
            .await
    };
    if let Err(e) = result {
        action = "server.deploy.failed";
        tracing::warn!(
            target = "vpnctld::redeploy",
            server = %server.id.0,
            error = %e,
            "audit write failed for deploy attempt (sse)"
        );
    }
    action
}
