use axum::extract::{Path, State};
use axum::response::{IntoResponse, Redirect, Response};

use super::super::helpers::{bad_request, internal_error, not_found};
use super::super::legacy::spawn_user_servers_redeploy;
use crate::AppState;
use crate::http_util::path_segment_encode;

/// `POST /admin/servers/{id}/kernels/{kernel}/enable` — add a kernel
/// to a server's runtime set. Mirrors `server_enable_protocol`.
pub(crate) async fn server_enable_kernel(
    State(state): State<AppState>,
    Path((server_id_str, kernel_id_str)): Path<(String, String)>,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id_str.clone());
    let kid = vpnctl_core::KernelId(kernel_id_str.clone());

    let server = match state.inv.get_server(&sid).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return not_found(&format!("no such server '{server_id_str}'"));
        }
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    // Reject unregistered kernel id — same posture as
    // server_enable_protocol: persisting a typo would silently no-op
    // every deploy.
    if state.registry.kernel(&kid).is_none() {
        let known: Vec<String> = state
            .registry
            .kernel_ids()
            .into_iter()
            .map(|k| k.0)
            .collect();
        return bad_request(&format!(
            "unknown kernel '{kernel_id_str}' — registered: {}",
            known.join(", ")
        ));
    }

    let inserted = match state.inv.add_server_kernel(&sid, &kid).await {
        Ok(n) => n,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };

    // NM-10 contract (audit 2026-06-10): a no-op re-POST (inserted == 0)
    // writes NO audit row — unconditional writes polluted the timeline
    // and the `newly_added` flag inside is honest-but-buried.
    if inserted == 1 {
        if let Err(e) = state
            .inv
            .audit(
                "admin",
                "server.kernel.enable",
                Some(&server_id_str),
                Some(&serde_json::json!({
                    "kernel": kernel_id_str,
                    "newly_added": inserted == 1,
                })),
            )
            .await
        {
            tracing::warn!(
                target = "vpnctld::admin",
                server = %server_id_str,
                error = %e,
                "audit write failed for server.kernel.enable"
            );
        }
        spawn_user_servers_redeploy(
            &state,
            vec![server],
            server_id_str.clone(),
            "server.kernel.enable",
        );
    }

    Redirect::to(&format!(
        "/admin/servers/{}/protocols",
        path_segment_encode(&server_id_str)
    ))
    .into_response()
}

/// `POST /admin/servers/{id}/kernels/{kernel}/disable` — remove a
/// kernel. Mirrors `server_disable_protocol`.
pub(crate) async fn server_disable_kernel(
    State(state): State<AppState>,
    Path((server_id_str, kernel_id_str)): Path<(String, String)>,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id_str.clone());
    let kid = vpnctl_core::KernelId(kernel_id_str.clone());

    let server = match state.inv.get_server(&sid).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return not_found(&format!("no such server '{server_id_str}'"));
        }
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };

    let removed = match state.inv.remove_server_kernel(&sid, &kid).await {
        Ok(n) => n,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };

    // NM-10 contract (audit 2026-06-10): a no-op re-POST (removed == 0)
    // writes NO audit row — unconditional writes polluted the timeline
    // and the `was_present` flag inside is honest-but-buried.
    if removed == 1 {
        if let Err(e) = state
            .inv
            .audit(
                "admin",
                "server.kernel.disable",
                Some(&server_id_str),
                Some(&serde_json::json!({
                    "kernel": kernel_id_str,
                    "was_present": removed == 1,
                })),
            )
            .await
        {
            tracing::warn!(
                target = "vpnctld::admin",
                server = %server_id_str,
                error = %e,
                "audit write failed for server.kernel.disable"
            );
        }
        spawn_user_servers_redeploy(
            &state,
            vec![server],
            server_id_str.clone(),
            "server.kernel.disable",
        );
    }

    Redirect::to(&format!(
        "/admin/servers/{}/protocols",
        path_segment_encode(&server_id_str)
    ))
    .into_response()
}
