use axum::extract::{Path, State};
use axum::response::{IntoResponse, Redirect, Response};

use super::super::helpers::{bad_request, internal_error, not_found};
use super::super::legacy::spawn_user_servers_redeploy;
use crate::AppState;
use crate::http_util::path_segment_encode;

/// `POST /admin/servers/{id}/protocols/{proto}/enable` — add a
/// protocol to a server's `enabled_protocols`. Idempotent at SQL.
/// Returns 404 if server doesn't exist, 400 if protocol id isn't
/// registered with the daemon (no point persisting a string that
/// nothing knows how to render). Audit row written. Always
/// redirects back to the server-detail page.
pub(crate) async fn server_enable_protocol(
    State(state): State<AppState>,
    Path((server_id_str, protocol_id_str)): Path<(String, String)>,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id_str.clone());
    let pid = vpnctl_core::ProtocolId(protocol_id_str.clone());

    // Existence check (404 if no server).
    let server = match state.inv.get_server(&sid).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return not_found(&format!("no such server '{server_id_str}'"));
        }
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    // Reject unregistered protocol id — persisting a typo would
    // silently no-op every render+deploy from now on.
    if state.registry.protocol(&pid).is_none() {
        let known: Vec<String> = state
            .registry
            .protocol_ids()
            .into_iter()
            .map(|p| p.0)
            .collect();
        return bad_request(&format!(
            "unknown protocol '{protocol_id_str}' — registered: {}",
            known.join(", ")
        ));
    }

    let inserted = match state.inv.add_server_protocol(&sid, &pid).await {
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
                "server.protocol.enable",
                Some(&server_id_str),
                Some(&serde_json::json!({
                    "protocol": protocol_id_str,
                    "newly_added": inserted == 1,
                })),
            )
            .await
        {
            tracing::warn!(
                target = "vpnctld::admin",
                server = %server_id_str,
                error = %e,
                "audit write failed for server.protocol.enable"
            );
        }
        // Auto-deploy — the protocol change must land on the node;
        // without this the rendered config diverges from inventory.
        spawn_user_servers_redeploy(
            &state,
            vec![server],
            server_id_str.clone(),
            "server.protocol.enable",
        );
    }

    Redirect::to(&format!(
        "/admin/servers/{}/protocols#enabled-protocols",
        path_segment_encode(&server_id_str)
    ))
    .into_response()
}

/// `POST /admin/servers/{id}/protocols/{proto}/disable` — remove a
/// protocol from a server's `enabled_protocols`. Idempotent. Same
/// 404/audit/redirect posture as `server_enable_protocol`.
pub(crate) async fn server_disable_protocol(
    State(state): State<AppState>,
    Path((server_id_str, protocol_id_str)): Path<(String, String)>,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id_str.clone());
    let pid = vpnctl_core::ProtocolId(protocol_id_str.clone());

    let server = match state.inv.get_server(&sid).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return not_found(&format!("no such server '{server_id_str}'"));
        }
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };

    let removed = match state.inv.remove_server_protocol(&sid, &pid).await {
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
                "server.protocol.disable",
                Some(&server_id_str),
                Some(&serde_json::json!({
                    "protocol": protocol_id_str,
                    "was_present": removed == 1,
                })),
            )
            .await
        {
            tracing::warn!(
                target = "vpnctld::admin",
                server = %server_id_str,
                error = %e,
                "audit write failed for server.protocol.disable"
            );
        }
        spawn_user_servers_redeploy(
            &state,
            vec![server],
            server_id_str.clone(),
            "server.protocol.disable",
        );
    }

    Redirect::to(&format!(
        "/admin/servers/{}/protocols#enabled-protocols",
        path_segment_encode(&server_id_str)
    ))
    .into_response()
}

/// `POST /admin/servers/{sid}/protocols/{pid}/hide` — flip
/// `server_protocols.hidden = 1` for (sid, pid). Render path
/// (sub.rs + vpn_router.rs) immediately stops emitting this
/// protocol for any user's next subscription pull. Existing
/// cached client URIs keep working (the live sing-box inbound is
/// untouched).
pub(crate) async fn server_protocol_hide(
    State(state): State<AppState>,
    Path((server_id_str, protocol_id_str)): Path<(String, String)>,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id_str.clone());
    let pid = vpnctl_core::ProtocolId(protocol_id_str.clone());
    match state.inv.set_server_protocol_hidden(&sid, &pid, true).await {
        Ok(()) => Redirect::to(&format!(
            "/admin/servers/{}/protocols#enabled-protocols",
            path_segment_encode(&server_id_str)
        ))
        .into_response(),
        Err(vpnctl_inventory::SqliteInventoryError::Invalid(msg)) => bad_request(&msg),
        Err(e) => internal_error(anyhow::Error::new(e)),
    }
}

/// `POST /admin/servers/{sid}/protocols/{pid}/unhide` — flip
/// `server_protocols.hidden = 0` for (sid, pid). Render path
/// resumes emitting this protocol on next subscription pull.
pub(crate) async fn server_protocol_unhide(
    State(state): State<AppState>,
    Path((server_id_str, protocol_id_str)): Path<(String, String)>,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id_str.clone());
    let pid = vpnctl_core::ProtocolId(protocol_id_str.clone());
    match state
        .inv
        .set_server_protocol_hidden(&sid, &pid, false)
        .await
    {
        Ok(()) => Redirect::to(&format!(
            "/admin/servers/{}/protocols#enabled-protocols",
            path_segment_encode(&server_id_str)
        ))
        .into_response(),
        Err(vpnctl_inventory::SqliteInventoryError::Invalid(msg)) => bad_request(&msg),
        Err(e) => internal_error(anyhow::Error::new(e)),
    }
}
