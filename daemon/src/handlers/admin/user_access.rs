//! User-access admin handlers: grant / revoke a user's access to a
//! server from the user-detail page. Extracted from `legacy.rs` as
//! part of the admin submodules refactor.

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Redirect, Response};

use super::helpers::{bad_request, internal_error, not_found, user_not_found};
use super::legacy::spawn_user_servers_redeploy;
use crate::AppState;
use crate::http_util::path_segment_encode;

/// `POST /admin/users/{id}/grants/{server_id}` — grant the user
/// access to the server. Idempotent: re-granting an existing pair
/// is a no-op at the SQL layer (`ON CONFLICT … DO NOTHING`), but the
/// handler still writes an audit row each time so operators can see
/// re-grant attempts in the timeline.
///
/// Both ids are validated to exist before the mutation — unknown
/// user → 404, unknown server → 404 with the same canonical body
/// shape. The `vpnctl admin: no such X` prefix is in `error_text`.
pub(crate) async fn user_grant_server(
    State(state): State<AppState>,
    Path((user_id_str, server_id_str)): Path<(String, String)>,
) -> Response {
    let uid = vpnctl_core::UserId(user_id_str.clone());
    let sid = vpnctl_core::ServerId(server_id_str.clone());

    // Both existence checks before mutation — same convention as
    // user_regen_sub_token. Prevents a generic 500 from "no such row"
    // surfaces in the inventory.
    match state.inv.get_user(&uid).await {
        Ok(Some(_)) => {}
        Ok(None) => return user_not_found(&user_id_str),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }
    let server = match state.inv.get_server(&sid).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return not_found(&format!("no such server '{server_id_str}'"));
        }
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };

    // Membership BEFORE the grant — audit only a NEW grant (an
    // idempotent re-grant must not falsely re-mark the server
    // pending-deploy; see `server_grant_user`).
    let was_granted = match state.inv.servers_for_user(&uid).await {
        Ok(v) => v.iter().any(|s| s.id == sid),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    if let Err(e) = state.inv.grant(&uid, &sid).await {
        return match e {
            vpnctl_inventory::SqliteInventoryError::Invalid(message) => bad_request(&message),
            other => internal_error(anyhow::Error::new(other)),
        };
    }
    // Canonical grant-audit shape (2026-06-04 unification): per-user
    // `user.grant` with target = USER id — what the pending-deploy
    // detector keys on. Previously this wrote `action="grant",
    // target=<server>`, which the detector never saw.
    if !was_granted {
        if let Err(e) = state
            .inv
            .audit(
                "admin",
                "user.grant",
                Some(&user_id_str),
                Some(&serde_json::json!({
                    "server": server_id_str,
                    "source": "user-detail",
                })),
            )
            .await
        {
            tracing::warn!(
                target = "vpnctld::admin",
                user = %user_id_str,
                server = %server_id_str,
                error = %e,
                "audit write failed for user.grant — mutation already committed"
            );
        }
        // Auto-deploy so the new UUID lands in the node's users[]
        // (HANDOFF §4.1: grant without deploy = «connects but no
        // internet»). Only on an ACTUAL new grant — a no-op re-grant
        // must not restart the node.
        spawn_user_servers_redeploy(&state, vec![server], user_id_str.clone(), "user.grant");
    }
    Redirect::to(&format!(
        "/admin/users/{}/access",
        path_segment_encode(&user_id_str)
    ))
    .into_response()
}

/// `POST /admin/users/{id}/grants/{server_id}/revoke` — revoke the
/// grant. Idempotent like `grant`; revoking a non-existent grant is
/// a no-op at the SQL layer but still audited (the operator's
/// intent is recorded regardless of pre-state).
pub(crate) async fn user_revoke_server(
    State(state): State<AppState>,
    Path((user_id_str, server_id_str)): Path<(String, String)>,
) -> Response {
    let uid = vpnctl_core::UserId(user_id_str.clone());
    let sid = vpnctl_core::ServerId(server_id_str.clone());

    match state.inv.get_user(&uid).await {
        Ok(Some(_)) => {}
        Ok(None) => return user_not_found(&user_id_str),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }
    let server = match state.inv.get_server(&sid).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return not_found(&format!("no such server '{server_id_str}'"));
        }
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };

    // Membership BEFORE the revoke — audit only an ACTUAL revoke
    // (mirror of the grant paths; see `server_revoke_user`).
    let was_granted = match state.inv.servers_for_user(&uid).await {
        Ok(v) => v.iter().any(|s| s.id == sid),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    if let Err(e) = state.inv.revoke(&uid, &sid).await {
        return internal_error(anyhow::Error::new(e));
    }
    // Canonical per-user `user.revoke` (target = USER id) — visible to
    // the pending-deploy detector, unlike the old server-targeted row.
    if was_granted {
        if let Err(e) = state
            .inv
            .audit(
                "admin",
                "user.revoke",
                Some(&user_id_str),
                Some(&serde_json::json!({
                    "server": server_id_str,
                    "source": "user-detail",
                })),
            )
            .await
        {
            tracing::warn!(
                target = "vpnctld::admin",
                user = %user_id_str,
                server = %server_id_str,
                error = %e,
                "audit write failed for user.revoke — mutation already committed"
            );
        }
        // Auto-deploy so the revoked UUID actually leaves the node's
        // users[] (mirror of the grant path; same best-effort shape as
        // disable/delete).
        spawn_user_servers_redeploy(&state, vec![server], user_id_str.clone(), "user.revoke");
    }
    Redirect::to(&format!(
        "/admin/users/{}/access",
        path_segment_encode(&user_id_str)
    ))
    .into_response()
}
