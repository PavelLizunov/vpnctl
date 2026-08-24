use axum::extract::{Path, State};
use axum::response::{IntoResponse, Redirect, Response};

use crate::AppState;
use crate::handlers::admin::helpers::{bad_request, internal_error};
use crate::http_util::path_segment_encode;

// ────────────────────────────────────────────────────────────────────────
// Migration 0018 — per-(server, protocol) hide + per-(user, server,
// protocol) deny override. Four POST handlers below mirror the
// inventory API (`set_server_protocol_hidden`, `set_grant_protocol_override`)
// 1:1. Each returns 303 to the originating page (server-detail or
// user-detail) so the operator sees post-mutation state without a
// stale form re-submit risk. Audit row is written by the inventory
// layer inside the same transaction — handler itself does NOT call
// `state.inv.audit()` (avoids double-audit).
//
// Convention: action is implied by the path suffix (`/hide` /
// `/unhide` / `/disable` / `/enable`) rather than a `value=` form
// field — keeps the markup template-side simple (one form per
// action button instead of a hidden input + JS).
// ────────────────────────────────────────────────────────────────────────

/// `POST /admin/users/{uid}/grants/{sid}/protocols/{pid}/disable` —
/// insert `grant_protocol_overrides` row with `state='disabled'`.
/// Render path skips this protocol for THIS user's subscription
/// while still emitting it for every other user.
pub(crate) async fn grant_protocol_disable(
    State(state): State<AppState>,
    Path((user_id_str, server_id_str, protocol_id_str)): Path<(String, String, String)>,
) -> Response {
    let uid = vpnctl_core::UserId(user_id_str.clone());
    let sid = vpnctl_core::ServerId(server_id_str.clone());
    let pid = vpnctl_core::ProtocolId(protocol_id_str.clone());
    match state
        .inv
        .set_grant_protocol_override(&uid, &sid, &pid, true)
        .await
    {
        Ok(()) => Redirect::to(&format!(
            "/admin/users/{}/access#server-access",
            path_segment_encode(&user_id_str)
        ))
        .into_response(),
        Err(vpnctl_inventory::SqliteInventoryError::Invalid(msg)) => bad_request(&msg),
        Err(e) => internal_error(anyhow::Error::new(e)),
    }
}

/// `POST /admin/users/{uid}/grants/{sid}/protocols/{pid}/enable` —
/// DELETE the per-user override row, returning the (user, server,
/// protocol) tuple to inherit-from-server-visibility.
pub(crate) async fn grant_protocol_enable(
    State(state): State<AppState>,
    Path((user_id_str, server_id_str, protocol_id_str)): Path<(String, String, String)>,
) -> Response {
    let uid = vpnctl_core::UserId(user_id_str.clone());
    let sid = vpnctl_core::ServerId(server_id_str.clone());
    let pid = vpnctl_core::ProtocolId(protocol_id_str.clone());
    match state
        .inv
        .set_grant_protocol_override(&uid, &sid, &pid, false)
        .await
    {
        Ok(()) => Redirect::to(&format!(
            "/admin/users/{}/access#server-access",
            path_segment_encode(&user_id_str)
        ))
        .into_response(),
        Err(vpnctl_inventory::SqliteInventoryError::Invalid(msg)) => bad_request(&msg),
        Err(e) => internal_error(anyhow::Error::new(e)),
    }
}
