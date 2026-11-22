use axum::extract::{Path, State};
use axum::response::{IntoResponse, Redirect, Response};

use super::grant_targets;
use super::helpers::{bad_request, internal_error, not_found, user_not_found};
use super::legacy::spawn_user_servers_redeploy;
use crate::AppState;
use crate::http_util::path_segment_encode;

pub(crate) async fn user_grant_server(
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

    // A no-op re-grant must stay idempotent even if the node's SSH check has
    // since gone stale; only a new grant needs a verified deploy-key path.
    let already_granted = match state.inv.servers_for_user(&uid).await {
        Ok(servers) => servers.iter().any(|granted| granted.id == sid),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    if !already_granted {
        let readiness = grant_targets::read(&state, &server).await;
        if !readiness.is_eligible() {
            return bad_request(&grant_targets::blocked_message(&server, readiness));
        }
    }

    let granted = match state
        .inv
        .grant_audited(&uid, &sid, "admin", "user-detail")
        .await
    {
        Ok(granted) => granted,
        Err(e) => {
            return match e {
                vpnctl_inventory::SqliteInventoryError::Invalid(message) => bad_request(&message),
                other => internal_error(anyhow::Error::new(other)),
            };
        }
    };
    if granted {
        spawn_user_servers_redeploy(&state, vec![server], user_id_str.clone(), "user.grant");
    }
    Redirect::to(&format!(
        "/admin/users/{}/access",
        path_segment_encode(&user_id_str)
    ))
    .into_response()
}

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

    let revoked = match state
        .inv
        .revoke_audited(&uid, &sid, "admin", "user-detail")
        .await
    {
        Ok(revoked) => revoked,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    if revoked {
        spawn_user_servers_redeploy(&state, vec![server], user_id_str.clone(), "user.revoke");
    }
    Redirect::to(&format!(
        "/admin/users/{}/access",
        path_segment_encode(&user_id_str)
    ))
    .into_response()
}
