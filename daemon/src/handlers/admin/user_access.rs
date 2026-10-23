use axum::extract::{Path, State};
use axum::response::{IntoResponse, Redirect, Response};

use super::helpers::{
    bad_request, internal_error, not_found, user_not_found, valid_server_id, valid_user_id,
};
use super::legacy::spawn_user_servers_redeploy;
use crate::AppState;
use crate::http_util::path_segment_encode;

pub(crate) async fn user_grant_server(
    State(state): State<AppState>,
    Path((user_id_str, server_id_str)): Path<(String, String)>,
) -> Response {
    if !valid_user_id(&user_id_str) {
        return bad_request(&format!("invalid user id format '{user_id_str}'"));
    }
    if !valid_server_id(&server_id_str) {
        return bad_request(&format!("invalid server id format '{server_id_str}'"));
    }
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
    if !valid_user_id(&user_id_str) {
        return bad_request(&format!("invalid user id format '{user_id_str}'"));
    }
    if !valid_server_id(&server_id_str) {
        return bad_request(&format!("invalid server id format '{server_id_str}'"));
    }
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

    let was_granted = match state.inv.servers_for_user(&uid).await {
        Ok(v) => v.iter().any(|s| s.id == sid),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    if let Err(e) = state.inv.revoke(&uid, &sid).await {
        return internal_error(anyhow::Error::new(e));
    }
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
        spawn_user_servers_redeploy(&state, vec![server], user_id_str.clone(), "user.revoke");
    }
    Redirect::to(&format!(
        "/admin/users/{}/access",
        path_segment_encode(&user_id_str)
    ))
    .into_response()
}
