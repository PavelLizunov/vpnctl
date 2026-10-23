use axum::extract::{Path, State};
use axum::response::{IntoResponse, Redirect, Response};

use super::super::helpers::{
    bad_request, internal_error, not_found, user_not_found, valid_server_id, valid_user_id,
};
use super::super::legacy::spawn_user_servers_redeploy;
use crate::AppState;
use crate::http_util::{form_field, path_segment_encode};

pub(crate) async fn server_grant_user(
    State(state): State<AppState>,
    Path((server_id_str, user_id_str)): Path<(String, String)>,
) -> Response {
    if !valid_server_id(&server_id_str) {
        return bad_request(&format!("invalid server id format '{server_id_str}'"));
    }
    if !valid_user_id(&user_id_str) {
        return bad_request(&format!("invalid user id format '{user_id_str}'"));
    }
    let sid = vpnctl_core::ServerId(server_id_str.clone());
    let uid = vpnctl_core::UserId(user_id_str.clone());
    let server = match state.inv.get_server(&sid).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return not_found(&format!("no such server '{server_id_str}'"));
        }
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    match state.inv.get_user(&uid).await {
        Ok(Some(_)) => {}
        Ok(None) => return user_not_found(&user_id_str),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }

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
                    "source": "server-detail",
                })),
            )
            .await
        {
            tracing::warn!(target = "vpnctld::admin", error = %e, "audit write failed for user.grant");
        }
        spawn_user_servers_redeploy(&state, vec![server], user_id_str.clone(), "user.grant");
    }
    Redirect::to(&format!(
        "/admin/servers/{}/grants",
        path_segment_encode(&server_id_str)
    ))
    .into_response()
}

pub(crate) async fn server_grant_user_form(
    State(state): State<AppState>,
    Path(server_id_str): Path<String>,
    body: String,
) -> Response {
    let Some(user_id) = crate::http_util::form_field(&body, "user_id") else {
        return bad_request("missing form field 'user_id'");
    };
    let user_id = user_id.trim().to_string();
    if user_id.is_empty() {
        return bad_request("empty 'user_id'");
    }
    server_grant_user(State(state), Path((server_id_str, user_id))).await
}

pub(crate) async fn server_revoke_user(
    State(state): State<AppState>,
    Path((server_id_str, user_id_str)): Path<(String, String)>,
) -> Response {
    if !valid_server_id(&server_id_str) {
        return bad_request(&format!("invalid server id format '{server_id_str}'"));
    }
    if !valid_user_id(&user_id_str) {
        return bad_request(&format!("invalid user id format '{user_id_str}'"));
    }
    let sid = vpnctl_core::ServerId(server_id_str.clone());
    let uid = vpnctl_core::UserId(user_id_str.clone());
    let server = match state.inv.get_server(&sid).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return not_found(&format!("no such server '{server_id_str}'"));
        }
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    match state.inv.get_user(&uid).await {
        Ok(Some(_)) => {}
        Ok(None) => return user_not_found(&user_id_str),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }
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
                    "source": "server-detail",
                })),
            )
            .await
        {
            tracing::warn!(target = "vpnctld::admin", error = %e, "audit write failed for user.revoke");
        }
        spawn_user_servers_redeploy(&state, vec![server], user_id_str.clone(), "user.revoke");
    }
    Redirect::to(&format!(
        "/admin/servers/{}/grants",
        path_segment_encode(&server_id_str)
    ))
    .into_response()
}

pub(crate) async fn server_grant_all_users(
    State(state): State<AppState>,
    Path(server_id_str): Path<String>,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id_str.clone());
    let server = match state.inv.get_server(&sid).await {
        Ok(Some(s)) => s,
        Ok(None) => return not_found(&format!("no such server '{server_id_str}'")),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    match state.inv.get_server_role(&server.id).await {
        Ok(vpnctl_inventory::ServerRole::VpnExit) => {}
        Ok(vpnctl_inventory::ServerRole::WorkloadOnly) => {
            return bad_request(&format!(
                "server '{server_id_str}' is workload-only and cannot receive grants"
            ));
        }
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }
    let users = match state.inv.list_users().await {
        Ok(u) => u,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    let already_granted: std::collections::HashSet<vpnctl_core::UserId> =
        match state.inv.users_for_server(&sid).await {
            Ok(v) => v.into_iter().map(|u| u.id).collect(),
            Err(e) => return internal_error(anyhow::Error::new(e)),
        };
    let mut granted: u32 = 0;
    let mut already: u32 = 0;
    let mut failed: u32 = 0;
    let mut skipped_disabled: u32 = 0;
    for u in &users {
        if u.disabled {
            skipped_disabled += 1;
            continue;
        }
        if already_granted.contains(&u.id) {
            already += 1;
            continue;
        }
        match state.inv.grant(&u.id, &sid).await {
            Ok(()) => {
                granted += 1;
                if let Err(e) = state
                    .inv
                    .audit(
                        "admin",
                        "user.grant",
                        Some(&u.id.0),
                        Some(&serde_json::json!({
                            "server": server_id_str,
                            "source": "server-detail.bulk",
                        })),
                    )
                    .await
                {
                    tracing::warn!(
                        target = "vpnctld::admin",
                        server = %server_id_str,
                        user = %u.id,
                        error = %e,
                        "audit write failed for user.grant (bulk) — mutation already committed"
                    );
                }
            }
            Err(e) => {
                failed += 1;
                tracing::warn!(
                    target = "vpnctld::admin",
                    server = %server_id_str,
                    user = %u.id,
                    error = %e,
                    "bulk-grant: per-user grant failed; continuing"
                );
            }
        }
    }
    if let Err(e) = state
        .inv
        .audit(
            "admin",
            "server.grants.bulk_grant",
            Some(&server_id_str),
            Some(&serde_json::json!({
                "granted": granted,
                "already_granted": already,
                "failed": failed,
                "skipped_disabled": skipped_disabled,
                "total_users": users.len(),
            })),
        )
        .await
    {
        tracing::warn!(
            target = "vpnctld::admin",
            server = %server_id_str,
            error = %e,
            "audit write failed for server.grants.bulk_grant — mutations already committed"
        );
    }
    tracing::info!(
        target = "vpnctld::admin",
        server = %server_id_str,
        granted = granted,
        already = already,
        failed = failed,
        total = users.len(),
        "bulk-grant complete"
    );
    if granted > 0 {
        spawn_user_servers_redeploy(
            &state,
            vec![server],
            server_id_str.clone(),
            "server.grants.bulk_grant",
        );
    }
    Redirect::to(&format!(
        "/admin/servers/{}/grants",
        path_segment_encode(&server_id_str)
    ))
    .into_response()
}

pub(crate) async fn server_revoke_all_users(
    State(state): State<AppState>,
    Path(server_id_str): Path<String>,
    body: String,
) -> Response {
    let confirm = form_field(&body, "confirm").unwrap_or_default();
    if confirm != server_id_str {
        return bad_request(&format!(
            "bulk-revoke confirm mismatch: form sent '{confirm}', URL targets '{server_id_str}' — type the server id exactly to confirm"
        ));
    }
    let sid = vpnctl_core::ServerId(server_id_str.clone());
    let server = match state.inv.get_server(&sid).await {
        Ok(Some(s)) => s,
        Ok(None) => return not_found(&format!("no such server '{server_id_str}'")),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    let granted = match state.inv.users_for_server(&sid).await {
        Ok(v) => v,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    let total_was = granted.len();
    let mut revoked: u32 = 0;
    let mut failed: u32 = 0;
    for u in &granted {
        match state.inv.revoke(&u.id, &sid).await {
            Ok(()) => {
                revoked += 1;
                if let Err(e) = state
                    .inv
                    .audit(
                        "admin",
                        "user.revoke",
                        Some(&u.id.0),
                        Some(&serde_json::json!({
                            "server": server_id_str,
                            "source": "server-detail.bulk",
                        })),
                    )
                    .await
                {
                    tracing::warn!(
                        target = "vpnctld::admin",
                        server = %server_id_str,
                        user = %u.id,
                        error = %e,
                        "audit write failed for user.revoke (bulk) — mutation already committed"
                    );
                }
            }
            Err(e) => {
                failed += 1;
                tracing::warn!(
                    target = "vpnctld::admin",
                    server = %server_id_str,
                    user = %u.id,
                    error = %e,
                    "bulk-revoke: per-user revoke failed; continuing"
                );
            }
        }
    }
    if let Err(e) = state
        .inv
        .audit(
            "admin",
            "server.grants.bulk_revoke",
            Some(&server_id_str),
            Some(&serde_json::json!({
                "revoked": revoked,
                "failed": failed,
                "total_was": total_was,
            })),
        )
        .await
    {
        tracing::warn!(
            target = "vpnctld::admin",
            server = %server_id_str,
            error = %e,
            "audit write failed for server.grants.bulk_revoke — mutations already committed"
        );
    }
    tracing::info!(
        target = "vpnctld::admin",
        server = %server_id_str,
        revoked = revoked,
        failed = failed,
        total_was = total_was,
        "bulk-revoke complete"
    );
    if revoked > 0 {
        spawn_user_servers_redeploy(
            &state,
            vec![server],
            server_id_str.clone(),
            "server.grants.bulk_revoke",
        );
    }
    Redirect::to(&format!(
        "/admin/servers/{}/grants",
        path_segment_encode(&server_id_str)
    ))
    .into_response()
}
