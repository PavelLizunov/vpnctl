use crate::AppState;
use crate::handlers::admin::helpers::{internal_error, user_not_found};
use crate::handlers::admin::legacy::spawn_user_servers_redeploy;
use crate::http_util::{form_field, path_segment_encode};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};

pub(crate) async fn user_rotate_uuid(
    State(state): State<AppState>,
    Path(user_id_str): Path<String>,
    body: String,
) -> Response {
    let Some(expected_sha256) = form_field(&body, "expected_sha256") else {
        return (StatusCode::BAD_REQUEST, "expected_sha256 field is required").into_response();
    };
    let uid = vpnctl_core::UserId(user_id_str.clone());
    let replacement = form_field(&body, "replacement").unwrap_or_else(vpnctl_crypto::gen_uuid);
    let ids = match state
        .inv
        .rotate_user_uuid(&uid, &expected_sha256, &replacement, "admin")
        .await
    {
        Ok(ids) => ids,
        Err(vpnctl_inventory::SqliteInventoryError::Invalid(message)) => {
            return match message.as_str() {
                "no such user" => user_not_found(&user_id_str),
                "current UUID has changed" => (StatusCode::CONFLICT, message).into_response(),
                _ => (StatusCode::BAD_REQUEST, message).into_response(),
            };
        }
        Err(error) => return internal_error(anyhow::Error::new(error)),
    };
    let servers = match state.inv.get_servers_batch(&ids).await {
        Ok(servers) => servers,
        Err(error) => return internal_error(anyhow::Error::new(error)),
    };
    spawn_user_servers_redeploy(&state, servers, user_id_str.clone(), "user.uuid.rotate");
    Redirect::to(&format!(
        "/admin/users/{}/overview",
        path_segment_encode(&user_id_str)
    ))
    .into_response()
}

pub(crate) async fn user_regen_sub_token(
    State(state): State<AppState>,
    Path(user_id_str): Path<String>,
) -> Response {
    let uid = vpnctl_core::UserId(user_id_str.clone());

    match state.inv.get_user(&uid).await {
        Ok(Some(_)) => {}
        Ok(None) => return user_not_found(&user_id_str),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }

    if let Err(e) = state.inv.regenerate_sub_token(&uid).await {
        return internal_error(anyhow::Error::new(e));
    }

    if let Err(e) = state
        .inv
        .audit("admin", "user.sub_token.regen", Some(&user_id_str), None)
        .await
    {
        tracing::warn!(
            target = "vpnctld::admin",
            user = %user_id_str,
            error = %e,
            "audit write failed for user.sub_token.regen — mutation already committed"
        );
    }

    Redirect::to(&format!(
        "/admin/users/{}/overview",
        path_segment_encode(&user_id_str)
    ))
    .into_response()
}

pub(crate) async fn user_mint_tuic_password(
    State(state): State<AppState>,
    Path(user_id_str): Path<String>,
) -> Response {
    let uid = vpnctl_core::UserId(user_id_str.clone());
    match state.inv.get_user(&uid).await {
        Ok(Some(_)) => {}
        Ok(None) => return user_not_found(&user_id_str),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }
    match state.inv.mint_tuic_password_if_absent(&uid).await {
        Ok(true) => {
            if let Err(e) = state
                .inv
                .audit("admin", "user.mint_tuic_password", Some(&user_id_str), None)
                .await
            {
                tracing::warn!(
                    target = "vpnctld::admin",
                    user = %user_id_str,
                    error = %e,
                    "audit write failed for user.mint_tuic_password — mutation already committed"
                );
            }
            let servers = state.inv.servers_for_user(&uid).await.unwrap_or_else(|e| {
                tracing::warn!(
                    target = "vpnctld::admin",
                    user = %user_id_str,
                    error = %e,
                    "servers_for_user failed; tuic mint not auto-applied — use Deploy all"
                );
                Vec::new()
            });
            spawn_user_servers_redeploy(
                &state,
                servers,
                user_id_str.clone(),
                "user.mint_tuic_password",
            );
        }
        Ok(false) => {}
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }
    Redirect::to(&format!(
        "/admin/users/{}/overview",
        path_segment_encode(&user_id_str)
    ))
    .into_response()
}

pub(crate) async fn user_regen_wireguard(
    State(state): State<AppState>,
    Path(user_id_str): Path<String>,
) -> Response {
    let uid = vpnctl_core::UserId(user_id_str.clone());

    match state.inv.get_user(&uid).await {
        Ok(Some(_)) => {}
        Ok(None) => return user_not_found(&user_id_str),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }

    let (priv_b64, pub_b64) = vpnctl_crypto::gen_wireguard_keypair();
    if let Err(e) = state
        .inv
        .set_user_wireguard_keypair(&uid, &pub_b64, &priv_b64)
        .await
    {
        return internal_error(anyhow::Error::new(e));
    }

    if let Err(e) = state
        .inv
        .audit(
            "admin",
            "user.wireguard.regen",
            Some(&user_id_str),
            Some(&serde_json::json!({
                "wg_keypair_provenance": "server-generated",
                "new_pubkey": pub_b64,
            })),
        )
        .await
    {
        tracing::warn!(
            target = "vpnctld::admin",
            user = %user_id_str,
            error = %e,
            "audit write failed for user.wireguard.regen — mutation already committed"
        );
    }

    let servers = state.inv.servers_for_user(&uid).await.unwrap_or_else(|e| {
        tracing::warn!(
            target = "vpnctld::admin",
            user = %user_id_str,
            error = %e,
            "servers_for_user failed; wireguard regen not auto-applied — use Deploy all"
        );
        Vec::new()
    });
    spawn_user_servers_redeploy(&state, servers, user_id_str.clone(), "user.wireguard.regen");

    Redirect::to(&format!(
        "/admin/users/{}/delivery",
        path_segment_encode(&user_id_str)
    ))
    .into_response()
}
