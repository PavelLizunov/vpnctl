use crate::AppState;
use crate::handlers::admin::helpers::{internal_error, user_not_found};
use crate::handlers::admin::legacy::spawn_user_servers_redeploy;
use crate::http_util::path_segment_encode;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Redirect, Response};

/// `POST /admin/users/{id}/sub-token/regenerate` — mint a fresh sub_token,
/// invalidate the previous one, write the audit row, redirect back to
/// the user-detail page (which will render the new token + new QR).
///
/// CSRF posture: same as the existing tweak handlers — Referer is
/// sanitised so a hostile origin can't redirect the operator off-site,
/// but the mutation itself is allowed (worst case: operator's own
/// client gets disconnected and they have to re-pull, no secret leak).
pub(crate) async fn user_regen_sub_token(
    State(state): State<AppState>,
    Path(user_id_str): Path<String>,
) -> Response {
    let uid = vpnctl_core::UserId(user_id_str.clone());

    // Step 1: existence check. The downstream regenerate_sub_token
    // would error with `Invalid("no such user: …")` but that maps to
    // a 500 via `internal_error`; an explicit 404 here matches every
    // other "unknown id" surface in the admin tree.
    match state.inv.get_user(&uid).await {
        Ok(Some(_)) => {}
        Ok(None) => return user_not_found(&user_id_str),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }

    // Step 2: mutation. Returns the new token, but we don't expose it
    // here — the redirect target re-renders the page from the inventory,
    // which is the single source of truth.
    if let Err(e) = state.inv.regenerate_sub_token(&uid).await {
        return internal_error(anyhow::Error::new(e));
    }

    // Step 3: audit. Best-effort; see module-level convention above.
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

    // Step 4: redirect. `path_segment_encode` so the redirect target
    // matches the URL the operator clicked from.
    Redirect::to(&format!(
        "/admin/users/{}/overview",
        path_segment_encode(&user_id_str)
    ))
    .into_response()
}

/// `POST /admin/users/{id}/tuic-password/mint` — mint a per-user
/// `tuic_password` for a user that has none. naive + Hysteria2 reuse
/// this field as their per-user secret, so a user without it silently
/// gets NO naive / Hysteria2 (or TUIC) links — exactly the `cdn`
/// 2026-06-07 incident. This is the operator's one-click fix.
/// Idempotent: a user who already has one is a no-op (we never rotate a
/// live password, which would break their links until redeploy). After
/// minting, the operator redeploys the user's servers so the node
/// accepts the new password.
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
            // Auto-deploy — the new password must land on every granted
            // node so the protocol accepts it (same contract as
            // grant/revoke auto-deploy).
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
        // Already had a password — idempotent no-op, no audit spam.
        Ok(false) => {}
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }
    Redirect::to(&format!(
        "/admin/users/{}/overview",
        path_segment_encode(&user_id_str)
    ))
    .into_response()
}

/// `POST /admin/users/{id}/wireguard/regenerate` — mint a fresh
/// Curve25519 pair, overwrite both `wireguard_pubkey` and
/// `wireguard_private` on the user row, audit, redirect to the
/// detail page (which shows the new pubkey + the "✓ stored" marker
/// for private). Every device using the OLD config stops working
/// after the next /sub/<token> re-fetch — the old pubkey is no
/// longer in the server's [Peer] list (will land on next
/// `vpnctl deploy <server>`).
///
/// Same CSRF/audit/404 posture as `user_regen_sub_token`.
pub(crate) async fn user_regen_wireguard(
    State(state): State<AppState>,
    Path(user_id_str): Path<String>,
) -> Response {
    let uid = vpnctl_core::UserId(user_id_str.clone());

    // Existence check — explicit 404 if no such user.
    match state.inv.get_user(&uid).await {
        Ok(Some(_)) => {}
        Ok(None) => return user_not_found(&user_id_str),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }

    // Mutate.
    let (priv_b64, pub_b64) = vpnctl_crypto::gen_wireguard_keypair();
    if let Err(e) = state
        .inv
        .set_user_wireguard_keypair(&uid, &pub_b64, &priv_b64)
        .await
    {
        return internal_error(anyhow::Error::new(e));
    }

    // Audit — pin provenance + new pubkey for traceability. Private
    // value never enters the log (key VALUES never do — only
    // provenance + the pubkey, which is itself public).
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

    // Auto-deploy — the new pubkey must land on every granted node's
    // [Peer] list; without this the old key stays active and the new
    // config fails (same contract as grant/revoke auto-deploy).
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
        "/admin/users/{}/overview",
        path_segment_encode(&user_id_str)
    ))
    .into_response()
}
