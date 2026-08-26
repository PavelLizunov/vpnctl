use axum::extract::{Path, State};
use axum::response::{IntoResponse, Redirect, Response};

use super::super::helpers::{bad_request, internal_error, not_found, user_not_found};
use super::super::legacy::spawn_user_servers_redeploy;
use crate::AppState;
use crate::http_util::{form_field, path_segment_encode};

/// `POST /admin/servers/{sid}/grants/{uid}` — grant the user access
/// from the SERVER side. Identical mutation to `user_grant_server`
/// (same `inv.grant` call), but the redirect target is the SERVER
/// detail page so the operator stays where they started. Mirror
/// pair: `server_revoke_user`.
pub(crate) async fn server_grant_user(
    State(state): State<AppState>,
    Path((server_id_str, user_id_str)): Path<(String, String)>,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id_str.clone());
    let uid = vpnctl_core::UserId(user_id_str.clone());
    // Existence checks — explicit 404 for both, otherwise the FK
    // violation surfaces as a generic 500.
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

    // Membership BEFORE the grant — the audit row is written only for
    // a NEW grant. An idempotent re-grant must NOT add a fresh
    // `user.grant` row: it would falsely re-mark the server
    // pending-deploy until a no-op redeploy (review-agent important;
    // matches the bulk path's skip-already-granted semantics).
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
    // `user.grant` row with target = USER id. The pending-deploy
    // detector keys on exactly this; the previous `action="grant",
    // target=<server>` row was invisible to it, so a grant made from
    // the server-detail page never raised the «config not yet
    // deployed» banner once the server had its first deploy baseline.
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
        // Auto-deploy — same contract as `user_grant_server` (HANDOFF
        // §4.1); the mutation is identical, only the redirect differs.
        spawn_user_servers_redeploy(&state, vec![server], user_id_str.clone(), "user.grant");
    }
    Redirect::to(&format!(
        "/admin/servers/{}/grants",
        path_segment_encode(&server_id_str)
    ))
    .into_response()
}

/// `POST /admin/servers/{sid}/grants` — the v2 3d grant bar: user id
/// arrives as a form field instead of a path segment. Validates the
/// field then delegates to [`server_grant_user`] (extractors are just
/// values) so the mutation, audit shape and auto-deploy stay single-
/// sourced.
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

/// `POST /admin/servers/{sid}/grants/{uid}/revoke` — revoke from the
/// SERVER side. Mirror of `server_grant_user`.
pub(crate) async fn server_revoke_user(
    State(state): State<AppState>,
    Path((server_id_str, user_id_str)): Path<(String, String)>,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id_str.clone());
    let uid = vpnctl_core::UserId(user_id_str.clone());
    let server = match state.inv.get_server(&sid).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return not_found(&format!("no such server '{server_id_str}'"));
        }
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    // User-existence check — the grant twin always had it; without it
    // an unknown user 200-redirected as if revoked (audit 2026-06-10).
    match state.inv.get_user(&uid).await {
        Ok(Some(_)) => {}
        Ok(None) => return user_not_found(&user_id_str),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }
    // Membership BEFORE the revoke — the audit row is written only for
    // an ACTUAL revoke (mirror of the grant paths' 2026-06-04 shape).
    let was_granted = match state.inv.servers_for_user(&uid).await {
        Ok(v) => v.iter().any(|s| s.id == sid),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    if let Err(e) = state.inv.revoke(&uid, &sid).await {
        return internal_error(anyhow::Error::new(e));
    }
    // Canonical per-user `user.revoke` (target = USER id) — the
    // pending-deploy detector keys on per-user mutation rows; the old
    // `action="revoke", target=<server>` row was invisible to it, so a
    // revoked UUID stayed live on the node with no warning anywhere.
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
        // Auto-deploy — mirror of `user_revoke_server`.
        spawn_user_servers_redeploy(&state, vec![server], user_id_str.clone(), "user.revoke");
    }
    Redirect::to(&format!(
        "/admin/servers/{}/grants",
        path_segment_encode(&server_id_str)
    ))
    .into_response()
}

/// `POST /admin/servers/{id}/grants/_grant-all` (B2, audit 2026-05-22,
/// shipped 2026-05-23) — grant access to **every existing user** on
/// this server. Common after deploying a new server: instead of
/// clicking «grant» for each user, click one button. Per-user grant
/// is idempotent at the SQL layer (`ON CONFLICT DO NOTHING`), so
/// re-running this on a fully-granted server is a no-op.
///
/// Audit shape (2026-06-04 unification): ONE summary row
/// (`server.grants.bulk_grant` with `{granted, already_granted,
/// failed, total_users}`) **plus a per-user `user.grant` row
/// (target = user id) for each NEWLY-granted user**. The per-user
/// rows are what the pending-deploy detector
/// (`servers_pending_deploy_for_user`) keys on — without them a
/// bulk grant after the server's first deploy never raised the
/// «config not yet deployed» banner. Timeline flood stays bounded:
/// re-running on a fully-granted server grants 0 → writes 0
/// per-user rows (idempotent), so only the first click of the «50
/// users» case pays the N rows — and those N are exactly the N
/// real mutations. Per-user grant failures (rare — inventory-layer
/// DB error) are counted in `failed` and logged at warn but DO NOT
/// abort the batch — partial success is operator-recoverable via
/// the per-row UI.
///
/// No confirm gate (safe + reversible — operator can revoke
/// per-user OR use the bulk revoke flow).
pub(crate) async fn server_grant_all_users(
    State(state): State<AppState>,
    Path(server_id_str): Path<String>,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id_str.clone());
    // 3-arm match (audit 2026-06-10): the old `if let Ok(None)` SWALLOWED
    // the DB-error arm and fell through as if the server existed.
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
        // Don't bulk-grant to soft-paused users (B1.user, audit
        // finding 2026-05-23). The grant would be functionally
        // harmless — disabled users' /sub renders an empty
        // config regardless — but silently un-paused-by-side-
        // effect violates the operator's «paused means out of
        // sight» mental model. Disabled users get caught here +
        // counted; operator can grant them individually after
        // enabling. Symmetric handling on revoke-all isn't
        // needed (revoking a disabled user is consistent with
        // them already being out-of-rotation).
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
                // Per-user `user.grant` row for each ACTUAL new grant —
                // the canonical shape the pending-deploy detector keys
                // on (see the handler doc-comment). Audit failure is
                // non-fatal: the grant is already committed.
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
    // Auto-deploy the affected server ONCE for the whole batch (not
    // once per user) so every new UUID lands in the node's users[].
    // Skipped on a fully-granted re-run (granted == 0 → no-op batch).
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

/// `POST /admin/servers/{id}/grants/_revoke-all` (B2, audit 2026-05-22,
/// shipped 2026-05-23) — revoke access for **every currently-granted
/// user** on this server. Destructive — operator must confirm by
/// re-typing the server id in the `confirm=<id>` form field (same
/// double-submit shape as user delete in C-3.4). Mismatch → 400.
///
/// Writes ONE summary audit row (`server.grants.bulk_revoke` with
/// `{revoked, failed, total_was}`) rather than N per-user rows.
/// Per-user revoke is idempotent at the SQL layer; failures are
/// counted + logged but don't abort the batch.
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
    // 3-arm match (audit 2026-06-10): the old `if let Ok(None)` SWALLOWED
    // the DB-error arm and fell through as if the server existed.
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
                // Per-user `user.revoke` row for each ACTUAL revoke
                // (the `granted` list is exactly the granted set, so
                // every Ok here is a real mutation). Mirrors the bulk
                // grant path; keeps the pending-deploy detector fed.
                // Audit failure non-fatal: revoke already committed.
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
    // Auto-deploy ONCE for the batch — mirror of the bulk-grant path.
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
