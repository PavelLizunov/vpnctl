use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};

use super::super::helpers::{
    bad_request, internal_error, not_found, render_page, theme_accent_lang, user_not_found,
};
use super::super::legacy::spawn_user_servers_redeploy;
use crate::AppState;
use crate::http_util::{form_field, path_segment_encode};
use maud::html;

pub(crate) async fn server_grant_user(
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
    let revoked = match state
        .inv
        .revoke_audited(&uid, &sid, "admin", "server-detail")
        .await
    {
        Ok(revoked) => revoked,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    if revoked {
        spawn_user_servers_redeploy(&state, vec![server], user_id_str.clone(), "user.revoke");
    }
    Redirect::to(&format!(
        "/admin/servers/{}/grants",
        path_segment_encode(&server_id_str)
    ))
    .into_response()
}

pub(crate) async fn server_grant_all_users(
    headers: HeaderMap,
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
    let mut failures = Vec::new();
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
                failures.push((u.id.0.clone(), e.to_string()));
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
    if granted > 0
        && let Err(e) = state
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
    let lang = crate::i18n::Locale::from_request(&headers);
    bulk_grants_result(
        &state,
        &headers,
        &server_id_str,
        &format!(
            "{} {granted}; {} {already}; {} {skipped_disabled}; {} {failed}.",
            crate::i18n::tr(lang, "Granted:", "Выдано:"),
            crate::i18n::tr(lang, "already granted:", "уже выдано:"),
            crate::i18n::tr(lang, "disabled users skipped:", "отключённых пропущено:"),
            crate::i18n::tr(lang, "failed:", "ошибок:"),
        ),
        &failures,
    )
    .await
}

pub(crate) async fn server_revoke_all_users(
    headers: HeaderMap,
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
    // Every grant, including disabled users': `users_for_server` hides them,
    // and a kept grant silently returns access when the user is re-enabled.
    let granted: Vec<vpnctl_core::UserId> = match state.inv.grant_dates_for_server(&sid).await {
        Ok(v) => v.into_iter().map(|(uid, _)| uid).collect(),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    let total_was = granted.len();
    let mut revoked: u32 = 0;
    let mut failed: u32 = 0;
    let mut failures = Vec::new();
    for uid in &granted {
        match state
            .inv
            .revoke_audited(uid, &sid, "admin", "server-detail.bulk")
            .await
        {
            Ok(true) => revoked += 1,
            Ok(false) => {}
            Err(e) => {
                failed += 1;
                failures.push((uid.0.clone(), e.to_string()));
                tracing::warn!(
                    target = "vpnctld::admin",
                    server = %server_id_str,
                    user = %uid,
                    error = %e,
                    "bulk-revoke: per-user revoke failed; continuing"
                );
            }
        }
    }
    if revoked > 0
        && let Err(e) = state
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
    let lang = crate::i18n::Locale::from_request(&headers);
    bulk_grants_result(
        &state,
        &headers,
        &server_id_str,
        &format!(
            "{} {revoked}; {} {failed}.",
            crate::i18n::tr(lang, "Revoked:", "Отозвано:"),
            crate::i18n::tr(lang, "failed:", "ошибок:"),
        ),
        &failures,
    )
    .await
}

async fn bulk_grants_result(
    state: &AppState,
    headers: &HeaderMap,
    server_id: &str,
    summary: &str,
    failures: &[(String, String)],
) -> Response {
    let (theme, accent, lang) = theme_accent_lang(headers);
    let body = html! {
        h1 { (crate::i18n::tr(lang, "Bulk access result", "Результат массового изменения доступа")) }
        section.ed-alert role="status" {
            p { (summary) }
            @if !failures.is_empty() {
                ul {
                    @for (user, reason) in failures {
                        li { b { (user) } ": " (reason) }
                    }
                }
            }
        }
        p { (crate::i18n::tr(lang, "These counts describe saved access changes. Check deployment status on the server page.", "Эти числа показывают сохранённые изменения доступа. Проверь статус деплоя на странице сервера.")) }
        a.ed-abtn href=(format!("/admin/servers/{}/grants", path_segment_encode(server_id))) {
            (crate::i18n::tr(lang, "Back to server access", "Назад к доступам сервера"))
        }
    };
    render_page(state, "servers", &theme, &accent, lang, body)
        .await
        .into_response()
}
