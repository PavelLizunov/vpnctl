use crate::AppState;
use crate::handlers::admin::helpers::{
    bad_request, internal_error, render_page, theme_accent_lang, user_not_found, valid_user_id,
};
use crate::handlers::admin::icons::{icon, status};
use crate::handlers::admin::legacy::{DEFAULT_TRAFFIC_THRESHOLD_PCT, spawn_user_servers_redeploy};
use crate::http_util::{form_field, path_segment_encode};
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use maud::{Markup, html};

pub(crate) async fn user_set_traffic_limit(
    State(state): State<AppState>,
    Path(user_id_str): Path<String>,
    body: String,
) -> Response {
    let uid = vpnctl_core::UserId(user_id_str.clone());

    match state.inv.get_user(&uid).await {
        Ok(Some(_)) => {}
        Ok(None) => return user_not_found(&user_id_str),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }

    let limit_gib: f64 = form_field(&body, "limit_gib")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.0);
    let threshold_pct: u8 = form_field(&body, "threshold_pct")
        .and_then(|s| s.parse().ok())
        .map(|v: u32| v.clamp(1, 100) as u8)
        .unwrap_or(DEFAULT_TRAFFIC_THRESHOLD_PCT);

    let limit_bytes: Option<u64> = if limit_gib > 0.0 && limit_gib.is_finite() {
        Some(((limit_gib * 1_073_741_824.0) as u64).min(i64::MAX as u64))
    } else {
        None
    };

    let changed = match state
        .inv
        .set_user_traffic_limit(&uid, limit_bytes, Some(threshold_pct))
        .await
    {
        Ok(changed) => changed,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    if changed {
        if let Err(e) = state
            .inv
            .audit(
                "admin",
                "user.traffic_limit.set",
                Some(&user_id_str),
                Some(&serde_json::json!({
                    "limit_bytes": limit_bytes,
                    "limit_gib": limit_gib,
                    "threshold_pct": threshold_pct,
                })),
            )
            .await
        {
            tracing::warn!(
                target = "vpnctld::admin",
                user = %user_id_str,
                error = %e,
                "audit write failed for user.traffic_limit.set"
            );
        }
    }

    Redirect::to(&format!(
        "/admin/users/{}/overview",
        path_segment_encode(&user_id_str)
    ))
    .into_response()
}

pub(crate) async fn user_create(State(state): State<AppState>, body: String) -> Response {
    let id_decoded: String = form_field(&body, "id")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    if !valid_user_id(&id_decoded) {
        return bad_request(&format!(
            "invalid user id '{id_decoded}' (allowed: 2-32 chars of a-z 0-9 . _ -; must start and end with a-z 0-9; no consecutive dots)"
        ));
    }

    const TUIC_PW_BYTES: usize = 24;
    let tuic_password = match vpnctl_crypto::gen_password(TUIC_PW_BYTES) {
        Ok(pw) => pw,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    let (wg_priv, wg_pub) = vpnctl_crypto::gen_wireguard_keypair();
    let device_id = match vpnctl_crypto::gen_vpn_router_device_id() {
        Ok(d) => d,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    let user = vpnctl_core::User {
        id: vpnctl_core::UserId(id_decoded.clone()),
        uuid: vpnctl_crypto::gen_uuid(),
        tuic_password: Some(tuic_password),
        wireguard_pubkey: Some(wg_pub),
        wireguard_private: Some(wg_priv),
        sub_token: None,
        vpn_router_device_id: Some(device_id),
        disabled: false,
    };

    if let Err(e) = state.inv.add_user(&user).await {
        return match e {
            vpnctl_inventory::SqliteInventoryError::AlreadyExists(what) => {
                bad_request(&format!("{what} already exists — pick a different id"))
            }
            other => internal_error(anyhow::Error::new(other)),
        };
    }

    if let Err(e) = state
        .inv
        .audit(
            "admin",
            "user.add",
            Some(&id_decoded),
            Some(&serde_json::json!({
                "uuid": user.uuid,
                "wg_pubkey_set": user.wireguard_pubkey.is_some(),
                "wg_keypair_provenance": "server-generated",
            })),
        )
        .await
    {
        tracing::warn!(
            target = "vpnctld::admin",
            user = %id_decoded,
            error = %e,
            "audit write failed for user.add — mutation already committed"
        );
    }

    let grant_all = form_field(&body, "grant_all").as_deref() == Some("1");
    if grant_all {
        match state.inv.list_fleet_servers().await {
            Ok(servers) => {
                let mut granted: u32 = 0;
                let mut granted_servers: Vec<vpnctl_core::Server> = Vec::new();
                for s in &servers {
                    if let Err(e) = state.inv.grant(&user.id, &s.id).await {
                        tracing::warn!(
                            target = "vpnctld::admin",
                            user = %id_decoded,
                            server = %s.id.0,
                            error = %e,
                            "grant-all: per-server grant failed; continuing"
                        );
                        continue;
                    }
                    granted += 1;
                    granted_servers.push(s.clone());
                    if let Err(e) = state
                        .inv
                        .audit(
                            "admin",
                            "user.grant",
                            Some(&id_decoded),
                            Some(&serde_json::json!({
                                "server": s.id.0,
                                "source": "user.create.grant_all",
                            })),
                        )
                        .await
                    {
                        tracing::warn!(
                            target = "vpnctld::admin",
                            user = %id_decoded,
                            server = %s.id.0,
                            error = %e,
                            "audit write failed for user.grant — mutation already committed"
                        );
                    }
                }
                if granted > 0 {
                    tracing::info!(
                        target = "vpnctld::admin",
                        user = %id_decoded,
                        granted = granted,
                        total = servers.len(),
                        "user-create grant-all complete"
                    );
                    spawn_user_servers_redeploy(
                        &state,
                        granted_servers,
                        id_decoded.clone(),
                        "user.create.grant_all",
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    target = "vpnctld::admin",
                    user = %id_decoded,
                    error = %e,
                    "grant-all: list_servers failed; user created without grants"
                );
            }
        }
    }

    Redirect::to(&format!(
        "/admin/users/{}",
        path_segment_encode(&id_decoded)
    ))
    .into_response()
}

pub(crate) async fn user_delete_confirm(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(user_id_str): Path<String>,
) -> Result<Markup, Response> {
    use crate::i18n::tr;
    let (theme, accent, lang) = theme_accent_lang(&headers);
    let uid = vpnctl_core::UserId(user_id_str.clone());
    let user = match state.inv.get_user(&uid).await {
        Ok(Some(u)) => u,
        Ok(None) => return Err(user_not_found(&user_id_str)),
        Err(e) => return Err(internal_error(anyhow::Error::new(e))),
    };
    let granted: Vec<String> = state
        .inv
        .servers_for_user(&uid)
        .await
        .map(|v| v.into_iter().map(|s| s.id.0).collect())
        .unwrap_or_default();
    let uid_enc = path_segment_encode(&user_id_str);
    let body = html! {
        nav.ed-crumb {
            a href=(format!("/admin/users/{uid_enc}")) style="color: var(--mute); text-decoration: none;" {
                (icon("arrow-left")) " " (tr(lang, "back to ", "назад к ")) (user_id_str)
            }
        }
        div.ed-headrow {
            h1.ed-sumbar__h { (tr(lang, "Delete ", "Удалить ")) em { (user_id_str) } "?" }
        }
        div style="display: flex; align-items: center; gap: 10px; border: 1px solid var(--red); border-left-width: 3px; background: color-mix(in oklab, var(--red) 8%, var(--paper)); padding: 9px 12px; margin: 10px 0 16px; font-family: var(--mono); font-size: 11px; color: var(--red);" {
            (icon("circle-x")) " " b { (tr(lang, "Point of no return.", "Точка невозврата.")) }
            (tr(
                lang,
                " This removes the user, all keys, all grants — and queues a deploy on each granted server so the node configs drop the entries.",
                " Удаляет пользователя, все ключи, все гранты — и ставит деплой на каждый выданный сервер, чтобы конфиги нод забыли записи.",
            ))
        }
        div style="display: grid; grid-template-columns: minmax(0, 1fr) 360px; gap: 20px; align-items: start;" {
            div {
                div.ed-art-eyebrow { (tr(lang, "What gets destroyed", "Что будет уничтожено")) }
                table.ed-feed style="margin-top: 8px;" {
                    tbody {
                        tr {
                            td style="width: 20px; color: var(--red);" { (status("minus", lang, "Will be removed", "Будет удалено")) }
                            td { "uuid " span.ed-grid__mut { (user.uuid) } }
                        }
                        tr {
                            td style="color: var(--red);" { (status("minus", lang, "Will be removed", "Будет удалено")) }
                            td {
                                (tr(lang, "keys: ", "ключи: "))
                                @let keys = {
                                    let mut v: Vec<&str> = Vec::new();
                                    if user.tuic_password.is_some() { v.push("tuic password"); }
                                    if user.wireguard_pubkey.is_some() { v.push("wg keypair"); }
                                    if user.sub_token.is_some() { v.push("sub-token"); }
                                    v
                                };
                                @if keys.is_empty() { span.ed-grid__mut { "—" } }
                                @else { (keys.join(" · ")) }
                            }
                        }
                        tr {
                            td style="color: var(--red);" { (status("minus", lang, "Will be removed", "Будет удалено")) }
                            td {
                                (granted.len()) " " (tr(lang, "grants", "грантов"))
                                @if !granted.is_empty() {
                                    ": " (granted.join(", "))
                                    " " span.ed-grid__mut { "· " (tr(lang, "deploy queued on each", "деплой встанет на каждый")) }
                                }
                            }
                        }
                        tr {
                            td style="color: var(--red);" { (status("minus", lang, "Will be removed", "Будет удалено")) }
                            td {
                                (tr(lang, "subscription URL", "URL подписки"))
                                " " span.ed-grid__mut { "· " (tr(lang, "the mobile app gets 404 on next poll", "приложение получит 404 при следующем опросе")) }
                            }
                        }
                        tr {
                            td style="color: var(--green);" { (status("check", lang, "Kept", "Сохраняется")) }
                            td {
                                b { (tr(lang, "kept: ", "остаётся: ")) }
                                (tr(
                                    lang,
                                    "audit history · 30-day access log (rows survive with NULL user_id) · IP bans",
                                    "история аудита · 30-дневный лог обращений (строки живут с NULL user_id) · IP-баны",
                                ))
                            }
                        }
                    }
                }
            }
            div {
                div.ed-art-eyebrow {
                    (tr(lang, "Type the id to confirm", "Введи id для подтверждения")) " "
                    span.ed-tip title=(tr(
                        lang,
                        "Same guard as the CLI: the typed value is re-checked server-side; a mismatch submits nothing.",
                        "Тот же предохранитель, что в CLI: введённое перепроверяется на сервере; несовпадение ничего не отправит.",
                    )) { (icon("info")) }
                }
                form method="post"
                     action=(format!("/admin/users/{uid_enc}/delete")) {
                    input type="text" name="confirm" required="required"
                          autocomplete="off"
                          placeholder=(user_id_str)
                          style="width: 100%; box-sizing: border-box; padding: 8px 12px; border: 1px solid var(--rule-s); background: var(--paper); font-family: var(--mono); font-size: 13px; color: var(--ink); margin: 8px 0 10px;";
                    div style="display: flex; gap: 8px;" {
                        a href=(format!("/admin/users/{uid_enc}"))
                          class="ed-abtn ed-abtn--secondary" style="flex: 1; text-align: center;" {
                            (icon("x")) (tr(lang, "cancel — keep the user", "отмена — оставить"))
                        }
                        button type="submit"
                               title=(format!("Delete user {user_id_str} permanently"))
                               class="ed-abtn ed-abtn--danger-solid" style="flex: 1;" {
                            (icon("trash-2")) (tr(lang, "delete forever", "удалить навсегда"))
                        }
                    }
                }
                p.ed-grid__mut style="font-family: var(--mono); font-size: 10px; margin-top: 8px;" {
                    (tr(
                        lang,
                        "the id has to match exactly — copy/paste counts",
                        "id должен совпасть точно — копипаста считается",
                    ))
                }
            }
        }
    };
    Ok(render_page(&state, "users", &theme, &accent, lang, body).await)
}

pub(crate) async fn user_delete(
    State(state): State<AppState>,
    Path(user_id_str): Path<String>,
    body: String,
) -> Response {
    let confirm = form_field(&body, "confirm").unwrap_or_default();
    if confirm != user_id_str {
        return bad_request(&format!(
            "delete confirm mismatch: form sent '{confirm}', URL targets '{user_id_str}' — type the user id exactly to confirm"
        ));
    }

    let uid = vpnctl_core::UserId(user_id_str.clone());
    match state.inv.get_user(&uid).await {
        Ok(Some(_)) => {}
        Ok(None) => return user_not_found(&user_id_str),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }
    let servers = state.inv.servers_for_user(&uid).await.unwrap_or_else(|e| {
        tracing::warn!(
            target = "vpnctld::admin",
            user = %user_id_str,
            error = %e,
            "servers_for_user failed; delete not auto-applied — use Deploy all"
        );
        Vec::new()
    });
    if let Err(e) = state.inv.remove_user(&uid).await {
        return internal_error(anyhow::Error::new(e));
    }
    if let Err(e) = state
        .inv
        .audit("admin", "user.remove", Some(&user_id_str), None)
        .await
    {
        tracing::warn!(
            target = "vpnctld::admin",
            user = %user_id_str,
            error = %e,
            "audit row for user.remove failed; mutation already committed"
        );
    }
    spawn_user_servers_redeploy(&state, servers, user_id_str.clone(), "user.remove");
    Redirect::to("/admin/users").into_response()
}

pub(crate) async fn user_set_disabled_true(
    State(state): State<AppState>,
    Path(user_id_str): Path<String>,
) -> Response {
    user_set_disabled_inner(state, user_id_str, true).await
}

pub(crate) async fn user_set_disabled_false(
    State(state): State<AppState>,
    Path(user_id_str): Path<String>,
) -> Response {
    user_set_disabled_inner(state, user_id_str, false).await
}

async fn user_set_disabled_inner(state: AppState, user_id_str: String, target: bool) -> Response {
    let uid = vpnctl_core::UserId(user_id_str.clone());
    let changed = match state.inv.set_user_disabled(&uid, target).await {
        Ok(b) => b,
        Err(vpnctl_inventory::SqliteInventoryError::Invalid(msg))
            if msg.starts_with("no such user") =>
        {
            return user_not_found(&user_id_str);
        }
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    if changed {
        let action = if target {
            "user.disable"
        } else {
            "user.enable"
        };
        if let Err(e) = state
            .inv
            .audit(
                "admin",
                action,
                Some(&user_id_str),
                Some(&serde_json::json!({
                    "disabled": target,
                })),
            )
            .await
        {
            tracing::warn!(
                target = "vpnctld::admin",
                user = %user_id_str,
                action = action,
                error = %e,
                "audit row failed for user disable/enable; mutation already committed"
            );
        }

        let servers = state.inv.servers_for_user(&uid).await.unwrap_or_else(|e| {
            tracing::warn!(
                target = "vpnctld::admin",
                user = %user_id_str,
                error = %e,
                "servers_for_user failed; disable/enable not auto-applied — use Deploy all"
            );
            Vec::new()
        });
        spawn_user_servers_redeploy(&state, servers, user_id_str.clone(), action);
    }
    Redirect::to(&format!(
        "/admin/users/{}/overview",
        path_segment_encode(&user_id_str)
    ))
    .into_response()
}
