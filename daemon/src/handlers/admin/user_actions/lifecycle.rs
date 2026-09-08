use crate::AppState;
use crate::handlers::admin::helpers::{
    bad_request, internal_error, render_page, theme_accent_lang, user_not_found, valid_user_id,
};
use crate::handlers::admin::legacy::{DEFAULT_TRAFFIC_THRESHOLD_PCT, spawn_user_servers_redeploy};
use crate::http_util::{form_field, path_segment_encode};
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use maud::{Markup, html};

/// `POST /admin/users/{id}/traffic-limit` — set monthly bandwidth
/// cap + alert threshold for one user. Form fields:
///   * `limit_gib` (float) — total upload+download/month in GiB.
///     `0` (or empty / negative / non-numeric) clears the cap.
///   * `threshold_pct` (int 1..=100) — alert fires at this fraction
///     of the cap. Defaults to `DEFAULT_TRAFFIC_THRESHOLD_PCT` (80)
///     when omitted.
///
/// 404 unknown user; 303 to user-detail on success. Audit row
/// records new values (NOT the user's accumulated usage — that's
/// a derived metric).
pub(crate) async fn user_set_traffic_limit(
    State(state): State<AppState>,
    Path(user_id_str): Path<String>,
    body: String,
) -> Response {
    let uid = vpnctl_core::UserId(user_id_str.clone());

    // Existence — explicit 404 (matches the rest of the admin tree).
    match state.inv.get_user(&uid).await {
        Ok(Some(_)) => {}
        Ok(None) => return user_not_found(&user_id_str),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }

    // Parse form. Two fields, both optional in the wire format —
    // missing limit_gib = clear, missing threshold = use default.
    let limit_gib: f64 = form_field(&body, "limit_gib")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.0);
    let threshold_pct: u8 = form_field(&body, "threshold_pct")
        .and_then(|s| s.parse().ok())
        .map(|v: u32| v.clamp(1, 100) as u8)
        .unwrap_or(DEFAULT_TRAFFIC_THRESHOLD_PCT);

    // 0 / negative / NaN = clear the limit (operator intent: "no cap").
    let limit_bytes: Option<u64> = if limit_gib > 0.0 && limit_gib.is_finite() {
        Some((limit_gib * 1_073_741_824.0) as u64)
    } else {
        None
    };

    if let Err(e) = state
        .inv
        .set_user_traffic_limit(&uid, limit_bytes, Some(threshold_pct))
        .await
    {
        return internal_error(anyhow::Error::new(e));
    }

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

    Redirect::to(&format!(
        "/admin/users/{}/overview",
        path_segment_encode(&user_id_str)
    ))
    .into_response()
}

/// `POST /admin/users` — create a new user from the form on
/// `/admin/users`. Form body is `id=<text>` (the only field — UUID,
/// tuic_password and sub_token are all minted server-side).
///
/// Outcomes:
///   * happy path → 303 to `/admin/users/<id>` (which re-renders the
///     fresh user with QR + share-links).
///   * empty / invalid id → 400 with the canonical error body.
///   * duplicate id → 400 with "already exists".
///   * inventory error → 500 via `internal_error`.
///
/// CSRF: handled by `csrf::require_same_origin` middleware on the
/// admin router (Origin must match Host). Audit row written on
/// success only.
pub(crate) async fn user_create(State(state): State<AppState>, body: String) -> Response {
    // `form_field` already routes through `decode_form_value`, so this
    // gives us the decoded value directly — no need for the prior
    // trim-then-decode dance. Trim normalises both literal and
    // `%20`-encoded leading/trailing whitespace (strictly safer than
    // the legacy pattern's trim-before-decode).
    let id_decoded: String = form_field(&body, "id")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    if !valid_user_id(&id_decoded) {
        return bad_request(&format!(
            "invalid user id '{id_decoded}' (allowed: 2-32 chars of a-z 0-9 . _ -; lowercase only)"
        ));
    }

    // Mint ALL secrets unconditionally — UUID, tuic_password, WG
    // keypair, sub_token. The form has only one field (`id`) so the
    // operator does ONE action (per CLAUDE.md "users are assumed
    // maximally low-tech" one-action ceiling — applies to the
    // operator UX too, not just the end user). Per-key management
    // (rotate WG keypair, replace pubkey with operator-provided, etc.)
    // lives on the user-detail page; creation is intentionally minimal.
    const TUIC_PW_BYTES: usize = 24;
    let tuic_password = match vpnctl_crypto::gen_password(TUIC_PW_BYTES) {
        Ok(pw) => pw,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    let (wg_priv, wg_pub) = vpnctl_crypto::gen_wireguard_keypair();
    // 2026-05-23 quickfix (Pavel: «добавил multiviruss и у него
    // только локальный конфиг»). Pre-fix, web user_create left
    // `vpn_router_device_id = NULL` and only the 33 Phase-3-imported
    // users got the production ninitux URL. Now we auto-mint a
    // 32-hex device_id on every web-create so the user-detail page
    // shows the production URL straight away — the legacy
    // `/sub/<token>` URL is demoted to «LAN fallback» as designed.
    // Mint failure (RNG) is fatal for the whole create — better to
    // refuse than to land in the «forgot the device_id again» state.
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
        // Migration 0026 default — newly-created users start enabled.
        disabled: false,
    };

    // Mutation. `AlreadyExists` (UNIQUE violation) gets a 400 with
    // the "already exists" body — operator's typical fix is to pick a
    // different id, no need to surface a generic 500.
    if let Err(e) = state.inv.add_user(&user).await {
        return match e {
            vpnctl_inventory::SqliteInventoryError::AlreadyExists(what) => {
                bad_request(&format!("{what} already exists — pick a different id"))
            }
            other => internal_error(anyhow::Error::new(other)),
        };
    }

    // Audit (best-effort; see module convention).
    // I1 unification (audit 2026-05-22): same payload shape as the
    // CLI path — `{uuid, wg_pubkey_set, wg_keypair_provenance}`.
    // Web ALWAYS server-generates the WG pair (the form has no
    // opt-out — operator preference is one-click). `wg_pubkey_set`
    // pinned at runtime against the actual mutation result rather
    // than hardcoded `true`; if a future regression makes wg_pub
    // None for any reason, the audit row will show it.
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

    // D1: grant access to every registered server, if the «grant
    // all servers» checkbox stays checked (default ON). Pre-
    // 2026-05-22 the user-create handler produced a user with ZERO
    // grants, then the operator had to drill into each server to
    // grant access. The form checkbox + this loop close the «one
    // click should produce a usable user» gap. Loop is sequential
    // (≤100 servers in homelab → ≤100ms total via the same indexed
    // grant path the per-server route uses); audit row per grant
    // matches `user_grant_server` semantics so the timeline can
    // still distinguish bulk-grant from individual grants by the
    // burst pattern.
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
                    // Audit each grant individually so the per-
                    // server timeline filter still surfaces the
                    // event. (Filtering by `action=user.grant` will
                    // include these rows alongside hand-grants.)
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
                    // ONE auto-deploy pass over every granted server
                    // (run_deploy_all deploys each server once) so the
                    // new user's UUID reaches all nodes' users[].
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

/// `GET /admin/users/{id}/delete-confirm` — destructive-action
/// double-submit confirm page (C-3.4). Renders a form that requires
/// the operator to retype the user-id; only a matching POST to
/// `/admin/users/{id}/delete` actually deletes.
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
    // v2 6c — the destroyed-scope table names the grants so the
    // operator sees exactly which nodes get a deploy queued.
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
                "← " (tr(lang, "back to ", "назад к ")) (user_id_str)
            }
        }
        div.ed-headrow {
            h1.ed-sumbar__h { (tr(lang, "Delete ", "Удалить ")) em { (user_id_str) } "?" }
        }
        // Point-of-no-return banner (red family, not warm).
        div style="display: flex; align-items: center; gap: 10px; border: 1px solid var(--red); border-left-width: 3px; background: color-mix(in oklab, var(--red) 8%, var(--paper)); padding: 9px 12px; margin: 10px 0 16px; font-family: var(--mono); font-size: 11px; color: var(--red);" {
            "✗ " b { (tr(lang, "Point of no return.", "Точка невозврата.")) }
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
                            td style="width: 20px; color: var(--red);" { "−" }
                            td { "uuid " span.ed-grid__mut { (user.uuid) } }
                        }
                        tr {
                            td style="color: var(--red);" { "−" }
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
                            td style="color: var(--red);" { "−" }
                            td {
                                (granted.len()) " " (tr(lang, "grants", "грантов"))
                                @if !granted.is_empty() {
                                    ": " (granted.join(", "))
                                    " " span.ed-grid__mut { "· " (tr(lang, "deploy queued on each", "деплой встанет на каждый")) }
                                }
                            }
                        }
                        tr {
                            td style="color: var(--red);" { "−" }
                            td {
                                (tr(lang, "subscription URL", "URL подписки"))
                                " " span.ed-grid__mut { "· " (tr(lang, "the mobile app gets 404 on next poll", "приложение получит 404 при следующем опросе")) }
                            }
                        }
                        tr {
                            td style="color: var(--green);" { "✓" }
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
                    )) { "ⓘ" }
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
                            (tr(lang, "cancel — keep the user", "отмена — оставить"))
                        }
                        button type="submit"
                               title=(format!("Delete user {user_id_str} permanently"))
                               class="ed-abtn ed-abtn--danger-solid" style="flex: 1;" {
                            (tr(lang, "delete forever", "удалить навсегда"))
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

/// `POST /admin/users/{id}/delete` — actually delete. Body must be
/// `confirm=<exact-user-id>`; mismatch → 400 (the GET-form sets up
/// the correct value, so a mismatch means the operator typed
/// something different on a manual curl OR a CSRF attempt slipped
/// past the middleware — neither is a normal flow).
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
    // Capture the user's servers BEFORE remove_user cascades the grants,
    // so the auto-deploy below can revoke their node access.
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
    // (B) Propagate the delete to the nodes — re-render configs (now without
    // this user) + reload sing-box — so a deleted user can't keep using a
    // cached config. Backgrounded; the redirect returns now.
    spawn_user_servers_redeploy(&state, servers, user_id_str.clone(), "user.remove");
    Redirect::to("/admin/users").into_response()
}

/// `POST /admin/users/{id}/disable` — set the disabled flag to
/// true (B1.user, migration 0026). Idempotent: re-POSTing on an
/// already-disabled user is a no-op redirect, no audit row written.
/// Returns 303 to the user-detail page so the operator sees the
/// «disabled» banner immediately.
pub(crate) async fn user_set_disabled_true(
    State(state): State<AppState>,
    Path(user_id_str): Path<String>,
) -> Response {
    user_set_disabled_inner(state, user_id_str, true).await
}

/// `POST /admin/users/{id}/enable` — restore access by clearing the
/// disabled flag. Same idempotency + audit shape as `disable`.
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
    // Audit-on-actual-mutation (NM-10 review-agent rule). No-op
    // re-POST writes nothing — timeline stays clean.
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

        // (B) Apply to the nodes without a manual «Deploy all»:
        // `users_for_server` now excludes disabled users, so this REVOKES
        // (disable) or RESTORES (enable) node access. Backgrounded.
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
