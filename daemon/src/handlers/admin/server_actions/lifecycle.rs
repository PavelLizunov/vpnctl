use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::handlers::admin::icons::icon;
use axum::extract::{Path, RawQuery, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use maud::html;
use tokio::sync::watch;

use super::super::helpers::{
    bad_request, error_resp, internal_error, not_found, render_page, shell, theme_accent_lang,
    valid_server_id,
};
use crate::AppState;
use crate::http_util::{form_field, path_segment_encode};
use crate::wizard_bootstrap::DeployGuard;
use vpnctl_core::Server;
use vpnctl_inventory::{SqliteInventory, SqliteInventoryError};

const DELETE_INLINE_WAIT: Duration = Duration::from_secs(2);
const DELETE_RESULT_TTL: Duration = Duration::from_secs(600);
const DELETE_PENDING_QUERY: &str = "deletion=pending";

#[derive(Clone)]
enum DeleteOutcome {
    Removed,
    Conflict(String),
    Failed,
}

impl IntoResponse for DeleteOutcome {
    fn into_response(self) -> Response {
        if let Some((status, message)) = self.problem() {
            error_resp(status, message)
        } else {
            Redirect::to("/admin/servers").into_response()
        }
    }
}

impl DeleteOutcome {
    fn problem(&self) -> Option<(StatusCode, &str)> {
        match self {
            Self::Removed => None,
            Self::Conflict(message) => Some((StatusCode::CONFLICT, message)),
            Self::Failed => Some((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Server removal could not be confirmed. Check the server list before retrying.",
            )),
        }
    }
}

type DeleteResult = Option<(Instant, DeleteOutcome)>;

#[derive(Default)]
pub(crate) struct ServerDeletions {
    jobs: Mutex<HashMap<String, watch::Receiver<DeleteResult>>>,
}

impl ServerDeletions {
    fn register(&self, id: String, receiver: watch::Receiver<DeleteResult>) {
        let mut jobs = self
            .jobs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        jobs.retain(|_, job| match job.borrow().as_ref() {
            Some((finished, _)) => finished.elapsed() < DELETE_RESULT_TTL,
            None => job.has_changed().is_ok(),
        });
        jobs.insert(id, receiver);
    }

    fn get(&self, id: &str) -> Option<watch::Receiver<DeleteResult>> {
        self.jobs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(id)
            .cloned()
    }
}

pub(crate) async fn server_set_routing_policy(
    State(state): State<AppState>,
    Path(id): Path<String>,
    body: String,
) -> Response {
    let sid = vpnctl_core::ServerId(id.clone());
    if match state.inv.get_server(&sid).await {
        Ok(Some(_)) => false,
        Ok(None) => true,
        Err(error) => return internal_error(anyhow::Error::new(error)),
    } {
        return not_found(&format!("no such server '{id}'"));
    }
    let Some(role) = form_field(&body, "role") else {
        return bad_request("role field is required");
    };
    let role: vpnctl_inventory::ServerRole = match role.parse() {
        Ok(value) => value,
        Err(error) => return bad_request(&error.to_string()),
    };
    let Some(jump_field) = form_field(&body, "jump_via") else {
        return bad_request("jump_via field is required (blank means direct)");
    };
    let jump = Some(jump_field)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(vpnctl_core::ServerId);
    if let Err(error) = state
        .inv
        .set_server_routing_policy_as("admin", &sid, role, jump.as_ref())
        .await
    {
        return bad_request(&error.to_string());
    }
    Redirect::to(&format!(
        "/admin/servers/{}/setup#routing-policy",
        path_segment_encode(&id)
    ))
    .into_response()
}

pub(crate) async fn server_set_client_detour_via(
    State(state): State<AppState>,
    Path(id): Path<String>,
    body: String,
) -> Response {
    let sid = vpnctl_core::ServerId(id.clone());
    if match state.inv.get_server(&sid).await {
        Ok(Some(_)) => false,
        Ok(None) => true,
        Err(error) => return internal_error(anyhow::Error::new(error)),
    } {
        return not_found(&format!("no such server '{id}'"));
    }
    let Some(detour_field) = form_field(&body, "client_detour_via") else {
        return bad_request("client_detour_via field is required (blank means direct)");
    };
    let detour = Some(detour_field)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(vpnctl_core::ServerId);
    if let Err(error) = state
        .inv
        .set_client_detour_via_as("admin", &sid, detour.as_ref())
        .await
    {
        return bad_request(&error.to_string());
    }
    Redirect::to(&format!(
        "/admin/servers/{}/setup#client-detour",
        path_segment_encode(&id)
    ))
    .into_response()
}

pub(crate) async fn server_set_desktop_subscription(
    State(state): State<AppState>,
    Path(id): Path<String>,
    body: String,
) -> Response {
    let Some(core_field) = form_field(&body, "core_version") else {
        return bad_request("core_version field is required");
    };
    let core_version = core_field.trim();
    let server = vpnctl_core::ServerId(id.clone());
    match state
        .inv
        .set_desktop_subscription_core(&server, (!core_version.is_empty()).then_some(core_version))
        .await
    {
        Ok(true) => Redirect::to(&format!(
            "/admin/servers/{}/setup#desktop-subscription",
            path_segment_encode(&id)
        ))
        .into_response(),
        Ok(false) => not_found(&format!("no such server '{id}'")),
        Err(vpnctl_inventory::SqliteInventoryError::Invalid(message)) => bad_request(&message),
        Err(error) => internal_error(anyhow::Error::new(error)),
    }
}

pub(crate) async fn server_quick_add(State(state): State<AppState>, body: String) -> Response {
    let id: String = form_field(&body, "id")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    if !valid_server_id(&id) {
        return bad_request(&format!(
            "invalid server id '{id}' (allowed: 1-64 chars of A-Z a-z 0-9 . _ -; must start and end with alphanumeric; no consecutive dots)"
        ));
    }

    let address_raw: String = form_field(&body, "address")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let address = match crate::wizard::validate_address(&address_raw) {
        Ok(s) => s.to_string(),
        Err(why) => {
            return bad_request(&format!("invalid address: {why}"));
        }
    };

    match state.inv.server_id_for_address(&address).await {
        Ok(Some(existing)) => {
            return bad_request(&format!(
                "address '{address}' is already registered to server '{existing}' — one node = one server record; edit '{existing}' instead of adding a duplicate"
            ));
        }
        Ok(None) => {}
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }

    let ssh_port: u16 = form_field(&body, "ssh_port")
        .and_then(|s| s.parse().ok())
        .unwrap_or(22);

    use vpnctl_core::{KernelId, ProtocolId, Server, ServerId};
    let kernel_id = KernelId("sing-box".into());
    let supported: Vec<ProtocolId> = state
        .registry
        .kernel(&kernel_id)
        .map(|k| k.supported_protocols())
        .unwrap_or_default();
    let default_protocols =
        crate::wizard_bootstrap::default_server_protocols(ssh_port, supported, &state.registry);

    let server = Server {
        id: ServerId(id.clone()),
        address: address.clone(),
        ssh_port,
        ssh_user: "root".into(),
        kernels: vec![kernel_id],
        enabled_protocols: default_protocols.clone(),
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    };

    if let Err(e) =
        crate::boosty_bandwidth::register_new_server(&state.inv, &server, &state.boosty_roster_url)
            .await
    {
        return match e {
            vpnctl_inventory::SqliteInventoryError::AlreadyExists(what) => {
                bad_request(&format!("{what} already exists"))
            }
            other => internal_error(anyhow::Error::new(other)),
        };
    }

    if let Err(e) = state
        .inv
        .audit(
            "admin",
            "server.quick_add",
            Some(&id),
            Some(&serde_json::json!({
                "address": address,
                "ssh_port": ssh_port,
                "kernels": ["sing-box"],
                "protocols": default_protocols.iter().map(|p| &p.0).collect::<Vec<_>>(),
            })),
        )
        .await
    {
        tracing::warn!(
            target = "vpnctld::admin",
            server = %id,
            error = %e,
            "audit write failed for server.quick_add"
        );
    }

    Redirect::to(&format!("/admin/servers/{}", path_segment_encode(&id))).into_response()
}

pub(crate) async fn server_delete_confirm(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(server_id_str): Path<String>,
    RawQuery(query): RawQuery,
) -> Response {
    use crate::i18n::tr;
    let (theme, accent, lang) = theme_accent_lang(&headers);
    let checking_status = query.as_deref() == Some(DELETE_PENDING_QUERY);
    if let Some(job) = state.server_deletions.get(&server_id_str)
        && let Some(response) = deletion_status(&job, &server_id_str, checking_status, &headers)
    {
        return response;
    }
    let sid = vpnctl_core::ServerId(server_id_str.clone());
    let server = match state.inv.get_server(&sid).await {
        Ok(Some(s)) => s,
        Ok(None) if checking_status => return Redirect::to("/admin/servers").into_response(),
        Ok(None) => return not_found(&format!("no such server '{server_id_str}'")),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    let grant_count = match state.inv.users_for_server(&sid).await {
        Ok(v) => Some(v.len()),
        Err(e) => {
            tracing::warn!(
                target = "vpnctld::admin",
                server = %server_id_str,
                error = %e,
                "users_for_server failed on delete-confirm; rendering count as unknown"
            );
            None
        }
    };
    let is_telegram_proxy = match state.inv.get_telegram_config().await {
        Ok(cfg) => cfg
            .and_then(|c| c.proxy_via_server_id)
            .is_some_and(|p| p == server_id_str),
        Err(e) => {
            tracing::warn!(
                target = "vpnctld::admin",
                server = %server_id_str,
                error = %e,
                "get_telegram_config failed on delete-confirm; relay warning suppressed"
            );
            false
        }
    };
    let back = format!("/admin/servers/{}", path_segment_encode(&server_id_str));
    let body = html! {
        div.ed-art-eyebrow {
            a href=(back) style="color: var(--mute); text-decoration: none;" { (icon("arrow-left")) (tr(lang, "back to server", "назад к серверу")) }
            (tr(lang, "  ·  delete", "  ·  удаление"))
        }
        h1.ed-art-h1 { (tr(lang, "delete ", "удалить ")) em { (server_id_str) } (tr(lang, " — really?", " — точно?")) }
        @if checking_status {
            p.ed-alert.ed-alert--warn role="alert" {
                (tr(lang, "The previous deletion status is unavailable. The server is still in the inventory.", "Состояние предыдущего удаления недоступно. Сервер всё ещё в инвентаре."))
            }
        }
        p.ed-art-deck {
            (tr(lang, "Drops the server (", "Удаляет сервер (")) span.ed-mono { (server.address) } (tr(lang, ") from the inventory. ", ") из инвентаря. "))
            b {
                @match grant_count {
                    Some(n) => { (n) (tr(lang, " grant(s)", " разрешений доступа")) },
                    None => { (tr(lang, "an unknown number of grants (inventory read failed — reload to retry)", "неизвестное число разрешений доступа (не удалось прочитать инвентарь — обнови страницу для повторной попытки)")) },
                }
            }
            (tr(lang, " cascade-delete — those users lose this server from their subscription on the next pull. ", " удаляются каскадно — эти пользователи потеряют сервер в подписке при следующем обновлении. "))
            b { (tr(lang, "Secrets", "Секреты")) }
            (tr(lang, " (REALITY keypair, short_id, obfs passwords) are deleted — re-adding the server later generates BRAND-NEW ones. ", " (пара ключей REALITY, short_id, пароли obfs) удаляются — при повторном добавлении сервера будут созданы НОВЫЕ. "))
            (tr(lang, "Protocols, kernels, probe history + alerts also cascade. If another server uses this one as a ProxyJump host, that link is cleared. ", "Протоколы, ядра, история проверок и алерты тоже удаляются. Если другой сервер использует этот как ProxyJump, эта связь будет сброшена. "))
            b { (tr(lang, "The sing-box on the node itself is NOT touched", "Сам sing-box на ноде НЕ затрагивается")) }
            (tr(lang, " — if the VPS stays running, stop or remove sing-box through the hosting provider's console.", " — если VPS продолжает работать, останови или удали sing-box через консоль хостера."))
        }
        @if is_telegram_proxy {
            p style="font-family: var(--mono); font-size: 11px; color: var(--acc); border: 1px solid var(--acc); padding: 8px 12px; margin: 10px 0;" {
                b { (tr(lang, "This server is the Telegram alert relay", "Этот сервер пересылает алерты в Telegram")) }
                (tr(lang, " (Settings → Notifications → egress). Deleting it breaks every alert send until you pick another relay or clear the setting.", " (Настройки → Уведомления → выход). После удаления отправка всех алертов перестанет работать, пока ты не выберешь другой сервер или не очистишь настройку."))
            }
        }
        p style="font-family: var(--serif); font-style: italic; color: var(--mute); padding: 8px 0;" {
            (tr(lang, "Type the server-id ", "Введи ID сервера "))
            span.ed-mono { (server_id_str) }
            (tr(lang, " in the box below to confirm. Exact match — copy/paste counts.", " в поле ниже для подтверждения. Нужно точное совпадение — можно скопировать и вставить."))
        }
        form method="post"
             action=(format!("/admin/servers/{}/delete", path_segment_encode(&server_id_str)))
             style="display: flex; gap: 10px; align-items: baseline; padding: 14px 16px; border: 1px solid var(--rule); margin: 16px 0;" {
            label style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase;" {
                (tr(lang, "confirm id", "подтверди ID"))
            }
            input type="text" name="confirm" required="required"
                  autocomplete="off"
                  style="flex: 1; max-width: 280px; padding: 4px 8px; border: 1px solid var(--rule-s); background: var(--paper); font-family: var(--mono); font-size: 12px; color: var(--ink);";
            button type="submit"
                   title=(format!("{} {server_id_str} {}", tr(lang, "Delete server", "Удалить сервер"), tr(lang, "from the inventory permanently", "из инвентаря навсегда")))
                   class="ed-abtn ed-abtn--danger-solid" {
                (icon("trash-2")) (tr(lang, "delete forever", "удалить навсегда"))
            }
            a href=(back)
              class="ed-abtn ed-abtn--secondary ed-abtn--sm" {
                (icon("x")) (tr(lang, "cancel", "отмена"))
            }
        }
    };
    render_page(&state, "servers", &theme, &accent, lang, body)
        .await
        .into_response()
}

fn delete_status_path(id: &str) -> String {
    format!(
        "/admin/servers/{}/delete-confirm?{DELETE_PENDING_QUERY}",
        path_segment_encode(id)
    )
}

fn deletion_status(
    job: &watch::Receiver<DeleteResult>,
    id: &str,
    checking_status: bool,
    headers: &HeaderMap,
) -> Option<Response> {
    use crate::i18n::tr;
    let result = job.borrow();
    let (theme, accent, lang) = theme_accent_lang(headers);
    let outcome = match result.as_ref() {
        None if job.has_changed().is_ok() => {
            let status_path = delete_status_path(id);
            if !checking_status {
                return Some(Redirect::to(&status_path).into_response());
            }
            let body = html! {
                h1.ed-art-h1 { (tr(lang, "Removing ", "Удаляем ")) em { (id) } }
                p.ed-art-deck data-server-delete-pending="" data-reload-after="2" role="status" {
                    (tr(lang, "Removing the server and its history from the inventory.", "Удаляем сервер и его историю из инвентаря."))
                }
                a.ed-abtn.ed-abtn--secondary href=(status_path) {
                    (tr(lang, "Check status", "Проверить состояние"))
                }
            };
            return Some(shell("servers", &theme, &accent, lang, 0, body).into_response());
        }
        Some((finished, outcome)) if checking_status && finished.elapsed() < DELETE_RESULT_TTL => {
            outcome
        }
        None if checking_status => &DeleteOutcome::Failed,
        _ => return None,
    };
    let Some((status, message)) = outcome.problem() else {
        return Some(Redirect::to("/admin/servers").into_response());
    };
    let body = html! {
        h1.ed-art-h1 { (tr(lang, "Removal failed", "Не удалось удалить сервер")) }
        p.ed-alert.ed-alert--warn role="alert" { (message) }
        a.ed-abtn.ed-abtn--secondary href="/admin/servers" {
            (tr(lang, "Back to servers", "К списку серверов"))
        }
    };
    Some((status, shell("servers", &theme, &accent, lang, 0, body)).into_response())
}

pub(crate) async fn server_delete(
    State(state): State<AppState>,
    Path(server_id_str): Path<String>,
    body: String,
) -> Response {
    let confirm = form_field(&body, "confirm").unwrap_or_default();
    if confirm != server_id_str {
        return bad_request(&format!(
            "delete confirm mismatch: form sent '{confirm}', URL targets '{server_id_str}' — type the server id exactly to confirm"
        ));
    }
    let deploy_guard = match DeployGuard::try_acquire(&server_id_str) {
        Some(g) => g,
        None => {
            return error_resp(
                StatusCode::CONFLICT,
                &format!(
                    "deploy in flight for server '{server_id_str}' — wait for it to finish, then delete"
                ),
            );
        }
    };
    let sid = vpnctl_core::ServerId(server_id_str.clone());
    let server = match state.inv.get_server(&sid).await {
        Ok(Some(s)) => s,
        Ok(None) => return not_found(&format!("no such server '{server_id_str}'")),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    let (sender, mut receiver) = watch::channel(None);
    let pending_path = delete_status_path(&server_id_str);
    state
        .server_deletions
        .register(server_id_str, receiver.clone());
    tokio::spawn(async move {
        let outcome = remove_server(&state.inv, server).await;
        sender.send_replace(Some((Instant::now(), outcome)));
        drop(deploy_guard);
    });

    match tokio::time::timeout(DELETE_INLINE_WAIT, receiver.changed()).await {
        Ok(Ok(())) => receiver.borrow().as_ref().map_or_else(
            || DeleteOutcome::Failed.into_response(),
            |(_, outcome)| outcome.clone().into_response(),
        ),
        Ok(Err(_)) => DeleteOutcome::Failed.into_response(),
        Err(_) => Redirect::to(&pending_path).into_response(),
    }
}

async fn remove_server(inv: &SqliteInventory, server: Server) -> DeleteOutcome {
    let grants_removed = inv
        .users_for_server(&server.id)
        .await
        .map(|v| v.len())
        .unwrap_or(0);
    if let Err(e) = inv.remove_server(&server.id).await {
        return match e {
            SqliteInventoryError::Invalid(message) => DeleteOutcome::Conflict(message),
            e => {
                tracing::error!(server = %server.id.0, error = %e, "server removal failed");
                DeleteOutcome::Failed
            }
        };
    }
    if let Err(e) = inv
        .audit(
            "admin",
            "server.remove",
            Some(&server.id.0),
            Some(&serde_json::json!({
                "address": server.address,
                "grants_removed": grants_removed,
            })),
        )
        .await
    {
        tracing::warn!(
            target = "vpnctld::admin",
            server = %server.id.0,
            error = %e,
            "audit row for server.remove failed; mutation already committed"
        );
    }
    DeleteOutcome::Removed
}
