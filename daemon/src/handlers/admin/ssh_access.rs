use axum::extract::{Path, State};
use axum::response::{IntoResponse, Redirect, Response};
use maud::{Markup, html};
use vpnctl_core::{Server, ServerId};
use vpnctl_inventory::{SshAccessCheck, SshAccessFailure, SshAccessState, SshAccessStatus};

use crate::AppState;
use crate::handlers::admin::helpers::{format_msk_iso, internal_error, not_found};
use crate::http_util::path_segment_encode;
use crate::i18n::{Locale, tr};

pub(crate) async fn recheck(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let server = match state.inv.get_server(&ServerId(id.clone())).await {
        Ok(Some(server)) => server,
        Ok(None) => return not_found(&format!("no such server '{id}'")),
        Err(error) => return internal_error(anyhow::Error::new(error)),
    };
    crate::ssh_access::start_check(state.inv, server);
    Redirect::to(&format!(
        "/admin/servers/{}/status#ssh-access",
        path_segment_encode(&id)
    ))
    .into_response()
}

fn failure_label(failure: SshAccessFailure, lang: Locale) -> &'static str {
    match failure {
        SshAccessFailure::Timeout => tr(lang, "Connection timed out", "Время подключения истекло"),
        SshAccessFailure::Authentication => tr(
            lang,
            "Deploy key was not accepted",
            "Ключ доступа не принят",
        ),
        SshAccessFailure::HostKey => tr(
            lang,
            "Server identity could not be verified",
            "Не удалось подтвердить ключ сервера",
        ),
        SshAccessFailure::Connection => tr(
            lang,
            "SSH connection could not be established",
            "Не удалось установить SSH-соединение",
        ),
        SshAccessFailure::MissingKey => {
            tr(lang, "Deploy key is unavailable", "Ключ доступа недоступен")
        }
        SshAccessFailure::InvalidRoute => tr(
            lang,
            "SSH route or server identity is not configured",
            "Не настроен SSH-маршрут или ключ сервера",
        ),
        SshAccessFailure::Stale => tr(lang, "No fresh measurement", "Нет свежего измерения"),
    }
}

fn badge(check: Option<&SshAccessCheck>, lang: Locale) -> Markup {
    let state = check.map_or(SshAccessState::Unknown, |c| c.state);
    let (label, color, code) = match state {
        SshAccessState::Available => (
            tr(lang, "Available", "Доступен"),
            "var(--soft)",
            "available",
        ),
        SshAccessState::Unavailable => (
            tr(lang, "Unavailable", "Недоступен"),
            "var(--acc)",
            "unavailable",
        ),
        SshAccessState::Unknown => (
            tr(lang, "Not verified", "Не проверен"),
            "var(--mute)",
            "unknown",
        ),
    };
    html! {
        span data-ssh-state=(code) style=(format!("color:{color};")) { (label) }
        @if let Some(check) = check {
            small.ed-grid__mut style="display:block;" {
                time datetime=(check.checked_at.to_rfc3339()) { (format_msk_iso(check.checked_at)) }
            }
            @if let Some(reason) = check.failure {
                small.ed-grid__mut style="display:block;" { (failure_label(reason, lang)) }
            }
        }
    }
}

pub(super) fn inline_status(
    server: &Server,
    status: Option<&SshAccessStatus>,
    lang: Locale,
) -> Markup {
    html! {
        div data-ssh-route="direct" {
            small.ed-grid__mut { (tr(lang, "Direct: ", "Напрямую: ")) }
            (badge(status.and_then(|s| s.direct.as_ref()), lang))
        }
        div data-ssh-route="jump" style="margin-top:6px;" {
            small.ed-grid__mut { (tr(lang, "Via jump: ", "Через jump: ")) }
            @if server.jump_via.is_some() { (badge(status.and_then(|s| s.jump.as_ref()), lang)) }
            @else { span.ed-grid__mut data-ssh-state="not-configured" { (tr(lang, "Not configured", "Не настроен")) } }
        }
    }
}

pub(super) fn detail_section(
    server: &Server,
    status: Option<&SshAccessStatus>,
    checking: bool,
    lang: Locale,
) -> Markup {
    let id = path_segment_encode(&server.id.0);
    html! {
        section #ssh-access style="margin:0 0 24px;" data-reload-after=[checking.then_some("3")] {
            h2 { (tr(lang, "SSH access", "SSH-доступ")) }
            p.ed-grid__mut { (tr(lang,
                "Independent SSH logins from vpnctld using its deploy key. Availability requires successful authentication. VPN connectivity is shown separately.",
                "Независимые SSH-подключения с vpnctld его ключом доступа. Доступность означает успешный вход. Работоспособность VPN показана отдельно.")) }
            div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin-bottom:12px;" {
                div data-ssh-route="direct" {
                    h3 { (tr(lang, "Direct", "Напрямую")) }
                    (badge(status.and_then(|s| s.direct.as_ref()), lang))
                }
                div data-ssh-route="jump" {
                    h3 { (tr(lang, "Via jump server", "Через jump-сервер")) }
                    @if let Some(jump) = server.jump_via.as_ref() {
                        (badge(status.and_then(|s| s.jump.as_ref()), lang))
                        p.ed-grid__mut {
                            (tr(lang, "Via ", "Через "))
                            a href=(format!("/admin/servers/{}", path_segment_encode(&jump.0))) { (jump.0) }
                        }
                    } @else {
                        span.ed-grid__mut data-ssh-state="not-configured" { (tr(lang, "Not configured", "Не настроен")) }
                        p { a href=(format!("/admin/servers/{id}/setup#routing-policy")) { (tr(lang, "Configure jump server", "Настроить jump-сервер")) } }
                    }
                }
            }
            form method="post" action=(format!("/admin/servers/{id}/ssh-check")) {
                button.ed-abtn.ed-abtn--secondary type="submit" disabled[checking] {
                    (tr(lang, "Check SSH access", "Проверить SSH-доступ"))
                }
                @if checking { span.ed-grid__mut role="status" { " " (tr(lang, "Checking… results will refresh automatically.", "Проверяем… результаты обновятся автоматически.")) } }
            }
        }
    }
}
