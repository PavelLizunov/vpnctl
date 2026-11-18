use std::collections::HashSet;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use maud::{Markup, html};
use vpnctl_core::{Server, ServerId};

use super::helpers::{
    bad_request, error_resp, format_msk_iso, internal_error, not_found, render_page,
    server_identity, server_names, theme_accent_lang,
};
use crate::AppState;
use crate::http_util::path_segment_encode;
use crate::i18n::{Locale, tr};
use crate::server_security::{
    self, APPLY_AUDIT, ApplyError, ApplyOutcome, BlockReason, CheckState, Nginx, Observation,
};
use crate::wizard_bootstrap::DeployGuard;

const FLEET: &str = "/admin/monitoring/security";

pub(super) fn label(lang: Locale) -> &'static str {
    tr(lang, "Security updates", "Обновления безопасности")
}

pub(super) fn path(id: &ServerId) -> String {
    format!("/admin/servers/{}/security", path_segment_encode(&id.0))
}

fn status(obs: Option<&Observation>, lang: Locale) -> Markup {
    let Some(obs) = obs else {
        return html! { (tr(lang, "Not checked", "Не проверено")) };
    };
    let label = if obs.stale() {
        tr(lang, "Check is out of date", "Проверка устарела")
    } else {
        match obs.report.state {
            CheckState::Checked if obs.report.packages.is_empty() => tr(
                lang,
                "No pending security updates in APT",
                "В APT нет ожидающих обновлений безопасности",
            ),
            CheckState::Checked => {
                return html! {
                    (obs.report.packages.len()) " "
                    (tr(lang, "security updates pending", "обновлений безопасности ожидают установки"))
                };
            }
            CheckState::Unsupported => tr(
                lang,
                "Unsupported OS release",
                "Выпуск ОС не поддерживается",
            ),
            CheckState::MissingApt => tr(
                lang,
                "System Python or python3-apt is missing",
                "Нет системного Python или python3-apt",
            ),
            CheckState::NoSecurityIndex => tr(
                lang,
                "Trusted APT security index unavailable",
                "Доверенный индекс безопасности APT недоступен",
            ),
            CheckState::DpkgUnsettled => tr(
                lang,
                "APT package state needs repair",
                "Состояние пакетов APT требует восстановления",
            ),
            CheckState::RefreshFailed => tr(
                lang,
                "APT index refresh failed",
                "Не удалось обновить индексы APT",
            ),
            CheckState::HostIdentity => tr(
                lang,
                "Verify the server's SSH route and host key",
                "Проверьте SSH-маршрут и ключ сервера",
            ),
            CheckState::Busy => tr(
                lang,
                "Package maintenance already running",
                "Обслуживание пакетов уже выполняется",
            ),
            CheckState::Unavailable => tr(lang, "Check unavailable", "Проверка недоступна"),
        }
    };
    html! { (label) }
}

fn time(obs: &Observation) -> Markup {
    html! { time datetime=(obs.checked_at.to_rfc3339()) { (format_msk_iso(obs.checked_at)) } }
}

pub(crate) async fn fleet(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Markup, Response> {
    let (theme, accent, lang) = theme_accent_lang(&headers);
    let (servers, mut stored) = tokio::try_join!(
        state.inv.list_servers(),
        state.inv.server_security_reports()
    )
    .map_err(|err| internal_error(anyhow::Error::new(err)))?;
    let names = server_names(&state.inv, &servers).await?;
    let mut rows = Vec::with_capacity(servers.len());
    for server in &servers {
        let report =
            server_security::observation(&state.inv, server, stored.remove(&server.id)).await;
        rows.push((server, report));
    }
    let body = html! {
        div.ed-tabs {
            a.ed-tab href="/admin/servers" { (tr(lang, "All servers", "Все серверы")) }
            a.ed-tab href="/admin/servers/billing" { (tr(lang, "Billing & Rental", "Оплата и аренда")) }
            a.ed-tab.ed-tab--on href=(FLEET) aria-current="page" { (label(lang)) }
        }
        h1.ed-sumbar__h { (label(lang)) }
        p { (tr(lang,
            "Review pending Debian and Ubuntu security updates across your servers.",
            "Проверяйте ожидающие обновления безопасности Debian и Ubuntu на всех серверах.")) }
        @if rows.is_empty() {
            p { (tr(lang, "Add a server to start checking for updates.", "Добавьте сервер, чтобы начать проверку обновлений.")) }
            a.ed-abtn.ed-abtn--secondary href="/admin/servers/new" { (tr(lang, "Add server", "Добавить сервер")) }
        } @else {
            div.ed-grid-wrap {
                table.ed-grid {
                    thead { tr {
                        th scope="col" { (tr(lang, "Server", "Сервер")) }
                        th scope="col" { (tr(lang, "APT security updates", "Обновления безопасности APT")) }
                        th scope="col" { (tr(lang, "Last check", "Последняя проверка")) }
                    } }
                    tbody {
                        @for (server, obs) in &rows {
                            tr {
                                th scope="row" {
                                    a.ed-grid__open href=(path(&server.id)) {
                                        (server_identity(&server.id, names.get(&server.id).map(String::as_str)))
                                    }
                                }
                                td {
                                    (status(obs.as_ref(), lang))
                                    @if let Some(nginx) = obs.as_ref().filter(|o| !o.stale()).and_then(|o| o.report.nginx.as_ref()) {
                                        div.ed-grid__sm { "NGINX · " (nginx_http2(nginx, lang)) }
                                    }
                                }
                                td { @if let Some(obs) = obs { (time(obs)) } @else { "—" } }
                            }
                        }
                    }
                }
            }
        }
    };
    Ok(render_page(&state, "servers", &theme, &accent, lang, body).await)
}

fn nginx_http2(nginx: &Nginx, lang: Locale) -> &'static str {
    match nginx.http2 {
        Some(true) => tr(lang, "HTTP/2 directive found", "Найдена директива HTTP/2"),
        Some(false) => tr(
            lang,
            "HTTP/2 directive not found",
            "Директива HTTP/2 не найдена",
        ),
        None => tr(lang, "Configuration unavailable", "Конфигурация недоступна"),
    }
}

fn nginx_advisories(nginx: &Nginx, lang: Locale) -> Markup {
    html! {
        section {
            h2 { "NGINX" }
            p {
                (nginx_http2(nginx, lang)) ". "
                (tr(lang, "This checks the configuration on disk. Verify live HTTP/2 exposure and distro backports separately.",
                    "Проверяется конфигурация на диске. Доступность HTTP/2 на работающем сервере и исправления дистрибутива проверяются отдельно."))
            }
            dl {
                dt { (tr(lang, "Installed binary", "Установленный бинарный файл")) }
                dd { (nginx.installed.as_deref().unwrap_or("—")) }
                dt { (tr(lang, "Running systemd service version", "Версия запущенной службы systemd")) }
                dd { (nginx.running.as_deref().unwrap_or("—")) }
            }
            p {
                (tr(lang, "HTTP/2 advisories", "Бюллетени по HTTP/2")) " "
                a href="https://nginx.org/en/security_advisories.html" {
                    "CVE-2026-123007 · CVE-2026-123633"
                }
            }
        }
    }
}

fn packages(obs: &Observation, endpoint: &str, busy: bool, lang: Locale) -> Markup {
    let actionable = !busy
        && !obs.stale()
        && obs.report.state == CheckState::Checked
        && obs.report.packages.iter().any(|pkg| pkg.blocked.is_none());
    html! {
        form method="post" action=[actionable.then(|| format!("{endpoint}/apply"))] {
            div.ed-grid-wrap {
                table.ed-grid {
                    thead { tr {
                        th scope="col" { (tr(lang, "Package", "Пакет")) }
                        th scope="col" { (tr(lang, "Installed", "Установленная версия")) }
                        th scope="col" { (tr(lang, "Security version", "Версия с исправлением")) }
                    } }
                    tbody {
                        @for package in &obs.report.packages {
                            tr {
                                th scope="row" {
                                    @if actionable && package.blocked.is_none() {
                                        label {
                                            input type="checkbox" name="package" value=(package.name);
                                            " " code { (package.name) }
                                        }
                                    } @else {
                                        code { (package.name) }
                                    }
                                    @match package.blocked {
                                        Some(BlockReason::Held) => {
                                            div.ed-grid__sm { (tr(lang, "Held by APT", "Версия закреплена в APT")) }
                                        }
                                        Some(BlockReason::Policy) => {
                                            div.ed-grid__sm { (tr(lang, "Blocked by APT policy", "Заблокировано политикой APT")) }
                                        }
                                        None => {}
                                    }
                                }
                                td { code { (package.installed) } }
                                td { code { (package.candidate) } }
                            }
                        }
                    }
                }
            }
            @if actionable {
                input type="hidden" name="revision" value=(obs.revision);
                p { label {
                    input type="checkbox" name="confirm" value="yes" required;
                    " " (tr(lang,
                        "I have a maintenance window. Installing updates can restart services.",
                        "Окно обслуживания согласовано. Установка обновлений может перезапустить службы."))
                } }
                button.ed-abtn.ed-abtn--secondary type="submit" {
                    (tr(lang, "Install selected updates", "Установить выбранные обновления"))
                }
            }
        }
    }
}

fn apply_status(outcome: ApplyOutcome, lang: Locale) -> &'static str {
    match outcome {
        ApplyOutcome::Started => tr(
            lang,
            "Installation started; result is still pending.",
            "Установка запущена. Результат пока неизвестен.",
        ),
        ApplyOutcome::Verified => tr(
            lang,
            "Installed package versions verified. Check service health before closing maintenance.",
            "Установленные версии пакетов подтверждены. Перед завершением обслуживания проверьте состояние служб.",
        ),
        ApplyOutcome::Changed => tr(
            lang,
            "Package versions or server details changed. Check again before installing.",
            "Версии пакетов или параметры сервера изменились. Повторите проверку перед установкой.",
        ),
        ApplyOutcome::RequiresOtherChanges => tr(
            lang,
            "APT needs additional package changes. Review related updates together.",
            "APT требует дополнительных изменений. Проверьте связанные обновления вместе.",
        ),
        ApplyOutcome::Blocked => tr(
            lang,
            "APT is busy or cannot start this transaction.",
            "APT занят или не может начать эту операцию.",
        ),
        ApplyOutcome::InstallUnverified => tr(
            lang,
            "Installation could not be verified. Some packages may have changed.",
            "Результат установки не подтверждён. Некоторые пакеты могли измениться.",
        ),
    }
}

async fn server(state: &AppState, id: String) -> Result<Server, Response> {
    state
        .inv
        .get_server(&ServerId(id))
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?
        .ok_or_else(|| not_found("no such server"))
}

pub(crate) async fn detail(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Markup, Response> {
    let (theme, accent, lang) = theme_accent_lang(&headers);
    let server = server(&state, id).await?;
    let names = server_names(&state.inv, std::slice::from_ref(&server)).await?;
    let stored = state
        .inv
        .server_security_report(&server.id)
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;
    let last_audit = state
        .inv
        .latest_audit_for_target_action(&server.id.0, APPLY_AUDIT)
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;
    let last_apply = stored.as_ref().and_then(|report| {
        let audit = last_audit?;
        let payload = audit.payload?;
        if payload.get("route_fingerprint")?.as_str()? != report.route_fingerprint {
            return None;
        }
        Some((
            audit.ts,
            serde_json::from_value::<ApplyOutcome>(payload.get("outcome")?.clone()).ok()?,
        ))
    });
    let obs = server_security::observation(&state.inv, &server, stored).await;
    let endpoint = path(&server.id);
    let busy = DeployGuard::is_active(&server.id.0);
    let body = html! {
        nav.ed-tabs aria-label=(tr(lang, "Server navigation", "Навигация по серверу")) {
            a.ed-tab href=(FLEET) { (label(lang)) }
            a.ed-tab href=(format!("/admin/servers/{}", path_segment_encode(&server.id.0))) {
                (server_identity(&server.id, names.get(&server.id).map(String::as_str)))
            }
        }
        div.ed-headrow {
            h1.ed-sumbar__h { (label(lang)) }
            div.ed-headrow__actions {
                @if busy {
                    a.ed-abtn.ed-abtn--secondary href=(endpoint) { (tr(lang, "Refresh status", "Обновить статус")) }
                } @else {
                    form method="post" action=(format!("{endpoint}/check")) {
                        button.ed-abtn.ed-abtn--secondary type="submit" {
                            (tr(lang, "Check for updates", "Проверить обновления"))
                        }
                    }
                }
            }
        }
        p role="status" {
            @if busy {
                (tr(lang, "Server maintenance in progress", "Выполняется обслуживание сервера"))
            } @else {
                (status(obs.as_ref(), lang))
            }
            @if let Some(obs) = &obs { " · " (time(obs)) }
        }
        @if let Some(obs) = &obs {
            @if let Some((finished_at, outcome)) = last_apply {
                p role="status" {
                    @if outcome == ApplyOutcome::Started && !busy {
                        (tr(lang, "Last installation has no recorded result. Check again and verify service health.",
                            "Результат последней установки не записан. Повторите проверку и проверьте состояние служб."))
                    } @else {
                        (apply_status(outcome, lang))
                    }
                    " "
                    time datetime=(finished_at.to_rfc3339()) { (format_msk_iso(finished_at)) }
                }
            }
            @if obs.report.reboot_required {
                p { (tr(lang, "The OS reports that a reboot is required.", "ОС сообщает, что требуется перезагрузка.")) }
            }
            @if !obs.report.packages.is_empty() {
                (packages(obs, &endpoint, busy, lang))
            }
            @if let Some(nginx) = &obs.report.nginx {
                (nginx_advisories(nginx, lang))
            }
        }
    };
    Ok(render_page(&state, "servers", &theme, &accent, lang, body).await)
}

pub(crate) async fn check(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Redirect, Response> {
    let server = server(&state, id).await?;
    let endpoint = path(&server.id);
    if !server_security::start_check(state.inv, server) {
        return Err(error_resp(
            StatusCode::CONFLICT,
            "server maintenance is already in progress",
        ));
    }
    Ok(Redirect::to(&endpoint))
}

pub(crate) async fn apply(
    State(state): State<AppState>,
    Path(id): Path<String>,
    body: String,
) -> Result<Response, Response> {
    let fields: Vec<_> = url::form_urlencoded::parse(body.as_bytes()).collect();
    let revision = fields
        .iter()
        .find(|(key, _)| key == "revision")
        .and_then(|(_, value)| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| bad_request("a valid security report revision is required"))?;
    let packages: Vec<_> = fields
        .iter()
        .filter(|(key, _)| key == "package")
        .map(|(_, value)| value.to_string())
        .collect();
    let unique: HashSet<_> = packages.iter().collect();
    if packages.is_empty()
        || packages.len() != unique.len()
        || packages.len() > 512
        || packages.iter().any(String::is_empty)
        || !fields
            .iter()
            .any(|(key, value)| key == "confirm" && value == "yes")
    {
        return Err(bad_request(
            "select packages and confirm the maintenance window",
        ));
    }
    let server = server(&state, id).await?;
    let endpoint = path(&server.id);
    server_security::start_apply(state.inv, server, revision, &packages)
        .await
        .map_err(|err| match err {
            ApplyError::Busy => error_resp(
                StatusCode::CONFLICT,
                "server maintenance is already in progress",
            ),
            ApplyError::Changed => error_resp(
                StatusCode::CONFLICT,
                "security report changed; check for updates again",
            ),
            ApplyError::Inventory(error) => internal_error(anyhow::Error::new(error)),
        })?;
    Ok(Redirect::to(&endpoint).into_response())
}
