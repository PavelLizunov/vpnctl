//! Cheburcheck presentation: stored observations only, no network activity.
use maud::{Markup, html};

use crate::cheburcheck::{DynamicPhase, FailureCode, ProbeReport, Report};
use crate::handlers::admin::helpers::format_msk_iso;
use crate::http_util::path_segment_encode;
use crate::i18n::{Locale, tr};

pub(super) struct PageModel {
    pub server_id: String,
    pub server_name: String,
    pub inventory_address: String,
    pub target_address: Option<String>,
    pub checked_address: Option<String>,
    pub state: &'static str,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub report: Option<Report>,
    pub busy: bool,
    pub cooldown_secs: u64,
    pub stale: bool,
    pub address_changed: bool,
}

fn path(id: &str) -> String {
    format!("/admin/servers/{}/cheburcheck", path_segment_encode(id))
}

fn refresh_needed(model: &PageModel) -> bool {
    model.state == "running" || model.busy || model.cooldown_secs > 0
}

fn state_label(model: &PageModel, lang: Locale) -> &'static str {
    if model.state == "running" {
        tr(lang, "Check in progress", "Проверка выполняется")
    } else if model.address_changed {
        tr(
            lang,
            "Address changed; check again",
            "Адрес изменился — повторите проверку",
        )
    } else if model.state == "interrupted" {
        tr(lang, "Check interrupted", "Проверка прервана")
    } else if model.stale {
        tr(
            lang,
            "Stored results need refreshing",
            "Сохранённые результаты устарели",
        )
    } else if let Some(report) = model.report.as_ref() {
        if matches!(
            report.dynamic.phase,
            DynamicPhase::Partial | DynamicPhase::Running
        ) {
            tr(
                lang,
                "Partial check results",
                "Частичные результаты проверки",
            )
        } else if report.failure.is_some()
            || matches!(
                report.dynamic.phase,
                DynamicPhase::NotStarted | DynamicPhase::Unavailable
            )
        {
            tr(lang, "Check did not complete", "Проверка не завершена")
        } else {
            tr(lang, "Check completed", "Проверка завершена")
        }
    } else {
        tr(lang, "Not checked", "Не проверено")
    }
}

fn timestamp(value: Option<&str>) -> Markup {
    match value {
        Some(value) => {
            let display = chrono::DateTime::parse_from_rfc3339(value)
                .map(|time| format_msk_iso(time.with_timezone(&chrono::Utc)))
                .unwrap_or_else(|_| value.to_owned());
            html! { time datetime=(value) { (display) } }
        }
        None => html! { "—" },
    }
}

fn disclosure(lang: Locale) -> Markup {
    html! {
        p.cc-deck {
            (tr(lang,
                "Starting a check sends the selected node’s public IP to Cheburcheck. VPN credentials are not sent.",
                "Запуск передаёт публичный IP выбранного узла в Cheburcheck. Учётные данные VPN не отправляются."))
        }
    }
}

fn polling_notice(lang: Locale) -> Markup {
    html! {
        p.cc-poll-error role="status" hidden {
            (tr(lang, "Could not refresh the check. Use Refresh to see the current state.",
                "Не удалось обновить проверку. Нажмите «Обновить», чтобы увидеть текущее состояние."))
        }
    }
}

fn verdict_label(value: &str, lang: Locale) -> String {
    match value {
        "tspu_block" => tr(lang, "TSPU filtering reported", "Признак ТСПУ-фильтрации"),
        "sni_block" => tr(lang, "SNI filtering reported", "Признак SNI-фильтрации"),
        "dns_spoofing" => tr(lang, "DNS interference reported", "Признак подмены DNS"),
        "cdn_block" => tr(lang, "CDN filtering reported", "Признак CDN-фильтрации"),
        "whitelist" => tr(lang, "Whitelist observation", "Наблюдение whitelist"),
        "ok" => tr(lang, "Response after DPI", "Есть ответ после DPI"),
        "uncertain" => tr(lang, "Uncertain", "Неясно"),
        other => other,
    }
    .to_owned()
}

fn verdict_class(report: &ProbeReport) -> &'static str {
    if report.verdicts.iter().any(|value| {
        matches!(
            value.as_str(),
            "tspu_block" | "sni_block" | "dns_spoofing" | "cdn_block"
        )
    }) {
        "cc-verdict cc-verdict--block"
    } else if report.verdicts.iter().any(|value| value == "ok") {
        "cc-verdict cc-verdict--response"
    } else {
        "cc-verdict"
    }
}

fn failure_notice(report: &Report, lang: Locale) -> Markup {
    let Some(failure) = report.failure.as_ref() else {
        return html! {};
    };
    let (code, message) = match failure.code {
        FailureCode::RateLimited => (
            "rate_limited",
            tr(
                lang,
                "Cheburcheck rate limit reached (429). The node’s availability is not determined by this error.",
                "Достигнут лимит Cheburcheck (429). Эта ошибка не определяет доступность узла.",
            ),
        ),
        FailureCode::Unavailable => (
            "unavailable",
            tr(
                lang,
                "Cheburcheck could not provide the check. No conclusion about the node follows from this service error.",
                "Cheburcheck не смог предоставить проверку. Ошибка сервиса не означает отказ узла.",
            ),
        ),
        FailureCode::InvalidResponse => (
            "invalid_response",
            tr(
                lang,
                "The service returned an incomplete or inconsistent response.",
                "Сервис вернул неполный или противоречивый ответ.",
            ),
        ),
        FailureCode::ResponseLimit => (
            "response_limit",
            tr(
                lang,
                "The service response exceeded the check’s data limit.",
                "Ответ сервиса превысил лимит данных проверки.",
            ),
        ),
        FailureCode::Timeout => (
            "timeout",
            tr(
                lang,
                "The external check did not finish within its time limit.",
                "Внешняя проверка не завершилась за отведённое время.",
            ),
        ),
        FailureCode::NoObservers => (
            "no_observers",
            tr(
                lang,
                "No external observers were available for this check.",
                "Для этой проверки нет доступных внешних наблюдателей.",
            ),
        ),
    };
    html! {
        aside.cc-notice data-error=(code) {
            p { (message) }
            @if let Some(seconds) = failure.retry_after_secs {
                p { (tr(lang, "Service retry interval: ", "Интервал повтора сервиса: "))
                    (seconds) " " (tr(lang, "seconds", "секунд")) "." }
            }
        }
    }
}

fn list_result(report: &Report, lang: Locale) -> Markup {
    html! {
        section.cc-section data-source="cheburcheck-list" {
            h2 { (tr(lang, "Blocklists", "Списки блокировок")) }
            @if let Some(list) = report.list.as_ref() {
                p class=(if list.blocked { "cc-list-match" } else { "cc-neutral" }) data-blocked=(list.blocked.to_string()) {
                    (if list.blocked {
                        tr(lang, "Matches found in the service’s lists", "Найдены совпадения в списках сервиса")
                    } else {
                        tr(lang, "No matches in the service’s lists", "Совпадений в списках сервиса нет")
                    })
                }
                p.cc-note { (tr(lang,
                    "A list miss does not establish that this IP is reachable. Compare the dynamic observations below.",
                    "Отсутствие в списках не подтверждает доступность IP. Сравните динамические наблюдения ниже.")) }
                @if !list.blocked_subnets.is_empty() || !list.providers.is_empty() {
                    details.cc-details data-detail-key="list-matches" {
                        summary { (tr(lang, "List matches", "Совпадения в списках")) }
                        ul {
                            @for subnet in &list.blocked_subnets { li { code { (subnet) } } }
                            @for provider in &list.providers { li { (provider) } }
                        }
                    }
                }
            } @else {
                p.cc-neutral { (tr(lang, "No list result received", "Результат по спискам не получен")) }
            }
        }
    }
}

fn dynamic_result(report: &Report, lang: Locale) -> Markup {
    let dynamic = &report.dynamic;
    let phase = match dynamic.phase {
        DynamicPhase::NotStarted => "not_started",
        DynamicPhase::Running => "running",
        DynamicPhase::Done => "done",
        DynamicPhase::Partial => "partial",
        DynamicPhase::Unavailable => "unavailable",
    };
    let cached = dynamic.reports.iter().filter(|row| row.cached).count();
    html! {
        section.cc-section data-source="cheburcheck-dynamic" data-phase=(phase) {
            h2 { (tr(lang, "Dynamic observations", "Динамические наблюдения")) }
            p.cc-note { (tr(lang,
                "Regional observations describe the network path. They do not verify an authenticated VPN session.",
                "Региональные наблюдения описывают сетевой путь. Они не проверяют авторизованное VPN-подключение.")) }
            @if matches!(dynamic.phase, DynamicPhase::Partial | DynamicPhase::Running) {
                p.cc-notice { (tr(lang, "The observation set is incomplete.", "Набор наблюдений неполный.")) }
            }
            @if dynamic.online_probes == Some(0) {
                p.cc-neutral { (tr(lang, "No observers available", "Нет доступных наблюдателей")) }
            } @else if dynamic.reports.is_empty() {
                p.cc-neutral { (tr(lang, "No dynamic reports received", "Динамические отчёты не получены")) }
            }
            dl.cc-metrics {
                div { dt { (tr(lang, "Reports received", "Получено отчётов")) }
                    dd { (dynamic.reports.len())
                        @if let Some(total) = dynamic.online_probes { span { " / " (total) } }
                    }
                }
                div { dt { (tr(lang, "TSPU reports", "Признак ТСПУ")) }
                    dd { (dynamic.verdict_count("tspu_block")) }
                }
                div { dt { (tr(lang, "Uncertain", "Неясно")) }
                    dd { (dynamic.verdict_count("uncertain")) }
                }
                div { dt { (tr(lang, "No report", "Нет отчёта")) }
                    dd { (dynamic.not_reported().map(|value| value.to_string()).unwrap_or_else(|| "—".into())) }
                }
            }
            p.cc-note { (tr(lang, "Cached reports: ", "Отчётов из кеша: ")) (cached)
                ". " (tr(lang,
                    "Uncertain or missing reports are not counted as blocking.",
                    "Неясные и отсутствующие отчёты не считаются блокировкой.")) }
            @if !dynamic.reports.is_empty() {
                details.cc-details data-detail-key="observer-results" {
                    summary { (tr(lang, "Reports by network and region", "Отчёты по сетям и регионам")) }
                    table.cc-reports {
                        caption { (tr(lang, "Cheburcheck observer reports", "Отчёты наблюдателей Cheburcheck")) }
                        thead { tr {
                            th scope="col" { (tr(lang, "Network and region", "Сеть и регион")) }
                            th scope="col" { (tr(lang, "Observation", "Наблюдение")) }
                            th scope="col" { (tr(lang, "Hops", "Прыжки")) }
                        } }
                        tbody {
                            @for row in &dynamic.reports {
                                tr {
                                    td {
                                        span.cc-mobile-label aria-hidden="true" { (tr(lang, "Network", "Сеть")) }
                                        span.cc-network {
                                            strong { (row.provider.as_deref().unwrap_or("—")) }
                                            span { (row.region.as_deref().unwrap_or("—")) }
                                            code { (row.asn.as_deref().unwrap_or("—")) }
                                        }
                                    }
                                    td {
                                        span.cc-mobile-label aria-hidden="true" { (tr(lang, "Observation", "Наблюдение")) }
                                        span class=(verdict_class(row)) {
                                            @if row.verdicts.is_empty() { (tr(lang, "Uncertain", "Неясно")) }
                                            @for (index, value) in row.verdicts.iter().enumerate() {
                                                @if index > 0 { "; " }
                                                (verdict_label(value, lang))
                                            }
                                            @if row.cached { small { (tr(lang, "cached", "из кеша")) } }
                                        }
                                    }
                                    td {
                                        span.cc-mobile-label aria-hidden="true" { (tr(lang, "Hops", "Прыжки")) }
                                        span.cc-hop {
                                            "DPI: " (row.dpi_hop.map(|value| value.to_string()).unwrap_or_else(|| "—".into()))
                                            br;
                                            (tr(lang, "Response: ", "Ответ: "))
                                            (row.target_hop.map(|value| value.to_string()).unwrap_or_else(|| "—".into()))
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

pub(super) fn render(model: &PageModel, lang: Locale) -> Markup {
    let check_path = path(&model.server_id);
    let disabled = refresh_needed(model) || model.target_address.is_none();
    html! {
        section #cheburcheck-checks .cc data-refresh=(refresh_needed(model).to_string())
            data-running=((model.state == "running").to_string()) data-state=(model.state)
            data-stale=(model.stale.to_string()) data-address-changed=(model.address_changed.to_string())
            aria-busy=((model.state == "running").to_string()) {
            header.cc-heading {
                div {
                    a.cc-back href="/admin/monitoring/cheburcheck" { "← Cheburcheck" }
                    h1 tabindex="-1" { (&model.server_name) }
                    @if model.server_name != model.server_id { p.cc-id { (&model.server_id) } }
                    (disclosure(lang))
                }
                form method="post" action=(&check_path) {
                    button #cc-run .ed-abtn.cc-run type="submit" disabled[disabled] {
                        (tr(lang, "Check with Cheburcheck", "Проверить через Cheburcheck"))
                    }
                }
            }
            div.cc-feedback aria-live="polite" {
                strong { (state_label(model, lang)) }
                @if model.busy && model.state != "running" {
                    p { (tr(lang, "Another node is being checked. Wait for it to finish.",
                        "Сейчас проверяется другой узел. Дождитесь завершения.")) }
                }
                @if model.cooldown_secs > 0 && model.state != "running" {
                    p { (tr(lang, "Next start in ", "Следующий запуск через "))
                        (model.cooldown_secs) " " (tr(lang, "seconds", "секунд")) "." }
                }
                @if model.state == "interrupted" {
                    p { (tr(lang, "The last run has no completed result. Start a new check.",
                        "Для последнего запуска нет завершённого результата. Запустите новую проверку.")) }
                }
            }
            (polling_notice(lang))
            dl.cc-meta {
                div { dt { (tr(lang, "Inventory address", "Адрес в инвентаре")) }
                    dd { code { (&model.inventory_address) } }
                }
                div { dt { (tr(lang, "Current target IP", "IP следующей проверки")) }
                    dd { code { (model.target_address.as_deref().unwrap_or("—")) } }
                }
                @if let Some(address) = model.checked_address.as_deref() {
                    div { dt { (tr(lang, "Checked IP", "IP сохранённой проверки")) }
                        dd { code { (address) } }
                    }
                }
                div { dt { (tr(lang, "Started", "Начало")) } dd { (timestamp(model.started_at.as_deref())) } }
                div { dt { (tr(lang, "Finished", "Завершение")) } dd { (timestamp(model.finished_at.as_deref())) } }
            }
            @if model.target_address.is_none() {
                p.cc-notice { (tr(lang, "This check needs a public inventory IP or one stored resolved public IP.",
                    "Для проверки нужен публичный IP в инвентаре или один сохранённый разрешённый публичный IP.")) }
            }
            @if model.address_changed {
                p.cc-notice { (tr(lang,
                    "These saved observations belong to a previous address. They do not assess the node’s current address.",
                    "Эти сохранённые наблюдения относятся к прежнему адресу. Они не оценивают текущий адрес узла.")) }
            } @else if model.stale {
                p.cc-notice { (tr(lang, "These observations are more than one hour old. Run a new check for a current result.",
                    "Этим наблюдениям больше часа. Для актуального результата запустите новую проверку.")) }
            }
            @if let Some(report) = model.report.as_ref() {
                div data-historical=(model.address_changed.to_string()) {
                    (failure_notice(report, lang))
                    (list_result(report, lang))
                    (dynamic_result(report, lang))
                }
            }
            aside.cc-caution {
                strong { (tr(lang, "Access recovery", "Восстановление доступа")) }
                p { (tr(lang,
                    "A VPS may keep working while its direct path is filtered. An alternate client entry or a new public IP may restore access; this check does not change routes or subscribers.",
                    "VPS может продолжать работать при фильтрации прямого пути. Другой входной узел или новый публичный IP могут вернуть доступ; эта проверка не меняет маршруты и подписчиков.")) }
                a href=(format!("/admin/servers/{}/setup#client-detour", path_segment_encode(&model.server_id))) {
                    (tr(lang, "Configure client entry", "Настроить вход для клиентов"))
                }
            }
            footer.cc-footer {
                a.cc-manual href=(&check_path) { (tr(lang, "Refresh", "Обновить")) }
                a href="https://cheburcheck.ru/" target="_blank" rel="noopener noreferrer" {
                    (tr(lang, "Source: Cheburcheck", "Источник: Cheburcheck"))
                }
            }
        }
    }
}

pub(super) fn overview(models: &[PageModel], lang: Locale) -> Markup {
    let refresh = models.iter().any(refresh_needed);
    html! {
        section #cheburcheck-checks .cc data-refresh=(refresh.to_string()) data-running="false" {
            header.cc-heading { div {
                a.cc-back href="/admin/monitoring" { "← " (tr(lang, "Monitoring", "Мониторинг")) }
                h1 tabindex="-1" { "Cheburcheck" }
                (disclosure(lang))
            } }
            (polling_notice(lang))
            @if models.is_empty() {
                div.cc-empty {
                    p { (tr(lang, "No configured nodes to check", "Нет настроенных узлов для проверки")) }
                    a.ed-abtn.ed-abtn--secondary href="/admin/servers" { (tr(lang, "Open servers", "Открыть серверы")) }
                }
            } @else {
                div.cc-nodes {
                    @for model in models {
                        article.cc-node data-server=(&model.server_id) data-state=(model.state)
                            data-stale=(model.stale.to_string()) data-address-changed=(model.address_changed.to_string()) {
                            div {
                                h2 { a href=(path(&model.server_id)) { (&model.server_name) } }
                                p.cc-id { code { (&model.inventory_address) }
                                    @if model.server_name != model.server_id { " · " (&model.server_id) }
                                }
                                p.cc-node-state { (state_label(model, lang)) }
                                @if !model.address_changed {
                                    @if let Some(report) = model.report.as_ref() {
                                        p.cc-note {
                                            (tr(lang, "Dynamic reports: ", "Динамических отчётов: ")) (report.dynamic.reports.len())
                                            " · " (tr(lang, "TSPU reports: ", "признак ТСПУ: ")) (report.dynamic.verdict_count("tspu_block"))
                                        }
                                    }
                                }
                                @if model.finished_at.is_some() {
                                    p.cc-note { (timestamp(model.finished_at.as_deref())) }
                                }
                            }
                            a.ed-abtn.ed-abtn--secondary.cc-open href=(path(&model.server_id)) {
                                (tr(lang, "Open check", "Открыть проверку"))
                            }
                        }
                    }
                }
            }
            p.cc-note { (tr(lang,
                "Choose a node to run a check. Opening this page does not contact Cheburcheck.",
                "Выберите узел для запуска проверки. Открытие этой страницы не обращается к Cheburcheck.")) }
            footer.cc-footer {
                a.cc-manual href="/admin/monitoring/cheburcheck" { (tr(lang, "Refresh", "Обновить")) }
                a href="https://cheburcheck.ru/" target="_blank" rel="noopener noreferrer" { "Cheburcheck" }
            }
        }
    }
}
