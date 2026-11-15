//! Presentation only: no network calls and no mutation of check state.
use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use maud::{Markup, html};

use super::{Outcome, PATH, ResultRow, Snapshot, Source, Target};
use crate::http_util::path_segment_encode;
use crate::i18n::{Locale, tr};

fn name<'a>(id: &'a str, names: &'a BTreeMap<String, String>) -> &'a str {
    names.get(id).map(String::as_str).unwrap_or(id)
}

fn source_name<'a>(
    source: &'a Source,
    names: &'a BTreeMap<String, String>,
    lang: Locale,
) -> &'a str {
    match source {
        Source::Controller => tr(lang, "Controller", "Контроллер"),
        Source::Server(id) => name(id, names),
    }
}

fn source_id(source: &Source) -> &str {
    match source {
        Source::Controller => "controller",
        Source::Server(id) => id,
    }
}

fn measured(outcome: &Outcome) -> bool {
    matches!(
        outcome,
        Outcome::Reachable(_) | Outcome::Failed | Outcome::Refused | Outcome::Timeout
    )
}

fn cell(row: Option<&ResultRow>, lang: Locale) -> Markup {
    let (class, code, label, detail) = match row.map(|r| &r.outcome) {
        Some(Outcome::Reachable(_)) => (
            "ok",
            "reachable",
            tr(lang, "Reachable", "Доступен"),
            tr(
                lang,
                "TCP connection established",
                "TCP-соединение установлено",
            ),
        ),
        Some(Outcome::Refused) => (
            "bad",
            "refused",
            tr(lang, "Refused", "Отклонено"),
            tr(
                lang,
                "The target refused the TCP connection",
                "Узел отклонил TCP-соединение",
            ),
        ),
        Some(Outcome::Timeout) => (
            "bad",
            "timeout",
            tr(lang, "Timed out", "Тайм-аут"),
            tr(
                lang,
                "No TCP connection within 2 seconds",
                "TCP-соединение не установлено за 2 секунды",
            ),
        ),
        Some(Outcome::Failed) => (
            "bad",
            "failed",
            tr(lang, "Connection error", "Ошибка связи"),
            tr(
                lang,
                "TCP connection failed; the cause is not identified",
                "Ошибка TCP-соединения; причина не установлена",
            ),
        ),
        Some(Outcome::SelfCheck) => (
            "neutral",
            "self",
            tr(lang, "Same node", "Этот же узел"),
            tr(
                lang,
                "A node is not an independent source for itself",
                "Узел не является независимой точкой для самого себя",
            ),
        ),
        Some(Outcome::NoAddress) => (
            "neutral",
            "no-address",
            tr(lang, "No address", "Нет адреса"),
            tr(
                lang,
                "No resolved IP in inventory",
                "В инвентаре нет разрешённого IP-адреса",
            ),
        ),
        Some(Outcome::SourceUnavailable) => (
            "neutral",
            "source-unavailable",
            tr(lang, "No measurement", "Нет замера"),
            tr(
                lang,
                "The source could not provide a result (SSH, trust or probe). This is not a target failure.",
                "Точка не предоставила результат: SSH, доверие к ключу или запуск пробы. Это не отказ проверяемого узла.",
            ),
        ),
        Some(Outcome::Unsupported | Outcome::UdpNotChecked) => (
            "neutral",
            "unsupported",
            tr(lang, "Not supported", "Не поддерживается"),
            tr(
                lang,
                "This transport is not checked",
                "Этот транспорт не проверяется",
            ),
        ),
        None => (
            "neutral",
            "not-checked",
            tr(lang, "Not checked", "Не проверено"),
            tr(
                lang,
                "No result in the current run",
                "В текущем запуске нет результата",
            ),
        ),
    };
    html! {
        span class=(format!("pc-result pc-result--{class}")) data-outcome=(code) title=(detail) {
            span.pc-result__label { (label) }
            @if let Some(ResultRow { outcome: Outcome::Reachable(ms), .. }) = row {
                span.pc-result__latency { (ms) " " (tr(lang, "ms", "мс")) }
            }
        }
    }
}

pub(super) fn render(
    targets: &[Target],
    names: &BTreeMap<String, String>,
    snapshot: &Snapshot,
    lang: Locale,
    now: DateTime<Utc>,
) -> Markup {
    // Only matching current inventory observations contribute to the summary.
    let rows: Vec<_> = snapshot
        .rows
        .iter()
        .filter(|r| targets.contains(&r.target))
        .collect();
    let tcp: Vec<_> = targets.iter().filter(|t| t.transport == "tcp").collect();
    let other: Vec<_> = targets.iter().filter(|t| t.transport != "tcp").collect();
    let reachable = rows
        .iter()
        .filter(|r| matches!(r.outcome, Outcome::Reachable(_)))
        .count();
    let attempted = rows.iter().filter(|r| measured(&r.outcome)).count();
    let missing = rows
        .iter()
        .filter(|r| {
            matches!(
                r.outcome,
                Outcome::SourceUnavailable | Outcome::NoAddress | Outcome::Unsupported
            )
        })
        .count();
    let sources = if snapshot.sources.is_empty() {
        vec![Source::Controller]
    } else {
        snapshot.sources.clone()
    };
    let stale = snapshot
        .finished_at
        .is_some_and(|time| now.signed_duration_since(time) > chrono::Duration::hours(1));
    let status = if snapshot.running {
        tr(lang, "Checking connections", "Проверяем соединения")
    } else if snapshot.failed {
        tr(lang, "Check did not finish", "Проверка не завершена")
    } else if snapshot.inventory_changed {
        tr(
            lang,
            "Inventory changed; run checks again",
            "Инвентарь изменился — повторите проверку",
        )
    } else if snapshot.finished_at.is_none() {
        tr(lang, "Ready to check", "Готово к проверке")
    } else if stale {
        tr(lang, "Results need refreshing", "Результаты пора обновить")
    } else if attempted == 0 {
        tr(lang, "No TCP measurements", "Нет замеров TCP")
    } else if attempted > reachable {
        tr(lang, "Some connections failed", "Есть ошибки соединения")
    } else if missing > 0 {
        tr(
            lang,
            "Some measurements are missing",
            "Часть замеров недоступна",
        )
    } else {
        tr(
            lang,
            "Measured TCP connections are reachable",
            "Проверенные TCP-соединения доступны",
        )
    };
    html! {
        section #private-checks .pc data-running=(snapshot.running.to_string()) aria-busy=(snapshot.running.to_string()) {
            header.pc-heading {
                div {
                    a.pc-back href="/admin/monitoring" { "← " (tr(lang, "Monitoring", "Мониторинг")) }
                    h1 { (tr(lang, "Node reachability", "Доступность узлов")) }
                    p.pc-deck { (tr(lang, "Compare connections from the controller and your servers. No public checking services.", "Сравните соединения с контроллера и ваших серверов. Без публичных сервисов проверки.")) }
                }
                form method="post" action=(PATH) {
                    button.ed-abtn.pc-run type="submit" disabled[snapshot.running || targets.is_empty()] {
                        (if snapshot.running { tr(lang, "Checking…", "Проверяем…") } else { tr(lang, "Run checks", "Проверить доступность") })
                    }
                }
            }
            div.pc-overview role="status" aria-live="polite" {
                div.pc-overview__state {
                    strong { (status) }
                    p {
                        @if snapshot.running {
                            (tr(lang, "Results will appear automatically. SSH checks may take about a minute.", "Результаты появятся автоматически. SSH-проверки могут занять около минуты."))
                        } @else if let Some(time) = snapshot.finished_at {
                            (tr(lang, "Last run: ", "Последний запуск: "))
                            time datetime=(time.to_rfc3339()) { (time.format("%d.%m.%Y · %H:%M:%S UTC")) }
                            @if let Some(start) = snapshot.started_at { " · " (time.signed_duration_since(start).num_seconds().max(0)) " " (tr(lang, "s", "с")) }
                        } @else { (tr(lang, "Start a check to collect current measurements.", "Запустите проверку, чтобы получить свежие замеры.")) }
                    }
                }
                @if snapshot.finished_at.is_some() && !snapshot.failed && !snapshot.inventory_changed {
                    dl.pc-totals {
                        div { dt { (tr(lang, "TCP reachable", "TCP доступно")) } dd { (reachable) " / " (attempted) } }
                        div { dt { (tr(lang, "Connection errors", "Ошибки связи")) } dd { (attempted.saturating_sub(reachable)) } }
                        div { dt { (tr(lang, "No measurement", "Нет замера")) } dd { (missing) } }
                    }
                }
            }
            @if snapshot.failed {
                p.pc-notice role="alert" { (tr(lang, "Could not finish the run. No previous measurements are shown as current. Try again using the button above.", "Не удалось завершить запуск. Старые замеры не выдаются за новые. Повторите проверку кнопкой выше.")) }
            }
            p.pc-poll-error role="alert" hidden { (tr(lang, "Automatic refresh stopped. Reload the page to see the current state.", "Автообновление остановилось. Обновите страницу, чтобы увидеть текущее состояние.")) }
            @if snapshot.running {
                a.pc-manual href=(PATH) { (tr(lang, "Refresh manually", "Обновить вручную")) }
            }
            @if targets.is_empty() {
                div.pc-empty {
                    h2 { (tr(lang, "No servers with configured protocols", "Нет серверов с настроенными протоколами")) }
                    p { (tr(lang, "No results yet. Add a server and enable a protocol to check its port.", "Результатов пока нет. Добавьте сервер и включите протокол, чтобы проверить его порт.")) }
                    a.ed-abtn href="/admin/servers" { (tr(lang, "Open servers", "Открыть серверы")) }
                }
            } @else {
                @if !tcp.is_empty() {
                    div.pc-section-heading { h2 { (tr(lang, "TCP comparison", "Сравнение TCP")) } p { (tr(lang, "Rows are destinations. Columns are where the check runs.", "В строках — проверяемые порты. В столбцах — откуда идёт проверка.")) } }
                    table.pc-matrix {
                        caption.ed-sr-only { (tr(lang, "TCP ports compared across controlled sources", "Сравнение TCP-портов с управляемых точек")) }
                        thead { tr {
                            th scope="col" { (tr(lang, "Destination / port", "Узел / порт")) }
                            @for source in &sources { th scope="col" {
                                (source_name(source, names, lang))
                                small { (match source { Source::Controller => tr(lang, "Control-plane network", "Сеть контроллера"), Source::Server(id) => id.as_str() }) }
                            } }
                        } }
                        tbody { @for target in tcp {
                            tr data-server=(&target.server) data-protocol=(&target.protocol) data-port=(target.port.map(|p| p.to_string()).unwrap_or_default()) {
                                th scope="row" {
                                    a href=(format!("/admin/servers/{}", path_segment_encode(&target.server))) { (name(&target.server, names)) }
                                    span.pc-target { @if name(&target.server, names) != target.server { (&target.server) " · " } (&target.protocol) " · " (target.port.map(|p| p.to_string()).unwrap_or_else(|| "—".into())) }
                                }
                                @for source in &sources {
                                    @let row = rows.iter().copied().find(|r| r.target == *target && r.source == *source);
                                    td data-source=(source_id(source)) {
                                        span.pc-mobile-source aria-hidden="true" { (source_name(source, names, lang)) @if let Source::Server(id) = source { small { (id) } } }
                                        (cell(row, lang))
                                        @if let Some(row) = row { time.ed-sr-only datetime=(row.time.to_rfc3339()) { (row.time.format("%H:%M:%S UTC")) } }
                                    }
                                }
                            }
                        } }
                    }
                    p.pc-legend { (tr(lang, "“Same node” is excluded. “No measurement” is a problem with the source, not proof that the destination is down.", "«Этот же узел» исключён из сравнения. «Нет замера» — проблема точки проверки, а не доказательство недоступности узла.")) }
                }
                @if !other.is_empty() {
                    details.pc-details {
                        summary { (tr(lang, "Not checked by this tool", "Не проверяются этим инструментом")) " · " (other.len()) }
                        p { (tr(lang, "UDP not checked: Hysteria and WireGuard need protocol-aware tests. An open TCP port says nothing about UDP.", "UDP не проверен: Hysteria и WireGuard требуют проверки самим протоколом. Открытый TCP-порт ничего не говорит о UDP.")) }
                        ul.pc-ports { @for target in other { li { strong { (name(&target.server, names)) } @if name(&target.server, names) != target.server { " (" (&target.server) ")" } " · " (&target.protocol) " · " (&target.transport) "/" (target.port.map(|p| p.to_string()).unwrap_or_else(|| "—".into())) } } }
                    }
                }
            }
            aside.pc-caution { strong { (tr(lang, "Transport reachability, not VPN health", "Доступность порта — ещё не работа VPN")) } p { (tr(lang, "A successful TCP connection does not verify a VPN handshake or identify censorship. Server sources are comparison points, not independent residential networks.", "Успешное TCP-соединение не подтверждает VPN-подключение и не определяет блокировку. Серверные точки дают сравнение, но не заменяют проверки из других домашних сетей.")) } }
            details.pc-details {
                summary { (tr(lang, "How these checks work", "Как устроена проверка")) }
                p { (tr(lang, "Only inventory addresses and configured ports are used. Remote probes run over SSH with a pinned host key; no VPN settings are changed.", "Используются только адреса инвентаря и настроенные порты. Удалённые пробы работают через SSH с закреплённым ключом узла; настройки VPN не меняются.")) }
                p { (tr(lang, "Results and the batch cursor are kept until restart. A hostname uses the first resolved IP. Each run checks up to 32 ports from the controller and up to 4 server sources; repeated runs rotate through larger inventories. Only the latest batch is shown.", "Результаты и позиция обхода хранятся до перезапуска. Для имени берётся первый разрешённый IP. Один запуск охватывает до 32 портов с контроллера и до 4 серверных точек; повторные запуски обходят остальные группы. Показана только последняя группа.")) }
                @if snapshot.total_targets > 0 {
                    p { (tr(lang, "Batch: ", "Группа: ")) (snapshot.selected_targets) " / " (snapshot.total_targets) " " (tr(lang, "ports", "портов")) "; " (sources.len()) " / " (snapshot.total_sources) " " (tr(lang, "sources", "точек")) "." }
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn rendering_distinguishes_self_missing_and_failure_without_false_totals() {
        let target = Target {
            server: "<node>".into(),
            address: "127.0.0.1".into(),
            ip: Some("127.0.0.1".parse().unwrap()),
            protocol: "reality".into(),
            transport: "tcp".into(),
            port: Some(443),
        };
        let now = Utc::now();
        let sources = vec![
            Source::Controller,
            Source::Server("<node>".into()),
            Source::Server("other".into()),
        ];
        let rows = sources
            .iter()
            .cloned()
            .zip([
                Outcome::Reachable(12),
                Outcome::SelfCheck,
                Outcome::SourceUnavailable,
            ])
            .map(|(source, outcome)| ResultRow {
                source,
                target: target.clone(),
                outcome,
                time: now,
            })
            .collect();
        let snapshot = Snapshot {
            rows,
            sources,
            finished_at: Some(now),
            ..Snapshot::default()
        };
        let html = render(&[target], &BTreeMap::new(), &snapshot, Locale::En, now).into_string();
        assert!(html.contains("&lt;node&gt;"));
        assert!(!html.contains("<node>"));
        for value in [
            "data-outcome=\"reachable\"",
            "data-outcome=\"self\"",
            "data-outcome=\"source-unavailable\"",
            "1 / 1",
            "Node reachability",
        ] {
            assert!(html.contains(value), "missing {value}");
        }
    }
}
