use crate::handlers::admin::helpers::format_msk_iso;
use crate::http_util::path_segment_encode;
use crate::i18n::{Locale, tr};
use maud::{Markup, html};
use vpnctl_inventory::{ServicePathIncident, ServicePathState, ServicePathStatus};

fn status_label(status: ServicePathStatus, lang: Locale) -> (&'static str, &'static str) {
    match status {
        ServicePathStatus::Available => (tr(lang, "TCP reachable", "TCP доступен"), "var(--soft)"),
        ServicePathStatus::Degraded => (tr(lang, "Deterioration", "Ухудшение"), "var(--acc)"),
        ServicePathStatus::Unreachable => {
            (tr(lang, "TCP unreachable", "TCP недоступен"), "var(--acc)")
        }
        ServicePathStatus::Recovering => {
            (tr(lang, "Recovering", "Восстанавливается"), "var(--mute)")
        }
        ServicePathStatus::Unknown => (
            tr(lang, "Unknown / stale", "Нет свежих данных"),
            "var(--mute)",
        ),
    }
}

pub(super) fn status_badge(state: Option<&ServicePathState>, lang: Locale) -> Markup {
    let status = state.map_or(ServicePathStatus::Unknown, |s| s.status);
    let (label, color) = status_label(status, lang);
    html! {
        span data-path-status=(format!("{status:?}").to_lowercase()) style=(format!("color: {color};")) {
            (label)
        }
        @if let Some(state) = state {
            small.ed-grid__mut style="display:block;" {
                (state.vantage) " · " (format_msk_iso(state.checked_at))
            }
        }
    }
}

pub(super) fn fleet_summary(
    servers: &[vpnctl_core::Server],
    paths: &std::collections::HashMap<vpnctl_core::ServerId, ServicePathState>,
    names: &crate::handlers::admin::helpers::ServerNames,
    lang: Locale,
) -> Markup {
    let statuses = [
        ServicePathStatus::Unreachable,
        ServicePathStatus::Degraded,
        ServicePathStatus::Recovering,
        ServicePathStatus::Unknown,
        ServicePathStatus::Available,
    ];
    let state_for = |server: &vpnctl_core::Server| {
        paths
            .get(&server.id)
            .map_or(ServicePathStatus::Unknown, |s| s.status)
    };
    html! {
        section #fleet-current-path style="margin-top:18px;" {
            h2 { (tr(lang, "Availability now", "Доступность сейчас")) }
            p.ed-grid__mut {
                (tr(lang,
                    "TCP VPN ports from the measurement network. Two failed rounds confirm an outage; two successful rounds confirm recovery. UDP and VPN login are checked separately.",
                    "TCP-порты VPN из сети проверки. Два неудачных раунда подтверждают отказ, два успешных — восстановление. UDP и вход в VPN проверяются отдельно."))
            }
            @if servers.is_empty() {
                p {
                    (tr(lang, "No servers to monitor. ", "Пока нет серверов для проверки. "))
                    a href="/admin/servers/new" { (tr(lang, "Add server", "Добавить сервер")) }
                }
            } @else {
                div style="display:flex;flex-wrap:wrap;gap:8px 20px;" {
                    @for status in statuses {
                        @let (label, color) = status_label(status, lang);
                        @let count = servers.iter().filter(|s| state_for(s) == status).count();
                        span data-path-count=(format!("{status:?}").to_lowercase()) style=(format!("color:{color};")) {
                            (label) ": " b { (count) }
                        }
                    }
                }
                div style="display:flex;flex-wrap:wrap;gap:12px 24px;margin-top:12px;" {
                    @for status in statuses.into_iter().filter(|s| *s != ServicePathStatus::Available) {
                        @for server in servers.iter().filter(|s| state_for(s) == status) {
                            div data-path-server=(server.id.0) {
                                a.ed-grid__id href=(format!("/admin/servers/{}/status#current-path-availability", path_segment_encode(&server.id.0))) {
                                    (crate::handlers::admin::helpers::named_server(&server.id, names))
                                }
                                " · " (status_badge(paths.get(&server.id), lang))
                            }
                        }
                    }
                }
            }
        }
    }
}

pub(super) fn detail_section(
    current: Option<&ServicePathState>,
    incidents: Option<&[ServicePathIncident]>,
    lang: Locale,
) -> Markup {
    html! {
        section #current-path-availability style="margin-bottom:24px;" {
            h2 { (tr(lang, "Current path availability", "Доступность сейчас")) }
            (status_badge(current, lang))
            p.ed-grid__mut {
                (tr(lang,
                    "TCP VPN ports from the named measurement network. This does not verify a new VPN login, UDP protocols or accessibility from every user's network. Node health and protocol tests are shown separately below.",
                    "TCP-порты VPN из указанной сети проверки. Это не проверка нового входа в VPN, UDP-протоколов или доступа из сетей всех пользователей. Состояние узла и проверки протоколов показаны ниже."))
            }
            p.ed-grid__mut {
                (tr(lang,
                    "Two failed rounds confirm an outage; two successful rounds confirm recovery. Missing measurements remain unknown. When auto-suppress is enabled, confirmed outages hide this server from subscriptions until recovery. Grants, keys and running services stay unchanged.",
                    "Два неудачных раунда подтверждают отказ, два успешных — восстановление. Без свежих измерений состояние неизвестно. При включённом авто-скрытии подтверждённый отказ убирает сервер из подписок до восстановления. Доступы, ключи и работающие службы сохраняются."))
            }
            h3 { (tr(lang, "Path incident history", "История отказов пути")) }
            @match incidents {
                None => { p { (tr(lang, "Incident history could not be loaded.", "Не удалось загрузить историю отказов.")) } }
                Some([]) => { p.ed-grid__mut { (tr(lang, "No recorded incidents yet.", "Зафиксированных эпизодов пока нет.")) } }
                Some(incidents) => {
                    @for incident in incidents {
                        details style="margin:12px 0;" data-path-incident=(incident.id) {
                            summary {
                                (format_msk_iso(incident.first_failure_at)) " · " (incident.vantage) " · "
                                @if let Some(at) = incident.recovered_at {
                                    (tr(lang, "recovered ", "восстановлен ")) (format_msk_iso(at))
                                } @else if incident.confirmed_at.is_some() {
                                    (tr(lang, "confirmed outage, recovery not confirmed", "отказ подтверждён, восстановление не подтверждено"))
                                } @else {
                                    (tr(lang, "deterioration, recovery not confirmed", "ухудшение, восстановление не подтверждено"))
                                }
                            }
                            p {
                                (tr(lang, "Last good round: ", "Последний успешный раунд: "))
                                @if let Some(at) = incident.last_success_at { (format_msk_iso(at)) }
                                @else { (tr(lang, "unknown", "неизвестно")) }
                                " · " (tr(lang, "First deterioration: ", "Первое ухудшение: ")) (format_msk_iso(incident.first_failure_at))
                            }
                            @if let Some(at) = incident.confirmed_at {
                                p { (tr(lang, "Outage confirmed: ", "Отказ подтверждён: ")) (format_msk_iso(at)) }
                            }
                            @if let Some(at) = incident.first_recovery_at {
                                p { (tr(lang, "First recovery success: ", "Первый успех восстановления: ")) (format_msk_iso(at)) }
                            }
                            p.ed-grid__mut {
                                (tr(lang, "The onset lies between the last good round and the first deterioration; exact onset is unknown. User activity is investigation context, not attribution of fault. This snapshot covers recorded streams/bytes, not every kernel or application.",
                                    "Начало находится между последним успехом и первым ухудшением; точная секунда неизвестна. Активность пользователей — контекст расследования, а не список виновных. Срез содержит наблюдавшиеся потоки и байты, а не все ядра и приложения."))
                            }
                            (diagnostics(&incident.diagnostics, lang))
                        }
                    }
                }
            }
        }
    }
}

fn diagnostics(value: &serde_json::Value, lang: Locale) -> Markup {
    let yes = |v: &serde_json::Value, key: &str| {
        if v[key].as_bool() == Some(true) {
            "+"
        } else {
            "—"
        }
    };
    html! {
        p.ed-grid__mut {
            (tr(lang, "Evidence window cutoff: ", "Конец окна до отказа: "))
            (value["cutoff_at"].as_str().unwrap_or("—"))
        }
        div.ed-table-scroll {
            table.ed-grid {
                thead { tr {
                    th { (tr(lang, "User", "Пользователь")) }
                    th { (tr(lang, "Streams 15m", "Потоки 15 мин")) }
                    th { (tr(lang, "Streams 60m", "Потоки 60 мин")) }
                    th { (tr(lang, "Bytes 60m", "Байты 60 мин")) }
                    th { (tr(lang, "Transition streams / bytes", "Переход: потоки / байты")) }
                } }
                tbody {
                    @for user in value["users"].as_array().into_iter().flatten() {
                        @let name = user["user"].as_str().unwrap_or("?");
                        tr {
                            td { a href=(format!("/admin/users/{}", path_segment_encode(name))) { (name) } }
                            td { (yes(user, "live_15m")) }
                            td { (yes(user, "live_60m")) }
                            td { (user["upload_60m"].as_u64().unwrap_or(0).saturating_add(user["download_60m"].as_u64().unwrap_or(0))) }
                            td { (yes(user, "transition_live")) " / " (user["transition_bytes"].as_u64().unwrap_or(0)) }
                        }
                    }
                }
            }
        }
        details {
            summary { (tr(lang, "Node and recent changes snapshot", "Срез узла и последних изменений")) }
            pre { (serde_json::to_string_pretty(value).unwrap_or_default()) }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_and_tcp_scope_never_claim_full_vpn_readiness() {
        let page = detail_section(None, None, Locale::En).into_string();
        assert!(page.contains("Unknown / stale"));
        assert!(page.contains("does not verify a new VPN login"));
        assert!(page.contains("could not be loaded"));
    }

    #[test]
    fn evidence_escapes_user_names_and_encodes_links() {
        let page = diagnostics(
            &serde_json::json!({"users": [{"user": "<test/user>"}]}),
            Locale::En,
        )
        .into_string();
        assert!(!page.contains("<test/user>"));
        assert!(page.contains("&lt;test/user&gt;"));
        assert!(page.contains("%2F"));
    }
}
