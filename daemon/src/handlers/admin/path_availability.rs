use crate::handlers::admin::helpers::format_msk_iso;
use crate::http_util::path_segment_encode;
use crate::i18n::{Locale, tr};
use maud::{Markup, html};
use vpnctl_inventory::{ServicePathIncident, ServicePathState, ServicePathStatus};

use chrono::{DateTime, Utc};
use vpnctl_core::{ProtocolId, Registry, Server};
use vpnctl_inventory::{AssuranceStage, AssuranceState, ProtocolAssuranceSample};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Status {
    Tcp(ServicePathStatus),
    UdpVerified,
    UdpFailed,
    UdpUnknown,
}

pub(super) struct Availability {
    has_tcp: bool,
    tcp: Option<ServicePathState>,
    udp: Option<UdpAvailability>,
}

struct UdpAvailability {
    total: usize,
    verified: usize,
    failed: usize,
    checked_at: Option<DateTime<Utc>>,
}

impl UdpAvailability {
    fn status(&self) -> Status {
        if self.verified > 0 {
            Status::UdpVerified
        } else if self.failed > 0 {
            Status::UdpFailed
        } else {
            Status::UdpUnknown
        }
    }
}

struct Transports<'a> {
    has_tcp: bool,
    udp_only: Vec<&'a ProtocolId>,
}

impl<'a> Transports<'a> {
    fn for_server(server: &'a Server, registry: &Registry) -> Self {
        let mut transports = Self {
            has_tcp: server.enabled_protocols.is_empty(),
            udp_only: Vec::new(),
        };
        for id in &server.enabled_protocols {
            let ports = registry
                .protocol(id)
                .map_or(&[][..], |protocol| protocol.listen_ports());
            let is_udp = |(transport, _): &(&str, u16)| transport.eq_ignore_ascii_case("udp");
            let has_udp = ports.iter().any(is_udp);
            let udp_only = has_udp && ports.iter().all(is_udp);
            transports.has_tcp |= !udp_only;
            // Assurance samples identify the protocol. UDP transport is unambiguous
            // only for protocols whose listeners are all UDP.
            if udp_only {
                transports.udp_only.push(id);
            }
        }
        transports
    }
}

pub(super) fn with_observations(
    server: &Server,
    registry: &Registry,
    tcp: Option<ServicePathState>,
    assurance: &[ProtocolAssuranceSample],
    now: DateTime<Utc>,
) -> Availability {
    observations(
        &Transports::for_server(server, registry),
        server,
        tcp,
        assurance,
        now,
    )
}

fn observations(
    transports: &Transports<'_>,
    server: &Server,
    tcp: Option<ServicePathState>,
    assurance: &[ProtocolAssuranceSample],
    now: DateTime<Utc>,
) -> Availability {
    Availability {
        has_tcp: transports.has_tcp,
        tcp,
        udp: (!transports.udp_only.is_empty())
            .then(|| udp_availability(server, &transports.udp_only, assurance, now)),
    }
}

fn udp_availability(
    server: &Server,
    attributable_protocols: &[&ProtocolId],
    assurance: &[ProtocolAssuranceSample],
    now: DateTime<Utc>,
) -> UdpAvailability {
    let max_age = crate::protocol_assurance_poller::status_max_age();
    let mut verified = 0;
    let mut failed = 0;
    let mut checked_at = None;
    for row in assurance.iter().filter(|row| {
        row.server_id == server.id
            && attributable_protocols.contains(&&row.protocol_id)
            && now
                .signed_duration_since(row.ts)
                .to_std()
                .is_ok_and(|age| age <= max_age)
    }) {
        match (row.stage, row.state) {
            (AssuranceStage::Transfer, AssuranceState::Verified) => verified += 1,
            (
                AssuranceStage::Handshake | AssuranceStage::Transfer,
                AssuranceState::Blocked | AssuranceState::Degraded,
            ) => failed += 1,
            _ => continue,
        }
        checked_at = checked_at.max(Some(row.ts));
    }
    UdpAvailability {
        total: attributable_protocols.len(),
        verified,
        failed,
        checked_at,
    }
}

pub(super) async fn load(
    state: &crate::AppState,
    server: &Server,
    now: DateTime<Utc>,
) -> Availability {
    let transports = Transports::for_server(server, &state.registry);
    let tcp = async {
        if !transports.has_tcp {
            return None;
        }
        state
            .inv
            .current_service_path(&server.id, now, crate::quality_poller::path_max_age_secs())
            .await
            .unwrap_or_else(|error| {
                tracing::warn!(target = "vpnctld::admin", server = %server.id, %error, "current path query failed");
                None
            })
    };
    let assurance = async {
        if transports.udp_only.is_empty() {
            return Vec::new();
        }
        state
            .inv
            .latest_protocol_assurance_for_server(&server.id)
            .await
            .unwrap_or_else(|error| {
                tracing::warn!(target = "vpnctld::admin", server = %server.id, %error, "UDP assurance query failed");
                Vec::new()
            })
    };
    let (tcp, assurance) = tokio::join!(tcp, assurance);
    observations(&transports, server, tcp, &assurance, now)
}

fn tcp_status(observation: Option<&Availability>) -> Option<Status> {
    if observation.is_some_and(|record| !record.has_tcp) {
        return None;
    }
    Some(Status::Tcp(
        observation
            .and_then(|record| record.tcp.as_ref())
            .map_or(ServicePathStatus::Unknown, |path| path.status),
    ))
}

fn attention_status(observation: Option<&Availability>) -> Option<Status> {
    tcp_status(observation)
        .filter(|status| *status != Status::Tcp(ServicePathStatus::Available))
        .or_else(|| {
            observation
                .and_then(|record| record.udp.as_ref())
                .filter(|udp| udp.verified < udp.total)
                .map(UdpAvailability::status)
        })
}

fn status_label(status: Status, lang: Locale) -> (&'static str, &'static str, &'static str) {
    use ServicePathStatus::*;
    match status {
        Status::Tcp(Available) => (
            "available",
            tr(lang, "TCP reachable", "TCP доступен"),
            "var(--soft)",
        ),
        Status::Tcp(Degraded) => (
            "degraded",
            tr(lang, "TCP deterioration", "Ухудшение TCP"),
            "var(--acc)",
        ),
        Status::Tcp(Unreachable) => (
            "unreachable",
            tr(lang, "TCP unreachable", "TCP недоступен"),
            "var(--acc)",
        ),
        Status::Tcp(Recovering) => (
            "recovering",
            tr(lang, "TCP recovering", "TCP восстанавливается"),
            "var(--mute)",
        ),
        Status::Tcp(Unknown) => (
            "unknown",
            tr(lang, "TCP · Unknown / stale", "TCP · Нет свежих данных"),
            "var(--mute)",
        ),
        Status::UdpVerified => (
            "udp_verified",
            tr(lang, "UDP VPN verified", "VPN по UDP проверен"),
            "var(--soft)",
        ),
        Status::UdpFailed => (
            "udp_failed",
            tr(lang, "UDP VPN check failed", "Ошибка проверки VPN по UDP"),
            "var(--acc)",
        ),
        Status::UdpUnknown => (
            "udp_unknown",
            tr(
                lang,
                "No fresh UDP VPN results",
                "Нет свежих проверок VPN по UDP",
            ),
            "var(--mute)",
        ),
    }
}

pub(super) fn status_badge(observation: Option<&Availability>, lang: Locale) -> Markup {
    html! {
        @if let Some(status) = tcp_status(observation) {
            @let (code, label, color) = status_label(status, lang);
            span data-path-transport="tcp" data-path-status=(code) style=(format!("color: {color};")) { (label) }
            @if let Some(state) = observation.and_then(|record| record.tcp.as_ref()) {
                small.ed-grid__mut style="display:block;" {
                    (state.vantage) " · " (format_msk_iso(state.checked_at))
                }
            }
        }
        @if let Some(udp) = observation.and_then(|record| record.udp.as_ref()) {
            @let (code, label, color) = status_label(udp.status(), lang);
            span data-path-transport="udp" data-path-status=(code) style=(format!("display:block;color: {color};")) { (label) }
            @if let Some(at) = udp.checked_at {
                @let UdpAvailability { verified, total, failed, .. } = *udp;
                @let unknown = total.saturating_sub(verified + failed);
                small.ed-grid__mut style="display:block;" {
                    (match lang {
                        Locale::En => format!("{verified}/{total} verified"),
                        Locale::Ru => format!("Проверено {verified} из {total}"),
                    })
                    @if failed > 0 {
                        " · " (match lang {
                            Locale::En => format!("{failed} failed"),
                            Locale::Ru => format!("{failed} с ошибкой"),
                        })
                    }
                    @if unknown > 0 {
                        " · " (match lang {
                            Locale::En => format!("{unknown} unverified"),
                            Locale::Ru => format!("{unknown} без подтверждения"),
                        })
                    }
                    " · " (format_msk_iso(at))
                }
            }
        }
    }
}

pub(super) fn fleet_summary(
    servers: &[vpnctl_core::Server],
    paths: &std::collections::HashMap<vpnctl_core::ServerId, Availability>,
    names: &crate::handlers::admin::helpers::ServerNames,
    lang: Locale,
) -> Markup {
    let statuses = [
        Status::Tcp(ServicePathStatus::Unreachable),
        Status::Tcp(ServicePathStatus::Degraded),
        Status::Tcp(ServicePathStatus::Recovering),
        Status::Tcp(ServicePathStatus::Unknown),
        Status::UdpFailed,
        Status::UdpUnknown,
        Status::Tcp(ServicePathStatus::Available),
        Status::UdpVerified,
    ];
    let has_status = |server: &Server, status: Status| {
        let path = paths.get(&server.id);
        match status {
            Status::Tcp(_) => tcp_status(path) == Some(status),
            _ => path
                .and_then(|record| record.udp.as_ref())
                .is_some_and(|udp| udp.status() == status),
        }
    };
    html! {
        section #fleet-current-path style="margin-top:18px;" {
            h2 { (tr(lang, "Availability now", "Доступность сейчас")) }
            p.ed-grid__mut {
                (tr(lang,
                    "TCP results show port reachability. Two failed rounds confirm an outage. Two successful rounds confirm recovery. UDP results come from external VPN client tests. Counts are per transport.",
                    "Для TCP показана доступность портов. Два неудачных раунда подтверждают отказ. Два успешных раунда подтверждают восстановление. Для UDP показаны результаты внешних проверок VPN. Счётчики ведутся отдельно по каждому транспорту."))
            }
            @if servers.is_empty() {
                p {
                    (tr(lang, "No servers to monitor. ", "Пока нет серверов для проверки. "))
                    a href="/admin/servers/new" { (tr(lang, "Add server", "Добавить сервер")) }
                }
            } @else {
                div style="display:flex;flex-wrap:wrap;gap:8px 20px;" {
                    @for status in statuses {
                        @let (code, label, color) = status_label(status, lang);
                        @let count = servers.iter().filter(|s| has_status(s, status)).count();
                        @if matches!(status, Status::Tcp(_)) || count > 0 {
                            span data-path-count=(code) style=(format!("color:{color};")) {
                                (label) ": " b { (count) }
                            }
                        }
                    }
                }
                div style="display:flex;flex-wrap:wrap;gap:12px 24px;margin-top:12px;" {
                    @for status in statuses {
                        @for server in servers.iter().filter(|s| attention_status(paths.get(&s.id)) == Some(status)) {
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
    current: Option<&Availability>,
    incidents: Option<&[ServicePathIncident]>,
    has_protocol_results: bool,
    lang: Locale,
) -> Markup {
    html! {
        section #current-path-availability style="margin-bottom:24px;" {
            h2 { (tr(lang, "Current path availability", "Доступность сейчас")) }
            (status_badge(current, lang))
            @if current.is_some_and(|record| record.udp.is_some()) {
                p.ed-grid__mut {
                    (tr(lang,
                        "An external VPN client confirms a protocol by transferring data through the tunnel. See the result for each protocol.",
                        "Внешний VPN-клиент проверяет передачу данных через туннель. Результат доступен для каждого протокола.",
                    ))
                    " " a href=(if has_protocol_results { "#protocol-assurance" } else { "#external-readiness" }) {
                        (tr(lang, "Protocol checks", "Проверка протоколов"))
                    }
                }
            }
            @if tcp_status(current).is_some() {
                p.ed-grid__mut {
                    (tr(lang,
                        "TCP VPN ports are checked from the named measurement network. A successful check confirms a connection to the port. Node health and protocol tests appear below.",
                        "TCP-порты VPN проверяются из указанной сети. Успешная проверка подтверждает соединение с портом. Состояние узла и проверки протоколов показаны ниже.",
                    ))
                }
                p.ed-grid__mut {
                    (tr(lang,
                        "Two failed rounds confirm an outage. Two successful rounds confirm recovery. With auto-suppress enabled, confirmed outages hide direct routes from subscriptions until recovery.",
                        "Два неудачных раунда подтверждают отказ. Два успешных раунда подтверждают восстановление. При включённом автоскрытии подтверждённый отказ убирает прямые маршруты из подписок до восстановления.",
                    ))
                }
            }
            h3 { (tr(lang, "TCP path incident history", "История отказов TCP")) }
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
        let page = detail_section(None, None, false, Locale::En).into_string();
        assert!(page.contains("Unknown / stale"));
        assert!(page.contains("A successful check confirms a connection to the port"));
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
