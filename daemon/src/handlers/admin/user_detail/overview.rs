//! Overview summary card for user-detail right column.

use maud::{Markup, html};

use crate::handlers::admin::helpers::{format_msk_iso, humanize_bytes};
use crate::handlers::admin::legacy::user_is_likely_shared;
use crate::http_util::path_segment_encode;

/// Densified overview for the user-detail right column: four facts,
/// 24h traffic split, and the grant summary. It only rearranges data
/// already loaded by `user_detail_render`; no extra query or client state.
pub(crate) fn user_overview_summary(
    user: &vpnctl_core::User,
    facts: (
        &vpnctl_inventory::UserLifecycle,
        Option<chrono::DateTime<chrono::Utc>>,
        &vpnctl_inventory::SubAccessAggregates,
        &[vpnctl_inventory::UaCluster],
    ),
    traffic: &[(vpnctl_core::ServerId, u64, u64)],
    inventory: (
        &[vpnctl_core::Server],
        &std::collections::HashSet<vpnctl_core::ServerId>,
    ),
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let (lifecycle, last_seen, aggregates, ua_clusters) = facts;
    let (all_servers, granted_ids) = inventory;
    let likely_shared = user_is_likely_shared(aggregates, ua_clusters);
    let traffic_total: u64 = traffic
        .iter()
        .map(|(_, up, down)| up.saturating_add(*down))
        .sum();

    html! {
        div.ed-fact-grid aria-label=(tr(lang, "Lifecycle and sharing summary", "Жизненный цикл и sharing summary")) {
            div.ed-fact title=(tr(lang, "Heuristic over the 30-day subscription-access window; cross-check Activity before acting.", "Эвристика по 30-дневному окну обращений к подписке; перед действием сверься с Activity.")) {
                div.ed-fact__k { (tr(lang, "Sharing verdict", "Вердикт по расшариванию")) " ⓘ" }
                div.ed-fact__v style=(if likely_shared { "color: var(--warm); font-weight: 600;" } else { "color: var(--green);" }) {
                    @if likely_shared { (tr(lang, "likely shared", "вероятно расшарен")) }
                    @else { (tr(lang, "single-user", "один пользователь")) }
                    " · " (aggregates.distinct_ips) " IP · "
                    (crate::i18n::n_of(lang, aggregates.distinct_asns, "ASN", "ASNs", "ASN", "ASN", "ASN"))
                    " · "
                    (crate::i18n::n_of(lang, aggregates.distinct_countries, "country", "countries", "страна", "страны", "стран"))
                }
            }
            div.ed-fact title=(tr(lang, "When this inventory row was created.", "Когда создана запись в инвентаре.")) {
                div.ed-fact__k { (tr(lang, "created", "создан")) }
                div.ed-fact__v { (format_msk_iso(lifecycle.created_at)) " · " (lifecycle.age_days) (tr(lang, "d", "д")) }
            }
            div.ed-fact title=(tr(lang, "Most recent subscription fetch or attributed VPN tick.", "Последнее обращение к подписке или атрибутированный VPN-тик.")) {
                div.ed-fact__k { (tr(lang, "last seen", "последний раз")) }
                div.ed-fact__v {
                    @match last_seen {
                        Some(ts) => (format_msk_iso(ts)),
                        None => (tr(lang, "never", "никогда")),
                    }
                }
            }
            div.ed-fact title=(tr(lang, "Most recent real, non-egress subscription fetch; clients normally poll every 3600s.", "Последнее реальное не-egress обращение к подписке; клиенты обычно опрашивают раз в 3600с.")) {
                div.ed-fact__k { (tr(lang, "last fetch", "последний fetch")) }
                div.ed-fact__v {
                    @match lifecycle.last_sub_fetch {
                        Some(ts) => (format_msk_iso(ts)),
                        None => (tr(lang, "never · polls 3600s", "никогда · опрос 3600с")),
                    }
                }
            }
        }

        section style="margin-top: 18px;" {
            div.ed-art-eyebrow {
                (tr(lang, "Traffic by server · 24h", "Трафик по серверам · 24ч")) " "
                span.ed-tip title=(tr(lang, "Per-server upload and download attributed to this user from clash-api ticks.", "Upload и download по серверам, атрибутированные этому пользователю из clash-api тиков.")) { "ⓘ" }
            }
            @if traffic.is_empty() {
                p.ed-grid__mut style="font-family: var(--serif); font-style: italic; font-size: 12px;" {
                    (tr(lang, "No per-server traffic recorded yet (NM-11).", "Трафик по серверам пока не записан (NM-11)."))
                }
            } @else {
                table.ed-grid style="margin-top: 8px;" {
                    thead { tr { th { (tr(lang, "server", "сервер")) } th.num { (tr(lang, "uploaded", "отправлено")) } th.num { (tr(lang, "downloaded", "принято")) } th.num { (tr(lang, "total", "всего")) } th { (tr(lang, "share", "доля")) } } }
                    tbody {
                        @for (sid, up, down) in traffic {
                            @let total = up.saturating_add(*down);
                            @let share = total.saturating_mul(100).checked_div(traffic_total).unwrap_or(0);
                            tr {
                                td { a.ed-grid__id href=(format!("/admin/servers/{}", path_segment_encode(&sid.0))) { (sid.0) } }
                                td.num { (humanize_bytes(*up)) }
                                td.num { (humanize_bytes(*down)) }
                                td.num { b { (humanize_bytes(total)) } }
                                td { div.ed-hist__bar title=(format!("{share}%")) { div style=(format!("width: {share}%;")) {} } }
                            }
                        }
                    }
                }
            }
        }

        section style="margin-top: 18px;" {
            div.ed-art-eyebrow { (tr(lang, "Access", "Доступ")) " · " (granted_ids.len()) " " (tr(lang, "servers granted", "серверов выдано")) }
            div.ed-grants-summary {
                @for server in all_servers {
                    @if granted_ids.contains(&server.id) {
                        a.ed-grant-chip.on href=(format!("/admin/servers/{}", path_segment_encode(&server.id.0))) { "✓ " (server.id.0) }
                    } @else {
                        form method="post" action=(format!("/admin/users/{}/grants/{}", path_segment_encode(&user.id.0), path_segment_encode(&server.id.0))) {
                            button.ed-grant-chip.off type="submit" title=(tr(lang, "Grant this server", "Выдать этот сервер")) {
                                (server.id.0) " — " (tr(lang, "not granted · grant →", "не выдан · выдать →"))
                            }
                        }
                    }
                }
            }
        }
    }
}
