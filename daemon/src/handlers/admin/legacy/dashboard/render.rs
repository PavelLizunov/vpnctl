use std::collections::HashSet;

use crate::handlers::admin::icons::{icon, status};
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use maud::{Markup, html};

use super::abuse::{dashboard_abuse_summary, load_likely_shared, sharing_review};
use super::fleet::{
    dashboard_fleet_table, dashboard_fleet_traffic_totals, dashboard_fleet_uptime,
    dashboard_health_feed, dashboard_quality_ranking, kernel_floor_rollup,
};
use super::telemetry::{
    dashboard_heavy_users, dashboard_live_activity_from_rows, dashboard_vpn_activity,
};
use crate::AppState;
use crate::handlers::admin::helpers::{internal_error, render_page, theme_accent_lang};
use crate::handlers::admin::legacy::server_detail::detail_tabs;
use crate::handlers::admin::legacy::user_sections::{
    pick_vpn_sparkline_window, vpn_traffic_chart, window_picker_section,
};

struct DashboardStats {
    servers: i64,
    users: i64,
    disabled_users: i64,
    grants: i64,
    distinct_protocols: usize,
}

async fn collect_dashboard_data(state: &AppState) -> anyhow::Result<DashboardStats> {
    let (servers_count, users_count, disabled_users_count, grants_count, server_list) = tokio::try_join!(
        state.inv.count_servers(),
        state.inv.count_users(),
        state.inv.count_disabled_users(),
        state.inv.count_grants(),
        state.inv.list_servers(),
    )?;
    let distinct_protocols: HashSet<_> = server_list
        .iter()
        .flat_map(|s| s.enabled_protocols.iter().map(|p| p.0.as_str()))
        .collect();
    Ok(DashboardStats {
        servers: servers_count,
        users: users_count,
        disabled_users: disabled_users_count,
        grants: grants_count,
        distinct_protocols: distinct_protocols.len(),
    })
}

fn dashboard_summary_bar(
    stats: &DashboardStats,
    conns_now: usize,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let tip = tr(
        lang,
        "Counts straight from the SQLite inventory backing this daemon (/var/lib/vpnctl/inv.db). Servers, users, grants and the daemon version update on every reload.",
        "Счётчики читаются напрямую из SQLite-инвентаря этого демона (/var/lib/vpnctl/inv.db). Серверы, пользователи, выданные доступы и версия демона обновляются при каждой перезагрузке.",
    );
    html! {
        div.ed-sumbar {
            h1.ed-sumbar__h {
                (tr(lang, "fleet ", "парк "))
                em { (tr(lang, "at a glance", "одним взглядом")) }
            }
            span.ed-tip title=(tip) { (status("info", lang, "Information", "Информация")) }
            span.ed-sumbar__stat {
                b { (stats.servers) } " "
                (crate::i18n::noun_for(lang, stats.servers as u64, "server", "servers", "сервер", "сервера", "серверов"))
            }
            span.ed-sumbar__stat {
                b { (stats.users) } " "
                (crate::i18n::noun_for(lang, stats.users as u64, "user", "users", "юзер", "юзера", "юзеров"))
                @if stats.disabled_users > 0 {
                    " · "
                    a.ed-sumbar__warn href="/admin/users"
                      title=(tr(
                          lang,
                          "Users with disabled=true (soft-suspended). Click to drill into the user list.",
                          "Пользователи с disabled=true (на паузе). Кликни, чтобы открыть список.",
                      )) {
                        b { (stats.disabled_users) } (tr(lang, " paused", " на паузе"))
                    }
                }
            }
            span.ed-sumbar__stat {
                b { (stats.grants) } " "
                (crate::i18n::noun_for(lang, stats.grants as u64, "grant", "grants", "доступ", "доступа", "доступов"))
            }
            span.ed-sumbar__stat {
                b { (stats.distinct_protocols) } " "
                (crate::i18n::noun_for(lang, stats.distinct_protocols as u64, "protocol", "protocols", "протокол", "протокола", "протоколов"))
            }
            span.ed-sumbar__stat { b { (conns_now) } " " (tr(lang, "conns now", "подкл. сейчас")) }
            span.ed-sumbar__live {
                (icon("circle"))
                "vpnctld " b { (vpnctl_core::build_version()) } " "
                em { (tr(lang, "live", "активен")) }
            }
        }
    }
}

#[derive(serde::Deserialize, Default)]
pub(crate) struct DashboardQuery {
    pub vpn_window: Option<String>,
    pub q: Option<String>,
    pub level: Option<String>,
    pub min_score: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum DashboardTab {
    Overview,
    Activity,
    Sharing,
}

impl DashboardTab {
    fn slug(self) -> &'static str {
        match self {
            DashboardTab::Overview => "overview",
            DashboardTab::Activity => "activity",
            DashboardTab::Sharing => "sharing",
        }
    }
}

pub(crate) async fn dashboard(
    headers: HeaderMap,
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<DashboardQuery>,
) -> Result<Markup, Response> {
    dashboard_render(headers, state, query, DashboardTab::Overview).await
}

pub(crate) async fn dashboard_activity(
    headers: HeaderMap,
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<DashboardQuery>,
) -> Result<Markup, Response> {
    dashboard_render(headers, state, query, DashboardTab::Activity).await
}

pub(crate) async fn sharing(
    headers: HeaderMap,
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<DashboardQuery>,
) -> Result<Markup, Response> {
    dashboard_render(headers, state, query, DashboardTab::Sharing).await
}

async fn dashboard_render(
    headers: HeaderMap,
    state: AppState,
    query: DashboardQuery,
    tab: DashboardTab,
) -> Result<Markup, Response> {
    let (theme, accent, lang) = theme_accent_lang(&headers);
    let window = pick_vpn_sparkline_window(query.vpn_window.as_deref());
    let since_hours = window.cells * window.bucket_hours;
    let fleet_rows = state
        .inv
        .recent_vpn_stats_fleet(since_hours.saturating_mul(2), window.bucket_hours)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", error = %e, "recent_vpn_stats_fleet failed");
            Vec::new()
        });

    let stats = collect_dashboard_data(&state)
        .await
        .map_err(internal_error)?;

    let heavy_users = if window.bucket_hours >= 24 {
        state
            .inv
            .top_users_by_daily_traffic(since_hours.div_ceil(24), 5)
            .await
    } else {
        state.inv.top_users_by_traffic(since_hours, 5).await
    }
    .unwrap_or_else(|e| {
        tracing::warn!(target = "vpnctld::admin", error = %e, "top users traffic query failed");
        Vec::new()
    });

    let server_list_fleet = state.inv.list_servers().await.unwrap_or_else(|e| {
        tracing::warn!(target = "vpnctld::admin", error = %e, "list_servers (fleet) failed");
        Vec::new()
    });

    let fleet_uptime: Vec<(
        vpnctl_core::ServerId,
        [Option<vpnctl_inventory::UptimeStat>; 3],
    )> = {
        let mut set = tokio::task::JoinSet::new();
        for s in &server_list_fleet {
            let inv = state.inv.clone();
            let sid = s.id.clone();
            set.spawn(async move {
                let (u24h, u7d, u30d) = tokio::join!(
                    inv.uptime_for_server(&sid, 24),
                    inv.uptime_for_server(&sid, 24 * 7),
                    inv.uptime_for_server(&sid, 24 * 30),
                );
                (sid, [u24h.ok(), u7d.ok(), u30d.ok()])
            });
        }
        let mut results = std::collections::HashMap::new();
        while let Some(res) = set.join_next().await {
            if let Ok((sid, stats)) = res {
                results.insert(sid, stats);
            }
        }
        server_list_fleet
            .iter()
            .map(|s| {
                (
                    s.id.clone(),
                    results.remove(&s.id).unwrap_or([None, None, None]),
                )
            })
            .collect()
    };

    let fleet_quality: Vec<(
        vpnctl_core::ServerId,
        vpnctl_inventory::ServiceQualityScore,
        vpnctl_inventory::ServiceQualityScore,
    )> = {
        let mut set = tokio::task::JoinSet::new();
        for s in &server_list_fleet {
            let inv = state.inv.clone();
            let sid = s.id.clone();
            set.spawn(async move {
                let (q24_res, q7_res) = tokio::join!(
                    inv.provisioned_service_quality_for_server(
                        &sid,
                        24,
                        vpnctl_inventory::QUALITY_MIN_SAMPLES
                    ),
                    inv.provisioned_service_quality_for_server(
                        &sid,
                        24 * 7,
                        vpnctl_inventory::QUALITY_MIN_SAMPLES
                    ),
                );
                let q24 = q24_res.unwrap_or_else(|_| {
                    vpnctl_inventory::score_samples(&[], 24, vpnctl_inventory::QUALITY_MIN_SAMPLES)
                });
                let q7 = q7_res.unwrap_or_else(|_| {
                    vpnctl_inventory::score_samples(
                        &[],
                        24 * 7,
                        vpnctl_inventory::QUALITY_MIN_SAMPLES,
                    )
                });
                (sid, q24, q7)
            });
        }
        let mut results = std::collections::HashMap::new();
        while let Some(res) = set.join_next().await {
            if let Ok((sid, q24, q7)) = res {
                results.insert(sid, (q24, q7));
            }
        }
        server_list_fleet
            .iter()
            .map(|s| {
                let (q24, q7) = results.remove(&s.id).unwrap_or_else(|| {
                    (
                        vpnctl_inventory::score_samples(
                            &[],
                            24,
                            vpnctl_inventory::QUALITY_MIN_SAMPLES,
                        ),
                        vpnctl_inventory::score_samples(
                            &[],
                            24 * 7,
                            vpnctl_inventory::QUALITY_MIN_SAMPLES,
                        ),
                    )
                });
                (s.id.clone(), q24, q7)
            })
            .collect()
    };

    let kernel_versions = state.inv.kernel_versions_fleet().await.unwrap_or_else(|e| {
        tracing::warn!(target = "vpnctld::admin", error = %e, "kernel_versions_fleet failed");
        Vec::new()
    });

    let latest_health_per_server: Vec<(
        vpnctl_core::ServerId,
        Option<vpnctl_inventory::NodeHealthRow>,
    )> = {
        let health_map = state
            .inv
            .latest_node_health_fleet()
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(target = "vpnctld::admin", error = %e, "latest_node_health_fleet failed");
                std::collections::HashMap::new()
            });
        server_list_fleet
            .iter()
            .map(|s| (s.id.clone(), health_map.get(&s.id).cloned()))
            .collect()
    };

    let active_conns_now: Vec<(vpnctl_core::ServerId, Option<usize>)> = server_list_fleet
        .iter()
        .map(|s| {
            let n = state
                .snapshot_cache
                .get_live(&s.id)
                .map(|snap| snap.snapshot.connections.len());
            (s.id.clone(), n)
        })
        .collect();
    let live_activity = dashboard_live_activity_from_rows(
        &server_list_fleet,
        &active_conns_now,
        &fleet_rows,
        window,
    );

    let recent_alerts = state.inv.recent_alerts(5, false).await.unwrap_or_else(|e| {
        tracing::warn!(target = "vpnctld::admin", error = %e, "recent_alerts failed");
        Vec::new()
    });
    let unacked_total = state.inv.unacked_alert_count().await.unwrap_or_else(|e| {
        tracing::warn!(target = "vpnctld::admin", error = %e, "unacked_alert_count failed");
        recent_alerts.len() as u64
    });

    let likely_shared = load_likely_shared(&state.inv).await;

    let coeffs: std::collections::HashMap<vpnctl_core::ServerId, f64> = server_list_fleet
        .iter()
        .map(|s| (s.id.clone(), s.usage_coefficient))
        .collect();

    let traffic_24h: std::collections::HashMap<vpnctl_core::ServerId, u64> = state
        .inv
        .weighted_vpn_traffic_by_server(24)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", error = %e, "weighted_vpn_traffic_by_server failed");
            Vec::new()
        })
        .into_iter()
        .collect();

    let conns_now: usize = active_conns_now.iter().filter_map(|(_, c)| *c).sum();

    let body = html! {
        div.ed-art-eyebrow { (crate::i18n::t(lang, crate::i18n::K::PageDashboard)) }
        (dashboard_summary_bar(&stats, conns_now, lang))
        (dashboard_fleet_table(&server_list_fleet, &latest_health_per_server, &active_conns_now, &traffic_24h, &kernel_versions, lang))
        (dashboard_quality_ranking(&fleet_quality, lang))
        (detail_tabs(
            "/admin",
            tab.slug(),
            &[
                ("overview", crate::i18n::tr(lang, "Overview", "Обзор")),
                ("activity", crate::i18n::tr(lang, "Activity", "Активность")),
                ("sharing", crate::i18n::tr(lang, "Sharing risk", "Риск расшаривания")),
            ],
            lang,
        ))

        @if tab == DashboardTab::Overview {
            div.ed-dash-cols {
                (dashboard_abuse_summary(&likely_shared, lang))
                (dashboard_health_feed(&recent_alerts, unacked_total, lang))
            }
            div style="margin-top: 14px;" {
                a href="/admin/activity#vpn-traffic"
                  style="display: inline-block; font-family: var(--mono); font-size: 12px; color: var(--mute); text-decoration: none; border: 1px solid var(--rule); border-radius: 3px; padding: 4px 10px;" {
                    (icon("history"))
                    (crate::i18n::tr(
                        lang,
                        "Traffic history · 1 / 7 / 30 days",
                        "История трафика · 1 / 7 / 30 дней",
                    ))
                }
            }
        }

        @if tab == DashboardTab::Activity {
            (window_picker_section("/admin/activity", window.slug, lang))
            (dashboard_fleet_uptime(&fleet_uptime, lang))
            (dashboard_vpn_activity(&live_activity, window, lang))
            div id="vpn-traffic" style="margin-top: 24px;" {
                div.ed-art-eyebrow {
                    (crate::i18n::tr(lang, "Fleet traffic", "Трафик флота"))
                    " · "
                    (match lang {
                        crate::i18n::Locale::En => window.label_en,
                        crate::i18n::Locale::Ru => window.label_ru,
                    })
                }
                (vpn_traffic_chart(&fleet_rows, window, lang))
                (dashboard_fleet_traffic_totals(&fleet_rows, &coeffs, window, lang))
            }
            (kernel_floor_rollup(&kernel_versions, lang))
            (dashboard_heavy_users(&heavy_users, window, lang))
        }

        @if tab == DashboardTab::Sharing {
            (sharing_review(&likely_shared, &query, lang))
        }
    };
    Ok(render_page(&state, "dashboard", &theme, &accent, lang, body).await)
}
