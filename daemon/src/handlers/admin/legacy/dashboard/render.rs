use std::collections::HashSet;

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

/// Aggregated counters used in the dashboard top-row metric tiles.
struct DashboardStats {
    servers: i64,
    users: i64,
    /// B1.user (audit 2026-05-22) — soft-suspended users. Surfaced
    /// in the Users tile sub-line so paused accounts stay visible
    /// even when the operator isn't scrolling through /admin/users.
    disabled_users: i64,
    grants: i64,
    distinct_protocols: usize,
}

/// Pull every counter the dashboard needs in one pass. All five inventory
/// queries (4 counters + recent audit) are independent so we kick them off
/// in parallel via `try_join` — the round-trips are cheap, but rendering
/// should still feel instant even after the inventory grows.
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

/// Render an editorial 4-cell metric row from the dashboard stats.
fn dashboard_summary_bar(
    stats: &DashboardStats,
    conns_now: usize,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    // Densification pass (2026-07-09): the four 68px KPI cards + the
    // explanatory deck above collapse into one dense mono line. The prose
    // folds into the ⓘ hover; the counts stay. Same data, a quarter of the
    // vertical space (see design_handoff_vpnctl_densify).
    let tip = tr(
        lang,
        "Counts straight from the SQLite inventory backing this daemon (/var/lib/vpnctl/inv.db). Servers, users, grants and the daemon version update on every reload.",
        "Счётчики читаются напрямую из SQLite-инвентаря этого демона (/var/lib/vpnctl/inv.db). Серверы, пользователи, выданные доступы и версия демона обновляются при каждой перезагрузке.",
    );
    html! {
        div.ed-sumbar {
            h1.ed-sumbar__h {
                (tr(lang, "homelab ", "homelab "))
                em { (tr(lang, "at a glance", "одним взглядом")) }
            }
            span.ed-tip title=(tip) { "ⓘ" }
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
                span.ed-sumbar__dot {}
                "vpnctld " b { (vpnctl_core::build_version()) } " "
                em { (tr(lang, "live", "активен")) }
            }
        }
    }
}

/// Dashboard URL query. Activity uses `vpn_window`; sharing uses the
/// three filters below. Keeping one query type lets every dashboard tab
/// flow through the same chrome and tab bar.
#[derive(serde::Deserialize, Default)]
pub(crate) struct DashboardQuery {
    pub vpn_window: Option<String>,
    pub q: Option<String>,
    pub level: Option<String>,
    pub min_score: Option<String>,
}

/// dashboard's in-page tabs (ui-audit follow-up). The at-a-glance KPI
/// metrics + today-digest + fleet table stay as CHROME (visible on every
/// tab — the landing page's whole point is the glance); the two tabs
/// split only the deeper drill-downs. `Overview` is the default (bare
/// `/admin/`).
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

// Thin axum handlers — one per tab route in app.rs. Bare `/admin/`
// (+ `/admin`, `/admin/overview`) render the overview tab.
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
    // 2026-05-23 — ONE window picker drives every time-series
    // tile on the dashboard: VPN activity, Heavy users, Fleet
    // traffic chart. Single source of truth in
    // VPN_SPARKLINE_WINDOWS; bookmarkable URL via
    // `?vpn_window=24h|7d|30d|all`.
    let window = pick_vpn_sparkline_window(query.vpn_window.as_deref());
    let since_hours = window.cells * window.bucket_hours;
    // PR-Dash dash#2 — pull TWICE the window so the real-traffic card
    // can compute Δ% vs the prior equal-length window Rust-side (no
    // second query). Inventory reads the ingest-time hourly rollup,
    // not every user's raw poll row.
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

    // Heavy users — raw ticks for 24h, existing daily rollups for
    // longer windows. The tile heading follows the selected window.
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

    // Post-2026-05-22 — fleet-wide uptime tile. Loops `list_servers`
    // and aggregates `uptime_for_server` for 24h / 7d / 30d. Loop
    // (vs a single SUM-of-SUMs SQL helper) keeps it dead-simple +
    // reuses the already-spec-tested per-server path; for ≤100
    // servers in a homelab the N+1 query cost is negligible.
    // Per-server detail page still gives drill-in.
    // PR-Dash dash#1 — server list reused by BOTH the fleet-uptime
    // loop AND the new fleet-at-a-glance table. Loaded ONCE here so
    // the at-a-glance card adds no second N+1 beyond the existing
    // per-server uptime loop budget.
    let server_list_fleet = state.inv.list_servers().await.unwrap_or_else(|e| {
        tracing::warn!(target = "vpnctld::admin", error = %e, "list_servers (fleet) failed");
        Vec::new()
    });

    let fleet_uptime = {
        let mut rows: Vec<(
            vpnctl_core::ServerId,
            [Option<vpnctl_inventory::UptimeStat>; 3],
        )> = Vec::with_capacity(server_list_fleet.len());
        for s in &server_list_fleet {
            let u24h = state.inv.uptime_for_server(&s.id, 24).await.ok();
            let u7d = state.inv.uptime_for_server(&s.id, 24 * 7).await.ok();
            let u30d = state.inv.uptime_for_server(&s.id, 24 * 30).await.ok();
            rows.push((s.id.clone(), [u24h, u7d, u30d]));
        }
        rows
    };

    let mut fleet_quality = Vec::with_capacity(server_list_fleet.len());
    for server in &server_list_fleet {
        let q24 = state
            .inv
            .service_quality_for_server(&server.id, 24, vpnctl_inventory::QUALITY_MIN_SAMPLES)
            .await
            .unwrap_or_else(|_| {
                vpnctl_inventory::score_samples(&[], 24, vpnctl_inventory::QUALITY_MIN_SAMPLES)
            });
        let q7 = state
            .inv
            .service_quality_for_server(&server.id, 24 * 7, vpnctl_inventory::QUALITY_MIN_SAMPLES)
            .await
            .unwrap_or_else(|_| {
                vpnctl_inventory::score_samples(&[], 24 * 7, vpnctl_inventory::QUALITY_MIN_SAMPLES)
            });
        fleet_quality.push((server.id.clone(), q24, q7));
    }

    // PR-Dash — newest kernel-versions JSON per server (Q-4e). Backs
    // BOTH the fleet-at-a-glance "sing-box version" column (dash#1) AND
    // the kernel-floor rollup card (dash#3). One grouped query.
    let kernel_versions = state.inv.kernel_versions_fleet().await.unwrap_or_else(|e| {
        tracing::warn!(target = "vpnctld::admin", error = %e, "kernel_versions_fleet failed");
        Vec::new()
    });

    // PR-Dash dash#1 — latest node-health snapshot per server, for the
    // at-a-glance disk%/mem%/up/last-probe columns. Reuses the existing
    // fleet loop budget (same `server_list_fleet`, no extra list query).
    let latest_health_per_server = {
        let mut out: Vec<(
            vpnctl_core::ServerId,
            Option<vpnctl_inventory::NodeHealthRow>,
        )> = Vec::with_capacity(server_list_fleet.len());
        for s in &server_list_fleet {
            let h = state.inv.latest_node_health(&s.id).await.unwrap_or_else(|e| {
                tracing::warn!(target = "vpnctld::admin", server = %s.id, error = %e, "latest_node_health failed");
                None
            });
            out.push((s.id.clone(), h));
        }
        out
    };

    // PR-Dash dash#1 — "active conns now" per server, read from the
    // in-memory clash-api snapshot cache (no DB round-trip). `None`
    // when the poller has never reached the server OR the last snapshot
    // went stale (polling stopped) — `get_live` gates on ~2 poll
    // intervals so a frozen snapshot can't keep reporting a live count.
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

    // Dashboard 1b — health feed: newest 5 unacked alerts + the unacked
    // total for the eyebrow. Quiet-dashboard contract: empty ⇒ no card.
    let recent_alerts = state.inv.recent_alerts(5, false).await.unwrap_or_else(|e| {
        tracing::warn!(target = "vpnctld::admin", error = %e, "recent_alerts failed");
        Vec::new()
    });
    let unacked_total = state.inv.unacked_alert_count().await.unwrap_or_else(|e| {
        tracing::warn!(target = "vpnctld::admin", error = %e, "unacked_alert_count failed");
        recent_alerts.len() as u64
    });

    // PR-Dash dash#5 (redesigned 2026-06-17) — composite account-sharing
    // risk. Gather raw signals fleet-wide over the retention window, score
    // each (simultaneity-weighted), keep only flagged users, strongest
    // first. Empty ⇒ card hidden.
    let likely_shared = load_likely_shared(&state.inv).await;

    // PR-Dash — per-server usage coefficients (for the weighted traffic
    // sums in dash#1 + dash#2). Built from the already-loaded server
    // list; no extra query.
    let coeffs: std::collections::HashMap<vpnctl_core::ServerId, f64> = server_list_fleet
        .iter()
        .map(|s| (s.id.clone(), s.usage_coefficient))
        .collect();

    // Fixed 24h fleet-table column is independent of the selected chart
    // bucket. Read the same compact hourly rollup as the chart.
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
        // Densification pass — the h1 + explanatory deck + four KPI cards
        // collapse into one dense summary bar (prose → ⓘ hover).
        (dashboard_summary_bar(&stats, conns_now, lang))
        // Dashboard 1b — dense fleet table, right under the summary bar.
        (dashboard_fleet_table(&server_list_fleet, &latest_health_per_server, &active_conns_now, &traffic_24h, &kernel_versions, lang))
        (dashboard_quality_ranking(&fleet_quality, lang))
        // ── in-page tabs (ui-audit follow-up). The KPI metrics +
        // today-digest + fleet table ABOVE are chrome (every tab — the
        // landing glance is never hidden); the three tabs below split only
        // the deeper drill-downs. Bare /admin/ == overview.
        (detail_tabs(
            "/admin",
            tab.slug(),
            &[
                ("overview", crate::i18n::tr(lang, "Overview", "Обзор")),
                ("activity", crate::i18n::tr(lang, "Activity", "Активность")),
                ("sharing", crate::i18n::tr(lang, "Sharing risk", "Риск расшаривания")),
            ],
        ))

        // ── OVERVIEW (default) — dashboard 1b two-panel row: what looks
        // shared (left) and what's unhealthy (right). Both panels keep the
        // quiet contract — an empty side simply renders nothing. Traffic-
        // limit crossings arrive as `user.traffic_limit` alerts, so they
        // surface in the health feed rather than a dedicated card.
        @if tab == DashboardTab::Overview {
            div.ed-dash-cols {
                (dashboard_abuse_summary(&likely_shared, lang))
                (dashboard_health_feed(&recent_alerts, unacked_total, lang))
            }
            // Issue 5 — the 24h / 7d / 30d / all traffic picker moved to
            // the Activity tab in the dashboard split, which hid it from
            // the Overview landing glance (Overview shows only a fixed 24h
            // fleet table). Surface a clear pointer so the existing
            // multi-window traffic history stays discoverable — a link, not
            // a duplicated chart/query.
            div style="margin-top: 14px;" {
                a href="/admin/activity#vpn-traffic"
                  style="display: inline-block; font-family: var(--mono); font-size: 12px; color: var(--mute); text-decoration: none; border: 1px solid var(--rule); border-radius: 3px; padding: 4px 10px;" {
                    (crate::i18n::tr(
                        lang,
                        "Traffic history · 1 / 7 / 30 days →",
                        "История трафика · 1 / 7 / 30 дней →",
                    ))
                }
            }
        }

        // ── ACTIVITY — the window-driven charts (traffic / uptime / usage).
        @if tab == DashboardTab::Activity {
            // Global time-window picker — ONE control drives VPN activity
            // + Fleet traffic + Heavy users, all on this tab. Base is the
            // activity tab so `?vpn_window=` reloads keep the operator here.
            (window_picker_section("/admin/activity", window.slug, lang))
            (dashboard_fleet_uptime(&fleet_uptime, lang))
            (dashboard_vpn_activity(&live_activity, window, lang))
            // Fleet-wide traffic chart (same window as the tiles above).
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
                // PR-Dash dash#2 — real ↑↓ totals + Δ% beside the chart.
                (dashboard_fleet_traffic_totals(&fleet_rows, &coeffs, window, lang))
            }
            // PR-Dash dash#3 — kernel-floor rollup (shared helper).
            (kernel_floor_rollup(&kernel_versions, lang))
            (dashboard_heavy_users(&heavy_users, window, lang))
        }

        // ── SHARING — full fleet-wide review in the same dashboard flow.
        @if tab == DashboardTab::Sharing {
            (sharing_review(&likely_shared, &query, lang))
        }
    };
    Ok(render_page(&state, "dashboard", &theme, &accent, lang, body).await)
}
