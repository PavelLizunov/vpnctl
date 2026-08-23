use std::collections::HashSet;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use maud::{Markup, html};

use super::super::helpers::*;
use super::*;
use crate::AppState;
use crate::http_util::path_segment_encode;

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

/// Parse a dotted version string (`"1.13.12"`, leading `v` tolerated)
/// into a comparable numeric tuple. Non-numeric / missing components
/// read as 0, and we pad to three components so `"1.13"` sorts below
/// `"1.13.1"`. Used by [`kernel_floor_rollup`] to find the fleet's
/// highest sing-box version (the de-facto target) and flag any node
/// below it. Returns `None` for an unparseable string (e.g. empty)
/// so the caller can skip it rather than treat it as `0.0.0`.
fn parse_version_tuple(raw: &str) -> Option<(u64, u64, u64)> {
    let trimmed = raw.trim().trim_start_matches('v');
    if trimmed.is_empty() {
        return None;
    }
    let mut parts = trimmed.split('.');
    // The first component must exist and parse, else the string isn't
    // a version we can reason about.
    let numeric_prefix = |s: &str| -> Option<u64> {
        let n: String = s.chars().take_while(char::is_ascii_digit).collect();
        (!n.is_empty()).then_some(n)?.parse().ok()
    };
    let major = numeric_prefix(parts.next()?)?;
    let minor = parts.next().and_then(numeric_prefix).unwrap_or(0);
    let patch = parts.next().and_then(numeric_prefix).unwrap_or(0);
    Some((major, minor, patch))
}

fn kernel_version_is_current(
    observed: &str,
    requirement: vpnctl_core::KernelVersionRequirement,
) -> bool {
    match requirement.policy {
        vpnctl_core::KernelVersionPolicy::Floor => {
            match (
                parse_version_tuple(observed),
                parse_version_tuple(requirement.value),
            ) {
                (Some(observed), Some(floor)) => observed >= floor,
                _ => false,
            }
        }
        vpnctl_core::KernelVersionPolicy::Pin => {
            observed.trim().trim_start_matches('v')
                == requirement.value.trim().trim_start_matches('v')
        }
    }
}

pub(super) fn server_detail_kernel_inventory_section(
    server: &vpnctl_core::Server,
    registry: &vpnctl_core::Registry,
    latest: Option<&vpnctl_inventory::NodeHealthRow>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let observations =
        kernel_observations_of(latest.and_then(|row| row.kernel_versions_json.as_deref()));
    let kernels = ordered_kernel_ids(server);
    let probe_age = latest.map(|row| chrono::Utc::now() - row.ts);
    let probe_stale = probe_age.is_some_and(|age| age.num_seconds() > 1200);
    html! {
        section id="kernel-version-inventory" style="margin-top: 28px;" {
            div.ed-art-eyebrow { (tr(lang, "Kernel versions", "Версии ядер")) }
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 12px;" {
                (tr(
                    lang,
                    "Every declared kernel, its installed build and the managed floor or pin. Probe state older than 20 minutes is marked stale.",
                    "Каждое объявленное ядро, установленная сборка и управляемый floor или pin. Проверка старше 20 минут помечается как устаревшая.",
                ))
                @if let Some(age) = probe_age {
                    " · " (tr(lang, "measured ", "измерено ")) (humanize_age(age, lang))
                }
            }
            table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11px;" {
                thead { tr style="border-bottom: 1px solid var(--ink);" {
                    th style="text-align:left;padding:5px 8px;" { (tr(lang, "declared kernel", "объявленное ядро")) }
                    th style="text-align:left;padding:5px 8px;" { (tr(lang, "installed", "установлено")) }
                    th style="text-align:left;padding:5px 8px;" { (tr(lang, "managed target", "целевая версия")) }
                    th style="text-align:left;padding:5px 8px;" { (tr(lang, "runtime", "сервис")) }
                    th style="text-align:left;padding:5px 8px;" { (tr(lang, "version state", "состояние версии")) }
                } }
                tbody {
                    @for kid in kernels {
                        @let requirement = registry.kernel(kid).and_then(|k| k.version_requirement());
                        @let observation = observations.get(&kid.0);
                        @let installed = observation.and_then(|o| o.version.as_deref());
                        @let current = installed.zip(requirement).map(|(v, r)| kernel_version_is_current(v, r));
                        tr data-kernel-version=(kid.0) style="border-bottom: 1px dotted var(--rule);" {
                            td style="padding:5px 8px;" { b { (kid.0) } }
                            td style="padding:5px 8px;" { (installed.unwrap_or("unknown")) }
                            td style="padding:5px 8px;" {
                                @if let Some(req) = requirement {
                                    (match req.policy {
                                        vpnctl_core::KernelVersionPolicy::Floor => "floor",
                                        vpnctl_core::KernelVersionPolicy::Pin => "pin",
                                    })
                                    " " (req.value)
                                } @else { "unmanaged" }
                            }
                            td style="padding:5px 8px;" {
                                @if probe_stale {
                                    span style="color:#e6a23c;" { (tr(lang, "stale", "устарело")) }
                                } @else {
                                    @match observation.and_then(|o| o.active) {
                                        Some(true) => span style="color:#2e7d32;" { (tr(lang, "active", "активно")) },
                                        Some(false) => span style="color:#c62828;" { (tr(lang, "inactive", "неактивно")) },
                                        None => span style="color:var(--mute);" { (tr(lang, "unknown", "неизвестно")) },
                                    }
                                }
                            }
                            td style="padding:5px 8px;" {
                                @if probe_stale {
                                    span style="color:#e6a23c;" { (tr(lang, "stale probe", "устаревшая проверка")) }
                                } @else {
                                    @match current {
                                        Some(true) => span style="color:#2e7d32;" { (tr(lang, "current", "актуально")) },
                                        Some(false) => span style="color:#c62828;" { (tr(lang, "stale", "устарело")) },
                                        None => span style="color:var(--mute);" { (tr(lang, "unknown", "неизвестно")) },
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

/// PR-Dash dash#3 (SHARED — PR-Server reuses this on the per-server
/// detail page) — fleet kernel-floor rollup.
///
/// Treats the **highest** sing-box version present anywhere in the
/// fleet as the de-facto target (the "floor" the operator should pull
/// everyone up to). Renders «sing-box N/M @ {floor} ✓ · K stale ⚠»
/// where N = servers already at the floor, M = servers reporting any
/// version, K = servers below it. When a fleet-wide kernel-update
/// action exists it links there — for the dashboard (static, CSP: no
/// inline JS) we link to /admin/servers where the SSE «update all
/// kernels» button lives. Renders the empty-state line when no node
/// has reported a version yet (quiet, no scary "0/0").
///
/// `kernel_versions` is `(ServerId, Option<kernel_versions_json>)` —
/// exactly the shape `kernel_versions_fleet()` (Q-4e) returns, so both
/// call sites pass it straight through.
pub(super) fn kernel_floor_rollup(
    kernel_versions: &[(vpnctl_core::ServerId, Option<String>)],
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::{K, t, tr};
    // Collect (server, parsed-version) only for servers that report a
    // sing-box version we can parse.
    let mut versioned: Vec<(u64, u64, u64)> = Vec::new();
    for (_, json) in kernel_versions {
        if let Some(v) = sing_box_version_of(json.as_deref()) {
            if let Some(tuple) = parse_version_tuple(&v) {
                versioned.push(tuple);
            }
        }
    }
    let reporting = versioned.len();
    let Some(floor) = versioned.iter().copied().max() else {
        // No node reported a parseable version. Quiet empty-state.
        return html! {
            section id="kernel-rollup" style="margin-top: 28px;" {
                div.ed-art-eyebrow { (t(lang, K::EyebrowKernelRollup)) }
                p style="font-family: var(--serif); font-style: italic; color: var(--mute); margin: 6px 0 0;" {
                    (t(lang, K::KernelRollupNoData))
                }
            }
        };
    };
    let at_floor = versioned.iter().filter(|v| **v == floor).count();
    let stale = reporting.saturating_sub(at_floor);
    let floor_str = format!("{}.{}.{}", floor.0, floor.1, floor.2);
    let all_current = stale == 0;

    html! {
        section id="kernel-rollup" style="margin-top: 28px;" {
            div.ed-art-eyebrow { (t(lang, K::EyebrowKernelRollup)) }
            p style="font-family: var(--serif); font-size: 14px; margin: 8px 0 0;" {
                "sing-box "
                b { (at_floor) "/" (reporting) }
                " @ "
                span.ed-mono { (floor_str) }
                " "
                @if all_current {
                    span style="color: #2e7d32;" {
                        "✓ " (t(lang, K::KernelRollupOnTarget))
                    }
                } @else {
                    span style="color: var(--acc);" {
                        "· " (stale) " " (t(lang, K::KernelRollupStale)) " ⚠"
                    }
                }
            }
            // When something is stale, point the operator at the place
            // where the fleet-wide «update all kernels» action lives.
            // The dashboard is static (CSP: no inline JS), so we LINK to
            // /admin/servers rather than embed the SSE button here.
            @if !all_current {
                p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 0;" {
                    (tr(
                        lang,
                        "Some nodes trail the newest sing-box on the fleet. Roll the binary forward from ",
                        "Часть нод отстаёт от самой свежей sing-box во флоте. Раскатать бинарь можно из раздела ",
                    ))
                    a href="/admin/servers" style="color: var(--ink);" {
                        (tr(lang, "Servers", "Серверы"))
                    }
                    (tr(
                        lang,
                        " — the «update all kernels» action upgrades binaries without touching config.",
                        " — действие «обновить все ядра» обновляет бинарники без правки конфига.",
                    ))
                }
            }
        }
    }
}

/// PR-Dash dash#1 — fleet-at-a-glance table. One row per server:
/// sing-box up · disk% · mem% · active conns now · 24h traffic ·
/// sing-box version · last-probe age. Every input is pre-loaded by the
/// caller (the at-a-glance card adds NO new N+1 beyond the existing
/// fleet-uptime loop). Empty cells render «—».
///
/// * `latest_health` — newest `node_health` row per server (disk/mem/
///   up + probe ts), looked up in the same loop as fleet-uptime.
/// * `active_conns` — live clash-api connection count per server from
///   the in-memory snapshot cache (no DB round-trip).
/// * `traffic_24h` — server-wide upload+download bytes over the last
///   24h, weighted by `usage_coefficient`, summed from the already-
///   loaded `recent_vpn_stats_fleet` rows.
/// * `kernel_versions` — newest `kernel_versions_json` per server (the
///   sing-box version column).
#[allow(clippy::too_many_arguments)]
fn dashboard_fleet_table(
    servers: &[vpnctl_core::Server],
    latest_health: &[(
        vpnctl_core::ServerId,
        Option<vpnctl_inventory::NodeHealthRow>,
    )],
    active_conns: &[(vpnctl_core::ServerId, Option<usize>)],
    traffic_24h: &std::collections::HashMap<vpnctl_core::ServerId, u64>,
    kernel_versions: &[(vpnctl_core::ServerId, Option<String>)],
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    if servers.is_empty() {
        // No fleet yet — the dashboard metrics deck + the servers page
        // already cover the "add a server" call-to-action; staying
        // quiet here avoids a third empty table.
        return html! {};
    }
    let now = chrono::Utc::now();
    let dash = "—";
    // Busiest node — its conns + traffic cells render bold (mock 1b) and
    // every share bar scales against its traffic.
    let max_traffic = traffic_24h.values().copied().max().unwrap_or(0);
    // Fleet-majority sing-box version: the most frequent reported one.
    // A node on any OTHER version gets a warm «≠» drift marker.
    let majority_version = fleet_majority_version(kernel_versions);
    html! {
        section id="fleet-at-a-glance" style="margin-top: 18px;" {
            div.ed-art-eyebrow {
                (tr(lang, "Fleet", "Флот")) " "
                span.ed-tip title=(tr(
                    lang,
                    "One row per server — sing-box state, disk/memory pressure (warm cell above 70%), live connections, 24h traffic with each node's share of the busiest, the on-node sing-box version (≠ marks drift from the fleet majority) and probe freshness. Open a server for the full drill-in.",
                    "Одна строка на сервер — состояние sing-box, нагрузка диска/памяти (тёплая ячейка выше 70%), живые подключения, трафик за 24ч с долей от самой нагруженной ноды, версия sing-box на ноде (≠ помечает дрейф от большинства флота) и свежесть пробы. Открой сервер для деталей.",
                )) { "ⓘ" }
            }
            table.ed-grid style="margin-top: 8px;" {
                thead {
                    tr {
                        th { (tr(lang, "server", "сервер")) }
                        th { (tr(lang, "state", "состояние")) }
                        th.num { (tr(lang, "disk", "диск")) }
                        th.num { (tr(lang, "mem", "память")) }
                        th.num { (tr(lang, "conns", "подкл.")) }
                        th.num { (tr(lang, "traffic 24h", "трафик 24ч")) }
                        th { (tr(lang, "share of traffic", "доля трафика")) }
                        th { (tr(lang, "kernel versions", "версии ядер")) }
                        th.num { (tr(lang, "probe", "проба")) }
                    }
                }
                tbody {
                    @for s in servers {
                        @let health = latest_health
                            .iter()
                            .find(|(id, _)| *id == s.id)
                            .and_then(|(_, h)| h.as_ref());
                        @let conns = active_conns
                            .iter()
                            .find(|(id, _)| *id == s.id)
                            .and_then(|(_, c)| *c);
                        @let kv_json = kernel_versions
                            .iter()
                            .find(|(id, _)| *id == s.id)
                            .and_then(|(_, j)| j.as_deref());
                        @let traffic = traffic_24h.get(&s.id).copied();
                        @let busiest = max_traffic > 0 && traffic == Some(max_traffic);
                        @let disk_pct = health.and_then(pct_disk);
                        @let mem_pct = health.and_then(pct_mem);
                        tr {
                            td { a.ed-grid__id href=(format!("/admin/servers/{}", path_segment_encode(&s.id.0))) { (s.id.0) } }
                            td.ed-grid__sm {
                                @match health.and_then(|h| h.sing_box_active) {
                                    Some(true) => span.ed-stat.ed-stat--active { span.ed-stat__dot {} (tr(lang, "up", "работает")) },
                                    Some(false) => span.ed-stat.ed-stat--failed { span.ed-stat__dot {} (tr(lang, "down", "не работает")) },
                                    None => span.ed-grid__mut { (dash) },
                                }
                            }
                            td class=(if disk_pct.is_some_and(|p| p > 70) { "num warn" } else { "num" }) {
                                @match disk_pct {
                                    Some(p) => { (p) "%" @if p > 70 { " ⚠" } },
                                    None => span.ed-grid__mut { (dash) },
                                }
                            }
                            td class=(if mem_pct.is_some_and(|p| p > 70) { "num warn" } else { "num" }) {
                                @match mem_pct {
                                    Some(p) => { (p) "%" @if p > 70 { " ⚠" } },
                                    None => span.ed-grid__mut { (dash) },
                                }
                            }
                            td.num {
                                @match conns {
                                    Some(c) => @if busiest { b { (c) } } @else { (c) },
                                    None => span.ed-grid__mut { (dash) },
                                }
                            }
                            td.num {
                                @match traffic {
                                    Some(b) => @if busiest { b { (humanize_bytes(b)) } } @else { (humanize_bytes(b)) },
                                    None => span.ed-grid__mut { (dash) },
                                }
                            }
                            td {
                                @if let Some(b) = traffic {
                                    @let share = b.saturating_mul(100).checked_div(max_traffic).unwrap_or(0);
                                    div.ed-hist__bar title=(format!("{share}%")) { div style=(format!("width: {share}%;")) {} }
                                } @else {
                                    span.ed-grid__mut { (dash) }
                                }
                            }
                            td.ed-grid__sm {
                                (kernel_versions_inline(s, kv_json, majority_version.as_deref()))
                            }
                            td.num.ed-grid__mut.ed-grid__sm {
                                @match health.map(|h| h.ts) {
                                    Some(ts) => (humanize_age(now - ts, lang)),
                                    None => (dash),
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// disk-used percentage from a health row, `None` when the probe
/// didn't carry both numerator + denominator. Floors a `>100%` reading
/// (impossible but defensive) at 100.
fn pct_disk(h: &vpnctl_inventory::NodeHealthRow) -> Option<u8> {
    let (used, total) = (h.disk_used_mib?, h.disk_total_mib?);
    if total == 0 {
        return None;
    }
    Some(((used.saturating_mul(100)) / total).min(100) as u8)
}

/// mem-USED percentage (`100 − available/total`) from a health row.
/// `None` when the probe lacked the figures.
fn pct_mem(h: &vpnctl_inventory::NodeHealthRow) -> Option<u8> {
    let (avail, total) = (h.mem_available_mib?, h.mem_total_mib?);
    if total == 0 {
        return None;
    }
    let free_pct = ((avail.saturating_mul(100)) / total).min(100) as u8;
    Some(100u8.saturating_sub(free_pct))
}

/// Compact "how long ago" string for the last-probe column. Buckets to
/// seconds / minutes / hours / days — the operator wants "is this
/// stale?" at a glance, not millisecond precision. Negative durations
/// (clock skew between probe write + render) clamp to «just now».
pub(super) fn humanize_age(d: chrono::Duration, lang: crate::i18n::Locale) -> String {
    use crate::i18n::tr;
    let secs = d.num_seconds();
    if secs < 60 {
        return tr(lang, "just now", "только что").to_string();
    }
    let mins = secs / 60;
    if mins < 60 {
        return format!("{}{}", mins, tr(lang, "m ago", "м назад"));
    }
    let hours = mins / 60;
    if hours < 24 {
        return format!("{}{}", hours, tr(lang, "h ago", "ч назад"));
    }
    let days = hours / 24;
    format!("{}{}", days, tr(lang, "d ago", "д назад"))
}

/// PR-Dash dash#2 — real fleet traffic totals beside the activity
/// chart. Uses the same aligned buckets as the chart so the bars and
/// totals cannot disagree at a day boundary.
///
/// `coeffs` maps each server to its `usage_coefficient`; unknown
/// servers default to 1.0.
fn dashboard_fleet_traffic_totals(
    rows: &[vpnctl_inventory::VpnStatsRow],
    coeffs: &std::collections::HashMap<vpnctl_core::ServerId, f64>,
    window: VpnSparklineWindow,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    use chrono::{DurationRound, TimeDelta, Utc};
    let bucket_seconds = i64::from(window.bucket_hours) * 3600;
    let Ok(now) = Utc::now().duration_trunc(TimeDelta::seconds(bucket_seconds)) else {
        return html! {};
    };
    let cur_start =
        now - TimeDelta::seconds(i64::from(window.cells.saturating_sub(1)) * bucket_seconds);
    let prior_start = cur_start - TimeDelta::seconds(i64::from(window.cells) * bucket_seconds);

    // Sum ALL rows (per-user attributed + unattributed remainder).
    // Since the NM-11 attribution fix the server-wide row holds only
    // the unattributed remainder, so filtering to user_id IS NULL
    // undercounts by the attributed share. Match `vpn_traffic_chart`
    // which already sums every row.
    let weight = |sid: &vpnctl_core::ServerId| -> f64 { coeffs.get(sid).copied().unwrap_or(1.0) };
    let mut cur_up = 0f64;
    let mut cur_dn = 0f64;
    let mut prior_total = 0f64;
    for r in rows {
        let Ok(row_bucket) = r.ts.duration_trunc(TimeDelta::seconds(bucket_seconds)) else {
            continue;
        };
        if row_bucket > now {
            continue;
        }
        let w = weight(&r.server_id);
        let up = r.upload_bytes as f64 * w;
        let dn = r.download_bytes as f64 * w;
        if row_bucket >= cur_start {
            cur_up += up;
            cur_dn += dn;
        } else if row_bucket >= prior_start {
            prior_total += up + dn;
        }
    }
    let cur_total = cur_up + cur_dn;
    // Δ% vs the prior equal window. None when the prior window had no
    // traffic (division by zero / "new baseline" — can't compute a
    // meaningful percentage from zero).
    let delta_pct: Option<i64> = if prior_total > 0.0 {
        Some((((cur_total - prior_total) / prior_total) * 100.0).round() as i64)
    } else {
        None
    };
    let window_label = match lang {
        crate::i18n::Locale::En => window.label_en,
        crate::i18n::Locale::Ru => window.label_ru,
    };

    html! {
        div style="margin-top: 12px; display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px;" {
            div title=(tr(lang, "Upload bytes (client → server) summed across the fleet over the window, weighted by each server's usage coefficient.", "Upload-байты (клиент → сервер), суммированные по флоту за окно, с учётом коэффициента трафика каждого сервера.")) {
                (status_tile(&format!("↑ {} {}", tr(lang, "upload", "отправка"), window_label), &humanize_bytes(cur_up as u64), "var(--ink)"))
            }
            div title=(tr(lang, "Download bytes (server → client) summed across the fleet over the window, weighted by each server's usage coefficient.", "Download-байты (сервер → клиент), суммированные по флоту за окно, с учётом коэффициента трафика каждого сервера.")) {
                (status_tile(&format!("↓ {} {}", tr(lang, "download", "загрузка"), window_label), &humanize_bytes(cur_dn as u64), "var(--ink)"))
            }
            div title=(tr(lang, "Total traffic this window vs the previous equal-length window.", "Суммарный трафик за это окно против предыдущего окна такой же длины.")) {
                @match delta_pct {
                    Some(p) if p > 0 => (status_tile(tr(lang, "vs prior", "против пред."), &format!("+{p}%"), "#c62828")),
                    Some(p) if p < 0 => (status_tile(tr(lang, "vs prior", "против пред."), &format!("{p}%"), "#2e7d32")),
                    Some(_) => (status_tile(tr(lang, "vs prior", "против пред."), "0%", "var(--mute)")),
                    None => (status_tile(tr(lang, "vs prior", "против пред."), "—", "var(--mute)")),
                }
            }
        }
    }
}

/// Dashboard 1b — health feed: the newest unacked alerts as a minimal
/// table (severity mark / kind / target / age), with the unacked total
/// in the eyebrow and a «full feed →» link to /admin/alerts. Replaces
/// the PR-Dash dash#4 (kind, severity)-counts card. Quiet-dashboard
/// contract kept — renders nothing when there are zero unacked alerts.
fn dashboard_health_feed(
    alerts: &[vpnctl_inventory::AdminAlert],
    unacked_total: u64,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    if alerts.is_empty() {
        // Quiet dashboard — no unacked alerts, no card.
        return html! {};
    }
    let now = chrono::Utc::now();
    html! {
        div {
            div.ed-art-eyebrow {
                (tr(lang, "Health feed", "Поток здоровья"))
                " · " (tr(lang, "open", "открыто")) " " (unacked_total)
            }
            table.ed-feed style="margin-top: 8px;" {
                tbody {
                    @for a in alerts {
                        // Kinds carry the subject after a colon
                        // (`user.traffic_limit:<uid>`); split so the kind
                        // column stays scannable and the subject joins
                        // the target cell.
                        @let (kind_base, kind_subject) = match a.kind.split_once(':') {
                            Some((k, s)) => (k, Some(s)),
                            None => (a.kind.as_str(), None),
                        };
                        tr {
                            td style="width: 20px;" {
                                @if a.severity.eq_ignore_ascii_case("critical") {
                                    span style="color: var(--red);" title=(a.severity) { "✖" }
                                } @else {
                                    span style="color: var(--warm);" title=(a.severity) { "⚠" }
                                }
                            }
                            td.ed-grid__mut.ed-grid__sm title=(a.summary) { (kind_base) }
                            td {
                                @match (&a.server_id, kind_subject) {
                                    (Some(sid), _) => {
                                        a href=(format!("/admin/servers/{}", path_segment_encode(&sid.0))) { (sid.0) }
                                    },
                                    (None, Some(subject)) => {
                                        // User-scoped kinds put the user id
                                        // after the colon — link it.
                                        a href=(format!("/admin/users/{}", path_segment_encode(subject))) { (subject) }
                                    },
                                    (None, None) => span.ed-grid__mut { "—" },
                                }
                            }
                            td.num.ed-grid__mut.ed-grid__sm { (humanize_age(now - a.created_at, lang)) }
                        }
                    }
                }
            }
            div style="margin-top: 6px;" {
                a href="/admin/alerts" style="font-family: var(--serif); font-style: italic; font-size: 11px; color: var(--acc); text-decoration: none;" {
                    (tr(lang, "full feed →", "весь поток →"))
                }
            }
        }
    }
}

/// PR-Dash dash#5 — abuse summary. Surfaces subs that look shared (one
/// Localized chip text for one sharing-risk reason (the carried value +
/// a short unit). The scorer orders reasons strongest-first, so the lead
/// chip is the smoking gun (concurrent IPs / impossible travel).
fn sharing_reason_label(
    r: crate::sharing_score::SharingReason,
    lang: crate::i18n::Locale,
) -> String {
    use crate::i18n::tr;
    use crate::sharing_score::SharingReason as R;
    let network =
        |n: u64| crate::i18n::noun_for(lang, n, "network", "networks", "сеть", "сети", "сетей");
    match r {
        R::TypicalConcurrentNets(n) => {
            format!(
                "{n} {} {}",
                network(n as u64),
                tr(lang, "at once (typical)", "обычно одновременно")
            )
        }
        R::DailyNets(n) => format!("{n} {}/{}", network(n as u64), tr(lang, "day", "день")),
        R::ImpossibleTravel(h) => {
            format!(
                "{h}× {}",
                tr(lang, "impossible travel", "невозможн. перемещ.")
            )
        }
    }
}

const SHARING_WINDOW_DAYS: u32 = 30;
const IMPOSSIBLE_TRAVEL_HOURS: f64 = 2.0;

async fn load_likely_shared(
    inv: &vpnctl_inventory::SqliteInventory,
) -> Vec<(vpnctl_core::UserId, crate::sharing_score::SharingScore)> {
    let mut rows: Vec<_> = inv
        .sharing_signals_all_users(SHARING_WINDOW_DAYS, IMPOSSIBLE_TRAVEL_HOURS)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", error = %e, "sharing_signals_all_users failed");
            Vec::new()
        })
        .into_iter()
        .filter(|s| !s.user_id.0.is_empty())
        .map(|s| {
            let sc = crate::sharing_score::score(&s);
            (s.user_id, sc)
        })
        .filter(|(_, sc)| sc.is_flagged())
        .collect();
    rows.sort_by_key(|b| std::cmp::Reverse(b.1.score));
    rows
}

fn sharing_rows(
    rows: &[&(vpnctl_core::UserId, crate::sharing_score::SharingScore)],
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::sharing_score::SharingLevel;
    html! {
        @for (uid, sc) in rows {
            @let tone = if sc.level == SharingLevel::High { "var(--red)" } else { "var(--warm)" };
            tr {
                td.num style="width: 34px;" {
                    b style=(format!("color: {tone};")) { (sc.score) }
                }
                td style="width: 96px;" {
                    div.ed-scorebar {
                        div style=(format!("width: {}%; background: {tone};", sc.score)) {}
                    }
                }
                td {
                    a href=(format!("/admin/users/{}/activity#source-ips", path_segment_encode(&uid.0))) {
                        (uid.0)
                    }
                }
                td.num.ed-grid__mut {
                    @for (i, reason) in sc.reasons.iter().take(2).enumerate() {
                        @if i > 0 { " · " }
                        (sharing_reason_label(*reason, lang))
                    }
                }
            }
        }
    }
}

/// PR-Dash dash#5 — account-sharing risk summary (redesigned 2026-06-17 to
/// a composite, explainable score; replaces the bare `distinct_asns >= 3`).
/// Each row shows the user, a 0-100 risk score (red=High, amber=Medium) and
/// the reasons that fired (strongest first: simultaneous IPs, impossible
/// travel, per-day IPs, client-app spread, …). Renders nothing when no user
/// reaches `FLAG_THRESHOLD` (quiet dashboard).
fn dashboard_abuse_summary(
    likely_shared: &[(vpnctl_core::UserId, crate::sharing_score::SharingScore)],
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    // Defensive: skip any empty id so this render can NEVER emit a nameless
    // link to `/admin/users/`.
    let rows: Vec<&(vpnctl_core::UserId, crate::sharing_score::SharingScore)> = likely_shared
        .iter()
        .filter(|(uid, _)| !uid.0.is_empty())
        .collect();
    if rows.is_empty() {
        return html! {};
    }
    let n = rows.len();
    html! {
        div {
            div.ed-art-eyebrow {
                (tr(lang, "Likely-shared subscriptions", "Похоже на расшаренные подписки"))
                " · " (n) " "
                span.ed-tip title=(tr(
                    lang,
                    "Risk score weights the TYPICAL simultaneous ISP-scale network count + impossible travel far above mere network diversity. One-off peaks and adjacent mobile-carrier subnets no longer trip it. Open a row to inspect the exact VPN source IPs.",
                    "Риск-скор сильнее всего учитывает ТИПИЧНОЕ число одновременных сетей масштаба ISP и невозможные перемещения. Разовые пики и соседние подсети мобильного оператора больше не срабатывают. Открой строку, чтобы увидеть реальные source IP VPN.",
                )) { "ⓘ" }
            }
            table.ed-feed style="margin-top: 8px;" {
                tbody {
                    (sharing_rows(&rows.iter().take(6).copied().collect::<Vec<_>>(), lang))
                }
            }
            @if n > 6 {
                div style="margin-top: 8px;" {
                    a href="/admin/sharing"
                      style="font-family: var(--mono); font-size: 10px; color: var(--acc); text-decoration: none;" {
                        "+" (n - 6) " " (tr(lang, "more flagged · open full list →", "ещё под флагом · открыть весь список →"))
                    }
                }
            }
        }
    }
}

// `clip_ts` helper removed 2026-05-23 — all UI timestamp callers
// now use `format_msk_iso` to render in operator-friendly MSK
// timezone with explicit «MSK» marker. The previous helper trimmed
// an RFC3339 UTC string without any timezone conversion, which
// surfaced as UTC times in: dashboard recent activity, idle-users
// panel, /admin/audit timeline, /admin/alerts feed, user-detail
// sub-access log. CSV export (audit.csv) keeps `to_rfc3339()`
// directly — ISO format is the correct interchange for external
// tools.

// IP classification lives in `crate::ip_kind` (single source of
// truth for both the admin render AND the access-log writer that
// fires `sub_access.suspicious_local_ip` alerts). The render-side
// chip wrappers left with the legacy Subscription-access table
// (R2 2026-07-10); the source-IPs section labels ranges itself.

// `parse_ua_short` moved to `crate::ua` (Track-1.2 / migration 0019)
// so the access-log writer can persist its result in
// `sub_access_log.device_class` from the same source of truth. Render
// sites call `crate::ua::parse_ua_short(...)` directly. The previous
// /// doc-block lived above this comment; deleted to satisfy
// `clippy::empty-line-after-doc-comments` since there's no `fn` it
// could document anymore.

// `classify_ip` unit tests moved with the implementation to
// `crate::ip_kind::tests`. The render-side chip wrappers left with the
// legacy Subscription-access table (R2 2026-07-10); the source-IPs
// section carries its own labelling.

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

fn sharing_review(
    all: &[(vpnctl_core::UserId, crate::sharing_score::SharingScore)],
    query: &DashboardQuery,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    use crate::sharing_score::SharingLevel;

    let q = query.q.as_deref().unwrap_or("").trim().to_ascii_lowercase();
    let level = match query.level.as_deref() {
        Some("high") => Some(SharingLevel::High),
        Some("medium") => Some(SharingLevel::Medium),
        _ => None,
    };
    let min_score = query
        .min_score
        .as_deref()
        .and_then(|v| v.parse::<u8>().ok())
        .map(|v| v.min(100));
    let rows: Vec<_> = all
        .iter()
        .filter(|(uid, sc)| {
            (q.is_empty() || uid.0.to_ascii_lowercase().contains(&q))
                && level.is_none_or(|wanted| sc.level == wanted)
                && min_score.is_none_or(|min| sc.score >= min)
        })
        .collect();

    let body = html! {
        div.ed-art-eyebrow {
            (tr(lang, "Sharing-risk review", "Проверка риска расшаривания"))
            " · " (rows.len()) "/" (all.len())
        }
        p.ed-deck {
            (tr(
                lang,
                "Thirty-day account-sharing signals, strongest first. The score is a heuristic, not a probability. Open a user to inspect the VPN source networks and rotate access if needed.",
                "Сигналы расшаривания за 30 дней, сначала самые сильные. Балл — эвристика, а не вероятность. Открой пользователя, чтобы проверить исходные сети VPN и при необходимости сменить доступ.",
            ))
        }
        form method="get" action="/admin/sharing" style="display: flex; flex-wrap: wrap; gap: 10px; align-items: end; margin: 16px 0;" {
            label for="sharing-q" style="display: grid; gap: 4px; font-family: var(--mono); font-size: 11px;" {
                (tr(lang, "User", "Пользователь"))
                input id="sharing-q" type="search" name="q" value=(query.q.as_deref().unwrap_or("")) placeholder="ninitux";
            }
            label for="sharing-level" style="display: grid; gap: 4px; font-family: var(--mono); font-size: 11px;" {
                (tr(lang, "Risk level", "Уровень риска"))
                select id="sharing-level" name="level" {
                    option value="" selected[level.is_none()] { (tr(lang, "any", "любой")) }
                    option value="high" selected[level == Some(SharingLevel::High)] { (tr(lang, "high", "высокий")) }
                    option value="medium" selected[level == Some(SharingLevel::Medium)] { (tr(lang, "medium", "средний")) }
                }
            }
            label for="sharing-min-score" style="display: grid; gap: 4px; font-family: var(--mono); font-size: 11px;" {
                (tr(lang, "Minimum score", "Минимальный балл"))
                input id="sharing-min-score" type="number" name="min_score" min="0" max="100"
                      value=(min_score.map(|v| v.to_string()).unwrap_or_default());
            }
            button type="submit" class="ed-abtn ed-abtn--secondary ed-abtn--sm" {
                (crate::i18n::t(lang, crate::i18n::K::BtnFilter))
            }
            a href="/admin/sharing" class="ed-abtn ed-abtn--secondary ed-abtn--sm" {
                (crate::i18n::t(lang, crate::i18n::K::BtnReset))
            }
        }
        @if rows.is_empty() {
            p.ed-empty {
                (tr(lang, "No flagged users match these filters.", "Нет отмеченных пользователей, подходящих под эти фильтры."))
            }
        } @else {
            table.ed-feed {
                tbody { (sharing_rows(&rows, lang)) }
            }
        }
    };
    body
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

/// Colour bucket for an uptime percentage. Shared by the per-server
/// `server_detail_uptime_section` chips and the dashboard-wide
/// `dashboard_fleet_uptime` chips so palette stays in one place. The
/// thresholds (≥99 green, ≥95 amber, <95 red, None grey) match Pavel's
/// confirmed SLO buckets for sing-box service uptime.
fn quality_score_color(score: Option<u8>) -> &'static str {
    match score {
        Some(80..=100) => "#2e7d32",
        Some(60..=79) => "#e6a23c",
        Some(_) => "#c62828",
        None => "var(--mute)",
    }
}

fn dashboard_quality_ranking(
    quality: &[(
        vpnctl_core::ServerId,
        vpnctl_inventory::ServiceQualityScore,
        vpnctl_inventory::ServiceQualityScore,
    )],
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    if quality.is_empty() {
        return html! {};
    }
    let mut rows: Vec<_> = quality.iter().collect();
    rows.sort_by(|a, b| b.1.score.cmp(&a.1.score).then_with(|| a.0.0.cmp(&b.0.0)));
    html! {
        section id="fleet-quality-ranking" style="margin-top:28px;" {
            div.ed-art-eyebrow { (tr(lang, "Fleet quality ranking · service path", "Рейтинг качества флота · service path")) }
            p style="font-family:var(--serif);font-style:italic;font-size:12px;color:var(--mute);margin:6px 0 12px;" {
                (tr(
                    lang,
                    "TCP connects to every declared ingress port from vpnctld. Service quality and SSH/control availability are scored separately.",
                    "TCP-подключения ко всем объявленным ingress-портам с vpnctld. Качество сервиса и доступность SSH/control оцениваются отдельно.",
                ))
            }
            table style="width:100%;border-collapse:collapse;font-family:var(--mono);font-size:11px;" {
                thead { tr style="border-bottom:1px solid var(--ink);" {
                    th style="text-align:right;padding:5px 8px;" { "#" }
                    th style="text-align:left;padding:5px 8px;" { (tr(lang, "server", "сервер")) }
                    th style="text-align:right;padding:5px 8px;" { (tr(lang, "service 24h", "сервис 24ч")) }
                    th style="text-align:right;padding:5px 8px;" { (tr(lang, "service 7d", "сервис 7д")) }
                    th style="text-align:right;padding:5px 8px;" { (tr(lang, "availability", "доступность")) }
                    th style="text-align:right;padding:5px 8px;" { (tr(lang, "loss", "потери")) }
                    th style="text-align:right;padding:5px 8px;" { "p95" }
                    th style="text-align:right;padding:5px 8px;" { (tr(lang, "control 24h", "control 24ч")) }
                } }
                tbody {
                    @for (index, (id, q24, q7)) in rows.iter().enumerate() {
                        tr data-quality-server=(id.0) style="border-bottom:1px dotted var(--rule);" {
                            td style="text-align:right;padding:5px 8px;color:var(--mute);" { (index + 1) }
                            td style="padding:5px 8px;" { a href=(format!("/admin/servers/{}", path_segment_encode(&id.0))) style="color:var(--ink);" { (id.0) } }
                            td style=(format!("text-align:right;padding:5px 8px;color:{};", quality_score_color(q24.score))) { (q24.score.map_or_else(|| "—".into(), |v| format!("{v}/100"))) }
                            td style=(format!("text-align:right;padding:5px 8px;color:{};", quality_score_color(q7.score))) { (q7.score.map_or_else(|| "—".into(), |v| format!("{v}/100"))) }
                            td style="text-align:right;padding:5px 8px;" { (q24.availability_pct.map_or_else(|| "—".into(), |v| format!("{v:.1}%"))) }
                            td style="text-align:right;padding:5px 8px;" { (q24.packet_loss_pct.map_or_else(|| "—".into(), |v| format!("{v:.1}%"))) }
                            td style="text-align:right;padding:5px 8px;" { (q24.p95_rtt_ms.map_or_else(|| "—".into(), |v| format!("{v} ms"))) }
                            td style="text-align:right;padding:5px 8px;" { (q24.control_score.map_or_else(|| "—".into(), |v| format!("{v}/100"))) }
                        }
                    }
                }
            }
        }
    }
}

pub(super) fn server_detail_quality_section(
    q24: Option<&vpnctl_inventory::ServiceQualityScore>,
    q7: Option<&vpnctl_inventory::ServiceQualityScore>,
    history: &[vpnctl_inventory::ServiceQualitySample],
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let Some(q24) = q24 else {
        return html! {};
    };
    html! {
        section id="server-quality" style="margin-top:18px;" {
            div.ed-art-eyebrow { (tr(lang, "Quality · service path", "Качество · service path")) }
            p style="font-family:var(--serif);font-style:italic;font-size:12px;color:var(--mute);margin:4px 0 12px;" {
                (tr(lang, "Small TCP probes to real declared ingress ports from ", "Небольшие TCP-пробы реальных объявленных ingress-портов из "))
                span.ed-mono { (q24.vantage.as_deref().unwrap_or("unknown")) }
                " · " (history.len()) " " (tr(lang, "samples in 24h", "замеров за 24ч"))
            }
            div style="display:flex;gap:10px;flex-wrap:wrap;font-family:var(--mono);font-size:11px;" {
                span { "24h " b style=(format!("color:{};", quality_score_color(q24.score))) { (q24.score.map_or_else(|| "—".into(), |v| format!("{v}/100"))) } }
                span { "7d " b style=(format!("color:{};", quality_score_color(q7.and_then(|q| q.score)))) { (q7.and_then(|q| q.score).map_or_else(|| "—".into(), |v| format!("{v}/100"))) } }
                span { (tr(lang, "availability ", "доступность ")) (q24.availability_pct.map_or_else(|| "—".into(), |v| format!("{v:.1}%"))) }
                span { (tr(lang, "loss ", "потери ")) (q24.packet_loss_pct.map_or_else(|| "—".into(), |v| format!("{v:.1}%"))) }
                span { "p95 " (q24.p95_rtt_ms.map_or_else(|| "—".into(), |v| format!("{v} ms"))) }
                span { "control " (q24.control_score.map_or_else(|| "—".into(), |v| format!("{v}/100"))) }
            }
        }
    }
}

pub(super) fn pct_color(pct: Option<u8>) -> &'static str {
    match pct {
        Some(p) if p >= 99 => "#2e7d32", // green
        Some(p) if p >= 95 => "#e6a23c", // amber
        Some(_) => "#c62828",            // red (incl. Some(0))
        None => "var(--mute)",           // grey
    }
}

/// Renders an uptime percent as the chip's visible text. `Some(p) →
/// "p%"` (integer; see `UptimeStat::uptime_pct` doc for why integer
/// vs decimal). `None → bilingual "— no data" / "— нет данных"` so
/// the empty branch is visually distinct from `Some(0%)` (down-the-
/// whole-window).
pub(super) fn pct_label(pct: Option<u8>, lang: crate::i18n::Locale) -> String {
    match pct {
        Some(p) => format!("{p}%"),
        None => crate::i18n::tr(lang, "— no data", "— нет данных").to_string(),
    }
}

/// Fleet-wide uptime tile — dashboard companion to the per-server
/// `server_detail_uptime_section`. Three chips (24h / 7d / 30d) each
/// carrying the **fleet-weighted average** sing-box uptime%.
///
/// **Aggregation choice (probe-weighted, not server-equal-weighted):**
/// SUM(up_rows across all servers) / SUM(decidable_rows across all servers).
/// A server polled ½ as often contributes ½ as much to the average — this
/// matches the per-server semantics (each chip already counts probe rows
/// not server-days) and means a single fresh server with 1 probe doesn't
/// drown out 3 mature servers with 600 probes each. Servers with zero
/// decidable rows are silently excluded from BOTH numerator + denominator.
///
/// Renders ONLY when at least one server has at least one decidable
/// probe in some window. Otherwise the section is omitted — the operator
/// already gets «no servers polled yet» context from the absence of any
/// per-server uptime data on /admin/servers detail pages.
///
/// Chip-click navigates to /admin/servers (list) — per-server drill-in
/// lives there. Stable `data-fleet-uptime-pct` attribute for scrape
/// targets + future SLO export.
fn dashboard_fleet_uptime(
    rows: &[(
        vpnctl_core::ServerId,
        [Option<vpnctl_inventory::UptimeStat>; 3],
    )],
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;

    // Aggregate one window across all servers into (up_rows, total_decidable, n_servers).
    // `total_decidable = total_rows - unknown_rows` — we exclude
    // probes where sing_box_active is NULL (probe failed mid-flight)
    // from BOTH halves of the ratio, matching `UptimeStat::uptime_pct`'s
    // own definition. Server-count is also tallied so the chip footer
    // can read «N/M servers polled».
    let agg = |window_idx: usize| -> (u64, u64, usize) {
        let mut up: u64 = 0;
        let mut decidable: u64 = 0;
        let mut polled_servers: usize = 0;
        for (_, windows) in rows {
            if let Some(stat) = windows[window_idx].as_ref() {
                let dec = stat.total_rows.saturating_sub(stat.unknown_rows);
                if dec > 0 {
                    up = up.saturating_add(stat.up_rows);
                    decidable = decidable.saturating_add(dec);
                    polled_servers += 1;
                }
            }
        }
        (up, decidable, polled_servers)
    };

    let totals: [(u64, u64, usize); 3] = [agg(0), agg(1), agg(2)];
    let total_servers = rows.len();

    // Empty-fleet branch: NO server has decidable data in any window.
    // Render nothing — quiet dashboard for an unpolled fleet.
    if totals.iter().all(|(_, dec, _)| *dec == 0) {
        return html! {};
    }

    let pct_for = |up: u64, dec: u64| -> Option<u8> {
        if dec == 0 {
            None
        } else {
            // u128 to be safe with very large probe counts;
            // saturating cast back to u8 (% can't exceed 100).
            let p = ((u128::from(up) * 100) / u128::from(dec)) as u64;
            Some(p.min(100) as u8)
        }
    };

    let chip = |label: &str, totals: (u64, u64, usize)| -> Markup {
        let (up, dec, polled) = totals;
        let pct = pct_for(up, dec);
        let color = pct_color(pct);
        let pct_text = pct_label(pct, lang);
        // `data-fleet-uptime-pct` mirrors the per-server chip
        // attribute — same scrape contract, different prefix.
        let pct_attr = pct.map(|p| p.to_string()).unwrap_or_else(|| "none".into());
        html! {
            div data-fleet-uptime-pct=(pct_attr)
                style="display: flex; flex-direction: column; gap: 4px; padding: 12px 16px; border: 1px solid var(--rule); background: var(--paper); min-width: 120px;" {
                div style="font-family: var(--mono); font-size: 10px; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase;" {
                    (label)
                }
                div style=(format!("font-family: var(--serif); font-weight: 500; color: {color}; font-size: 22px; line-height: 1;")) {
                    (pct_text)
                }
                div style="font-family: var(--mono); font-size: 10px; color: var(--mute);" {
                    (dec) " " (crate::i18n::noun_for(lang, dec, "probe", "probes", "проба", "пробы", "проб"))
                    " · " (polled) "/" (total_servers) " " (tr(lang, "polled", "опрош."))
                }
            }
        }
    };

    html! {
        section id="fleet-uptime" style="margin-top: 28px;" {
            div.ed-art-eyebrow {
                (tr(lang, "Fleet uptime · sing-box services", "Аптайм флота · сервисы sing-box"))
            }
            p style="font-family: var(--serif); font-style: italic; color: var(--mute); margin: 4px 0 12px 0;" {
                (tr(
                    lang,
                    "Probe-weighted average across all polled servers. Drill into a server detail page for per-window breakdown + last outage.",
                    "Среднее взвешенное по пробам со всех опрошенных серверов. На странице сервера — детальный разбор по окнам и время последнего инцидента.",
                ))
            }
            div style="display: flex; gap: 12px; flex-wrap: wrap;" {
                (chip(tr(lang, "last 24h", "24 часа"), totals[0]))
                (chip(tr(lang, "last 7d",  "7 дней"),  totals[1]))
                (chip(tr(lang, "last 30d", "30 дней"), totals[2]))
            }
        }
    }
}

fn dashboard_live_activity_from_rows(
    servers: &[vpnctl_core::Server],
    active_conns: &[(vpnctl_core::ServerId, Option<usize>)],
    rows: &[vpnctl_inventory::VpnStatsRow],
    window: VpnSparklineWindow,
) -> Vec<(vpnctl_core::ServerId, vpnctl_inventory::ServerLiveActivity)> {
    use chrono::{DurationRound, TimeDelta, Utc};

    let bucket_seconds = i64::from(window.bucket_hours) * 3600;
    let now = Utc::now()
        .duration_trunc(TimeDelta::seconds(bucket_seconds))
        .ok();
    let oldest = now.map(|end| {
        end - TimeDelta::seconds(i64::from(window.cells.saturating_sub(1)) * bucket_seconds)
    });

    let mut by_server: std::collections::HashMap<
        vpnctl_core::ServerId,
        vpnctl_inventory::ServerLiveActivity,
    > = servers
        .iter()
        .map(|server| {
            (
                server.id.clone(),
                vpnctl_inventory::ServerLiveActivity::default(),
            )
        })
        .collect();

    if let (Some(oldest), Some(now)) = (oldest, now) {
        for row in rows {
            let Ok(row_bucket) = row.ts.duration_trunc(TimeDelta::seconds(bucket_seconds)) else {
                continue;
            };
            if row_bucket < oldest || row_bucket > now {
                continue;
            }
            let Some(activity) = by_server.get_mut(&row.server_id) else {
                continue;
            };
            let is_latest = activity.last_sample_ts.is_none_or(|last| row.ts > last);
            activity.bytes_up_window = activity.bytes_up_window.saturating_add(row.upload_bytes);
            activity.bytes_dn_window = activity.bytes_dn_window.saturating_add(row.download_bytes);
            if is_latest {
                activity.last_sample_ts = Some(row.ts);
                activity.active_now = row.active_connections;
            }
        }
    }

    // A fresh in-memory snapshot is more authoritative than the persisted
    // aggregate. Missing/stale cache entries fall back to the latest row.
    for (server_id, count) in active_conns {
        if let (Some(activity), Some(count)) = (by_server.get_mut(server_id), count) {
            activity.active_now = u32::try_from(*count).unwrap_or(u32::MAX);
        }
    }

    servers
        .iter()
        .map(|server| {
            (
                server.id.clone(),
                by_server.remove(&server.id).unwrap_or_default(),
            )
        })
        .collect()
}

/// Phase 4b — dashboard «VPN activity» tile. Sums the already-loaded
/// chart buckets per server and shows total bytes, active conns now,
/// and the per-server breakdown.
/// Renders even when the poller has zero data so the operator
/// sees the structure (instead of guessing whether the section
/// would EVER appear). Empty-state copy points at the NM-11
/// upstream limit so the operator knows why per-user attribution
/// is zero today.
fn dashboard_vpn_activity(
    rows: &[(vpnctl_core::ServerId, vpnctl_inventory::ServerLiveActivity)],
    window: VpnSparklineWindow,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let total_up: u64 = rows
        .iter()
        .map(|(_, a)| a.bytes_up_window)
        .fold(0u64, u64::saturating_add);
    let total_dn: u64 = rows
        .iter()
        .map(|(_, a)| a.bytes_dn_window)
        .fold(0u64, u64::saturating_add);
    let total_active: u32 = rows
        .iter()
        .map(|(_, a)| a.active_now)
        .fold(0u32, u32::saturating_add);
    let any_polled = rows.iter().any(|(_, a)| a.last_sample_ts.is_some());
    let window_label = match lang {
        crate::i18n::Locale::En => window.label_en,
        crate::i18n::Locale::Ru => window.label_ru,
    };

    html! {
        div style="margin: 18px 0 0; padding: 14px 16px; border: 1px solid var(--rule); background: var(--paper);" {
            div.ed-art-eyebrow {
                (tr(lang, "VPN activity · ", "VPN-активность · "))
                (window_label)
            }
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 12px;" {
                (tr(
                    lang,
                    // Refreshed (audit 2026-06-10): per-user numbers DO
                    // exist now — the sing-box access-log scraper
                    // attributes traffic per user; only the clash-api
                    // path stays blocked upstream (NM-11).
                    "Server-wide totals from each node's clash-api (sing-box 5-minute tick). Per-user numbers come from the access-log scraper on each user's page (clash-api itself omits the User field upstream — NM-11).",
                    "Сервер-агрегатные показатели из clash-api каждой ноды (тик sing-box 5 минут). Per-user цифры считает скрейпер access-логов — смотри страницу юзера (сам clash-api не передаёт поле User — NM-11).",
                ))
            }
            @if !any_polled {
                p style="font-family: var(--serif); font-style: italic; color: var(--mute); margin: 4px 0 0;" {
                    (tr(
                        lang,
                        "No clash-api samples yet — the poller hasn't reached any node. Check ",
                        "Снимков clash-api ещё нет — поллер не дошёл ни до одной ноды. Проверить ",
                    ))
                    a href="/admin/servers" style="color: var(--ink);" { (tr(lang, "Servers", "Серверы")) }
                    (tr(
                        lang,
                        " for deploy state.",
                        " на статус деплоя.",
                    ))
                }
            } @else {
                div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin: 8px 0 12px;" {
                    div title=(tr(lang, "Sum of active_connections across all servers' freshest server-wide tick.", "Сумма active_connections по всем серверам (свежий сервер-агрегатный тик).")) {
                        (status_tile(tr(lang, "active now", "активных сейчас"), &total_active.to_string(), "var(--ink)"))
                    }
                    @let up_title = format!("{}{}", tr(lang, "Total upload bytes (client → server) across every node in window: ", "Total upload-байт (клиент → сервер) по всем нодам за окно: "), window_label);
                    @let dn_title = format!("{}{}", tr(lang, "Total download bytes (server → client) across every node in window: ", "Total download-байт (сервер → клиент) по всем нодам за окно: "), window_label);
                    @let up_label = format!("{} {}", tr(lang, "upload", "upload"), window_label);
                    @let dn_label = format!("{} {}", tr(lang, "download", "download"), window_label);
                    div title=(up_title) {
                        (status_tile(&up_label, &humanize_bytes(total_up), "var(--ink)"))
                    }
                    div title=(dn_title) {
                        (status_tile(&dn_label, &humanize_bytes(total_dn), "var(--ink)"))
                    }
                }
                // Per-server breakdown — compact mono table.
                table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11px;" {
                    thead {
                        tr style="border-bottom: 1px solid var(--ink);" {
                            th style="text-align: left; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { (tr(lang, "server", "сервер")) }
                            th style="text-align: right; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { (tr(lang, "active", "активных")) }
                            th style="text-align: right; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { (tr(lang, "upload", "upload")) }
                            th style="text-align: right; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { (tr(lang, "download", "download")) }
                            th style="text-align: right; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { (tr(lang, "last poll", "последний")) }
                        }
                    }
                    tbody {
                        @for (sid, act) in rows {
                            tr style="border-bottom: 1px dotted var(--rule);" {
                                td style="padding: 4px 8px;" {
                                    a href=(format!("/admin/servers/{}", crate::http_util::path_segment_encode(&sid.0))) style="color: var(--ink); text-decoration: none;" { (sid.0) }
                                }
                                td style="padding: 4px 8px; text-align: right;" { (act.active_now) }
                                td style="padding: 4px 8px; text-align: right;" { (humanize_bytes(act.bytes_up_window)) }
                                td style="padding: 4px 8px; text-align: right;" { (humanize_bytes(act.bytes_dn_window)) }
                                td style="padding: 4px 8px; text-align: right; color: var(--mute);" {
                                    @match act.last_sample_ts {
                                        Some(ts) => (format_msk(ts)),
                                        None => (tr(lang, "—", "—")),
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

// PR-Dash dash#4 — the count-only `dashboard_alerts_tile` was replaced
// by `dashboard_alerts_breakdown` (defined above, near the other PR-Dash
// cards), which renders the (kind, severity) breakdown from
// `alerts_by_kind_severity` instead of a bare count.

/// Render the "heavy users · <window>" section on the dashboard.
/// Sorted DESC by total bytes (upload + download). Empty list →
/// explanatory empty-state explaining the polling prerequisite.
pub(super) fn dashboard_heavy_users(
    rows: &[vpnctl_inventory::HeavyUser],
    window: VpnSparklineWindow,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::{K, t, tr};
    let window_label = match lang {
        crate::i18n::Locale::En => window.label_en,
        crate::i18n::Locale::Ru => window.label_ru,
    };
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow
            title=(tr(
                lang,
                "Top-N by sum of (upload+download bytes) across all servers in the selected window. Data source: clash-api 5-minute polls. wgturn / WireGuard traffic NOT included (kernel-level, no clash-api visibility); only sing-box-mediated protocols (VLESS, TUIC, Trojan, Hysteria2, AnyTLS, Shadowsocks-2022) appear here.",
                "Топ-N по сумме (upload+download байт) на всех серверах за выбранное окно. Источник: 5-минутные опросы clash-api. Трафик wgturn / WireGuard НЕ учитывается (kernel-уровень, clash-api их не видит); только протоколы которые видит sing-box (VLESS, TUIC, Trojan, Hysteria2, AnyTLS, Shadowsocks-2022).",
            )) {
            (tr(lang, "Heavy users · ", "Тяжёлые пользователи · "))
            (window_label)
        }
        @if rows.is_empty() {
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
                (tr(
                    lang,
                    "No per-user traffic recorded yet. The clash-api poller ticks every 5 minutes — once the daemon's SSH deploy key is in each node's ",
                    "Трафик по пользователям ещё не записан. Опрос clash-api идёт раз в 5 минут — как только SSH deploy-ключ демона окажется в ",
                ))
                span.ed-mono { "~/.ssh/authorized_keys" }
                (tr(lang, " (see ", " каждой ноды (см. "))
                a href="/admin/settings/system#deploy-ssh-key" style="color: var(--ink);" {
                    (t(lang, K::NavSettings))
                }
                (tr(
                    lang,
                    ") the section populates on the next tick.",
                    ") — секция наполнится на следующем тике.",
                ))
            }
        } @else {
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
                (tr(lang, "Top ", "Топ ")) (rows.len())
                (tr(lang, " accounts by total (upload + download) over ", " аккаунтов по суммарному (upload + download) за "))
                (window_label)
                (tr(
                    lang,
                    ". Click through to investigate; the user page has the full breakdown + sparkline.",
                    ". Кликни чтобы разобраться — страница пользователя содержит полную разбивку + sparkline.",
                ))
            }
            table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 12px;" {
                thead {
                    tr style="color: var(--mute); border-bottom: 1px solid var(--rule);" {
                        th style="text-align: left; padding: 4px 0; font-weight: 600;" {
                            (tr(lang, "User", "Пользователь"))
                        }
                        th style="text-align: right; padding: 4px 10px; font-weight: 600;" {
                            "↑ " (tr(lang, "Upload", "Отдача"))
                        }
                        th style="text-align: right; padding: 4px 10px; font-weight: 600;" {
                            "↓ " (tr(lang, "Download", "Приём"))
                        }
                        th style="text-align: right; padding: 4px 0; font-weight: 600;" {
                            "Σ " (tr(lang, "Total", "Всего"))
                        }
                    }
                }
                tbody {
                    @for hu in rows {
                        tr style="border-bottom: 1px dotted var(--rule);" {
                            td style="text-align: left; padding: 4px 0;" {
                                a href=(format!("/admin/users/{}", path_segment_encode(&hu.user_id.0)))
                                  style="color: var(--ink); text-decoration: none; font-weight: 600;" {
                                    (hu.user_id.0)
                                }
                            }
                            td style="text-align: right; padding: 4px 10px; color: var(--mute);" {
                                (humanize_bytes(hu.upload_bytes))
                            }
                            td style="text-align: right; padding: 4px 10px; color: var(--mute);" {
                                (humanize_bytes(hu.download_bytes))
                            }
                            td style="text-align: right; padding: 4px 0; font-weight: 600;" {
                                (humanize_bytes(hu.total_bytes))
                            }
                        }
                    }
                }
            }
        }
    }
}

// Error response helpers moved to helpers.rs. Their response body remains
// intentionally opaque; full error chains stay in the service log.
// `internal_error` and `error_text` moved to helpers.rs

/// Inline-SVG sparkline. Pure SSR — width/height pinned, no JS,
/// stroke uses `var(--acc)` so the accent toggle in the Tweaks panel
/// recolours every chart on the page consistently.
/// The sparkline renderer. (The unlabelled legacy wrapper
/// `sparkline_svg` was deleted in R2 once its last caller learned to
/// pass an explicit axis + caption.)
///
/// * `y_max = Some(cap)` pins the y-axis — **percent series pass 100**
///   so a flat 28 % disk line sits at 28 % of the box height instead of
///   gluing to the top edge and reading as "maxed out" (design review
///   2026-07-10). `None` auto-scales to the window max (byte/MiB
///   series, where only the shape matters).
/// * `label_max = false` drops the in-SVG "max N" corner text for
///   callers that render their own max caption under the chart —
///   previously both rendered and disagreed by one (SVG truncated,
///   caption rounded: «max 51» inside, «max 52%» below).
pub(super) fn sparkline_svg_scaled(
    values: &[f64],
    width: u32,
    height: u32,
    y_max: Option<f64>,
    label_max: bool,
) -> Markup {
    if values.is_empty() {
        return html! {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute); padding: 6px 0;" {
                "(no data in window)"
            }
        };
    }
    let data_max = values.iter().cloned().fold(0.0_f64, f64::max);
    let scale = y_max.unwrap_or(data_max).max(1.0);
    let n = values.len();
    let stride = if n > 1 {
        (width as f64 - 4.0) / (n - 1) as f64
    } else {
        0.0
    };
    let h = height as f64 - 4.0;
    let points: String = values
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let x = 2.0 + (i as f64) * stride;
            // min(1.0) guards a >cap outlier (e.g. % rounding artifacts)
            // from drawing outside the box.
            let y = 2.0 + h - (v / scale).min(1.0) * h;
            format!("{x:.1},{y:.1}")
        })
        .collect::<Vec<_>>()
        .join(" ");
    // Filled area under the curve — same points + close-down to baseline.
    let area_points = format!(
        "2,{baseline} {points} {last_x:.1},{baseline}",
        baseline = height as f64 - 2.0,
        last_x = 2.0 + (n - 1) as f64 * stride
    );
    html! {
        svg width=(width) height=(height) viewBox=(format!("0 0 {width} {height}"))
            xmlns="http://www.w3.org/2000/svg"
            style="display: block; margin: 8px 0;" {
            polygon points=(area_points) fill="var(--acc)" opacity="0.10" {}
            polyline points=(points) fill="none" stroke="var(--acc)" stroke-width="1.5" {}
            @if label_max {
                // Right-side max-value label so operator can read the
                // peak. Rounded (not truncated) so it always agrees
                // with any {:.0}-formatted caption of the same series.
                text x=(width - 4) y="14"
                     text-anchor="end"
                     style="font-family: var(--mono); font-size: 10px; fill: var(--mute);" {
                    "max " (data_max.round() as u64)
                }
            }
        }
    }
}

// Editorial server card moved to servers.rs.
// `fp_short`, `server_row`, and `servers` moved to servers.rs
