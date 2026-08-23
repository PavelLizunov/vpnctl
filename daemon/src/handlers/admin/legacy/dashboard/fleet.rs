use maud::{Markup, html};

use super::telemetry::humanize_age;
use crate::handlers::admin::helpers::{
    fleet_majority_version, humanize_bytes, kernel_observations_of, kernel_versions_inline,
    ordered_kernel_ids, sing_box_version_of,
};
use crate::handlers::admin::legacy::server_detail::status_tile;
use crate::handlers::admin::legacy::user_sections::VpnSparklineWindow;
use crate::http_util::path_segment_encode;

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

pub(in crate::handlers::admin::legacy) fn server_detail_kernel_inventory_section(
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
pub(in crate::handlers::admin::legacy) fn kernel_floor_rollup(
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
pub(in crate::handlers::admin::legacy) fn dashboard_fleet_table(
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
                                    div.ed-hist__bar title=(format!("{share}%")) { div style=(format!("width: {share}%;")) {} };
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

/// PR-Dash dash#2 — real fleet traffic totals beside the activity
/// chart. Uses the same aligned buckets as the chart so the bars and
/// totals cannot disagree at a day boundary.
///
/// `coeffs` maps each server to its `usage_coefficient`; unknown
/// servers default to 1.0.
pub(in crate::handlers::admin::legacy) fn dashboard_fleet_traffic_totals(
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
pub(in crate::handlers::admin::legacy) fn dashboard_health_feed(
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

pub(in crate::handlers::admin::legacy) fn dashboard_quality_ranking(
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

pub(in crate::handlers::admin::legacy) fn server_detail_quality_section(
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

pub(in crate::handlers::admin::legacy) fn pct_color(pct: Option<u8>) -> &'static str {
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
pub(in crate::handlers::admin::legacy) fn pct_label(pct: Option<u8>, lang: crate::i18n::Locale) -> String {
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
pub(in crate::handlers::admin::legacy) fn dashboard_fleet_uptime(
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
