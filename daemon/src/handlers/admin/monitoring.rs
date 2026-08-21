//! Admin monitoring page handlers (fleet health surface, v2 3a).

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use maud::{Markup, html};

use super::helpers::*;
use super::ui::*;
use crate::AppState;
use crate::http_util::path_segment_encode;

/// Phase F monitoring page. Pulls hourly + daily access buckets from
/// `sub_access_log`, gap-fills, renders two inline-SVG sparklines
/// (hits + distinct IPs) plus headline KPIs. No JS — pure SSR.
pub(crate) async fn monitoring(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Markup, Response> {
    use crate::i18n::tr;
    let (theme, accent, lang) = theme_accent_lang(&headers);

    // Design v2 3a — the monitoring page IS the fleet-health surface:
    // six status tiles, per-node uptime, 24h resource trends, the
    // monitor's real thresholds, probe failures and the GeoIP DB age.
    // The former sub-access analytics moved out (the aggregate JSON
    // stays at /api/v1/stats/sub-access; heavy-users live on the
    // dashboard's Activity tab).
    let servers = state
        .inv
        .list_servers()
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;

    let mut latest: Vec<(vpnctl_core::Server, Option<vpnctl_inventory::NodeHealthRow>)> =
        Vec::with_capacity(servers.len());
    let mut uptimes: Vec<[Option<vpnctl_inventory::UptimeStat>; 3]> =
        Vec::with_capacity(servers.len());
    let mut trends: Vec<Vec<vpnctl_inventory::NodeHealthRow>> = Vec::with_capacity(servers.len());
    for s in &servers {
        let h = state.inv.latest_node_health(&s.id).await.unwrap_or(None);
        let u24 = state.inv.uptime_for_server(&s.id, 24).await.ok();
        let u7 = state.inv.uptime_for_server(&s.id, 24 * 7).await.ok();
        let u30 = state.inv.uptime_for_server(&s.id, 24 * 30).await.ok();
        let t = state
            .inv
            .recent_node_health_for_server(&s.id, 24)
            .await
            .unwrap_or_default();
        latest.push((s.clone(), h));
        uptimes.push([u24, u7, u30]);
        trends.push(t);
    }
    let kernel_versions = state.inv.kernel_versions_fleet().await.unwrap_or_default();
    let alerts_by_kind = state
        .inv
        .alerts_by_kind_severity()
        .await
        .unwrap_or_default();
    let recent_all_alerts = state.inv.recent_alerts(50, true).await.unwrap_or_default();

    // ── tile aggregates ──────────────────────────────────────────────
    let probeable_total = latest.len();
    let up_count = latest
        .iter()
        .filter(|(_, h)| h.as_ref().and_then(|h| h.sing_box_active) == Some(true))
        .count();
    let open_total: u64 = alerts_by_kind.iter().map(|(_, _, n)| *n).sum();
    let open_sub_access: u64 = alerts_by_kind
        .iter()
        .filter(|(k, _, _)| k.starts_with("sub_access."))
        .map(|(_, _, n)| *n)
        .sum();
    let open_node = open_total.saturating_sub(open_sub_access);
    let worst_mem: Option<(u8, &str)> = latest
        .iter()
        .filter_map(|(s, h)| h.as_ref().and_then(pct_mem).map(|p| (p, s.id.0.as_str())))
        .max_by_key(|(p, _)| *p);
    let worst_disk: Option<(u8, &str)> = latest
        .iter()
        .filter_map(|(s, h)| h.as_ref().and_then(pct_disk).map(|p| (p, s.id.0.as_str())))
        .max_by_key(|(p, _)| *p);
    let worst_log_mib: Option<(u64, &str)> = latest
        .iter()
        .filter_map(|(s, h)| {
            h.as_ref()
                .and_then(|h| h.sing_box_log_bytes)
                .map(|b| (b / (1024 * 1024), s.id.0.as_str()))
        })
        .max_by_key(|(m, _)| *m);
    let majority_version = fleet_majority_version(&kernel_versions);
    let drifted: Vec<(&str, String)> = kernel_versions
        .iter()
        .filter_map(|(id, j)| {
            let v = sing_box_version_of(j.as_deref())?;
            if majority_version.as_ref() != Some(&v) {
                let (sid, _) = latest
                    .iter()
                    .find(|(s, _)| s.id == *id)
                    .map(|(s, h)| (s.id.0.as_str(), h))?;
                Some((sid, v))
            } else {
                None
            }
        })
        .collect();
    let probes_24h: u64 = uptimes
        .iter()
        .filter_map(|u| u[0].as_ref())
        .map(|s| s.total_rows)
        .sum();
    let last_sweep = latest
        .iter()
        .filter_map(|(_, h)| h.as_ref().map(|h| h.ts))
        .max();
    let probe_tick_min = std::env::var("VPNCTLD_NODE_PROBE_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(600)
        / 60;
    let now = chrono::Utc::now();
    let has_open = |kind: &str| -> bool { alerts_by_kind.iter().any(|(k, _, _)| k == kind) };
    // Probe failures — the unreachable alerts (open OR acked) from the
    // last 7 days; recovery events show as the acked state.
    let probe_failures: Vec<&vpnctl_inventory::AdminAlert> = recent_all_alerts
        .iter()
        .filter(|a| {
            a.kind.starts_with("server.unreachable")
                && (now - a.created_at) < chrono::Duration::days(7)
        })
        .collect();
    let geoip = geoip_db_stat();

    let mem_watermark_note = format!(
        "{} · {} {}%",
        worst_mem.map(|(_, sid)| sid).unwrap_or("—"),
        tr(lang, "alert at", "алерт от"),
        crate::health_monitor::MEM_PRESSURE_TRIGGER_PCT,
    );
    let disk_watermark_note = format!(
        "{} · {} {}%",
        worst_disk.map(|(_, sid)| sid).unwrap_or("—"),
        tr(lang, "alert at", "алерт от"),
        crate::health_monitor::DISK_PRESSURE_TRIGGER_PCT,
    );

    let body = html! {
        div.ed-art-eyebrow { (crate::i18n::t(lang, crate::i18n::K::PageMonitoring)) }
        div.ed-headrow {
            h1.ed-sumbar__h { (tr(lang, "Fleet ", "Здоровье ")) em { (tr(lang, "health", "флота")) } }
            span.ed-tip title=(tr(
                lang,
                "node_probe runs on a fixed tick over SSH: service state per kernel, disk/mem/load, log sizes, listening ports. Unknown probes are excluded from uptime denominators.",
                "node_probe ходит по SSH с фиксированным тиком: состояние сервисов по каждому ядру, диск/память/load, размеры логов, слушающие порты. Неопределённые пробы не входят в знаменатель uptime.",
            )) { "ⓘ" }
            span style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                (probeable_total) " " (tr(lang, "nodes", "нод"))
                " · " (tr(lang, "probe tick ", "тик проб ")) (probe_tick_min) " " (tr(lang, "min", "мин"))
                @if let Some(ts) = last_sweep {
                    " · " (tr(lang, "last sweep ", "последний обход "))
                    (humanize_age(now - ts, lang))
                }
            }
            div.ed-headrow__actions {
                form method="post" action="/admin/monitoring/probe-all" {
                    button type="submit"
                           class="ed-abtn ed-abtn--secondary ed-abtn--sm"
                           title=(tr(
                               lang,
                               "Runs the full probe sweep immediately instead of waiting for the next tick. SSH into every node — takes a few seconds per node; a down node adds its connect timeout.",
                               "Запускает полный обход проб немедленно, не дожидаясь следующего тика. SSH на каждую ноду — несколько секунд на ноду; упавшая нода добавляет свой connect-timeout.",
                           )) {
                        (tr(lang, "probe all now", "опросить все сейчас"))
                    }
                }
            }
        }

        div.ed-status-strip style="margin-top: 12px;" {
            (status_tile_with_warn(
                tr(lang, "fleet", "флот"),
                &format!("{up_count} / {probeable_total} up"),
                if up_count == probeable_total { "var(--green)" } else { "var(--red)" },
                up_count != probeable_total,
            ))
            (status_tile_with_warn(
                tr(lang, "open alerts", "открытых алертов"),
                &open_total.to_string(),
                "var(--ink)",
                open_total > 0,
            ))
            (status_tile_with_warn(
                tr(lang, "mem peak", "пик памяти"),
                &worst_mem.map(|(p, _)| format!("{p}%")).unwrap_or("—".into()),
                "var(--ink)",
                worst_mem.is_some_and(|(p, _)| p > 70),
            ))
            (status_tile_with_warn(
                tr(lang, "disk peak", "пик диска"),
                &worst_disk.map(|(p, _)| format!("{p}%")).unwrap_or("—".into()),
                "var(--ink)",
                worst_disk.is_some_and(|(p, _)| p > 70),
            ))
            (status_tile_with_warn(
                tr(lang, "version drift", "дрейф версий"),
                &match drifted.len() {
                    0 => tr(lang, "in sync", "синхронно").to_string(),
                    n => format!("{n} {}", tr(lang, "node(s)", "нод")),
                },
                "var(--ink)",
                !drifted.is_empty(),
            ))
            (status_tile_with_warn(
                tr(lang, "probes 24h", "проб за 24ч"),
                &probes_24h.to_string(),
                "var(--ink)",
                false,
            ))
        }
        div style="font-family: var(--mono); font-size: 10px; color: var(--mute); margin: -12px 0 4px;" {
            (tr(lang, "open: ", "открыто: ")) (open_sub_access) " sub-access · " (open_node) " node"
            " — " (tr(lang, "mem: ", "память: ")) (mem_watermark_note)
            " — " (tr(lang, "disk: ", "диск: ")) (disk_watermark_note)
            @if let Some((sid, v)) = drifted.first() {
                " — " (tr(lang, "drift: ", "дрейф: ")) (sid) " · " (v) " ≠"
            }
        }

        section style="margin-top: 14px;" {
            div.ed-art-eyebrow {
                (tr(lang, "Uptime · sing-box service", "Uptime · сервис sing-box")) " "
                span.ed-tip title=(tr(
                    lang,
                    "Rolling-window aggregate over sing_box_active from the node_probe poller. «up» = the service reports active at probe time; unknown probes are excluded from the denominator.",
                    "Скользящие окна sing_box_active от node_probe-поллера. «up» = сервис показал active в момент пробы; неопределённые пробы не входят в знаменатель.",
                )) { "ⓘ" }
            }
            table.ed-grid style="margin-top: 8px;" {
                thead {
                    tr {
                        th { (tr(lang, "server", "сервер")) }
                        th.num { "24h" }
                        th.num { "7d" }
                        th.num { "30d" }
                        th.num { (tr(lang, "probes 30d", "проб за 30д")) }
                        th { (tr(lang, "last incident", "последний инцидент")) }
                        th {}
                    }
                }
                tbody {
                    @for (i, (s, h)) in latest.iter().enumerate() {
                        @let [u24, u7, u30] = &uptimes[i];
                        @let mem_hot = h.as_ref().and_then(pct_mem).is_some_and(|p| p > 70);
                        @let detail_href = format!("/admin/servers/{}", path_segment_encode(&s.id.0));
                        @let pct_cell = |u: &Option<vpnctl_inventory::UptimeStat>| -> Markup {
                            match u.as_ref().and_then(|u| u.uptime_pct) {
                                Some(p) => html! {
                                    span style=(format!("color: {};", pct_color(Some(p)))) { (p) "%" }
                                },
                                None => html! { span.ed-grid__mut { "—" } },
                            }
                        };
                        tr class=(if mem_hot { "on-warn" } else { "" }) {
                            td {
                                a.ed-grid__id href=(detail_href) { (s.id.0) }
                                @if mem_hot {
                                    " " span.ed-grid__flag title=(tr(lang, "Memory above the 70% heat watermark", "Память выше тепловой отметки 70%")) { "⚠" }
                                }
                            }
                            td.num { b { (pct_cell(u24)) } }
                            td.num { (pct_cell(u7)) }
                            td.num { (pct_cell(u30)) }
                            td.num.ed-grid__mut {
                                (u30.as_ref().map(|u| u.total_rows).unwrap_or(0))
                            }
                            td.ed-grid__mut.ed-grid__sm {
                                @match u30.as_ref().and_then(|u| u.last_outage_at) {
                                    Some(ts) => (format_msk_iso(ts)),
                                    None => "—",
                                }
                            }
                            td.num { a.ed-grid__open href=(detail_href) { (tr(lang, "open →", "открыть →")) } }
                        }
                    }
                }
            }
        }

        section style="margin-top: 18px;" {
            div.ed-art-eyebrow {
                (tr(lang, "Resource trend · last 24h", "Тренд ресурсов · последние 24ч")) " "
                span.ed-tip title=(tr(
                    lang,
                    "10-min probe snapshots, oldest → newest. A climbing line = slow leak; flat with one spike = transient burst. A warm max = the metric crossed its watermark inside the window.",
                    "10-минутные снимки проб, старое → новое. Растущая линия = медленная утечка; плоская с одним пиком = кратковременный всплеск. Тёплый max = метрика пересекла отметку внутри окна.",
                )) { "ⓘ" }
            }
            table.ed-grid style="margin-top: 8px;" {
                thead {
                    tr {
                        th style="width: 70px;" { (tr(lang, "server", "сервер")) }
                        th { (tr(lang, "disk %", "диск %")) }
                        th { (tr(lang, "mem %", "память %")) }
                        th { "sing-box log MiB" }
                        th.num style="width: 90px;" { (tr(lang, "1-min load", "load 1мин")) }
                    }
                }
                tbody {
                    @for (i, (s, h)) in latest.iter().enumerate() {
                        @let rows = &trends[i];
                        @let chron: Vec<&vpnctl_inventory::NodeHealthRow> = rows.iter().rev().collect();
                        @let disk_series: Vec<f64> = chron.iter().filter_map(|r| {
                            let (u, t) = (r.disk_used_mib?, r.disk_total_mib?);
                            if t == 0 { None } else { Some(u as f64 * 100.0 / t as f64) }
                        }).collect();
                        @let mem_series: Vec<f64> = chron.iter().filter_map(|r| {
                            let (a, t) = (r.mem_available_mib?, r.mem_total_mib?);
                            if t == 0 { None } else { Some(100.0 - a as f64 * 100.0 / t as f64) }
                        }).collect();
                        @let log_series: Vec<f64> = chron.iter().filter_map(|r| {
                            r.sing_box_log_bytes.map(|b| b as f64 / (1024.0 * 1024.0))
                        }).collect();
                        @let fmax = |v: &[f64]| v.iter().copied().reduce(f64::max).unwrap_or(0.0);
                        @let (dmax, mmax, lmax) = (fmax(&disk_series), fmax(&mem_series), fmax(&log_series));
                        @let load = h.as_ref().and_then(|h| h.load_1min_x100).map(|l| format!("{:.2}", l as f64 / 100.0));
                        @let cell = |series: &[f64], max: f64, warm: bool, unit: &str| -> Markup {
                            // % series get the fixed 0–100 axis; the
                            // MiB series auto-scales (shape only). The
                            // caption below is the max label, so the
                            // in-SVG one is off.
                            let y_max = if unit == "%" { Some(100.0) } else { None };
                            html! {
                                @if series.is_empty() {
                                    span.ed-grid__mut { "—" }
                                } @else {
                                    (sparkline_svg_scaled(series, 200, 30, y_max, false))
                                    div style=(if warm { "font-family: var(--mono); font-size: 10px; color: var(--warm); font-weight: 600;" } else { "font-family: var(--mono); font-size: 10px; color: var(--mute);" }) {
                                        "max " b { (format!("{max:.0}")) } (unit)
                                        @if warm { " ⚠" }
                                    }
                                }
                            }
                        };
                        tr {
                            td { a.ed-grid__id href=(format!("/admin/servers/{}", path_segment_encode(&s.id.0))) { (s.id.0) } }
                            td { (cell(&disk_series, dmax, dmax > 70.0, "%")) }
                            td { (cell(&mem_series, mmax, mmax > 70.0, "%")) }
                            td { (cell(&log_series, lmax, lmax > 500.0, " MiB")) }
                            td.num {
                                @match load {
                                    Some(l) => (l),
                                    None => span.ed-grid__mut { "—" },
                                }
                            }
                        }
                    }
                }
            }
        }

        div.ed-dash-cols {
            div {
                div.ed-art-eyebrow {
                    (tr(lang, "Alert thresholds", "Пороги алертов")) " "
                    span.ed-tip title=(tr(
                        lang,
                        "Watermarks the health monitor evaluates on every probe. Crossing one opens an alert; recovery auto-resolves it (with hysteresis on disk/mem). The 70% warm tint in tables is a visual watermark only — alerts fire at the values below.",
                        "Отметки, которые монитор здоровья проверяет на каждой пробе. Пересечение открывает алерт; восстановление закрывает его само (с гистерезисом на диске/памяти). Тёплые ячейки от 70% в таблицах — только визуальная отметка; алерты срабатывают на значениях ниже.",
                    )) { "ⓘ" }
                }
                table.ed-grid style="margin-top: 8px;" {
                    thead {
                        tr {
                            th { (tr(lang, "metric", "метрика")) }
                            th.num { (tr(lang, "warn at", "порог")) }
                            th.num { (tr(lang, "worst now", "худшее сейчас")) }
                            th { (tr(lang, "where", "где")) }
                            th { (tr(lang, "state", "состояние")) }
                        }
                    }
                    tbody {
                        @let state_cell = |open: bool| -> Markup {
                            if open {
                                html! { span style="color: var(--warm);" { "⚠ " (tr(lang, "open", "открыт")) } }
                            } else {
                                html! { span style="color: var(--green);" { "ok" } }
                            }
                        };
                        tr {
                            td { "mem_used_pct" }
                            td.num { (crate::health_monitor::MEM_PRESSURE_TRIGGER_PCT) "%" }
                            td class=(if worst_mem.is_some_and(|(p, _)| p > 70) { "num warn" } else { "num" }) {
                                (worst_mem.map(|(p, _)| format!("{p}%")).unwrap_or("—".into()))
                            }
                            td.ed-grid__mut { (worst_mem.map(|(_, s)| s).unwrap_or("—")) }
                            td { (state_cell(has_open("server.mem.pressure"))) }
                        }
                        tr {
                            td { "disk_used_pct" }
                            td.num { (crate::health_monitor::DISK_PRESSURE_TRIGGER_PCT) "%" }
                            td class=(if worst_disk.is_some_and(|(p, _)| p > 70) { "num warn" } else { "num" }) {
                                (worst_disk.map(|(p, _)| format!("{p}%")).unwrap_or("—".into()))
                            }
                            td.ed-grid__mut { (worst_disk.map(|(_, s)| s).unwrap_or("—")) }
                            td { (state_cell(has_open("server.disk.pressure"))) }
                        }
                        tr {
                            td { "singbox_log_mib" }
                            td.num { (crate::health_monitor::SINGBOX_LOG_TRIGGER_BYTES / (1024 * 1024)) }
                            td class=(if worst_log_mib.is_some_and(|(m, _)| m > 500) { "num warn" } else { "num" }) {
                                (worst_log_mib.map(|(m, _)| m.to_string()).unwrap_or("—".into()))
                            }
                            td.ed-grid__mut { (worst_log_mib.map(|(_, s)| s).unwrap_or("—")) }
                            td { (state_cell(has_open("server.singbox.log.too_big"))) }
                        }
                        tr {
                            td { "unreachable" }
                            td.num {
                                (crate::node_probe_poller::DEFAULT_UNREACHABLE_THRESHOLD)
                                (tr(lang, "× fails", "× сбоя"))
                            }
                            td.num { (probeable_total - up_count) }
                            td.ed-grid__mut { (tr(lang, "fleet", "флот")) }
                            td { (state_cell(has_open("server.unreachable"))) }
                        }
                        tr {
                            td { "version_drift" }
                            td.num { (tr(lang, "any", "любой")) }
                            td class=(if drifted.is_empty() { "num" } else { "num warn" }) { (drifted.len()) }
                            td.ed-grid__mut {
                                @match drifted.first() {
                                    Some((sid, _)) => (sid),
                                    None => "—",
                                }
                            }
                            td {
                                @if drifted.is_empty() { (state_cell(false)) }
                                @else { span style="color: var(--warm);" { "≠ " (tr(lang, "drifted", "дрейф")) } }
                            }
                        }
                    }
                }
            }
            div {
                div.ed-art-eyebrow {
                    (tr(lang, "Probe failures · 7d", "Сбои проб · 7д"))
                    " · " (probe_failures.len()) " " (tr(lang, "events", "событий"))
                }
                @if probe_failures.is_empty() {
                    p.ed-grid__mut style="font-family: var(--serif); font-style: italic; font-size: 12px;" {
                        (tr(lang, "No probe failures in the last 7 days.", "За последние 7 дней сбоев проб не было."))
                    }
                } @else {
                    table.ed-feed style="margin-top: 8px;" {
                        tbody {
                            @for a in &probe_failures {
                                tr {
                                    td.ed-grid__mut style="width: 110px;" { (a.created_at.format("%m-%d %H:%M").to_string()) }
                                    td {
                                        @match &a.server_id {
                                            Some(sid) => a href=(format!("/admin/servers/{}", path_segment_encode(&sid.0))) { (sid.0) },
                                            None => span.ed-grid__mut { "—" },
                                        }
                                    }
                                    td.ed-grid__mut.ed-grid__sm { (a.summary) }
                                    td.num {
                                        @if a.acked_at.is_some() { span style="color: var(--green);" { "✓" } }
                                        @else { span style="color: var(--warm);" { "⚠" } }
                                    }
                                }
                            }
                        }
                    }
                }
                div style="border-top: 1px solid var(--rule); margin: 14px 0 10px;" {}
                div.ed-art-eyebrow {
                    (tr(lang, "GeoIP DB", "База GeoIP")) " "
                    span.ed-tip title=(tr(
                        lang,
                        "MMDB city+ASN files enrich every new sub_access_log row offline. Refresh from Settings — new DBs load on next vpnctld restart.",
                        "MMDB-файлы city+ASN обогащают каждую новую строку sub_access_log оффлайн. Обновление — в Настройках; новые базы подхватываются при рестарте vpnctld.",
                    )) { "ⓘ" }
                }
                div style="font-family: var(--mono); font-size: 11px; color: var(--mute); margin-top: 6px;" {
                    "city db "
                    @match &geoip.city_mtime {
                        Some(m) => b { (m) },
                        None => (tr(lang, "missing", "нет")),
                    }
                    " · asn db "
                    @match &geoip.asn_mtime {
                        Some(m) => b { (m) },
                        None => (tr(lang, "missing", "нет")),
                    }
                    " · "
                    a href="/admin/settings/system#geoip" style="color: var(--acc);" {
                        (tr(lang, "update in Settings →", "обновить в Настройках →"))
                    }
                }
            }
        }
    };
    Ok(render_page(&state, "monitoring", &theme, &accent, lang, body).await)
}

/// Design v2 3a — «probe all now». Runs the SAME per-server probe the
/// poller runs on its tick, immediately, then bounces back to the
/// monitoring page (whose tables re-read the freshly written
/// node_health rows). Sequential SSH — a few seconds per node; a down
/// node adds its connect timeout. Alert state-machines stay with the
/// background monitor; this only refreshes the data.
pub(crate) async fn monitoring_probe_all(
    State(state): State<AppState>,
) -> Result<Response, Response> {
    let servers = state
        .inv
        .list_servers()
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;
    let mut probed = 0u32;
    for s in &servers {
        let outcome = crate::node_probe_poller::probe_one_server(&state.inv, s).await;
        tracing::info!(
            target = "vpnctld::admin",
            server = %s.id.0,
            ?outcome,
            "manual probe sweep (monitoring page)"
        );
        probed += 1;
    }
    let _ = state
        .inv
        .audit(
            "admin",
            "monitoring.probe_all",
            None,
            Some(&serde_json::json!({ "servers": probed })),
        )
        .await;
    Ok(axum::response::Redirect::to("/admin/monitoring").into_response())
}
