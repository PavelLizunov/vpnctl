use maud::{Markup, html};

use crate::handlers::admin::helpers::{format_msk_iso, humanize_bytes, pct_label};
use crate::handlers::admin::legacy::dashboard::{pct_color, sparkline_svg_scaled};

/// Phase H+ — rolling uptime SLO section. Three chips (24h / 7d /
/// 30d) under the live-status hero. Reads `UptimeStat` values
/// fetched in the handler (uptime_for_server SQL aggregate, one
/// indexed range scan per window).
///
/// Renders NOTHING when all three windows have None — the hero
/// already shows the «no probes yet» empty state and stacking
/// another empty block would be UI noise.
///
/// Chip colour rules (per chip, independent of the others):
///   * `Some(100)`          → green «100%» — perfect, no outages
///   * `Some(>= 99)`        → green
///   * `Some(>= 95)`        → amber
///   * `Some(< 95)`         → red
///   * `Some(0)`            → red «0%» (was DOWN for the entire
///     window — distinct from None!)
///   * `None`               → grey «— no data» (no decidable rows)
///
/// Display precision is **integer %** (formatted via `{p}%` on `u8`)
/// — not one-decimal. `Option<u8>` carries enough resolution for the
/// «pick a colour bucket» purpose without false-precision in the
/// rendered chip («99%» vs «98.7%» — the latter implies precision
/// the 10-min poll cadence simply doesn't deliver).
///
/// Last-outage display: shows ISO timestamp of the most recent
/// `sing_box_active=0` row across ALL THREE windows (the widest is
/// 30d so it captures any). Renders only if found.
///
/// Last-probe staleness: if the most recent probe across all three
/// windows is older than 1200s (= 2× the DEFAULT 600s probe
/// interval), render an amber «poller may be stale» footer. The
/// threshold is hardcoded rather than reading
/// `VPNCTLD_NODE_PROBE_INTERVAL_SECS` from env — the env override
/// is daemon-startup only and the UI would have to observe its
/// own process to read it. **Caveat:** if the operator has set
/// `VPNCTLD_NODE_PROBE_INTERVAL_SECS=1800` or higher, this 1200s
/// threshold will false-positive the «stale» chip after the first
/// natural-interval tick. Acceptable today (production runs with
/// the default 600s) — file a follow-up if Pavel ever raises the
/// interval persistently.
pub(crate) fn server_detail_uptime_section(
    u24h: Option<&vpnctl_inventory::UptimeStat>,
    u7d: Option<&vpnctl_inventory::UptimeStat>,
    u30d: Option<&vpnctl_inventory::UptimeStat>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;

    // Don't render the section when there's literally no data:
    //   * All three queries failed → suppress (DB error path).
    //   * All three returned `total_rows == 0` → suppress (the
    //     hero already shows «no probes yet» — stacking another
    //     empty block would be UI noise).
    //
    // Subtlety: `uptime_for_server` returns `Ok(UptimeStat { 0,
    // 0, 0, ... })` for an empty window — it does NOT return
    // `Err`. So an `is_none()` check on the Option would always
    // be false in practice (only Err → None via `.ok()`). The
    // load-bearing check is on `total_rows`.
    let any_data = u24h.is_some_and(|s| s.total_rows > 0)
        || u7d.is_some_and(|s| s.total_rows > 0)
        || u30d.is_some_and(|s| s.total_rows > 0);
    if !any_data {
        return html! {};
    }

    let row = |label: &str, stat: Option<&vpnctl_inventory::UptimeStat>| -> Markup {
        let pct = stat.and_then(|s| s.uptime_pct);
        let color = pct_color(pct);
        let pct_text = pct_label(pct, lang);
        let row_count: u64 = stat.map(|s| s.total_rows).unwrap_or(0);
        let down_count: u64 = stat.map(|s| s.down_rows).unwrap_or(0);
        // `data-uptime-pct` is a stable scrape-target for admin_smoke
        // tests + a future operator tool that wants to extract SLOs
        // without parsing the CSS. The value is the raw u8 or the
        // literal string "none" for the no-data branch. Choosing the
        // attribute over inline-text means the test can't false-pass
        // on unrelated `100%` substrings elsewhere on the page (e.g.
        // disk-pressure tile at 100%).
        let pct_attr = pct.map(|p| p.to_string()).unwrap_or_else(|| "none".into());
        html! {
            tr data-uptime-pct=(pct_attr) {
                th { (label) }
                td.num style=(format!("font-family: var(--serif); font-weight: 600; color: {color};")) {
                    (pct_text)
                }
                td.num.ed-grid__mut.ed-grid__sm {
                    (row_count) " " (crate::i18n::noun_for(lang, row_count, "probe", "probes", "проба", "пробы", "проб"))
                    @if down_count > 0 { " · " (down_count) " " (tr(lang, "down", "падений")) }
                }
            }
        }
    };

    // Pick the most recent outage across all three windows (30d is
    // widest, so if it has one, that's our answer; fall through if
    // somehow the wider window missed but a narrower didn't).
    let last_outage = u30d
        .and_then(|s| s.last_outage_at)
        .or_else(|| u7d.and_then(|s| s.last_outage_at))
        .or_else(|| u24h.and_then(|s| s.last_outage_at));

    // Most recent probe (any state). For staleness chip.
    let last_probe = u24h
        .and_then(|s| s.last_probe_at)
        .or_else(|| u7d.and_then(|s| s.last_probe_at))
        .or_else(|| u30d.and_then(|s| s.last_probe_at));

    let stale = last_probe
        .map(|ts| (chrono::Utc::now() - ts).num_seconds() > 1200)
        .unwrap_or(false);

    html! {
        section #uptime-section style="margin-top: 18px;" {
            div.ed-art-eyebrow {
                (tr(lang, "Uptime · sing-box service", "Uptime · сервис sing-box"))
                " "
                span.ed-tip title=(tr(
                    lang,
                    "Rolling-window aggregate over sing_box_active from the node_probe poller (10-min default tick). Up means the service reported active at probe time; unknown probes are excluded from the denominator.",
                    "Скользящие окна sing_box_active от node_probe-поллера (тик по умолчанию 10 минут). Up означает, что сервис показал active; неопределённые пробы не входят в знаменатель.",
                )) { "ⓘ" }
            }
            table.ed-grid style="margin-top: 8px;" {
                tbody {
                    (row(tr(lang, "last 24h", "24 часа"), u24h))
                    (row(tr(lang, "last 7d",  "7 дней"),  u7d))
                    (row(tr(lang, "last 30d", "30 дней"), u30d))
                }
            }
            @if last_outage.is_some() || stale {
                div style="margin-top: 12px; font-family: var(--mono); font-size: 11px; color: var(--mute); display: flex; flex-direction: column; gap: 4px;" {
                    @if let Some(ts) = last_outage {
                        @let mins = chrono::Utc::now().signed_duration_since(ts).num_minutes().max(0);
                        div {
                            (tr(lang, "Last outage observed: ", "Последнее падение: "))
                            span style="color: var(--ink);" { (format_msk_iso(ts)) }
                            " ("
                            @if mins < 60 {
                                (mins) " " (tr(lang, "min ago", "мин назад"))
                            } @else if mins < 24 * 60 {
                                (mins / 60) " " (tr(lang, "h ago", "ч назад"))
                            } @else {
                                (mins / (24 * 60)) " " (tr(lang, "d ago", "д назад"))
                            }
                            ")"
                        }
                    }
                    @if stale {
                        div style="color: #e6a23c;" {
                            (tr(
                                lang,
                                "Most recent probe is >20 min old — the poller may be stalled. Use the manual sweep button on this page to refresh.",
                                "Последняя проба старше 20 минут — поллер может быть остановлен. Нажми кнопку ручного сканирования на этой странице, чтобы обновить.",
                            ))
                        }
                    }
                }
            }
        }
    }
}

/// Hero block — most-recent probe at-a-glance KPIs, OR an empty state
/// describing why the box is empty (no probe data yet — either fresh
/// server, deploy key not pushed, or poller not running).
pub(super) fn server_detail_hero(
    latest: &Option<vpnctl_inventory::NodeHealthRow>,
    server: &vpnctl_core::Server,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let Some(h) = latest else {
        return html! {
            div.ed-rule {}
            div.ed-art-eyebrow { (tr(lang, "Live status", "Живой статус")) }
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
                // Honest copy (audit 2026-06-10): the poller is LIVE
                // (spawn_node_probe_poller, 10-min cadence) and probes
                // sing-box servers only — blank means «not probed yet»
                // or «not probeable», not «feature unshipped».
                (tr(
                    lang,
                    "No probes yet. The node-telemetry poller SSHes ",
                    "Probe-ов пока нет. Поллер телеметрии SSH-ит ",
                ))
                span.ed-mono { (server.address) }
                (tr(
                    lang,
                    " every 10 min for disk/mem/load + listening ports. Blank here means the first probe hasn't landed (fresh server / daemon restart), the node is unreachable over SSH, or this server has no sing-box kernel (only sing-box nodes are probed).",
                    " каждые 10 минут за disk/mem/load + слушающими портами. Пусто значит: первый probe ещё не прошёл (новый сервер / рестарт демона), нода недоступна по SSH, либо у сервера нет ядра sing-box (probe-ятся только sing-box ноды).",
                ))
            }
        };
    };
    let sb = h
        .sing_box_active
        .map(|b| {
            if b {
                tr(lang, "active", "активен")
            } else {
                tr(lang, "down", "не работает")
            }
        })
        .unwrap_or("?");
    let f2b = h
        .fail2ban_active
        .map(|b| {
            if b {
                tr(lang, "active", "активен")
            } else {
                tr(lang, "down", "не работает")
            }
        })
        .unwrap_or("?");
    let disk_used_pct = h
        .disk_used_mib
        .zip(h.disk_total_mib)
        .filter(|(_, t)| *t > 0)
        .map(|(u, t)| (u * 100 / t).min(100));
    let disk_pct = disk_used_pct
        .map(|pct| format!("{pct}%"))
        .unwrap_or("?".into());
    let mem_used_pct = h
        .mem_available_mib
        .zip(h.mem_total_mib)
        .filter(|(_, t)| *t > 0)
        .map(|(a, t)| 100u64.saturating_sub(a * 100 / t));
    let mem_pct = mem_used_pct
        .map(|pct| format!("{pct}%"))
        .unwrap_or("?".into());
    let load = h
        .load_1min_x100
        .map(|l| format!("{:.2}", f64::from(l) / 100.0))
        .unwrap_or("?".into());
    let log_size = h
        .sing_box_log_bytes
        .map(humanize_bytes)
        .unwrap_or("?".into());

    let sb_color = match h.sing_box_active {
        Some(true) => "var(--soft)",
        Some(false) => "var(--acc)",
        None => "var(--mute)",
    };
    let f2b_color = match h.fail2ban_active {
        Some(true) => "var(--soft)",
        Some(false) => "var(--acc)",
        None => "var(--mute)",
    };
    let log_alert_color = match h.sing_box_log_bytes {
        Some(b) if b > 500 * 1024 * 1024 => "var(--acc)",
        _ => "var(--ink)",
    };

    html! {
        div.ed-status-strip title=(format!("{} · {}", tr(lang, "last probe", "последняя проба"), format_msk_iso(h.ts))) {
            (status_tile_with_warn("sing-box", sb, sb_color, h.sing_box_active == Some(false)))
            (status_tile_with_warn("fail2ban", f2b, f2b_color, h.fail2ban_active == Some(false)))
            (status_tile_with_warn(tr(lang, "disk used", "диск занят"), &disk_pct, "var(--ink)", disk_used_pct.is_some_and(|v| v > 70)))
            (status_tile_with_warn(tr(lang, "memory used", "память занята"), &mem_pct, "var(--ink)", mem_used_pct.is_some_and(|v| v > 70)))
            (status_tile_with_warn(tr(lang, "1-min load", "load 1мин"), &load, "var(--ink)", false))
            (status_tile_with_warn(tr(lang, "sing-box log", "лог sing-box"), &log_size, log_alert_color, h.sing_box_log_bytes.is_some_and(|b| b > 500 * 1024 * 1024)))
        }
    }
}

pub(crate) fn status_tile(label: &str, value: &str, value_color: &str) -> Markup {
    status_tile_with_warn(label, value, value_color, false)
}

pub(crate) fn status_tile_with_warn(
    label: &str,
    value: &str,
    value_color: &str,
    warn: bool,
) -> Markup {
    html! {
        div class=(if warn { "ed-status-tile warn" } else { "ed-status-tile" }) {
            div.ed-status-tile__k { (label) }
            div.ed-status-tile__v style=(format!("color: {value_color};")) {
                (value)
                @if warn { " ⚠" }
            }
        }
    }
}

/// A3 (audit 2026-05-22) — 24h resource-trend sparklines for the
/// per-server detail page. Three small SVG charts: disk %, mem-used %,
/// sing-box log MiB. Each uses the existing reusable `sparkline_svg`
/// helper (so styling stays consistent with the dashboard + monitoring
/// page; accent-toggle in Tweaks panel recolours everything).
///
/// **Renders only when there's at least one node_health row in the
/// 24h window.** Fresh server (no probes yet) gets nothing — the hero
/// section already says «no data yet» for that case; we don't need to
/// repeat it.
///
/// Each row in `trend_rows` came from `recent_node_health_for_server`
/// which sorts DESC (newest first). For the sparkline we reverse so
/// time flows left-to-right.
pub(super) fn server_detail_resource_trend_section(
    trend_rows: &[vpnctl_inventory::NodeHealthRow],
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    if trend_rows.is_empty() {
        return html! {};
    }
    // Iterate oldest→newest so the sparkline reads chronologically.
    let mut chronological: Vec<&vpnctl_inventory::NodeHealthRow> = trend_rows.iter().collect();
    chronological.reverse();

    // Disk usage % per row. Skip rows missing either side of the
    // ratio (None → no point added; sparkline tolerates a shorter
    // series gracefully).
    let disk_pct_series: Vec<f64> = chronological
        .iter()
        .filter_map(|r| {
            let used = r.disk_used_mib?;
            let total = r.disk_total_mib?;
            if total == 0 {
                return None;
            }
            Some(((used as f64) / (total as f64)) * 100.0)
        })
        .collect();

    // Memory-used % per row (probe stores AVAILABLE, hence 100 - avail/total).
    let mem_used_pct_series: Vec<f64> = chronological
        .iter()
        .filter_map(|r| {
            let avail = r.mem_available_mib?;
            let total = r.mem_total_mib?;
            if total == 0 {
                return None;
            }
            Some(100.0 - ((avail as f64) / (total as f64)) * 100.0)
        })
        .collect();

    // sing-box log size in MiB. The threshold alert
    // (server.singbox.log.too_big) fires at 500 MiB; sparkline shows
    // the climb so operator can predict «when will we hit 500».
    let log_mib_series: Vec<f64> = chronological
        .iter()
        .filter_map(|r| r.sing_box_log_bytes.map(|b| (b as f64) / (1024.0 * 1024.0)))
        .collect();

    let n_samples = chronological.len();
    let max_value = |series: &[f64]| series.iter().copied().reduce(f64::max).unwrap_or_default();
    let disk_max = max_value(&disk_pct_series);
    let mem_max = max_value(&mem_used_pct_series);
    let log_max = max_value(&log_mib_series);
    html! {
        section id="resource-trend" style="margin-top: 18px;" {
            div.ed-art-eyebrow {
                (tr(lang, "Resource trend · last 24h", "Тренд ресурсов · последние 24ч"))
                " "
                span.ed-tip title=(tr(
                    lang,
                    "10-min probe snapshots over the last 24h. Sparkline reads left-to-right (oldest → newest); the «max» label on each chart is the peak in the window. Use these to tell a slow leak (climbing line) from a transient burst (flat line, one spike).",
                    "10-минутные снимки probe за последние 24 часа. Sparkline читается слева-направо (старое → новое); метка «max» в каждом графике — пик за окно. Помогает отличить медленную утечку (растущая линия) от кратковременного всплеска (плоская линия с одним пиком).",
                )) { "ⓘ" }
            }
            div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-top: 8px;" {
                div {
                    div style="font-family: var(--mono); font-size: 11px; color: var(--mute); text-transform: uppercase; letter-spacing: 0.14em;" {
                        (tr(lang, "Disk %", "Диск %"))
                    }
                    (sparkline_svg_scaled(&disk_pct_series, 280, 60, Some(100.0), false))
                    div style="font-family: var(--mono); font-size: 10px; color: var(--mute);" {
                        (tr(lang, "max ", "макс ")) (format!("{disk_max:.0}%"))
                        " · " (disk_pct_series.len()) " " (tr(lang, "samples", "точек"))
                    }
                }
                div {
                    div style="font-family: var(--mono); font-size: 11px; color: var(--mute); text-transform: uppercase; letter-spacing: 0.14em;" {
                        (tr(lang, "Mem used %", "Память исп. %"))
                    }
                    (sparkline_svg_scaled(&mem_used_pct_series, 280, 60, Some(100.0), false))
                    div style=(if mem_max > 70.0 { "font-family: var(--mono); font-size: 10px; color: var(--warm); font-weight: 600;" } else { "font-family: var(--mono); font-size: 10px; color: var(--mute);" }) {
                        (tr(lang, "max ", "макс ")) (format!("{mem_max:.0}%"))
                        @if mem_max > 70.0 { " ⚠" }
                        " · " (mem_used_pct_series.len()) " " (tr(lang, "samples", "точек"))
                    }
                }
                div {
                    div style="font-family: var(--mono); font-size: 11px; color: var(--mute); text-transform: uppercase; letter-spacing: 0.14em;" {
                        (tr(lang, "sing-box log MiB", "sing-box лог MiB"))
                    }
                    (sparkline_svg_scaled(&log_mib_series, 280, 60, None, false))
                    div style="font-family: var(--mono); font-size: 10px; color: var(--mute);" {
                        (tr(lang, "max ", "макс ")) (format!("{log_max:.0} MiB"))
                        " · " (log_mib_series.len()) " " (tr(lang, "samples", "точек"))
                    }
                }
            }
            p style="font-family: var(--serif); font-style: italic; font-size: 11px; color: var(--mute); margin-top: 6px;" {
                "(" (n_samples) " " (tr(lang, "probe ticks in the window", "тиков probe в окне"))  ")"
            }
        }
    }
}
