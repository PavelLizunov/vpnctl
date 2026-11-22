use std::collections::{BTreeMap, BTreeSet};

use crate::handlers::admin::icons::icon;
use chrono::{Datelike, Utc};
use maud::{Markup, html};

use crate::AppState;
use crate::handlers::admin::helpers::{display_tz, humanize_bytes};
use crate::handlers::admin::legacy::dashboard::sparkline_svg_scaled;
use crate::handlers::admin::legacy::server_detail::status_tile;
use crate::http_util::path_segment_encode;
use crate::i18n::{K, Locale, t, tr};

#[derive(Clone, Copy, Debug)]
pub(in crate::handlers::admin::legacy) struct VpnSparklineWindow {
    pub(in crate::handlers::admin::legacy) slug: &'static str,
    pub(in crate::handlers::admin::legacy) label_en: &'static str,
    pub(in crate::handlers::admin::legacy) label_ru: &'static str,
    pub(in crate::handlers::admin::legacy) cells: u32,
    pub(in crate::handlers::admin::legacy) bucket_hours: u32,
    pub(in crate::handlers::admin::legacy) per_bucket_en: &'static str,
    pub(in crate::handlers::admin::legacy) per_bucket_ru: &'static str,
}

pub(in crate::handlers::admin::legacy) const VPN_SPARKLINE_WINDOWS: &[VpnSparklineWindow] = &[
    VpnSparklineWindow {
        slug: "24h",
        label_en: "24h",
        label_ru: "24ч",
        cells: 24,
        bucket_hours: 1,
        per_bucket_en: "per hour",
        per_bucket_ru: "в час",
    },
    VpnSparklineWindow {
        slug: "7d",
        label_en: "7 days",
        label_ru: "7 дней",
        cells: 7,
        bucket_hours: 24,
        per_bucket_en: "per day",
        per_bucket_ru: "в сутки",
    },
    VpnSparklineWindow {
        slug: "30d",
        label_en: "30 days",
        label_ru: "30 дней",
        cells: 30,
        bucket_hours: 24,
        per_bucket_en: "per day",
        per_bucket_ru: "в сутки",
    },
    VpnSparklineWindow {
        slug: "all",
        label_en: "all",
        label_ru: "всё",
        cells: 30,
        bucket_hours: 24 * 30,
        per_bucket_en: "per month",
        per_bucket_ru: "в месяц",
    },
];

pub(in crate::handlers::admin::legacy) fn pick_vpn_sparkline_window(
    slug: Option<&str>,
) -> VpnSparklineWindow {
    let s = slug.unwrap_or("24h");
    VPN_SPARKLINE_WINDOWS
        .iter()
        .find(|w| w.slug == s)
        .copied()
        .unwrap_or(VPN_SPARKLINE_WINDOWS[0])
}

/// One period definition used by the KPI tiles, per-server table, trend and
/// chart. Fixed windows cover exactly `[now - cells × bucket, now]`; the oldest
/// bucket may start mid-clock-hour and is included in every total. The `all`
/// window expands its cells until the oldest retained row fits.
#[derive(Clone, Copy, Debug)]
struct VpnChartWindow {
    cells: usize,
    bucket_hours: u32,
    start: i64,
    end: i64,
}

impl VpnChartWindow {
    fn bucket_seconds(self) -> i64 {
        i64::from(self.bucket_hours) * 3600
    }

    fn bucket_index(self, ts: i64) -> Option<usize> {
        if self.cells == 0 || ts < self.start || ts > self.end {
            return None;
        }
        let seconds = self.bucket_seconds().max(1);
        Some(((ts.saturating_sub(self.start) / seconds).max(0) as usize).min(self.cells - 1))
    }

    fn bucket_start(self, index: usize) -> i64 {
        self.start
            .saturating_add((index as i64).saturating_mul(self.bucket_seconds()))
    }
}

fn vpn_chart_window_at(
    window: VpnSparklineWindow,
    rows: &[vpnctl_inventory::VpnStatsRow],
    now: i64,
) -> VpnChartWindow {
    let bucket_seconds = i64::from(window.bucket_hours).max(1) * 3600;
    let mut cells = window.cells.max(1) as usize;
    if window.slug == "all" {
        let oldest = rows
            .iter()
            .map(|row| row.ts.timestamp())
            .min()
            .unwrap_or(now);
        let needed = now
            .saturating_sub(oldest)
            .max(0)
            .div_euclid(bucket_seconds)
            .saturating_add(1);
        cells = cells.max(usize::try_from(needed).unwrap_or(usize::MAX));
    }
    let start = now.saturating_sub((cells as i64).saturating_mul(bucket_seconds));
    VpnChartWindow {
        cells,
        bucket_hours: window.bucket_hours.max(1),
        start,
        end: now,
    }
}

fn vpn_chart_window(
    window: VpnSparklineWindow,
    rows: &[vpnctl_inventory::VpnStatsRow],
) -> VpnChartWindow {
    vpn_chart_window_at(window, rows, Utc::now().timestamp())
}

fn nice_byte_ceiling(n: u64) -> u64 {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    const TIB: u64 = 1024 * GIB;
    let units = [
        KIB,
        2 * KIB,
        5 * KIB,
        10 * KIB,
        20 * KIB,
        50 * KIB,
        100 * KIB,
        200 * KIB,
        500 * KIB,
        MIB,
        2 * MIB,
        5 * MIB,
        10 * MIB,
        20 * MIB,
        50 * MIB,
        100 * MIB,
        200 * MIB,
        500 * MIB,
        GIB,
        2 * GIB,
        5 * GIB,
        10 * GIB,
        20 * GIB,
        50 * GIB,
        100 * GIB,
        200 * GIB,
        500 * GIB,
        TIB,
        2 * TIB,
        5 * TIB,
        10 * TIB,
    ];
    for &u in &units {
        if u >= n.max(1) {
            return u;
        }
    }
    n
}

fn x_axis_tick_label(timestamp: i64, bucket_hours: u32) -> String {
    let Some(t) = chrono::DateTime::from_timestamp(timestamp, 0) else {
        return "—".to_owned();
    };
    let fmt = if bucket_hours == 1 {
        "%H:%M"
    } else if bucket_hours == 24 {
        "%b %d"
    } else {
        "%b %Y"
    };
    t.with_timezone(&display_tz()).format(fmt).to_string()
}

fn vpn_traffic_trend_series(
    rows: &[vpnctl_inventory::VpnStatsRow],
    chart: VpnChartWindow,
) -> Vec<f64> {
    let mut per_cell: Vec<u64> = vec![0; chart.cells];
    for r in rows {
        let Some(idx) = chart.bucket_index(r.ts.timestamp()) else {
            continue;
        };
        per_cell[idx] =
            per_cell[idx].saturating_add(r.upload_bytes.saturating_add(r.download_bytes));
    }
    per_cell.into_iter().map(|v| v as f64).collect()
}

fn vpn_traffic_cells(
    rows: &[vpnctl_inventory::VpnStatsRow],
    chart: VpnChartWindow,
) -> (Vec<u64>, Vec<u64>) {
    let mut up_per_cell: Vec<u64> = vec![0; chart.cells];
    let mut dn_per_cell: Vec<u64> = vec![0; chart.cells];
    for r in rows {
        let Some(idx) = chart.bucket_index(r.ts.timestamp()) else {
            continue;
        };
        up_per_cell[idx] = up_per_cell[idx].saturating_add(r.upload_bytes);
        dn_per_cell[idx] = dn_per_cell[idx].saturating_add(r.download_bytes);
    }
    (up_per_cell, dn_per_cell)
}

fn vpn_traffic_chart(
    rows: &[vpnctl_inventory::VpnStatsRow],
    chart: VpnChartWindow,
    window: VpnSparklineWindow,
    lang: Locale,
) -> Markup {
    let per_bucket = match lang {
        Locale::En => window.per_bucket_en,
        Locale::Ru => window.per_bucket_ru,
    };
    let cells = chart.cells;
    if cells == 0 {
        return html! {};
    }
    let (up_per_cell, dn_per_cell) = vpn_traffic_cells(rows, chart);
    let raw_max = up_per_cell
        .iter()
        .zip(dn_per_cell.iter())
        .map(|(u, d)| u.saturating_add(*d))
        .max()
        .unwrap_or(0);
    let total_window: u64 = up_per_cell
        .iter()
        .zip(dn_per_cell.iter())
        .map(|(u, d)| u.saturating_add(*d))
        .sum();
    let y_max = nice_byte_ceiling(raw_max);
    let vb_w = 720;
    let vb_h = 240;
    let pad_l = 64;
    let pad_r = 16;
    let pad_t = 12;
    let pad_b = 44;
    let plot_w = (vb_w - pad_l - pad_r) as f64;
    let plot_h = (vb_h - pad_t - pad_b) as f64;
    let n_ticks_y: usize = 4;
    let bar_slot = plot_w / cells as f64;
    let bar_gap = if cells > 14 { 2.0 } else { 4.0 };
    let bar_w = (bar_slot - bar_gap).max(2.0);
    let mut svg_inner = String::new();
    for t in 0..=n_ticks_y {
        let frac = t as f64 / n_ticks_y as f64;
        let val = ((y_max as f64) * frac) as u64;
        let y = pad_t as f64 + plot_h - frac * plot_h;
        svg_inner.push_str(&format!(
            r#"<line x1="{x1}" y1="{y:.1}" x2="{x2}" y2="{y:.1}" stroke="var(--rule)" stroke-width="0.5"/>"#,
            x1 = pad_l,
            x2 = vb_w - pad_r,
        ));
        svg_inner.push_str(&format!(
            r#"<text x="{x:.1}" y="{ty:.1}" text-anchor="end" font-family="var(--mono)" font-size="10" fill="var(--mute)">{label}</text>"#,
            x = pad_l as f64 - 6.0,
            ty = y + 3.0,
            label = if val == 0 {
                "0".to_string()
            } else {
                humanize_bytes(val)
            },
        ));
    }
    svg_inner.push_str(&format!(
        r#"<line x1="{x1}" y1="{y:.1}" x2="{x2}" y2="{y:.1}" stroke="var(--ink)" stroke-width="0.8"/>"#,
        x1 = pad_l,
        x2 = vb_w - pad_r,
        y = pad_t as f64 + plot_h,
    ));
    for i in 0..cells {
        let up = up_per_cell[i];
        let dn = dn_per_cell[i];
        let total = up.saturating_add(dn);
        let x_left = pad_l as f64 + i as f64 * bar_slot + bar_gap / 2.0;
        let bucket_start = chart.bucket_start(i);
        let tooltip = format!(
            "{label}\n↓ download: {dn_h}\n↑ upload: {up_h}\ntotal: {t_h}",
            label = x_axis_tick_label(bucket_start, window.bucket_hours),
            dn_h = humanize_bytes(dn),
            up_h = humanize_bytes(up),
            t_h = humanize_bytes(total),
        );
        svg_inner.push_str(&format!(
            r#"<g><title>{tooltip}</title><rect x="{x:.1}" y="{ht_y}" width="{w:.1}" height="{ht_h:.1}" fill="transparent"/>"#,
            x = x_left,
            ht_y = pad_t,
            w = bar_w,
            ht_h = plot_h,
        ));
        if y_max > 0 && total > 0 {
            let up_h = (up as f64 / y_max as f64) * plot_h;
            let dn_h = (dn as f64 / y_max as f64) * plot_h;
            let up_y = pad_t as f64 + plot_h - up_h;
            let dn_y = up_y - dn_h;
            if up_h > 0.3 {
                svg_inner.push_str(&format!(
                    r#"<rect x="{x:.1}" y="{up_y:.1}" width="{w:.1}" height="{up_h:.1}" fill="var(--soft)"/>"#,
                    x = x_left,
                    w = bar_w,
                ));
            }
            if dn_h > 0.3 {
                svg_inner.push_str(&format!(
                    r#"<rect x="{x:.1}" y="{dn_y:.1}" width="{w:.1}" height="{dn_h:.1}" fill="var(--acc)"/>"#,
                    x = x_left,
                    w = bar_w,
                ));
            }
        }
        svg_inner.push_str("</g>");
    }
    let tick_every = match cells {
        0..=8 => 1,
        9..=16 => 2,
        17..=32 => 5,
        _ => 6,
    };
    for i in 0..cells {
        if i % tick_every != 0 && i != cells - 1 {
            continue;
        }
        let x_center = pad_l as f64 + i as f64 * bar_slot + bar_slot / 2.0;
        let bucket_start = chart.bucket_start(i);
        let label = x_axis_tick_label(bucket_start, window.bucket_hours);
        svg_inner.push_str(&format!(
            r#"<text x="{x:.1}" y="{y}" text-anchor="middle" font-family="var(--mono)" font-size="10" fill="var(--mute)">{label}</text>"#,
            x = x_center,
            y = vb_h - pad_b + 18,
        ));
    }
    let svg = format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {vb_w} {vb_h}" preserveAspectRatio="xMidYMid meet" aria-label="VPN traffic chart" style="display: block; width: 100%; max-width: 720px; height: auto;">{svg_inner}</svg>"#,
    );
    html! {
        div style="margin: 12px 0; padding: 12px 14px; background: var(--paper); border: 1px solid var(--rule);" {
            (maud::PreEscaped(svg))
            div style="display: flex; flex-wrap: wrap; justify-content: space-between; align-items: baseline; gap: 12px; font-family: var(--mono); font-size: 11px; color: var(--mute); margin-top: 4px; padding: 0 4px;" {
                span {
                    span style="display: inline-block; width: 10px; height: 10px; background: var(--acc); vertical-align: middle; margin-right: 4px;" {}
                    (tr(lang, "download", "загрузка"))
                    "  ·  "
                    span style="display: inline-block; width: 10px; height: 10px; background: var(--soft); vertical-align: middle; margin-right: 4px;" {}
                    (tr(lang, "upload", "отправка"))
                }
                span {
                    (tr(lang, "max ", "макс "))
                    b style="color: var(--ink);" { (humanize_bytes(raw_max)) }
                    " " (per_bucket) "  ·  "
                    (tr(lang, "total ", "всего "))
                    b style="color: var(--ink);" { (humanize_bytes(total_window)) }
                }
            }
        }
    }
}

pub(in crate::handlers::admin::legacy) fn window_picker_section(
    base_url: &str,
    active_slug: &str,
    lang: Locale,
) -> Markup {
    html! {
        div id="timeframe" style="margin: 20px 0 6px; padding: 10px 14px; border: 1px solid var(--rule); background: var(--paper); display: flex; flex-wrap: wrap; gap: 18px; align-items: baseline;" {
            span style="font-family: var(--mono); font-size: 11px; color: var(--mute); text-transform: uppercase; letter-spacing: 0.14em;" {
                (tr(lang, "Window", "Окно"))
            }
            div style="display: flex; gap: 14px; font-family: var(--mono); font-size: 13px;" {
                @for w in VPN_SPARKLINE_WINDOWS {
                    @let label = match lang {
                        Locale::En => w.label_en,
                        Locale::Ru => w.label_ru,
                    };
                    @if w.slug == active_slug {
                        span style="font-weight: 600; color: var(--ink); border-bottom: 1.5px solid var(--ink); padding-bottom: 1px;" {
                            (label)
                        }
                    } @else {
                        a href=(format!("{base_url}?vpn_window={}#timeframe", w.slug))
                          style="color: var(--mute); text-decoration: none; border-bottom: 1px dotted var(--mute); padding-bottom: 1px;" {
                            (label)
                        }
                    }
                }
            }
            span style="font-family: var(--serif); font-style: italic; color: var(--mute); font-size: 11px; margin-left: auto;" {
                (tr(
                    lang,
                    "Period for traffic statistics.",
                    "Период для статистики трафика.",
                ))
            }
        }
    }
}

pub(crate) const DEFAULT_TRAFFIC_THRESHOLD_PCT: u8 = 80;

fn fmt_traffic_progress(used: u64, limit: u64) -> String {
    let pct = if limit == 0 {
        0
    } else {
        ((used as u128 * 100) / limit as u128).min(999) as u32
    };
    format!(
        "{used} / {limit} ({pct}%)",
        used = humanize_bytes(used),
        limit = humanize_bytes(limit),
    )
}

/// Render GiB with enough decimal places to round-trip sub-GiB caps.
/// A one-decimal field turned a 50 MiB cap into `0.0`, so saving the unchanged
/// form silently cleared it.
fn format_limit_gib(bytes: u64) -> String {
    let mut text = format!("{:.9}", bytes as f64 / 1_073_741_824.0);
    while text.ends_with('0') {
        text.pop();
    }
    if text.ends_with('.') {
        text.push('0');
    }
    text
}

fn project_month_end(used: u64) -> Option<u64> {
    if used == 0 {
        return None;
    }
    let now = Utc::now();
    let day = u64::from(now.day()).max(1);
    let days_in_month = u64::from(days_in_month(now.year(), now.month()));
    let projected = (u128::from(used) * u128::from(days_in_month)) / u128::from(day);
    Some(projected.min(u128::from(u64::MAX)) as u64)
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
            if leap { 29 } else { 28 }
        }
        _ => 30,
    }
}

pub(crate) async fn user_traffic_limit_section(
    state: &AppState,
    uid: &vpnctl_core::UserId,
    lang: Locale,
    traffic_filters: Option<(&str, Option<&str>)>,
) -> Markup {
    let return_to = if traffic_filters.is_some() {
        "traffic"
    } else {
        "overview"
    };
    let used = state
        .inv
        .user_traffic_this_month(uid)
        .await
        .map(Some)
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "user_traffic_this_month failed");
            None
        });
    let (limit_opt, threshold_opt) = match state.inv.get_user_traffic_limit(uid).await {
        Ok(limit) => limit,
        Err(e) => {
            tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "get_user_traffic_limit failed");
            return html! {
                div.ed-rule {}
                div.ed-art-eyebrow { (tr(lang, "Traffic limit · month-to-date", "Лимит трафика · с начала месяца")) }
                p.ed-alert role="alert" {
                    (tr(lang, "Traffic limit unavailable. Reload this page before editing the limit.", "Лимит трафика недоступен. Обнови страницу перед изменением лимита."))
                }
                p {
                    (tr(lang, "Used this month: ", "Использовано в этом месяце: "))
                    @match used {
                        Some(bytes) => (humanize_bytes(bytes)),
                        None => (tr(lang, "unknown", "неизвестно")),
                    }
                }
            };
        }
    };
    let threshold_eff = threshold_opt.unwrap_or(DEFAULT_TRAFFIC_THRESHOLD_PCT);
    html! {
        section id="traffic-limit" {
        div.ed-rule {}
        div.ed-art-eyebrow { (tr(lang, "Traffic limit · month-to-date", "Лимит трафика · с начала месяца")) }
        @match (limit_opt, used) {
            (Some(lim), Some(used)) if lim > 0 => {
                @let pct = ((used as u128 * 100) / lim as u128).min(999) as u32;
                @let over_threshold = pct >= u32::from(threshold_eff);
                @let over_limit = pct >= 100;
                p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
                    (tr(
                        lang,
                        "Includes traffic from all nodes with their usage multipliers for this calendar month. Alert threshold: ",
                        "За календарный месяц по всем узлам с учётом их коэффициентов. Порог оповещения — ",
                    ))
                    span.ed-mono { (threshold_eff) "%" } "."
                }
                div style="font-family: var(--mono); font-size: 13px; margin: 0 0 8px;" {
                    (fmt_traffic_progress(used, lim))
                    @if over_limit {
                        " · "
                        span style="color: var(--acc); font-weight: 600;" { (tr(lang, "OVER LIMIT", "СВЕРХ ЛИМИТА")) }
                    } @else if over_threshold {
                        " · "
                        span style="color: var(--acc);" { (tr(lang, "near limit", "у лимита")) }
                    }
                }
                @let bar_pct = pct.min(100);
                @let bar_fill = if over_threshold { "var(--acc)" } else { "var(--ink)" };
                @let _ = over_limit;
                div style="height: 8px; background: var(--rule); margin-bottom: 16px; overflow: hidden;" {
                    div style=(format!("height: 100%; width: {bar_pct}%; background: {bar_fill};")) {}
                }
                @if let Some(projected) = project_month_end(used) {
                    @let proj_pct = ((projected as u128 * 100) / lim as u128).min(999) as u32;
                    @let proj_over = proj_pct >= 100;
                    p style="font-family: var(--mono); font-size: 12px; margin: 0 0 14px; color: var(--mute);" {
                        (tr(lang, "projected ", "прогноз "))
                        span style=(if proj_over { "color: var(--acc); font-weight: 600;" } else { "color: var(--ink);" }) {
                            (humanize_bytes(projected))
                        }
                        (tr(lang, " by month-end (", " к концу месяца ("))
                        (proj_pct) (tr(lang, "% of cap)", "% лимита)"))
                        @if proj_over {
                            " · "
                            (tr(lang, "on track to exceed the cap", "по тренду превысит лимит"))
                        }
                    }
                }
                p style="font-family: var(--mono); font-size: 12px; margin: 0 0 14px; color: var(--mute);" {
                    @if over_limit {
                        (tr(lang, "over the cap by ", "сверх лимита на "))
                        b style="color: var(--acc);" { (humanize_bytes(used.saturating_sub(lim))) }
                    } @else {
                        (tr(lang, "remaining this month: ", "остаток за месяц: "))
                        b style="color: var(--ink);" { (humanize_bytes(lim.saturating_sub(used))) }
                    }
                    " · " (tr(lang, "calendar-month cap", "лимит календарного месяца"))
                }
            }
            (limit, None) => {
                p role="status" {
                    (tr(lang, "Used this month: unknown. Reload to retry.", "Использовано в этом месяце: неизвестно. Обнови страницу для повторной проверки."))
                    @if let Some(lim) = limit {
                        " " (tr(lang, "Monthly cap: ", "Месячный лимит: ")) (humanize_bytes(lim))
                    }
                }
            }
            (_, Some(used)) => {
                p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
                    (tr(lang, "Charged this month (weighted): ", "Начислено за месяц (взвешено): "))
                    span.ed-mono { (humanize_bytes(used)) }
                    (tr(lang, " — no monthly cap configured. Set one below to get the ", " — месячный лимит не задан. Задай ниже, чтобы получать "))
                    span.ed-mono { (DEFAULT_TRAFFIC_THRESHOLD_PCT) "%-" (tr(lang, "of-limit alert", "от-лимита алерт")) }
                    (tr(lang, " on the dashboard.", " на дашборде."))
                }
            }
        }

        details.ed-traffic-disclosure open[return_to == "overview"] {
            summary { (tr(lang, "Edit monthly limit and alert", "Изменить лимит и порог оповещения")) }
            form method="post"
                 action=(format!("/admin/users/{}/traffic-limit", path_segment_encode(&uid.0)))
                 style="display: flex; gap: 10px; align-items: baseline; flex-wrap: wrap; padding: 10px 12px; background: var(--paper); border: 1px solid var(--rule);" {
                input type="hidden" name="limit_loaded" value="1";
                input type="hidden" name="return_to" value=(return_to);
                @if let Some((window, selected_node)) = traffic_filters {
                    input type="hidden" name="vpn_window" value=(pick_vpn_sparkline_window(Some(window)).slug);
                    @if let Some(node) = selected_node {
                        input type="hidden" name="vpn_server" value=(node);
                    }
                }
                label for="user-limit-gib" style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase;" {
                    (tr(lang, "limit", "лимит"))
                }
                @let limit_gib_value = limit_opt.map(format_limit_gib).unwrap_or_default();
                @let limit_bytes_value = limit_opt.map(|bytes| bytes.to_string()).unwrap_or_default();
                input type="hidden" name="limit_gib_loaded" value=(limit_gib_value);
                input type="hidden" name="limit_bytes_loaded" value=(limit_bytes_value);
                input id="user-limit-gib" type="number" name="limit_gib" step="any" min="0" max="100000"
                      value=(limit_gib_value)
                      placeholder=(tr(lang, "no cap", "нет лимита"))
                      title=(tr(
                          lang,
                          "Monthly cap in GiB (upload + download summed). 0 / empty = no cap. Resets on the first of each month.",
                          "Месячный лимит в GiB (upload + download суммой). 0 / пусто = без лимита. Сбрасывается первого числа месяца.",
                      ))
                      style="max-width: 130px; padding: 4px 8px; border: 1px solid var(--rule-s); background: var(--paper); font-family: var(--mono); font-size: 12px; color: var(--ink);";
                span style="font-family: var(--mono); font-size: 11px; color: var(--mute);" { (tr(lang, "GiB / month", "GiB / месяц")) }
                label for="user-limit-threshold" style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase; margin-left: 8px;" {
                    (tr(lang, "alert at", "алерт при"))
                }
                input id="user-limit-threshold" type="number" name="threshold_pct" step="1" min="1" max="100"
                      value=(threshold_eff)
                      title=(tr(
                          lang,
                          "Fire a dashboard alert (and Telegram if configured) when used / cap >= this percent. Default 80%.",
                          "Поднять алерт на дашборде (и в Telegram, если настроен), когда израсходовано ≥ этого процента лимита. По умолчанию 80%.",
                      ))
                      style="max-width: 56px; padding: 4px 8px; border: 1px solid var(--rule-s); background: var(--paper); font-family: var(--mono); font-size: 12px; color: var(--ink);";
                span style="font-family: var(--mono); font-size: 11px; color: var(--mute);" { "%" }
                button type="submit"
                       title=(tr(
                           lang,
                           "Set both fields. 0 GiB = clear the limit (no cap).",
                           "Сохраняет оба поля. 0 GiB = снять лимит.",
                       ))
                       style="padding: 4px 12px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer; margin-left: auto;" {
                    (icon("save")) (t(lang, K::BtnSave))
                }
            }
        }
        }
    }
}

fn chart_totals(rows: &[vpnctl_inventory::VpnStatsRow], chart: VpnChartWindow) -> (u64, u64, u32) {
    let mut up = 0u64;
    let mut down = 0u64;
    let mut peak = 0u32;
    for row in rows {
        if chart.bucket_index(row.ts.timestamp()).is_none() {
            continue;
        }
        up = up.saturating_add(row.upload_bytes);
        down = down.saturating_add(row.download_bytes);
        peak = peak.max(row.active_connections);
    }
    (up, down, peak)
}

fn bytes_from_f64(value: f64) -> u64 {
    if value.is_nan() || value <= 0.0 {
        0
    } else if !value.is_finite() || value >= u64::MAX as f64 {
        u64::MAX
    } else {
        value as u64
    }
}

fn weighted_bytes(up: u64, down: u64, coefficient: f64) -> u64 {
    let coefficient = if coefficient.is_finite() {
        coefficient.max(0.0)
    } else {
        0.0
    };
    bytes_from_f64((up.saturating_add(down) as f64) * coefficient)
}

fn user_traffic_href(uid: &str, slug: &str, server: Option<&str>) -> String {
    let mut href = format!(
        "/admin/users/{}/traffic?vpn_window={slug}",
        path_segment_encode(uid)
    );
    if let Some(server) = server {
        href.push_str("&vpn_server=");
        href.push_str(&path_segment_encode(server));
    }
    href.push_str("#timeframe");
    href
}

fn user_traffic_controls(
    uid: &str,
    active_slug: &str,
    selected_server: Option<&str>,
    servers: &[(String, String)],
    lang: Locale,
) -> Markup {
    let base = format!("/admin/users/{}/traffic", path_segment_encode(uid));
    html! {
        div id="timeframe" style="margin: 20px 0 6px; padding: 10px 14px; border: 1px solid var(--rule); background: var(--paper); display: flex; flex-wrap: wrap; gap: 18px; align-items: baseline;" {
            span style="font-family: var(--mono); font-size: 11px; color: var(--mute); text-transform: uppercase; letter-spacing: 0.14em;" {
                (tr(lang, "Window", "Окно"))
            }
            div style="display: flex; gap: 14px; font-family: var(--mono); font-size: 13px;" {
                @for w in VPN_SPARKLINE_WINDOWS {
                    @let label = match lang {
                        Locale::En => w.label_en,
                        Locale::Ru => w.label_ru,
                    };
                    @if w.slug == active_slug {
                        span style="font-weight: 600; color: var(--ink); border-bottom: 1.5px solid var(--ink); padding-bottom: 1px;" {
                            (label)
                        }
                    } @else {
                        a href=(user_traffic_href(uid, w.slug, selected_server))
                          style="color: var(--mute); text-decoration: none; border-bottom: 1px dotted var(--mute); padding-bottom: 1px;" {
                            (label)
                        }
                    }
                }
            }
        }
        form method="get" action=(base)
             style="display: flex; flex-wrap: wrap; gap: 12px; align-items: end; margin: 0 0 16px; padding: 10px 14px; border: 1px solid var(--rule); border-top: 0; background: var(--paper);" {
            input type="hidden" name="vpn_window" value=(active_slug);
            label style="display: grid; gap: 4px; font-family: var(--mono); font-size: 10px; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase;" {
                (tr(lang, "Node", "Нода"))
                select name="vpn_server" style="min-width: 180px; padding: 4px 8px; border: 1px solid var(--rule-s); background: var(--paper); color: var(--ink); font-family: var(--mono); font-size: 12px;" {
                    option value="" selected[selected_server.is_none()] { (tr(lang, "all nodes", "все ноды")) }
                    @for (sid, label) in servers {
                        option value=(sid.as_str()) selected[selected_server == Some(sid.as_str())] { (label) }
                    }
                }
            }
            button type="submit"
                   style="padding: 4px 12px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                (tr(lang, "apply", "применить"))
            }
            @if selected_server.is_some() {
                a href=(user_traffic_href(uid, active_slug, None))
                  style="font-family: var(--mono); font-size: 11px; color: var(--mute); text-decoration: none; border-bottom: 1px dotted var(--mute); padding-bottom: 1px;" {
                    (tr(lang, "clear node", "сбросить ноду"))
                }
            }
            span style="font-family: var(--serif); font-style: italic; color: var(--mute); font-size: 11px; margin-left: auto;" {
                (tr(
                    lang,
                    "Graph, table and totals below share this period and node selection. Fixed windows roll back from now; the oldest partial bucket is included.",
                    "График, таблица и итоги ниже используют один период и выбранную ноду. Фиксированные окна отсчитываются назад от текущего момента; самый старый неполный интервал включён.",
                ))
            }
        }
    }
}

pub(crate) async fn live_vpn_stats_section(
    state: &AppState,
    uid: &vpnctl_core::UserId,
    window_slug: Option<&str>,
    server_slug: Option<&str>,
    lang: Locale,
) -> Markup {
    let window = pick_vpn_sparkline_window(window_slug);
    let selected_server = server_slug.map(str::trim).filter(|value| !value.is_empty());
    let since_hours = if window.slug == "all" {
        u32::MAX
    } else {
        window.cells * window.bucket_hours
    };
    let (all_rows, load_failed) = match state.inv.recent_vpn_stats_for_user(uid, since_hours).await
    {
        Ok(rows) => (rows, false),
        Err(e) => {
            tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "recent_vpn_stats_for_user failed");
            (Vec::new(), true)
        }
    };

    let (all_servers, coefficients_failed) = match state.inv.list_servers().await {
        Ok(servers) => (servers, false),
        Err(e) => {
            tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "list_servers (traffic selector) failed");
            (Vec::new(), true)
        }
    };
    let coefficients: BTreeMap<String, f64> = all_servers
        .iter()
        .filter(|server| server.usage_coefficient.is_finite())
        .map(|server| (server.id.0.clone(), server.usage_coefficient))
        .collect();
    let mut option_ids: BTreeSet<String> =
        all_rows.iter().map(|row| row.server_id.0.clone()).collect();
    if let Ok(granted) = state.inv.servers_for_user(uid).await {
        option_ids.extend(granted.into_iter().map(|server| server.id.0));
    }
    if let Some(selected) = selected_server {
        option_ids.insert(selected.to_string());
    }
    let server_options: Vec<(String, String)> = option_ids
        .into_iter()
        .map(|id| {
            let label = coefficients.get(&id).map_or_else(
                || id.clone(),
                |coefficient| {
                    if (*coefficient - 1.0).abs() > f64::EPSILON {
                        format!("{id} · ×{coefficient:.2}")
                    } else {
                        id.clone()
                    }
                },
            );
            (id, label)
        })
        .collect();

    let rows: Vec<vpnctl_inventory::VpnStatsRow> = all_rows
        .into_iter()
        .filter(|row| selected_server.is_none_or(|server| row.server_id.0 == server))
        .collect();
    let chart = vpn_chart_window(window, &rows);
    let (total_up, total_dn, peak_conns) = chart_totals(&rows, chart);
    let mut per_server: BTreeMap<String, (u64, u64, u32)> = BTreeMap::new();
    for row in &rows {
        if chart.bucket_index(row.ts.timestamp()).is_none() {
            continue;
        }
        let entry = per_server.entry(row.server_id.0.clone()).or_default();
        entry.0 = entry.0.saturating_add(row.upload_bytes);
        entry.1 = entry.1.saturating_add(row.download_bytes);
        entry.2 = entry.2.max(row.active_connections);
    }
    let mut weighted_by_server: BTreeMap<String, u64> = BTreeMap::new();
    for (server, (up, down, _)) in &per_server {
        if let Some(coefficient) = coefficients.get(server).copied() {
            weighted_by_server.insert(server.clone(), weighted_bytes(*up, *down, coefficient));
        }
    }
    let mut weighted_total_value = 0.0_f64;
    let mut charged_available = !coefficients_failed;
    for row in &rows {
        if chart.bucket_index(row.ts.timestamp()).is_none() {
            continue;
        }
        let Some(coefficient) = coefficients.get(&row.server_id.0).copied() else {
            charged_available = false;
            continue;
        };
        weighted_total_value += (row.upload_bytes as f64 + row.download_bytes as f64) * coefficient;
    }
    // Truncate once after summing, matching the monthly SQL's CAST(SUM(...)).
    let weighted_total = charged_available.then(|| bytes_from_f64(weighted_total_value));
    let has_window_rows = rows
        .iter()
        .any(|row| chart.bucket_index(row.ts.timestamp()).is_some());
    let snapshot_count = rows
        .iter()
        .filter(|row| chart.bucket_index(row.ts.timestamp()).is_some())
        .count();

    let window_label = match lang {
        Locale::En => window.label_en,
        Locale::Ru => window.label_ru,
    };
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow {
            (tr(lang, "Live VPN stats · ", "Живая статистика VPN · "))
            (window_label)
            @if let Some(server) = selected_server {
                " · " (server)
            }
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 0;" {
            (tr(
                lang,
                "Measured traffic comes from the nodes’ per-user counters. Charged traffic includes each node’s multiplier and counts toward the user’s monthly limit.",
                "Фактический трафик берётся из счётчиков пользователя на узлах. В месячный лимит он засчитывается с учётом коэффициента каждого узла.",
            ))
        }
        (user_traffic_controls(
            &uid.0,
            window.slug,
            selected_server,
            &server_options,
            lang,
        ))
        @if load_failed {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute);" {
                (tr(lang, "(temporarily unavailable — please retry)", "(временно недоступно — повтори попытку)"))
            }
        } @else if !has_window_rows {
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
                (tr(lang, "No traffic samples for this selection. Choose another period or check the node’s status.", "Для выбранного периода и узла нет измерений. Выберите другой период или проверьте состояние узла.")) " "
                @if let Some(node) = selected_server {
                    a href=(format!("/admin/servers/{}/status", path_segment_encode(node))) {
                        (tr(lang, "Open node status", "Состояние узла"))
                    }
                } @else {
                    a href="/admin/servers" { (tr(lang, "View servers", "К серверам")) }
                }
            }
        } @else {
            div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; margin: 12px 0 18px;" {
                (status_tile(tr(lang, "uploaded (measured)", "Отправлено"), &humanize_bytes(total_up), "var(--ink)"))
                (status_tile(tr(lang, "downloaded (measured)", "Получено"), &humanize_bytes(total_dn), "var(--ink)"))
                (status_tile(tr(lang, "total (measured)", "Фактический трафик"), &humanize_bytes(total_up.saturating_add(total_dn)), "var(--ink)"))
                (status_tile(tr(lang, "charged (weighted)", "В зачёт лимита"), &weighted_total.map(humanize_bytes).unwrap_or_else(|| "—".into()), "var(--ink)"))
                (status_tile(tr(lang, "peak conns", "Пик подключений"), &peak_conns.to_string(), "var(--ink)"))
            }
            @if !charged_available {
                p role="status" style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--acc); margin: -4px 0 14px;" {
                    (tr(
                        lang,
                        "Charged totals unavailable: a node usage coefficient could not be read. Measured bytes are unaffected.",
                        "Начисленные итоги недоступны: не удалось прочитать коэффициент узла. Фактические байты показаны без изменений.",
                    ))
                }
            }
            @let trend = vpn_traffic_trend_series(&rows, chart);
            @if trend.iter().any(|&v| v > 0.0) {
                @let trend_max = trend.iter().copied().fold(0.0_f64, f64::max);
                div style="margin: 6px 0 18px;" {
                    div style="font-family: var(--mono); font-size: 10px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--mute); margin-bottom: 2px;" {
                        (tr(lang, "traffic trend · ", "тренд трафика · ")) (window_label)
                        @if let Some(server) = selected_server {
                            " · " (server)
                        }
                    }
                    (sparkline_svg_scaled(&trend, 1160, 60, None, false))
                    div style="font-family: var(--mono); font-size: 10px; color: var(--mute);" {
                        (tr(lang, "max ", "макс ")) (humanize_bytes(trend_max as u64))
                        (tr(lang, " per bucket", " на интервал"))
                    }
                }
            }
            @if !per_server.is_empty() {
                div.ed-traffic-table tabindex="0" role="region" aria-label=(tr(lang, "Traffic by node", "Расход по узлам")) {
                    table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11px;" {
                        thead {
                            tr style="border-bottom: 1px solid var(--ink);" {
                                th style="text-align: left; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { (tr(lang, "server", "сервер")) }
                                th title=(tr(
                                    lang,
                                    "Raw upload-byte deltas from the nodes' per-user accounting counters over the picked period. Counts everything the node attributes to this user's auth — VLESS, TUIC, Trojan; WireGuard is not visible to these counters.",
                                    "Сырые upload-дельты из счётчиков пользователя на узлах за выбранный период. Учитывается всё, что узел относит к auth этого юзера — VLESS, TUIC, Trojan; WireGuard этим счётчикам не виден.",
                                ))
                                   style="text-align: right; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { (tr(lang, "uploaded · measured", "отправлено · измерено")) }
                                th title=(tr(lang, "Same period + same caveats as uploaded — download direction, measured bytes.", "Тот же период и те же оговорки, что и у «отправлено» — направление download, измеренные байты."))
                                   style="text-align: right; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { (tr(lang, "downloaded · measured", "принято · измерено")) }
                                th style="text-align: right; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { (tr(lang, "total · measured", "всего · измерено")) }
                                th title=(tr(
                                    lang,
                                    "Measured traffic for the selected period, multiplied by this node’s usage coefficient. The monthly balance above includes all nodes.",
                                    "Трафик за выбранный период с учётом коэффициента узла. Выше показан расход за календарный месяц по всем узлам.",
                                ))
                                   style="text-align: right; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { (tr(lang, "charged · weighted", "начислено · взвешено")) }
                                th title=(tr(
                                    lang,
                                    "Maximum simultaneous active connections seen for this user during any 5-min poll window. >50 from a phone client = unusual (chat apps + browser keep ~5-15 sustained); >200 typically means torrent / web-crawler.",
                                    "Максимум одновременных соединений юзера в любом 5-минутном окне поллера. >50 с телефона — необычно (мессенджеры + браузер держат ~5-15); >200 — обычно торрент / краулер.",
                                ))
                                   style="text-align: right; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { (tr(lang, "peak conns", "пик соед.")) }
                            }
                        }
                        tbody {
                            @for (server_id, (up, dn, conns)) in &per_server {
                                @let total = up.saturating_add(*dn);
                                @let weighted = weighted_by_server
                                    .get(server_id)
                                    .map(|bytes| humanize_bytes(*bytes))
                                    .unwrap_or_else(|| "—".into());
                                tr style="border-bottom: 1px dotted var(--rule);" {
                                    td style="padding: 5px 8px; color: var(--ink);" {
                                        a href=(format!("/admin/servers/{}/activity?vpn_window={}#server-traffic", path_segment_encode(server_id), window.slug))
                                          style="color: var(--ink); border-bottom: 1px dotted var(--ink); text-decoration: none;" {
                                            (server_id)
                                        }
                                    }
                                    td style="padding: 5px 8px; text-align: right; color: var(--ink);" { (humanize_bytes(*up)) }
                                    td style="padding: 5px 8px; text-align: right; color: var(--ink);" { (humanize_bytes(*dn)) }
                                    td style="padding: 5px 8px; text-align: right; color: var(--ink); font-weight: 600;" { (humanize_bytes(total)) }
                                    td style="padding: 5px 8px; text-align: right; color: var(--ink);" { (weighted) }
                                    td style="padding: 5px 8px; text-align: right; color: var(--ink);" { (conns) }
                                }
                            }
                        }
                    }
                }
            }
            div id="vpn-traffic" {
                (vpn_traffic_chart(&rows, chart, window, lang))
            }
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin-top: 10px;" {
                (tr(lang, "Aggregated from ", "Агрегировано из ")) (snapshot_count)
                @if snapshot_count == 1 {
                    (tr(lang, " snapshot", " снэпшота"))
                } @else {
                    (tr(lang, " snapshots", " снэпшотов"))
                }
                (tr(
                    lang,
                    " over the selected period. Rows are auto-purged after 32 days.",
                    " за выбранный период. Строки автоудаляются через 32 дня.",
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row_at(ts: i64, up: u64, down: u64) -> vpnctl_inventory::VpnStatsRow {
        vpnctl_inventory::VpnStatsRow {
            ts: chrono::DateTime::from_timestamp(ts, 0).unwrap_or_else(Utc::now),
            server_id: vpnctl_core::ServerId("s1".into()),
            user_id: None,
            upload_bytes: up,
            download_bytes: down,
            active_connections: 1,
        }
    }

    #[test]
    fn all_window_includes_the_oldest_retained_bucket() {
        let now = Utc::now().timestamp();
        let rows = vec![row_at(now - 1500 * 86_400, 100, 200)];
        let all_window = pick_vpn_sparkline_window(Some("all"));
        let chart = vpn_chart_window_at(all_window, &rows, now);
        assert!(
            chart.cells > 30,
            "all must expand beyond the old thirty-month cap"
        );
        let trend = vpn_traffic_trend_series(&rows, chart);
        assert!(trend.iter().any(|value| *value > 0.0));
        let bounded = vpn_chart_window_at(pick_vpn_sparkline_window(Some("24h")), &rows, now);
        assert_eq!(bounded.cells, 24);
        assert_eq!(bounded.bucket_hours, 1);
    }

    #[test]
    fn chart_cells_and_totals_include_the_oldest_partial_interval_once() {
        let now = 1_700_000_000;
        let oldest_partial = now - 24 * 3600 + 1800;
        let rows = vec![
            row_at(oldest_partial, 10, 20),
            row_at(now - 3600, 3, 4),
            row_at(now - 25 * 3600, 900, 900),
        ];
        let chart = vpn_chart_window_at(pick_vpn_sparkline_window(Some("24h")), &rows, now);
        assert_eq!(chart.cells, 24);
        assert_eq!(chart.bucket_index(oldest_partial), Some(0));
        assert_eq!(chart.bucket_index(now - 25 * 3600), None);

        let (up, down, _) = chart_totals(&rows, chart);
        assert_eq!((up, down), (13, 24));
        let (up_cells, down_cells) = vpn_traffic_cells(&rows, chart);
        assert_eq!(up_cells.iter().sum::<u64>(), up);
        assert_eq!(down_cells.iter().sum::<u64>(), down);
        assert_eq!(
            vpn_traffic_trend_series(&rows, chart).iter().sum::<f64>(),
            37.0
        );
    }

    #[test]
    fn traffic_limit_display_round_trips_sub_gib_caps() {
        assert_eq!(format_limit_gib(50 * 1024 * 1024), "0.048828125");
        assert_eq!(format_limit_gib(5 * 1_073_741_824), "5.0");
        assert_eq!(format_limit_gib(1_073_741_824 + 536_870_912), "1.5");
    }
}
