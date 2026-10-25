use std::collections::BTreeMap;

use crate::handlers::admin::icons::icon;
use chrono::{Datelike, DurationRound, TimeDelta, Utc};
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

pub(in crate::handlers::admin::legacy) fn fit_vpn_sparkline_window(
    mut window: VpnSparklineWindow,
    rows: &[vpnctl_inventory::VpnStatsRow],
) -> VpnSparklineWindow {
    if window.slug == "all" {
        let bucket_seconds = i64::from(window.bucket_hours) * 3600;
        if let Ok(now) = Utc::now().duration_trunc(TimeDelta::seconds(bucket_seconds)) {
            // Truncate like vpn_traffic_trend_series does, or the oldest row
            // lands one bucket past the last cell.
            let oldest = rows
                .iter()
                .map(|row| row.ts)
                .min()
                .and_then(|ts| ts.duration_trunc(TimeDelta::seconds(bucket_seconds)).ok())
                .unwrap_or(now);
            let cells = (now - oldest).num_seconds().max(0) / bucket_seconds + 1;
            window.cells = window.cells.max(u32::try_from(cells).unwrap_or(u32::MAX));
        }
    }
    window
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

fn x_axis_tick_label(t: chrono::DateTime<Utc>, bucket_hours: u32) -> String {
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
    window: VpnSparklineWindow,
) -> Vec<f64> {
    let cells = window.cells as usize;
    let bucket_seconds = window.bucket_hours as i64 * 3600;
    let now = match Utc::now().duration_trunc(TimeDelta::seconds(bucket_seconds)) {
        Ok(t) => t,
        Err(_) => return vec![0.0; cells],
    };
    let mut per_cell: Vec<u64> = vec![0; cells];
    for r in rows {
        let row_t = match r.ts.duration_trunc(TimeDelta::seconds(bucket_seconds)) {
            Ok(t) => t,
            Err(_) => continue,
        };
        let buckets_ago = now.signed_duration_since(row_t).num_seconds() / bucket_seconds;
        if !(0..cells as i64).contains(&buckets_ago) {
            continue;
        }
        let idx = (cells as i64 - 1 - buckets_ago) as usize;
        per_cell[idx] =
            per_cell[idx].saturating_add(r.upload_bytes.saturating_add(r.download_bytes));
    }
    per_cell.into_iter().map(|v| v as f64).collect()
}

pub(in crate::handlers::admin::legacy) fn vpn_traffic_chart(
    rows: &[vpnctl_inventory::VpnStatsRow],
    window: VpnSparklineWindow,
    lang: Locale,
) -> Markup {
    let per_bucket = match lang {
        Locale::En => window.per_bucket_en,
        Locale::Ru => window.per_bucket_ru,
    };
    let cells = window.cells as usize;
    let bucket_seconds = window.bucket_hours as i64 * 3600;
    let now = match Utc::now().duration_trunc(TimeDelta::seconds(bucket_seconds)) {
        Ok(t) => t,
        Err(_) => return html! {},
    };
    let mut up_per_cell: Vec<u64> = vec![0; cells];
    let mut dn_per_cell: Vec<u64> = vec![0; cells];
    for r in rows {
        let row_t = match r.ts.duration_trunc(TimeDelta::seconds(bucket_seconds)) {
            Ok(t) => t,
            Err(_) => continue,
        };
        let diff = now.signed_duration_since(row_t);
        let buckets_ago = diff.num_seconds() / bucket_seconds;
        if !(0..cells as i64).contains(&buckets_ago) {
            continue;
        }
        let idx = (cells as i64 - 1 - buckets_ago) as usize;
        up_per_cell[idx] = up_per_cell[idx].saturating_add(r.upload_bytes);
        dn_per_cell[idx] = dn_per_cell[idx].saturating_add(r.download_bytes);
    }
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
        let bucket_start =
            now - chrono::Duration::seconds((cells as i64 - 1 - i as i64) * bucket_seconds);
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
        let bucket_start =
            now - chrono::Duration::seconds((cells as i64 - 1 - i as i64) * bucket_seconds);
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
                    "→ all charts + tiles below update together (custom date range — coming next)",
                    "→ все графики и плитки ниже обновляются вместе (произвольный диапазон дат — в следующем релизе)",
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
) -> Markup {
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
                        "Total upload + download this calendar month vs. the configured monthly cap. Alert fires at ",
                        "Суммарно upload + download за календарный месяц vs. настроенный месячный лимит. Алерт срабатывает при ",
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
                    (tr(lang, "Used this month: ", "Использовано в этом месяце: "))
                    span.ed-mono { (humanize_bytes(used)) }
                    (tr(lang, " — no monthly cap configured. Set one below to get the ", " — месячный лимит не задан. Задай ниже, чтобы получать "))
                    span.ed-mono { (DEFAULT_TRAFFIC_THRESHOLD_PCT) "%-" (tr(lang, "of-limit alert", "от-лимита алерт")) }
                    (tr(lang, " on the dashboard.", " на дашборде."))
                }
            }
        }

        form method="post"
             action=(format!("/admin/users/{}/traffic-limit", path_segment_encode(&uid.0)))
             style="display: flex; gap: 10px; align-items: baseline; flex-wrap: wrap; padding: 10px 12px; background: var(--paper); border: 1px solid var(--rule);" {
            input type="hidden" name="limit_loaded" value="1";
            label style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase;" {
                (tr(lang, "limit", "лимит"))
            }
            @let limit_gib_value = limit_opt
                .map(|b| format!("{:.1}", b as f64 / 1_073_741_824.0))
                .unwrap_or_default();
            input type="number" name="limit_gib" step="0.1" min="0" max="100000"
                  value=(limit_gib_value)
                  placeholder=(tr(lang, "no cap", "нет лимита"))
                  title=(tr(
                      lang,
                      "Monthly cap in GiB (upload + download summed). 0 / empty = no cap. Resets on the first of each month.",
                      "Месячный лимит в GiB (upload + download суммой). 0 / пусто = без лимита. Сбрасывается первого числа месяца.",
                  ))
                  style="max-width: 80px; padding: 4px 8px; border: 1px solid var(--rule-s); background: var(--paper); font-family: var(--mono); font-size: 12px; color: var(--ink);";
            span style="font-family: var(--mono); font-size: 11px; color: var(--mute);" { (tr(lang, "GiB / month", "GiB / месяц")) }
            label style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase; margin-left: 8px;" {
                (tr(lang, "alert at", "алерт при"))
            }
            input type="number" name="threshold_pct" step="1" min="1" max="100"
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

pub(crate) async fn live_vpn_stats_section(
    state: &AppState,
    uid: &vpnctl_core::UserId,
    window_slug: Option<&str>,
    lang: Locale,
) -> Markup {
    let window = pick_vpn_sparkline_window(window_slug);
    let since_hours = if window.slug == "all" {
        u32::MAX
    } else {
        window.cells * window.bucket_hours
    };
    let rows = match state.inv.recent_vpn_stats_for_user(uid, since_hours).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "recent_vpn_stats_for_user failed");
            return html! {
                div.ed-rule {}
                div.ed-art-eyebrow { (tr(lang, "Live VPN stats", "Живая статистика VPN")) }
                p style="font-family: var(--serif); font-style: italic; color: var(--mute);" {
                    (tr(lang, "(temporarily unavailable — please retry)", "(временно недоступно — повтори попытку)"))
                }
            };
        }
    };
    if rows.is_empty() {
        return html! {
            div.ed-rule {}
            div.ed-art-eyebrow { (t(lang, K::EyebrowLiveStats)) }
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
                (tr(
                    lang,
                    "No live stats yet. The clash-api poller runs every 5 minutes — blank means no snapshot has covered this user yet: the node may be unreachable over SSH, its sing-box may lack the clash-api block, or the user hasn't connected. The poller needs the SSH key on the vpnctld host's ",
                    "Живой статистики пока нет. Поллер clash-api снимает снэпшоты каждые 5 минут — пусто значит ни один снэпшот ещё не зацепил этого юзера: нода может быть недоступна по SSH, в её sing-box может не быть clash-api блока, либо юзер не подключался. Поллеру нужен SSH-ключ на хосте vpnctld в ",
                ))
                span.ed-mono { "/var/lib/vpnctl/.ssh" }
                (tr(
                    lang,
                    " plus per-node authorisation. Once wired, this section will show real per-user upload/download totals and active connection counts.",
                    " плюс авторизация на каждой ноде. Когда подключим — раздел покажет реальные upload/download по пользователю и активные подключения.",
                ))
            }
        };
    }

    let window = fit_vpn_sparkline_window(window, &rows);
    let mut total_up: u64 = 0;
    let mut total_dn: u64 = 0;
    let mut peak_conns: u32 = 0;
    let mut per_server: BTreeMap<String, (u64, u64, u32)> = BTreeMap::new();
    for r in &rows {
        total_up = total_up.saturating_add(r.upload_bytes);
        total_dn = total_dn.saturating_add(r.download_bytes);
        if r.active_connections > peak_conns {
            peak_conns = r.active_connections;
        }
        let entry = per_server.entry(r.server_id.0.clone()).or_default();
        entry.0 = entry.0.saturating_add(r.upload_bytes);
        entry.1 = entry.1.saturating_add(r.download_bytes);
        if r.active_connections > entry.2 {
            entry.2 = r.active_connections;
        }
    }

    let window_label = match lang {
        Locale::En => window.label_en,
        Locale::Ru => window.label_ru,
    };
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow {
            (tr(lang, "Live VPN stats · ", "Живая VPN-статистика · "))
            (window_label)
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            (tr(
                lang,
                "Pulled from each node's clash-api by the daemon. Numbers reflect actual VPN traffic (delta-vs-prior-snapshot per tick), not subscription-config fetches.",
                "Снимается с clash-api каждой ноды демоном. Числа — реальный VPN-трафик (дельта-к-прошлому-снэпшоту на каждом тике), не запросы конфига подписки.",
            ))
        }
        div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin: 12px 0 18px;" {
            (status_tile("uploaded", &humanize_bytes(total_up), "var(--ink)"))
            (status_tile("downloaded", &humanize_bytes(total_dn), "var(--ink)"))
            (status_tile("peak conns", &peak_conns.to_string(), "var(--ink)"))
        }
        (window_picker_section(
            &format!("/admin/users/{}/traffic", path_segment_encode(&uid.0)),
            window.slug,
            lang,
        ))
        @let trend = vpn_traffic_trend_series(&rows, window);
        @if trend.iter().any(|&v| v > 0.0) {
            @let trend_max = trend.iter().copied().fold(0.0_f64, f64::max);
            div style="margin: 6px 0 18px;" {
                div style="font-family: var(--mono); font-size: 10px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--mute); margin-bottom: 2px;" {
                    (tr(lang, "traffic trend · ", "тренд трафика · ")) (window_label)
                }
                (sparkline_svg_scaled(&trend, 1160, 60, None, false))
                div style="font-family: var(--mono); font-size: 10px; color: var(--mute);" {
                    (tr(lang, "max ", "макс ")) (humanize_bytes(trend_max as u64))
                    (tr(lang, " per bucket", " на интервал"))
                }
            }
        }
        @if !per_server.is_empty() {
            table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11px;" {
                thead {
                    tr style="border-bottom: 1px solid var(--ink);" {
                        th style="text-align: left; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { (tr(lang, "server", "сервер")) }
                        th title=(tr(
                            lang,
                            "Sum of upload-bytes deltas from clash-api 5-min ticks over the picked window, weighted by each node's usage coefficient. Counts everything sing-box saw on this user's auth — VLESS, TUIC, Trojan; WireGuard NOT included (kernel-level, no clash-api visibility).",
                            "Сумма upload-дельт clash-api (тик 5 минут) за выбранное окно, взвешенная коэффициентом нагрузки ноды. Считает всё, что sing-box видел на auth этого юзера — VLESS, TUIC, Trojan; WireGuard НЕ входят (kernel-уровень, clash-api их не видит).",
                        ))
                           style="text-align: right; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { (tr(lang, "uploaded", "отправлено")) }
                        th title=(tr(lang, "Same window + same caveats as uploaded — download direction.", "То же окно и те же оговорки, что и у «отправлено» — направление download."))
                           style="text-align: right; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { (tr(lang, "downloaded", "принято")) }
                        th style="text-align: right; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { (tr(lang, "total", "всего")) }
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
                        tr style="border-bottom: 1px dotted var(--rule);" {
                            td style="padding: 5px 8px; color: var(--ink);" { (server_id) }
                            td style="padding: 5px 8px; text-align: right; color: var(--ink);" { (humanize_bytes(*up)) }
                            td style="padding: 5px 8px; text-align: right; color: var(--ink);" { (humanize_bytes(*dn)) }
                            td style="padding: 5px 8px; text-align: right; color: var(--ink); font-weight: 600;" { (humanize_bytes(up.saturating_add(*dn))) }
                            td style="padding: 5px 8px; text-align: right; color: var(--ink);" { (conns) }
                        }
                    }
                }
            }
        }
        div id="vpn-traffic" {
            (vpn_traffic_chart(&rows, window, lang))
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin-top: 10px;" {
            (tr(lang, "Aggregated from ", "Агрегировано из ")) (rows.len())
            @if rows.len() == 1 {
                (tr(lang, " snapshot", " снэпшота"))
            } @else {
                (tr(lang, " snapshots", " снэпшотов"))
            }
            (tr(
                lang,
                " over the last 24 hours. Rows are auto-purged after 32 days.",
                " за последние 24 часа. Строки автоудаляются через 32 дня.",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_window_includes_the_oldest_retained_bucket() {
        let rows = vec![vpnctl_inventory::VpnStatsRow {
            ts: Utc::now() - chrono::Duration::days(1500),
            server_id: vpnctl_core::ServerId("s1".into()),
            user_id: None,
            upload_bytes: 100,
            download_bytes: 200,
            active_connections: 1,
        }];
        let all = fit_vpn_sparkline_window(pick_vpn_sparkline_window(Some("all")), &rows);
        assert!(
            all.cells > 30,
            "all must expand beyond the old thirty-month cap"
        );
        let trend = vpn_traffic_trend_series(&rows, all);
        assert!(trend.iter().any(|value| *value > 0.0));
        let bounded = fit_vpn_sparkline_window(pick_vpn_sparkline_window(Some("24h")), &rows);
        assert_eq!(bounded.cells, 24);
        assert_eq!(bounded.bucket_hours, 1);
    }
}
