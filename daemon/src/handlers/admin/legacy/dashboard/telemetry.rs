use maud::{Markup, html};

use crate::handlers::admin::helpers::{format_msk, humanize_bytes};
use crate::handlers::admin::legacy::server_detail::status_tile;
use crate::handlers::admin::legacy::user_sections::VpnSparklineWindow;
use crate::http_util::path_segment_encode;

/// Compact "how long ago" string for the last-probe column. Buckets to
/// seconds / minutes / hours / days — the operator wants "is this
/// stale?" at a glance, not millisecond precision. Negative durations
/// (clock skew between probe write + render) clamp to «just now».
pub(in crate::handlers::admin::legacy) fn humanize_age(d: chrono::Duration, lang: crate::i18n::Locale) -> String {
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

pub(in crate::handlers::admin::legacy) fn dashboard_live_activity_from_rows(
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
pub(in crate::handlers::admin::legacy) fn dashboard_vpn_activity(
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

/// Render the "heavy users · <window>" section on the dashboard.
/// Sorted DESC by total bytes (upload + download). Empty list →
/// explanatory empty-state explaining the polling prerequisite.
pub(in crate::handlers::admin::legacy) fn dashboard_heavy_users(
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
pub(in crate::handlers::admin::legacy) fn sparkline_svg_scaled(
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
