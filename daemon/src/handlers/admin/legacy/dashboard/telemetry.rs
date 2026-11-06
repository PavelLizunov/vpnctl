use crate::handlers::admin::icons::icon;
use maud::{Markup, html};

use crate::handlers::admin::helpers::humanize_bytes;
use crate::handlers::admin::legacy::user_sections::VpnSparklineWindow;
use crate::http_util::path_segment_encode;

pub(in crate::handlers::admin::legacy) fn humanize_age(
    d: chrono::Duration,
    lang: crate::i18n::Locale,
) -> String {
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
                "Top-N by sum of (upload+download bytes) across all servers in the selected window. Data source: clash-api 5-minute polls. WireGuard traffic NOT included (kernel-level, no clash-api visibility); only sing-box-mediated protocols (VLESS, TUIC, Trojan, Hysteria2, AnyTLS, Shadowsocks-2022) appear here.",
                "Топ-N по сумме (upload+download байт) на всех серверах за выбранное окно. Источник: 5-минутные опросы clash-api. Трафик WireGuard НЕ учитывается (kernel-уровень, clash-api их не видит); только протоколы которые видит sing-box (VLESS, TUIC, Trojan, Hysteria2, AnyTLS, Shadowsocks-2022).",
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
                            (icon("arrow-up")) (tr(lang, "Upload", "Отдача"))
                        }
                        th style="text-align: right; padding: 4px 10px; font-weight: 600;" {
                            (icon("arrow-down")) (tr(lang, "Download", "Приём"))
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
            let y = 2.0 + h - (v / scale).min(1.0) * h;
            format!("{x:.1},{y:.1}")
        })
        .collect::<Vec<_>>()
        .join(" ");
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
                text x=(width - 4) y="14"
                     text-anchor="end"
                     style="font-family: var(--mono); font-size: 10px; fill: var(--mute);" {
                    "max " (data_max.round() as u64)
                }
            }
        }
    }
}
