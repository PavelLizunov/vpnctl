use std::collections::HashMap;

use chrono::{Duration, Utc};
use maud::{Markup, html};

use crate::AppState;
use crate::handlers::admin::helpers::{
    enrich_destination_label, extract_ip_from_label, format_msk,
};
use crate::http_util::path_segment_encode;
use crate::i18n::{Locale, tr};

/// Phase 5c — «Когда была активна» session timeline. Builds an
/// implicit «active from-to» window per (user, server) from the
/// 5-min clash-poll observations: consecutive ticks extend the
/// session; a gap > 15 minutes closes it. Empty until the
/// poller has run at least one tick post-Phase-5c deploy.
pub(crate) async fn user_sessions_section(
    state: &AppState,
    uid: &vpnctl_core::UserId,
    lang: Locale,
) -> Markup {
    const LIMIT: i64 = 20;
    let rows = state
        .inv
        .recent_sessions_for_user(uid, LIMIT)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "recent_sessions_for_user failed");
            Vec::new()
        });
    // TT-4: a session is "live" if its last tick landed within ~one
    // poll interval (5-min poll + slack) of now.
    let now = Utc::now();
    let live_cutoff = Duration::minutes(6);
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow {
            (tr(lang, "Sessions · recent 20", "Сессии · последние 20"))
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            (tr(
                lang,
                "Implicit «active from-to» windows per (user, server), newest activity first. Derived from 5-min clash-poll observations: consecutive ticks extend the session; a gap >15 minutes closes it and the next tick opens a new row. Because activity is sampled every 5 minutes, a window seen in a single tick renders «≤5m» (real duration unknown below that granularity). Peak conns shows the busiest snapshot during the session.",
                "Окна «активна с-по» на (юзер, сервер), свежая активность сверху. Источник — 5-минутные тики clash-poll: последовательные тики расширяют сессию, пропуск >15 минут закрывает её, следующий тик открывает новую. Активность сэмплится раз в 5 минут, поэтому окно, увиденное одним тиком, показывается как «≤5m» (точная длительность ниже этой гранулярности неизвестна). Peak conns — самый загруженный snapshot в этой сессии.",
            ))
        }
        @if rows.is_empty() {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute);" {
                (tr(
                    lang,
                    "No sessions yet. The poller writes one row per (user, server, activity window) — wait for the next clash-api scrape.",
                    "Сессий ещё нет. Поллер пишет одну запись на (юзер, сервер, окно активности) — подожди следующий скрейп clash-api.",
                ))
            }
        } @else {
            table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11px;" {
                thead {
                    tr style="border-bottom: 1px solid var(--ink);" {
                        th style="text-align: left; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                            (tr(lang, "server", "сервер"))
                        }
                        th style="text-align: left; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                            (tr(lang, "started", "началось"))
                        }
                        th style="text-align: left; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                            (tr(lang, "last seen", "последний"))
                        }
                        th style="text-align: right; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                            (tr(lang, "duration", "длительность"))
                        }
                        th style="text-align: right; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;"
                           title=(tr(lang, "Max active_connections observed across all 5-min ticks within the session.", "Max active_connections по всем 5-минутным тикам внутри сессии.")) {
                            (tr(lang, "peak conns", "макс. соед."))
                        }
                    }
                }
                tbody {
                    @for r in &rows {
                        @let dur = r.duration();
                        @let mins = dur.num_minutes().max(0);
                        // TT-4: single-tick windows (started==last_seen)
                        // are «≤5m» not the misleading «0m» — the user
                        // WAS active, we just can't resolve below the
                        // 5-min poll granularity.
                        @let dur_str = if mins == 0 {
                            "≤5m".to_string()
                        } else if mins >= 60 {
                            format!("{}h{:02}m", mins / 60, mins % 60)
                        } else {
                            format!("{mins}m")
                        };
                        @let is_live = now.signed_duration_since(r.last_seen) < live_cutoff;
                        tr style=(if is_live { "border-bottom: 1px dotted var(--rule); background: color-mix(in oklab, var(--green) 7%, var(--paper));" } else { "border-bottom: 1px dotted var(--rule);" }) {
                            td style="padding: 4px 8px;" {
                                a href=(format!("/admin/servers/{}", path_segment_encode(&r.server_id.0))) style="color: var(--ink); text-decoration: none;" { (r.server_id.0) }
                            }
                            td style="padding: 4px 8px;" { (format_msk(r.started_at)) }
                            td style="padding: 4px 8px;" {
                                (format_msk(r.last_seen))
                                @if is_live {
                                    " " span style="color: var(--green); font-weight: 600;" {
                                        "● " (tr(lang, "live", "активна"))
                                    }
                                }
                            }
                            td style="padding: 4px 8px; text-align: right; font-weight: 500;" { (dur_str) }
                            td style="padding: 4px 8px; text-align: right;" { (r.conn_count_peak) }
                        }
                    }
                }
            }
        }
    }
}

/// Phase 5b — «Куда ходит этот юзер» section. Top destinations
/// over the last 7 days, ranked by hit count (number of 5-min
/// clash-poll ticks where the pair was observed). Empty until
/// the poller has run at least one tick post-Phase-5b deploy.
pub(crate) async fn user_top_destinations_section(
    state: &AppState,
    uid: &vpnctl_core::UserId,
    lang: Locale,
) -> Markup {
    const TOP_N: u32 = 20;
    const WINDOW_DAYS: u32 = 7;
    let rows = state
        .inv
        .top_destinations_for_user(uid, WINDOW_DAYS, TOP_N)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "top_destinations_for_user failed");
            Vec::new()
        });

    // Phase 5d: enrich bare-IP labels via `dns_ptr_cache`. The
    // poller writes `IP:port` when sing-box's metadata.host was
    // empty (most TCP-to-IP traffic); the resolver background
    // job populates `dns_ptr_cache` separately. At render time we
    // bulk-lookup so each row that's still a bare IP can be shown
    // as `hostname:port (ip)` — matching the format
    // `snapshot_cache::aggregate_by_destination` uses on the
    // server-detail page (one canonical render shape for both).
    let mut ip_candidates: Vec<String> = rows
        .iter()
        .filter_map(|r| extract_ip_from_label(&r.destination_label).map(str::to_owned))
        .collect();
    ip_candidates.sort();
    ip_candidates.dedup();
    let dns_map = if ip_candidates.is_empty() {
        HashMap::new()
    } else {
        state
            .inv
            .lookup_dns_ptr_bulk(&ip_candidates)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "lookup_dns_ptr_bulk failed");
                HashMap::new()
            })
    };

    html! {
        div.ed-rule {}
        div.ed-art-eyebrow {
            (tr(lang, "Top destinations · last 7 days", "Топ destinations · 7 дней"))
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            (tr(
                lang,
                "Which hosts this user connects to most often. Derived from clash-api snapshots (one hit per 5-minute tick where a connection to that destination was active). Reverse-DNS resolved when possible (Phase 5a-2 cache).",
                "На какие хосты юзер ходит чаще всего. Источник — snapshot'ы clash-api (один hit на 5-минутный тик, в котором соединение к этому destination было активно). Reverse-DNS подставляется когда возможно (Phase 5a-2 cache).",
            ))
        }
        @if rows.is_empty() {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute);" {
                (tr(
                    lang,
                    "No destination history yet. The poller writes one hit per (destination, 5-min tick) — wait for the next clash-api scrape to fill this section.",
                    "Истории destinations ещё нет. Поллер пишет один hit на (destination, 5-минутный тик) — подожди следующий скрейп clash-api.",
                ))
            }
        } @else {
            table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11px;" {
                thead {
                    tr style="border-bottom: 1px solid var(--ink);" {
                        th style="text-align: left; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                            (tr(lang, "destination", "destination"))
                        }
                        th style="text-align: right; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;"
                           title=(tr(lang, "Number of 5-min ticks where a connection to this destination was alive. Not connection count — a long-lived connection contributes N hits, N = ticks-it-was-up.", "Число 5-мин тиков, в которых соединение к этому destination было активно. Не число соединений — долгое соединение даёт N hits, N = тиков-сколько-жило.")) {
                            (tr(lang, "hits · 7d", "hits · 7д"))
                        }
                        th style="text-align: right; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                            (tr(lang, "last seen", "последний раз"))
                        }
                    }
                }
                tbody {
                    @for r in &rows {
                        tr style="border-bottom: 1px dotted var(--rule);" {
                            td style="padding: 4px 8px; overflow-wrap: anywhere;" {
                                (enrich_destination_label(&r.destination_label, &dns_map))
                            }
                            td style="padding: 4px 8px; text-align: right; font-weight: 500;" { (r.hit_count) }
                            td style="padding: 4px 8px; text-align: right; color: var(--mute);" {
                                (format_msk(r.last_seen))
                            }
                        }
                    }
                }
            }
        }
    }
}
