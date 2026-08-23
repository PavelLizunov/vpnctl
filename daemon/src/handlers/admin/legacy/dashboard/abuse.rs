use maud::{Markup, html};

use crate::http_util::path_segment_encode;

const SHARING_WINDOW_DAYS: u32 = 30;
const IMPOSSIBLE_TRAVEL_HOURS: f64 = 2.0;

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

pub(super) async fn load_likely_shared(
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
pub(super) fn dashboard_abuse_summary(
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

pub(super) fn sharing_review(
    all: &[(vpnctl_core::UserId, crate::sharing_score::SharingScore)],
    query: &super::render::DashboardQuery,
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
