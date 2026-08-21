//! Fleet-wide search page (`/admin/search`) — substring search across
//! users / servers / alerts with drill-through links to the canonical
//! detail pages.
//!
//! Extracted from `legacy.rs` as part of the admin submodules refactor.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use maud::{Markup, html};

use super::alerts::localized_alert;
use super::helpers::{internal_error, render_page, theme_accent_lang};
use super::users::mask_secret;
use crate::AppState;
use crate::http_util::path_segment_encode;

/// Query string for `/admin/search` — single optional `q` field.
#[derive(serde::Deserialize, Default)]
pub(crate) struct SearchQuery {
    pub q: Option<String>,
}

/// `GET /admin/search?q=foo` (A5, audit 2026-05-22, shipped 2026-05-23)
/// — fleet-wide substring search across users / servers / alerts.
/// Click any hit to drill into the canonical detail page.
///
/// Empty `q` renders a search prompt page; non-empty `q` runs three
/// independent SQL substring scans in parallel and groups the hits
/// per type. Per-group cap = 50 rows; pathological `q="a"` won't
/// drown the page in a 10k-row table.
///
/// **Audit deliberately NOT included** — the existing /admin/audit
/// page already has a filter form on actor + action + free-text via
/// the URL, and pulling audit substring search into the universal
/// `/admin/search` would duplicate that surface AND surface large
/// payload JSON snippets the operator usually doesn't want
/// mixed with «which users match X». Link to /admin/audit from the
/// search results footer instead.
pub(crate) async fn search(
    headers: HeaderMap,
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<SearchQuery>,
) -> Result<Markup, Response> {
    let (theme, accent, lang) = theme_accent_lang(&headers);
    let query_raw = q.q.unwrap_or_default();
    let query = query_raw.trim();
    /// Per-group cap; below the existing /admin/users + /admin/servers
    /// scroll-friendliness thresholds so the results page never feels
    /// heavier than the canonical lists.
    const PER_GROUP_LIMIT: i64 = 50;

    let (users, servers, alerts) = if query.is_empty() {
        (Vec::new(), Vec::new(), Vec::new())
    } else {
        let (u, s, a) = tokio::try_join!(
            state.inv.search_users(query, PER_GROUP_LIMIT),
            state.inv.search_servers(query, PER_GROUP_LIMIT),
            state.inv.search_alerts(query, PER_GROUP_LIMIT),
        )
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;
        (u, s, a)
    };

    let total_hits = users.len() + servers.len() + alerts.len();
    let body = html! {
        div.ed-art-eyebrow {
            (crate::i18n::tr(lang, "Fleet search", "Поиск по флоту"))
        }
        div.ed-headrow {
            h1.ed-sumbar__h {
                @if query.is_empty() {
                    (crate::i18n::tr(lang, "find ", "найти "))
                    em { (crate::i18n::tr(lang, "anything", "что угодно")) }
                } @else {
                    "«" (query) "» — " (total_hits) " "
                    em { (crate::i18n::tr(lang, "matches", "совпадений")) }
                }
            }
            span.ed-tip title=(crate::i18n::tr(
                lang,
                "Substring match across user ids / UUIDs / sub_tokens / device_ids, server ids / addresses, and alert kinds / summaries. Case-insensitive. Cap of 50 hits per group.",
                "Подстрочный поиск по id / UUID / sub_token / device_id пользователей, по id / адресам серверов, по kind / summary алертов. Регистронезависимо. Не больше 50 совпадений в каждой группе.",
            )) { "ⓘ" }
            @if !query.is_empty() {
                span style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                    (users.len()) " " (crate::i18n::tr(lang, "users", "польз."))
                    " · " (servers.len()) " " (crate::i18n::tr(lang, "servers", "серверов"))
                    " · " (alerts.len()) " " (crate::i18n::tr(lang, "alerts", "алертов"))
                    " · "
                    a href=(format!("/admin/audit?target={}", path_segment_encode(query))) style="color: var(--acc);" {
                        (crate::i18n::tr(lang, "audit events →", "события аудита →"))
                    }
                }
            }
        }
        form method="get" action="/admin/search"
             style="margin: 16px 0; display: flex; gap: 8px; align-items: baseline;" {
            input type="text" name="q"
                  value=(query)
                  autofocus="autofocus"
                  placeholder=(crate::i18n::tr(lang, "user id, ip, uuid, alert kind...", "id юзера, ip, uuid, kind алерта..."))
                  style="flex: 1; padding: 6px 10px; border: 1px solid var(--rule-s); background: var(--paper); font-family: var(--mono); font-size: 13px; color: var(--ink);";
            button type="submit"
                   style="padding: 6px 16px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 12px; cursor: pointer;" {
                (crate::i18n::tr(lang, "search", "искать"))
            }
        }

        @if query.is_empty() {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute); padding: 16px 0;" {
                (crate::i18n::tr(
                    lang,
                    "Type something above to begin. Hits link straight to the user / server / alert detail page.",
                    "Введи что-нибудь выше. Каждый результат — ссылка на страницу пользователя / сервера / алерта.",
                ))
            }
        } @else {
            p style="font-family: var(--mono); font-size: 11px; color: var(--mute); padding: 4px 0;" {
                (total_hits) " "
                (crate::i18n::tr(lang, "hits across ", "совпадений по "))
                (users.len()) " " (crate::i18n::tr(lang, "users · ", "юзерам · "))
                (servers.len()) " " (crate::i18n::tr(lang, "servers · ", "серверам · "))
                (alerts.len()) " " (crate::i18n::tr(lang, "alerts", "алертам"))
            }
            @if total_hits == 0 {
                p style="font-family: var(--serif); font-style: italic; color: var(--mute); padding: 16px 0;" {
                    (crate::i18n::tr(
                        lang,
                        "No matches. Audit-log searches still live on the ",
                        "Ничего не найдено. Поиск по audit-логу всё ещё на ",
                    ))
                    // Percent-encode the operator's q so a query
                    // like `foo&actor=admin` doesn't smuggle a
                    // second parameter into the fallback URL —
                    // `path_segment_encode` over-encodes (encodes
                    // `:` etc) but URLs still parse correctly.
                    a href=(format!("/admin/audit?action={}", path_segment_encode(query)))
                      style="color: var(--ink);" {
                        "/admin/audit"
                    }
                    // Honest copy (2026-06-10): the action filter is
                    // PREFIX-only — the old «accepts substrings» promise
                    // made this deep link near-useless for typical
                    // search terms.
                    (crate::i18n::tr(lang, " page (action filter is prefix-match).", " (фильтр action ищет по префиксу)."))
                }
            }
            @if !users.is_empty() {
                div.ed-art-eyebrow style="margin-top: 20px;" {
                    (crate::i18n::tr(lang, "Users", "Пользователи")) " (" (users.len()) ")"
                }
                ul style="list-style: none; padding: 0; font-family: var(--serif); font-size: 13px; line-height: 1.7;" {
                    @for u in &users {
                        li style="display: flex; gap: 10px; padding: 2px 0; border-bottom: 1px dotted var(--rule);" {
                            a href=(format!("/admin/users/{}", path_segment_encode(&u.id.0)))
                              style="color: var(--ink); text-decoration: none; border-bottom: 1px dotted var(--ink);" {
                                b { (u.id.0) }
                            }
                            span style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                                // Masked (audit 2026-06-10): the full
                                // uuid IS the VLESS credential; the
                                // users list shows a masked preview for
                                // exactly that reason — search must not
                                // be the page that leaks it whole.
                                "uuid=" (mask_secret(&u.uuid))
                                @if u.disabled {
                                    " · "
                                    span style="color: var(--acc);" {
                                        (crate::i18n::tr(lang, "PAUSED", "ПАУЗА"))
                                    }
                                }
                            }
                        }
                    }
                }
            }
            @if !servers.is_empty() {
                div.ed-art-eyebrow style="margin-top: 20px;" {
                    (crate::i18n::tr(lang, "Servers", "Серверы")) " (" (servers.len()) ")"
                }
                ul style="list-style: none; padding: 0; font-family: var(--serif); font-size: 13px; line-height: 1.7;" {
                    @for s in &servers {
                        li style="display: flex; gap: 10px; padding: 2px 0; border-bottom: 1px dotted var(--rule);" {
                            a href=(format!("/admin/servers/{}", path_segment_encode(&s.id.0)))
                              style="color: var(--ink); text-decoration: none; border-bottom: 1px dotted var(--ink);" {
                                b { (s.id.0) }
                            }
                            span style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                                (s.address) ":" (s.ssh_port)
                            }
                        }
                    }
                }
            }
            @if !alerts.is_empty() {
                div.ed-art-eyebrow style="margin-top: 20px;" {
                    (crate::i18n::tr(lang, "Alerts", "Алерты")) " (" (alerts.len()) ")"
                }
                ul style="list-style: none; padding: 0; font-family: var(--serif); font-size: 13px; line-height: 1.7;" {
                    @for a in &alerts {
                        @let rendered = localized_alert(a, lang);
                        li style="display: flex; gap: 10px; padding: 2px 0; border-bottom: 1px dotted var(--rule);" {
                            // Alert detail isn't a route yet; link to
                            // /admin/alerts where the operator can ack
                            // / dig in. Show ack-state inline so the
                            // search results immediately surface
                            // open-vs-historical context.
                            a href="/admin/alerts"
                              style="color: var(--ink); text-decoration: none; border-bottom: 1px dotted var(--ink);" {
                                b title=(a.kind) { (rendered.icon) " " (crate::alert_text::to_plain(&rendered.title)) }
                            }
                            span style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                                (a.severity) " · "
                                @if a.acked_at.is_some() {
                                    span style="color: var(--mute);" {
                                        (crate::i18n::tr(lang, "acked", "принят"))
                                    }
                                } @else {
                                    span style="color: var(--acc);" {
                                        (crate::i18n::tr(lang, "OPEN", "ОТКРЫТ"))
                                    }
                                }
                                " · " (crate::alert_text::to_plain(&rendered.body))
                            }
                        }
                    }
                }
            }
        }
    };
    Ok(render_page(&state, "search", &theme, &accent, lang, body).await)
}
