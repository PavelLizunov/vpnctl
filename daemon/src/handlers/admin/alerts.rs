//! Alerts feed (`/admin/alerts`) — the admin_alerts table with the
//! ack / ack-family / ack-all actions — plus the alert localisation
//! helper shared with the search page.
//!
//! Extracted from `legacy.rs` as part of the admin submodules refactor.

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use maud::{Markup, html};

use super::helpers::{bad_request, humanize_age, internal_error, render_page, theme_accent_lang};
use crate::AppState;
use crate::http_util::path_segment_encode;

// ────────────────────────────────────────────────────────────────────
//  Phase G — admin_alerts feed + ack action
// ────────────────────────────────────────────────────────────────────

pub(crate) async fn alerts(
    headers: HeaderMap,
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<AlertsQuery>,
) -> Result<Markup, Response> {
    let (theme, accent, lang) = theme_accent_lang(&headers);

    /// Generous cap — the feed wants enough history to spot patterns
    /// without paginating. Older rows are retention-pruned (acked
    /// >30d ago drops; unacked never).
    const ALERTS_LIMIT: i64 = 200;
    let include_acked = q.show.as_deref() == Some("all");
    let alerts_rows = state
        .inv
        .recent_alerts(ALERTS_LIMIT, include_acked)
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;
    let unacked_total = state
        .inv
        .unacked_alert_count()
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;

    // v2 5a — family split: the sub_access.* spam cluster gets its own
    // grouped table; node/fleet/user alerts the second. Counts feed the
    // header meta line.
    let (sub_rows, node_rows): (Vec<_>, Vec<_>) = alerts_rows
        .iter()
        .partition(|a| a.kind.starts_with("sub_access."));
    // The auto-resolve wording mirrors the health monitor's REAL
    // hysteresis constants (trigger 95 → recover 90 mem, 90 → 85 disk).
    let auto_resolve_note = |kind: &str| -> &'static str {
        use crate::i18n::tr;
        if kind.starts_with("server.mem.pressure") {
            tr(lang, "on drop < 90%", "при спаде < 90%")
        } else if kind.starts_with("server.disk.pressure") {
            tr(lang, "on drop < 85%", "при спаде < 85%")
        } else if kind == "server.singbox.log.too_big" {
            tr(lang, "on rotate", "после ротации")
        } else if kind.starts_with("server.unreachable") {
            tr(lang, "on next ok probe", "при следующей ok-пробе")
        } else if kind.starts_with("server.fingerprint.drift") {
            tr(lang, "on match", "при совпадении")
        } else if kind.starts_with("user.traffic_limit") {
            tr(lang, "on usage drop", "при спаде расхода")
        } else {
            tr(lang, "manual ack", "только вручную")
        }
    };
    let subject_cell = |a: &vpnctl_inventory::AdminAlert| -> Markup {
        match (&a.server_id, a.kind.split_once(':')) {
            (Some(sid), _) => html! {
                a.ed-grid__id href=(format!("/admin/servers/{}", path_segment_encode(&sid.0))) { (sid.0) }
            },
            (None, Some((_, subj))) if !subj.is_empty() => html! {
                a.ed-grid__id href=(format!("/admin/users/{}", path_segment_encode(subj))) { (subj) }
            },
            _ => html! { span.ed-grid__mut { "—" } },
        }
    };
    let ack_cell = |a: &vpnctl_inventory::AdminAlert| -> Markup {
        if a.acked_at.is_some() {
            html! { span.ed-grid__mut.ed-grid__sm { (crate::i18n::tr(lang, "acked", "принят")) } }
        } else {
            html! {
                form method="post" action=(format!("/admin/alerts/{}/ack", a.id))
                     style="margin: 0; padding: 0; display: inline;" {
                    button type="submit" class="ed-abtn ed-abtn--secondary ed-abtn--sm" { "ack" }
                }
            }
        }
    };
    let now = chrono::Utc::now();

    let body = html! {
        div.ed-art-eyebrow { (crate::i18n::t(lang, crate::i18n::K::PageAlerts)) }
        div.ed-headrow {
            h1.ed-sumbar__h {
                (unacked_total) " "
                em { (crate::i18n::noun_for(lang, unacked_total, "open alert", "open alerts", "открытый алерт", "открытых алерта", "открытых алертов")) }
            }
            span.ed-tip title=(crate::i18n::tr(
                lang,
                "Opened by the health monitor and the sub-access analyzer. Node alerts auto-resolve on recovery; sub-access alerts stay until acked. Ack is idempotent and audited; acked rows stay under «show all» for 30 days.",
                "Открываются монитором здоровья и анализатором обращений. Нодовые алерты закрываются сами при восстановлении; sub-access висят до ack. Ack идемпотентен и аудируется; принятые видны в «показать всё» 30 дней.",
            )) { "ⓘ" }
            span style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                (sub_rows.iter().filter(|a| a.acked_at.is_none()).count()) " sub-access · "
                (node_rows.iter().filter(|a| a.acked_at.is_none()).count()) " "
                (crate::i18n::tr(lang, "node", "нодовых"))
            }
            div.ed-headrow__actions {
                @if include_acked {
                    a href="/admin/alerts" style="font-family: var(--mono); font-size: 11px; color: var(--mute); text-decoration: none;" {
                        (crate::i18n::tr(lang, "← only unacked", "← только непринятые"))
                    }
                } @else {
                    a href="/admin/alerts?show=all" style="font-family: var(--mono); font-size: 11px; color: var(--mute); text-decoration: none;" {
                        (crate::i18n::tr(lang, "show all →", "показать всё →"))
                    }
                }
                @if unacked_total > 0 {
                    @let confirm_msg = crate::i18n::tr(
                        lang,
                        "Ack all unacked alerts? They will stay visible under «show all» for 30 days; nothing is deleted, just marked seen.",
                        "Принять все непринятые алерты? Они останутся видимы в «показать всё» 30 дней; ничего не удаляется, только помечается просмотренным.",
                    );
                    form method="post"
                         action="/admin/alerts/ack-all"
                         style="display: inline; margin: 0;"
                         data-confirm=(confirm_msg) {
                        button type="submit"
                               title=(crate::i18n::tr(
                                   lang,
                                   "Mark every unacked alert as seen in one click. Doesn't clear or fix the underlying conditions — just clears the dashboard tile.",
                                   "Отметить все непринятые как просмотренные одним кликом. Не чинит условия — лишь обнуляет тайл дашборда.",
                               ))
                               class="ed-abtn ed-abtn--secondary ed-abtn--sm" {
                            (crate::i18n::tr(lang, "ack all", "принять все"))
                            " (" (unacked_total) ")…"
                        }
                    }
                }
            }
        }
        @if alerts_rows.is_empty() {
            div.ed-empty {
                p {
                    @if include_acked {
                        (crate::i18n::tr(
                            lang,
                            "no alerts on record. Either the homelab has been ",
                            "ни одного алерта в записях. Либо homelab был ",
                        ))
                        em { (crate::i18n::tr(lang, "extraordinarily", "удивительно")) }
                        (crate::i18n::tr(
                            lang,
                            " quiet, or vpnctld hasn't been running long enough for the probe to fire one.",
                            " тихим, либо vpnctld запущен недостаточно долго чтобы probe что-то поймал.",
                        ))
                    } @else {
                        (crate::i18n::tr(
                            lang,
                            "no unacked alerts. Nothing means nothing's wrong (or every condition has been acknowledged). To browse history: ",
                            "нет непринятых алертов. Пусто значит всё хорошо (либо все условия приняты). Посмотреть историю: ",
                        ))
                        a href="/admin/alerts?show=all" {
                            (crate::i18n::tr(lang, "show all →", "показать всё →"))
                        }
                    }
                }
            }
        }
        @if !sub_rows.is_empty() {
            @let sub_unacked = sub_rows.iter().filter(|a| a.acked_at.is_none()).count();
            div.ed-headrow style="margin-top: 14px;" {
                div.ed-art-eyebrow {
                    "sub_access · " (sub_rows.len()) " "
                    span.ed-tip title=(crate::i18n::tr(
                        lang,
                        "A /sub fetch arrived from a private-range source IP. Usually a client refreshing over its own tunnel; occasionally a proxy hiding the real origin. Ack after review — a repeat fetch reopens.",
                        "Обращение к /sub пришло с приватного диапазона. Обычно клиент обновлялся через собственный туннель; изредка — прокси, скрывающий источник. Ack после просмотра — повторное обращение переоткроет.",
                    )) { "ⓘ" }
                }
                @if sub_unacked > 0 {
                    // v2 5a — ack the whole family in one click.
                    form.ed-headrow__actions method="post" action="/admin/alerts/ack-family/sub_access."
                         data-confirm=(crate::i18n::tr(
                             lang,
                             "Ack every unacked sub_access alert? They stay under «show all» for 30 days.",
                             "Принять все непринятые sub_access-алерты? Останутся в «показать всё» 30 дней.",
                         )) {
                        button type="submit" class="ed-abtn ed-abtn--secondary ed-abtn--sm" {
                            (crate::i18n::tr(lang, "ack all ", "принять все ")) "(" (sub_unacked) ")"
                        }
                    }
                }
            }
            // R3 2026-07-10: the detail column used to repeat the full
            // localized sentence («User X's subscription was fetched
            // from a local/proxy IP … the logged client IP will be
            // wrong») on EVERY row — the subject already names the user
            // and the ⓘ above explains the rest, so 32 rows read as one
            // paragraph copy-pasted 32×. Now: source IP + range kind +
            // UA (the datum that actually varies row-to-row), full
            // sentence still on hover.
            table.ed-grid style="margin-top: 8px;" {
                thead {
                    tr {
                        th style="width: 26px;" {}
                        th style="width: 130px;" { (crate::i18n::tr(lang, "opened", "открыт")) }
                        th style="width: 160px;" { (crate::i18n::tr(lang, "subject", "субъект")) }
                        th style="width: 150px;" { (crate::i18n::tr(lang, "source IP", "IP источника")) }
                        th { (crate::i18n::tr(lang, "client", "клиент")) }
                        th style="width: 90px;" {}
                    }
                }
                tbody {
                    @for a in &sub_rows {
                        @let fields = sub_access_detail_fields(a);
                        tr class=(if a.acked_at.is_some() { "" } else { "on-warn" }) {
                            td { span style="color: var(--warm);" { "⚠" } }
                            td.ed-grid__mut.ed-grid__sm { (humanize_age(now - a.created_at, lang)) }
                            td { (subject_cell(a)) }
                            td.ed-grid__sm title=(a.summary) {
                                (fields.0)
                                @if let Some(kind) = fields.1 {
                                    " " span.ed-grid__mut { "[" (kind) "]" }
                                }
                            }
                            td.ed-grid__mut.ed-grid__sm { (fields.2) }
                            td.num { (ack_cell(a)) }
                        }
                    }
                }
            }
        }
        @if !node_rows.is_empty() {
            div.ed-art-eyebrow style="margin-top: 14px;" {
                (crate::i18n::tr(lang, "node · fleet · user — ", "нода · флот · юзер — ")) (node_rows.len())
            }
            table.ed-grid style="margin-top: 8px;" {
                thead {
                    tr {
                        th style="width: 26px;" {}
                        th style="width: 130px;" { (crate::i18n::tr(lang, "opened", "открыт")) }
                        th style="width: 210px;" { (crate::i18n::tr(lang, "kind", "тип")) }
                        th { (crate::i18n::tr(lang, "subject · detail", "субъект · детали")) }
                        th style="width: 130px;" { (crate::i18n::tr(lang, "auto-resolve", "автозакрытие")) }
                        th style="width: 90px;" {}
                    }
                }
                tbody {
                    @for a in &node_rows {
                        @let kind_base = a.kind.split(':').next().unwrap_or(&a.kind);
                        tr class=(if a.acked_at.is_some() { "" } else if a.severity.eq_ignore_ascii_case("critical") { "on-warn" } else { "" }) {
                            td {
                                @if a.severity.eq_ignore_ascii_case("critical") {
                                    span style="color: var(--red);" { "✖" }
                                } @else {
                                    span style="color: var(--warm);" { "⚠" }
                                }
                            }
                            td.ed-grid__mut.ed-grid__sm {
                                @if a.acked_at.is_some() { (crate::i18n::tr(lang, "resolved ", "закрыт ")) }
                                (humanize_age(now - a.created_at, lang))
                            }
                            td.ed-grid__mut.ed-grid__sm { (kind_base) }
                            @let rendered = localized_alert(a, lang);
                            td.ed-grid__sm {
                                (subject_cell(a))
                                " " span.ed-grid__mut title=(crate::alert_text::to_plain(&rendered.body)) {
                                    "· " (crate::alert_text::to_plain(&rendered.title))
                                }
                                @if let Some(act) = &rendered.action {
                                    " " span.ed-grid__mut.ed-grid__sm style="font-style: italic;" {
                                        "— " (crate::alert_text::to_plain(act))
                                    }
                                }
                            }
                            td.ed-grid__mut.ed-grid__sm { (auto_resolve_note(&a.kind)) }
                            td.num { (ack_cell(a)) }
                        }
                    }
                }
            }
        }
    };
    Ok(render_page(&state, "alerts", &theme, &accent, lang, body).await)
}

/// `POST /admin/alerts/{id}/ack` — operator dismisses one alert.
/// Idempotent: re-acking is a no-op. Always redirects back to
/// `/admin/alerts` (POST-redirect-GET so refresh-after-submit doesn't
/// re-submit). Writes an audit row with the alert id + kind so the
/// timeline shows who acknowledged what.
///
/// Path/State ordering: `Path` first, `State` after — matches the
/// convention used elsewhere in this file (`user_delete`,
/// `user_grant_server`). Caught by review-agent on the burst diff.
pub(crate) async fn alert_ack(
    axum::extract::Path(id): axum::extract::Path<i64>,
    State(state): State<AppState>,
) -> Response {
    // Reject negative / zero ids early — autoincrement starts at 1.
    // Treat as a no-op redirect rather than 400 to keep ack idempotent
    // (a stale form should not 4xx; the dashboard tile POSTs without
    // re-fetching the feed first).
    if id <= 0 {
        return Redirect::to("/admin/alerts").into_response();
    }
    let changed = match state.inv.ack_alert(id).await {
        Ok(b) => b,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    if changed {
        if let Err(e) = state
            .inv
            .audit(
                "admin",
                "alert.ack",
                Some(&id.to_string()),
                Some(&serde_json::json!({"alert_id": id})),
            )
            .await
        {
            // Audit write failed but the user-visible ack already
            // committed — surface at warn so the operator can grep
            // the journal if the audit timeline looks short.
            tracing::warn!(
                target = "vpnctld::admin::alert_ack",
                alert_id = id,
                error = %e,
                "ack succeeded but audit row failed; timeline will be missing this entry"
            );
        }
    }
    Redirect::to("/admin/alerts").into_response()
}

/// `POST /admin/alerts/ack-family/{prefix}` — v2 5a: ack a whole alert
/// family (all unacked kinds under `prefix`) in one click. Only two
/// safe prefixes are accepted so the route can't be abused to ack an
/// arbitrary kind by crafting a URL: `sub_access.` and `server.`.
pub(crate) async fn alert_ack_family(
    State(state): State<AppState>,
    Path(prefix): Path<String>,
) -> Response {
    let allowed = matches!(prefix.as_str(), "sub_access." | "server.");
    if !allowed {
        return bad_request("alerts: only the sub_access. and server. families can be group-acked");
    }
    let count = match state.inv.ack_unacked_by_kind_prefix(&prefix).await {
        Ok(n) => n,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    if count > 0 {
        let _ = state
            .inv
            .audit(
                "admin",
                "alerts.ack_family",
                Some(&prefix),
                Some(&serde_json::json!({ "count": count, "prefix": prefix })),
            )
            .await;
    }
    axum::response::Redirect::to("/admin/alerts").into_response()
}

/// `POST /admin/alerts/ack-all` — operator dismisses every currently-
/// unacked alert in one go. Companion to per-row `alert_ack` for the
/// «I've triaged a backlog, clear them» workflow (fire-drill 2026-05-
/// 22: 33 `sub_access.suspicious_local_ip` alerts had accumulated
/// from legit LAN testing — clicking 33 ack buttons is a UX bug,
/// not a feature).
///
/// Idempotent — re-POSTing after everything is acked returns 0
/// rows-affected and writes NO audit row (audit-on-actual-mutation
/// convention, NM-10 review-agent rule).
///
/// Always 303s back to `/admin/alerts` so refresh-after-submit
/// can't re-submit (POST-redirect-GET).
pub(crate) async fn alert_ack_all(State(state): State<AppState>) -> Response {
    let count = match state.inv.ack_all_unacked_alerts().await {
        Ok(n) => n,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    // Audit ONLY when something actually changed. A no-op POST
    // shouldn't pollute the timeline (matches NM-10 review-agent
    // catch on `set_server_protocol_hidden` no-op-audit-spam).
    if count > 0 {
        if let Err(e) = state
            .inv
            .audit(
                "admin",
                "alerts.ack_all",
                None,
                Some(&serde_json::json!({ "count": count })),
            )
            .await
        {
            tracing::warn!(
                target = "vpnctld::admin::alert_ack_all",
                count = count,
                error = %e,
                "ack-all succeeded but audit row failed; timeline will be missing this entry"
            );
        }
    }
    Redirect::to("/admin/alerts").into_response()
}

#[derive(serde::Deserialize, Debug, Default)]
pub(crate) struct AlertsQuery {
    /// `Some("all")` = include acked rows; default = unacked only.
    pub show: Option<String>,
}

/// R3 2026-07-10 — compact detail for a `sub_access.*` alert row:
/// `(ip, ip_kind, ua)` pulled from the payload. Returns the raw IP
/// string (empty → «—»), the range-kind tag (`Some("LAN")` etc.), and
/// a short client label. The full localized sentence stays on the
/// row's `title=` hover; this replaces 32× repeated boilerplate with
/// the datum that actually varies per row (the source IP).
fn sub_access_detail_fields(a: &vpnctl_inventory::AdminAlert) -> (String, Option<String>, String) {
    let payload: Option<serde_json::Value> = a
        .payload_json
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok());
    let get = |key: &str| -> Option<String> {
        payload
            .as_ref()
            .and_then(|p| p.get(key))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty())
    };
    let ip = get("ip").unwrap_or_else(|| "—".into());
    let ip_kind = get("ip_kind");
    // device_class (parsed) beats the raw UA; fall back to «—».
    let ua = get("device_class")
        .or_else(|| get("ua"))
        .unwrap_or_else(|| "—".into());
    (ip, ip_kind, ua)
}

/// Render an `AdminAlert` into its localized `{icon,title,body,action}`
/// for the admin UI — the SAME `alert_text::render_alert` the Telegram
/// push uses, so the dashboard + /admin/alerts speak the operator's
/// language instead of the stored English summary. Subject = the user id
/// (for `user.*:id` kinds) or the server's country label; payload comes
/// from the stored `payload_json`.
pub(crate) fn localized_alert(
    a: &vpnctl_inventory::AdminAlert,
    lang: crate::i18n::Locale,
) -> crate::alert_text::RenderedAlert {
    // server_id wins over a `:`-suffix: server alerts can ALSO carry a
    // suffix (e.g. `server.fingerprint.drift:de`), where the suffix is
    // the raw id — we want the country label. The suffix is only the
    // subject for user-scoped alerts (server_id is None).
    let subject = if let Some(sid) = &a.server_id {
        crate::handlers::vpn_router::server_display_label(&sid.0, None)
    } else if let Some((_, suffix)) = a.kind.split_once(':') {
        suffix.to_string()
    } else {
        String::new()
    };
    let payload: serde_json::Value = a
        .payload_json
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or(serde_json::Value::Null);
    crate::alert_text::render_alert(&a.kind, &a.severity, &subject, &payload, lang)
}
