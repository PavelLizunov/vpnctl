use crate::handlers::admin::icons::{icon, status};
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use maud::{Markup, html};

use super::helpers::{bad_request, humanize_age, internal_error, render_page, theme_accent_lang};
use crate::AppState;
use crate::http_util::path_segment_encode;

pub(crate) async fn alerts(
    headers: HeaderMap,
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<AlertsQuery>,
) -> Result<Markup, Response> {
    let (theme, accent, lang) = theme_accent_lang(&headers);

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

    let (sub_rows, node_rows): (Vec<_>, Vec<_>) = alerts_rows
        .iter()
        .partition(|a| a.kind.starts_with("sub_access."));
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
                    button type="submit" class="ed-abtn ed-abtn--secondary ed-abtn--sm" { (icon("check")) "ack" }
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
            )) { (icon("info")) }
            span style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                (sub_rows.iter().filter(|a| a.acked_at.is_none()).count()) " sub-access · "
                (node_rows.iter().filter(|a| a.acked_at.is_none()).count()) " "
                (crate::i18n::tr(lang, "node", "нодовых"))
            }
            div.ed-headrow__actions {
                @if include_acked {
                    a href="/admin/alerts" style="font-family: var(--mono); font-size: 11px; color: var(--mute); text-decoration: none;" {
                        (icon("arrow-left")) (crate::i18n::tr(lang, "only unacked", "только непринятые"))
                    }
                } @else {
                    a href="/admin/alerts?show=all" style="font-family: var(--mono); font-size: 11px; color: var(--mute); text-decoration: none;" {
                        (crate::i18n::tr(lang, "show all", "показать всё")) (icon("arrow-right"))
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
                            (icon("check")) (crate::i18n::tr(lang, "ack all", "принять все"))
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
                            "no alerts on record. Either the fleet has been ",
                            "ни одного алерта в записях. Либо парк был ",
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
                            (crate::i18n::tr(lang, "show all", "показать всё")) (icon("arrow-right"))
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
                    )) { (icon("info")) }
                }
                @if sub_unacked > 0 {
                    form.ed-headrow__actions method="post" action="/admin/alerts/ack-family/sub_access."
                         data-confirm=(crate::i18n::tr(
                             lang,
                             "Ack every unacked sub_access alert? They stay under «show all» for 30 days.",
                             "Принять все непринятые sub_access-алерты? Останутся в «показать всё» 30 дней.",
                         )) {
                        button type="submit" class="ed-abtn ed-abtn--secondary ed-abtn--sm" {
                            (icon("check")) (crate::i18n::tr(lang, "ack all ", "принять все ")) "(" (sub_unacked) ")"
                        }
                    }
                }
            }
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
                            td { span style="color: var(--warm);" { (status("triangle-alert", lang, "Warning", "Предупреждение")) } }
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
                                    span style="color: var(--red);" { (status("circle-x", lang, "Critical alert", "Критический алерт")) }
                                } @else {
                                    span style="color: var(--warm);" { (status("triangle-alert", lang, "Warning", "Предупреждение")) }
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

pub(crate) async fn alert_ack(
    axum::extract::Path(id): axum::extract::Path<i64>,
    State(state): State<AppState>,
) -> Response {
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

pub(crate) async fn alert_ack_all(State(state): State<AppState>) -> Response {
    let count = match state.inv.ack_all_unacked_alerts().await {
        Ok(n) => n,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
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
    pub show: Option<String>,
}

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
    let ua = get("device_class")
        .or_else(|| get("ua"))
        .unwrap_or_else(|| "—".into());
    (ip, ip_kind, ua)
}

pub(crate) fn localized_alert(
    a: &vpnctl_inventory::AdminAlert,
    lang: crate::i18n::Locale,
) -> crate::alert_text::RenderedAlert {
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
