//! Boosty subscription bridge admin handlers (`/admin/boosty`): the
//! bridge status page, settings save, manual sync, and the
//! link / unlink / disable actions. Links Boosty subscribers to vpnctl
//! users and reconciles VPN access with subscription state (see
//! `vpnctl-boosty-bridge`).
//!
//! Extracted from `legacy.rs` as part of the admin submodules refactor.

use crate::handlers::admin::icons::icon;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use maud::{Markup, html};

use super::audit::{action_kind, redact_audit_payload, summarize_audit_payload};
use super::helpers::{
    bad_request, format_msk_iso, internal_error, render_page, theme_accent_lang, user_not_found,
};
use crate::AppState;
use crate::http_util::{form_field, path_segment_encode};

// ────────────────────────────────────────────────────────────────────────
// Boosty subscription bridge (/admin/boosty)
//
// Links Boosty subscribers to vpnctl users and reconciles VPN access with
// subscription state (see `vpnctl-boosty-bridge`). The poller auto-enables
// active subscribers; lapses are surfaced here for the operator to disable
// with a button (or auto-disabled when `auto_disable_lapsed` is on).
// ────────────────────────────────────────────────────────────────────────

/// Mask a credential to `••••<last4>` — never render secrets verbatim.
fn boosty_mask_secret(secret: Option<&str>) -> String {
    match secret {
        None => "(unset)".to_string(),
        Some(v) if v.chars().count() <= 4 => "••••".to_string(),
        Some(v) => {
            let last4: String = {
                let mut c: Vec<char> = v.chars().rev().take(4).collect();
                c.reverse();
                c.into_iter().collect()
            };
            format!("••••{last4}")
        }
    }
}

fn boosty_time(ts: Option<i64>) -> String {
    ts.filter(|ts| *ts > 0)
        .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0))
        .map(format_msk_iso)
        .unwrap_or_else(|| "—".into())
}

/// `GET /admin/boosty` — bridge status, settings form, and the actionable
/// link/disable surfaces, rendered from the LAST APPLIED sync report
/// (stored by the poller / «sync now» / CLI `--apply`). Deliberately NO
/// live sync on a GET: admin GETs must not mutate state (csrf.rs
/// contract), and a live pass would rotate the Boosty refresh token and
/// race the poller (spurious invalid_grant).
pub(crate) async fn boosty_page(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Markup, Response> {
    let (theme, accent, lang) = theme_accent_lang(&headers);

    let settings = state
        .inv
        .get_boosty_settings()
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;
    let links = state
        .inv
        .list_boosty_links()
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;
    let users = state
        .inv
        .list_users()
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;

    // Users not yet linked → candidates for the link dropdown.
    let linked_ids: std::collections::HashSet<&str> =
        links.iter().map(|(u, _)| u.0.as_str()).collect();
    let unlinked_users: Vec<&str> = users
        .iter()
        .map(|u| u.id.0.as_str())
        .filter(|id| !linked_ids.contains(id))
        .collect();
    // Subscriber ids already linked — used to drop them from the stored
    // report's "new subscribers to link" list at render time. The report
    // is a snapshot of the last sync; after the operator links someone the
    // redirect must show them gone WITHOUT waiting for the next sync (else
    // the just-linked row lingers and reads as "nothing happened").
    let linked_sub_ids: std::collections::HashSet<i64> =
        links.iter().map(|(_, sid)| *sid).collect();

    // Last applied sync report (best-effort: absent/unparseable → None —
    // the page degrades to settings + links, never 500s on report drift).
    let last_report: Option<(vpnctl_boosty_bridge::SyncReport, String)> =
        match state.inv.boosty_last_report().await {
            Ok(Some((json, ts))) => serde_json::from_str(&json).ok().map(|r| (r, ts)),
            _ => None,
        };
    let report = last_report.as_ref().map(|(r, _)| r);
    let last_sync_at = last_report.as_ref().map(|(_, ts)| ts.as_str());
    let boosty_events = state
        .inv
        .recent_audit_paginated(50, 0, None, Some("boosty."), None, None)
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;

    use crate::i18n::tr;
    let configured = settings.blog_url.as_deref().is_some_and(|v| !v.is_empty())
        && (settings
            .access_token
            .as_deref()
            .is_some_and(|v| !v.is_empty())
            || (settings
                .refresh_token
                .as_deref()
                .is_some_and(|v| !v.is_empty())
                && settings.device_id.as_deref().is_some_and(|v| !v.is_empty())));

    let host = headers
        .get(axum::http::header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("vpnctld");
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|p| p.to_str().ok())
        .unwrap_or("http");
    let admin_origin = format!("{proto}://{host}");
    let default_blog = settings.blog_url.as_deref().unwrap_or("ninitux");

    let admin_origin_js = serde_json::to_string(&admin_origin).unwrap_or_default();
    let default_blog_js = serde_json::to_string(default_blog).unwrap_or_default();

    let bookmarklet_js = format!(
        r#"(function(){{function toast(icon,title,desc,color){{var el=document.getElementById('vpnctl-toast');if(!el){{el=document.createElement('div');el.id='vpnctl-toast';el.style.cssText='position:fixed;top:20px;right:20px;z-index:2147483647;background:#18181b;color:#fff;padding:14px 18px;border-radius:10px;font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;font-size:13px;box-shadow:0 12px 36px rgba(0,0,0,0.6);border:2px solid '+color+';display:flex;align-items:center;gap:12px;max-width:380px;line-height:1.4;';document.body.appendChild(el);}}el.style.borderColor=color;el.textContent='';var iS=document.createElement('span');iS.style.cssText='font-size:22px;flex-shrink:0;';iS.textContent=icon;var cD=document.createElement('div');var tB=document.createElement('b');tB.style.cssText='color:'+color+';font-size:14px;';tB.textContent=title;var dD=document.createElement('div');dD.style.cssText='color:#d4d4d8;margin-top:2px;';dD.textContent=desc;cD.appendChild(tB);cD.appendChild(dD);el.appendChild(iS);el.appendChild(cD);}}if(location.hostname!=='boosty.to'&&!location.hostname.endsWith('.boosty.to')){{toast('⚠️','vpnctl Connect','Откройте вкладку блога на boosty.to и нажмите закладку снова!','#f59e0b');return;}}toast('🔄','vpnctl Connect','Считываем токены авторизации Boosty...','#3b82f6');function c(n){{var m=document.cookie.match(new RegExp('(?:^|; )'+n+'=([^;]*)'));return m?decodeURIComponent(m[1]):null;}}var lsAuth=null,lsClient=null;try{{lsAuth=localStorage.getItem('auth');lsClient=localStorage.getItem('_clientId')||localStorage.getItem('_clentId');}}catch(e){{}}var a=lsAuth||c('auth'),d=lsClient||c('_clientId');if(!a){{toast('❌','vpnctl Connect','Токены не найдены. Убедитесь, что вы авторизованы на boosty.to!','#ef4444');return;}}try{{var j=JSON.parse(a),p=location.pathname.split('/').filter(Boolean),b=(p.length>0&&!['app','feed','dialog','settings','messages'].includes(p[0]))?p[0]:'';b=b||{default_blog_js};var origin={admin_origin_js};var payload={{v:2,blog:b,access_token:j.accessToken||'',refresh_token:j.refreshToken||'',device_id:d||''}};toast('✅','vpnctl Connect','Токены блога «'+b+'» найдены! Перенаправляем в админку...','#22c55e');setTimeout(function(){{location.href=origin+'/admin/boosty#quick_connect='+encodeURIComponent(JSON.stringify(payload));}},500);}}catch(e){{toast('❌','vpnctl Connect','Ошибка чтения токенов: '+e,'#ef4444');}}}})();"#
    );
    let bookmarklet_href = format!("javascript:{}", bookmarklet_js);

    let body = html! {
        div.ed-art-eyebrow { "Boosty" }
        div.ed-headrow {
            h1.ed-art-h1 {
                (tr(lang, "subscription ", "мост ")) em { (tr(lang, "bridge", "подписок")) }
            }
            span.ed-tip title=(tr(
                lang,
                "The poller reconciles vpnctl access with Boosty subscription state on its own interval: active subscribers get their VPN user enabled, lapses are surfaced here to disable (or auto-disabled). This page renders the LAST APPLIED sync — a GET never triggers a live pass (it would rotate the refresh token and race the poller).",
                "Поллер сам сверяет доступ vpnctl со статусом подписки Boosty по своему интервалу: активным подписчикам включается VPN-юзер, отвалившиеся всплывают здесь для отключения (или отключаются авто). Страница показывает ПОСЛЕДНИЙ применённый синк — GET не запускает живой проход (он бы ротировал refresh-токен и гонялся с поллером).",
            )) { (icon("info")) }
            // Live enabled/disabled pill.
            span.ed-stat style=(if settings.enabled { "color: var(--green);" } else { "color: var(--mute);" }) {
                @if settings.enabled {
                    (icon("circle"))
                    (tr(lang, "polling on", "опрос включён"))
                } @else {
                    (tr(lang, "polling off", "опрос выключен"))
                }
            }
            div.ed-headrow__actions {
                form method="post" action="/admin/boosty/sync" style="margin: 0;" {
                    button type="submit"
                           title=(tr(
                               lang,
                               "Run one reconcile pass right now (POST — safe). Auto-enables active subscribers; lapses appear below.",
                               "Прогнать один проход сверки сейчас (POST — безопасно). Включает активных; отвалившиеся появятся ниже.",
                           ))
                           class="ed-abtn ed-abtn--secondary ed-abtn--sm" {
                        (icon("rotate-cw")) (tr(lang, "sync now", "синхронизировать"))
                    }
                }
            }
        }
        p.ed-art-deck {
            (tr(lang,
                "Link Boosty subscribers to VPN users; access follows the subscription.",
                "Связь подписчиков Boosty с VPN-пользователями; доступ следует за подпиской."))
        }

        // ── Sync-health callouts (only when the last report carries them).
        @if let Some(r) = report {
            @if !r.suppressed_disables.is_empty() {
                div style="border: 1px solid var(--red); border-left-width: 3px; background: color-mix(in oklab, var(--red) 8%, var(--paper)); padding: 8px 12px; margin: 12px 0; font-family: var(--serif); font-size: 12px; line-height: 1.5;" {
                    b style="color: var(--red);" { (icon("triangle-alert")) (tr(lang, "Empty roster — disables suppressed.", "Пустой ростер — отключения подавлены.")) }
                    " "
                    (tr(lang,
                        "The last sync got zero subscribers back (likely a wrong blog url or expired token). No one was disabled. Untouched: ",
                        "Последний синк вернул ноль подписчиков (скорее всего неверный blog url или протухший токен). Никто не отключён. Не тронуты: "))
                    span.ed-mono { (r.suppressed_disables.join(", ")) }
                }
            }
            @if !r.errors.is_empty() {
                div style="border: 1px solid var(--red); border-left-width: 3px; background: color-mix(in oklab, var(--red) 8%, var(--paper)); padding: 8px 12px; margin: 12px 0; font-family: var(--serif); font-size: 12px; line-height: 1.5;" {
                    b style="color: var(--red);" { (tr(lang, "Last sync errors:", "Ошибки последнего синка:")) }
                    " " span.ed-mono { (r.errors.join(" · ")) }
                }
            }
        }

        // ── Status strip — the runtime facts at a glance ─────────
        div.ed-status-strip style="grid-template-columns: repeat(4, minmax(0, 1fr));" {
            div.ed-status-tile {
                div.ed-status-tile__k { (tr(lang, "bridge", "мост")) }
                div.ed-status-tile__v style=(if configured { "color: var(--green);" } else { "color: var(--warm);" }) {
                    @if configured { (tr(lang, "configured", "настроен")) }
                    @else { (tr(lang, "incomplete", "не настроен")) }
                }
                div style="font-family: var(--mono); font-size: 10px; color: var(--mute); margin-top: 2px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" {
                    @match &settings.blog_url {
                        Some(b) => (b),
                        None => (tr(lang, "no blog url", "нет blog url")),
                    }
                }
            }
            div.ed-status-tile {
                div.ed-status-tile__k { (tr(lang, "linked users", "привязано")) }
                div.ed-status-tile__v { (links.len()) }
            }
            div.ed-status-tile {
                div.ed-status-tile__k { (tr(lang, "poll interval", "интервал опроса")) }
                div.ed-status-tile__v { (settings.poll_interval_secs / 60) (tr(lang, " min", " мин")) }
                div style="font-family: var(--mono); font-size: 10px; color: var(--mute); margin-top: 2px;" {
                    (tr(lang, "auto-disable ", "авто-откл. "))
                    @if settings.auto_disable_lapsed { b style="color: var(--green);" { (tr(lang, "on", "вкл")) } }
                    @else { (tr(lang, "off", "выкл")) }
                }
            }
            div.ed-status-tile {
                div.ed-status-tile__k { (tr(lang, "last applied sync", "последний синк")) }
                div.ed-status-tile__v style="font-size: 14px;" {
                    @match last_sync_at {
                        Some(ts) => @match chrono::DateTime::parse_from_rfc3339(ts) {
                            Ok(t) => (format_msk_iso(t.with_timezone(&chrono::Utc))),
                            Err(_) => (ts),
                        },
                        None => (tr(lang, "never", "никогда")),
                    }
                }
            }
        }

        // ── Revenue summary — MRR, cumulative payments, active payers ──
        @if let Some(r) = report {
            @let income = r.income_summary();
            div.ed-status-strip style="grid-template-columns: repeat(3, minmax(0, 1fr)); margin-top: 14px;" {
                div.ed-status-tile {
                    div.ed-status-tile__k { (tr(lang, "monthly income (mrr)", "доход в месяц (mrr)")) }
                    div.ed-status-tile__v style="color: var(--green); font-family: var(--mono); font-weight: 600;" {
                        (format!("{:.2} ₽", income.mrr_rub_cents as f64 / 100.0))
                    }
                    div style="font-family: var(--mono); font-size: 10px; color: var(--mute); margin-top: 2px;" {
                        (income.active_payers) " " (tr(lang, "paying subscriber(s)", "платящих подписчиков"))
                    }
                }
                div.ed-status-tile {
                    div.ed-status-tile__k { (tr(lang, "total revenue (to date)", "всего собрано (to date)")) }
                    div.ed-status-tile__v style="font-family: var(--mono); font-weight: 600;" {
                        (format!("{:.2} ₽", income.total_revenue_rub_cents as f64 / 100.0))
                    }
                    div style="font-family: var(--mono); font-size: 10px; color: var(--mute); margin-top: 2px;" {
                        (tr(lang, "cumulative subscriber payments", "суммарные выплаты по ростеру"))
                    }
                }
                div.ed-status-tile {
                    div.ed-status-tile__k { (tr(lang, "active payers / total", "плательщиков / всего")) }
                    div.ed-status-tile__v style="font-family: var(--mono);" {
                        (r.active_subscribers) " / " (r.total_subscribers)
                    }
                    div style="font-family: var(--mono); font-size: 10px; color: var(--mute); margin-top: 2px;" {
                        @if r.excluded_unpaid > 0 {
                            (r.excluded_unpaid) " " (tr(lang, "free followers", "бесплатных фолловеров"))
                        } @else {
                            (tr(lang, "all on paid tiers", "все на платных уровнях"))
                        }
                    }
                }
            }
        }

        // ── Paid-only note: free followers the gate excluded ────
        @if let Some(r) = report {
            @if r.excluded_unpaid > 0 {
                p style="font-family: var(--mono); font-size: 11px; color: var(--mute); margin: 10px 0 0;" {
                    (r.excluded_unpaid) " "
                    (tr(lang,
                        "active free-tier follower(s) excluded — VPN is for paid levels only.",
                        "активных бесплатных подписчиков исключены — VPN только для платных уровней."))
                }
            }
        }

        // ── Actionable: new subscribers to link ─────────────────
        @if let Some(r) = report {
            @let new_to_link: Vec<&vpnctl_boosty_bridge::NewSubscriberInfo> = r
                .new_subscribers
                .iter()
                .filter(|s| !linked_sub_ids.contains(&s.subscriber_id))
                .collect();
            @if !new_to_link.is_empty() {
                div.ed-rule {}
                div.ed-art-eyebrow {
                    (tr(lang, "New subscribers", "Новые подписчики")) " · " (new_to_link.len()) " "
                    span.ed-tip title=(tr(
                        lang,
                        "Active Boosty subscribers the last sync found that aren't linked to a vpnctl user yet. Pick a user to bind them — access then follows the subscription automatically.",
                        "Активные подписчики Boosty из последнего синка, ещё не привязанные к юзеру vpnctl. Выбери юзера — дальше доступ следует за подпиской автоматически.",
                    )) { (icon("info")) }
                }
                table.ed-grid style="margin-top: 8px;" {
                    thead { tr {
                        th { (tr(lang, "subscriber", "подписчик")) }
                        th { (tr(lang, "link to user", "привязать к")) }
                        th style="width: 110px;" {}
                    }}
                    tbody {
                        @for sub in &new_to_link {
                            @let form_id = format!("boosty-link-{}", sub.subscriber_id);
                            tr {
                                td {
                                    b { (sub.name) }
                                    " " span.ed-grid__mut { (sub.subscriber_id) }
                                }
                                td {
                                    form id=(form_id) method="post" action="/admin/boosty/link" style="margin: 0;" {
                                        input type="hidden" name="subscriber_id" value=(sub.subscriber_id);
                                        select name="user" required {
                                            option value="" { (tr(lang, "link to user…", "привязать к…")) }
                                            @for uid in &unlinked_users {
                                                option value=(uid) { (uid) }
                                            }
                                        }
                                    }
                                }
                                td.num {
                                    button type="submit" form=(form_id) class="ed-abtn ed-abtn--secondary ed-abtn--sm" {
                                        (icon("link")) (tr(lang, "link", "привязать"))
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // ── Lapsed, awaiting confirm to disable ─────────────
            @if !r.lapsed_pending.is_empty() {
                div.ed-rule {}
                div.ed-art-eyebrow {
                    (tr(lang, "Lapsed — confirm disable", "Отвалились — подтвердите отключение")) " · " (r.lapsed_pending.len()) " "
                    span.ed-tip title=(tr(
                        lang,
                        "Linked users whose Boosty subscription has lapsed. With auto-disable OFF you confirm each one here; disabling cuts their VPN access (reversible — re-subscribing re-enables on the next sync).",
                        "Привязанные юзеры, чья подписка Boosty истекла. При выключенном авто-отключении подтверждаешь каждого здесь; отключение режет VPN-доступ (обратимо — при возобновлении подписки включится на следующем синке).",
                    )) { (icon("info")) }
                }
                div style="display: flex; flex-wrap: wrap; gap: 8px; margin-top: 8px;" {
                    @for uid in &r.lapsed_pending {
                        form method="post" action=(format!("/admin/boosty/disable/{uid}")) style="margin: 0;" {
                            button type="submit"
                                   title=(tr(lang, "Disable this user's VPN access (subscription lapsed).", "Отключить VPN-доступ юзера (подписка истекла)."))
                                   class="ed-abtn ed-abtn--warning ed-abtn--sm" {
                                (icon("pause")) (uid) " · " (tr(lang, "disable", "отключить"))
                            }
                        }
                    }
                }
            }

            @if !r.grace_pending.is_empty() {
                div.ed-rule {}
                div.ed-art-eyebrow {
                    (tr(lang, "Inside grace period", "Внутри отсрочки")) " · " (r.grace_pending.len())
                }
                p style="font-family: var(--mono); font-size: 11px; color: var(--mute); margin: 8px 0 0;" {
                    (r.grace_pending.join(", ")) " · "
                    (tr(lang, "access remains enabled", "доступ пока включён"))
                }
            }

            @if !r.provisioned.is_empty() {
                div.ed-rule {}
                div.ed-art-eyebrow {
                    (tr(lang, "Created automatically", "Созданы автоматически")) " · " (r.provisioned.len())
                }
                p style="font-family: var(--mono); font-size: 11px; color: var(--green); margin: 8px 0 0;" {
                    (r.provisioned.join(", "))
                }
            }

            @if !r.enabled.is_empty() || !r.disabled.is_empty() {
                div.ed-rule {}
                div style="display: flex; flex-wrap: wrap; gap: 28px; font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                    @if !r.enabled.is_empty() {
                        div {
                            (tr(lang, "Enabled by last sync: ", "Включены последним синком: "))
                            span style="color: var(--green);" { (r.enabled.join(", ")) }
                        }
                    }
                    @if !r.disabled.is_empty() {
                        div {
                            (tr(lang, "Auto-disabled by last sync: ", "Авто-отключены последним синком: "))
                            span style="color: var(--warm);" { (r.disabled.join(", ")) }
                        }
                    }
                }
            }
        }

        // ── Linked users ────────────────────────────────────────
        div.ed-rule {}
        div.ed-art-eyebrow { (tr(lang, "Linked users", "Привязанные пользователи")) }
        @if links.is_empty() {
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 0;" {
                (tr(lang,
                    "No Boosty links yet. Configure the bridge below, run a sync, then bind new subscribers to users.",
                    "Привязок Boosty пока нет. Настрой мост ниже, запусти синк, затем привяжи новых подписчиков к юзерам."))
            }
        } @else {
            table.ed-grid style="margin-top: 8px;" {
                thead { tr {
                    th { (tr(lang, "user", "пользователь")) }
                    th { (tr(lang, "boosty subscriber", "подписчик boosty")) }
                    th style="width: 110px;" {}
                }}
                tbody {
                    @for (uid, sid) in &links {
                        @let uid_enc = path_segment_encode(&uid.0);
                        tr {
                            td { a.ed-grid__id href=(format!("/admin/users/{uid_enc}")) { (uid.0) } }
                            td.ed-grid__mut { (sid) }
                            td.num {
                                form method="post" action=(format!("/admin/boosty/unlink/{}", uid_enc)) style="margin: 0;" {
                                    button type="submit"
                                           title=(tr(lang, "Remove the Boosty↔user link. Does NOT disable the VPN user; just stops the subscription driving their access.", "Убрать связь Boosty↔юзер. НЕ отключает VPN-юзера; лишь перестаёт управлять доступом по подписке."))
                                           class="ed-abtn ed-abtn--secondary ed-abtn--sm" {
                                        (icon("unlink")) (tr(lang, "unlink", "отвязать"))
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // ── Subscriber roster snapshot ─────────────────────────
        @if let Some(r) = report {
            @if !r.subscribers.is_empty() {
                div.ed-rule {}
                div.ed-art-eyebrow {
                    (tr(lang, "Boosty roster snapshot", "Снимок подписчиков Boosty")) " · "
                    (r.subscribers.iter().filter(|s| s.present).count())
                }
                p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 8px;" {
                    (tr(
                        lang,
                        "Payments is Boosty's observed cumulative value, not a transaction, refund or currency ledger. Missing means absent from the latest API roster, not a confirmed unsubscribe.",
                        "Payments — наблюдаемое накопительное значение Boosty, а не реестр транзакций, возвратов или валют. Missing означает отсутствие в последнем ответе API, а не подтверждённую отписку.",
                    ))
                }
                table.ed-grid {
                    thead { tr {
                        th { (tr(lang, "subscriber", "подписчик")) }
                        th { (tr(lang, "status", "статус")) }
                        th { (tr(lang, "level", "уровень")) }
                        th { (tr(lang, "price / payments", "цена / payments")) }
                        th { (tr(lang, "on / off / next pay", "начало / конец / след. платёж")) }
                        th { (tr(lang, "API flags", "флаги API")) }
                    }}
                    tbody {
                        @for sub in &r.subscribers {
                            tr {
                                td {
                                    b { (sub.name) }
                                    " " span.ed-grid__mut { (sub.subscriber_id) }
                                }
                                td {
                                    @if sub.present {
                                        (sub.status)
                                    } @else {
                                        span style="color: var(--warm);" { "missing" }
                                        " · " span.ed-grid__mut { (boosty_time(sub.missing_since)) }
                                    }
                                }
                                td {
                                    (sub.level_name)
                                    " " span.ed-grid__mut { "#" (sub.level_id) " · " (sub.level_price) }
                                }
                                td.ed-grid__mut { (sub.price) " / " (sub.payments) }
                                td.ed-grid__mut {
                                    (boosty_time(Some(sub.on_time))) " / "
                                    (boosty_time(sub.off_time)) " / "
                                    (boosty_time(sub.next_pay_time))
                                }
                                td.ed-grid__mut {
                                    @if sub.subscribed { "subscribed " }
                                    @if sub.is_fee_paid { "fee-paid " }
                                    @if sub.can_write { "can-write " }
                                    @if sub.is_black_listed { "blacklisted" }
                                }
                            }
                        }
                    }
                }
            }
        }

        // ── Durable Boosty event timeline ───────────────────────
        div.ed-rule {}
        div.ed-art-eyebrow {
            (tr(lang, "Boosty events · latest 50", "События Boosty · последние 50"))
            " · " a href="/admin/audit?action=boosty." { (icon("history")) (tr(lang, "full audit", "полный аудит")) }
        }
        @if boosty_events.is_empty() {
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 0;" {
                (tr(lang, "No Boosty events yet; the first successful sync records a baseline.", "Событий Boosty пока нет; первый успешный синк запишет базовую точку."))
            }
        } @else {
            div.ed-time.ed-time--compact {
                @for e in &boosty_events {
                    div.ed-time-row {
                        span.ed-time-row__t { (format_msk_iso(e.ts)) }
                        span class=(format!("ed-time-row__a ed-time-row__a--{}", action_kind(&e.action))) { (e.action) }
                        span.ed-time-row__pl {
                            @if let Some(target) = &e.target { span.ed-mono { (target) " · " } }
                            @if let Some(payload) = &e.payload {
                                (summarize_audit_payload(payload))
                                " "
                                details style="display: inline-block; vertical-align: baseline;" {
                                    summary style="cursor: pointer; color: var(--acc); font-family: var(--mono); font-size: 10px; list-style: none; display: inline;" { (icon("code")) "{…}" }
                                    pre style="margin: 4px 0 0; padding: 8px 10px; background: var(--paper-2); border: 1px solid var(--rule); font-family: var(--mono); font-size: 10px; white-space: pre-wrap; max-width: 680px;" {
                                        (serde_json::to_string_pretty(&redact_audit_payload(payload)).unwrap_or_default())
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // ── Bridge settings ─────────────────────────────────────
        div.ed-rule {}
        div.ed-art-eyebrow {
            (tr(lang, "Bridge settings", "Настройки моста")) " "
            span.ed-tip title=(tr(
                lang,
                "Boosty API credentials + poll cadence. Preferred: 1-Click Quick Connect. Manual fields are available below in fallback settings.",
                "Учётные данные API Boosty + интервал опроса. Основной способ: 1-Click подключение. Ручные поля доступны ниже в резервных настройках.",
            )) { (icon("info")) }
        }

        // ── 1-Click Quick Connect Bookmarklet Card ───────────────
        div.ed-card style="margin: 10px 0 16px; border: 1px solid color-mix(in oklab, var(--accent) 50%, var(--rule)); background: color-mix(in oklab, var(--accent) 4%, var(--paper)); padding: 16px 20px; border-radius: 4px;" {
            div.ed-card__hd {
                (tr(lang, "1-Click Quick Connect (No DevTools / F12)", "Быстрое подключение в 1 клик (без F12 и консоли)"))
            }
            p style="font-family: var(--serif); font-size: 13px; color: var(--ink); margin: 0 0 14px; line-height: 1.5;" {
                (tr(
                    lang,
                    "No console commands or manual cookie copying: drag the button below to your browser bookmarks bar, open your creator page on boosty.to, and click the bookmark. It will automatically read tokens and connect this server.",
                    "Без консоли и ручного копирования кук: перетащите кнопку ниже на панель закладок браузера, откройте страницу блога на boosty.to и нажмите закладку. Она сама считает токены и мгновенно свяжет ваш сервер.",
                ))
            }
            div style="display: flex; flex-wrap: wrap; gap: 10px; align-items: center;" {
                a.ed-abtn.ed-abtn--primary href=(bookmarklet_href) draggable="true"
                  data-bookmarklet-link=""
                  title=(tr(lang, "Drag this button to your bookmarks bar", "Перетащите эту кнопку на панель закладок")) {
                    (icon("link")) " " (tr(lang, "🔑 Connect Boosty", "🔑 Подключить Boosty"))
                }
                button.ed-abtn.ed-abtn--secondary type="button"
                  data-copy-bookmarklet=""
                  data-script=(bookmarklet_js) {
                    (icon("code")) " " (tr(lang, "Copy script", "Скопировать скрипт"))
                }
            }
        }

        // Help modal for clicking the bookmarklet button directly on the admin page
        div id="bookmarklet-help-modal" style="display: none; position: fixed; inset: 0; z-index: 10000; background: rgba(0,0,0,0.65); backdrop-filter: blur(2px); align-items: center; justify-content: center; padding: 16px;" {
            div style="background: var(--paper); border: 1px solid var(--rule); border-radius: 8px; max-width: 520px; width: 100%; padding: 22px 24px; box-shadow: 0 20px 40px rgba(0,0,0,0.3); font-family: var(--serif); line-height: 1.5; color: var(--ink);" {
                div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px;" {
                    h3 style="margin: 0; font-size: 16px; font-family: var(--mono); font-weight: 600; color: var(--ink);" {
                        (tr(lang, "💡 1-Click Connect instructions", "💡 Как запустить быстрое подключение"))
                    }
                    button type="button" data-modal-close="bookmarklet-help-modal" style="border: none; background: none; cursor: pointer; font-size: 18px; color: var(--mute); padding: 0 4px;" { "✕" }
                }
                p style="font-size: 13px; margin: 0 0 12px;" {
                    (tr(
                        lang,
                        "Browsers block websites from directly accessing other tabs for security. The button works as a browser bookmark:",
                        "Браузер запрещает админке напрямую считывать данные других вкладок из соображений безопасности. Эта кнопка работает как закладка в браузере:",
                    ))
                }
                ol style="font-size: 13px; padding-left: 20px; margin: 0 0 16px; display: flex; flex-direction: column; gap: 8px;" {
                    li {
                        (tr(
                            lang,
                            "Enable the bookmarks bar: press Ctrl + Shift + B (or Cmd + Shift + B on Mac).",
                            "Включите панель закладок: нажмите Ctrl + Shift + B (или Cmd + Shift + B на Mac).",
                        ))
                    }
                    li {
                        (tr(
                            lang,
                            "Drag the blue button «🔑 Connect Boosty» onto your bookmarks bar.",
                            "Мышкой перетащите синюю кнопку «🔑 Подключить Boosty» вверх на панель закладок.",
                        ))
                    }
                    li {
                        (tr(
                            lang,
                            "Open your blog page on boosty.to and click that bookmark on your bookmarks bar!",
                            "Откройте вкладку вашего блога на boosty.to и нажмите появившуюся закладку прямо там!",
                        ))
                    }
                }
                div style="display: flex; justify-content: flex-end; gap: 10px;" {
                    button type="button" class="ed-abtn ed-abtn--primary" data-modal-close="bookmarklet-help-modal" {
                        (tr(lang, "Got it", "Понятно"))
                    }
                }
            }
        }

        // Import success banner (shown when loaded with #quick_connect=...)
        div id="quick-connect-banner" style="display: none; border: 1px solid var(--green); border-left-width: 4px; background: color-mix(in oklab, var(--green) 10%, var(--paper)); padding: 14px 18px; margin: 12px 0 16px; font-family: var(--serif); font-size: 13px; line-height: 1.5;" {
            div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 14px;" {
                div {
                    b style="color: var(--green); font-size: 14px;" { (icon("check")) " " (tr(lang, "Boosty credentials detected!", "Учётные данные Boosty готовы к подключению!")) }
                    div id="quick-connect-blog-info" style="margin-top: 4px; color: var(--ink); font-family: var(--mono); font-size: 12px;" {}
                    div style="margin-top: 2px; color: var(--mute); font-size: 12px;" {
                        (tr(lang, "Click the button to save credentials, enable background polling and run immediate sync.", "Нажмите кнопку, чтобы подтвердить данные, включить фоновый опрос и сразу синхронизировать подписчиков."))
                    }
                }
                div {
                    button type="submit" form="boosty-settings-form" name="quick_sync_now" value="1" class="ed-abtn ed-abtn--primary" style="padding: 6px 18px; font-size: 13px; font-weight: 600; display: inline-flex; align-items: center; gap: 6px;" {
                        (icon("rotate-cw")) (tr(lang, "🔑 Confirm & Sync now", "🔑 Подтвердить подключение и синхронизировать"))
                    }
                }
            }
        }

        form id="boosty-settings-form" method="post" action="/admin/boosty/settings" {
            // Main automation policy controls (always visible)
            div style="display: flex; flex-wrap: wrap; gap: 18px; align-items: center; margin: 14px 0 16px; padding: 10px 14px; background: var(--paper-2); border: 1px solid var(--rule); border-radius: 4px;" {
                label style="display: flex; align-items: center; gap: 6px; font-family: var(--mono); font-size: 12px; color: var(--ink);" {
                    input id="boosty_enabled" type="checkbox" name="enabled" checked[settings.enabled];
                    (tr(lang, "enabled (poller runs)", "включено (поллер работает)"))
                }
                label style="display: flex; align-items: center; gap: 6px; font-family: var(--mono); font-size: 12px; color: var(--ink);" {
                    input type="checkbox" name="auto_disable_lapsed" checked[settings.auto_disable_lapsed];
                    (tr(lang, "auto-disable lapsed subscribers", "авто-отключать отвалившихся"))
                }
                label style="display: flex; align-items: center; gap: 6px; font-family: var(--mono); font-size: 12px; color: var(--ink);" {
                    input type="checkbox" name="auto_create_users" checked[settings.auto_create_users];
                    (tr(lang, "auto-create users for new paid subscribers", "авто-создавать пользователей для новых платных подписчиков"))
                }
                button type="submit" class="ed-abtn ed-abtn--secondary ed-abtn--sm" style="margin-left: auto;" {
                    (icon("save")) (crate::i18n::t(lang, crate::i18n::K::BtnSave))
                }
            }

            // Fallback: Manual settings hidden inside a spoiler details element
            details.ed-spoiler style="margin-top: 14px; border: 1px solid var(--rule); border-radius: 4px; padding: 12px 16px; background: var(--paper-2);" {
                summary style="cursor: pointer; font-family: var(--mono); font-size: 12px; color: var(--mute); font-weight: 600; user-select: none;" {
                    (tr(lang, "⚙️ Fallback: Manual settings & technical parameters", "⚙️ Резервный способ — ручная настройка и параметры"))
                }
                div style="margin-top: 14px;" {
                    div style="display: flex; flex-wrap: wrap; gap: 24px; margin: 0 0 12px; font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                        span { (tr(lang, "access fallback ", "резервный access ")) span style="color: var(--ink);" { (boosty_mask_secret(settings.access_token.as_deref())) } }
                        span { (tr(lang, "refresh preferred ", "основной refresh ")) span style="color: var(--ink);" { (boosty_mask_secret(settings.refresh_token.as_deref())) } }
                        span { (tr(lang, "device · with refresh ", "device · для refresh ")) span style="color: var(--ink);" { (boosty_mask_secret(settings.device_id.as_deref())) } }
                    }
                    p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 0 0 12px;" {
                        (tr(
                            lang,
                            "Preferred: refresh token + device id (renewed automatically). Access token is a short-lived fallback used only when that pair is incomplete.",
                            "Основной способ: refresh token + device id (обновляются автоматически). Access token — короткоживущий резерв, он используется только если пара заполнена не полностью.",
                        ))
                    }
                    div style="display: grid; grid-template-columns: 200px 1fr; gap: 10px 14px; align-items: center; max-width: 720px;" {
                        label for="boosty_blog_url" style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                            (tr(lang, "blog url / slug", "блог url / slug"))
                        }
                        input id="boosty_blog_url" type="text" name="blog_url"
                              value=(settings.blog_url.as_deref().unwrap_or(""))
                              placeholder="boosty.to/yourblog";

                        label for="boosty_access" style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                            (tr(lang, "access token · fallback", "access token · резервный"))
                        }
                        input id="boosty_access" type="password" name="access_token" autocomplete="off"
                              placeholder=(tr(lang, "blank = keep existing", "пусто = оставить как есть"));

                        label for="boosty_refresh" style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                            (tr(lang, "refresh token · preferred", "refresh token · основной"))
                        }
                        input id="boosty_refresh" type="password" name="refresh_token" autocomplete="off"
                              placeholder=(tr(lang, "blank = keep existing", "пусто = оставить как есть"));

                        label for="boosty_device" style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                            (tr(lang, "device id · with refresh", "device id · для refresh"))
                        }
                        input id="boosty_device" type="password" name="device_id" autocomplete="off"
                              placeholder=(tr(lang, "blank = keep existing", "пусто = оставить как есть"));

                        label for="boosty_interval" style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                            (tr(lang, "poll interval (s)", "интервал опроса (с)"))
                        }
                        input id="boosty_interval" type="number" name="poll_interval_secs" min="60"
                              title=(tr(lang, "Minimum 60 seconds. Applies after a daemon restart.", "Минимум 60 секунд. Применяется после рестарта демона."))
                              value=(settings.poll_interval_secs);

                        label for="boosty_grace_days" style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                            (tr(lang, "disable grace (days)", "отсрочка отключения (дни)"))
                        }
                        input id="boosty_grace_days" type="number" name="grace_days" min="0" max="365"
                              title=(tr(lang, "Automatic disable waits this many days after Boosty off_time or the first observed lapse.", "Авто-отключение ждёт столько дней после Boosty off_time или первого обнаружения просрочки."))
                              value=(settings.grace_days);
                    }
                    div style="margin-top: 14px;" {
                        button type="submit" class="ed-abtn ed-abtn--secondary ed-abtn--sm" {
                            (icon("save")) (crate::i18n::t(lang, crate::i18n::K::BtnSave))
                        }
                    }
                }
            }
        }
    };

    Ok(render_page(&state, "boosty", &theme, &accent, lang, body).await)
}

/// `POST /admin/boosty/settings` — save bridge config. Blank secret inputs
/// leave the stored value untouched (so the masked display never wipes a
/// credential). Audited WITHOUT secret values.
pub(crate) async fn boosty_settings_save(State(state): State<AppState>, body: String) -> Response {
    let mut s = match state.inv.get_boosty_settings().await {
        Ok(s) => s,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };

    if let Some(b) = form_field(&body, "blog_url") {
        let b = b.trim();
        s.blog_url = if b.is_empty() {
            None
        } else {
            Some(b.to_string())
        };
    }
    // Secrets: only overwrite when a non-blank value is supplied (a blank
    // input keeps the stored value, so the masked display can't wipe it).
    if let Some(t) = form_field(&body, "access_token")
        && !t.trim().is_empty()
    {
        s.access_token = Some(t.trim().to_string());
    }
    if let Some(t) = form_field(&body, "refresh_token")
        && !t.trim().is_empty()
    {
        s.refresh_token = Some(t.trim().to_string());
    }
    if let Some(d) = form_field(&body, "device_id")
        && !d.trim().is_empty()
    {
        s.device_id = Some(d.trim().to_string());
    }
    if let Some(i) = form_field(&body, "poll_interval_secs").and_then(|v| v.parse::<u64>().ok())
        && i > 0
    {
        // The HTML min=60 is client-side only — clamp server-side too so a
        // hand-crafted POST can't turn the poller into a tight loop.
        s.poll_interval_secs = i.max(60);
    }
    if let Some(days) = form_field(&body, "grace_days").and_then(|v| v.parse::<u16>().ok()) {
        s.grace_days = days.min(365);
    }
    // Checkboxes: present only when checked.
    s.enabled = form_field(&body, "enabled").is_some();
    s.auto_disable_lapsed = form_field(&body, "auto_disable_lapsed").is_some();
    s.auto_create_users = form_field(&body, "auto_create_users").is_some();

    if let Err(e) = state.inv.set_boosty_settings(&s).await {
        return internal_error(anyhow::Error::new(e));
    }
    if let Err(e) = state
        .inv
        .audit(
            "admin",
            "boosty.configure",
            None,
            Some(&serde_json::json!({
                "enabled": s.enabled,
                "blog_url": s.blog_url,
                "poll_interval_secs": s.poll_interval_secs,
                "auto_disable_lapsed": s.auto_disable_lapsed,
                "grace_days": s.grace_days,
                "auto_create_users": s.auto_create_users,
            })),
        )
        .await
    {
        tracing::warn!(target = "vpnctld::boosty", error = %e, "audit boosty.configure failed");
    }

    if form_field(&body, "quick_sync_now").is_some() && s.enabled {
        if let Err(resp) =
            run_boosty_sync_and_deploy(&state, s.auto_disable_lapsed, "boosty.quick_connect").await
        {
            return resp;
        }
    }

    Redirect::to("/admin/boosty").into_response()
}

/// Shared helper to execute a Boosty sync and background-deploy flipped users.
async fn run_boosty_sync_and_deploy(
    state: &AppState,
    auto_disable_lapsed: bool,
    source_tag: &'static str,
) -> Result<(), Response> {
    use vpnctl_boosty_bridge::ApplyMode;
    let mode = if auto_disable_lapsed {
        ApplyMode::Full
    } else {
        ApplyMode::EnableOnly
    };
    match vpnctl_boosty_bridge::sync_from_inventory(&state.inv, mode).await {
        Ok(report) => {
            let _ = state
                .inv
                .ack_open_alerts(crate::boosty_sync_poller::SYNC_FAILED_ALERT_KIND, None)
                .await;
            tracing::info!(
                target = "vpnctld::boosty",
                enabled = report.enabled.len(),
                disabled = report.disabled.len(),
                provisioned = report.provisioned.len(),
                "{source_tag} boosty sync"
            );
            let flipped: Vec<String> = report
                .enabled
                .iter()
                .chain(report.disabled.iter())
                .chain(report.provisioned.iter())
                .cloned()
                .collect();
            if !flipped.is_empty() {
                let inv = state.inv.clone();
                let registry = std::sync::Arc::clone(&state.registry);
                let key = crate::app::deploy_key_path();
                tokio::spawn(async move {
                    crate::boosty_sync_poller::deploy_flipped_users(
                        &inv, &registry, &key, &flipped, source_tag,
                    )
                    .await;
                });
            }
            Ok(())
        }
        Err(e) => {
            tracing::warn!(target = "vpnctld::boosty", error = %e, "{source_tag} sync failed");
            Err(bad_request(&format!("boosty sync failed: {e}")))
        }
    }
}

/// `POST /admin/boosty/sync` — run one reconcile now (auto-enable active,
/// surface lapses). Redirects back; the report is logged.
pub(crate) async fn boosty_sync_now(State(state): State<AppState>) -> Response {
    let settings = match state.inv.get_boosty_settings().await {
        Ok(s) => s,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    // A disabled bridge must not apply flips or deploy nodes — «sync now»
    // is a manual tick of the ENABLED bridge, not a bypass of the switch.
    if !settings.enabled {
        return bad_request("boosty bridge is disabled — enable it in the settings first");
    }
    if let Err(resp) =
        run_boosty_sync_and_deploy(&state, settings.auto_disable_lapsed, "boosty.sync_now").await
    {
        return resp;
    }
    Redirect::to("/admin/boosty").into_response()
}

/// `POST /admin/boosty/link` — link a subscriber to a user.
pub(crate) async fn boosty_link(State(state): State<AppState>, body: String) -> Response {
    let user = form_field(&body, "user").unwrap_or_default();
    if user.is_empty() {
        return bad_request("missing `user` field");
    }
    let subscriber_id = match form_field(&body, "subscriber_id").and_then(|v| v.parse::<i64>().ok())
    {
        Some(id) => id,
        None => return bad_request("missing or invalid `subscriber_id`"),
    };

    let uid = vpnctl_core::UserId(user.clone());
    match state.inv.get_user(&uid).await {
        Ok(Some(_)) => {}
        Ok(None) => return user_not_found(&user),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }
    // Audit-on-actual-mutation: a same-pair re-link is a no-op.
    let changed = match state.inv.link_boosty_subscriber(&uid, subscriber_id).await {
        Ok(b) => b,
        Err(e) => return bad_request(&e.to_string()),
    };
    if changed
        && let Err(e) = state
            .inv
            .audit(
                "admin",
                "boosty.link",
                Some(&user),
                Some(&serde_json::json!({ "subscriber_id": subscriber_id })),
            )
            .await
    {
        tracing::warn!(target = "vpnctld::boosty", error = %e, "audit boosty.link failed");
    }
    Redirect::to("/admin/boosty").into_response()
}

/// `POST /admin/boosty/unlink/{user}` — remove a user's Boosty link.
pub(crate) async fn boosty_unlink(
    State(state): State<AppState>,
    Path(user): Path<String>,
) -> Response {
    // Audit-on-actual-mutation: unlinking an unlinked user is a no-op.
    let changed = match state
        .inv
        .unlink_boosty_subscriber(&vpnctl_core::UserId(user.clone()))
        .await
    {
        Ok(b) => b,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    if changed
        && let Err(e) = state
            .inv
            .audit("admin", "boosty.unlink", Some(&user), None)
            .await
    {
        tracing::warn!(target = "vpnctld::boosty", error = %e, "audit boosty.unlink failed");
    }
    Redirect::to("/admin/boosty").into_response()
}

/// `POST /admin/boosty/disable/{user}` — disable a lapsed subscriber's
/// user (soft-mute; the "confirm disable" button), then re-deploy the
/// user's servers so the node-side access is actually cut.
pub(crate) async fn boosty_disable(
    State(state): State<AppState>,
    Path(user): Path<String>,
) -> Response {
    let uid = vpnctl_core::UserId(user.clone());
    // Same error mapping as user_set_disabled_inner: unknown user → 404,
    // DB failure → 500 (a 400 would blame the operator's request).
    let changed = match state.inv.set_user_disabled(&uid, true).await {
        Ok(b) => b,
        Err(vpnctl_inventory::SqliteInventoryError::Invalid(msg))
            if msg.starts_with("no such user") =>
        {
            return user_not_found(&user);
        }
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    // Audit-on-actual-mutation (NM-10): a double-submit of the confirm
    // button writes nothing and deploys nothing.
    if changed {
        if let Err(e) = state
            .inv
            .audit(
                "admin",
                "boosty.disable",
                Some(&user),
                Some(&serde_json::json!({ "reason": "operator-confirmed lapse" })),
            )
            .await
        {
            tracing::warn!(target = "vpnctld::boosty", error = %e, "audit boosty.disable failed");
        }
        let inv = state.inv.clone();
        let registry = std::sync::Arc::clone(&state.registry);
        let key = crate::app::deploy_key_path();
        let users = vec![user.clone()];
        tokio::spawn(async move {
            crate::boosty_sync_poller::deploy_flipped_users(
                &inv,
                &registry,
                &key,
                &users,
                "boosty.disable",
            )
            .await;
        });
    }
    Redirect::to("/admin/boosty").into_response()
}
