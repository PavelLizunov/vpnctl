//! Audit timeline page (`/admin/audit`) with filters + pagination, the
//! CSV exports (`/admin/audit.csv`, `/admin/users/{id}/access.csv`), and
//! the audit-payload helpers (summary / redaction / action kind) shared
//! with the dashboard and Boosty surfaces.
//!
//! Extracted from `legacy.rs` as part of the admin submodules refactor.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use maud::{Markup, html};

use super::helpers::{
    display_tz, format_msk_iso, internal_error, render_page, theme_accent_lang, user_not_found,
};
use crate::AppState;
use crate::http_util::path_segment_encode;

/// Pull human-relevant fields out of an audit row's JSON payload
/// for the timeline display. Targets the high-frequency mutations
/// (protocol/kernel enable+disable, grant/revoke, regen, etc.) and
/// emits a compact `key=value` summary. Keys not in the explicit
/// allowlist are skipped (audit payloads sometimes include large
/// arrays we don't want to render inline). Returns empty string
/// when nothing useful surfaces — caller suppresses the separator.
///
/// **NEVER expose secrets** — the allowlist is positive (only the
/// names we explicitly want to render); raw token/password fields
/// stay invisible by default. Pinned by
/// `audit_summary_never_leaks_secret_fields`.
/// v2 5b — deep-copy a payload with secret-looking values replaced, so
/// the <details> expander can show the STRUCTURE without leaking what
/// the summary whitelist deliberately hides. Denylist by key substring.
pub(crate) fn redact_audit_payload(payload: &serde_json::Value) -> serde_json::Value {
    match payload {
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.iter()
                .map(|(k, v)| {
                    let kl = k.to_ascii_lowercase();
                    let secret = kl.contains("password")
                        || kl.contains("private")
                        || kl.contains("token")
                        || kl.contains("secret");
                    let nv = if secret {
                        serde_json::Value::String("<redacted>".into())
                    } else {
                        redact_audit_payload(v)
                    };
                    (k.clone(), nv)
                })
                .collect(),
        ),
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(redact_audit_payload).collect())
        }
        other => other.clone(),
    }
}

pub(crate) fn summarize_audit_payload(payload: &serde_json::Value) -> String {
    let Some(map) = payload.as_object() else {
        return String::new();
    };
    let mut parts: Vec<String> = Vec::new();
    // Whitelist of fields safe to render inline. Order = display order.
    // `protocol`, `kernel`, `user`, `from`, `wg_keypair_provenance`,
    // `new_pubkey`, `newly_added`, `was_present`, `address`,
    // `ssh_port`, `users` (count), `kernels_rendered`,
    // `config_bytes_total`, `protocols` (count).
    const SAFE_KEYS: &[&str] = &[
        "protocol",
        "kernel",
        "user",
        "from",
        "wg_keypair_provenance",
        "newly_added",
        "was_present",
        "address",
        "ssh_port",
        // R2 2026-07-10 — alert.fire rows read as blanks without their
        // kind; bulk grant/ack rows without their count.
        "kind",
        "count",
        "server",
        "name",
        "status",
        "level",
        "payments",
    ];
    for k in SAFE_KEYS {
        if let Some(v) = map.get(*k) {
            // Render as plain string/number/bool — no nested objects
            // (those usually carry secrets). Lists too (could be long).
            let s = match v {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Number(n) => n.to_string(),
                serde_json::Value::Bool(b) => b.to_string(),
                _ => continue,
            };
            parts.push(format!("{k}={s}"));
        }
    }
    parts.join(" ")
}

/// Map an audit action like "server.deploy" to a CSS modifier matching
/// the editorial palette (deploy/create/grant/revoke/...). Unknown
/// suffixes fall back to "other" — never to a known kind, otherwise a
/// new untyped action would silently masquerade as a deploy in the
/// timeline.
pub(crate) fn action_kind(action: &str) -> &'static str {
    let kind = action.split('.').next_back().unwrap_or("");
    match kind {
        "deploy" => "deploy",
        "create" => "create",
        "grant" => "grant",
        "revoke" => "revoke",
        "regenerate" => "regenerate",
        "delete" | "remove" => "delete",
        "bootstrap" => "bootstrap",
        _ => "other",
    }
}

/// Phase D — paginated, filterable audit timeline. Replaces the
/// Phase A placeholder body. Reads `?actor=`, `?action=`, `?page=`
/// from the query string; renders a filter form, sticky-date
/// section headers (Today / Yesterday / `<YYYY-MM-DD>`), and
/// prev/next pagination links. CSV export lives at a separate
/// endpoint (`/admin/audit.csv`) keyed by the same query params.
pub(crate) async fn audit(
    headers: HeaderMap,
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<AuditQuery>,
) -> Result<Markup, Response> {
    let (theme, accent, lang) = theme_accent_lang(&headers);

    let actor = q.actor.as_deref().filter(|s| !s.is_empty());
    let action = q.action.as_deref().filter(|s| !s.is_empty());
    let target = q.target.as_deref().filter(|s| !s.is_empty());
    let exclude = q.action_exclude();
    let hiding = exclude.is_some();
    /// Hard cap so `?page=99999...` can't overflow `page * PAGE_SIZE`.
    /// 1M pages × 50/page = 50M rows — way past any plausible audit
    /// history; clamping there is friendlier than panicking on overflow.
    const MAX_PAGE: i64 = 1_000_000;
    let page = q.page.unwrap_or(0).clamp(0, MAX_PAGE);

    /// Page size — small enough that even a busy operator scans
    /// each page quickly, large enough that 99% of audit history
    /// lookups don't need pagination at all.
    const PAGE_SIZE: i64 = 50;

    // Fetch one extra row to detect "is there a next page?".
    // `page` is already clamped to MAX_PAGE above, so `* PAGE_SIZE` can't
    // overflow i64.
    let offset = page * PAGE_SIZE;
    let entries = state
        .inv
        .recent_audit_paginated(PAGE_SIZE + 1, offset, actor, action, target, exclude)
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;

    // v2 5b — «N events on file · M match» header counts.
    let (audit_total, audit_matched) = state
        .inv
        .audit_counts(actor, action, target, exclude)
        .await
        .unwrap_or((0, 0));
    let has_next = entries.len() as i64 > PAGE_SIZE;
    let visible: Vec<&vpnctl_inventory::AuditEntry> =
        entries.iter().take(PAGE_SIZE as usize).collect();
    let has_prev = page > 0;

    let body = html! {
        div.ed-art-eyebrow { (crate::i18n::t(lang, crate::i18n::K::PageAudit)) }
        h1.ed-art-h1 {
            (crate::i18n::tr(lang, "every ", "каждое "))
            em { (crate::i18n::tr(lang, "mutation", "изменение")) }
            (crate::i18n::tr(lang, " on file", " в базе"))
        }
        p.ed-art-deck {
            (crate::i18n::tr(
                lang,
                "Append-only stream of every state change the daemon or CLI has made to ",
                "Поток append-only — каждое изменение состояния которое демон или CLI сделали в ",
            ))
            span.ed-mono { "/var/lib/vpnctl/inv.db" }
            (crate::i18n::tr(
                lang,
                ". Use the filters to narrow by actor or action prefix; the CSV button exports the same filtered slice.",
                ". Используй фильтры чтобы сузить по автору / префиксу действия; кнопка CSV экспортирует ту же выборку.",
            ))
        }

        div style="font-family: var(--mono); font-size: 11px; color: var(--mute); margin-top: 10px; display: flex; gap: 12px; align-items: baseline;" {
            span {
                (audit_total) " "
                (crate::i18n::noun_for(lang, audit_total, "event on file", "events on file", "событие в записи", "события в записи", "событий в записи"))
                @if actor.is_some() || action.is_some() || target.is_some() || hiding {
                    " · " b style="color: var(--ink);" { (audit_matched) } " "
                    (crate::i18n::tr(lang, "match the filter", "подходят под фильтр"))
                }
            }
            // Housekeeping toggle — the hourly backup.snapshot rows
            // otherwise fill the whole first page (design review
            // 2026-07-10). Preserves the other filters either way.
            @if hiding {
                a href=(audit_url("/admin/audit", actor, action, target, false, None))
                  style="color: var(--acc);"
                  title=(crate::i18n::tr(
                      lang,
                      "Snapshots are hidden. Click to show every row again.",
                      "Снапшоты скрыты. Кликни, чтобы снова показать все строки.",
                  )) {
                    (crate::i18n::tr(lang, "show snapshots →", "показать снапшоты →"))
                }
            } @else {
                a href=(audit_url("/admin/audit", actor, action, target, true, None))
                  style="color: var(--mute);"
                  title=(crate::i18n::tr(
                      lang,
                      "Hide the hourly backup.snapshot housekeeping rows so real changes surface.",
                      "Скрыть почасовые housekeeping-строки backup.snapshot, чтобы всплыли реальные изменения.",
                  )) {
                    (crate::i18n::tr(lang, "hide snapshots →", "скрыть снапшоты →"))
                }
            }
        }
        form method="get" action="/admin/audit"
             style="display: flex; gap: 12px; align-items: baseline; padding: 12px 14px; border: 1px solid var(--rule); margin: 10px 0 24px; font-family: var(--mono); font-size: 11px;" {
            label { (crate::i18n::tr(lang, "actor", "автор")) }
            select name="actor"
                   title=(crate::i18n::tr(
                       lang,
                       "admin = web UI, cli = vpnctl binary on the daemon host, daemon = scheduler / background job",
                       "admin = веб-UI, cli = бинарь vpnctl на хосте демона, daemon = шедулер / фоновая задача",
                   ))
                   style="padding: 3px 6px; border: 1px solid var(--rule-s); font-family: var(--mono); font-size: 11px;" {
                option value="" { (crate::i18n::tr(lang, "(any)", "(любой)")) }
                @for opt in ["admin", "cli", "daemon"] {
                    @if Some(opt) == actor {
                        option value=(opt) selected="selected" { (opt) }
                    } @else {
                        option value=(opt) { (opt) }
                    }
                }
            }
            label { (crate::i18n::tr(lang, "action prefix", "префикс действия")) }
            input type="text" name="action"
                  value=(action.unwrap_or(""))
                  // Hint refreshed post-grant-rename (2026-06-10):
                  // grants now write `user.grant` / `user.revoke` /
                  // `server.grants.bulk_*` — the old bare `grant.` hint
                  // matched only the protocol-override actions.
                  placeholder="server. / user.grant / user. / settings."
                  title=(crate::i18n::tr(
                      lang,
                      "PREFIX match on the action column (not substring — `sub_token` won't match `user.sub_token.regen`; `user.` will). Convention: dot-separated domain.subdomain.verb (e.g. `server.protocol.set_hidden`, `user.grant`, `user.sub_token.regen`). Underscores allowed INSIDE a verb.",
                      "Поиск по ПРЕФИКСУ в колонке action (не подстрока — `sub_token` не найдёт `user.sub_token.regen`; `user.` найдёт). Конвенция: точка-разделитель domain.subdomain.verb (напр. `server.protocol.set_hidden`, `user.grant`, `user.sub_token.regen`). Подчёркивания допустимы ВНУТРИ verb.",
                  ))
                  style="padding: 3px 6px; max-width: 320px; border: 1px solid var(--rule-s); font-family: var(--mono); font-size: 11px;";
            label { (crate::i18n::tr(lang, "target contains", "цель содержит")) }
            input type="text" name="target"
                  value=(target.unwrap_or(""))
                  placeholder=(crate::i18n::tr(lang, "user or server id…", "id юзера или сервера…"))
                  title=(crate::i18n::tr(
                      lang,
                      "SUBSTRING match on the target column — `brat` matches `main-brat`.",
                      "Поиск ПОДСТРОКИ в колонке target — `brat` найдёт `main-brat`.",
                  ))
                  style="padding: 3px 6px; max-width: 180px; border: 1px solid var(--rule-s); font-family: var(--mono); font-size: 11px;";
            button type="submit"
                   title=(crate::i18n::tr(
                       lang,
                       "Apply actor + action-prefix filters. URL stores them so the page is bookmarkable.",
                       "Применить фильтры по автору + префиксу действия. URL сохраняет их — страницу можно бookmark-нуть.",
                   ))
                   style="padding: 3px 10px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                (crate::i18n::t(lang, crate::i18n::K::BtnFilter))
            }
            a href="/admin/audit"
              title=(crate::i18n::tr(
                  lang,
                  "Clear all filters and return to the unfiltered timeline.",
                  "Очистить все фильтры и вернуться к нефильтрованной ленте.",
              ))
              style="padding: 3px 10px; border: 1px solid var(--rule-s); background: transparent; color: var(--mute); font-family: var(--mono); font-size: 11px; text-decoration: none;" {
                (crate::i18n::t(lang, crate::i18n::K::BtnReset))
            }
            a href=(audit_url("/admin/audit.csv", actor, action, target, hiding, None))
              title=(crate::i18n::tr(
                  lang,
                  "Download the currently-filtered slice as CSV (up to 10000 rows). Honours both actor + action filters.",
                  "Скачать текущую выборку как CSV (до 10000 строк). Учитывает оба фильтра.",
              ))
              style="margin-left: auto; padding: 3px 10px; border: 1px solid var(--rule-s); background: transparent; color: var(--ink); font-family: var(--mono); font-size: 11px; text-decoration: none;" {
                (crate::i18n::t(lang, crate::i18n::K::BtnExportCsv))
            }
        }

        @if visible.is_empty() {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute); padding: 24px 0;" {
                @if actor.is_some() || action.is_some() {
                    (crate::i18n::tr(
                        lang,
                        "No audit rows match the current filter.",
                        "Под текущий фильтр не подошла ни одна строка аудита.",
                    ))
                } @else {
                    (crate::i18n::tr(
                        lang,
                        "No audit rows yet — this stream fills as the daemon does work.",
                        "Записей аудита ещё нет — поток наполняется по мере работы демона.",
                    ))
                }
            }
        } @else {
            (audit_timeline_grouped(&visible, lang))
        }

        div style="display: flex; gap: 16px; padding: 16px 0; font-family: var(--mono); font-size: 12px;" {
            @if has_prev {
                a href=(audit_url("/admin/audit", actor, action, target, hiding, Some(page - 1)))
                  style="color: var(--ink); text-decoration: none;" {
                    (crate::i18n::tr(lang, "← prev", "← назад"))
                }
            } @else {
                span style="color: var(--mute);" {
                    (crate::i18n::tr(lang, "← prev", "← назад"))
                }
            }
            @let page_title = match lang {
                crate::i18n::Locale::En => format!(
                    "URL convention: ?page=N is 0-based (omitted when 0). Current URL: ?page={page}. Visible label: page {}.",
                    page + 1
                ),
                crate::i18n::Locale::Ru => format!(
                    "Конвенция URL: ?page=N считается с 0 (пропускается когда 0). Текущий URL: ?page={page}. Видимая метка: страница {}.",
                    page + 1
                ),
            };
            span style="color: var(--mute);" title=(page_title) {
                (crate::i18n::tr(lang, "page ", "стр. ")) (page + 1)
            }
            @if has_next {
                a href=(audit_url("/admin/audit", actor, action, target, hiding, Some(page + 1)))
                  style="color: var(--ink); text-decoration: none;" {
                    (crate::i18n::tr(lang, "next →", "вперёд →"))
                }
            } @else {
                span style="color: var(--mute);" {
                    (crate::i18n::tr(lang, "next →", "вперёд →"))
                }
            }
        }
    };
    Ok(render_page(&state, "audit", &theme, &accent, lang, body).await)
}

/// Query-string args for the audit timeline. All optional; empty
/// string is treated as "no filter on this axis" by the handler.
#[derive(serde::Deserialize, Debug, Default)]
pub(crate) struct AuditQuery {
    pub actor: Option<String>,
    pub action: Option<String>,
    /// v2 5b — substring filter on the target column.
    pub target: Option<String>,
    /// Housekeeping visibility. The hourly `backup.snapshot` rows are
    /// hidden BY DEFAULT (they filled the whole first screen — R2
    /// 2026-07-10); `?hide=none` shows everything. The R1 value
    /// `?hide=snapshots` still parses as the (now default) hidden
    /// state so bookmarks keep working.
    pub hide: Option<String>,
    pub page: Option<i64>,
}

impl AuditQuery {
    /// The exact audit action excluded by the current `hide` value —
    /// single source for the handler, the CSV export and the chip URL.
    pub(crate) fn action_exclude(&self) -> Option<&'static str> {
        match self.hide.as_deref() {
            Some("none") => None,
            _ => Some("backup.snapshot"),
        }
    }
}

/// Build a `/admin/audit*` URL preserving the current filter query.
/// Pass `Some(page)` for paginated HTML targets, `None` for the CSV
/// export endpoint (which doesn't paginate). Single helper avoids the
/// near-duplicate URL builders that the previous chunk had.
fn audit_url(
    base: &str,
    actor: Option<&str>,
    action: Option<&str>,
    target: Option<&str>,
    hide_snapshots: bool,
    page: Option<i64>,
) -> String {
    let mut q = String::from(base);
    let mut sep = '?';
    if let Some(a) = actor {
        q.push(sep);
        q.push_str(&format!("actor={}", path_segment_encode(a)));
        sep = '&';
    }
    if let Some(a) = action {
        q.push(sep);
        q.push_str(&format!("action={}", path_segment_encode(a)));
        sep = '&';
    }
    if let Some(t) = target {
        q.push(sep);
        q.push_str(&format!("target={}", path_segment_encode(t)));
        sep = '&';
    }
    if !hide_snapshots {
        // Hidden is the default — only the SHOW-everything state needs
        // a query param.
        q.push(sep);
        q.push_str("hide=none");
        sep = '&';
    }
    if let Some(p) = page {
        q.push(sep);
        q.push_str(&format!("page={p}"));
    }
    q
}

/// Render the entries grouped by date with sticky `Today / Yesterday
/// / <date>` section headers. Reuses the existing `dashboard_audit`
/// row markup so the visual style stays consistent.
fn audit_timeline_grouped(
    entries: &[&vpnctl_inventory::AuditEntry],
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    use chrono::{Duration, Utc};
    // 2026-05-23 — group day-by-day in the operator-configured
    // display TZ. Otherwise an event at 23:30 UTC (= 02:30 MSK
    // next day) falls into the wrong day-header relative to the
    // ts shown beside it (which is rendered via format_msk_iso =
    // local TZ).
    let tz = display_tz();
    let today = Utc::now().with_timezone(&tz).date_naive();
    let yesterday = today - Duration::days(1);
    let mut current_label: Option<String> = None;
    html! {
        div.ed-time {
            @for e in entries {
                @let day = e.ts.with_timezone(&tz).date_naive();
                @let label = if day == today {
                    tr(lang, "Today", "Сегодня").to_string()
                } else if day == yesterday {
                    tr(lang, "Yesterday", "Вчера").to_string()
                } else {
                    day.format("%Y-%m-%d").to_string()
                };
                @if Some(&label) != current_label.as_ref() {
                    div style="margin: 18px 0 6px; padding: 4px 0; font-family: var(--mono); font-size: 10px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--mute); border-bottom: 1px solid var(--rule);" {
                        (label)
                    }
                }
                div.ed-time-row {
                    span.ed-time-row__t { (format_msk_iso(e.ts)) }
                    span class=(format!("ed-time-row__a ed-time-row__a--{}", action_kind(&e.action))) {
                        (e.action)
                    }
                    span.ed-time-row__tgt {
                        @match &e.target {
                            Some(t) => (t),
                            None => "—",
                        }
                    }
                    span.ed-time-row__pl {
                        (tr(lang, "by ", "автор: ")) (e.actor)
                        @if let Some(p) = &e.payload {
                            @let summary = summarize_audit_payload(p);
                            @if !summary.is_empty() {
                                " · " span.ed-mono { (summary) }
                            }
                            // v2 5b — full payload behind a pure-HTML
                            // <details> expander (CSP-safe, no JS).
                            " "
                            details style="display: inline-block; vertical-align: baseline;" {
                                summary style="cursor: pointer; color: var(--acc); font-family: var(--mono); font-size: 10px; list-style: none; display: inline;" { "{…}" }
                                pre style="margin: 4px 0 0; padding: 8px 10px; background: var(--paper-2); border: 1px solid var(--rule); font-family: var(--mono); font-size: 10px; white-space: pre-wrap; max-width: 680px;" {
                                    (serde_json::to_string_pretty(&redact_audit_payload(p)).unwrap_or_default())
                                }
                            }
                        }
                    }
                }
                @let _ = current_label.replace(label);
            }
        }
    }
}

/// `GET /admin/users/{id}/access.csv` — v2 4c: the full GeoIP-resolved
/// sub-access log for one user as CSV (up to 10k newest rows).
pub(crate) async fn user_access_csv(
    State(state): State<AppState>,
    Path(user_id_str): Path<String>,
) -> Response {
    let uid = vpnctl_core::UserId(user_id_str.clone());
    match state.inv.get_user(&uid).await {
        Ok(Some(_)) => {}
        Ok(None) => return user_not_found(&user_id_str),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }
    const CSV_LIMIT: i64 = 10_000;
    let rows = match state.inv.recent_sub_access_paged(&uid, CSV_LIMIT, 0).await {
        Ok(v) => v,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    let mut out = String::from("ts,ip,country,asn,user_agent,status,is_vpn_egress\n");
    for e in &rows {
        out.push_str(&csv_field(&e.ts.to_rfc3339()));
        out.push(',');
        out.push_str(&csv_field(&e.ip));
        out.push(',');
        out.push_str(&csv_field(e.geo_country.as_deref().unwrap_or("")));
        out.push(',');
        out.push_str(&csv_field(e.geo_asn.as_deref().unwrap_or("")));
        out.push(',');
        out.push_str(&csv_field(e.ua.as_deref().unwrap_or("")));
        out.push(',');
        out.push_str(&e.status.to_string());
        out.push(',');
        out.push_str(if e.is_vpn_egress { "1" } else { "0" });
        out.push('\n');
    }
    let stamp = chrono::Utc::now().format("%Y%m%d");
    let filename = format!("vpnctl-access-{}-{stamp}.csv", user_id_str);
    (
        StatusCode::OK,
        [
            ("content-type", "text/csv; charset=utf-8".to_string()),
            (
                "content-disposition",
                format!("attachment; filename=\"{filename}\""),
            ),
        ],
        out,
    )
        .into_response()
}

/// `GET /admin/audit.csv?actor=...&action=...` — same filter set as
/// the HTML timeline but returns a CSV body with `Content-Disposition:
/// attachment; filename="vpnctl-audit-<YYYYMMDD>.csv"`. Limit is high
/// (10000 rows) — operator running a yearly export shouldn't have to
/// page; if they need more they bump the limit query.
pub(crate) async fn audit_csv(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<AuditQuery>,
) -> Response {
    let actor = q.actor.as_deref().filter(|s| !s.is_empty());
    let action = q.action.as_deref().filter(|s| !s.is_empty());
    let target = q.target.as_deref().filter(|s| !s.is_empty());
    let exclude = q.action_exclude();

    /// Generous cap; the operator can re-export with ?limit= once we
    /// add that to AuditQuery in a follow-up.
    const CSV_LIMIT: i64 = 10_000;

    let entries = match state
        .inv
        .recent_audit_paginated(CSV_LIMIT, 0, actor, action, target, exclude)
        .await
    {
        Ok(v) => v,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };

    // Build CSV manually — adding the `csv` crate for one writer
    // would be over-engineering for 4 columns. Quote any field
    // containing `"`, `,` or newline; double-up internal quotes.
    let mut out = String::from("ts,actor,action,target,payload\n");
    for e in &entries {
        out.push_str(&csv_field(&e.ts.to_rfc3339()));
        out.push(',');
        out.push_str(&csv_field(&e.actor));
        out.push(',');
        out.push_str(&csv_field(&e.action));
        out.push(',');
        out.push_str(&csv_field(e.target.as_deref().unwrap_or("")));
        out.push(',');
        // serde_json::to_string on a Value should never fail, but if
        // it ever did the row would silently lose its payload column.
        // Log instead of swallowing so the operator notices.
        let payload_str = match &e.payload {
            None => String::new(),
            Some(v) => match serde_json::to_string(v) {
                Ok(s) => s,
                Err(err) => {
                    tracing::warn!(
                        target = "vpnctld::admin::audit_csv",
                        audit_id = e.id,
                        error = %err,
                        "audit payload failed to serialize for CSV; emitting empty cell"
                    );
                    String::new()
                }
            },
        };
        out.push_str(&csv_field(&payload_str));
        out.push('\n');
    }

    let stamp = chrono::Utc::now().format("%Y%m%d");
    let filename = format!("vpnctl-audit-{stamp}.csv");
    (
        StatusCode::OK,
        [
            ("content-type", "text/csv; charset=utf-8".to_string()),
            (
                "content-disposition",
                format!("attachment; filename=\"{filename}\""),
            ),
        ],
        out,
    )
        .into_response()
}

/// Quote a single CSV field per RFC 4180. If the field contains
/// `"`, `,`, `\n`, or `\r` we wrap it in double-quotes and double
/// any internal quotes; otherwise return the field verbatim.
fn csv_field(s: &str) -> String {
    // Formula-injection guard (audit 2026-06-10, OWASP CSV-injection):
    // Excel/LibreOffice execute a cell starting with = + - @ as a
    // formula — an attacker-influenced field (user id, alert summary)
    // beginning with `=HYPERLINK(...)` would run on the operator's
    // machine when the export is opened. Standard mitigation: prefix a
    // single quote, which spreadsheets treat as a text marker. Server
    // ids may legitimately start with `-` — they render with a visible
    // leading `'` in a spreadsheet, an accepted cosmetic cost.
    let injectable = matches!(s.chars().next(), Some('=' | '+' | '-' | '@'));
    let s = if injectable {
        format!("'{s}")
    } else {
        s.to_string()
    };
    let needs_quote = s.contains(['"', ',', '\n', '\r']);
    if !needs_quote {
        return s;
    }
    let escaped = s.replace('"', "\"\"");
    format!("\"{escaped}\"")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod csv_tests {
    use super::csv_field;

    /// OWASP CSV-injection pin (audit 2026-06-10): a field starting
    /// with = + - @ must be neutralised with a leading quote so
    /// Excel/LibreOffice render text instead of executing a formula.
    #[test]
    fn csv_field_neutralises_formula_prefixes() {
        assert_eq!(csv_field("=HYPERLINK(1)"), "'=HYPERLINK(1)");
        assert_eq!(csv_field("+1"), "'+1");
        assert_eq!(csv_field("-srv"), "'-srv");
        assert_eq!(csv_field("@cmd"), "'@cmd");
        // Quoting still composes with the injection guard.
        assert_eq!(csv_field("=a,b"), "\"'=a,b\"");
        // Plain fields stay untouched.
        assert_eq!(csv_field("user.grant"), "user.grant");
        assert_eq!(csv_field("a\"b"), "\"a\"\"b\"");
    }
}
