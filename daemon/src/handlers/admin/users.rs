//! Users admin handlers: read-only list page.
//!
//! Add / regenerate / delete go in Phase C-2 once the inventory write
//! paths gain audit-logging (CLAUDE.md invariant). Extracted from
//! `legacy.rs` as part of the admin submodules refactor.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use maud::{Markup, html};

use super::helpers::{internal_error, render_page, theme_accent_lang};
use crate::AppState;
use crate::http_util::path_segment_encode;

/// Mask all but the first/last 4 chars of a long opaque token. Used for
/// sub_token, tuic_password etc. — the operator should be able to spot
/// the right user by the prefix without exposing the full secret in
/// shoulder-surf range.
///
/// Counts in **chars**, not bytes. The token contract for vpnctl is
/// url-safe base64 (`sub_token`, 43 ASCII chars) or other opaque ASCII
/// secrets, so chars and bytes coincide. If a multibyte secret ever
/// shows up here the visible head/tail still come out correctly thanks
/// to `chars()`-based slicing.
pub(crate) fn mask_secret(s: &str) -> String {
    let n = s.chars().count();
    if n <= 8 {
        // Too short to mask meaningfully — show in full.
        return s.to_string();
    }
    let head: String = s.chars().take(4).collect();
    let tail: String = s.chars().skip(n - 4).collect();
    format!("{head}…{tail} ({n} chars)")
}

// `path_segment_encode` moved to `crate::http_util::path_segment_encode`
// (2026-05-18, post-host-fingerprint consolidation pass) — same
// implementation was byte-identical in `daemon/src/wizard_bootstrap.rs`
// (the wizard's doc-comment explicitly admitted the duplication).
// Both surfaces now route through the shared helper.

/// Per-user row in the dense users table (densify 2c).
///
/// `grants_count` is `usize` (the natural count from `Vec::len()`); maud
/// renders any `Display` integer so we don't need to pre-narrow into
/// `i64` and risk an overflow fallback that would silently mislead the
/// operator.
fn user_row(
    idx: usize,
    u: &vpnctl_core::User,
    grants_count: usize,
    live_conns: u32,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let sub_token_preview = u.sub_token.as_deref().map(mask_secret);
    let uuid_preview: String = u.uuid.chars().take(8).collect();
    let detail_href = format!("/admin/users/{}", path_segment_encode(&u.id.0));
    html! {
        tr class=(if live_conns > 0 { "on-green" } else { "" }) {
            td.ed-grid__mut { (format!("{:02}", idx + 1)) }
            td { a.ed-grid__id href=(detail_href) { (u.id.0) } }
            td {
                @if live_conns > 0 {
                    span.ed-stat.ed-stat--active {
                        span.ed-stat__dot {}
                        (tr(lang, "online", "онлайн")) " · " (live_conns) " "
                        @if live_conns == 1 { (tr(lang, "conn", "соединение")) }
                        @else { (tr(lang, "conns", "соединений")) }
                    }
                } @else {
                    span.ed-grid__mut { "— " (tr(lang, "offline", "офлайн")) }
                }
            }
            td.ed-grid__sm title=(u.uuid) { (uuid_preview) "…" }
            td.ed-grid__sm {
                @match &sub_token_preview {
                    Some(s) => span title=(s) { (s) },
                    None => em.ed-grid__mut { (tr(lang, "unset", "не задан")) },
                }
            }
            td.num { b { (grants_count) } }
            td.ed-grid__sm {
                @if u.tuic_password.is_some() { span style="color: var(--green);" { "tuic ✓" } }
                @else { span.ed-grid__mut { "tuic —" } }
                " · "
                @if u.wireguard_pubkey.is_some() { span style="color: var(--green);" { "wg ✓" } }
                @else { span.ed-grid__mut { "wg —" } }
            }
            td.num { a.ed-grid__open href=(detail_href) { (tr(lang, "detail · QR →", "детали · QR →")) } }
        }
    }
}

/// Query params for the user list: search + sort. Both optional;
/// defaults preserve the historic alphabetic-by-id ordering.
/// Sort kinds: "id" (default), "id-desc", "servers" (fewest grants
/// first, ascending), "servers-desc" (most grants first, descending).
/// The bare name is ascending and `-desc` is descending, matching the
/// id / id-desc convention. Search `q` is a case-
/// insensitive substring match on user.id.0 — no fancy fuzzy
/// matching, just enough to cut a 30+ user list down.
#[derive(serde::Deserialize, Default, Debug)]
pub(crate) struct UsersQuery {
    pub q: Option<String>,
    pub sort: Option<String>,
}

pub(crate) async fn users(
    headers: HeaderMap,
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<UsersQuery>,
) -> Result<Markup, Response> {
    let (theme, accent, lang) = theme_accent_lang(&headers);

    // list_users + servers_for_user-per-user would be N+1; instead use
    // the inventory's grants-count map (one query) and look up by user.
    let (users_list, servers_list) =
        tokio::try_join!(state.inv.list_users(), state.inv.list_servers())
            .map_err(|e| internal_error(anyhow::Error::new(e)))?;

    // Presence is an in-memory fold over the already-polled clash-api
    // snapshots. Patched nodes put the authenticated user directly on
    // each connection; unresolved legacy connections stay uncounted on
    // this fleet overview (the user detail keeps the heavier IP fallback).
    let mut live_conns_per_user: std::collections::HashMap<String, u32> =
        std::collections::HashMap::new();
    for server in &servers_list {
        // `get_live`: a stale snapshot (polling stopped) must not keep
        // painting users as connected on this fleet overview.
        if let Some(snap) = state.snapshot_cache.get_live(&server.id) {
            for connection in &snap.snapshot.connections {
                if let Some(user_id) = connection.metadata.user.as_deref() {
                    *live_conns_per_user.entry(user_id.to_string()).or_default() += 1;
                }
            }
        }
    }

    // Per-user grants count: the existing aggregations only group by
    // server_id, not user_id. Since N is small (homelab) we issue one
    // small query per user — this is bounded by the operator's user
    // count and will not be a hot path.
    let mut grants_per_user: Vec<usize> = Vec::with_capacity(users_list.len());
    for u in &users_list {
        let n = state
            .inv
            .servers_for_user(&u.id)
            .await
            .map(|v| v.len())
            .map_err(|e| internal_error(anyhow::Error::new(e)))?;
        grants_per_user.push(n);
    }

    // Apply Pavel iter C2: search filter + sort. We build a sortable
    // (user, grants_count, original_index) tuple list so the row
    // numbering stays stable for the visible subset.
    let q_lower = query
        .q
        .as_deref()
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_default();
    let mut pairs: Vec<(usize, &vpnctl_core::User, usize)> = users_list
        .iter()
        .zip(grants_per_user.iter().copied())
        .enumerate()
        .map(|(i, (u, g))| (i, u, g))
        .filter(|(_, u, _)| {
            q_lower.is_empty() || u.id.0.to_ascii_lowercase().contains(q_lower.as_str())
        })
        .collect();
    let sort_kind = query.sort.as_deref().unwrap_or("id");
    match sort_kind {
        "id-desc" => pairs.sort_by(|a, b| b.1.id.0.cmp(&a.1.id.0)),
        "servers" => pairs.sort_by(|a, b| a.2.cmp(&b.2).then_with(|| a.1.id.0.cmp(&b.1.id.0))),
        "servers-desc" => pairs.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.1.id.0.cmp(&b.1.id.0))),
        _ => pairs.sort_by(|a, b| a.1.id.0.cmp(&b.1.id.0)), // "id" default
    }
    // Helper to build a sort link that preserves the search.
    let make_sort_href = |kind: &str| -> String {
        if q_lower.is_empty() {
            format!("/admin/users?sort={kind}")
        } else {
            format!(
                "/admin/users?sort={kind}&q={}",
                path_segment_encode(&q_lower)
            )
        }
    };
    let total_users = users_list.len();
    let visible_users = pairs.len();
    let sort_link = |kind: &str, label: &str| -> Markup {
        let active = sort_kind == kind;
        html! {
            a href=(make_sort_href(kind))
              style=(if active { "color: var(--ink); text-decoration: underline; margin-left: 8px;" } else { "color: var(--mute); margin-left: 8px;" }) {
                (label)
            }
        }
    };

    let body = html! {
        div.ed-art-eyebrow { (crate::i18n::t(lang, crate::i18n::K::PageUsers)) }
        div.ed-headrow {
            h1.ed-sumbar__h {
                (users_list.len()) " "
                em { (crate::i18n::noun_for(lang, users_list.len() as u64, "user", "users", "пользователь", "пользователя", "пользователей")) }
                (crate::i18n::tr(lang, " on file", " в базе"))
            }
            span.ed-tip title=(crate::i18n::tr(
                lang,
                "Each user has a public subscription URL at https://ninitux.com/api/v1/app/config/<device_id>; /sub/<token> remains the LAN-only fallback. Open a row for the QR you'll point a phone at.",
                "У каждого пользователя есть публичный URL подписки https://ninitux.com/api/v1/app/config/<device_id>; /sub/<token> остаётся LAN-only fallback. Открой строку — там QR для телефона.",
            )) { "ⓘ" }
            @if !users_list.is_empty() {
                div.ed-headrow__actions style="font-family: var(--mono); font-size: 11px;" {
                    (crate::i18n::tr(lang, "sort:", "сортировка:"))
                    // One direction per metric — matches the grants-tab
                    // sort vocabulary (`id ↑ · online ↓ · traffic ↓`).
                    // `?sort=id-desc` still parses for old bookmarks;
                    // it just isn't offered.
                    (sort_link("id", "id ↑"))
                    (sort_link("servers-desc", crate::i18n::tr(lang, "servers ↓", "серверы ↓")))
                    (sort_link("servers", crate::i18n::tr(lang, "servers ↑", "серверы ↑")))
                }
            }
        }

        // Search stays first in DOM: autofocus + Enter must remain a
        // safe GET, never the create POST (Pavel's 2026-05-19 bug).
        div.ed-inbar {
            @if !users_list.is_empty() {
                form method="get" action="/admin/users"
                     style="display: flex; gap: 6px; align-items: center;" {
                    span.ed-inbar__label { (crate::i18n::tr(lang, "search", "поиск")) }
                    input type="text" name="q" value=(q_lower)
                          placeholder=(crate::i18n::tr(lang, "user id substring", "подстрока user id"))
                          autofocus;
                    @if sort_kind != "id" { input type="hidden" name="sort" value=(sort_kind); }
                    button.ed-abtn.ed-abtn--secondary.ed-abtn--sm type="submit" {
                        (crate::i18n::tr(lang, "go", "ок"))
                    }
                    @if !q_lower.is_empty() {
                        a href=(make_sort_href(sort_kind)) style="color: var(--mute);" {
                            (crate::i18n::tr(lang, "× clear", "× очистить"))
                        }
                    }
                }
                @if visible_users != total_users {
                    span.ed-grid__mut {
                        (crate::i18n::tr(lang, "showing ", "показано ")) (visible_users)
                        (crate::i18n::tr(lang, " of ", " из ")) (total_users)
                    }
                }
            }
            form method="post" action="/admin/users"
                 style="display: flex; gap: 8px; align-items: center; margin-left: auto; padding-left: 10px; border-left: 1px dashed var(--accent);" {
                span.ed-inbar__label { (crate::i18n::tr(lang, "new user", "новый пользователь")) }
                // Live-lowercase/sanitize moved to admin.js
                // (`data-lowercase-id`) — the old inline `oninput` was
                // CSP-refused and never ran in a real browser; the
                // `pattern=` + server-side gate were the only guards.
                input type="text" name="id" required="required"
                      placeholder="alice"
                      pattern="[a-z0-9._-]{2,32}"
                      maxlength="32"
                      data-lowercase-id
                      title=(crate::i18n::tr(
                          lang,
                          "2-32 chars: a-z 0-9 . _ - only. Spaces become hyphens; uppercase becomes lowercase; other chars are stripped as you type.",
                          "2-32 символа: a-z 0-9 . _ - только. Пробелы превращаются в дефисы; верхний регистр в нижний; остальные символы отбрасываются по мере набора.",
                      ))
                      style="width: 150px;";
                label style="display: flex; align-items: center; gap: 4px;"
                      title=(crate::i18n::tr(
                          lang,
                          "Grant access to EVERY currently-registered server (default ON). Uncheck to create a user with zero grants — useful for test accounts or paused users.",
                          "Дать доступ КО ВСЕМ зарегистрированным сейчас серверам (по-умолчанию вкл). Сними галку, чтобы создать пользователя без грантов — полезно для тестового или приостановленного аккаунта.",
                      )) {
                    input type="checkbox" name="grant_all" value="1" checked="checked" style="margin: 0;";
                    (crate::i18n::tr(lang, "grant all servers", "выдать все серверы"))
                }
                button.ed-abtn.ed-abtn--recovery.ed-abtn--sm type="submit"
                       title=(crate::i18n::tr(
                           lang,
                           "Mint UUID + tuic_password + sub_token + WG keypair, optionally grant all servers; redirect to /admin/users/<id> where keys are visible",
                           "Сгенерирует UUID + tuic_password + sub_token + WG-пару, по-желанию выдаст все серверы; редирект на /admin/users/<id> где ключи видны",
                       )) {
                    (crate::i18n::tr(lang, "create → mints uuid + keys", "создать → uuid + ключи"))
                }
                span.ed-tip title=(crate::i18n::tr(
                    lang,
                    "all keys are auto-generated and shown on the user page.",
                    "Все ключи генерируются автоматически и видны на странице пользователя.",
                )) { "ⓘ" }
            }
        }

        @if users_list.is_empty() {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute); padding: 24px 0;" {
                (crate::i18n::tr(lang, "No users yet. Type an id above and hit ", "Пользователей пока нет. Введи id выше и нажми "))
                span.ed-mono { (crate::i18n::tr(lang, "create", "создать")) }
                (crate::i18n::tr(lang, ". Then grant server access with the per-server toggles on the user's page.", ". Затем выдай доступ к серверу переключателями на странице юзера."))
            }
        } @else if pairs.is_empty() {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute); padding: 12px 0;" {
                (crate::i18n::tr(lang, "No users match ", "Под фильтр не подошёл никто: "))
                span.ed-mono { "q=" (q_lower) }
                (crate::i18n::tr(lang, ". Loosen the search above or ", ". Расслабь поиск выше или "))
                a href="/admin/users" style="color: var(--ink);" {
                    (crate::i18n::tr(lang, "clear it", "очисти его"))
                }
                "."
            }
        } @else {
            table.ed-grid id="users-grid" {
                thead {
                    tr {
                        th { "№" }
                        th { (crate::i18n::tr(lang, "user", "пользователь")) }
                        th { (crate::i18n::tr(lang, "presence", "присутствие")) }
                        th { "uuid" }
                        th { "sub-token" }
                        th.num { (crate::i18n::tr(lang, "servers", "серверы")) }
                        th { (crate::i18n::tr(lang, "keys", "ключи")) }
                        th {}
                    }
                }
                tbody {
                    @for (display_idx, (_orig_idx, u, g)) in pairs.iter().enumerate() {
                        (user_row(
                            display_idx,
                            u,
                            *g,
                            live_conns_per_user.get(&u.id.0).copied().unwrap_or(0),
                            lang,
                        ))
                    }
                }
            }
            p.ed-grid__mut style="font-family: var(--mono); font-size: 10px; margin-top: 8px;" {
                (crate::i18n::tr(lang, "showing ", "показано ")) (visible_users)
                (crate::i18n::tr(lang, " of ", " из ")) (total_users)
            }
        }
    };
    Ok(render_page(&state, "users", &theme, &accent, lang, body).await)
}
