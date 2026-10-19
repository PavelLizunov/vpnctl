use crate::handlers::admin::icons::{icon, status};
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use maud::{Markup, html};

use super::helpers::{humanize_bytes, internal_error, render_page, theme_accent_lang};
use crate::AppState;
use crate::http_util::path_segment_encode;

pub(crate) fn mask_secret(s: &str) -> String {
    let n = s.chars().count();
    if n <= 8 {
        return s.to_string();
    }
    let head: String = s.chars().take(4).collect();
    let tail: String = s.chars().skip(n - 4).collect();
    format!("{head}…{tail} ({n} chars)")
}

fn user_row(
    idx: usize,
    u: &vpnctl_core::User,
    grants_count: usize,
    live_conns: u32,
    traffic_24h: u64,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let sub_token_preview = u.sub_token.as_deref().map(mask_secret);
    let uuid_preview: String = u.uuid.chars().take(8).collect();
    let detail_href = format!("/admin/users/{}", path_segment_encode(&u.id.0));
    let traffic_href = format!("/admin/users/{}/traffic", path_segment_encode(&u.id.0));
    html! {
        tr class=(if live_conns > 0 { "on-green" } else { "" }) {
            td.ed-grid__mut { (format!("{:02}", idx + 1)) }
            td { a.ed-grid__id href=(detail_href) { (u.id.0) } }
            td {
                @if live_conns > 0 {
                    span.ed-stat.ed-stat--active {
                        (icon("circle"))
                        (tr(lang, "online", "онлайн")) " · " (live_conns) " "
                        @if live_conns == 1 { (tr(lang, "conn", "соединение")) }
                        @else { (tr(lang, "conns", "соединений")) }
                    }
                } @else {
                    span.ed-grid__mut { "— " (tr(lang, "offline", "офлайн")) }
                }
            }
            td.num {
                @if traffic_24h > 0 {
                    a href=(traffic_href) style="color: var(--ink);" { b { (humanize_bytes(traffic_24h)) } }
                } @else {
                    span.ed-grid__mut { "—" }
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
                @if u.tuic_password.is_some() { span style="color: var(--green);" { "tuic " (status("check", lang, "Key stored", "Ключ сохранён")) } }
                @else { span.ed-grid__mut { "tuic —" } }
                " · "
                @if u.wireguard_pubkey.is_some() { span style="color: var(--green);" { "wg " (status("check", lang, "Key stored", "Ключ сохранён")) } }
                @else { span.ed-grid__mut { "wg —" } }
            }
            td.num { a.ed-grid__open href=(detail_href) { (tr(lang, "detail · QR", "детали · QR")) (icon("arrow-right")) } }
        }
    }
}

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

    let (users_list, servers_list, grants_map) = tokio::try_join!(
        state.inv.list_users(),
        state.inv.list_servers(),
        state.inv.servers_count_per_user(),
    )
    .map_err(|e| internal_error(anyhow::Error::new(e)))?;
    let heavy = state
        .inv
        .top_users_by_traffic(24, u32::MAX)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "users list: 24h traffic query failed; column left empty");
            Vec::new()
        });
    let traffic_24h: std::collections::HashMap<String, u64> = heavy
        .into_iter()
        .map(|h| (h.user_id.0, h.total_bytes))
        .collect();
    let traffic_of = |id: &str| traffic_24h.get(id).copied().unwrap_or(0);

    let mut live_conns_per_user: std::collections::HashMap<String, u32> =
        std::collections::HashMap::new();
    for server in &servers_list {
        if let Some(snap) = state.snapshot_cache.get_live(&server.id) {
            for connection in &snap.snapshot.connections {
                if let Some(user_id) = connection.metadata.user.as_deref() {
                    *live_conns_per_user.entry(user_id.to_string()).or_default() += 1;
                }
            }
        }
    }

    let grants_per_user: Vec<usize> = users_list
        .iter()
        .map(|u| usize::try_from(grants_map.get(&u.id).copied().unwrap_or(0)).unwrap_or(0))
        .collect();

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
        "traffic" => pairs.sort_by(|a, b| {
            traffic_of(&b.1.id.0)
                .cmp(&traffic_of(&a.1.id.0))
                .then_with(|| a.1.id.0.cmp(&b.1.id.0))
        }),
        _ => pairs.sort_by(|a, b| a.1.id.0.cmp(&b.1.id.0)),
    }
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
                (label) (status(if kind.ends_with("-desc") { "arrow-down" } else { "arrow-up" }, lang, if kind.ends_with("-desc") { "Descending" } else { "Ascending" }, if kind.ends_with("-desc") { "По убыванию" } else { "По возрастанию" }))
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
                "Each user has a public subscription URL at <public address>/api/v1/app/config/<device_id> (address in Settings → System); /sub/<token> remains the LAN-only fallback. Open a row for the QR you'll point a phone at.",
                "У каждого пользователя есть публичный URL подписки <публичный адрес>/api/v1/app/config/<device_id> (адрес в Настройки → Система); /sub/<token> остаётся LAN-only fallback. Открой строку — там QR для телефона.",
            )) { (icon("info")) }
            @if !users_list.is_empty() {
                div.ed-headrow__actions style="font-family: var(--mono); font-size: 11px;" {
                    (crate::i18n::tr(lang, "sort:", "сортировка:"))
                    (sort_link("id", "id"))
                    (sort_link("traffic", crate::i18n::tr(lang, "traffic 24h", "трафик 24ч")))
                    @if sort_kind == "servers-desc" {
                        (sort_link("servers", crate::i18n::tr(lang, "servers", "серверы")))
                    } @else {
                        (sort_link("servers-desc", crate::i18n::tr(lang, "servers", "серверы")))
                    }
                }
            }
        }

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
                        (icon("search")) (crate::i18n::tr(lang, "go", "ок"))
                    }
                    @if !q_lower.is_empty() {
                        a href=(make_sort_href(sort_kind)) style="color: var(--mute);" {
                            (icon("x")) (crate::i18n::tr(lang, "clear", "очистить"))
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
            form.ed-users-new method="post" action="/admin/users"
                 style="display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-left: auto; padding-left: 10px; border-left: 1px dashed var(--acc);" {
                span.ed-inbar__label { (crate::i18n::tr(lang, "new user", "новый пользователь")) }
                input type="text" name="id" required="required"
                      placeholder="alice"
                      pattern="(?!.*\\.\\.)[a-z0-9][a-z0-9._\\-]{0,30}[a-z0-9]"
                      maxlength="32"
                      data-lowercase-id
                      title=(crate::i18n::tr(
                          lang,
                          "2-32 chars: a-z 0-9 . _ -; must start and end with a-z 0-9; no consecutive dots. Spaces become hyphens; uppercase becomes lowercase; other chars are stripped as you type.",
                          "2-32 символа: a-z 0-9 . _ -; начинаются и заканчиваются на a-z 0-9; без двойных точек. Пробелы превращаются в дефисы; верхний регистр в нижний; остальные символы отбрасываются по мере набора.",
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
                    (icon("plus")) (crate::i18n::tr(lang, "create", "создать")) " " (icon("arrow-right")) " " (crate::i18n::tr(lang, "mints uuid + keys", "uuid + ключи"))
                }
                span.ed-tip title=(crate::i18n::tr(
                    lang,
                    "all keys are auto-generated and shown on the user page.",
                    "Все ключи генерируются автоматически и видны на странице пользователя.",
                )) { (icon("info")) }
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
                    (icon("x")) (crate::i18n::tr(lang, "clear it", "очисти его"))
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
                        th.num { (crate::i18n::tr(lang, "traffic 24h", "трафик 24ч")) }
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
                            traffic_of(&u.id.0),
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
