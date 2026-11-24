use crate::handlers::admin::icons::{icon, status};
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use maud::{Markup, html};

use super::grant_targets;
use super::helpers::{
    format_msk_iso, humanize_bytes, internal_error, named_server, render_page, server_names,
    theme_accent_lang,
};
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

struct UserListRow<'a> {
    user: &'a vpnctl_core::User,
    grants_count: usize,
    created_at: Option<chrono::DateTime<chrono::Utc>>,
    last_activity: Option<chrono::DateTime<chrono::Utc>>,
}

/// Unknown dates sort last in both directions.
fn compare_dates(
    a: &Option<chrono::DateTime<chrono::Utc>>,
    b: &Option<chrono::DateTime<chrono::Utc>>,
    descending: bool,
) -> std::cmp::Ordering {
    match (a, b) {
        (Some(a), Some(b)) if descending => b.cmp(a),
        (Some(a), Some(b)) => a.cmp(b),
        (None, None) => std::cmp::Ordering::Equal,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (Some(_), None) => std::cmp::Ordering::Less,
    }
}

fn date_cell(date: Option<chrono::DateTime<chrono::Utc>>) -> Markup {
    html! {
        td.ed-grid__sm {
            @match date {
                Some(ts) => time datetime=(ts.to_rfc3339()) { (format_msk_iso(ts)) },
                None => span.ed-grid__mut { "—" },
            }
        }
    }
}

fn user_row(
    idx: usize,
    row: &UserListRow<'_>,
    live_conns: u32,
    traffic_24h: u64,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let u = row.user;
    let grants_count = row.grants_count;
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
            (date_cell(row.created_at))
            (date_cell(row.last_activity))
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

    let (user_rows, servers_list, grants_map, fleet_servers) = tokio::try_join!(
        state.inv.users_list_with_activity(),
        state.inv.list_servers(),
        state.inv.servers_count_per_user(),
        state.inv.list_fleet_servers(),
    )
    .map_err(|e| internal_error(anyhow::Error::new(e)))?;
    let readiness_by_server = grant_targets::read_many(&state, &fleet_servers).await;
    let grant_names = server_names(&state.inv, &fleet_servers).await?;
    let ready_grant_servers: Vec<&vpnctl_core::Server> = fleet_servers
        .iter()
        .filter(|server| {
            readiness_by_server
                .get(&server.id)
                .is_some_and(|readiness| readiness.is_eligible())
        })
        .collect();
    let skipped_grant_servers: Vec<(&vpnctl_core::Server, grant_targets::GrantReadiness)> =
        fleet_servers
            .iter()
            .filter_map(|server| {
                readiness_by_server
                    .get(&server.id)
                    .copied()
                    .filter(|readiness| !readiness.is_eligible())
                    .map(|readiness| (server, readiness))
            })
            .collect();
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

    let q_lower = query
        .q
        .as_deref()
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_default();
    let mut pairs: Vec<UserListRow<'_>> = user_rows
        .iter()
        .filter(|entry| {
            q_lower.is_empty()
                || entry
                    .user
                    .id
                    .0
                    .to_ascii_lowercase()
                    .contains(q_lower.as_str())
        })
        .map(|entry| UserListRow {
            user: &entry.user,
            grants_count: usize::try_from(grants_map.get(&entry.user.id).copied().unwrap_or(0))
                .unwrap_or(0),
            created_at: entry.created_at,
            last_activity: entry.last_activity,
        })
        .collect();
    let sort_kind = query.sort.as_deref().unwrap_or("id");
    match sort_kind {
        "id-desc" => pairs.sort_by(|a, b| b.user.id.0.cmp(&a.user.id.0)),
        "created" => pairs.sort_by(|a, b| {
            compare_dates(&a.created_at, &b.created_at, false)
                .then_with(|| a.user.id.0.cmp(&b.user.id.0))
        }),
        "created-desc" => pairs.sort_by(|a, b| {
            compare_dates(&a.created_at, &b.created_at, true)
                .then_with(|| a.user.id.0.cmp(&b.user.id.0))
        }),
        "activity" => pairs.sort_by(|a, b| {
            compare_dates(&a.last_activity, &b.last_activity, false)
                .then_with(|| a.user.id.0.cmp(&b.user.id.0))
        }),
        "activity-desc" => pairs.sort_by(|a, b| {
            compare_dates(&a.last_activity, &b.last_activity, true)
                .then_with(|| a.user.id.0.cmp(&b.user.id.0))
        }),
        "servers" => pairs.sort_by(|a, b| {
            a.grants_count
                .cmp(&b.grants_count)
                .then_with(|| a.user.id.0.cmp(&b.user.id.0))
        }),
        "servers-desc" => pairs.sort_by(|a, b| {
            b.grants_count
                .cmp(&a.grants_count)
                .then_with(|| a.user.id.0.cmp(&b.user.id.0))
        }),
        "traffic" | "traffic-asc" => pairs.sort_by(|a, b| {
            let order = traffic_of(&a.user.id.0).cmp(&traffic_of(&b.user.id.0));
            let order = if sort_kind == "traffic" {
                order.reverse()
            } else {
                order
            };
            order.then_with(|| a.user.id.0.cmp(&b.user.id.0))
        }),
        _ => pairs.sort_by(|a, b| a.user.id.0.cmp(&b.user.id.0)),
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
    let total_users = user_rows.len();
    let visible_users = pairs.len();
    let sort_header = |label: &str, asc_kind: &str, desc_kind: &str, numeric: bool| -> Markup {
        let (target, aria_sort, arrow) = match sort_kind {
            sort if sort == asc_kind => (desc_kind, "ascending", "arrow-up"),
            sort if sort == desc_kind => (asc_kind, "descending", "arrow-down"),
            _ if asc_kind == "id" => (asc_kind, "none", "arrow-up"),
            _ => (desc_kind, "none", "arrow-down"),
        };
        let (action_en, action_ru) = if target == asc_kind {
            ("Sort ascending", "Сортировать по возрастанию")
        } else {
            ("Sort descending", "Сортировать по убыванию")
        };
        html! {
            th class=[numeric.then_some("num")] aria-sort=(aria_sort) {
                a href=(make_sort_href(target))
                  style=(if aria_sort == "none" { "display: block; color: inherit;" } else { "display: block; color: var(--ink); text-decoration: underline;" })
                  title=(crate::i18n::tr(lang, action_en, action_ru)) {
                    (label) " " (icon(arrow))
                }
            }
        }
    };

    let body = html! {
        div.ed-art-eyebrow { (crate::i18n::t(lang, crate::i18n::K::PageUsers)) }
        div.ed-headrow {
            h1.ed-sumbar__h {
                (user_rows.len()) " "
                em { (crate::i18n::noun_for(lang, user_rows.len() as u64, "user", "users", "пользователь", "пользователя", "пользователей")) }
                (crate::i18n::tr(lang, " on file", " в базе"))
            }
            span.ed-tip title=(crate::i18n::tr(
                lang,
                "Each user has a public subscription URL at <public address>/api/v1/app/config/<device_id> (address in Settings → System); /sub/<token> remains the LAN-only fallback. Open a row for the QR you'll point a phone at.",
                "У каждого пользователя есть публичный URL подписки <публичный адрес>/api/v1/app/config/<device_id> (адрес в Настройки → Система); /sub/<token> остаётся LAN-only fallback. Открой строку — там QR для телефона.",
            )) { (icon("info")) }
        }

        div.ed-inbar {
            @if !user_rows.is_empty() {
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
                          "Grant access to every READY server: workload-only servers and servers without a verified SSH deploy-key path are skipped. Uncheck to create a user with zero grants — useful for test accounts or paused users.",
                          "Дать доступ ко ВСЕМ ГОТОВЫМ серверам: workload-only и серверы без проверенного SSH deploy-key пути пропускаются. Сними галку, чтобы создать пользователя без грантов — полезно для тестового или приостановленного аккаунта.",
                      )) {
                    input type="checkbox" name="grant_all" value="1" checked="checked" style="margin: 0;";
                    (crate::i18n::tr(lang, "grant all ready servers", "выдать все готовые серверы"))
                }
                @if !fleet_servers.is_empty() {
                    span.ed-grid__mut style="font-size: 10px; line-height: 1.35; max-width: 230px;"
                         title=(crate::i18n::tr(
                             lang,
                             "Eligible servers have a fresh successful deploy-key SSH check on the route vpnctld will use (direct, or the configured jump).",
                             "Готовые серверы имеют свежую успешную проверку SSH deploy-ключом по тому маршруту, который использует vpnctld (напрямую или через настроенный jump).",
                         )) {
                        (ready_grant_servers.len()) " " (crate::i18n::tr(lang, "ready", "готовы"))
                        @if !skipped_grant_servers.is_empty() {
                            " · " (skipped_grant_servers.len()) " " (crate::i18n::tr(lang, "not ready", "не готовы"))
                        }
                    }
                }
                button.ed-abtn.ed-abtn--recovery.ed-abtn--sm type="submit"
                       title=(crate::i18n::tr(
                           lang,
                           "Mint UUID + tuic_password + sub_token + WG keypair, optionally grant every READY server (unverified servers are skipped); redirect to /admin/users/<id> where keys are visible",
                           "Сгенерирует UUID + tuic_password + sub_token + WG-пару, по-желанию выдаст все готовые серверы (непроверенные пропускаются); редирект на /admin/users/<id> где ключи видны",
                       )) {
                    (icon("plus")) (crate::i18n::tr(lang, "create", "создать")) " " (icon("arrow-right")) " " (crate::i18n::tr(lang, "mints uuid + keys", "uuid + ключи"))
                }
                span.ed-tip title=(crate::i18n::tr(
                    lang,
                    "all keys are auto-generated and shown on the user page.",
                    "Все ключи генерируются автоматически и видны на странице пользователя.",
                )) { (icon("info")) }
                @if !ready_grant_servers.is_empty() {
                    details style="flex-basis: 100%; font-family: var(--mono); font-size: 10px; color: var(--mute);"
                            title=(crate::i18n::tr(
                                lang,
                                "These servers currently qualify for automatic grants: fresh deploy-key SSH check on the route vpnctld will use.",
                                "Эти серверы сейчас подходят для автоматической выдачи: свежая проверка SSH deploy-ключом по маршруту, который использует vpnctld.",
                            )) {
                        summary style="cursor: pointer;" {
                            (crate::i18n::tr(lang, "ready targets: ", "готовые цели: "))
                            (ready_grant_servers.len())
                        }
                        div style="margin: 6px 0 0 16px; line-height: 1.55;" {
                            @for (index, server) in ready_grant_servers.iter().enumerate() {
                                @if index > 0 { " · " }
                                b { (named_server(&server.id, &grant_names)) }
                            }
                        }
                    }
                }
                @if !skipped_grant_servers.is_empty() {
                    details style="flex-basis: 100%; font-family: var(--mono); font-size: 10px; color: var(--mute);"
                            title=(crate::i18n::tr(
                                lang,
                                "These servers stay ungranted so the user is never handed access that cannot be deployed.",
                                "Эти серверы останутся без доступа, чтобы пользователь не получил доступ, который невозможно задеплоить.",
                            )) {
                        summary style="cursor: pointer;" {
                            (crate::i18n::tr(
                                lang,
                                "why some servers are skipped",
                                "почему часть серверов пропускается",
                            ))
                        }
                        ul style="margin: 6px 0 0 16px; padding: 0; line-height: 1.55;" {
                            @for (server, readiness) in &skipped_grant_servers {
                                li {
                                    b { (named_server(&server.id, &grant_names)) }
                                    " — " (readiness.reason(lang))
                                    @if *readiness != grant_targets::GrantReadiness::WorkloadOnly {
                                        " · "
                                        a href=(grant_targets::GrantReadiness::check_href(&server.id)) style="color: var(--acc);" {
                                            (crate::i18n::tr(lang, "check SSH access", "проверить SSH-доступ"))
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        @if user_rows.is_empty() {
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
                        (sort_header(crate::i18n::tr(lang, "user", "пользователь"), "id", "id-desc", false))
                        th { (crate::i18n::tr(lang, "presence", "присутствие")) }
                        (sort_header(crate::i18n::tr(lang, "date added", "дата добавления"), "created", "created-desc", false))
                        (sort_header(crate::i18n::tr(lang, "last activity", "последняя активность"), "activity", "activity-desc", false))
                        (sort_header(crate::i18n::tr(lang, "weighted traffic 24h", "взвеш. трафик 24ч"), "traffic-asc", "traffic", true))
                        th { "uuid" }
                        th { "sub-token" }
                        (sort_header(crate::i18n::tr(lang, "servers", "серверы"), "servers", "servers-desc", true))
                        th { (crate::i18n::tr(lang, "keys", "ключи")) }
                        th {}
                    }
                }
                tbody {
                    @for (display_idx, row) in pairs.iter().enumerate() {
                        (user_row(
                            display_idx,
                            row,
                            live_conns_per_user.get(&row.user.id.0).copied().unwrap_or(0),
                            traffic_of(&row.user.id.0),
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
