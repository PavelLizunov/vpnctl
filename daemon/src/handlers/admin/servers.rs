//! Server list handler and table row renderer.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use maud::{Markup, html};

use super::helpers::{internal_error, kernel_versions_inline, render_page, theme_accent_lang};
use crate::AppState;
use crate::http_util::path_segment_encode;

/// Truncate an `SHA256:<base64>` host-fingerprint to `SHA256:head4…tail4`
/// for a dense table cell; the full value rides in the cell's `title=`.
/// Non-SHA256 strings (e.g. `(unverified)`) pass through unchanged.
pub(crate) fn fp_short(fp: &str) -> String {
    if let Some(hash) = fp.strip_prefix("SHA256:") {
        let chars: Vec<char> = hash.chars().collect();
        if chars.len() > 10 {
            let head: String = chars.iter().take(4).collect();
            let tail: String = chars[chars.len() - 4..].iter().collect();
            return format!("SHA256:{head}…{tail}");
        }
    }
    fp.to_string()
}

/// One inventory row in the dense `.ed-grid` servers table (densify 2a).
/// Same visible/hidden protocol split as the old card via the pre-loaded
/// hidden matrix (NM-10: defaults to visible when the matrix doesn't know
/// a pid — in-memory cache vs on-disk table diverge only via raw SQL).
fn server_row(
    idx: usize,
    s: &vpnctl_core::Server,
    user_count: i64,
    hidden_matrix: &std::collections::HashMap<
        (vpnctl_core::ServerId, vpnctl_core::ProtocolId),
        bool,
    >,
    health: Option<&vpnctl_inventory::NodeHealthRow>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let mut visible_protos: Vec<&str> = Vec::with_capacity(s.enabled_protocols.len());
    let mut hidden_protos: Vec<&str> = Vec::new();
    for p in &s.enabled_protocols {
        if hidden_matrix
            .get(&(s.id.clone(), p.clone()))
            .copied()
            .unwrap_or(false)
        {
            hidden_protos.push(p.0.as_str());
        } else {
            visible_protos.push(p.0.as_str());
        }
    }
    let visible_str = if visible_protos.is_empty() {
        "—".to_string()
    } else {
        visible_protos.join(" · ")
    };
    let fp_full = s
        .trusted_host_fingerprint
        .as_deref()
        .unwrap_or_else(|| tr(lang, "(unverified)", "(не подтверждён)"));
    let mut health_warnings = Vec::new();
    if let Some(h) = health {
        if h.sing_box_active == Some(false) {
            health_warnings.push(tr(lang, "sing-box down", "sing-box не работает").to_string());
        }
        if h.fail2ban_active == Some(false) {
            health_warnings.push(tr(lang, "fail2ban down", "fail2ban не работает").to_string());
        }
        if let Some(pct) = h
            .mem_available_mib
            .zip(h.mem_total_mib)
            .filter(|(_, total)| *total > 0)
            .map(|(available, total)| 100u64.saturating_sub(available * 100 / total))
            .filter(|pct| *pct > 70)
        {
            health_warnings.push(format!("{} {pct}%", tr(lang, "memory", "память")));
        }
        if let Some(pct) = h
            .disk_used_mib
            .zip(h.disk_total_mib)
            .filter(|(_, total)| *total > 0)
            .map(|(used, total)| (used * 100 / total).min(100))
            .filter(|pct| *pct > 70)
        {
            health_warnings.push(format!("{} {pct}%", tr(lang, "disk", "диск")));
        }
    }
    let has_health_warning = !health_warnings.is_empty();
    let detail_href = format!("/admin/servers/{}", path_segment_encode(&s.id.0));
    html! {
        tr class=(if has_health_warning { "on-warn" } else { "" }) {
            td.ed-grid__mut { (format!("{:02}", idx + 1)) }
            td {
                a.ed-grid__id href=(detail_href) { (s.id.0) }
                @if has_health_warning {
                    " " span.ed-grid__flag title=(health_warnings.join(" · ")) { "⚠" }
                }
            }
            td {
                (s.address) ":" (s.ssh_port)
                " " span.ed-grid__mut { "· " (s.ssh_user) "@" }
            }
            td.ed-grid__mut { (s.hoster) }
            td.num { b { (user_count) } " " (tr(lang, "users", "польз.")) }
            td.ed-grid__sm {
                (visible_str)
                @if !hidden_protos.is_empty() {
                    " "
                    span.ed-grid__flag
                        title=(match lang {
                            crate::i18n::Locale::En => format!(
                                "{} hidden from subscription (still listening on the node): {}",
                                hidden_protos.len(),
                                hidden_protos.join(", "),
                            ),
                            crate::i18n::Locale::Ru => format!(
                                "{} скрыто из подписки (нода продолжает слушать): {}",
                                hidden_protos.len(),
                                hidden_protos.join(", "),
                            ),
                        }) {
                        "+" (hidden_protos.len()) " " (tr(lang, "hidden", "скрыт"))
                    }
                }
            }
            td.ed-grid__mut.ed-grid__sm title=(fp_full) { (fp_short(fp_full)) }
            td.num { (format!("{:.2}", s.usage_coefficient)) }
            td.num { a.ed-grid__open href=(detail_href) { (tr(lang, "open →", "открыть →")) } }
        }
    }
}

pub(crate) async fn servers(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Markup, Response> {
    let (theme, accent, lang) = theme_accent_lang(&headers);

    let (server_list, user_counts, hidden_matrix, latest_health) = tokio::try_join!(
        state.inv.list_servers(),
        state.inv.users_count_per_server(),
        state.inv.list_all_server_protocols_with_hidden(),
        state.inv.latest_node_health_fleet(),
    )
    .map_err(|e| internal_error(anyhow::Error::new(e)))?;

    let body = html! {
        div.ed-art-eyebrow { (crate::i18n::t(lang, crate::i18n::K::PageServers)) }
        div.ed-headrow {
            h1.ed-sumbar__h {
                (server_list.len()) " "
                em { (crate::i18n::noun_for(lang, server_list.len() as u64, "server", "servers", "сервер", "сервера", "серверов")) }
                (crate::i18n::tr(lang, " in inventory", " в инвентаре"))
            }
            span.ed-tip
                title=(crate::i18n::tr(
                    lang,
                    "Read straight from the SQLite inventory. Add a server through the wizard (paste IP + root password, the daemon does the rest) — it bootstraps secrets and deploys the config automatically.",
                    "Читаются напрямую из SQLite-инвентаря. Добавь сервер через мастер (вставь IP + root-пароль, остальное сделает демон) — он сам создаст секреты и задеплоит конфиг.",
                )) { "ⓘ" }
            @if !server_list.is_empty() {
                div.ed-headrow__actions {
                    button type="button"
                           data-sse-url="/admin/servers/update-kernels-all/sse"
                           data-log="update-kernels-log"
                           data-busy-label=(crate::i18n::tr(lang, "updating all kernels… (watch the log)", "обновляю все ядра… (смотри лог)"))
                           data-retry-label=(crate::i18n::tr(lang, "retry update all", "повторить обновление всех"))
                           title=(crate::i18n::tr(
                               lang,
                               "Upgrade the kernel binaries on EVERY server (apt upgrade + service restart) without re-rendering any config. Run after a kernel release to roll the new binary across the fleet. The running config is left untouched, so this is safe even on a node whose inventory has drifted. Best-effort — a down node is reported, the rest still update.",
                               "Обновить бинарники ядер на ВСЕХ серверах (apt upgrade + рестарт сервиса) без перерендера конфига. Запусти после релиза ядра, чтобы раскатать новый бинарь по флоту. Рабочий конфиг не трогается, поэтому безопасно даже на ноде с дрейфом инвентаря. Best-effort — упавшая нода отмечается, остальные обновляются.",
                           ))
                           class="ed-abtn ed-abtn--secondary ed-abtn--sm" {
                        (crate::i18n::tr(lang, "update all kernels", "обновить все ядра"))
                        " (" (server_list.len()) ")"
                    }
                    button id="deploy-button" type="button"
                           data-sse-url="/admin/servers/deploy-all/sse"
                           data-busy-label=(crate::i18n::tr(lang, "deploying all… (watch the log)", "деплою все… (смотри лог)"))
                           data-retry-label=(crate::i18n::tr(lang, "retry deploy all", "повторить деплой всех"))
                           title=(crate::i18n::tr(
                               lang,
                               "Re-deploy EVERY server: pushes each node's sing-box config so newly-added users' UUIDs land on all of them. Run once after adding a user or granting servers. Best-effort — a down node is reported, the rest still deploy.",
                               "Передеплоить ВСЕ серверы: пушит конфиг sing-box на каждую ноду, чтобы UUID новых юзеров попали на все. Нажми один раз после добавления юзера или выдачи грантов. Best-effort — упавшая нода отмечается, остальные деплоятся.",
                           ))
                           class="ed-abtn ed-abtn--recovery ed-abtn--sm" {
                        (crate::i18n::tr(lang, "deploy all servers →", "развернуть все серверы →"))
                        " (" (server_list.len()) ")"
                    }
                }
            }
        }

        @if !server_list.is_empty() {
            section id="fleet-kernel-versions" style="margin: 14px 0;" {
                div.ed-art-eyebrow { (crate::i18n::tr(lang, "Kernel versions", "Версии ядер")) }
                div style="display:grid;gap:5px;margin-top:6px;font-family:var(--mono);font-size:11px;" {
                    @for server in &server_list {
                        div style="display:flex;justify-content:space-between;gap:16px;border-bottom:1px dotted var(--rule);padding:3px 0;" {
                            a href=(format!("/admin/servers/{}", path_segment_encode(&server.id.0))) style="color:var(--ink);" { (server.id.0) }
                            (kernel_versions_inline(
                                server,
                                latest_health
                                    .get(&server.id)
                                    .and_then(|row| row.kernel_versions_json.as_deref()),
                                None,
                            ))
                        }
                    }
                }
            }
        }

        form.ed-inbar method="post" action="/admin/servers/quick-add" {
            span.ed-inbar__label { (crate::i18n::tr(lang, "add server", "добавить сервер")) }
            input type="text" name="id" required="required"
                  placeholder=(crate::i18n::tr(lang, "e.g. fra-01", "напр. fra-01"))
                  pattern="[A-Za-z0-9._-]+"
                  title=(crate::i18n::tr(
                      lang,
                      "Letters, digits, dot, underscore, hyphen — no spaces or slashes",
                      "Буквы, цифры, точка, подчёркивание, дефис — без пробелов и слешей",
                  ))
                  style="max-width: 130px;";
            input type="text" name="address" required="required"
                  placeholder=(crate::i18n::tr(lang, "ip or hostname", "ip или хост"))
                  title=(crate::i18n::tr(
                      lang,
                      "IPv4 / IPv6 / hostname of an already-bootstrapped node",
                      "IPv4 / IPv6 / хост уже развёрнутой ноды",
                  ))
                  style="max-width: 180px;";
            input type="number" name="ssh_port" value="22" min="1" max="65535"
                  title=(crate::i18n::tr(
                      lang,
                      "SSH port — 22 (DO) or 2222 (Cloudzy)",
                      "SSH порт — 22 (DO) или 2222 (Cloudzy)",
                  ))
                  style="max-width: 58px;";
            button type="submit"
                   class="ed-abtn ed-abtn--primary ed-abtn--sm"
                   title=(crate::i18n::tr(
                       lang,
                       "Registers the server with default kernels=sing-box + every sing-box-supported protocol enabled. Tweak everything on the detail page right after.",
                       "Регистрирует сервер с ядром sing-box и всеми поддерживаемыми им протоколами. Настройки правь на странице сервера сразу после.",
                   )) {
                (crate::i18n::tr(lang, "register", "зарегистрировать"))
            }
            span.ed-tip
                title=(crate::i18n::tr(
                    lang,
                    "→ default kernels=sing-box, all kernel-supported protocols enabled. Tweak on the detail page.",
                    "→ ядро sing-box по умолчанию, включены все поддерживаемые им протоколы. Тонкая настройка — на странице сервера.",
                )) { "ⓘ" }
            a.ed-grid__open href="/admin/servers/new" style="margin-left: auto;" {
                (crate::i18n::tr(
                    lang,
                    "wizard → bootstrap a fresh node from scratch",
                    "мастер → развернуть свежую ноду с нуля",
                ))
            }
        }

        @if !server_list.is_empty() {
            pre id="deploy-log" hidden
                style="margin: 0 0 16px; padding: 10px 12px; background: var(--paper-tint); border: 1px solid var(--rule); font-family: var(--mono); font-size: 11px; line-height: 1.5; max-height: 360px; overflow-y: auto; white-space: pre-wrap;" {}
            pre id="update-kernels-log" hidden
                style="margin: 0 0 16px; padding: 10px 12px; background: var(--paper-tint); border: 1px solid var(--rule); font-family: var(--mono); font-size: 11px; line-height: 1.5; max-height: 360px; overflow-y: auto; white-space: pre-wrap;" {}
        }

        @if server_list.is_empty() {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute); padding: 24px 0;" {
                (crate::i18n::tr(lang, "No servers yet. Click ", "Серверов ещё нет. Кликни "))
                span.ed-mono { (crate::i18n::tr(lang, "add server →", "добавить сервер →")) }
                (crate::i18n::tr(
                    lang,
                    " above and the wizard will bootstrap a fresh node — then refresh.",
                    " выше, и мастер подготовит свежую ноду — затем обнови страницу.",
                ))
            }
        } @else {
            table.ed-grid {
                thead {
                    tr {
                        th style="width: 34px;" { "№" }
                        th { (crate::i18n::tr(lang, "server", "сервер")) }
                        th { (crate::i18n::tr(lang, "endpoint", "адрес")) }
                        th { (crate::i18n::tr(lang, "hoster", "хостер")) }
                        th.num { (crate::i18n::tr(lang, "grants", "гранты")) }
                        th { (crate::i18n::tr(lang, "protocols", "протоколы")) }
                        th { (crate::i18n::tr(lang, "fingerprint", "отпечаток")) }
                        th.num { (crate::i18n::tr(lang, "usage ×", "коэф. ×")) }
                        th {}
                    }
                }
                tbody {
                    @for (idx, s) in server_list.iter().enumerate() {
                        (server_row(
                            idx,
                            s,
                            user_counts.get(&s.id).copied().unwrap_or(0),
                            &hidden_matrix,
                            latest_health.get(&s.id),
                            lang,
                        ))
                    }
                }
            }
        }
    };
    Ok(render_page(&state, "servers", &theme, &accent, lang, body).await)
}
