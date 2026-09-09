use super::deploy_sse::read_cookie;
use crate::AppState;
use crate::handlers::admin::helpers::{
    bad_request, internal_error, render_page, theme_accent_lang,
};
use crate::handlers::admin::icons::{icon, status};
use crate::http_util::form_field;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, header};
use axum::response::{IntoResponse, Redirect, Response};
use maud::{Markup, html};
/// `GET /admin/servers/new` — render the wizard's step-1 form.
///
/// Two fields: server address (IP or hostname) and root password.
/// Submit POSTs to the same URL; success goes to `/admin/servers/new/step-2`.
/// Cancel link leads back to `/admin/servers`.
pub(crate) async fn wizard_new(headers: HeaderMap, State(state): State<AppState>) -> Markup {
    let (theme, accent, lang) = theme_accent_lang(&headers);
    use crate::i18n::tr;
    let body = html! {
        div.ed-art-eyebrow { (tr(lang, "Add server · step 1 of 2", "Добавить сервер · шаг 1 из 2")) }
        h1.ed-art-h1 {
            (tr(lang, "Paste an ", "Вставь ")) em { "IP" }
            (tr(lang, " and the ", " и ")) em { (tr(lang, "root password", "root-пароль")) }
        }
        p.ed-art-deck {
            (tr(lang, "The daemon will SSH in as the user below", "Демон зайдёт по SSH под указанным ниже пользователем"))
            // Honest copy (review 2026-06-04): the pipeline pushes the
            // key, installs fail2ban + sing-box and applies the config —
            // it does NOT create a non-root user or harden sshd_config
            // (that's a future `harden` phase). Don't promise it.
            (tr(
                lang,
                ", push its key, install fail2ban + sing-box, render the config, and prove the service is live — all on the next screen. SSH hardening (non-root user, sshd lockdown) is not part of this wizard yet.",
                ", запушит свой ключ, установит fail2ban + sing-box, отрендерит конфиг и проверит что сервис живёт — всё это на следующем экране. SSH-hardening (non-root пользователь, lockdown sshd) пока не входит в этот мастер.",
            ))
        }

        form method="post" action="/admin/servers/new"
             style="margin: 24px 0; padding: 18px 20px; border: 1px solid var(--rule); background: var(--paper); display: flex; flex-direction: column; gap: 14px;" {
            div style="display: flex; flex-direction: column; gap: 4px;" {
                label for="address"
                      style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase;" {
                    (tr(lang, "address", "адрес"))
                }
                input id="address" name="address" type="text" required="required"
                      placeholder="198.51.100.42 or vpn-de1.example.org"
                      autocomplete="off" autocapitalize="none" spellcheck="false"
                      pattern="[A-Za-z0-9.:_-]+"
                      title=(tr(
                          lang,
                          "IPv4, IPv6 or hostname — no shell metacharacters",
                          "IPv4, IPv6 или хост — без shell-метасимволов",
                      ))
                      style="padding: 6px 10px; border: 1px solid var(--rule-s); background: var(--paper); font-family: var(--mono); font-size: 13px; color: var(--ink);";
                p style="font-family: var(--serif); font-style: italic; font-size: 11px; color: var(--mute); margin: 0;" {
                    // Honest copy (review 2026-06-04): the wizard keeps
                    // whatever SSH port you enter — there is no
                    // automatic harden-to-2222 step.
                    (tr(
                        lang,
                        "DigitalOcean droplets must keep SSH on port 22 (Cloud Firewall blocks the rest). The wizard connects on the port you enter and keeps it — no automatic port change.",
                        "Дроплеты DigitalOcean должны держать SSH на 22 (Cloud Firewall блокирует остальное). Мастер подключается на введённый порт и оставляет его — порт автоматически не меняется.",
                    ))
                }
            }
            div style="display: flex; flex-direction: column; gap: 4px;" {
                label for="ssh_user"
                      style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase;" {
                    (tr(lang, "ssh user (default root)", "ssh пользователь (по умолчанию root)"))
                }
                input id="ssh_user" name="ssh_user" type="text" value="root"
                      autocomplete="username" autocapitalize="none" spellcheck="false"
                      pattern="[A-Za-z0-9_-]+" maxlength="32"
                      title=(tr(lang, "Examples: root, debian, ubuntu", "Примеры: root, debian, ubuntu"))
                      style="padding: 6px 10px; border: 1px solid var(--rule-s); background: var(--paper); font-family: var(--mono); font-size: 13px; color: var(--ink); max-width: 240px;";
                p style="font-family: var(--serif); font-style: italic; font-size: 11px; color: var(--mute); margin: 0;" {
                    (tr(
                        lang,
                        "For non-root users, passwordless sudo is required. Bahnhof commonly provides debian.",
                        "Для пользователя не root нужен беспарольный sudo. Bahnhof часто выдаёт пользователя debian.",
                    ))
                }
            }
            div style="display: flex; flex-direction: column; gap: 4px;" {
                label for="root_password"
                      style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase;" {
                    (tr(lang, "ssh password", "ssh-пароль"))
                }
                input id="root_password" name="root_password" type="password" required="required"
                      autocomplete="new-password"
                      style="padding: 6px 10px; border: 1px solid var(--rule-s); background: var(--paper); font-family: var(--mono); font-size: 13px; color: var(--ink);";
                p style="font-family: var(--serif); font-style: italic; font-size: 11px; color: var(--mute); margin: 0;" {
                    // Honest copy (review 2026-06-04): the wizard does
                    // NOT disable password auth — every later step just
                    // uses key auth instead.
                    (tr(
                        lang,
                        "Used once to push our SSH key; every later step authenticates with the key. Held in daemon memory for 10 minutes; nothing is written to disk. Password auth stays as the host had it.",
                        "Используется один раз чтобы запушить наш SSH-ключ; дальше все шаги ходят по ключу. Лежит в памяти демона 10 минут; на диск ничего не пишется. Password-auth остаётся как был на хосте.",
                    ))
                }
            }
            div style="display: flex; flex-direction: column; gap: 4px;" {
                label for="ssh_port"
                      style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase;" {
                    (tr(lang, "ssh port (optional, default 22)", "ssh порт (опционально, по умолч. 22)"))
                }
                input id="ssh_port" name="ssh_port" type="text" inputmode="numeric"
                      placeholder="22"
                      autocomplete="off" autocapitalize="none" spellcheck="false"
                      pattern="[0-9]*"
                      title=(tr(lang, "leave blank for 22; Cloudzy ships 2222", "оставь пусто для 22; у Cloudzy — 2222"))
                      style="padding: 6px 10px; border: 1px solid var(--rule-s); background: var(--paper); font-family: var(--mono); font-size: 13px; color: var(--ink); max-width: 140px;";
                p style="font-family: var(--serif); font-style: italic; font-size: 11px; color: var(--mute); margin: 0;" {
                    (tr(lang, "Leave blank for 22 (the common case). Cloudzy is ", "Оставь пусто для 22 (обычный случай). Cloudzy — это "))
                    span.ed-mono { "2222" }
                    (tr(
                        lang,
                        "; check the hoster's panel if SSH connect-fails on the next screen.",
                        "; проверь панель хостера если SSH-коннект упадёт на следующем экране.",
                    ))
                }
            }
            div style="display: flex; gap: 12px; align-items: center; margin-top: 6px;" {
                button type="submit"
                       title=(tr(
                           lang,
                           "Validate inputs and continue to the bootstrap log",
                           "Проверить ввод и продолжить к bootstrap-логу",
                       ))
                       style="padding: 6px 14px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                    (icon("arrow-right")) (tr(lang, "continue", "продолжить"))
                }
                a href="/admin/servers"
                  style="font-family: var(--mono); font-size: 11px; color: var(--mute); text-decoration: none; padding: 6px 8px;" {
                    (icon("x")) (tr(lang, "cancel", "отмена"))
                }
            }
        }
    };
    render_page(&state, "servers", &theme, &accent, lang, body).await
}

/// `POST /admin/servers/new` — validate the step-1 input, stash it in
/// the wizard session store, set the session cookie, redirect to
/// step 2.
///
/// On validation failure returns 400 with the canonical
/// `vpnctl admin: …` body — the operator fixes the offending field
/// without consulting source. Success redirects to step 2 (303 so a
/// browser refresh lands on step 2, not a duplicate POST).
pub(crate) async fn wizard_new_submit(State(state): State<AppState>, body: String) -> Response {
    let address_raw = form_field(&body, "address").unwrap_or_default();
    let user_raw = form_field(&body, "ssh_user").unwrap_or_default();
    let password_raw = form_field(&body, "root_password").unwrap_or_default();
    let port_raw = form_field(&body, "ssh_port").unwrap_or_default();

    let address = match crate::wizard::validate_address(&address_raw) {
        Ok(s) => s.to_string(),
        Err(why) => {
            return bad_request(&format!("invalid address — {why}"));
        }
    };
    let user_candidate = if user_raw.trim().is_empty() {
        "root"
    } else {
        user_raw.trim()
    };
    let ssh_user = match crate::wizard::validate_ssh_user(user_candidate) {
        Ok(s) => s.to_string(),
        Err(why) => return bad_request(&format!("invalid ssh_user — {why}")),
    };
    if let Err(why) = crate::wizard::validate_password(&password_raw) {
        return bad_request(&format!("invalid root password — {why}"));
    }
    let ssh_port = match crate::wizard::validate_ssh_port(&port_raw) {
        Ok(p) => p,
        Err(why) => {
            return bad_request(&format!("invalid ssh_port — {why}"));
        }
    };

    // Duplicate-address guard (HANDOFF §6 #2): reject at step 1 — before
    // the operator commits to a full bootstrap — if this address already
    // belongs to a registered server. Two records for one node fight over
    // its `users[]` and the second deploy trips the DG-1 guard (the
    // `us` / `us1` incident, 2026-07-08).
    match state.inv.server_id_for_address(&address).await {
        Ok(Some(existing)) => {
            return bad_request(&format!(
                "address '{address}' is already registered to server '{existing}' — one node = one server record; edit '{existing}' instead of bootstrapping a duplicate"
            ));
        }
        Ok(None) => {}
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }

    let session_id = state
        .wizard
        .insert(address, ssh_user, password_raw, ssh_port);

    // Cookie scope: only the wizard endpoints. Path=/admin/servers/new
    // means the browser doesn't ship the session id to /admin/users,
    // /admin/audit, etc.
    let cookie = format!(
        "{name}={id}; HttpOnly; SameSite=Strict; Path=/admin/servers/new; Max-Age=600",
        name = crate::wizard::COOKIE_NAME,
        id = session_id,
    );
    let mut resp = Redirect::to("/admin/servers/new/step-2").into_response();
    if let Ok(v) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(header::SET_COOKIE, v);
    }
    resp
}

/// `GET /admin/servers/new/step-2` — render the streaming-bootstrap
/// page. Pulls the wizard session out of the cookie (same store as
/// step 1 wrote into), then renders a page whose body has:
///
///   * a header with the address being bootstrapped,
///   * a live `<pre>` log pane that an inline EventSource fills in
///     line-by-line as the bootstrap progresses,
///   * a footer that swaps to a "✓ done — go to <server>" link when
///     the bootstrap completes successfully, OR a fail summary +
///     "← start over" link on error.
///
/// The actual bootstrap work happens in `wizard_step2_sse` (the
/// EventSource source), which calls into
/// `crate::wizard_bootstrap::run_bootstrap`. NOTE: the SSE session
/// is SINGLE-SHOT — the first attach consumes it, so a refresh gets
/// «session missing», NOT a re-attach (the bootstrap itself keeps
/// running server-side; result lands on the server detail page +
/// audit timeline). A job-id store with multi-viewer attach is the
/// future fix if re-attach is ever wanted.
///
/// On missing/expired session: 400 + canonical error body — the
/// operator's session has timed out and there's nothing actionable
/// on this screen without it.
pub(crate) async fn wizard_step2_stub(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Response {
    let (theme, accent, lang) = theme_accent_lang(&headers);
    let session =
        read_cookie(&headers, crate::wizard::COOKIE_NAME).and_then(|id| state.wizard.get(id));

    let session = match session {
        Some(s) => s,
        None => {
            // No session = direct hit on step-2 without going through
            // step-1, OR the session expired (10-min TTL). Either way
            // the operator needs to start over.
            return bad_request(
                "wizard session expired or missing — start over from /admin/servers/new",
            );
        }
    };

    // The EventSource URL re-uses the same cookie — the browser
    // ships it automatically because the cookie Path is
    // `/admin/servers/new` (which covers the SSE endpoint too).
    let body = html! {
        div.ed-art-eyebrow {
            (crate::i18n::tr(lang, "Add server · step 2 of 2", "Добавить сервер · шаг 2 из 2"))
        }
        div.ed-headrow {
            h1.ed-sumbar__h {
                (crate::i18n::tr(lang, "Bootstrap ", "Bootstrap ")) em { (crate::i18n::tr(lang, "a fresh node", "свежую ноду")) }
            }
            span.ed-tip title=(crate::i18n::tr(
                lang,
                "SSHes in with the supplied user and password once, installs the deploy key, discards the password, installs kernels, mints secrets, deploys, probes. Non-root users are elevated with passwordless sudo. Don't close this tab — the live log attaches once; the bootstrap finishes server-side either way and the result lands on the server's detail page + audit timeline.",
                "Заходит по SSH под указанным пользователем и паролем один раз, ставит deploy-ключ, забывает пароль, ставит ядра, чеканит секреты, деплоит, пробит. Пользователь не root повышается через беспарольный sudo. Не закрывай вкладку — живой лог подключается один раз; bootstrap всё равно доработает серверно, результат будет на странице сервера и в audit-таймлайне.",
            )) { (status("info", lang, "Information", "Информация")) }
            span style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                (session.address) ":" (session.ssh_port) " · " (session.ssh_user) " " (crate::i18n::tr(lang, "· password used once", "· пароль одноразово"))
            }
        }

        div style="display: grid; grid-template-columns: 340px minmax(0, 1fr); gap: 20px; align-items: start; margin-top: 12px;" {
            div {
                div.ed-art-eyebrow { (crate::i18n::tr(lang, "Target", "Цель")) }
                table.ed-feed style="margin: 8px 0 16px;" {
                    tbody {
                        tr { td.ed-grid__mut style="width: 90px;" { "host" } td { (session.address) ":" (session.ssh_port) } }
                        tr { td.ed-grid__mut { "ssh user" } td { (session.ssh_user) " · " span.ed-grid__mut { (crate::i18n::tr(lang, "password used once", "пароль одноразово")) } } }
                        tr { td.ed-grid__mut { "kernels" } td.ed-grid__sm { "sing-box" } }
                    }
                }
                div.ed-art-eyebrow { (crate::i18n::tr(lang, "Steps", "Шаги")) }
                // The checklist lights up as `step` events arrive
                // (admin.js maps each phase to its row). Phases are the
                // ones wizard_bootstrap actually emits.
                table.ed-feed id="wizard-steps" style="margin-top: 8px;" {
                    tbody {
                        @let step_row = |phase: &str, label: &str| -> Markup {
                            html! {
                                tr data-step-phase=(phase) {
                                    td.step-mark style="width: 20px; color: var(--mute);" role="img" aria-label=(crate::i18n::tr(lang, "Pending", "Ожидание")) { (icon("circle-dashed")) }
                                    td { (label) }
                                }
                            }
                        };
                        (step_row("server", crate::i18n::tr(lang, "ssh + deploy key + harden", "ssh + deploy-ключ + харденинг")))
                        (step_row("deploy", crate::i18n::tr(lang, "install kernels + mint secrets", "установка ядер + секреты")))
                        (step_row("apply", crate::i18n::tr(lang, "apply config + start services", "применить конфиг + сервисы")))
                        (step_row("probe", crate::i18n::tr(lang, "probe ports + pin fingerprint", "проба портов + отпечаток")))
                        (step_row("done", crate::i18n::tr(lang, "complete", "готово")))
                    }
                }
                div style="margin-top: 12px;" {
                    a href="/admin/servers/new"
                      style="font-family: var(--mono); font-size: 11px; color: var(--mute); text-decoration: none;" {
                        (icon("arrow-left")) (crate::i18n::tr(lang, "start over", "начать заново"))
                    }
                }
            }
            div {
                div.ed-art-eyebrow {
                    (crate::i18n::tr(lang, "Live log", "Живой лог"))
                    " " span.ed-grid__mut style="font-family: var(--mono); font-size: 10px;" { "SSE · autoscroll" }
                }
                // CSP-safe: admin.js opens the EventSource on load
                // (data-sse-autostart) — no inline <script>.
                pre id="wizard-log"
                    data-sse-autostart="/admin/servers/new/step-2/sse"
                    data-steps-box="wizard-steps"
                    style="margin: 8px 0 0; padding: 14px 18px; border: 1px solid var(--rule); background: var(--paper-tint); font-family: var(--mono); font-size: 12px; line-height: 1.5; color: var(--ink); height: 360px; overflow-y: auto; white-space: pre-wrap;" {
                    (crate::i18n::tr(lang, "▸ connecting to the daemon…", "▸ подключение к демону…"))
                }
            }
        }
    };
    render_page(&state, "servers", &theme, &accent, lang, body)
        .await
        .into_response()
}
