use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use maud::{Markup, html};

use super::super::helpers::*;
use crate::AppState;
use crate::http_util::form_field;
// ────────────────────────────────────────────────────────────────────────
//  Phase E — add-server wizard.
//
//  Sub-iter 4a (this commit): step-1 form + submit + step-2 stub.
//  Sub-iter 4b: SSE handler streaming `vpnctl bootstrap` + `vpnctl deploy`.
//  Sub-iter 4c: completion page + audit + return to /admin/servers.
//
//  The wizard is the operator's main reason for the admin UI to exist
//  per CLAUDE.md "Strategic context" — paste IP+root password and the
//  daemon does the rest. Sub-iter 4a establishes the session plumbing
//  so 4b can focus on the SSE plumbing without also designing input
//  validation and cookie schemes.
//
//  Security model: the session cookie is HttpOnly, SameSite=Strict,
//  Path=/admin/servers/new, and Max-Age=600s. The CSRF middleware
//  already requires a same-origin Origin header on POST; this stack
//  means a cross-origin attacker can neither read the cookie nor
//  forge a wizard step. The 32-byte random session id is opaque
//  outside the daemon process.
// ────────────────────────────────────────────────────────────────────────

/// Pull a single named cookie's value out of the `Cookie` header.
/// Returns `None` if the header is absent or the cookie name isn't
/// present. Does no URL-decoding — wizard ids are base64-url and
/// don't contain anything that would need decoding.
///
/// Hand-rolled rather than pulling `cookie` crate as a dep — the only
/// existing cookie reader in this module is in `theme_accent`, which
/// also walks the header by hand. Two readers, same pattern.
fn read_cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for piece in raw.split(';') {
        let kv = piece.trim();
        if let Some(rest) = kv.strip_prefix(name)
            && let Some(value) = rest.strip_prefix('=')
        {
            return Some(value);
        }
    }
    None
}

// `form_field(body, name) -> Option<String>` moved to
// `crate::http_util::form_field` (2026-05-18) — same shape, now the
// single source of truth. The wizard's local copy was identical;
// `user_create` / `server_quick_add` / `set_traffic_limit` and 7
// other handlers used a different inline pattern (`unwrap_or("")` +
// `decode_form_value`) that's now `form_field(...).unwrap_or_default()`.

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
                    (tr(lang, "continue →", "продолжить →"))
                }
                a href="/admin/servers"
                  style="font-family: var(--mono); font-size: 11px; color: var(--mute); text-decoration: none; padding: 6px 8px;" {
                    (tr(lang, "cancel", "отмена"))
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
            )) { "ⓘ" }
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
                                    td.step-mark style="width: 20px; color: var(--mute);" { "•" }
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
                        "← " (crate::i18n::tr(lang, "start over", "начать заново"))
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

/// `GET /admin/servers/new/step-2/sse` — the EventSource endpoint
/// the step-2 page connects to. Reads the wizard cookie, fetches the
/// session, builds a `BootstrapPlan`, then streams events from
/// `wizard_bootstrap::run_bootstrap` as Server-Sent Events.
///
/// Events use the named-event form (`event: step\ndata: {json}\n\n`)
/// so the front-end can attach separate handlers per event type via
/// `EventSource.addEventListener('step', …)`. Saves us writing a
/// discriminator in the client JSON parser.
///
/// **Why we delete the session on first attach**: the wizard runs
/// exactly once. After the first SSE handler starts the bootstrap,
/// the session is consumed — re-opening the URL would re-run the
/// whole pipeline (including a second `inv.add_server` that fails
/// with AlreadyExists). Single-shot is the only sane semantics.
pub(crate) async fn wizard_step2_sse(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Response {
    use axum::response::sse::{Event, KeepAlive, Sse};
    use futures_core::Stream;
    use std::pin::Pin;
    use tokio_stream::StreamExt;

    let cookie = read_cookie(&headers, crate::wizard::COOKIE_NAME).map(str::to_string);
    let Some(session_id) = cookie else {
        return bad_request("wizard session missing — start over from /admin/servers/new");
    };
    let Some(session) = state.wizard.get(&session_id) else {
        return bad_request("wizard session expired — start over from /admin/servers/new");
    };
    // Single-shot semantics — after the SSE handler attaches, the
    // session is gone. Refresh on the page falls back to the
    // "session missing" branch (with a "start over" link).
    state.wizard.remove(&session_id);

    // Derive a non-colliding server id from the address. If the
    // operator wizards the same IP twice, `find_available_server_id`
    // picks `<id>-2`, `<id>-3`, … (bounded to avoid an infinite
    // loop on a corrupt inventory). Pure helper — unit-tested in
    // `wizard_bootstrap::tests`.
    let base_id = crate::wizard_bootstrap::derive_server_id(&session.address);
    if base_id.is_empty() {
        // Should be impossible — wizard validates address upfront —
        // but defensive: empty id would fail inv.add_server with a
        // useless error. Surface upfront instead.
        return bad_request(
            "address didn't produce any safe id chars — start over with a different address",
        );
    }
    let existing: std::collections::HashSet<String> = match state.inv.list_servers().await {
        Ok(list) => list.into_iter().map(|s| s.id.0).collect(),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    let server_id = match crate::wizard_bootstrap::find_available_server_id(&existing, &base_id) {
        Ok(s) => s,
        Err(e) => return error_resp(StatusCode::CONFLICT, &e),
    };

    let plan = crate::wizard_bootstrap::BootstrapPlan {
        server_id,
        address: session.address,
        ssh_user: session.ssh_user,
        ssh_port: session.ssh_port,
        root_password: session.root_password,
        deploy_key_path: crate::app::deploy_key_path(),
        known_hosts_path: std::path::PathBuf::from("/var/lib/vpnctl/.ssh/known_hosts"),
    };

    // Map each BootstrapEvent → axum SSE Event with a named event
    // type. The infallible Result wrapper is what axum's Sse::new
    // expects (`Result<Event, Error>`) — we never produce errors
    // here because the bootstrap pipeline encodes failures as
    // `BootstrapEvent::Error` payloads, not stream-level errors.
    let inv = state.inv.clone();
    let registry = std::sync::Arc::clone(&state.registry);
    let raw = crate::wizard_bootstrap::run_bootstrap(plan, inv, registry);
    let mapped = raw.map(|ev| {
        let name = match &ev {
            crate::wizard_bootstrap::BootstrapEvent::Step { .. } => "step",
            crate::wizard_bootstrap::BootstrapEvent::Ok { .. } => "ok",
            crate::wizard_bootstrap::BootstrapEvent::Error { .. } => "error",
        };
        // The SSE Event is built from the JSON-serialised payload.
        // serde_json failure is effectively impossible on our
        // BootstrapEvent types (basic Rust strings + integers,
        // tagged enum), but if it ever happens we keep the original
        // event name and log loudly — silently swapping to a fake
        // error event would have the front-end think a `step` was a
        // terminal failure.
        let json = serde_json::to_string(&ev).unwrap_or_else(|e| {
            tracing::error!(
                target = "vpnctld::wizard",
                event_name = name,
                error = %e,
                "wizard SSE event serialisation failed — emitting placeholder"
            );
            format!("{{\"kind\":\"step\",\"phase\":\"serialise-error\",\"message\":\"daemon failed to serialise this event ({e}); please retry the action\"}}")
        });
        Ok::<_, std::convert::Infallible>(Event::default().event(name).data(json))
    });

    // Box the stream so the return type fits a single Pin<Box<dyn …>>.
    // Without this, `Sse::new` would carry the unnameable `impl
    // Stream` type all the way up to the route registration.
    let stream: Pin<
        Box<dyn Stream<Item = std::result::Result<Event, std::convert::Infallible>> + Send>,
    > = Box::pin(mapped);

    // KeepAlive sends `: keep-alive\n\n` comments every 15s so
    // intermediate proxies (or a tab in the background) don't drop
    // the connection during a long apt-get install.
    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(std::time::Duration::from_secs(15)))
        .into_response()
}

/// `GET /admin/servers/{id}/deploy/sse` — EventSource endpoint that
/// RE-deploys an existing server, streaming `step` / `ok` / `error`
/// events so the operator watches each phase live and sees the terminal
/// status (item-1, 2026-05-31). The heavy lifting is
/// `wizard_bootstrap::run_redeploy`, which ends in an `error` event when
/// any kernel step failed — so a crash-looping sing-box never reads as
/// success (the bug the old synchronous 303-redirect handler had).
///
/// EventSource can only issue GET, so this state-changing request can't
/// ride the POST-only Origin CSRF middleware. Guard explicitly: reject a
/// browser `Sec-Fetch-Site: cross-site` / `none` (a `<img>`/prefetch CSRF
/// attempt). Absent header = non-browser tooling (curl) which carries no
/// ambient admin cookie to forge with, so it's allowed — same posture as
/// the wizard + geoip SSE endpoints, plus basic-auth on the whole tree.
pub(crate) async fn server_deploy_sse(
    axum::extract::Path(server_id): axum::extract::Path<String>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Response {
    use axum::response::sse::{Event, KeepAlive, Sse};
    use futures_core::Stream;
    use std::pin::Pin;
    use tokio_stream::StreamExt;

    // Same-origin guard for the state-changing GET.
    if let Some(sfs) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        // Unified predicate (audit 2026-06-10, same as the geoip SSE):
        // allow only "same-origin" (EventSource from an admin page) and
        // "none" (direct navigation). The old check let "same-site"
        // through while refusing "none" — opposite of the geoip guard.
        if sfs != "same-origin" && sfs != "none" {
            return error_resp(
                StatusCode::FORBIDDEN,
                "cross-origin deploy trigger refused (same-origin only)",
            );
        }
    }

    let sid = vpnctl_core::ServerId(server_id.clone());
    let server = match state.inv.get_server(&sid).await {
        Ok(Some(s)) => s,
        Ok(None) => return not_found(&format!("no such server '{server_id}'")),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };

    let key_path = crate::app::deploy_key_path();
    let raw = crate::wizard_bootstrap::run_redeploy(
        server,
        state.inv.clone(),
        std::sync::Arc::clone(&state.registry),
        key_path,
    );
    let mapped = raw.map(|ev| {
        let name = match &ev {
            crate::wizard_bootstrap::BootstrapEvent::Step { .. } => "step",
            crate::wizard_bootstrap::BootstrapEvent::Ok { .. } => "ok",
            crate::wizard_bootstrap::BootstrapEvent::Error { .. } => "error",
        };
        let json = serde_json::to_string(&ev).unwrap_or_else(|e| {
            tracing::error!(
                target = "vpnctld::redeploy",
                event_name = name,
                error = %e,
                "redeploy SSE event serialisation failed — emitting placeholder"
            );
            format!(
                "{{\"kind\":\"step\",\"phase\":\"serialise-error\",\"message\":\"daemon failed to serialise this event ({e}); please retry the action\"}}"
            )
        });
        Ok::<_, std::convert::Infallible>(Event::default().event(name).data(json))
    });
    let stream: Pin<
        Box<dyn Stream<Item = std::result::Result<Event, std::convert::Infallible>> + Send>,
    > = Box::pin(mapped);
    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(std::time::Duration::from_secs(15)))
        .into_response()
}

/// `GET /admin/servers/deploy-all/sse` — EventSource that re-deploys
/// EVERY server in one streamed pass (the "Deploy all" button, 2026-06-03).
/// Run after adding a user / granting servers so the new UUID reaches all
/// nodes (a grant only updates inv.db; the node's sing-box isn't touched
/// until a deploy). Same Sec-Fetch-Site same-origin guard + basic-auth as
/// the single-server SSE deploy. Best-effort across the fleet — heavy
/// lifting in `wizard_bootstrap::run_deploy_all`.
pub(crate) async fn servers_deploy_all_sse(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Response {
    if let Some(resp) = refuse_cross_origin_sse(&headers) {
        return resp;
    }

    let servers = match state.inv.list_fleet_servers().await {
        Ok(s) => s,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    deploy_servers_sse_response(&state, servers)
}

/// `GET /admin/users/{id}/deploy-pending/sse` — deploys ONLY the servers
/// the pending-deploy banner names for this user. Before 2026-07-10 the
/// banner button reused the fleet-wide deploy-all: one pending `us`
/// redeployed cdn/de/is/nl too — harmless (idempotent, reload-not-
/// restart) but noisy and inconsistent with the scoped banner
/// (operator report, design review R2).
pub(crate) async fn user_deploy_pending_sse(
    headers: HeaderMap,
    Path(user_id_str): Path<String>,
    State(state): State<AppState>,
) -> Response {
    if let Some(resp) = refuse_cross_origin_sse(&headers) {
        return resp;
    }
    let uid = vpnctl_core::UserId(user_id_str.clone());
    match state.inv.get_user(&uid).await {
        Ok(Some(_)) => {}
        Ok(None) => return user_not_found(&user_id_str),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }
    let granted = match state.inv.servers_for_user(&uid).await {
        Ok(v) => v,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    let granted_ids: Vec<vpnctl_core::ServerId> = granted.iter().map(|s| s.id.clone()).collect();
    let pending = match state
        .inv
        .servers_pending_deploy_for_user(&uid, &granted_ids)
        .await
    {
        Ok(v) => v,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    let servers: Vec<vpnctl_core::Server> = granted
        .into_iter()
        .filter(|s| pending.contains(&s.id))
        .collect();
    // Racing a just-finished deploy leaves nothing to do — say so
    // instead of streaming an empty run.
    if servers.is_empty() {
        use axum::response::sse::{Event, KeepAlive, Sse};
        let ev = Event::default()
            .event("ok")
            .data(r#"{"kind":"ok","message":"nothing pending — every granted server already carries this user's config"}"#);
        let stream = tokio_stream::once(Ok::<_, std::convert::Infallible>(ev));
        return Sse::new(stream)
            .keep_alive(KeepAlive::new().interval(std::time::Duration::from_secs(15)))
            .into_response();
    }
    deploy_servers_sse_response(&state, servers)
}

/// Shared Sec-Fetch-Site guard for the SSE deploy triggers. Allows
/// only "same-origin" (EventSource from an admin page) and "none"
/// (direct navigation) — unified predicate from the 2026-06-10 audit.
fn refuse_cross_origin_sse(headers: &HeaderMap) -> Option<Response> {
    if let Some(sfs) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        if sfs != "same-origin" && sfs != "none" {
            return Some(error_resp(
                StatusCode::FORBIDDEN,
                "cross-origin deploy trigger refused (same-origin only)",
            ));
        }
    }
    None
}

/// Stream a `run_deploy_all` pass over `servers` as an SSE response —
/// the shared tail of the fleet-wide and per-user-pending deploy
/// triggers.
fn deploy_servers_sse_response(state: &AppState, servers: Vec<vpnctl_core::Server>) -> Response {
    use axum::response::sse::{Event, KeepAlive, Sse};
    use futures_core::Stream;
    use std::pin::Pin;
    use tokio_stream::StreamExt;

    let key_path = crate::app::deploy_key_path();
    let raw = crate::wizard_bootstrap::run_deploy_all(
        servers,
        state.inv.clone(),
        std::sync::Arc::clone(&state.registry),
        key_path,
    );
    let mapped = raw.map(|ev| {
        let name = match &ev {
            crate::wizard_bootstrap::BootstrapEvent::Step { .. } => "step",
            crate::wizard_bootstrap::BootstrapEvent::Ok { .. } => "ok",
            crate::wizard_bootstrap::BootstrapEvent::Error { .. } => "error",
        };
        let json = serde_json::to_string(&ev).unwrap_or_else(|e| {
            tracing::error!(
                target = "vpnctld::deploy_all",
                event_name = name,
                error = %e,
                "deploy-all SSE event serialisation failed — emitting placeholder"
            );
            format!(
                "{{\"kind\":\"step\",\"phase\":\"serialise-error\",\"message\":\"daemon failed to serialise this event ({e}); please retry the action\"}}"
            )
        });
        Ok::<_, std::convert::Infallible>(Event::default().event(name).data(json))
    });
    let stream: Pin<
        Box<dyn Stream<Item = std::result::Result<Event, std::convert::Infallible>> + Send>,
    > = Box::pin(mapped);
    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(std::time::Duration::from_secs(15)))
        .into_response()
}

/// `GET /admin/servers/{id}/update-kernels/sse` — EventSource endpoint
/// that UPGRADES the kernel binaries on an existing server (update-kernels
/// PR2). For each declared kernel it streams `status → install → done`
/// running ONLY `ensure_installed` (apt upgrade + service restart) — it
/// never renders or applies a config, so it works on inventory-drift nodes
/// without entering the DG-1 UUID-removal guard. The heavy lifting is
/// `wizard_bootstrap::run_update_kernels`, which ends in an `error` event
/// when any kernel step failed.
///
/// EventSource can only issue GET, so this state-changing request can't
/// ride the POST-only Origin CSRF middleware. Guard explicitly: reject a
/// browser `Sec-Fetch-Site: cross-site` / non-same-origin (a `<img>`/
/// prefetch CSRF attempt). Absent header = non-browser tooling (curl)
/// which carries no ambient admin cookie to forge with, so it's allowed —
/// same posture as the deploy + geoip SSE endpoints, plus basic-auth on
/// the whole tree.
pub(crate) async fn server_update_kernels_sse(
    axum::extract::Path(server_id): axum::extract::Path<String>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Response {
    use axum::response::sse::{Event, KeepAlive, Sse};
    use futures_core::Stream;
    use std::pin::Pin;
    use tokio_stream::StreamExt;

    // Same-origin guard for the state-changing GET.
    if let Some(sfs) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        if sfs != "same-origin" && sfs != "none" {
            return error_resp(
                StatusCode::FORBIDDEN,
                "cross-origin update-kernels trigger refused (same-origin only)",
            );
        }
    }

    let sid = vpnctl_core::ServerId(server_id.clone());
    let server = match state.inv.get_server(&sid).await {
        Ok(Some(s)) => s,
        Ok(None) => return not_found(&format!("no such server '{server_id}'")),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };

    let key_path = crate::app::deploy_key_path();
    let raw = crate::wizard_bootstrap::run_update_kernels(
        server,
        state.inv.clone(),
        std::sync::Arc::clone(&state.registry),
        key_path,
    );
    let mapped = raw.map(|ev| {
        let name = match &ev {
            crate::wizard_bootstrap::BootstrapEvent::Step { .. } => "step",
            crate::wizard_bootstrap::BootstrapEvent::Ok { .. } => "ok",
            crate::wizard_bootstrap::BootstrapEvent::Error { .. } => "error",
        };
        let json = serde_json::to_string(&ev).unwrap_or_else(|e| {
            tracing::error!(
                target = "vpnctld::update_kernels",
                event_name = name,
                error = %e,
                "update-kernels SSE event serialisation failed — emitting placeholder"
            );
            format!(
                "{{\"kind\":\"step\",\"phase\":\"serialise-error\",\"message\":\"daemon failed to serialise this event ({e}); please retry the action\"}}"
            )
        });
        Ok::<_, std::convert::Infallible>(Event::default().event(name).data(json))
    });
    let stream: Pin<
        Box<dyn Stream<Item = std::result::Result<Event, std::convert::Infallible>> + Send>,
    > = Box::pin(mapped);
    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(std::time::Duration::from_secs(15)))
        .into_response()
}

/// `GET /admin/servers/update-kernels-all/sse` — EventSource that upgrades
/// the kernel binaries on EVERY server in one streamed pass (the "Update
/// all kernels" button). Same Sec-Fetch-Site same-origin guard + basic-
/// auth as the single-server SSE update. Best-effort across the fleet —
/// heavy lifting in `wizard_bootstrap::run_update_kernels_all`. The
/// 3-segment path avoids the `{id}` clash — same trick as
/// `deploy-all/sse`.
pub(crate) async fn servers_update_kernels_all_sse(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Response {
    use axum::response::sse::{Event, KeepAlive, Sse};
    use futures_core::Stream;
    use std::pin::Pin;
    use tokio_stream::StreamExt;

    if let Some(sfs) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        if sfs != "same-origin" && sfs != "none" {
            return error_resp(
                StatusCode::FORBIDDEN,
                "cross-origin update-kernels trigger refused (same-origin only)",
            );
        }
    }

    let servers = match state.inv.list_fleet_servers().await {
        Ok(s) => s,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };

    let key_path = crate::app::deploy_key_path();
    let raw = crate::wizard_bootstrap::run_update_kernels_all(
        servers,
        state.inv.clone(),
        std::sync::Arc::clone(&state.registry),
        key_path,
    );
    let mapped = raw.map(|ev| {
        let name = match &ev {
            crate::wizard_bootstrap::BootstrapEvent::Step { .. } => "step",
            crate::wizard_bootstrap::BootstrapEvent::Ok { .. } => "ok",
            crate::wizard_bootstrap::BootstrapEvent::Error { .. } => "error",
        };
        let json = serde_json::to_string(&ev).unwrap_or_else(|e| {
            tracing::error!(
                target = "vpnctld::update_kernels",
                event_name = name,
                error = %e,
                "update-kernels-all SSE event serialisation failed — emitting placeholder"
            );
            format!(
                "{{\"kind\":\"step\",\"phase\":\"serialise-error\",\"message\":\"daemon failed to serialise this event ({e}); please retry the action\"}}"
            )
        });
        Ok::<_, std::convert::Infallible>(Event::default().event(name).data(json))
    });
    let stream: Pin<
        Box<dyn Stream<Item = std::result::Result<Event, std::convert::Infallible>> + Send>,
    > = Box::pin(mapped);
    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(std::time::Duration::from_secs(15)))
        .into_response()
}

// ────────────────────────────────────────────────────────────────────────
//  Phase 3c — Settings GeoIP «update now» SSE button.
//
//  Streams the live output of `vpnctl geoip-update` as named SSE
//  events. Auth-gated by the basic-auth middleware (same as every
//  other /admin route). One audit row per fire — provenance only,
//  no payload (the subprocess output is in journalctl).
//
//  See `crate::geoip_update_runner` for the subprocess pattern.
// ────────────────────────────────────────────────────────────────────────

/// SSE source for the Settings GeoIP «update now» button. Streams
/// `/usr/local/bin/vpnctl geoip-update` stdout/stderr line-by-line
/// to the browser. Each Step event carries a `stream:"stdout"` or
/// `"stderr"` field so the front-end can colour stderr lines for
/// the operator. Final Ok/Error event closes the stream.
///
/// CSRF defense: the endpoint is GET (EventSource only does GET),
/// state-changing (spawns a subprocess + writes an audit row).
/// We gate on `Sec-Fetch-Site` — modern browsers stamp it on every
/// fetch; an attacker's `<img src=…>` from a cross-site page would
/// set it to `cross-site` and get rejected here BEFORE the audit
/// or spawn. Absence (CLI / curl / very old browser) is allowed —
/// those aren't the realistic attack surface for a LAN-only
/// homelab admin.
pub(crate) async fn settings_geoip_update_now_sse(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Response {
    use axum::response::sse::{Event, KeepAlive, Sse};
    use futures_core::Stream;
    use std::pin::Pin;
    use tokio_stream::StreamExt;

    if let Some(sfs) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        // "same-origin" = EventSource from /admin/settings page,
        // "none" = direct address-bar navigation. Anything else is
        // a cross-context attach — refuse without spawning or
        // logging. (Returns the unified prefix via error_resp.)
        if sfs != "same-origin" && sfs != "none" {
            return error_resp(
                StatusCode::FORBIDDEN,
                "cross-origin request rejected — open the admin UI directly",
            );
        }
    }

    // One audit row per fire — provenance only. The actual download
    // log goes to journalctl (subprocess stderr). If the audit
    // write fails the fire still proceeds (we don't want the button
    // to mysteriously do nothing because of an unrelated audit
    // problem).
    if let Err(e) = state
        .inv
        .audit("admin", "settings.geoip.update_now.fired", None, None)
        .await
    {
        tracing::warn!(
            target = "vpnctld::admin",
            error = %e,
            "audit write failed for settings.geoip.update_now.fired — subprocess will still run"
        );
    }

    let vpnctl_bin = crate::geoip_update_runner::resolve_vpnctl_bin();
    let raw = crate::geoip_update_runner::run_update(vpnctl_bin);
    let mapped = raw.map(|ev| {
        let name = ev.event_name();
        let json = serde_json::to_string(&ev).unwrap_or_else(|e| {
            tracing::error!(
                target = "vpnctld::admin",
                event_name = name,
                error = %e,
                "geoip-update SSE event serialisation failed — emitting placeholder"
            );
            format!(
                "{{\"kind\":\"step\",\"stream\":\"stderr\",\"message\":\"daemon failed to serialise this event ({e}); please retry the action\"}}"
            )
        });
        Ok::<_, std::convert::Infallible>(Event::default().event(name).data(json))
    });

    let stream: Pin<
        Box<dyn Stream<Item = std::result::Result<Event, std::convert::Infallible>> + Send>,
    > = Box::pin(mapped);

    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(std::time::Duration::from_secs(15)))
        .into_response()
}
