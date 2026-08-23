use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};

use crate::AppState;
use crate::handlers::admin::helpers::{
    bad_request, error_resp, format_local_with_pattern, internal_error,
};
use crate::http_util::form_field;

/// `POST /admin/settings/digest-now` — send the fleet digest to Telegram
/// on demand (the daily scheduler sends it automatically; this is the
/// «send it now» button). Audited; 303 back to /admin/settings.
pub(crate) async fn settings_digest_now(State(state): State<AppState>) -> Response {
    crate::node_probe_poller::send_digest(&state.inv).await;
    if let Err(e) = state
        .inv
        .audit("admin", "settings.digest.send", None, None)
        .await
    {
        tracing::warn!(
            target = "vpnctld::admin::settings_digest_now",
            error = %e,
            "audit row for digest-now failed; digest was sent"
        );
    }
    Redirect::to("/admin/settings/notifications#telegram-notifications").into_response()
}

/// `POST /admin/settings/notification-language` — set the operator's
/// notification language (`ru` / `en`). Persisted in
/// `notification_settings.language`; drives `alert_text::render_alert`
/// at push time so Telegram alerts (and the localized test-send) speak
/// the chosen language. Audited; 303-redirects back to /admin/settings.
pub(crate) async fn settings_notification_language(
    State(state): State<AppState>,
    body: String,
) -> Response {
    let lang_in = form_field(&body, "language").unwrap_or_default();
    let lang = lang_in.trim();
    if lang != "ru" && lang != "en" {
        return bad_request("notification language must be 'ru' or 'en'");
    }
    if let Err(e) = state.inv.set_notification_language(Some(lang)).await {
        return internal_error(anyhow::Error::new(e));
    }
    if let Err(e) = state
        .inv
        .audit(
            "admin",
            "settings.notification.language",
            None,
            Some(&serde_json::json!({ "language": lang })),
        )
        .await
    {
        tracing::warn!(
            target = "vpnctld::admin::settings_notification_language",
            error = %e,
            "audit row for notification-language change failed; setting was applied"
        );
    }
    Redirect::to("/admin/settings/notifications").into_response()
}

/// `POST /admin/settings/telegram` — save the Telegram bot
/// transport config (Phase G chunk 3 part 1). Atomic update of both
/// fields. Either empty input → that field set to NULL in DB →
/// `is_enabled()` becomes false → transport disabled.
///
/// **Secret handling:** the token is NEVER logged or echoed back to
/// the operator after save. The audit_log payload records ONLY a
/// boolean («token set or cleared») + the chat_id; the token itself
/// stays in `notification_settings` only.
///
/// **Validation:**
///   * `token` shape: contains `:` and a non-trivial post-colon body
///     (Telegram bot tokens are `<bot_id>:<auth_hex>`); we don't pin
///     the exact length because BotFather has changed the format
///     across years.
///   * `chat_id`: either all-digits (with optional leading `-`) for
///     private chats / groups, OR `@<channel_name>` for public
///     channels.
///
/// Both checks reject obvious garbage with a 400 before the row is
/// written, so a typo doesn't silently kill alerts the operator
/// expects to receive.
pub(crate) async fn settings_telegram(State(state): State<AppState>, body: String) -> Response {
    let token_in = form_field(&body, "telegram_bot_token").unwrap_or_default();
    let chat_id_in = form_field(&body, "telegram_chat_id").unwrap_or_default();
    let token = token_in.trim();
    let chat_id = chat_id_in.trim();

    // Empty token semantics: «keep existing» NOT «clear». The «clear»
    // path requires the operator to clear BOTH fields (their browser
    // sends both inputs even when blank, so detecting clear-intent
    // means «chat_id is also empty»).
    let token_arg: Option<String> = if token.is_empty() {
        if chat_id.is_empty() {
            // Both empty → operator wants to disable. Clear both.
            None
        } else {
            // Operator changed chat_id but didn't paste a new token →
            // preserve the existing token. Fetch current.
            match state.inv.get_telegram_config().await {
                Ok(Some(cfg)) => cfg.token,
                // Singleton row missing — same condition the GET
                // handler surfaces in red on the page. Loud here too
                // so the operator doesn't silently disable the
                // transport while believing they updated chat_id.
                Ok(None) => {
                    return error_resp(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "notification_settings singleton row missing (migration 0014 not applied?) — restart vpnctld to re-run migrations, then re-save with token + chat-id both filled in",
                    );
                }
                Err(e) => return internal_error(anyhow::Error::new(e)),
            }
        }
    } else {
        // Shape gate: Telegram bot tokens always have a colon in the
        // middle. Reject obvious paste-error.
        if !token.contains(':') || token.len() < 20 {
            return bad_request(
                "bot token looks malformed (expected '<bot_id>:<auth_hex>' from @BotFather)",
            );
        }
        Some(token.to_string())
    };

    let chat_id_arg: Option<String> = if chat_id.is_empty() {
        None
    } else {
        // Shape gate: numeric (optionally leading `-`) or `@channel`.
        let looks_numeric = chat_id
            .strip_prefix('-')
            .unwrap_or(chat_id)
            .chars()
            .all(|c| c.is_ascii_digit())
            && !chat_id.is_empty()
            && chat_id != "-";
        let looks_channel = chat_id.starts_with('@')
            && chat_id.len() >= 2
            && chat_id[1..]
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !looks_numeric && !looks_channel {
            return bad_request(
                "chat-id must be numeric (e.g. 123456789, or -100123... for supergroups) or '@channel_name'",
            );
        }
        Some(chat_id.to_string())
    };

    // ─── Phase G chunk 3.5 — proxy_via_server_id ─────────────────
    // Empty = direct (NULL in DB). Non-empty = inventory server id.
    // We DON'T validate the id against the inventory here because:
    //   (1) the dropdown can only emit existing ids OR empty;
    //   (2) if an operator hand-crafts a POST with a fake id, the
    //       build_alert_sink path will log + fall back to direct
    //       mode (loud-but-non-fatal), AND the test-send button will
    //       surface the SSH error the very next time they click it.
    let proxy_via_raw = form_field(&body, "proxy_via_server_id").unwrap_or_default();
    let proxy_arg: Option<String> = if proxy_via_raw.trim().is_empty() {
        None
    } else {
        Some(proxy_via_raw.trim().to_string())
    };

    if let Err(e) = state
        .inv
        .set_telegram_config(
            token_arg.as_deref(),
            chat_id_arg.as_deref(),
            proxy_arg.as_deref(),
        )
        .await
    {
        return internal_error(anyhow::Error::new(e));
    }

    // Audit row. Payload carries the chat_id + proxy_via_server_id
    // (both operator-visible anyway) + a boolean for «token state
    // changed». NEVER the token.
    if let Err(e) = state
        .inv
        .audit(
            "admin",
            "settings.telegram.set",
            None,
            Some(&serde_json::json!({
                "token_set": token_arg.is_some(),
                "chat_id_set": chat_id_arg.is_some(),
                "chat_id": chat_id_arg.as_deref().unwrap_or(""),
                "proxy_via_server_id": proxy_arg.as_deref().unwrap_or(""),
            })),
        )
        .await
    {
        tracing::warn!(
            target = "vpnctld::admin::settings_telegram",
            error = %e,
            "audit row for settings.telegram.set failed; config saved"
        );
    }

    // Fragment anchor → browser scrolls back to the Telegram
    // section instead of jumping to the top of /admin/settings
    // after Save / test-send.
    Redirect::to("/admin/settings/notifications#telegram-notifications").into_response()
}

/// `POST /admin/settings/telegram/test` — synchronously send a test
/// message via the currently-configured Telegram bot. Surfaces
/// success (redirect to /admin/settings) or failure (502 Bad Gateway
/// with the truncated curl-stderr line, so the operator can
/// distinguish «bot blocked», «wrong chat-id», «proxy down», «РФ
/// blocked api.telegram.org» without journalctl access).
///
/// Audit row written either way — operator action, regardless of
/// outcome. Payload includes `success: bool` + error string when
/// failed (NO token).
///
/// **NOT fire-and-forget** — unlike the probe-loop's push, this
/// handler awaits the curl call so the response carries the verdict.
/// Default timeout is 20s (curl `--max-time`), so the operator's
/// HTTP request can take that long in the worst case.
pub(crate) async fn settings_telegram_test(State(state): State<AppState>) -> Response {
    // Use the SAME sink-construction logic as the production push
    // loop (`node_probe_poller::build_alert_sink`) so the test-send
    // path doesn't drift on details like `proxy_via_server_id` —
    // operator's test verifies the exact same pipeline that real
    // alerts use.
    let sink = match crate::node_probe_poller::build_alert_sink(&state.inv).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return bad_request(
                "Telegram transport not configured — fill in both fields on /admin/settings first",
            );
        }
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };

    // Render the test message in the operator's chosen language, in the
    // SAME pretty HTML format real alerts use — so the test verifies not
    // just connectivity but that the operator likes the look + locale.
    let loc = match state.inv.get_telegram_config().await {
        Ok(Some(cfg)) => crate::i18n::Locale::from_lang_code(cfg.language.as_deref()),
        _ => crate::i18n::Locale::En,
    };
    let time_local = format_local_with_pattern(chrono::Utc::now(), "%d.%m %H:%M");
    let sample = crate::alert_text::RenderedAlert {
        icon: "🟢",
        title: crate::i18n::tr(loc, "Telegram connected — vpnctl", "Telegram подключён — vpnctl")
            .to_string(),
        body: crate::i18n::tr(
            loc,
            "This is a test message. Real alerts arrive in this format: a severity icon, what happened, and what to do.",
            "Это тестовое сообщение. Реальные алерты приходят в этом формате: иконка важности, что случилось и что делать.",
        )
        .to_string(),
        action: None,
    };
    let text = crate::alert_text::to_telegram_html(&sample, loc, &time_local, false);
    let send_result = sink.send_text("test", "info", &text, true).await;

    // Audit either way.
    let audit_payload = match &send_result {
        Ok(_) => serde_json::json!({"success": true}),
        Err(e) => serde_json::json!({"success": false, "error": e.to_string()}),
    };
    if let Err(audit_err) = state
        .inv
        .audit(
            "admin",
            "settings.telegram.test_send",
            None,
            Some(&audit_payload),
        )
        .await
    {
        tracing::warn!(
            target = "vpnctld::admin::settings_telegram_test",
            error = %audit_err,
            "audit row for test_send failed; result was {:?}",
            send_result.is_ok()
        );
    }

    match send_result {
        Ok(_) => {
            Redirect::to("/admin/settings/notifications#telegram-notifications").into_response()
        }
        Err(e) => {
            let raw = e.to_string();
            // Don't double up on remediation hints: `classify_ssh_failure`
            // (in alert_sink) already produces a specific message for
            // the SSH path (Permission denied / refused / timed out /
            // host-key). Appending the generic «common causes» list on
            // top of that classified message creates redundancy that
            // dilutes the actionable bit — caught by Pavel during live
            // testing 2026-05-18. Only append the generic list when
            // the failure was NOT SSH-level (curl-direct path or
            // Telegram-API-level «ok:false»).
            let msg = if raw.contains("ssh-then-curl") {
                format!("test-send failed: {e}")
            } else {
                format!(
                    "test-send failed: {e} — common causes: \
                     chat-id wrong (Telegram returns 'chat not found'), \
                     token revoked, \
                     bot never started conversation with you \
                     (open the bot in Telegram + tap Start), \
                     api.telegram.org blocked (use the «egress» dropdown \
                     on /admin/settings to route via an inventory server, \
                     or set VPNCTLD_HTTPS_PROXY env)"
                )
            };
            error_resp(StatusCode::BAD_GATEWAY, &msg)
        }
    }
}
