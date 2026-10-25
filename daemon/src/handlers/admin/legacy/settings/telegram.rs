use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};

use crate::AppState;
use crate::handlers::admin::helpers::{
    bad_request, error_resp, format_local_with_pattern, internal_error,
};
use crate::http_util::form_field;

pub(crate) async fn settings_digest_now(State(state): State<AppState>) -> Response {
    match crate::node_probe_poller::send_digest(&state.inv).await {
        Ok(true) => {}
        Ok(false) => {
            return bad_request(
                "Telegram transport unavailable — check the notification settings before sending a digest",
            );
        }
        Err(e) => {
            return error_resp(
                StatusCode::BAD_GATEWAY,
                &format!("digest delivery failed: {e}"),
            );
        }
    }
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

pub(crate) async fn settings_telegram(State(state): State<AppState>, body: String) -> Response {
    let token_in = form_field(&body, "telegram_bot_token").unwrap_or_default();
    let chat_id_in = form_field(&body, "telegram_chat_id").unwrap_or_default();
    let token = token_in.trim();
    let chat_id = chat_id_in.trim();

    let token_arg: Option<String> = if token.is_empty() {
        if chat_id.is_empty() {
            None
        } else {
            match state.inv.get_telegram_config().await {
                Ok(Some(cfg)) => cfg.token,
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
        Some(token.to_string())
    };

    if token_arg
        .as_deref()
        .is_some_and(|value| !crate::alert_sink::valid_telegram_bot_token(value))
    {
        return bad_request(
            "bot token looks malformed (expected '<bot_id>:<auth_token>' from @BotFather)",
        );
    }

    let chat_id_arg: Option<String> = if chat_id.is_empty() {
        None
    } else {
        if !crate::alert_sink::valid_telegram_chat_id(chat_id) {
            return bad_request(
                "chat-id must be numeric (e.g. 123456789, or -100123... for supergroups) or '@channel_name'",
            );
        }
        Some(chat_id.to_string())
    };

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

    Redirect::to("/admin/settings/notifications#telegram-notifications").into_response()
}

pub(crate) async fn settings_telegram_test(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    use crate::i18n::{Locale, tr};
    let lang = Locale::from_request(&headers);
    let sink = match crate::node_probe_poller::build_alert_sink(&state.inv).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return bad_request(
                "Telegram transport not configured — fill in both fields on /admin/settings first",
            );
        }
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };

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
            let prefix = tr(
                lang,
                "test-send failed",
                "не удалось отправить тестовое сообщение",
            );
            let msg = if raw.contains("ssh-then-curl") {
                format!("{prefix}: {e}")
            } else {
                format!(
                    "{prefix}: {e} — {}",
                    tr(
                        lang,
                        "common causes: chat-id wrong (Telegram returns 'chat not found'), \
                         token revoked, bot never started conversation with you \
                         (open the bot in Telegram + tap Start), api.telegram.org blocked \
                         (use the «egress» dropdown on /admin/settings/notifications to route \
                         via an inventory server, or set VPNCTLD_HTTPS_PROXY env)",
                        "частые причины: неверный chat-id (Telegram возвращает 'chat not found'), \
                         токен отозван, диалог с ботом не начат (открой бота в Telegram и нажми Start), \
                         api.telegram.org заблокирован (выбери сервер в поле «выход» \
                         на /admin/settings/notifications для отправки через него \
                         или задай переменную окружения VPNCTLD_HTTPS_PROXY)",
                    ),
                )
            };
            error_resp(StatusCode::BAD_GATEWAY, &msg)
        }
    }
}
