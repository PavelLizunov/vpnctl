use crate::handlers::admin::icons::icon;
use maud::{Markup, html};
use std::collections::HashSet;
use vpnctl_core::{Server, ServerId, User};
use vpnctl_inventory::{SubAccessAggregates, UaCluster, UserLifecycle};

use crate::AppState;
use crate::handlers::admin::legacy::{qr_svg, user_traffic_limit_section};
use crate::handlers::admin::user_detail::overview::user_overview_summary;
use crate::handlers::admin::users::mask_secret;
use crate::http_util::path_segment_encode;
use crate::i18n::Locale;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn render_overview_tab(
    state: &AppState,
    user: &User,
    app_device_id: &Option<String>,
    app_config_url_str: &Option<String>,
    sub_token: &Option<String>,
    sub_url_str: &Option<String>,
    lifecycle: &UserLifecycle,
    last_seen: Option<chrono::DateTime<chrono::Utc>>,
    access_aggregates: &SubAccessAggregates,
    ua_clusters: &[UaCluster],
    traffic_by_server: &[(ServerId, u64, u64)],
    all_servers: &[Server],
    granted_ids: &HashSet<ServerId>,
    lang: Locale,
) -> Markup {
    html! {
        div.ed-user-overview {
            aside.ed-user-overview__sub {
            div.ed-art-eyebrow style="margin-top: 28px;" {
                (crate::i18n::tr(lang, "Subscription", "Подписка"))
                " "
                span.ed-tip title=(crate::i18n::tr(
                    lang,
                    "The QR and URL are the same ready-to-import artefact, built on the public address from Settings → System; the legacy token endpoint is the LAN fallback.",
                    "QR и URL — один готовый к импорту артефакт на публичном адресе из Настройки → Система; старый token endpoint — LAN fallback.",
                )) { (icon("info")) }
            }
            @match (&app_device_id, &app_config_url_str, &sub_token, &sub_url_str) {
                (Some(device_id), Some(app_url), _, _) => {
                    div style="padding: 12px 14px; background: var(--paper-2); border: 1px solid var(--rule); margin-top: 8px;" {
                        div style="display: flex; justify-content: center; margin-bottom: 12px;" {
                            (qr_svg(app_url))
                        }
                        div style="font-family: var(--mono); font-size: 11px; line-height: 1.7; min-width: 0;" {
                            div.ed-user-overview__url style="word-break: break-all; white-space: normal; font-weight: 500;" { (app_url) }
                            div.ed-user-overview__url title=(device_id) style="color: var(--mute);" { "device " (device_id) }
                            div style="margin-top: 8px; color: var(--soft); font-family: var(--serif); font-style: italic; font-size: 11px;" {
                                (crate::i18n::tr(lang, "Public address: ", "Публичный адрес: "))
                                a href="/admin/settings/system#public-address" style="color: var(--acc);" {
                                    (crate::i18n::tr(lang, "Settings → System", "Настройки → Система"))
                                }
                                ". "
                                (crate::i18n::tr(
                                    lang,
                                    "The user's mobile app polls this URL on a fixed schedule (3600s). ",
                                    "Мобильное приложение опрашивает этот URL по таймеру (3600 сек). ",
                                ))
                                (crate::i18n::tr(
                                    lang,
                                    "Share the QR or the URL — both encode the same thing.",
                                    "Отдай QR или URL — кодируют одно и то же.",
                                ))
                            }
                        }
                    }
                    @if let (Some(token), Some(legacy_url)) = (sub_token.as_ref(), sub_url_str.as_ref()) {
                        details style="margin-top: 8px; font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                            summary style="cursor: pointer;" { (icon("link")) "legacy /sub/<token> fallback (LAN-only)" }
                            div style="padding: 8px 0 0 16px; line-height: 1.7;" {
                                div { span style="color: var(--mute);" { "url   " } (legacy_url) }
                                div { span style="color: var(--mute);" { "token " } (mask_secret(token)) }
                                form method="post"
                                     action=(format!("/admin/users/{}/sub-token/regenerate", path_segment_encode(&user.id.0)))
                                     style="margin-top: 10px;" {
                                    button type="submit"
                                           title=(crate::i18n::tr(
                                               lang,
                                               "Mint a new sub_token. Does NOT affect the app config URL above — that one is keyed by device_id, which is stable.",
                                               "Сгенерировать новый sub_token. НЕ влияет на URL конфигурации приложения выше — он привязан к device_id, который стабилен.",
                                           ))
                                           class="ed-abtn ed-abtn--secondary" {
                                        (icon("rotate-cw")) (crate::i18n::tr(lang, "rotate sub-token", "ротировать sub-token"))
                                    }
                                }
                            }
                        }
                    }
                }
                (None, _, Some(token), Some(url)) => {
                    div style="padding: 8px 0;" {
                        (qr_svg(url))
                        div style="font-family: var(--mono); font-size: 11px; line-height: 1.7; min-width: 0;" {
                            div.ed-user-overview__url { (url) }
                            div { span style="color: var(--mute);" { (crate::i18n::tr(lang, "token ", "token ")) } (mask_secret(token)) }
                            div style="margin-top: 12px; color: var(--soft); font-family: var(--serif); font-style: italic;" {
                                (crate::i18n::tr(lang, "Legacy ", "Легаси ")) span.ed-mono { "/sub/<token>" }
                                (crate::i18n::tr(lang, " URL — LAN-only. No ", " URL — только LAN. У этого пользователя нет "))
                                span.ed-mono { "vpn_router_device_id" }
                                (crate::i18n::tr(
                                    lang,
                                    " for this user, so the public app config URL is not available.",
                                    ", поэтому публичный URL конфигурации приложения недоступен.",
                                ))
                            }
                            form method="post"
                                 action=(format!("/admin/users/{}/sub-token/regenerate", path_segment_encode(&user.id.0)))
                                 style="margin-top: 14px;" {
                                button type="submit"
                                       title=(crate::i18n::tr(
                                           lang,
                                           "Mint a new sub_token; the previous URL stops working immediately",
                                           "Сгенерировать новый sub_token; предыдущий URL перестанет работать немедленно",
                                       ))
                                       class="ed-abtn ed-abtn--warning" {
                                    (icon("rotate-cw")) (crate::i18n::tr(lang, "rotate sub-token", "ротировать sub-token"))
                                }
                            }
                        }
                    }
                }
                _ => {
                    p style="font-family: var(--serif); font-style: italic; color: var(--mute);" {
                        "No sub-token assigned to this user. "
                        form method="post"
                             action=(format!("/admin/users/{}/sub-token/regenerate", path_segment_encode(&user.id.0)))
                             style="display: inline; margin-left: 8px;" {
                            button type="submit"
                                   title="Generate this user's FIRST sub-token + the public /sub/<token> URL. Safe — no existing config to invalidate; the user's QR + clients will start working after this."
                                   class="ed-abtn ed-abtn--recovery" {
                                    (icon("key-round")) "mint sub-token"
                                }
                        }
                    }
                }
            }

            @if user.tuic_password.is_none() {
                div.ed-rule {}
                div.ed-art-eyebrow { (crate::i18n::tr(lang, "Extra-protocol password", "Пароль доп-протоколов")) }
                div style="padding: 12px 0;" {
                    p style="font-family: var(--serif); color: var(--acc); font-size: 13px; line-height: 1.6;" {
                        (icon("triangle-alert"))
                        (crate::i18n::tr(
                            lang,
                            "No tuic_password — TUIC, naive and Hysteria2 links can't be minted for this user, so those protocols silently won't appear in their config (VLESS is unaffected).",
                            "Нет tuic_password — ссылки TUIC, naive и Hysteria2 для этого юзера не собираются, поэтому эти протоколы молча не попадают в его конфиг (VLESS не затронут).",
                        ))
                    }
                    form method="post"
                         action=(format!("/admin/users/{}/tuic-password/mint", path_segment_encode(&user.id.0)))
                         style="margin-top: 10px;" {
                        button type="submit"
                               title=(crate::i18n::tr(
                                   lang,
                                   "Mint this user's per-user password used by TUIC / naive / Hysteria2. Safe — no existing secret to invalidate. Redeploy the user's servers afterwards so the node accepts it.",
                                   "Сгенерировать per-user пароль для TUIC / naive / Hysteria2. Безопасно — нечего инвалидировать. Затем передеплой серверы юзера, чтобы узел принял пароль.",
                               ))
                               class="ed-abtn ed-abtn--recovery" {
                            (icon("key-round")) (crate::i18n::tr(lang, "mint tuic password", "сгенерировать tuic-пароль"))
                        }
                    }
                    p style="font-family: var(--serif); font-style: italic; color: var(--soft); font-size: 12px; margin-top: 8px;" {
                        (crate::i18n::tr(
                            lang,
                            "After minting, redeploy the affected server(s) so the node accepts the new password.",
                            "После генерации передеплой затронутые серверы, чтобы узел принял новый пароль.",
                        ))
                    }
                }
            }
            }
            section {
                (user_overview_summary(
                    user,
                    (lifecycle, last_seen, access_aggregates, ua_clusters),
                    traffic_by_server,
                    (all_servers, granted_ids),
                    lang,
                ))
            }
        }


            (user_traffic_limit_section(state, &user.id, lang).await)

            div.ed-rule {}
            div.ed-art-eyebrow style="margin-top: 24px;" {
                (crate::i18n::tr(lang, "Access state", "Состояние доступа"))
            }
            @if user.disabled {
                div style="border: 1px solid var(--acc); background: var(--paper-2); padding: 14px 16px; margin: 12px 0;" {
                    div style="font-family: var(--serif); font-weight: 500; color: var(--acc); font-size: 14px;" {
                        (crate::i18n::tr(lang, "user is DISABLED", "пользователь ОТКЛЮЧЁН"))
                    }
                    p style="font-family: var(--serif); font-style: italic; color: var(--mute); margin: 6px 0 10px;" {
                        (crate::i18n::tr(
                            lang,
                            "Subscription endpoints return an empty config. Secrets, sub-token, WG keypair and grants are unchanged — re-enable to restore access byte-for-byte.",
                            "Endpoints подписки возвращают пустой config. Секреты, sub-token, WG-пара и гранты не тронуты — включи обратно, чтобы вернуть доступ байт-в-байт.",
                        ))
                    }
                    form method="post"
                         action=(format!("/admin/users/{}/enable", path_segment_encode(&user.id.0)))
                         style="display: inline;" {
                        button type="submit"
                               class="ed-abtn ed-abtn--primary" {
                            (icon("power")) (crate::i18n::tr(lang, "enable user", "включить пользователя"))
                        }
                    }
                }
            } @else {
                div style="background: var(--paper-2); border: 1px solid var(--rule); padding: 12px 14px; margin: 12px 0;" {
                    p style="font-family: var(--serif); font-style: italic; color: var(--mute); margin: 0 0 8px;" {
                        (crate::i18n::tr(
                            lang,
                            "Pause a user's subscription without rotating secrets or revoking grants. Re-enable later restores access byte-for-byte. Useful for: forgotten phone, paused billing, temporary access freeze.",
                            "Поставь подписку на паузу без ротации секретов и без отзыва грантов. Повторное включение вернёт доступ байт-в-байт. Полезно для: забытого телефона, паузы в оплате, временной заморозки доступа.",
                        ))
                    }
                    form method="post"
                         action=(format!("/admin/users/{}/disable", path_segment_encode(&user.id.0)))
                         style="display: inline;" {
                        button type="submit"
                               title=(crate::i18n::tr(
                                   lang,
                                   "Soft mute: /sub/<token> and /api/v1/app/config/<device_id> return an empty config. Everything else is preserved.",
                                   "Мягкое отключение: /sub/<token> и /api/v1/app/config/<device_id> возвращают пустой config. Всё остальное сохраняется.",
                               ))
                               class="ed-abtn ed-abtn--warning ed-abtn--sm" {
                            (icon("pause")) (crate::i18n::tr(lang, "disable user", "отключить пользователя"))
                        }
                    }
                }
            }


    }
}
