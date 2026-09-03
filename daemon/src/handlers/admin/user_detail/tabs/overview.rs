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
    ninitux_device_id: &Option<String>,
    ninitux_url_str: &Option<String>,
    sub_token: &Option<String>,
    sub_url_str: &Option<String>,
    lifecycle: &UserLifecycle,
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
            // Subscription URL + QR — the headline for this page.
            //
            // Two URLs may exist per user post-Phase-5 (ninitux cutover,
            // 2026-05-19):
            //   * PRIMARY: the ninitux production URL
            //     `https://ninitux.com/api/v1/app/config/<device_id>` —
            //     the URL clients actually fetch. Only present when the
            //     user has a `vpn_router_device_id` pinned (33/33
            //     production users do; legacy bash-only or freshly-
            //     created users may not).
            //   * SECONDARY / LAN fallback: the legacy `/sub/<token>`
            //     URL served by vpnctld directly on port 18402. Useful
            //     for LAN debugging and as the fallback artefact for
            //     users without a device_id.
            //
            // The QR encodes the PRIMARY URL when available — that's
            // what a mobile-app user must scan. Showing the LAN URL in
            // the QR (the pre-Phase-5 behaviour) silently broke any
            // share-via-QR workflow because the client app can't reach
            // 192.168.0.236 from outside the operator's LAN. Caught by
            // visual review 2026-05-19; this block is the fix.
            div.ed-art-eyebrow style="margin-top: 28px;" {
                (crate::i18n::tr(lang, "Subscription", "Подписка"))
                " "
                span.ed-tip title=(crate::i18n::tr(
                    lang,
                    "The QR and URL are the same ready-to-import artefact. ninitux.com is the production endpoint; the legacy token endpoint is the LAN fallback.",
                    "QR и URL — один готовый к импорту артефакт. ninitux.com — production endpoint; старый token endpoint — LAN fallback.",
                )) { "ⓘ" }
            }
            @match (&ninitux_device_id, &ninitux_url_str, &sub_token, &sub_url_str) {
                (Some(device_id), Some(ninitux), _, _) => {
                    // Primary: ninitux production URL — QR scans this.
                    div style="padding: 12px 14px; background: var(--paper-2); border: 1px solid var(--rule); margin-top: 8px;" {
                        div style="display: flex; justify-content: center; margin-bottom: 12px;" {
                            (qr_svg(ninitux))
                        }
                        div style="font-family: var(--mono); font-size: 11px; line-height: 1.7; min-width: 0;" {
                            div.ed-user-overview__url style="word-break: break-all; white-space: normal; font-weight: 500;" { (ninitux) }
                            div.ed-user-overview__url title=(device_id) style="color: var(--mute);" { "device " (device_id) }
                            div style="margin-top: 8px; color: var(--soft); font-family: var(--serif); font-style: italic; font-size: 11px;" {
                                (crate::i18n::tr(lang, "Production URL served via nginx on ", "Production URL подаётся через nginx на "))
                                span.ed-mono { "ninitux.com" }
                                (crate::i18n::tr(lang, " → vpnctld. ", " → vpnctld. "))
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
                    // Legacy LAN fallback — collapsed below the primary,
                    // muted styling, only useful for LAN debugging.
                    @if let (Some(token), Some(legacy_url)) = (sub_token.as_ref(), sub_url_str.as_ref()) {
                        details style="margin-top: 8px; font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                            summary style="cursor: pointer;" { "legacy /sub/<token> fallback (LAN-only)" }
                            div style="padding: 8px 0 0 16px; line-height: 1.7;" {
                                div { span style="color: var(--mute);" { "url   " } (legacy_url) }
                                div { span style="color: var(--mute);" { "token " } (mask_secret(token)) }
                                form method="post"
                                     action=(format!("/admin/users/{}/sub-token/regenerate", path_segment_encode(&user.id.0)))
                                     style="margin-top: 10px;" {
                                    button type="submit"
                                           title=(crate::i18n::tr(
                                               lang,
                                               "Mint a new sub_token. Does NOT affect the ninitux URL above — that one is keyed by device_id, which is stable.",
                                               "Сгенерировать новый sub_token. НЕ влияет на ninitux URL выше — тот ключевой по device_id, который стабилен.",
                                           ))
                                           class="ed-abtn ed-abtn--secondary" {
                                        (crate::i18n::tr(lang, "rotate sub-token", "ротировать sub-token"))
                                    }
                                }
                            }
                        }
                    }
                }
                (None, _, Some(token), Some(url)) => {
                    // No device_id pinned — fall back to legacy /sub/<token>
                    // as the primary. Operator should pin a device_id to
                    // unlock the ninitux URL (import script or future web
                    // action).
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
                                    " pinned for this user, so the production ",
                                    ", поэтому production-URL ",
                                ))
                                span.ed-mono { "ninitux.com" }
                                (crate::i18n::tr(lang, " URL is not available yet. Pin one via ", " пока недоступен. Привяжи через "))
                                span.ed-mono { "scripts/import_from_subscription_server.py --apply" } "."
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
                                    (crate::i18n::tr(lang, "rotate sub-token", "ротировать sub-token"))
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
                                    "mint sub-token"
                                }
                        }
                    }
                }
            }

            // Extra-protocol per-user password — TUIC / naive / Hysteria2 all
            // reuse `tuic_password`. Shown ONLY when absent: a user without it
            // silently gets NO naive/HY2/TUIC links (the cdn 2026-06-07
            // incident). One-click mint turns that silent skip into a fix.
            @if user.tuic_password.is_none() {
                div.ed-rule {}
                div.ed-art-eyebrow { (crate::i18n::tr(lang, "Extra-protocol password", "Пароль доп-протоколов")) }
                div style="padding: 12px 0;" {
                    p style="font-family: var(--serif); color: var(--acc); font-size: 13px; line-height: 1.6;" {
                        (crate::i18n::tr(
                            lang,
                            "⚠ No tuic_password — TUIC, naive and Hysteria2 links can't be minted for this user, so those protocols silently won't appear in their config (VLESS is unaffected).",
                            "⚠ Нет tuic_password — ссылки TUIC, naive и Hysteria2 для этого юзера не собираются, поэтому эти протоколы молча не попадают в его конфиг (VLESS не затронут).",
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
                            (crate::i18n::tr(lang, "mint tuic password", "сгенерировать tuic-пароль"))
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
                    (lifecycle, access_aggregates.last_seen, access_aggregates, ua_clusters),
                    traffic_by_server,
                    (all_servers, granted_ids),
                    lang,
                ))
            }
        }

            // WireGuard / AmneziaWG key material + distribution. Always
            // shows the pubkey verbatim (it's public). Private key marker
            // only — actual value flows through `/sub/<token>` (sing-box-
            // style clients) AND as inline QR/share-links below for
            // WG-native clients (AmneziaVPN, official WireGuard app).
            // Per CLAUDE.md "users are low-tech" — the operator must see
            // every artefact needed to onboard the user in one place.

            // ── Traffic limit + alert threshold (Pavel D.6c) ──────────
            // Show current month-to-date usage + the configured cap
            // (if any) + an inline form to change both, plus the user#3
            // month-end projection when a cap is set. Re-runs the usage
            // query so the page-after-redirect immediately reflects new
            // limits.
            (user_traffic_limit_section(state, &user.id, lang).await)

            // B1.user (audit 2026-05-22) — soft suspend. Banner +
            // toggle button. When user.disabled = true, an amber banner
            // says «this user is paused»; button reads «enable». When
            // false, just the «disable» button as part of the normal
            // user-detail card flow. No double-submit confirm because
            // the action is fully reversible (one click in either
            // direction, no secrets rotated, no grants lost).
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
                            (crate::i18n::tr(lang, "enable user", "включить пользователя"))
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
                            (crate::i18n::tr(lang, "disable user", "отключить пользователя"))
                        }
                    }
                }
            }


    }
}
