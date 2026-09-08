use crate::handlers::admin::icons::icon;
use crate::http_util::path_segment_encode;
use maud::{Markup, html};
use std::collections::HashMap;

/// Migration 0018 / NM-10: the two axes are server.hidden (set on
/// server-detail) and grant_protocol_overrides.state='disabled'
/// (set here). Visibility resolution is OR-semantics — either axis
/// suppresses the protocol from this user's subscription URL.
///
/// `hidden_map = None` is treated as an empty map (server has no
/// enabled protocols at all — render an empty-state explainer).
pub(crate) fn user_detail_per_protocol_grid(
    uid: &vpnctl_core::UserId,
    server: &vpnctl_core::Server,
    hidden_map: Option<&HashMap<vpnctl_core::ProtocolId, bool>>,
    user_overrides: &HashMap<(vpnctl_core::ServerId, vpnctl_core::ProtocolId), bool>,
    registry: &vpnctl_core::Registry,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let uid_enc = path_segment_encode(&uid.0);
    let sid_enc = path_segment_encode(&server.id.0);
    // Iterate the `server_protocols` table directly (not the in-memory
    // `enabled_protocols` field) so the OR-semantics deny resolution
    // matches `visible_protocols_for_subscription` BYTE-for-BYTE.
    // Review-agent 2026-05-20: a divergence between the in-memory
    // `enabled_protocols` cache and the on-disk `server_protocols`
    // rows would silently lie about what the operator's clients see
    // on next pull. Sort alphabetically to match the canonical
    // query's `ORDER BY sp.protocol_id` .
    let mut pids: Vec<&vpnctl_core::ProtocolId> =
        hidden_map.map(|m| m.keys().collect()).unwrap_or_default();
    pids.sort_by(|a, b| a.0.cmp(&b.0));
    html! {
        div style="margin: 8px 0 4px 16px; padding: 8px 12px 6px; border-left: 2px solid var(--rule); font-family: var(--mono); font-size: 11px; line-height: 1.6;" {
            div style="color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase; font-size: 10px; margin-bottom: 6px;" {
                (tr(lang, "Per-protocol delivery", "Доставка по протоколам"))
            }
            @if pids.is_empty() {
                p style="font-family: var(--serif); font-style: italic; color: var(--mute); margin: 0; font-size: 12px;" {
                    (tr(
                        lang,
                        "No protocols enabled on this server yet. Add one on the ",
                        "На этом сервере пока ничего не включено. Добавь хотя бы один через ",
                    ))
                    a href=(format!("/admin/servers/{sid_enc}"))
                      target="_blank"
                      rel="noopener"
                      style="color: var(--ink);" {
                        (tr(lang, "server detail page", "страницу сервера"))
                    }
                    (tr(lang, " — then the per-protocol toggles will appear here.", " — тогда тоглы по протоколам появятся здесь."))
                }
            } @else {
                ul style="list-style: none; padding: 0; margin: 0;" {
                    @for pid in &pids {
                        @let is_hidden = hidden_map
                            .and_then(|m| m.get(*pid).copied())
                            .unwrap_or(false);
                        @let is_user_blocked = user_overrides
                            .get(&(server.id.clone(), (*pid).clone()))
                            .copied()
                            .unwrap_or(false);
                        @let pid_enc = path_segment_encode(&pid.0);
                        // NM-12: same registry-driven risk chip the
                        // server-detail uses. Shrinks the protocol
                        // name to 10px (vs 11px row-default) when
                        // Weak — small visual sentence saying "you
                        // shouldn't be delivering this here".
                        @let risk = registry.protocol(pid).map(|p| p.dpi_risk());
                        @let pid_is_weak = matches!(risk, Some(vpnctl_core::DpiRisk::Weak));
                        li style="display: flex; align-items: baseline; gap: 10px; padding: 2px 0;" {
                            span style=(format!(
                                "flex: 1; color: var(--ink); font-size: {};",
                                if pid_is_weak { "10px" } else { "11px" },
                            )) {
                                (pid.0)
                                @if let Some(r) = risk {
                                    " "
                                    span title=(r.tooltip())
                                         style=(format!(
                                             "font-family: var(--mono); font-size: 9px; padding: 0 4px; border: 1px solid {}; color: {}; letter-spacing: 0.04em; margin-left: 2px;",
                                             r.border_css(),
                                             r.text_css(),
                                         )) {
                                        (r.label())
                                    }
                                }
                            }
                            @if is_hidden && is_user_blocked {
                                span style="color: var(--mute);" {
                                    (tr(lang, "server-hidden + user-blocked", "скрыт-на-сервере + заблокирован-у-юзера"))
                                }
                                form method="post"
                                     action=(format!("/admin/users/{uid_enc}/grants/{sid_enc}/protocols/{pid_enc}/enable"))
                                     style="margin: 0;" {
                                    button type="submit"
                                           title=(tr(
                                               lang,
                                               "Clear this user's override. Server-hidden flag remains — adjust on the server detail page.",
                                               "Очистить override этого пользователя. Флаг server-hidden останется — правится на странице сервера.",
                                           ))
                                           style="padding: 1px 6px; border: 1px solid var(--rule-s); background: transparent; color: var(--mute); font-family: var(--mono); font-size: 10px; cursor: pointer;" {
                                        (icon("lock-keyhole-open")) (tr(lang, "unblock (user)", "разблокировать (юзер)"))
                                    }
                                }
                            } @else if is_hidden {
                                span style="color: var(--mute);" {
                                    (tr(lang, "server-hidden (read-only here)", "скрыт на сервере (здесь только чтение)"))
                                }
                            } @else if is_user_blocked {
                                span style="color: var(--acc);" {
                                    (icon("x")) (tr(lang, "user-blocked", "заблокирован у юзера"))
                                }
                                form method="post"
                                     action=(format!("/admin/users/{uid_enc}/grants/{sid_enc}/protocols/{pid_enc}/enable"))
                                     style="margin: 0;" {
                                    @let unblock_title = match lang {
                                        crate::i18n::Locale::En => format!("Deliver {} to {} again on {}", pid.0, uid.0, server.id.0),
                                        crate::i18n::Locale::Ru => format!("Начать снова доставлять {} пользователю {} на {}", pid.0, uid.0, server.id.0),
                                    };
                                    button type="submit"
                                           title=(unblock_title)
                                           style="padding: 1px 6px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 10px; cursor: pointer;" {
                                        (icon("lock-keyhole-open")) (tr(lang, "unblock", "разблокировать"))
                                    }
                                }
                            } @else {
                                span style="color: var(--acc);" { (icon("check")) (tr(lang, "delivered", "доставляется")) }
                                form method="post"
                                     action=(format!("/admin/users/{uid_enc}/grants/{sid_enc}/protocols/{pid_enc}/disable"))
                                     style="margin: 0;" {
                                    @let block_title = match lang {
                                        crate::i18n::Locale::En => format!("Stop delivering {} to {} on {} (per-user override; other users keep getting it)", pid.0, uid.0, server.id.0),
                                        crate::i18n::Locale::Ru => format!("Перестать доставлять {} пользователю {} на {} (per-user override; остальным продолжает идти)", pid.0, uid.0, server.id.0),
                                    };
                                    button type="submit"
                                           title=(block_title)
                                           style="padding: 1px 6px; border: 1px solid var(--rule-s); background: transparent; color: var(--mute); font-family: var(--mono); font-size: 10px; cursor: pointer;" {
                                        (icon("lock-keyhole")) (tr(lang, "block", "заблокировать"))
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
