use crate::handlers::admin::icons::{icon, status};
use chrono::{DateTime, Utc};
use maud::{Markup, html};
use std::collections::{HashMap, HashSet};
use vpnctl_core::{ProtocolId, Server, ServerId, User};

use crate::AppState;
use crate::handlers::admin::grant_targets::GrantReadiness;
use crate::handlers::admin::helpers::format_msk_iso;
use crate::handlers::admin::legacy::user_detail_per_protocol_grid;
use crate::handlers::admin::users::mask_secret;
use crate::http_util::path_segment_encode;
use crate::i18n::Locale;

#[allow(clippy::too_many_arguments)]
pub(crate) fn render_access_tab(
    state: &AppState,
    user: &User,
    all_servers: &[Server],
    granted_ids: &HashSet<ServerId>,
    pending_deploy_servers: &[ServerId],
    pending_deploy_known: bool,
    user_grant_dates: &HashMap<ServerId, Option<DateTime<Utc>>>,
    access_protos: &HashMap<ServerId, Vec<String>>,
    grant_readiness: &HashMap<ServerId, GrantReadiness>,
    hidden_per_server: &HashMap<ServerId, HashMap<ProtocolId, bool>>,
    user_overrides: &HashMap<(ServerId, ProtocolId), bool>,
    names: &crate::handlers::admin::helpers::ServerNames,
    lang: Locale,
) -> Markup {
    let blocked_ungranted = all_servers
        .iter()
        .filter(|server| {
            !granted_ids.contains(&server.id)
                && !matches!(
                    grant_readiness.get(&server.id),
                    Some(GrantReadiness::Eligible | GrantReadiness::WorkloadOnly)
                )
        })
        .count();
    html! {
        div.ed-art-eyebrow style="margin-top: 12px;" {
            (crate::i18n::tr(lang, "Grants · per-server key state", "Гранты · состояние ключей по серверам")) " "
            span.ed-tip title=(crate::i18n::tr(
                lang,
                "Application is derived from the deployment audit, not a live node inspection or VPN connection test.",
                "Применение определяется по журналу деплоя, а не по проверке живой ноды или VPN-подключения.",
            )) { (icon("info")) }
        }
        @let keys_str = html! {
            "uuid " (status("check", lang, "Key minted", "Ключ создан"))
            @if user.tuic_password.is_some() { " · tuic " (status("check", lang, "Key minted", "Ключ создан")) }
            @if user.wireguard_pubkey.is_some() { " · wg " (status("check", lang, "Key minted", "Ключ создан")) }
        };
        @if blocked_ungranted > 0 {
            div style="border: 1px solid var(--warm); border-left-width: 3px; background: color-mix(in oklab, var(--warm) 8%, var(--paper)); padding: 8px 11px; margin: 10px 0; font-family: var(--serif); font-size: 12px; line-height: 1.55; color: var(--ink);" {
                (icon("triangle-alert"))
                " "
                (crate::i18n::tr(
                    lang,
                    "New grants are limited to servers with a verified SSH deploy-key path. A row without it shows the failed or missing check and a link to run it again.",
                    "Новые гранты доступны только на серверах с проверенным SSH deploy-key путём. В строке без него показана причина и ссылка, чтобы запустить проверку снова.",
                ))
            }
        }
        table.ed-grid style="margin-top: 8px;" {
            thead {
                tr {
                    th style="width: 70px;" { (crate::i18n::tr(lang, "server", "сервер")) }
                    th { (crate::i18n::tr(lang, "granted", "выдан")) }
                    th { (crate::i18n::tr(lang, "keys minted", "ключи")) }
                    th { (crate::i18n::tr(lang, "application per audit", "применение по журналу")) }
                    th { (crate::i18n::tr(lang, "protocols available", "доступные протоколы")) }
                    th.num style="width: 110px;" {}
                }
            }
            tbody {
                @for srv in all_servers {
                    @let is_granted = granted_ids.contains(&srv.id);
                    @let is_pending = pending_deploy_servers.contains(&srv.id);
                    @let readiness = grant_readiness.get(&srv.id).copied();
                    @let ready = readiness.is_some_and(|value| value.is_eligible());
                    @let reason = match readiness {
                        Some(value) => value.reason(lang),
                        None => crate::i18n::tr(lang, "SSH not verified", "SSH не проверен").to_string(),
                    };
                    @let sid_enc = path_segment_encode(&srv.id.0);
                    @let uid_enc = path_segment_encode(&user.id.0);
                    tr class=(if is_granted && is_pending { "on-warn" } else { "" }) {
                        td { b { (crate::handlers::admin::helpers::named_server(&srv.id, names)) } }
                        td.ed-grid__sm {
                            @if is_granted {
                                span style="color: var(--green);" { (status("check", lang, "Granted", "Выдан")) " " }
                                span.ed-grid__mut {
                                    @match user_grant_dates.get(&srv.id).copied().flatten() {
                                        Some(ts) => (format_msk_iso(ts)),
                                        None => "—",
                                    }
                                }
                            } @else {
                                span.ed-grid__mut { "— " (crate::i18n::tr(lang, "not granted", "не выдан")) }
                            }
                        }
                        td.ed-grid__sm {
                            @if is_granted { (keys_str) }
                            @else { span.ed-grid__mut { "—" } }
                        }
                        td.ed-grid__sm {
                            @if !is_granted { span.ed-grid__mut { "—" } }
                            @else if !pending_deploy_known {
                                span.ed-grid__mut { (crate::i18n::tr(lang, "application unknown", "применение неизвестно")) }
                            } @else if is_pending {
                                span.ed-grid__flag { (icon("triangle-alert")) " " (crate::i18n::tr(lang, "pending deploy", "ждёт деплоя")) }
                            } @else {
                                span style="color: var(--green);" { (status("check", lang, "Deployed", "Развёрнут")) }
                            }
                        }
                        td.ed-grid__mut.ed-grid__sm {
                            @match access_protos.get(&srv.id) {
                                Some(v) if !v.is_empty() => (v.join(" · ")),
                                _ => "—",
                            }
                        }
                        td.num {
                            @if is_granted {
                                form method="post"
                                     action=(format!("/admin/users/{uid_enc}/grants/{sid_enc}/revoke"))
                                     data-confirm=(crate::i18n::tr(lang, "Revoke this user's access to the server? Access ends after the next deploy.", "Отозвать доступ пользователя к серверу? Доступ пропадёт после следующего деплоя."))
                                     style="margin: 0; padding: 0; display: inline;" {
                                    button type="submit" class="ed-abtn ed-abtn--warning ed-abtn--sm" {
                                        (icon("minus")) (crate::i18n::tr(lang, "revoke", "отозвать"))
                                    }
                                }
                            } @else if ready {
                                form method="post"
                                     action=(format!("/admin/users/{uid_enc}/grants/{sid_enc}"))
                                     style="margin: 0; padding: 0; display: inline;" {
                                    button type="submit" class="ed-abtn ed-abtn--sm" {
                                        (icon("plus")) (crate::i18n::tr(lang, "grant", "выдать"))
                                    }
                                }
                            } @else if readiness == Some(GrantReadiness::WorkloadOnly) {
                                span { (reason) }
                            } @else {
                                span.ed-grid__flag title=(reason) {
                                    (icon("triangle-alert")) " " (crate::i18n::tr(lang, "SSH unverified", "SSH не проверен"))
                                }
                                " "
                                a href=(crate::handlers::admin::grant_targets::GrantReadiness::check_href(&srv.id))
                                  style="font-family: var(--mono); font-size: 10px; color: var(--acc);" {
                                    (crate::i18n::tr(lang, "check", "проверить"))
                                }
                            }
                        }
                    }
                }
            }
        }
        div.ed-art-eyebrow style="margin-top: 16px;" {
            (crate::i18n::tr(lang, "Per-protocol identities", "Идентичности по протоколам"))
        }
        table.ed-feed style="margin: 8px 0 16px;" {
            tbody {
                tr {
                    td.ed-grid__mut style="width: 150px;" { "uuid (vless/tuic)" }
                    td { (user.uuid) }
                }
                tr {
                    td.ed-grid__mut { "tuic password" }
                    td.ed-grid__mut {
                        @match &user.tuic_password {
                            Some(p) => { (mask_secret(p)) " · " (p.chars().count()) "ch" },
                            None => "—",
                        }
                    }
                }
                tr {
                    td.ed-grid__mut { "wg pubkey" }
                    td.ed-grid__mut {
                        @match &user.wireguard_pubkey {
                            Some(k) => { (mask_secret(k)) " · " (k.chars().count()) "ch" },
                            None => "—",
                        }
                    }
                }
                tr {
                    td.ed-grid__mut { "sub-token" }
                    td.ed-grid__mut {
                        @match &user.sub_token {
                            Some(t) => { (mask_secret(t)) " · " (t.chars().count()) "ch" },
                            None => "—",
                        }
                    }
                }
            }
        }
            div.ed-rule {}
            div.ed-art-eyebrow id="server-access" {
                (crate::i18n::t(lang, crate::i18n::K::EyebrowServerAccess))
            }
            @if all_servers.is_empty() {
                p style="font-family: var(--serif); font-style: italic; color: var(--mute); padding: 12px 0;" {
                    (crate::i18n::tr(
                        lang,
                        "No servers in the inventory yet. Add one from the Servers page wizard (paste IP + root password).",
                        "Серверов в инвентаре ещё нет. Добавь сервер через мастер на странице серверов (вставь IP + root-пароль).",
                    ))
                }
            } @else {
                ul style="list-style: none; padding: 0; font-family: var(--serif); font-size: 14px; line-height: 1.8;" {
                    @for s in all_servers {
                        @let readiness = grant_readiness.get(&s.id).copied();
                        @let ready = readiness.is_some_and(|value| value.is_eligible());
                        @let reason = match readiness {
                            Some(value) => value.reason(lang),
                            None => crate::i18n::tr(lang, "SSH not verified", "SSH не проверен").to_string(),
                        };
                        li style="padding: 4px 0; border-bottom: 1px dotted var(--rule);" {
                            div style="display: flex; align-items: baseline; gap: 12px;" {
                                span style="flex: 1;" {
                                    a href=(format!("/admin/servers/{}", path_segment_encode(&s.id.0)))
                                      target="_blank"
                                      rel="noopener"
                                      title=(match lang {
                                          crate::i18n::Locale::En => format!("Open /admin/servers/{} in a new tab", s.id.0),
                                          crate::i18n::Locale::Ru => format!("Открыть /admin/servers/{} в новой вкладке", s.id.0),
                                      })
                                      style="color: var(--ink); text-decoration: none; border-bottom: 1px dotted var(--ink);" {
                                        b { (crate::handlers::admin::helpers::named_server(&s.id, names)) }
                                    }
                                    " (" span.ed-mono { (s.address) ":" (s.ssh_port) } ", "
                                    (s.kernels.iter().map(|k| k.0.clone()).collect::<Vec<_>>().join("+"))
                                    ")"
                                }
                                @if granted_ids.contains(&s.id) {
                                    span style="font-family: var(--mono); font-size: 11px; color: var(--acc);" {
                                        (icon("check")) (crate::i18n::tr(lang, "access", "доступ"))
                                    }
                                    form method="post"
                                         action=(format!("/admin/users/{}/grants/{}/revoke",
                                                         path_segment_encode(&user.id.0),
                                                         path_segment_encode(&s.id.0)))
                                         data-confirm=(crate::i18n::tr(lang, "Revoke this user's access to the server? Access ends after the next deploy.", "Отозвать доступ пользователя к серверу? Доступ пропадёт после следующего деплоя."))
                                         style="margin: 0;" {
                                        @let title_str = match lang {
                                            crate::i18n::Locale::En => format!("Revoke {}'s access to {}", user.id.0, s.id.0),
                                            crate::i18n::Locale::Ru => format!("Отозвать доступ {} к {}", user.id.0, s.id.0),
                                        };
                                        button type="submit"
                                               title=(title_str)
                                               style="padding: 2px 8px; border: 1px solid var(--rule-s); background: transparent; font-family: var(--mono); font-size: 11px; color: var(--mute); cursor: pointer;" {
                                            (icon("minus")) (crate::i18n::tr(lang, "revoke", "отозвать"))
                                        }
                                    }
                                } @else if ready {
                                    span style="font-family: var(--mono); font-size: 11px; color: var(--mute);" { "—" }
                                    form method="post"
                                         action=(format!("/admin/users/{}/grants/{}",
                                                         path_segment_encode(&user.id.0),
                                                         path_segment_encode(&s.id.0)))
                                         style="margin: 0;" {
                                        @let title_str = match lang {
                                            crate::i18n::Locale::En => format!("Grant {} access to {}", user.id.0, s.id.0),
                                            crate::i18n::Locale::Ru => format!("Выдать доступ {} к {}", user.id.0, s.id.0),
                                        };
                                        button type="submit"
                                               title=(title_str)
                                               style="padding: 2px 8px; border: 1px solid var(--ink); background: transparent; font-family: var(--mono); font-size: 11px; color: var(--ink); cursor: pointer;" {
                                            (icon("plus")) (crate::i18n::tr(lang, "grant", "выдать"))
                                        }
                                    }
                                } @else if readiness == Some(GrantReadiness::WorkloadOnly) {
                                    span { (reason) }
                                } @else {
                                    span title=(reason)
                                          style="font-family: var(--mono); font-size: 11px; color: var(--warm);" {
                                        (icon("triangle-alert")) " " (crate::i18n::tr(lang, "SSH unverified", "SSH не проверен"))
                                    }
                                    " "
                                    a href=(crate::handlers::admin::grant_targets::GrantReadiness::check_href(&s.id))
                                      style="font-family: var(--mono); font-size: 10px; color: var(--acc);" {
                                        (crate::i18n::tr(lang, "check", "проверить"))
                                    }
                                }
                            }
                            @if granted_ids.contains(&s.id) {
                                (user_detail_per_protocol_grid(
                                    &user.id,
                                    s,
                                    hidden_per_server.get(&s.id),
                                    user_overrides,
                                    &state.registry,
                                    lang,
                                ))
                            }
                        }
                    }
                }
            }


    }
}
