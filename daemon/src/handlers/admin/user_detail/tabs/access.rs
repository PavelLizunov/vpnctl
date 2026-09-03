use chrono::{DateTime, Utc};
use maud::{Markup, html};
use std::collections::{HashMap, HashSet};
use vpnctl_core::{ProtocolId, Server, ServerId, User};

use crate::AppState;
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
    user_grant_dates: &HashMap<ServerId, Option<DateTime<Utc>>>,
    access_protos: &HashMap<ServerId, Vec<String>>,
    hidden_per_server: &HashMap<ServerId, HashMap<ProtocolId, bool>>,
    user_overrides: &HashMap<(ServerId, ProtocolId), bool>,
    lang: Locale,
) -> Markup {
    html! {
        // v2 4b — per-server grant/key-state table above the existing
        // per-protocol delivery grid.
        div.ed-art-eyebrow style="margin-top: 12px;" {
            (crate::i18n::tr(lang, "Grants · per-server key state", "Гранты · состояние ключей по серверам")) " "
            span.ed-tip title=(crate::i18n::tr(
                lang,
                "Keys are minted at grant time; «on node» means the deployed config actually contains them. Grant + forget-to-deploy is the #1 silent failure — the banner above tracks it.",
                "Ключи чеканятся при гранте; «на ноде» значит, что задеплоенный конфиг реально их содержит. Грант без деплоя — тихий сбой №1, баннер выше его отслеживает.",
            )) { "ⓘ" }
        }
        @let keys_str = {
            let mut parts = vec!["uuid ✓"];
            if user.tuic_password.is_some() { parts.push("tuic ✓"); }
            if user.wireguard_pubkey.is_some() { parts.push("wg ✓"); }
            parts.join(" · ")
        };
        table.ed-grid style="margin-top: 8px;" {
            thead {
                tr {
                    th style="width: 70px;" { (crate::i18n::tr(lang, "server", "сервер")) }
                    th { (crate::i18n::tr(lang, "granted", "выдан")) }
                    th { (crate::i18n::tr(lang, "keys minted", "ключи")) }
                    th { (crate::i18n::tr(lang, "on node", "на ноде")) }
                    th { (crate::i18n::tr(lang, "protocols available", "доступные протоколы")) }
                    th.num style="width: 110px;" {}
                }
            }
            tbody {
                @for srv in all_servers {
                    @let is_granted = granted_ids.contains(&srv.id);
                    @let is_pending = pending_deploy_servers.contains(&srv.id);
                    @let sid_enc = path_segment_encode(&srv.id.0);
                    @let uid_enc = path_segment_encode(&user.id.0);
                    tr class=(if is_granted && is_pending { "on-warn" } else { "" }) {
                        td { b { (srv.id.0) } }
                        td.ed-grid__sm {
                            @if is_granted {
                                span style="color: var(--green);" { "✓ " }
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
                            @else if is_pending {
                                span.ed-grid__flag { "⚠ " (crate::i18n::tr(lang, "pending deploy", "ждёт деплоя")) }
                            } @else {
                                span style="color: var(--green);" { "✓" }
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
                                     style="margin: 0; padding: 0; display: inline;" {
                                    button type="submit" class="ed-abtn ed-abtn--warning ed-abtn--sm" {
                                        (crate::i18n::tr(lang, "revoke →", "отозвать →"))
                                    }
                                }
                            } @else {
                                form method="post"
                                     action=(format!("/admin/users/{uid_enc}/grants/{sid_enc}"))
                                     style="margin: 0; padding: 0; display: inline;" {
                                    button type="submit" class="ed-abtn ed-abtn--sm" {
                                        (crate::i18n::tr(lang, "grant →", "выдать →"))
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        // v2 4b — per-protocol identities, masked (secrets never leave
        // the server unmasked; length hint only — mock's reveal button
        // deliberately not implemented).
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
            // NM-12 follow-up: the per-grant disable/enable buttons in
            // the per-protocol grid below redirect with the
            // `#server-access` fragment so the operator stays anchored
            // here after a click instead of being scrolled to the top.
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
                        // Outer li wraps BOTH the grant toggle row AND
                        // (for granted servers only) the per-protocol
                        // delivery grid. Single `border-bottom` keeps the
                        // visual rule between *servers*, not between the
                        // grant toggle and its own grid below.
                        li style="padding: 4px 0; border-bottom: 1px dotted var(--rule);" {
                            div style="display: flex; align-items: baseline; gap: 12px;" {
                                // Server id → link to /admin/servers/{id} in a
                                // new tab (Pavel 2026-05-19: «хочу чтоб через
                                // пользователя можно было открыть страницу
                                // сервера в отдельном окне»). `target="_blank"`
                                // + `rel="noopener"` so the new tab doesn't
                                // share window.opener with the user-detail
                                // page (security hygiene + tab-isolation).
                                span style="flex: 1;" {
                                    a href=(format!("/admin/servers/{}", path_segment_encode(&s.id.0)))
                                      target="_blank"
                                      rel="noopener"
                                      title=(match lang {
                                          crate::i18n::Locale::En => format!("Open /admin/servers/{} in a new tab", s.id.0),
                                          crate::i18n::Locale::Ru => format!("Открыть /admin/servers/{} в новой вкладке", s.id.0),
                                      })
                                      style="color: var(--ink); text-decoration: none; border-bottom: 1px dotted var(--ink);" {
                                        b { (s.id.0) }
                                    }
                                    " (" span.ed-mono { (s.address) ":" (s.ssh_port) } ", "
                                    (s.kernels.iter().map(|k| k.0.clone()).collect::<Vec<_>>().join("+"))
                                    ")"
                                }
                                @if granted_ids.contains(&s.id) {
                                    span style="font-family: var(--mono); font-size: 11px; color: var(--acc);" {
                                        (crate::i18n::tr(lang, "✓ access", "✓ доступ"))
                                    }
                                    form method="post"
                                         action=(format!("/admin/users/{}/grants/{}/revoke",
                                                         path_segment_encode(&user.id.0),
                                                         path_segment_encode(&s.id.0)))
                                         style="margin: 0;" {
                                        @let title_str = match lang {
                                            crate::i18n::Locale::En => format!("Revoke {}'s access to {}", user.id.0, s.id.0),
                                            crate::i18n::Locale::Ru => format!("Отозвать доступ {} к {}", user.id.0, s.id.0),
                                        };
                                        button type="submit"
                                               title=(title_str)
                                               style="padding: 2px 8px; border: 1px solid var(--rule-s); background: transparent; font-family: var(--mono); font-size: 11px; color: var(--mute); cursor: pointer;" {
                                            (crate::i18n::tr(lang, "revoke", "отозвать"))
                                        }
                                    }
                                } @else {
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
                                            (crate::i18n::tr(lang, "grant", "выдать"))
                                        }
                                    }
                                }
                            }
                            // Per-(user, server, protocol) delivery grid
                            // (migration 0018 / NM-10). Renders ONLY for
                            // GRANTED servers — ungranted ones have no
                            // (user, server) row to attach overrides to,
                            // so `set_grant_protocol_override` would
                            // refuse with Invalid. Each protocol cell
                            // shows its current delivery state +
                            // block/unblock button. Server-hidden
                            // protocols are flagged read-only (operator
                            // adjusts those on /admin/servers/{id}).
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
