use crate::handlers::admin::helpers::ordered_kernel_ids;
use crate::http_util::path_segment_encode;
use maud::{Markup, html};
use std::collections::{HashMap, HashSet};

pub(crate) fn server_detail_protocols_section(
    server: &vpnctl_core::Server,
    registry: &vpnctl_core::Registry,
    hidden_map: &HashMap<vpnctl_core::ProtocolId, bool>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::{K, t, tr};
    let enabled: HashSet<&vpnctl_core::ProtocolId> = server.enabled_protocols.iter().collect();
    let all_protocols = registry.protocol_ids();
    // Multi-kernel: protocol is "compatible" if ANY of the server's
    // declared kernels supports it. Annotation below tells the operator
    // WHICH kernel handles it (resolves "wireguard runs on amneziawg,
    // tuic on sing-box" disambiguation that matters once a node has
    // multiple kernels).
    let kernel_supports_map: Vec<(vpnctl_core::KernelId, HashSet<vpnctl_core::ProtocolId>)> =
        server
            .kernels
            .iter()
            .filter_map(|kid| {
                registry
                    .kernel(kid)
                    .map(|k| (kid.clone(), k.supported_protocols().into_iter().collect()))
            })
            .collect();
    let kernel_supports: HashSet<vpnctl_core::ProtocolId> = kernel_supports_map
        .iter()
        .flat_map(|(_, sup)| sup.iter().cloned())
        .collect();
    let sid_enc = path_segment_encode(&server.id.0);
    html! {
        div.ed-rule {}
        // NM-12 follow-up (Pavel 2026-05-20: «каждый раз когда я
        // жму disable меня выкидывает в верх страницы»): all 4
        // visibility-toggle handlers below this row redirect to
        // `/admin/servers/{id}/protocols#enabled-protocols`. The browser
        // honours the fragment and scrolls the operator back to
        // THIS section instead of resetting to the page top.
        div.ed-art-eyebrow id="enabled-protocols" { (t(lang, K::EyebrowEnabledProtocols)) }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 8px;" {
            (tr(
                lang,
                "Check what runs on this node. Protocols are wire formats; their kernels (one or more) are picked from the section above.",
                "Что крутится на этой ноде. Протоколы — это wire-форматы; их ядра (одно или больше) выбираются выше в секции Ядра.",
            ))
        }
        // Same deploy-required rule as the Kernels note above. Kept as
        // a marker for operators who scroll straight here, but R2
        // compressed it to one line — two identical banner paragraphs
        // on one screen read as a copy-paste bug.
        div style="padding: 6px 12px; margin: 0 0 12px; background: var(--paper); border-left: 3px solid var(--accent); font-family: var(--serif); font-size: 12px; line-height: 1.5;" {
            b style="color: var(--accent); font-family: var(--mono); letter-spacing: 0.1em; text-transform: uppercase; font-size: 11px;" {
                (tr(lang, "⚠ toggle here = inventory only", "⚠ тогл здесь = только инвентарь"))
            }
            (tr(lang, " — goes live on ", " — вступает в силу по "))
            a href="#deploy-button"
              style="color: var(--ink); border-bottom: 1px dotted var(--ink); text-decoration: none; font-weight: 500;" {
                span.ed-mono { (t(lang, K::BtnDeploy)) }
            }
            (tr(lang, " (details in the note under Kernels).", " (подробности — в заметке под Ядрами)."))
        }
        ul style="list-style: none; padding: 0; font-family: var(--mono); font-size: 12px; line-height: 1.8;" {
            @for pid in &all_protocols {
                @let is_on = enabled.contains(pid);
                @let compatible = kernel_supports.contains(pid);
                // Migration 0018 / NM-10: per-(server, protocol)
                // hidden flag. Only meaningful for `is_on=true` rows
                // (hidden state on an off-protocol is silently
                // ignored by the render path). Defaults to false
                // when the bulk-loader didn't return a row for this
                // pid (e.g. add_protocol invariant on enabled but
                // schema-missing row).
                @let is_hidden = hidden_map.get(pid).copied().unwrap_or(false);
                // NM-12: DPI / active-probing resilience tier. Read
                // straight from the protocol impl in the registry —
                // none of the inventory mutations carry this; it's
                // compile-time static. Missing protocol (impossible
                // in production, registry seeds itself in main()) →
                // None → no chip rendered.
                @let risk = registry.protocol(pid).map(|p| p.dpi_risk());
                @let pid_is_weak = matches!(risk, Some(vpnctl_core::DpiRisk::Weak));
                li style="display: flex; align-items: baseline; gap: 12px; padding: 4px 0; border-bottom: 1px dotted var(--rule);" {
                    // Weak protocols get font-size 11px (vs 12px for
                    // Moderate/Strong) — Pavel 2026-05-20: «можешь
                    // даже шрифт меньше сделать у них». Visual
                    // de-emphasis without removing the row, so the
                    // operator can still see + toggle it.
                    span style=(format!(
                        "flex: 1; color: {}; font-size: {};",
                        if compatible { "var(--ink)" } else { "var(--mute)" },
                        if pid_is_weak { "11px" } else { "12px" },
                    )) {
                        (pid.0)
                        @if let Some(r) = risk {
                            " "
                            // DPI-risk chip: green/grey/red, sits
                            // alongside the protocol id so the
                            // operator's eye catches it. Colour
                            // helpers on `DpiRisk` are the single
                            // source of truth — adding a future tier
                            // (or recolouring the palette) is one
                            // edit in core/src/lib.rs. Tooltip carries
                            // the per-tier explainer string.
                            span title=(r.tooltip())
                                 style=(format!(
                                     "font-family: var(--mono); font-size: 10px; padding: 1px 6px; border: 1px solid {}; color: {}; letter-spacing: 0.04em;",
                                     r.border_css(),
                                     r.text_css(),
                                 )) {
                                (r.label())
                            }
                        }
                        @if !compatible {
                            " "
                            span style="font-size: 10px; color: var(--mute); font-style: italic; font-family: var(--serif);" {
                                (tr(lang, "(not supported by ", "(не поддерживается "))
                                @if server.kernels.len() == 1 {
                                    (tr(lang, "kernel ", "ядром ")) (server.kernels[0].0)
                                } @else {
                                    (tr(lang, "any kernel on this server: ", "ни одним ядром на этом сервере: "))
                                    (ordered_kernel_ids(server).iter().map(|k| k.0.clone()).collect::<Vec<_>>().join(", "))
                                }
                                ")"
                            }
                        }
                    }
                    @if is_on {
                        @if is_hidden {
                            span style="font-family: var(--mono); font-size: 11px; color: var(--acc); margin-right: 4px;" {
                                (tr(lang, "✓ on · hidden", "✓ вкл · скрыт"))
                            }
                        } @else {
                            span style="font-family: var(--mono); font-size: 11px; color: var(--acc); margin-right: 4px;" {
                                (tr(lang, "✓ on", "✓ вкл"))
                            }
                        }
                        form method="post"
                             action=(format!("/admin/servers/{}/protocols/{}/disable", sid_enc, path_segment_encode(&pid.0)))
                             style="margin: 0; padding: 0;" {
                            @let dis_proto_title = match lang {
                                crate::i18n::Locale::En => format!("Remove {} from {}.enabled_protocols. Takes effect on next deploy.", pid.0, server.id.0),
                                crate::i18n::Locale::Ru => format!("Убрать {} из {}.enabled_protocols. Применится при следующем деплое.", pid.0, server.id.0),
                            };
                            button type="submit"
                                   title=(dis_proto_title)
                                   class="ed-abtn ed-abtn--warning ed-abtn--sm" {
                                (t(lang, K::BtnDisable))
                            }
                        }
                        @if !compatible {
                            span style="font-family: var(--mono); font-size: 10px; color: var(--mute); font-style: italic;" {
                                (tr(lang, "(disable to clear)", "(выключи чтобы убрать)"))
                            }
                        } @else if is_hidden {
                            form method="post"
                                 action=(format!("/admin/servers/{}/protocols/{}/unhide", sid_enc, path_segment_encode(&pid.0)))
                                 style="margin: 0; padding: 0;" {
                                @let unhide_title = match lang {
                                    crate::i18n::Locale::En => format!("Resume emitting {} in this server's subscription URLs. Live sing-box inbound was never stopped; this just unmutes the render.", pid.0),
                                    crate::i18n::Locale::Ru => format!("Снова отдавать {} в URL подписок этого сервера. Живой sing-box inbound никто не останавливал; это только снимает mute с рендера.", pid.0),
                                };
                                button type="submit"
                                       title=(unhide_title)
                                       class="ed-abtn ed-abtn--sm" {
                                    (t(lang, K::BtnUnhide))
                                }
                            }
                        } @else {
                            form method="post"
                                 action=(format!("/admin/servers/{}/protocols/{}/hide", sid_enc, path_segment_encode(&pid.0)))
                                 style="margin: 0; padding: 0;" {
                                @let hide_title = match lang {
                                    crate::i18n::Locale::En => format!("Stop emitting {} in this server's subscription URLs WITHOUT removing the live inbound. Existing client URIs keep working until they re-pull.", pid.0),
                                    crate::i18n::Locale::Ru => format!("Перестать отдавать {} в URL подписок этого сервера БЕЗ удаления живого inbound. Закешированные клиентские URI продолжают работать до следующего pull.", pid.0),
                                };
                                button type="submit"
                                       title=(hide_title)
                                       class="ed-abtn ed-abtn--secondary ed-abtn--sm" {
                                    (t(lang, K::BtnHide))
                                }
                            }
                        }
                    } @else if compatible {
                        span style="font-family: var(--mono); font-size: 11px; color: var(--mute); margin-right: 4px;" {
                            "—"
                        }
                        form method="post"
                             action=(format!("/admin/servers/{}/protocols/{}/enable", sid_enc, path_segment_encode(&pid.0)))
                             style="margin: 0; padding: 0;" {
                            @let en_proto_title = match lang {
                                crate::i18n::Locale::En => format!("Add {} to {}.enabled_protocols. Takes effect on next deploy.", pid.0, server.id.0),
                                crate::i18n::Locale::Ru => format!("Добавить {} в {}.enabled_protocols. Применится при следующем деплое.", pid.0, server.id.0),
                            };
                            button type="submit"
                                   title=(en_proto_title)
                                   class="ed-abtn ed-abtn--sm" {
                                (t(lang, K::BtnEnable))
                            }
                        }
                    } @else {
                        span style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                            (tr(lang, "incompatible", "несовместимо"))
                        }
                    }
                }
            }
        }
    }
}
