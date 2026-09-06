use maud::{Markup, html};
use vpnctl_core::{ProtocolId, Server, ServerId, User};

use crate::AppState;
use crate::handlers::admin::legacy::share_link_card;
use crate::handlers::admin::users::mask_secret;
use crate::http_util::path_segment_encode;
use crate::i18n::Locale;

#[allow(clippy::too_many_arguments)]
pub(crate) fn render_delivery_tab(
    _state: &AppState,
    user: &User,
    servers: &[Server],
    ninitux_url_str: Option<&str>,
    sub_url_str: Option<&str>,
    sub_token: Option<&str>,
    mihomo_sub_url_str: Option<&str>,
    chain_route_summary: &str,
    chain_sub_url_str: Option<&str>,
    amnezia_links: &[(ServerId, String)],
    awg_links: &[(ServerId, String)],
    amnezia_files: &[(ServerId, u8, bool)],
    share_links: &[(ServerId, ProtocolId, String)],
    wg_capable_granted: &[&ServerId],
    wg_capable_inventory: &[&ServerId],
    lang: Locale,
) -> Markup {
    html! {
        // v2 4a — compact subscription recap on top of Delivery: the
        // one artefact the operator actually hands out, plus the legacy
        // fallback. The QR itself lives on Overview (linked) — the mock
        // duplicates it here; we link instead of double-rendering.
        div.ed-inbar {
            span.ed-inbar__label { (crate::i18n::tr(lang, "subscription", "подписка")) }
            @match (ninitux_url_str, sub_url_str) {
                (Some(u), _) | (None, Some(u)) => {
                    span style="font-family: var(--mono); font-size: 10px; color: var(--ink); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 420px;" { (u) }
                },
                (None, None) => {
                    em.ed-grid__mut { (crate::i18n::tr(lang, "no subscription URL yet — mint a sub-token below", "URL подписки нет — сгенерируй sub-token ниже")) }
                },
            }
            a.ed-grid__open href=(format!("/admin/users/{}", path_segment_encode(&user.id.0))) {
                (crate::i18n::tr(lang, "QR on Overview →", "QR на Обзоре →"))
            }
            span.ed-tip title=(crate::i18n::tr(
                lang,
                "The mobile app polls this URL on a fixed schedule; rotating the sub-token below invalidates the old URL immediately.",
                "Приложение опрашивает этот URL по расписанию; ротация sub-token ниже мгновенно гасит старый URL.",
            )) { "ⓘ" }
            @if let Some(t) = sub_token {
                span.ed-grid__mut style="margin-left: auto; font-family: var(--mono); font-size: 10px;" {
                    (crate::i18n::tr(lang, "legacy /sub/", "легаси /sub/"))
                    (mask_secret(t))
                    " · " (crate::i18n::tr(lang, "LAN-only fallback", "LAN-only fallback"))
                }
            }
        }
        @if let Some(url) = mihomo_sub_url_str {
            div style="margin: 20px 0; padding: 16px; border: 1px solid var(--rule); background: var(--paper-2);" {
                div.ed-art-eyebrow {
                    (crate::i18n::tr(lang, "Mihomo / Omarchy subscription", "Mihomo / Omarchy подписка"))
                }
                (share_link_card(url, &html! {
                    (crate::i18n::tr(
                        lang,
                        "Import this URL into Mihomo, Omarchy, Clash Meta, or compatible clients. It delivers a ready YAML config and uses dialer-proxy only when a direct entry node is available.",
                        "Импортируй этот URL в Mihomo, Omarchy, Clash Meta или совместимые клиенты. Он отдаёт готовый YAML и использует dialer-proxy только при доступном прямом входном узле.",
                    ))
                }))
            }
        }
        @if let Some(url) = chain_sub_url_str {
            div style="margin: 20px 0; padding: 16px; border: 1px solid var(--rule); background: var(--paper-2);" {
                div.ed-art-eyebrow {
                    (crate::i18n::tr(lang, "Sing-box chain subscription", "Sing-box подписка с цепочкой"))
                }
                div style="font-family: var(--mono); font-size: 11px; color: var(--mute); margin: 8px 0;" {
                    (chain_route_summary)
                }
                (share_link_card(url, &html! {
                    (crate::i18n::tr(
                        lang,
                        "Import this URL when the chained exit is needed. The target disappears automatically if its entry server is unavailable; standalone links remain direct-only.",
                        "Импортируй этот URL, когда нужен выход через цепочку. Целевой сервер автоматически исчезнет, если входной сервер недоступен; отдельные ссылки остаются только прямыми.",
                    ))
                }))
            }
        }
            @if !amnezia_files.is_empty() {
                div.ed-rule {}
                div.ed-art-eyebrow { (crate::i18n::tr(lang, "AmneziaWG native files", "Нативные файлы AmneziaWG")) }
                p.ed-grid__mut {
                    (crate::i18n::tr(lang,
                        "Import one file into a client supporting the stated AmneziaWG version, not stock WireGuard. Downloads never generate or rotate keys.",
                        "Импортируй файл в клиент с поддержкой указанной версии AmneziaWG, не обычный WireGuard. Скачивание не создаёт и не меняет ключи."))
                }
                @for (sid, version, ready) in amnezia_files {
                    div style="margin: 8px 0;" {
                        span.ed-mono { (sid.0) " · AmneziaWG " (if *version == 2 { "2.0" } else { "3.1" }) " " }
                        @if *ready {
                            a.ed-abtn.ed-abtn--secondary href=(format!("/admin/users/{}/amneziawg/{version}/conf/{}",
                                path_segment_encode(&user.id.0), path_segment_encode(&sid.0))) {
                                (crate::i18n::tr(lang, "download .conf", "скачать .conf"))
                            }
                        } @else {
                            span.ed-grid__mut {
                                (crate::i18n::tr(lang,
                                    "File not ready. Review the user keypair below and server Settings, then deploy the server.",
                                    "Файл не готов. Проверь пару ключей ниже и настройки сервера, затем задеплой сервер."))
                            }
                            " " a href=(format!("/admin/servers/{}/setup", path_segment_encode(&sid.0))) {
                                (crate::i18n::tr(lang, "Server Settings", "Настройки сервера"))
                            }
                        }
                    }
                }
            }
            div.ed-rule {}
            div.ed-art-eyebrow { (crate::i18n::tr(lang, "WireGuard keypair", "WireGuard-пара ключей")) }
            @match (&user.wireguard_pubkey, &user.wireguard_private) {
                (Some(pub_b64), Some(_priv_marker)) => {
                    div style="padding: 12px 0;" {
                        div style="font-family: var(--mono); font-size: 12px; line-height: 1.7;" {
                            div { span style="color: var(--mute);" { "pubkey  " } (pub_b64) }
                            div {
                                span style="color: var(--mute);" { "private " }
                                span.ed-mono style="color: var(--acc);" { "✓ stored — served via /sub/<token> only" }
                            }
                        }
                        p style="font-family: var(--serif); font-style: italic; color: var(--soft); font-size: 12px; margin-top: 8px;" {
                            "Both halves were generated when the user was created. Pick the distribution flow matching the user's client app:"
                        }
                        form method="post"
                             action=(format!("/admin/users/{}/wireguard/regenerate", path_segment_encode(&user.id.0)))
                             style="margin-top: 12px;" {
                            button type="submit"
                                   title="Mint a fresh Curve25519 pair. The previous keys stop working — every device using the old config must re-import."
                                   class="ed-abtn ed-abtn--warning" {
                                "rotate WG keypair"
                            }
                        }

                        // Distribution panel — one column per client app.
                        // Same secret material, several wire formats:
                        //   * Flow A — sing-box JSON via /sub/<token> URL
                        //   * Flow B — wireguard:// (official WG app, Hiddify)
                        //   * Flow C — vpn://    (AmneziaVPN)
                        //
                        // Plus a .conf-file download per WG-capable server
                        // as a universal fallback (drag-drop into ANY WG
                        // client incl AmneziaVPN's "File with settings"
                        // button).
                        //
                        // Pre-2026-05-17 (commit `799e28b`) Flow B claimed
                        // to cover BOTH AmneziaVPN and the WG app, but the
                        // `wireguard://?conf=` format AmneziaVPN rejects
                        // with ErrorCode 900 («нет контейнеров») — Amnezia
                        // expects its own `vpn://<base64(qCompress(json))>`
                        // deep-link. Split into B + C; honest labels.
                        //
                        // Grid uses `auto-fit minmax(340px, 1fr)` so the
                        // column count adapts to viewport (3 cols; wraps
                        // to 2x2 on narrower viewports).
                        div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); gap: 20px; margin-top: 24px; padding-top: 16px; border-top: 1px dotted var(--rule);" {
                            // Flow A — sing-box / Hiddify subscription URL.
                            // The QR renders the same sub_url shown in the
                            // Subscription block at the top of the page;
                            // duplicated here on purpose so the operator
                            // copies the WG-via-Hiddify link from the same
                            // distribution panel as the WG-native link.
                            div {
                                div style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase; margin-bottom: 8px;" {
                                    (crate::i18n::tr(lang, "Flow A — Hiddify / Sing-box", "Поток A — Hiddify / Sing-box"))
                                }
                                @match (&sub_token, &sub_url_str) {
                                    (Some(_), Some(url)) => {
                                        div style="font-family: var(--mono); font-size: 11px; color: var(--mute); margin-bottom: 6px;" {
                                            (crate::i18n::tr(
                                                lang,
                                                "all granted servers · refreshes on its own",
                                                "все выданные серверы · обновляется само",
                                            ))
                                        }
                                        (share_link_card(url, &html! {
                                            (crate::i18n::tr(
                                                lang,
                                                "Sing-box / Hiddify pulls the full config (every protocol on every granted server, including WireGuard with the private key embedded) and refreshes on its own schedule. ",
                                                "Sing-box / Hiddify тянет полный конфиг (все протоколы на всех выданных серверах, включая WireGuard с приватным ключом) и обновляет сам по расписанию. ",
                                            ))
                                            b { (crate::i18n::tr(
                                                lang,
                                                "Recommended default — one URL covers everything.",
                                                "Рекомендованный default — один URL покрывает всё.",
                                            )) }
                                        }))
                                    }
                                    _ => {
                                        p style="font-family: var(--serif); font-style: italic; color: var(--mute); font-size: 12px; margin: 0;" {
                                            (crate::i18n::tr(lang, "Mint a sub-token in the ", "Сгенерируй sub-token в блоке "))
                                            b { (crate::i18n::tr(lang, "Subscription", "Подписка")) }
                                            (crate::i18n::tr(lang, " block above to populate this card.", " выше, чтобы заполнить эту карточку.", ))
                                        }
                                    }
                                }
                            }
                            // Flow B — official WireGuard app + Hiddify.
                            // The `wireguard://?conf=<base64>` link works
                            // in the official WG mobile/desktop apps and
                            // in Hiddify, NOT in AmneziaVPN (separate Flow
                            // C below covers that).
                            div {
                                div style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase; margin-bottom: 8px;" {
                                    (crate::i18n::tr(lang, "Flow B — official WireGuard app / Hiddify", "Поток B — официальное WireGuard / Hiddify"))
                                }
                                @let wg_links: Vec<_> = share_links
                                    .iter()
                                    .filter(|(_, pid, _)| pid.0 == "wireguard")
                                    .collect();
                                @if wg_links.is_empty() {
                                    @if servers.is_empty() {
                                        p style="font-family: var(--serif); font-style: italic; color: var(--mute); font-size: 12px; margin: 0;" {
                                            (crate::i18n::tr(
                                                lang,
                                                "No servers granted to this user yet. Grant a server in the ",
                                                "У пользователя пока нет грантов. Выдай сервер в секции ",
                                            ))
                                            b { (crate::i18n::tr(lang, "Server access", "Доступ к серверам")) }
                                            (crate::i18n::tr(
                                                lang,
                                                " section below — if it runs WireGuard, the QR appears here.",
                                                " ниже — если сервер крутит WireGuard, QR появится здесь.",
                                            ))
                                        }
                                    } @else if wg_capable_granted.is_empty() {
                                        // Case B — granted servers exist but
                                        // NONE declare wireguard. Most
                                        // common case for bash-imported
                                        // users (vps-is-01 et al. run
                                        // VLESS/TUIC/Hy2, not WG).
                                        p style="font-family: var(--serif); font-size: 12px; line-height: 1.55; color: var(--ink); margin: 0 0 8px;" {
                                            b { (crate::i18n::tr(
                                                lang,
                                                "Keys exist, but no granted server runs WireGuard.",
                                                "Ключи есть, но ни на одном выданном сервере не крутится WireGuard.",
                                            )) }
                                            (crate::i18n::tr(
                                                lang,
                                                " The user has a WG keypair (see pubkey above), so the moment a WG-capable server is granted — or ",
                                                " У пользователя есть WG-пара ключей (см. pubkey выше), так что в момент когда WG-сервер будет выдан — либо ",
                                            ))
                                            span.ed-mono { "wireguard" }
                                            (crate::i18n::tr(
                                                lang,
                                                " is added to an existing server's ",
                                                " добавится в ",
                                            ))
                                            span.ed-mono { "enabled_protocols" }
                                            (crate::i18n::tr(
                                                lang,
                                                " — the QR will appear here.",
                                                " существующего сервера — QR появится здесь.",
                                            ))
                                        }
                                        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 0 0 6px;" {
                                            (crate::i18n::tr(lang, "Currently granted: ", "Текущие гранты: "))
                                            @for (i, s) in servers.iter().enumerate() {
                                                @if i > 0 { ", " }
                                                span.ed-mono { (s.id.0) }
                                            }
                                            (crate::i18n::tr(lang, " — none have ", " — ни у одного нет "))
                                            span.ed-mono { "wireguard" }
                                            (crate::i18n::tr(lang, " in their protocol list.", " в списке протоколов."))
                                        }
                                        @if !wg_capable_inventory.is_empty() {
                                            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 0;" {
                                                (crate::i18n::tr(
                                                    lang,
                                                    "WG-capable servers in the inventory you could grant: ",
                                                    "WG-серверы в инвентаре, которые можно выдать: ",
                                                ))
                                                @for (i, sid) in wg_capable_inventory.iter().enumerate() {
                                                    @if i > 0 { ", " }
                                                    span.ed-mono { (sid.0) }
                                                }
                                                "."
                                            }
                                        } @else {
                                            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 0;" {
                                                (crate::i18n::tr(
                                                    lang,
                                                    "No WG-capable server in the entire inventory. The ",
                                                    "В инвентаре нет ни одного WG-сервера. ",
                                                ))
                                                span.ed-mono { "amneziawg" }
                                                (crate::i18n::tr(lang, " kernel + ", " kernel + "))
                                                span.ed-mono { "wireguard" }
                                                (crate::i18n::tr(
                                                    lang,
                                                    " protocol need to be enabled on the server first — open its Settings page, add the protocol and kernel, then redeploy.",
                                                    " протокол должны быть сначала включены на сервере — открой страницу настроек сервера, добавь протокол и ядро, затем задеплой.",
                                                ))
                                            }
                                        }
                                    } @else {
                                        // Case C — at least one granted
                                        // server DOES declare wireguard but
                                        // share_link failed (most likely:
                                        // missing wireguard.server_public_key
                                        // secret). Existing journalctl
                                        // pointer remains the right action.
                                        p style="font-family: var(--serif); font-style: italic; color: var(--mute); font-size: 12px; margin: 0;" {
                                            (crate::i18n::tr(lang, "Granted servers ", "Выданные серверы "))
                                            @for (i, sid) in wg_capable_granted.iter().enumerate() {
                                                @if i > 0 { ", " }
                                                span.ed-mono { (sid.0) }
                                            }
                                            (crate::i18n::tr(
                                                lang,
                                                " declare wireguard but the share-link render failed. Likely missing ",
                                                " объявляют wireguard, но рендер share-link провалился. Скорее всего нет ",
                                            ))
                                            span.ed-mono { "wireguard.server_public_key" }
                                            " / "
                                            span.ed-mono { "wireguard.server_private_key" }
                                            (crate::i18n::tr(lang, " server secret — open the server's Settings page to review its secrets.", " серверного секрета — открой страницу настроек сервера и проверь секреты."))
                                        }
                                    }
                                } @else {
                                    // R2 2026-07-10: one explainer per flow
                                    // + per-server QRs behind <details> —
                                    // 4 servers × 3 flows used to unroll
                                    // into a 12-QR wall with the same
                                    // paragraph repeated under each.
                                    p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 0 0 8px;" {
                                        (crate::i18n::tr(
                                            lang,
                                            "Opens in the official WireGuard app (mobile + desktop) and Hiddify; the private key is base64-embedded inside. Expand a server for its QR.",
                                            "Открывается в официальном WireGuard (mobile + desktop) и Hiddify; приватный ключ закодирован внутри. Разверни сервер, чтобы показать QR.",
                                        ))
                                    }
                                    @for (sid, _pid, link) in &wg_links {
                                        details style="margin-bottom: 4px; border-bottom: 1px dotted var(--rule);" {
                                            summary style="cursor: pointer; font-family: var(--mono); font-size: 11px; color: var(--ink); padding: 5px 0;" {
                                                (crate::i18n::tr(lang, "server ", "сервер ")) b { (sid.0) }
                                                span style="color: var(--mute);" {
                                                    " · " (link.len()) (crate::i18n::tr(lang, " chars", " символов")) " · QR"
                                                }
                                            }
                                            div style="margin: 8px 0 12px;" {
                                                div style="font-family: var(--mono); font-size: 11px; color: var(--mute); margin-bottom: 6px;" {
                                                    a href=(format!("/admin/users/{}/wireguard/conf/{}",
                                                                    path_segment_encode(&user.id.0),
                                                                    path_segment_encode(&sid.0)))
                                                      download=(format!("{}-{}.conf", user.id.0, sid.0))
                                                      style="color: var(--mute); text-decoration: underline;" {
                                                        (crate::i18n::tr(lang, "download .conf", "скачать .conf"))
                                                    }
                                                }
                                                (share_link_card(link, &html! {
                                                    (crate::i18n::tr(
                                                        lang,
                                                        "Click the box above to select-all + copy.",
                                                        "Кликни на блок выше, чтобы выделить и скопировать.",
                                                    ))
                                                }))
                                            }
                                        }
                                    }
                                }
                            }
                            // Flow C — AmneziaVPN-native deep link.
                            // Same secret material as Flow B but wrapped
                            // in AmneziaVPN's `vpn://<base64(qCompress(json))>`
                            // container format. Without this card,
                            // AmneziaVPN rejects the Flow B link with
                            // ErrorCode 900 («нет контейнеров»).
                            div {
                                div style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase; margin-bottom: 8px;" {
                                    (crate::i18n::tr(lang, "Flow C — AmneziaVPN", "Поток C — AmneziaVPN"))
                                }
                                @let amnezia_links: Vec<_> = amnezia_links
                                    .iter()
                                    .collect();
                                @if amnezia_links.is_empty() {
                                    @if servers.is_empty() {
                                        p style="font-family: var(--serif); font-style: italic; color: var(--mute); font-size: 12px; margin: 0;" {
                                            (crate::i18n::tr(
                                                lang,
                                                "Grant a WireGuard-capable server to populate this card.",
                                                "Выдай сервер с WireGuard, чтобы заполнить эту карточку.",
                                            ))
                                        }
                                    } @else if wg_capable_granted.is_empty() {
                                        p style="font-family: var(--serif); font-style: italic; color: var(--mute); font-size: 12px; margin: 0;" {
                                            (crate::i18n::tr(
                                                lang,
                                                "No granted server runs WireGuard yet — add ",
                                                "Ни на одном выданном сервере не крутится WireGuard — добавь ",
                                            ))
                                            span.ed-mono { "wireguard" }
                                            (crate::i18n::tr(
                                                lang,
                                                " to an existing server's protocols on its detail page.",
                                                " в протоколы существующего сервера на странице деталей.",
                                            ))
                                        }
                                    } @else {
                                        p style="font-family: var(--serif); font-style: italic; color: var(--mute); font-size: 12px; margin: 0;" {
                                            (crate::i18n::tr(lang, "Granted WG servers ", "Выданные WG-серверы "))
                                            @for (i, sid) in wg_capable_granted.iter().enumerate() {
                                                @if i > 0 { ", " }
                                                span.ed-mono { (sid.0) }
                                            }
                                            (crate::i18n::tr(
                                                lang,
                                                " — but AmneziaVPN link rendering failed (open the server's Settings page to review its secrets).",
                                                " — но рендер AmneziaVPN-ссылки провалился (открой страницу настроек сервера и проверь секреты).",
                                            ))
                                        }
                                    }
                                } @else {
                                    p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 0 0 8px;" {
                                        (crate::i18n::tr(
                                            lang,
                                            "QR / paste opens in AmneziaVPN (zlib-compressed JSON-container inside); the ",
                                            "QR или вставка открывается в AmneziaVPN (внутри zlib-сжатый JSON-контейнер); ",
                                        ))
                                        span.ed-mono { ".conf" }
                                        (crate::i18n::tr(
                                            lang,
                                            " download is the fallback for AmneziaVPN's ",
                                            " — резерв через ",
                                        ))
                                        em { (crate::i18n::tr(lang, "File with settings", "Файл с настройками")) }
                                        (crate::i18n::tr(lang, " import path. Expand a server for its QR.", ". Разверни сервер, чтобы показать QR."))
                                    }
                                    @for (sid, link) in amnezia_links {
                                        details style="margin-bottom: 4px; border-bottom: 1px dotted var(--rule);" {
                                            summary style="cursor: pointer; font-family: var(--mono); font-size: 11px; color: var(--ink); padding: 5px 0;" {
                                                (crate::i18n::tr(lang, "server ", "сервер ")) b { (sid.0) }
                                                span style="color: var(--mute);" {
                                                    " · " (link.len()) (crate::i18n::tr(lang, " chars", " символов")) " · QR"
                                                }
                                            }
                                            div style="margin: 8px 0 12px;" {
                                                div style="font-family: var(--mono); font-size: 11px; color: var(--mute); margin-bottom: 6px;" {
                                                    a href=(format!("/admin/users/{}/wireguard/conf/{}",
                                                                    path_segment_encode(&user.id.0),
                                                                    path_segment_encode(&sid.0)))
                                                      download=(format!("{}-{}.conf", user.id.0, sid.0))
                                                      style="color: var(--mute); text-decoration: underline;" {
                                                        (crate::i18n::tr(lang, "download .conf", "скачать .conf"))
                                                    }
                                                }
                                                (share_link_card(link, &html! {
                                                    (crate::i18n::tr(
                                                        lang,
                                                        "Click the box above to select-all + copy.",
                                                        "Кликни на блок выше, чтобы выделить и скопировать.",
                                                    ))
                                                }))
                                            }
                                        }
                                    }
                                }
                            }
                            // Flow F — AmneziaWG `awg://` link for the
                            // operator's sing-box-lx-based client app. Carries
                            // the per-server obfs (s1/s2/h1-h4 minted by
                            // bootstrap) + the server-generated client key, so
                            // it's a one-tap import. Only renders when at least
                            // one granted server runs the amneziawg kernel
                            // (obfs minted ⇒ a link was produced). Letter F:
                            // A=sub, B=wireguard://, C=AmneziaVPN vpn://,
                            // F=AmneziaWG awg://.
                            @if !awg_links.is_empty() {
                                div {
                                    div style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase; margin-bottom: 8px;" {
                                        (crate::i18n::tr(lang, "Flow F — AmneziaWG (awg://)", "Поток F — AmneziaWG (awg://)"))
                                    }
                                    p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 0 0 8px;" {
                                        (crate::i18n::tr(
                                            lang,
                                            "Opens in the sing-box-lx-based app — per-server AmneziaWG obfuscation (s1/s2/h1-h4) baked in; one-tap, no on-device key-gen. Expand a server for its QR.",
                                            "Открывается в приложении на sing-box-lx — per-server AmneziaWG-обфускация (s1/s2/h1-h4) уже внутри; один тап, без генерации ключей. Разверни сервер, чтобы показать QR.",
                                        ))
                                    }
                                    @for (sid, link) in awg_links {
                                        details style="margin-bottom: 4px; border-bottom: 1px dotted var(--rule);" {
                                            summary style="cursor: pointer; font-family: var(--mono); font-size: 11px; color: var(--ink); padding: 5px 0;" {
                                                (crate::i18n::tr(lang, "server ", "сервер ")) b { (sid.0) }
                                                span style="color: var(--mute);" {
                                                    " · " (link.len()) (crate::i18n::tr(lang, " chars", " символов")) " · QR"
                                                }
                                            }
                                            div style="margin: 8px 0 12px;" {
                                                (share_link_card(link, &html! {
                                                    (crate::i18n::tr(
                                                        lang,
                                                        "Click the box above to select-all + copy.",
                                                        "Кликни на блок выше, чтобы выделить и скопировать.",
                                                    ))
                                                }))
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                (Some(pub_b64), None) => {
                    // Public-only imports need an explicit, warned rotation;
                    // a GET must never silently replace the device-owned pair.
                    div style="padding: 12px 0;" {
                        div style="font-family: var(--mono); font-size: 12px; line-height: 1.7;" {
                            div { span style="color: var(--mute);" { "pubkey  " } (pub_b64) }
                            div {
                                span style="color: var(--mute);" { "private " }
                                span.ed-mono style="color: var(--mute);" { "on user device (operator-paranoid path)" }
                            }
                        }
                        p.ed-grid__mut {
                            (crate::i18n::tr(lang,
                                "Ready files require a stored private key. Rotating replaces the existing pair; devices using it must re-import after deployment.",
                                "Для готового файла нужен сохранённый приватный ключ. Ротация заменит текущую пару; после деплоя устройствам потребуется повторный импорт."))
                        }
                        form method="post" action=(format!("/admin/users/{}/wireguard/regenerate", path_segment_encode(&user.id.0))) {
                            button type="submit" class="ed-abtn ed-abtn--warning" {
                                (crate::i18n::tr(lang, "rotate WG keypair", "сменить WG-пару ключей"))
                            }
                        }
                    }
                }
                (None, _) => {
                    // Should be impossible for users created via the web
                    // form (always auto-gens both). Falls through for
                    // legacy users imported pre-2026-05-16 — show a
                    // self-heal button.
                    div style="padding: 12px 0;" {
                        p style="font-family: var(--serif); font-style: italic; color: var(--mute);" {
                            (crate::i18n::tr(
                                lang,
                                "No WireGuard keypair on this user. Imported from the legacy bash project, or created before the auto-gen default.",
                                "У этого пользователя нет WireGuard-пары. Импортирован из старого bash-проекта или создан до того как auto-gen стал дефолтом.",
                            ))
                        }
                        form method="post"
                             action=(format!("/admin/users/{}/wireguard/regenerate", path_segment_encode(&user.id.0)))
                             style="margin-top: 8px;" {
                            button type="submit"
                                   title="Mint a fresh Curve25519 keypair for this user (legacy self-heal — only shown when the user has no key on file). No existing WireGuard client config to break."
                                   style="padding: 4px 10px; border: 1px solid var(--ink); background: transparent; font-family: var(--mono); font-size: 11px; color: var(--ink); cursor: pointer;" {
                                "generate WG keypair"
                            }
                        }
                    }
                }
            }

            // Server access (Phase C-3.3) — full server inventory with a
            // per-row grant/revoke form. Granted rows show "✓ access ·
            // [revoke]"; ungranted rows show "[grant]". One POST per
            // click, server returns 303 to this same detail page so the
            // operator sees the post-mutation state immediately.


            // Per-protocol share-links — only meaningful for granted servers.
            // ponytail: collapsed <details> — the Flow cards above already deliver
            // every link with a QR; this raw server×protocol dump (up to ~32 lines)
            // is the copy-all / debug view, not prime-scroll content. Content stays
            // in the DOM (just collapsed), so copy-contract + smoke tests still see it.
            @if !servers.is_empty() {
                details style="margin-top: 24px;" {
                    summary style="cursor: pointer;" {
                        span.ed-art-eyebrow {
                            (crate::i18n::tr(lang, "Per-protocol share links", "Ссылки на отдельные протоколы"))
                        }
                    }
                    @if share_links.is_empty() {
                        p style="font-family: var(--serif); font-style: italic; color: var(--mute); margin-top: 8px;" {
                            (crate::i18n::tr(
                                lang,
                                "No share-links could be rendered (missing secrets or unregistered protocols). Open each server's Settings page to review its secrets.",
                                "Не удалось отрендерить ни одной ссылки (нет секретов или протокол не зарегистрирован). Открой страницу настроек каждого сервера и проверь секреты.",
                            ))
                        }
                    } @else {
                        ul style="list-style: none; padding: 0; margin-top: 8px; font-family: var(--mono); font-size: 11px; line-height: 1.7; color: var(--soft);" {
                            @for (sid, pid, link) in share_links {
                                li style="padding: 4px 0; border-bottom: 1px dotted var(--rule);" {
                                    span style="color: var(--mute);" { (sid.0) " · " (pid.0) " · " }
                                    (link)
                                }
                            }
                        }
                    }
                }
            }


    }
}
