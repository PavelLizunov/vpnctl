use crate::handlers::admin::icons::icon;
use maud::{Markup, html};
use vpnctl_core::{ProtocolId, Server, ServerId, User};

use super::super::delivery_readiness::{primary_artifact, recipient_scope};
use crate::AppState;
use crate::handlers::admin::legacy::{qr_svg, share_link_card};
use crate::handlers::admin::users::mask_secret;
use crate::http_util::path_segment_encode;
use crate::i18n::Locale;

#[allow(clippy::too_many_arguments)]
pub(crate) fn render_delivery_tab(
    _state: &AppState,
    user: &User,
    servers: &[Server],
    pending_deploy_servers: &[ServerId],
    pending_deploy_known: bool,
    public_base_configured: bool,
    has_renderable_grants: bool,
    app_config_url_str: Option<&str>,
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
    names: &crate::handlers::admin::helpers::ServerNames,
    lang: Locale,
) -> Markup {
    let primary = primary_artifact(app_config_url_str, sub_url_str);
    html! {
        section #recommended-delivery style="margin: 0 0 18px; padding: 14px 16px; border: 1px solid var(--rule); background: var(--paper-2);" {
            div.ed-art-eyebrow {
                (crate::i18n::tr(lang, "Recommended share", "Ссылка для пользователя")) " "
                span.ed-tip title=(crate::i18n::tr(
                    lang,
                    "One import-ready artefact. It is shown only when the user is enabled, an applied node has a renderable grant, deployment evidence exists, and the recipient host is not obviously local to this daemon. Private LAN/Tailscale addresses keep the copy action with a scope note. The other delivery methods stay available below.",
                    "Передайте пользователю ссылку или QR-код. Для выдачи нужен хотя бы один доступный для импорта протокол на сервере с применёнными настройками.",
                )) { (icon("info")) }
            }
            @if user.disabled {
                div style="margin-top: 8px; font-family: var(--serif); font-size: 13px; line-height: 1.6; color: var(--ink);" {
                    b { (crate::i18n::tr(lang, "This user is disabled.", "Пользователь отключён.")) }
                    " "
                    (crate::i18n::tr(
                        lang,
                        "The subscription and app-config endpoints return an empty config, so a ready link would not work. Enable the user first; keys and grants are preserved.",
                        "Включите пользователя, чтобы подписка снова содержала настройки. Его ключи и доступы сохранены.",
                    ))
                    div style="margin-top: 10px;" {
                        form method="post" action=(format!("/admin/users/{}/enable", path_segment_encode(&user.id.0))) style="display: inline;" {
                            button type="submit" class="ed-abtn ed-abtn--primary ed-abtn--sm" {
                                (icon("power")) (crate::i18n::tr(lang, "enable user", "включить пользователя"))
                            }
                        }
                    }
                }
            } @else if servers.is_empty() {
                div style="margin-top: 8px; font-family: var(--serif); font-size: 13px; line-height: 1.6; color: var(--ink);" {
                    b { (crate::i18n::tr(lang, "No deliverable server grants yet.", "Грантов на серверы, готовых к выдаче, пока нет.")) }
                    " "
                    (crate::i18n::tr(
                        lang,
                        "Grant at least one ready server before handing out a link; an empty subscription is not a usable artefact.",
                        "Выдай хотя бы один готовый сервер перед выдачей ссылки; пустая подписка — не рабочий артефакт.",
                    ))
                    div style="margin-top: 10px;" {
                        a class="ed-abtn ed-abtn--primary ed-abtn--sm"
                          href=(format!("/admin/users/{}/access#server-access", path_segment_encode(&user.id.0))) {
                            (icon("plus")) (crate::i18n::tr(lang, "grant server access", "выдать доступ к серверу")) " " (icon("arrow-right"))
                        }
                    }
                }
            } @else if !pending_deploy_known {
                div style="margin-top: 8px; font-family: var(--serif); font-size: 13px; line-height: 1.6; color: var(--ink);" {
                    b { (crate::i18n::tr(lang, "Application is not confirmed.", "Применение не подтверждено.")) }
                    " "
                    (crate::i18n::tr(
                        lang,
                        "The deployment audit could not be read, so this page cannot promise the link is live. Deploy the user's servers, then reload.",
                        "Журнал деплоя не читается, поэтому страница не может обещать, что ссылка уже работает. Задеплой серверы пользователя и перезагрузи страницу.",
                    ))
                    div style="margin-top: 10px;" {
                        a class="ed-abtn ed-abtn--secondary ed-abtn--sm"
                          href=(format!("/admin/users/{}/access", path_segment_encode(&user.id.0))) {
                            (icon("server")) (crate::i18n::tr(lang, "review access", "проверить доступ"))
                        }
                    }
                }
            } @else if pending_deploy_servers.len() >= servers.len() {
                div style="margin-top: 8px; font-family: var(--serif); font-size: 13px; line-height: 1.6; color: var(--ink);" {
                    b {
                        (pending_deploy_servers.len()) " "
                        (crate::i18n::noun_for(
                            lang,
                            pending_deploy_servers.len() as u64,
                            "server is not applied yet.",
                            "servers are not applied yet.",
                            "сервер ещё не применён.",
                            "сервера ещё не применены.",
                            "серверов ещё не применены.",
                        ))
                    }
                    " "
                    (crate::i18n::tr(
                        lang,
                        "Access is saved, but none of the granted nodes carries this user yet. Use the deploy-pending action above, then reload before handing over the link.",
                        "Доступ сохранён, но ни одна выданная нода ещё не знает пользователя. Нажми «задеплоить недостающие» выше и перезагрузи страницу перед выдачей ссылки.",
                    ))
                    div style="margin-top: 6px; font-family: var(--mono); font-size: 10px; color: var(--warm);" {
                        @for (index, sid) in pending_deploy_servers.iter().enumerate() {
                            @if index > 0 { ", " }
                            (crate::handlers::admin::helpers::named_server(sid, names))
                        }
                    }
                }
            } @else if !has_renderable_grants {
                div style="margin-top: 8px; font-family: var(--serif); font-size: 13px; line-height: 1.6; color: var(--ink);" {
                    b { (crate::i18n::tr(lang, "No renderable protocol is delivered on an applied node yet.", "Подписка пока пуста.")) }
                    " "
                    (crate::i18n::tr(
                        lang,
                        "The grants exist, but every protocol is hidden for this user, the node is suppressed, or the link renderer failed. A link would be empty, so it is not recommended. Review user access and the server protocol settings, then reload.",
                        "Проверьте, что пользователю разрешён хотя бы один протокол и его показ в подписках включён на сервере.",
                    ))
                    div style="margin-top: 10px; display: flex; gap: 8px; flex-wrap: wrap;" {
                        a class="ed-abtn ed-abtn--secondary ed-abtn--sm"
                          href=(format!("/admin/users/{}/access#server-access", path_segment_encode(&user.id.0))) {
                            (icon("users")) (crate::i18n::tr(lang, "review user access", "проверить доступ пользователя"))
                        }
                    }
                }
            } @else {
                @match primary {
                    Some(artifact) => {
                        @let scope = recipient_scope(artifact.url);
                        @if scope.blocks_copy() {
                            div style="margin-top: 8px; font-family: var(--serif); font-size: 13px; line-height: 1.6; color: var(--ink);" {
                                b { (scope.headline(lang)) }
                                " "
                                (scope.detail(lang, public_base_configured))
                                div style="margin-top: 8px; font-family: var(--mono); font-size: 10px; color: var(--warm); word-break: break-all;" {
                                    (artifact.url)
                                }
                                div style="margin-top: 10px;" {
                                    a class="ed-abtn ed-abtn--primary ed-abtn--sm" href="/admin/settings/system#public-address" {
                                        (icon("settings-2")) (crate::i18n::tr(lang, "set public address", "указать публичный адрес")) " " (icon("arrow-right"))
                                    }
                                }
                            }
                        } @else {
                            div style="display: flex; gap: 16px; align-items: flex-start; flex-wrap: wrap; margin-top: 8px;" {
                                (qr_svg(artifact.url))
                                div style="flex: 1; min-width: 260px; display: flex; flex-direction: column; gap: 8px;" {
                                    div style="font-family: var(--mono); font-size: 10px; letter-spacing: 0.12em; text-transform: uppercase; color: var(--mute);" {
                                        (artifact.kind.label(lang))
                                    }
                                    textarea #recommended-share-url readonly="readonly" rows="3"
                                              data-select-on-click
                                              title=(crate::i18n::tr(lang, "Click to select, then copy — or use the copy button.", "Кликни, чтобы выделить, затем скопируй — или используй кнопку."))
                                              style="width: 100%; box-sizing: border-box; padding: 8px 10px; font-family: var(--mono); font-size: 10px; line-height: 1.45; color: var(--ink); background: var(--paper); border: 1px solid var(--rule); resize: vertical; word-break: break-all;" {
                                        (artifact.url)
                                    }
                                    div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap;" {
                                        button type="button"
                                               data-copy-recommended="recommended-share-url"
                                               data-copy-status="recommended-share-status"
                                               class="ed-abtn ed-abtn--primary ed-abtn--sm" {
                                            (icon("link")) (crate::i18n::tr(lang, "copy link", "скопировать ссылку"))
                                        }
                                        span #recommended-share-status role="status" aria-live="polite"
                                             style="font-family: var(--mono); font-size: 10px; color: var(--green);" {}
                                    }
                                    div style="font-family: var(--serif); font-style: italic; color: var(--mute); font-size: 12px; line-height: 1.5;" {
                                        (artifact.kind.note(lang))
                                    }
                                    @if let Some(hint) = scope.hint(lang, public_base_configured) {
                                        div style="font-family: var(--mono); font-size: 10px; line-height: 1.55; color: var(--warm);" {
                                            (icon("info")) " " (hint)
                                        }
                                    }
                                }
                            }
                        }
                    },
                    None => {
                        div style="margin-top: 8px; font-family: var(--serif); font-size: 13px; line-height: 1.6; color: var(--ink);" {
                            b { (crate::i18n::tr(lang, "No ready share link yet.", "Готовой ссылки пока нет.")) }
                            " "
                            (crate::i18n::tr(
                                lang,
                                "This user has no subscription token and no app-config device ID. Mint a sub-token to create the universal import URL.",
                                "У пользователя нет sub-token и device ID конфига приложения. Сгенерируй sub-token, чтобы создать универсальную ссылку для импорта.",
                            ))
                            div style="margin-top: 10px;" {
                                form method="post"
                                     action=(format!("/admin/users/{}/sub-token/regenerate", path_segment_encode(&user.id.0))) {
                                    button type="submit" class="ed-abtn ed-abtn--primary ed-abtn--sm" {
                                        (icon("key-round")) (crate::i18n::tr(lang, "mint sub-token", "сгенерировать sub-token"))
                                    }
                                }
                            }
                        }
                    },
                }
                @if !pending_deploy_servers.is_empty() {
                    div style="margin-top: 10px; border-top: 1px dotted var(--rule); padding-top: 8px; font-family: var(--serif); font-size: 12px; line-height: 1.55; color: var(--warm);" {
                        (icon("triangle-alert")) " "
                        b {
                            (pending_deploy_servers.len()) " "
                            (crate::i18n::noun_for(
                                lang,
                                pending_deploy_servers.len() as u64,
                                "server is still pending.",
                                "servers are still pending.",
                                "сервер всё ещё ждёт деплоя.",
                                "сервера всё ещё ждут деплоя.",
                                "серверов всё ещё ждут деплоя.",
                            ))
                        }
                        " "
                        (crate::i18n::tr(
                            lang,
                            "Access for this user is still pending on these servers:",
                            "Доступ пользователя ещё ожидает применения на серверах:",
                        ))
                        " "
                        @for (index, sid) in pending_deploy_servers.iter().enumerate() {
                            @if index > 0 { ", " }
                            span.ed-mono { (crate::handlers::admin::helpers::named_server(sid, names)) }
                        }
                        (crate::i18n::tr(
                            lang,
                            ". Use the deploy-pending action above, then reload for the complete artifact.",
                            ". Чтобы применить доступ, запустите деплой ожидающих серверов.",
                        ))
                    }
                }
            }
        }
        details.ed-delivery-alternatives {
        summary { (crate::i18n::tr(lang, "Other clients, formats and keys", "Другие клиенты, форматы и ключи")) }
        div.ed-inbar {
            span.ed-inbar__label { (crate::i18n::tr(lang, "subscription", "подписка")) }
            @match (app_config_url_str, sub_url_str) {
                (Some(u), _) | (None, Some(u)) => {
                    span style="font-family: var(--mono); font-size: 10px; color: var(--ink); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 420px;" { (u) }
                },
                (None, None) => {
                    em.ed-grid__mut { (crate::i18n::tr(lang, "no subscription URL yet — mint a sub-token below", "URL подписки нет — сгенерируй sub-token ниже")) }
                },
            }
            a.ed-grid__open href=(format!("/admin/users/{}", path_segment_encode(&user.id.0))) {
                (crate::i18n::tr(lang, "QR on Overview", "QR на Обзоре")) (icon("arrow-right"))
            }
            span.ed-tip title=(crate::i18n::tr(
                lang,
                "The mobile app polls this URL on a fixed schedule. Rotating the sub-token immediately invalidates links that use it; app-config links use device_id and remain unchanged.",
                "Приложение опрашивает этот URL по расписанию. Ротация sub-token мгновенно делает ссылки с ним недействительными; ссылки app-config используют device_id и остаются без изменений.",
            )) { (icon("info")) }
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
            @if chain_sub_url_str.is_none() && servers.iter().any(|server| server.enabled_protocols.iter().any(|protocol| matches!(protocol.0.as_str(), "hysteria2" | "tuic-v5"))) {
                (share_link_card(&format!("{url}?format=sing-box"), &html! {
                    (crate::i18n::tr(
                        lang,
                        "Import in sing-box 1.13 or later. Available Hysteria2 and TUIC routes require a verified TLS pin. Mihomo 1.19.20 or later also supports these routes.",
                        "Импортируй в sing-box 1.13 или новее. Доступные маршруты Hysteria2 и TUIC требуют проверенного отпечатка TLS. Эти маршруты также поддерживает Mihomo 1.19.20 или новее.",
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
                        span.ed-mono { (crate::handlers::admin::helpers::named_server(sid, names)) " · AmneziaWG " (if *version == 2 { "2.0" } else { "3.1" }) " " }
                        @if *ready {
                            a.ed-abtn.ed-abtn--secondary href=(format!("/admin/users/{}/amneziawg/{version}/conf/{}",
                                path_segment_encode(&user.id.0), path_segment_encode(&sid.0))) {
                                (icon("download")) (crate::i18n::tr(lang, "download .conf", "скачать .conf"))
                            }
                        } @else {
                            span.ed-grid__mut {
                                (crate::i18n::tr(lang,
                                    "File not ready. Review the user keypair below and server Settings, then deploy the server.",
                                    "Файл не готов. Проверь пару ключей ниже и настройки сервера, затем задеплой сервер."))
                            }
                            " " a href=(format!("/admin/servers/{}/setup", path_segment_encode(&sid.0))) {
                                (icon("settings-2")) (crate::i18n::tr(lang, "Server Settings", "Настройки сервера"))
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
                                span.ed-mono style="color: var(--acc);" { (icon("check")) "stored — served via /sub/<token> only" }
                            }
                        }
                        p style="font-family: var(--serif); font-style: italic; color: var(--soft); font-size: 12px; margin-top: 8px;" {
                            "Both halves were generated when the user was created. Pick the distribution flow matching the user's client app:"
                        }
                        form method="post"
                             action=(format!("/admin/users/{}/wireguard/regenerate", path_segment_encode(&user.id.0)))
                             data-confirm=(crate::i18n::tr(lang, "Generate a new WireGuard key pair? Configs already handed to the user stop working after the next deploy.", "Сгенерировать новую пару ключей WireGuard? Выданные пользователю конфиги перестанут работать после следующего деплоя."))
                             style="margin-top: 12px;" {
                            button type="submit"
                                   title="Mint a fresh Curve25519 pair. The previous keys stop working — every device using the old config must re-import."
                                   class="ed-abtn ed-abtn--warning" {
                                (icon("rotate-cw")) "rotate WG keypair"
                            }
                        }

                        div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); gap: 20px; margin-top: 24px; padding-top: 16px; border-top: 1px dotted var(--rule);" {
                            div {
                                div style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase; margin-bottom: 8px;" {
                                    (crate::i18n::tr(lang, "Flow A — Hiddify / Sing-box", "Поток A — Hiddify / Sing-box"))
                                }
                                @match (&sub_token, &sub_url_str) {
                                    (Some(_), Some(url)) => {
                                        div style="font-family: var(--mono); font-size: 11px; color: var(--mute); margin-bottom: 6px;" {
                                            (crate::i18n::tr(
                                                lang,
                                                "granted servers · visible protocols only · refreshes on its own",
                                                "выданные серверы · только видимые протоколы · обновляется само",
                                            ))
                                        }
                                        (share_link_card(url, &html! {
                                            (crate::i18n::tr(
                                                lang,
                                                "Sing-box / Hiddify pulls the full config (visible protocols on granted servers, including WireGuard with the private key embedded when delivered) and refreshes on its own schedule. ",
                                                "Sing-box / Hiddify тянет полный конфиг (видимые протоколы на выданных серверах, включая WireGuard с приватным ключом, когда он отдаётся) и обновляет сам по расписанию. ",
                                            ))
                                            b { (crate::i18n::tr(
                                                lang,
                                                "Recommended default — one URL for the visible client config.",
                                                "Рекомендованный default — один URL для видимого клиентского конфига.",
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
                                                span.ed-mono { (crate::handlers::admin::helpers::named_server(&s.id, names)) }
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
                                                    span.ed-mono { (crate::handlers::admin::helpers::named_server(sid, names)) }
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
                                        p style="font-family: var(--serif); font-style: italic; color: var(--mute); font-size: 12px; margin: 0;" {
                                            (crate::i18n::tr(lang, "Granted servers ", "Выданные серверы "))
                                            @for (i, sid) in wg_capable_granted.iter().enumerate() {
                                                @if i > 0 { ", " }
                                                span.ed-mono { (crate::handlers::admin::helpers::named_server(sid, names)) }
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
                                                (icon("server")) (crate::i18n::tr(lang, "server ", "сервер ")) b { (crate::handlers::admin::helpers::named_server(sid, names)) }
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
                                                        (icon("download")) (crate::i18n::tr(lang, "download .conf", "скачать .conf"))
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
                                                span.ed-mono { (crate::handlers::admin::helpers::named_server(sid, names)) }
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
                                                (icon("server")) (crate::i18n::tr(lang, "server ", "сервер ")) b { (crate::handlers::admin::helpers::named_server(sid, names)) }
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
                                                        (icon("download")) (crate::i18n::tr(lang, "download .conf", "скачать .conf"))
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
                                                (icon("server")) (crate::i18n::tr(lang, "server ", "сервер ")) b { (crate::handlers::admin::helpers::named_server(sid, names)) }
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
                        form method="post" action=(format!("/admin/users/{}/wireguard/regenerate", path_segment_encode(&user.id.0)))
                             data-confirm=(crate::i18n::tr(lang, "Generate a new WireGuard key pair? Configs already handed to the user stop working after the next deploy.", "Сгенерировать новую пару ключей WireGuard? Выданные пользователю конфиги перестанут работать после следующего деплоя.")) {
                            button type="submit" class="ed-abtn ed-abtn--warning" {
                                (icon("rotate-cw")) (crate::i18n::tr(lang, "rotate WG keypair", "сменить WG-пару ключей"))
                            }
                        }
                    }
                }
                (None, _) => {
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
                                (icon("key-round")) "generate WG keypair"
                            }
                        }
                    }
                }
            }



            @if !servers.is_empty() {
                details style="margin-top: 24px;" {
                    summary style="cursor: pointer;" {
                        span.ed-art-eyebrow {
                            (icon("link")) (crate::i18n::tr(lang, "Per-protocol share links", "Ссылки на отдельные протоколы"))
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
                                li data-share-server=(sid.0) data-share-protocol=(pid.0)
                                   style="padding: 4px 0; border-bottom: 1px dotted var(--rule);" {
                                    span style="color: var(--mute);" { (crate::handlers::admin::helpers::named_server(sid, names)) " · " (pid.0) " · " }
                                    (link)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
