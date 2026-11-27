use crate::handlers::admin::icons::icon;
use crate::handlers::vpn_router::server_display_label;
use crate::http_util::path_segment_encode;
use maud::{Markup, html};
use std::collections::HashMap;

pub(crate) fn server_detail_naive_config_section(
    server: &vpnctl_core::Server,
    server_secrets: &HashMap<String, String>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    if !server.enabled_protocols.iter().any(|p| p.0 == "naive") {
        return html! {};
    }
    let sid_enc = path_segment_encode(&server.id.0);
    let domain = server_secrets
        .get("naive.domain")
        .map(String::as_str)
        .unwrap_or("");
    let email = server_secrets
        .get("naive.acme_email")
        .map(String::as_str)
        .unwrap_or("");
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow
            title=(tr(lang,
                "Caddy + forwardproxy serves a real cover website (HTTP 200) to probes and tunnels authenticated clients. Domain + email feed Caddy's built-in ACME (Let's Encrypt).",
                "Caddy + forwardproxy отдаёт настоящий сайт-прикрытие (HTTP 200) зондам и туннелирует аутентифицированных клиентов. Домен + почта идут во встроенный ACME Caddy (Let's Encrypt).")) {
            (tr(lang, "NAIVE (CADDY) CONFIG", "КОНФИГ NAIVE (CADDY)"))
        }
        p.ed-form-hint {
            (tr(lang,
                "Before deploy: point a DNS A-record at this server and open TCP 80+443 — Caddy's ACME needs both. vpnctl can't do DNS for you.",
                "До деплоя: направь DNS A-запись на этот сервер и открой TCP 80+443 — встроенному ACME Caddy нужны оба. DNS vpnctl за тебя не сделает."))
        }
        form.ed-form method="post"
             action=(format!("/admin/servers/{sid_enc}/naive-config")) {
            div.ed-form-grid {
                div.ed-form-row {
                    label.ed-form-label for="naive-domain" { (tr(lang, "domain", "домен")) }
                    input.ed-field id="naive-domain" type="text" name="domain" maxlength="253" required
                          value=(domain)
                          placeholder="cdn.example.com";
                }
                div.ed-form-row {
                    label.ed-form-label for="naive-acme-email" { (tr(lang, "ACME email", "ACME почта")) }
                    input.ed-field id="naive-acme-email" type="text" name="acme_email" maxlength="254"
                          value=(email)
                          placeholder="admin@example.com";
                }
            }
            div.ed-form-actions {
                button.ed-btn-primary type="submit"
                       title=(tr(lang, "Save naive domain + ACME email", "Сохранить домен naive + ACME почту")) {
                    (icon("save")) (tr(lang, "Save naive config", "Сохранить конфиг"))
                }
            }
        }
    }
}

pub(crate) fn server_detail_vlessws_config_section(
    server: &vpnctl_core::Server,
    server_secrets: &HashMap<String, String>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    if !server.enabled_protocols.iter().any(|p| p.0 == "vless-ws") {
        return html! {};
    }
    let sid_enc = path_segment_encode(&server.id.0);
    let domain = server_secrets
        .get("vlessws.domain")
        .map(String::as_str)
        .unwrap_or("");
    let email = server_secrets
        .get("vlessws.acme_email")
        .map(String::as_str)
        .unwrap_or("");
    let port = server_secrets
        .get("vlessws.listen_port")
        .map(String::as_str)
        .unwrap_or("");
    let path_minted = server_secrets.contains_key("vlessws.path");
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow
            title=(tr(lang,
                "Caddy terminates a real Let's-Encrypt cert on the front port, serves a decoy site at /, and reverse_proxies one secret path to a loopback sing-box VLESS+ws inbound. DIRECT (no CDN) — the RU-DPI-resistant, client-universal fallback that runs alongside REALITY on :443.",
                "Caddy терминирует настоящий сертификат Let's-Encrypt на фронт-порту, отдаёт сайт-приманку на /, и reverse_proxy одного секретного пути на loopback sing-box VLESS+ws. ПРЯМОЙ (без CDN) — устойчивый к RU-DPI, совместимый со всеми клиентами фолбэк рядом с REALITY на :443.")) {
            (tr(lang, "VLESS-WS (CADDY) CONFIG", "КОНФИГ VLESS-WS (CADDY)"))
        }
        p.ed-form-hint {
            (tr(lang,
                "Before deploy: point a DNS A-record at this server and open TCP 80 (ACME) + the front port. The secret ws path is generated automatically on deploy.",
                "До деплоя: направь DNS A-запись на этот сервер и открой TCP 80 (ACME) + фронт-порт. Секретный ws-путь генерируется автоматически при деплое."))
            @if path_minted {
                (tr(lang, " The path is set.", " Путь задан."))
            } @else {
                (tr(lang, " The path is not minted yet (deploy to generate it).", " Путь ещё не сгенерирован (задеплой, чтобы создать его)."))
            }
        }
        form.ed-form method="post"
             action=(format!("/admin/servers/{sid_enc}/vlessws-config")) {
            div.ed-form-grid {
                div.ed-form-row.ed-form-row--wide {
                    label.ed-form-label for="vlessws-domain" { (tr(lang, "domain", "домен")) }
                    input.ed-field id="vlessws-domain" type="text" name="domain" maxlength="253" required
                          value=(domain)
                          placeholder="vpn.example.com";
                }
                div.ed-form-row {
                    label.ed-form-label for="vlessws-front-port" { (tr(lang, "front port", "фронт-порт")) }
                    input.ed-field id="vlessws-front-port" type="text" name="listen_port" maxlength="5" inputmode="numeric"
                          value=(port)
                          placeholder="8443"
                          title=(tr(lang, "Public TLS port Caddy serves on — NOT 443 (REALITY owns that). Blank = 8443.", "Публичный TLS-порт Caddy — НЕ 443 (его занимает REALITY). Пусто = 8443."));
                }
                div.ed-form-row {
                    label.ed-form-label for="vlessws-acme-email" { (tr(lang, "ACME email", "ACME почта")) }
                    input.ed-field id="vlessws-acme-email" type="text" name="acme_email" maxlength="254"
                          value=(email)
                          placeholder="admin@example.com";
                }
            }
            div.ed-form-actions {
                button.ed-btn-primary type="submit"
                       title=(tr(lang, "Save vless-ws domain + front port + ACME email", "Сохранить домен vless-ws + фронт-порт + ACME почту")) {
                    (icon("save")) (tr(lang, "Save vless-ws config", "Сохранить конфиг"))
                }
            }
        }
    }
}

pub(crate) fn server_detail_reality_config_section(
    server: &vpnctl_core::Server,
    server_secrets: &HashMap<String, String>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    if !server
        .enabled_protocols
        .iter()
        .any(|p| p.0 == "vless+reality")
    {
        return html! {};
    }
    let sid_enc = path_segment_encode(&server.id.0);
    let port = server_secrets
        .get("vless.listen_port")
        .map(String::as_str)
        .unwrap_or("");
    let sni = server_secrets
        .get("vless.sni")
        .map(String::as_str)
        .unwrap_or(vpnctl_protocols::DEFAULT_REALITY_SNI);
    let current_fp = server_secrets
        .get("vless.fp")
        .map(String::as_str)
        .filter(|fp| vpnctl_protocols::is_valid_reality_fp(fp))
        .unwrap_or("");
    let handshake_server = server_secrets
        .get("vless.handshake_server")
        .map(String::as_str)
        .unwrap_or("");
    let handshake_port = server_secrets
        .get("vless.handshake_port")
        .map(String::as_str)
        .unwrap_or("");
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow
            title=(tr(lang,
                "REALITY binds this port directly. Default 443 (gold-standard HTTPS cover); set an alternate port when a co-tenant owns 443 on this host (naive/caddy, legacy 3x-ui). Saving re-validates against every other protocol's port and takes effect on deploy.",
                "REALITY слушает этот порт напрямую. По умолчанию 443 (золотой стандарт HTTPS-маскировки); задай другой порт, если 443 на этом хосте занят со-жителем (naive/caddy, легаси 3x-ui). При сохранении проверяется против портов всех остальных протоколов и вступает в силу при деплое.")) {
            (tr(lang, "VLESS+REALITY CONFIG", "КОНФИГ VLESS+REALITY"))
        }
        p.ed-form-hint {
            (tr(lang,
                "Deploy after saving. Clients receive the new handshake domain when they refresh their subscription after the deploy.",
                "После сохранения выполни деплой. Клиенты получат новый домен рукопожатия при обновлении подписки после деплоя."))
        }
        form.ed-form method="post"
             action=(format!("/admin/servers/{sid_enc}/reality-config")) {
            div.ed-form-grid {
                div.ed-form-row.ed-form-row--wide {
                    label.ed-form-label for="reality-sni" {
                        (tr(lang, "handshake domain", "домен рукопожатия"))
                    }
                    input.ed-field id="reality-sni" type="text" name="sni" maxlength="253" required
                          value=(sni)
                          title=(tr(lang, "Hostname of the HTTPS site used for the REALITY handshake.", "Имя HTTPS-сайта для рукопожатия REALITY."));
                }
                div.ed-form-row {
                    label.ed-form-label for="reality-fp" {
                        (tr(lang, "uTLS fingerprint", "uTLS-отпечаток"))
                    }
                    select.ed-field id="reality-fp" name="fp"
                           title=(tr(lang, "Client TLS fingerprint emitted in subscriptions. Blank keeps the legacy default (randomized); chrome is recommended for new deployments.", "TLS-отпечаток клиента в подписках. Пусто оставляет прежнее значение (randomized); для новых узлов рекомендуется chrome.")) {
                        option value="" selected[current_fp.is_empty()] {
                            (tr(lang, "default (randomized)", "по умолчанию (randomized)"))
                        }
                        @for candidate in vpnctl_protocols::VALID_REALITY_FPS {
                            option value=(candidate) selected[current_fp == *candidate] { (candidate) }
                        }
                    }
                }
                div.ed-form-row {
                    label.ed-form-label for="reality-handshake-port" {
                        (tr(lang, "handshake port", "порт рукопожатия"))
                    }
                    input.ed-field id="reality-handshake-port" type="text" name="handshake_port" maxlength="5" inputmode="numeric"
                          value=(handshake_port)
                          placeholder="443"
                          title=(tr(lang, "Optional TCP port for the server-side REALITY handshake. Blank = 443.", "Опциональный TCP-порт серверного рукопожатия REALITY. Пусто = 443."));
                }
                div.ed-form-row.ed-form-row--wide {
                    label.ed-form-label for="reality-handshake-server" {
                        (tr(lang, "handshake target", "цель рукопожатия"))
                    }
                    input.ed-field id="reality-handshake-server" type="text" name="handshake_server" maxlength="253"
                          value=(handshake_server)
                          placeholder=(sni)
                          title=(tr(lang, "Optional host or IP for the server-side REALITY handshake (for self-SNI e.g. 127.0.0.1). Blank uses the handshake domain.", "Опциональный хост или IP для серверного рукопожатия REALITY (для self-SNI, напр. 127.0.0.1). Пусто = домен рукопожатия."));
                }
                div.ed-form-row {
                    label.ed-form-label for="reality-listen-port" {
                        (tr(lang, "listen port", "порт"))
                    }
                    input.ed-field id="reality-listen-port" type="text" name="listen_port" maxlength="5" inputmode="numeric"
                          value=(port)
                          placeholder="443"
                          title=(tr(lang, "TCP port REALITY binds. Blank = 443. Must not collide with any other protocol on this node.", "TCP-порт, который слушает REALITY. Пусто = 443. Не должен совпадать с портом другого протокола на этом узле."));
                }
            }
            div.ed-form-actions {
                button.ed-btn-primary type="submit"
                       title=(tr(lang, "Save REALITY settings", "Сохранить настройки REALITY")) {
                    (icon("save")) (tr(lang, "Save REALITY config", "Сохранить конфиг"))
                }
            }
        }
    }
}

pub(crate) fn server_detail_quic_tls_section(
    server: &vpnctl_core::Server,
    server_secrets: &HashMap<String, String>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    if !server
        .enabled_protocols
        .iter()
        .any(|p| matches!(p.0.as_str(), "tuic-v5" | "hysteria2"))
    {
        return html! {};
    }
    let sid_enc = path_segment_encode(&server.id.0);
    let server_name = server_secrets
        .get("tls.server_name")
        .map(String::as_str)
        .unwrap_or("");
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow
            title=(tr(lang,
                "Optional TLS SNI sent by TUIC v5 and Hysteria2 clients with SPKI-pinned self-signed certs. Leave blank to omit server_name (legacy behavior).",
                "Опциональный TLS SNI для клиентов TUIC v5 и Hysteria2 с привязанным отпечатком самоподписанного сертификата. Пусто — не отправлять server_name (прежнее поведение).")) {
            (tr(lang, "QUIC TLS SNI (TUIC / HYSTERIA2)", "QUIC TLS SNI (TUIC / HYSTERIA2)"))
        }
        p.ed-form-hint {
            (tr(lang,
                "Clients receive the updated SNI when they refresh their subscription. Leave blank to clear.",
                "Клиенты получат обновлённый SNI при обновлении подписки. Оставь пустым, чтобы очистить."))
        }
        form.ed-form method="post"
             action=(format!("/admin/servers/{sid_enc}/quic-tls-config")) {
            div.ed-form-grid {
                div.ed-form-row.ed-form-row--wide {
                    label.ed-form-label for="quic-tls-server-name" {
                        (tr(lang, "TLS server_name", "TLS server_name"))
                    }
                    input.ed-field id="quic-tls-server-name" type="text" name="server_name" maxlength="253"
                          value=(server_name)
                          placeholder="ozon.ru"
                          title=(tr(lang, "Optional hostname emitted as tls.server_name for pinned TUIC/Hysteria2 clients.", "Опциональное имя хоста, передаваемое как tls.server_name для клиентов TUIC/Hysteria2."));
                }
            }
            div.ed-form-actions {
                button.ed-btn-primary type="submit"
                       title=(tr(lang, "Save QUIC TLS SNI", "Сохранить QUIC TLS SNI")) {
                    (icon("save")) (tr(lang, "save QUIC TLS SNI", "сохранить QUIC TLS SNI"))
                }
            }
        }
    }
}

pub(crate) fn server_detail_user_bandwidth_section(
    server: &vpnctl_core::Server,
    secrets: &std::collections::HashMap<String, String>,
    roster: Option<&crate::boosty_bandwidth::Roster>,
    onboarding_default: Option<&(u32, String)>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::boosty_bandwidth::{PENDING_KEY, POLICY_KEY, TierPolicy};
    use crate::i18n::tr;
    use vpnctl_kernels::{USER_BANDWIDTH_KEY, USER_BANDWIDTH_MAX_MBPS};

    if !server.kernels.iter().any(|kernel| kernel.0 == "sing-box") {
        return html! {};
    }
    let sid = path_segment_encode(&server.id.0);
    let rate = secrets.get(USER_BANDWIDTH_KEY).map_or("0", String::as_str);
    let saved_policy = secrets
        .get(POLICY_KEY)
        .and_then(|json| TierPolicy::from_saved(json));
    let can_set_default = saved_policy.is_some()
        && rate
            .parse::<u32>()
            .is_ok_and(|mbps| (1..=USER_BANDWIDTH_MAX_MBPS).contains(&mbps));
    let is_default = onboarding_default.is_some_and(|(mbps, policy)| {
        rate.parse::<u32>() == Ok(*mbps) && secrets.get(POLICY_KEY) == Some(policy)
    });
    let saved = saved_policy
        .as_ref()
        .filter(|policy| roster.is_some_and(|roster| policy.blog == roster.blog));
    let mut levels = roster
        .map(|roster| roster.levels.clone())
        .unwrap_or_default();
    if let Some(policy) = saved {
        for id in policy.levels.keys() {
            levels.entry(*id).or_default();
        }
    }
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow id="user-bandwidth" {
            (tr(lang, "Speed per user", "Скорость на пользователя"))
        }
        p.ed-form-hint {
            (tr(lang, "Each user's sing-box connections share this upload and download budget on this node. Zero means unlimited. Check deploy status to confirm that the kernel applied the setting.",
                "Все соединения sing-box одного пользователя на этом узле делят этот лимит на приём и отдачу. Ноль означает без ограничения. Результат применения видно в статусе деплоя."))
        }
        form.ed-form method="post" action=(format!("/admin/servers/{sid}/user-bandwidth")) {
            div.ed-form-row.ed-form-row--inline {
                label.ed-form-label for="user-bandwidth-mbps" { (tr(lang, "Mbit/s", "Мбит/с")) }
                input.ed-field id="user-bandwidth-mbps" name="mbps" type="number" min="0"
                    max=(USER_BANDWIDTH_MAX_MBPS) value=(rate) required;
                button.ed-btn-primary type="submit" { (tr(lang, "Apply uniform speed", "Применить единый лимит")) }
            }
        }
        @if secrets.get(PENDING_KEY).is_some_and(|value| value == "1") {
            p.ed-form-hint {
                (tr(lang, "The base limit is saved. Apply Boosty rates when a fresh roster is available.",
                    "Базовый лимит сохранён. Примените лимиты Boosty, когда будет доступен свежий список подписчиков."))
            }
        }
        details.ed-spoiler {
            summary { (tr(lang, "Speed by Boosty tier", "Скорость по уровням Boosty")) }
            @if let Some(roster) = roster {
                p.ed-form-hint {
                    (tr(lang, "Boosty account", "Аккаунт Boosty")) " " (&roster.blog)
                    " · " time datetime=(&roster.captured_at) { (&roster.captured_at) }
                }
                p.ed-form-hint {
                    (tr(lang, "Blank tiers use the default. Apply again to refresh after subscription changes.",
                        "Пустое поле означает базовый лимит. Примените повторно после изменения подписок."))
                }
                @if saved_policy.is_some() && saved.is_none() {
                    p.ed-form-hint { (tr(lang, "The active Boosty account has changed.", "Активный аккаунт Boosty сменился.")) }
                }
                form.ed-form method="post" action=(format!("/admin/servers/{sid}/user-bandwidth")) {
                    input type="hidden" name="boosty_blog" value=(roster.blog);
                    div.ed-form-grid {
                        div.ed-form-row {
                            label.ed-form-label for="boosty-base-speed" { (tr(lang, "Default (Mbit/s)", "Базовый лимит (Мбит/с)")) }
                            input.ed-field id="boosty-base-speed" name="mbps" type="number" min="1"
                                max=(USER_BANDWIDTH_MAX_MBPS) value=(if rate == "0" { "" } else { rate }) placeholder="40" required;
                        }
                        @for (id, label) in &levels {
                            @let input_id = format!("boosty-speed-{id}");
                            @let mbps = saved.and_then(|policy| policy.levels.get(id)).map(u32::to_string).unwrap_or_default();
                            div.ed-form-row {
                                label.ed-form-label for=(&input_id) { (label) " #" (id) }
                                input.ed-field id=(&input_id) name=(format!("tier_{id}")) type="number"
                                    min="1" max=(USER_BANDWIDTH_MAX_MBPS) value=(mbps);
                            }
                        }
                    }
                    div.ed-form-actions {
                        button.ed-btn-primary type="submit" { (tr(lang, "Apply Boosty rates", "Применить лимиты Boosty")) }
                    }
                }
            } @else {
                p.ed-form-hint { (tr(lang, "Waiting for a fresh roster from the Boosty dashboard.", "Ожидается свежий список подписчиков из панели Boosty.")) }
            }
            @if is_default {
                p.ed-form-hint {
                    (tr(lang, "These rates are the default for newly added nodes.",
                        "Эти лимиты используются для новых узлов."))
                }
            } @else if can_set_default {
                form method="post" action=(format!("/admin/servers/{sid}/user-bandwidth-default")) {
                    button.ed-abtn.ed-abtn--secondary type="submit" {
                        (tr(lang, "Use saved Boosty rates for new nodes", "Использовать сохранённые лимиты Boosty для новых узлов"))
                    }
                }
            }
        }
    }
}

pub(crate) fn server_detail_hysteria2_obfs_section(
    server: &vpnctl_core::Server,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    if !server.enabled_protocols.iter().any(|p| p.0 == "hysteria2") {
        return html! {};
    }
    let sid_enc = path_segment_encode(&server.id.0);
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow {
            (tr(lang, "HYSTERIA2 OBFUSCATION", "ОБФУСКАЦИЯ HYSTERIA2"))
        }
        p.ed-form-hint {
            (tr(lang,
                "Generate a new obfuscation password, then deploy. Clients receive the new password when they refresh their subscription after the deploy; cached configurations must be refreshed.",
                "Создай новый пароль обфускации, затем выполни деплой. Клиенты получат новый пароль при обновлении подписки после деплоя; сохранённые конфигурации нужно обновить."))
        }
        form method="post" action=(format!("/admin/servers/{sid_enc}/hysteria2-obfs-rotate")) {
            button type="submit" class="ed-abtn" {
                (icon("rotate-cw"))
                (tr(lang, "rotate obfuscation password", "сменить пароль обфускации"))
            }
        }
    }
}

pub(crate) fn server_detail_ss2022_mode_section(
    server: &vpnctl_core::Server,
    secrets: &HashMap<String, String>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    if !server
        .enabled_protocols
        .iter()
        .any(|p| p.0 == "shadowsocks-2022")
    {
        return html! {};
    }
    let sid_enc = path_segment_encode(&server.id.0);
    let multi_user = secrets
        .get("ss2022.mode")
        .is_some_and(|v| v == "multi-user");
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow { "SHADOWSOCKS-2022" }
        p {
            (tr(lang, "Key mode: ", "Режим ключей: "))
            (if multi_user {
                tr(lang, "per-user keys", "персональные ключи")
            } else {
                tr(lang, "shared key (legacy)", "общий ключ (прежний режим)")
            })
        }
        p.ed-form-hint {
            (tr(lang,
                "After changing the mode and the next deploy, every SS2022 user must re-import their profile. Per-user keys allow revocation on deploy and require an AES method; chacha20 does not support them.",
                "После смены режима и следующего деплоя каждый пользователь SS2022 должен заново импортировать профиль. Персональные ключи позволяют отзывать доступ при деплое и требуют метод AES; chacha20 их не поддерживает."))
        }
        form method="post" action=(format!("/admin/servers/{sid_enc}/ss2022-mode")) {
            input type="hidden" name="mode" value=(if multi_user { "shared" } else { "multi-user" });
            button type="submit" class="ed-abtn" {
                (tr(lang,
                    if multi_user { "switch to shared key" } else { "switch to per-user keys" },
                    if multi_user { "перейти на общий ключ" } else { "перейти на персональные ключи" }))
            }
        }
    }
}

pub(crate) fn server_detail_display_name_section(
    server: &vpnctl_core::Server,
    current: Option<&str>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let sid_enc = path_segment_encode(&server.id.0);
    let effective = server_display_label(&server.id.0, current);
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow
            title=(tr(
                lang,
                "Friendly name end users see in their client's server list — the '{Country}' part of the subscription label (e.g. 'Kyrgyzstan VLESS ~alice'). Blank = fall back to the built-in country map, then the uppercased server id.",
                "Понятное имя, которое пользователь видит в списке серверов клиента — часть '{Country}' в метке подписки (напр. 'Kyrgyzstan VLESS ~alice'). Пусто = фолбэк на встроенную карту стран, затем на server id в верхнем регистре.",
            )) {
            (tr(lang, "DISPLAY NAME", "ОТОБРАЖАЕМОЕ ИМЯ"))
        }
        p.ed-form-hint {
            (tr(lang, "Subscription label clients see: ", "Метка в подписке, которую видят клиенты: "))
            span.ed-mono { (effective) " VLESS ~<user>" }
            @if current.is_none() {
                (tr(lang, " — auto (no custom name set)", " — авто (своё имя не задано)"))
            }
        }
        form.ed-form method="post"
             action=(format!("/admin/servers/{sid_enc}/display-name")) {
            div.ed-form-row.ed-form-row--inline.ed-form-row--grow {
                label.ed-form-label.ed-sr-only for="server-display-name" {
                    (tr(lang, "Display name", "Отображаемое имя"))
                }
                input.ed-field id="server-display-name" type="text" name="display_name" maxlength="64"
                      value=(current.unwrap_or(""))
                      placeholder=(tr(lang, "e.g. Kyrgyzstan  (blank = auto)", "напр. Kyrgyzstan  (пусто = авто)"));
                button.ed-btn-primary type="submit"
                       title=(tr(
                           lang,
                           "Save this server's display label. Takes effect on the next subscription pull by each client; cached URIs are unaffected.",
                           "Сохранить отображаемую метку этого сервера. Применится при следующем обновлении подписки у каждого клиента; на кэшированные URI не влияет.",
                       )) {
                    (icon("save")) (tr(lang, "Save display name", "Сохранить"))
                }
            }
        }
    }
}

pub(crate) fn server_detail_billing_section(
    server: &vpnctl_core::Server,
    current: Option<&vpnctl_inventory::ServerBilling>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    use vpnctl_inventory::BillingCycle;
    let sid_enc = path_segment_encode(&server.id.0);
    let return_to = format!("/admin/servers/{sid_enc}/setup");

    html! {
        div.ed-rule {}
        div.ed-art-eyebrow
            title=(tr(
                lang,
                "Server rental billing parameters — due date, recurring cycle, cost, hoster portal link, and renewal terms.",
                "Параметры аренды сервера — срок следующей оплаты, период, стоимость, ссылка на биллинг хостера и статус автопродления.",
            )) {
            (tr(lang, "RENTAL & BILLING", "АРЕНДА И ОПЛАТА"))
        }

        @if let Some(b) = current {
            div style="margin: 8px 0 12px; padding: 10px 14px; background: var(--paper-2); border: 1px solid var(--rule); font-family: var(--mono); font-size: 12px;" {
                div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;" {
                    div {
                        b { (format!("{:.2} {}", b.amount_cents as f64 / 100.0, b.currency)) }
                        " / "
                        (match (b.billing_cycle, lang) {
                            (BillingCycle::Monthly, crate::i18n::Locale::Ru) => "месяц",
                            (BillingCycle::Monthly, crate::i18n::Locale::En) => "month",
                            (BillingCycle::Quarterly, crate::i18n::Locale::Ru) => "квартал (3 мес)",
                            (BillingCycle::Quarterly, crate::i18n::Locale::En) => "quarter",
                            (BillingCycle::SemiAnnual, crate::i18n::Locale::Ru) => "полгода (6 мес)",
                            (BillingCycle::SemiAnnual, crate::i18n::Locale::En) => "6 months",
                            (BillingCycle::Annual, crate::i18n::Locale::Ru) => "год",
                            (BillingCycle::Annual, crate::i18n::Locale::En) => "year",
                        })
                        " · "
                        (tr(lang, "Next due: ", "Срок оплаты: "))
                        b { (b.due_date) }
                        @if b.auto_renew {
                            " · " span style="color: var(--green);" { (icon("check")) (tr(lang, " Auto-renew", " Автопродление")) }
                        }
                    }
                    div style="display: flex; gap: 8px; align-items: center;" {
                        @if let Some(ref url) = b.billing_url {
                            a.ed-abtn.ed-abtn--secondary.ed-abtn--sm href=(url) target="_blank" rel="noopener noreferrer" {
                                (tr(lang, "Hoster Portal ↗", "В кабинет ↗"))
                            }
                        }
                        form method="post" action=(format!("/admin/servers/{sid_enc}/billing/advance")) style="margin: 0;" {
                            input type="hidden" name="return_to" value=(return_to) {}
                            button type="submit" class="ed-abtn ed-abtn--sm" title=(tr(lang, "Mark paid and advance date by 1 cycle", "Отметить оплату и сдвинуть дату на 1 цикл")) {
                                (icon("check")) " " (tr(lang, "+1 cycle", "+1 цикл"))
                            }
                        }
                    }
                }
                @if let Some(ref notes) = b.notes {
                    @if !notes.is_empty() {
                        div style="margin-top: 6px; font-size: 11px; color: var(--mute);" {
                            (tr(lang, "Notes: ", "Заметки: ")) (notes)
                        }
                    }
                }
            }
        } @else {
            p.ed-form-hint {
                (tr(lang, "No billing terms configured for this server yet. Set due date and pricing below.", "Параметры оплаты для этого сервера ещё не заданы. Укажи дату и стоимость ниже."))
            }
        }

        form.ed-form method="post"
             action=(format!("/admin/servers/{sid_enc}/billing")) {
            input type="hidden" name="return_to" value=(return_to) {}

            div.ed-form-grid {
                div.ed-form-row {
                    label.ed-form-label for="billing-due-date" {
                        (tr(lang, "Due date", "Дата оплаты"))
                    }
                    input.ed-field id="billing-due-date" type="date" name="due_date" required
                           value=(current.map(|b| b.due_date.as_str()).unwrap_or("")) {}
                }

                div.ed-form-row {
                    label.ed-form-label for="billing-cycle" {
                        (tr(lang, "Billing cycle", "Период"))
                    }
                    select.ed-field id="billing-cycle" name="billing_cycle" {
                        @let cur_c = current.map(|b| b.billing_cycle).unwrap_or(BillingCycle::Monthly);
                        option value="monthly" selected[cur_c == BillingCycle::Monthly] { (tr(lang, "Monthly", "1 месяц")) }
                        option value="quarterly" selected[cur_c == BillingCycle::Quarterly] { (tr(lang, "Quarterly (3 mo)", "3 месяца")) }
                        option value="semi-annual" selected[cur_c == BillingCycle::SemiAnnual] { (tr(lang, "Semi-annual (6 mo)", "6 месяцев")) }
                        option value="annual" selected[cur_c == BillingCycle::Annual] { (tr(lang, "Annual (12 mo)", "1 год")) }
                    }
                }

                div.ed-form-row {
                    label.ed-form-label for="billing-amount" {
                        (tr(lang, "Amount", "Стоимость"))
                    }
                    input.ed-field id="billing-amount" type="text" name="amount" placeholder="0.00"
                           value=(current.map(|b| format!("{:.2}", b.amount_cents as f64 / 100.0)).unwrap_or_default()) {}
                }

                div.ed-form-row {
                    label.ed-form-label for="billing-currency" {
                        (tr(lang, "Currency", "Валюта"))
                    }
                    input.ed-field id="billing-currency" list="currency_list" name="currency" maxlength="8"
                           value=(current.map(|b| b.currency.as_str()).unwrap_or("EUR"))
                           style="text-transform: uppercase;" {}
                }

                div.ed-form-row {
                    label.ed-form-label for="billing-past-paid"
                          title=(tr(lang, "Past cycles already paid (history record)", "Сколько циклов было оплачено ранее (запись в историю)")) {
                        (tr(lang, "Past paid", "Оплачено ранее"))
                    }
                    input.ed-field id="billing-past-paid" type="number" min="0" max="120" name="initial_payments_count" placeholder="0" {}
                }

                div.ed-form-row {
                    label.ed-form-check {
                        @let auto = current.map(|b| b.auto_renew).unwrap_or(false);
                        input type="checkbox" name="auto_renew" value="1" checked[auto] {}
                        (tr(lang, "Auto-renewal (card charge)", "Автосписание с карты"))
                    }
                }

                div.ed-form-row.ed-form-row--wide {
                    label.ed-form-label for="billing-url" {
                        (tr(lang, "Hoster portal URL", "Ссылка на кабинет хостера"))
                    }
                    input.ed-field id="billing-url" type="url" name="billing_url" placeholder="https://..."
                           value=(current.and_then(|b| b.billing_url.as_deref()).unwrap_or("")) {}
                }

                div.ed-form-row.ed-form-row--wide {
                    label.ed-form-label for="billing-notes" {
                        (tr(lang, "Notes / contract", "Заметки / договор"))
                    }
                    input.ed-field id="billing-notes" type="text" name="notes" placeholder=(tr(lang, "Account, card, contract...", "Аккаунт, карта, заметка..."))
                           value=(current.and_then(|b| b.notes.as_deref()).unwrap_or("")) {}
                }
            }

            div.ed-form-actions {
                button.ed-btn-primary type="submit" {
                    (icon("check")) (tr(lang, "Save parameters", "Сохранить"))
                }
            }
        }
    }
}

pub(crate) fn server_detail_auto_suppress_section(
    server: &vpnctl_core::Server,
    opt_in: bool,
    suppressed_at: Option<&str>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let sid_enc = path_segment_encode(&server.id.0);
    let button_class = if opt_in {
        "ed-abtn ed-abtn--secondary"
    } else {
        "ed-abtn ed-abtn--primary"
    };
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow
            title=(tr(
                lang,
                "Enabled for new servers. Two fully failed TCP VPN-port rounds from the measurement network hide this server from subscriptions; two fully successful rounds restore it. Missing measurements and SSH availability do not trigger hiding or recovery. Grants and keys stay unchanged.",
                "Включено для новых серверов. Два полностью неудачных раунда TCP-портов VPN из сети проверки скрывают сервер из подписок; два полностью успешных возвращают его. Отсутствие измерений и состояние SSH не вызывают скрытие или возврат. Доступы и ключи сохраняются.",
            )) {
            (tr(lang, "AUTO-SUPPRESS WHEN DOWN", "АВТО-СКРЫТИЕ ПРИ ПАДЕНИИ"))
        }
        @if let Some(ts) = suppressed_at {
            div style="font-family: var(--mono); font-size: 12px; padding: 8px 12px; background: var(--paper-tint); border: 1px solid var(--acc); color: var(--acc); margin: 8px 0 12px;" {
                (icon("eye-off")) (tr(lang, "currently SUPPRESSED since ", "сейчас СКРЫТ с ")) (ts)
                (tr(lang, " — hidden from subscriptions; auto-restores on recovery.", " — скрыт из подписок; вернётся автоматически при восстановлении."))
            }
        } @else {
            p.ed-form-hint {
                @if opt_in {
                    (tr(lang, "Enabled — waiting for confirmed TCP outage or recovery evidence.", "Включено — скрытие и возврат только по подтверждённым TCP-проверкам."))
                } @else {
                    (tr(lang, "Off — a down server stays in the subscription (clients fall back themselves).", "Выкл — упавший сервер остаётся в подписке (клиенты фолбэкаются сами)."))
                }
            }
        }
        form method="post"
             action=(format!("/admin/servers/{sid_enc}/auto-suppress"))
             style="display: inline;" {
            input type="hidden" name="enabled" value=(if opt_in { "false" } else { "true" });
            button type="submit" class=(button_class) {
                @if opt_in {
                    (icon("eye")) (tr(lang, "turn off auto-suppress", "выключить авто-скрытие"))
                } @else {
                    (icon("eye-off")) (tr(lang, "turn on auto-suppress", "включить авто-скрытие"))
                }
            }
        }
    }
}

pub(crate) fn server_detail_udp_pair_section(lang: crate::i18n::Locale) -> Markup {
    use crate::i18n::tr;
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow {
            (tr(lang, "Saved NaiveProxy and Hysteria2 UDP pairing", "Сохранённая UDP-пара NaiveProxy и Hysteria2"))
        }
        p.ed-muted {
            (tr(lang,
                "This setting belongs to the legacy URI format. Hysteria2 is available through a subscription with a verified TLS pin.",
                "Эта настройка относится к прежнему формату ссылок. Hysteria2 доступен по подписке с проверенным отпечатком TLS."))
        }
    }
}

pub(crate) fn server_detail_reserved_ports_section(
    server: &vpnctl_core::Server,
    reserved: &[u16],
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let sid_enc = path_segment_encode(&server.id.0);
    let prefill: String = reserved
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(",");
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow
            title=(tr(
                lang,
                "Per-server allowlist of ports the daemon must NEVER bind via sing-box. Use when a co-tenant service (legacy 3x-ui Docker container, separate xray, another VPN stack) owns one of the standard ports — deploys are refused fail-closed if any rendered inbound would collide.",
                "Список портов на этом сервере, которые демону ЗАПРЕЩЕНО занимать через sing-box. Используется когда на хосте уже крутится сторонний сервис (legacy 3x-ui Docker, отдельный xray, другой VPN-стек) на стандартном порту — деплой отказывается, если какой-то рендеренный inbound попытается их занять, fail-closed.",
            )) {
                (tr(lang, "RESERVED PORTS", "ЗАРЕЗЕРВИРОВАННЫЕ ПОРТЫ"))
            }
        p.ed-form-hint {
            (tr(
                lang,
                "Ports the daemon refuses to bind on this node. The sing-box pre-apply guard fails closed when any rendered inbound collides — so a co-tenant 3x-ui (or any other service vpnctl doesn't manage) can never get overwritten by a forgetful deploy.",
                "Порты, которые демон отказывается занимать на этой ноде. Пре-apply-guard sing-box падает fail-closed, если любой рендеренный inbound пересечётся — сторонний 3x-ui (или любой другой сервис, которым vpnctl не управляет) никогда не будет перезаписан забывчивым деплоем.",
            ))
        }
        div style="font-family: var(--mono); font-size: 12px; padding: 8px 12px; background: var(--paper-tint); border: 1px solid var(--rule); margin: 4px 0 12px;" {
            @if reserved.is_empty() {
                em style="color: var(--mute);" {
                    (tr(
                        lang,
                        "(no ports reserved — deploys are free to use every port the renderer picks)",
                        "(ничего не зарезервировано — деплои свободно используют любые порты, которые выбирает рендерер)",
                    ))
                }
            } @else {
                (tr(lang, "current: ", "сейчас: "))
                @for (i, port) in reserved.iter().enumerate() {
                    @if i > 0 { ", " }
                    b { (port) }
                }
            }
        }
        form.ed-form method="post"
             action=(format!("/admin/servers/{sid_enc}/reserved-ports")) {
            div.ed-form-row.ed-form-row--inline.ed-form-row--grow {
                label.ed-form-label.ed-sr-only for="reserved-ports" {
                    (tr(lang, "Reserved ports", "Зарезервированные порты"))
                }
                input.ed-field id="reserved-ports" type="text" name="ports" value=(prefill)
                      placeholder="443,2053,2096"
                      pattern="[0-9, ]*"
                      title=(tr(
                          lang,
                          "Comma-separated port numbers (1..=65535). Empty value clears the list.",
                          "Номера портов через запятую (1..=65535). Пустое поле очищает список.",
                      ));
                button.ed-btn-primary type="submit"
                       title=(tr(
                           lang,
                           "Replace the reserved-ports list with the values above. Future sing-box deploys refuse to bind any port in the list.",
                           "Заменить список зарезервированных портов значениями выше. Будущие деплои sing-box откажутся занимать любой порт из списка.",
                       )) {
                    (icon("save")) (tr(lang, "Save reserved ports", "Сохранить"))
                }
            }
        }
    }
}

pub(crate) fn server_detail_dnstt_section(
    server: &vpnctl_core::Server,
    secrets: &HashMap<String, String>,
    health: Option<&vpnctl_inventory::NodeHealthRow>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    if server.address.parse::<std::net::Ipv4Addr>().is_err() {
        return html! {};
    }
    let domain = secrets.get("dnstt.domain").map_or("", String::as_str);
    let resolver = secrets.get("dnstt.resolver").map_or("", String::as_str);
    let noise = secrets.get("dnstt.public_key").map_or("", String::as_str);
    let applied = secrets
        .get("observed.dnstt.applied")
        .is_some_and(|value| value == &format!("{domain}+{resolver}+{noise}"));
    let enabled = server.enabled_protocols.iter().any(|p| p.0 == "dnstt");
    let active = health
        .filter(|row| chrono::Utc::now() - row.ts < chrono::Duration::minutes(30))
        .and_then(|row| row.kernel_versions_json.as_deref())
        .and_then(|json| serde_json::from_str::<serde_json::Value>(json).ok())
        .and_then(|value| value["dnstt"]["active"].as_bool());
    let state = match (enabled, applied, active) {
        (false, _, _) => tr(lang, "Disabled", "Выключен"),
        (true, false, _) => tr(lang, "Pending deploy", "Ожидает развёртывания"),
        (true, true, Some(true)) => tr(lang, "Services active", "Службы активны"),
        (true, true, Some(false)) => tr(lang, "Services down", "Службы остановлены"),
        (true, true, None) => tr(
            lang,
            "Applied, awaiting a fresh probe",
            "Применено, ожидает свежей пробы",
        ),
    };
    let sid = path_segment_encode(&server.id.0);
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow id="dnstt" { "DNSTT + SSH" }
        p.ed-form-hint { (state) }
        form.ed-form method="post" action=(format!("/admin/servers/{sid}/dnstt-config")) {
            div.ed-form-grid {
                div.ed-form-row {
                    label.ed-form-label for="dnstt-domain" { (tr(lang, "Delegated DNS zone", "Делегированная DNS-зона")) }
                    input.ed-field id="dnstt-domain" type="text" name="domain" value=(domain) maxlength="100" required;
                }
                div.ed-form-row {
                    label.ed-form-label for="dnstt-resolver" { (tr(lang, "UDP DNS resolver IPv4", "IPv4 DNS-резолвера по UDP")) }
                    input.ed-field id="dnstt-resolver" type="text" name="resolver" value=(resolver) maxlength="15" required;
                }
            }
            div.ed-form-actions {
                button.ed-btn-primary type="submit" {
                    (icon("save")) (tr(lang, "Save DNSTT settings", "Сохранить настройки DNSTT"))
                }
            }
        }
    }
}

pub(crate) fn server_detail_turnrelay_section(
    server: &vpnctl_core::Server,
    secrets: &HashMap<String, String>,
    health: Option<&vpnctl_inventory::NodeHealthRow>,
    fleet: (
        &[vpnctl_core::Server],
        &crate::handlers::admin::helpers::ServerNames,
    ),
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    if server.address.parse::<std::net::IpAddr>().is_err() {
        return html! {};
    }
    let enabled = server
        .enabled_protocols
        .iter()
        .any(|protocol| protocol.0 == "turnrelay");
    let kernel = server.kernels.iter().any(|kernel| kernel.0 == "turnrelay");
    if !enabled && !kernel {
        return html! {};
    }
    let sid = path_segment_encode(&server.id.0);
    let port = secrets
        .get("turnrelay.listen_port")
        .map(String::as_str)
        .unwrap_or("");
    let mode = secrets
        .get("turnrelay.mode")
        .map(String::as_str)
        .unwrap_or(vpnctl_protocols::TURNRELAY_DEFAULT_MODE);
    let (servers, names) = fleet;
    let selected_entry = secrets
        .get("turnrelay.relay_server_id")
        .map_or("", String::as_str);
    let turn_server = secrets
        .get("turnrelay.turn_server")
        .map(String::as_str)
        .unwrap_or("");
    let turn_username = secrets
        .get("turnrelay.turn_username")
        .map(String::as_str)
        .unwrap_or("");
    let turn_password_set = secrets
        .get("turnrelay.turn_password")
        .is_some_and(|value| !value.is_empty());
    let connections = secrets
        .get("turnrelay.connections")
        .map(String::as_str)
        .unwrap_or("2");
    let udp = secrets
        .get("turnrelay.udp")
        .is_none_or(|value| !matches!(value.as_str(), "false" | "0"));
    let publish = secrets
        .get("turnrelay.publish")
        .map(String::as_str)
        .unwrap_or("");
    let publish_targets = secrets
        .get("turnrelay.publish_targets")
        .map(String::as_str)
        .unwrap_or("");
    let fingerprint = secrets
        .get("observed.turnrelay.cert_sha256")
        .filter(|value| vpnctl_protocols::is_valid_turnrelay_fingerprint(value));
    let applied = fingerprint.is_some()
        && vpnctl_protocols::turnrelay_applied_digest(&vpnctl_core::RenderCtx::new(
            server, secrets,
        ))
        .ok()
        .is_some_and(|digest| {
            secrets
                .get("observed.turnrelay.applied")
                .is_some_and(|value| value == &digest)
        });
    let active = health
        .filter(|row| chrono::Utc::now() - row.ts < chrono::Duration::minutes(30))
        .and_then(|row| row.kernel_versions_json.as_deref())
        .and_then(|json| serde_json::from_str::<serde_json::Value>(json).ok())
        .and_then(|value| value["turnrelay"]["active"].as_bool());
    let state = match (enabled, applied, active) {
        (false, _, _) => tr(lang, "Disabled", "Выключен"),
        (true, false, _) => tr(lang, "Pending deploy", "Ожидает развёртывания"),
        (true, true, Some(true)) => tr(lang, "Service active", "Служба активна"),
        (true, true, Some(false)) => tr(lang, "Service down", "Служба остановлена"),
        (true, true, None) => tr(
            lang,
            "Applied, awaiting a fresh probe",
            "Применено, ожидает свежей пробы",
        ),
    };
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow id="turnrelay"
            title=(tr(lang,
                "Exit-only TURN relay: clients reach this node through a TURN provider and pin its certificate. The exit password is minted once; client-visible settings are issued only after a successful deploy.",
                "Выходной TURN-релей: клиенты приходят на этот узел через TURN-провайдера и пиннят его сертификат. Пароль выхода создаётся один раз; клиентские настройки выдаются только после успешного деплоя.")) {
            (tr(lang, "TURNRELAY (EXIT)", "TURNRELAY (ВЫХОД)"))
        }
        p.ed-form-hint { (state) }
        @if let Some(fingerprint) = fingerprint {
            p style="font-family: var(--mono); font-size: 11px; color: var(--mute); overflow-wrap: anywhere;" {
                (tr(lang, "certificate SHA-256: ", "SHA-256 сертификата: ")) (fingerprint)
            }
        }
        form.ed-form method="post" action=(format!("/admin/servers/{sid}/turnrelay-config")) {
            div.ed-form-grid {
                div.ed-form-row {
                    label.ed-form-label for="turnrelay-listen-port" {
                        (tr(lang, "UDP port (blank = 53492)", "UDP-порт (пусто = 53492)"))
                    }
                    input.ed-field id="turnrelay-listen-port" type="text" name="listen_port" value=(port) maxlength="5" inputmode="numeric";
                }
                div.ed-form-row {
                    label.ed-form-label for="turnrelay-mode" {
                        (tr(lang, "Obfuscation mode", "Режим обфускации"))
                    }
                    select.ed-field id="turnrelay-mode" name="mode" {
                        option value="dtls" selected[mode == "dtls"] { "dtls" }
                        option value="srtp" selected[mode == "srtp"] { "srtp" }
                    }
                }
                div.ed-form-row.ed-form-row--wide {
                    label.ed-form-label for="turnrelay-entry" {
                        (tr(lang, "Managed TURN relay (entry)", "Управляемый TURN-релей (вход)"))
                    }
                    select.ed-field id="turnrelay-entry" name="relay_server_id" {
                        option value="" selected[selected_entry.is_empty()] {
                            (tr(lang, "Manual / external", "Ручной / внешний"))
                        }
                        @for entry in servers.iter().filter(|entry| entry.id != server.id && crate::handlers::admin::turnrelay::enabled(entry, "turnrelay-relay")) {
                            option value=(entry.id.0) selected[entry.id.0 == selected_entry] {
                                (names.get(&entry.id).unwrap_or(&entry.id.0))
                            }
                        }
                    }
                }
                div.ed-form-row.ed-form-row--wide {
                    label.ed-form-label for="turnrelay-server" {
                        (tr(lang, "TURN server host:port", "TURN-сервер host:port"))
                    }
                    input.ed-field id="turnrelay-server" type="text" name="turn_server" value=(turn_server) maxlength="255";
                }
                div.ed-form-row {
                    label.ed-form-label for="turnrelay-username" {
                        (tr(lang, "TURN username", "Имя пользователя TURN"))
                    }
                    input.ed-field id="turnrelay-username" type="text" name="turn_username" value=(turn_username) maxlength="256";
                }
                div.ed-form-row {
                    label.ed-form-label for="turnrelay-password" {
                        (tr(lang, "TURN password", "Пароль TURN"))
                    }
                    input.ed-field id="turnrelay-password" type="password" name="turn_password" value="" maxlength="512"
                        autocomplete="new-password"
                        placeholder=(if turn_password_set {
                            tr(lang, "unchanged", "без изменений")
                        } else {
                            tr(lang, "required", "обязательно")
                        });
                }
                div.ed-form-row {
                    label.ed-form-label for="turnrelay-connections" {
                        (tr(lang, "Connections (1..60)", "Соединений (1..60)"))
                    }
                    input.ed-field id="turnrelay-connections" type="number" name="connections" value=(connections) min="1" max="60" required;
                }
                label.ed-form-check for="turnrelay-udp" {
                    input id="turnrelay-udp" type="checkbox" name="udp" value="true" checked[udp];
                    (tr(lang, "carry UDP through the relay", "передавать UDP через релей"))
                }
                div.ed-form-row.ed-form-row--wide {
                    label.ed-form-label for="turnrelay-publish" {
                        (tr(lang, "Publish (comma-separated, e.g. vless+reality)", "Публиковать (через запятую, напр. vless+reality)"))
                    }
                    input.ed-field id="turnrelay-publish" type="text" name="publish" value=(publish) maxlength="128"
                        placeholder="vless+reality";
                }
                div.ed-form-row.ed-form-row--wide {
                    label.ed-form-label for="turnrelay-publish-targets" {
                        (tr(lang, "Cross-server targets (server IDs or *)", "Кросс-серверные цели (ID серверов или *)"))
                    }
                    input.ed-field id="turnrelay-publish-targets" type="text" name="publish_targets" value=(publish_targets) maxlength="512"
                        placeholder="*";
                }
                p.ed-form-hint.ed-form-row--wide {
                    (tr(lang,
                        "A managed entry supplies the TURN address and credentials when you save. Manual settings apply on the next deploy. Relayed VLESS profiles require VPNRouter with turnrelay-v1.",
                        "Управляемый вход задаёт адрес и учётные данные TURN при сохранении. Ручные настройки вступают в силу при следующем деплое. Для релейных VLESS-профилей нужен VPNRouter с поддержкой turnrelay-v1."))
                }
            }
            div.ed-form-actions {
                button.ed-btn-primary type="submit" {
                    (tr(lang, "Save TurnRelay settings", "Сохранить настройки TurnRelay"))
                }
            }
        }
    }
}

pub(crate) fn server_detail_turnrelay_relay_section(
    server: &vpnctl_core::Server,
    secrets: &HashMap<String, String>,
    exits: Option<&std::collections::BTreeSet<String>>,
    names: &crate::handlers::admin::helpers::ServerNames,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::handlers::admin::turnrelay::{ENTRY, PORT, enabled};
    use crate::i18n::tr;
    if !enabled(server, ENTRY) && !server.kernels.iter().any(|kernel| kernel.0 == ENTRY) {
        return html! {};
    }
    let sid = path_segment_encode(&server.id.0);
    let port = secrets
        .get(PORT)
        .and_then(|port| port.parse::<u16>().ok())
        .filter(|port| *port > 0)
        .unwrap_or(vpnctl_protocols::TURNRELAY_RELAY_PORT);
    html! {
        div.ed-rule {}
        section id="turnrelay-relay" {
            h2.ed-art-eyebrow { (tr(lang, "TURNRELAY RELAY (ENTRY)", "TURNRELAY РЕЛЕЙ (ВХОД)")) }
            p.ed-form-hint {
                (tr(lang, "Linked exits", "Привязанные выходы"))
                @if let Some(exits) = exits {
                    @for exit in exits {
                        " " a.ed-role-peer href=(format!("/admin/servers/{}", path_segment_encode(exit))) {
                            (names.get(&vpnctl_core::ServerId(exit.clone())).unwrap_or(exit))
                        }
                    }
                } @else {
                    " · " (tr(lang, "None", "Нет"))
                }
            }
            form.ed-form method="post" action=(format!("/admin/servers/{sid}/turnrelay-relay-config")) {
                div.ed-form-grid {
                    div.ed-form-row {
                        label.ed-form-label for="turnrelay-relay-port" { (tr(lang, "TCP and UDP port", "Порт TCP и UDP")) }
                        input.ed-field id="turnrelay-relay-port" name="listen_port" type="number" min="1" max="65535" value=(port) required;
                    }
                    div.ed-form-row {
                        label.ed-form-label for="turnrelay-relay-username" { (tr(lang, "TURN username", "Имя пользователя TURN")) }
                        input.ed-field id="turnrelay-relay-username" type="text" value=(secrets.get("turnrelay_relay.username").map_or("", String::as_str)) readonly;
                    }
                }
                div.ed-form-actions {
                    button.ed-btn-primary type="submit" { (tr(lang, "Save TURN entry settings", "Сохранить настройки входа TURN")) }
                }
            }
        }
    }
}

pub(crate) fn server_detail_vmess_section(
    server: &vpnctl_core::Server,
    secrets: &HashMap<String, String>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    if !server.kernels.iter().any(|kernel| kernel.0 == "sing-box") {
        return html! {};
    }
    let sid = path_segment_encode(&server.id.0);
    let domain = secrets
        .get("vmess.domain")
        .map(String::as_str)
        .unwrap_or("");
    let port = secrets
        .get("vmess.listen_port")
        .map(String::as_str)
        .unwrap_or("443");
    let detour = secrets
        .get("vmess.preferred_entry")
        .map(String::as_str)
        .unwrap_or("");
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow id="vmess" { "VMess WebSocket + TLS" }
        form.ed-form method="post" action=(format!("/admin/servers/{sid}/vmess-config")) {
            div.ed-form-grid {
                div.ed-form-row.ed-form-row--wide {
                    label.ed-form-label for="vmess-domain" { (tr(lang, "TLS hostname", "Имя хоста TLS")) }
                    input.ed-field id="vmess-domain" type="text" name="domain" value=(domain) required maxlength="253";
                }
                div.ed-form-row {
                    label.ed-form-label for="vmess-listen-port" { (tr(lang, "TCP port", "Порт TCP")) }
                    input.ed-field id="vmess-listen-port" type="number" name="listen_port" value=(port) min="1" max="65535" required;
                }
                div.ed-form-row {
                    label.ed-form-label for="vmess-detour" { (tr(lang, "Optional VLESS Reality entry server ID", "ID входного сервера VLESS Reality, если нужен")) }
                    input.ed-field id="vmess-detour" type="text" name="detour_via" value=(detour);
                }
                div.ed-form-row.ed-form-row--wide {
                    label.ed-form-label for="vmess-certificate" { (tr(lang, "PEM certificate chain", "Цепочка сертификатов PEM")) }
                    textarea.ed-field id="vmess-certificate" name="certificate" rows="4" autocomplete="off" {}
                }
                div.ed-form-row.ed-form-row--wide {
                    label.ed-form-label for="vmess-key" { (tr(lang, "PEM private key", "Закрытый ключ PEM")) }
                    textarea.ed-field id="vmess-key" name="key" rows="4" autocomplete="off" {}
                }
                @if secrets.contains_key("vmess.key") {
                    p.ed-form-hint.ed-form-row--wide {
                        (tr(lang, "Leave both PEM fields blank to keep the saved pair.", "Оставьте оба поля PEM пустыми, чтобы сохранить действующую пару."))
                    }
                }
            }
            div.ed-form-actions {
                button.ed-btn-primary type="submit" {
                    (icon("save")) (tr(lang, "Save VMess settings", "Сохранить настройки VMess"))
                }
            }
        }
    }
}

pub(crate) fn server_detail_trusttunnel_section(
    server: &vpnctl_core::Server,
    secrets: &HashMap<String, String>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let sid = path_segment_encode(&server.id.0);
    let setting = |key, default| secrets.get(key).map_or(default, String::as_str);
    let port = vpnctl_protocols::TRUSTTUNNEL_PORT.to_string();
    let pin_ready = secrets
        .get("observed.tls.cert_public_key_sha256")
        .is_some_and(|pin| pin.len() == 64 && pin.bytes().all(|byte| byte.is_ascii_hexdigit()));
    html! {
        div.ed-rule {}
        h2.ed-art-eyebrow id="trusttunnel" { "TrustTunnel" }
        @if !secrets.contains_key("trusttunnel.domain") && !pin_ready {
            p.ed-form-hint {
                (tr(lang,
                    "Deploy the node to record its certificate pin before issuing TrustTunnel profiles.",
                    "Выполните деплой ноды, чтобы записать отпечаток сертификата и выдать профили TrustTunnel."))
            }
        }
        form.ed-form method="post" action=(format!("/admin/servers/{sid}/trusttunnel-config")) {
            div.ed-form-grid {
                div.ed-form-row {
                    label.ed-form-label for="trusttunnel-port" { (tr(lang, "Listen port", "Порт прослушивания")) }
                    input.ed-field id="trusttunnel-port" name="listen_port" type="number" min="1" max="65535"
                        value=(setting("trusttunnel.listen_port", &port)) required;
                }
                @for (name, label, value) in [
                    ("quic", tr(lang, "HTTP/3 listener", "Прослушивание HTTP/3"), setting("trusttunnel.quic", "true")),
                    ("client_quic", tr(lang, "Use HTTP/3 in client profiles", "Использовать HTTP/3 в профилях клиента"), setting("trusttunnel.client_quic", "false")),
                    ("udp", tr(lang, "UDP forwarding", "Перенаправление UDP"), setting("trusttunnel.udp", "true")),
                ] {
                    div.ed-form-row {
                        label.ed-form-label for=(format!("trusttunnel-{name}")) { (label) }
                        select.ed-field id=(format!("trusttunnel-{name}")) name=(name) {
                            option value="true" selected[value == "true"] { (tr(lang, "Enabled", "Включено")) }
                            option value="false" selected[value == "false"] { (tr(lang, "Disabled", "Выключено")) }
                        }
                    }
                }
                div.ed-form-row {
                    label.ed-form-label for="trusttunnel-sni" { (tr(lang, "SNI for the managed certificate", "SNI управляемого сертификата")) }
                    input.ed-field id="trusttunnel-sni" name="sni" type="text" maxlength="253" value=(setting("trusttunnel.sni", ""));
                }
                div.ed-form-row {
                    label.ed-form-label for="trusttunnel-domain" { (tr(lang, "Custom TLS hostname", "Имя хоста для собственного TLS")) }
                    input.ed-field id="trusttunnel-domain" name="domain" type="text" maxlength="253" value=(setting("trusttunnel.domain", ""));
                }
                div.ed-form-row {
                    label.ed-form-label for="trusttunnel-certificate" { (tr(lang, "PEM certificate chain", "Цепочка сертификатов PEM")) }
                    textarea.ed-field id="trusttunnel-certificate" name="certificate" rows="4" autocomplete="off" {}
                }
                div.ed-form-row {
                    label.ed-form-label for="trusttunnel-key" { (tr(lang, "PEM private key", "Закрытый ключ PEM")) }
                    textarea.ed-field id="trusttunnel-key" name="key" rows="4" autocomplete="off" {}
                }
            }
            p.ed-form-hint {
                (tr(lang,
                    "Leave the custom hostname blank to use the node certificate. Leave both PEM fields blank to keep a saved pair.",
                    "Оставьте имя хоста пустым, чтобы использовать сертификат ноды. Оставьте оба поля PEM пустыми, чтобы сохранить текущую пару."))
            }
            div.ed-form-actions {
                button.ed-btn-primary type="submit" { (icon("save")) (tr(lang, "Save TrustTunnel settings", "Сохранить настройки TrustTunnel")) }
            }
        }
    }
}

pub(crate) fn server_detail_mieru_section(
    server: &vpnctl_core::Server,
    secrets: &HashMap<String, String>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let sid = path_segment_encode(&server.id.0);
    let port = vpnctl_protocols::MIERU_PORT.to_string();
    let fields: [(&str, &str, &str, &[&str]); 3] = [
        (
            "transport",
            tr(lang, "Transport", "Транспорт"),
            "tcp",
            &["tcp", "udp"],
        ),
        (
            "multiplexing",
            tr(lang, "Multiplexing", "Мультиплексирование"),
            "middle",
            &["default", "off", "low", "middle", "high"],
        ),
        (
            "handshake_mode",
            tr(lang, "Handshake mode", "Режим рукопожатия"),
            "standard",
            &["default", "standard", "no_wait"],
        ),
    ];
    html! {
        div.ed-rule {}
        h2.ed-art-eyebrow id="mieru" { "Mieru" }
        form.ed-form method="post" action=(format!("/admin/servers/{sid}/mieru-config")) {
            div.ed-form-grid {
                div.ed-form-row {
                    label.ed-form-label for="mieru-port" { (tr(lang, "Listen port", "Порт прослушивания")) }
                    input.ed-field id="mieru-port" name="listen_port" type="number" min="1" max="65535"
                        value=(secrets.get("mieru.listen_port").unwrap_or(&port)) required;
                }
                @for (name, label, default, options) in fields {
                    @let value = secrets.get(&format!("mieru.{name}")).map_or(default, String::as_str);
                    div.ed-form-row {
                        label.ed-form-label for=(format!("mieru-{name}")) { (label) }
                        select.ed-field id=(format!("mieru-{name}")) name=(name) {
                            @for option in options {
                                option value=(option) selected[*option == value] { (option) }
                            }
                        }
                    }
                }
            }
            div.ed-form-actions {
                button.ed-btn-primary type="submit" { (icon("save")) (tr(lang, "Save Mieru settings", "Сохранить настройки Mieru")) }
            }
        }
    }
}
