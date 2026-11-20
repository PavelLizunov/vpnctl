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
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 10px;" {
            (tr(lang,
                "Before deploy: point a DNS A-record at this server and open TCP 80+443 — Caddy's ACME needs both. vpnctl can't do DNS for you.",
                "До деплоя: направь DNS A-запись на этот сервер и открой TCP 80+443 — встроенному ACME Caddy нужны оба. DNS vpnctl за тебя не сделает."))
        }
        form method="post"
             action=(format!("/admin/servers/{sid_enc}/naive-config"))
             style="display: grid; grid-template-columns: 96px 1fr; gap: 6px 8px; align-items: center; max-width: 520px;" {
            label style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                (tr(lang, "domain", "домен"))
            }
            input type="text" name="domain" maxlength="253" required
                  value=(domain)
                  placeholder="cdn.example.com"
                  style="padding: 4px 8px; font-family: var(--mono); font-size: 12px; border: 1px solid var(--rule);";
            label style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                (tr(lang, "ACME email", "ACME почта"))
            }
            input type="text" name="acme_email" maxlength="254"
                  value=(email)
                  placeholder="admin@example.com"
                  style="padding: 4px 8px; font-family: var(--mono); font-size: 12px; border: 1px solid var(--rule);";
            span {}
            button type="submit"
                   title=(tr(lang, "Save naive domain + ACME email", "Сохранить домен naive + ACME почту"))
                   style="justify-self: start; padding: 4px 12px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                (icon("save")) (tr(lang, "save naive config", "сохранить конфиг"))
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
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 10px;" {
            (tr(lang,
                "Before deploy: point a DNS A-record at this server and open TCP 80 (ACME) + the front port. The secret ws path is generated automatically on deploy.",
                "До деплоя: направь DNS A-запись на этот сервер и открой TCP 80 (ACME) + фронт-порт. Секретный ws-путь генерируется автоматически при деплое."))
            @if path_minted {
                (tr(lang, " The path is set.", " Путь задан."))
            } @else {
                (tr(lang, " The path is not minted yet (deploy to generate it).", " Путь ещё не сгенерирован (задеплой, чтобы создать его)."))
            }
        }
        form method="post"
             action=(format!("/admin/servers/{sid_enc}/vlessws-config"))
             style="display: grid; grid-template-columns: 96px 1fr; gap: 6px 8px; align-items: center; max-width: 520px;" {
            label style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                (tr(lang, "domain", "домен"))
            }
            input type="text" name="domain" maxlength="253" required
                  value=(domain)
                  placeholder="vpn.example.com"
                  style="padding: 4px 8px; font-family: var(--mono); font-size: 12px; border: 1px solid var(--rule);";
            label style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                (tr(lang, "front port", "фронт-порт"))
            }
            input type="text" name="listen_port" maxlength="5" inputmode="numeric"
                  value=(port)
                  placeholder="8443"
                  title=(tr(lang, "Public TLS port Caddy serves on — NOT 443 (REALITY owns that). Blank = 8443.", "Публичный TLS-порт Caddy — НЕ 443 (его занимает REALITY). Пусто = 8443."))
                  style="padding: 4px 8px; font-family: var(--mono); font-size: 12px; border: 1px solid var(--rule);";
            label style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                (tr(lang, "ACME email", "ACME почта"))
            }
            input type="text" name="acme_email" maxlength="254"
                  value=(email)
                  placeholder="admin@example.com"
                  style="padding: 4px 8px; font-family: var(--mono); font-size: 12px; border: 1px solid var(--rule);";
            span {}
            button type="submit"
                   title=(tr(lang, "Save vless-ws domain + front port + ACME email", "Сохранить домен vless-ws + фронт-порт + ACME почту"))
                   style="justify-self: start; padding: 4px 12px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                (icon("save")) (tr(lang, "save vless-ws config", "сохранить конфиг"))
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
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow
            title=(tr(lang,
                "REALITY binds this port directly. Default 443 (gold-standard HTTPS cover); set an alternate port when a co-tenant owns 443 on this host (naive/caddy, legacy 3x-ui). Saving re-validates against every other protocol's port and takes effect on deploy.",
                "REALITY слушает этот порт напрямую. По умолчанию 443 (золотой стандарт HTTPS-маскировки); задай другой порт, если 443 на этом хосте занят со-жителем (naive/caddy, легаси 3x-ui). При сохранении проверяется против портов всех остальных протоколов и вступает в силу при деплое.")) {
            (tr(lang, "VLESS+REALITY CONFIG", "КОНФИГ VLESS+REALITY"))
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 10px;" {
            (tr(lang,
                "Deploy after saving. Clients receive the new handshake domain when they refresh their subscription after the deploy.",
                "После сохранения выполни деплой. Клиенты получат новый домен рукопожатия при обновлении подписки после деплоя."))
        }
        form method="post"
             action=(format!("/admin/servers/{sid_enc}/reality-config"))
             style="display: grid; grid-template-columns: 96px 1fr; gap: 6px 8px; align-items: center; max-width: 520px;" {
            label for="reality-sni" style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                (tr(lang, "handshake domain", "домен рукопожатия"))
            }
            input id="reality-sni" type="text" name="sni" maxlength="253" required
                  value=(sni)
                  title=(tr(lang, "Hostname of the HTTPS site used for the REALITY handshake.", "Имя HTTPS-сайта для рукопожатия REALITY."))
                  style="min-width: 0; padding: 4px 8px; font-family: var(--mono); font-size: 12px; border: 1px solid var(--rule);";
            label style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                (tr(lang, "listen port", "порт"))
            }
            input type="text" name="listen_port" maxlength="5" inputmode="numeric"
                  value=(port)
                  placeholder="443"
                  title=(tr(lang, "TCP port REALITY binds. Blank = 443. Must not collide with any other protocol on this node.", "TCP-порт, который слушает REALITY. Пусто = 443. Не должен совпадать с портом другого протокола на этом узле."))
                  style="padding: 4px 8px; font-family: var(--mono); font-size: 12px; border: 1px solid var(--rule);";
            span {}
            button type="submit"
                   title=(tr(lang, "Save REALITY settings", "Сохранить настройки REALITY"))
                   style="justify-self: start; padding: 4px 12px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                (icon("save")) (tr(lang, "save reality config", "сохранить конфиг"))
            }
        }
    }
}

pub(crate) fn server_detail_user_bandwidth_section(
    server: &vpnctl_core::Server,
    secrets: &std::collections::HashMap<String, String>,
    roster: Option<&crate::boosty_bandwidth::Roster>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::boosty_bandwidth::{POLICY_KEY, TierPolicy};
    use crate::i18n::tr;
    use vpnctl_kernels::{USER_BANDWIDTH_KEY, USER_BANDWIDTH_MAX_MBPS};

    if !server.kernels.iter().any(|kernel| kernel.0 == "sing-box") {
        return html! {};
    }
    let sid = path_segment_encode(&server.id.0);
    let rate = secrets.get(USER_BANDWIDTH_KEY).map_or("0", String::as_str);
    let saved_policy = secrets
        .get(POLICY_KEY)
        .and_then(|json| serde_json::from_str::<TierPolicy>(json).ok())
        .filter(|policy| !policy.blog.is_empty());
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
        p.ed-grid__mut {
            (tr(lang, "Each user's sing-box connections share this upload and download budget on this node. Zero means unlimited. Check deploy status to confirm that the kernel applied the setting.",
                "Все соединения sing-box одного пользователя на этом узле делят этот лимит на приём и отдачу. Ноль означает без ограничения. Результат применения видно в статусе деплоя."))
        }
        form method="post" action=(format!("/admin/servers/{sid}/user-bandwidth")) {
            label for="user-bandwidth-mbps" { (tr(lang, "Mbit/s", "Мбит/с")) }
            " "
            input.ed-inp id="user-bandwidth-mbps" name="mbps" type="number" min="0"
                max=(USER_BANDWIDTH_MAX_MBPS) value=(rate) required;
            " "
            button.ed-abtn type="submit" { (tr(lang, "Apply uniform speed", "Применить единый лимит")) }
        }
        details.ed-spoiler {
            summary { (tr(lang, "Speed by Boosty tier", "Скорость по уровням Boosty")) }
            @if let Some(roster) = roster {
                p.ed-grid__mut {
                    (tr(lang, "Boosty account", "Аккаунт Boosty")) " " (&roster.blog)
                    " · " time datetime=(&roster.captured_at) { (&roster.captured_at) }
                }
                p.ed-grid__mut {
                    (tr(lang, "Blank tiers use the default. Apply again to refresh after subscription changes.",
                        "Пустое поле означает базовый лимит. Примените повторно после изменения подписок."))
                }
                @if saved_policy.is_some() && saved.is_none() {
                    p.ed-grid__mut { (tr(lang, "The active Boosty account has changed.", "Активный аккаунт Boosty сменился.")) }
                }
                form method="post" action=(format!("/admin/servers/{sid}/user-bandwidth")) {
                    input type="hidden" name="boosty_blog" value=(roster.blog);
                    p {
                        label for="boosty-base-speed" { (tr(lang, "Default (Mbit/s)", "Базовый лимит (Мбит/с)")) }
                        " "
                        input.ed-inp id="boosty-base-speed" name="mbps" type="number" min="1"
                            max=(USER_BANDWIDTH_MAX_MBPS) value=(if rate == "0" { "" } else { rate }) placeholder="40" required;
                    }
                    @for (id, label) in &levels {
                        @let input_id = format!("boosty-speed-{id}");
                        @let mbps = saved.and_then(|policy| policy.levels.get(id)).map(u32::to_string).unwrap_or_default();
                        p {
                            label for=(&input_id) { (label) " #" (id) }
                            " "
                            input.ed-inp id=(&input_id) name=(format!("tier_{id}")) type="number"
                                min="1" max=(USER_BANDWIDTH_MAX_MBPS) value=(mbps);
                        }
                    }
                    button.ed-abtn type="submit" { (tr(lang, "Apply Boosty rates", "Применить лимиты Boosty")) }
                }
            } @else {
                p.ed-grid__mut { (tr(lang, "Waiting for a fresh roster from the Boosty dashboard.", "Ожидается свежий список подписчиков из панели Boosty.")) }
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
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 10px;" {
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
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 10px;" {
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
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 12px;" {
            (tr(lang, "Subscription label clients see: ", "Метка в подписке, которую видят клиенты: "))
            span.ed-mono { (effective) " VLESS ~<user>" }
            @if current.is_none() {
                (tr(lang, " — auto (no custom name set)", " — авто (своё имя не задано)"))
            }
        }
        form method="post"
             action=(format!("/admin/servers/{sid_enc}/display-name"))
             style="display: flex; gap: 8px; align-items: center;" {
            input type="text" name="display_name" maxlength="64"
                  value=(current.unwrap_or(""))
                  placeholder=(tr(lang, "e.g. Kyrgyzstan  (blank = auto)", "напр. Kyrgyzstan  (пусто = авто)"))
                  style="flex: 1; padding: 4px 8px; font-family: var(--mono); font-size: 12px; border: 1px solid var(--rule);";
            button type="submit"
                   title=(tr(
                       lang,
                       "Save this server's display label. Takes effect on the next subscription pull by each client; cached URIs are unaffected.",
                       "Сохранить отображаемую метку этого сервера. Применится при следующем обновлении подписки у каждого клиента; на кэшированные URI не влияет.",
                   ))
                   style="padding: 4px 12px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                (icon("save")) (tr(lang, "save name", "сохранить"))
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
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 12px;" {
                (tr(lang, "No billing terms configured for this server yet. Set due date and pricing below.", "Параметры оплаты для этого сервера ещё не заданы. Укажи дату и стоимость ниже."))
            }
        }

        form method="post"
             action=(format!("/admin/servers/{sid_enc}/billing"))
             style="margin: 14px 0 4px; max-width: 1080px; display: flex; flex-direction: column; gap: 12px; font-family: var(--mono); font-size: 11px;" {
            input type="hidden" name="return_to" value=(return_to) {}

            div style="display: flex; flex-wrap: wrap; gap: 12px; align-items: flex-end;" {
                div style="flex: 0 0 140px;" {
                    label style="display: block; color: var(--mute); margin-bottom: 4px; font-size: 10px; text-transform: uppercase; letter-spacing: 0.05em;" {
                        (tr(lang, "Due date", "Дата оплаты"))
                    }
                    input type="date" name="due_date" required
                           value=(current.map(|b| b.due_date.as_str()).unwrap_or(""))
                           style="width: 100%; box-sizing: border-box; height: 32px; padding: 5px 8px; border: 1px solid var(--rule); background: var(--paper); color: var(--ink);" {}
                }

                div style="flex: 0 0 130px;" {
                    label style="display: block; color: var(--mute); margin-bottom: 4px; font-size: 10px; text-transform: uppercase; letter-spacing: 0.05em;" {
                        (tr(lang, "Billing cycle", "Период"))
                    }
                    select name="billing_cycle" style="width: 100%; box-sizing: border-box; height: 32px; padding: 5px 8px; border: 1px solid var(--rule); background: var(--paper); color: var(--ink);" {
                        @let cur_c = current.map(|b| b.billing_cycle).unwrap_or(BillingCycle::Monthly);
                        option value="monthly" selected[cur_c == BillingCycle::Monthly] { (tr(lang, "Monthly", "1 месяц")) }
                        option value="quarterly" selected[cur_c == BillingCycle::Quarterly] { (tr(lang, "Quarterly (3 mo)", "3 месяца")) }
                        option value="semi-annual" selected[cur_c == BillingCycle::SemiAnnual] { (tr(lang, "Semi-annual (6 mo)", "6 месяцев")) }
                        option value="annual" selected[cur_c == BillingCycle::Annual] { (tr(lang, "Annual (12 mo)", "1 год")) }
                    }
                }

                div style="flex: 0 0 95px;" {
                    label style="display: block; color: var(--mute); margin-bottom: 4px; font-size: 10px; text-transform: uppercase; letter-spacing: 0.05em;" {
                        (tr(lang, "Amount", "Стоимость"))
                    }
                    input type="text" name="amount" placeholder="0.00"
                           value=(current.map(|b| format!("{:.2}", b.amount_cents as f64 / 100.0)).unwrap_or_default())
                           style="width: 100%; box-sizing: border-box; height: 32px; padding: 5px 8px; border: 1px solid var(--rule); background: var(--paper); color: var(--ink); text-align: right;" {}
                }

                div style="flex: 0 0 80px;" {
                    label style="display: block; color: var(--mute); margin-bottom: 4px; font-size: 10px; text-transform: uppercase; letter-spacing: 0.05em;" {
                        (tr(lang, "Currency", "Валюта"))
                    }
                    input list="currency_list" name="currency" maxlength="8"
                           value=(current.map(|b| b.currency.as_str()).unwrap_or("EUR"))
                           style="width: 100%; box-sizing: border-box; height: 32px; padding: 5px 8px; border: 1px solid var(--rule); background: var(--paper); color: var(--ink); text-transform: uppercase; text-align: center;" {}
                }

                div style="flex: 0 0 110px;" {
                    label style="display: block; color: var(--mute); margin-bottom: 4px; font-size: 10px; text-transform: uppercase; letter-spacing: 0.05em;"
                          title=(tr(lang, "Past cycles already paid (history record)", "Сколько циклов было оплачено ранее (запись в историю)")) {
                        (tr(lang, "Past paid", "Оплачено ранее"))
                    }
                    input type="number" min="0" max="120" name="initial_payments_count" placeholder="0"
                           style="width: 100%; box-sizing: border-box; height: 32px; padding: 5px 8px; border: 1px solid var(--rule); background: var(--paper); color: var(--ink); text-align: right;" {}
                }

                div style="margin-left: auto; padding-bottom: 6px;" {
                    label style="display: inline-flex; align-items: center; gap: 6px; cursor: pointer; color: var(--ink); font-size: 11px;" {
                        @let auto = current.map(|b| b.auto_renew).unwrap_or(false);
                        input type="checkbox" name="auto_renew" value="1" checked[auto] {}
                        (tr(lang, "Auto-renewal (card charge)", "Автосписание с карты"))
                    }
                }
            }

            div style="display: flex; flex-wrap: wrap; gap: 12px; align-items: flex-end;" {
                div style="flex: 1.2 1 240px;" {
                    label style="display: block; color: var(--mute); margin-bottom: 4px; font-size: 10px; text-transform: uppercase; letter-spacing: 0.05em;" {
                        (tr(lang, "Hoster portal URL", "Ссылка на кабинет хостера"))
                    }
                    input type="url" name="billing_url" placeholder="https://..."
                           value=(current.and_then(|b| b.billing_url.as_deref()).unwrap_or(""))
                           style="width: 100%; box-sizing: border-box; height: 32px; padding: 5px 8px; border: 1px solid var(--rule); background: var(--paper); color: var(--ink);" {}
                }

                div style="flex: 1 1 200px;" {
                    label style="display: block; color: var(--mute); margin-bottom: 4px; font-size: 10px; text-transform: uppercase; letter-spacing: 0.05em;" {
                        (tr(lang, "Notes / contract", "Заметки / договор"))
                    }
                    input type="text" name="notes" placeholder=(tr(lang, "Account, card, contract...", "Аккаунт, карта, заметка..."))
                           value=(current.and_then(|b| b.notes.as_deref()).unwrap_or(""))
                           style="width: 100%; box-sizing: border-box; height: 32px; padding: 5px 8px; border: 1px solid var(--rule); background: var(--paper); color: var(--ink);" {}
                }

                div style="flex: 0 0 auto;" {
                    button type="submit" class="ed-abtn ed-abtn--primary"
                           style="height: 32px; padding: 0 16px; display: inline-flex; align-items: center; gap: 6px; box-sizing: border-box;" {
                        (icon("check")) " " (tr(lang, "Save parameters", "Сохранить"))
                    }
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
    let (btn_bg, btn_fg) = if opt_in {
        ("transparent", "var(--ink)")
    } else {
        ("var(--ink)", "var(--paper)")
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
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 12px;" {
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
            button type="submit"
                   style=(format!("padding: 4px 12px; border: 1px solid var(--ink); background: {btn_bg}; color: {btn_fg}; font-family: var(--mono); font-size: 11px; cursor: pointer;")) {
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
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            (tr(
                lang,
                "Ports the daemon refuses to bind on this node. The sing-box pre-apply guard fails closed when any rendered inbound collides — so a co-tenant 3x-ui (or any other service vpnctl doesn't manage) can never get overwritten by a forgetful deploy.",
                "Порты, которые демон отказывается занимать на этой ноде. Пре-apply-guard sing-box падает fail-closed, если любой рендеренный inbound пересечётся — сторонний 3x-ui (или любой другой сервис, которым vpnctl не управляет) никогда не будет перезаписан забывчивым деплоем.",
            ))
        }
        div style="font-family: var(--mono); font-size: 12px; padding: 8px 12px; background: var(--paper-tint); border: 1px solid var(--rule); margin-bottom: 12px;" {
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
        form method="post"
             action=(format!("/admin/servers/{sid_enc}/reserved-ports"))
             style="display: flex; gap: 8px; align-items: center;" {
            input type="text" name="ports" value=(prefill)
                  placeholder="443,2053,2096"
                  style="flex: 1; padding: 4px 8px; font-family: var(--mono); font-size: 12px; border: 1px solid var(--rule);"
                  pattern="[0-9, ]*"
                  title=(tr(
                      lang,
                      "Comma-separated port numbers (1..=65535). Empty value clears the list.",
                      "Номера портов через запятую (1..=65535). Пустое поле очищает список.",
                  ));
            button type="submit"
                   title=(tr(
                       lang,
                       "Replace the reserved-ports list with the values above. Future sing-box deploys refuse to bind any port in the list.",
                       "Заменить список зарезервированных портов значениями выше. Будущие деплои sing-box откажутся занимать любой порт из списка.",
                   ))
                   style="padding: 6px 14px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                (icon("save")) (tr(lang, "save", "сохранить"))
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
        p { (state) }
        form method="post" action=(format!("/admin/servers/{sid}/dnstt-config")) {
            label { (tr(lang,"Delegated DNS zone","Делегированная DNS-зона")) " "
                input.ed-field type="text" name="domain" value=(domain) maxlength="100" required;
            }
            label { (tr(lang,"UDP DNS resolver IPv4","IPv4 DNS-резолвера по UDP")) " "
                input.ed-field type="text" name="resolver" value=(resolver) maxlength="15" required;
            }
            button.ed-abtn type="submit" { (tr(lang,"Save DNSTT settings","Сохранить настройки DNSTT")) }
        }
    }
}
