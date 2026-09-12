use crate::handlers::admin::icons::icon;
use crate::handlers::vpn_router::server_display_label;
use crate::http_util::path_segment_encode;
use maud::{Markup, html};
use std::collections::HashMap;

/// Naive (Caddy + forwardproxy) per-server config. The operator sets
/// `naive.domain` + `naive.acme_email` (server_secrets) that the caddy
/// kernel renders into the Caddyfile and Caddy's built-in ACME uses to
/// mint the Let's Encrypt cert. Rendered ONLY when the `naive` protocol
/// is enabled on this server (empty markup otherwise). Carries the
/// prerequisite reminder vpnctl CANNOT satisfy for the operator: a DNS
/// A-record pointing here + open TCP 80/443.
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

/// vless-ws (Caddy + reverse_proxy) per-server config. The operator sets
/// `vlessws.domain` + `vlessws.acme_email` + `vlessws.listen_port`
/// (server_secrets); the secret ws path (`vlessws.path`) is auto-minted at
/// deploy, so there's no field for it. Rendered ONLY when the `vless-ws`
/// protocol is enabled on this server. Carries the prerequisite reminder
/// vpnctl CANNOT satisfy: a DNS A-record pointing here + open TCP 80 (ACME)
/// and the front port.
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
    // Whether the secret ws path has been minted yet (deploy mints it).
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
                  placeholder="de.ninitux.top"
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

/// VLESS+REALITY per-server listen port (`vless.listen_port`). Default 443
/// is the gold-standard cover; on a co-tenant host where something else
/// owns 443 (naive/caddy here, legacy 3x-ui elsewhere) the operator moves
/// reality to an alt port. Rendered ONLY when `vless+reality` is enabled.
/// The value is load-bearing for the firewall step, the port-conflict guard
/// and the drift table above (`effective_listen_ports`), so it gets the
/// same web surface as `vlessws.listen_port` — "web is the ONLY operator
/// surface" (PR #139 review finding 7).
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
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow
            title=(tr(lang,
                "REALITY binds this port directly. Default 443 (gold-standard HTTPS cover); set an alternate port when a co-tenant owns 443 on this host (naive/caddy, legacy 3x-ui). Saving re-validates against every other protocol's port and takes effect on deploy.",
                "REALITY слушает этот порт напрямую. По умолчанию 443 (золотой стандарт HTTPS-маскировки); задай другой порт, если 443 на этом хосте занят со-жителем (naive/caddy, легаси 3x-ui). При сохранении проверяется против портов всех остальных протоколов и вступает в силу при деплое.")) {
            (tr(lang, "VLESS+REALITY CONFIG", "КОНФИГ VLESS+REALITY"))
        }
        form method="post"
             action=(format!("/admin/servers/{sid_enc}/reality-config"))
             style="display: grid; grid-template-columns: 96px 1fr; gap: 6px 8px; align-items: center; max-width: 520px;" {
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
                   title=(tr(lang, "Save the REALITY listen port", "Сохранить порт REALITY"))
                   style="justify-self: start; padding: 4px 12px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                (icon("save")) (tr(lang, "save reality port", "сохранить порт"))
            }
        }
    }
}

/// Display-name section on the server-detail page (migration 0029).
/// `current` is the operator-set `servers.display_name` (None = unset).
/// Lets the operator pin the friendly `{Country}` label end users see in
/// their client's server list — blank clears it back to the built-in
/// ISO-code→country map, then the uppercased id. Web equivalent of an
/// otherwise-unsettable field (there's no CLI for it yet).
pub(crate) fn server_detail_display_name_section(
    server: &vpnctl_core::Server,
    current: Option<&str>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let sid_enc = path_segment_encode(&server.id.0);
    // What the label resolves to RIGHT NOW (custom → country-map → UPPER),
    // so the operator sees the effective value, not just the override.
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

/// Server billing section on the server-detail page (migration 0057).
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
             style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 10px; font-family: var(--mono); font-size: 11px; margin-top: 8px;" {
            input type="hidden" name="return_to" value=(return_to) {}

            div {
                label style="display: block; color: var(--mute); margin-bottom: 2px;" {
                    (tr(lang, "Due date", "Дата оплаты"))
                }
                input type="date" name="due_date" required
                       value=(current.map(|b| b.due_date.as_str()).unwrap_or(""))
                       style="width: 100%; padding: 4px 6px; border: 1px solid var(--rule); background: var(--paper); color: var(--ink);" {}
            }

            div {
                label style="display: block; color: var(--mute); margin-bottom: 2px;" {
                    (tr(lang, "Cycle", "Период"))
                }
                select name="billing_cycle" style="width: 100%; padding: 4px 6px; border: 1px solid var(--rule); background: var(--paper); color: var(--ink);" {
                    @let cur_c = current.map(|b| b.billing_cycle).unwrap_or(BillingCycle::Monthly);
                    option value="monthly" selected[cur_c == BillingCycle::Monthly] { (tr(lang, "Monthly", "1 месяц")) }
                    option value="quarterly" selected[cur_c == BillingCycle::Quarterly] { (tr(lang, "Quarterly (3 mo)", "3 месяца")) }
                    option value="semi-annual" selected[cur_c == BillingCycle::SemiAnnual] { (tr(lang, "Semi-annual (6 mo)", "6 месяцев")) }
                    option value="annual" selected[cur_c == BillingCycle::Annual] { (tr(lang, "Annual (12 mo)", "1 год")) }
                }
            }

            div {
                label style="display: block; color: var(--mute); margin-bottom: 2px;" {
                    (tr(lang, "Amount", "Сумма"))
                }
                input type="text" name="amount" placeholder="0.00"
                       value=(current.map(|b| format!("{:.2}", b.amount_cents as f64 / 100.0)).unwrap_or_default())
                       style="width: 100%; padding: 4px 6px; border: 1px solid var(--rule); background: var(--paper); color: var(--ink);" {}
            }

            div {
                label style="display: block; color: var(--mute); margin-bottom: 2px;" {
                    (tr(lang, "Currency", "Валюта"))
                }
                select name="currency" style="width: 100%; padding: 4px 6px; border: 1px solid var(--rule); background: var(--paper); color: var(--ink);" {
                    @let cur_curr = current.map(|b| b.currency.as_str()).unwrap_or("EUR");
                    option value="EUR" selected[cur_curr == "EUR"] { "EUR (€)" }
                    option value="USD" selected[cur_curr == "USD"] { "USD ($)" }
                    option value="RUB" selected[cur_curr == "RUB"] { "RUB (₽)" }
                    option value="CHF" selected[cur_curr == "CHF"] { "CHF" }
                }
            }

            div {
                label style="display: block; color: var(--mute); margin-bottom: 2px;" {
                    (tr(lang, "Billing portal URL", "Ссылка на биллинг"))
                }
                input type="url" name="billing_url" placeholder="https://..."
                       value=(current.and_then(|b| b.billing_url.as_deref()).unwrap_or(""))
                       style="width: 100%; padding: 4px 6px; border: 1px solid var(--rule); background: var(--paper); color: var(--ink);" {}
            }

            div {
                label style="display: block; color: var(--mute); margin-bottom: 2px;" {
                    (tr(lang, "Notes / contract", "Заметки / договор"))
                }
                input type="text" name="notes" placeholder=(tr(lang, "Card, account, contract...", "Карта, аккаунт, договор..."))
                       value=(current.and_then(|b| b.notes.as_deref()).unwrap_or(""))
                       style="width: 100%; padding: 4px 6px; border: 1px solid var(--rule); background: var(--paper); color: var(--ink);" {}
            }

            div style="grid-column: 1 / -1; display: flex; align-items: center; justify-content: space-between; margin-top: 4px;" {
                label style="display: inline-flex; align-items: center; gap: 6px; cursor: pointer;" {
                    @let auto = current.map(|b| b.auto_renew).unwrap_or(false);
                    input type="checkbox" name="auto_renew" value="1" checked[auto] {}
                    (tr(lang, "Auto-renew enabled", "Включено автопродление"))
                }

                button type="submit"
                       style="padding: 4px 12px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                    (icon("save")) (tr(lang, "save billing", "сохранить биллинг"))
                }
            }
        }
    }
}

/// Auto-suppress section on the server-detail page (migration 0030).
/// Per-server opt-in to drop this server from the subscription render
/// while it's unreachable: the health monitor sets `suppressed_at` once
/// it crosses the `server.unreachable` threshold (≈30 min of failed
/// probes), and clears it on the first successful probe. Separate from
/// the manual hide (NM-10) so a suppress cycle preserves the operator's
/// per-protocol visibility. Shows the live state + a toggle.
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
                "When ON, the daemon removes this server from clients' subscriptions after it fails the unreachable threshold (3 consecutive SSH probes ≈ 30 min) and restores it on the first successful probe. OFF (default) = a down server stays in the subscription and clients fall back on their own.",
                "Когда ВКЛ, демон убирает этот сервер из подписок клиентов после порога недоступности (3 неудачные SSH-пробы подряд ≈ 30 мин) и возвращает при первой успешной пробе. ВЫКЛ (по умолчанию) = упавший сервер остаётся в подписке, клиенты фолбэкаются сами.",
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
                    (tr(lang, "Armed — server is currently reachable; will auto-hide if it goes down.", "Взведено — сервер сейчас доступен; авто-скроется если упадёт."))
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

/// naive↔HY2 UDP-pairing opt-in on the server-detail page (migration 0031,
/// UX-3). Takes effect only when this server exposes BOTH naive and
/// hysteria2 — the render then stamps both share-links with `pair=<server
/// id>`. Always rendered (discoverable); the copy explains the both-protocols
/// requirement. Single-server only by construction (the tag is the id).
pub(crate) fn server_detail_udp_pair_section(
    server: &vpnctl_core::Server,
    enabled: bool,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let sid_enc = path_segment_encode(&server.id.0);
    let (btn_bg, btn_fg) = if enabled {
        ("transparent", "var(--ink)")
    } else {
        ("var(--ink)", "var(--paper)")
    };
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow
            title=(tr(
                lang,
                "When ON, this node's naive AND HY2 share-links carry a shared `pair=<server id>` tag, so a client routes UDP — which naive can't carry — over the HY2 co-located on the same node. Effective only if this server has BOTH naive and HY2 enabled. Pairing is single-server only (the tag is this server's id). OFF (default) = no pair tag.",
                "Когда ВКЛ, naive- и HY2-ссылки этого узла получают общий тег `pair=<id сервера>`, чтобы клиент гнал UDP (который naive не умеет) через HY2 на том же узле. Действует только если на сервере включены И naive, И HY2. Пара — строго в рамках одного сервера (тег = id этого сервера). ВЫКЛ (по умолчанию) = без тега pair.",
            )) {
            (tr(lang, "UDP PAIRING (NAIVE ↔ HY2)", "UDP-ПАРА (NAIVE ↔ HY2)"))
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 12px;" {
            @if enabled {
                (tr(lang, "On — naive & HY2 on this node share a `pair` tag (a client routes UDP over the co-located HY2). No effect unless both run here.", "Вкл — naive и HY2 этого узла имеют общий тег `pair` (клиент гонит UDP через парный HY2). Без эффекта, если оба не подняты здесь."))
            } @else {
                (tr(lang, "Off — no pairing tag. Turn on for a node that runs BOTH naive and HY2.", "Выкл — без тега pair. Включи для узла, где есть И naive, И HY2."))
            }
        }
        form method="post"
             action=(format!("/admin/servers/{sid_enc}/udp-pair"))
             style="display: inline;" {
            input type="hidden" name="enabled" value=(if enabled { "false" } else { "true" });
            button type="submit"
                   style=(format!("padding: 4px 12px; border: 1px solid var(--ink); background: {btn_bg}; color: {btn_fg}; font-family: var(--mono); font-size: 11px; cursor: pointer;")) {
                @if enabled {
                    (icon("unlink")) (tr(lang, "turn off pairing", "выключить пару"))
                } @else {
                    (icon("link")) (tr(lang, "turn on pairing", "включить пару"))
                }
            }
        }
    }
}

/// Reserved-ports section on the server-detail page (migration 0028).
/// Renders ALWAYS (even when the list is empty) so the operator has
/// a discoverable place to add port pins for a newly-detected co-
/// tenant service without having to remember the CLI invocation. The
/// list semantics are: any port here will be REFUSED by the sing-
/// box pre-apply guard, fail-closed.
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
