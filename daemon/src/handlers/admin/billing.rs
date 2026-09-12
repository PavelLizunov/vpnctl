//! Server rental billing overview and payment tracking page.

use std::collections::BTreeMap;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use chrono::{NaiveDate, Utc};
use maud::{Markup, html};

use super::helpers::{internal_error, render_page, theme_accent_lang};
use crate::AppState;
use crate::handlers::admin::icons::icon;
use crate::http_util::path_segment_encode;
use vpnctl_inventory::{BillingCycle, ServerBillingItem};

pub(crate) async fn servers_billing(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Markup, Response> {
    let (theme, accent, lang) = theme_accent_lang(&headers);

    let items = state
        .inv
        .list_fleet_billing()
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;

    let today = Utc::now().date_naive();

    // Summary calculations
    let mut monthly_totals: BTreeMap<String, i64> = BTreeMap::new();
    let mut due_soon_count = 0usize;
    let mut overdue_count = 0usize;
    let mut configured_count = 0usize;
    let mut next_due: Option<(&ServerBillingItem, i64, NaiveDate)> = None;

    for item in &items {
        if let Some(ref b) = item.billing {
            configured_count += 1;
            let monthly_cents = match b.billing_cycle {
                BillingCycle::Monthly => b.amount_cents,
                BillingCycle::Quarterly => b.amount_cents / 3,
                BillingCycle::SemiAnnual => b.amount_cents / 6,
                BillingCycle::Annual => b.amount_cents / 12,
            };
            *monthly_totals.entry(b.currency.clone()).or_default() += monthly_cents;

            if let Ok(due) = vpnctl_inventory::validate_due_date(&b.due_date) {
                let days = (due - today).num_days();
                if days < 0 {
                    overdue_count += 1;
                } else if days <= 7 {
                    due_soon_count += 1;
                }

                if next_due.is_none()
                    || days < next_due.as_ref().map(|(_, d, _)| *d).unwrap_or(i64::MAX)
                {
                    next_due = Some((item, days, due));
                }
            }
        }
    }

    let body = html! {
        div.ed-art-eyebrow { (crate::i18n::t(lang, crate::i18n::K::PageServers)) }

        div.ed-tabs style="margin-bottom: 18px;" {
            a.ed-tab href="/admin/servers" {
                (crate::i18n::tr(lang, "All servers", "Все серверы"))
            }
            a.ed-tab.ed-tab--on href="/admin/servers/billing" {
                (crate::i18n::tr(lang, "Billing & Rental", "Оплата и аренда"))
            }
        }

        div.ed-headrow {
            h1.ed-sumbar__h {
                (crate::i18n::tr(lang, "Server rental & payment schedule", "График аренды и оплаты серверов"))
            }
            span.ed-tip title=(crate::i18n::tr(
                lang,
                "Due dates, recurring cycles and costs across all leased servers. Backed by the server_billing inventory table.",
                "Сроки следующей оплаты, периоды продления и стоимость по всем арендованным серверам. Читается напрямую из таблицы server_billing.",
            )) { (icon("info")) }
        }

        // Summary KPI Fact Grid
        div.ed-fact-grid style="margin: 14px 0 20px;" {
            // Card 1: Next due
            div.ed-fact {
                div style="font-family: var(--mono); font-size: 10px; color: var(--mute); letter-spacing: 0.08em; text-transform: uppercase;" {
                    (crate::i18n::tr(lang, "Next payment", "Ближайший платёж"))
                }
                div style="margin-top: 6px; font-family: var(--mono); font-size: 14px; font-weight: 600; color: var(--ink);" {
                    @match next_due {
                        Some((item, days, due)) => {
                            a href=(format!("/admin/servers/{}", path_segment_encode(&item.server_id.0))) style="color: var(--ink); text-decoration: underline;" {
                                (item.server_id.0)
                            }
                            @if let Some(ref b) = item.billing {
                                " · " (format_amount(b.amount_cents, &b.currency))
                            }
                            div style="margin-top: 4px; font-size: 11px; font-weight: 400;" {
                                (due.format("%d.%m.%Y").to_string()) " (" (format_days_badge(days, lang)) ")"
                            }
                        }
                        None => {
                            span style="color: var(--mute); font-style: italic; font-weight: 400;" {
                                (crate::i18n::tr(lang, "No dates configured", "Сроки не настроены"))
                            }
                        }
                    }
                }
            }

            // Card 2: Estimated monthly burn rate
            div.ed-fact {
                div style="font-family: var(--mono); font-size: 10px; color: var(--mute); letter-spacing: 0.08em; text-transform: uppercase;" {
                    (crate::i18n::tr(lang, "Monthly burn rate", "Расходы в месяц"))
                }
                div style="margin-top: 6px; font-family: var(--mono); font-size: 14px; font-weight: 600; color: var(--ink);" {
                    @if monthly_totals.is_empty() {
                        span style="color: var(--mute); font-style: italic; font-weight: 400;" {
                            "0.00 €"
                        }
                    } @else {
                        @let totals_str = monthly_totals
                            .iter()
                            .map(|(curr, cents)| format_amount(*cents, curr))
                            .collect::<Vec<_>>()
                            .join(" · ");
                        (totals_str)
                    }
                }
                div style="margin-top: 4px; font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                    (configured_count) " / " (items.len()) " " (crate::i18n::tr(lang, "servers configured", "серверов настроено"))
                }
            }

            // Card 3: Actionable attention
            div.ed-fact {
                div style="font-family: var(--mono); font-size: 10px; color: var(--mute); letter-spacing: 0.08em; text-transform: uppercase;" {
                    (crate::i18n::tr(lang, "Attention status", "Требуют внимания"))
                }
                div style="margin-top: 6px; font-family: var(--mono); font-size: 14px; font-weight: 600;" {
                    @if overdue_count > 0 {
                        span style="color: var(--red);" {
                            (icon("triangle-alert")) " "
                            (overdue_count) " " (crate::i18n::tr(lang, "overdue", "просрочено"))
                        }
                    } @else if due_soon_count > 0 {
                        span style="color: var(--warm);" {
                            (icon("clock")) " "
                            (due_soon_count) " " (crate::i18n::tr(lang, "due within 7 days", "к оплате до 7 дней"))
                        }
                    } @else {
                        span style="color: var(--green);" {
                            (icon("check")) " " (crate::i18n::tr(lang, "All payments on schedule", "Все платежи в графике"))
                        }
                    }
                }
                div style="margin-top: 4px; font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                    (crate::i18n::tr(lang, "overdue / due ≤ 7 days", "просрочено / срок ≤ 7 дней"))
                }
            }
        }

        // Table
        div.ed-grid-wrap {
            table.ed-grid {
                thead {
                    tr {
                        th style="width: 34px;" { "№" }
                        th { (crate::i18n::tr(lang, "server", "сервер")) }
                        th { (crate::i18n::tr(lang, "hoster", "хостер")) }
                        th { (crate::i18n::tr(lang, "next due", "срок оплаты")) }
                        th { (crate::i18n::tr(lang, "days left", "до оплаты")) }
                        th { (crate::i18n::tr(lang, "cycle & amount", "тариф и сумма")) }
                        th { (crate::i18n::tr(lang, "auto-renew", "автопродление")) }
                        th { (crate::i18n::tr(lang, "hoster console", "личный кабинет")) }
                        th { (crate::i18n::tr(lang, "notes", "заметки")) }
                        th style="text-align: right;" { (crate::i18n::tr(lang, "actions", "действия")) }
                    }
                }
                tbody {
                    @for (idx, item) in items.iter().enumerate() {
                        @let sid = &item.server_id.0;
                        @let sid_enc = path_segment_encode(sid);
                        @let label = item.display_name.as_deref().unwrap_or(sid);

                        tr {
                            td.ed-grid__mut { (format!("{:02}", idx + 1)) }
                            td {
                                a.ed-grid__id href=(format!("/admin/servers/{sid_enc}")) {
                                    b { (label) }
                                }
                                @if item.display_name.is_some() {
                                    span.ed-grid__mut.ed-grid__sm { " (" (sid) ")" }
                                }
                            }
                            td.ed-grid__sm { (item.hoster) }
                            @match item.billing {
                                Some(ref b) => {
                                    @let due_res = vpnctl_inventory::validate_due_date(&b.due_date);
                                    td.ed-grid__sm {
                                        @match due_res {
                                            Ok(d) => (d.format("%d.%m.%Y").to_string()),
                                            Err(_) => (b.due_date),
                                        }
                                    }
                                    td.ed-grid__sm {
                                        @match due_res {
                                            Ok(d) => (format_days_badge((d - today).num_days(), lang)),
                                            Err(_) => { span style="color: var(--warm);" { "invalid date" } },
                                        }
                                    }
                                    td.ed-grid__sm {
                                        b { (format_amount(b.amount_cents, &b.currency)) }
                                        " / "
                                        (cycle_label(b.billing_cycle, lang))
                                    }
                                    td.ed-grid__sm {
                                        @if b.auto_renew {
                                            span style="color: var(--green);" {
                                                (icon("check")) " " (crate::i18n::tr(lang, "Card / Auto", "Карта / Авто"))
                                            }
                                        } @else {
                                            span style="color: var(--mute);" {
                                                (crate::i18n::tr(lang, "Manual", "Вручную"))
                                            }
                                        }
                                    }
                                    td.ed-grid__sm {
                                        @match b.billing_url {
                                            Some(ref url) => {
                                                a.ed-abtn.ed-abtn--secondary.ed-abtn--sm href=(url) target="_blank" rel="noopener noreferrer" {
                                                    (crate::i18n::tr(lang, "Console ↗", "В кабинет ↗"))
                                                }
                                            }
                                            None => { span.ed-grid__mut { "—" } }
                                        }
                                    }
                                    td.ed-grid__sm title=(b.notes.as_deref().unwrap_or("")) {
                                        @match b.notes {
                                            Some(ref n) if !n.is_empty() => (truncate_str(n, 20)),
                                            _ => { span.ed-grid__mut { "—" } },
                                        }
                                    }
                                    td style="text-align: right; white-space: nowrap;" {
                                        form method="post" action=(format!("/admin/servers/{sid_enc}/billing/advance")) style="display: inline; margin: 0 4px 0 0;" {
                                            input type="hidden" name="return_to" value="/admin/servers/billing" {}
                                            button type="submit" class="ed-abtn ed-abtn--sm" title=(crate::i18n::tr(lang, "Mark paid and advance due date by 1 cycle", "Отметить оплату и сдвинуть дату на 1 цикл")) {
                                                (icon("check")) " " (crate::i18n::tr(lang, "+1 cycle", "+1 цикл"))
                                            }
                                        }
                                    }
                                }
                                None => {
                                    td.ed-grid__mut { "—" }
                                    td.ed-grid__mut { (crate::i18n::tr(lang, "unconfigured", "не настроено")) }
                                    td.ed-grid__mut { "—" }
                                    td.ed-grid__mut { "—" }
                                    td.ed-grid__mut { "—" }
                                    td.ed-grid__mut { "—" }
                                    td style="text-align: right;" {
                                        span.ed-grid__mut { (crate::i18n::tr(lang, "see edit form below", "см. форму ниже")) }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Section: Edit / configure server billing
        section style="margin-top: 32px; border-top: 1px solid var(--rule); padding-top: 20px;" {
            div.ed-art-eyebrow {
                (crate::i18n::tr(lang, "Configure server rental parameters", "Настройка параметров аренды сервера"))
            }

            p style="font-family: var(--serif); font-size: 13px; color: var(--mute); margin: 6px 0 16px;" {
                (crate::i18n::tr(
                    lang,
                    "Select a server to set or update its payment due date, cost, provider billing link, and renewal terms.",
                    "Выбери сервер, чтобы указать или обновить дату следующей оплаты, стоимость, ссылку на биллинг хостера и параметры продления.",
                ))
            }

            @for item in &items {
                @let sid = &item.server_id.0;
                @let sid_enc = path_segment_encode(sid);
                @let b_opt = item.billing.as_ref();

                details style="margin-bottom: 8px; border: 1px solid var(--rule); background: var(--paper-2); padding: 10px 14px;" {
                    summary style="cursor: pointer; font-family: var(--mono); font-size: 12px; font-weight: 600; color: var(--ink);" {
                        (sid)
                        @if let Some(ref d) = item.display_name {
                            " (" (d) ")"
                        }
                        " · " (item.hoster) " · "
                        @if let Some(b) = b_opt {
                            span style="color: var(--green); font-weight: 400;" {
                                (crate::i18n::tr(lang, "Configured", "Настроено"))
                                " (" (format_amount(b.amount_cents, &b.currency)) ")"
                            }
                        } @else {
                            span style="color: var(--warm); font-weight: 400;" {
                                (crate::i18n::tr(lang, "Not configured — click to add", "Не настроено — кликни для ввода"))
                            }
                        }
                    }

                    form method="post" action=(format!("/admin/servers/{sid_enc}/billing")) style="margin: 14px 0 4px; display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; font-family: var(--mono); font-size: 11px;" {
                        input type="hidden" name="return_to" value="/admin/servers/billing" {}

                        div {
                            label style="display: block; color: var(--mute); margin-bottom: 4px;" {
                                (crate::i18n::tr(lang, "Due date (YYYY-MM-DD)", "Дата оплаты (ГГГГ-ММ-ДД)"))
                            }
                            input type="date" name="due_date" required
                                   value=(b_opt.map(|b| b.due_date.as_str()).unwrap_or(""))
                                   style="width: 100%; padding: 6px 8px; border: 1px solid var(--rule); background: var(--paper); color: var(--ink);" {}
                        }

                        div {
                            label style="display: block; color: var(--mute); margin-bottom: 4px;" {
                                (crate::i18n::tr(lang, "Billing cycle", "Период оплаты"))
                            }
                            select name="billing_cycle" style="width: 100%; padding: 6px 8px; border: 1px solid var(--rule); background: var(--paper); color: var(--ink);" {
                                @let cur_cycle = b_opt.map(|b| b.billing_cycle).unwrap_or(BillingCycle::Monthly);
                                option value="monthly" selected[cur_cycle == BillingCycle::Monthly] { (crate::i18n::tr(lang, "Monthly", "1 месяц")) }
                                option value="quarterly" selected[cur_cycle == BillingCycle::Quarterly] { (crate::i18n::tr(lang, "Quarterly (3 mo)", "3 месяца")) }
                                option value="semi-annual" selected[cur_cycle == BillingCycle::SemiAnnual] { (crate::i18n::tr(lang, "Semi-annual (6 mo)", "6 месяцев")) }
                                option value="annual" selected[cur_cycle == BillingCycle::Annual] { (crate::i18n::tr(lang, "Annual (12 mo)", "1 год")) }
                            }
                        }

                        div {
                            label style="display: block; color: var(--mute); margin-bottom: 4px;" {
                                (crate::i18n::tr(lang, "Amount (e.g. 5.00)", "Стоимость (напр. 5.00)"))
                            }
                            input type="text" name="amount" placeholder="0.00"
                                   value=(b_opt.map(|b| format!("{:.2}", b.amount_cents as f64 / 100.0)).unwrap_or_default())
                                   style="width: 100%; padding: 6px 8px; border: 1px solid var(--rule); background: var(--paper); color: var(--ink);" {}
                        }

                        div {
                            label style="display: block; color: var(--mute); margin-bottom: 4px;" {
                                (crate::i18n::tr(lang, "Currency", "Валюта"))
                            }
                            select name="currency" style="width: 100%; padding: 6px 8px; border: 1px solid var(--rule); background: var(--paper); color: var(--ink);" {
                                @let cur_c = b_opt.map(|b| b.currency.as_str()).unwrap_or("EUR");
                                option value="EUR" selected[cur_c == "EUR"] { "EUR (€)" }
                                option value="USD" selected[cur_c == "USD"] { "USD ($)" }
                                option value="RUB" selected[cur_c == "RUB"] { "RUB (₽)" }
                                option value="CHF" selected[cur_c == "CHF"] { "CHF" }
                            }
                        }

                        div {
                            label style="display: block; color: var(--mute); margin-bottom: 4px;" {
                                (crate::i18n::tr(lang, "Provider console URL", "Ссылка на биллинг хостера"))
                            }
                            input type="url" name="billing_url" placeholder="https://..."
                                   value=(b_opt.and_then(|b| b.billing_url.as_deref()).unwrap_or(""))
                                   style="width: 100%; padding: 6px 8px; border: 1px solid var(--rule); background: var(--paper); color: var(--ink);" {}
                        }

                        div {
                            label style="display: block; color: var(--mute); margin-bottom: 4px;" {
                                (crate::i18n::tr(lang, "Notes / contract", "Заметки / договор"))
                            }
                            input type="text" name="notes" placeholder=(crate::i18n::tr(lang, "Account, card, notes...", "Аккаунт, карта, заметка..."))
                                   value=(b_opt.and_then(|b| b.notes.as_deref()).unwrap_or(""))
                                   style="width: 100%; padding: 6px 8px; border: 1px solid var(--rule); background: var(--paper); color: var(--ink);" {}
                        }

                        div style="grid-column: 1 / -1; display: flex; align-items: center; justify-content: space-between; margin-top: 6px;" {
                            label style="display: inline-flex; align-items: center; gap: 8px; cursor: pointer;" {
                                @let auto = b_opt.map(|b| b.auto_renew).unwrap_or(false);
                                input type="checkbox" name="auto_renew" value="1" checked[auto] {}
                                (crate::i18n::tr(lang, "Auto-renewal enabled (card charge)", "Включено автопродление (списание с карты)"))
                            }

                            button type="submit" class="ed-abtn ed-abtn--primary" {
                                (icon("check")) " " (crate::i18n::tr(lang, "Save parameters", "Сохранить параметры"))
                            }
                        }
                    }
                }
            }
        }
    };

    Ok(render_page(&state, "servers", &theme, &accent, lang, body).await)
}

fn format_amount(cents: i64, currency: &str) -> String {
    let sym = match currency {
        "EUR" => "€",
        "USD" => "$",
        "RUB" => "₽",
        _ => currency,
    };
    format!("{:.2} {}", cents as f64 / 100.0, sym)
}

fn format_days_badge(days: i64, lang: crate::i18n::Locale) -> Markup {
    let text = match (days, lang) {
        (d, crate::i18n::Locale::Ru) if d < 0 => format!("просрочено на {} дн.", -d),
        (d, crate::i18n::Locale::En) if d < 0 => format!("overdue {}d", -d),
        (0, crate::i18n::Locale::Ru) => "оплата сегодня".to_string(),
        (0, crate::i18n::Locale::En) => "due today".to_string(),
        (d, crate::i18n::Locale::Ru) => format!("через {d} дн."),
        (d, crate::i18n::Locale::En) => format!("in {d}d"),
    };
    if days < 0 {
        html! {
            span style="color: var(--red); font-weight: 600;" { (text) }
        }
    } else if days == 0 {
        html! {
            span style="color: var(--red); font-weight: 600;" { (text) }
        }
    } else if days <= 3 {
        html! {
            span style="color: var(--warm); font-weight: 600;" { (text) }
        }
    } else if days <= 7 {
        html! {
            span style="color: var(--ink); font-weight: 600;" { (text) }
        }
    } else {
        html! {
            span style="color: var(--green);" { (text) }
        }
    }
}

fn cycle_label(cycle: BillingCycle, lang: crate::i18n::Locale) -> &'static str {
    match (cycle, lang) {
        (BillingCycle::Monthly, crate::i18n::Locale::Ru) => "мес",
        (BillingCycle::Monthly, crate::i18n::Locale::En) => "mo",
        (BillingCycle::Quarterly, crate::i18n::Locale::Ru) => "3 мес",
        (BillingCycle::Quarterly, crate::i18n::Locale::En) => "quarter",
        (BillingCycle::SemiAnnual, crate::i18n::Locale::Ru) => "6 мес",
        (BillingCycle::SemiAnnual, crate::i18n::Locale::En) => "6 mo",
        (BillingCycle::Annual, crate::i18n::Locale::Ru) => "год",
        (BillingCycle::Annual, crate::i18n::Locale::En) => "yr",
    }
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.chars().count() > max_len {
        format!("{}…", s.chars().take(max_len).collect::<String>())
    } else {
        s.to_string()
    }
}
