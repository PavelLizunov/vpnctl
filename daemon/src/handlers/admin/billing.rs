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

    let (items, settings, rates) = tokio::try_join!(
        state.inv.list_fleet_billing(),
        state.inv.get_currency_settings(),
        state.inv.list_currency_rates(),
    )
    .map_err(|e| internal_error(anyhow::Error::new(e)))?;

    let boosty_report_opt = state.inv.boosty_last_report().await.ok().flatten();

    let today = Utc::now().date_naive();
    let display_cur = &settings.display_currency;

    // Active markup multiplier
    let markup_bps = settings
        .markup_overrides
        .get(display_cur)
        .copied()
        .unwrap_or(settings.default_markup_bps);
    let markup_coeff_f64 = markup_bps as f64 / 10_000.0;

    // Collect per-server data
    let mut monthly_totals_raw: BTreeMap<String, i64> = BTreeMap::new();
    let mut due_soon_count = 0usize;
    let mut overdue_count = 0usize;
    let mut configured_count = 0usize;
    let mut next_due: Option<(&ServerBillingItem, i64, NaiveDate)> = None;

    let mut fleet_monthly_converted_minor: i64 = 0;
    let mut fleet_total_spend_converted_minor: i64 = 0;
    let mut total_payments_count: i64 = 0;

    struct ComputedServerItem<'a> {
        item: &'a ServerBillingItem,
        converted_monthly: Option<i64>,
        total_spend: i64,
        payment_count: i64,
    }

    let mut computed_items = Vec::with_capacity(items.len());

    for item in &items {
        let (spend, pcount) = state
            .inv
            .server_spend_and_count(&item.server_id, display_cur)
            .await
            .unwrap_or((0, 0));

        fleet_total_spend_converted_minor = fleet_total_spend_converted_minor.saturating_add(spend);
        total_payments_count = total_payments_count.saturating_add(pcount);

        let mut conv_monthly = None;

        if let Some(ref b) = item.billing {
            configured_count += 1;
            let monthly_cents =
                vpnctl_inventory::monthly_equivalent(b.amount_cents, b.billing_cycle);
            *monthly_totals_raw.entry(b.currency.clone()).or_default() += monthly_cents;

            if let Ok(Some(conv)) = state
                .inv
                .convert_amount(monthly_cents, &b.currency, display_cur)
                .await
            {
                fleet_monthly_converted_minor =
                    fleet_monthly_converted_minor.saturating_add(conv.amount_minor);
                conv_monthly = Some(conv.amount_minor);
            }

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

        computed_items.push(ComputedServerItem {
            item,
            converted_monthly: conv_monthly,
            total_spend: spend,
            payment_count: pcount,
        });
    }

    let fleet_annual_converted_minor = fleet_monthly_converted_minor.saturating_mul(12);

    let boosty_income = boosty_report_opt
        .and_then(|(json, _)| serde_json::from_str::<vpnctl_boosty_bridge::SyncReport>(&json).ok())
        .map(|r| r.income_summary());

    let mut boosty_mrr_converted_minor: Option<i64> = None;
    let mut boosty_total_revenue_converted_minor: Option<i64> = None;

    if let Some(inc) = boosty_income {
        if inc.mrr_rub_cents > 0 {
            if let Ok(Some(conv)) = state
                .inv
                .convert_amount_spot(inc.mrr_rub_cents, "RUB", display_cur)
                .await
            {
                boosty_mrr_converted_minor = Some(conv.amount_minor);
            }
        } else {
            boosty_mrr_converted_minor = Some(0);
        }

        if inc.total_revenue_rub_cents > 0 {
            if let Ok(Some(conv)) = state
                .inv
                .convert_amount_spot(inc.total_revenue_rub_cents, "RUB", display_cur)
                .await
            {
                boosty_total_revenue_converted_minor = Some(conv.amount_minor);
            }
        } else {
            boosty_total_revenue_converted_minor = Some(0);
        }
    }

    let net_monthly_margin_minor: Option<i64> =
        boosty_mrr_converted_minor.map(|mrr| mrr.saturating_sub(fleet_monthly_converted_minor));
    let coverage_ratio_f64: Option<f64> = boosty_mrr_converted_minor.and_then(|mrr| {
        if fleet_monthly_converted_minor > 0 {
            Some((mrr as f64) / (fleet_monthly_converted_minor as f64))
        } else {
            None
        }
    });

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
                "Due dates, recurring cycles, pricing and multi-currency exchange rates across all leased servers.",
                "Сроки следующей оплаты, периоды продления, стоимость и мультивалютный пересчёт по всем арендованным серверам.",
            )) { (icon("info")) }
        }

        // Currency Settings Toolbar
        div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; margin: 12px 0 16px; padding: 10px 14px; background: var(--paper-2); border: 1px solid var(--rule); font-family: var(--mono); font-size: 11px;" {
            form method="post" action="/admin/servers/billing/settings" style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin: 0;" {
                input type="hidden" name="return_to" value="/admin/servers/billing" {}

                span style="color: var(--mute); text-transform: uppercase; font-size: 10px; letter-spacing: 0.08em; font-weight: 600;" {
                    (crate::i18n::tr(lang, "Display currency:", "Валюта сводки:"))
                }
                select name="display_currency" style="padding: 3px 8px; border: 1px solid var(--rule); background: var(--paper); color: var(--ink); font-family: var(--mono); font-size: 11px;" {
                    @for code in ["RUB", "EUR", "USD", "CHF", "SEK", "GBP", "TRY", "KGS", "KZT"] {
                        option value=(code) selected[code == display_cur] {
                            (code) " (" (currency_symbol(code)) ")"
                        }
                    }
                }

                span style="color: var(--mute);" { "·" }

                span style="color: var(--mute); text-transform: uppercase; font-size: 10px; letter-spacing: 0.08em; font-weight: 600;" {
                    (crate::i18n::tr(lang, "Fee coefficient:", "Коэффициент наценки:"))
                }
                input type="number" step="0.01" min="1.00" max="2.00" name="markup_coeff" value=(format!("{:.2}", markup_coeff_f64))
                       style="width: 58px; padding: 3px 6px; border: 1px solid var(--rule); background: var(--paper); color: var(--ink); font-family: var(--mono); font-size: 11px; text-align: right;" {}

                @if markup_bps > 10000 {
                    span style="color: var(--warm); font-size: 10px;" title=(crate::i18n::tr(lang, "Accounts for intermediary bank/card fee", "Учитывает комиссию банка/посредника")) {
                        "(+" (format!("{:.1}", (markup_coeff_f64 - 1.0) * 100.0)) "%)"
                    }
                }

                button type="submit" class="ed-abtn ed-abtn--secondary ed-abtn--sm" {
                    (crate::i18n::tr(lang, "Apply", "Применить"))
                }
            }

            div style="display: flex; align-items: center; gap: 8px;" {
                form method="post" action="/admin/servers/billing/refresh-rates" style="margin: 0;" {
                    input type="hidden" name="return_to" value="/admin/servers/billing" {}
                    button type="submit" class="ed-abtn ed-abtn--secondary ed-abtn--sm" title=(crate::i18n::tr(lang, "Fetch live rates from public central bank APIs", "Загрузить свежие курсы из публичных API центробанков")) {
                        (icon("rotate-cw")) " " (crate::i18n::tr(lang, "Refresh rates", "Обновить курсы"))
                    }
                }
            }
        }

        // Rates banner indicator
        @if !rates.is_empty() {
            div style="font-family: var(--mono); font-size: 10px; color: var(--mute); margin: -10px 0 16px 4px;" {
                (crate::i18n::tr(lang, "Active rates (EUR base): ", "Действующие курсы (база EUR): "))
                @let rates_text = rates
                    .iter()
                    .filter(|r| ["USD", "RUB", "CHF", "SEK"].contains(&r.target_currency.as_str()))
                    .map(|r| format!("1 EUR = {:.2} {}", r.rate_micros as f64 / 1_000_000.0, r.target_currency))
                    .collect::<Vec<_>>()
                    .join(" · ");
                (rates_text)
            }
        }

        // Financial Overview & P&L (Boosty Income vs Server Fleet Expenses)
        @if let Some(inc) = boosty_income {
            div.ed-rule style="margin: 12px 0 16px;" {}
            div.ed-headrow {
                h2.ed-sumbar__h style="font-size: 15px;" {
                    (crate::i18n::tr(lang, "Financial Balance & P&L", "Финансовый баланс и окупаемость (P&L)"))
                }
                span.ed-tip title=(crate::i18n::tr(
                    lang,
                    "Net margin comparing monthly Boosty subscriber revenue against server fleet leasing costs in the display currency.",
                    "Сравнение регулярного дохода с подписок Boosty и расходов на аренду серверов в выбранной валюте сводки.",
                )) { (icon("info")) }
            }

            div.ed-fact-grid style="margin: 10px 0 20px; grid-template-columns: repeat(3, minmax(0, 1fr));" {
                // Card 1: Boosty Income (MRR & Total Revenue)
                div.ed-fact {
                    div style="font-family: var(--mono); font-size: 10px; color: var(--mute); letter-spacing: 0.08em; text-transform: uppercase;" {
                        (crate::i18n::tr(lang, "Boosty Income (MRR)", "Доход Boosty (MRR)"))
                    }
                    div style="margin-top: 6px; font-family: var(--mono); font-size: 14px; font-weight: 600; color: var(--ink);" {
                        @match boosty_mrr_converted_minor {
                            Some(mrr) => {
                                span style="color: var(--green);" { (format_amount(mrr, display_cur)) }
                                " "
                                span style="font-weight: 400; font-size: 11px; color: var(--mute);" {
                                    (crate::i18n::tr(lang, "/mo", "/мес"))
                                }
                            }
                            None => {
                                span style="color: var(--mute); font-style: italic; font-weight: 400;" {
                                    (crate::i18n::tr(lang, "No rate for RUB", "Нет курса к RUB"))
                                }
                            }
                        }
                    }
                    div style="margin-top: 4px; font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                        (inc.active_payers) " " (crate::i18n::tr(lang, "payers", "плательщиков"))
                        " · "
                        @if let Some(rev) = boosty_total_revenue_converted_minor {
                            (crate::i18n::tr(lang, "all-time: ", "история блога: ")) (format_amount(rev, display_cur))
                        } @else {
                            (crate::i18n::tr(lang, "all-time: ", "история блога: ")) (format!("{:.0} ₽", inc.total_revenue_rub_cents as f64 / 100.0))
                        }
                    }
                }

                // Card 2: Server Expenses (Monthly & Total Spend)
                div.ed-fact {
                    div style="font-family: var(--mono); font-size: 10px; color: var(--mute); letter-spacing: 0.08em; text-transform: uppercase;" {
                        (crate::i18n::tr(lang, "Server Expenses", "Расходы на серверы"))
                    }
                    div style="margin-top: 6px; font-family: var(--mono); font-size: 14px; font-weight: 600; color: var(--ink);" {
                        @if fleet_monthly_converted_minor > 0 {
                            (format_amount(fleet_monthly_converted_minor, display_cur))
                            " "
                            span style="font-weight: 400; font-size: 11px; color: var(--mute);" {
                                (crate::i18n::tr(lang, "/mo", "/мес"))
                            }
                        } @else {
                            span style="color: var(--mute); font-style: italic; font-weight: 400;" {
                                "0.00 " (currency_symbol(display_cur))
                            }
                        }
                    }
                    div style="margin-top: 4px; font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                        (configured_count) " " (crate::i18n::tr(lang, "servers", "серверов"))
                        " · "
                        (crate::i18n::tr(lang, "total spend: ", "всего расход: "))
                        (format_amount(fleet_total_spend_converted_minor, display_cur))
                    }
                }

                // Card 3: Net Margin / Monthly Run-rate
                div.ed-fact {
                    div style="font-family: var(--mono); font-size: 10px; color: var(--mute); letter-spacing: 0.08em; text-transform: uppercase;" {
                        (crate::i18n::tr(lang, "Net Margin (P&L)", "Чистая прибыль (P&L)"))
                    }
                    div style="margin-top: 6px; font-family: var(--mono); font-size: 14px; font-weight: 600;" {
                        @match net_monthly_margin_minor {
                            Some(net) if net > 0 => {
                                span style="color: var(--green);" {
                                    "+" (format_amount(net, display_cur))
                                }
                                " "
                                span style="font-weight: 400; font-size: 11px; color: var(--mute);" {
                                    (crate::i18n::tr(lang, "/mo", "/мес"))
                                }
                            }
                            Some(net) if net < 0 => {
                                span style="color: var(--warm);" {
                                    "-" (format_amount(net.saturating_abs(), display_cur))
                                }
                                " "
                                span style="font-weight: 400; font-size: 11px; color: var(--mute);" {
                                    (crate::i18n::tr(lang, "/mo", "/мес"))
                                }
                            }
                            Some(_) => {
                                span style="color: var(--ink);" {
                                    (format_amount(0, display_cur))
                                }
                                " "
                                span style="font-weight: 400; font-size: 11px; color: var(--mute);" {
                                    (crate::i18n::tr(lang, "/mo (breakeven)", "/мес (в ноль)"))
                                }
                            }
                            None => {
                                span style="color: var(--mute); font-style: italic; font-weight: 400;" {
                                    (crate::i18n::tr(lang, "No rate for RUB", "Нет курса к RUB"))
                                }
                            }
                        }
                    }
                    div style="margin-top: 4px; font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                        @match coverage_ratio_f64 {
                            Some(ratio) if ratio >= 1.0 => {
                                (format!("{}: {:.0}% ({:.1}×)",
                                    crate::i18n::tr(lang, "cost coverage", "покрытие расходов"),
                                    ratio * 100.0,
                                    ratio
                                ))
                            }
                            Some(ratio) if ratio > 0.0 => {
                                @let cov = (ratio * 100.0).floor();
                                @let def = (100.0 - cov).max(1.0);
                                (format!("{}: {:.0}% ({}: {:.0}%)",
                                    crate::i18n::tr(lang, "cost coverage", "покрытие расходов"),
                                    cov,
                                    crate::i18n::tr(lang, "deficit", "дефицит"),
                                    def
                                ))
                            }
                            Some(_) => {
                                (crate::i18n::tr(lang, "cost coverage: 0%", "покрытие расходов: 0%"))
                            }
                            None => {
                                @if fleet_monthly_converted_minor == 0 {
                                    (crate::i18n::tr(lang, "zero server expenses", "серверы не тарифицированы"))
                                } @else {
                                    (crate::i18n::tr(lang, "awaiting exchange rate", "ожидает курса валюты"))
                                }
                            }
                        }
                    }
                }
            }
        } @else {
            div style="font-family: var(--mono); font-size: 11px; color: var(--mute); margin: 0 0 16px 4px;" {
                (crate::i18n::tr(lang, "Tip: Connect Boosty on ", "Подсказка: Подключите Boosty на "))
                a href="/admin/boosty" style="color: var(--ink); text-decoration: underline;" { "/admin/boosty" }
                (crate::i18n::tr(lang, " to see income and P&L net margin here.", " для отображения доходов и чистой прибыли."))
            }
        }

        div.ed-rule style="margin: 12px 0 16px;" {}

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

            // Card 2: Estimated monthly / annual budget in display currency
            div.ed-fact {
                div style="font-family: var(--mono); font-size: 10px; color: var(--mute); letter-spacing: 0.08em; text-transform: uppercase;" {
                    (crate::i18n::tr(lang, "Budget (Month / Year)", "Бюджет (месяц / год)"))
                    @if markup_bps > 10000 {
                        " · " (format!("×{:.2}", markup_coeff_f64))
                    }
                }
                div style="margin-top: 6px; font-family: var(--mono); font-size: 14px; font-weight: 600; color: var(--ink);" {
                    @if fleet_monthly_converted_minor > 0 {
                        (format_amount(fleet_monthly_converted_minor, display_cur))
                        " "
                        span style="font-weight: 400; font-size: 11px; color: var(--mute);" {
                            (crate::i18n::tr(lang, "/mo · ", "/мес · "))
                        }
                        (format_amount(fleet_annual_converted_minor, display_cur))
                        " "
                        span style="font-weight: 400; font-size: 11px; color: var(--mute);" {
                            (crate::i18n::tr(lang, "/yr", "/год"))
                        }
                    } @else if !monthly_totals_raw.is_empty() {
                        @let totals_str = monthly_totals_raw
                            .iter()
                            .map(|(curr, cents)| format_amount(*cents, curr))
                            .collect::<Vec<_>>()
                            .join(" · ");
                        (totals_str)
                    } @else {
                        span style="color: var(--mute); font-style: italic; font-weight: 400;" {
                            "0.00 " (currency_symbol(display_cur))
                        }
                    }
                }
                div style="margin-top: 4px; font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                    @if !monthly_totals_raw.is_empty() {
                        (crate::i18n::tr(lang, "raw: ", "исходно: "))
                        @let raw_list = monthly_totals_raw
                            .iter()
                            .map(|(c, a)| format_amount(*a, c))
                            .collect::<Vec<_>>()
                            .join(" + ");
                        (raw_list)
                    } @else {
                        (configured_count) " / " (items.len()) " " (crate::i18n::tr(lang, "servers configured", "серверов настроено"))
                    }
                }
            }

            // Card 3: Total spend to date (cumulative historical payments)
            div.ed-fact {
                div style="font-family: var(--mono); font-size: 10px; color: var(--mute); letter-spacing: 0.08em; text-transform: uppercase;" {
                    (crate::i18n::tr(lang, "Total Spend (To Date)", "Всего выплачено (Total Spend)"))
                }
                div style="margin-top: 6px; font-family: var(--mono); font-size: 14px; font-weight: 600; color: var(--ink);" {
                    @if fleet_total_spend_converted_minor > 0 {
                        (format_amount(fleet_total_spend_converted_minor, display_cur))
                    } @else {
                        span style="color: var(--mute); font-style: italic; font-weight: 400;" {
                            "0.00 " (currency_symbol(display_cur))
                        }
                    }
                }
                div style="margin-top: 4px; font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                    @if total_payments_count > 0 {
                        (total_payments_count) " " (crate::i18n::tr(lang, "recorded payments", "зафиксированных платежей"))
                    } @else {
                        (crate::i18n::tr(lang, "via +1 cycle or edit form", "через +1 цикл или форму"))
                    }
                }
            }

            // Card 4: Actionable attention
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
                        th { (crate::i18n::tr(lang, "in display currency", "в валюте сводки")) }
                        th { (crate::i18n::tr(lang, "total spend", "всего оплачено")) }
                        th { (crate::i18n::tr(lang, "auto-renew", "автопродление")) }
                        th { (crate::i18n::tr(lang, "hoster console", "личный кабинет")) }
                        th { (crate::i18n::tr(lang, "notes", "заметки")) }
                        th style="text-align: right;" { (crate::i18n::tr(lang, "actions", "действия")) }
                    }
                }
                tbody {
                    @for (idx, comp) in computed_items.iter().enumerate() {
                        @let item = comp.item;
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
                                        @match comp.converted_monthly {
                                            Some(conv_m) => {
                                                b { (format_amount(conv_m, display_cur)) }
                                                " " (crate::i18n::tr(lang, "/mo", "/мес"))
                                            }
                                            None => { span.ed-grid__mut { "—" } }
                                        }
                                    }
                                    td.ed-grid__sm {
                                        @if comp.total_spend > 0 {
                                            b { (format_amount(comp.total_spend, display_cur)) }
                                            " "
                                            span.ed-grid__mut.ed-grid__sm {
                                                "(" (comp.payment_count) ")"
                                            }
                                        } @else {
                                            span.ed-grid__mut { "0 " (currency_symbol(display_cur)) }
                                        }
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

            datalist id="currency_list" {
                option value="EUR" { "EUR (€)" }
                option value="USD" { "USD ($)" }
                option value="RUB" { "RUB (₽)" }
                option value="CHF" { "CHF" }
                option value="SEK" { "SEK (kr)" }
                option value="GBP" { "GBP (£)" }
                option value="TRY" { "TRY (₺)" }
                option value="KGS" { "KGS (сом)" }
                option value="KZT" { "KZT (₸)" }
            }

            @for comp in &computed_items {
                @let item = comp.item;
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
                            @if comp.total_spend > 0 {
                                span style="color: var(--mute); font-weight: 400; margin-left: 8px;" {
                                    "· " (crate::i18n::tr(lang, "Total spend: ", "Всего оплачено: "))
                                    (format_amount(comp.total_spend, display_cur))
                                }
                            }
                        } @else {
                            span style="color: var(--warm); font-weight: 400;" {
                                (crate::i18n::tr(lang, "Not configured — click to add", "Не настроено — кликни для ввода"))
                            }
                        }
                    }

                    form method="post" action=(format!("/admin/servers/{sid_enc}/billing"))
                         style="margin: 14px 0 4px; max-width: 1080px; display: flex; flex-direction: column; gap: 12px; font-family: var(--mono); font-size: 11px;" {
                        input type="hidden" name="return_to" value="/admin/servers/billing" {}

                        div style="display: flex; flex-wrap: wrap; gap: 12px; align-items: flex-end;" {
                            div style="flex: 0 0 140px;" {
                                label style="display: block; color: var(--mute); margin-bottom: 4px; font-size: 10px; text-transform: uppercase; letter-spacing: 0.05em;" {
                                    (crate::i18n::tr(lang, "Due date", "Дата оплаты"))
                                }
                                input type="date" name="due_date" required
                                       value=(b_opt.map(|b| b.due_date.as_str()).unwrap_or(""))
                                       style="width: 100%; box-sizing: border-box; height: 32px; padding: 5px 8px; border: 1px solid var(--rule); background: var(--paper); color: var(--ink);" {}
                            }

                            div style="flex: 0 0 130px;" {
                                label style="display: block; color: var(--mute); margin-bottom: 4px; font-size: 10px; text-transform: uppercase; letter-spacing: 0.05em;" {
                                    (crate::i18n::tr(lang, "Billing cycle", "Период"))
                                }
                                select name="billing_cycle" style="width: 100%; box-sizing: border-box; height: 32px; padding: 5px 8px; border: 1px solid var(--rule); background: var(--paper); color: var(--ink);" {
                                    @let cur_cycle = b_opt.map(|b| b.billing_cycle).unwrap_or(BillingCycle::Monthly);
                                    option value="monthly" selected[cur_cycle == BillingCycle::Monthly] { (crate::i18n::tr(lang, "Monthly", "1 месяц")) }
                                    option value="quarterly" selected[cur_cycle == BillingCycle::Quarterly] { (crate::i18n::tr(lang, "Quarterly (3 mo)", "3 месяца")) }
                                    option value="semi-annual" selected[cur_cycle == BillingCycle::SemiAnnual] { (crate::i18n::tr(lang, "Semi-annual (6 mo)", "6 месяцев")) }
                                    option value="annual" selected[cur_cycle == BillingCycle::Annual] { (crate::i18n::tr(lang, "Annual (12 mo)", "1 год")) }
                                }
                            }

                            div style="flex: 0 0 95px;" {
                                label style="display: block; color: var(--mute); margin-bottom: 4px; font-size: 10px; text-transform: uppercase; letter-spacing: 0.05em;" {
                                    (crate::i18n::tr(lang, "Amount", "Стоимость"))
                                }
                                input type="text" name="amount" placeholder="0.00"
                                       value=(b_opt.map(|b| format!("{:.2}", b.amount_cents as f64 / 100.0)).unwrap_or_default())
                                       style="width: 100%; box-sizing: border-box; height: 32px; padding: 5px 8px; border: 1px solid var(--rule); background: var(--paper); color: var(--ink); text-align: right;" {}
                            }

                            div style="flex: 0 0 80px;" {
                                label style="display: block; color: var(--mute); margin-bottom: 4px; font-size: 10px; text-transform: uppercase; letter-spacing: 0.05em;" {
                                    (crate::i18n::tr(lang, "Currency", "Валюта"))
                                }
                                input list="currency_list" name="currency" maxlength="8"
                                       value=(b_opt.map(|b| b.currency.as_str()).unwrap_or("EUR"))
                                       style="width: 100%; box-sizing: border-box; height: 32px; padding: 5px 8px; border: 1px solid var(--rule); background: var(--paper); color: var(--ink); text-transform: uppercase; text-align: center;" {}
                            }

                            div style="flex: 0 0 110px;" {
                                label style="display: block; color: var(--mute); margin-bottom: 4px; font-size: 10px; text-transform: uppercase; letter-spacing: 0.05em;"
                                      title=(crate::i18n::tr(lang, "Past cycles already paid (history record)", "Сколько циклов было оплачено ранее (запись в историю)")) {
                                    (crate::i18n::tr(lang, "Past paid", "Оплачено ранее"))
                                }
                                input type="number" min="0" max="120" name="initial_payments_count" placeholder="0"
                                       style="width: 100%; box-sizing: border-box; height: 32px; padding: 5px 8px; border: 1px solid var(--rule); background: var(--paper); color: var(--ink); text-align: right;" {}
                            }

                            div style="margin-left: auto; padding-bottom: 6px;" {
                                label style="display: inline-flex; align-items: center; gap: 6px; cursor: pointer; color: var(--ink); font-size: 11px;" {
                                    @let auto = b_opt.map(|b| b.auto_renew).unwrap_or(false);
                                    input type="checkbox" name="auto_renew" value="1" checked[auto] {}
                                    (crate::i18n::tr(lang, "Auto-renewal (card charge)", "Автосписание с карты"))
                                }
                            }
                        }

                        div style="display: flex; flex-wrap: wrap; gap: 12px; align-items: flex-end;" {
                            div style="flex: 1.2 1 240px;" {
                                label style="display: block; color: var(--mute); margin-bottom: 4px; font-size: 10px; text-transform: uppercase; letter-spacing: 0.05em;" {
                                    (crate::i18n::tr(lang, "Hoster portal URL", "Ссылка на кабинет хостера"))
                                }
                                input type="url" name="billing_url" placeholder="https://..."
                                       value=(b_opt.and_then(|b| b.billing_url.as_deref()).unwrap_or(""))
                                       style="width: 100%; box-sizing: border-box; height: 32px; padding: 5px 8px; border: 1px solid var(--rule); background: var(--paper); color: var(--ink);" {}
                            }

                            div style="flex: 1 1 200px;" {
                                label style="display: block; color: var(--mute); margin-bottom: 4px; font-size: 10px; text-transform: uppercase; letter-spacing: 0.05em;" {
                                    (crate::i18n::tr(lang, "Notes / contract", "Заметки / договор"))
                                }
                                input type="text" name="notes" placeholder=(crate::i18n::tr(lang, "Account, card, contract...", "Аккаунт, карта, заметка..."))
                                       value=(b_opt.and_then(|b| b.notes.as_deref()).unwrap_or(""))
                                       style="width: 100%; box-sizing: border-box; height: 32px; padding: 5px 8px; border: 1px solid var(--rule); background: var(--paper); color: var(--ink);" {}
                            }

                            div style="flex: 0 0 auto;" {
                                button type="submit" class="ed-abtn ed-abtn--primary"
                                       style="height: 32px; padding: 0 16px; display: inline-flex; align-items: center; gap: 6px; box-sizing: border-box;" {
                                    (icon("check")) " " (crate::i18n::tr(lang, "Save parameters", "Сохранить"))
                                }
                            }
                        }
                    }
                }
            }
        }
    };

    Ok(render_page(&state, "servers", &theme, &accent, lang, body).await)
}

fn currency_symbol(code: &str) -> &'static str {
    match code {
        "EUR" => "€",
        "USD" => "$",
        "RUB" => "₽",
        "GBP" => "£",
        "CHF" => "CHF",
        "SEK" => "kr",
        "TRY" => "₺",
        "KZT" => "₸",
        _ => "",
    }
}

fn format_amount(cents: i64, currency: &str) -> String {
    let sym = currency_symbol(currency);
    if sym.is_empty() {
        format!("{:.2} {}", cents as f64 / 100.0, currency)
    } else {
        format!("{:.2} {}", cents as f64 / 100.0, sym)
    }
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
