mod client;
mod views;
mod workflows;

use std::time::Duration;

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use maud::{Markup, html};
use serde::Deserialize;

use super::{DASHBOARD_PATH, SYNC_PATH};
use crate::AppState;
use crate::handlers::admin::helpers::{error_resp, format_msk_iso, render_page, theme_accent_lang};
use crate::http_util::form_field;
use crate::i18n::{Locale, tr};

use client::{AuthorClient, AuthorIssue};
use views::{Query, View};

#[derive(Deserialize)]
struct Overview {
    roster: Option<Roster>,
    #[serde(default)]
    summaries: Vec<Summary>,
    #[serde(default)]
    metrics: Vec<Metrics>,
    #[serde(default, rename = "moneyTotals")]
    money_totals: Vec<MoneyTotal>,
    #[serde(default)]
    sources: Vec<Source>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Roster {
    total: usize,
    paid_count: Option<usize>,
    free_count: Option<usize>,
    estimated_monthly_minor: Option<i64>,
    captured_at: String,
    currency: Option<String>,
}

#[derive(Deserialize)]
struct Summary {
    currency: Option<String>,
    details: Balance,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Balance {
    balance_minor: Option<i64>,
}

#[derive(Deserialize)]
struct Metrics {
    currency: Option<String>,
    details: MetricValues,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MetricValues {
    total_money_minor: Option<i64>,
    inc_subscribers: Option<MetricCount>,
    dec_subscribers: Option<MetricCount>,
    recurrents: Option<MetricCount>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum MetricCount {
    Integer(i64),
    Text(String),
}

fn metric_count(value: Option<&MetricCount>) -> String {
    match value {
        Some(MetricCount::Integer(count)) => count.to_string(),
        Some(MetricCount::Text(count)) => count
            .parse::<i64>()
            .map_or_else(|_| "—".into(), |count| count.to_string()),
        None => "—".into(),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MoneyTotal {
    source: String,
    currency: Option<String>,
    amount_minor: Option<i64>,
    count: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Source {
    label: String,
    status: String,
    last_success_at: Option<String>,
}

pub(super) async fn page(
    state: &AppState,
    headers: &HeaderMap,
    standalone: &reqwest::Url,
    uri: &axum::http::Uri,
) -> Response {
    let (theme, accent, lang) = theme_accent_lang(headers);
    let query = Query::from_uri(uri);
    let mut standalone = standalone.clone();
    standalone.set_fragment(query.view.standalone_fragment());
    let content = match AuthorClient::from_roster_url(&state.boosty_roster_url) {
        Ok(client) => tokio::time::timeout(
            Duration::from_secs(3),
            views::content(&client, state, &query, lang),
        )
        .await
        .unwrap_or(Err(AuthorIssue::Unavailable)),
        Err(issue) => Err(issue),
    };
    let body = html! {
        section id="boosty-author-dashboard" {
            div.ed-headrow {
                h1.ed-art-h1 { "Boosty" }
                div.ed-headrow__actions {
                    a.ed-abtn.ed-abtn--secondary href=(SYNC_PATH) {
                        (tr(lang, "VPN accounts and sync", "Связи с VPN и синхронизация"))
                    }
                    form method="post" action="/admin/boosty/author/refresh" {
                        button.ed-abtn type="submit" {
                            (tr(lang, "Refresh data", "Обновить данные"))
                        }
                    }
                }
            }
            nav.ed-tabs.ed-boosty-tabs aria-label="Boosty" {
                @for tab in View::ALL {
                    a class=(if query.view == tab { "ed-tab ed-tab--on" } else { "ed-tab" })
                        href=(tab.url())
                        aria-current=[(query.view == tab).then_some("page")] {
                        (tab.label(lang))
                    }
                }
            }
            @match content {
                Ok(view) => { (view) }
                Err(AuthorIssue::Rejected(StatusCode::BAD_REQUEST)) => {
                    p.ed-art-deck { (tr(lang, "Check the filters and try again.", "Проверьте фильтры и повторите запрос.")) }
                }
                Err(AuthorIssue::Rejected(StatusCode::NOT_FOUND)) => {
                    p.ed-art-deck { (tr(lang, "This Boosty record is no longer available.", "Эта запись Boosty больше недоступна.")) }
                }
                Err(_) => {
                    p.ed-art-deck {
                        (tr(lang, "Boosty data is temporarily unavailable. Try refreshing the page.",
                            "Данные Boosty временно недоступны. Попробуйте обновить страницу."))
                    }
                }
            }
            p {
                a href=(standalone.as_str()) target="_blank" rel="noopener noreferrer" {
                    (query.view.standalone_label(lang))
                }
            }
        }
    };
    render_page(state, "boosty", &theme, &accent, lang, body)
        .await
        .into_response()
}

pub(super) async fn refresh(state: &AppState) -> Response {
    if state.boosty_dashboard_url.is_none() {
        return error_resp(
            StatusCode::NOT_FOUND,
            "The Boosty author dashboard is disabled.",
        );
    }
    let response = match AuthorClient::from_roster_url(&state.boosty_roster_url) {
        Ok(client) => {
            client
                .post::<RefreshReceipt>(&["sync"], &serde_json::json!({}))
                .await
        }
        Err(issue) => Err(issue),
    };
    match response {
        Ok(RefreshReceipt { ok: true }) => Redirect::to(DASHBOARD_PATH).into_response(),
        Err(AuthorIssue::Rejected(StatusCode::BAD_REQUEST)) => error_resp(
            StatusCode::CONFLICT,
            "Connect the Boosty account in the standalone panel before refreshing.",
        ),
        _ => error_resp(
            StatusCode::SERVICE_UNAVAILABLE,
            "Could not confirm the Boosty refresh. Reload the dashboard to check its status.",
        ),
    }
}

#[derive(Deserialize)]
struct RefreshReceipt {
    ok: bool,
}

pub(super) async fn refresh_conversation(state: &AppState, body: &str) -> Response {
    if state.boosty_dashboard_url.is_none() {
        return error_resp(
            StatusCode::NOT_FOUND,
            "The Boosty author dashboard is disabled.",
        );
    }
    let Some(id) = form_field(body, "dialog_id").filter(|id| views::valid_inbox_id(id)) else {
        return error_resp(
            StatusCode::BAD_REQUEST,
            "Select a Boosty conversation to refresh.",
        );
    };
    let response = match AuthorClient::from_roster_url(&state.boosty_roster_url) {
        Ok(client) => {
            client
                .post::<RefreshReceipt>(&["inbox", "sync"], &serde_json::json!({"dialogId": id}))
                .await
        }
        Err(issue) => Err(issue),
    };
    match response {
        Ok(RefreshReceipt { ok: true }) => {
            Redirect::to(&format!("{DASHBOARD_PATH}?view=messages&dialog={id}")).into_response()
        }
        Err(AuthorIssue::Rejected(StatusCode::NOT_FOUND)) => error_resp(
            StatusCode::NOT_FOUND,
            "This Boosty conversation is no longer available.",
        ),
        _ => error_resp(
            StatusCode::SERVICE_UNAVAILABLE,
            "Could not confirm the conversation refresh. Reload the conversation to check for updated messages.",
        ),
    }
}

fn date(value: Option<&str>) -> String {
    value
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|value| format_msk_iso(value.to_utc()))
        .unwrap_or_else(|| "—".into())
}

fn money(value: Option<i64>, currency: Option<&str>) -> String {
    let (Some(value), Some(currency)) = (value, currency) else {
        return "—".into();
    };
    let prefix = if value < 0 { "−" } else { "" };
    let value = value.unsigned_abs();
    format!("{prefix}{}.{:02} {currency}", value / 100, value % 100)
}

fn overview_view(data: &Overview, lang: Locale) -> Markup {
    html! {
        @if let Some(roster) = &data.roster {
            p.ed-art-deck {
                (tr(lang, "Subscriber list updated", "Список подписчиков обновлён"))
                " " (date(Some(&roster.captured_at)))
            }
            dl.ed-boosty-summary {
                div { dt { (tr(lang, "Subscribers", "Подписчики")) } dd { (roster.total) } }
                div { dt { (tr(lang, "Paid", "Платные")) }
                    dd { (roster.paid_count.map_or_else(|| "—".into(), |n| n.to_string())) } }
                div { dt { (tr(lang, "Free", "Бесплатные")) }
                    dd { (roster.free_count.map_or_else(|| "—".into(), |n| n.to_string())) } }
                div { dt { (tr(lang, "Estimated monthly subscriptions", "Оценка подписок за месяц")) }
                    dd { (money(roster.estimated_monthly_minor, roster.currency.as_deref())) } }
                @if let Some(summary) = data.summaries.first() {
                    div { dt { (tr(lang, "Balance", "Баланс")) }
                        dd { (money(summary.details.balance_minor, summary.currency.as_deref())) } }
                }
            }
        } @else {
            p.ed-art-deck {
                (tr(lang, "The subscriber list has not been loaded. Check the Boosty connection.",
                    "Список подписчиков пока не загружен. Проверьте подключение Boosty."))
            }
        }
        @if !data.money_totals.is_empty() {
            h2 { (tr(lang, "Financial history", "Финансовая история")) }
            div.ed-grid-wrap {
                table.ed-grid {
                    thead { tr {
                        th { (tr(lang, "Source", "Источник")) }
                        th.num { (tr(lang, "Records", "Записи")) }
                        th.num { (tr(lang, "Total", "Сумма")) }
                    } }
                    tbody { @for row in &data.money_totals {
                        tr {
                            td { (source_name(&row.source, lang)) }
                            td.num { (row.count) }
                            td.num { (money(row.amount_minor, row.currency.as_deref())) }
                        }
                    } }
                }
            }
        }
        @if let Some(metrics) = data.metrics.first() {
            h2 { (tr(lang, "Last 30 days", "Последние 30 дней")) }
            dl.ed-boosty-summary {
                div { dt { (tr(lang, "Total collected", "Поступления")) }
                    dd { (money(metrics.details.total_money_minor, metrics.currency.as_deref())) } }
                div { dt { (tr(lang, "New subscribers", "Новые подписчики")) }
                    dd { (metric_count(metrics.details.inc_subscribers.as_ref())) } }
                div { dt { (tr(lang, "Lost subscribers", "Ушедшие подписчики")) }
                    dd { (metric_count(metrics.details.dec_subscribers.as_ref())) } }
                div { dt { (tr(lang, "Renewals", "Продления")) }
                    dd { (metric_count(metrics.details.recurrents.as_ref())) } }
            }
        }
        @if !data.sources.is_empty() {
            h2 { (tr(lang, "Sources", "Источники")) }
            (sources(&data.sources, lang))
        }
    }
}

fn source_name(source: &str, lang: Locale) -> &str {
    match source {
        "donations" => tr(lang, "Donations", "Донаты"),
        "postSales" => tr(lang, "Post sales", "Продажи постов"),
        "bundleSales" => tr(lang, "Bundle sales", "Продажи наборов"),
        "holds" => tr(lang, "Holds", "Удержания"),
        "payouts" => tr(lang, "Payouts", "Выплаты"),
        "events" => tr(lang, "Boosty events", "События Boosty"),
        "cancellations" => tr(lang, "Cancellations", "Причины отмен"),
        "observed" | "subscribers" => tr(lang, "Subscriber changes", "Изменения подписок"),
        "posts" => tr(lang, "Posts", "Публикации"),
        "levels" => tr(lang, "Subscription tiers", "Уровни подписки"),
        "goals" => tr(lang, "Goals", "Цели"),
        "summary" => tr(lang, "Balance and totals", "Баланс и итоги"),
        "metrics" => tr(lang, "30-day metrics", "Показатели за 30 дней"),
        "charts" => tr(lang, "Daily metrics", "Дневные показатели"),
        "visits" => tr(lang, "Visit sources", "Источники посещений"),
        "paymentSources" => tr(lang, "Payment sources", "Источники оплат"),
        "referrals" => tr(lang, "Referral totals", "Итоги рефералов"),
        "referralUsers" => tr(lang, "Referral users", "Реферальные пользователи"),
        _ => source,
    }
}

fn sources(items: &[Source], lang: Locale) -> Markup {
    html! {
        div.ed-grid-wrap {
            table.ed-grid {
                thead { tr {
                    th { (tr(lang, "Source", "Источник")) }
                    th { (tr(lang, "Status", "Статус")) }
                    th { (tr(lang, "Last updated", "Обновлено")) }
                } }
                tbody { @for source in items {
                    tr {
                        td { (source.label) }
                        td { (source_status(&source.status, lang)) }
                        td { (date(source.last_success_at.as_deref())) }
                    }
                } }
            }
        }
    }
}

fn source_status(status: &str, lang: Locale) -> &str {
    match status {
        "ok" => tr(lang, "Current", "Обновлено"),
        "error" => tr(lang, "Update failed", "Ошибка обновления"),
        "pending" => tr(lang, "Waiting for data", "Ожидаем данные"),
        "partial" => tr(lang, "Partial", "Частичные данные"),
        _ => status,
    }
}
