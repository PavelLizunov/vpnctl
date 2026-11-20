use maud::{Markup, html};
use serde::Deserialize;

use super::client::{AuthorClient, AuthorIssue};
use super::date;
use super::views::{Page, Query, empty, pager};
use crate::i18n::{Locale, tr};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Automation {
    enabled: bool,
    auto_deliver: bool,
    telegram_configured: bool,
    vpn_configured: bool,
    jobs: Page<Job>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Job {
    name: String,
    detected_at: Option<String>,
    delivery_state: String,
    telegram_state: String,
    remind_at: Option<String>,
    acknowledged_at: Option<String>,
}

pub(super) async fn automation(
    client: &AuthorClient,
    query: &Query,
    lang: Locale,
) -> Result<Markup, AuthorIssue> {
    let data = client
        .get::<Automation>(
            &["automation"],
            &[
                ("cached", 1),
                ("limit", super::views::PAGE_SIZE),
                ("offset", query.offset),
            ],
        )
        .await?;
    Ok(html! {
        dl.ed-boosty-summary {
            div { dt { (tr(lang, "Process new subscriptions", "Обработка новых подписок")) }
                dd { (enabled(data.enabled, lang)) } }
            div { dt { (tr(lang, "Automatic delivery", "Автоматическая выдача")) }
                dd { (enabled(data.auto_deliver, lang)) } }
            div { dt { "Telegram" } dd { (enabled(data.telegram_configured, lang)) } }
            div { dt { (tr(lang, "vpnctl inventory", "Инвентарь vpnctl")) }
                dd { (if data.vpn_configured { tr(lang, "Configured", "Настроен") } else { tr(lang, "Disconnected", "Не подключён") }) } }
        }
        @if data.jobs.items.is_empty() {
            (empty(lang))
        } @else {
            div.ed-grid-wrap {
                table.ed-grid {
                    thead { tr {
                        th { (tr(lang, "Subscriber", "Подписчик")) }
                        th { (tr(lang, "Detected", "Обнаружен")) }
                        th { (tr(lang, "Delivery", "Выдача")) }
                        th { "Telegram" }
                        th { (tr(lang, "Next reminder", "Напоминание")) }
                    } }
                    tbody { @for job in &data.jobs.items {
                        tr {
                            td { (job.name) }
                            td { (date(job.detected_at.as_deref())) }
                            td {
                                @if job.acknowledged_at.is_some() {
                                    (tr(lang, "Delivered manually", "Выдано вручную"))
                                } @else { (job_state(&job.delivery_state, lang)) }
                            }
                            td { (job_state(&job.telegram_state, lang)) }
                            td { (date(job.remind_at.as_deref())) }
                        }
                    } }
                }
            }
        }
        (pager(query, data.jobs.total, lang))
    })
}

fn enabled(value: bool, lang: Locale) -> &'static str {
    if value {
        tr(lang, "On", "Вкл.")
    } else {
        tr(lang, "Off", "Выкл.")
    }
}

fn job_state(value: &str, lang: Locale) -> &str {
    match value {
        "pending" => tr(lang, "Waiting", "Ожидает"),
        "prepared" => tr(lang, "Prepared", "Подготовлено"),
        "sending" => tr(lang, "Sending", "Отправляется"),
        "sent" | "delivered" => tr(lang, "Delivered", "Отправлено"),
        "delivery_unknown" | "review" | "needs_review" => {
            tr(lang, "Needs review", "Нужна проверка")
        }
        "skipped" => tr(lang, "Skipped", "Пропущено"),
        _ => value,
    }
}
