use maud::{Markup, html};
use serde::Deserialize;

use super::client::{AuthorClient, AuthorIssue};
use super::views::{Page, Query, View, empty, pager, valid_inbox_id};
use super::{DASHBOARD_PATH, date};
use crate::i18n::{Locale, tr};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Dialog {
    id: String,
    name: Option<String>,
    last_message_at: Option<String>,
    preview: Option<String>,
    unread_count: Option<usize>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Conversation {
    dialog: Dialog,
    messages: Vec<Message>,
    before_cursor: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Message {
    direction: String,
    text: String,
    created_at: Option<String>,
    is_deleted: Option<bool>,
}

pub(super) async fn inbox(
    client: &AuthorClient,
    query: &Query,
    lang: Locale,
) -> Result<Markup, AuthorIssue> {
    if let Some(id) = &query.dialog {
        let mut params = vec![("limit", "30"), ("cached", "1")];
        if let Some(cursor) = &query.before {
            params.push(("before", cursor));
        }
        let conversation = client
            .get::<Conversation>(&["inbox", "dialogs", id], &params)
            .await?;
        return Ok(html! {
            p { a href=(View::Messages.url()) { (tr(lang, "Back to conversations", "К перепискам")) } }
            div.ed-headrow {
                h2 { (dialog_name(&conversation.dialog)) }
                div.ed-headrow__actions {
                    form method="post" action="/admin/boosty/author/refresh-conversation" {
                        input type="hidden" name="dialog_id" value=(id);
                        button.ed-abtn type="submit" { (tr(lang, "Refresh conversation", "Обновить переписку")) }
                    }
                }
            }
            @if let Some(before) = conversation.before_cursor.as_deref().filter(|cursor| valid_inbox_id(cursor)) {
                p {
                    a.ed-abtn href=(format!("{DASHBOARD_PATH}?view=messages&dialog={id}&before={before}")) {
                        (tr(lang, "Older messages", "Более ранние сообщения"))
                    }
                }
            }
            @if conversation.messages.is_empty() {
                (empty(lang))
            } @else {
                div.ed-grid-wrap {
                    table.ed-grid {
                        thead { tr {
                            th { (tr(lang, "Date", "Дата")) }
                            th { (tr(lang, "From", "От кого")) }
                            th { (tr(lang, "Message", "Сообщение")) }
                        } }
                        tbody { @for message in &conversation.messages {
                            tr {
                                td { (date(message.created_at.as_deref())) }
                                td {
                                    @match message.direction.as_str() {
                                        "outgoing" => { (tr(lang, "Author", "Автор")) }
                                        "incoming" => { (dialog_name(&conversation.dialog)) }
                                        _ => { "—" }
                                    }
                                }
                                td.ed-boosty-message {
                                    @if message.is_deleted == Some(true) {
                                        (tr(lang, "Message deleted", "Сообщение удалено"))
                                    } @else { (message.text) }
                                }
                            }
                        } }
                    }
                }
            }
        });
    }
    let page = client
        .get::<Page<Dialog>>(&["inbox"], &query.request())
        .await?;
    Ok(html! {
        @if page.items.is_empty() {
            (empty(lang))
        } @else {
            div.ed-grid-wrap {
                table.ed-grid {
                    thead { tr {
                        th { (tr(lang, "Conversation", "Переписка")) }
                        th { (tr(lang, "Latest message", "Последнее сообщение")) }
                        th { (tr(lang, "Date", "Дата")) }
                        th.num { (tr(lang, "Unread", "Непрочитанные")) }
                    } }
                    tbody { @for dialog in &page.items {
                        tr {
                            td {
                                @if valid_inbox_id(&dialog.id) {
                                    a.ed-grid__id href=(format!("{DASHBOARD_PATH}?view=messages&dialog={}", dialog.id)) {
                                        (dialog_name(dialog))
                                    }
                                } @else { (dialog_name(dialog)) }
                            }
                            td { (dialog.preview.as_deref().unwrap_or("—")) }
                            td { (date(dialog.last_message_at.as_deref())) }
                            td.num { (dialog.unread_count.map_or_else(|| "—".into(), |count| count.to_string())) }
                        }
                    } }
                }
            }
        }
        (pager(query, page.total, lang))
    })
}

fn dialog_name(dialog: &Dialog) -> &str {
    dialog
        .name
        .as_deref()
        .filter(|name| !name.is_empty())
        .unwrap_or(&dialog.id)
}

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
