use maud::{Markup, html};
use serde::Deserialize;

use super::super::views::{PAGE_SIZE, Query, pager};
use super::super::{DASHBOARD_PATH, date};
use super::{AuthorClient, AuthorIssue, Reply, valid_blog, valid_inbox_id, valid_request_id};
use crate::handlers::admin::helpers::versioned_asset;
use crate::i18n::{Locale, tr};

#[derive(Deserialize)]
struct Directory {
    blog: Option<String>,
    items: Vec<Dialog>,
    total: usize,
    #[serde(default)]
    summary: Summary,
    #[serde(default)]
    support: Support,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Summary {
    unread_messages: Option<usize>,
    last_synced_at: Option<String>,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Support {
    enabled: Option<bool>,
    handoff_count: Option<usize>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Dialog {
    id: String,
    name: Option<String>,
    last_message_at: Option<String>,
    preview: Option<String>,
    unread_count: Option<usize>,
    can_write: Option<bool>,
    blocked: Option<bool>,
    #[serde(default)]
    needs_owner: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Conversation {
    blog: Option<String>,
    dialog: Dialog,
    messages: Vec<Message>,
    before_cursor: Option<String>,
    next_cursor: Option<String>,
    history_generation: Option<u64>,
    pending_reply: Option<Pending>,
}

#[derive(Deserialize)]
struct Pending {
    #[serde(flatten)]
    reply: Reply,
    text: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Message {
    id: Option<String>,
    direction: String,
    text: String,
    created_at: Option<String>,
    is_deleted: Option<bool>,
    pay_wall: Option<bool>,
}

pub(in super::super) async fn page(
    client: &AuthorClient,
    query: &Query,
    lang: Locale,
) -> Result<Markup, AuthorIssue> {
    let offset = query.offset.to_string();
    let count = PAGE_SIZE.to_string();
    let params = [
        ("limit", count.as_str()),
        ("offset", offset.as_str()),
        ("search", query.search.as_str()),
        ("unread", query.unread.as_str()),
        ("handoffOnly", query.handoff.as_str()),
    ];
    let directory = client.get::<Directory>(&["inbox"], &params);
    let selected = async {
        let Some(id) = &query.dialog else {
            return Ok(None);
        };
        let mut params = vec![("limit", "30"), ("cached", "1")];
        if let Some(before) = &query.before {
            params.push(("before", before));
        }
        client
            .get::<Conversation>(&["inbox", "dialogs", id], &params)
            .await
            .map(Some)
    };
    let (directory, selected) = tokio::join!(directory, selected);
    let directory = directory?;
    let blog = directory
        .blog
        .as_deref()
        .filter(|blog| valid_blog(blog))
        .unwrap_or("");
    let stale_blog = query
        .blog
        .as_deref()
        .is_some_and(|requested| requested != blog);
    let selected = selected.ok().flatten().filter(|thread| {
        !stale_blog
            && thread.blog.as_deref() == Some(blog)
            && query.dialog.as_deref() == Some(thread.dialog.id.as_str())
    });
    Ok(html! {
        script src=(versioned_asset("boosty-inbox.js")) defer {}
        section.ed-boosty-inbox id="boosty-inbox" data-blog=(blog)
            data-dialog=[selected.as_ref().map(|thread| thread.dialog.id.as_str())] {
            div.ed-headrow {
                h2 { (tr(lang, "Conversations", "Переписки")) }
                div.ed-headrow__actions {
                    button.ed-abtn type="button" data-inbox-operation="refresh" disabled[blog.is_empty()] {
                        (tr(lang, "Refresh inbox", "Обновить переписки"))
                    }
                }
            }
            @if !blog.is_empty() {
                p.ed-art-deck {
                    (directory.total) " " (tr(lang, "conversations", "переписок")) " · "
                    (tr(lang, "Unread", "Непрочитанные")) " "
                    (directory.summary.unread_messages.map_or_else(|| "—".into(), |n| n.to_string())) " · "
                    (tr(lang, "Updated", "Обновлено")) " " (date(directory.summary.last_synced_at.as_deref()))
                }
                @if directory.support.enabled == Some(true) || directory.support.handoff_count.is_some_and(|n| n > 0) {
                    p.ed-detail-meta {
                        @if directory.support.enabled == Some(true) { (tr(lang, "Auto replies enabled", "Автоответы включены")) " · " }
                        (tr(lang, "Need your reply", "Нужен ваш ответ")) " "
                        (directory.support.handoff_count.map_or_else(|| "—".into(), |n| n.to_string()))
                    }
                }
            }
            div class=(if selected.is_some() { "ed-boosty-inbox__layout ed-boosty-inbox--selected" } else { "ed-boosty-inbox__layout" }) {
                aside.ed-boosty-inbox__directory {
                    (filters(query, lang))
                    ul.ed-boosty-inbox__list {
                        @for dialog in directory.items.iter().filter(|dialog| valid_inbox_id(&dialog.id)) {
                            li {
                                a href=(format!("{}&blog={blog}&dialog={}", query.at(query.offset), dialog.id))
                                    aria-current=[(query.dialog.as_deref() == Some(dialog.id.as_str())).then_some("page")] {
                                    span.ed-boosty-inbox__row {
                                        strong { (name(dialog)) }
                                        time { (date(dialog.last_message_at.as_deref())) }
                                    }
                                    @if let Some(preview) = &dialog.preview {
                                        span.ed-boosty-inbox__preview { (preview) }
                                    }
                                    @if dialog.needs_owner || dialog.unread_count.is_some_and(|count| count > 0) {
                                        small {
                                            @if dialog.needs_owner { (tr(lang, "Needs your reply", "Нужен ваш ответ")) }
                                            @if let Some(count) = dialog.unread_count.filter(|count| *count > 0) {
                                                " " (count) " " (tr(lang, "unread", "непрочитанных"))
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    @if blog.is_empty() {
                        p.ed-art-deck { (tr(lang, "Connect the Boosty account to load conversations.", "Подключите аккаунт Boosty, чтобы загрузить переписки.")) }
                    } @else if directory.items.is_empty() {
                        p.ed-art-deck { (tr(lang, "No conversations match the filters.", "По этим фильтрам переписок нет.")) }
                    }
                    (pager(query, directory.total, lang))
                }
                section.ed-boosty-inbox__thread {
                    @if let Some(thread) = &selected {
                        (thread_panel(thread, query, lang))
                    } @else {
                        p.ed-art-deck {
                            @if stale_blog {
                                (tr(lang, "This link points to a different Boosty account.", "Ссылка ведёт к другому аккаунту Boosty."))
                            } @else if query.dialog.is_some() {
                                (tr(lang, "The conversation is unavailable. Refresh the inbox and try again.", "Переписка недоступна. Обновите список и попробуйте снова."))
                            } @else {
                                (tr(lang, "Select a conversation to read or reply.", "Выберите переписку, чтобы прочитать её или ответить."))
                            }
                        }
                        @if !stale_blog && query.before.is_some() && let Some(id) = &query.dialog {
                            a.ed-abtn href=(format!("{}&blog={blog}&dialog={id}", query.at(query.offset))) {
                                (tr(lang, "Latest messages", "Последние сообщения"))
                            }
                        }
                    }
                    p.ed-boosty-inbox__status id="boosty-inbox-status" role="status" aria-live="polite" {}
                }
            }
        }
    })
}

fn filters(query: &Query, lang: Locale) -> Markup {
    html! {
        form.ed-boosty-inbox__filters method="get" action=(DASHBOARD_PATH) {
            input type="hidden" name="view" value="messages";
            label {
                (tr(lang, "Search conversations", "Найти переписку"))
                input type="search" name="search" maxlength="200" value=(query.search)
                    placeholder=(tr(lang, "Name, ID, or latest message", "Имя, ID или последнее сообщение"));
            }
            label.ed-boosty-inbox__check {
                input type="checkbox" name="unread" value="1" checked[query.unread == "1"];
                (tr(lang, "Unread", "Непрочитанные"))
            }
            label.ed-boosty-inbox__check {
                input type="checkbox" name="handoff" value="1" checked[query.handoff == "1"];
                (tr(lang, "Needs my reply", "Нужен мой ответ"))
            }
            button.ed-abtn type="submit" { (tr(lang, "Search", "Найти")) }
        }
    }
}

fn thread_panel(thread: &Conversation, query: &Query, lang: Locale) -> Markup {
    let id = &thread.dialog.id;
    let blog = thread.blog.as_deref().unwrap_or("");
    let pending = thread.pending_reply.as_ref().filter(|pending| {
        pending.reply.dialog_id == *id && valid_request_id(&pending.reply.request_id)
    });
    let writable = thread.dialog.can_write == Some(true) && thread.dialog.blocked != Some(true);
    html! {
        div.ed-headrow {
            h3 { (name(&thread.dialog)) }
            div.ed-headrow__actions {
                a.ed-abtn.ed-boosty-inbox__back href=(query.at(query.offset)) {
                    (tr(lang, "Conversations", "К перепискам"))
                }
                button.ed-abtn type="button" data-inbox-operation="refresh" data-dialog=(id) {
                    (tr(lang, "Refresh", "Обновить"))
                }
            }
        }
        @if query.before.is_some() {
            a.ed-abtn href=(format!("{}&blog={blog}&dialog={id}", query.at(query.offset))) {
                (tr(lang, "Latest messages", "Последние сообщения"))
            }
        }
        @if let Some(before) = thread.before_cursor.as_deref().filter(|id| valid_inbox_id(id)) {
            a.ed-abtn href=(format!("{}&blog={blog}&dialog={id}&before={before}", query.at(query.offset))) {
                (tr(lang, "Older messages", "Более ранние сообщения"))
            }
        } @else if let (Some(cursor), Some(generation)) = (&thread.next_cursor, thread.history_generation) {
            button.ed-abtn type="button" data-inbox-operation="refresh"
                data-dialog=(id) data-offset=(cursor) data-generation=(generation)
                data-before=[thread.messages.first().and_then(|m| m.id.as_deref()).filter(|id| valid_inbox_id(id))] {
                (tr(lang, "Load older history", "Загрузить более раннюю историю"))
            }
        }
        @if thread.messages.is_empty() {
            p.ed-art-deck { (tr(lang, "No messages in this part of the conversation.", "В этой части переписки сообщений нет.")) }
        } @else {
            ol.ed-boosty-inbox__messages {
                @for message in &thread.messages {
                    li data-outgoing=[(message.direction == "outgoing").then_some("1")] {
                        span.ed-boosty-inbox__row {
                            strong {
                                @match message.direction.as_str() {
                                    "outgoing" => { (tr(lang, "Author", "Автор")) }
                                    "incoming" => { (name(&thread.dialog)) }
                                    _ => { "—" }
                                }
                            }
                            time { (date(message.created_at.as_deref())) }
                        }
                        p.ed-boosty-message {
                            @if message.is_deleted == Some(true) {
                                (tr(lang, "Message deleted", "Сообщение удалено"))
                            } @else if message.pay_wall == Some(true) && message.text.is_empty() {
                                (tr(lang, "Paid message", "Платное сообщение"))
                            } @else { (message.text) }
                        }
                    }
                }
            }
        }
        form.ed-boosty-inbox__composer id="boosty-inbox-compose"
            data-writable=(if writable { "1" } else { "0" })
            data-request-id=[pending.map(|entry| entry.reply.request_id.as_str())] {
            label for="boosty-inbox-reply" { (tr(lang, "Your reply", "Ваш ответ")) }
            textarea id="boosty-inbox-reply" maxlength="8000" rows="4"
                readonly[pending.is_some() || !writable] { (pending.map_or("", |entry| entry.text.as_str())) }
            div.ed-boosty-inbox__controls {
                button.ed-abtn.ed-abtn--primary type="submit" disabled {
                    (tr(lang, "Send", "Отправить"))
                }
                select id="boosty-inbox-topic" aria-label=(tr(lang, "Draft topic", "Тема черновика")) {
                    option value="" { (tr(lang, "Draft on the conversation", "Черновик по переписке")) }
                    option value="ios_ru" { (tr(lang, "iPhone with Russian Apple ID", "iPhone с российским Apple ID")) }
                    option value="ios" { "iPhone" }
                    option value="android" { "Android" }
                    option value="desktop" { (tr(lang, "Computer", "Компьютер")) }
                    option value="connection" { (tr(lang, "First connection", "Первое подключение")) }
                }
                button.ed-abtn type="button" data-inbox-operation="draft" disabled {
                    (tr(lang, "Prepare draft", "Подготовить черновик"))
                }
            }
            div.ed-boosty-inbox__controls id="boosty-inbox-pending" hidden[pending.is_none()] {
                button.ed-abtn type="button" data-inbox-operation="reconcile" {
                    (tr(lang, "Check delivery", "Проверить отправку"))
                }
                button.ed-abtn type="button" data-inbox-operation="abandon" {
                    (tr(lang, "Close the check", "Закрыть проверку"))
                }
            }
        }
    }
}

fn name(dialog: &Dialog) -> &str {
    dialog
        .name
        .as_deref()
        .filter(|name| !name.is_empty())
        .unwrap_or(&dialog.id)
}
