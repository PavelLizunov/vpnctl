use std::{convert::Infallible, time::Duration};

use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio_stream::wrappers::ReceiverStream;

use super::client::{AuthorClient, AuthorIssue};
use super::views::valid_inbox_id;
use crate::AppState;
use crate::handlers::admin::helpers::error_resp;

mod layout;
pub(super) use layout::page;

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Operation {
    Send,
    Draft,
    Check,
    Reconcile,
    Abandon,
    Refresh,
    Viewed,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Action {
    operation: Operation,
    blog: String,
    dialog_id: Option<String>,
    request_id: Option<String>,
    text: Option<String>,
    topic: Option<String>,
    offset: Option<String>,
    history_generation: Option<u64>,
}

fn valid_request_id(id: &str) -> bool {
    (8..=100).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

fn valid_blog(blog: &str) -> bool {
    !blog.is_empty()
        && blog.len() <= 100
        && blog
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

impl Action {
    fn valid(&self) -> bool {
        if !valid_blog(&self.blog)
            || self
                .dialog_id
                .as_deref()
                .is_some_and(|id| !valid_inbox_id(id))
            || self
                .request_id
                .as_deref()
                .is_some_and(|id| !valid_request_id(id))
            || self
                .text
                .as_deref()
                .is_some_and(|text| text.encode_utf16().count() > 8_000)
            || self.offset.as_deref().is_some_and(|offset| {
                offset.is_empty() || offset.len() > 8_192 || offset.chars().any(char::is_control)
            })
        {
            return false;
        }
        if !matches!(self.operation, Operation::Refresh) && self.dialog_id.is_none() {
            return false;
        }
        match self.operation {
            Operation::Send => {
                self.request_id
                    .as_deref()
                    .is_some_and(|id| !id.starts_with("auto-"))
                    && self
                        .text
                        .as_deref()
                        .is_some_and(|text| !text.trim().is_empty())
            }
            Operation::Check | Operation::Reconcile | Operation::Abandon => {
                self.request_id.is_some()
            }
            Operation::Draft => matches!(
                self.topic.as_deref(),
                None | Some("" | "ios_ru" | "ios" | "android" | "desktop" | "connection")
            ),
            Operation::Refresh => {
                self.offset.is_none()
                    || (self.dialog_id.is_some() && self.history_generation.is_some())
            }
            Operation::Viewed => true,
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Reply {
    pub request_id: String,
    pub dialog_id: String,
    pub status: String,
}

#[derive(Deserialize)]
struct ReplyReceipt {
    reply: Reply,
}

#[derive(Deserialize)]
struct DraftReceipt {
    text: String,
}

#[derive(Deserialize)]
struct RefreshReceipt {
    ok: bool,
}

#[derive(Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
enum Outcome {
    Done,
    Reply { reply: Reply },
    Draft { text: String },
    Error { status: u16, not_dispatched: bool },
}

pub(super) fn inbox_action(state: &AppState, body: &str) -> Response {
    if state.boosty_dashboard_url.is_none() {
        return error_resp(
            StatusCode::NOT_FOUND,
            "The Boosty author dashboard is disabled.",
        );
    }
    let Ok(action) = serde_json::from_str::<Action>(body) else {
        return error_resp(StatusCode::BAD_REQUEST, "Invalid Boosty inbox action.");
    };
    if body.len() > 65_536 || !action.valid() {
        return error_resp(
            StatusCode::BAD_REQUEST,
            "Check the Boosty inbox action and try again.",
        );
    }
    let Ok(client) = AuthorClient::with_timeout(&state.boosty_roster_url, Duration::from_secs(115))
    else {
        return error_resp(
            StatusCode::SERVICE_UNAVAILABLE,
            "The Boosty service is unavailable.",
        );
    };
    let (sender, receiver) = tokio::sync::mpsc::channel(1);
    tokio::spawn(async move {
        let result = match execute(&client, &action).await {
            Ok(outcome) => outcome,
            Err(AuthorIssue::Rejected(status)) => Outcome::Error {
                status: status.as_u16(),
                not_dispatched: false,
            },
            Err(AuthorIssue::NotDispatched(status)) => Outcome::Error {
                status: status.as_u16(),
                not_dispatched: true,
            },
            Err(AuthorIssue::Unavailable) => Outcome::Error {
                status: 503,
                not_dispatched: false,
            },
        };
        let data = serde_json::to_string(&result)
            .unwrap_or_else(|_| "{\"result\":\"error\",\"status\":503}".into());
        let _ = sender
            .send(Ok::<_, Infallible>(
                Event::default().event("inbox").data(data),
            ))
            .await;
    });
    Sse::new(ReceiverStream::new(receiver))
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(5)))
        .into_response()
}

async fn execute(client: &AuthorClient, action: &Action) -> Result<Outcome, AuthorIssue> {
    let dialog = action.dialog_id.as_deref().unwrap_or_default();
    let id = action.request_id.as_deref().unwrap_or_default();
    let blog = &action.blog;
    if matches!(action.operation, Operation::Check) {
        let receipt = client
            .get::<ReplyReceipt>(
                &["inbox", "replies", id],
                &[
                    ("cached", "1"),
                    ("blog", blog.as_str()),
                    ("dialogId", dialog),
                ],
            )
            .await?;
        return accepted_reply(receipt, dialog, id);
    }
    match action.operation {
        Operation::Send | Operation::Reconcile | Operation::Abandon => {
            let path = match action.operation {
                Operation::Send => "reply",
                Operation::Reconcile => "reconcile",
                _ => "abandon",
            };
            let text = match (action.operation, action.text.as_deref()) {
                (Operation::Abandon, None | Some("")) => Some("Closed before sending"),
                (_, text) => text,
            };
            let receipt = client
                .post::<ReplyReceipt>(
                    &["inbox", path],
                    &json!({
                        "blog": blog, "dialogId": dialog, "requestId": id, "text": text
                    }),
                )
                .await?;
            accepted_reply(receipt, dialog, id)
        }
        Operation::Draft => {
            let receipt = client
                .post::<DraftReceipt>(
                    &["inbox", "draft"],
                    &json!({
                        "blog": blog, "dialogId": dialog, "topic": action.topic
                    }),
                )
                .await?;
            Ok(Outcome::Draft { text: receipt.text })
        }
        Operation::Refresh | Operation::Viewed => {
            let path = if matches!(action.operation, Operation::Refresh) {
                "sync"
            } else {
                "viewed"
            };
            let receipt = client
                .post::<RefreshReceipt>(
                    &["inbox", path],
                    &json!({
                        "blog": blog, "dialogId": action.dialog_id, "offset": action.offset,
                        "historyGeneration": action.history_generation
                    }),
                )
                .await?;
            receipt
                .ok
                .then_some(Outcome::Done)
                .ok_or(AuthorIssue::Unavailable)
        }
        Operation::Check => Err(AuthorIssue::Unavailable),
    }
}

fn accepted_reply(
    receipt: ReplyReceipt,
    dialog: &str,
    request_id: &str,
) -> Result<Outcome, AuthorIssue> {
    if receipt.reply.dialog_id != dialog || receipt.reply.request_id != request_id {
        return Err(AuthorIssue::Unavailable);
    }
    Ok(Outcome::Reply {
        reply: receipt.reply,
    })
}
