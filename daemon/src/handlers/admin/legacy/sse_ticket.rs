//! Single-use start tickets for the GET SSE endpoints that launch operations.
//!
//! `EventSource` can only issue GET, so the CSRF middleware never sees these
//! requests, and `Sec-Fetch-Site` is not sent to plain-HTTP origins. The page
//! first obtains a ticket with a same-origin POST (covered by the CSRF
//! middleware) and passes it as `?ticket=`; the SSE handler consumes it before
//! starting anything.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use axum::http::{StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};

use crate::handlers::admin::helpers::{bad_request, error_resp, internal_error};
use crate::http_util::form_field;

const TICKET_TTL: Duration = Duration::from_secs(120);
const MAX_OUTSTANDING: usize = 256;

fn tickets() -> &'static Mutex<HashMap<String, (String, Instant)>> {
    static TICKETS: OnceLock<Mutex<HashMap<String, (String, Instant)>>> = OnceLock::new();
    TICKETS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn is_ticketed_path(path: &str) -> bool {
    path.starts_with("/admin/")
        && (path.ends_with("/sse") || path == "/admin/settings/geoip/update-now")
        && path != "/admin/servers/new/step-2/sse"
}

pub(crate) fn issue(path: &str) -> std::io::Result<String> {
    let ticket = vpnctl_crypto::gen_password(24)?;
    let now = Instant::now();
    let mut map = tickets()
        .lock()
        .map_err(|_| std::io::Error::other("sse ticket store poisoned"))?;
    map.retain(|_, (_, issued)| now.duration_since(*issued) < TICKET_TTL);
    if map.len() >= MAX_OUTSTANDING {
        return Err(std::io::Error::other("too many outstanding sse tickets"));
    }
    map.insert(ticket.clone(), (path.to_string(), now));
    Ok(ticket)
}

pub(crate) fn consume(ticket: &str, path: &str) -> bool {
    let Ok(mut map) = tickets().lock() else {
        return false;
    };
    match map.remove(ticket) {
        Some((bound, issued)) => bound == path && issued.elapsed() < TICKET_TTL,
        None => false,
    }
}

/// `None` when the request carries a valid ticket for its own path.
pub(crate) fn refuse_without_ticket(uri: &Uri) -> Option<Response> {
    let ticket = uri
        .query()
        .and_then(|q| form_field(q, "ticket"))
        .unwrap_or_default();
    if !ticket.is_empty() && consume(&ticket, uri.path()) {
        return None;
    }
    Some(error_resp(
        StatusCode::FORBIDDEN,
        "start ticket missing or expired — start this action with its button in the admin UI",
    ))
}

pub(crate) async fn sse_ticket(body: String) -> Response {
    let path = form_field(&body, "path").unwrap_or_default();
    if !is_ticketed_path(&path) {
        return bad_request("path is not a ticketed admin action");
    }
    match issue(&path) {
        Ok(ticket) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
                (header::CACHE_CONTROL, "no-store"),
            ],
            ticket,
        )
            .into_response(),
        Err(e) => internal_error(anyhow::Error::new(e)),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn ticket_is_single_use_and_path_bound() {
        let t = issue("/admin/servers/a/deploy/sse").unwrap();
        assert!(!consume(&t, "/admin/servers/b/deploy/sse"));
        let t = issue("/admin/servers/a/deploy/sse").unwrap();
        assert!(consume(&t, "/admin/servers/a/deploy/sse"));
        assert!(!consume(&t, "/admin/servers/a/deploy/sse"));
    }

    #[test]
    fn only_operation_sse_paths_are_ticketed() {
        assert!(is_ticketed_path("/admin/servers/deploy-all/sse"));
        assert!(is_ticketed_path("/admin/settings/geoip/update-now"));
        assert!(!is_ticketed_path("/admin/servers/new/step-2/sse"));
        assert!(!is_ticketed_path("/sub/x/sse"));
        assert!(!is_ticketed_path("/admin/users"));
    }

    #[test]
    fn request_without_ticket_is_refused() {
        let uri: Uri = "/admin/servers/deploy-all/sse".parse().unwrap();
        assert!(refuse_without_ticket(&uri).is_some());
        let t = issue("/admin/servers/deploy-all/sse").unwrap();
        let uri: Uri = format!("/admin/servers/deploy-all/sse?ticket={t}")
            .parse()
            .unwrap();
        assert!(refuse_without_ticket(&uri).is_none());
    }
}
