use crate::AppState;
use crate::handlers::admin::helpers::{
    bad_request, error_resp, internal_error, not_found, user_not_found,
};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};

pub(super) fn read_cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    for hdr in headers.get_all(header::COOKIE) {
        let Ok(raw) = hdr.to_str() else { continue };
        for piece in raw.split(';') {
            let kv = piece.trim();
            if let Some(rest) = kv.strip_prefix(name)
                && let Some(value) = rest.strip_prefix('=')
            {
                return Some(value);
            }
        }
    }
    None
}
/// `GET /admin/servers/new/step-2/sse` — the EventSource endpoint
/// the step-2 page connects to. Reads the wizard cookie, fetches the
/// session, builds a `BootstrapPlan`, then streams events from
/// `wizard_bootstrap::run_bootstrap` as Server-Sent Events.
///
/// Events use the named-event form (`event: step\ndata: {json}\n\n`)
/// so the front-end can attach separate handlers per event type via
/// `EventSource.addEventListener('step', …)`. Saves us writing a
/// discriminator in the client JSON parser.
///
/// **Why we delete the session on first attach**: the wizard runs
/// exactly once. After the first SSE handler starts the bootstrap,
/// the session is consumed — re-opening the URL would re-run the
/// whole pipeline (including a second `inv.add_server` that fails
/// with AlreadyExists). Single-shot is the only sane semantics.
pub(crate) async fn wizard_step2_sse(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Response {
    use axum::response::sse::{Event, KeepAlive, Sse};
    use futures_core::Stream;
    use std::pin::Pin;
    use tokio_stream::StreamExt;

    let cookie = read_cookie(&headers, crate::wizard::COOKIE_NAME).map(str::to_string);
    let Some(session_id) = cookie else {
        return bad_request("wizard session missing — start over from /admin/servers/new");
    };
    let Some(session) = state.wizard.get(&session_id) else {
        return bad_request("wizard session expired — start over from /admin/servers/new");
    };
    // Single-shot semantics — after the SSE handler attaches, the
    // session is gone. Refresh on the page falls back to the
    // "session missing" branch (with a "start over" link).
    state.wizard.remove(&session_id);

    // Derive a non-colliding server id from the address. If the
    // operator wizards the same IP twice, `find_available_server_id`
    // picks `<id>-2`, `<id>-3`, … (bounded to avoid an infinite
    // loop on a corrupt inventory). Pure helper — unit-tested in
    // `wizard_bootstrap::tests`.
    let base_id = crate::wizard_bootstrap::derive_server_id(&session.address);
    if base_id.is_empty() {
        // Should be impossible — wizard validates address upfront —
        // but defensive: empty id would fail inv.add_server with a
        // useless error. Surface upfront instead.
        return bad_request(
            "address didn't produce any safe id chars — start over with a different address",
        );
    }
    let existing: std::collections::HashSet<String> = match state.inv.list_servers().await {
        Ok(list) => list.into_iter().map(|s| s.id.0).collect(),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    let server_id = match crate::wizard_bootstrap::find_available_server_id(&existing, &base_id) {
        Ok(s) => s,
        Err(e) => return error_resp(StatusCode::CONFLICT, &e),
    };

    let plan = crate::wizard_bootstrap::BootstrapPlan {
        server_id,
        address: session.address,
        ssh_user: session.ssh_user,
        ssh_port: session.ssh_port,
        root_password: session.root_password,
        deploy_key_path: crate::app::deploy_key_path(),
        known_hosts_path: std::path::PathBuf::from("/var/lib/vpnctl/.ssh/known_hosts"),
    };

    // Map each BootstrapEvent → axum SSE Event with a named event
    // type. The infallible Result wrapper is what axum's Sse::new
    // expects (`Result<Event, Error>`) — we never produce errors
    // here because the bootstrap pipeline encodes failures as
    // `BootstrapEvent::Error` payloads, not stream-level errors.
    let inv = state.inv.clone();
    let registry = std::sync::Arc::clone(&state.registry);
    let raw = crate::wizard_bootstrap::run_bootstrap(plan, inv, registry);
    let mapped = raw.map(|ev| {
        let name = match &ev {
            crate::wizard_bootstrap::BootstrapEvent::Step { .. } => "step",
            crate::wizard_bootstrap::BootstrapEvent::Ok { .. } => "ok",
            crate::wizard_bootstrap::BootstrapEvent::Error { .. } => "error",
        };
        // The SSE Event is built from the JSON-serialised payload.
        // serde_json failure is effectively impossible on our
        // BootstrapEvent types (basic Rust strings + integers,
        // tagged enum), but if it ever happens we keep the original
        // event name and log loudly — silently swapping to a fake
        // error event would have the front-end think a `step` was a
        // terminal failure.
        let json = serde_json::to_string(&ev).unwrap_or_else(|e| {
            tracing::error!(
                target = "vpnctld::wizard",
                event_name = name,
                error = %e,
                "wizard SSE event serialisation failed — emitting placeholder"
            );
            format!("{{\"kind\":\"step\",\"phase\":\"serialise-error\",\"message\":\"daemon failed to serialise this event ({e}); please retry the action\"}}")
        });
        Ok::<_, std::convert::Infallible>(Event::default().event(name).data(json))
    });

    // Box the stream so the return type fits a single Pin<Box<dyn …>>.
    // Without this, `Sse::new` would carry the unnameable `impl
    // Stream` type all the way up to the route registration.
    let stream: Pin<
        Box<dyn Stream<Item = std::result::Result<Event, std::convert::Infallible>> + Send>,
    > = Box::pin(mapped);

    // KeepAlive sends `: keep-alive\n\n` comments every 15s so
    // intermediate proxies (or a tab in the background) don't drop
    // the connection during a long apt-get install.
    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(std::time::Duration::from_secs(15)))
        .into_response()
}

/// `GET /admin/servers/{id}/deploy/sse` — EventSource endpoint that
/// RE-deploys an existing server, streaming `step` / `ok` / `error`
/// events so the operator watches each phase live and sees the terminal
/// status (item-1, 2026-05-31). The heavy lifting is
/// `wizard_bootstrap::run_redeploy`, which ends in an `error` event when
/// any kernel step failed — so a crash-looping sing-box never reads as
/// success (the bug the old synchronous 303-redirect handler had).
///
/// EventSource can only issue GET, so this state-changing request can't
/// ride the POST-only Origin CSRF middleware. Guard explicitly: reject a
/// browser `Sec-Fetch-Site: cross-site` / `none` (a `<img>`/prefetch CSRF
/// attempt). Absent header = non-browser tooling (curl) which carries no
/// ambient admin cookie to forge with, so it's allowed — same posture as
/// the wizard + geoip SSE endpoints, plus basic-auth on the whole tree.
pub(crate) async fn server_deploy_sse(
    axum::extract::Path(server_id): axum::extract::Path<String>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Response {
    use axum::response::sse::{Event, KeepAlive, Sse};
    use futures_core::Stream;
    use std::pin::Pin;
    use tokio_stream::StreamExt;

    // Same-origin guard for the state-changing GET.
    if let Some(sfs) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        // Unified predicate (audit 2026-06-10, same as the geoip SSE):
        // allow only "same-origin" (EventSource from an admin page) and
        // "none" (direct navigation). The old check let "same-site"
        // through while refusing "none" — opposite of the geoip guard.
        if sfs != "same-origin" && sfs != "none" {
            return error_resp(
                StatusCode::FORBIDDEN,
                "cross-origin deploy trigger refused (same-origin only)",
            );
        }
    }

    let sid = vpnctl_core::ServerId(server_id.clone());
    let server = match state.inv.get_server(&sid).await {
        Ok(Some(s)) => s,
        Ok(None) => return not_found(&format!("no such server '{server_id}'")),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };

    let key_path = crate::app::deploy_key_path();
    let raw = crate::wizard_bootstrap::run_redeploy(
        server,
        state.inv.clone(),
        std::sync::Arc::clone(&state.registry),
        key_path,
    );
    let mapped = raw.map(|ev| {
        let name = match &ev {
            crate::wizard_bootstrap::BootstrapEvent::Step { .. } => "step",
            crate::wizard_bootstrap::BootstrapEvent::Ok { .. } => "ok",
            crate::wizard_bootstrap::BootstrapEvent::Error { .. } => "error",
        };
        let json = serde_json::to_string(&ev).unwrap_or_else(|e| {
            tracing::error!(
                target = "vpnctld::redeploy",
                event_name = name,
                error = %e,
                "redeploy SSE event serialisation failed — emitting placeholder"
            );
            format!(
                "{{\"kind\":\"step\",\"phase\":\"serialise-error\",\"message\":\"daemon failed to serialise this event ({e}); please retry the action\"}}"
            )
        });
        Ok::<_, std::convert::Infallible>(Event::default().event(name).data(json))
    });
    let stream: Pin<
        Box<dyn Stream<Item = std::result::Result<Event, std::convert::Infallible>> + Send>,
    > = Box::pin(mapped);
    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(std::time::Duration::from_secs(15)))
        .into_response()
}

/// `GET /admin/servers/deploy-all/sse` — EventSource that re-deploys
/// EVERY server in one streamed pass (the "Deploy all" button, 2026-06-03).
/// Run after adding a user / granting servers so the new UUID reaches all
/// nodes (a grant only updates inv.db; the node's sing-box isn't touched
/// until a deploy). Same Sec-Fetch-Site same-origin guard + basic-auth as
/// the single-server SSE deploy. Best-effort across the fleet — heavy
/// lifting in `wizard_bootstrap::run_deploy_all`.
pub(crate) async fn servers_deploy_all_sse(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Response {
    if let Some(resp) = refuse_cross_origin_sse(&headers) {
        return resp;
    }

    let servers = match state.inv.list_fleet_servers().await {
        Ok(s) => s,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    deploy_servers_sse_response(&state, servers)
}

/// `GET /admin/users/{id}/deploy-pending/sse` — deploys ONLY the servers
/// the pending-deploy banner names for this user. Before 2026-07-10 the
/// banner button reused the fleet-wide deploy-all: one pending `us`
/// redeployed cdn/de/is/nl too — harmless (idempotent, reload-not-
/// restart) but noisy and inconsistent with the scoped banner
/// (operator report, design review R2).
pub(crate) async fn user_deploy_pending_sse(
    headers: HeaderMap,
    Path(user_id_str): Path<String>,
    State(state): State<AppState>,
) -> Response {
    if let Some(resp) = refuse_cross_origin_sse(&headers) {
        return resp;
    }
    let uid = vpnctl_core::UserId(user_id_str.clone());
    match state.inv.get_user(&uid).await {
        Ok(Some(_)) => {}
        Ok(None) => return user_not_found(&user_id_str),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }
    let granted = match state.inv.servers_for_user(&uid).await {
        Ok(v) => v,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    let granted_ids: Vec<vpnctl_core::ServerId> = granted.iter().map(|s| s.id.clone()).collect();
    let pending = match state
        .inv
        .servers_pending_deploy_for_user(&uid, &granted_ids)
        .await
    {
        Ok(v) => v,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    let servers: Vec<vpnctl_core::Server> = granted
        .into_iter()
        .filter(|s| pending.contains(&s.id))
        .collect();
    // Racing a just-finished deploy leaves nothing to do — say so
    // instead of streaming an empty run.
    if servers.is_empty() {
        use axum::response::sse::{Event, KeepAlive, Sse};
        let ev = Event::default()
            .event("ok")
            .data(r#"{"kind":"ok","message":"nothing pending — every granted server already carries this user's config"}"#);
        let stream = tokio_stream::once(Ok::<_, std::convert::Infallible>(ev));
        return Sse::new(stream)
            .keep_alive(KeepAlive::new().interval(std::time::Duration::from_secs(15)))
            .into_response();
    }
    deploy_servers_sse_response(&state, servers)
}

/// Shared Sec-Fetch-Site guard for the SSE deploy triggers. Allows
/// only "same-origin" (EventSource from an admin page) and "none"
/// (direct navigation) — unified predicate from the 2026-06-10 audit.
fn refuse_cross_origin_sse(headers: &HeaderMap) -> Option<Response> {
    if let Some(sfs) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        if sfs != "same-origin" && sfs != "none" {
            return Some(error_resp(
                StatusCode::FORBIDDEN,
                "cross-origin deploy trigger refused (same-origin only)",
            ));
        }
    }
    None
}

/// Stream a `run_deploy_all` pass over `servers` as an SSE response —
/// the shared tail of the fleet-wide and per-user-pending deploy
/// triggers.
fn deploy_servers_sse_response(state: &AppState, servers: Vec<vpnctl_core::Server>) -> Response {
    use axum::response::sse::{Event, KeepAlive, Sse};
    use futures_core::Stream;
    use std::pin::Pin;
    use tokio_stream::StreamExt;

    let key_path = crate::app::deploy_key_path();
    let raw = crate::wizard_bootstrap::run_deploy_all(
        servers,
        state.inv.clone(),
        std::sync::Arc::clone(&state.registry),
        key_path,
    );
    let mapped = raw.map(|ev| {
        let name = match &ev {
            crate::wizard_bootstrap::BootstrapEvent::Step { .. } => "step",
            crate::wizard_bootstrap::BootstrapEvent::Ok { .. } => "ok",
            crate::wizard_bootstrap::BootstrapEvent::Error { .. } => "error",
        };
        let json = serde_json::to_string(&ev).unwrap_or_else(|e| {
            tracing::error!(
                target = "vpnctld::deploy_all",
                event_name = name,
                error = %e,
                "deploy-all SSE event serialisation failed — emitting placeholder"
            );
            format!(
                "{{\"kind\":\"step\",\"phase\":\"serialise-error\",\"message\":\"daemon failed to serialise this event ({e}); please retry the action\"}}"
            )
        });
        Ok::<_, std::convert::Infallible>(Event::default().event(name).data(json))
    });
    let stream: Pin<
        Box<dyn Stream<Item = std::result::Result<Event, std::convert::Infallible>> + Send>,
    > = Box::pin(mapped);
    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(std::time::Duration::from_secs(15)))
        .into_response()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn read_cookie_handles_multiple_headers_and_first_match() {
        let mut headers = HeaderMap::new();
        headers.append(
            header::COOKIE,
            HeaderValue::from_static("foo=bar; wiz_id=123"),
        );
        headers.append(
            header::COOKIE,
            HeaderValue::from_static("wiz_id=456; baz=qux"),
        );

        assert_eq!(read_cookie(&headers, "wiz_id"), Some("123"));
        assert_eq!(read_cookie(&headers, "baz"), Some("qux"));
        assert_eq!(read_cookie(&headers, "missing"), None);
    }
}
