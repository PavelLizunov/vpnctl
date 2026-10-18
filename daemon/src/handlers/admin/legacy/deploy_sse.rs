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
    state.wizard.remove(&session_id);

    let base_id = crate::wizard_bootstrap::derive_server_id(&session.address);
    if base_id.is_empty() {
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

    let inv = state.inv.clone();
    let registry = std::sync::Arc::clone(&state.registry);
    let raw = crate::wizard_bootstrap::run_bootstrap(plan, inv, registry);
    let mapped = raw.map(|ev| {
        let name = match &ev {
            crate::wizard_bootstrap::BootstrapEvent::Step { .. } => "step",
            crate::wizard_bootstrap::BootstrapEvent::Ok { .. } => "ok",
            crate::wizard_bootstrap::BootstrapEvent::Error { .. } => "error",
        };
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

    let stream: Pin<
        Box<dyn Stream<Item = std::result::Result<Event, std::convert::Infallible>> + Send>,
    > = Box::pin(mapped);

    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(std::time::Duration::from_secs(15)))
        .into_response()
}

pub(crate) async fn server_deploy_sse(
    axum::extract::Path(server_id): axum::extract::Path<String>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Response {
    use axum::response::sse::{Event, KeepAlive, Sse};
    use futures_core::Stream;
    use std::pin::Pin;
    use tokio_stream::StreamExt;

    if let Some(sfs) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
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
