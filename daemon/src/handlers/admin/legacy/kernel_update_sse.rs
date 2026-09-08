use crate::AppState;
use crate::handlers::admin::helpers::{error_resp, internal_error, not_found};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
/// `GET /admin/servers/{id}/update-kernels/sse` — EventSource endpoint
/// that UPGRADES the kernel binaries on an existing server (update-kernels
/// PR2). For each declared kernel it streams `status → install → done`
/// running ONLY `ensure_installed` (apt upgrade + service restart) — it
/// never renders or applies a config, so it works on inventory-drift nodes
/// without entering the DG-1 UUID-removal guard. The heavy lifting is
/// `wizard_bootstrap::run_update_kernels`, which ends in an `error` event
/// when any kernel step failed.
///
/// EventSource can only issue GET, so this state-changing request can't
/// ride the POST-only Origin CSRF middleware. Guard explicitly: reject a
/// browser `Sec-Fetch-Site: cross-site` / non-same-origin (a `<img>`/
/// prefetch CSRF attempt). Absent header = non-browser tooling (curl)
/// which carries no ambient admin cookie to forge with, so it's allowed —
/// same posture as the deploy + geoip SSE endpoints, plus basic-auth on
/// the whole tree.
pub(crate) async fn server_update_kernels_sse(
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
        if sfs != "same-origin" && sfs != "none" {
            return error_resp(
                StatusCode::FORBIDDEN,
                "cross-origin update-kernels trigger refused (same-origin only)",
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
    let raw = crate::wizard_bootstrap::run_update_kernels(
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
                target = "vpnctld::update_kernels",
                event_name = name,
                error = %e,
                "update-kernels SSE event serialisation failed — emitting placeholder"
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

/// `GET /admin/servers/update-kernels-all/sse` — EventSource that upgrades
/// the kernel binaries on EVERY server in one streamed pass (the "Update
/// all kernels" button). Same Sec-Fetch-Site same-origin guard + basic-
/// auth as the single-server SSE update. Best-effort across the fleet —
/// heavy lifting in `wizard_bootstrap::run_update_kernels_all`. The
/// 3-segment path avoids the `{id}` clash — same trick as
/// `deploy-all/sse`.
pub(crate) async fn servers_update_kernels_all_sse(
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
                "cross-origin update-kernels trigger refused (same-origin only)",
            );
        }
    }

    let servers = match state.inv.list_fleet_servers().await {
        Ok(s) => s,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };

    let key_path = crate::app::deploy_key_path();
    let raw = crate::wizard_bootstrap::run_update_kernels_all(
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
                target = "vpnctld::update_kernels",
                event_name = name,
                error = %e,
                "update-kernels-all SSE event serialisation failed — emitting placeholder"
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

// ────────────────────────────────────────────────────────────────────────
//  Phase 3c — Settings GeoIP «update now» SSE button.
//
//  Streams the live output of `vpnctl geoip-update` as named SSE
//  events. Auth-gated by the basic-auth middleware (same as every
//  other /admin route). One audit row per fire — provenance only,
//  no payload (the subprocess output is in journalctl).
//
//  See `crate::geoip_update_runner` for the subprocess pattern.
// ────────────────────────────────────────────────────────────────────────
