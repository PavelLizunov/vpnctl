use crate::AppState;
use crate::handlers::admin::helpers::error_resp;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
/// `/usr/local/bin/vpnctl geoip-update` stdout/stderr line-by-line
/// to the browser. Each Step event carries a `stream:"stdout"` or
/// `"stderr"` field so the front-end can colour stderr lines for
/// the operator. Final Ok/Error event closes the stream.
///
/// CSRF defense: the endpoint is GET (EventSource only does GET),
/// state-changing (spawns a subprocess + writes an audit row).
/// We gate on `Sec-Fetch-Site` — modern browsers stamp it on every
/// fetch; an attacker's `<img src=…>` from a cross-site page would
/// set it to `cross-site` and get rejected here BEFORE the audit
/// or spawn. Absence (CLI / curl / very old browser) is allowed —
/// those aren't the realistic attack surface for a LAN-only
/// homelab admin.
pub(crate) async fn settings_geoip_update_now_sse(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Response {
    use axum::response::sse::{Event, KeepAlive, Sse};
    use futures_core::Stream;
    use std::pin::Pin;
    use tokio_stream::StreamExt;

    if let Some(sfs) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        // "same-origin" = EventSource from /admin/settings page,
        // "none" = direct address-bar navigation. Anything else is
        // a cross-context attach — refuse without spawning or
        // logging. (Returns the unified prefix via error_resp.)
        if sfs != "same-origin" && sfs != "none" {
            return error_resp(
                StatusCode::FORBIDDEN,
                "cross-origin request rejected — open the admin UI directly",
            );
        }
    }

    // One audit row per fire — provenance only. The actual download
    // log goes to journalctl (subprocess stderr). If the audit
    // write fails the fire still proceeds (we don't want the button
    // to mysteriously do nothing because of an unrelated audit
    // problem).
    if let Err(e) = state
        .inv
        .audit("admin", "settings.geoip.update_now.fired", None, None)
        .await
    {
        tracing::warn!(
            target = "vpnctld::admin",
            error = %e,
            "audit write failed for settings.geoip.update_now.fired — subprocess will still run"
        );
    }

    let vpnctl_bin = crate::geoip_update_runner::resolve_vpnctl_bin();
    let raw = crate::geoip_update_runner::run_update(vpnctl_bin);
    let mapped = raw.map(|ev| {
        let name = ev.event_name();
        let json = serde_json::to_string(&ev).unwrap_or_else(|e| {
            tracing::error!(
                target = "vpnctld::admin",
                event_name = name,
                error = %e,
                "geoip-update SSE event serialisation failed — emitting placeholder"
            );
            format!(
                "{{\"kind\":\"step\",\"stream\":\"stderr\",\"message\":\"daemon failed to serialise this event ({e}); please retry the action\"}}"
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
