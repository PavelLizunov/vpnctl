//! `GET /sub/<token>` — opaque-token-keyed sing-box client config.
//!
//! Hiddify-style clients are pointed at this URL once and re-pull on
//! their own schedule. We resolve the token to a user, walk all servers
//! granted to that user, and emit a sing-box client JSON containing one
//! outbound per (server × protocol) plus a selector for switching.
//!
//! Phase Track-1 hook: every successful resolve (200) writes one row
//! into `sub_access_log` so the admin can see "how many distinct IPs
//! are pulling THIS user's URL". Failed resolves (404 unknown token)
//! are deliberately NOT logged — we don't want a probing attacker to
//! be able to fill the table by spamming garbage tokens.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::extract::{ConnectInfo, Path, Request, State};
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use serde_json::{Value, json};
use vpnctl_core::{RenderCtx, User, UserId};

use crate::app::AppState;

/// One-shot flag: true once we've already warned about a missing
/// `ConnectInfo` extension. Without this flag a misconfigured daemon
/// would spam the journal with one warn per request — once is enough
/// for the operator to notice. Resets on daemon restart, which is what
/// we want (a fresh warn after a deploy that re-broke the wiring).
static WARNED_MISSING_CONNECT_INFO: AtomicBool = AtomicBool::new(false);

pub(crate) async fn get(
    State(state): State<AppState>,
    Path(token): Path<String>,
    // The Request extractor must come last (it owns the body). We pull
    // headers + ConnectInfo from it manually so the handler works both
    // in production (where `into_make_service_with_connect_info` injects
    // ConnectInfo as a request extension) and in `tower::ServiceExt::
    // oneshot` test rigs (where no make-service ran and the extension is
    // absent — falls back to `0.0.0.0` so the access log row still lands
    // and downstream tests can assert the write happened).
    request: Request,
) -> impl IntoResponse {
    let ua = request
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    // IP only, port stripped — the port rotates per connection and would
    // explode the cardinality of "distinct IPs". Both v4 and v6 land as
    // `IpAddr::to_string()` (192.0.2.1 / fe80::1) — same shape SQLite
    // can index without a separate column.
    let peer_ip: Option<std::net::IpAddr> = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip());
    let ip = match peer_ip {
        Some(addr) => addr.to_string(),
        None => {
            // Production rigs MUST install ConnectInfo via
            // `into_make_service_with_connect_info::<SocketAddr>()`. If
            // the extension is missing, every access-log row will land
            // with `0.0.0.0` and the abuse-signal counters silently
            // collapse all clients to one bucket. Warn once per process
            // so the operator notices in journalctl. Test rigs (oneshot
            // Service::call) deliberately don't install ConnectInfo;
            // there the warn is a benign single line.
            if !WARNED_MISSING_CONNECT_INFO.swap(true, Ordering::Relaxed) {
                tracing::warn!(
                    target = "vpnctld::sub",
                    "ConnectInfo extension absent — sub_access_log will record 0.0.0.0 for every hit \
                     until make-service is fixed; this kills the abuse-signal accuracy"
                );
            }
            "0.0.0.0".to_string()
        }
    };

    // Phase Track-2 rate limit: per-IP gate runs FIRST, BEFORE the
    // token is resolved. This way unknown-token probing also gets
    // throttled (a probing attacker can't keep hitting random tokens
    // for free). Per-token gate runs AFTER the token resolves to
    // bound the by_token map size by the user count, not by attacker
    // creativity. Both gates issue HTTP 429 with `Retry-After`.
    if let Some(addr) = peer_ip {
        if let Err(retry) = state.rate_limiter.try_acquire_ip(addr) {
            return rate_limited(retry, "ip");
        }
    }

    match resolve(&state, &token).await {
        Ok((user_id, cfg)) => {
            // Per-token gate runs only on successful resolve so the
            // by_token map is bounded by user count.
            if let Err(retry) = state.rate_limiter.try_acquire_token(&token) {
                return rate_limited(retry, "token");
            }

            let body = cfg.to_string();
            // 32-bit defensive — `body.len()` is `usize`; on a 32-bit
            // build `as u64` would silently truncate if it ever exceeded
            // 4 GiB (impossible for a sub-config, but the same defensive
            // cast pattern is used in `log_sub_access` for the bytes
            // bind, so keep symmetry).
            let bytes = u64::try_from(body.len()).unwrap_or(u64::MAX);

            // Bounded back-pressure (audit-fix Plan B / retroactive
            // review #3 / security #2): hand the record to the
            // dedicated writer task via a non-blocking `try_send`.
            // Channel-full → record dropped + warn-log; channel-closed
            // → error-log (writer crashed). Either way the HTTP
            // response stays 200 — we never block on the log write
            // and we never spawn an unbounded number of tasks. See
            // `crate::access_log` module docs for the full rationale.
            let _ = crate::access_log::try_enqueue(
                &state.access_log_tx,
                crate::access_log::AccessLogRecord {
                    user_id,
                    ip,
                    ua,
                    status: 200,
                    bytes,
                },
            );

            (StatusCode::OK, [("content-type", "application/json")], body).into_response()
        }
        Err(SubError::NotFound) => (StatusCode::NOT_FOUND, "unknown token\n").into_response(),
        Err(SubError::Internal(msg)) => {
            tracing::error!(target = "vpnctld::sub", error = %msg, "sub render failed");
            // Don't leak internals to the user — generic 500.
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error\n").into_response()
        }
    }
}

/// Build the 429 response with `Retry-After` (seconds). The `gate`
/// argument identifies which axis (ip / token) tripped — it ends up
/// in the response body so an operator running curl during incident
/// response can tell whether they're hitting their own per-IP limit
/// (legit traffic) or a per-token limit (URL-shared scenario).
fn rate_limited(retry_after_secs: u64, gate: &'static str) -> axum::response::Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [
            ("retry-after", retry_after_secs.to_string()),
            ("content-type", "text/plain; charset=utf-8".to_string()),
        ],
        format!("rate limited ({gate}); retry in {retry_after_secs}s\n"),
    )
        .into_response()
}

#[derive(Debug)]
enum SubError {
    NotFound,
    Internal(String),
}

async fn resolve(state: &AppState, token: &str) -> Result<(UserId, Value), SubError> {
    let user = state
        .inv
        .find_user_by_sub_token(token)
        .await
        .map_err(|e| SubError::Internal(format!("inventory: {e}")))?
        .ok_or(SubError::NotFound)?;
    let user_id = user.id.clone();

    let servers = state
        .inv
        .servers_for_user(&user.id)
        .await
        .map_err(|e| SubError::Internal(format!("inventory: {e}")))?;

    let mut outbounds: Vec<Value> = Vec::new();
    let mut tags: Vec<String> = Vec::new();

    for server in &servers {
        let secrets = state
            .inv
            .list_server_secrets(&server.id)
            .await
            .map_err(|e| SubError::Internal(format!("inventory: {e}")))?;
        let ctx = RenderCtx::new(server, &secrets);

        for pid in &server.enabled_protocols {
            let Some(proto) = state.registry.protocol(pid) else {
                tracing::warn!(
                    target = "vpnctld::sub",
                    protocol = %pid,
                    "protocol not registered, skipping"
                );
                continue;
            };
            match proto.client_config(&ctx, &user) {
                Ok(mut value) => {
                    let tag = format!("{}-{}", server.id.0, pid.0);
                    if let Some(obj) = value.as_object_mut() {
                        obj.insert("tag".into(), json!(tag));
                    }
                    outbounds.push(value);
                    tags.push(tag);
                }
                Err(e) => {
                    tracing::warn!(
                        target = "vpnctld::sub",
                        server = %server.id,
                        protocol = %pid,
                        error = %e,
                        "client_config failed, skipping"
                    );
                }
            }
        }
    }

    let cfg = build_client_envelope(&user, outbounds, &tags);
    Ok((user_id, cfg))
}

/// Wrap the per-server outbounds in a minimal sing-box client envelope:
/// a `selector` lets the user pick a route in the UI, plus the standard
/// `direct` / `block` outbounds.
fn build_client_envelope(_user: &User, mut outbounds: Vec<Value>, tags: &[String]) -> Value {
    if !tags.is_empty() {
        let selector_outbounds: Vec<Value> = tags.iter().map(|t| json!(t)).collect();
        outbounds.insert(
            0,
            json!({
                "type": "selector",
                "tag": "proxy",
                "outbounds": selector_outbounds,
                "default": tags.first(),
            }),
        );
    }
    outbounds.push(json!({ "type": "direct", "tag": "direct" }));
    outbounds.push(json!({ "type": "block",  "tag": "block"  }));

    json!({
        "log": { "level": "info", "timestamp": true },
        "outbounds": outbounds,
        "route": {
            "rules": [
                { "protocol": "dns", "outbound": "direct" }
            ],
            "final": "proxy",
            "auto_detect_interface": true
        }
    })
}
