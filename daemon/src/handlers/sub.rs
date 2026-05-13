//! `GET /sub/<token>` — opaque-token-keyed sing-box client config.
//!
//! Hiddify-style clients are pointed at this URL once and re-pull on
//! their own schedule. We resolve the token to a user, walk all servers
//! granted to that user, and emit a sing-box client JSON containing one
//! outbound per (server × protocol) plus a selector for switching.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde_json::{Value, json};
use vpnctl_core::{RenderCtx, User};

use crate::app::AppState;

pub(crate) async fn get(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> impl IntoResponse {
    match resolve(&state, &token).await {
        Ok(cfg) => (
            StatusCode::OK,
            [("content-type", "application/json")],
            cfg.to_string(),
        )
            .into_response(),
        Err(SubError::NotFound) => (StatusCode::NOT_FOUND, "unknown token\n").into_response(),
        Err(SubError::Internal(msg)) => {
            tracing::error!(target = "vpnctld::sub", error = %msg, "sub render failed");
            // Don't leak internals to the user — generic 500.
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error\n").into_response()
        }
    }
}

#[derive(Debug)]
enum SubError {
    NotFound,
    Internal(String),
}

async fn resolve(state: &AppState, token: &str) -> Result<Value, SubError> {
    let user = state
        .inv
        .find_user_by_sub_token(token)
        .await
        .map_err(|e| SubError::Internal(format!("inventory: {e}")))?
        .ok_or(SubError::NotFound)?;

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
    Ok(cfg)
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
