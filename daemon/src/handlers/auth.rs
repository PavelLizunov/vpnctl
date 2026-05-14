//! Basic-auth middleware for the admin UI.
//!
//! Reads expected credentials from env at startup (`VPNCTLD_ADMIN_USER`,
//! `VPNCTLD_ADMIN_PASSWORD`). When both are set, every request that
//! traverses this layer must carry `Authorization: Basic ...` matching
//! them; otherwise the layer is a no-op (useful for local smoke).
//!
//! Comparison is constant-time via `subtle` — no early-exit timing
//! oracle on the password.

use std::sync::Arc;

use axum::extract::Request;
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use base64::{Engine, engine::general_purpose::STANDARD};
use subtle::ConstantTimeEq;

#[derive(Clone)]
pub(crate) struct BasicAuth {
    pub user: Arc<String>,
    pub password: Arc<String>,
}

impl BasicAuth {
    /// Construct from env. Returns `None` if either var is missing —
    /// caller decides whether to enforce or skip the layer.
    pub(crate) fn from_env() -> Option<Self> {
        let user = std::env::var("VPNCTLD_ADMIN_USER").ok()?;
        let pw = std::env::var("VPNCTLD_ADMIN_PASSWORD").ok()?;
        if user.is_empty() || pw.is_empty() {
            return None;
        }
        Some(Self {
            user: Arc::new(user),
            password: Arc::new(pw),
        })
    }
}

pub(crate) async fn require_basic_auth(
    axum::extract::State(auth): axum::extract::State<BasicAuth>,
    req: Request,
    next: Next,
) -> Response {
    if check(&req, &auth) {
        return next.run(req).await;
    }
    // Match the `vpnctl admin: …` copy contract used by every other
    // backend response (see `handlers::admin::error_text`). Operators
    // grep `journalctl -u vpnctld` for the prefix.
    let mut resp = (StatusCode::UNAUTHORIZED, "vpnctl admin: auth required\n").into_response();
    if let Ok(hv) = HeaderValue::from_str(r#"Basic realm="vpnctl admin", charset="UTF-8""#) {
        resp.headers_mut().insert(header::WWW_AUTHENTICATE, hv);
    }
    resp
}

fn check(req: &Request, auth: &BasicAuth) -> bool {
    let Some(hv) = req.headers().get(header::AUTHORIZATION) else {
        return false;
    };
    let Ok(s) = hv.to_str() else { return false };
    let Some(b64) = s.strip_prefix("Basic ") else {
        return false;
    };
    let Ok(decoded) = STANDARD.decode(b64.trim()) else {
        return false;
    };
    let Ok(creds) = std::str::from_utf8(&decoded) else {
        return false;
    };
    let Some((u, p)) = creds.split_once(':') else {
        return false;
    };
    // Constant-time compare on BOTH user and password (never short-circuit
    // on user mismatch — that would let an attacker enumerate the user).
    let user_ok: bool = u.as_bytes().ct_eq(auth.user.as_bytes()).into();
    let pw_ok: bool = p.as_bytes().ct_eq(auth.password.as_bytes()).into();
    user_ok && pw_ok
}
