//! Corporate browser portal and independent company-scoped client capabilities.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::Request;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::Response;
use tower::ServiceExt;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;

pub mod diagnostics;
pub mod eligibility;
mod handlers;
mod security;
mod views;

pub use security::resolve_client_ip;

use crate::AppState;
use crate::handlers::auth::LoginThrottle;

const HOST: &str = "admin.corp.ninitux.com";
const ORIGIN: &str = "https://admin.corp.ninitux.com";
const COOKIE: &str = "__Host-vpnctl_corp";
const MAX_BODY: usize = 65_536;
const SESSION_SECONDS: i64 = 28_800;

#[derive(Clone, Debug)]
struct PortalState {
    app: AppState,
    logins: Arc<LoginThrottle>,
}

pub(crate) fn isolate(legacy: Router, app: AppState) -> Router {
    let corp = Router::new()
        .fallback(handlers::handle)
        .with_state(PortalState {
            app,
            logins: Arc::default(),
        })
        .layer(RequestBodyLimitLayer::new(MAX_BODY))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(15),
        ));
    Router::new().fallback_service(tower::service_fn(move |request: Request| {
        let legacy = legacy.clone();
        let corp = corp.clone();
        async move {
            let response = match security::corp_host(&request) {
                Ok(false) => return legacy.oneshot(request).await,
                Ok(true) => {
                    if security::ambiguous_headers(request.headers()) {
                        handlers::error(
                            StatusCode::BAD_REQUEST,
                            "Не удалось проверить запрос. Обновите страницу.",
                        )
                    } else {
                        let response = corp.oneshot(request).await?;
                        match response.status() {
                            StatusCode::PAYLOAD_TOO_LARGE => handlers::error(
                                StatusCode::PAYLOAD_TOO_LARGE,
                                "Слишком большой список правил.",
                            ),
                            StatusCode::REQUEST_TIMEOUT => handlers::error(
                                StatusCode::REQUEST_TIMEOUT,
                                "Сервер не успел ответить. Обновите список, чтобы проверить результат.",
                            ),
                            _ => response,
                        }
                    }
                }
                Err(()) => handlers::error(StatusCode::BAD_REQUEST, "Некорректный адрес запроса."),
            };
            Ok::<_, Infallible>(secure(response))
        }
    }))
}

pub(crate) fn secure(mut response: Response) -> Response {
    // Native same-origin forms need Origin; external destinations receive no referrer.
    let referrer_policy = if !response.status().is_redirection()
        && !response.headers().contains_key(header::CONTENT_DISPOSITION)
        && response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("text/html"))
    {
        "same-origin"
    } else {
        "no-referrer"
    };
    for (name, value) in [
        ("cache-control", "no-store"),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", referrer_policy),
        ("x-robots-tag", "noindex, nofollow"),
        (
            "content-security-policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'",
        ),
    ] {
        response
            .headers_mut()
            .insert(name, HeaderValue::from_static(value));
    }
    response.headers_mut().remove(header::SERVER);
    response
}
