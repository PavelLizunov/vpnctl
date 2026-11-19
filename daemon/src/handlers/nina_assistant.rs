use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{ConnectInfo, DefaultBodyLimit, FromRequest, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Extension, Json, Router};
use reqwest::{Client, Url, redirect};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::client_nodes::{Identity, limits};
use crate::app::AppState;

const PATH: &str = "/api/v1/assistant/diagnose";
const UPSTREAM_LIMIT: usize = 32 * 1024;
const CHECK_IDS: [&str; 6] = [
    "dns.youtube",
    "dns.discord",
    "dns.control",
    "https.youtube",
    "https.discord",
    "public_ipv4",
];
const PROMPT: &str = "Ты помощник NINA. Объясни по-русски результаты локальной диагностики сети. Укажи, что удалось проверить, и предложи один безопасный следующий шаг при наличии ошибки. Отвечай кратко обычным текстом. Успешный HTTPS-запрос к сайту не подтверждает работу видео или голоса. Не утверждай, что знаешь причину сбоя, если отчёт её не показывает.";

type Result<T> = std::result::Result<T, ApiError>;

enum ApiError {
    Unauthorized,
    Disabled,
    InvalidReport,
    TooLarge,
    Quota(Option<u64>),
    Unavailable,
    Gateway,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        use StatusCode as Status;
        let (status, code) = match self {
            Self::Unauthorized => (Status::UNAUTHORIZED, "unauthorized"),
            Self::Disabled => (Status::FORBIDDEN, "subscription_disabled"),
            Self::InvalidReport => (Status::BAD_REQUEST, "invalid_report"),
            Self::TooLarge => (Status::PAYLOAD_TOO_LARGE, "report_too_large"),
            Self::Quota(_) => (Status::TOO_MANY_REQUESTS, "quota_exceeded"),
            Self::Unavailable => (Status::SERVICE_UNAVAILABLE, "unavailable"),
            Self::Gateway => (Status::BAD_GATEWAY, "gateway_error"),
        };
        let mut response = (status, Json(json!({"error": code}))).into_response();
        if let Self::Quota(Some(retry)) = self
            && let Ok(retry) = header::HeaderValue::from_str(&retry.to_string())
        {
            response.headers_mut().insert(header::RETRY_AFTER, retry);
        }
        response
    }
}

pub(super) struct Gateway {
    client: Client,
    url: Url,
    model: String,
    authorization: header::HeaderValue,
    key: Zeroizing<String>,
}

impl Gateway {
    pub(super) fn new(endpoint: &str, model: &str, key: &str) -> anyhow::Result<Self> {
        let url = Url::parse(endpoint)?;
        let loopback = matches!(url.host_str(), Some("127.0.0.1" | "[::1]"));
        anyhow::ensure!(
            (url.scheme() == "https" || (url.scheme() == "http" && loopback))
                && url.host().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none(),
            "invalid NINA gateway URL"
        );
        anyhow::ensure!(
            !model.is_empty() && model.len() <= 128 && model.bytes().all(|b| b.is_ascii_graphic()),
            "invalid NINA gateway model"
        );
        anyhow::ensure!(
            !key.is_empty() && key.len() <= 512 && key.bytes().all(|b| b.is_ascii_graphic()),
            "invalid NINA gateway key"
        );
        let value = Zeroizing::new(format!("Bearer {key}"));
        let mut authorization = header::HeaderValue::from_str(&value)?;
        authorization.set_sensitive(true);
        let client = Client::builder()
            .no_proxy()
            .redirect(redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(12))
            .build()?;
        Ok(Self {
            client,
            url,
            model: model.to_owned(),
            authorization,
            key: Zeroizing::new(key.to_owned()),
        })
    }

    fn from_env() -> Option<Self> {
        let endpoint = [
            "VPNCTLD_NINA_GATEWAY_URL",
            "VPNCTLD_NINA_GATEWAY_MODEL",
            "VPNCTLD_NINA_GATEWAY_KEY_FILE",
        ]
        .map(|name| std::env::var(name).ok());
        let [url, model, path] = endpoint;
        if url.is_none() && model.is_none() && path.is_none() {
            return None;
        }
        if let (Some(url), Some(model), Some(path)) = (url, model, path)
            && let Ok(key) = std::fs::read_to_string(path)
        {
            let key = Zeroizing::new(key);
            if let Ok(gateway) = Self::new(&url, &model, key.trim()) {
                return Some(gateway);
            }
        }
        tracing::warn!(
            "NINA assistant disabled because its gateway settings are incomplete or invalid"
        );
        None
    }

    async fn explain(&self, report: &Report, credential: &str) -> Result<Value> {
        let report = serde_json::to_string(report).map_err(|_| ApiError::InvalidReport)?;
        let request = json!({
            "model": self.model,
            "messages": [
                {"role": "system", "content": PROMPT},
                {"role": "user", "content": report},
            ],
            "max_tokens": 400,
            "stream": false,
        });
        let mut response = self
            .client
            .post(self.url.clone())
            .header(header::AUTHORIZATION, self.authorization.clone())
            .header(header::CONTENT_TYPE, "application/json")
            .body(request.to_string())
            .send()
            .await
            .map_err(|_| ApiError::Gateway)?;
        if response.status() == StatusCode::TOO_MANY_REQUESTS {
            return Err(ApiError::Quota(None));
        }
        if response.status() != StatusCode::OK {
            return Err(ApiError::Gateway);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| ApiError::Gateway)? {
            if chunk.len() > UPSTREAM_LIMIT - bytes.len() {
                return Err(ApiError::Gateway);
            }
            bytes.extend_from_slice(&chunk);
        }
        let payload: Value = serde_json::from_slice(&bytes).map_err(|_| ApiError::Gateway)?;
        let explanation = payload["choices"][0]["message"]["content"]
            .as_str()
            .ok_or(ApiError::Gateway)?
            .trim();
        if explanation.is_empty()
            || (credential.len() >= 8 && explanation.contains(credential))
            || explanation.contains(self.key.as_str())
        {
            return Err(ApiError::Gateway);
        }
        let mut end = explanation.len().min(4096);
        while !explanation.is_char_boundary(end) {
            end -= 1;
        }
        Ok(json!({"schema": 1, "explanation": &explanation[..end]}))
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Report {
    schema: u32,
    state: String,
    #[serde(deserialize_with = "Deserialize::deserialize")]
    enabled: Option<bool>,
    checks: Vec<Check>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Check {
    id: String,
    ok: bool,
}

impl Report {
    fn valid(&self) -> bool {
        self.schema == 1
            && matches!(
                self.state.as_str(),
                "active"
                    | "inactive"
                    | "activating"
                    | "deactivating"
                    | "failed"
                    | "missing"
                    | "unknown"
            )
            && self.checks.len() == CHECK_IDS.len()
            && CHECK_IDS
                .iter()
                .all(|id| self.checks.iter().any(|check| check.id == *id))
    }
}

pub(crate) fn from_env() -> Router<AppState> {
    router(Gateway::from_env())
}

pub(super) fn router(gateway: Option<Gateway>) -> Router<AppState> {
    Router::new()
        .route(PATH, post(diagnose))
        .layer(Extension(gateway.map(Arc::new)))
        .layer(DefaultBodyLimit::max(2048))
        .layer(
            tower_http::set_header::SetResponseHeaderLayer::if_not_present(
                header::CACHE_CONTROL,
                header::HeaderValue::from_static("no-store"),
            ),
        )
}

fn header_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let all = headers.get_all(name);
    let mut values = all.iter();
    let value = values.next()?.to_str().ok()?;
    values.next().is_none().then_some(value)
}

fn credential(headers: &HeaderMap) -> Option<(Identity, &str)> {
    let identity = match header_value(headers, "x-vpnctl-identity")? {
        "subscription" => Identity::Subscription,
        "device" => Identity::Device,
        _ => return None,
    };
    let (scheme, token) = header_value(headers, "authorization")?.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer") && identity.valid(token)).then_some((identity, token))
}

async fn diagnose(
    State(state): State<AppState>,
    Extension(gateway): Extension<Option<Arc<Gateway>>>,
    request: Request,
) -> Result<Json<Value>> {
    if let Some(ConnectInfo(peer)) = request.extensions().get::<ConnectInfo<SocketAddr>>() {
        let ip = crate::real_ip::resolve_peer_real_ip(request.headers(), peer.ip());
        limits::acquire(&state.rate_limiter, b"nina:ip", &ip.to_string(), 120)
            .map_err(|retry| ApiError::Quota(Some(retry)))?;
    }
    let (identity, token) = credential(request.headers()).ok_or(ApiError::Unauthorized)?;
    let user = identity
        .find_user(&state.inv, token)
        .await
        .map_err(|_| ApiError::Unavailable)?
        .ok_or(ApiError::Unauthorized)?;
    if user.disabled {
        return Err(ApiError::Disabled);
    }
    let token = Zeroizing::new(token.to_owned());
    let Json(report) = Json::<Report>::from_request(request, &state)
        .await
        .map_err(|rejection| {
            if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
                ApiError::TooLarge
            } else {
                ApiError::InvalidReport
            }
        })?;
    if !report.valid() {
        return Err(ApiError::InvalidReport);
    }
    let gateway = gateway.ok_or(ApiError::Unavailable)?;
    limits::acquire(&state.rate_limiter, b"nina:user", &user.id.0, 6)
        .map_err(|retry| ApiError::Quota(Some(retry)))?;
    gateway.explain(&report, &token).await.map(Json)
}
