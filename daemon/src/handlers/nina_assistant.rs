use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{ConnectInfo, DefaultBodyLimit, FromRequest, Request, State};
use axum::http::{Extensions, HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Extension, Json, Router};
use reqwest::{Client, Url, redirect};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::client_nodes::{Identity, limits};
use crate::app::AppState;

const PATH: &str = "/api/v1/assistant/diagnose";
const OPENCODE_GO: &str = "https://opencode.ai/inference/go/openai/v1/chat/completions";
const DEEPSEEK_FLASH: &str = "deepseek-v4.1-flash";
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

pub(super) type Result<T> = std::result::Result<T, ApiError>;

#[derive(Debug)]
pub(super) enum ApiError {
    Unauthorized,
    Disabled,
    InvalidReport,
    TooLarge,
    Quota(Option<u64>),
    DiagnosisBusy,
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
            Self::DiagnosisBusy => (Status::TOO_MANY_REQUESTS, "diagnosis_busy"),
            Self::Quota(_) => (Status::TOO_MANY_REQUESTS, "quota_exceeded"),
            Self::Unavailable => (Status::SERVICE_UNAVAILABLE, "unavailable"),
            Self::Gateway => (Status::BAD_GATEWAY, "gateway_error"),
        };
        let mut response = (status, Json(json!({"error": code}))).into_response();
        let retry = match self {
            Self::DiagnosisBusy => Some(1),
            Self::Quota(retry) => retry,
            _ => None,
        };
        if let Some(retry) = retry
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

    pub(super) fn from_env(names: [&str; 3]) -> Option<Self> {
        let [url, model, path] = names.map(|name| std::env::var(name).ok());
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
            setting = names[0],
            "Assistant gateway settings are incomplete or invalid"
        );
        None
    }

    fn uses_open_code_flash(&self) -> bool {
        self.url.as_str() == OPENCODE_GO && self.model == DEEPSEEK_FLASH
    }

    fn request(&self, report: &Report) -> Result<reqwest::RequestBuilder> {
        let report = serde_json::to_string(report).map_err(|_| ApiError::InvalidReport)?;
        Ok(self.chat_request(PROMPT, &report, "NINA-Assistant/1.0"))
    }

    pub(super) fn chat_request(
        &self,
        prompt: &str,
        report: &str,
        user_agent: &str,
    ) -> reqwest::RequestBuilder {
        self.chat_request_with_limit(prompt, report, user_agent, 400)
    }

    pub(super) fn chat_request_with_limit(
        &self,
        prompt: &str,
        report: &str,
        user_agent: &str,
        max_tokens: u32,
    ) -> reqwest::RequestBuilder {
        let mut body = json!({
            "model": self.model,
            "messages": [
                {"role": "system", "content": prompt},
                {"role": "user", "content": report},
            ],
            "max_tokens": max_tokens,
            "stream": false,
        });
        let mut request = self
            .client
            .post(self.url.clone())
            .header(header::AUTHORIZATION, self.authorization.clone())
            .header(header::CONTENT_TYPE, "application/json");
        if self.url.as_str() == OPENCODE_GO {
            request = request
                .header(header::USER_AGENT, user_agent)
                .header("x-opencode-session", vpnctl_crypto::gen_uuid());
        }
        if self.uses_open_code_flash() {
            body["thinking"] = json!({"type": "disabled"});
        }
        request.body(body.to_string())
    }

    async fn explain(&self, report: &Report, credential: &str) -> Result<Value> {
        let bytes = self.complete(self.request(report)?).await?;
        self.decode_explanation(&bytes, credential)
    }

    pub(super) async fn complete(&self, request: reqwest::RequestBuilder) -> Result<Vec<u8>> {
        let mut response = request.send().await.map_err(|_| ApiError::Gateway)?;
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
        Ok(bytes)
    }

    fn decode_explanation(&self, bytes: &[u8], credential: &str) -> Result<Value> {
        let payload: Value = serde_json::from_slice(bytes).map_err(|_| ApiError::Gateway)?;
        let explanation = self.content(&payload, credential)?;
        let mut end = explanation.len().min(4096);
        while !explanation.is_char_boundary(end) {
            end -= 1;
        }
        Ok(json!({"schema": 1, "explanation": &explanation[..end]}))
    }

    pub(super) fn content<'a>(&self, payload: &'a Value, credential: &str) -> Result<&'a str> {
        if self.uses_open_code_flash() && payload["model"].as_str() != Some(DEEPSEEK_FLASH) {
            return Err(ApiError::Gateway);
        }
        let explanation = payload["choices"][0]["message"]["content"]
            .as_str()
            .ok_or(ApiError::Gateway)?
            .trim();
        if explanation.is_empty() || self.contains_secret(explanation, credential) {
            return Err(ApiError::Gateway);
        }
        Ok(explanation)
    }

    pub(super) fn contains_secret(&self, text: &str, credential: &str) -> bool {
        (credential.len() >= 8 && text.contains(credential)) || self.contains_key(text)
    }

    pub(super) fn contains_key(&self, text: &str) -> bool {
        text.contains(self.key.as_str())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod request_tests {
    use super::*;

    #[test]
    fn only_the_opencode_go_request_has_its_session_and_thinking_options() {
        let report = Report {
            schema: 1,
            state: "active".into(),
            enabled: Some(true),
            checks: Vec::new(),
        };
        let gateway = Gateway::new(OPENCODE_GO, DEEPSEEK_FLASH, "synthetic-key").unwrap();
        let first = gateway.request(&report).unwrap().build().unwrap();
        let second = gateway.request(&report).unwrap().build().unwrap();
        assert_eq!(first.headers()[header::USER_AGENT], "NINA-Assistant/1.0");
        assert_ne!(
            first.headers()["x-opencode-session"],
            second.headers()["x-opencode-session"]
        );
        let body: Value =
            serde_json::from_slice(first.body().unwrap().as_bytes().unwrap()).unwrap();
        assert_eq!(body["model"], DEEPSEEK_FLASH);
        assert_eq!(body["thinking"]["type"], "disabled");

        let other = Gateway::new(
            "https://synthetic.example/chat/completions",
            DEEPSEEK_FLASH,
            "synthetic-key",
        )
        .unwrap();
        let request = other.request(&report).unwrap().build().unwrap();
        assert!(!request.headers().contains_key("x-opencode-session"));
        let body: Value =
            serde_json::from_slice(request.body().unwrap().as_bytes().unwrap()).unwrap();
        assert!(body.get("thinking").is_none());

        let other = Gateway::new(OPENCODE_GO, "synthetic-model", "synthetic-key").unwrap();
        let request = other.request(&report).unwrap().build().unwrap();
        assert!(request.headers().contains_key("x-opencode-session"));
        let body: Value =
            serde_json::from_slice(request.body().unwrap().as_bytes().unwrap()).unwrap();
        assert!(body.get("thinking").is_none());
    }

    #[test]
    fn open_code_flash_explanations_must_identify_the_model() {
        let gateway = Gateway::new(OPENCODE_GO, DEEPSEEK_FLASH, "synthetic-key").unwrap();
        let mut response = json!({"choices":[{"message":{"content":"Explanation"}}]});
        assert!(
            gateway
                .decode_explanation(response.to_string().as_bytes(), "synthetic-subscriber")
                .is_err()
        );
        response["model"] = json!("synthetic-other-model");
        assert!(
            gateway
                .decode_explanation(response.to_string().as_bytes(), "synthetic-subscriber")
                .is_err()
        );
        response["model"] = json!(DEEPSEEK_FLASH);
        let reply = gateway
            .decode_explanation(response.to_string().as_bytes(), "synthetic-subscriber")
            .unwrap();
        assert_eq!(reply["explanation"], "Explanation");
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
    router(Gateway::from_env([
        "VPNCTLD_NINA_GATEWAY_URL",
        "VPNCTLD_NINA_GATEWAY_MODEL",
        "VPNCTLD_NINA_GATEWAY_KEY_FILE",
    ]))
}

pub(super) fn router(gateway: Option<Gateway>) -> Router<AppState> {
    configure_route(Router::new().route(PATH, post(diagnose)), gateway)
}

pub(super) fn configure_route(
    route: Router<AppState>,
    gateway: Option<Gateway>,
) -> Router<AppState> {
    route
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
    let (user_id, token) =
        authorize(&state, request.headers(), request.extensions(), b"nina:ip").await?;
    let report: Report = read_report(request, &state).await?;
    if !report.valid() {
        return Err(ApiError::InvalidReport);
    }
    let gateway = gateway.ok_or(ApiError::Unavailable)?;
    limit_account(&state, b"nina:user", &user_id)?;
    gateway.explain(&report, &token).await.map(Json)
}

pub(super) async fn authorize(
    state: &AppState,
    headers: &HeaderMap,
    extensions: &Extensions,
    ip_bucket: &[u8],
) -> Result<(String, Zeroizing<String>)> {
    let account = authorized_account(state, headers, extensions, ip_bucket).await?;
    Ok((account.id, account.presented))
}

pub(super) struct AuthorizedAccount {
    pub(super) id: String,
    pub(super) presented: Zeroizing<String>,
    pub(super) alternate: Option<Zeroizing<String>>,
}

pub(super) async fn authorized_account(
    state: &AppState,
    headers: &HeaderMap,
    extensions: &Extensions,
    ip_bucket: &[u8],
) -> Result<AuthorizedAccount> {
    if let Some(ConnectInfo(peer)) = extensions.get::<ConnectInfo<SocketAddr>>() {
        let ip = crate::real_ip::resolve_peer_real_ip(headers, peer.ip());
        limits::acquire(&state.rate_limiter, ip_bucket, &ip.to_string(), 120)
            .map_err(|retry| ApiError::Quota(Some(retry)))?;
    }
    let (identity, token) = credential(headers).ok_or(ApiError::Unauthorized)?;
    let user = identity
        .find_user(&state.inv, token)
        .await
        .map_err(|_| ApiError::Unavailable)?
        .ok_or(ApiError::Unauthorized)?;
    if user.disabled {
        return Err(ApiError::Disabled);
    }
    let alternate = match identity {
        Identity::Device => user.sub_token,
        Identity::Subscription => user.vpn_router_device_id,
    };
    Ok(AuthorizedAccount {
        id: user.id.0,
        presented: Zeroizing::new(token.to_owned()),
        alternate: alternate.map(Zeroizing::new),
    })
}

pub(super) async fn read_report<T: DeserializeOwned>(
    request: Request,
    state: &AppState,
) -> Result<T> {
    let Json(report) = Json::<T>::from_request(request, state)
        .await
        .map_err(|rejection| {
            if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
                ApiError::TooLarge
            } else {
                ApiError::InvalidReport
            }
        })?;
    Ok(report)
}

pub(super) fn limit_account(state: &AppState, bucket: &[u8], user_id: &str) -> Result<()> {
    limits::acquire(&state.rate_limiter, bucket, user_id, 6)
        .map_err(|retry| ApiError::Quota(Some(retry)))
}
