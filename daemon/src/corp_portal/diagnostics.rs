//! Private, bounded bridge. Browser input never chooses an upstream or credential.
use std::fmt;
use std::io::Read;
use std::time::Duration;

use axum::http::{HeaderValue, StatusCode, header};
use reqwest::{Method, Url};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use zeroize::Zeroizing;

const MAX_RESPONSE: usize = 256 * 1024;

#[derive(Debug, thiserror::Error)]
#[error("corporate diagnostics configuration is unavailable")]
pub struct ConfigError;

#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    base: Url,
    bearer: HeaderValue,
    company: Option<HeaderValue>,
}
impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client").finish_non_exhaustive()
    }
}
impl Client {
    pub fn new(base_url: &str, bearer: &str) -> Result<Self, ConfigError> {
        let base = Url::parse(base_url).map_err(|_| ConfigError)?;
        let private = match base.host() {
            Some(url::Host::Ipv4(ip)) => ip.is_private() || ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => {
                ip.is_loopback()
                    || ip.is_unique_local()
                    || ip
                        .to_ipv4_mapped()
                        .is_some_and(|v4| v4.is_private() || v4.is_loopback())
            }
            _ => false,
        };
        if base.host().is_none()
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
            || !(base.scheme() == "https" || (base.scheme() == "http" && private))
            || !(32..=512).contains(&bearer.len())
            || !bearer
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-._~+/=".contains(&byte))
        {
            return Err(ConfigError);
        }
        let mut bearer =
            HeaderValue::from_str(&format!("Bearer {bearer}")).map_err(|_| ConfigError)?;
        bearer.set_sensitive(true);
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| ConfigError)?;
        Ok(Self {
            http,
            base,
            bearer,
            company: None,
        })
    }

    pub(crate) fn from_env() -> Option<Self> {
        let load = || -> Result<Self, ConfigError> {
            let base =
                std::env::var("VPNCTLD_CORP_DIAGNOSTICS_BASE_URL").map_err(|_| ConfigError)?;
            let path =
                std::env::var_os("VPNCTLD_CORP_DIAGNOSTICS_TOKEN_FILE").ok_or(ConfigError)?;
            let mut token = Zeroizing::new(String::new());
            std::fs::File::open(path)
                .map_err(|_| ConfigError)?
                .take(515)
                .read_to_string(&mut token)
                .map_err(|_| ConfigError)?;
            if token.len() > 514 {
                return Err(ConfigError);
            }
            Self::new(&base, token.trim_end_matches(['\r', '\n']))
        };
        load().ok()
    }

    pub(crate) fn for_company(&self, policy_id: &str) -> Result<Self, BridgeError> {
        if !(1..=64).contains(&policy_id.len())
            || !policy_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(BridgeError::Invalid);
        }
        let mut client = self.clone();
        client.company = Some(HeaderValue::from_str(policy_id).map_err(|_| BridgeError::Invalid)?);
        Ok(client)
    }
    async fn request<T: DeserializeOwned + Serialize>(
        &self,
        method: Method,
        suffix: &str,
        query: &[(String, String)],
    ) -> Result<T, BridgeError> {
        let expected = if method == Method::GET {
            StatusCode::OK
        } else {
            StatusCode::ACCEPTED
        };
        self.request_at(
            method,
            &format!("/internal/corp-diagnostics/reports{suffix}"),
            query,
            None,
            expected,
        )
        .await
    }
    async fn request_at<T: DeserializeOwned + Serialize>(
        &self,
        method: Method,
        path: &str,
        query: &[(String, String)],
        body: Option<&serde_json::Value>,
        expected: StatusCode,
    ) -> Result<T, BridgeError> {
        let mut url = self.base.clone();
        url.set_path(&format!("{}{path}", self.base.path().trim_end_matches('/')));
        if !query.is_empty() {
            url.query_pairs_mut()
                .extend_pairs(query.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        }
        let mut request = self
            .http
            .request(method.clone(), url)
            .header(header::AUTHORIZATION, self.bearer.clone())
            .header(header::ACCEPT, "application/json");
        if let Some(company) = &self.company {
            request = request.header("x-corp-company", company.clone());
        }
        if method == Method::POST {
            let body = match body {
                Some(value) => serde_json::to_vec(value).map_err(|_| BridgeError::Invalid)?,
                None => b"{}".to_vec(),
            };
            request = request
                .header(header::CONTENT_TYPE, "application/json")
                .body(body);
        }
        let mut response = request.send().await.map_err(|_| BridgeError::Unavailable)?;
        match response.status() {
            status if status == expected => {}
            StatusCode::NOT_FOUND => return Err(BridgeError::NotFound),
            StatusCode::BAD_REQUEST => return Err(BridgeError::Invalid),
            StatusCode::CONFLICT if method == Method::POST => return Err(BridgeError::Conflict),
            _ => return Err(BridgeError::Unavailable),
        }
        if response
            .content_length()
            .is_some_and(|size| size > MAX_RESPONSE as u64)
        {
            return Err(BridgeError::Unavailable);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| BridgeError::Unavailable)?
        {
            if body.len().saturating_add(chunk.len()) > MAX_RESPONSE {
                return Err(BridgeError::Unavailable);
            }
            body.extend_from_slice(&chunk);
        }
        let secret = self
            .bearer
            .as_bytes()
            .get(7..)
            .ok_or(BridgeError::Unavailable)?;
        if body.windows(secret.len()).any(|window| window == secret) {
            return Err(BridgeError::Unavailable);
        }
        let value: T = serde_json::from_slice(&body).map_err(|_| BridgeError::Unavailable)?;
        let projected = serde_json::to_vec(&value).map_err(|_| BridgeError::Unavailable)?;
        let origin = self.base.origin().ascii_serialization();
        if projected
            .windows(secret.len())
            .any(|window| window == secret)
            || projected
                .windows(origin.len())
                .any(|window| window == origin.as_bytes())
        {
            return Err(BridgeError::Unavailable);
        }
        Ok(value)
    }
    pub(crate) async fn provision(
        &self,
        policy_id: &str,
        label: &str,
    ) -> Result<ProvisionedSupport, BridgeError> {
        self.for_company(policy_id)?;
        if label.is_empty() || label.chars().count() > 128 || label.chars().any(char::is_control) {
            return Err(BridgeError::Invalid);
        }
        let mut root = self.clone();
        root.company = None;
        let result: ProvisionedSupport = root
            .request_at(
                Method::POST,
                "/internal/corp-companies/provision",
                &[],
                Some(&serde_json::json!({"policy_id":policy_id,"label":label})),
                StatusCode::OK,
            )
            .await?;
        let endpoint =
            Url::parse(&result.support.endpoint).map_err(|_| BridgeError::Unavailable)?;
        if result.schema != 1
            || result.policy_id != policy_id
            || endpoint.scheme() != "https"
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || !(32..=512).contains(&result.support.token.len())
            || !result
                .support
                .token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~+/=".contains(&b))
        {
            return Err(BridgeError::Unavailable);
        }
        Ok(result)
    }
    pub(super) async fn list(&self, query: &[(String, String)]) -> Result<List, BridgeError> {
        let list: List = self.request(Method::GET, "", query).await?;
        if list.schema != 1
            || list.reports.len() > 100
            || list.reports.iter().any(|r| !r.valid())
            || list.next_cursor.as_deref().is_some_and(|id| !valid_id(id))
        {
            return Err(BridgeError::Unavailable);
        }
        Ok(list)
    }
    pub(super) async fn detail(&self, id: &str) -> Result<Detail, BridgeError> {
        let detail: Detail = self.request(Method::GET, &format!("/{id}"), &[]).await?;
        if detail.schema != 1
            || detail.report.report_id != id
            || !detail.report.valid()
            || detail.analysis.as_ref().is_some_and(|a| {
                !a.valid() || !serde_json::to_vec(a).is_ok_and(|v| v.len() <= 24 * 1024)
            })
            || detail.provenance.as_ref().is_some_and(|p| !p.valid())
        {
            return Err(BridgeError::Unavailable);
        }
        Ok(detail)
    }
    pub(super) async fn retry(&self, id: &str) -> Result<Retry, BridgeError> {
        let retry: Retry = self
            .request(Method::POST, &format!("/{id}/retry"), &[])
            .await?;
        if retry.schema != 1 || retry.state != "pending" {
            return Err(BridgeError::Unavailable);
        }
        Ok(retry)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SupportConfig {
    pub endpoint: String,
    pub token: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProvisionedSupport {
    pub schema: u8,
    pub policy_id: String,
    pub support: SupportConfig,
}

pub(crate) enum BridgeError {
    Unavailable,
    NotFound,
    Invalid,
    Conflict,
}
pub(super) fn valid_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn plain(value: &str, limit: usize) -> bool {
    value.chars().count() <= limit
        && !value.chars().any(|c| {
            c.is_control()
                || matches!(c,
            '\u{00ad}' | '\u{061c}' | '\u{180e}' | '\u{200b}'..='\u{200f}' |
            '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{206f}' | '\u{feff}' |
            '\u{fff9}'..='\u{fffb}' | '\u{e0001}' | '\u{e0020}'..='\u{e007f}')
        })
}
#[derive(Deserialize, Serialize)]
pub(super) struct Summary {
    report_id: String,
    received_utc: String,
    bytes: u64,
    device_label: Option<String>,
    analysis_state: String,
    verdict: Option<String>,
    summary_ru: Option<String>,
    model: Option<String>,
    updated_utc: Option<String>,
}
impl Summary {
    fn valid(&self) -> bool {
        valid_id(&self.report_id)
            && plain(&self.received_utc, 80)
            && self.device_label.as_ref().is_none_or(|s| plain(s, 256))
            && matches!(
                self.analysis_state.as_str(),
                "received" | "pending" | "running" | "ready" | "failed" | "unavailable"
            )
            && self.verdict.as_deref().is_none_or(valid_verdict)
            && self.summary_ru.as_ref().is_none_or(|s| plain(s, 2000))
            && self.model.as_ref().is_none_or(|s| plain(s, 256))
            && self.updated_utc.as_ref().is_none_or(|s| plain(s, 80))
    }
}
fn valid_verdict(s: &str) -> bool {
    matches!(
        s,
        "problem_found" | "no_problem_evidenced" | "insufficient_data"
    )
}
#[derive(Deserialize, Serialize)]
pub(super) struct List {
    schema: u8,
    reports: Vec<Summary>,
    next_cursor: Option<String>,
}
#[derive(Deserialize, Serialize)]
pub(super) struct Detail {
    schema: u8,
    report: Summary,
    analysis: Option<Analysis>,
    provenance: Option<Provenance>,
}
#[derive(Deserialize, Serialize)]
pub(super) struct Retry {
    schema: u8,
    state: String,
}
#[derive(Deserialize, Serialize)]
struct Analysis {
    schema: String,
    assessments: Vec<Assessment>,
    confirmed: Vec<Finding>,
    probable: Vec<Finding>,
    unknown: Vec<Finding>,
    chronology: Vec<Chronology>,
    owner_explanation: String,
    next_steps_ru: Vec<String>,
    public_analysis: PublicAnalysis,
}
impl Analysis {
    fn valid(&self) -> bool {
        self.schema == "corp-diagnosis/1"
            && self.assessments.len() <= 4
            && self.assessments.iter().all(|a| {
                matches!(
                    a.scope.as_str(),
                    "update_delivery" | "client_runtime" | "tunnel_and_policy" | "evidence_quality"
                ) && valid_verdict(&a.verdict)
                    && matches!(a.confidence.as_str(), "high" | "medium" | "low")
                    && matches!(a.time_scope.as_str(), "current" | "unknown")
                    && plain(&a.explanation_ru, 2000)
                    && valid_evidence(&a.evidence)
            })
            && [&self.confirmed, &self.probable, &self.unknown]
                .iter()
                .all(|list| {
                    list.len() <= 32
                        && list.iter().all(|f| {
                            plain(&f.statement, 2000)
                                && matches!(
                                    f.time_scope.as_str(),
                                    "current" | "historical" | "unknown"
                                )
                                && valid_evidence(&f.evidence)
                        })
                })
            && self.chronology.len() <= 32
            && self
                .chronology
                .iter()
                .all(|c| plain(&c.statement, 2000) && valid_evidence(&c.evidence))
            && plain(&self.owner_explanation, 2000)
            && self.next_steps_ru.len() <= 3
            && self.next_steps_ru.iter().all(|s| plain(s, 1000))
            && self.public_analysis.valid()
    }
}
#[derive(Deserialize, Serialize)]
struct Assessment {
    scope: String,
    verdict: String,
    confidence: String,
    time_scope: String,
    explanation_ru: String,
    evidence: Vec<Evidence>,
}
#[derive(Deserialize, Serialize)]
struct Finding {
    statement: String,
    time_scope: String,
    evidence: Vec<Evidence>,
}
#[derive(Deserialize, Serialize)]
struct Chronology {
    statement: String,
    evidence: Vec<Evidence>,
}
#[derive(Deserialize, Serialize)]
#[serde(tag = "kind")]
enum Evidence {
    #[serde(rename = "log")]
    Log { file: String, line: u64 },
    #[serde(rename = "operator_fact")]
    OperatorFact { field: String },
    #[serde(rename = "packet")]
    Packet { field: String },
}
fn valid_evidence(evidence: &[Evidence]) -> bool {
    evidence.len() <= 64
        && evidence.iter().all(|e| match e {
            Evidence::Log { file, line } => {
                *line > 0
                    && plain(file, 128)
                    && !file.contains(['/', '\\', ':'])
                    && !file.contains("..")
            }
            Evidence::OperatorFact { field } | Evidence::Packet { field } => plain(field, 256),
        })
}
#[derive(Deserialize, Serialize)]
struct PublicAnalysis {
    version: u8,
    state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    message_ru: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message_en: Option<String>,
}
#[derive(Deserialize, Serialize)]
struct Provenance {
    requested_model: Option<String>,
    returned_model: Option<String>,
    prompt_sha256: Option<String>,
    input_sha256: Option<String>,
    run_id: Option<String>,
    started_utc: Option<String>,
    completed_utc: Option<String>,
    prompt_version: Option<String>,
    status: Option<String>,
}

impl Provenance {
    fn valid(&self) -> bool {
        [&self.requested_model, &self.returned_model]
            .iter()
            .all(|value| value.as_ref().is_none_or(|s| plain(s, 256)))
            && [&self.prompt_sha256, &self.input_sha256]
                .iter()
                .all(|value| value.as_deref().is_none_or(valid_id))
            && [&self.started_utc, &self.completed_utc]
                .iter()
                .all(|value| value.as_ref().is_none_or(|s| plain(s, 80)))
            && [&self.run_id, &self.prompt_version, &self.status]
                .iter()
                .all(|value| value.as_ref().is_none_or(|s| plain(s, 128)))
    }
}

impl PublicAnalysis {
    fn valid(&self) -> bool {
        self.version == 1
            && matches!(self.state.as_str(), "pending" | "ready" | "unavailable")
            && [&self.message_ru, &self.message_en].iter().all(|value| {
                value.as_ref().is_none_or(|text| {
                    !text.is_empty() && plain(text, 300) && text.encode_utf16().count() <= 300
                })
            })
            && (self.state != "ready" || self.message_ru.is_some() || self.message_en.is_some())
    }
}
