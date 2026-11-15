use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;

use reqwest::header::{ACCEPT, RETRY_AFTER};
use reqwest::{Response, StatusCode, Url};
use serde::Deserialize;

use super::{
    DynamicPhase, Failure, FailureCode, ListResult, MAX_CONTEXT_BYTES, MAX_REPORTS, MAX_SSE_BYTES,
    MAX_STATIC_BYTES, MAX_TEXT_BYTES, ProbeAccumulator, Report, SseDecoder,
};

const PUBLIC_BASE_URL: &str = "https://cheburcheck.ru/";

#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    base_url: Url,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Client")
            .field("base_url", &self.base_url.as_str())
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
struct Lookup {
    target: String,
    blocked: bool,
    id: Option<String>,
    #[serde(default)]
    blocked_subnets: Vec<String>,
    #[serde(default)]
    cdn_providers: BTreeMap<String, serde_json::Value>,
}

impl Client {
    pub fn new() -> Result<Self, Failure> {
        Self::for_base_url(PUBLIC_BASE_URL)
    }

    pub fn for_base_url(base_url: &str) -> Result<Self, Failure> {
        let url = Url::parse(base_url).map_err(|_| Failure::new(FailureCode::InvalidResponse))?;
        let host = url.host_str().unwrap_or_default();
        let host_ip = host.trim_matches(['[', ']']).parse::<IpAddr>().ok();
        let loopback = host == "localhost" || host_ip.is_some_and(|ip| ip.is_loopback());
        let raw_authority_and_path = base_url
            .split_once("://")
            .map(|(_, rest)| rest)
            .unwrap_or_default();
        let authority = raw_authority_and_path
            .split(['/', '?', '#'])
            .next()
            .unwrap_or_default();
        let raw_path = &raw_authority_and_path[authority.len()..];
        if !(url.scheme() == "https" || url.scheme() == "http" && loopback)
            || !url.username().is_empty()
            || url.password().is_some()
            || authority.contains('@')
            || authority.contains('\\')
            || !matches!(raw_path, "" | "/")
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
            || host.is_empty()
        {
            return Err(Failure::new(FailureCode::InvalidResponse));
        }
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(65))
            .user_agent("vpnctl-cheburcheck/1.0");
        if loopback {
            builder = builder.no_proxy();
        }
        let http = builder
            .build()
            .map_err(|_| Failure::new(FailureCode::Unavailable))?;
        Ok(Self {
            http,
            base_url: url,
        })
    }

    pub async fn check(&self, address: IpAddr) -> Report {
        let (list, context) = match self.lookup(address).await {
            Ok(value) => value,
            Err(failure) => return Report::failed(failure),
        };
        let mut report = Report {
            list: Some(list),
            ..Report::default()
        };
        let context = match context {
            Some(context)
                if !matches!(context.as_str(), "" | "." | "..")
                    && context.len() <= MAX_CONTEXT_BYTES =>
            {
                context
            }
            Some(context) if context.len() > MAX_CONTEXT_BYTES => {
                set_dynamic_failure(&mut report, Failure::new(FailureCode::ResponseLimit));
                return report;
            }
            _ => {
                set_dynamic_failure(&mut report, Failure::new(FailureCode::InvalidResponse));
                return report;
            }
        };
        let mut accumulator = ProbeAccumulator::new();
        let outcome = self.probe(&context, &mut accumulator).await;
        report.dynamic = accumulator.snapshot();
        if let Err(failure) = outcome {
            set_dynamic_failure(&mut report, failure);
        }
        report
    }

    async fn lookup(&self, address: IpAddr) -> Result<(ListResult, Option<String>), Failure> {
        let mut url = self.base_url.clone();
        url.set_path("/api/v1/check");
        url.query_pairs_mut()
            .append_pair("target", &address.to_string());
        let response = self
            .http
            .get(url)
            .header(ACCEPT, "application/json")
            .timeout(Duration::from_secs(12))
            .send()
            .await
            .map_err(|error| network_failure(&error))?;
        let response = successful(response)?;
        let bytes = read_bounded(response, MAX_STATIC_BYTES).await?;
        let lookup: Lookup = serde_json::from_slice(&bytes)
            .map_err(|_| Failure::new(FailureCode::InvalidResponse))?;
        if lookup.target.parse::<IpAddr>().ok() != Some(address) {
            return Err(Failure::new(FailureCode::InvalidResponse));
        }
        if lookup.blocked_subnets.len() > MAX_REPORTS
            || lookup.cdn_providers.len() > MAX_REPORTS
            || lookup
                .blocked_subnets
                .iter()
                .chain(lookup.cdn_providers.keys())
                .any(|value| value.len() > MAX_TEXT_BYTES)
        {
            return Err(Failure::new(FailureCode::ResponseLimit));
        }
        Ok((
            ListResult {
                blocked: lookup.blocked,
                blocked_subnets: lookup.blocked_subnets,
                providers: lookup.cdn_providers.into_keys().collect(),
            },
            lookup.id,
        ))
    }

    async fn probe(
        &self,
        context: &str,
        accumulator: &mut ProbeAccumulator,
    ) -> Result<(), Failure> {
        let mut url = self.base_url.clone();
        url.set_path(&format!(
            "/api/v1/probe/{}",
            crate::http_util::path_segment_encode(context)
        ));
        let response = self
            .http
            .get(url)
            .header(ACCEPT, "text/event-stream")
            .send()
            .await
            .map_err(|error| network_failure(&error))?;
        let mut response = successful(response)?;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_SSE_BYTES as u64)
        {
            return Err(Failure::new(FailureCode::ResponseLimit));
        }
        let mut decoder = SseDecoder::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| network_failure(&error))?
        {
            // Apply completed frames before a later malformed line in the same
            // HTTP chunk so a failure retains observations already received.
            for line in chunk.split_inclusive(|byte| *byte == b'\n') {
                for event in decoder.push(line)? {
                    if accumulator.apply(&event.event, &event.data)? {
                        return Ok(());
                    }
                }
            }
        }
        Err(Failure::new(FailureCode::InvalidResponse))
    }
}

fn set_dynamic_failure(report: &mut Report, failure: Failure) {
    report.dynamic.phase = if report.dynamic.reports.is_empty() {
        DynamicPhase::Unavailable
    } else {
        DynamicPhase::Partial
    };
    report.failure = Some(failure);
}

fn successful(response: Response) -> Result<Response, Failure> {
    if response.status().is_success() {
        return Ok(response);
    }
    if response.status() == StatusCode::TOO_MANY_REQUESTS {
        let retry_after_secs = response
            .headers()
            .get(RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(retry_after)
            .unwrap_or(60)
            .clamp(1, 3600);
        return Err(Failure {
            code: FailureCode::RateLimited,
            retry_after_secs: Some(retry_after_secs as u32),
        });
    }
    Err(Failure::new(FailureCode::Unavailable))
}

fn retry_after(value: &str) -> Option<u64> {
    if let Ok(seconds) = value.trim().parse() {
        return Some(seconds);
    }
    let deadline = chrono::DateTime::parse_from_rfc2822(value).ok()?;
    let seconds = (deadline.with_timezone(&chrono::Utc) - chrono::Utc::now()).num_seconds();
    Some(u64::try_from(seconds).unwrap_or(0))
}

async fn read_bounded(mut response: Response, limit: usize) -> Result<Vec<u8>, Failure> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(Failure::new(FailureCode::ResponseLimit));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| network_failure(&error))?
    {
        if chunk.len() > limit.saturating_sub(bytes.len()) {
            return Err(Failure::new(FailureCode::ResponseLimit));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn network_failure(error: &reqwest::Error) -> Failure {
    Failure::new(if error.is_timeout() {
        FailureCode::Timeout
    } else {
        FailureCode::Unavailable
    })
}
