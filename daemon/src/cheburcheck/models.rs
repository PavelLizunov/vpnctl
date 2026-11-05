use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListResult {
    pub blocked: bool,
    pub blocked_subnets: Vec<String>,
    pub providers: Vec<String>,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DynamicPhase {
    #[default]
    NotStarted,
    Running,
    Done,
    Partial,
    Unavailable,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProbeReport {
    pub region: Option<String>,
    pub provider: Option<String>,
    pub asn: Option<String>,
    pub cached: bool,
    pub verdicts: Vec<String>,
    pub target_hop: Option<u16>,
    pub dpi_hop: Option<u16>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DynamicResult {
    pub phase: DynamicPhase,
    pub online_probes: Option<u32>,
    pub reports: Vec<ProbeReport>,
}

impl DynamicResult {
    /// Count observers reporting the verdict, not repeated values in one reply.
    pub fn verdict_count(&self, verdict: &str) -> usize {
        self.reports
            .iter()
            .filter(|report| report.verdicts.iter().any(|value| value == verdict))
            .count()
    }

    pub fn not_reported(&self) -> Option<u32> {
        self.online_probes.map(|online| {
            online.saturating_sub(u32::try_from(self.reports.len()).unwrap_or(u32::MAX))
        })
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FailureCode {
    RateLimited,
    Unavailable,
    InvalidResponse,
    ResponseLimit,
    Timeout,
    NoObservers,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Failure {
    pub code: FailureCode,
    pub retry_after_secs: Option<u32>,
}

impl Failure {
    pub(super) fn new(code: FailureCode) -> Self {
        Self {
            code,
            retry_after_secs: None,
        }
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self.code {
            FailureCode::RateLimited => "external service rate limit",
            FailureCode::Unavailable => "external service unavailable",
            FailureCode::InvalidResponse => "invalid external response",
            FailureCode::ResponseLimit => "external response limit exceeded",
            FailureCode::Timeout => "external check timed out",
            FailureCode::NoObservers => "no external observers available",
        })
    }
}

impl std::error::Error for Failure {}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Report {
    pub list: Option<ListResult>,
    pub dynamic: DynamicResult,
    pub failure: Option<Failure>,
}

impl Report {
    pub(super) fn failed(failure: Failure) -> Self {
        Self {
            dynamic: DynamicResult {
                phase: DynamicPhase::Unavailable,
                ..DynamicResult::default()
            },
            failure: Some(failure),
            ..Self::default()
        }
    }
}
