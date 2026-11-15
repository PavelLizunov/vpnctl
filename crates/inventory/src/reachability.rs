use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServicePathStatus {
    Available,
    Degraded,
    Unreachable,
    Recovering,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServicePathState {
    pub status: ServicePathStatus,
    pub vantage: String,
    pub checked_at: DateTime<Utc>,
    pub last_success_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServicePathIncident {
    pub id: i64,
    pub vantage: String,
    pub last_success_at: Option<DateTime<Utc>>,
    pub first_failure_at: DateTime<Utc>,
    pub confirmed_at: Option<DateTime<Utc>>,
    pub first_recovery_at: Option<DateTime<Utc>>,
    pub recovered_at: Option<DateTime<Utc>>,
    pub diagnostics: serde_json::Value,
}
