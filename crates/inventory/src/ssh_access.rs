use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SshAccessRoute {
    Direct,
    Jump,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SshAccessState {
    Available,
    Unavailable,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SshAccessFailure {
    Timeout,
    Authentication,
    HostKey,
    Connection,
    MissingKey,
    InvalidRoute,
    Stale,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshAccessCheck {
    pub state: SshAccessState,
    pub failure: Option<SshAccessFailure>,
    pub checked_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default)]
pub struct SshAccessStatus {
    pub direct: Option<SshAccessCheck>,
    pub jump: Option<SshAccessCheck>,
}
