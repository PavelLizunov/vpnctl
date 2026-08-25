use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use vpnctl_core::{ProtocolId, ServerId};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AssuranceStage {
    Render,
    ServerConfig,
    Listener,
    ExternalPath,
    ClientImport,
    Handshake,
    Transfer,
}

impl AssuranceStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Render => "render",
            Self::ServerConfig => "server_config",
            Self::Listener => "listener",
            Self::ExternalPath => "external_path",
            Self::ClientImport => "client_import",
            Self::Handshake => "handshake",
            Self::Transfer => "transfer",
        }
    }
}

impl std::str::FromStr for AssuranceStage {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "render" => Ok(Self::Render),
            "server_config" => Ok(Self::ServerConfig),
            "listener" => Ok(Self::Listener),
            "external_path" => Ok(Self::ExternalPath),
            "client_import" => Ok(Self::ClientImport),
            "handshake" => Ok(Self::Handshake),
            "transfer" => Ok(Self::Transfer),
            _ => Err(format!("unknown assurance stage: {value}")),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AssuranceState {
    Verified,
    Degraded,
    Blocked,
    Unknown,
}

impl AssuranceState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Degraded => "degraded",
            Self::Blocked => "blocked",
            Self::Unknown => "unknown",
        }
    }
}

impl std::str::FromStr for AssuranceState {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "verified" => Ok(Self::Verified),
            "degraded" => Ok(Self::Degraded),
            "blocked" => Ok(Self::Blocked),
            "unknown" => Ok(Self::Unknown),
            _ => Err(format!("unknown assurance state: {value}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtocolAssuranceSample {
    pub ts: DateTime<Utc>,
    pub server_id: ServerId,
    pub protocol_id: ProtocolId,
    pub client_kind: String,
    pub stage: AssuranceStage,
    pub state: AssuranceState,
    pub latency_ms: Option<u64>,
    pub failure_code: Option<String>,
}
