use std::fmt;
use std::net::IpAddr;

use vpnctl_core::{ServerId, UserId};

use crate::SqliteInventoryError;

pub const CORP_MAX_REVISION: u64 = 9_007_199_254_740_991;

#[derive(thiserror::Error)]
pub enum CorpStoreError {
    #[error("Corp storage error")]
    Inventory(#[from] SqliteInventoryError),
    #[error("Corp state changed; reload before retrying")]
    Conflict,
    #[error("Corp policy is unavailable")]
    Unavailable,
    #[error("invalid Corp input: {0}")]
    InvalidInput(&'static str),
}

impl fmt::Debug for CorpStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inventory(_) => f.write_str("Inventory(<redacted>)"),
            Self::Conflict => f.write_str("Conflict"),
            Self::Unavailable => f.write_str("Unavailable"),
            Self::InvalidInput(message) => f.debug_tuple("InvalidInput").field(message).finish(),
        }
    }
}

impl From<sqlx::Error> for CorpStoreError {
    fn from(error: sqlx::Error) -> Self {
        Self::Inventory(error.into())
    }
}

impl From<serde_json::Error> for CorpStoreError {
    fn from(error: serde_json::Error) -> Self {
        Self::Inventory(error.into())
    }
}

pub type CorpResult<T> = Result<T, CorpStoreError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorpStatus {
    pub user_id: UserId,
    pub policy_id: String,
    pub enabled: bool,
    pub auth_generation: u64,
    pub config_version: u64,
    pub revision: u64,
    pub active_key_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorpCompany {
    pub company_id: String,
    pub status: CorpStatus,
}

#[derive(Clone, Debug)]
pub struct CorpCompanySession {
    pub company_id: String,
    pub session: CorpSession,
}

#[derive(Clone, PartialEq, Eq)]
pub struct CorpReaderToken {
    pub id: String,
    pub token: String,
}

#[derive(Clone, PartialEq, Eq)]
pub struct CorpSigningKey {
    pub id: String,
    pub pkcs8: String,
    pub spki: String,
}

#[derive(Clone, PartialEq, Eq)]
pub struct CorpCredentials {
    pub password_phc: String,
    pub reader_tokens: Vec<CorpReaderToken>,
    pub signing_keys: Vec<CorpSigningKey>,
    pub active_key_id: String,
}

#[derive(Clone)]
pub struct CorpRecord {
    pub status: CorpStatus,
    pub credentials: CorpCredentials,
}

#[derive(Clone)]
pub struct CorpSetup {
    pub user_id: UserId,
    pub policy_id: String,
    pub credentials: CorpCredentials,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorpVerifiedEgress {
    pub server_id: ServerId,
    pub ip: IpAddr,
    pub configuration_fingerprint: String,
    pub verified_at: i64,
}

#[derive(Clone)]
pub struct CorpSessionInput {
    pub token_hash: String,
    pub csrf_token: String,
    pub expires_at: i64,
}

#[derive(Clone)]
pub struct CorpSession {
    pub auth_generation: u64,
    pub config_version: u64,
    pub csrf_token: String,
    pub expires_at: i64,
}

#[derive(Clone)]
pub struct CorpPublication {
    pub expected_revision: u64,
    pub expected_config_version: u64,
    pub key_id: String,
    pub published_at: i64,
    pub payload_sha256: String,
    pub payload: Vec<u8>,
    pub envelope: Vec<u8>,
}

#[derive(Clone)]
pub struct CorpRevision {
    pub revision: u64,
    pub key_id: String,
    pub published_at: i64,
    pub payload_sha256: String,
    pub payload: Vec<u8>,
    pub envelope: Vec<u8>,
}

macro_rules! redacted_debug {
    ($($type:ty),+ $(,)?) => {
        $(impl fmt::Debug for $type {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($type)).finish_non_exhaustive()
            }
        })+
    };
}

redacted_debug!(
    CorpReaderToken,
    CorpSigningKey,
    CorpCredentials,
    CorpRecord,
    CorpSetup,
    CorpSessionInput,
    CorpSession,
    CorpPublication
);

impl fmt::Debug for CorpRevision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CorpRevision")
            .field("revision", &self.revision)
            .field("key_id", &self.key_id)
            .field("published_at", &self.published_at)
            .field("payload_sha256", &self.payload_sha256)
            .finish_non_exhaustive()
    }
}
