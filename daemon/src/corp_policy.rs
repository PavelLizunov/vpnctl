//! Complete managed-site policies shared with the VPNRouter Business client.

use serde::{Deserialize, Serialize};

mod domains;
mod wire;

pub use domains::{normalize_site, seed_rules, validate_rules};
pub use wire::{PolicySigningKey, SecretKeyDer, validate_public_key, verify_envelope};

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid Corp policy data")]
pub struct PolicyError;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRule {
    pub domain: String,
    pub action: String,
    pub comment: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyPayload {
    pub schema: u64,
    pub policy_id: String,
    pub key_id: String,
    pub revision: u64,
    pub published_at: u64,
    pub apply: String,
    pub rules: Vec<PolicyRule>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedPolicy {
    pub payload: PolicyPayload,
    pub payload_bytes: Vec<u8>,
    pub envelope: Vec<u8>,
    pub payload_sha256: String,
}
