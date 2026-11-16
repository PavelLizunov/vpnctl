//! Complete managed-site policies shared with the VPNRouter Business client.

use serde::{Deserialize, Serialize};

mod domains;
mod phone;
mod wire;

pub use domains::{normalize_site, seed_rules, validate_rules};
pub use phone::{normalize_phone_value, seed_phone_rules, validate_phone_rules};
pub use wire::{
    PolicySigningKey, SecretKeyDer, validate_public_key, verify_envelope, verify_phone_envelope,
};

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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhoneRule {
    #[serde(rename = "type")]
    pub kind: String,
    pub value: String,
    pub action: String,
    pub comment: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhonePayload {
    pub schema: u64,
    pub kind: String,
    pub policy_id: String,
    pub key_id: String,
    pub revision: u64,
    pub published_at: u64,
    pub apply: String,
    pub rules: Vec<PhoneRule>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedPhonePolicy {
    pub payload: PhonePayload,
    pub payload_bytes: Vec<u8>,
    pub envelope: Vec<u8>,
    pub payload_sha256: String,
}
