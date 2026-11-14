use std::collections::HashSet;
use std::net::IpAddr;

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::types::*;

pub(super) const MAX_UNIX_TIME: i64 = 253_402_300_799;

fn invalid(message: &'static str) -> CorpStoreError {
    CorpStoreError::InvalidInput(message)
}

pub(super) fn identifier(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

pub(super) fn actor(value: &str) -> CorpResult<()> {
    if !(1..=128).contains(&value.len()) || value.chars().any(char::is_control) {
        return Err(invalid("actor must contain 1-128 bytes without controls"));
    }
    Ok(())
}

pub(super) fn hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(super) fn unix_time(value: i64) -> bool {
    (1..=MAX_UNIX_TIME).contains(&value)
}

pub(super) fn next_counter(value: u64) -> CorpResult<u64> {
    value
        .checked_add(1)
        .filter(|next| *next <= CORP_MAX_REVISION)
        .ok_or(CorpStoreError::Conflict)
}

fn base64_shape(value: &str, max: usize) -> bool {
    let unpadded = value.trim_end_matches('=');
    !value.is_empty()
        && value.len() <= max
        && value.len().is_multiple_of(4)
        && value.len() - unpadded.len() <= 2
        && !unpadded.is_empty()
        && unpadded
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/'))
}

pub(super) fn credentials(value: &CorpCredentials) -> CorpResult<CorpCredentials> {
    if !(32..=512).contains(&value.password_phc.len())
        || !value.password_phc.is_ascii()
        || value.password_phc.bytes().any(|b| b.is_ascii_control())
        || !value.password_phc.starts_with("$argon2id$")
    {
        return Err(invalid("expected a bounded Argon2id PHC"));
    }
    if !(1..=2).contains(&value.reader_tokens.len())
        || !(1..=4).contains(&value.signing_keys.len())
        || !identifier(&value.active_key_id)
    {
        return Err(invalid("invalid credential overlap or active key"));
    }
    let mut ids = HashSet::new();
    let mut tokens = HashSet::new();
    for reader in &value.reader_tokens {
        if !identifier(&reader.id)
            || !ids.insert(&reader.id)
            || !tokens.insert(&reader.token)
            || !(32..=512).contains(&reader.token.len())
            || reader.token.trim_end_matches('=').is_empty()
            || !reader.token.trim_end_matches('=').bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
            })
        {
            return Err(invalid("invalid reader credential"));
        }
    }
    ids.clear();
    let mut public_keys = HashSet::new();
    for key in &value.signing_keys {
        if !identifier(&key.id)
            || !ids.insert(&key.id)
            || !public_keys.insert(&key.spki)
            || !base64_shape(&key.pkcs8, 8192)
            || !base64_shape(&key.spki, 2048)
        {
            return Err(invalid("invalid signing credential"));
        }
    }
    if !value
        .signing_keys
        .iter()
        .any(|key| key.id == value.active_key_id)
    {
        return Err(invalid("active key is absent"));
    }
    let mut normalized = value.clone();
    normalized.reader_tokens.sort_by(|a, b| a.id.cmp(&b.id));
    normalized.signing_keys.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(normalized)
}

pub(super) fn encode_credentials(value: &CorpCredentials) -> String {
    serde_json::json!({
        "password_phc": value.password_phc,
        "active_key_id": value.active_key_id,
        "reader_tokens": value.reader_tokens.iter().map(|r| {
            serde_json::json!({"id": r.id, "token": r.token})
        }).collect::<Vec<_>>(),
        "signing_keys": value.signing_keys.iter().map(|k| {
            serde_json::json!({"id": k.id, "pkcs8": k.pkcs8, "spki": k.spki})
        }).collect::<Vec<_>>()
    })
    .to_string()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredReader {
    id: String,
    token: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredKey {
    id: String,
    pkcs8: String,
    spki: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredCredentials {
    password_phc: String,
    active_key_id: String,
    reader_tokens: Vec<StoredReader>,
    signing_keys: Vec<StoredKey>,
}

pub(super) fn decode_credentials(json: &str) -> CorpResult<CorpCredentials> {
    let stored: StoredCredentials = serde_json::from_str(json)?;
    let value = CorpCredentials {
        password_phc: stored.password_phc,
        active_key_id: stored.active_key_id,
        reader_tokens: stored
            .reader_tokens
            .into_iter()
            .map(|r| CorpReaderToken {
                id: r.id,
                token: r.token,
            })
            .collect(),
        signing_keys: stored
            .signing_keys
            .into_iter()
            .map(|k| CorpSigningKey {
                id: k.id,
                pkcs8: k.pkcs8,
                spki: k.spki,
            })
            .collect(),
    };
    credentials(&value)
}

pub(super) fn egress(entries: &[CorpVerifiedEgress]) -> CorpResult<Vec<CorpVerifiedEgress>> {
    if entries.len() > 512 {
        return Err(invalid("at most 512 verified exit mappings are allowed"));
    }
    let mut normalized = entries.to_vec();
    let mut seen = HashSet::new();
    for entry in &mut normalized {
        if let IpAddr::V6(v6) = entry.ip
            && let Some(v4) = v6.to_ipv4_mapped()
        {
            entry.ip = IpAddr::V4(v4);
        }
        if !identifier(&entry.server_id.0)
            || !hex_digest(&entry.configuration_fingerprint)
            || !unix_time(entry.verified_at)
            || !seen.insert((entry.server_id.clone(), entry.ip))
        {
            return Err(invalid("invalid or duplicate verified exit mapping"));
        }
    }
    normalized.sort_by(|a, b| (&a.server_id.0, a.ip).cmp(&(&b.server_id.0, b.ip)));
    Ok(normalized)
}

pub(super) fn session(value: &CorpSessionInput, now: i64) -> CorpResult<()> {
    if !unix_time(now)
        || !unix_time(value.expires_at)
        || value.expires_at <= now
        || value.expires_at > now.saturating_add(86_400)
        || !hex_digest(&value.token_hash)
        || value.csrf_token.len() != 43
        || !URL_SAFE_NO_PAD
            .decode(&value.csrf_token)
            .is_ok_and(|bytes| {
                bytes.len() == 32 && URL_SAFE_NO_PAD.encode(&bytes) == value.csrf_token
            })
    {
        return Err(invalid("invalid session digest, CSRF or expiration"));
    }
    Ok(())
}

pub(super) fn publication(value: &CorpPublication, status: &CorpStatus) -> CorpResult<usize> {
    if !identifier(&value.key_id)
        || !unix_time(value.published_at)
        || !hex_digest(&value.payload_sha256)
        || !(1..=49_152).contains(&value.payload.len())
        || !(1..=65_536).contains(&value.envelope.len())
    {
        return Err(invalid("invalid publication metadata or size"));
    }
    let payload: Value = serde_json::from_slice(&value.payload)?;
    let object = payload
        .as_object()
        .ok_or_else(|| invalid("payload must be an object"))?;
    let revision = next_counter(status.revision)?;
    if object.len() != 7
        || payload["schema"].as_u64() != Some(1)
        || payload["policy_id"].as_str() != Some(status.policy_id.as_str())
        || payload["key_id"].as_str() != Some(value.key_id.as_str())
        || payload["revision"].as_u64() != Some(revision)
        || payload["published_at"].as_i64() != Some(value.published_at)
        || !matches!(payload["apply"].as_str(), Some("now" | "next_connection"))
    {
        return Err(invalid("payload metadata does not match publication"));
    }
    let rules = payload["rules"]
        .as_array()
        .ok_or_else(|| invalid("rules must be an array"))?;
    if rules.len() > 512
        || rules.iter().any(|rule| {
            rule.as_object().is_none_or(|o| o.len() != 3)
                || rule["domain"]
                    .as_str()
                    .is_none_or(|domain| domain.is_empty() || domain.len() > 253)
                || !matches!(rule["action"].as_str(), Some("direct" | "proxy"))
                || rule["comment"].as_str().is_none_or(|comment| {
                    comment.len() > 256 || comment.chars().any(char::is_control)
                })
        })
    {
        return Err(invalid("invalid bounded rule list"));
    }
    let envelope: StoredEnvelope = serde_json::from_slice(&value.envelope)
        .map_err(|_| invalid("invalid envelope structure"))?;
    let decoded_payload = STANDARD
        .decode(&envelope.payload)
        .map_err(|_| invalid("invalid envelope payload encoding"))?;
    let signature = STANDARD
        .decode(&envelope.signature)
        .map_err(|_| invalid("invalid envelope signature encoding"))?;
    if decoded_payload != value.payload
        || STANDARD.encode(&decoded_payload) != envelope.payload
        || signature.len() != 64
        || STANDARD.encode(&signature) != envelope.signature
        || format!("{:x}", Sha256::digest(&value.payload)) != value.payload_sha256
    {
        return Err(invalid("envelope or digest does not match payload"));
    }
    Ok(rules.len())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredEnvelope {
    payload: String,
    signature: String,
}
