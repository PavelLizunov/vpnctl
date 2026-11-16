use std::collections::BTreeMap;
use std::fmt;

use base64::{Engine, engine::general_purpose::STANDARD};
use p256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};
use p256::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{
    PhonePayload, PolicyError, PolicyPayload, SignedPhonePolicy, SignedPolicy,
    validate_phone_rules, validate_rules,
};

const MAX_ENVELOPE: usize = 65536;
const MAX_PAYLOAD: usize = 49152;
const MAX_REVISION: u64 = 9007199254740991;
const MAX_PUBLICATION: u64 = 253402300799;

pub struct PolicySigningKey(SigningKey);

impl fmt::Debug for PolicySigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PolicySigningKey([REDACTED])")
    }
}

pub struct SecretKeyDer(Zeroizing<Vec<u8>>);

impl fmt::Debug for SecretKeyDer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKeyDer([REDACTED])")
    }
}

impl SecretKeyDer {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl PolicySigningKey {
    pub fn generate() -> Result<Self, PolicyError> {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        for _ in 0..16 {
            getrandom::fill(bytes.as_mut()).map_err(|_| PolicyError)?;
            if let Ok(key) = SigningKey::from_slice(bytes.as_ref()) {
                return Ok(Self(key));
            }
        }
        Err(PolicyError)
    }

    pub fn from_pkcs8_der(bytes: &[u8]) -> Result<Self, PolicyError> {
        SigningKey::from_pkcs8_der(bytes)
            .map(Self)
            .map_err(|_| PolicyError)
    }

    pub fn export_pkcs8_der(&self) -> Result<SecretKeyDer, PolicyError> {
        let der = self.0.to_pkcs8_der().map_err(|_| PolicyError)?;
        Ok(SecretKeyDer(Zeroizing::new(der.as_bytes().to_vec())))
    }

    pub fn spki_base64(&self) -> Result<String, PolicyError> {
        let der = self
            .0
            .verifying_key()
            .to_public_key_der()
            .map_err(|_| PolicyError)?;
        Ok(STANDARD.encode(der.as_bytes()))
    }

    pub fn sign(&self, payload: &PolicyPayload) -> Result<SignedPolicy, PolicyError> {
        validate_payload(payload)?;
        let (payload_bytes, envelope, payload_sha256) = self.sign_bytes(payload)?;
        Ok(SignedPolicy {
            payload: payload.clone(),
            payload_bytes,
            envelope,
            payload_sha256,
        })
    }

    pub fn sign_phone(&self, payload: &PhonePayload) -> Result<SignedPhonePolicy, PolicyError> {
        payload.validate()?;
        let (payload_bytes, envelope, payload_sha256) = self.sign_bytes(payload)?;
        Ok(SignedPhonePolicy {
            payload: payload.clone(),
            payload_bytes,
            envelope,
            payload_sha256,
        })
    }

    fn sign_bytes(
        &self,
        payload: &impl Serialize,
    ) -> Result<(Vec<u8>, Vec<u8>, String), PolicyError> {
        let payload_bytes = serde_json::to_vec(payload).map_err(|_| PolicyError)?;
        if payload_bytes.len() > MAX_PAYLOAD {
            return Err(PolicyError);
        }
        let signature: Signature = self.0.try_sign(&payload_bytes).map_err(|_| PolicyError)?;
        let envelope = serde_json::to_vec(&Envelope {
            payload: STANDARD.encode(&payload_bytes),
            signature: STANDARD.encode(signature.to_bytes()),
        })
        .map_err(|_| PolicyError)?;
        if envelope.len() > MAX_ENVELOPE {
            return Err(PolicyError);
        }
        let payload_sha256 = digest(&payload_bytes);
        Ok((payload_bytes, envelope, payload_sha256))
    }
}

pub fn validate_public_key(spki: &str) -> Result<(), PolicyError> {
    import_public_key(spki).map(|_| ())
}

pub fn verify_envelope(
    envelope: &[u8],
    expected_policy_id: &str,
    keys: &BTreeMap<String, String>,
) -> Result<SignedPolicy, PolicyError> {
    let (payload, payload_bytes, payload_sha256) =
        verify_bytes(envelope, expected_policy_id, keys)?;
    Ok(SignedPolicy {
        payload,
        payload_bytes,
        envelope: envelope.to_vec(),
        payload_sha256,
    })
}

pub fn verify_phone_envelope(
    envelope: &[u8],
    expected_policy_id: &str,
    keys: &BTreeMap<String, String>,
) -> Result<SignedPhonePolicy, PolicyError> {
    let (payload, payload_bytes, payload_sha256) =
        verify_bytes(envelope, expected_policy_id, keys)?;
    Ok(SignedPhonePolicy {
        payload,
        payload_bytes,
        envelope: envelope.to_vec(),
        payload_sha256,
    })
}

trait WirePayload: DeserializeOwned {
    fn validate(&self) -> Result<(), PolicyError>;
    fn policy_id(&self) -> &str;
    fn key_id(&self) -> &str;
}

impl WirePayload for PolicyPayload {
    fn validate(&self) -> Result<(), PolicyError> {
        validate_payload(self)
    }
    fn policy_id(&self) -> &str {
        &self.policy_id
    }
    fn key_id(&self) -> &str {
        &self.key_id
    }
}

impl WirePayload for PhonePayload {
    fn validate(&self) -> Result<(), PolicyError> {
        if self.schema != 1
            || self.kind != "telephony"
            || !identifier(&self.policy_id)
            || !identifier(&self.key_id)
            || !(1..=MAX_REVISION).contains(&self.revision)
            || !(1..=MAX_PUBLICATION).contains(&self.published_at)
            || !matches!(self.apply.as_str(), "next_connection" | "now")
        {
            return Err(PolicyError);
        }
        validate_phone_rules(&self.rules)
    }
    fn policy_id(&self) -> &str {
        &self.policy_id
    }
    fn key_id(&self) -> &str {
        &self.key_id
    }
}

fn verify_bytes<T: WirePayload>(
    envelope: &[u8],
    expected_policy_id: &str,
    keys: &BTreeMap<String, String>,
) -> Result<(T, Vec<u8>, String), PolicyError> {
    if envelope.is_empty() || envelope.len() > MAX_ENVELOPE || !identifier(expected_policy_id) {
        return Err(PolicyError);
    }
    let outer: Envelope = parse_json(envelope)?;
    let payload_bytes = decode_base64(&outer.payload, MAX_PAYLOAD)?;
    let signature_bytes = decode_base64(&outer.signature, 64)?;
    let signature = Signature::from_slice(&signature_bytes).map_err(|_| PolicyError)?;
    let payload: T = parse_json(&payload_bytes)?;
    payload.validate()?;
    if payload.policy_id() != expected_policy_id {
        return Err(PolicyError);
    }
    let key = import_public_key(keys.get(payload.key_id()).ok_or(PolicyError)?)?;
    key.verify(&payload_bytes, &signature)
        .map_err(|_| PolicyError)?;
    let payload_sha256 = digest(&payload_bytes);
    Ok((payload, payload_bytes, payload_sha256))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    payload: String,
    signature: String,
}

fn validate_payload(payload: &PolicyPayload) -> Result<(), PolicyError> {
    if payload.schema != 1
        || !identifier(&payload.policy_id)
        || !identifier(&payload.key_id)
        || !(1..=MAX_REVISION).contains(&payload.revision)
        || !(1..=MAX_PUBLICATION).contains(&payload.published_at)
        || !matches!(payload.apply.as_str(), "next_connection" | "now")
    {
        return Err(PolicyError);
    }
    validate_rules(&payload.rules)
}

fn identifier(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
}

fn import_public_key(encoded: &str) -> Result<VerifyingKey, PolicyError> {
    let bytes = decode_base64(encoded, 256)?;
    VerifyingKey::from_public_key_der(&bytes).map_err(|_| PolicyError)
}

fn decode_base64(value: &str, maximum_bytes: usize) -> Result<Vec<u8>, PolicyError> {
    if value.is_empty()
        || value.len() > maximum_bytes.div_ceil(3) * 4
        || !value.len().is_multiple_of(4)
    {
        return Err(PolicyError);
    }
    let bytes = STANDARD.decode(value).map_err(|_| PolicyError)?;
    if bytes.is_empty() || bytes.len() > maximum_bytes || STANDARD.encode(&bytes) != value {
        return Err(PolicyError);
    }
    Ok(bytes)
}

fn parse_json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, PolicyError> {
    // Check nesting before serde allocates containers. The caller has already
    // bounded the byte slice; serde owns complete lexical/schema validation.
    std::str::from_utf8(bytes).map_err(|_| PolicyError)?;
    let mut depth = 0_usize;
    let mut quoted = false;
    let mut escaped = false;
    for &byte in bytes {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
        } else {
            match byte {
                b'"' => quoted = true,
                b'{' | b'[' => {
                    depth += 1;
                    if depth > 8 {
                        return Err(PolicyError);
                    }
                }
                b'}' | b']' => depth = depth.checked_sub(1).ok_or(PolicyError)?,
                _ => {}
            }
        }
    }
    serde_json::from_slice(bytes).map_err(|_| PolicyError)
}

fn digest(bytes: &[u8]) -> String {
    format!("{:X}", Sha256::digest(bytes))
}
