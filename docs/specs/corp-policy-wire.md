# Contract: Corp policy wire foundation

## Intent and invariants

Serve the same complete managed-site list that VPNRouter verifies. This module
does not authorize browser access, persist revisions, or claim client application.
Storage must retain the exact envelope, increment revisions atomically, and reject
conflicting publication. Private signing keys never enter client provisioning,
Debug output, serde serialization, logs, or the public fixtures.

## Public Rust interface

The module is `vpnctld::corp_policy`. All fallible functions return
`Result<T, PolicyError>`; callers must not rely on error text.

```rust
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRule {
    pub domain: String,
    pub action: String,
    pub comment: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    pub payload_sha256: String, // uppercase hexadecimal SHA-256 of exact bytes
}
pub struct PolicySigningKey { /* private key; redacted Debug; no Serialize */ }
pub struct SecretKeyDer { /* zeroized PKCS8; redacted Debug; no Serialize */ }
impl SecretKeyDer { pub fn as_bytes(&self) -> &[u8]; }
impl PolicySigningKey {
    pub fn generate() -> Result<Self, PolicyError>;
    pub fn from_pkcs8_der(bytes: &[u8]) -> Result<Self, PolicyError>;
    pub fn export_pkcs8_der(&self) -> Result<SecretKeyDer, PolicyError>;
    pub fn spki_base64(&self) -> Result<String, PolicyError>;
    pub fn sign(&self, payload: &PolicyPayload) -> Result<SignedPolicy, PolicyError>;
}
pub fn normalize_site(input: &str) -> Result<String, PolicyError>;
pub fn validate_rules(rules: &[PolicyRule]) -> Result<(), PolicyError>;
pub fn seed_rules() -> Result<Vec<PolicyRule>, PolicyError>;
pub fn validate_public_key(spki: &str) -> Result<(), PolicyError>;
pub fn verify_envelope(
    envelope: &[u8], expected_policy_id: &str,
    keys: &std::collections::BTreeMap<String, String>,
) -> Result<SignedPolicy, PolicyError>;
```

### Domains and editable rules

- `normalize_site` accepts a DNS name or HTTP(S) URL, rejects empty/control-bearing
  input and input over 4096 UTF-16 code units, trims exterior whitespace, extracts
  the URL hostname, strips one terminal dot, and returns lowercase ASCII IDNA.
  Reject userinfo, backslashes, IP literals/numeric IP spellings, wildcard/regex,
  invalid A-labels, empty labels, underscores, overlong names/labels, and labels
  starting or ending with a hyphen. Bare names cannot contain a port or path.
  The UI must show this normalized result before publishing it.
- DNS names need at least two labels and at most 253 ASCII bytes, with labels of
  at most 63 bytes. Public suffixes are rejected using the exact pinned Mozilla
  PSL in `daemon/assets/corp-policy/public_suffix_list.dat`, including ICANN,
  PRIVATE, wildcard, and exception rules. Normalization alone may return a
  protected name; `validate_rules` rejects it as an editable rule.
- `validate_rules` must not normalize or repair wire domains. Require exact
  normalized lowercase ASCII, at most 512 rules, `direct`/`proxy`, comments at
  most 256 UTF-8 bytes without Unicode control characters, and unique domains.
  Opposite directions on intersecting suffixes are invalid; same-direction
  parent/child rules are valid. Matching is label-boundary aware.
- Protected suffixes and intersecting ancestors/descendants are not editable:
  `uiscom.ru`, `uiscom.co`, `comagic.ru`, `callbackhunter.com`,
  `admin.corp.ninitux.com`. An empty managed list is valid.
- `seed_rules` reads the exact embedded Business preset copied as
  `business-rules.json` at VPNRouter `b874f33faea7daf464ada1e5cf73750bdfd573a2`.
  It returns enabled editable domain-suffix entries in source order, excluding
  protected domains, IP exceptions, and process rules; it validates the result.

### Signed bytes and strict decoding

- Keys are P-256 only. Generation uses fallible OS randomness; imports require
  valid P-256 PKCS8 DER, exports use PKCS8 DER and SPKI DER. Public SPKI is
  canonical padded standard base64, with decoded DER at most 256 bytes.
- `sign` validates first, emits compact deterministic JSON with the struct field
  order above, then signs those exact bytes using ECDSA P-256/SHA-256 and 64-byte
  IEEE P1363 `r || s`. It returns the exact bytes, envelope and digest.
- Envelope has exactly string fields `payload` and `signature`, both canonical
  padded RFC 4648 standard base64. Envelope is nonempty and at most 65536 bytes;
  decoded payload is nonempty and at most 49152 bytes. Final envelope size is
  checked before success. No HTTP/clock/replay decision belongs in this module.
- Payload has exactly the fields above. Schema must be integer 1; policy/key IDs
  are 1-64 ASCII letters, digits, `-`, `_`, or `.`; revision is 1 through
  9007199254740991; publication time is 1 through 253402300799 Unix seconds;
  apply is exactly `next_connection` or `now`.
- Verification bounds bytes before JSON allocation, requires strict UTF-8 and
  JSON depth at most 8, and rejects duplicates, unknown/missing fields, invalid
  types, decimal/exponent integers, trailing data/comments/commas and invalid
  rules. Expected policy ID and provisioned key ID match exactly. Only the
  selected provisioned SPKI verifies the exact payload bytes. Valid verification
  returns the original envelope and payload bytes unchanged, never reserialized.

## Verification

Spec-derived tests use only this contract and copied synthetic fixtures
`daemon/assets/corp-policy/{v1,domains}.json`. They cover both apply timings,
empty/seeded rules, key import/export and redacted Debug, normalization and PSL
exceptions, protected/suffix conflicts, schema/integer/size limits, duplicate and
unknown fields, altered signed bytes/signatures, and wrong identities/keys.
The fixture private key was discarded; no production values are test inputs.
Compilation and tests run in exact-SHA GitHub CI, not on the control-plane host.
