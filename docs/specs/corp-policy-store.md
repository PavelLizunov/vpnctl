# Corp policy storage contract

## Intent and invariants

One persistent Corp binding serves the fixed corporate portal. It references an
existing inventory UserId, starts disabled, and retains its policy identity and
monotonic publication floor permanently. It is not a tenancy or role framework.
The daemon owns password/P-256/domain validation and signing; inventory owns
bounded storage, state transitions, concurrency and atomic audit.

Every mutating method acquires one pool connection, sets `synchronous=FULL`
before `BEGIN IMMEDIATE`, and commits state plus audit on that same connection.
The connection remains FULL when returned to the pool. Errors, including audit
failure, roll back. No-op security/egress replacements and absent-session revoke
write no audit. No existing migration is edited; add migration 0070.

## Public Rust interface

All types below are re-exported from `vpnctl_inventory`. `CorpResult<T>` is
`Result<T, CorpStoreError>`, whose variants are `Inventory(SqliteInventoryError)`,
`Conflict`, `Unavailable`, and `InvalidInput(&'static str)`.

```rust
pub const CORP_MAX_REVISION: u64 = 9_007_199_254_740_991;

pub struct CorpStatus {
    pub user_id: UserId,
    pub policy_id: String,
    pub enabled: bool,
    pub auth_generation: u64,
    pub config_version: u64,
    pub revision: u64,
    pub active_key_id: String,
}
pub struct CorpReaderToken { pub id: String, pub token: String }
pub struct CorpSigningKey {
    pub id: String,
    pub pkcs8: String,
    pub spki: String,
}
pub struct CorpCredentials {
    pub password_phc: String,
    pub reader_tokens: Vec<CorpReaderToken>,
    pub signing_keys: Vec<CorpSigningKey>,
    pub active_key_id: String,
}
pub struct CorpRecord { pub status: CorpStatus, pub credentials: CorpCredentials }
pub struct CorpSetup {
    pub user_id: UserId,
    pub policy_id: String,
    pub credentials: CorpCredentials,
}
pub struct CorpVerifiedEgress {
    pub server_id: ServerId,
    pub ip: std::net::IpAddr,
    pub configuration_fingerprint: String,
    pub verified_at: i64,
}
pub struct CorpSessionInput {
    pub token_hash: String,
    pub csrf_token: String,
    pub expires_at: i64,
}
pub struct CorpSession {
    pub auth_generation: u64,
    pub config_version: u64,
    pub csrf_token: String,
    pub expires_at: i64,
}
pub struct CorpPublication {
    pub expected_revision: u64,
    pub expected_config_version: u64,
    pub key_id: String,
    pub published_at: i64,
    pub payload_sha256: String,
    pub payload: Vec<u8>,
    pub envelope: Vec<u8>,
}
pub struct CorpRevision {
    pub revision: u64,
    pub key_id: String,
    pub published_at: i64,
    pub payload_sha256: String,
    pub payload: Vec<u8>,
    pub envelope: Vec<u8>,
}

impl SqliteInventory {
    pub async fn corp_record(&self) -> CorpResult<Option<CorpRecord>>;
    pub async fn create_corp(&self, setup: &CorpSetup, actor: &str) -> CorpResult<CorpStatus>;
    pub async fn update_corp_security(&self, expected_config_version: u64,
        enabled: bool, credentials: &CorpCredentials, actor: &str) -> CorpResult<CorpStatus>;
    pub async fn replace_corp_egress(&self, expected_config_version: u64,
        entries: &[CorpVerifiedEgress], actor: &str) -> CorpResult<CorpStatus>;
    pub async fn corp_verified_egress(&self) -> CorpResult<Vec<CorpVerifiedEgress>>;
    pub async fn refresh_corp_egress(&self, expected_config_version: u64,
        previous: &[CorpVerifiedEgress], refreshed: &[CorpVerifiedEgress],
        actor: &str) -> CorpResult<CorpStatus>;
    pub async fn issue_corp_session(&self, expected_auth_generation: u64,
        session: &CorpSessionInput, now: i64, actor: &str) -> CorpResult<()>;
    pub async fn corp_session(&self, token_hash: &str, now: i64) -> CorpResult<Option<CorpSession>>;
    pub async fn revoke_corp_session(&self, token_hash: &str, actor: &str) -> CorpResult<bool>;
    pub async fn revoke_corp_sessions(&self, expected_config_version: u64,
        actor: &str) -> CorpResult<CorpStatus>;
    pub async fn publish_corp_policy(&self, publication: &CorpPublication,
        actor: &str) -> CorpResult<CorpRevision>;
    pub async fn corp_current_policy(&self, expected_config_version: u64) -> CorpResult<Option<CorpRevision>>;
    pub async fn corp_revision(&self, revision: u64) -> CorpResult<Option<CorpRevision>>;
    pub async fn corp_history(&self, limit: usize) -> CorpResult<Vec<CorpRevision>>;
}
```

All data types are Clone. Status, verified egress and revision metadata may have
safe Debug output. Credentials, signing keys, reader tokens, setup, record and
sessions have explicitly redacted Debug and no Serialize implementation. Exact
payload/envelope bodies also stay out of Debug. No error/audit includes secrets.

## Behavior and bounds

- `create_corp`: requires an existing enabled user and valid credentials. Creates
  disabled singleton with revision 0, config/auth generation 1, no egress or
  sessions. A second create returns Conflict, even after user deletion. There is
  no binding-delete/rebind API. Policy identity/UserId cannot be changed by other
  methods. User deletion preserves history, disables Corp, invalidates sessions
  and records one audit; re-creating that UserId never silently enables Corp.
  Disabling the bound user invalidates sessions even if later re-enabled.
  If either authority counter is already exhausted, disabling the bound user
  also disables Corp permanently; old in-flight login cannot regain authority.
- Identifiers: 1-64 ASCII alphanumeric, `_`, `-`, `.`. Actor: 1-128 UTF-8 bytes,
  no controls. Password PHC: 32-512 ASCII bytes, starts `$argon2id$`; daemon must
  validate the PHC parameters and generate hashes. Reader overlap: 1-2 entries,
  distinct IDs and tokens, each token 32-512 ASCII bytes matching nonempty
  `[A-Za-z0-9\-._~+/]+` followed by zero or more terminal `=` characters. Interior
  `=` is invalid. Reader/key arrays normalize by ID, so their order is immaterial.
  Signing overlap: 1-4 unique IDs and SPKIs; active ID must exist. PKCS8/SPKI are
  bounded nonempty base64 strings (at most 8192/2048 bytes respectively); daemon
  validates DER, P-256 curve and matching public/private material before calling.
  Ordinary restricted SQLite/backups store recoverable material; no at-rest
  encryption claim. Export does not implicitly rotate a reader credential.
- `update_corp_security`: CAS config_version; changes to enabled state/password/
  readers/keys raise config_version and auth_generation, delete existing sessions,
  audit once. Identical normalized input returns unchanged status without audit.
  Enabling requires the bound user still exists and is enabled. Disabling or
  repairing secrets remains possible for a deleted/disabled user. Counters never
  wrap or reset; config_version and auth_generation are in 1..CORP_MAX_REVISION.
  Exhaustion returns Conflict.
- Egress: at most 512 entries, unique `(server_id, canonical IP)`, each server
  must exist, verified_at in 1..253402300799 and fingerprint exactly 64 lowercase
  hex characters. IPv4-mapped IPv6 canonicalizes to IPv4. Caller must compare the
  stored fingerprint with the CURRENT effective server configuration and current
  subscription eligibility before admitting any IP. No inventory/DNS addresses
  are implicitly verified. Whole-list replacement is CAS config_version, raises
  config/auth generations and revokes sessions on an actual change only.
  Entries normalize by canonical `(server_id, IP)` before comparison, so array
  order is immaterial.
- Timestamp-only renewal uses `refresh_corp_egress` and the complete previous
  row set as an additional CAS. It preserves generations and sessions, permits
  only nondecreasing timestamps for unchanged identities, and atomically audits
  actual renewal. The detailed bounds, user/no-op checks and failure contract
  are owned by [egress preparation](corp-policy-egress-preparation.md).
- Sessions: token_hash is exactly 64 lowercase hex characters (SHA-256 computed
  by daemon); CSRF is exactly 43 URL-safe unpadded base64 characters from 32 random
  bytes. `now` is positive bounded Unix seconds; expiration must be in
  `(now, now + 86400]`. Issue requires enabled Corp, existing enabled user and
  matching auth generation in the insertion transaction. At most 128 unexpired
  sessions; expired entries are removed as part of issuance (same audit).
  Duplicate token digest returns Conflict. Lookup returns None for missing,
  expired, revoked, stale-generation or disabled/deleted-user sessions.
  Revoke-all increments both generations even with no rows, invalidating in-flight
  password verification. Session raw bearer tokens are never stored or audited.
- Publish: requires active Corp/user, expected config version and expected current
  revision; new revision is exactly current + 1 and at most CORP_MAX_REVISION.
  key_id must equal the current active signer; every signer/security rotation
  changes config_version. Payload is 1..49152 bytes of JSON, envelope 1..65536
  bytes. Store checks payload metadata against schema 1, immutable policy ID,
  current active key, new revision, supplied published_at, valid apply timing and
  at most 512 rules. It also checks bounded envelope structure, rejects duplicate
  envelope fields, strictly decodes canonical padded standard base64, and requires
  decoded `envelope.payload` to equal the supplied payload byte for byte. Signature
  decoding must yield exactly 64 bytes. Store computes SHA-256 of the exact payload
  and requires equality with the supplied 64-character lowercase digest. A mismatch
  is InvalidInput and leaves the revision floor, history and audit unchanged.
  Daemon must have validated domains, duplicate payload fields, timestamp and the
  cryptographic signature against the current signing key BEFORE this API.
  No reserialization: original payload/envelope bytes are stored and returned.
  Audit contains only policy identity, revision, key ID, digest and rule count.
  Commit advances floor, inserts revision and keeps newest 100 history rows in
  one transaction. Audit failure leaves floor and all history unchanged.
- `corp_current_policy`: requires active Corp/user and matching config version,
  else Unavailable/Conflict; revision 0 returns None. This permits the daemon to
  verify a reader from `corp_record` and reject concurrent credential rotation.
  Operator history getters remain available while disabled; history limit 1..100,
  newest first; revision lookup accepts 1..CORP_MAX_REVISION and rejects other
  values as InvalidInput; missing/pruned revision returns None. Restoring old content is an
  ordinary newly signed publication at current + 1, never a floor reset.

## Verification

Independent spec tests cover durable reopen, one singleton, preservation across
user deletion, no secret Debug, no-op audits, stale CAS and login generation,
reader/signer overlap and bounds, IPv4/IPv6 normalization and stale fingerprint
preservation, session expiry/revocation/caps, exact byte publication, concurrent
writers, audit-trigger rollback, disabled/deleted users, max revision and bounded
history. Source formatting/checks locally; compilation and execution only in CI.

Boundary/fault fixtures may open their own temporary SQLite database directly.
The supported fixture contract is `corp_policy_settings` with singleton `id = 1`
and integer columns `auth_generation`, `config_version`, `revision`, and `enabled`.
Set the counters to synthetic bounds only in test databases; no public API resets
them. A temporary `BEFORE INSERT` trigger on `audit_log` may abort insertion to
verify atomic rollback. These fixture hooks are not operator interfaces.
