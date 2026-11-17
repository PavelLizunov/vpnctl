# Corp companies implementation contract

The owner explicitly resumed username/company implementation after the prepared
contract. Necessary server builds and CI are in scope; Windows/client builds
remain outside this change. Existing workstation compilation restrictions stay.

## Storage API (frozen for parallel implementation)

Expose from vpnctl_inventory:

- Cloneable CorpInventory, a company-scoped handle sharing the existing pool.
- CorpCompany { company_id: String, status: CorpStatus }.
- CorpCompanySession { company_id: String, session: CorpSession }.
- SqliteInventory::corp_for(&self, company_id: &str) -> CorpInventory.
- async SqliteInventory::corp_companies() -> CorpResult<Vec<CorpCompany>>.
- async SqliteInventory::corp_company_for_username(&self, username: &str)
  -> CorpResult<Option<CorpCompany>> (exact existing users.id lookup; that ID is the subscription username).
- async SqliteInventory::corp_company_session(&self, token_hash: &str, now: i64)
  -> CorpResult<Option<CorpCompanySession>>. Resolve the unique session token,
  require that company's generation/configuration/enabled user as before.

CorpInventory exposes all existing Corp store methods with unchanged names,
arguments and result types. Scope every query/write/history/egress/session/CAS
operation to its company. Existing SqliteInventory Corp methods remain wrappers
for the fixed company_id "legacy" only; never choose the first/last company.
Keep existing CorpStatus/Record/Setup/Credentials/Session structs unchanged.
A new company uses a generated immutable ID; company_id need not equal policy_id.
Existing data migrates to company_id "legacy" with all bytes/counters preserved.
Company IDs are nonempty bounded ASCII identifiers (same safe identifier rules
as existing policy/user IDs); invalid writes return InvalidInput. User IDs and
policy IDs are unique across company bindings. Duplicate create returns Conflict.

Add migration0075, do not rewrite0071/0074. Settings key becomes company_id;
site and phone journals key(company_id,revision), phone floor by company;
egress key(company_id,server_id,ip); sessions retain globally unique token_hash
and gain company_id. Existing empty DBs must still support legacy create.
Create initializes that company's phone floor0. Scoped user disable/delete
triggers revoke only that user's company sessions and preserve other companies.
Keep signed bytes, keys, password hashes, existing generations and expiry,
retention boundaries, safe-integer/overflow rules, atomic CAS, durable writes,
no-op audit behavior and independent site/phone publication unchanged.

## Required storage scenarios

Two enabled fixture users/company handles A/B may publish revision1 concurrently
with different signed bytes; histories/current feeds and phone floors differ.
Stale version/revision in A must not affect B. Security updates, user disable or
delete in A revoke A only. Egress and sessions cannot cross handles. Globally
unique session hash collisions fail. Username resolution uses the bound existing user ID; no new general user-rename
feature is introduced. Legacy wrappers never select B. Migrated legacy payload/envelope
bytes, identity, credentials, floors and expiry are unchanged. Test migration
with populated pre0075 tables and fresh database, not only new scoped creates.

## Trusted receiver company API (frozen)

Keep existing root service bearer. On private internal requests, X-Corp-Company
is the existing opaque policy_id (1..64 ASCII letters/digits/._-) from the authenticated server-side record.
Reject duplicate/malformed company headers; unknown company must not fall back
to legacy. Browser values never confer this authority. Headerless old internal
requests can serve only the original legacy identity for compatibility.

Optional inbox-config fields: legacy_policy_id and upload_endpoint. On boot,
legacy_policy_id binds that exact identifier to existing corp_identity_sha256 without
changing old keys/reports/categories. With an explicit company header, resolve
its durable binding to a support upload identity. Existing enabled identity
checks still apply on all reads/writes. Registration does not publish routes.

Root-service-authenticated POST /internal/corp-companies/provision accepts exact
JSON {policy_id,label}; policy_id uses existing 1..64-byte identifier bounds, label nonempty bounded display text.
Returns {schema:1,policy_id,support:{endpoint,token}}. upload_endpoint is a fixed
validated HTTPS config value; never supplied by browser or request. New IDs
receive distinct upload tokens/identity hashes. Persist and fsync the complete
new credential before returning it; repeated provisioning is idempotent,
including restart/lost successful response. A key-write attempt consumes its
durable creation intent before that separate commit; an uncertain/missing-key
state fails closed while retaining the full credential for deliberate recovery.
Never recreate a removed key or undo disablement. Preserve all existing keys/credentials.
Serialize registry/key mutations with safe no-symlink atomic writes; never log
or print tokens. Existing legacy registration returns its existing full token
only if retained; if unavailable do not rotate or replace it implicitly.

Reports list/detail/retry/delete and categories use only the resolved identity.
Analyzer and upload behavior stay identity-scoped. Rejection paths for wrong
bearer, unknown/duplicate company, foreign report and category CAS must be
covered with focused tests. No service operations, credential operations or
production requests by implementation/test agents.

## Browser/server integration

Portal login requires username plus company password; company selection never
comes from egress IP. Shared egress is valid for two companies when each user's
grants/fresh proof permit it. Existing valid sessions remain on migrated legacy.
Resolve all browser operations from that session. Reader tokens select exactly
one company's existing signed feeds without changing wire shape or endpoint.
Operator list/detail/setup and all controls are company-scoped. Normalize emits
X-Corp-Company only from authorized context; Caddy captures it from backend200,
strips caller-selected context and forwards it only with private service auth.
Diagnostics backend likewise supplies policy_id from authenticated context.
Serve the whole operator admin UI on its configured HTTPS origin, so one login
works for its dashboard and Corp pages; preserve strict origin/CSRF checks.

## Existing public DTO/API appendix for spec-only test authors

```rust
pub struct CorpStatus {
    pub user_id: UserId,
    pub policy_id: String,
    pub enabled: bool,
    pub auth_generation: u64,
    pub config_version: u64,
    pub revision: u64,
    pub active_key_id: String,
}
pub struct CorpReaderToken {
    pub id: String,
    pub token: String,
}
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
pub struct CorpRecord {
    pub status: CorpStatus,
    pub credentials: CorpCredentials,
}
pub struct CorpSetup {
    pub user_id: UserId,
    pub policy_id: String,
    pub credentials: CorpCredentials,
}
pub struct CorpVerifiedEgress {
    pub server_id: ServerId,
    pub ip: IpAddr,
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
    pub async fn corp_record(&self) -> CorpResult<Option<CorpRecord>>;
    pub async fn create_corp(&self, setup: &CorpSetup, actor: &str) -> CorpResult<CorpStatus>;
    pub async fn update_corp_security(
        &self,
        expected_config_version: u64,
        enabled: bool,
        credentials: &CorpCredentials,
        actor: &str,
    ) -> CorpResult<CorpStatus>;
    pub async fn replace_corp_egress(
        &self,
        expected_config_version: u64,
        entries: &[CorpVerifiedEgress],
        actor: &str,
    ) -> CorpResult<CorpStatus>;
    pub async fn refresh_corp_egress(
        &self,
        expected_config_version: u64,
        previous: &[CorpVerifiedEgress],
        refreshed: &[CorpVerifiedEgress],
        actor: &str,
    ) -> CorpResult<CorpStatus>;
    pub async fn corp_verified_egress(&self) -> CorpResult<Vec<CorpVerifiedEgress>>;
    pub async fn issue_corp_session(
        &self,
        expected_auth_generation: u64,
        session: &CorpSessionInput,
        now: i64,
        actor: &str,
    ) -> CorpResult<()>;
    pub async fn corp_session(
        &self,
        token_hash: &str,
        now: i64,
    ) -> CorpResult<Option<CorpSession>>;
    pub async fn revoke_corp_session(&self, token_hash: &str, actor: &str) -> CorpResult<bool>;
    pub async fn revoke_corp_sessions(
        &self,
        expected_config_version: u64,
        actor: &str,
    ) -> CorpResult<CorpStatus>;
    pub async fn publish_corp_policy(
        &self,
        publication: &CorpPublication,
        actor: &str,
    ) -> CorpResult<CorpRevision>;
    pub async fn publish_corp_phone_policy(
        &self,
        publication: &CorpPublication,
        actor: &str,
    ) -> CorpResult<CorpRevision>;
    pub async fn corp_current_policy(
        &self,
        expected_config_version: u64,
    ) -> CorpResult<Option<CorpRevision>>;
    pub async fn corp_current_phone_policy(
        &self,
        expected_config_version: u64,
    ) -> CorpResult<Option<CorpRevision>>;
    pub async fn corp_revision(&self, revision: u64) -> CorpResult<Option<CorpRevision>>;
    pub async fn corp_phone_revision(&self, revision: u64) -> CorpResult<Option<CorpRevision>>;
    pub async fn corp_history(&self, limit: usize) -> CorpResult<Vec<CorpRevision>>;
    pub async fn corp_phone_history(&self, limit: usize) -> CorpResult<Vec<CorpRevision>>;
```

Fixture API: SqliteInventory::open(&Path).await; add_user(&User).await;
add_server(&Server).await. User fields: id:UserId, uuid:String, tuic_password,
wireguard_pubkey,wireguard_private,sub_token,vpn_router_device_id:Option<String>,
disabled:bool. Server fields: id:ServerId,address:String,ssh_port:u16,ssh_user:
String,kernels:Vec,enabled_protocols:Vec,trusted_host_fingerprint:Option,hoster:
String,jump_via:Option,usage_coefficient:f64. IDs/UUIDs must differ per fixture.
Fixture credentials may use synthetic bounded PHC and base64 keys; storage
checks structure/byte binding, cryptographic verification is a daemon concern.
Publication envelopes bind base64 payload and64-byte base64 signature; payload
metadata must match publication revision,key_id,policy_id,published_at. Use SHA256.
For migration fixtures, old accepted migrations0001..0074 are public schema
fixtures and may be read; never read the new0075 implementation or corp.rs.
Required tests file: crates/inventory/tests/spec_corp_companies.rs.

## HTTP fixture API for independent receiver tests

Dynamic-import packaging/business-support/receiver.py as a module. Public fixture
API: Store(reports_path, keys_path, trusted_proxy='127.0.0.1', inbox_config=path);
Receiver(('127.0.0.1',0), store) is a ThreadingHTTPServer and chooses Handler.
Run serve_forever in a test thread, shutdown/server_close during cleanup. Keys
JSON is {sha256(upload_token):{label,enabled:true}}. Inbox JSON schema1 uses
corp_identity_sha256,service_token_file plus legacy_policy_id/upload_endpoint.
The token/config files must be private real files; temporary paths are permitted.
Optional require_company_header:true rejects headerless internal data requests
(400) while still admitting authenticated provision. Default false keeps legacy
compatibility. Internal service auth uses Authorization:Bearer <service token>.
Category POSTs also need X-Corp-Expected-Length equal actual UTF8 body length.
Use real HTTP calls, not implementation monkeypatches, to prove rejection and
identity isolation. Receipt ownership format is an accepted public old fixture;
old test fixtures may be imported for setup only, never read new receiver code
to derive the expected security behavior.

## Independent HTTP acceptance requirements

Login form always includes username/name=username autocomplete=username and a
company password. POST/login requires exactly username/password (duplicates,
missing username and unknown fields fail). Unknown username or wrong company
password cannot create a session. A and B may share one verified exit and both
log in with their own credentials. Existing valid legacy sessions remain valid.
GET/api/corp/state includes company.username; its rules and csrf belong to that
session. POST/normalize's X-Corp-Company response is that record's policy_id even
if the caller forges X-Corp-Company. Cross-company CSRF fails403. Reader tokens
return only their company's existing signed envelope. Ambiguous reader tokens
across bindings are rejected, never routed to the first match. No company list
appears on anonymous login. Form failures preserve username, never password.

Operator company-specific forms use company_id plus expected_config_version;
missing company_id is the fixed legacy compatibility scope. New setup still
uses existing user_id and explicit confirm_binding; the server generates a new
company ID, preserving the original fixed legacy binding. GET/admin/corp/companies
lists company links; GET/admin/corp/company/{id} owns that company's controls.
Same configured HTTPS operator session works for normal admin and Corp pages.
The trusted short Tailscale hostname's GET/HEAD admin routes redirect to that
configured HTTPS origin; stale noncanonical POSTs are rejected, never replayed.

Independent fixture construction may read the ACCEPTED PRE-CHANGE test fixture
setup in git show01cff06b:daemon/tests/spec_corp_policy_http.rs and
spec_corp_operator.rs; it is infrastructure, not the new implementation or its
assertion oracle. Public app API: app::make_app_state_for_tests(inv,registry)
returns(AppState, JoinHandle); app::router(state) builds the public router.
Use build_registry, two users, one granted VLESS server, eligible_servers to get
its actual fingerprint, and scoped corp_verified_egress entries with fresh now.
Implement tests in new daemon/tests/spec_corp_companies_http.rs only.

A client may assert X-Corp-Expected-Company=username to detect a login switch
in another tab. The server compares it to the authenticated session's username
and rejects mismatch401 before reads/writes; it never selects a company from
that assertion. New Rules/Diagnostics UI sends the server-rendered username.

Receiver receipt fixture public schema: a recent <report_id>.json object has
identity=SHA256(upload token),report_id=64 lowercase hex,received_utc=ISO8601,
bytes=archive size and optional diagnosis:{state:"received"}; a same-ID .zip
regular recent file exists. Foreign requests must fail404 while that report's
own company detail/list succeeds. Prior accepted test_receiver.py fixtures may
be read/imported for infrastructure only, not assertions or new implementation.

## Integration review corrections before CI

An unusable401/403 session can render the anonymous login for the current
verified exit; genuine backend errors are preserved. Unknown username, wrong
password and failed company access share the same login rejection, with dummy
password work for unknown users. A per-company eligibility/state failure is
reported while healthy companies continue refreshing. Diagnostics provisioning
failure preserves the committed company and one-time password reveal, explains
the incomplete state and links to its retry/export control. New HTTP regressions
and fixture-backed company-list/selected-company browser pages cover these fixes.
