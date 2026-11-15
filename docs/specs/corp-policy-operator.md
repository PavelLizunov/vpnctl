# Corp operator web controls

## Intent, scope and verification plan

Implementation contract frozen against green HTTP candidate
`5758b2010ee24306cf19eb4576db83d7a534f1a6` on 2026-11-15. Implement one
strictly authenticated operator page for setup, credential overlap, access
shutdown, session revocation, protected capability export and sanitized status.
The binding starts disabled. This preparation block does not implement actual
egress probes or activate access; those follow after the client transport fix.
No deployment, client migration or general operator-auth redesign belongs here.

Independent tests derive from this contract and use isolated inventory plus the
real app router. No local compilation, runtime tests or browsers: publication
follows [agent-workflow.md](agent-workflow.md), then exact-SHA CI. Lead owns the
spec, ledger, generated files and publication; implementation and spec-test
writers own disjoint source/test files. Rollback is a task-branch revert before
activation, preserving existing policy/history and credentials.

## Boundary and request rules

- Reserve `/admin/corp` and the POST routes below on the operator branch only.
  Preserve the outer exclusive Corp-host dispatch in `corp_portal::isolate`.
  The canonical Corp browser host, including its disabled/unknown-path cases,
  must never reach these routes; credentials must not change that decision.
- All new GET and POST routes require successfully constructed configured
  `BasicAuth` and a valid existing operator authentication (Basic header or its
  verified operator cookie). Absent/malformed configuration returns 503, even
  where the legacy operator tree allows absent authentication. Wrong/missing
  operator authentication returns 401. Corp session/reader credentials confer
  no operator authority. Reject duplicate relevant auth/cookie headers before
  the legacy permissive extractor can choose one.
- Pin one trusted operator HTTPS origin from `VPNCTLD_CORP_OPERATOR_ORIGIN`,
  distinct from the Corp origin. Require
  request Host/URI authority to agree with that configured origin. Never derive
  it from arbitrary Host, Origin or untrusted forwarding headers. Missing or
  invalid origin configuration returns 503 on the new subtree. Exact single
  Origin is mandatory on POST; no Referer fallback, authority-only comparison,
  `null`, trailing slash or alternate scheme. Cross-site Fetch Metadata denies.
- Add a purpose-separated operator CSRF token to the GET page and every form.
  It must be unpredictable, authenticated, time bounded (maximum one hour),
  bound to the authenticated operator and configured origin, and invalid after
  operator credential/install-secret changes. Compare in constant time. Use the purpose-separated stateless HMAC construction below; never reuse
  Corp CSRF/session material.
- POST accepts URL-encoded forms, exactly the fields specified below plus
  `csrf`; rejects duplicate/unknown/missing fields and wrong content type with
  422. IDs obey storage bounds. Decimal versions must be exact bounded u64
  integers in canonical decimal form (no leading zeros except `0`). No secrets, tokens, IDs selecting another binding, redirect targets,
  IPs, URLs, command arguments or private keys arrive through query parameters.
  Preserve the legacy 8192-byte body cap and timeout; harden even error replies.
- Every response is no-store, nosniff, DENY framing and noindex. HTML responses
  use Referrer-Policy: same-origin so ordinary same-origin form POSTs retain
  their Origin header and external referrers remain suppressed. Non-HTML
  responses retain no-referrer. Missing/null/wrong Origin still fails closed;
  restrictive self-only scripts/styles/forms/connect, no inline script or remote
  resources. Escape dynamic markup. Responses and tracing never contain raw
  headers, forms, secret values, stored credential structs or inventory errors.

## Page and forms

GET `/admin/corp` returns 200 with escaped Russian responsive markup, a fresh
CSRF token and sanitized current state; no binding is a setup state, not an
error. Show the immutable bound user's display label and availability, enabled
switch, policy identity, revision, config version, reader/key IDs, active key,
and per-eligible-server verification states. Do not serialize `CorpRecord` or
`CorpCredentials`; project only an explicit allowlist of safe fields. Status
must distinguish absent, disabled, missing/disabled user, unverified, stale,
configuration changed and ready; ready is not proof of client rollout.

All existing-binding forms carry `expected_config_version` from this page.
Re-read current credentials, alter only the requested field and call inventory
CAS. Never retry stale writes automatically. No route deletes or rebinds Corp,
resets a generation/revision, publishes content or changes user grants.

| POST route under `/admin/corp` | Additional exact fields | Successful behavior |
|---|---|---|
| `/setup` | `user_id`, `confirm_binding=true` | Require existing enabled user; generate policy ID, password, reader and P-256 key; call `create_corp`; remains disabled with revision 0. Show password once after commit. |
| `/enabled` | `expected_config_version`, `enabled` (`true`/`false`), `confirm=true` | Use `update_corp_security` preserving credentials. Disable always remains available; enable follows the gate below. |
| `/password/rotate` | `expected_config_version`, `confirm=true` | Generate a fresh password/PHC, replace only password, show password once after commit. No password overlap. |
| `/readers/add` | `expected_config_version` | Generate and append one reader; reject at two. Existing reader remains accepted. New reader ID appears on page; token only through protected export. |
| `/readers/remove` | `expected_config_version`, `reader_id`, `confirm=true` | Remove selected reader; reject unknown ID or last remaining reader. |
| `/signers/add` | `expected_config_version` | Generate and append inactive P-256 signer; reject at four, never evict another key implicitly. |
| `/signers/activate` | `expected_config_version`, `key_id`, `confirm=true` | Select existing validated signer; retain previous keys; next ordinary publication uses it. |
| `/signers/remove` | `expected_config_version`, `key_id`, `confirm=true` | Reject active/unknown key or any key needed to validate current or retained history; otherwise remove. |
| `/sessions/revoke` | `expected_config_version`, `confirm=true` | Call `revoke_corp_sessions`, including when no sessions exist. |
| `/export` | `expected_config_version`, `reader_id` | Protected capability download; no mutation, rotation or audit-on-read. |
| `/probe` | `expected_config_version`, `server_id` | Until a trusted proof provider is separately specified, return 503 with sanitized “verification unavailable”; no network or mutation. |

Ordinary committed changes return 303 to `/admin/corp`. Setup/password rotation
return 200 with the one-time password and a continue link, never a secret in a
redirect/flash cookie. Refreshing GET cannot recover plaintext. A lost response
requires inspecting state and rotating again, never retrying setup blindly.
Export returns 200 attachment with a fixed filename and no redirects. Probe
failure/status is shown on the operator page; never ask the operator to SSH.

Generate password and reader from independent 32-byte CSPRNG values, canonical
URL-safe unpadded base64; generate IDs independently within storage identifier
bounds. Password hash is Argon2id v19, 19456 KiB, two iterations, one lane,
16 random salt bytes and 32 output bytes, using shared bounded password work.
Entropy/hash/key failure returns generic 503 with no mutation. Use
`PolicySigningKey::generate`, `export_pkcs8_der`, `spki_base64`; store standard
base64 PKCS8/SPKI. Validate matching P-256 material before setup and credential writes. Disabling
access with unchanged credentials is an emergency authority-removal operation:
skip daemon cryptographic validation for disable only, while retaining storage
shape validation, CAS, session revocation and atomic audit. A corrupt existing
PKCS8/SPKI pair must not prevent disable.
Secret-bearing temporaries use redacted/zeroizing wrappers; never derive Debug
or Serialize on a handler model containing them.

Security and egress mutations inherit inventory's atomic FULL/BEGIN IMMEDIATE
transaction, same-transaction audit and CAS. `update_corp_security` and actual
egress changes revoke all Corp sessions and advance auth/config generations;
identical normalized security input remains a no-op. Session revoke always
advances generations. All preserve UserId, policy ID, history and revision.
Actor is a bounded fixed operator-action label, never supplied by a form.

## Enable and verification gate

Enable requires an enabled existing bound user, internally valid credentials,
current eligible server choices and at least one fresh, matching verified exit
mapping. Recheck eligibility immediately before CAS. The browser still applies
its per-request eligibility/fingerprint/24-hour expiry checks; the operator
switch alone never grants access. Revision 0 is allowed and clearly shown as
“no policy published”; enabling does not seed/publish or bypass reader 404.

The unresolved effective TCP/UDP transport proof in CORP-EGRESS-PROOF and
CORP-PORTAL-TRANSPORT blocks enabling in this implementation slice. Render the
button disabled with an explanation; a crafted enable POST returns 503 without
mutation until the lead approves and specifies that proof gate. Disable, repair,
rotation and session revocation work while disabled or the bound user is absent.

Status reads use `eligible_servers` and `corp_verified_egress`, comparing current
fingerprints and timestamps; no DNS resolution, server SSH or assurance pass can
promote a mapping. Do not expose share links, secret-derived canonical input,
private addresses, pinned SSH material or raw runner output. A later proof API
must bind actual observed canonical exit IP to exact eligible connection,
user/server, current fingerprint, expiry and transport coverage; compare the
fingerprint again before `replace_corp_egress(expected_config_version, ...)`.
Failed/cancelled/conflicting probes preserve all previous evidence and cannot
refresh its age. No manual “verified IP” form or invented provider signature.

## Export and rotation limits

The download is the exact optional `business.policy` object accepted by the
client: `{policy_id,endpoint,read_token,keys}` with `keys` an array of `{id,spki}`
for all retained keys. `endpoint` is the
fixed HTTPS Corp reader URL from the HTTP contract, without query credentials;
reader authentication stays in the Authorization header. No password/PHC,
signing private key/PKCS8, VPN subscription capability or DB/session data.
The file is itself sensitive because it grants read access. Export one explicitly
selected current reader, including while disabled for preparation; missing
binding is 404. Recheck config version immediately before returning; stale is
409. Already issued bytes cannot be revoked retroactively; reader removal
invalidates future fetches. The object must be inserted into the preserved complete private bundle; it is
not a standalone employee import file or a replacement VPN subscription.

Reader overlap is explicit add -> export/migrate -> remove; no timed retirement
or auto-eviction. Signer overlap is add -> export/migrate trust -> activate ->
retire when safe. Export new trust before activating, but server cannot attest
that clients imported it; require confirmation and explain offline clients.
Removing a signer used by retained history would break current historical
validation, so block it. At four retained keys, rotation may require a later
history/trust migration contract; never silently prune or reset policy identity.
Rotations do not re-sign the current envelope or claim clients applied anything.

## Failure and independent verification contract

After authentication: malformed form/invalid action 422; wrong Origin/CSRF 403;
missing target 404; stale CAS, duplicate setup, overlap limit, exhausted counter
or unsafe retirement 409; unavailable bound user on enable 503; inventory,
audit, crypto and unsupported proof/configuration errors generic 503. Unknown
routes return 404, unsupported methods 405. No errors contain underlying store
messages. Audit failure must leave all state unchanged. Timeouts/network loss
can race a commit: retain context, require reloading status before another write,
and explain that one-time password recovery means a new rotation.

Spec tests must cover every route's success, denied-auth and invalid/stale-input
path; absent/malformed BasicAuth; Corp host, cookie and reader isolation; exact
Origin and CSRF expiry/tampering; duplicate headers/form keys and size bounds;
immutable binding after deletion; setup remains disabled; blocked enable/probe;
all overlaps/last-reader/active-and-history-signer rejection; password/reader
revocation and in-flight generation races; CAS and audit rollback; sanitized
status/error/Debug and export field allowlist; one-time password loss; unchanged
policy identity/revision/envelope across rotations; no-op audit behavior and
reopen persistence. Render synthetic 340/420 px operator pages and verify labels,
escaping, one-time reveal and conflict reconciliation without external traffic.

## Source-backed interfaces and lead decisions

Existing APIs, not proposed new Rust symbols:

- `daemon/src/app/routes.rs`: `router`, `admin_router`, optional BasicAuth branch,
  legacy body/timeout limits; `daemon/src/corp_portal.rs`: `isolate` host boundary.
- `daemon/src/handlers/auth.rs`: `BasicAuth::from_parts`, `require_basic_auth`,
  `bounded_password_work`, `VERIFY_PERMITS`; session authentication remains
  private. `handlers/csrf.rs::require_same_origin` is insufficient for this scope.
- `crates/inventory/src/sqlite/corp.rs` and `corp/types.rs`: `corp_record`,
  `create_corp`, `update_corp_security`, `revoke_corp_sessions`,
  `corp_verified_egress`, `replace_corp_egress`, `corp_history` and redacted types;
  exact signatures/bounds are in [storage](corp-policy-store.md).
- `daemon/src/corp_policy/wire.rs`: `PolicySigningKey` generation/import/export,
  `spki_base64`, `verify_envelope`; `corp_portal/eligibility.rs::eligible_servers`
  has the exact signature in [eligibility](corp-policy-eligibility.md).
- `daemon/src/protocol_assurance_poller.rs::RunnerResult` contains stage/state,
  latency/failure/client kind, no observed exit IP. It is not an egress proof API.

## Frozen integration and test interfaces

Public daemon interfaces (to implement in this block):

```rust
pub mod corp_operator {
    #[derive(Clone)] // no secret-bearing Debug/Serialize
    pub struct OperatorConfig { /* private fields */ }
    impl OperatorConfig {
        pub fn from_parts(user: Option<String>, password: Option<String>,
            origin: Option<String>, install_secret: &str) -> Self;
        pub fn with_clock(self,
            clock: std::sync::Arc<dyn Fn() -> i64 + Send + Sync>) -> Self;
    }
}
pub mod app {
    pub fn router_with_corp_operator(state: AppState,
        config: crate::corp_operator::OperatorConfig) -> axum::Router;
}
```

`from_parts` retains unavailable/malformed configuration as an opaque denied
state (503), not a panic or accidental absent-auth state. The production
`app::router` obtains the same config from existing admin user/password and
installation secret plus `VPNCTLD_CORP_OPERATOR_ORIGIN`, with a UTC clock.
The injected router uses the same exclusive Corp-host and operator-path dispatch;
it must not bypass limits, hardening or authorization. Mount the strict subtree
before the legacy operator auth/CSRF layers, behind the outer Corp-host boundary.
A path equal to `/admin/corp` or beginning `/admin/corp/` never falls through to
legacy handlers, including errors, unknown paths and trailing slash forms.
Expose a navigation link from the existing operator UI. All state-changing
operations have visible HTML forms, including inactive-key activation and removal.

Origin configuration is a canonical HTTPS origin with a nonempty host and
optional port, no userinfo, path (including trailing slash), query or fragment.
It must equal URL origin serialization and differ from the fixed Corp origin.
Host comparison is case-insensitive with the exact configured authority;
absolute URI authority/scheme must also agree. Reject query strings on this
subtree with 422. Reject ambiguous Host/Authorization/Cookie/Origin fields with
400 before authentication; duplicate operator session cookie names also fail.
Missing/incorrect configured Host is 400. Cross-site Fetch Metadata is 403.
Malformed form bodies are 422; bodies over 8192 bytes are 413.

Reuse the existing successful BasicAuth/cookie verification and shared password
work semaphore; do not duplicate password verification or weaken legacy auth.
Add purpose-specific methods to BasicAuth for CSRF, keeping its session key
private. CSRF format is `v1.<issued>.<nonce>.<mac>`: issued is canonical positive
decimal UTC seconds, nonce is canonical base64url-no-pad of 32 random bytes,
mac is canonical base64url-no-pad HMAC-SHA256 under the existing derived admin
session key. MAC input is the UTF-8 bytes of
`vpnctl-corp-operator-csrf-v1\0` followed by length-prefixed username and origin
(`<byte_length>:<value>`), then `:<issued>:<nonce>`.
Verify MAC in constant time, require `issued <= now < issued + 3600`, reject
noncanonical encodings, extra fields and malformed/overflow/future timestamps.
Token generation failure returns 503. Credential/install-secret/user/origin
changes invalidate earlier tokens. Every HTML form includes the hidden input
`name="csrf" value="..."`; no token appears in a URL. Password reveal uses
`<code id="corp-generated-password">...</code>` for isolated assertion and
private owner capture; ordinary GET and exports never contain that password.
No server-side claim is made that the owner saved the reveal. A lost response
requires state inspection and deliberate rotation with a fresh version.

Test fixture support already available, without environment mutation:
`SqliteInventory::open(&Path).await`, `add_user(&vpnctl_core::User).await`,
`get_user(&UserId).await`, `list_users().await`, and
`app::make_app_state_for_tests(inv, Arc::new(vpnctl_kernels::build_registry()?))`
returning `(AppState, JoinHandle<()>)`. Abort that fixture job at teardown.
A User has fields `id: UserId(String)`, `uuid: String`, `tuic_password`,
`wireguard_pubkey`, `wireguard_private`, `sub_token`, `vpn_router_device_id`
(all optional strings) and `disabled: bool`. Use synthetic IDs and UUIDs.
AppState is Clone and exposes `inv: SqliteInventory`; storage/wire APIs are
specified in the adjacent contracts. Pass inventory by value (clone when needed).
Inventory also offers `remove_user(&UserId) -> Result<()>`,
`set_user_disabled(&UserId, bool) -> Result<bool>` and
`recent_audit(i64) -> Result<Vec<AuditEntry>>`, all async. User display label here
is the escaped UserId string. A successful Basic-auth GET issues the existing
`vpnctl_admin_session` cookie, which can authenticate later strict requests.

Optional synthetic export `CORP_OPERATOR_UI_OUTPUT_DIR` from independent tests
writes actual `setup.html`, `status.html`, `password-result.html`, `conflict.html`
pages plus matching JSON `{status,headers}` metadata and actual CSS at
`assets/operator.css` (served by `/admin/corp/assets/operator.css`). Export only
security headers, never Set-Cookie. Use only fixed synthetic credentials and disable network
in the browser fixture. Assert every form exists and exercise user actions via
real router tests; later CI browser tests inspect 340/420px layouts and reveal.

## Candidate verification receipt

Implemented setup/disable, password/readers/signers rotation, session revocation,
exact `business.policy` export, strict origin/auth/CSRF and Russian operator forms.
Enable/probe remain unavailable until actual-egress proof is implemented. The
independent spec writer supplied 39 request-level tests, including emergency
disable with a mismatched existing key pair and a synthetic unverified server
for UI export. Two independent diff reviewers examined source/tests/browser/CI;
lead fixed the confirmed setup ordering issue and rejected the history-limit
hypothesis against storage's atomic newest-100 retention contract. Source-only
formatting, workflow and JS syntax checks passed. No local compilation, runtime
or browser execution occurred; exact-head CI and new screenshot inspection are
pending. No production configuration or access was changed.

CI follow-up at `8462654` (run `43703472561`): all 39 operator and 34
portal HTTP tests passed, and Cargo check/Clippy/static musl succeeded. Native
browser form submission failed because HTML's `no-referrer` policy serializes
the form Origin as `null`; full tests and `just ci` also failed the old
eight-item navigation assertion. Both findings were recorded before correction.
HTML now preserves same-origin form Origin without sending external referrers;
downloads, redirects and API responses retain `no-referrer`. Login browser
verification submits the actual password form. Independent spec tests now total
40 operator and 35 portal cases and explicitly reject `Origin: null`. Corp uses
the shared navigation renderer and decorative icon; the nine-item regression
still verifies every previous link, icon and localized label.

Independent final diff review returned no findings. Local formatting, JS syntax,
actionlint, generated CSS/map, whitespace and secret checks passed. Runtime and
browser checks remain CI-only and are pending for this
correction. Client portal transport at VPNRouter `098b7d34` is green (13
successful jobs, three expected manual-delivery skips); that is source/CI
evidence, not a deployed portal or actual-egress proof.
