# Client node metadata

## Intent and invariants

Add read-only country/load for authenticated VPNRouter subscriptions. Production
baseline is 662b411. Existing `/sub`, share links, app/config and admin outputs
remain byte compatible. Never allocate peers/WG addresses, refresh DNS, execute
SSH or change inventory/audit/subscription-fetch counters from metadata polling.
No admin credential in a client. No fleet, peer, private-key, SSH or employee data.

## Interface and data contract

- GET `/api/v1/app/node-status/device/{device_id}` uses existing VPNRouter device identity.
  GET `/api/v1/app/node-status/subscription/{token}` uses existing subscription identity. Missing,
  malformed, unknown, disabled or revoked credentials return the same generic
  401 response. Nested/trailing path segments must not become credentials.
- Use bounded in-memory throttling without persistent bans/access logs, with
  token namespaces separate from existing subscription-render quota. Return
  429 + Retry-After when throttled. Token budget is 60 requests/minute per identity; the 61st immediate request is 429, while a distinct identity has its own budget. IP attempts are also bounded without persistent state. Trace only matched route templates; no secrets.
- All responses have no-store/nosniff/no-referrer headers. Success JSON:
  `{"schema":1,"generated_at":UNIX_SECONDS,"max_age_seconds":TTL,"nodes":[...]}`.
- Each node has ONLY `endpoint_host`, `country_iso`, `memory_total_mib`,
  `memory_available_mib`, `load_1min_x100`, `observed_at`, `age_seconds`, `freshness`.
  Optional data is JSON null, never zero as a stand-in for absent data. Country
  is uppercase ISO alpha-2 from existing local AppState.geo lookup of the node
  IP, or existing cached resolved IPs for a hostname. Conflicting/missing cached
  countries mean null. No outbound lookup or use of provider names/access logs.
- Query only servers granted to that enabled user with role vpn-exit; apply the
  existing protocol enable/visibility/override policy. Never include another
  user's grants, hidden nodes, peers or audit rows. Match endpoints to issued
  host semantics, not display labels. Explicit DTO fields prevent extra leakage.
- Use existing latest node_health data. Valid memory has total>0, 0<=available
  <=total; invalid/missing pair becomes null. Load outside 0..u32::MAX becomes null (existing inventory typed range). The
  value is Unix load average times100, NOT CPU percentage. Do not invent CPU%.
- `observed_at` is the sample Unix timestamp. Derive age on the server, not from
  the client's wall clock. TTL is two effective probe intervals +120 seconds
  (default interval 600 => TTL 1320), with saturating arithmetic and an upper TTL cap of 86400 seconds. A future sample
  has unknown freshness/age. No sample => unknown/null. Within TTL => fresh;
  older => stale. Keep sample values/timestamps when stale, labeled stale.
- Device and subscription identities for the same user yield the same projection.
  Empty grants return nodes:[]; unavailable metrics do not suppress country.

## Independent spec tests and fixture contract

Tests live in `daemon/src/handlers/client_nodes/spec_tests.rs` and may import
`super::spec_support::{Fixture, Sample}`. The implementation owner supplies a
TEST-ONLY fixture module without consulting these tests. Fixture methods:

- `Fixture::new().await -> Fixture` (fresh temporary SQLite + AppState/router).
- `fixture.user(disabled: bool).await -> UserFixture` with public `device_id`
  and `sub_token` Strings; distinct calls create distinct users.
- `fixture.node(endpoint_host: &str, visible: bool, role: &str).await -> NodeFixture`.
- `fixture.grant(&user, &node).await`, `fixture.revoke(&user, &node).await`.
- `fixture.sample(&node, Sample { total:Option<i64>, available:Option<i64>,
  load_x100:Option<i64>, observed_at:i64 }).await`.
- `fixture.now() -> i64`, `fixture.ttl() -> u64` (effective interval default).
- `fixture.request(path: &str).await -> (StatusCode, HeaderMap, serde_json::Value)`
  through the actual registered router/handler, not a mock response.
- `fixture.read_only_counts().await -> serde_json::Value` snapshots relevant
  peer/WG-allocation/audit/subscription-access counts; no metadata mutation.

Writer sees only this spec, not implementation. Cover valid fields/null/boundary,
auth/disabled/nested identities, grant isolation/visibility/role/revocation,
read-only counts, identical device/sub-token data, absent/stale/future samples,
headers and the explicit response allowlist. Use only synthetic endpoint data.
Country may be null in an empty test GeoIP database; do not fake a country from
labels. A separate deterministic projection unit test must cover local lookup
and hostname ambiguity without network access.

## Verification and outcome

Required: independent diff-only reviewer before commit, independent spec writer,
legacy byte regressions, gitleaks, fmt/check/clippy/tests/deny and GitHub CI on exact
SHA. Harness runs no SDK/project build or automatic gc. Record CI as substitute
for unavailable local heavy gates. Source editing does not mean production live.
Deployment later uses the approved same-revision daemon+CLI workflow, protected
backup and affected-surface/grant/header/legacy verification. No mutation yet.


## Pre-commit independent review disposition

Source-only diff reviewer identified two important issues before any commit:
(1) a future-sample test used an epoch outside Chrono's representable range,
causing the fixture to panic before reaching the endpoint; use a valid distant
future date (year9999 epoch 253402300799) while retaining unknown-age assertions.
(2) unauthenticated IP churn could fill the shared 4096 bucket table and block new
legitimate authenticated identities. Separate anonymous IP capacity/eviction from
credential capacity and add a deterministic saturation regression. Both findings
are recorded before correction; no production or CI execution is claimed.

## Pre-CI source receipt

- Independent spec writer supplied 28 fresh-SQLite real-router scenarios without
  reading implementation. Separate diff-only review found the two issues above;
  both were corrected, and a new independent diff-only review returned [].
- Added separate anonymous/credential capacities, LRU anonymous admission and
  deterministic saturation/reset regressions; valid year9999 future input and
  TTL saturation boundaries are present. No source review is a test execution.
- Existing grant/visibility/endpoint/render helpers were searched for duplicate
  logic. Metadata projection deliberately does not call render/input helpers that
  allocate peers or record subscription fetches. Existing rate-limit ownership
  anchors bounded ephemeral polling state without consuming render quota.
- cargo fmt --all and fmt check passed; deterministic project map was regenerated
  and checked. No locked dependency version changed (one test dependency edge).
- Harness policy prohibits local builds/full tests/SDK installs and automatic gc.
  check/clippy/full tests/deny/legacy-byte and SSH suites therefore require exact
  SHA GitHub CI. Local gitleaks is unavailable; CI gitleaks remains a required
  unresolved gate. No production installation, service restart or live API claim.
- Production activation is separate from implementation. Follow the explicit
  commercial-operations change window/approval policy after reviewable artifacts
  and isolated candidate verification are ready. Preserve the previous complete
  runtime set independently: deploy.sh removes its temporary rollback files after
  a successful installation, before service activation.

Base provenance: deployed662b411 is the head of existing PR #307, five commits
ahead of main239d2a55. This task does not rewrite or merge that work. The new
metadata diff is relative to662b411; the main-targeted PR retains that production
baseline so its CI validates the complete prospective runtime tree.
