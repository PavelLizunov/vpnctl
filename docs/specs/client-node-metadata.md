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

## CI correction: test fixture visibility

Exact-head de4976b passes cargo check, fmt, deny, gitleaks and managed artifacts.
Clippy rejects ten unrestricted pub methods inside the private test fixture
(unreachable_pub under -D warnings). Restrict those fixture methods to pub(super),
which still admits the sibling spec tests. No lint suppression or production
change is needed. Record this before correction; full tests/SSH suites and the
replacement exact-head CI remain pending.

CI43e07bb: the non-exit spec fixture used vpn-entry, which the existing role CHECK rejects before the endpoint runs.
Use the permitted workload-only role with the same exclusion assertions; no production or schema change.

CI2ace802 reaches the grant step and exposes an additional fixture constraint:
migration0053 rejects grants to workload-only servers even when inserted directly.
The negative endpoint oracle remains unchanged. Add an explicit TEST-ONLY legacy
grant seeder in the unique temporary fixture DB, remove only that local insert
trigger before the synthetic grant, and keep the real role-filtering endpoint
assertion. Never change production schema, migrations, grant logic or live state.
This corrects the fixture rather than deleting the denied-role consumer case.

## Confirmed cross-repository P2 before correction

Final GPT ASTRA XHIGH reviewed client25f3ca38/backend2ace802 and found raw endpoint
deduplication incompatible with the client's canonical keys. Admin config keeps
case; one Reality+Naive node can emit both node.example.test and NODE.example.test,
so the client rejects the entire snapshot. Coordinator traced and confirmed it.
After current176e1ad CI is green, canonicalize SAME-NODE DNS case/trailing-dot and
IP spellings before deduplication. Never merge genuinely ambiguous different-node
rows or weaken client duplicate rejection. Add producer-to-consumer regression,
independent diff review and final Astra recheck. No implementation/live claim yet.

## Alias correction and reviewable deployment artifacts

Exact176e1ad now passes all ten CI jobs, including full workspace tests and
Docker SSH suites. The next block fixes the confirmed alias producer contract.
Within ONE server, canonicalize DNS ASCII case and one optional trailing root
dot, plus equivalent IP spellings, BEFORE endpoint deduplication. Reject malformed
hosts; distinct hosts remain distinct, and different physical-server rows must
not be silently merged. The strict client duplicate oracle remains unchanged.

An independent spec writer receives only this contract and fixture signatures:
Fixture::new/user/node/grant/request as above; NEW
fixture.protocol_alias(&node, protocol_id:&str, endpoint_host:&str).await seeds
a visible enabled naive or vless-ws alias without DNS/network. It is TEST-ONLY.
Write endpoint_alias_spec_tests.rs using actual router responses: same-node case,
trailing-dot and IPv6 equivalence yield one canonical host; different aliases
remain separate; different nodes sharing an alias remain distinct/ambiguous.
Also provide a synthetic JSON snapshot with generated_at2000, ttl1320, one
canonical DNS host, all sample/country fieldsnull and freshnessunknown. Backend
response comparison may normalize ONLY its generated_at to2000; client consumer
parses the identical fixture. No identity/live data enters either fixture.

Prepare a generic GitHub pull-request/manual candidate-artifact workflow so the
reviewed exact head can produce musl daemon+CLI, pinned managed sing-box/helper
and same-revision assets together. Existing CI remains the activation gate.
Build only on GitHub after capacity/tool preflight, embed VPNCTL_BUILD_SHA, include
source/digests, upload binaries/assets only (no config/inventory/secrets), and
perform no deployment/tag/release. Controlled production activation remains a
separate owner-approved step under commercial-operations; no new live claim.

Alias/artifact block source receipt: same-node endpoints now canonicalize before
BTreeSet insertion; different-node ambiguity is preserved and malformed aliases
are omitted. An independent spec-only writer adds11 actual-router tests and a
shared synthetic snapshot; the C# HTTP consumer parses an identical copy. A
separate boundary test keeps bracket/IP/error cases. No new library dependency.
Source search found no interchangeable canonicalization helper; existing inline
SNI validation has different IP/root-dot policy and remains untouched.
Independent diff-only review of the complete block returned[]. cargo fmt/app-map
checks and workflow shell/Python/YAML syntax checks pass. No local compilation,
full tests or SDK installation. New exact-head CI and final Astra recheck remain
pending. Candidate artifacts contain no live state and perform no deployment.

## Confirmed preactivation CPU compatibility failure

Candidate1fafc61 passes hosted CI but both Rust binaries SIGILL on actualVM119,
whose verified flags lackAVX/AVX2. Existing662b411 remains healthy and untouched.
Child-only trace resolves c5f96ec2 atELF0xaeea54 to
aws_lc_0_45_0_OPENSSL_cpuid_setup+0x64 (vmovd). This is C crypto initialization,
not a DB/permissions failure. No explicit native flags were found; do not claim
the original flag cause. Protected four-binary/asset backup, consistent SQLite
backup/integrity/FK and separate restore selfcheck already pass.

Record before correction: force baseline x86-64 for Rust and C cross-compilation
using supported target CFLAGS/AWS_LC_SYS_CFLAGS; add an AVX-less Nehalem QEMU
version gate on GitHub before upload. No tool/SDK install or new build on Harness
or production, no CPU/security configuration change and no live activation of
the rejected artifact. Existing candidate smoke and exact-source gates remain.
