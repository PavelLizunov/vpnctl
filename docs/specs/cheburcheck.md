# Cheburcheck: targeted external observations

## Intent and scope

Owner request, 2026-11-05: integrate static and dynamic Cheburcheck checks into
vpnctl. This explicitly permits sending the selected configured node's public IP
to that service and supersedes the former blanket exclusion in
`private-vantage-checks.md`. Controlled private checks keep their existing path.
No background sweep, route/subscriber mutation or public-service dependency at
startup is introduced. A check is not a VPN handshake or an automatic repair.

## HTTP and operator contract

- Authenticated GET `/admin/monitoring/cheburcheck`: configured servers, latest
  observations and links to each check; GET never calls the external service.
- Authenticated GET/POST `/admin/servers/{id}/cheburcheck`: page / start one run.
  Existing same-origin POST/CSRF rules apply. Missing server is 404. Only its
  literal public IP, or exactly one stored resolved public IP, is eligible;
  unsupported/private addresses return 422 without external network activity.
- Accepted POST returns 303 to that node's check page. The runner is detached
  from the HTTP response and bounded to 80 seconds. One run globally; busy POST
  is 409. Starts are at least 15 seconds apart; earlier POST is 429 with bounded
  Retry-After. Rejected starts do not clear existing results or write audit rows.
- Results are stored using the existing audit journal, under
  `server.cheburcheck.started` and `server.cheburcheck.result`, not new health or
  assurance rows. Existing audit retention applies. Start/result payloads carry
  a matching run ID, inventory address, chosen IP and timestamps. A latest start
  without a matching result after restart is interrupted, not healthy/running.
  Concurrent GETs at normal completion must see running or finished, never a
  false interrupted state caused by mixing old journal data with a cleared run.
- UI shows source, target, timestamp, running/partial/failed/interrupted/stale
  and address-changed states, with the checked IP separate from the current
  target IP. Stale means older than one hour. A list miss is
  labelled only as a list miss; regional TSPU findings remain visible alongside
  it. Missing/uncertain observer replies are not counted as blocks. Cached
  observer results are identified. All upstream text is escaped.
  The node page's `#cheburcheck-checks` container exposes `data-state` as
  `not_checked`, `running`, `finished` or `interrupted` for scoped refresh.
- The page names the external service and that the selected IP is sent there.
  Credentials, subscription URLs, raw lookup IDs/check contexts are never sent
  as targets, stored in reports, exposed in UI or included in errors/logs.
  Malformed inventory addresses containing full URLs/credentials are not echoed
  on check pages, including the overview; show an unavailable address instead.
- Link from monitoring and server details. Normal forms and manual refresh work;
  scoped polling refreshes running/busy/cooldown pages without repeated clicks.

## Public adapter contract (`vpnctld::cheburcheck`)

Types derive Clone/Debug/Serialize/Deserialize/PartialEq where applicable.

```rust
pub struct ListResult {
    pub blocked: bool,
    pub blocked_subnets: Vec<String>,
    pub providers: Vec<String>,
}
pub enum DynamicPhase { NotStarted, Running, Done, Partial, Unavailable }
pub struct ProbeReport {
    pub region: Option<String>, pub provider: Option<String>,
    pub asn: Option<String>, pub cached: bool, pub verdicts: Vec<String>,
    pub target_hop: Option<u16>, pub dpi_hop: Option<u16>,
}
pub struct DynamicResult {
    pub phase: DynamicPhase, pub online_probes: Option<u32>,
    pub reports: Vec<ProbeReport>,
}
impl DynamicResult {
    pub fn verdict_count(&self, verdict: &str) -> usize;
    pub fn not_reported(&self) -> Option<u32>;
}
pub enum FailureCode {
    RateLimited, Unavailable, InvalidResponse, ResponseLimit, Timeout, NoObservers,
}
pub struct Failure { pub code: FailureCode, pub retry_after_secs: Option<u32> }
pub struct Report {
    pub list: Option<ListResult>, pub dynamic: DynamicResult,
    pub failure: Option<Failure>,
}
pub struct SseEvent { pub event: String, pub data: String }
pub struct SseDecoder { /* private */ }
impl SseDecoder {
    pub fn new() -> Self;
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<SseEvent>, Failure>;
}
pub struct ProbeAccumulator { /* private */ }
impl ProbeAccumulator {
    pub fn new() -> Self;
    pub fn apply(&mut self, event: &str, data: &str) -> Result<bool, Failure>;
    pub fn snapshot(&self) -> DynamicResult;
}
pub struct Client { /* private */ }
impl Client {
    pub fn new() -> Result<Self, Failure>;
    pub fn for_base_url(base_url: &str) -> Result<Self, Failure>;
    pub async fn check(&self, address: std::net::IpAddr) -> Report;
}
```

`Client::new` uses only `https://cheburcheck.ru`. `for_base_url` is an injection
seam for local fixtures: HTTPS endpoints and HTTP loopback are accepted; userinfo,
query, fragment and non-root path are rejected. Redirects are disabled. No URL
override is exposed in the admin request or environment. Lookup is GET
`/api/v1/check?target=<ip>`; its transient signed `id` supplies GET
`/api/v1/probe/<encoded-id>`. Target must match the requested IP before starting
the probe. No observer registration/token is needed.

Static body <=128 KiB; SSE total <=512 KiB; buffered event <=32 KiB; <=256
distinct reports; context <=2048 bytes. SSE handles split UTF-8 chunks, LF/CRLF,
comments and multiline data. Unknown event types are ignored. Malformed known
events/oversize data fail explicitly. Duplicate observer IDs are ignored.
`started.online_probes` and `done.response_count/online_probes` must agree with
collected distinct reports; contradictory totals cannot be Done. Done with zero
observers is Unavailable/NoObservers. EOF/timeout before Done preserves partial
reports, never implies a healthy target. A response behind DPI is not a VPN test.

Upstream 429 gives RateLimited and parsed Retry-After clamped to 1..3600 seconds
(default 60); no automatic retry. Network/status/parse errors use safe fixed
failure codes; never format reqwest errors containing signed paths. Partial
dynamic failure keeps a successful list result, with partial/unavailable state.
Unsupported future verdict strings remain bounded/escaped and never become `ok`.

For external HTTP tests, add
`vpnctld::make_app_state_with_cheburcheck_for_tests(inv, registry, client)` with
the same return type as `make_app_state_for_tests`; it replaces only this client.
Tests use loopback service fixtures and documentation IP targets, no live calls.

### Fixture schemas and state seams

Lookup fixture (extra upstream fields are ignored):
```json
{"id":"fixture-signed-context","target":"198.51.100.9","blocked":false,"blocked_subnets":[],"cdn_providers":{}}
```
SSE frames use `event: <name>\ndata: <JSON>\n\n`:
```json
{"event":"started","data":{"online_probes":2}}
{"event":"result","data":{"probe_id":"1","cached":false,"region":"Example","provider":"Example ISP","asn":"AS64500","verdicts":["tspu_block"],"target_hop":null,"dpi_hop":2}}
{"event":"result","data":{"probe_id":"2","cached":true,"region":"Other","provider":"Other ISP","asn":"AS64501","verdicts":["uncertain"],"target_hop":null,"dpi_hop":null}}
{"event":"done","data":{"response_count":2,"online_probes":2}}
```
DynamicResult serializes phase in snake_case and stores no probe IDs. Provider
keys in `cdn_providers` become `ListResult.providers`. Lists are bounded and
text fields capped; unknown verdict strings remain bounded (at most 64 bytes).

Existing fixture construction APIs:
```rust
SqliteInventory::open(path: &std::path::Path) -> impl Future<Output=Result<SqliteInventory, _>>;
SqliteInventory::add_server(&self, server: &vpnctl_core::Server) -> impl Future<Output=Result<(), _>>;
SqliteInventory::audit(&self, actor:&str, action:&str, target:Option<&str>, payload:Option<&serde_json::Value>) -> impl Future<Output=Result<(), _>>;
Registry::new() -> Registry;
make_app_state_with_cheburcheck_for_tests(inv:SqliteInventory, registry:std::sync::Arc<Registry>, client:Client)
    -> (vpnctld::AppState, tokio::task::JoinHandle<()>);
vpnctld::router(state: vpnctld::AppState) -> axum::Router;
```
Server fixture shape:
```rust
Server { id: ServerId(String), address: String, ssh_port: u16,
 ssh_user: String, kernels: Vec<KernelId>, enabled_protocols:Vec<ProtocolId>,
 trusted_host_fingerprint:Option<String>, hoster:String,
 jump_via:Option<ServerId>, usage_coefficient:f64 }
```
An empty Registry suffices for these check pages. With admin credential env unset,
the established in-process test router accepts GET; cross-origin POST is always
403. Do not mutate process-wide environment to synthesize auth configuration.

Audit payload shape (used to seed stale/interrupted fixtures):
```json
{"run_id":"fixture-run","address":"198.51.100.9","inventory_address":"198.51.100.9","started_at":"2026-01-01T00:00:00Z","finished_at":"2026-01-01T00:00:10Z","report":{"list":{"blocked":false,"blocked_subnets":[],"providers":[]},"dynamic":{"phase":"done","online_probes":1,"reports":[{"region":"Example","provider":"Example","asn":"AS64500","cached":false,"verdicts":["tspu_block"],"target_hop":null,"dpi_hop":2}]},"failure":null}}
```
Started payload has the same identity/timestamps with finished_at/report null.
POST payload/body cannot override the target. Prior reports remain available in
the journal, but an unmatched latest start is interrupted, not a fresh old result.

A new exact journal lookup avoids prefix/substring ambiguity:
```rust
SqliteInventory::latest_audit_for_target_action(&self,target:&str,action:&str)
    -> impl Future<Output=Result<Option<vpnctl_inventory::AuditEntry>, _>>;
```
It returns the newest exact target/action pair by monotonic row ID, or None.
AuditEntry exposes id:i64, action:String, target:Option<String>, payload:Option<Value>,
ts:DateTime<Utc>, actor:String. Test target/action near-matches as well as no row.

## Verification

Independent spec-derived tests cover decoder fragmentation/bounds, deduplication,
zero/mismatched totals, static-miss plus dynamic blocks, rate limits, partial
failure and credential/context omission. Admin tests cover auth/CSRF, inventory-
only targets, retained results after reconstructed AppState, changed address and
escaped remote strings. Existing private checks and subscriptions stay unchanged.
Record actual checks separately from planned cases. No forced production outage
is part of this integration.
