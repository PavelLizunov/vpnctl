# Corp exit observation lifecycle

## Intent and slice boundary

At green baseline `ea16c24`, add the single-use HTTPS observer, serialized owned
probe jobs, revalidation/persistence, operator controls and refresh scheduling.
The production subprocess runner is a following slice: default/test app state
has an unavailable runner until explicitly supplied. This is source preparation,
not a live probe, deployment or activation. The selected TCP plan and renewal
contracts in [egress preparation](corp-policy-egress-preparation.md) apply.

The following block records the lifecycle baseline. Current production runner
construction and refresh wiring are specified by [owned runtime](corp-policy-runtime.md),
which supersedes its preparation-only disabled-production statements. Test
constructors remain isolated and disabled.

## Public daemon seam

Module `vpnctld::corp_egress` exposes the following API. New public types have
safe Debug; requests/controllers/tickets redact all private state and no type
holding a connection or challenge implements Serialize.

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProbeError { Unavailable, NotFound, Busy, Conflict, Failed, CleanupFailed }

pub struct ProbeRequest {
    pub outbound: serde_json::Value,
    pub token: zeroize::Zeroizing<String>,
}

#[async_trait::async_trait]
pub trait ProbeRunner: std::fmt::Debug + Send + Sync {
    fn available(&self) -> bool;
    async fn run(&self, request: ProbeRequest) -> Result<(), ProbeError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttemptState { Idle, Running, Verified, Failed, Conflict, Unavailable }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attempt { pub state: AttemptState, pub finished_at: Option<i64> }

pub struct ProbeTicket; // private oneshot receiver
impl ProbeTicket {
    pub async fn wait(self) -> Result<(), ProbeError>;
}

pub struct EgressController;
impl EgressController {
    pub fn new(runner: std::sync::Arc<dyn ProbeRunner>,
        clock: std::sync::Arc<dyn Fn() -> i64 + Send + Sync>) -> Self;
    pub fn disabled() -> Self;
    pub fn available(&self) -> bool;
    pub fn attempt(&self, server: &vpnctl_core::ServerId) -> Attempt;
    pub fn observe(&self, token: &str, ip: std::net::IpAddr) -> Result<(), ProbeError>;
    pub async fn queue_probe(self: &std::sync::Arc<Self>, app: crate::AppState,
        expected_config_version: u64, server: vpnctl_core::ServerId)
        -> Result<ProbeTicket, ProbeError>;
    pub async fn ready_to_enable(&self, app: &crate::AppState,
        expected_config_version: u64) -> Result<bool, ProbeError>;
    pub async fn refresh_due(self: &std::sync::Arc<Self>, app: crate::AppState)
        -> Result<(), ProbeError>;
}
pub fn spawn_refresh(app: crate::AppState) -> tokio::task::JoinHandle<()>;
```

Add public `AppState.corp_egress: Arc<EgressController>`. Constructors create
isolated disabled controllers, never shared static challenge state. No network
or poller starts in test constructors. This slice leaves production disabled;
the owned-runtime integration will supply the real runner and start refresh.
Existing injected operator router and clock remain supported.

ProbeRequest Debug (normal/pretty) is exactly `ProbeRequest { .. }`; controller
and ticket Debug expose no runner, token, path, connection, or callback. Static
sanitized ProbeError messages never contain underlying inventory/runner errors.

## Jobs, challenges and persistence

- Unavailable/poisoned runner returns Unavailable without starting work. At most
  ONE accepted job globally per controller; overlapping manual/automatic jobs
  return Busy immediately (no unbounded queue). Acquire a permit before async
  preflight and retain it through the owned job and complete runner cleanup.
- Before acceptance require a binding (NotFound), exact config version
  (Conflict), enabled existing bound user (Unavailable), and exact selected
  server plan (NotFound if absent). Eligibility/inventory errors fail closed.
  Binding may be disabled: setup must be able to gather proof. Cap plan size
  at eight outbounds; empty/oversized plans fail without running anything.
- An accepted job is owned by the controller, not by the request future.
  Dropping ProbeTicket, closing the page or timing out the response does not
  cancel/release it. `wait` returns its eventual result. No task handle capable
  of aborting the owned job is exposed. Keep at most 512 sanitized attempt rows;
  evict only finished rows if necessary. Running and saved proof are separate.
- Probe every selected outbound sequentially, unchanged from CorpProbePlan.
  Each gets an independent CSPRNG 32-byte canonical unpadded base64url token.
  Tokens are only passed in memory to the trusted runner and HTTPS header, never
  URLs, files, command arguments, status or logs. Store only its SHA-256 and
  pending observation in the controller. There is at most one pending challenge.
  Its identity implicitly belongs to the owned job's binding/version/fingerprint
  and current endpoint; never reuse a challenge for another endpoint/job.
- A challenge expires after 30 seconds of Tokio monotonic time, which isolated
  CI can advance without sleeping. `observe` requires the
  exact canonical token, uses constant-time hash comparison and consumes it
  exactly once. Missing, wrong, expired or replayed token returns Failed, with
  no prior observation changed. Canonicalize mapped IPv4; require IPv4 and reject
  unspecified, loopback, private, link-local, broadcast and multicast addresses.
  Documentation-prefix fixture addresses such as 192.0.2.1 are allowed.
- A runner success alone proves nothing: require a consumed observation for
  that exact challenge AND a successful runner return. Runner failure, missing
  callback, conflicting config, invalid time or incomplete endpoint coverage
  discards all newly observed IPs and preserves saved proof/age. Clear challenges
  between endpoints and on every failure. Existing proof never becomes younger
  because an attempt started. Old callbacks after completion are rejected.
- Runner owns a bounded operation and cleanup: at most 15 seconds of network/
  process work plus two seconds cleanup per endpoint. The controller does not
  cancel a runner future on a timer (which could orphan its helper); reject
  starting another endpoint after 60 seconds total elapsed. A runner reporting
  CleanupFailed poisons the controller before releasing its permit, discards
  proof, and blocks every future job/enable until daemon restart. Unexpected
  job cancellation/panic must clear the challenge and fail closed too.
- After all endpoints succeed, re-read the binding and exact eligible plan;
  require same user/policy/config version/fingerprint and enabled existing user.
  Require a positive bounded completion clock that did not move before job
  start. Deduplicate observed IPs only AFTER full coverage. Set verified_at to
  completion time; replace this server's entire previous rows, preserving other
  servers. Re-read rows/version before persisting. Same canonical identity set
  uses refresh_corp_egress with exact previous-row CAS; otherwise use existing
  replace_corp_egress. Never retry a conflict automatically. Set Verified only
  after durable success; static outcome state otherwise records failure.
- `ready_to_enable` requires available controller, binding/version and enabled
  user plus at least one row matching a current eligible fingerprint with
  `0 < verified_at <= now` and age <=86400 seconds. It returns false for no fresh
  proof. It does not mutate inventory or validate signing keys: the operator
  must additionally validate credentials before its existing security CAS.

## Fixed HTTPS observer

Only on the exclusive Corp host, before browser login/exit gates, expose
`POST /api/v1/corp/egress-observation`. No redirect, arbitrary target URL or IP
field. Reject query strings (422), nonempty body (422; read at most 1024 bytes,
larger is 413), wrong method (405), absent/incorrect/expired/replayed bearer
challenge (401). Existing outer ambiguous-header/Host checks still apply.
Authorization must be exactly one `Bearer <token>` header. Browser cookies,
reader tokens and operator auth are not observation credentials.

Require actual ConnectInfo peer and use existing resolve_client_ip with the
configured trusted-proxy decision; no peer/unverifiable forwarding returns 403.
Never accept a claimed IP in body/query. Pass only that resolved IP to observe.
On success return 204, no body, and `X-Corp-Probe: <same-token>` for the runner's
HTTPS response binding. Shared no-store/no-referrer/CSP hardening still applies.
No access log/audit writes, egress mutation, credential or IP in error replies.
The endpoint works while Corp is disabled because setup needs real proof.

## Operator integration and refresh

Keep existing auth/Origin/CSRF/form/version validation. `/probe` queues an owned
job and returns 303 to `/admin/corp` immediately after acceptance; Busy/Conflict
map to409, missing target to404, unavailable/failed to503. Show per-server last
attempt state separately from persisted proof, including running and retry
states. Use static Russian copy, no raw diagnostics. Expose a refresh link so
nontechnical users can see completion without resubmitting a form.

The enable form is actionable only when controller available and fresh matching
proof exists; its POST rechecks readiness and validates credentials, then calls
the existing CAS. No proof/unavailable returns503, stale version409, with no
mutation. Disable remains available and skips crypto validation as before.
No HTTP request can supply/override a verified IP or a process/network target.
Default disabled test fixtures retain existing unavailable UI behavior.

`refresh_due` is a bounded scan of at most four currently eligible servers per
call, rotating a cursor so failed early servers do not starve later ones. Probe
when no matching fresh row exists or any matching row is at least six hours old;
skip genuinely fresh complete rows. Queue/wait sequentially; each server uses
the current config version. Do not automatically retry conflicts or interfere
with a manual job; Busy ends the scan. Failed probes preserve previous evidence.
`spawn_refresh` waits 30 seconds initially then ticks every ten minutes with
MissedTickBehavior::Delay. It calls the same method, no overlapping scan, no
permanent disabling on transient failure. Restart retains saved proof, loses
pending jobs/challenges and resumes expiry-aware refresh. No production spawn
until the bounded owned-helper runner is supplied in the next slice.

## Verification

Independent spec tests use actual routers/storage and a controlled fake runner.
Fixtures can construct AppState then assign its public controller. A fake runner
may retain the request token in memory and drive the real observer router with
synthetic ConnectInfo; use a shared optional Router slot set after construction,
clear it in cleanup to avoid reference cycles. Do not inspect production code.
Test correct and forged/replayed observations, body/Host/peer boundaries, missing
callback, partial multi-host failure, stale binding/fingerprint/clock, caller
drop, single-job contention, cleanup poison, persistence/audit rollback,
timestamp-only session retention, changed-IP revocation, expiry, manual/refresh
competition and operator enable/probe outcomes. Existing 75 HTTP and browser
scenarios remain gates. An injected runner is not production egress evidence.

Source-only local validation, independent diff review, exact-head full CI and
new UI state screenshots are required. The following runtime slice additionally
needs real process/socket/TLS/cancellation tests in CI and ingress/delivery docs.

## Candidate verification receipt

The implementation adds the observer, owned controller jobs, proof persistence,
enable/probe forms, distinct attempt/proof status and bounded refresh scheduler.
Default app constructors remain unavailable; no production poller is started.
The independent spec writer supplied 26 tests and four actual-router browser
fixtures (ready, running, failed and enabled). Existing browser scenarios now
also exercise confirmation, retry and status reload for these states.

Two independent source-diff reviews and one complete-diff review returned no
findings. Lead review moved completion acknowledgement after permit release,
used explicit Arc cloning and narrowly allowed the intentional panic fixture; each
finding was recorded before its correction. Full compilation, tests, browser
execution and screenshot inspection remain pending at the candidate SHA in CI.
Local compilation/runtime/browser execution is prohibited on this workstation.

The next required block is the bounded sing-box runner: exact retained-socket
ownership, authenticated SOCKS, verified TLS and challenge echo, private config,
safe process-group teardown and production refresh wiring. Injected-runner tests
do not establish actual egress proof. No deployment or activation was performed.


Verified lifecycle baseline: `79b03a1aa0438b88f5abd03e8c5255adead1bae4`,
run `43711228300`, all 12 jobs passed. Canonical logs record exit 0 for all
five Cargo commands and `just ci`; full tests include all 26 egress cases and
540 active admin smoke tests. Browser artifact `14159864044` records 38 page
and interaction groups. Lead inspected narrow ready/running/failed/enabled
screens, including bottom controls, saved proof versus attempt and native
confirmation. No production egress or deployment was exercised.
