# Contract: cooperating controllers

## Intent & invariants

Opt-in HA runs two reachable web frontends and exactly one controller runtime.
The existing standalone startup, database and client output stay unchanged when
HA is disabled. Development and fault tests do not modify production services.

- Followers proxy **all** application requests, including GET, to the leader;
  they do not open/migrate the writable inventory or start application workers.
- Authority comes from a three-voter quorum. A heartbeat timeout alone is never
  permission to promote. No custom consensus algorithm is implemented in vpnctl.
- Loss of authority closes admission and fences the entire worker cgroup,
  including SSH descendants, within the configured stop budget.
- A successor starts only after authenticated fencing evidence for the previous
  controller's external actions and verification of its replicated inventory.
  Missing evidence, unknown execution outcome or stale data blocks promotion.
- Replication is asynchronous: the owner selected the simpler recovery-point
  tradeoff on 2026-11-17. A promotion can lose changes since the last verified
  generation, including acknowledged changes. Show the measured interval and
  lag in the UI; never advertise zero-loss or synchronous commits.
- Credentials and subscription identities present in the verified generation,
  matching schema/build and canonical client bytes survive promotion.
- Never replay a mutating HTTP request after an ambiguous upstream failure.
- Root power fencing of the Aruba VPS must not be substituted for controller
  fencing: the VPS also hosts an independent production VLESS service.

## Interface / data contract

The first implementation separates a pure transition guard, quorum/storage
adapters, a worker supervisor and an HTTP gateway. The guard does not perform
I/O and does not authenticate its inputs; adapters must authenticate authority,
replication and fencing evidence before presenting it to the guard.

Pure guard API in `vpnctld::ha::coordinator`:

```rust
pub struct HaConfig {
    pub node_id: String,
    pub stop_budget_ms: u64,
    pub max_replica_age_ms: u64,
    pub schema_version: u64,
    pub build: String,
}
pub struct PreviousLeader { pub node_id: String, pub epoch: u64 }
pub struct Lease {
    pub holder: String,
    pub epoch: u64,
    pub expires_at_ms: u64,
    pub previous: Option<PreviousLeader>,
}
pub struct ReplicaProof {
    pub verified_at_ms: u64,
    pub inventory_revision: u64,
    pub required_revision: u64,
    pub schema_version: u64,
    pub build: String,
    pub integrity_verified: bool,
    pub identities_verified: bool,
}
pub struct FenceProof {
    pub previous_node_id: String,
    pub previous_epoch: u64,
    pub successor_epoch: u64,
    pub external_actions_fenced: bool,
}
pub enum Role { Isolated, Follower, Candidate, Leader, Draining }
pub enum Action { None, StopWorker }
pub struct Coordinator { /* private state */ }
impl Coordinator {
    pub fn new(config: HaConfig) -> Result<Self, String>;
    pub fn role(&self) -> Role;
    pub fn observe(&mut self, lease: Option<Lease>, now_ms: u64) -> Action;
    pub fn activate(&mut self, replica: &ReplicaProof,
        fence: Option<&FenceProof>, now_ms: u64) -> Result<(), String>;
    pub fn tick(&mut self, now_ms: u64) -> Action;
    pub fn worker_stopped(&mut self, now_ms: u64);
    pub fn may_serve(&self, now_ms: u64) -> bool;
}
```

Times are supplied by the adapter in one monotonic clock domain, not wall time.
Configuration requires a nonempty node/build, a positive stop budget and replica
age budget. Epoch zero, empty holders, expired leases, non-increasing transitions,
invalid previous epochs and a changed previous-holder claim within one epoch
are not valid authority. The greatest structurally valid observed epoch is
never forgotten. An identical same-epoch observation is idempotent; it may only
extend the same holder/previous claim before that local grant is fenced.

A local valid grant yields Candidate. Activation requires more than the stop
budget remaining, a fresh non-future proof, revision >= required revision,
exact schema/build, integrity and identities verification, and a matching fence
for the lease's previous leader. A first cluster lease without a previous leader
requires no fence; the quorum adapter alone controls cluster bootstrap.

Activation twice is rejected. A leader loses admission at
`expires_at_ms - stop_budget_ms`, or immediately on missing/invalid/different
authority. It becomes Draining and returns StopWorker until the supervisor
confirms `worker_stopped`. A newer grant cannot reactivate a draining worker.
After stop confirmation, the latest valid observation determines Candidate,
Follower or Isolated. Same-epoch observations may extend the same holder's lease,
but cannot shorten it, resurrect expired authority or revive a fenced epoch.

The web surface must show leader, role, quorum, replication age/revision,
fencing readiness and blocked reason, with authenticated controls for readiness,
planned handover and pausing automatic promotion. CLI remains disaster recovery.

## Verification checklist

- [ ] Spec-only independent tests cover guard success, rejection and boundary
  paths, stale/expired observations, partition and old-process resume.
- [ ] Real isolated quorum, replica and worker processes: one leader, leader
  crash, quorum loss, stale replica, failed fencing and restart during an action.
- [ ] HTTP tests preserve status, raw URI, cookies, streaming and trusted IP;
  ambiguous mutation failure is never automatically retried.
- [ ] Existing standalone and byte-level subscription compatibility suites pass.
- [ ] Independent diff review, canonical gates, exact-head CI and retained
  credentials; report implementation, integration and live activation separately.

## Runtime adapter contract (opt-in, asynchronous)

The packaged `scripts/ha/controller_ha.py` supervisor is a separate opt-in service;
ordinary `vpnctld` invocation is unchanged. Python 3.11+, systemd unified cgroups
and an independently operated, TLS-authenticated three-server Consul cluster are
required. There is no vpnctl consensus implementation. Controllers and the
independent executor/storage witness use mutually authenticated TLS on a separate
control listener; public application listeners never expose control RPCs.

Consul sessions use TTL 15 seconds, release behavior and zero lock delay. A
consistent transaction checks the last durable lease-record index and locks it
with the new session, monotonically incrementing its stored epoch and retaining
the previous holder/epoch. ACLs prohibit deleting the record or non-session
writes. Only successful renewal followed by a consistent matching record grants
local admission, bounded from the renewal request's monotonic start, with a
stop budget deducted. No response extends authority after that deadline.

The supervisor starts the entire application as a dedicated systemd service,
with KillMode=control-group, SendSIGKILL=yes, bounded TimeoutStopSec and a
fixed two-second systemd watchdog. A minimal guard is the cgroup main process,
starts vpnctld without notification credentials, and accepts only its own epoch
and boot ID in an atomically written monotonic-deadline file. It stops heartbeats
and exits before deadline minus watchdog minus stop budget. Lease renewal may
update that file only from a proven grant. A stopped guard cannot heartbeat;
systemd remains outside the cgroup and kills every descendant.
Before any activation the previous controller's authenticated control service
persists an epoch fence, kills/stops the fixed worker unit and proves the cgroup
is empty. Unreachable or suspended control service blocks promotion. This is
controller-only fencing; it never power-cycles the host or unrelated VPN units.

Every daemon subprocess SSH operation, including stdin, upload, reads, jump
routes and password bootstrap, routes through the supervisor's private Unix
socket to the independent executor. No direct fallback is permitted in HA mode. End-to-end helper budget is twice
the transport timeout plus 60 seconds for pinned-jump scanning; enclosing
witness HTTP and worker socket budgets add 10 and 30 seconds respectively.
The executor verifies the current session/epoch against Consul for each request,
persists and fsyncs an intent before dispatch, serializes execution, and refuses
old epochs. It invokes the same pinned-build vpnctld transport helper once.
A transport error, interrupted helper or executor restart with an unfinished
intent is **uncertain**, never success and never automatically replayed.
An epoch barrier closes old admission and succeeds only when all earlier jobs
are durably completed. Unknown outcomes block promotion, with the exact job ID
visible. Recovery requires independently proving remote completion; there is
no boolean-success hook or automatic override. Executor/storage witness loss
blocks external actions and promotion: this dependency is explicit, not HA of
the witness itself.

`replica.py` contract (Python stdlib, usable without importing the supervisor):
`SnapshotStore(root, build, schema)` owns immutable generation directories.
`create(source_db, identity_files, generation, created_at_ms)` uses SQLite's
online backup API, copies explicitly named identity files, and returns a manifest
dict. `verify(generation, now_ms, max_age_ms)` returns that manifest only when
all exact file hashes, database integrity/FKs, migration schema, identity digest,
build, generation and non-future creation time are valid; age greater than the
limit fails. File names are fixed logical names, not arbitrary relative paths.
`install(generation, target_db, identity_targets, now_ms, max_age_ms)` verifies
first and atomically replaces destination files; caller MUST have proved worker
stopped, and failed/interrupted multi-file installs are never activated.
Export/import use fixed-name byte records, validate before publication, never
mutate an existing generation, and fsync data/directories before advertising.
Identity validation includes the complete database plus explicit deploy key,
known_hosts and environment/config bytes; hashes attest copied bytes, not an
independent assertion that an arbitrary source identity is correct.

Generation pointers are published through the authenticated witness only after
complete verification. Promotion requires the witness's latest advertised
generation, exact worker executable/build/config/schema, and age within the
configured budget. Followers never refresh creation time by re-verification.
The UI reports generation, source creation time, measured snapshot age, configured
replication interval and maximum accepted age; the actual RPO at promotion is
that snapshot age and may include acknowledged lost writes. Recovered nodes are
fenced and install this generation before rejoining; their divergent SQLite
files are never promoted, merged or automatically uploaded.

Both public frontends proxy every application method/path, including GET and
subscriptions, to the currently admitted leader worker. They preserve raw
path/query, streaming/SSE, response status and multiple Set-Cookie fields.
They remove hop-by-hop headers (including Connection-nominated headers), strip
client-supplied forwarding/IP headers and set X-Real-IP from the actual peer or
explicit trusted proxy CIDRs. Cross-controller forwarding uses the mTLS control
listener, bounded to one hop. The gateway strips a supplied application-forward
marker and adds its own on this authenticated hop, so even `/_ha/` application
paths reach the worker and cannot be confused with control RPCs. Mutations are sent at most once; ambiguous failures
return 502/503 and are never replayed.

A separate authenticated `/admin/ha` page remains available without inventory
access. It displays role/leader, quorum, snapshot generation/age/RPO, cgroup and
executor fence readiness and exact blocked reason. Same-origin authenticated
POST controls run readiness, initialize an empty cluster from a stopped seed,
request planned handover and persistently pause/resume automatic failover.
Missing quorum, snapshot, matching artifacts or any fencing evidence fails closed.

## SSH bridge and executable metadata

`vpnctl_ssh::subprocess::handle_ha_execute_request(bytes: &[u8])` is an async
function returning `vpnctl_core::Result<Vec<u8>>`. The hidden
`vpnctld --ha-execute` mode reads one request from stdin and writes its JSON
response plus a newline, before tracing, database/config resolution or workers.
Invocation with any `VPNCTLD_HA_EXECUTOR_SOCKET` value present is rejected.
The witness deploy key comes only from its nonempty `VPNCTLD_DEPLOY_KEY`;
requests cannot supply a key or local path. The helper invokes the ordinary
production pinned/TOFU transport once, never retries, and stages known_hosts in
a private directory.

Requests are flat JSON objects with required `host`, `user`, `port`,
`timeout_ms`, `operation` and `remote_cmd`, plus optional/null `jump`,
`target_fingerprint`, `known_hosts_b64`, `stdin_b64` and `password`. Jump objects
use `PinnedJumpRoute`'s host/user/port and two fingerprint fields. `operation`
is `exec` (password forbidden) or `exec_password` (password required, stdin
forbidden). `timeout_ms` is 1..=3_600_000. Endpoints require nonempty valid
host/user and a nonzero port. Unknown top-level fields, invalid base64,
malformed requests and frames above 64 MiB are rejected. Binary fields use
standard base64. Responses contain `ok` and `stdout_b64`, optional `error`, and
successful changed `known_hosts_b64`. Dispatch failures return `ok:false` and
empty stdout; they remain potentially uncertain remote outcomes. Changed
known_hosts is installed by the caller only after a valid successful response;
concurrent append-only trust additions survive, and conflicting concurrent
rewrites fail closed.
The broker uses one private Unix connection and finite deadline, with no direct
SSH fallback or replay after any failure. Every transport method, including
uploads, reads, stdin, unprivileged commands and password bootstrap, traverses
this broker whenever the environment variable is present.

In broker mode, new subprocess transports use `VPNCTLD_HA_KNOWN_HOSTS` as their
default known_hosts path when it is set, so trust updates reach the replicated
identity file; explicit `.known_hosts(...)` paths still take precedence. Without
broker mode the existing standalone default is unchanged. Unreadable configured
known_hosts fails the operation without direct SSH fallback. In broker mode,
`ensure_deploy_key` rejects a missing private key before creating directories or
generating any replacement identity; an existing key is validated as usual.

`vpnctl_inventory::embedded_migration_checksums() -> Vec<(i64, Vec<u8>)>` returns
the embedded version and complete SQLx checksum for every migration in ascending
version order without opening a database. Hidden `vpnctld --ha-artifact` writes
one JSON object before tracing/config/database access: `build_sha` contains the
compile-time `VPNCTL_BUILD_SHA` or `unknown`; `executable_sha256` hashes the actual
running `/proc/self/exe`; `schema` is the maximum embedded migration version;
`migrations` contains ordered `{version, checksum_hex}` records; and
`migrations_sha256` is SHA256 of the concatenated ASCII records
`<decimal version>:<lowercase complete checksum hex>\n`. Both helper flags are
mutually exclusive. Activation checks the artifact's executable hash, exact
schema and migration fingerprint against configuration and the verified
replica's database-derived `migration_sha256`; a maximum version alone is not
schema compatibility and must never authorize an implicit startup migration.

Python adapter public test interfaces: `common.Consul(config, context=None)`
provides session(node)->id, renew(id)->monotonic_deadline, get(name)->Consul KV
metadata plus decoded `record` (or None), acquire(node,id)->record|None,
authority(node,epoch,id)->record (raises on rejection), release(id), settings(),
set_settings(dict). All reads are consistent; no failed request authorizes work.
`executor.Executor(root, consul, helper, deploy_key, build)` provides
execute(identity, {epoch,session,build,transport})->transport response,
barrier(identity,{epoch,session})->{previous,successor_epoch,external_actions_fenced},
status()->{closed_through,blocked_jobs,ready}. Its root is exclusively locked for
its lifetime. Helper invocation is `[helper,"--ha-execute"]`, one JSON request on
stdin. Only helper success with valid JSON `ok:true,stdout_b64:<valid base64>`
marks completion. Any malformed/error/timeout/crash is uncertain across restart;
authority failure dispatches nothing; barriers never erase uncertain jobs.
`gateway.Server((host,port), app, control=False, context=None)` uses an app with
config (`node_id`, `peers`, `trusted_proxies`, `admin_token_file`), upstream()->
(url,SSLContext|None), local_upstream()->url, status()->dict and action(name,target).
Gateways cap concurrent connections at 64 and initial/header reads at 15 seconds.
Public app forwarding does not require management auth; `/admin/ha` requires
Basic user `ha` and file token, POST additionally requires the page's CSRF field.
Control forwarding requires a verified certificate CN in configured peers and
never forwards onward (local worker only). `worker.Worker(config)` exposes
start(monotonic_deadline,socket_path,epoch=1), extend(deadline), stop(), stopped()->bool;
`systemd_user:true` is an isolated test/user-manager option, not a fake cgroup.

PinnedJumpRoute JSON field names are `host`, `user`, `port`, `jump_fingerprint`,
and `target_fingerprint`; the latter two are verified host-key fingerprints.

Envelope/encoding, timeout and direct-endpoint validation errors reject the
helper request before dispatch. Pinned-route transport preparation can instead
return an `ok:false` error response without dispatch; both forms must leave the
SSH invocation count at zero. Neither is permission to retry an uncertain job.
