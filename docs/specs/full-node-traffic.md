# Full node traffic and hoster quotas

## Intent & invariants

Server activity uses cumulative NIC RX/TX, including the traffic currently shown
as GAP, across every protocol and OS traffic. Never add GAP to NIC a second time.
Per-user VPN accounting, grants, routing, client artifacts and existing secrets
are unchanged. A hoster's chargeable direction is configurable, never inferred
from country. No default quota is assigned: the owner's tentative 4 TB is not
confirmed for a particular server. No automatic disconnect, suppression or hop.

## Interface / data contract

- Retain node-health NIC history for at least 40 days, separately from ordinary
  30-day health/alert retention. Read indexed, bounded windows; no polling SSH on
  page GET. Sum observed counter deltas, not absolute boot totals. A decrease
  counts the new counter and marks interrupted coverage; an interface change
  establishes a new baseline without counting the new interface's lifetime.
- Missing/invalid/negative/non-integer counters, malformed/future timestamps,
  arithmetic overflow or excessive (>100000) rows yield unavailable usage.
  Fewer than two usable observations also yield unavailable, never measured zero.
  Health-only rows with both counters NULL are skipped; gaps are evaluated
  between usable NIC samples. One missing direction or counters without an
  interface are invalid.
- Windows include only readings at or after start and at/before now, ordered by
  collection sequence; backwards timestamps invalidate the window. Any selected
  future observation invalidates the window instead of being silently dropped. Counter gaps
  above max_gap_seconds, counter resets and interface changes mark interruption.
  Complete coverage additionally starts within max_gap_seconds of period start
  and ends within max_gap_seconds of now. Partial totals are explicitly observed
  lower bounds, with their actual start/end shown; do not claim an exact balance.
- Daily activity remains low/medium/high at <25, <100, >=100 GiB, based on full
  RX+TX, fresh telemetry and at least 20 distinct observed UTC hours. Interrupted,
  stale or inadequate coverage is unknown, not low. node_activity_bytes reads
  [now-86400, now], uses max_age_seconds as the maximum observation gap, and
  returns None for max_age_seconds=0. It does not require complete start-edge
  coverage: the existing 20-hour late-start policy is retained. Existing response fields,
  auth/privacy/grant filtering remain unchanged; old clients need no new build.
- Server Activity and Monitoring show full NIC usage, last observation and
  partial/stale state separately from VPN attribution and live connection counts.
- Server Activity has a web form for optional per-server quota, direction rx/tx/
  both, monthly reset day 1..31 (UTC; clamp short months), warning percent 1..100.
  Decimal GB/TB and binary GiB/TiB are explicit; exact decimal parsing, no floats.
  POST /admin/servers/{id}/traffic-limit saves/clears with normal auth/CSRF,
  rejects invalid input before mutation and audits only actual changes atomically.
- Monthly usage follows the configured reset-day period; unconfigured nodes show
  calendar-month observed RX/TX with no invented allowance. Show observed usage,
  configured limit, percentage and remaining only when coverage is complete.
  Warn at configured threshold and critical at 100%; missing/stale/partial data
  cannot clear a warning as low usage. Observed lower bounds may trigger alerts.
- No historical traffic or quota values are invented. Existing NIC history can
  be used; a month not fully represented is labelled partial. Quota settings use
  an additive table with server FK cascade. Migration needs verified backup and
  restore self-test before activation; preserve the deployed ba4af48 features.

## Public inventory API for independent spec tests

```rust
pub struct NodeNicUsage { // Clone, Debug, PartialEq, Eq
    pub rx_bytes: u64, pub tx_bytes: u64, pub total_bytes: u64,
    pub samples: usize, pub observed_hours: usize,
    pub first_sample_ts: chrono::DateTime<chrono::Utc>,
    pub last_sample_ts: chrono::DateTime<chrono::Utc>,
    pub interrupted: bool, pub complete: bool,
}
pub struct ServerTrafficLimit { // Clone, Debug, PartialEq, Eq, Serialize, Deserialize
    pub limit_bytes: u64, pub direction: String,
    pub reset_day: u8, pub warning_pct: u8,
}
pub fn server_traffic_period(now: i64, reset_day: u8) -> Result<(i64, i64)>;
impl SqliteInventory {
    pub async fn node_nic_usage(&self, sid: &ServerId, start: i64, now: i64,
        max_gap_seconds: u64) -> Result<Option<NodeNicUsage>>;
    pub async fn get_server_traffic_limit(&self, sid: &ServerId)
        -> Result<Option<ServerTrafficLimit>>;
    pub async fn set_server_traffic_limit(&self, sid: &ServerId,
        limit: Option<&ServerTrafficLimit>, actor: &str) -> Result<bool>;
    pub async fn node_activity_bytes(&self, sid: &ServerId, now: i64,
        max_age_seconds: u64) -> Result<Option<u64>>;
}
```

Types/functions re-export from vpnctl_inventory. `node_nic_usage` accepts windows
0 < now-start <= 40 days and max_gap_seconds > 0; invalid arguments return Invalid.
`server_traffic_period` returns inclusive start / exclusive next reset UTC seconds;
invalid day or timestamp returns Invalid. Clamping is month-local (Jan31 -> Feb28
-> Mar31, including leap years), without sticky February resets. The setter
rejects missing servers, zero/>i64::MAX limits, unknown directions and invalid
days/thresholds. Clearing absent settings is a no-op; identical saves are no-ops.
A real save/clear writes server.traffic_limit.set in the same transaction; audit
failure rolls the setting back. Getter missing-server/absent settings is None.

Test fixtures may open a fresh SqliteInventory(path), add_server(Server) and use
an independent sqlx SQLite connection to that temporary file for raw observations.
node_health columns: sample_seq auto PK, sample_id unique TEXT, ts TEXT, server_id,
nic_iface TEXT, nic_rx_bytes INTEGER, nic_tx_bytes INTEGER; other columns nullable.
Synthetic observations should set sample_id uniquely. Existing server shape:
Server {id:ServerId, address:String, ssh_port:u16, ssh_user:String,
kernels:Vec<KernelId>, enabled_protocols:Vec<ProtocolId>,
trusted_host_fingerprint:Option<String>, hoster:String, jump_via:Option<ServerId>,
usage_coefficient:f64}. recent_audit(usize/i64 integer literal) returns entries
with action/target/payload. Tests never use production, network or live identities.

## Verification

Independent spec tests exercise reset/window/overflow/isolation/billing-calendar,
setter validation/no-op/audit rollback and full-NIC activity boundaries. Real
router tests cover quota auth/CSRF, form rendering, partial history, total-vs-user
separation and unchanged subscription bytes. Diff-only review; fmt, check, clippy,
workspace tests, deny, gitleaks, exact-head CI and same-source candidate package.
