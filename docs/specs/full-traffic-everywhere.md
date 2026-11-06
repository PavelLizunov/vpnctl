# Full server traffic on every admin surface

## Intent and invariants

All server/fleet totals, rankings and traffic charts use the same validated NIC
RX+TX source, including GAP, without usage coefficients. Main `/admin/` and every
dashboard tab show full observed 24-hour traffic per node. `/admin/activity` and
server Activity charts show the selected rolling 24h / 7d / 30d / retained-40d
window. Existing monthly accounting uses the same reader. User-attributed stats,
connections, billing identities, subscriptions, grants and routes stay separate.
Missing readings are unavailable, not zero; partial/stale totals are labelled
observed minimum. Fleet totals state measured/total nodes, so missing nodes never
silently become a complete fleet total. No invented historical data/comparisons.

## Data and interface

Extend the existing inventory API (all existing validation/reset/coverage rules
in full-node-traffic.md remain):

```rust
pub struct NodeNicDelta { // Clone, Debug, PartialEq, Eq; root re-export
    pub ts: chrono::DateTime<chrono::Utc>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}
// Add to NodeNicUsage:
pub deltas: Vec<NodeNicDelta>;
```

Each consecutive usable sample pair emits one delta at the later sample's UTC
time, in collection order. Nondecreasing counters use differences; a reset counts
only the new value in the reset direction. Interface changes emit zero for both
directions and mark interrupted, never count an interface's lifetime. Health-only
NULL rows remain skipped. Sum of emitted RX/TX equals the returned usage RX/TX;
invalid/overflow/future/backwards windows still return None rather than a partial
vector. Measured zero emits a zero delta and remains available. Existing numeric
fields/quality unchanged. Read once per node/window, never per chart cell or over
SSH on GET. Private admin charts bucket deltas by observation end time within the
exact chosen window; no interpolation into unknown intervals. Zero measured
traffic and missing history have distinct states. No fleet coefficient applied.
Per-user traffic components retain explicitly attributed semantics.

Independent synthetic fixtures: SqliteInventory::open(&Path).await, add_server
(&Server).await, plus sqlx::SqlitePool connected to the temporary SQLite file.
Server: id:ServerId(String),address:String (192.0.2.1),ssh_port:u16,ssh_user:String,
kernels:Vec<KernelId>,enabled_protocols:Vec<ProtocolId>,trusted_host_fingerprint:
Option<String>,hoster:String,jump_via:Option<ServerId>,usage_coefficient:f64.
Insert node_health(sample_id unique TEXT,server_id TEXT,ts RFC3339 TEXT,nic_iface
TEXT,nic_rx_bytes INTEGER,nic_tx_bytes INTEGER); other columns nullable.
Call inv.node_nic_usage(&sid,start:i64,now:i64,max_gap_seconds:u64).await ->
Result<Option<NodeNicUsage>,SqliteInventoryError>. Fresh temporary DB per test;
no production/network. Tests use allow(unwrap_used,expect_used) on test file.

## Verification

Independent delta-spec tests: normal/zero/reset/interface/gap/NULL/failure cases
and sum conservation. Real-router tests pin main per-server full totals, ignored
coefficients/attributed traffic, partial/missing states, selected 24h/7d/30d/all
charts and fleet/server consistency. Diff-only review; fmt/check/clippy/test/deny,
gitleaks, exact-head CI, same-SHA deploy and live main/activity/Monitoring checks.
