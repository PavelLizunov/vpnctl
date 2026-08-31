# Spec: Cumulative Per-User Traffic Accounting
## 1. Intent & Invariants
- What: replace snapshot-only byte attribution with cumulative sing-box V2Ray Stats so short-lived connections are counted.
- One Stats response supplies inbound server totals and per-user totals; Clash remains live metadata only, and AmneziaWG keeps its existing poller.
- Counters and their persisted baselines update in one SQLite transaction: a failed write never advances a baseline, and a successful retry cannot double-count.
- Process uptime detects restarts even when new counters overtake old values; lower individual counters remain reset-safe. The first observation establishes a zero-delta baseline.
- The Stats API and helper bind/run on the managed node only; no stats listener is exposed publicly and no user IDs or counters are logged.
- vpnctl ships a revision-coupled sing-box build with `with_v2ray_api`; APT is held after install so upgrades cannot silently remove accounting support.
- Existing share links, subscription output, inventory ownership, and Kernel × Protocol boundaries remain byte-compatible.

## 2. Interface / Data Contract
```rust
pub struct VpnCumulativeCounter {
    pub user_id: UserId,
    pub upload_total: u64,
    pub download_total: u64,
}
pub struct VpnCumulativeTick {
    pub server_upload_total: u64,
    pub server_download_total: u64,
    pub uptime_seconds: u64,
    pub active_connections: u32,
    pub users: Vec<VpnCumulativeCounter>,
}

impl SqliteInventory {
    pub async fn record_vpn_cumulative_stats(
        &self,
        server_id: &ServerId,
        tick: &VpnCumulativeTick,
    ) -> Result<u64>; // number of non-zero raw rows persisted
}
```

```json
{"server_upload_total":600,"server_download_total":900,"uptime_seconds":42,"users":{"alice":{"upload_total":123,"download_total":456}}}
```
- The node helper queries `127.0.0.1:10085`, uses a bounded timeout, never resets upstream counters, rejects malformed/negative/unknown counter names, and emits deterministic JSON.
- Server baselines persist one-tick pending/ahead reconciliation; user baselines are keyed by `(server_id, user_id)`, and both cascade with owners.

## 3. Verification Checklist (Definition of Done)
- [ ] A connection that opens and closes between Clash polls is counted from cumulative stats.
- [ ] First observation stores a baseline without inventing historical traffic.
- [ ] Monotonic counters produce exact deltas; lower counters produce reset-safe deltas.
- [ ] Empty, duplicate, unknown-user, and failed-transaction cases do not corrupt or advance baselines.
- [ ] Daemon restart continues from persisted baselines without loss or duplication.
- [ ] sing-box config exposes V2Ray Stats only on loopback and includes every enabled rendered user.
- [ ] Helper timeout, malformed response, and unavailable API fail closed without resetting counters.
- [ ] Existing Clash server-wide rows and AmneziaWG user rows are not duplicated.
- [ ] Share-link/subscription byte-equality tests, targeted tests, `just ci`, independent review, and GitHub CI pass.
