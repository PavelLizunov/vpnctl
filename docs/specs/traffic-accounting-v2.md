# Spec: Cumulative Per-User Traffic Accounting
## 1. Intent & Invariants
- What: replace snapshot-only byte attribution with cumulative sing-box V2Ray Stats so short-lived connections are counted.
- One Stats response supplies inbound server totals and per-user totals; Clash remains live metadata only, and AmneziaWG keeps its existing poller.
- Counters and their persisted baselines update in one SQLite transaction: a failed write never advances a baseline, and a successful retry cannot double-count.
- Process generation is the node boot ID plus sing-box's `ExecMainStartTimestampMonotonic`. When both observations have a generation token, a changed token counts fresh counters from zero even if uptime and counters exceed their baselines; an unchanged token uses counter deltas. When either token is absent, retain the legacy heuristic: decreased uptime, or a controller-time uptime shortfall greater than 10 seconds together with a decreased server counter. Lower individual counters remain reset-safe. The first observation establishes a zero-delta baseline.
- Migration `0067` corrects historical `0043` daily seeds only when the midnight bucket still carries the seed's `T23:59:59.999Z` `last_sample_ts` marker (any real tick replaces it), both midnight byte counters equal the summed daily counters, and other hours exist for that server/day. Each direction becomes `max(0, daily - other hours)`; other buckets and metadata remain unchanged. Only actual corrections are audited. Migration `0043` remains unchanged.
- Raw traffic retention is 32 days (`VPN_STATS_RETENTION_DAYS`), exceeding the longest calendar-month accounting window (31 days); monthly usage and traffic-limit alerts retain the first day throughout the month. Historical raw views remain bounded by retention.
- Live connection counts use fresh snapshots, never historical bucket peaks. Persist successful empty Clash polls as zero; missing or expired samples are unknown (`—` in the admin UI). Freshness is two configured Clash poll intervals, matching the snapshot cache.
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
    pub generation: Option<String>,
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
- The SSH collection command frames the unchanged helper JSON with `vpnctl-generation:<boot_id>:<start_monotonic>\n`. Tokens must contain a lowercase canonical UUID and a positive decimal `u64`, with a total length of at most 57 bytes. An empty header or legacy unframed JSON means no token. Unavailable generation probes fall back to the legacy heuristic; malformed tokens fail the observation. Generation probes before and after the helper must agree, otherwise the observation fails without advancing baselines.
- Migration `0068` adds nullable `generation` to server baselines. Tokens persist atomically with counters; inserting a known generation or changing/clearing it writes an audit row without storing the token. An unchanged generation produces no generation audit.
- Server baselines persist one-tick pending/ahead reconciliation; user baselines are keyed by `(server_id, user_id)`, and both cascade with owners.
- Cumulative counters for users missing from inventory are skipped inside the accounting transaction: no per-user rows or baselines are written for them, including on the first observation. Their bytes remain in the server remainder and become unattributed traffic through the existing one-tick reconciliation; known-user and server baselines still advance atomically.
- `ServerLiveActivity::active_now` is `Option<u32>` (`None` means no fresh sample). `server_live_activity` and `all_servers_live_activity` take `max_age_secs` separately from the historical byte window.

## 3. Verification Checklist (Definition of Done)
- [ ] A connection that opens and closes between Clash polls is counted from cumulative stats.
- [ ] First observation stores a baseline without inventing historical traffic.
- [ ] Monotonic counters produce exact deltas; lower counters produce reset-safe deltas.
- [ ] Changed boot/process generation counts fresh totals even above the baseline; unchanged generation uses deltas and missing tokens retain the old heuristic. Persisted generations survive daemon restart.
- [ ] Collection rejects malformed/oversized tokens and mid-query restarts; unavailable probes and legacy output remain supported.
- [ ] Migration `0067` fixes overlapping daily seeds, clamps negative remainders to zero, preserves genuine midnight raw buckets and isolated days, and audits only actual changes.
- [ ] Empty and unknown-user ticks preserve server totals; unknown users never create per-user rows or baselines or block known-user accounting, including on the first observation.
- [ ] Duplicate-user and failed-transaction cases do not advance any baselines.
- [ ] Daemon restart continues from persisted baselines without loss or duplication.
- [ ] sing-box config exposes V2Ray Stats only on loopback and includes every enabled rendered user.
- [ ] Helper timeout, malformed response, and unavailable API fail closed without resetting counters.
- [ ] Existing Clash server-wide rows and AmneziaWG user rows are not duplicated.
- [ ] Share-link/subscription byte-equality tests, targeted tests, `just ci`, independent review, and GitHub CI pass.
