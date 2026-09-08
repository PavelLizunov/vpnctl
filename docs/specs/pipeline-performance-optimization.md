# Spec: Comprehensive Service Performance & Pipeline Optimization

## 1. Intent & Invariants
- **What:** Eliminate $O(N)$ latency scaling across the fleet (parallel deployment and node polling), eliminate redundant SSH/SQL round-trips (on-node binary checksum verification, single-probe kernel observation), introduce SQLite access log batching, and decompose 6 monolithic modules >900 LOC.
- **Invariants:**
  - 100% byte-for-byte backward compatibility of client subscription configs, share links, and QR codes.
  - Per-server isolation of deployment locks (`DeployGuard`); no cross-server deadlock.
  - SQLite transactions in `inv.db` remain atomic and durable; no partial mutations.
  - Zero disruption to production infrastructure during implementation.

## 2. Interface / Data Contract
```rust
// 1. Bounded concurrent fleet deployment and kernel updates
pub async fn deploy_all_bounded(
    servers: Vec<Server>,
    inv: SqliteInventory,
    registry: Arc<Registry>,
    key_path: Option<PathBuf>,
    concurrency_limit: usize,
) -> impl Stream<Item = BootstrapEvent>;

// 2. SSH and kernel artifact transfer optimization (crates/kernels/src/sing_box.rs)
// Avoid redundant 30+ MB upload when remote node already matches binary hash:
async fn is_artifact_up_to_date(ssh: &dyn SshTransport, remote_path: &str, local_sha256: &str) -> Result<bool>;

// 3. Batch access logging (crates/inventory, daemon/src/access_log.rs)
pub async fn log_sub_access_batch(&self, records: &[AccessLogRecord]) -> Result<()>;

// 4. Single-roundtrip node probe (daemon/src/node_probe_poller/probe_inspector.rs)
// Populate probe.kernel_active and probe.kernel_versions directly from PROBE_SCRIPT output,
// removing the redundant secondary kernel.status(ssh) loops.

// 5. Fleet-wide dashboard query optimization
// Replace per-server query loops with existing/optimized fleet-level aggregations.
```

## 3. Verification Checklist (Definition of Done)
- [ ] **Artifact skip:** Re-deploying a node whose `/usr/bin/sing-box` already matches the local binary hash skips uploading 30+ MB.
- [ ] **Fleet speedup:** `deploy_all` and `update_kernels_all` fan out across independent nodes with bounded concurrency (default 4).
- [ ] **Probe single round-trip:** `node_probe_poller` issues exactly one SSH session per node, extracting kernel active flags and versions directly from the probe script.
- [ ] **No N+1 on dashboard:** `/admin/` dashboard uses fleet-wide aggregated queries instead of looping per-server queries.
- [ ] **Batch logging:** `access_log` writer task drains pending queue items in batches of up to 50 records per SQLite transaction.
- [ ] **Code modularity:** High-LOC modules (>900 lines) partitioned into cohesive submodules with unit tests cleanly separated.
- [ ] **Regression & CI:** All existing unit tests, integration tests, `just ci`, and GitHub Actions CI pass with exit code 0.
