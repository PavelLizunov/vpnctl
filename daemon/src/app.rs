//! Wire the axum Router. Kept separate from `main.rs` so tests can build
//! the same Router without the network/signal plumbing.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::MatchedPath;
use axum::http::Request;
use axum::routing::{get, post};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::services::ServeDir;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tracing::info_span;

use tokio::sync::mpsc;

use crate::handlers::auth::BasicAuth;

use crate::access_log::{self, AccessLogRecord};
use crate::config::DaemonConfig;
use crate::handlers;
use crate::rate_limit::RateLimiter;
use crate::wizard::WizardStore;
use vpnctl_core::Registry;
use vpnctl_inventory::SqliteInventory;

/// Per-process state cloned into every handler.
///
/// * `access_log_tx` — Phase Track-1 producer side of the bounded
///   mpsc that drains into `sub_access_log` (see `crate::access_log`
///   for the full rationale).
/// * `rate_limiter` — Phase Track-2 token-bucket limiter for `/sub`,
///   throttles abuse before the daemon spends meaningful work (see
///   `crate::rate_limit` for the design).
///
/// Cloning `AppState` clones the `Sender` and bumps the `Arc`s — the
/// channel stays open and the limiter stays shared across all
/// per-request clones.
#[derive(Clone)]
pub struct AppState {
    pub inv: SqliteInventory,
    pub registry: Arc<Registry>,
    pub access_log_tx: mpsc::Sender<AccessLogRecord>,
    pub rate_limiter: Arc<RateLimiter>,
    /// Phase E — add-server wizard's in-flight session store. Holds
    /// the operator's step-1 input (IP + root password) between the
    /// step-1 POST and the step-2 SSE handler. See `crate::wizard`
    /// for TTL + key schema.
    pub wizard: Arc<WizardStore>,
    /// Phase 4c — in-memory cache of the last clash-api snapshot
    /// per VPN server. Filled by `spawn_clash_poller` on every
    /// successful 5-minute tick; read by the server-detail handler
    /// to render the «Live connections» drill-down. Cheap to
    /// `.clone()` (internal `Arc`).
    pub snapshot_cache: crate::snapshot_cache::SnapshotCache,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState").finish_non_exhaustive()
    }
}

/// Default deploy-key path for vpnctld. Matches the path the
/// `/admin/settings` page surfaces + the path the clash-api poller
/// reads via `VPNCTLD_DEPLOY_KEY` env (which still wins if set).
pub const DEFAULT_DEPLOY_KEY_PATH: &str = "/var/lib/vpnctl/.ssh/id_ed25519";

/// Default backup directory for vpnctld. Surfaced in the Settings page's
/// Backups section. Same value as `vpnctl_inventory::DEFAULT_BACKUP_DIR`
/// — re-exported here so the daemon's other surfaces (download
/// handler, scheduler) can reference one canonical constant.
pub const DEFAULT_BACKUP_DIR: &str = vpnctl_inventory::DEFAULT_BACKUP_DIR;

pub async fn build(config: DaemonConfig) -> anyhow::Result<Router> {
    let inv = SqliteInventory::open(&config.db_path).await?;
    let registry = Arc::new(build_registry()?);

    // Auto-bootstrap vpnctld's deploy SSH key on first start.
    // Generates an ed25519 keypair at `/var/lib/vpnctl/.ssh/id_ed25519`
    // via the system `ssh-keygen` binary (no Rust crypto deps).
    // Idempotent — re-call when the key already exists is a no-op.
    // The public half is surfaced in the admin Settings page so the
    // operator can paste it into each VPN node's authorized_keys.
    // After that, every web-deploy / poller call is fully self-service.
    let deploy_key_path = std::path::PathBuf::from(DEFAULT_DEPLOY_KEY_PATH);
    if let Err(e) = crate::ssh_subprocess::ensure_deploy_key(&deploy_key_path).await {
        tracing::warn!(
            target = "vpnctld::startup",
            path = %deploy_key_path.display(),
            error = %e,
            "deploy key auto-generation failed — web deploy + poller will fall back to logging warnings until resolved. Most common cause: vpnctld user lacks write access to /var/lib/vpnctl/.ssh/"
        );
    } else {
        tracing::info!(
            target = "vpnctld::startup",
            path = %deploy_key_path.display(),
            "deploy key ready (auto-generated if absent)"
        );
    }

    // Phase Track-1.1 retention scheduler: hourly purge of access-log
    // rows older than 30 days. The user-detail page promises this
    // ("auto-purged after 30 days") — without the scheduler the rows
    // accumulate forever and the UI lies.
    //
    // Spawned ONLY here, not in `router()` — tests construct AppState
    // directly via `router(state)` and don't need a background tokio
    // task running per test (those leak handles across the test
    // process). Production goes through `build()` and gets one purger
    // per daemon process. The returned JoinHandle is intentionally
    // dropped — the task lives until the process exits, and the
    // tokio runtime aborts it on graceful shutdown.
    drop(spawn_retention_purger(inv.clone()));

    // Phase Track-3 chunk 4 — periodic clash-api poller.
    // Uses SubprocessSshTransport (Path C), so no Cargo-feature
    // gate + no glibc 2.38 dep. Spawned unconditionally; the poller
    // itself logs-and-skips when the SSH key isn't on the homelab
    // host yet OR when a node hasn't authorised it.
    //
    // Phase 4c — the poller also fills `snapshot_cache` with the
    // full per-tick snapshot (per-connection detail) so the admin
    // UI's «Live connections» drill-down has data to render.
    let snapshot_cache = crate::snapshot_cache::SnapshotCache::new();
    drop(crate::clash_poller::spawn_clash_poller(
        inv.clone(),
        snapshot_cache.clone(),
    ));

    // Phase 5a-2 — periodic reverse-DNS resolver. Walks
    // `snapshot_cache` for unique destination IPs lacking a host
    // field, calls `getent hosts <ip>`, caches result in
    // `dns_ptr_cache`. Admin UI's «top destinations» table
    // enriches IP-only labels with the cached hostname.
    drop(crate::dns_resolver::spawn_dns_resolver(
        inv.clone(),
        snapshot_cache.clone(),
    ));

    // Phase H chunk 4 — periodic node_health probe (systemctl /
    // disk / mem / load / listening ports / sing-box log size).
    // Same SubprocessSshTransport, same skip-when-no-key behaviour,
    // independent cadence (10 min by default vs clash's 5 min — see
    // node_probe_poller doc-comment for the cadence rationale).
    // Until this is wired, `/admin/servers/{id}` shows empty-state
    // forever because the underlying `node_health` table never
    // gets a row.
    drop(crate::node_probe_poller::spawn_node_probe_poller(
        inv.clone(),
    ));

    // Phase G — operator-facing alerts on top of node_health rows.
    // Same cadence as the probe (10 min) — no point scanning faster
    // than the probe writes. Each scan diffs the two newest rows per
    // server and INSERTs an admin_alerts row + mirrored audit row
    // on every state-change.
    drop(crate::health_monitor::spawn_health_monitor(inv.clone()));

    // Phase Track-1 back-pressure (audit-fix B + retroactive review #3
    // / security #2): a dedicated writer task drains a bounded mpsc
    // channel into `sub_access_log`. Without this, an attacker
    // holding ONE valid sub-token could OOM the daemon by spawning a
    // tokio task per request.
    let (access_log_tx, _writer_handle) = access_log::spawn_writer(inv.clone());

    // Phase Track-2 rate limiter: token bucket per (IP, token).
    // Defaults give 5-burst then 1 token / 30 sec. See `rate_limit`
    // module docs for the design rationale.
    let rate_limiter = Arc::new(RateLimiter::default());

    // Phase E — wizard session store. Created here (not inline in the
    // AppState literal) so the rate-limit cleanup task can share it
    // and sweep expired sessions on its tick (Round-3 L1).
    let wizard = Arc::new(WizardStore::new());

    // Periodic cleanup of idle bucket entries (otherwise the per-IP
    // map grows unbounded over time). 10-minute cadence is plenty —
    // the idle TTL is 1 hour by default. Also sweeps abandoned wizard
    // sessions (their TTL is 10 min, matching this cadence).
    drop(spawn_rate_limit_cleanup(
        Arc::clone(&rate_limiter),
        inv.clone(),
        Arc::clone(&wizard),
    ));

    // Phase C-4 — hourly inventory snapshot to /var/lib/vpnctl/backups
    // plus retention pruning (24h / 30d / 12mo). Settings UI surfaces
    // the snapshot list + a manual "snapshot now" button + per-file
    // download anchor for operator off-site (USB, Forgejo, etc).
    // Restore is CLI-only — the daemon literally can't replace its
    // own open DB file while it's holding it (see `vpnctl restore`).
    drop(spawn_backup_scheduler(
        inv.clone(),
        std::path::PathBuf::from(vpnctl_inventory::DEFAULT_BACKUP_DIR),
    ));

    // 2026-05-23 — initialise the global display-TZ cache from
    // `display_settings.timezone` (migration 0027). Parse failure
    // → log + fall back to Europe/Moscow (the seed default).
    match inv.get_display_timezone().await {
        Ok(name) => {
            let tz: chrono_tz::Tz = name.parse().unwrap_or_else(|_| {
                tracing::warn!(
                    target = "vpnctld::startup",
                    saved_name = %name,
                    "display_settings.timezone is not a valid IANA name; falling back to Europe/Moscow"
                );
                chrono_tz::Europe::Moscow
            });
            crate::handlers::admin::init_display_tz(tz);
        }
        Err(e) => {
            tracing::warn!(target = "vpnctld::startup", error = %e, "get_display_timezone failed; using Europe/Moscow default");
            crate::handlers::admin::init_display_tz(chrono_tz::Europe::Moscow);
        }
    }

    let state = AppState {
        inv,
        registry,
        access_log_tx,
        rate_limiter,
        wizard,
        snapshot_cache,
    };
    Ok(router(state))
}

/// Test-only: build an `AppState` with the access-log writer wired up,
/// the same way `build()` does. Returns the `AppState` plus the
/// writer's `JoinHandle` so the test can `abort()` it deterministically
/// at teardown (the task otherwise lives until all senders drop, which
/// happens when the state goes out of scope — usually fine, but tests
/// that want to inspect the writer's behavior need the explicit handle).
///
/// The rate limiter is built with `RateLimiter::default()` (production
/// capacity). Tests that want to exercise throttling can build their
/// own state with a tighter limiter; see
/// `make_app_state_with_rate_limiter` for that path.
pub fn make_app_state_for_tests(
    inv: SqliteInventory,
    registry: Arc<Registry>,
) -> (AppState, tokio::task::JoinHandle<()>) {
    make_app_state_with_rate_limiter(inv, registry, Arc::new(RateLimiter::default()))
}

/// Test-only: like `make_app_state_for_tests` but takes a custom
/// `RateLimiter` so tests can exercise throttling against a
/// deterministically-tuned limiter (e.g. capacity=2, refill=0/sec)
/// without waiting for production-rate refills.
pub fn make_app_state_with_rate_limiter(
    inv: SqliteInventory,
    registry: Arc<Registry>,
    rate_limiter: Arc<RateLimiter>,
) -> (AppState, tokio::task::JoinHandle<()>) {
    let (access_log_tx, handle) = access_log::spawn_writer(inv.clone());
    (
        AppState {
            inv,
            registry,
            access_log_tx,
            rate_limiter,
            wizard: Arc::new(WizardStore::new()),
            snapshot_cache: crate::snapshot_cache::SnapshotCache::new(),
        },
        handle,
    )
}

/// Spawn the rate-limiter cleanup task. Returns the `JoinHandle`
/// (production discards; tests can abort to confirm spawn worked).
/// Sweeps both the in-memory bucket maps AND the persistent
/// `sub_rate_bans` table (Phase Track-2 chunk 2 — expired bans
/// would otherwise accumulate forever).
///
/// Also piggybacks the wizard-session sweep (Round-3 L1): abandoned
/// add-server wizard sessions hold a plaintext root password and are
/// otherwise only lazily purged on re-fetch — an id that's never
/// re-fetched (operator closed the tab) would retain the secret until
/// restart. The 10-min cadence here matches the wizard's 10-min TTL,
/// so an abandoned session is evicted within ~one TTL of going stale.
pub(crate) fn spawn_rate_limit_cleanup(
    limiter: Arc<RateLimiter>,
    inv: SqliteInventory,
    wizard: Arc<WizardStore>,
) -> tokio::task::JoinHandle<()> {
    use tokio::time::{MissedTickBehavior, interval};

    /// 10-minute cadence — the bucket idle-TTL is 1 hour by default,
    /// so we sweep 6× per TTL window. Cheap (HashMap retain is
    /// O(n) but n is bounded by active source IPs in the last hour).
    /// The persistent-ban purge is one indexed DELETE — also cheap.
    const TICK: Duration = Duration::from_secs(600);

    tokio::spawn(async move {
        let mut tick = interval(TICK);
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        tick.tick().await; // drop the immediate first fire (startup hot)
        loop {
            tick.tick().await;
            let (ip, token) = limiter.cleanup();
            if ip > 0 || token > 0 {
                tracing::debug!(
                    target = "vpnctld::rate_limit",
                    ip_dropped = ip,
                    token_dropped = token,
                    "swept idle rate-limit buckets"
                );
            }
            // Round-3 L1: evict abandoned wizard sessions past their
            // TTL so plaintext root passwords don't linger in memory.
            let wiz_dropped = wizard.sweep_expired();
            if wiz_dropped > 0 {
                tracing::debug!(
                    target = "vpnctld::wizard",
                    sessions_dropped = wiz_dropped,
                    "swept expired wizard sessions"
                );
            }
            match inv.purge_expired_bans().await {
                Ok(0) => {}
                Ok(n) => tracing::info!(
                    target = "vpnctld::rate_limit",
                    bans_dropped = n,
                    "swept expired persistent bans"
                ),
                Err(e) => tracing::warn!(
                    target = "vpnctld::rate_limit",
                    error = %e,
                    "purge_expired_bans failed; retry next tick"
                ),
            }
        }
    })
}

/// Spawn the access-log retention purger. Returns the `JoinHandle` so
/// callers (production: discard; tests: abort to prove the spawn worked
/// without letting the loop actually tick). The loop body is
/// `inv.purge_sub_access_older_than(30)` which has full spec coverage in
/// `crates/inventory/tests/spec_sub_access.rs` — the scheduler itself
/// is dumb wiring around it.
pub(crate) fn spawn_retention_purger(inv: SqliteInventory) -> tokio::task::JoinHandle<()> {
    use std::time::Duration;
    use tokio::time::{MissedTickBehavior, interval};

    /// 30-day retention matches the user-detail page copy. Configurable
    /// later via the Settings section.
    const RETENTION_DAYS: u32 = 30;
    /// Hourly cadence is plenty — the purge cost grows linearly with
    /// row count, and at homelab scale (<10k rows/day) one tick per
    /// hour bounds the table to ~30 days × 24 h × 10k = ~7M rows worst
    /// case, safely indexed.
    const TICK_INTERVAL: Duration = Duration::from_secs(3600);

    tokio::spawn(async move {
        let mut tick = interval(TICK_INTERVAL);
        // Skip the immediate first tick — daemon startup is hot enough
        // (migrations, registry init); a purge on the same scheduler
        // pass adds noise to the journal without doing useful work.
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        tick.tick().await;
        loop {
            tick.tick().await;
            match inv.purge_sub_access_older_than(RETENTION_DAYS).await {
                Ok(0) => tracing::debug!(
                    target = "vpnctld::retention",
                    days = RETENTION_DAYS,
                    "sub_access purge tick: nothing to remove"
                ),
                Ok(n) => tracing::info!(
                    target = "vpnctld::retention",
                    days = RETENTION_DAYS,
                    removed = n,
                    "purged old sub_access_log rows"
                ),
                Err(e) => tracing::warn!(
                    target = "vpnctld::retention",
                    error = %e,
                    "sub_access retention purge failed; will retry next tick"
                ),
            }
            // Track-3 chunk 3: sweep vpn_connection_stats on the same
            // cadence. Same retention window — the table grows with
            // N_servers × N_users × ticks/h × hours_kept and would
            // accumulate forever otherwise. Logs separately so journal
            // tags identify which sweep removed how much.
            match inv.purge_vpn_stats_older_than(RETENTION_DAYS).await {
                Ok(0) => tracing::debug!(
                    target = "vpnctld::retention",
                    days = RETENTION_DAYS,
                    "vpn_connection_stats purge tick: nothing to remove"
                ),
                Ok(n) => tracing::info!(
                    target = "vpnctld::retention",
                    days = RETENTION_DAYS,
                    removed = n,
                    "purged old vpn_connection_stats rows"
                ),
                Err(e) => tracing::warn!(
                    target = "vpnctld::retention",
                    error = %e,
                    "vpn_connection_stats purge failed; will retry next tick"
                ),
            }
            // Phase H chunk 4: sweep node_health on the same cadence.
            // The probe inserts ~144 rows/server/day (every 10 min);
            // a 5-server homelab generates ~22K rows over 30 days —
            // trivial in row count but kept aligned with the other
            // retention windows for operator-mental-model consistency.
            match crate::node_probe_poller::purge_old(&inv, RETENTION_DAYS).await {
                Ok(0) => tracing::debug!(
                    target = "vpnctld::retention",
                    days = RETENTION_DAYS,
                    "node_health purge tick: nothing to remove"
                ),
                Ok(n) => tracing::info!(
                    target = "vpnctld::retention",
                    days = RETENTION_DAYS,
                    removed = n,
                    "purged old node_health rows"
                ),
                Err(e) => tracing::warn!(
                    target = "vpnctld::retention",
                    error = %e,
                    "node_health purge failed; will retry next tick"
                ),
            }
            // Phase G: sweep ACKED admin_alerts on the same cadence.
            // UNACKED alerts are intentionally never auto-purged —
            // an alert that fires once and is forgotten must stay
            // visible until the operator explicitly dismisses it.
            // See migration 0011 doc-comment for the rationale.
            match inv.purge_acked_alerts_older_than(RETENTION_DAYS).await {
                Ok(0) => tracing::debug!(
                    target = "vpnctld::retention",
                    days = RETENTION_DAYS,
                    "admin_alerts purge tick: nothing to remove"
                ),
                Ok(n) => tracing::info!(
                    target = "vpnctld::retention",
                    days = RETENTION_DAYS,
                    removed = n,
                    "purged old acked admin_alerts rows"
                ),
                Err(e) => tracing::warn!(
                    target = "vpnctld::retention",
                    error = %e,
                    "admin_alerts purge failed; will retry next tick"
                ),
            }

            // Phase 5c — sweep vpn_user_sessions rolling 30d.
            match inv.purge_user_sessions_older_than(RETENTION_DAYS).await {
                Ok(0) => tracing::debug!(
                    target = "vpnctld::retention",
                    days = RETENTION_DAYS,
                    "vpn_user_sessions purge tick: nothing to remove"
                ),
                Ok(n) => tracing::info!(
                    target = "vpnctld::retention",
                    days = RETENTION_DAYS,
                    removed = n,
                    "purged old vpn_user_sessions rows"
                ),
                Err(e) => tracing::warn!(
                    target = "vpnctld::retention",
                    error = %e,
                    "vpn_user_sessions purge failed; will retry next tick"
                ),
            }

            // Phase 5b — sweep vpn_user_destinations rolling 30d.
            match inv.purge_user_destinations_older_than(RETENTION_DAYS).await {
                Ok(0) => tracing::debug!(
                    target = "vpnctld::retention",
                    days = RETENTION_DAYS,
                    "vpn_user_destinations purge tick: nothing to remove"
                ),
                Ok(n) => tracing::info!(
                    target = "vpnctld::retention",
                    days = RETENTION_DAYS,
                    removed = n,
                    "purged old vpn_user_destinations rows"
                ),
                Err(e) => tracing::warn!(
                    target = "vpnctld::retention",
                    error = %e,
                    "vpn_user_destinations purge failed; will retry next tick"
                ),
            }

            // Phase 5a-2 — sweep dns_ptr_cache on the same cadence.
            // 7-day TTL — PTR records change rarely (ISP renames,
            // CDN failovers) but not never; weekly refresh keeps
            // the cache accurate without thrashing.
            const DNS_TTL_DAYS: u32 = 7;
            match inv.purge_dns_ptr_older_than(DNS_TTL_DAYS).await {
                Ok(0) => tracing::debug!(
                    target = "vpnctld::retention",
                    days = DNS_TTL_DAYS,
                    "dns_ptr_cache purge tick: nothing to remove"
                ),
                Ok(n) => tracing::info!(
                    target = "vpnctld::retention",
                    days = DNS_TTL_DAYS,
                    removed = n,
                    "purged old dns_ptr_cache rows"
                ),
                Err(e) => tracing::warn!(
                    target = "vpnctld::retention",
                    error = %e,
                    "dns_ptr_cache purge failed; will retry next tick"
                ),
            }

            // Phase 5a-1 — daily rollup of vpn_connection_stats →
            // vpn_user_daily. Re-roll TODAY + YESTERDAY so we
            // capture late-arriving ticks straddling the midnight
            // UTC boundary. Rollup is idempotent (UPSERT). The
            // daily table is the long-term retention layer; the
            // raw 30-day vpn_connection_stats gets purged above,
            // but the aggregated daily totals survive indefinitely.
            for date_offset in &["now", "-1 day"] {
                let date_utc = chrono::Utc::now();
                let target_date = if *date_offset == "-1 day" {
                    (date_utc - chrono::Duration::days(1))
                        .format("%Y-%m-%d")
                        .to_string()
                } else {
                    date_utc.format("%Y-%m-%d").to_string()
                };
                match inv.rollup_vpn_user_daily(&target_date).await {
                    Ok(n) => tracing::debug!(
                        target = "vpnctld::retention",
                        date = %target_date,
                        rolled_rows = n,
                        "vpn_user_daily rollup tick"
                    ),
                    Err(e) => tracing::warn!(
                        target = "vpnctld::retention",
                        date = %target_date,
                        error = %e,
                        "vpn_user_daily rollup failed; will retry next tick"
                    ),
                }
            }
        }
    })
}

/// Phase C-4 — hourly inventory snapshot + retention pruner.
///
/// One tick per hour:
///   1. `snapshot_now(inv, dir)` writes a fresh `inv.db.<ts>.bak`
///   2. `prune_snapshots(dir, Retention::default())` enforces the
///      24-hourly / 30-daily / 12-monthly cap so the disk doesn't
///      fill up on a long-running daemon.
///   3. Audit row written either way (success row carries snapshot
///      path + retained/dropped counts; failure row carries the
///      error string so the operator can see WHY backups stopped).
///
/// First snapshot fires ~60 seconds after daemon start (NOT
/// immediately) so the daemon's hot-path migrations have a chance
/// to settle before the VACUUM INTO write-lock window.
///
/// Returns the `JoinHandle` so production discards it (task lives
/// as long as the runtime) and tests can `abort()` after the spawn
/// assertion.
pub(crate) fn spawn_backup_scheduler(
    inv: SqliteInventory,
    backup_dir: PathBuf,
) -> tokio::task::JoinHandle<()> {
    use std::time::Duration;

    /// Per CLAUDE.md «backups are critical, not optional» — hourly
    /// is the minimum useful cadence (loses at most ~60 min of
    /// operator activity on a host failure). Operator can trigger
    /// extra snapshots from Settings ("snapshot now" button).
    const TICK: Duration = Duration::from_secs(3600);
    /// Delay before the first tick — keeps the daemon's hot
    /// startup path (migrations, registry init, deploy-key gen,
    /// SSE wizard wakeup) clear of a VACUUM INTO write-lock.
    const STARTUP_DELAY: Duration = Duration::from_secs(60);
    spawn_backup_scheduler_with(inv, backup_dir, STARTUP_DELAY, TICK)
}

/// Outcome of the snapshot self-test gate that runs between mint and
/// prune (Round-3 fix #3). Returned by [`decide_prune_after_verify`]
/// so the verify-then-prune decision is unit-testable without an
/// async runtime or a real SQLite snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifyGate {
    /// Whether the freshly-minted snapshot is sound enough to prune
    /// around. `false` keeps the prior good snapshots untouched this
    /// tick.
    pub prune_ok: bool,
    /// Operator-facing reason the snapshot was rejected, for the audit
    /// payload + warn log. `None` when the snapshot passed.
    pub verify_err: Option<String>,
}

/// Decide whether to prune after self-testing a freshly-minted
/// snapshot.
///
/// Pruning enforces retention by DELETING older snapshot files. The
/// hazard fix #3 closes: if the newest snapshot is logically broken
/// (e.g. minted while the DB was empty/truncated) we must NOT prune,
/// or retention could eventually delete the last *good* snapshot and
/// leave only bad ones.
///
/// Rules:
///   * `verify` errored → the self-test could not even run (file
///     missing, permission denied, OOM). Treat as not-prunable and
///     surface the error.
///   * `overall == Fail` → a hard integrity failure (empty
///     sqlite_master, migration replay failed, zero users/servers).
///     Do not prune; keep the prior good snapshot.
///   * `overall == Ok | Warn` → prune. `Warn` covers benign cases
///     (older/newer migration count, no grants yet, stale-by-a-few-
///     hours) that don't mean the snapshot is unrestorable, so they
///     must not block retention — otherwise a homelab that just
///     hasn't granted anyone yet would never prune and fill the disk.
pub(crate) fn decide_prune_after_verify(
    verify: &std::result::Result<
        vpnctl_inventory::SelfTestReport,
        vpnctl_inventory::SqliteInventoryError,
    >,
) -> VerifyGate {
    match verify {
        Err(e) => VerifyGate {
            prune_ok: false,
            verify_err: Some(format!("self-test could not run: {e}")),
        },
        Ok(report) => match report.overall {
            vpnctl_inventory::CheckStatus::Fail => VerifyGate {
                prune_ok: false,
                verify_err: Some(format!(
                    "snapshot self-test FAILED ({} checks); prune skipped to preserve prior good snapshot",
                    report.checks.len()
                )),
            },
            vpnctl_inventory::CheckStatus::Ok | vpnctl_inventory::CheckStatus::Warn => VerifyGate {
                prune_ok: true,
                verify_err: None,
            },
        },
    }
}

/// Parameterised variant — tests use it with tiny delays so the
/// scheduler fires within the test's timeout window.
pub(crate) fn spawn_backup_scheduler_with(
    inv: SqliteInventory,
    backup_dir: PathBuf,
    startup_delay: std::time::Duration,
    tick: std::time::Duration,
) -> tokio::task::JoinHandle<()> {
    use tokio::time::{MissedTickBehavior, interval, sleep};

    tokio::spawn(async move {
        sleep(startup_delay).await;
        let mut tick = interval(tick);
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let snapshot_result = vpnctl_inventory::snapshot_now(&inv, &backup_dir).await;

            // Round-3 fix #3: self-test the fresh snapshot BEFORE
            // pruning. A snapshot that minted a file but is logically
            // incomplete would otherwise be retained as good and the
            // prune step could delete the prior, actually-good
            // snapshot around it. Only prune once the new file passes
            // (or warns benignly). On snapshot-mint failure there's no
            // new file to verify and nothing trustworthy to prune
            // around, so we skip prune too.
            let verify_gate: Option<VerifyGate> = match snapshot_result.as_ref() {
                Ok(path) => Some(decide_prune_after_verify(
                    &vpnctl_inventory::verify_snapshot(path).await,
                )),
                Err(_) => None,
            };

            let should_prune = verify_gate.as_ref().map(|g| g.prune_ok).unwrap_or(false);
            let verify_err: Option<String> =
                verify_gate.as_ref().and_then(|g| g.verify_err.clone());

            let prune_result = if should_prune {
                Some(vpnctl_inventory::prune_snapshots(
                    &backup_dir,
                    vpnctl_inventory::Retention::default(),
                ))
            } else {
                None
            };
            let snapshot_path: Option<String> = snapshot_result
                .as_ref()
                .ok()
                .map(|p| p.display().to_string());
            let snapshot_err: Option<String> =
                snapshot_result.as_ref().err().map(|e| e.to_string());
            let pruned: u64 = prune_result
                .as_ref()
                .map(|r| *r.as_ref().unwrap_or(&0))
                .unwrap_or(0);
            let prune_err: Option<String> = prune_result
                .as_ref()
                .and_then(|r| r.as_ref().err().map(|e| e.to_string()));
            match (&snapshot_err, &verify_err, &prune_err) {
                (None, None, None) => tracing::info!(
                    target = "vpnctld::backup",
                    snapshot = snapshot_path.as_deref().unwrap_or(""),
                    pruned = pruned,
                    "inv.db snapshot complete (self-test passed)"
                ),
                _ => tracing::warn!(
                    target = "vpnctld::backup",
                    snapshot_err = snapshot_err.as_deref().unwrap_or(""),
                    verify_err = verify_err.as_deref().unwrap_or(""),
                    prune_err = prune_err.as_deref().unwrap_or(""),
                    pruned = pruned,
                    "inv.db snapshot did not fully succeed; prune may have been skipped — will retry next tick"
                ),
            }
            // Audit (regardless of success — operator wants to see
            // the failure too). The payload is operator-facing —
            // visible in the audit-timeline page and CSV export.
            if let Err(e) = inv
                .audit(
                    "admin",
                    "backup.snapshot",
                    None,
                    Some(&serde_json::json!({
                        "trigger": "scheduler",
                        "snapshot_path": snapshot_path,
                        "snapshot_err": snapshot_err,
                        "verify_err": verify_err,
                        "pruned": pruned,
                        "prune_err": prune_err,
                    })),
                )
                .await
            {
                tracing::warn!(
                    target = "vpnctld::backup",
                    error = %e,
                    "audit write failed for backup.snapshot"
                );
            }
        }
    })
}

/// Pulled out so tests can inject a state pointed at a tempdir DB.
pub fn router(state: AppState) -> Router {
    // Trace-layer span uses MatchedPath ("/sub/{token}") instead of the raw
    // URI ("/sub/<actual-secret-token>"). Otherwise every subscriber's token
    // would land in INFO-level logs and any aggregator downstream — that's a
    // critical leak (review-agent caught it before it shipped).
    let trace_layer = TraceLayer::new_for_http().make_span_with(|req: &Request<_>| {
        let matched = req
            .extensions()
            .get::<MatchedPath>()
            .map_or("<unknown>", MatchedPath::as_str);
        info_span!("http", method = %req.method(), path = matched)
    });

    let admin_router = admin_router(state.clone());

    Router::new()
        .route("/api/v1/health", get(handlers::health::get))
        // Phase F monitoring stats (NOT behind admin auth — exposes
        // only aggregate counts, no per-IP/per-token details).
        .route(
            "/api/v1/stats/sub-access",
            get(handlers::stats::sub_access),
        )
        .route("/sub/{token}", get(handlers::sub::get))
        // Phase 3 — ninitux subscription-server compat endpoint
        // (`https://ninitux.com/api/v1/app/config/<device_id>`). Same
        // response shape as subscription-server; nginx on 192.168.0.207
        // cuts over from subscription-server:8100 → vpnctld:18402 in
        // Phase 5. See `docs/COMPREHENSIVE_AUDIT_2026-05-19.md` and
        // `handlers/vpn_router.rs` for the byte-equivalence contract.
        // Phase 3 happy path + defense-in-depth catch-all in ONE
        // wildcard route. The handler dispatches based on `tail`
        // shape (single 32-hex segment → device lookup; anything
        // else → canonical `device_not_registered` shape). See
        // `handlers/vpn_router.rs::get_config` for the dispatch
        // contract + why we can't split this into `{device_id}` +
        // `{*tail}` separate routes (matchit 0.8.4 panics on the
        // overlap). Bare-prefix routes (no device_id at all) point
        // at a sibling `get_config_root_catchall` because the `*tail`
        // wildcard requires ≥1 segment.
        .route(
            "/api/v1/app/config/{*tail}",
            get(handlers::vpn_router::get_config),
        )
        .route(
            "/api/v1/app/config",
            get(handlers::vpn_router::get_config_root_catchall),
        )
        .route(
            "/api/v1/app/config/",
            get(handlers::vpn_router::get_config_root_catchall),
        )
        .with_state(state)
        .merge(admin_router)
        .layer(TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(15),
        ))
        .layer(RequestBodyLimitLayer::new(8 * 1024)) // GET only — paranoia
        .layer(trace_layer)
}

/// `/admin/*` subtree. Phase A: shell + tweaks + static assets, all
/// behind basic-auth IF env vars present (otherwise open — useful for
/// local smoke).
fn admin_router(state: AppState) -> Router {
    use crate::handlers::admin;

    // Resolve assets dir relative to CARGO_MANIFEST_DIR for `cargo run`,
    // falling back to ./daemon/assets for `vpnctld` invoked from the
    // workspace root, falling back to ./assets for a binary distributed
    // alongside its assets dir. We pick whichever exists.
    let assets_dir: PathBuf = [
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets"),
        PathBuf::from("daemon/assets"),
        PathBuf::from("assets"),
    ]
    .into_iter()
    .find(|p| p.exists())
    .unwrap_or_else(|| PathBuf::from("daemon/assets"));

    // Explicit routes instead of `nest("/admin", ...)` — axum 0.8's nest
    // does NOT auto-match the trailing-slash variant of the inner "/" route
    // (so `/admin` works but `/admin/` 404s). Explicitly register both.
    // `nest_service` is fine for static — its prefix-match handles the
    // trailing slash naturally.
    //
    // Phase A section routes render the same shell with `active_nav` set
    // and a placeholder body; real content lands in subsequent phases.
    // Without these, clicking a nav anchor 404'd.
    //
    // Each section is registered with AND without the trailing slash —
    // axum 0.8 routes match exactly, so `/admin/users` and `/admin/users/`
    // would otherwise diverge (200 vs 404). Same reason `/admin` and
    // `/admin/` are both wired for dashboard.
    let with_admin = Router::new()
        .route("/admin", get(admin::dashboard))
        .route("/admin/", get(admin::dashboard))
        .route("/admin/monitoring", get(admin::monitoring))
        .route("/admin/monitoring/", get(admin::monitoring))
        .route("/admin/servers", get(admin::servers))
        .route("/admin/servers/", get(admin::servers))
        // Phase H chunk 3: server detail page with live telemetry +
        // declared-vs-observed drift section. Reads
        // `inv.latest_node_health` + `inv.recent_node_health_for_server`;
        // empty-state until chunk 4 wires the periodic poller.
        .route("/admin/servers/{id}", get(admin::server_detail))
        .route("/admin/servers/{id}/", get(admin::server_detail))
        // Phase v0.8 — TOFU pin via web. Manual paste OR auto-detect
        // via ssh-keyscan (form's `mode` field).
        .route(
            "/admin/servers/{id}/set-fingerprint",
            post(admin::server_set_fingerprint),
        )
        // Display name (migration 0029). Operator pins the friendly
        // subscription label end users see ({Country} VLESS ~user);
        // blank clears it back to the country-map fallback.
        .route(
            "/admin/servers/{id}/display-name",
            post(admin::server_set_display_name),
        )
        // Naive (Caddy) per-server config — operator sets naive.domain +
        // naive.acme_email (server_secrets) consumed by the caddy kernel's
        // Caddyfile render + Caddy's built-in ACME (Let's Encrypt).
        .route(
            "/admin/servers/{id}/naive-config",
            post(admin::server_set_naive_config),
        )
        // Auto-suppress opt-in (migration 0030). Toggle whether the
        // server is auto-hidden from subscriptions while unreachable
        // (health monitor sets/clears the runtime suppressed_at flag).
        .route(
            "/admin/servers/{id}/auto-suppress",
            post(admin::server_set_auto_suppress),
        )
        // naive↔HY2 UDP-pairing opt-in (migration 0031, UX-3).
        .route(
            "/admin/servers/{id}/udp-pair",
            post(admin::server_set_udp_pair),
        )
        // Delete a server from inventory (retype-to-confirm, mirrors user
        // delete). GET renders the confirm page; POST does the cascade
        // delete + audits server.remove.
        .route(
            "/admin/servers/{id}/delete-confirm",
            get(admin::server_delete_confirm),
        )
        .route("/admin/servers/{id}/delete", post(admin::server_delete))
        // Reserved-ports list (migration 0028). Operator pins ports
        // the daemon must never touch via sing-box — a sing-box
        // pre-apply guard refuses any rendered inbound on a
        // reserved port. Used for co-tenant scenarios (legacy
        // 3x-ui Docker on :443 sharing the host with vpnctl's
        // sing-box on :8443).
        .route(
            "/admin/servers/{id}/reserved-ports",
            post(admin::server_set_reserved_ports),
        )
        // (route `/admin/servers/{id}/wgturn/vk-link` removed
        // 2026-05-19 — VK link is now end-user-supplied at connect
        // time, not a per-server admin input. See
        // crates/kernels/src/wgturn.rs render_config comment.)
        // Quick-add — register an existing server in inventory with
        // default kernel + protocols. Distinct from the
        // Phase-E wizard at `/admin/servers/new` (which bootstraps a
        // fresh node from scratch).
        .route(
            "/admin/servers/quick-add",
            post(admin::server_quick_add),
        )
        // The operator-facing Deploy button (per CLAUDE.md "Web is
        // the ONLY operator surface"). Bootstraps every missing
        // server-secret + audits. SSH-touching parts (install kernel
        // + apply config) are tracked separately as web-deploy-apply
        // TODO — gated until the daemon ships with a working SSH
        // path on bookworm-2.36.
        .route(
            "/admin/servers/{id}/deploy",
            post(admin::server_deploy),
        )
        // SSE-streamed re-deploy (item-1, 2026-05-31). EventSource (GET)
        // endpoint that streams per-step progress + a terminal ok/error
        // so the operator sees what's happening and how it finished —
        // unlike the POST above, which 303-redirected as "success" even
        // when sing-box crash-looped. Same-origin guarded in-handler.
        .route(
            "/admin/servers/{id}/deploy/sse",
            get(admin::server_deploy_sse),
        )
        // "Deploy all" (2026-06-03) — SSE-streamed re-deploy of EVERY
        // server in one click, so a newly-added user's UUID reaches all
        // nodes without per-server clicks. 3-segment path — no clash with
        // the {id} routes above. Same-origin guarded in-handler.
        .route(
            "/admin/servers/deploy-all/sse",
            get(admin::servers_deploy_all_sse),
        )
        // Migration 0018: per-(server, protocol) hide flag + per-(user,
        // server, protocol) deny override. 4 POST handlers — server-
        // level chip is on /admin/servers/{id}; per-user grid is on
        // /admin/users/{id} (rendered with checkboxes that POST these
        // URLs). See handlers/admin.rs `server_protocol_hide` etc.
        .route(
            "/admin/servers/{sid}/protocols/{pid}/hide",
            post(admin::server_protocol_hide),
        )
        .route(
            "/admin/servers/{sid}/protocols/{pid}/unhide",
            post(admin::server_protocol_unhide),
        )
        .route(
            "/admin/users/{uid}/grants/{sid}/protocols/{pid}/disable",
            post(admin::grant_protocol_disable),
        )
        .route(
            "/admin/users/{uid}/grants/{sid}/protocols/{pid}/enable",
            post(admin::grant_protocol_enable),
        )
        // Server-side grant mutations (Pavel iter B). Identical mutation
        // to /admin/users/{id}/grants/{server_id} but the redirect goes
        // to the server detail page so the operator stays where they
        // started. URL shape mirrors the user-side equivalents.
        .route(
            "/admin/servers/{sid}/grants/{uid}",
            post(admin::server_grant_user),
        )
        .route(
            "/admin/servers/{sid}/grants/{uid}/revoke",
            post(admin::server_revoke_user),
        )
        // Server protocols toggle — inventory-only mutation; the
        // operator runs `vpnctl deploy <server>` from the CLI to
        // push. Routes are split into enable/disable rather than
        // a single toggle so the operator's intent is in the URL
        // (audit-friendly + handles double-submit gracefully).
        .route(
            "/admin/servers/{id}/protocols/{proto}/enable",
            post(admin::server_enable_protocol),
        )
        .route(
            "/admin/servers/{id}/protocols/{proto}/disable",
            post(admin::server_disable_protocol),
        )
        // Multi-kernel: same enable/disable shape for kernels.
        // Adding amneziawg to a sing-box node = first step before
        // enabling wireguard protocol.
        .route(
            "/admin/servers/{id}/kernels/{kernel}/enable",
            post(admin::server_enable_kernel),
        )
        .route(
            "/admin/servers/{id}/kernels/{kernel}/disable",
            post(admin::server_disable_kernel),
        )
        // Phase E sub-iter 4a: add-server wizard step 1.
        // GET renders the form (IP + root password); POST validates,
        // stashes to a server-side session keyed by HttpOnly cookie,
        // and 303s to the step-2 stub. Sub-iter 4b will replace the
        // step-2 stub with the SSE-streamed bootstrap log.
        .route("/admin/servers/new", get(admin::wizard_new))
        .route("/admin/servers/new/", get(admin::wizard_new))
        .route("/admin/servers/new", post(admin::wizard_new_submit))
        .route("/admin/servers/new/", post(admin::wizard_new_submit))
        .route(
            "/admin/servers/new/step-2",
            get(admin::wizard_step2_stub),
        )
        .route(
            "/admin/servers/new/step-2/",
            get(admin::wizard_step2_stub),
        )
        // Phase E sub-iter 4b — SSE source for the step-2 page.
        // EventSource attaches here, the daemon streams BootstrapEvents
        // as named SSE events (step / ok / error). Single-shot:
        // the handler consumes the wizard session on attach (refresh
        // falls back to a "session missing" page with a "start over"
        // link). See `wizard_step2_sse` + `crate::wizard_bootstrap`
        // for the pipeline.
        .route(
            "/admin/servers/new/step-2/sse",
            get(admin::wizard_step2_sse),
        )
        .route("/admin/users", get(admin::users))
        .route("/admin/users/", get(admin::users))
        // Phase C-3.2: web add-user form posts here. Form has one
        // field (`id`); the rest of the user (UUID, tuic_password,
        // sub_token) is minted server-side.
        .route("/admin/users", post(admin::user_create))
        .route("/admin/users/", post(admin::user_create))
        // User detail: `/admin/users/<id>` (with and without trailing
        // slash). Path param doesn't capture an empty segment, so
        // `/admin/users/` continues to hit the list above.
        .route("/admin/users/{id}", get(admin::user_detail))
        .route("/admin/users/{id}/", get(admin::user_detail))
        // Phase C-3 writes (Users). Each write goes via POST so a casual
        // GET (link preview, prefetch, search-bot) cannot mutate state.
        .route(
            "/admin/users/{id}/sub-token/regenerate",
            post(admin::user_regen_sub_token),
        )
        // Mint a per-user tuic_password for a user that has none. naive +
        // Hysteria2 reuse this field, so without it those protocols
        // silently drop from the user's subscription (cdn 2026-06-07).
        .route(
            "/admin/users/{id}/tuic-password/mint",
            post(admin::user_mint_tuic_password),
        )
        // Rotate the WireGuard keypair. Both halves replaced
        // atomically; previous pubkey will fall off the server's
        // [Peer] block on the next `vpnctl deploy`. UI lives on
        // the user-detail page (see `WireGuard keypair` section).
        .route(
            "/admin/users/{id}/wireguard/regenerate",
            post(admin::user_regen_wireguard),
        )
        // Download a drag-drop-ready WG `.conf` file for this
        // (user, server) pair. Works in EVERY WG client — official
        // WG app, Hiddify, AmneziaVPN's "File with settings"
        // picker. Universal fallback even when neither
        // `wireguard://?conf=` (Flow B) nor `vpn://...` (Flow C)
        // is what the recipient's app expects.
        .route(
            "/admin/users/{id}/wireguard/conf/{server_id}",
            get(admin::user_wireguard_conf_download),
        )
        // Pavel iter D.6c — per-user monthly bandwidth cap +
        // alert threshold. POST takes limit_gib + threshold_pct;
        // 0 / empty / non-numeric limit clears the cap.
        .route(
            "/admin/users/{id}/traffic-limit",
            post(admin::user_set_traffic_limit),
        )
        // Phase C-3.3: per-(user, server) grant + revoke. Both POST (HTML
        // forms can't easily DELETE), both idempotent at the SQL layer
        // but audited every time so re-grant attempts show in the
        // timeline. The `/revoke` suffix keeps URL routing
        // unambiguous: `…/grants/{id}` = grant, `…/grants/{id}/revoke`
        // = revoke. Same path-param tuple `(user_id, server_id)`.
        .route(
            "/admin/users/{id}/grants/{server_id}",
            post(admin::user_grant_server),
        )
        .route(
            "/admin/users/{id}/grants/{server_id}/revoke",
            post(admin::user_revoke_server),
        )
        // Phase C-3.4 — destructive: GET shows a double-submit confirm
        // form, POST deletes only if `confirm=<exact-id>` matches.
        .route(
            "/admin/users/{id}/delete-confirm",
            get(admin::user_delete_confirm),
        )
        .route("/admin/users/{id}/delete", post(admin::user_delete))
        // B2 (audit 2026-05-22, shipped 2026-05-23) — bulk
        // grant / revoke on a server detail page. Grant-all
        // is safe (idempotent, reversible per user) → no
        // confirm. Revoke-all is destructive (operator might
        // mass-disable access by mistake) → double-submit
        // confirm via the same shape as user delete.
        .route(
            "/admin/servers/{id}/grants/_grant-all",
            post(admin::server_grant_all_users),
        )
        .route(
            "/admin/servers/{id}/grants/_revoke-all",
            post(admin::server_revoke_all_users),
        )
        // B1.user — soft suspend / restore.  Disabled users get an
        // empty sub config (see sub.rs / vpn_router.rs) until
        // re-enabled. Idempotent: re-POSTing same target state is
        // a no-op redirect.
        .route(
            "/admin/users/{id}/disable",
            post(admin::user_set_disabled_true),
        )
        .route(
            "/admin/users/{id}/enable",
            post(admin::user_set_disabled_false),
        )
        // A5 (audit 2026-05-22, shipped 2026-05-23) — fleet-wide
        // search across users / servers / alerts. See handler doc
        // for why audit isn't part of the same surface.
        .route("/admin/search", get(admin::search))
        .route("/admin/audit", get(admin::audit))
        .route("/admin/audit/", get(admin::audit))
        // Phase D — CSV export uses the same filter query string as
        // the HTML timeline. Distinct path so browsers + curl can
        // hit it directly without a form submission.
        .route("/admin/audit.csv", get(admin::audit_csv))
        // Phase G — operator-facing alerts feed + ack action. The
        // dashboard tile links to /admin/alerts; ack POST is per-id.
        .route("/admin/alerts", get(admin::alerts))
        .route("/admin/alerts/", get(admin::alerts))
        .route("/admin/alerts/{id}/ack", post(admin::alert_ack))
        .route("/admin/alerts/ack-all", post(admin::alert_ack_all))
        .route("/admin/settings", get(admin::settings))
        .route("/admin/settings/", get(admin::settings))
        // 2026-05-23 — operator-configurable display TZ. POST writes
        // inventory + invalidates the global cache so subsequent
        // page renders use the new zone immediately.
        .route(
            "/admin/settings/timezone",
            post(admin::settings_timezone_set),
        )
        // Phase 3c — Settings GeoIP «update now» SSE source. Streams
        // the live stdout/stderr of `vpnctl geoip-update` as named
        // SSE events (step / ok / error). GET because EventSource
        // only does GET; the action is idempotent (no state mutation
        // beyond the disk file the subprocess writes itself + an
        // audit row). See `geoip_update_runner` for the subprocess
        // pattern (std::process::Command, NOT tokio::process —
        // glibc-2.39 hazard explained in the module doc).
        .route(
            "/admin/settings/geoip/update-now",
            get(admin::settings_geoip_update_now_sse),
        )
        // Phase G chunk 3 — Telegram bot config POST. Singleton row;
        // empty inputs = clear/disable. CSRF middleware (Origin check)
        // runs ahead of this, so a cross-origin form-post can't write.
        .route(
            "/admin/settings/telegram",
            post(admin::settings_telegram),
        )
        // Phase G chunk 3 part 2 — synchronous test-send so the
        // operator can verify credentials without waiting for an
        // actual alert. Surfaces curl/API errors as 502.
        .route(
            "/admin/settings/telegram/test",
            post(admin::settings_telegram_test),
        )
        // Phase G chunk 3.5 follow-up — recovery action for servers
        // added without wizard (quick-add / migrate-from-bash). One-
        // shot password-auth SSH + pubkey append; same logic as
        // wizard step 3. See server_push_deploy_key doc-comment.
        .route(
            "/admin/servers/{id}/push-deploy-key",
            post(admin::server_push_deploy_key),
        )
        // Phase C-4 — manual snapshot trigger + per-file download.
        // Download is GET (so a normal `<a download>` works); snapshot
        // trigger is POST (it mutates filesystem state + writes an
        // audit row). Filename validation in the handler keeps `..`
        // and absolute paths out of the backup dir.
        .route(
            "/admin/backup/snapshot",
            post(admin::backup_snapshot_now),
        )
        .route(
            "/admin/backup/download/{name}",
            get(admin::backup_download),
        )
        // Phase 5c — restore self-test. POST runs `verify_snapshot`
        // against the latest local snapshot in a tempdir (no touch
        // to live inv.db) and renders an HTML report. URL is
        // bookmarkable so the operator can browser-back to a stale
        // report if they realise mid-investigation they wanted to
        // compare with the previous run.
        .route(
            "/admin/backup/self-test",
            post(admin::backup_self_test),
        )
        .route("/admin/tweak/{kind}", post(admin::set_tweak))
        // Pavel 2026-05-26: ends the «постоянно пароль ввожу» loop.
        // Session cookie is HttpOnly so JS can't clear it directly;
        // a server-side POST that emits `Max-Age=0` is the only way
        // to log out without nuking the entire browser profile.
        .route("/admin/logout", post(admin::logout))
        .nest_service("/admin/assets", ServeDir::new(&assets_dir))
        .with_state(state);

    // CSRF guard runs FIRST (outermost layer), so basic-auth never even
    // gets a chance to validate credentials on a cross-origin POST. This
    // also means the 403 lands without consuming the auth check, so an
    // attacker can't probe whether a given user/password combo is valid
    // via a CSRF flow.
    // `route_layer` (NOT `layer`) for the same anti-fingerprinting
    // reason as the auth layer below: `.layer()` wraps the router's
    // default 404 fallback, so a POST to any unrelated path (e.g.
    // /etc/passwd) returned `403 vpnctl admin: csrf — Origin (or
    // Referer) must match Host` + the Host/Origin/Referer dump —
    // identifying the backend as vpnctld. Caught by pre-monitoring
    // vuln scan 2026-05-20. `route_layer` confines the CSRF check
    // to matched admin routes; unmatched paths fall through to
    // axum's default 404 with no body.
    let with_csrf = with_admin.route_layer(axum::middleware::from_fn(
        crate::handlers::csrf::require_same_origin,
    ));

    // Security-headers layer for the admin tree. Defense-in-depth
    // against XSS (CSP), MIME-sniffing attacks (nosniff), clickjacking
    // (frame-ancestors / X-Frame-Options), and referrer leakage to
    // any external resource we might fetch (none today, but pre-pin).
    // Added 2026-05-18 per security audit. Notes:
    //   * `script-src 'self' 'unsafe-inline'` — we use inline `style=`
    //     attrs heavily (maud-generated). `unsafe-inline` for STYLE
    //     not SCRIPT — script is `'self'` only. No inline `<script>`
    //     today.
    //   * `connect-src 'self'` — pre-blocks future XSS attempts to
    //     exfil via fetch() to evil.com.
    //   * `frame-ancestors 'none'` is the modern equivalent of
    //     X-Frame-Options: DENY; we set both for old browsers.
    // All five `SetResponseHeaderLayer`s use `route_layer` so the
    // headers attach ONLY to responses from matched admin routes.
    // With `.layer()` the headers also flowed into axum's default
    // 404 fallback, producing a distinctive header fingerprint on
    // any unrelated path (CSP with `frame-ancestors 'none'; form-
    // action 'self'`, Permissions-Policy with the full sensor-deny
    // list, etc) — `curl -I http://192.168.0.236:18402/etc/passwd`
    // returned an HTML-admin-shaped 404 with admin-only response
    // headers. Caught by pre-monitoring vuln scan 2026-05-20.
    let with_security_headers = with_csrf
        .route_layer(tower_http::set_header::SetResponseHeaderLayer::if_not_present(
            axum::http::header::CONTENT_SECURITY_POLICY,
            axum::http::HeaderValue::from_static(
                "default-src 'self'; \
                 script-src 'self'; \
                 style-src 'self' 'unsafe-inline'; \
                 img-src 'self' data:; \
                 font-src 'self' https://fonts.gstatic.com; \
                 connect-src 'self'; \
                 frame-ancestors 'none'; \
                 base-uri 'self'; \
                 form-action 'self'",
            ),
        ))
        .route_layer(tower_http::set_header::SetResponseHeaderLayer::if_not_present(
            axum::http::header::X_CONTENT_TYPE_OPTIONS,
            axum::http::HeaderValue::from_static("nosniff"),
        ))
        .route_layer(tower_http::set_header::SetResponseHeaderLayer::if_not_present(
            axum::http::header::X_FRAME_OPTIONS,
            axum::http::HeaderValue::from_static("DENY"),
        ))
        // Referrer-Policy: SAME-ORIGIN, not no-referrer.
        //
        // The 2026-05-18 security-audit shipped `no-referrer` which
        // stripped Referer from EVERY outbound request — including
        // our own same-origin form POSTs. Combined with browsers
        // that send `Origin: null` for opaque-origin contexts
        // (privacy mode, sandboxed iframe, certain extensions), this
        // 100%-bricks the CSRF middleware: both Origin and Referer
        // are unusable → every POST/PUT/DELETE/PATCH gets blocked
        // with «Origin (or Referer) header required and must match
        // Host». Pavel hit this in prod 2026-05-19 and couldn't
        // mutate ANYTHING through /admin/*.
        //
        // `same-origin` keeps the privacy guarantee that nothing
        // leaks to external sites (admin tree doesn't link out
        // anyway) AND keeps Referer alive on our own POSTs so the
        // CSRF middleware's Origin→Referer fallback works.
        .route_layer(tower_http::set_header::SetResponseHeaderLayer::if_not_present(
            axum::http::header::REFERRER_POLICY,
            axum::http::HeaderValue::from_static("same-origin"),
        ))
        // `Permissions-Policy` deprecates Feature-Policy. Block every
        // sensor + device API we don't use (= all of them).
        .route_layer(tower_http::set_header::SetResponseHeaderLayer::if_not_present(
            axum::http::HeaderName::from_static("permissions-policy"),
            axum::http::HeaderValue::from_static(
                "accelerometer=(), camera=(), geolocation=(), gyroscope=(), \
                 magnetometer=(), microphone=(), payment=(), usb=()",
            ),
        ));

    match BasicAuth::from_env() {
        Ok(Some(auth)) => {
            // `route_layer` (NOT `layer`) so the auth challenge fires ONLY
            // on matched admin routes. With `.layer()` the middleware
            // wrapped axum's fallback too: every unrelated path (e.g.
            // `/etc/passwd`, `/`, `/foo`) reaching this router returned
            // `401 WWW-Authenticate: Basic realm="vpnctl admin"` —
            // identifying the backend as vpnctld to any probe. Caught by
            // pre-monitoring vuln scan 2026-05-20 (`curl
            // http://192.168.0.236:18402/etc/passwd` → 401 admin realm).
            //
            // `route_layer` leaves unmatched paths with axum's default
            // 404 (no body, no admin realm). Matched `/admin/*` routes
            // still get the auth check — same UX for legitimate operators,
            // no fingerprint leak for probes hitting random paths.
            with_security_headers.route_layer(axum::middleware::from_fn_with_state(
                auth,
                crate::handlers::auth::require_basic_auth,
            ))
        }
        // Auth intentionally unset (env vars missing/empty) — local-smoke
        // path. The startup gate (`assert_auth_safe_for_addr`) already
        // refused a non-loopback bind in this state, so reaching here
        // means a loopback bind where open admin is acceptable.
        Ok(None) => with_security_headers,
        // Malformed credential config (a `$argon2…` password that doesn't
        // parse). FAIL CLOSED — lock the admin tree behind a 503 rather
        // than fall through to an unauthenticated router. Unreachable on a
        // live daemon: the startup gate refuses to boot on this verdict.
        // Kept as a belt-and-braces guarantee that the router can NEVER be
        // built in a fail-open state (the pre-2026-06-04 bug).
        Err(e) => {
            tracing::error!(
                target = "vpnctld::auth",
                error = %e,
                "admin auth config malformed — locking admin tree (fail closed)"
            );
            with_security_headers.route_layer(axum::middleware::from_fn(
                crate::handlers::auth::deny_all_misconfigured,
            ))
        }
    }
}

/// Same canonical Registry as the CLI uses. Kept in a tiny helper so a
/// future shared `crate vpnctl-registry` can replace this without changing
/// callers. `pub(crate)` so secret-minting tests (and any other in-crate
/// caller that needs the canonical protocol set) build the real registry
/// rather than a hand-rolled subset that could drift.
pub(crate) fn build_registry() -> anyhow::Result<Registry> {
    use vpnctl_kernels::{
        AmneziaWg, Caddy, DnsTunnel as DnsTunnelKernel, SingBox, WgTurn as WgTurnKernel,
    };
    use vpnctl_protocols::{
        AnyTls, DnsTunnel as DnsTunnelProtocol, Hysteria2, Naive, Shadowsocks2022, Trojan, TuicV5,
        VlessReality, WgTurn as WgTurnProtocol, WireGuard,
    };

    let mut reg = Registry::new();
    reg.register_kernel(Box::new(SingBox::new()))?;
    reg.register_kernel(Box::new(AmneziaWg::new()))?;
    // wgturn-core — VK-TURN-relayed WireGuard emergency channel.
    // Mirrors `cli/src/registry.rs::build`. The duplication is
    // pre-existing (see this function's doc-comment); a future
    // `vpnctl-registry` crate consolidates both sites.
    reg.register_kernel(Box::new(WgTurnKernel::new()))?;
    // Caddy + forwardproxy@naive — serves the `naive` protocol with a
    // real masquerade website. MUST stay in lockstep with cli/registry.rs.
    reg.register_kernel(Box::new(Caddy::new()))?;
    // dns-tunnel — slipstream-rust DNS-over-НСДИ last-resort transport.
    // Owns TWO units (slipstream-server UDP:53 + loopback VLESS sing-box).
    // MUST stay in lockstep with cli/registry.rs.
    reg.register_kernel(Box::new(DnsTunnelKernel::new()))?;
    reg.register_protocol(Box::new(VlessReality::new()))?;
    reg.register_protocol(Box::new(TuicV5::new()))?;
    reg.register_protocol(Box::new(Hysteria2::new()))?;
    reg.register_protocol(Box::new(Shadowsocks2022::new()))?;
    reg.register_protocol(Box::new(WireGuard::new()))?;
    reg.register_protocol(Box::new(AnyTls::new()))?;
    reg.register_protocol(Box::new(Trojan::new()))?;
    reg.register_protocol(Box::new(WgTurnProtocol::new()))?;
    // naive — Chromium-fingerprint proxy served by the Caddy kernel.
    // Without this the daemon's /sub render + admin dpi-chip silently
    // drop naive (the CLI deploy still worked, hiding the gap).
    reg.register_protocol(Box::new(Naive::new()))?;
    // dns-tunnel — companion stub to the dns-tunnel kernel. Two-process
    // client → appears_in_sing_box_sub() is false. MUST stay in lockstep
    // with cli/registry.rs.
    reg.register_protocol(Box::new(DnsTunnelProtocol::new()))?;
    Ok(reg)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod registry_drift_guard {
    use super::build_registry;

    /// The daemon's registry MUST stay in lockstep with
    /// `cli/src/registry.rs::build` — the `/sub` render and the admin
    /// dpi-chip resolve protocols through THIS registry, so anything
    /// registered in the CLI but not here is silently dropped from every
    /// subscription (exactly what happened to `naive` until 2026-06-04).
    /// Full-set pin: adding/removing a protocol or kernel at one site
    /// without the other (or this list) trips the assert.
    #[test]
    fn build_registry_matches_canonical_set() {
        let reg = build_registry().unwrap();
        let mut protos: Vec<String> = reg.protocol_ids().into_iter().map(|p| p.0).collect();
        let mut kernels: Vec<String> = reg.kernel_ids().into_iter().map(|k| k.0).collect();
        protos.sort();
        kernels.sort();

        let mut want_protos = [
            "anytls",
            "dns-tunnel",
            "hysteria2",
            "naive",
            "shadowsocks-2022",
            "trojan",
            "tuic-v5",
            "vless+reality",
            "wgturn",
            "wireguard",
        ]
        .map(String::from)
        .to_vec();
        want_protos.sort();

        let mut want_kernels = ["amneziawg", "caddy", "dns-tunnel", "sing-box", "wgturn"]
            .map(String::from)
            .to_vec();
        want_kernels.sort();

        assert_eq!(protos, want_protos, "daemon protocol registry drifted");
        assert_eq!(kernels, want_kernels, "daemon kernel registry drifted");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod backup_verify_gate_tests {
    use super::decide_prune_after_verify;
    use vpnctl_inventory::{CheckResult, CheckStatus, SelfTestReport, SqliteInventoryError};

    /// Minimal report carrying just an `overall` status — the gate
    /// only reads `overall` (+ `checks.len()` for the reason string).
    fn report(overall: CheckStatus) -> SelfTestReport {
        SelfTestReport {
            snapshot_path: "/tmp/inv.db.test.bak".to_string(),
            snapshot_size_bytes: 4096,
            snapshot_age_seconds: Some(10),
            schema_migrations_applied: 1,
            user_count: if matches!(overall, CheckStatus::Fail) {
                0
            } else {
                3
            },
            server_count: 2,
            grant_count: 1,
            users_with_sub_token: 3,
            started_at: chrono::Utc::now(),
            duration_ms: 5,
            overall: overall.clone(),
            checks: vec![CheckResult {
                name: "synthetic",
                status: overall,
                detail: "test".to_string(),
            }],
        }
    }

    #[test]
    fn backup_scheduler_skips_prune_on_failed_verify() {
        // A snapshot whose self-test FAILS must not be pruned around,
        // and the failure must surface (audit/log) so the operator
        // sees why retention paused.
        let gate = decide_prune_after_verify(&Ok(report(CheckStatus::Fail)));
        assert!(!gate.prune_ok, "FAIL verify must skip prune");
        assert!(
            gate.verify_err.is_some(),
            "FAIL verify must surface an error string"
        );
    }

    #[test]
    fn backup_scheduler_skips_prune_when_verify_cannot_run() {
        // verify_snapshot itself errored (file missing / OOM): we
        // can't trust the new snapshot, so keep prior good ones.
        let err: std::result::Result<SelfTestReport, SqliteInventoryError> =
            Err(SqliteInventoryError::Invalid("stat snapshot: nope".into()));
        let gate = decide_prune_after_verify(&err);
        assert!(!gate.prune_ok, "un-runnable verify must skip prune");
        let reason = gate.verify_err.expect("must carry a reason");
        assert!(
            reason.starts_with("self-test could not run:"),
            "reason should be prefixed; got {reason:?}"
        );
        assert!(
            reason.contains("stat snapshot: nope"),
            "reason should include the underlying error; got {reason:?}"
        );
    }

    #[test]
    fn backup_scheduler_prunes_on_passing_verify() {
        // A clean self-test proceeds to prune exactly as before.
        let gate = decide_prune_after_verify(&Ok(report(CheckStatus::Ok)));
        assert!(gate.prune_ok, "OK verify must prune");
        assert!(gate.verify_err.is_none());
    }

    #[test]
    fn backup_scheduler_prunes_on_warn_verify() {
        // Warn is benign (no grants yet, older/newer migration count,
        // slightly stale) — it must NOT block retention, or a fresh
        // homelab would never prune and fill the disk.
        let gate = decide_prune_after_verify(&Ok(report(CheckStatus::Warn)));
        assert!(gate.prune_ok, "WARN verify must still prune");
        assert!(gate.verify_err.is_none());
    }
}
