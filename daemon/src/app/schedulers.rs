//! Periodic background schedulers for the daemon (retention, backups, rate-limit cleanup, fleet digest).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use vpnctl_inventory::SqliteInventory;

use crate::rate_limit::RateLimiter;
use crate::wizard::WizardStore;

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

/// Spawn the daily fleet-digest scheduler. Sends a localized Telegram
/// digest (all-clear 🟢 or open-problems list) every
/// `VPNCTLD_DIGEST_INTERVAL_SECS` (default 86400 = 24h, min 60). The
/// first digest fires one interval after start, not at boot. Returns the
/// `JoinHandle` for test/abort symmetry. No-op when the transport isn't
/// configured (`send_digest` returns early). The digest content is
/// unit-tested in `alert_text::render_digest_html`; this is dumb wiring.
pub(crate) fn spawn_digest_scheduler(inv: SqliteInventory) -> tokio::task::JoinHandle<()> {
    const DEFAULT_SECS: u64 = 86_400;
    let secs = std::env::var("VPNCTLD_DIGEST_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|n| *n >= 60)
        .unwrap_or(DEFAULT_SECS);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(secs));
        // Skip the immediate first tick — don't fire a digest at boot.
        tick.tick().await;
        loop {
            tick.tick().await;
            crate::node_probe_poller::send_digest(&inv).await;
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
            match crate::quality_poller::purge_old(&inv, RETENTION_DAYS).await {
                Ok(0) => tracing::debug!(
                    target = "vpnctld::retention",
                    days = RETENTION_DAYS,
                    "server_quality_samples purge tick: nothing to remove"
                ),
                Ok(n) => tracing::info!(
                    target = "vpnctld::retention",
                    days = RETENTION_DAYS,
                    removed = n,
                    "purged old server_quality_samples rows"
                ),
                Err(e) => tracing::warn!(
                    target = "vpnctld::retention",
                    error = %e,
                    "server_quality_samples purge failed; will retry next tick"
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

            // 2026-06-14 — sweep vpn_user_source_ips rolling 30d
            // (source-IP counterpart to vpn_user_destinations).
            match inv.purge_user_source_ips_older_than(RETENTION_DAYS).await {
                Ok(0) => tracing::debug!(
                    target = "vpnctld::retention",
                    days = RETENTION_DAYS,
                    "vpn_user_source_ips purge tick: nothing to remove"
                ),
                Ok(n) => tracing::info!(
                    target = "vpnctld::retention",
                    days = RETENTION_DAYS,
                    removed = n,
                    "purged old vpn_user_source_ips rows"
                ),
                Err(e) => tracing::warn!(
                    target = "vpnctld::retention",
                    error = %e,
                    "vpn_user_source_ips purge failed; will retry next tick"
                ),
            }

            // IP-concurrency peaks share the source-IP retention window.
            match inv
                .purge_user_ip_concurrency_older_than(RETENTION_DAYS)
                .await
            {
                Ok(0) => tracing::debug!(
                    target = "vpnctld::retention",
                    days = RETENTION_DAYS,
                    "vpn_user_ip_concurrency purge tick: nothing to remove"
                ),
                Ok(n) => tracing::info!(
                    target = "vpnctld::retention",
                    days = RETENTION_DAYS,
                    removed = n,
                    "purged old vpn_user_ip_concurrency rows"
                ),
                Err(e) => tracing::warn!(
                    target = "vpnctld::retention",
                    error = %e,
                    "vpn_user_ip_concurrency purge failed; will retry next tick"
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
