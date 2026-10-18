use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use vpnctl_inventory::SqliteInventory;

use crate::rate_limit::RateLimiter;
use crate::wizard::WizardStore;

pub(crate) fn spawn_rate_limit_cleanup(
    limiter: Arc<RateLimiter>,
    inv: SqliteInventory,
    wizard: Arc<WizardStore>,
) -> tokio::task::JoinHandle<()> {
    use tokio::time::{MissedTickBehavior, interval};

    const TICK: Duration = Duration::from_secs(600);

    tokio::spawn(async move {
        let mut tick = interval(TICK);
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        tick.tick().await;
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

pub(crate) fn spawn_digest_scheduler(inv: SqliteInventory) -> tokio::task::JoinHandle<()> {
    const DEFAULT_SECS: u64 = 86_400;
    let secs = std::env::var("VPNCTLD_DIGEST_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|n| *n >= 60)
        .unwrap_or(DEFAULT_SECS);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(secs));
        tick.tick().await;
        loop {
            tick.tick().await;
            crate::node_probe_poller::send_digest(&inv).await;
        }
    })
}

pub(crate) fn spawn_retention_purger(inv: SqliteInventory) -> tokio::task::JoinHandle<()> {
    use std::time::Duration;
    use tokio::time::{MissedTickBehavior, interval};

    const RETENTION_DAYS: u32 = 30;
    const TICK_INTERVAL: Duration = Duration::from_secs(3600);

    tokio::spawn(async move {
        let mut tick = interval(TICK_INTERVAL);
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
            match crate::protocol_assurance_poller::purge_old(&inv, RETENTION_DAYS).await {
                Ok(0) => tracing::debug!(
                    target = "vpnctld::retention",
                    days = RETENTION_DAYS,
                    "protocol assurance purge tick: nothing to remove"
                ),
                Ok(n) => tracing::info!(
                    target = "vpnctld::retention",
                    days = RETENTION_DAYS,
                    removed = n,
                    "purged old protocol assurance rows"
                ),
                Err(e) => {
                    tracing::warn!(target = "vpnctld::retention", error = %e, "protocol assurance purge failed; will retry next tick")
                }
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

pub(crate) fn spawn_backup_scheduler(
    inv: SqliteInventory,
    backup_dir: PathBuf,
) -> tokio::task::JoinHandle<()> {
    const TICK: Duration = Duration::from_secs(3600);
    const STARTUP_DELAY: Duration = Duration::from_secs(60);
    spawn_backup_scheduler_with(inv, backup_dir, STARTUP_DELAY, TICK)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifyGate {
    pub prune_ok: bool,
    pub verify_err: Option<String>,
}

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
        let gate = decide_prune_after_verify(&Ok(report(CheckStatus::Fail)));
        assert!(!gate.prune_ok, "FAIL verify must skip prune");
        assert!(
            gate.verify_err.is_some(),
            "FAIL verify must surface an error string"
        );
    }

    #[test]
    fn backup_scheduler_skips_prune_when_verify_cannot_run() {
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
        let gate = decide_prune_after_verify(&Ok(report(CheckStatus::Ok)));
        assert!(gate.prune_ok, "OK verify must prune");
        assert!(gate.verify_err.is_none());
    }

    #[test]
    fn backup_scheduler_prunes_on_warn_verify() {
        let gate = decide_prune_after_verify(&Ok(report(CheckStatus::Warn)));
        assert!(gate.prune_ok, "WARN verify must still prune");
        assert!(gate.verify_err.is_none());
    }
}
