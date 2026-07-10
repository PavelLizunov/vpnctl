//! Periodic Boosty → VPN subscription reconciliation.
//!
//! Every `boosty_settings.poll_interval_secs` (when the bridge is enabled)
//! this pulls the blog's subscriber roster and reconciles VPN access:
//! active subscribers' linked users are auto-enabled; lapsed subscribers'
//! linked users are either auto-disabled (`auto_disable_lapsed = 1`) or
//! just surfaced (default — the operator confirms via the admin page). See
//! [`vpnctl_boosty_bridge`] for the reconcile logic + safety invariant
//! (only LINKED users are ever touched).
//!
//! A `disabled` flip only changes inv.db; the nodes keep serving their old
//! `users[]` until a deploy re-renders their configs. So every applied flip
//! is followed by [`deploy_flipped_users`] — the same render+apply pipeline
//! as the manual per-user disable button (`run_redeploy`), deduplicated
//! across the affected users' servers.
//!
//! Structurally the same shape as [`crate::node_probe_poller`]: spawn a
//! tokio task, drop the immediate first fire, tick, do one bounded unit of
//! work, never panic. The per-tick logic ([`run_tick`]) is a free function
//! so it can be driven directly in a test without the interval clock.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use vpnctl_boosty_bridge::{ApplyMode, sync_from_settings};
use vpnctl_core::{Registry, Server, UserId};
use vpnctl_inventory::SqliteInventory;

/// Fallback cadence when settings carry no positive interval.
const DEFAULT_INTERVAL_SECS: u64 = 3600;

/// Alert kind for a failed sync pass. One bridge → one instance (no
/// per-server suffix); the partial-UNIQUE dedup keeps a single open row.
const SYNC_FAILED_ALERT_KIND: &str = "boosty.sync.failed";

/// Spawn the Boosty sync poller. Returns the handle so production (which
/// discards) and tests share one interface, matching the other pollers.
pub fn spawn_boosty_sync_poller(
    inv: SqliteInventory,
    registry: Arc<Registry>,
    deploy_key_path: PathBuf,
) -> tokio::task::JoinHandle<()> {
    use tokio::time::{MissedTickBehavior, interval};

    tokio::spawn(async move {
        // Resolve the cadence once at spawn (a changed interval takes
        // effect on the next daemon start — same as the env-driven
        // pollers). `enabled` + `mode` ARE re-read every tick so toggling
        // the bridge on/off doesn't need a restart.
        let interval_secs = match inv.get_boosty_settings().await {
            Ok(s) if s.poll_interval_secs > 0 => s.poll_interval_secs,
            _ => DEFAULT_INTERVAL_SECS,
        };

        let mut tick = interval(Duration::from_secs(interval_secs));
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        // Drop the immediate first fire — daemon startup is hot.
        tick.tick().await;

        loop {
            tick.tick().await;
            run_tick(&inv, &registry, &deploy_key_path).await;
        }
    })
}

/// One reconciliation tick. No-op (fast) when the bridge is disabled.
/// Never panics — every error is logged and swallowed so the loop
/// survives a transient Boosty outage or a bad token.
pub async fn run_tick(inv: &SqliteInventory, registry: &Arc<Registry>, deploy_key_path: &Path) {
    let settings = match inv.get_boosty_settings().await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                target = "vpnctld::boosty",
                error = %e,
                "read boosty_settings failed; skipping tick"
            );
            return;
        }
    };

    if !settings.enabled {
        return;
    }

    // "Auto-provision, disable on a button" is the default: auto-enable
    // active subscribers, only SURFACE lapses. Flip auto_disable_lapsed to
    // also auto-disable.
    let mode = if settings.auto_disable_lapsed {
        ApplyMode::Full
    } else {
        ApplyMode::EnableOnly
    };

    match sync_from_settings(inv, &settings, mode).await {
        Ok(report) => {
            // Recovery: a working pass silently acks the open failure
            // alert (auto-recovery pattern — good news needs no manual
            // ack).
            note_sync_recovery(inv).await;
            tracing::info!(
                target = "vpnctld::boosty",
                enabled = report.enabled.len(),
                disabled = report.disabled.len(),
                lapsed_pending = report.lapsed_pending.len(),
                new_subscribers = report.new_subscribers.len(),
                suppressed_disables = report.suppressed_disables.len(),
                errors = report.errors.len(),
                "boosty sync tick"
            );
            for e in &report.errors {
                tracing::warn!(target = "vpnctld::boosty", error = %e, "sync action failed");
            }

            // Push the flips to the nodes. Sequential (awaited) on purpose:
            // the next tick can't start until this one's deploys finish, so
            // the poller never races itself on a node.
            let flipped: Vec<String> = report
                .enabled
                .iter()
                .chain(report.disabled.iter())
                .cloned()
                .collect();
            if !flipped.is_empty() {
                deploy_flipped_users(inv, registry, deploy_key_path, &flipped, "boosty.sync").await;
            }
        }
        Err(e) => {
            tracing::warn!(
                target = "vpnctld::boosty",
                error = %e,
                "boosty sync failed"
            );
            note_sync_failure(inv, &e).await;
        }
    }
}

/// Fire the sync-failure alert (dedup'd while open) + Telegram push. A
/// dead bridge is otherwise INVISIBLE: new subscribers silently stop
/// being enabled and the operator finds out from users. Text contract
/// lives in [`vpnctl_boosty_bridge::sync_failure_summary`] (auth = dead
/// creds + the web fix surface; anything else = transient).
async fn note_sync_failure(inv: &SqliteInventory, err: &vpnctl_boosty_bridge::BridgeError) {
    let summary = vpnctl_boosty_bridge::sync_failure_summary(err);
    match inv
        .insert_alert_if_no_unacked(SYNC_FAILED_ALERT_KIND, None, "warning", &summary, None)
        .await
    {
        Ok(Some(alert_id)) => {
            let payload = serde_json::json!({
                "auth": matches!(err, vpnctl_boosty_bridge::BridgeError::Auth(_)),
                "summary": summary,
            });
            crate::node_probe_poller::push_alert(
                inv,
                SYNC_FAILED_ALERT_KIND,
                "warning",
                "boosty",
                &payload,
                Some(alert_id),
            )
            .await;
        }
        // Already open — dedup'd; no push spam while the operator ignores it.
        Ok(None) => {}
        Err(e) => tracing::warn!(
            target = "vpnctld::boosty",
            error = %e,
            "insert boosty.sync.failed alert failed"
        ),
    }
}

/// Recovery half of [`note_sync_failure`]: silently ack the open alert.
async fn note_sync_recovery(inv: &SqliteInventory) {
    if let Err(e) = inv.ack_open_alerts(SYNC_FAILED_ALERT_KIND, None).await {
        tracing::warn!(
            target = "vpnctld::boosty",
            error = %e,
            "auto-ack boosty.sync.failed failed"
        );
    }
}

/// Re-deploy every server granted to the flipped users, so the `disabled`
/// flips actually reach the nodes (`users_for_server` excludes disabled
/// users at render time — without this, a re-subscribed user stays locked
/// out at the node and a lapsed one keeps VPN access).
///
/// Servers are deduplicated across users and deployed one at a time via
/// [`crate::wizard_bootstrap::run_redeploy`] (which carries the per-server
/// DeployGuard and writes the `server.deploy` audit row that clears the
/// pending-deploy banner). Per-server failures are collected, logged, and
/// audited — one summary `boosty.autodeploy` row per batch (bulk-op
/// convention), never a panic.
pub(crate) async fn deploy_flipped_users(
    inv: &SqliteInventory,
    registry: &Arc<Registry>,
    deploy_key_path: &Path,
    user_ids: &[String],
    trigger: &'static str,
) {
    use tokio_stream::StreamExt;

    // Union of the users' granted servers, deduplicated by server id.
    let mut by_id: BTreeMap<String, Server> = BTreeMap::new();
    for uid in user_ids {
        match inv.servers_for_user(&UserId(uid.clone())).await {
            Ok(servers) => {
                for s in servers {
                    by_id.insert(s.id.0.clone(), s);
                }
            }
            Err(e) => tracing::warn!(
                target = "vpnctld::boosty",
                user = %uid,
                error = %e,
                "servers_for_user failed; node deploy for this user skipped"
            ),
        }
    }
    if by_id.is_empty() {
        return;
    }
    let servers: Vec<Server> = by_id.into_values().collect();
    let server_ids: Vec<String> = servers.iter().map(|s| s.id.0.clone()).collect();

    let mut failed: Vec<String> = Vec::new();
    for server in servers {
        let sid = server.id.0.clone();
        let mut stream = Box::pin(crate::wizard_bootstrap::run_redeploy(
            server,
            inv.clone(),
            Arc::clone(registry),
            deploy_key_path.to_path_buf(),
        ));
        let mut err: Option<String> = None;
        while let Some(ev) = stream.next().await {
            if let crate::wizard_bootstrap::BootstrapEvent::Error { phase, message } = ev {
                err = Some(format!("{phase}: {message}"));
            }
        }
        if let Some(e) = err {
            failed.push(format!("{sid}: {e}"));
        }
    }

    if failed.is_empty() {
        tracing::info!(
            target = "vpnctld::boosty",
            users = ?user_ids,
            servers = ?server_ids,
            trigger,
            "boosty autodeploy applied (configs re-rendered + reloaded)"
        );
    } else {
        tracing::warn!(
            target = "vpnctld::boosty",
            users = ?user_ids,
            failed = ?failed,
            trigger,
            "boosty autodeploy: some servers failed — retry via Deploy all"
        );
    }
    if let Err(e) = inv
        .audit(
            "boosty-bridge",
            "boosty.autodeploy",
            None,
            Some(&serde_json::json!({
                "trigger": trigger,
                "users": user_ids,
                "servers": server_ids,
                "ok": failed.is_empty(),
                "failed": failed,
            })),
        )
        .await
    {
        tracing::warn!(target = "vpnctld::boosty", error = %e, "audit boosty.autodeploy failed");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// A disabled bridge (the default seeded state) makes `run_tick` a
    /// safe no-op — no network, no writes, no panic.
    #[tokio::test]
    async fn run_tick_is_noop_when_disabled() {
        let tmp = tempfile::tempdir().unwrap();
        let inv = SqliteInventory::open(&tmp.path().join("inv.db"))
            .await
            .unwrap();
        let registry = Arc::new(crate::app::build_registry().unwrap());
        // Default settings: enabled = false.
        run_tick(&inv, &registry, Path::new("/nonexistent-key")).await;
        // Nothing to assert beyond "did not panic / hang"; the bridge is
        // off so no Boosty call was attempted.
    }

    /// AC-D1: a failed pass fires ONE dedup'd warning alert; a second
    /// failure while it's open adds nothing; a successful pass silently
    /// acks it; the next failure after recovery opens a NEW alert.
    #[tokio::test]
    async fn sync_failure_alert_dedups_and_recovers() {
        let tmp = tempfile::tempdir().unwrap();
        let inv = SqliteInventory::open(&tmp.path().join("inv.db"))
            .await
            .unwrap();
        let err = vpnctl_boosty_bridge::BridgeError::Config("x".into());

        note_sync_failure(&inv, &err).await;
        note_sync_failure(&inv, &err).await;
        assert_eq!(
            inv.unacked_alert_count().await.unwrap(),
            1,
            "dedup while open"
        );

        note_sync_recovery(&inv).await;
        assert_eq!(
            inv.unacked_alert_count().await.unwrap(),
            0,
            "recovery auto-acks"
        );

        note_sync_failure(&inv, &err).await;
        assert_eq!(
            inv.unacked_alert_count().await.unwrap(),
            1,
            "re-fires after recovery"
        );
    }

    /// Flipped users with no grants (or unknown ids) deploy nothing and
    /// write no audit row — the batch is a clean no-op, not an error.
    #[tokio::test]
    async fn deploy_flipped_users_without_grants_is_noop() {
        let tmp = tempfile::tempdir().unwrap();
        let inv = SqliteInventory::open(&tmp.path().join("inv.db"))
            .await
            .unwrap();
        let registry = Arc::new(crate::app::build_registry().unwrap());
        deploy_flipped_users(
            &inv,
            &registry,
            Path::new("/nonexistent-key"),
            &["ghost".to_string()],
            "test",
        )
        .await;
        let audits = inv.recent_audit(10).await.unwrap();
        assert!(
            audits.iter().all(|a| a.action != "boosty.autodeploy"),
            "no servers -> no autodeploy audit row"
        );
    }
}
