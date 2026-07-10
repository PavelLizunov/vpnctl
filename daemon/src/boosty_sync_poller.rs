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
//! Structurally the same shape as [`crate::node_probe_poller`]: spawn a
//! tokio task, drop the immediate first fire, tick, do one bounded unit of
//! work, never panic. The per-tick logic ([`run_tick`]) is a free function
//! so it can be driven directly in a test without the interval clock.

use std::time::Duration;

use vpnctl_boosty_bridge::{ApplyMode, sync_from_settings};
use vpnctl_inventory::SqliteInventory;

/// Fallback cadence when settings carry no positive interval.
const DEFAULT_INTERVAL_SECS: u64 = 3600;

/// Spawn the Boosty sync poller. Returns the handle so production (which
/// discards) and tests share one interface, matching the other pollers.
pub fn spawn_boosty_sync_poller(inv: SqliteInventory) -> tokio::task::JoinHandle<()> {
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
            run_tick(&inv).await;
        }
    })
}

/// One reconciliation tick. No-op (fast) when the bridge is disabled.
/// Never panics — every error is logged and swallowed so the loop
/// survives a transient Boosty outage or a bad token.
pub async fn run_tick(inv: &SqliteInventory) {
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
            tracing::info!(
                target = "vpnctld::boosty",
                enabled = report.enabled.len(),
                disabled = report.disabled.len(),
                lapsed_pending = report.lapsed_pending.len(),
                new_subscribers = report.new_subscribers.len(),
                errors = report.errors.len(),
                "boosty sync tick"
            );
            for e in &report.errors {
                tracing::warn!(target = "vpnctld::boosty", error = %e, "sync action failed");
            }
        }
        Err(e) => tracing::warn!(
            target = "vpnctld::boosty",
            error = %e,
            "boosty sync failed"
        ),
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
        // Default settings: enabled = false.
        run_tick(&inv).await;
        // Nothing to assert beyond "did not panic / hang"; the bridge is
        // off so no Boosty call was attempted.
    }
}
