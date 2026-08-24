use std::time::Duration;

use vpnctl_inventory::SqliteInventory;

use super::{FailState, dispatch_alerts, probe_one_server_with_registry};

/// Realistic homelab cadence for telemetry. Slower than clash-api
/// (5 min) because node probe is "is the service alive + disk OK"
/// rather than "what's happening NOW with user traffic" — 10 min
/// is fine, halves SSH overhead vs co-cadence with clash.
///
/// Override via env `VPNCTLD_NODE_PROBE_INTERVAL_SECS`. Tests use
/// short intervals to validate the loop; production sticks with
/// the default.
const DEFAULT_INTERVAL_SECS: u64 = 10 * 60;

/// Spawn the node-probe poller. Returns the [`tokio::task::JoinHandle`]
/// so production (which discards) and tests (which assert spawn)
/// have the same interface, matching [`crate::clash_poller::spawn_clash_poller`].
///
/// **No feature gate required** — uses
/// [`crate::ssh_subprocess::SubprocessSshTransport`] which shells out
/// to the system `/usr/bin/ssh` binary (no glibc-2.38 hazard).
pub fn spawn_node_probe_poller(inv: SqliteInventory) -> tokio::task::JoinHandle<()> {
    use tokio::time::{MissedTickBehavior, interval};

    // `> 0` guard + warn-on-bad lives in `config::parse_positive_secs`:
    // `interval(Duration::from_secs(0))` panics → poller crash-loop.
    let interval_secs = crate::config::parse_positive_secs(
        "VPNCTLD_NODE_PROBE_INTERVAL_SECS",
        DEFAULT_INTERVAL_SECS,
    );

    tokio::spawn(async move {
        let registry = match crate::app::build_registry() {
            Ok(registry) => registry,
            Err(e) => {
                tracing::error!(
                    target = "vpnctld::node_probe",
                    error = %e,
                    "canonical registry failed to build; node probe poller stopped"
                );
                return;
            }
        };
        let mut tick = interval(Duration::from_secs(interval_secs));
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        // Drop the immediate first fire — daemon startup is hot;
        // gives the operator a grace period before the first probe.
        tick.tick().await;

        let mut fail_state = FailState::new();

        loop {
            tick.tick().await;
            let servers = match inv.list_servers().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(
                        target = "vpnctld::node_probe",
                        error = %e,
                        "list_servers failed; skipping tick"
                    );
                    continue;
                }
            };
            // Prune FailState entries for ids no longer in inventory
            // BEFORE iterating. Catches the «delete + re-add same id»
            // case where stale fired=true would suppress the next
            // BecameUnreachable. Bug-hunt agent finding 2026-05-18.
            let live_ids: std::collections::HashSet<vpnctl_core::ServerId> =
                servers.iter().map(|s| s.id.clone()).collect();
            fail_state.prune(&live_ids);

            for server in &servers {
                let outcome = probe_one_server_with_registry(&inv, &registry, server).await;
                dispatch_alerts(&inv, server, &outcome, &mut fail_state).await;
            }
        }
    })
}

/// Convenience: cumulative "expire" pass over `node_health` rows
/// older than `days`. Wired into the existing retention scheduler in
/// `daemon::app::spawn_retention_purger`. Pure delegate; lives here
/// rather than inline in `app.rs` so the whole node-probe surface
/// (probe + poller + purge) stays in one place.
///
/// Returns the inventory crate's own `Result` so callers don't have
/// to import `sqlx` directly (vpnctld doesn't pull sqlx as a direct
/// dep — only the inventory crate does).
pub async fn purge_old(
    inv: &SqliteInventory,
    days: u32,
) -> std::result::Result<u64, vpnctl_inventory::SqliteInventoryError> {
    inv.purge_node_health_older_than(days).await
}
