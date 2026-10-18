use std::time::Duration;

use vpnctl_inventory::SqliteInventory;

use super::{FailState, dispatch_alerts, probe_one_server_with_registry};

const DEFAULT_INTERVAL_SECS: u64 = 10 * 60;

pub fn spawn_node_probe_poller(inv: SqliteInventory) -> tokio::task::JoinHandle<()> {
    use tokio::time::{MissedTickBehavior, interval};

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

pub async fn purge_old(
    inv: &SqliteInventory,
    days: u32,
) -> std::result::Result<u64, vpnctl_inventory::SqliteInventoryError> {
    inv.purge_node_health_older_than(days).await
}
