use std::collections::HashMap;

use vpnctl_core::{ServerId, UserId};
use vpnctl_inventory::{SqliteInventory, VpnStatsDelta};

fn is_real_client_ip(
    ip: &str,
    known_server_addrs: &std::collections::HashSet<std::net::IpAddr>,
) -> bool {
    crate::ip_kind::classify_ip(ip) == crate::ip_kind::IpKind::Public
        && !vpnctl_inventory::sqlite::OUR_EGRESS_CONTROL_IPS.contains(&ip)
        && ip
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| !known_server_addrs.contains(&ip))
}

pub(crate) const DEFAULT_INTERVAL_SECS: u64 = 5 * 60;

pub(crate) fn poll_interval_secs() -> u64 {
    crate::config::parse_positive_secs("VPNCTLD_POLL_INTERVAL_SECS", DEFAULT_INTERVAL_SECS)
}

pub fn spawn_clash_poller(
    inv: SqliteInventory,
    snapshot_cache: crate::snapshot_cache::SnapshotCache,
) -> tokio::task::JoinHandle<()> {
    use std::time::Duration;
    use tokio::time::{MissedTickBehavior, interval};

    let interval_secs = poll_interval_secs();

    tokio::spawn(async move {
        let mut tick = interval(Duration::from_secs(interval_secs));
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        tick.tick().await;
        let mut tracked_servers = std::collections::HashSet::<ServerId>::new();

        loop {
            tick.tick().await;
            let servers = match inv.list_fleet_servers().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(
                        target = "vpnctld::poller",
                        error = %e,
                        "list_servers failed; skipping tick"
                    );
                    continue;
                }
            };
            let alive: std::collections::HashSet<ServerId> =
                servers.iter().map(|server| server.id.clone()).collect();
            for id in tracked_servers.difference(&alive) {
                tracing::debug!(
                    target = "vpnctld::poller",
                    server = %id.0,
                    "forgetting server (removed from inventory)"
                );
                snapshot_cache.forget(id);
            }
            tracked_servers = alive;

            let known_server_addrs = match inv.refresh_server_resolved_addresses().await {
                Ok(addresses) => addresses,
                Err(e) => {
                    tracing::warn!(
                        target = "vpnctld::poller",
                        error = %e,
                        "server address resolution failed; using cached addresses"
                    );
                    inv.known_server_ips().await.unwrap_or_default()
                }
            };

            for server in &servers {
                poll_one_server(&inv, &snapshot_cache, server, &known_server_addrs).await;
            }
        }
    })
}

async fn poll_one_server(
    inv: &SqliteInventory,
    snapshot_cache: &crate::snapshot_cache::SnapshotCache,
    server: &vpnctl_core::Server,
    known_server_addrs: &std::collections::HashSet<std::net::IpAddr>,
) {
    if !server.kernels.iter().any(|k| k.0 == "sing-box") {
        tracing::debug!(
            target = "vpnctld::poller",
            server = %server.id.0,
            "skipping (no sing-box kernel)"
        );
        return;
    }

    let key_path = crate::app::deploy_key_path();
    if !key_path.exists() {
        tracing::info!(
            target = "vpnctld::poller",
            server = %server.id.0,
            key = %key_path.display(),
            "skipping: deploy SSH key not yet on the control host"
        );
        return;
    }

    let jump = match inv.resolve_jump_host(server).await {
        Ok(j) => j,
        Err(e) => {
            tracing::warn!(
                target = "vpnctld::poller",
                server = %server.id.0,
                "jump host resolution failed: {e}"
            );
            return;
        }
    };

    let ssh = crate::ssh_subprocess::SubprocessSshTransport::new(
        server.address.clone(),
        server.ssh_user.clone(),
        key_path,
    )
    .port(server.ssh_port)
    .trusted_fingerprint(server.trusted_host_fingerprint.clone())
    .with_jump(jump);

    use crate::clash_api::{ClashClient, SshClashClient};
    let client = SshClashClient::new(&ssh);
    let snapshot = match client.snapshot().await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                target = "vpnctld::poller",
                server = %server.id.0,
                error = %e,
                "clash-api snapshot failed"
            );
            return;
        }
    };

    snapshot_cache.store(server.id.clone(), snapshot.clone());

    let mut dest_dedup: std::collections::HashSet<(String, String)> =
        std::collections::HashSet::new();
    let mut ip_dedup: std::collections::HashSet<(String, String)> =
        std::collections::HashSet::new();
    for c in &snapshot.connections {
        let Some(user_id) = c.metadata.user.as_deref() else {
            continue;
        };
        if !c.metadata.source_ip.is_empty() {
            ip_dedup.insert((user_id.to_string(), c.metadata.source_ip.clone()));
        }
        let label = if !c.metadata.host.is_empty() {
            if c.metadata.destination_port.is_empty() {
                c.metadata.host.clone()
            } else {
                format!("{}:{}", c.metadata.host, c.metadata.destination_port)
            }
        } else if !c.metadata.destination_ip.is_empty() {
            if c.metadata.destination_port.is_empty() {
                c.metadata.destination_ip.clone()
            } else {
                format!(
                    "{}:{}",
                    c.metadata.destination_ip, c.metadata.destination_port
                )
            }
        } else {
            continue;
        };
        dest_dedup.insert((user_id.to_string(), label));
    }
    let dest_pairs: Vec<(vpnctl_core::UserId, String)> = dest_dedup
        .into_iter()
        .map(|(u, l)| (vpnctl_core::UserId(u), l))
        .collect();
    let source_ip_pairs: Vec<(vpnctl_core::UserId, String)> = ip_dedup
        .into_iter()
        .map(|(u, ip)| (vpnctl_core::UserId(u), ip))
        .collect();
    if !dest_pairs.is_empty() {
        if let Err(e) = inv.record_user_destinations(&dest_pairs).await {
            tracing::warn!(
                target = "vpnctld::poller",
                server = %server.id.0,
                error = %e,
                "record_user_destinations failed (will retry next tick)"
            );
        }
    }
    if !source_ip_pairs.is_empty() {
        if let Err(e) = inv.record_user_source_ips(&source_ip_pairs).await {
            tracing::warn!(
                target = "vpnctld::poller",
                server = %server.id.0,
                error = %e,
                "record_user_source_ips failed (will retry next tick)"
            );
        }
    }

    {
        let mut per_user_nets: HashMap<String, std::collections::HashSet<String>> = HashMap::new();
        for (u, ip) in &source_ip_pairs {
            if is_real_client_ip(ip, known_server_addrs) {
                per_user_nets
                    .entry(u.0.clone())
                    .or_default()
                    .insert(vpnctl_inventory::sqlite::network_key(ip));
            }
        }
        let peaks: Vec<(vpnctl_core::UserId, u32)> = per_user_nets
            .into_iter()
            .map(|(u, nets)| (vpnctl_core::UserId(u), nets.len() as u32))
            .collect();
        if !peaks.is_empty() {
            if let Err(e) = inv.record_user_ip_concurrency(&peaks).await {
                tracing::warn!(
                    target = "vpnctld::poller",
                    server = %server.id.0,
                    error = %e,
                    "record_user_ip_concurrency failed (will retry next tick)"
                );
            }
        }
    }

    const SESSION_GAP_MINS: i64 = 15;
    use std::collections::HashMap as StdMap;
    let mut per_user_conn_count: StdMap<String, u32> = StdMap::new();
    for c in &snapshot.connections {
        if let Some(u) = c.metadata.user.as_deref() {
            *per_user_conn_count.entry(u.to_string()).or_insert(0) += 1;
        }
    }
    let now_utc = chrono::Utc::now();
    for (user_str, conn_count) in &per_user_conn_count {
        if let Err(e) = inv
            .session_observe(
                &vpnctl_core::UserId(user_str.clone()),
                &server.id,
                now_utc,
                SESSION_GAP_MINS,
                0,
                *conn_count,
            )
            .await
        {
            tracing::warn!(
                target = "vpnctld::poller",
                server = %server.id.0,
                user = %user_str,
                error = %e,
                "session_observe failed (session timeline may have a gap)"
            );
        }
    }

    use crate::singbox_stats::{SshStatsClient, StatsClient};
    let cumulative = match SshStatsClient::new(&ssh).cumulative_snapshot().await {
        Ok(snapshot) => snapshot,
        Err(error) => {
            tracing::warn!(
                target = "vpnctld::poller",
                server = %server.id.0,
                error = %error,
                "cumulative sing-box stats failed; baselines unchanged"
            );
            return;
        }
    };
    let tick = vpnctl_inventory::VpnCumulativeTick {
        server_upload_total: cumulative.server_upload_total,
        server_download_total: cumulative.server_download_total,
        uptime_seconds: cumulative.uptime_seconds,
        active_connections: u32::try_from(snapshot.connections.len()).unwrap_or(u32::MAX),
        users: cumulative.users,
    };
    let rows = match inv.record_vpn_cumulative_stats(&server.id, &tick).await {
        Ok(rows) => rows,
        Err(error) => {
            tracing::warn!(
                target = "vpnctld::poller",
                server = %server.id.0,
                error = %error,
                "record_vpn_cumulative_stats failed; baselines unchanged"
            );
            return;
        }
    };
    if rows == 0 {
        tracing::debug!(
            target = "vpnctld::poller",
            server = %server.id.0,
            "cumulative baselines seeded or quiet tick"
        );
    } else {
        tracing::info!(
            target = "vpnctld::poller",
            server = %server.id.0,
            delta_rows = rows,
            "persisted cumulative sing-box delta"
        );
    }

    let mut live_rows = Vec::with_capacity(per_user_conn_count.len().saturating_add(1));
    if !snapshot.connections.is_empty() {
        live_rows.push(VpnStatsDelta {
            user_id: None,
            upload_bytes: 0,
            download_bytes: 0,
            active_connections: u32::try_from(snapshot.connections.len()).unwrap_or(u32::MAX),
        });
    }
    live_rows.extend(
        per_user_conn_count
            .into_iter()
            .map(|(user_id, active_connections)| VpnStatsDelta {
                user_id: Some(UserId(user_id)),
                upload_bytes: 0,
                download_bytes: 0,
                active_connections,
            }),
    );
    if let Err(error) = inv.record_vpn_stats(&server.id, &live_rows).await {
        tracing::warn!(
            target = "vpnctld::poller",
            server = %server.id.0,
            error = %error,
            "recording live Clash connection counts failed"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn is_real_client_ip_excludes_known_server_hops_control_and_private() {
        let known = [
            "104.194.156.93".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
        ]
        .into_iter()
        .collect();

        assert!(is_real_client_ip("8.8.8.8", &known));

        assert!(
            !is_real_client_ip("104.194.156.93", &known),
            "a registered server address must not count as a concurrent client"
        );
        assert!(!is_real_client_ip("2001:0db8:0:0::1", &known));

        assert!(!is_real_client_ip("83.97.108.34", &known));

        assert!(!is_real_client_ip("192.168.0.207", &known));
        assert!(!is_real_client_ip("127.0.0.1", &known));
    }
}
