//! sing-box telemetry poller.
//!
//! Clash API remains the live-connection/source/destination snapshot. Exact
//! per-user bytes come from the node-side cumulative V2Ray Stats helper; the
//! inventory layer persists server and user baselines atomically with interval
//! deltas, so daemon restarts and short-lived connections do not lose traffic.

use std::collections::HashMap;

use vpnctl_core::{ServerId, UserId};
use vpnctl_inventory::{SqliteInventory, VpnStatsDelta};

/// True when `ip` is a REAL external client for the purposes of the
/// per-snapshot sharing signal — the daemon-side mirror of the inventory's
/// SQL `real_client_ip_predicate`, so every signal agrees on «what is a real
/// client». Drops:
///   * non-public space (RFC 1918 / loopback / link-local) via
///     [`crate::ip_kind::classify_ip`],
///   * the hardcoded control egress(es) in
///     [`vpnctl_inventory::sqlite::OUR_EGRESS_CONTROL_IPS`],
///   * registered VPN server addresses (`known_server_addrs`) — a node hop or
///     full-tunnel egress. Without this last clause a VPN-over-VPN hop (user
///     on node A egressing through node B) shows node A's address as a second
///     «network» and becomes the strongest, rotation-immune sharing signal for
///     a single legitimate user. The SQL signals already exclude these via
///     `NOT IN (SELECT address FROM servers)`; this keeps the concurrency term
///     consistent with them.
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

/// Realistic homelab cadence: rapid enough that the UI feels live (5-min
/// sparkline buckets), slow enough that an idle node + idle homelab pull
/// ~12 polls/h × few hundred bytes. Configurable via env var
/// `VPNCTLD_POLL_INTERVAL_SECS` — useful for tests (short) or quiet seasons
/// (long). Module-level so the snapshot-cache staleness check can track
/// whatever cadence the poller actually runs at.
pub(crate) const DEFAULT_INTERVAL_SECS: u64 = 5 * 60;

/// The configured clash-api poll interval in seconds (env
/// `VPNCTLD_POLL_INTERVAL_SECS` or the 5-min default). Shared with the
/// snapshot cache so «stale» means «no successful poll for ~2 of whatever
/// interval the poller is on» rather than a hardcoded wall-clock guess.
pub(crate) fn poll_interval_secs() -> u64 {
    crate::config::parse_positive_secs("VPNCTLD_POLL_INTERVAL_SECS", DEFAULT_INTERVAL_SECS)
}

/// Daemon-side scheduler that pulls one Clash live snapshot and one
/// cumulative V2Ray Stats snapshot from each server every poll interval,
/// then commits the derived deltas through the inventory transaction.
///
/// Robustness contract:
///
/// * **Per-server failures are isolated.** SSH unreachable, no
///   deploy key, clash-api off, parser error — each one fails the
///   ONE server's tick and continues to the next. The poller never
///   crashes the daemon.
///
/// * **Missing SSH key is a WARN, not a panic.** Until the
///   operator copies `/var/lib/vpnctl/.ssh/id_ed25519` onto the
///   homelab host and authorises it on every VPN node, this
///   poller logs and skips. The user-detail empty-state already
///   tells the operator about this prerequisite.
///
/// * **Removed servers are forgotten.** The live snapshot cache is pruned
///   against the current inventory on every tick.
///
/// * **One tick per interval, sequentially per server.** Five
///   servers × 1 s of SSH each ≈ 5 s per tick. The default
///   `POLL_INTERVAL` of 5 min gives ~98% idle. If the homelab
///   grows past ~50 servers this needs parallelisation, but at
///   that scale we'd have many other things to revisit.
///
/// **No feature gate required** — uses
/// `crate::ssh_subprocess::SubprocessSshTransport` which shells out
/// to the system `/usr/bin/ssh` binary (bookworm-2.36-native, no
/// glibc-2.38 syscalls). Previously gated behind `polling`; the
/// gate was removed when Path C (subprocess wrapper) landed.
pub fn spawn_clash_poller(
    inv: SqliteInventory,
    snapshot_cache: crate::snapshot_cache::SnapshotCache,
) -> tokio::task::JoinHandle<()> {
    use std::time::Duration;
    use tokio::time::{MissedTickBehavior, interval};

    // `> 0` guard + warn-on-bad lives in `config::parse_positive_secs`:
    // `interval(Duration::from_secs(0))` panics → poller crash-loop. The
    // default + env knob live in `poll_interval_secs` (shared with the
    // snapshot-cache staleness check).
    let interval_secs = poll_interval_secs();

    tokio::spawn(async move {
        let mut tick = interval(Duration::from_secs(interval_secs));
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        // Skip the first immediate tick — daemon startup is hot,
        // and the operator typically wants 5 min of grace.
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
            // Forget cached snapshots for servers removed from inventory.
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

            // Registered server addresses, so the per-snapshot sharing
            // signal can drop VPN-over-VPN hops — the same `NOT IN
            // (SELECT address FROM servers)` semantics the SQL-side
            // `real_client_ip_predicate` applies to every other signal.
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

/// One-server tick. Pure side-effect, never panics — every error
/// is logged at warn-or-info and swallowed. `known_server_addrs` is the
/// set of registered server addresses this tick, used to keep VPN-over-VPN
/// hops out of the per-snapshot sharing signal (see [`is_real_client_ip`]).
async fn poll_one_server(
    inv: &SqliteInventory,
    snapshot_cache: &crate::snapshot_cache::SnapshotCache,
    server: &vpnctl_core::Server,
    known_server_addrs: &std::collections::HashSet<std::net::IpAddr>,
) {
    // Only sing-box nodes expose clash-api at 9090. AmneziaWG nodes are
    // skipped here — their per-user source IPs are collected separately by
    // `crate::wg_stats_poller` (`awg show awg0 dump` → user via
    // `wireguard_pubkey`), which feeds the sharing verdict's daily-networks
    // term. That poller is the "amneziawg metrics from wg show" path this
    // comment used to defer.
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
        // Pre-deploy: SSH key not yet provisioned on the homelab
        // host. Log once at info per tick per server so the
        // operator can grep for it; don't spam at warn.
        tracing::info!(
            target = "vpnctld::poller",
            server = %server.id.0,
            key = %key_path.display(),
            "skipping: deploy SSH key not yet on the homelab host"
        );
        return;
    }

    // Subprocess SSH (Path C) — wraps the system `/usr/bin/ssh`,
    // no russh, no glibc-2.38 dep. Built per-server per-tick (cheap;
    // each tick is one process spawn for one `curl` against
    // clash-api). Future optimisation: ssh ControlMaster session
    // multiplexing if poll cadence drops below ~30 s. For 5-min
    // ticks this is overkill.
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

    // Cache the snapshot for the «Live connections» drill-down. The managed
    // Clash patch preserves `metadata.user` for live/session/source/destination
    // views; exact bytes are ingested from cumulative V2Ray Stats below. No
    // log scraping or active-connection snapshot is used for byte accounting.
    snapshot_cache.store(server.id.clone(), snapshot.clone());

    // Phase 5b — record «куда ходит» (destination) AND «откуда
    // подключается» (source IP) pairs for this tick (one per resolved
    // (user_id, X) seen). Dedupe at tick level: ONE hit per (user, X)
    // regardless of how many connections share the pair, since both
    // tables are hit-COUNT-per-tick, not connection-count. Built in
    // one pass over the snapshot — the user resolution is shared.
    let mut dest_dedup: std::collections::HashSet<(String, String)> =
        std::collections::HashSet::new();
    let mut ip_dedup: std::collections::HashSet<(String, String)> =
        std::collections::HashSet::new();
    for c in &snapshot.connections {
        let Some(user_id) = c.metadata.user.as_deref() else {
            continue;
        };
        // Source IP — recorded independently of whether the
        // destination resolved: an attributed connection always has a
        // client IP worth classifying. Empty source IPs are dropped
        // (nothing to geo-locate / classify).
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

    // Sharing-signal foundation (2026-06-17): the count of DISTINCT public
    // source IPs a user has IN THIS SNAPSHOT is, by construction, how many
    // separate clients are connected to this node at the same instant — the
    // single strongest "shared subscription" signal (industry: simultaneity
    // beats cumulative ASN-over-30d). `source_ip_pairs` is already the
    // deduped (user, ip) set for this snapshot, so a per-user count == the
    // user's distinct-IP count right now. Infra / private / control IPs are
    // excluded (never a real concurrent client). Persist the DAILY PEAK.
    {
        // Count distinct ISP-scale access NETWORKS, not raw IPs — a single
        // mobile device rotates across adjacent carrier subnets, so raw-IP
        // or /24 counting would fake concurrency. `network_key` uses /16 for
        // IPv4 and /64 for IPv6.
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

    // Phase 5c — session observation: per (resolved user, this
    // server), advance or open a session window. SESSION_GAP_MINS
    // matches the 15-min budget; a 5-min poll cadence means we
    // tolerate ONE missed tick before considering the session
    // ended. Active connection count = how many of THIS user's
    // connections are alive in the snapshot.
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
                // Cumulative inventory ingest handles byte budgets;
                // sessions track only «была активна» windows.
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

    // Preserve Clash's live per-user connection counts without using its
    // snapshot bytes for accounting. Zero-byte rows cannot double-count the
    // cumulative ingest and remain useful to existing user activity views.
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

    /// Issue 3 — the concurrency/sharing filter must drop registered server
    /// addresses (a VPN-over-VPN hop) exactly like the SQL-side signals do,
    /// alongside the control egress and non-public space. Otherwise a single
    /// user egressing node A→B shows node A as a second «network» and trips
    /// the dominant, rotation-immune sharing signal on their own.
    #[test]
    fn is_real_client_ip_excludes_known_server_hops_control_and_private() {
        // Two registered VPN server addresses.
        let known = [
            "104.194.156.93".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
        ]
        .into_iter()
        .collect();

        // A genuine remote client passes.
        assert!(is_real_client_ip("8.8.8.8", &known));

        // A VPN-over-VPN hop (another registered node's address) is NOT a
        // real client — this is the regression the fix targets.
        assert!(
            !is_real_client_ip("104.194.156.93", &known),
            "a registered server address must not count as a concurrent client"
        );
        assert!(!is_real_client_ip("2001:0db8:0:0::1", &known));

        // The hardcoded control egress stays excluded.
        assert!(!is_real_client_ip("83.97.108.34", &known));

        // Non-public space stays excluded.
        assert!(!is_real_client_ip("192.168.0.207", &known));
        assert!(!is_real_client_ip("127.0.0.1", &known));
    }
}
