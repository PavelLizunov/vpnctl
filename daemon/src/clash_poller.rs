//! Track-3 chunk 2 — clash-api poller diff engine.
//!
//! Sits between `crate::clash_api::SshClashClient` (chunk 1) and
//! `vpnctl_inventory::SqliteInventory::record_vpn_stats` (chunk 2 SQL
//! side). Per server, it remembers the previous snapshot's totals; on
//! every new snapshot it computes the delta-vs-prior and emits one
//! `VpnStatsDelta` per active user plus one server-wide row.
//!
//! # Restart semantics
//!
//! sing-box's clash-api totals reset to 0 every time the daemon
//! restarts on the VPN node. Without restart detection, the next
//! delta would be `current - large_prior = negative`, which would
//! render as "billions of bytes" if we cast naively. The diff engine
//! detects a restart by comparing the new total against the prior:
//! if the new total is STRICTLY LESS than the prior, treat the new
//! total itself as the delta (i.e. "everything since the restart").
//!
//! # First snapshot
//!
//! On the very first snapshot from a server we have no prior to
//! diff against. We initialize the prior totals and emit NO rows
//! (a delta requires two samples). The poller will emit its first
//! row on the SECOND tick.
//!
//! # Quiet ticks
//!
//! Ticks where every (user, total) pair didn't move emit zero rows
//! — quiet nodes don't bloat the table. The poller's `tick` method
//! returns the rows it WOULD write; the caller decides whether to
//! call `record_vpn_stats` (skip if empty).

use std::collections::HashMap;

use vpnctl_core::{ServerId, UserId};
use vpnctl_inventory::{SqliteInventory, VpnStatsDelta};

use crate::clash_api::Snapshot;

/// Per-server cumulative-totals memory. The diff engine keeps one
/// per known server.
#[derive(Debug, Default, Clone)]
struct ServerTotals {
    /// Server-wide bytes since the last sing-box restart.
    server_upload: u64,
    server_download: u64,
    /// Per-user lifetime bytes since the last restart. Drops users
    /// that disappear from the snapshot (their connections closed)
    /// — the next reappearance is treated as a fresh start.
    per_user: HashMap<String, (u64, u64)>,
}

/// Stateful diff engine. One instance per `vpnctld` process; the
/// poller calls `tick(server_id, snapshot)` once per server per
/// poll interval.
#[derive(Debug, Default)]
pub struct DiffEngine {
    state: HashMap<ServerId, ServerTotals>,
}

impl DiffEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Process one snapshot. Returns the deltas the caller should
    /// persist. Empty Vec means either:
    ///  * first snapshot for this server (state seeded, nothing to
    ///    diff against), OR
    ///  * a quiet tick (totals didn't move).
    ///
    /// In both cases the poller should NOT call `record_vpn_stats`
    /// on an empty Vec — the inventory layer treats empty as a no-op
    /// but the audit/log noise is unnecessary.
    ///
    /// Phase 4e — `attribution` is a `(source_ip, source_port) →
    /// user_id` map derived from sing-box log scraping. We use it
    /// as the user resolver when `metadata.user` is None (which is
    /// always the case in production due to NM-11 — sing-box's
    /// clash-api drops the field). Empty map → no per-user
    /// attribution this tick (server-wide row still lands).
    pub fn tick(
        &mut self,
        server_id: &ServerId,
        snapshot: &Snapshot,
        attribution: &crate::sing_box_log_scraper::AttributionMap,
    ) -> Vec<VpnStatsDelta> {
        let prior = self.state.get(server_id).cloned();
        // Build new state from this snapshot. Resolve user_id
        // per-connection: first try metadata.user (works on
        // patched sing-box builds where NM-11 is fixed), then
        // fall back to the log-derived attribution map (works on
        // upstream-stock sing-box). Connections that resolve to
        // None are still credited to the server-wide row but NOT
        // to any user.
        let mut new_per_user: HashMap<String, (u64, u64)> = HashMap::new();
        for c in &snapshot.connections {
            let user_resolved: Option<&str> = c.metadata.user.as_deref().or_else(|| {
                attribution
                    .get(&(c.metadata.source_ip.clone(), c.metadata.source_port.clone()))
                    .map(|s| s.as_str())
            });
            if let Some(u) = user_resolved {
                let entry = new_per_user.entry(u.to_string()).or_default();
                entry.0 = entry.0.saturating_add(c.upload);
                entry.1 = entry.1.saturating_add(c.download);
            }
        }
        let new_totals = ServerTotals {
            server_upload: snapshot.upload_total,
            server_download: snapshot.download_total,
            per_user: new_per_user,
        };

        // First snapshot ever for this server → seed and bail.
        let Some(prior) = prior else {
            self.state.insert(server_id.clone(), new_totals);
            return Vec::new();
        };

        let mut deltas: Vec<VpnStatsDelta> = Vec::new();

        // Server-wide row. Restart detection: a strictly-smaller
        // total means sing-box restarted; treat the new total as
        // the delta.
        let server_up_d = delta(prior.server_upload, new_totals.server_upload);
        let server_dn_d = delta(prior.server_download, new_totals.server_download);
        let server_active = u32::try_from(snapshot.connections.len()).unwrap_or(u32::MAX);
        if server_up_d > 0 || server_dn_d > 0 || server_active > 0 {
            deltas.push(VpnStatsDelta {
                user_id: None,
                upload_bytes: server_up_d,
                download_bytes: server_dn_d,
                active_connections: server_active,
            });
        }

        // Per-user rows. For each user in the new snapshot:
        //   * If prior had them → emit `new.saturating_sub(prior)` —
        //     i.e. 0 when the new sum is LESS than the prior sum.
        //     This is conservative on purpose: per-user totals ARE
        //     a sum across currently-active connections, so a
        //     legitimate "one connection closed, another opened
        //     smaller" scenario would (with a per-user restart
        //     heuristic) DOUBLE-COUNT — the closed connection's
        //     bytes were already credited on a prior tick, AND the
        //     new sum would get credited again as a "fresh start".
        //     Better to under-attribute on a connection-cycle than
        //     to lie. Real sing-box restarts are caught at the
        //     server-wide level above; per-user attribution simply
        //     resumes from the new baseline on the next tick.
        //     (Caught by review-agent on the burst review of
        //     cd61838^..492fdeb.)
        //   * If prior didn't have them → this is a NEW user this
        //     tick; emit the new totals as the delta (their session
        //     started since the prior tick).
        for (user, &(new_up, new_dn)) in &new_totals.per_user {
            let (up_d, dn_d) = match prior.per_user.get(user) {
                Some(&(p_up, p_dn)) => (new_up.saturating_sub(p_up), new_dn.saturating_sub(p_dn)),
                None => (new_up, new_dn),
            };
            // Phase 4e — count active conns using the SAME resolver
            // we used to accumulate bytes above; otherwise the
            // (bytes, active) pair for one user could disagree
            // (bytes from attribution map, active from metadata.user
            // which is always None on stock sing-box).
            let active = u32::try_from(
                snapshot
                    .connections
                    .iter()
                    .filter(|c| {
                        let r = c.metadata.user.as_deref().or_else(|| {
                            attribution
                                .get(&(
                                    c.metadata.source_ip.clone(),
                                    c.metadata.source_port.clone(),
                                ))
                                .map(|s| s.as_str())
                        });
                        r == Some(user.as_str())
                    })
                    .count(),
            )
            .unwrap_or(u32::MAX);
            if up_d > 0 || dn_d > 0 || active > 0 {
                deltas.push(VpnStatsDelta {
                    user_id: Some(UserId(user.clone())),
                    upload_bytes: up_d,
                    download_bytes: dn_d,
                    active_connections: active,
                });
            }
        }

        // Update state for the next tick.
        self.state.insert(server_id.clone(), new_totals);
        deltas
    }

    /// Drop one server's tracked totals.
    ///
    /// **Call-site contract for chunk 4 (poller wiring):** after
    /// every `inv.list_servers()` pass, the poller MUST call
    /// `forget(&id)` for any `ServerId` that was previously tracked
    /// but is no longer in the inventory result. Without this, the
    /// in-memory `state` map grows monotonically as servers are
    /// removed from inventory — slow leak in a long-running daemon.
    /// (Caught by review-agent on the burst review of
    /// cd61838^..492fdeb; pinned here so chunk 4 can't forget.)
    pub fn forget(&mut self, server_id: &ServerId) {
        self.state.remove(server_id);
    }

    /// Test-only: how many servers we're tracking.
    #[cfg(test)]
    fn tracked_servers(&self) -> usize {
        self.state.len()
    }
}

/// Compute `new - prior`, treating `new < prior` as a restart
/// (return `new` itself — the new total is the delta from zero).
fn delta(prior: u64, new: u64) -> u64 {
    if new < prior { new } else { new - prior }
}

/// Phase Track-3 chunk 4 — daemon-side scheduler that pulls one
/// clash-api snapshot from each server every `POLL_INTERVAL` and
/// records the diff. The "engine" half (DiffEngine) lives above;
/// this is the runtime wiring.
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
/// * **DiffEngine gets `forget()` for removed servers.** Per the
///   contract pinned in `DiffEngine::forget` — without this the
///   in-memory state grows monotonically.
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

    /// Realistic homelab cadence: rapid enough that the UI feels
    /// live (5-min sparkline buckets), slow enough that an idle
    /// node + idle homelab pull ~12 polls/h × few hundred bytes.
    /// Configurable via env var `VPNCTLD_POLL_INTERVAL_SECS` —
    /// useful for tests (short) or quiet seasons (long).
    const DEFAULT_INTERVAL_SECS: u64 = 5 * 60;
    let interval_secs: u64 = std::env::var("VPNCTLD_POLL_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_INTERVAL_SECS);

    tokio::spawn(async move {
        let mut tick = interval(Duration::from_secs(interval_secs));
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        // Skip the first immediate tick — daemon startup is hot,
        // and the operator typically wants 5 min of grace.
        tick.tick().await;
        let mut engine = DiffEngine::new();

        loop {
            tick.tick().await;
            let servers = match inv.list_servers().await {
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
            // forget() any server that vanished from inventory
            // since last tick (DiffEngine leak guard).
            let alive: std::collections::HashSet<ServerId> =
                servers.iter().map(|s| s.id.clone()).collect();
            let tracked: Vec<ServerId> = engine
                .state
                .keys()
                .filter(|k| !alive.contains(k))
                .cloned()
                .collect();
            for id in tracked {
                tracing::debug!(
                    target = "vpnctld::poller",
                    server = %id.0,
                    "forgetting server (removed from inventory)"
                );
                engine.forget(&id);
                // Mirror the leak guard for the cache's persistent
                // attribution accumulator + last snapshot.
                snapshot_cache.forget(&id);
            }

            for server in &servers {
                poll_one_server(&inv, &mut engine, &snapshot_cache, server).await;
            }
        }
    })
}

/// One-server tick. Pure side-effect, never panics — every error
/// is logged at warn-or-info and swallowed.
async fn poll_one_server(
    inv: &SqliteInventory,
    engine: &mut DiffEngine,
    snapshot_cache: &crate::snapshot_cache::SnapshotCache,
    server: &vpnctl_core::Server,
) {
    // Only sing-box nodes expose clash-api at 9090 today. AmneziaWG
    // nodes are skipped silently — operator's amnezia-only servers
    // don't generate stats yet (queued for a future "amneziawg
    // metrics from wg show" path).
    if !server.kernels.iter().any(|k| k.0 == "sing-box") {
        tracing::debug!(
            target = "vpnctld::poller",
            server = %server.id.0,
            "skipping (no sing-box kernel)"
        );
        return;
    }

    let key_path = std::env::var("VPNCTLD_DEPLOY_KEY")
        .unwrap_or_else(|_| "/var/lib/vpnctl/.ssh/id_ed25519".to_string());
    if !std::path::Path::new(&key_path).exists() {
        // Pre-deploy: SSH key not yet provisioned on the homelab
        // host. Log once at info per tick per server so the
        // operator can grep for it; don't spam at warn.
        tracing::info!(
            target = "vpnctld::poller",
            server = %server.id.0,
            key = %key_path,
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
    let ssh = crate::ssh_subprocess::SubprocessSshTransport::new(
        server.address.clone(),
        server.ssh_user.clone(),
        std::path::PathBuf::from(&key_path),
    )
    .port(server.ssh_port);

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

    // Phase 4d — scrape sing-box log to build the (source_ip,
    // port) → user_id attribution map. Best-effort: an SSH or
    // parse failure means we store an empty map (snapshot still
    // lands, UI falls back to sub_access correlation). NM-11
    // work-around — sing-box's wire-format omits the user field,
    // but the on-disk log has it. See sing_box_log_scraper docs.
    let log_path = crate::sing_box_log_scraper::resolve_log_path();
    let tail_n = crate::sing_box_log_scraper::resolve_tail_lines();
    let attribution = match crate::sing_box_log_scraper::scrape(&ssh, &log_path, tail_n).await {
        Ok(map) => map,
        Err(e) => {
            tracing::warn!(
                target = "vpnctld::poller",
                server = %server.id.0,
                error = %e,
                "sing-box log scrape failed (per-conn attribution will be empty this tick; sub_access fallback still applies)"
            );
            std::collections::HashMap::new()
        }
    };
    let scrape_hits = attribution.len();
    // Phase 4c + attribution-persist fix — store the full snapshot
    // (per-connection detail) + MERGE this tick's fresh scrape into
    // the persistent per-server attribution accumulator, then prune
    // it to the live connection set. `store_merged` does all three
    // atomically under the cache write lock and returns the merged+
    // pruned map for this tick's per-connection resolution.
    //
    // Why merge instead of replace: the scrape only sees the last
    // `tail -n N` lines (~12 min on a busy node). A long-lived
    // connection whose accept line has scrolled out of that window
    // is ABSENT from `attribution` this tick — but it's still in
    // clash-api's connection set, so an earlier tick's observation
    // (kept in the accumulator) keeps it attributed. Pruning to the
    // live set evicts closed connections so the map stays bounded
    // and a later port-reuse can't inherit a stale user. The merged
    // map is also what the «Live connections» drill-down reads.
    let attribution_for_tick =
        snapshot_cache.store_merged(server.id.clone(), snapshot.clone(), attribution);
    if scrape_hits > 0 || !attribution_for_tick.is_empty() {
        tracing::debug!(
            target = "vpnctld::poller",
            server = %server.id.0,
            scrape_entries = scrape_hits,
            merged_entries = attribution_for_tick.len(),
            "sing-box log scrape merged into persistent attribution"
        );
    }

    // Phase 5b — record «куда ходит этот юзер» pairs (one per
    // (resolved user_id, destination_label) seen in this tick).
    // Dedupe at tick level: ONE hit per (user, dest) regardless
    // of how many connections share the pair, since the table
    // is hit-COUNT-per-tick, not connection-count.
    let dest_pairs: Vec<(vpnctl_core::UserId, String)> = {
        let mut dedup: std::collections::HashSet<(String, String)> =
            std::collections::HashSet::new();
        for c in &snapshot.connections {
            let user = c.metadata.user.as_deref().or_else(|| {
                attribution_for_tick
                    .get(&(c.metadata.source_ip.clone(), c.metadata.source_port.clone()))
                    .map(|s| s.as_str())
            });
            if let Some(user_id) = user {
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
                dedup.insert((user_id.to_string(), label));
            }
        }
        dedup
            .into_iter()
            .map(|(u, l)| (vpnctl_core::UserId(u), l))
            .collect()
    };
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
        let user = c.metadata.user.as_deref().or_else(|| {
            attribution_for_tick
                .get(&(c.metadata.source_ip.clone(), c.metadata.source_port.clone()))
                .map(|s| s.as_str())
        });
        if let Some(u) = user {
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
                // bytes_delta = 0 here — the diff engine handles
                // bytes; sessions track «была активна» windows,
                // not byte budgets. If we want bytes per session
                // later, pipe the per-user delta through.
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

    let deltas = engine.tick(&server.id, &snapshot, &attribution_for_tick);
    if deltas.is_empty() {
        tracing::debug!(
            target = "vpnctld::poller",
            server = %server.id.0,
            "first snapshot or quiet tick — nothing to persist"
        );
        return;
    }

    if let Err(e) = inv.record_vpn_stats(&server.id, &deltas).await {
        tracing::warn!(
            target = "vpnctld::poller",
            server = %server.id.0,
            error = %e,
            "record_vpn_stats failed"
        );
        return;
    }
    tracing::info!(
        target = "vpnctld::poller",
        server = %server.id.0,
        delta_rows = deltas.len(),
        "persisted clash-api delta"
    );
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::clash_api::{Connection, ConnectionMeta};

    fn snap(server_up: u64, server_dn: u64, conns: Vec<(&str, u64, u64)>) -> Snapshot {
        Snapshot {
            upload_total: server_up,
            download_total: server_dn,
            connections: conns
                .into_iter()
                .enumerate()
                .map(|(i, (user, up, dn))| Connection {
                    id: format!("c{i}"),
                    upload: up,
                    download: dn,
                    start: "2026-05-15T20:30:00Z".into(),
                    metadata: ConnectionMeta {
                        network: "tcp".into(),
                        destination_ip: "1.2.3.4".into(),
                        destination_port: "443".into(),
                        source_ip: "10.0.0.1".into(),
                        source_port: "12345".into(),
                        host: String::new(),
                        user: Some(user.into()),
                    },
                })
                .collect(),
        }
    }

    fn sid(s: &str) -> ServerId {
        ServerId(s.into())
    }

    #[test]
    fn first_snapshot_emits_no_rows_just_seeds() {
        let mut e = DiffEngine::new();
        let s = snap(1024, 2048, vec![("alice", 100, 200)]);
        let out = e.tick(&sid("srv-1"), &s, &HashMap::new());
        assert!(out.is_empty(), "first snapshot must emit nothing");
        assert_eq!(e.tracked_servers(), 1);
    }

    #[test]
    fn second_snapshot_emits_per_server_and_per_user_deltas() {
        let mut e = DiffEngine::new();
        e.tick(
            &sid("srv-1"),
            &snap(1024, 2048, vec![("alice", 100, 200)]),
            &HashMap::new(),
        );
        let out = e.tick(
            &sid("srv-1"),
            &snap(1500, 3000, vec![("alice", 250, 500)]),
            &HashMap::new(),
        );
        // Expect: 1 server-wide row + 1 per-alice row.
        assert_eq!(out.len(), 2);
        let server_row = out
            .iter()
            .find(|d| d.user_id.is_none())
            .expect("server-wide row missing");
        assert_eq!(server_row.upload_bytes, 1500 - 1024);
        assert_eq!(server_row.download_bytes, 3000 - 2048);
        assert_eq!(server_row.active_connections, 1);
        let alice_row = out
            .iter()
            .find(|d| d.user_id.as_ref().map(|u| u.0.as_str()) == Some("alice"))
            .expect("alice row missing");
        assert_eq!(alice_row.upload_bytes, 250 - 100);
        assert_eq!(alice_row.download_bytes, 500 - 200);
        assert_eq!(alice_row.active_connections, 1);
    }

    #[test]
    fn quiet_tick_emits_nothing() {
        let mut e = DiffEngine::new();
        let s = snap(1024, 2048, vec![]);
        e.tick(&sid("srv-1"), &s, &HashMap::new());
        let out = e.tick(&sid("srv-1"), &s, &HashMap::new());
        assert!(
            out.is_empty(),
            "no movement + no connections must emit no rows"
        );
    }

    #[test]
    fn restart_detected_uses_new_total_as_delta_at_server_level() {
        // sing-box restart resets the server-wide totals to ~0; the
        // diff engine MUST surface the new total (not wrap to a
        // billion-byte u64 underflow) on the server-wide row.
        // Per-user rows use saturating_sub instead and emit 0 on
        // a smaller-than-prior new total — see the next test for why.
        let mut e = DiffEngine::new();
        e.tick(
            &sid("srv-1"),
            &snap(10_000, 20_000, vec![("alice", 5_000, 10_000)]),
            &HashMap::new(),
        );
        let out = e.tick(
            &sid("srv-1"),
            &snap(50, 100, vec![("alice", 30, 60)]),
            &HashMap::new(),
        );
        let server_row = out.iter().find(|d| d.user_id.is_none()).unwrap();
        assert_eq!(
            server_row.upload_bytes, 50,
            "restart must surface NEW total as delta on server-wide row"
        );
        assert_eq!(server_row.download_bytes, 100);
        let alice_row = out
            .iter()
            .find(|d| d.user_id.as_ref().map(|u| u.0.as_str()) == Some("alice"))
            .unwrap();
        // Conservative per-user under-attribution: new<prior ⇒ delta=0
        // (see next test for the bug this prevents).
        assert_eq!(
            alice_row.upload_bytes, 0,
            "per-user delta MUST be 0 when new<prior; restart attribution is server-wide-only"
        );
        assert_eq!(alice_row.download_bytes, 0);
        // active_connections still reflects what was actually seen.
        assert_eq!(alice_row.active_connections, 1);
    }

    /// Connection-cycle bug guard (review-agent finding on
    /// cd61838^..492fdeb): if alice has one TCP conn that uploaded
    /// 1000B and it CLOSES while a fresh conn opens at 200B, the
    /// per-user sum drops 1000→200. Per-user restart-detection
    /// would emit 200 as a fresh delta on top of the 1000 already
    /// credited — DOUBLE-COUNT. Saturating-sub prevents that.
    #[test]
    fn per_user_smaller_total_emits_zero_no_double_count() {
        let mut e = DiffEngine::new();
        // Tick 1: alice has one connection, 1000 up / 2000 down.
        e.tick(
            &sid("srv-1"),
            &snap(1000, 2000, vec![("alice", 1000, 2000)]),
            &HashMap::new(),
        );
        // Tick 2: that connection closed, alice opened a fresh small
        // one at 100 up / 200 down. Server total grew (sing-box still
        // remembers the closed connection's bytes), but the per-user
        // sum (across active conns only) shrank.
        let out = e.tick(
            &sid("srv-1"),
            &snap(2000, 4000, vec![("alice", 100, 200)]),
            &HashMap::new(),
        );
        let alice_row = out
            .iter()
            .find(|d| d.user_id.as_ref().map(|u| u.0.as_str()) == Some("alice"))
            .expect("alice row should still appear (active_connections > 0)");
        assert_eq!(
            alice_row.upload_bytes, 0,
            "shrinking per-user sum MUST emit 0 — anything else double-counts"
        );
        assert_eq!(alice_row.download_bytes, 0);
        assert_eq!(alice_row.active_connections, 1);
    }

    /// Negative test (review-agent #3): pin behaviour against an
    /// inverted impl. A `tick()` that always returned `Vec::new()`
    /// would pass `quiet_tick_emits_nothing` AND
    /// `first_snapshot_emits_no_rows_just_seeds`; this test fires
    /// only when the engine actually computes deltas, so the
    /// always-empty implementation FAILS here.
    #[test]
    fn engine_actually_computes_deltas_not_always_empty() {
        let mut e = DiffEngine::new();
        e.tick(&sid("srv-1"), &snap(0, 0, vec![]), &HashMap::new());
        let out = e.tick(
            &sid("srv-1"),
            &snap(123_456, 789_012, vec![("alice", 100, 200)]),
            &HashMap::new(),
        );
        assert!(
            !out.is_empty(),
            "second snapshot with movement MUST produce at least one row"
        );
        let server_row = out.iter().find(|d| d.user_id.is_none()).unwrap();
        assert_eq!(server_row.upload_bytes, 123_456);
        assert_eq!(server_row.download_bytes, 789_012);
    }

    #[test]
    fn new_user_appearing_emits_their_full_totals_as_delta() {
        let mut e = DiffEngine::new();
        e.tick(
            &sid("srv-1"),
            &snap(1024, 2048, vec![("alice", 100, 200)]),
            &HashMap::new(),
        );
        let out = e.tick(
            &sid("srv-1"),
            &snap(2048, 4096, vec![("alice", 100, 200), ("bob", 500, 1000)]),
            &HashMap::new(),
        );
        let bob_row = out
            .iter()
            .find(|d| d.user_id.as_ref().map(|u| u.0.as_str()) == Some("bob"))
            .expect("bob's first row must be emitted");
        assert_eq!(bob_row.upload_bytes, 500);
        assert_eq!(bob_row.download_bytes, 1000);
    }

    #[test]
    fn multi_server_state_isolated() {
        let mut e = DiffEngine::new();
        e.tick(&sid("srv-1"), &snap(1024, 0, vec![]), &HashMap::new());
        e.tick(&sid("srv-2"), &snap(2048, 0, vec![]), &HashMap::new());
        let out_1 = e.tick(&sid("srv-1"), &snap(1100, 0, vec![]), &HashMap::new());
        let out_2 = e.tick(&sid("srv-2"), &snap(2100, 0, vec![]), &HashMap::new());
        // srv-1 delta is 76, srv-2 delta is 52 — must not cross-pollinate.
        assert_eq!(out_1[0].upload_bytes, 76);
        assert_eq!(out_2[0].upload_bytes, 52);
    }

    #[test]
    fn forget_drops_state_so_next_tick_is_treated_as_first() {
        let mut e = DiffEngine::new();
        e.tick(&sid("srv-1"), &snap(1024, 0, vec![]), &HashMap::new());
        assert_eq!(e.tracked_servers(), 1);
        e.forget(&sid("srv-1"));
        assert_eq!(e.tracked_servers(), 0);
        let out = e.tick(&sid("srv-1"), &snap(2048, 0, vec![]), &HashMap::new());
        assert!(
            out.is_empty(),
            "after forget, next tick is treated as first snapshot"
        );
    }

    // ── Phase 4e — log-derived attribution resolves user_id ──

    /// Build a snapshot connection where metadata.user is None
    /// (NM-11 production reality) but source_ip + source_port are
    /// populated — exactly the input pattern the attribution map
    /// needs to resolve to a user.
    fn snap_with_sources(
        server_up: u64,
        server_dn: u64,
        conns: Vec<(&str, &str, u64, u64)>, // (src_ip, src_port, upload, download)
    ) -> Snapshot {
        Snapshot {
            upload_total: server_up,
            download_total: server_dn,
            connections: conns
                .into_iter()
                .enumerate()
                .map(|(i, (ip, port, up, dn))| Connection {
                    id: format!("c{i}"),
                    upload: up,
                    download: dn,
                    start: "2026-05-21T20:30:00Z".into(),
                    metadata: ConnectionMeta {
                        network: "tcp".into(),
                        destination_ip: "1.2.3.4".into(),
                        destination_port: "443".into(),
                        source_ip: ip.into(),
                        source_port: port.into(),
                        host: String::new(),
                        // NM-11 reality — sing-box drops this field
                        // on the wire even though it knows the user
                        // server-side.
                        user: None,
                    },
                })
                .collect(),
        }
    }

    #[test]
    fn attribution_map_resolves_user_id_when_metadata_user_is_none() {
        // Snapshot has two connections from the same source IP
        // (different ports — different conns on one device).
        // Attribution map says (1.1.1.1, 11111) → alice and
        // (1.1.1.1, 22222) → alice. Both bytes should be credited
        // to alice as a single per-user row.
        let mut e = DiffEngine::new();
        let attr: HashMap<(String, String), String> = [
            (
                ("1.1.1.1".to_string(), "11111".to_string()),
                "alice".to_string(),
            ),
            (
                ("1.1.1.1".to_string(), "22222".to_string()),
                "alice".to_string(),
            ),
        ]
        .into_iter()
        .collect();
        // First tick seeds the prior totals; emits no rows.
        e.tick(
            &sid("srv-1"),
            &snap_with_sources(0, 0, vec![]),
            &HashMap::new(),
        );
        // Second tick — alice's two conns appear.
        let out = e.tick(
            &sid("srv-1"),
            &snap_with_sources(
                1000,
                2000,
                vec![
                    ("1.1.1.1", "11111", 400, 800),
                    ("1.1.1.1", "22222", 600, 1200),
                ],
            ),
            &attr,
        );
        let alice_row = out
            .iter()
            .find(|d| d.user_id.as_ref().map(|u| u.0.as_str()) == Some("alice"))
            .expect("alice row must exist when attribution resolved both conns");
        assert_eq!(alice_row.upload_bytes, 1000, "400+600 = both conns summed");
        assert_eq!(
            alice_row.download_bytes, 2000,
            "800+1200 = both conns summed"
        );
        assert_eq!(
            alice_row.active_connections, 2,
            "two conns counted as active"
        );
    }

    #[test]
    fn no_attribution_for_unmapped_source_means_no_per_user_row() {
        // Snapshot has one conn from an IP that's NOT in the
        // attribution map → no per-user row, only the server-wide
        // delta. metadata.user is None per NM-11.
        let mut e = DiffEngine::new();
        e.tick(
            &sid("srv-1"),
            &snap_with_sources(0, 0, vec![]),
            &HashMap::new(),
        );
        let out = e.tick(
            &sid("srv-1"),
            &snap_with_sources(500, 1000, vec![("9.9.9.9", "5555", 500, 1000)]),
            &HashMap::new(), // empty attribution
        );
        assert!(
            out.iter().all(|d| d.user_id.is_none()),
            "no attribution → no per-user rows; got {:?}",
            out.iter().map(|d| &d.user_id).collect::<Vec<_>>()
        );
        let server_row = out
            .iter()
            .find(|d| d.user_id.is_none())
            .expect("server row");
        assert_eq!(server_row.upload_bytes, 500);
    }

    #[test]
    fn metadata_user_wins_over_attribution_map_when_both_present() {
        // Forward-compat: if a future sing-box build (or upstream
        // patch) emits `metadata.user`, we use it directly and
        // ignore the attribution fallback. Defends against
        // post-NM-11-fix drift where both could disagree.
        let mut e = DiffEngine::new();
        let attr: HashMap<(String, String), String> = [(
            ("1.1.1.1".to_string(), "11111".to_string()),
            "wrong-from-log".to_string(),
        )]
        .into_iter()
        .collect();
        let mut snap = snap_with_sources(0, 0, vec![]);
        snap.upload_total = 100;
        snap.download_total = 200;
        snap.connections.push(Connection {
            id: "c0".into(),
            upload: 100,
            download: 200,
            start: "2026-05-21T20:30:00Z".into(),
            metadata: ConnectionMeta {
                network: "tcp".into(),
                destination_ip: "1.2.3.4".into(),
                destination_port: "443".into(),
                source_ip: "1.1.1.1".into(),
                source_port: "11111".into(),
                host: String::new(),
                user: Some("right-from-wire".into()), // sing-box patched
            },
        });
        e.tick(
            &sid("srv-1"),
            &snap_with_sources(0, 0, vec![]),
            &HashMap::new(),
        );
        let out = e.tick(&sid("srv-1"), &snap, &attr);
        let user_rows: Vec<&str> = out
            .iter()
            .filter_map(|d| d.user_id.as_ref().map(|u| u.0.as_str()))
            .collect();
        assert_eq!(
            user_rows,
            vec!["right-from-wire"],
            "metadata.user from the wire wins; attribution fallback ignored"
        );
    }
}
