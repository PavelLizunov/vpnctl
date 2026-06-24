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
    /// Per-CONNECTION cumulative bytes keyed by the clash-api
    /// connection id (a UUID, stable for the connection's lifetime).
    /// Per-user deltas are derived by diffing each connection id
    /// independently, so a connection closing while a fresh one opens
    /// under the same user is NOT double-counted, and a closing
    /// connection's final-interval bytes ARE credited (its last
    /// observed total was diffed on the tick it last appeared). Closed
    /// connections vanish from the snapshot and are pruned here on the
    /// next tick (the map is rebuilt from the live set each tick).
    per_conn: HashMap<String, (u64, u64)>,
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
    /// Resolve each connection's user from `metadata.user` (emitted by
    /// our patched sing-box clash-api — the NM-11 fix; see
    /// `clash_api::ConnectionMeta::user`). Bytes are attributed per
    /// CONNECTION id, and the server-wide (`user_id = None`) row carries
    /// the UNATTRIBUTED REMAINDER — the interval total minus the sum of
    /// this tick's per-user deltas. That keeps the reporting invariant
    /// `SUM(server-wide + per-user) == true interval total`, so a
    /// downstream `SUM(upload_bytes)` over a window (see
    /// `SqliteInventory::server_live_activity`) never double-counts the
    /// attributed portion. As attribution approaches 100% the remainder
    /// trends to ~0 (only sub-poll-interval connections never sampled).
    pub fn tick(&mut self, server_id: &ServerId, snapshot: &Snapshot) -> Vec<VpnStatsDelta> {
        let prior = self.state.get(server_id).cloned();

        // Rebuild per-connection state from this snapshot and, in the
        // same pass, accumulate per-user byte deltas by diffing each
        // connection id against its prior cumulative bytes. A NEW id
        // (first time seen, or post-restart fresh UUID) contributes its
        // full current bytes; a known id contributes its growth. Closed
        // connections simply don't reappear and are dropped from state.
        let mut new_per_conn: HashMap<String, (u64, u64)> = HashMap::new();
        let mut per_user: HashMap<String, (u64, u64)> = HashMap::new();
        let mut per_user_active: HashMap<String, u32> = HashMap::new();
        for c in &snapshot.connections {
            new_per_conn.insert(c.id.clone(), (c.upload, c.download));
            let (up_d, dn_d) = match prior.as_ref().and_then(|p| p.per_conn.get(&c.id)) {
                Some(&(p_up, p_dn)) => {
                    (c.upload.saturating_sub(p_up), c.download.saturating_sub(p_dn))
                }
                None => (c.upload, c.download),
            };
            if let Some(user) = c.metadata.user.as_deref() {
                let entry = per_user.entry(user.to_string()).or_default();
                entry.0 = entry.0.saturating_add(up_d);
                entry.1 = entry.1.saturating_add(dn_d);
                *per_user_active.entry(user.to_string()).or_insert(0) += 1;
            }
        }
        let new_totals = ServerTotals {
            server_upload: snapshot.upload_total,
            server_download: snapshot.download_total,
            per_conn: new_per_conn,
        };

        // First snapshot ever for this server → seed and bail.
        let Some(prior) = prior else {
            self.state.insert(server_id.clone(), new_totals);
            return Vec::new();
        };

        let mut deltas: Vec<VpnStatsDelta> = Vec::new();

        // Server-wide interval total (restart detection: a strictly-
        // smaller total means sing-box restarted → treat the new total
        // as the delta).
        let server_up_total = delta(prior.server_upload, new_totals.server_upload);
        let server_dn_total = delta(prior.server_download, new_totals.server_download);
        // The attributed sum this tick. Subtract it so the server-wide
        // row holds only the UNATTRIBUTED remainder (no double-count).
        let attributed_up: u64 = per_user.values().map(|&(u, _)| u).sum();
        let attributed_dn: u64 = per_user.values().map(|&(_, d)| d).sum();
        let server_up_rem = server_up_total.saturating_sub(attributed_up);
        let server_dn_rem = server_dn_total.saturating_sub(attributed_dn);
        let server_active = u32::try_from(snapshot.connections.len()).unwrap_or(u32::MAX);
        if server_up_rem > 0 || server_dn_rem > 0 || server_active > 0 {
            deltas.push(VpnStatsDelta {
                user_id: None,
                upload_bytes: server_up_rem,
                download_bytes: server_dn_rem,
                active_connections: server_active,
            });
        }

        // Per-user rows from the per-connection deltas accumulated above.
        for (user, &(up_d, dn_d)) in &per_user {
            let active = per_user_active.get(user).copied().unwrap_or(0);
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
    // `> 0` guard + warn-on-bad lives in `config::parse_positive_secs`:
    // `interval(Duration::from_secs(0))` panics → poller crash-loop.
    let interval_secs =
        crate::config::parse_positive_secs("VPNCTLD_POLL_INTERVAL_SECS", DEFAULT_INTERVAL_SECS);

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

    // Cache the snapshot for the «Live connections» drill-down. Our
    // patched sing-box clash-api now emits `metadata.user` per
    // connection (the NM-11 fix; see `clash_api::ConnectionMeta::user`),
    // so per-user attribution comes straight off the wire — no sing-box
    // log scrape needed. That scrape used to pull the full
    // multi-hundred-MB log over SSH every tick (de's log is ~700 MB);
    // removing it is the bulk of this poll's I/O savings.
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
        // Count distinct /24 NETWORKS, not raw IPs — a single mobile device
        // rotates across many IPs within one carrier /24, so raw-IP counting
        // would fake concurrency. Two distinct /24s in one snapshot ⇒ two
        // separate access networks online together.
        let mut per_user_nets: HashMap<String, std::collections::HashSet<String>> = HashMap::new();
        for (u, ip) in &source_ip_pairs {
            if crate::ip_kind::classify_ip(ip) == crate::ip_kind::IpKind::Public
                && !vpnctl_inventory::sqlite::OUR_EGRESS_CONTROL_IPS.contains(&ip.as_str())
            {
                per_user_nets
                    .entry(u.0.clone())
                    .or_default()
                    .insert(vpnctl_inventory::sqlite::ipv4_net24(ip));
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

    let deltas = engine.tick(&server.id, &snapshot);
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

    fn conn(id: &str, user: &str, up: u64, dn: u64) -> Connection {
        Connection {
            id: id.into(),
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
        }
    }

    /// Snapshot with auto-assigned connection ids (`c0`, `c1`, …) — one
    /// per `(user, upload, download)` triple.
    fn snap(server_up: u64, server_dn: u64, conns: Vec<(&str, u64, u64)>) -> Snapshot {
        Snapshot {
            upload_total: server_up,
            download_total: server_dn,
            connections: conns
                .into_iter()
                .enumerate()
                .map(|(i, (user, up, dn))| conn(&format!("c{i}"), user, up, dn))
                .collect(),
        }
    }

    /// Snapshot with explicit connection objects — for restart /
    /// connection-cycle scenarios where connection-id identity matters.
    fn snap_ids(server_up: u64, server_dn: u64, conns: Vec<Connection>) -> Snapshot {
        Snapshot {
            upload_total: server_up,
            download_total: server_dn,
            connections: conns,
        }
    }

    fn sid(s: &str) -> ServerId {
        ServerId(s.into())
    }

    fn server_row(out: &[VpnStatsDelta]) -> Option<&VpnStatsDelta> {
        out.iter().find(|d| d.user_id.is_none())
    }
    fn user_row<'a>(out: &'a [VpnStatsDelta], u: &str) -> Option<&'a VpnStatsDelta> {
        out.iter()
            .find(|d| d.user_id.as_ref().map(|x| x.0.as_str()) == Some(u))
    }

    #[test]
    fn first_snapshot_emits_no_rows_just_seeds() {
        let mut e = DiffEngine::new();
        let out = e.tick(&sid("srv-1"), &snap(1024, 2048, vec![("alice", 100, 200)]));
        assert!(out.is_empty(), "first snapshot must emit nothing");
        assert_eq!(e.tracked_servers(), 1);
    }

    #[test]
    fn second_snapshot_emits_server_remainder_and_per_user_deltas() {
        let mut e = DiffEngine::new();
        e.tick(&sid("srv-1"), &snap(1024, 2048, vec![("alice", 100, 200)]));
        let out = e.tick(&sid("srv-1"), &snap(1500, 3000, vec![("alice", 250, 500)]));
        // alice's connection (c0) grew 100→250 / 200→500 ⇒ (150, 300).
        let alice = user_row(&out, "alice").expect("alice row");
        assert_eq!(alice.upload_bytes, 150);
        assert_eq!(alice.download_bytes, 300);
        assert_eq!(alice.active_connections, 1);
        // Server-wide row holds the REMAINDER: total delta (476, 952)
        // minus attributed (150, 300).
        let srv = server_row(&out).expect("server-wide row");
        assert_eq!(srv.upload_bytes, 476 - 150);
        assert_eq!(srv.download_bytes, 952 - 300);
        assert_eq!(srv.active_connections, 1);
        // Invariant: server-wide + per-user == true interval total.
        assert_eq!(srv.upload_bytes + alice.upload_bytes, 476);
        assert_eq!(srv.download_bytes + alice.download_bytes, 952);
    }

    #[test]
    fn quiet_tick_emits_nothing() {
        let mut e = DiffEngine::new();
        e.tick(&sid("srv-1"), &snap(1024, 2048, vec![]));
        let out = e.tick(&sid("srv-1"), &snap(1024, 2048, vec![]));
        assert!(
            out.is_empty(),
            "no movement + no connections must emit no rows"
        );
    }

    #[test]
    fn restart_fresh_conn_ids_credit_post_restart_bytes() {
        // sing-box restart: server totals reset AND every connection gets
        // a fresh UUID. The server-wide row surfaces the remainder of the
        // new (small) total; the new connection's bytes credit its user.
        let mut e = DiffEngine::new();
        e.tick(
            &sid("srv-1"),
            &snap_ids(10_000, 20_000, vec![conn("old", "alice", 5_000, 10_000)]),
        );
        let out = e.tick(
            &sid("srv-1"),
            &snap_ids(50, 100, vec![conn("new", "alice", 30, 60)]),
        );
        let alice = user_row(&out, "alice").expect("alice row");
        assert_eq!((alice.upload_bytes, alice.download_bytes), (30, 60));
        // Restart: server total delta = new total (50, 100); remainder
        // = (50-30, 100-60).
        let srv = server_row(&out).expect("server-wide row");
        assert_eq!((srv.upload_bytes, srv.download_bytes), (20, 40));
    }

    #[test]
    fn connection_cycle_no_double_count() {
        // alice's connection A grows, then closes while a fresh B opens.
        // Each id is diffed independently — B credits only its own bytes.
        let mut e = DiffEngine::new();
        e.tick(
            &sid("srv-1"),
            &snap_ids(1000, 2000, vec![conn("A", "alice", 1000, 2000)]),
        );
        let out1 = e.tick(
            &sid("srv-1"),
            &snap_ids(1500, 2500, vec![conn("A", "alice", 1500, 2500)]),
        );
        let a1 = user_row(&out1, "alice").expect("alice row t1");
        assert_eq!((a1.upload_bytes, a1.download_bytes), (500, 500));
        let out2 = e.tick(
            &sid("srv-1"),
            &snap_ids(1600, 2700, vec![conn("B", "alice", 100, 200)]),
        );
        let a2 = user_row(&out2, "alice").expect("alice row t2");
        assert_eq!(
            (a2.upload_bytes, a2.download_bytes),
            (100, 200),
            "fresh connection credits only its own bytes — no double-count of the closed one"
        );
    }

    #[test]
    fn engine_actually_computes_deltas_not_always_empty() {
        let mut e = DiffEngine::new();
        e.tick(&sid("srv-1"), &snap(0, 0, vec![]));
        let out = e.tick(
            &sid("srv-1"),
            &snap(123_456, 789_012, vec![("alice", 100, 200)]),
        );
        assert!(
            !out.is_empty(),
            "second snapshot with movement MUST produce at least one row"
        );
        let alice = user_row(&out, "alice").expect("alice row");
        assert_eq!((alice.upload_bytes, alice.download_bytes), (100, 200));
        let srv = server_row(&out).expect("server-wide row");
        assert_eq!(srv.upload_bytes, 123_456 - 100);
        assert_eq!(srv.download_bytes, 789_012 - 200);
    }

    #[test]
    fn new_user_appearing_emits_their_full_totals_as_delta() {
        let mut e = DiffEngine::new();
        e.tick(&sid("srv-1"), &snap(1024, 2048, vec![("alice", 100, 200)]));
        let out = e.tick(
            &sid("srv-1"),
            &snap(2048, 4096, vec![("alice", 100, 200), ("bob", 500, 1000)]),
        );
        let bob = user_row(&out, "bob").expect("bob's first row");
        assert_eq!((bob.upload_bytes, bob.download_bytes), (500, 1000));
    }

    #[test]
    fn multi_server_state_isolated() {
        let mut e = DiffEngine::new();
        e.tick(&sid("srv-1"), &snap(1024, 0, vec![]));
        e.tick(&sid("srv-2"), &snap(2048, 0, vec![]));
        let out_1 = e.tick(&sid("srv-1"), &snap(1100, 0, vec![]));
        let out_2 = e.tick(&sid("srv-2"), &snap(2100, 0, vec![]));
        assert_eq!(out_1[0].upload_bytes, 76);
        assert_eq!(out_2[0].upload_bytes, 52);
    }

    #[test]
    fn forget_drops_state_so_next_tick_is_treated_as_first() {
        let mut e = DiffEngine::new();
        e.tick(&sid("srv-1"), &snap(1024, 0, vec![]));
        assert_eq!(e.tracked_servers(), 1);
        e.forget(&sid("srv-1"));
        assert_eq!(e.tracked_servers(), 0);
        let out = e.tick(&sid("srv-1"), &snap(2048, 0, vec![]));
        assert!(
            out.is_empty(),
            "after forget, next tick is treated as first snapshot"
        );
    }
}
