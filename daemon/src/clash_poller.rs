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
use vpnctl_inventory::VpnStatsDelta;

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
    pub fn tick(&mut self, server_id: &ServerId, snapshot: &Snapshot) -> Vec<VpnStatsDelta> {
        let prior = self.state.get(server_id).cloned();
        // Build new state from this snapshot.
        let mut new_per_user: HashMap<String, (u64, u64)> = HashMap::new();
        for c in &snapshot.connections {
            if let Some(u) = c.metadata.user.as_deref() {
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
        //   * If prior had them → emit the delta (with restart
        //     detection per-user, since a single user's connection
        //     might have closed and reopened independently of a
        //     full sing-box restart).
        //   * If prior didn't have them → this is a NEW user this
        //     tick; emit the new totals as the delta (their session
        //     started since the prior tick).
        for (user, &(new_up, new_dn)) in &new_totals.per_user {
            let (up_d, dn_d) = match prior.per_user.get(user) {
                Some(&(p_up, p_dn)) => (delta(p_up, new_up), delta(p_dn, new_dn)),
                None => (new_up, new_dn),
            };
            let active = u32::try_from(
                snapshot
                    .connections
                    .iter()
                    .filter(|c| c.metadata.user.as_deref() == Some(user.as_str()))
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

    /// Drop one server's tracked totals (e.g. after the server gets
    /// removed from inventory). Lazy alternative: prune unknown
    /// servers on each tick — but the poller already iterates the
    /// inventory list, so a removed server simply stops getting
    /// `tick()` calls and its entry sits dormant.
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
        let out = e.tick(&sid("srv-1"), &s);
        assert!(out.is_empty(), "first snapshot must emit nothing");
        assert_eq!(e.tracked_servers(), 1);
    }

    #[test]
    fn second_snapshot_emits_per_server_and_per_user_deltas() {
        let mut e = DiffEngine::new();
        e.tick(&sid("srv-1"), &snap(1024, 2048, vec![("alice", 100, 200)]));
        let out = e.tick(&sid("srv-1"), &snap(1500, 3000, vec![("alice", 250, 500)]));
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
        e.tick(&sid("srv-1"), &s);
        let out = e.tick(&sid("srv-1"), &s);
        assert!(
            out.is_empty(),
            "no movement + no connections must emit no rows"
        );
    }

    #[test]
    fn restart_detected_uses_new_total_as_delta_no_negative_overflow() {
        let mut e = DiffEngine::new();
        e.tick(
            &sid("srv-1"),
            &snap(10_000, 20_000, vec![("alice", 5_000, 10_000)]),
        );
        // sing-box restarted on the node — totals reset to small values.
        let out = e.tick(&sid("srv-1"), &snap(50, 100, vec![("alice", 30, 60)]));
        let server_row = out.iter().find(|d| d.user_id.is_none()).unwrap();
        assert_eq!(
            server_row.upload_bytes, 50,
            "restart must surface NEW total as delta, not wrap"
        );
        assert_eq!(server_row.download_bytes, 100);
        let alice_row = out
            .iter()
            .find(|d| d.user_id.as_ref().map(|u| u.0.as_str()) == Some("alice"))
            .unwrap();
        assert_eq!(alice_row.upload_bytes, 30);
        assert_eq!(alice_row.download_bytes, 60);
    }

    #[test]
    fn new_user_appearing_emits_their_full_totals_as_delta() {
        let mut e = DiffEngine::new();
        e.tick(&sid("srv-1"), &snap(1024, 2048, vec![("alice", 100, 200)]));
        let out = e.tick(
            &sid("srv-1"),
            &snap(2048, 4096, vec![("alice", 100, 200), ("bob", 500, 1000)]),
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
        e.tick(&sid("srv-1"), &snap(1024, 0, vec![]));
        e.tick(&sid("srv-2"), &snap(2048, 0, vec![]));
        let out_1 = e.tick(&sid("srv-1"), &snap(1100, 0, vec![]));
        let out_2 = e.tick(&sid("srv-2"), &snap(2100, 0, vec![]));
        // srv-1 delta is 76, srv-2 delta is 52 — must not cross-pollinate.
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
