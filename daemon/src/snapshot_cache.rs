//! Phase 4c — In-memory cache of the last `clash-api` snapshot per
//! VPN server, plus aggregate helpers for the «Live connections»
//! drill-down on `/admin/servers/<id>`.
//!
//! ## Why a cache (and why in-memory only)
//!
//! The poller (`clash_poller::spawn_clash_poller`) already pulls a
//! full `Snapshot { connections: Vec<Connection>, … }` from each
//! server every 5 minutes. Today we agregate that into one server-
//! wide `vpn_connection_stats` row and **discard** the per-
//! connection detail. For the admin UI's per-connection breakdown
//! we need the same detail back — but writing every connection to
//! SQLite would be ~370k rows/day at 3 servers (426 conn × 288
//! ticks × 3), and we don't actually need history beyond «what's
//! happening right now».
//!
//! Trade-off: keep the last snapshot per server in memory only.
//! Daemon restart → empty for the next 5 minutes until the poller
//! tick refills it. Size: ~85 KiB per server × 3 = ~255 KiB total.
//!
//! ## NM-11 status
//!
//! sing-box's clash-api `TrackerMetadata.MarshalJSON` drops the
//! `user` field, so we can't attribute connections to inventory
//! `users.id`. BUT: it preserves `sourceIP` — the real public IP
//! of the client behind the VLESS auth. Combined with
//! `sub_access_log.ip` (where we recorded the same client's IP
//! when they last fetched their subscription URL) we can join
//! sourceIP → user_id in most cases. See
//! `SqliteInventory::users_for_source_ips`. That's the closest we
//! can get to per-user attribution without the upstream patch.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use vpnctl_core::ServerId;

use crate::clash_api::Snapshot;

/// Process-shared cache of last-tick clash-api snapshots, keyed by
/// `ServerId`. Cloneable handle (the inner `Arc` makes `.clone()`
/// cheap — both AppState and the poller hold their own clones, but
/// write through the same `RwLock`).
#[derive(Debug, Clone, Default)]
pub struct SnapshotCache {
    inner: Arc<RwLock<HashMap<ServerId, Arc<Snapshot>>>>,
}

impl SnapshotCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Store the freshest snapshot for `server`. Replaces any
    /// previous entry. Poisoned lock (from another thread panicking
    /// mid-write — `RwLock` becomes unusable) is logged-and-ignored:
    /// next successful write recovers, the alternative is to crash
    /// the daemon on a lock-poisoning event that doesn't actually
    /// affect SQL correctness.
    pub fn store(&self, server: ServerId, snap: Snapshot) {
        match self.inner.write() {
            Ok(mut g) => {
                g.insert(server, Arc::new(snap));
            }
            Err(e) => {
                tracing::warn!(
                    target = "vpnctld::snapshot_cache",
                    error = %e,
                    "snapshot cache RwLock poisoned — skipping store; next tick recovers"
                );
            }
        }
    }

    /// Borrow the freshest snapshot for `server`. None when the
    /// poller has never reached this server (fresh daemon start,
    /// server out-of-order, deploy key missing, etc).
    pub fn get(&self, server: &ServerId) -> Option<Arc<Snapshot>> {
        self.inner.read().ok()?.get(server).cloned()
    }
}

/// One aggregated bucket — used by both source-IP and destination
/// aggregations. `conns` is connection count, `upload` / `download`
/// are per-bucket sums in bytes. `label` is the human-readable key
/// (IP, `host:port`, etc) for rendering.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnAggregate {
    pub label: String,
    pub conns: u32,
    pub upload: u64,
    pub download: u64,
}

impl ConnAggregate {
    pub fn total(&self) -> u64 {
        self.upload.saturating_add(self.download)
    }
}

/// Group `snap.connections` by **destination** (prefer
/// `metadata.host` when sing-box resolved one — that's the real
/// DNS name like `youtube.com` — otherwise fall back to
/// `destinationIP:port`). Returns aggregates sorted by total bytes
/// DESC. Limit to `top_n` to keep the render budget tight.
pub fn aggregate_by_destination(snap: &Snapshot, top_n: usize) -> Vec<ConnAggregate> {
    let mut by_dest: HashMap<String, ConnAggregate> = HashMap::new();
    for c in &snap.connections {
        let label = if !c.metadata.host.is_empty() {
            // Prefer DNS name when sing-box has it — far more
            // useful than a raw IP for the operator.
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
            "(unknown)".to_string()
        };
        let entry = by_dest
            .entry(label.clone())
            .or_insert_with(|| ConnAggregate {
                label,
                conns: 0,
                upload: 0,
                download: 0,
            });
        entry.conns = entry.conns.saturating_add(1);
        entry.upload = entry.upload.saturating_add(c.upload);
        entry.download = entry.download.saturating_add(c.download);
    }
    let mut out: Vec<ConnAggregate> = by_dest.into_values().collect();
    out.sort_by_key(|a| std::cmp::Reverse(a.total()));
    out.truncate(top_n);
    out
}

/// Group `snap.connections` by source IP (real client public IP,
/// preserved despite NM-11). Returns aggregates sorted by total
/// bytes DESC. Empty source IPs are bucketed under `(unknown)` so
/// they're visible rather than silently dropped.
pub fn aggregate_by_source(snap: &Snapshot, top_n: usize) -> Vec<ConnAggregate> {
    let mut by_src: HashMap<String, ConnAggregate> = HashMap::new();
    for c in &snap.connections {
        let label = if c.metadata.source_ip.is_empty() {
            "(unknown)".to_string()
        } else {
            c.metadata.source_ip.clone()
        };
        let entry = by_src
            .entry(label.clone())
            .or_insert_with(|| ConnAggregate {
                label,
                conns: 0,
                upload: 0,
                download: 0,
            });
        entry.conns = entry.conns.saturating_add(1);
        entry.upload = entry.upload.saturating_add(c.upload);
        entry.download = entry.download.saturating_add(c.download);
    }
    let mut out: Vec<ConnAggregate> = by_src.into_values().collect();
    out.sort_by_key(|a| std::cmp::Reverse(a.total()));
    out.truncate(top_n);
    out
}

/// TCP / UDP / other split for the «network breakdown» row.
/// Counts connections + sums bytes per network kind. «other» is
/// any value of `metadata.network` other than literal `"tcp"` or
/// `"udp"` (defensive — unlikely from sing-box but possible).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkBreakdown {
    pub tcp_conns: u32,
    pub tcp_bytes: u64,
    pub udp_conns: u32,
    pub udp_bytes: u64,
    pub other_conns: u32,
    pub other_bytes: u64,
}

pub fn network_breakdown(snap: &Snapshot) -> NetworkBreakdown {
    let mut nb = NetworkBreakdown::default();
    for c in &snap.connections {
        let bytes = c.upload.saturating_add(c.download);
        match c.metadata.network.as_str() {
            "tcp" => {
                nb.tcp_conns = nb.tcp_conns.saturating_add(1);
                nb.tcp_bytes = nb.tcp_bytes.saturating_add(bytes);
            }
            "udp" => {
                nb.udp_conns = nb.udp_conns.saturating_add(1);
                nb.udp_bytes = nb.udp_bytes.saturating_add(bytes);
            }
            _ => {
                nb.other_conns = nb.other_conns.saturating_add(1);
                nb.other_bytes = nb.other_bytes.saturating_add(bytes);
            }
        }
    }
    nb
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::clash_api::{Connection, ConnectionMeta, Snapshot};

    fn conn(
        src: &str,
        dst_ip: &str,
        dst_port: &str,
        host: &str,
        net: &str,
        upload: u64,
        download: u64,
    ) -> Connection {
        Connection {
            id: format!("id-{src}-{dst_ip}"),
            upload,
            download,
            start: "2026-05-21T18:00:00Z".into(),
            metadata: ConnectionMeta {
                network: net.into(),
                destination_ip: dst_ip.into(),
                destination_port: dst_port.into(),
                source_ip: src.into(),
                source_port: "12345".into(),
                host: host.into(),
                user: None,
            },
        }
    }

    fn snap(conns: Vec<Connection>) -> Snapshot {
        Snapshot {
            upload_total: conns.iter().map(|c| c.upload).sum(),
            download_total: conns.iter().map(|c| c.download).sum(),
            connections: conns,
        }
    }

    #[test]
    fn cache_store_then_get_roundtrip() {
        let c = SnapshotCache::new();
        let sid = ServerId("de".into());
        c.store(
            sid.clone(),
            snap(vec![conn(
                "1.1.1.1", "2.2.2.2", "443", "x", "tcp", 100, 200,
            )]),
        );
        let got = c.get(&sid).expect("snapshot must be present");
        assert_eq!(got.connections.len(), 1);
    }

    #[test]
    fn cache_get_for_unknown_server_returns_none() {
        let c = SnapshotCache::new();
        assert!(c.get(&ServerId("never-stored".into())).is_none());
    }

    #[test]
    fn aggregate_by_destination_prefers_host_over_ip_and_sorts_by_total_bytes() {
        let s = snap(vec![
            conn("1.1.1.1", "8.8.8.8", "443", "youtube.com", "tcp", 100, 1000),
            conn("1.1.1.1", "8.8.8.8", "443", "youtube.com", "tcp", 50, 500),
            conn("1.1.1.1", "1.1.1.1", "53", "", "udp", 10, 20),
        ]);
        let top = aggregate_by_destination(&s, 10);
        assert_eq!(top.len(), 2, "youtube.com:443 + 1.1.1.1:53");
        assert_eq!(top[0].label, "youtube.com:443");
        assert_eq!(top[0].conns, 2);
        assert_eq!(top[0].upload, 150);
        assert_eq!(top[0].download, 1500);
        assert_eq!(top[1].label, "1.1.1.1:53");
    }

    #[test]
    fn aggregate_by_destination_falls_back_to_ip_when_host_empty() {
        let s = snap(vec![conn(
            "1.1.1.1",
            "172.217.16.142",
            "443",
            "",
            "tcp",
            10,
            20,
        )]);
        let top = aggregate_by_destination(&s, 10);
        assert_eq!(top[0].label, "172.217.16.142:443");
    }

    #[test]
    fn aggregate_by_destination_unknown_when_both_host_and_ip_empty() {
        let s = snap(vec![conn("1.1.1.1", "", "", "", "tcp", 10, 20)]);
        let top = aggregate_by_destination(&s, 10);
        assert_eq!(top[0].label, "(unknown)");
    }

    #[test]
    fn aggregate_by_source_groups_by_source_ip_and_sorts_desc() {
        let s = snap(vec![
            conn("83.97.108.34", "1.2.3.4", "443", "", "tcp", 100, 200),
            conn("83.97.108.34", "5.6.7.8", "443", "", "tcp", 50, 100),
            conn("178.35.106.202", "9.9.9.9", "443", "", "tcp", 10, 20),
        ]);
        let top = aggregate_by_source(&s, 10);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].label, "83.97.108.34");
        assert_eq!(top[0].conns, 2);
        assert_eq!(top[0].upload, 150);
        assert_eq!(top[0].download, 300);
        assert_eq!(top[1].label, "178.35.106.202");
    }

    #[test]
    fn aggregate_by_source_buckets_empty_source_ip_under_unknown_label() {
        let s = snap(vec![conn("", "1.2.3.4", "443", "", "tcp", 10, 20)]);
        let top = aggregate_by_source(&s, 10);
        assert_eq!(top[0].label, "(unknown)");
    }

    #[test]
    fn network_breakdown_splits_tcp_udp_other_correctly() {
        let s = snap(vec![
            conn("1.1.1.1", "8.8.8.8", "443", "", "tcp", 100, 200),
            conn("1.1.1.1", "8.8.8.8", "443", "", "tcp", 50, 50),
            conn("1.1.1.1", "9.9.9.9", "53", "", "udp", 10, 20),
            conn("1.1.1.1", "0.0.0.0", "0", "", "icmp", 5, 5),
        ]);
        let nb = network_breakdown(&s);
        assert_eq!(nb.tcp_conns, 2);
        assert_eq!(nb.tcp_bytes, 100 + 200 + 50 + 50);
        assert_eq!(nb.udp_conns, 1);
        assert_eq!(nb.udp_bytes, 10 + 20);
        assert_eq!(nb.other_conns, 1);
        assert_eq!(nb.other_bytes, 10);
    }

    #[test]
    fn aggregate_truncates_to_top_n() {
        let conns: Vec<Connection> = (0..20)
            .map(|i| {
                conn(
                    &format!("10.0.0.{i}"),
                    &format!("11.0.0.{i}"),
                    "443",
                    "",
                    "tcp",
                    100 * (i + 1) as u64,
                    100 * (i + 1) as u64,
                )
            })
            .collect();
        let s = snap(conns);
        let top = aggregate_by_source(&s, 5);
        assert_eq!(top.len(), 5);
        // Highest total is i=19 (200*(19+1) = 4000); top should
        // start with 10.0.0.19.
        assert_eq!(top[0].label, "10.0.0.19");
    }
}
