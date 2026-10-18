use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use chrono::{DateTime, Utc};
use vpnctl_core::ServerId;

use crate::clash_api::Snapshot;

#[derive(Debug)]
pub struct ServerSnapshot {
    pub snapshot: Snapshot,
    pub observed_at: DateTime<Utc>,
}

impl ServerSnapshot {
    pub fn is_stale(&self, now: DateTime<Utc>, poll_interval: Duration) -> bool {
        let threshold = chrono::Duration::from_std(poll_interval.saturating_mul(2))
            .unwrap_or(chrono::Duration::MAX);
        now.signed_duration_since(self.observed_at) > threshold
    }
}

#[derive(Debug, Default)]
struct CacheState {
    snapshots: HashMap<ServerId, Arc<ServerSnapshot>>,
}

#[derive(Debug, Clone, Default)]
pub struct SnapshotCache {
    inner: Arc<RwLock<CacheState>>,
}

impl SnapshotCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn store(&self, server: ServerId, snap: Snapshot) {
        self.store_at(server, snap, Utc::now());
    }

    pub fn store_at(&self, server: ServerId, snap: Snapshot, observed_at: DateTime<Utc>) {
        let entry = Arc::new(ServerSnapshot {
            snapshot: snap,
            observed_at,
        });
        match self.inner.write() {
            Ok(mut g) => {
                g.snapshots.insert(server, entry);
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

    pub fn forget(&self, server: &ServerId) {
        match self.inner.write() {
            Ok(mut g) => {
                g.snapshots.remove(server);
            }
            Err(e) => {
                tracing::warn!(
                    target = "vpnctld::snapshot_cache",
                    error = %e,
                    "snapshot cache RwLock poisoned — skipping forget; next tick recovers"
                );
            }
        }
    }

    pub fn get(&self, server: &ServerId) -> Option<Arc<ServerSnapshot>> {
        self.inner.read().ok()?.snapshots.get(server).cloned()
    }

    pub fn get_if_fresh(
        &self,
        server: &ServerId,
        now: DateTime<Utc>,
        poll_interval: Duration,
    ) -> Option<Arc<ServerSnapshot>> {
        let entry = self.get(server)?;
        (!entry.is_stale(now, poll_interval)).then_some(entry)
    }

    pub fn get_live(&self, server: &ServerId) -> Option<Arc<ServerSnapshot>> {
        self.get_if_fresh(
            server,
            Utc::now(),
            Duration::from_secs(crate::clash_poller::poll_interval_secs()),
        )
    }
}

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

pub fn aggregate_by_destination(
    snap: &Snapshot,
    top_n: usize,
    dns_ptr_map: &HashMap<String, Option<String>>,
) -> Vec<ConnAggregate> {
    let mut by_dest: HashMap<String, ConnAggregate> = HashMap::new();
    for c in &snap.connections {
        let label = if !c.metadata.host.is_empty() {
            if c.metadata.destination_port.is_empty() {
                c.metadata.host.clone()
            } else {
                format!("{}:{}", c.metadata.host, c.metadata.destination_port)
            }
        } else if !c.metadata.destination_ip.is_empty() {
            let cached_hostname = dns_ptr_map
                .get(&c.metadata.destination_ip)
                .and_then(|v| v.as_deref());
            match (cached_hostname, c.metadata.destination_port.is_empty()) {
                (Some(host), true) => format!("{} ({})", host, c.metadata.destination_ip),
                (Some(host), false) => format!(
                    "{}:{} ({})",
                    host, c.metadata.destination_port, c.metadata.destination_ip
                ),
                (None, true) => c.metadata.destination_ip.clone(),
                (None, false) => format!(
                    "{}:{}",
                    c.metadata.destination_ip, c.metadata.destination_port
                ),
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
        assert_eq!(got.snapshot.connections.len(), 1);
    }

    #[test]
    fn cache_get_for_unknown_server_returns_none() {
        let c = SnapshotCache::new();
        assert!(c.get(&ServerId("never-stored".into())).is_none());
    }

    fn clock() -> (chrono::DateTime<chrono::Utc>, std::time::Duration) {
        use chrono::TimeZone;
        (
            chrono::Utc.with_ymd_and_hms(2026, 7, 29, 12, 0, 0).unwrap(),
            std::time::Duration::from_secs(300),
        )
    }

    #[test]
    fn snapshot_is_fresh_within_two_intervals() {
        let (now, interval) = clock();
        let fresh_now = ServerSnapshot {
            snapshot: Snapshot::default(),
            observed_at: now,
        };
        assert!(!fresh_now.is_stale(now, interval));

        let one_missed = ServerSnapshot {
            snapshot: Snapshot::default(),
            observed_at: now - chrono::Duration::seconds(599),
        };
        assert!(
            !one_missed.is_stale(now, interval),
            "one missed tick (age < 2 intervals) must stay fresh"
        );
    }

    #[test]
    fn snapshot_is_stale_past_two_intervals() {
        let (now, interval) = clock();
        let stale = ServerSnapshot {
            snapshot: Snapshot::default(),
            observed_at: now - chrono::Duration::seconds(601),
        };
        assert!(stale.is_stale(now, interval));
    }

    #[test]
    fn get_if_fresh_returns_entry_when_fresh_and_none_when_stale() {
        let (now, interval) = clock();
        let c = SnapshotCache::new();
        let sid = ServerId("de".into());
        let s = snap(vec![conn(
            "1.1.1.1", "2.2.2.2", "443", "x", "tcp", 100, 200,
        )]);

        c.store_at(sid.clone(), s.clone(), now);
        assert!(
            c.get_if_fresh(&sid, now, interval).is_some(),
            "a just-stored snapshot must be live"
        );

        c.store_at(sid.clone(), s, now - chrono::Duration::seconds(3600));
        assert!(
            c.get(&sid).is_some(),
            "raw get still sees the (stale) entry"
        );
        assert!(
            c.get_if_fresh(&sid, now, interval).is_none(),
            "a snapshot older than ~2 intervals must not be served as live"
        );
    }

    #[test]
    fn aggregate_by_destination_prefers_host_over_ip_and_sorts_by_total_bytes() {
        let s = snap(vec![
            conn("1.1.1.1", "8.8.8.8", "443", "youtube.com", "tcp", 100, 1000),
            conn("1.1.1.1", "8.8.8.8", "443", "youtube.com", "tcp", 50, 500),
            conn("1.1.1.1", "1.1.1.1", "53", "", "udp", 10, 20),
        ]);
        let top = aggregate_by_destination(&s, 10, &HashMap::new());
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
        let top = aggregate_by_destination(&s, 10, &HashMap::new());
        assert_eq!(top[0].label, "172.217.16.142:443");
    }

    #[test]
    fn aggregate_by_destination_uses_dns_ptr_cache_when_host_empty_and_cache_hit() {
        let s = snap(vec![conn(
            "1.1.1.1",
            "35.217.1.178",
            "50005",
            "",
            "udp",
            100,
            200,
        )]);
        let mut cache: HashMap<String, Option<String>> = HashMap::new();
        cache.insert(
            "35.217.1.178".to_string(),
            Some("r3.googlevideo.com".to_string()),
        );
        let top = aggregate_by_destination(&s, 10, &cache);
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].label, "r3.googlevideo.com:50005 (35.217.1.178)");
    }

    #[test]
    fn aggregate_by_destination_skips_cache_when_negative_entry() {
        let s = snap(vec![conn("1.1.1.1", "5.5.5.5", "443", "", "tcp", 10, 20)]);
        let mut cache: HashMap<String, Option<String>> = HashMap::new();
        cache.insert("5.5.5.5".to_string(), None);
        let top = aggregate_by_destination(&s, 10, &cache);
        assert_eq!(top[0].label, "5.5.5.5:443");
    }

    #[test]
    fn aggregate_by_destination_uses_metadata_host_over_dns_cache() {
        let s = snap(vec![conn(
            "1.1.1.1",
            "8.8.8.8",
            "443",
            "actually-sni.example.com",
            "tcp",
            10,
            20,
        )]);
        let mut cache: HashMap<String, Option<String>> = HashMap::new();
        cache.insert("8.8.8.8".to_string(), Some("dns.google".to_string()));
        let top = aggregate_by_destination(&s, 10, &cache);
        assert_eq!(top[0].label, "actually-sni.example.com:443");
    }

    #[test]
    fn aggregate_by_destination_unknown_when_both_host_and_ip_empty() {
        let s = snap(vec![conn("1.1.1.1", "", "", "", "tcp", 10, 20)]);
        let top = aggregate_by_destination(&s, 10, &HashMap::new());
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
        assert_eq!(top[0].label, "10.0.0.19");
    }
}
