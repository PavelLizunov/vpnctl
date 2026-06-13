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
use crate::sing_box_log_scraper::AttributionMap;

/// Phase 4d — one snapshot + its source-IP/port → user_id
/// attribution map, bundled for atomic store / load. The
/// attribution map may be empty (sing-box log scrape failed,
/// daemon just started, etc); the snapshot half is always
/// populated when the entry exists.
#[derive(Debug, Default)]
pub struct ServerSnapshot {
    pub snapshot: Snapshot,
    /// (source_ip, source_port) → user_id from `sing-box` log.
    /// Empty map means «scrape happened but matched nothing»
    /// (e.g. the tail window was past the connection's accept
    /// time) — DISTINCT from None which we don't model here.
    pub attribution: AttributionMap,
}

/// Inner state behind the cache's `RwLock`. Two maps keyed by the
/// same `ServerId`:
///
/// * `snapshots` — the freshest `ServerSnapshot` per server (snapshot
///   + the attribution map the UI drill-down reads).
/// * `persistent_attribution` — the **accumulated** `(source_ip,
///   source_port) → user_id` map per server that SURVIVES across poll
///   ticks. See `store_merged` for the merge/prune lifecycle.
///
/// Keeping both under one lock means a poll tick's merge + prune +
/// snapshot-store is a single critical section — no lock-ordering to
/// reason about, and two servers polling concurrently never touch the
/// same map entries (they key on distinct `ServerId`s).
#[derive(Debug, Default)]
struct CacheState {
    snapshots: HashMap<ServerId, Arc<ServerSnapshot>>,
    persistent_attribution: HashMap<ServerId, AttributionMap>,
}

/// Process-shared cache of last-tick clash-api snapshots + log-
/// derived attribution maps, keyed by `ServerId`. Cloneable
/// handle (the inner `Arc` makes `.clone()` cheap — both AppState
/// and the poller hold their own clones, but write through the
/// same `RwLock`).
#[derive(Debug, Clone, Default)]
pub struct SnapshotCache {
    inner: Arc<RwLock<CacheState>>,
}

impl SnapshotCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Store the freshest snapshot + its attribution for `server`.
    /// Replaces any previous entry. Poisoned lock (from another
    /// thread panicking mid-write — `RwLock` becomes unusable)
    /// is logged-and-ignored: next successful write recovers,
    /// the alternative is to crash the daemon on a lock-poisoning
    /// event that doesn't actually affect SQL correctness.
    ///
    /// NOTE: this replaces the stored attribution wholesale. It does
    /// NOT touch the persistent accumulator — for the poller's
    /// attribution lifecycle use `store_merged`. Kept for callers
    /// (and tests) that genuinely want a one-shot store.
    pub fn store(&self, server: ServerId, snap: Snapshot, attribution: AttributionMap) {
        let entry = Arc::new(ServerSnapshot {
            snapshot: snap,
            attribution,
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

    /// Poller attribution lifecycle (the fix for the log-window-scroll
    /// under-attribution bug). One atomic critical section per tick:
    ///
    /// 1. **Merge** `fresh` (this tick's log scrape) into the
    ///    persistent per-server accumulator — new keys inserted, and a
    ///    newer scrape observation for an existing `(ip, port)` key
    ///    OVERWRITES the old user (so a port reused by a different user
    ///    after a close maps to the newer user).
    /// 2. **Prune** the accumulator down to the keys present in the
    ///    CURRENT clash-api connection set (`snap.connections`'
    ///    `(source_ip, source_port)` pairs). A closed connection's key
    ///    is evicted, which both bounds memory to ~live-connections and
    ///    stops a future port-reuse from mis-attributing to a stale
    ///    user.
    /// 3. **Store** the snapshot with the merged+pruned map as its
    ///    `attribution`, so the «Live connections» drill-down reads the
    ///    accumulated view too.
    ///
    /// Returns a clone of the merged+pruned map for the caller to use
    /// as THIS tick's per-connection resolver. On a poisoned lock the
    /// snapshot is dropped (next tick recovers) and `fresh` is returned
    /// unchanged so the tick still attributes whatever the scrape saw.
    pub fn store_merged(
        &self,
        server: ServerId,
        snap: Snapshot,
        fresh: AttributionMap,
    ) -> AttributionMap {
        // The set of keys currently live in clash-api. Pruning to this
        // set is what bounds the accumulator (closed conns evicted).
        let live_keys: std::collections::HashSet<(String, String)> = snap
            .connections
            .iter()
            .map(|c| (c.metadata.source_ip.clone(), c.metadata.source_port.clone()))
            .collect();

        let mut g = match self.inner.write() {
            Ok(g) => g,
            Err(e) => {
                tracing::warn!(
                    target = "vpnctld::snapshot_cache",
                    error = %e,
                    "snapshot cache RwLock poisoned — skipping merged store; returning fresh map only"
                );
                return fresh;
            }
        };

        let acc = g.persistent_attribution.entry(server.clone()).or_default();
        // 1. Merge: fresh observations win on conflict (port reuse).
        for (key, user) in fresh {
            acc.insert(key, user);
        }
        // 2. Prune: keep only keys that are live in this tick's
        //    connection set. Bounds memory + evicts stale port owners.
        acc.retain(|key, _| live_keys.contains(key));
        let merged = acc.clone();

        // 3. Store the snapshot with the merged view for the drill-down.
        g.snapshots.insert(
            server,
            Arc::new(ServerSnapshot {
                snapshot: snap,
                attribution: merged.clone(),
            }),
        );
        merged
    }

    /// Drop a server's persistent attribution accumulator (+ its cached
    /// snapshot). Call when a server leaves inventory so the maps don't
    /// grow monotonically — mirrors `DiffEngine::forget`.
    pub fn forget(&self, server: &ServerId) {
        match self.inner.write() {
            Ok(mut g) => {
                g.snapshots.remove(server);
                g.persistent_attribution.remove(server);
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

    /// Borrow the freshest server-snapshot bundle for `server`.
    /// None when the poller has never reached this server.
    pub fn get(&self, server: &ServerId) -> Option<Arc<ServerSnapshot>> {
        self.inner.read().ok()?.snapshots.get(server).cloned()
    }

    /// Test-only: size of the persistent attribution accumulator for
    /// `server` (None if the server was never seen). Lets tests assert
    /// pruning actually evicts keys without reaching into private state.
    #[cfg(test)]
    fn persistent_len(&self, server: &ServerId) -> Option<usize> {
        self.inner
            .read()
            .ok()?
            .persistent_attribution
            .get(server)
            .map(|m| m.len())
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

/// Group `snap.connections` by **destination**. Label resolution
/// priority (Phase 5a-2):
///   1. `metadata.host` if non-empty (sing-box already resolved
///      DNS — typically from HTTPS SNI / HTTP Host).
///   2. `dns_ptr_map[destination_ip]` if cache hit (positive).
///      → label becomes `<hostname>:<port> (<ip>)` so the operator
///      still sees the raw IP for debugging.
///   3. `destination_ip:port` if everything else fails.
///
/// Returns aggregates sorted by total bytes DESC, truncated to
/// `top_n`. Pass an empty `dns_ptr_map` to skip enrichment (tests
/// and pre-5a-2 call sites).
pub fn aggregate_by_destination(
    snap: &Snapshot,
    top_n: usize,
    dns_ptr_map: &HashMap<String, Option<String>>,
) -> Vec<ConnAggregate> {
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
            // Phase 5a-2: consult reverse-DNS cache. Some(Some)
            // = resolved hostname (enrich label). Some(None) =
            // cached "no PTR" (use bare IP). None = not yet
            // looked up (use bare IP).
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
            HashMap::new(),
        );
        let got = c.get(&sid).expect("snapshot must be present");
        assert_eq!(got.snapshot.connections.len(), 1);
        assert!(got.attribution.is_empty());
    }

    #[test]
    fn cache_round_trips_attribution_map() {
        let c = SnapshotCache::new();
        let sid = ServerId("de".into());
        let mut attr = HashMap::new();
        attr.insert(("83.97.108.34".into(), "55512".into()), "main-brat".into());
        c.store(sid.clone(), snap(vec![]), attr);
        let got = c.get(&sid).expect("must be present");
        assert_eq!(
            got.attribution
                .get(&("83.97.108.34".into(), "55512".into()))
                .map(|s| s.as_str()),
            Some("main-brat")
        );
    }

    // ── attribution-persist fix — store_merged lifecycle ─────────

    /// A connection with a controllable `(source_ip, source_port)` —
    /// the attribution key. The default `conn(..)` helper hard-codes
    /// port 12345, which collapses every connection onto one key.
    fn conn_sp(src_ip: &str, src_port: &str) -> Connection {
        Connection {
            id: format!("id-{src_ip}-{src_port}"),
            upload: 10,
            download: 20,
            start: "2026-06-13T18:00:00Z".into(),
            metadata: ConnectionMeta {
                network: "udp".into(),
                destination_ip: "1.2.3.4".into(),
                destination_port: "443".into(),
                source_ip: src_ip.into(),
                source_port: src_port.into(),
                host: String::new(),
                user: None,
            },
        }
    }

    fn attr_of(pairs: &[(&str, &str, &str)]) -> AttributionMap {
        pairs
            .iter()
            .map(|(ip, port, user)| ((ip.to_string(), port.to_string()), user.to_string()))
            .collect()
    }

    /// Contract 1: a connection whose accept line scrolled out of the
    /// `tail -n N` window (tick2 scrape is EMPTY for it) STAYS
    /// attributed because clash-api still lists it and an earlier tick
    /// recorded it in the persistent accumulator.
    #[test]
    fn attribution_persists_when_accept_line_scrolls_out() {
        let c = SnapshotCache::new();
        let sid = ServerId("is".into());
        let conns = vec![conn_sp("9.9.9.9", "40000")];

        // Tick 1: scrape sees the accept line → (9.9.9.9,40000)→alice,
        // and clash-api lists that one connection.
        let m1 = c.store_merged(
            sid.clone(),
            snap(conns.clone()),
            attr_of(&[("9.9.9.9", "40000", "alice")]),
        );
        assert_eq!(
            m1.get(&("9.9.9.9".into(), "40000".into()))
                .map(|s| s.as_str()),
            Some("alice")
        );

        // Tick 2: window scrolled — scrape is EMPTY — but clash-api
        // STILL lists the same long-lived connection.
        let m2 = c.store_merged(sid.clone(), snap(conns), AttributionMap::new());
        assert_eq!(
            m2.get(&("9.9.9.9".into(), "40000".into()))
                .map(|s| s.as_str()),
            Some("alice"),
            "long-lived conn must stay attributed after its accept line scrolls out"
        );
        // The drill-down feed (cache.get().attribution) sees it too.
        let got = c.get(&sid).expect("snapshot present");
        assert_eq!(
            got.attribution
                .get(&("9.9.9.9".into(), "40000".into()))
                .map(|s| s.as_str()),
            Some("alice"),
            "merged map must be what the «Live connections» drill-down reads"
        );
    }

    /// Contract 3 (proven first because it sets up contract 2's
    /// "later reuse attributes the NEW user"): once a key is pruned
    /// because its connection closed, a later reuse of the same
    /// `(ip, port)` by a DIFFERENT user attributes the new user, never
    /// the stale one.
    #[test]
    fn attribution_port_reuse_updates_to_newer_user() {
        let c = SnapshotCache::new();
        let sid = ServerId("is".into());

        // Tick 1: (5.5.5.5,50000) → alice, listed by clash-api.
        c.store_merged(
            sid.clone(),
            snap(vec![conn_sp("5.5.5.5", "50000")]),
            attr_of(&[("5.5.5.5", "50000", "alice")]),
        );
        // Tick 2: alice's conn closed — NOT in clash-api set → pruned.
        c.store_merged(sid.clone(), snap(vec![]), AttributionMap::new());
        assert_eq!(
            c.persistent_len(&sid),
            Some(0),
            "closed connection's key must be evicted by prune"
        );
        // Tick 3: same (ip,port) reused by bob, scrape sees the new
        // accept line, clash-api lists it again.
        let m3 = c.store_merged(
            sid.clone(),
            snap(vec![conn_sp("5.5.5.5", "50000")]),
            attr_of(&[("5.5.5.5", "50000", "bob")]),
        );
        assert_eq!(
            m3.get(&("5.5.5.5".into(), "50000".into()))
                .map(|s| s.as_str()),
            Some("bob"),
            "reused (ip,port) must map to the NEW user, not the stale alice"
        );
    }

    /// Contract 2: an entry whose `(ip, port)` is NOT in the current
    /// clash-api connection set is evicted from the persistent map —
    /// bounding memory AND preventing stale mis-attribution. Also
    /// proves merge-then-prune wins over a fresh observation that
    /// isn't actually live (defensive): if a key is in `fresh` but the
    /// connection isn't in the snapshot, it's pruned, so the map stays
    /// bounded to ~live connections.
    #[test]
    fn attribution_prunes_closed_connections() {
        let c = SnapshotCache::new();
        let sid = ServerId("is".into());

        // Tick 1: two live conns, both attributed.
        let m1 = c.store_merged(
            sid.clone(),
            snap(vec![conn_sp("1.1.1.1", "1000"), conn_sp("2.2.2.2", "2000")]),
            attr_of(&[("1.1.1.1", "1000", "alice"), ("2.2.2.2", "2000", "bob")]),
        );
        assert_eq!(m1.len(), 2);
        assert_eq!(c.persistent_len(&sid), Some(2));

        // Tick 2: alice's conn closed (only bob's remains in clash-api),
        // scrape empty. alice must be pruned; bob persists.
        let m2 = c.store_merged(
            sid.clone(),
            snap(vec![conn_sp("2.2.2.2", "2000")]),
            AttributionMap::new(),
        );
        assert!(
            !m2.contains_key(&("1.1.1.1".into(), "1000".into())),
            "alice's closed connection must be pruned from the map"
        );
        assert_eq!(
            m2.get(&("2.2.2.2".into(), "2000".into()))
                .map(|s| s.as_str()),
            Some("bob"),
            "bob's still-live connection must persist"
        );
        assert_eq!(
            c.persistent_len(&sid),
            Some(1),
            "pruning bounds the accumulator to the live connection set"
        );
    }

    #[test]
    fn store_merged_forget_clears_persistent_map() {
        let c = SnapshotCache::new();
        let sid = ServerId("is".into());
        c.store_merged(
            sid.clone(),
            snap(vec![conn_sp("1.1.1.1", "1000")]),
            attr_of(&[("1.1.1.1", "1000", "alice")]),
        );
        assert_eq!(c.persistent_len(&sid), Some(1));
        c.forget(&sid);
        assert_eq!(
            c.persistent_len(&sid),
            None,
            "forget must drop the per-server accumulator entirely"
        );
        assert!(
            c.get(&sid).is_none(),
            "forget must drop the cached snapshot"
        );
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
        // Phase 5a-2: when sing-box gives only an IP (no SNI/Host),
        // the reverse-DNS cache fills the gap. Cached hostname becomes
        // `hostname:port (ip)` so the operator sees BOTH.
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
        // Cached "no PTR" → bare IP, not enriched.
        let s = snap(vec![conn("1.1.1.1", "5.5.5.5", "443", "", "tcp", 10, 20)]);
        let mut cache: HashMap<String, Option<String>> = HashMap::new();
        cache.insert("5.5.5.5".to_string(), None);
        let top = aggregate_by_destination(&s, 10, &cache);
        assert_eq!(top[0].label, "5.5.5.5:443");
    }

    #[test]
    fn aggregate_by_destination_uses_metadata_host_over_dns_cache() {
        // sing-box already resolved (via SNI) → metadata.host wins,
        // cache ignored to preserve the protocol's own DNS answer.
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
        // metadata.host wins; cache.dns.google ignored.
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
        // Highest total is i=19 (200*(19+1) = 4000); top should
        // start with 10.0.0.19.
        assert_eq!(top[0].label, "10.0.0.19");
    }
}
