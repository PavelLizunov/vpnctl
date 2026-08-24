//! AmneziaWG per-user source-IP poller — closes the sharing-detection
//! blind spot the clash-poller leaves behind.
//!
//! sing-box protocols get per-user attribution off clash-api's
//! `metadata.user` (see [`crate::clash_poller`]). But the `wireguard`
//! protocol is served by the **amneziawg** kernel (interface `awg0`), which
//! has no clash-api — so `clash_poller::poll_one_server` skips amneziawg
//! nodes, and its own comment names THIS path as the intended fix
//! («amneziawg metrics from wg show»). Until now a subscription shared over
//! WireGuard was invisible to [`crate::sharing_score`]: its source IPs never
//! reached `vpn_user_source_ips`, so the verdict's daily-/24-networks term
//! couldn't see it.
//!
//! This poller SSHes each amneziawg node (same [`SubprocessSshTransport`] +
//! deploy-key path the clash-poller uses), runs `awg show awg0 dump`, maps
//! each peer's public key to a user via `users.wireguard_pubkey`, and records
//! the peer's real endpoint IP into `vpn_user_source_ips` — the SAME table the
//! sharing verdict reads. No schema change; the render + verdict pick it up
//! automatically. It also diffs each peer's cumulative rx/tx into a per-user
//! byte delta recorded via `record_vpn_stats` (the same per-user traffic table
//! clash-api fills), so WG traffic finally counts toward the monthly limit.
//!
//! **What the source IPs feed:** the daily-distinct-/24-networks signal, NOT the
//! per-snapshot concurrency term. One WG pubkey is one peer per node — a
//! shared subscription's devices ROAM the single peer's endpoint rather than
//! appearing as two simultaneous endpoints — so concurrency stays clash-only,
//! but the endpoint flapping across the window accumulates distinct daily /24s
//! (which is exactly what catches WG sharing).
//!
//! Raw endpoint IPs are recorded verbatim; the sharing query already filters
//! infra / RFC1918 / egress IPs via `real_client_ip_predicate`, matching the
//! clash-poller's record-raw-filter-on-read contract.

use std::collections::{HashMap, HashSet};
use vpnctl_core::{SshTransport, UserId};
use vpnctl_inventory::{SqliteInventory, VpnStatsDelta};

/// AmneziaWG interface name — `awg-quick@awg0`, pinned by the amneziawg
/// kernel (`crates/kernels/src/amnezia_wg.rs`).
const AWG_IFACE: &str = "awg0";

/// One parsed peer from `awg show <iface> dump`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WgPeer {
    pub pubkey: String,
    /// Endpoint IP (port stripped). Empty when the peer has never connected
    /// (`(none)` in the dump).
    pub endpoint_ip: String,
    /// Cumulative bytes received FROM the peer since the interface came up
    /// (client → node = upload). Diffed tick-to-tick into a per-user delta.
    pub rx: u64,
    /// Cumulative bytes sent TO the peer (node → client = download).
    pub tx: u64,
}

/// In-memory per-peer cumulative-byte baseline, keyed by `(server_id, pubkey)`.
/// Lives for the poller task's lifetime so consecutive ticks can diff. Pruned
/// each tick to bound growth (re-keyed / deleted peers + removed servers).
type ByteState = HashMap<(String, String), (u64, u64)>;

/// Spawn the amneziawg source-IP poller. Ticks every
/// `VPNCTLD_WG_STATS_INTERVAL_SECS` seconds (default 300, matching the
/// clash-poller cadence). Returns the join handle; the caller `drop`s it to
/// detach (the task runs for the daemon's lifetime).
pub fn spawn_wg_stats_poller(inv: SqliteInventory) -> tokio::task::JoinHandle<()> {
    let interval_secs = std::env::var("VPNCTLD_WG_STATS_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(300);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        // Skip (not Burst) missed ticks — a slow poll must not schedule a
        // back-to-back catch-up storm of SSH sessions.
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Per-peer cumulative-byte baselines, persisted across ticks so bytes
        // can be diffed into deltas. Seeded on the first tick (no delta then).
        let mut byte_state: ByteState = HashMap::new();
        loop {
            tick.tick().await;
            poll_all(&inv, &mut byte_state).await;
        }
    })
}

/// One tick: build the pubkey→user map once, then poll every amneziawg node.
async fn poll_all(inv: &SqliteInventory, byte_state: &mut ByteState) {
    let servers = match inv.list_servers().await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(target = "vpnctld::wg_poller", error = %e, "list_servers failed");
            return;
        }
    };
    let awg_ids: HashSet<String> = servers
        .iter()
        .filter(|s| s.kernels.iter().any(|k| k.0 == "amneziawg"))
        .map(|s| s.id.0.clone())
        .collect();
    if awg_ids.is_empty() {
        byte_state.clear(); // no amneziawg node — drop any stale baselines
        return;
    }
    // Drop baselines for servers no longer amneziawg (removed / kernel dropped)
    // so the map can't grow unbounded across inventory churn.
    byte_state.retain(|(s, _), _| awg_ids.contains(s));

    let users = match inv.list_users().await {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!(target = "vpnctld::wg_poller", error = %e, "list_users failed");
            return;
        }
    };
    let pubkey_to_user = build_pubkey_map(users);
    if pubkey_to_user.is_empty() {
        return; // no WG users → no peer can be attributed
    }

    for server in &servers {
        if awg_ids.contains(&server.id.0) {
            poll_one_wg_server(inv, server, &pubkey_to_user, byte_state).await;
        }
    }
}

/// Build the `wireguard_pubkey → UserId` lookup, skipping users without a
/// pubkey. Two users can't share a pubkey (it's their WG identity), so the
/// last-wins collision is irrelevant in practice.
fn build_pubkey_map(users: Vec<vpnctl_core::User>) -> HashMap<String, UserId> {
    users
        .into_iter()
        .filter_map(|u| {
            let pk = u
                .wireguard_pubkey
                .as_deref()
                .unwrap_or("")
                .trim()
                .to_string();
            if pk.is_empty() {
                None
            } else {
                Some((pk, u.id))
            }
        })
        .collect()
}

/// Poll one amneziawg node: `awg show awg0 dump` over SSH, map peers to
/// users, record the (user, endpoint-IP) pairs. Best-effort — an unreachable
/// node is logged and skipped; the next tick retries.
async fn poll_one_wg_server(
    inv: &SqliteInventory,
    server: &vpnctl_core::Server,
    pubkey_to_user: &HashMap<String, UserId>,
    byte_state: &mut ByteState,
) {
    let key_path = crate::app::deploy_key_path();
    if !key_path.exists() {
        tracing::info!(
            target = "vpnctld::wg_poller",
            server = %server.id.0,
            key = %key_path.display(),
            "skipping: deploy SSH key not yet on the homelab host"
        );
        return;
    }

    let ssh = crate::ssh_subprocess::SubprocessSshTransport::new(
        server.address.clone(),
        server.ssh_user.clone(),
        key_path,
    )
    .port(server.ssh_port);

    let dump = match ssh.exec(&format!("awg show {AWG_IFACE} dump")).await {
        Ok(out) => out,
        Err(e) => {
            tracing::warn!(
                target = "vpnctld::wg_poller",
                server = %server.id.0,
                error = %e,
                "awg show dump failed"
            );
            return;
        }
    };

    let peers = parse_wg_dump(&dump);

    // Part A — source IPs (feeds the sharing verdict's daily-networks term).
    let ip_pairs = attribute_peers(&peers, pubkey_to_user);
    if !ip_pairs.is_empty() {
        if let Err(e) = inv.record_user_source_ips(&ip_pairs).await {
            tracing::warn!(
                target = "vpnctld::wg_poller",
                server = %server.id.0,
                error = %e,
                "record_user_source_ips failed (will retry next tick)"
            );
        }
    }

    // Part B — per-user byte deltas (traffic-limit coverage for WG users).
    let deltas = compute_byte_deltas(&server.id.0, &peers, pubkey_to_user, byte_state);
    if !deltas.is_empty() {
        if let Err(e) = inv.record_vpn_stats(&server.id, &deltas).await {
            tracing::warn!(
                target = "vpnctld::wg_poller",
                server = %server.id.0,
                error = %e,
                "record_vpn_stats failed (will retry next tick)"
            );
        }
    }
}

/// Diff each peer's cumulative rx/tx against its last-seen baseline in `state`
/// into per-user byte deltas, then update the baseline. Reset-safe: a peer
/// whose counter went DOWN (interface restarted) contributes its full current
/// value (via [`delta`]). A first-seen peer seeds its baseline and contributes
/// nothing this tick (no false spike). Stale baselines for this server's
/// unseen pubkeys are pruned so the map stays bounded. `active_connections` is
/// 0 — WireGuard is connectionless, so bytes (not a live-conn count) are the
/// signal; presence stays clash-api's domain.
pub fn compute_byte_deltas(
    server_id: &str,
    peers: &[WgPeer],
    pubkey_to_user: &HashMap<String, UserId>,
    state: &mut ByteState,
) -> Vec<VpnStatsDelta> {
    let mut per_user: HashMap<UserId, (u64, u64)> = HashMap::new();
    let mut seen: HashSet<String> = HashSet::new();
    for p in peers {
        let Some(uid) = pubkey_to_user.get(&p.pubkey) else {
            continue;
        };
        seen.insert(p.pubkey.clone());
        let key = (server_id.to_string(), p.pubkey.clone());
        let (up_d, dn_d) = match state.get(&key) {
            Some(&(last_rx, last_tx)) => (delta(last_rx, p.rx), delta(last_tx, p.tx)),
            None => (0, 0), // first sight → seed only
        };
        state.insert(key, (p.rx, p.tx));
        if up_d > 0 || dn_d > 0 {
            let e = per_user.entry(uid.clone()).or_insert((0, 0));
            e.0 = e.0.saturating_add(up_d);
            e.1 = e.1.saturating_add(dn_d);
        }
    }
    // Drop this server's baselines for pubkeys no longer present (re-keyed /
    // revoked peers) — bounds the map without touching other servers' keys.
    state.retain(|(s, pk), _| s != server_id || seen.contains(pk));

    per_user
        .into_iter()
        .map(|(uid, (up, dn))| VpnStatsDelta {
            user_id: Some(uid),
            upload_bytes: up,
            download_bytes: dn,
            active_connections: 0,
        })
        .collect()
}

/// Reset-safe counter diff: a strictly-smaller `new` means the amneziawg
/// interface restarted (counters zeroed) → treat `new` as the delta. Mirrors
/// `clash_poller::delta`.
fn delta(prior: u64, new: u64) -> u64 {
    if new < prior { new } else { new - prior }
}

/// Map parsed peers to `(user, source_ip)` pairs: drop peers with no endpoint
/// or an unknown pubkey, and dedupe within the tick (one hit per user+IP).
pub fn attribute_peers(
    peers: &[WgPeer],
    pubkey_to_user: &HashMap<String, UserId>,
) -> Vec<(UserId, String)> {
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut pairs = Vec::new();
    for p in peers {
        if p.endpoint_ip.is_empty() {
            continue;
        }
        let Some(uid) = pubkey_to_user.get(&p.pubkey) else {
            continue;
        };
        if seen.insert((uid.0.clone(), p.endpoint_ip.clone())) {
            pairs.push((uid.clone(), p.endpoint_ip.clone()));
        }
    }
    pairs
}

/// Parse `awg show <iface> dump` (identical format to `wg show`). The first
/// line is the interface (private-key, public-key, listen-port, fwmark); each
/// following TAB-separated line is a peer:
///   public-key  preshared-key  endpoint  allowed-ips  latest-handshake  rx  tx  keepalive
pub fn parse_wg_dump(out: &str) -> Vec<WgPeer> {
    out.lines()
        .skip(1) // interface header line
        .filter_map(|line| {
            let cols: Vec<&str> = line.split('\t').collect();
            // Need at least pubkey, psk, endpoint, allowed-ips.
            if cols.len() < 4 {
                return None;
            }
            let pubkey = cols[0].trim();
            if pubkey.is_empty() {
                return None;
            }
            // Peer columns: pubkey psk endpoint allowed-ips latest-handshake
            // rx tx keepalive. rx/tx (cols 5/6) are absent on a short/legacy
            // line → default 0 (source-IP tracking still works with ≥4 cols).
            Some(WgPeer {
                pubkey: pubkey.to_string(),
                endpoint_ip: strip_endpoint_ip(cols[2].trim()),
                rx: cols.get(5).and_then(|s| s.trim().parse().ok()).unwrap_or(0),
                tx: cols.get(6).and_then(|s| s.trim().parse().ok()).unwrap_or(0),
            })
        })
        .collect()
}

/// `1.2.3.4:51820` → `1.2.3.4`; `[2001:db8::1]:51820` → `2001:db8::1`;
/// `(none)` / empty → `""`.
fn strip_endpoint_ip(ep: &str) -> String {
    if ep.is_empty() || ep == "(none)" {
        return String::new();
    }
    if let Some(rest) = ep.strip_prefix('[') {
        // IPv6: [addr]:port — take everything up to ']'.
        return rest.split(']').next().unwrap_or("").to_string();
    }
    // IPv4: addr:port — the address has no ':' so split on the last one.
    match ep.rsplit_once(':') {
        Some((ip, _port)) => ip.to_string(),
        None => ep.to_string(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use vpnctl_core::{User, UserId};

    fn user(id: &str, pubkey: Option<&str>) -> User {
        User {
            id: UserId(id.into()),
            uuid: "u".into(),
            tuic_password: None,
            wireguard_pubkey: pubkey.map(str::to_string),
            wireguard_private: None,
            sub_token: Some("t".into()),
            vpn_router_device_id: None,
            disabled: false,
        }
    }

    #[test]
    fn strip_endpoint_handles_v4_v6_and_none() {
        assert_eq!(strip_endpoint_ip("1.2.3.4:51820"), "1.2.3.4");
        assert_eq!(strip_endpoint_ip("[2001:db8::1]:51820"), "2001:db8::1");
        assert_eq!(strip_endpoint_ip("(none)"), "");
        assert_eq!(strip_endpoint_ip(""), "");
    }

    #[test]
    fn parse_skips_interface_line_and_keeps_peers() {
        // Line 1 = interface (4 cols); lines 2-4 = peers. Peer 3 never
        // connected → endpoint `(none)` → empty IP.
        let dump = "PRIV_IFACE_KEY\tPUB_IFACE_KEY\t51820\toff\n\
                    PEERKEY1\t(none)\t9.9.9.9:40001\t10.13.13.2/32\t1720000000\t1024\t2048\toff\n\
                    PEERKEY2\tPSK\t[2001:db8::5]:40002\t10.13.13.3/32\t1720000100\t512\t768\toff\n\
                    PEERKEY3\t(none)\t(none)\t10.13.13.4/32\t0\t0\t0\toff";
        let peers = parse_wg_dump(dump);
        assert_eq!(peers.len(), 3);
        assert_eq!(peers[0].pubkey, "PEERKEY1");
        assert_eq!(peers[0].endpoint_ip, "9.9.9.9");
        assert_eq!(peers[1].endpoint_ip, "2001:db8::5");
        assert_eq!(peers[2].endpoint_ip, ""); // never connected
        // rx/tx parsed from cols 5/6.
        assert_eq!((peers[0].rx, peers[0].tx), (1024, 2048));
        assert_eq!((peers[1].rx, peers[1].tx), (512, 768));
        assert_eq!((peers[2].rx, peers[2].tx), (0, 0));
    }

    #[test]
    fn parse_tolerates_empty_and_short_lines() {
        assert!(parse_wg_dump("").is_empty());
        // Only an interface line, no peers.
        assert!(parse_wg_dump("PRIV\tPUB\t51820\toff").is_empty());
    }

    #[test]
    fn build_pubkey_map_skips_users_without_pubkey() {
        let map = build_pubkey_map(vec![
            user("alice", Some("PEERKEY1")),
            user("bob", None),
            user("carol", Some("  ")), // whitespace-only → skipped
        ]);
        assert_eq!(map.len(), 1);
        assert_eq!(map.get("PEERKEY1").unwrap().0, "alice");
    }

    #[test]
    fn attribute_drops_unknown_pubkeys_and_empty_ips_and_dedupes() {
        let map = build_pubkey_map(vec![user("alice", Some("PEERKEY1"))]);
        let peers = vec![
            WgPeer {
                pubkey: "PEERKEY1".into(),
                endpoint_ip: "9.9.9.9".into(),
                rx: 0,
                tx: 0,
            },
            // same user + IP again in the same tick → deduped
            WgPeer {
                pubkey: "PEERKEY1".into(),
                endpoint_ip: "9.9.9.9".into(),
                rx: 0,
                tx: 0,
            },
            // unknown pubkey → dropped
            WgPeer {
                pubkey: "STRANGER".into(),
                endpoint_ip: "8.8.8.8".into(),
                rx: 0,
                tx: 0,
            },
            // known user, no endpoint → dropped
            WgPeer {
                pubkey: "PEERKEY1".into(),
                endpoint_ip: "".into(),
                rx: 0,
                tx: 0,
            },
        ];
        let pairs = attribute_peers(&peers, &map);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0.0, "alice");
        assert_eq!(pairs[0].1, "9.9.9.9");
    }

    fn peer(pk: &str, rx: u64, tx: u64) -> WgPeer {
        WgPeer {
            pubkey: pk.into(),
            endpoint_ip: "9.9.9.9".into(),
            rx,
            tx,
        }
    }

    #[test]
    fn byte_deltas_seed_then_diff_then_handle_reset() {
        let map = build_pubkey_map(vec![user("alice", Some("PK"))]);
        let mut state: ByteState = HashMap::new();

        // Tick 1 — first sight → seed baseline, NO delta (no false spike).
        let d1 = compute_byte_deltas("de", &[peer("PK", 1000, 5000)], &map, &mut state);
        assert!(d1.is_empty(), "first tick seeds only");

        // Tick 2 — counters grew → delta = growth.
        let d2 = compute_byte_deltas("de", &[peer("PK", 1500, 9000)], &map, &mut state);
        assert_eq!(d2.len(), 1);
        assert_eq!(d2[0].user_id.as_ref().unwrap().0, "alice");
        assert_eq!(d2[0].upload_bytes, 500); // rx 1000 → 1500
        assert_eq!(d2[0].download_bytes, 4000); // tx 5000 → 9000
        assert_eq!(d2[0].active_connections, 0); // WG is connectionless

        // Tick 3 — counters DROPPED (interface restarted) → treat current as
        // the delta, not a giant negative wrap.
        let d3 = compute_byte_deltas("de", &[peer("PK", 200, 300)], &map, &mut state);
        assert_eq!(d3[0].upload_bytes, 200);
        assert_eq!(d3[0].download_bytes, 300);

        // Tick 4 — same counters, no growth → no row.
        let d4 = compute_byte_deltas("de", &[peer("PK", 200, 300)], &map, &mut state);
        assert!(d4.is_empty());
    }

    #[test]
    fn byte_deltas_prune_stale_peers_and_ignore_unknown() {
        let map = build_pubkey_map(vec![user("alice", Some("PK1"))]);
        let mut state: ByteState = HashMap::new();
        // Seed PK1 on de + an unknown pubkey (dropped, never enters state).
        compute_byte_deltas(
            "de",
            &[peer("PK1", 100, 100), peer("PK2", 9, 9)],
            &map,
            &mut state,
        );
        assert_eq!(state.len(), 1, "only the attributable peer is tracked");
        assert!(state.contains_key(&("de".into(), "PK1".into())));

        // Next tick PK1 is gone from the dump → its stale baseline is pruned.
        compute_byte_deltas("de", &[], &map, &mut state);
        assert!(
            state.is_empty(),
            "stale baseline pruned when peer disappears"
        );
    }
}
