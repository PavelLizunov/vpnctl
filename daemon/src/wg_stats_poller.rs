use std::collections::{HashMap, HashSet};
use vpnctl_core::{SshTransport, UserId};
use vpnctl_inventory::{SqliteInventory, VpnStatsDelta};

const AWG_IFACE: &str = "awg0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WgPeer {
    pub pubkey: String,
    pub endpoint_ip: String,
    pub rx: u64,
    pub tx: u64,
}

type ByteState = HashMap<(String, String), (u64, u64)>;

pub fn spawn_wg_stats_poller(inv: SqliteInventory) -> tokio::task::JoinHandle<()> {
    let interval_secs = std::env::var("VPNCTLD_WG_STATS_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(300);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut byte_state: ByteState = HashMap::new();
        loop {
            tick.tick().await;
            poll_all(&inv, &mut byte_state).await;
        }
    })
}

async fn poll_all(inv: &SqliteInventory, byte_state: &mut ByteState) {
    let servers = match inv.list_fleet_servers().await {
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
        byte_state.clear();
        return;
    }
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
        return;
    }

    for server in &servers {
        if awg_ids.contains(&server.id.0) {
            poll_one_wg_server(inv, server, &pubkey_to_user, byte_state).await;
        }
    }
}

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
            "skipping: deploy SSH key not yet on the control host"
        );
        return;
    }

    let jump = match inv.resolve_jump_host(server).await {
        Ok(j) => j,
        Err(e) => {
            tracing::warn!(
                target = "vpnctld::wg_poller",
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
            None => (0, 0),
        };
        state.insert(key, (p.rx, p.tx));
        if up_d > 0 || dn_d > 0 {
            let e = per_user.entry(uid.clone()).or_insert((0, 0));
            e.0 = e.0.saturating_add(up_d);
            e.1 = e.1.saturating_add(dn_d);
        }
    }
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

fn delta(prior: u64, new: u64) -> u64 {
    if new < prior { new } else { new - prior }
}

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

pub fn parse_wg_dump(out: &str) -> Vec<WgPeer> {
    out.lines()
        .skip(1)
        .filter_map(|line| {
            let cols: Vec<&str> = line.split('\t').collect();
            if cols.len() < 4 {
                return None;
            }
            let pubkey = cols[0].trim();
            if pubkey.is_empty() {
                return None;
            }
            Some(WgPeer {
                pubkey: pubkey.to_string(),
                endpoint_ip: strip_endpoint_ip(cols[2].trim()),
                rx: cols.get(5).and_then(|s| s.trim().parse().ok()).unwrap_or(0),
                tx: cols.get(6).and_then(|s| s.trim().parse().ok()).unwrap_or(0),
            })
        })
        .collect()
}

fn strip_endpoint_ip(ep: &str) -> String {
    if ep.is_empty() || ep == "(none)" {
        return String::new();
    }
    if let Some(rest) = ep.strip_prefix('[') {
        return rest.split(']').next().unwrap_or("").to_string();
    }
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
        let dump = "PRIV_IFACE_KEY\tPUB_IFACE_KEY\t51820\toff\n\
                    PEERKEY1\t(none)\t9.9.9.9:40001\t10.13.13.2/32\t1720000000\t1024\t2048\toff\n\
                    PEERKEY2\tPSK\t[2001:db8::5]:40002\t10.13.13.3/32\t1720000100\t512\t768\toff\n\
                    PEERKEY3\t(none)\t(none)\t10.13.13.4/32\t0\t0\t0\toff";
        let peers = parse_wg_dump(dump);
        assert_eq!(peers.len(), 3);
        assert_eq!(peers[0].pubkey, "PEERKEY1");
        assert_eq!(peers[0].endpoint_ip, "9.9.9.9");
        assert_eq!(peers[1].endpoint_ip, "2001:db8::5");
        assert_eq!(peers[2].endpoint_ip, "");
        assert_eq!((peers[0].rx, peers[0].tx), (1024, 2048));
        assert_eq!((peers[1].rx, peers[1].tx), (512, 768));
        assert_eq!((peers[2].rx, peers[2].tx), (0, 0));
    }

    #[test]
    fn parse_tolerates_empty_and_short_lines() {
        assert!(parse_wg_dump("").is_empty());
        assert!(parse_wg_dump("PRIV\tPUB\t51820\toff").is_empty());
    }

    #[test]
    fn build_pubkey_map_skips_users_without_pubkey() {
        let map = build_pubkey_map(vec![
            user("alice", Some("PEERKEY1")),
            user("bob", None),
            user("carol", Some("  ")),
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
            WgPeer {
                pubkey: "PEERKEY1".into(),
                endpoint_ip: "9.9.9.9".into(),
                rx: 0,
                tx: 0,
            },
            WgPeer {
                pubkey: "STRANGER".into(),
                endpoint_ip: "8.8.8.8".into(),
                rx: 0,
                tx: 0,
            },
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

        let d1 = compute_byte_deltas("de", &[peer("PK", 1000, 5000)], &map, &mut state);
        assert!(d1.is_empty(), "first tick seeds only");

        let d2 = compute_byte_deltas("de", &[peer("PK", 1500, 9000)], &map, &mut state);
        assert_eq!(d2.len(), 1);
        assert_eq!(d2[0].user_id.as_ref().unwrap().0, "alice");
        assert_eq!(d2[0].upload_bytes, 500);
        assert_eq!(d2[0].download_bytes, 4000);
        assert_eq!(d2[0].active_connections, 0);

        let d3 = compute_byte_deltas("de", &[peer("PK", 200, 300)], &map, &mut state);
        assert_eq!(d3[0].upload_bytes, 200);
        assert_eq!(d3[0].download_bytes, 300);

        let d4 = compute_byte_deltas("de", &[peer("PK", 200, 300)], &map, &mut state);
        assert!(d4.is_empty());
    }

    #[test]
    fn byte_deltas_prune_stale_peers_and_ignore_unknown() {
        let map = build_pubkey_map(vec![user("alice", Some("PK1"))]);
        let mut state: ByteState = HashMap::new();
        compute_byte_deltas(
            "de",
            &[peer("PK1", 100, 100), peer("PK2", 9, 9)],
            &map,
            &mut state,
        );
        assert_eq!(state.len(), 1, "only the attributable peer is tracked");
        assert!(state.contains_key(&("de".into(), "PK1".into())));

        compute_byte_deltas("de", &[], &map, &mut state);
        assert!(
            state.is_empty(),
            "stale baseline pruned when peer disappears"
        );
    }
}
