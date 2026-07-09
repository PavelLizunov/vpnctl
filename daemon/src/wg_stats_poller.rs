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
//! automatically.
//!
//! **What it feeds:** the daily-distinct-/24-networks signal, NOT the
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
use std::path::Path;
use vpnctl_core::{SshTransport, UserId};
use vpnctl_inventory::SqliteInventory;

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
}

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
        loop {
            tick.tick().await;
            poll_all(&inv).await;
        }
    })
}

/// One tick: build the pubkey→user map once, then poll every amneziawg node.
async fn poll_all(inv: &SqliteInventory) {
    let servers = match inv.list_servers().await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(target = "vpnctld::wg_poller", error = %e, "list_servers failed");
            return;
        }
    };
    if !servers
        .iter()
        .any(|s| s.kernels.iter().any(|k| k.0 == "amneziawg"))
    {
        return; // no amneziawg node — nothing to poll
    }

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
        if server.kernels.iter().any(|k| k.0 == "amneziawg") {
            poll_one_wg_server(inv, server, &pubkey_to_user).await;
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
) {
    let key_path = std::env::var("VPNCTLD_DEPLOY_KEY")
        .unwrap_or_else(|_| "/var/lib/vpnctl/.ssh/id_ed25519".to_string());
    if !Path::new(&key_path).exists() {
        tracing::info!(
            target = "vpnctld::wg_poller",
            server = %server.id.0,
            key = %key_path,
            "skipping: deploy SSH key not yet on the homelab host"
        );
        return;
    }

    let ssh = crate::ssh_subprocess::SubprocessSshTransport::new(
        server.address.clone(),
        server.ssh_user.clone(),
        std::path::PathBuf::from(&key_path),
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

    let pairs = attribute_peers(&parse_wg_dump(&dump), pubkey_to_user);
    if pairs.is_empty() {
        return;
    }
    if let Err(e) = inv.record_user_source_ips(&pairs).await {
        tracing::warn!(
            target = "vpnctld::wg_poller",
            server = %server.id.0,
            error = %e,
            "record_user_source_ips failed (will retry next tick)"
        );
    }
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
            Some(WgPeer {
                pubkey: pubkey.to_string(),
                endpoint_ip: strip_endpoint_ip(cols[2].trim()),
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
            },
            // same user + IP again in the same tick → deduped
            WgPeer {
                pubkey: "PEERKEY1".into(),
                endpoint_ip: "9.9.9.9".into(),
            },
            // unknown pubkey → dropped
            WgPeer {
                pubkey: "STRANGER".into(),
                endpoint_ip: "8.8.8.8".into(),
            },
            // known user, no endpoint → dropped
            WgPeer {
                pubkey: "PEERKEY1".into(),
                endpoint_ip: "".into(),
            },
        ];
        let pairs = attribute_peers(&peers, &map);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0.0, "alice");
        assert_eq!(pairs[0].1, "9.9.9.9");
    }
}
