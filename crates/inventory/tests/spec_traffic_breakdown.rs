//! Spec for NIC ground-truth traffic accounting: `sum_nic_deltas` (pure
//! per-interval delta + reboot/reset guard) and `server_traffic_breakdown`
//! (NIC total vs clash-attributed vs the GAP). Written from spec only.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use tempfile::TempDir;
use vpnctl_core::{KernelId, Server, ServerId, UserId};
use vpnctl_inventory::{SqliteInventory, VpnStatsDelta, sum_nic_deltas};

async fn open(dir: &TempDir) -> SqliteInventory {
    SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .expect("open")
}

/// Add a minimal server (node_health + vpn_connection_stats FK to it).
async fn add_srv(inv: &SqliteInventory, id: &str) -> ServerId {
    let sid = ServerId(id.into());
    inv.add_server(&Server {
        id: sid.clone(),
        address: "1.1.1.1".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .expect("add_server");
    sid
}

// record_node_health has many infra args; this trims the noise for tests
// that only care about the NIC counters.
#[allow(clippy::too_many_arguments)]
async fn rec_nic(inv: &SqliteInventory, sid: &ServerId, iface: &str, rx: u64, tx: u64) {
    inv.record_node_health(
        sid,
        Some(true),
        Some(true),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(iface),
        Some(rx),
        Some(tx),
    )
    .await
    .expect("record_node_health");
}

// ─── sum_nic_deltas (pure) ───────────────────────────────────────────

/// (iface, rx, tx) reading builder — trims the `.to_string()` noise.
fn rd(iface: &str, rx: u64, tx: u64) -> (String, u64, u64) {
    (iface.to_string(), rx, tx)
}

#[test]
fn sum_nic_deltas_monotonic_sums_intervals() {
    // Same iface, cumulative oldest→newest → summed per-interval deltas.
    let r = [
        rd("eth0", 100, 10),
        rd("eth0", 300, 30),
        rd("eth0", 500, 80),
    ];
    assert_eq!(sum_nic_deltas(&r), (400, 70));
}

#[test]
fn sum_nic_deltas_needs_two_readings() {
    let empty: Vec<(String, u64, u64)> = Vec::new();
    assert_eq!(sum_nic_deltas(&empty), (0, 0));
    assert_eq!(sum_nic_deltas(&[rd("eth0", 999, 999)]), (0, 0));
}

#[test]
fn sum_nic_deltas_reset_guard_counts_new_value() {
    // 1000→1200 (Δ200), 1200→50 reboot (Δ50, NOT a huge wrap), 50→90 (Δ40)
    // = 290. Without the guard a naive subtraction would underflow/explode.
    let r = [
        rd("eth0", 1000, 0),
        rd("eth0", 1200, 0),
        rd("eth0", 50, 0),
        rd("eth0", 90, 0),
    ];
    assert_eq!(sum_nic_deltas(&r).0, 290);
}

#[test]
fn sum_nic_deltas_iface_change_breaks_continuity() {
    // eth0 1000→1500 (Δ500), then iface renames to ens18 with a HIGHER
    // counter 9000 — must NOT diff across ifaces (would be 7500 garbage).
    // Treated as a reset: count 9000 itself → 500 + 9000 = 9500.
    let r = [
        rd("eth0", 1000, 0),
        rd("eth0", 1500, 0),
        rd("ens18", 9000, 0),
    ];
    assert_eq!(sum_nic_deltas(&r).0, 9500);
}

// ─── server_traffic_breakdown ────────────────────────────────────────

#[tokio::test]
async fn breakdown_computes_nic_attributed_and_gap() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let sid = add_srv(&inv, "de").await;
    // Two NIC readings (insertion order = chronological via the rowid
    // tiebreak): rx 1000→1500 (Δ500), tx 500→800 (Δ300) → nic_total 800.
    rec_nic(&inv, &sid, "ens18", 1000, 500).await;
    rec_nic(&inv, &sid, "ens18", 1500, 800).await;
    // Clash-attributed: one user delta up=100 dn=200 → attributed 300.
    inv.record_vpn_stats(
        &sid,
        &[VpnStatsDelta {
            user_id: Some(UserId("alice".into())),
            upload_bytes: 100,
            download_bytes: 200,
            active_connections: 1,
        }],
    )
    .await
    .unwrap();

    let b = inv.server_traffic_breakdown(&sid, 24).await.unwrap();
    assert_eq!(b.nic_samples, 2);
    assert_eq!(b.nic_total_bytes, 800, "rx Δ500 + tx Δ300");
    assert_eq!(b.attributed_bytes, 300, "clash up+dn");
    assert_eq!(b.gap_bytes, 500, "800 nic − 300 attributed = the gap");
    assert_eq!(b.nic_iface.as_deref(), Some("ens18"));
}

#[tokio::test]
async fn breakdown_empty_when_no_nic_samples() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let sid = ServerId("fi".into());
    let b = inv.server_traffic_breakdown(&sid, 24).await.unwrap();
    assert_eq!(b.nic_samples, 0);
    assert_eq!(b.nic_total_bytes, 0);
    assert_eq!(b.gap_bytes, 0);
    assert_eq!(b.nic_iface, None);
}

#[tokio::test]
async fn breakdown_gap_saturates_when_attributed_exceeds_nic() {
    // At window edges clash can momentarily exceed NIC — the gap must
    // saturate at 0, never underflow.
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let sid = add_srv(&inv, "is").await;
    rec_nic(&inv, &sid, "eth0", 0, 0).await;
    rec_nic(&inv, &sid, "eth0", 100, 0).await;
    inv.record_vpn_stats(
        &sid,
        &[VpnStatsDelta {
            user_id: None,
            upload_bytes: 10_000,
            download_bytes: 0,
            active_connections: 0,
        }],
    )
    .await
    .unwrap();
    let b = inv.server_traffic_breakdown(&sid, 24).await.unwrap();
    assert_eq!(b.nic_total_bytes, 100);
    assert_eq!(b.attributed_bytes, 10_000);
    assert_eq!(b.gap_bytes, 0, "saturating — never negative");
}

#[tokio::test]
async fn breakdown_attributed_sums_per_user_and_server_wide_rows() {
    // Attributed = ALL clash rows (per-user + NULL server-wide remainder).
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let sid = add_srv(&inv, "nl").await;
    rec_nic(&inv, &sid, "ens18", 0, 0).await;
    rec_nic(&inv, &sid, "ens18", 5000, 5000).await; // nic_total 10000
    inv.record_vpn_stats(
        &sid,
        &[
            VpnStatsDelta {
                user_id: Some(UserId("u1".into())),
                upload_bytes: 1000,
                download_bytes: 0,
                active_connections: 1,
            },
            VpnStatsDelta {
                user_id: None, // server-wide remainder
                upload_bytes: 500,
                download_bytes: 0,
                active_connections: 0,
            },
        ],
    )
    .await
    .unwrap();
    let b = inv.server_traffic_breakdown(&sid, 24).await.unwrap();
    assert_eq!(b.attributed_bytes, 1500, "per-user 1000 + server-wide 500");
    assert_eq!(b.gap_bytes, 8500, "10000 nic − 1500 attributed");
}
