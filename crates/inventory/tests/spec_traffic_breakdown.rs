#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use tempfile::TempDir;
use vpnctl_core::{KernelId, Server, ServerId, UserId};
use vpnctl_inventory::{SqliteInventory, VpnStatsDelta, sum_nic_deltas};

async fn open(dir: &TempDir) -> SqliteInventory {
    SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .expect("open")
}

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
        None,
    )
    .await
    .expect("record_node_health");
    tokio::time::sleep(std::time::Duration::from_millis(15)).await;
}

fn rd(iface: &str, rx: u64, tx: u64) -> (String, u64, u64) {
    (iface.to_string(), rx, tx)
}

#[test]
fn sum_nic_deltas_monotonic_sums_intervals() {
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
    let r = [
        rd("eth0", 1000, 0),
        rd("eth0", 1500, 0),
        rd("ens18", 9000, 0),
    ];
    assert_eq!(sum_nic_deltas(&r).0, 9500);
}

#[tokio::test]
async fn breakdown_computes_nic_attributed_and_gap() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let sid = add_srv(&inv, "de").await;
    rec_nic(&inv, &sid, "ens18", 1000, 500).await;
    rec_nic(&inv, &sid, "ens18", 1500, 800).await;
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
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let sid = add_srv(&inv, "nl").await;
    rec_nic(&inv, &sid, "ens18", 0, 0).await;
    rec_nic(&inv, &sid, "ens18", 5000, 5000).await;
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
                user_id: None,
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
