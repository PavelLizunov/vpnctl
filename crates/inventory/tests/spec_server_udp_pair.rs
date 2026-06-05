//! Spec for migration `0031_servers_udp_pair_enabled.sql` (UX-3) — the
//! per-server naive↔HY2 UDP-pairing opt-in. Pins the
//! `set_server_udp_pair_enabled` / `is_server_udp_pair_enabled` contract:
//!   * Default: off.
//!   * Toggle on/off persists.
//!   * Audit-on-actual-change only (idempotent re-set is silent).
//!   * Unknown id → `Invalid` on the setter; `false` on the getter.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use tempfile::TempDir;
use vpnctl_core::{KernelId, ProtocolId, Server, ServerId};
use vpnctl_inventory::{SqliteInventory, SqliteInventoryError};

async fn open(dir: &TempDir) -> SqliteInventory {
    SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .expect("open")
}

fn srv(id: &str) -> Server {
    Server {
        id: ServerId(id.into()),
        address: format!("{id}.example.com"),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("vless+reality".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

async fn audit_count(inv: &SqliteInventory, action: &str) -> usize {
    inv.recent_audit(1000)
        .await
        .unwrap()
        .into_iter()
        .filter(|a| a.action == action)
        .count()
}

#[tokio::test]
async fn default_off() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("lv")).await.unwrap();
    assert!(
        !inv.is_server_udp_pair_enabled(&ServerId("lv".into()))
            .await
            .unwrap(),
        "UDP pairing must default OFF"
    );
}

#[tokio::test]
async fn toggle_on_off_persists() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("lv")).await.unwrap();
    let sid = ServerId("lv".into());

    inv.set_server_udp_pair_enabled(&sid, true).await.unwrap();
    assert!(inv.is_server_udp_pair_enabled(&sid).await.unwrap());

    inv.set_server_udp_pair_enabled(&sid, false).await.unwrap();
    assert!(!inv.is_server_udp_pair_enabled(&sid).await.unwrap());
}

#[tokio::test]
async fn audits_only_on_actual_change() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("lv")).await.unwrap();
    let sid = ServerId("lv".into());

    inv.set_server_udp_pair_enabled(&sid, true).await.unwrap(); // change
    inv.set_server_udp_pair_enabled(&sid, true).await.unwrap(); // no-op
    assert_eq!(audit_count(&inv, "server.udp_pair.set").await, 1);

    inv.set_server_udp_pair_enabled(&sid, false).await.unwrap(); // change
    inv.set_server_udp_pair_enabled(&sid, false).await.unwrap(); // no-op
    assert_eq!(audit_count(&inv, "server.udp_pair.set").await, 2);
}

#[tokio::test]
async fn unknown_server_errors_invalid_on_set_false_on_get() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let bad = ServerId("nope".into());
    assert!(matches!(
        inv.set_server_udp_pair_enabled(&bad, true).await,
        Err(SqliteInventoryError::Invalid(_))
    ));
    assert!(
        !inv.is_server_udp_pair_enabled(&bad).await.unwrap(),
        "getter on unknown id → false, not an error"
    );
}
