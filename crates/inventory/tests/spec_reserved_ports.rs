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

#[tokio::test]
async fn default_reserved_ports_is_empty() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("ru")).await.unwrap();
    let ports = inv
        .get_reserved_ports(&ServerId("ru".into()))
        .await
        .unwrap();
    assert!(ports.is_empty(), "default must be empty, got {ports:?}");
}

#[tokio::test]
async fn set_and_get_roundtrip_preserves_sorted_deduped() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("ru")).await.unwrap();
    let sid = ServerId("ru".into());
    inv.set_reserved_ports(&sid, &[2096, 443, 2053, 443])
        .await
        .unwrap();
    let got = inv.get_reserved_ports(&sid).await.unwrap();
    assert_eq!(got, vec![443, 2053, 2096]);
}

#[tokio::test]
async fn set_reserved_ports_on_unknown_server_errors_invalid() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let err = inv
        .set_reserved_ports(&ServerId("does-not-exist".into()), &[443])
        .await
        .expect_err("must error on unknown server");
    assert!(matches!(err, SqliteInventoryError::Invalid(_)));
}

#[tokio::test]
async fn get_reserved_ports_on_unknown_server_returns_empty() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let got = inv
        .get_reserved_ports(&ServerId("does-not-exist".into()))
        .await
        .unwrap();
    assert!(got.is_empty());
}

#[tokio::test]
async fn idempotent_resave_writes_zero_audit_rows() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("ru")).await.unwrap();
    let sid = ServerId("ru".into());

    inv.set_reserved_ports(&sid, &[443, 2053]).await.unwrap();
    inv.set_reserved_ports(&sid, &[443, 2053]).await.unwrap();
    inv.set_reserved_ports(&sid, &[2053, 443]).await.unwrap();

    let rows = inv
        .recent_audit(64)
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.action == "server.reserved_ports.set")
        .count();
    assert_eq!(
        rows, 1,
        "exactly one audit row should be written for the actual mutation"
    );
}

#[tokio::test]
async fn changing_list_writes_one_audit_row_per_mutation() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("ru")).await.unwrap();
    let sid = ServerId("ru".into());

    inv.set_reserved_ports(&sid, &[443]).await.unwrap();
    inv.set_reserved_ports(&sid, &[443, 2053]).await.unwrap();
    inv.set_reserved_ports(&sid, &[]).await.unwrap();

    let rows = inv
        .recent_audit(64)
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.action == "server.reserved_ports.set")
        .count();
    assert_eq!(rows, 3);
}

#[tokio::test]
async fn empty_list_clears_reservation() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("ru")).await.unwrap();
    let sid = ServerId("ru".into());
    inv.set_reserved_ports(&sid, &[443, 2053]).await.unwrap();
    inv.set_reserved_ports(&sid, &[]).await.unwrap();
    let got = inv.get_reserved_ports(&sid).await.unwrap();
    assert!(got.is_empty());
}
