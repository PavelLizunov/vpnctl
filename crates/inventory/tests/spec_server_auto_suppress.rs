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
async fn default_off_and_not_suppressed() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("fi")).await.unwrap();
    let sid = ServerId("fi".into());
    assert_eq!(
        inv.server_auto_suppress_state(&sid).await.unwrap(),
        (false, None)
    );
    assert!(!inv.is_server_auto_suppressed(&sid).await.unwrap());
}

#[tokio::test]
async fn render_gate_requires_both_optin_and_suppressed() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("fi")).await.unwrap();
    let sid = ServerId("fi".into());

    inv.set_server_auto_suppress(&sid, true).await.unwrap();
    assert!(!inv.is_server_auto_suppressed(&sid).await.unwrap());

    assert!(inv.set_server_suppressed(&sid, true).await.unwrap());
    assert!(inv.is_server_auto_suppressed(&sid).await.unwrap());
    let (opt, ts) = inv.server_auto_suppress_state(&sid).await.unwrap();
    assert!(opt && ts.is_some());
}

#[tokio::test]
async fn set_suppressed_is_idempotent_and_audits_on_transition() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("fi")).await.unwrap();
    let sid = ServerId("fi".into());
    inv.set_server_auto_suppress(&sid, true).await.unwrap();

    assert!(inv.set_server_suppressed(&sid, true).await.unwrap());
    assert!(!inv.set_server_suppressed(&sid, true).await.unwrap());
    assert_eq!(audit_count(&inv, "server.auto_suppressed").await, 1);

    assert!(inv.set_server_suppressed(&sid, false).await.unwrap());
    assert!(!inv.set_server_suppressed(&sid, false).await.unwrap());
    assert_eq!(audit_count(&inv, "server.auto_restored").await, 1);
}

#[tokio::test]
async fn turning_optin_off_lifts_active_suppression() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("fi")).await.unwrap();
    let sid = ServerId("fi".into());
    inv.set_server_auto_suppress(&sid, true).await.unwrap();
    inv.set_server_suppressed(&sid, true).await.unwrap();
    assert!(inv.is_server_auto_suppressed(&sid).await.unwrap());

    inv.set_server_auto_suppress(&sid, false).await.unwrap();
    let (opt, ts) = inv.server_auto_suppress_state(&sid).await.unwrap();
    assert!(!opt, "opt-in cleared");
    assert_eq!(ts, None, "active suppression lifted");
    assert!(!inv.is_server_auto_suppressed(&sid).await.unwrap());
}

#[tokio::test]
async fn unknown_server_errors_invalid() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let bad = ServerId("nope".into());
    assert!(matches!(
        inv.set_server_auto_suppress(&bad, true).await,
        Err(SqliteInventoryError::Invalid(_))
    ));
    assert!(matches!(
        inv.set_server_suppressed(&bad, true).await,
        Err(SqliteInventoryError::Invalid(_))
    ));
}
