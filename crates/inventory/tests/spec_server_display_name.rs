//! Spec for migration `0029_servers_display_name.sql` — operator-set
//! per-server display label used as the `{Country}` part of the
//! subscription URI fragment / sing-box outbound tag. Pins the public
//! `server_display_name` / `set_server_display_name` contract:
//!   * Default = None (column NULL) — every existing server keeps its
//!     country-map fallback until the operator sets a name.
//!   * Blank / whitespace-only stored or supplied → normalised to None
//!     (a "clear"), never an empty string.
//!   * Idempotent re-saves of the same value write ZERO audit rows
//!     (NM-10 audit-on-actual-mutation contract).
//!   * Unknown server id → `Invalid` error on set.

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
async fn default_display_name_is_none() {
    // Migration 0029 adds a nullable column with no default → every
    // server post-add has None until the operator sets one.
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("kg")).await.unwrap();
    let got = inv
        .server_display_name(&ServerId("kg".into()))
        .await
        .unwrap();
    assert_eq!(got, None);
}

#[tokio::test]
async fn set_and_get_roundtrip() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("kg")).await.unwrap();
    let sid = ServerId("kg".into());
    inv.set_server_display_name(&sid, Some("Kyrgyzstan"))
        .await
        .unwrap();
    assert_eq!(
        inv.server_display_name(&sid).await.unwrap(),
        Some("Kyrgyzstan".to_string())
    );
}

#[tokio::test]
async fn blank_or_whitespace_clears_to_none() {
    // A blank submission is a "clear", not an empty-string label —
    // so the render falls back to the country map, never renders "".
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("kg")).await.unwrap();
    let sid = ServerId("kg".into());
    inv.set_server_display_name(&sid, Some("Kyrgyzstan"))
        .await
        .unwrap();
    inv.set_server_display_name(&sid, Some("   "))
        .await
        .unwrap();
    assert_eq!(inv.server_display_name(&sid).await.unwrap(), None);
}

#[tokio::test]
async fn trims_surrounding_whitespace() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("kg")).await.unwrap();
    let sid = ServerId("kg".into());
    inv.set_server_display_name(&sid, Some("  Kyrgyzstan  "))
        .await
        .unwrap();
    assert_eq!(
        inv.server_display_name(&sid).await.unwrap(),
        Some("Kyrgyzstan".to_string())
    );
}

#[tokio::test]
async fn idempotent_resave_writes_no_audit_row() {
    // NM-10 audit-on-actual-mutation: setting the same value twice
    // must produce exactly one audit row, not two.
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("kg")).await.unwrap();
    let sid = ServerId("kg".into());
    inv.set_server_display_name(&sid, Some("Kyrgyzstan"))
        .await
        .unwrap();
    inv.set_server_display_name(&sid, Some("Kyrgyzstan"))
        .await
        .unwrap();
    assert_eq!(audit_count(&inv, "server.display_name.set").await, 1);
}

#[tokio::test]
async fn each_actual_change_audits() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("kg")).await.unwrap();
    let sid = ServerId("kg".into());
    inv.set_server_display_name(&sid, Some("Kyrgyzstan"))
        .await
        .unwrap(); // set
    inv.set_server_display_name(&sid, Some("Bishkek"))
        .await
        .unwrap(); // change
    inv.set_server_display_name(&sid, None).await.unwrap(); // clear
    assert_eq!(audit_count(&inv, "server.display_name.set").await, 3);
}

#[tokio::test]
async fn set_on_unknown_server_errors_invalid() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let err = inv
        .set_server_display_name(&ServerId("does-not-exist".into()), Some("X"))
        .await
        .expect_err("must error on unknown server");
    assert!(matches!(err, SqliteInventoryError::Invalid(_)));
}
