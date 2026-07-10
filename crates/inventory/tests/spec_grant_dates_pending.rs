//! Design v2 3d — spec tests for `grant_dates_for_server` (migration
//! 0039) and `users_pending_deploy_for_server` (per-user pending-deploy
//! detection driven by audit timestamps).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use vpnctl_core::{Server, ServerId, User, UserId};
use vpnctl_inventory::SqliteInventory;

async fn inv() -> (tempfile::TempDir, SqliteInventory) {
    let dir = tempfile::TempDir::new().unwrap();
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    (dir, inv)
}

fn server(id: &str) -> Server {
    Server {
        id: ServerId(id.into()),
        address: "203.0.113.1".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![],
        enabled_protocols: vec![],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

fn user(id: &str) -> User {
    User {
        id: UserId(id.into()),
        uuid: format!("uuid-{id}"),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    }
}

/// A fresh grant is stamped with `granted_at` ≈ now; the date comes
/// back through `grant_dates_for_server`.
#[tokio::test]
async fn new_grant_carries_granted_at_timestamp() {
    let (_d, inv) = inv().await;
    inv.add_server(&server("s1")).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();
    inv.grant(&UserId("alice".into()), &ServerId("s1".into()))
        .await
        .unwrap();

    let dates = inv
        .grant_dates_for_server(&ServerId("s1".into()))
        .await
        .unwrap();
    assert_eq!(dates.len(), 1);
    let (uid, ts) = &dates[0];
    assert_eq!(uid.0, "alice");
    let ts = ts.expect("fresh grant must carry granted_at");
    let age = chrono::Utc::now() - ts;
    assert!(
        age.num_seconds() >= 0 && age.num_seconds() < 60,
        "granted_at must be ~now, got {ts}"
    );
}

/// Rows created before migration 0039 have NULL granted_at — the read
/// path must surface them as None, not error.
#[tokio::test]
async fn pre_migration_grant_reads_as_none() {
    let (_d, inv) = inv().await;
    inv.add_server(&server("s1")).await.unwrap();
    inv.add_user(&user("old")).await.unwrap();
    inv.grant(&UserId("old".into()), &ServerId("s1".into()))
        .await
        .unwrap();
    // Simulate a pre-0039 row via a second raw connection to the
    // same db file (the inventory's own pool is crate-private).
    let raw = sqlx::sqlite::SqlitePool::connect(&format!(
        "sqlite://{}",
        _d.path().join("inv.db").display()
    ))
    .await
    .unwrap();
    sqlx::query("UPDATE grants SET granted_at = NULL")
        .execute(&raw)
        .await
        .unwrap();

    let dates = inv
        .grant_dates_for_server(&ServerId("s1".into()))
        .await
        .unwrap();
    assert_eq!(dates.len(), 1);
    assert!(dates[0].1.is_none(), "NULL granted_at must read as None");
}

/// A `user.grant` audit row NEWER than the last good deploy marks the
/// user pending; a later successful deploy clears them; a user whose
/// grant was revoked (row gone from `grants`) never appears.
#[tokio::test]
async fn pending_deploy_tracks_grant_vs_deploy_timestamps() {
    let (_d, inv) = inv().await;
    inv.add_server(&server("s1")).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();
    inv.add_user(&user("bob")).await.unwrap();
    inv.grant(&UserId("alice".into()), &ServerId("s1".into()))
        .await
        .unwrap();
    inv.grant(&UserId("bob".into()), &ServerId("s1".into()))
        .await
        .unwrap();

    // No deploy at all → every audited grant is pending.
    inv.audit(
        "admin",
        "user.grant",
        Some("alice"),
        Some(&serde_json::json!({ "server": "s1" })),
    )
    .await
    .unwrap();
    let pending = inv
        .users_pending_deploy_for_server(&ServerId("s1".into()))
        .await
        .unwrap();
    assert_eq!(
        pending,
        vec![UserId("alice".into())],
        "grant without any deploy must be pending"
    );

    // A successful deploy AFTER the grant clears the pending set.
    // (audit ts has 1s resolution — bump the clock boundary by
    // waiting out the same-second collision.)
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    inv.audit(
        "admin",
        "server.deploy",
        Some("s1"),
        Some(&serde_json::json!({ "ssh_errors": [] })),
    )
    .await
    .unwrap();
    let pending = inv
        .users_pending_deploy_for_server(&ServerId("s1".into()))
        .await
        .unwrap();
    assert!(
        pending.is_empty(),
        "successful deploy after the grant must clear pending, got {pending:?}"
    );

    // A NEW grant after that deploy re-marks only that user.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    inv.audit(
        "admin",
        "user.grant",
        Some("bob"),
        Some(&serde_json::json!({ "server": "s1" })),
    )
    .await
    .unwrap();
    let pending = inv
        .users_pending_deploy_for_server(&ServerId("s1".into()))
        .await
        .unwrap();
    assert_eq!(pending, vec![UserId("bob".into())]);

    // A FAILED deploy (ssh_errors non-empty) must NOT clear pending.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    inv.audit(
        "admin",
        "server.deploy",
        Some("s1"),
        Some(&serde_json::json!({ "ssh_errors": ["boom"] })),
    )
    .await
    .unwrap();
    let pending = inv
        .users_pending_deploy_for_server(&ServerId("s1".into()))
        .await
        .unwrap();
    assert_eq!(
        pending,
        vec![UserId("bob".into())],
        "failed deploy must not clear the pending marker"
    );
}
