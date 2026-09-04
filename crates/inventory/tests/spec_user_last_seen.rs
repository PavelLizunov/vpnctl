//! Spec for `SqliteInventory::user_last_seen`.
//!
//! Contract: returns `Option<DateTime<Utc>>` representing the latest observed
//! activity for a user across all telemetry sources:
//! 1. `sub_access_log` (subscription config pulls)
//! 2. `vpn_connection_stats` (attributed traffic ticks with bytes or active conns)
//! 3. `vpn_user_sessions` (active VPN session windows)
//!
//! When a user pulled their subscription 8 days ago, but transferred VPN traffic
//! today, `user_last_seen` must return today's timestamp, NOT the 8-day-old sub fetch.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use tempfile::TempDir;
use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
use vpnctl_inventory::SqliteInventory;

fn db_path(dir: &TempDir) -> PathBuf {
    dir.path().join("inventory.db")
}

async fn open(dir: &TempDir) -> SqliteInventory {
    SqliteInventory::open(&db_path(dir)).await.expect("open")
}

async fn raw_pool(dir: &TempDir) -> sqlx::SqlitePool {
    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", db_path(dir).display()))
        .await
        .unwrap();
    sqlx::query("PRAGMA foreign_keys = ON")
        .execute(&pool)
        .await
        .unwrap();
    pool
}

fn user(id: &str) -> User {
    User {
        id: UserId(id.into()),
        uuid: format!("00000000-0000-0000-0000-{id:0>12}"),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: Some(format!("token-{id}")),
        vpn_router_device_id: None,
        disabled: false,
    }
}

fn server(id: &str) -> Server {
    Server {
        id: ServerId(id.into()),
        address: "1.2.3.4".into(),
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
async fn user_last_seen_none_for_fresh_user() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let uid = UserId("alice".into());
    inv.add_user(&user("alice")).await.unwrap();

    let last_seen = inv.user_last_seen(&uid).await.unwrap();
    assert!(
        last_seen.is_none(),
        "fresh user with no activity must return None"
    );
}

#[tokio::test]
async fn user_last_seen_picks_sub_access_when_only_sub_exists() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let pool = raw_pool(&dir).await;
    let uid = UserId("alice".into());
    inv.add_user(&user("alice")).await.unwrap();

    sqlx::query(
        "INSERT INTO sub_access_log (ts, user_id, ip, status, bytes)
         VALUES ('2026-08-27T11:18:13.452Z', 'alice', '1.1.1.1', 200, 1024)",
    )
    .execute(&pool)
    .await
    .unwrap();

    let last_seen = inv.user_last_seen(&uid).await.unwrap().expect("last_seen");
    assert_eq!(
        last_seen.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
        "2026-08-27T11:18:13.452Z"
    );
}

#[tokio::test]
async fn user_last_seen_picks_fresher_vpn_traffic_over_older_sub_fetch() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let pool = raw_pool(&dir).await;
    let uid = UserId("gelios".into());
    inv.add_user(&user("gelios")).await.unwrap();
    inv.add_server(&server("srv-1")).await.unwrap();
    inv.grant(&uid, &ServerId("srv-1".into())).await.unwrap();

    // 1. User fetched sub 8 days ago:
    sqlx::query(
        "INSERT INTO sub_access_log (ts, user_id, ip, status, bytes)
         VALUES ('2026-08-27T11:18:13.452Z', 'gelios', '1.1.1.1', 200, 1024)",
    )
    .execute(&pool)
    .await
    .unwrap();

    // 2. User generated VPN traffic today:
    sqlx::query(
        "INSERT INTO vpn_connection_stats (ts, server_id, user_id, upload_bytes, download_bytes, active_connections)
         VALUES ('2026-09-04T13:08:02.427Z', 'srv-1', 'gelios', 1000, 5000, 0)",
    )
    .execute(&pool)
    .await
    .unwrap();

    let last_seen = inv.user_last_seen(&uid).await.unwrap().expect("last_seen");
    assert_eq!(
        last_seen.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
        "2026-09-04T13:08:02.427Z",
        "last_seen must reflect today's VPN traffic tick, not the 8-day-old sub fetch"
    );
}

#[tokio::test]
async fn user_last_seen_picks_fresher_session_over_older_ticks() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let pool = raw_pool(&dir).await;
    let uid = UserId("bob".into());
    inv.add_user(&user("bob")).await.unwrap();
    inv.add_server(&server("srv-1")).await.unwrap();
    inv.grant(&uid, &ServerId("srv-1".into())).await.unwrap();

    sqlx::query(
        "INSERT INTO sub_access_log (ts, user_id, ip, status, bytes)
         VALUES ('2026-08-20T10:00:00.000Z', 'bob', '1.1.1.1', 200, 1024)",
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO vpn_user_sessions (id, user_id, server_id, started_at, last_seen, conn_count_peak, total_bytes)
         VALUES (1, 'bob', 'srv-1', '2026-09-01T12:00:00.000Z', '2026-09-01T14:30:00.000Z', 1, 50000)",
    )
    .execute(&pool)
    .await
    .unwrap();

    let last_seen = inv.user_last_seen(&uid).await.unwrap().expect("last_seen");
    assert_eq!(
        last_seen.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
        "2026-09-01T14:30:00.000Z"
    );
}

#[tokio::test]
async fn user_last_seen_ignores_zero_traffic_and_zero_conns_ticks() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let pool = raw_pool(&dir).await;
    let uid = UserId("charlie".into());
    inv.add_user(&user("charlie")).await.unwrap();
    inv.add_server(&server("srv-1")).await.unwrap();
    inv.grant(&uid, &ServerId("srv-1".into())).await.unwrap();

    sqlx::query(
        "INSERT INTO sub_access_log (ts, user_id, ip, status, bytes)
         VALUES ('2026-08-25T10:00:00.000Z', 'charlie', '1.1.1.1', 200, 1024)",
    )
    .execute(&pool)
    .await
    .unwrap();

    // A quiet tick with 0 bytes and 0 active connections:
    sqlx::query(
        "INSERT INTO vpn_connection_stats (ts, server_id, user_id, upload_bytes, download_bytes, active_connections)
         VALUES ('2026-09-04T12:00:00.000Z', 'srv-1', 'charlie', 0, 0, 0)",
    )
    .execute(&pool)
    .await
    .unwrap();

    let last_seen = inv.user_last_seen(&uid).await.unwrap().expect("last_seen");
    assert_eq!(
        last_seen.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
        "2026-08-25T10:00:00.000Z",
        "zero-byte/zero-conn quiet tick must not count as user activity"
    );
}

#[tokio::test]
async fn user_last_seen_picks_active_connection_even_with_zero_bytes() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let pool = raw_pool(&dir).await;
    let uid = UserId("dave".into());
    inv.add_user(&user("dave")).await.unwrap();
    inv.add_server(&server("srv-1")).await.unwrap();
    inv.grant(&uid, &ServerId("srv-1".into())).await.unwrap();

    // 1. Sub access 5 days ago:
    sqlx::query(
        "INSERT INTO sub_access_log (ts, user_id, ip, status, bytes)
         VALUES ('2026-08-30T10:00:00.000Z', 'dave', '1.1.1.1', 200, 1024)",
    )
    .execute(&pool)
    .await
    .unwrap();

    // 2. An idle active connection tick today (0 bytes, but active_connections = 2):
    sqlx::query(
        "INSERT INTO vpn_connection_stats (ts, server_id, user_id, upload_bytes, download_bytes, active_connections)
         VALUES ('2026-09-04T15:00:00.000Z', 'srv-1', 'dave', 0, 0, 2)",
    )
    .execute(&pool)
    .await
    .unwrap();

    let last_seen = inv.user_last_seen(&uid).await.unwrap().expect("last_seen");
    assert_eq!(
        last_seen.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
        "2026-09-04T15:00:00.000Z",
        "tick with active_connections > 0 must count as user activity even with 0 bytes"
    );
}

#[tokio::test]
async fn user_last_seen_picks_fresher_sub_access_when_newer_than_old_vpn_traffic() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let pool = raw_pool(&dir).await;
    let uid = UserId("eve".into());
    inv.add_user(&user("eve")).await.unwrap();
    inv.add_server(&server("srv-1")).await.unwrap();
    inv.grant(&uid, &ServerId("srv-1".into())).await.unwrap();

    // 1. Old VPN traffic:
    sqlx::query(
        "INSERT INTO vpn_connection_stats (ts, server_id, user_id, upload_bytes, download_bytes, active_connections)
         VALUES ('2026-08-20T12:00:00.000Z', 'srv-1', 'eve', 10000, 20000, 0)",
    )
    .execute(&pool)
    .await
    .unwrap();

    // 2. Newer sub pull:
    sqlx::query(
        "INSERT INTO sub_access_log (ts, user_id, ip, status, bytes)
         VALUES ('2026-09-01T08:00:00.000Z', 'eve', '1.1.1.1', 200, 1024)",
    )
    .execute(&pool)
    .await
    .unwrap();

    let last_seen = inv.user_last_seen(&uid).await.unwrap().expect("last_seen");
    assert_eq!(
        last_seen.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
        "2026-09-01T08:00:00.000Z",
        "newer sub access must take priority over older VPN traffic"
    );
}

#[tokio::test]
async fn user_last_seen_isolates_between_users_and_ignores_server_wide_rows() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let pool = raw_pool(&dir).await;
    let u_alice = UserId("alice".into());
    let u_bob = UserId("bob".into());
    inv.add_user(&user("alice")).await.unwrap();
    inv.add_user(&user("bob")).await.unwrap();
    inv.add_server(&server("srv-1")).await.unwrap();
    inv.grant(&u_alice, &ServerId("srv-1".into())).await.unwrap();
    inv.grant(&u_bob, &ServerId("srv-1".into())).await.unwrap();

    // Alice has recent traffic:
    sqlx::query(
        "INSERT INTO vpn_connection_stats (ts, server_id, user_id, upload_bytes, download_bytes, active_connections)
         VALUES ('2026-09-04T12:00:00.000Z', 'srv-1', 'alice', 500, 1000, 1)",
    )
    .execute(&pool)
    .await
    .unwrap();

    // Server-wide remainder row (user_id = NULL) has even newer traffic:
    sqlx::query(
        "INSERT INTO vpn_connection_stats (ts, server_id, user_id, upload_bytes, download_bytes, active_connections)
         VALUES ('2026-09-04T14:00:00.000Z', 'srv-1', NULL, 5000, 10000, 5)",
    )
    .execute(&pool)
    .await
    .unwrap();

    // Bob only has an old sub pull:
    sqlx::query(
        "INSERT INTO sub_access_log (ts, user_id, ip, status, bytes)
         VALUES ('2026-08-20T10:00:00.000Z', 'bob', '1.1.1.1', 200, 1024)",
    )
    .execute(&pool)
    .await
    .unwrap();

    let bob_seen = inv.user_last_seen(&u_bob).await.unwrap().expect("bob_seen");
    assert_eq!(
        bob_seen.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
        "2026-08-20T10:00:00.000Z",
        "bob must not be affected by alice's traffic or server-wide rows"
    );

    let alice_seen = inv.user_last_seen(&u_alice).await.unwrap().expect("alice_seen");
    assert_eq!(
        alice_seen.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
        "2026-09-04T12:00:00.000Z",
        "alice must see her own traffic, but not the newer NULL-user row"
    );
}
