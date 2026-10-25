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

    sqlx::query(
        "INSERT INTO sub_access_log (ts, user_id, ip, status, bytes)
         VALUES ('2026-08-27T11:18:13.452Z', 'gelios', '1.1.1.1', 200, 1024)",
    )
    .execute(&pool)
    .await
    .unwrap();

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

    sqlx::query(
        "INSERT INTO sub_access_log (ts, user_id, ip, status, bytes)
         VALUES ('2026-08-30T10:00:00.000Z', 'dave', '1.1.1.1', 200, 1024)",
    )
    .execute(&pool)
    .await
    .unwrap();

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

    sqlx::query(
        "INSERT INTO vpn_connection_stats (ts, server_id, user_id, upload_bytes, download_bytes, active_connections)
         VALUES ('2026-08-20T12:00:00.000Z', 'srv-1', 'eve', 10000, 20000, 0)",
    )
    .execute(&pool)
    .await
    .unwrap();

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
    inv.grant(&u_alice, &ServerId("srv-1".into()))
        .await
        .unwrap();
    inv.grant(&u_bob, &ServerId("srv-1".into())).await.unwrap();

    sqlx::query(
        "INSERT INTO vpn_connection_stats (ts, server_id, user_id, upload_bytes, download_bytes, active_connections)
         VALUES ('2026-09-04T12:00:00.000Z', 'srv-1', 'alice', 500, 1000, 1)",
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO vpn_connection_stats (ts, server_id, user_id, upload_bytes, download_bytes, active_connections)
         VALUES ('2026-09-04T14:00:00.000Z', 'srv-1', NULL, 5000, 10000, 5)",
    )
    .execute(&pool)
    .await
    .unwrap();

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

    let alice_seen = inv
        .user_last_seen(&u_alice)
        .await
        .unwrap()
        .expect("alice_seen");
    assert_eq!(
        alice_seen.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
        "2026-09-04T12:00:00.000Z",
        "alice must see her own traffic, but not the newer NULL-user row"
    );
}

#[tokio::test]
async fn user_last_seen_survives_purge_of_each_activity_source() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let pool = raw_pool(&dir).await;
    inv.add_server(&server("srv-1")).await.unwrap();
    for id in ["sub-only", "vpn-only", "session-only", "quiet", "fresh"] {
        inv.add_user(&user(id)).await.unwrap();
    }
    sqlx::query(
        "INSERT INTO sub_access_log (ts, user_id, ip, status, bytes)
         VALUES ('2000-01-01T11:12:13.456Z', 'sub-only', '192.0.2.1', 200, 100)",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO vpn_connection_stats
         (ts, server_id, user_id, upload_bytes, download_bytes, active_connections)
         VALUES ('2000-01-02T12:13:14.567Z', 'srv-1', 'vpn-only', 0, 0, 1),
                ('2000-01-03T00:00:00.000Z', 'srv-1', 'quiet', 0, 0, 0),
                ('2000-01-04T00:00:00.000Z', 'srv-1', NULL, 100, 200, 1)",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO vpn_user_sessions
         (user_id, server_id, started_at, last_seen, conn_count_peak, total_bytes)
         VALUES ('session-only', 'srv-1', '2000-01-01T00:00:00.000Z',
                 '2000-01-03T13:14:15.678Z', 1, 100)",
    )
    .execute(&pool)
    .await
    .unwrap();
    for (id, expected) in [
        ("sub-only", "2000-01-01T11:12:13.456Z"),
        ("vpn-only", "2000-01-02T12:13:14.567Z"),
        ("session-only", "2000-01-03T13:14:15.678Z"),
    ] {
        let uid = UserId(id.into());
        let before = inv.user_last_seen(&uid).await.unwrap().unwrap();
        assert_eq!(
            before.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
            expected
        );
    }

    assert_eq!(inv.purge_sub_access_older_than(30).await.unwrap(), 1);
    assert_eq!(inv.purge_vpn_stats_older_than(32).await.unwrap(), 3);
    assert_eq!(inv.purge_user_sessions_older_than(30).await.unwrap(), 1);
    for (id, expected) in [
        ("sub-only", "2000-01-01T11:12:13.456Z"),
        ("vpn-only", "2000-01-02T12:13:14.567Z"),
        ("session-only", "2000-01-03T13:14:15.678Z"),
    ] {
        let uid = UserId(id.into());
        let after = inv.user_last_seen(&uid).await.unwrap().unwrap();
        assert_eq!(after.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(), expected);
    }
    for id in ["quiet", "fresh"] {
        assert!(
            inv.user_last_seen(&UserId(id.into()))
                .await
                .unwrap()
                .is_none()
        );
    }
    let audits: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action = 'user.last_activity'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(audits, 3, "only actual last-activity updates are audited");

    // An older deletion must never move persisted last activity backwards.
    sqlx::query(
        "INSERT INTO sub_access_log (ts, user_id, ip, status, bytes)
         VALUES ('1999-01-01T00:00:00.000Z', 'sub-only', '192.0.2.1', 200, 1)",
    )
    .execute(&pool)
    .await
    .unwrap();
    inv.purge_sub_access_older_than(30).await.unwrap();
    let audits_after: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action = 'user.last_activity'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(audits_after, audits);
    let last_seen = inv
        .user_last_seen(&UserId("sub-only".into()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        last_seen.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
        "2000-01-01T11:12:13.456Z"
    );
}
