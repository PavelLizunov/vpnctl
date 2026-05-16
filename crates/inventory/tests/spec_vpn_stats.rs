//! Spec for `record_vpn_stats`, `recent_vpn_stats_for_user`,
//! `recent_vpn_stats_for_server`, `purge_vpn_stats_older_than` on
//! `SqliteInventory`. Written from spec only — impl NOT consulted.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use chrono::Utc;
use tempfile::TempDir;

use vpnctl_core::{KernelId, Server, ServerId, User, UserId};
use vpnctl_inventory::{SqliteInventory, VpnStatsDelta};

fn db_path(dir: &TempDir) -> PathBuf {
    dir.path().join("inventory.db")
}

async fn open(dir: &TempDir) -> SqliteInventory {
    SqliteInventory::open(&db_path(dir)).await.expect("open")
}

fn server(id: &str) -> Server {
    Server {
        id: ServerId(id.to_string()),
        address: format!("{id}.example.com"),
        ssh_port: 22,
        ssh_user: "root".to_string(),
        kernels: vec![KernelId("sing-box".to_string())],
        enabled_protocols: vec![],
        trusted_host_fingerprint: None,
        hoster: "generic".to_string(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

fn user(id: &str) -> User {
    User {
        id: UserId(id.to_string()),
        uuid: format!("uuid-{id}"),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
    }
}

fn ud(uid: Option<&str>, up: u64, down: u64, conns: u32) -> VpnStatsDelta {
    VpnStatsDelta {
        user_id: uid.map(|s| UserId(s.to_string())),
        upload_bytes: up,
        download_bytes: down,
        active_connections: conns,
    }
}

// 1. record_vpn_stats with empty deltas inserts ZERO rows (no-op).
#[tokio::test]
async fn record_vpn_stats_empty_deltas_is_noop() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("s1")).await.unwrap();

    inv.record_vpn_stats(&ServerId("s1".into()), &[])
        .await
        .unwrap();

    let server_rows = inv
        .recent_vpn_stats_for_server(&ServerId("s1".into()), 24)
        .await
        .unwrap();
    assert!(
        server_rows.is_empty(),
        "empty deltas must insert zero rows, got: {server_rows:?}"
    );
}

// 2. record_vpn_stats sets `ts` from the daemon's wall clock at INSERT
//    time — the caller does NOT supply it. Read back the row and
//    confirm ts is "approximately now" (±5s).
#[tokio::test]
async fn record_vpn_stats_sets_ts_to_now_on_insert() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("s1")).await.unwrap();
    inv.add_user(&user("u1")).await.unwrap();

    let before = Utc::now();
    inv.record_vpn_stats(&ServerId("s1".into()), &[ud(Some("u1"), 100, 200, 1)])
        .await
        .unwrap();
    let after = Utc::now();

    let rows = inv
        .recent_vpn_stats_for_user(&UserId("u1".into()), 1)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    let ts = rows[0].ts;
    let slack = chrono::Duration::seconds(5);
    assert!(
        ts >= before - slack && ts <= after + slack,
        "ts must be approximately now (±5s); ts={ts}, before={before}, after={after}"
    );
    assert_eq!(rows[0].server_id, ServerId("s1".into()));
    assert_eq!(rows[0].user_id, Some(UserId("u1".into())));
    assert_eq!(rows[0].upload_bytes, 100);
    assert_eq!(rows[0].download_bytes, 200);
    assert_eq!(rows[0].active_connections, 1);
}

// 3. recent_vpn_stats_for_user EXCLUDES server-wide rows (user_id IS NULL).
#[tokio::test]
async fn recent_for_user_excludes_server_wide_rows() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("s1")).await.unwrap();
    inv.add_user(&user("u1")).await.unwrap();

    inv.record_vpn_stats(
        &ServerId("s1".into()),
        &[
            ud(Some("u1"), 10, 20, 1),
            ud(None, 999, 888, 7), // server-wide row
        ],
    )
    .await
    .unwrap();

    let user_rows = inv
        .recent_vpn_stats_for_user(&UserId("u1".into()), 24)
        .await
        .unwrap();
    assert_eq!(
        user_rows.len(),
        1,
        "only the per-user row should be returned"
    );
    assert_eq!(user_rows[0].user_id, Some(UserId("u1".into())));
    assert!(
        user_rows.iter().all(|r| r.user_id.is_some()),
        "recent_vpn_stats_for_user must filter out user_id IS NULL rows"
    );
}

// 4. recent_vpn_stats_for_server INCLUDES both per-user and server-wide rows.
#[tokio::test]
async fn recent_for_server_includes_both_user_and_server_wide_rows() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("s1")).await.unwrap();
    inv.add_user(&user("u1")).await.unwrap();
    inv.add_user(&user("u2")).await.unwrap();

    inv.record_vpn_stats(
        &ServerId("s1".into()),
        &[
            ud(Some("u1"), 1, 2, 1),
            ud(Some("u2"), 3, 4, 1),
            ud(None, 5, 6, 2),
        ],
    )
    .await
    .unwrap();

    let rows = inv
        .recent_vpn_stats_for_server(&ServerId("s1".into()), 24)
        .await
        .unwrap();
    assert_eq!(rows.len(), 3, "server query must include all 3 rows");
    let server_wide_count = rows.iter().filter(|r| r.user_id.is_none()).count();
    assert_eq!(server_wide_count, 1, "the NULL-user row must be present");
}

// 5. since_hours = 0 excludes everything (strict ts > now-0).
#[tokio::test]
async fn since_hours_zero_excludes_everything() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("s1")).await.unwrap();
    inv.add_user(&user("u1")).await.unwrap();

    inv.record_vpn_stats(
        &ServerId("s1".into()),
        &[ud(Some("u1"), 1, 2, 1), ud(None, 3, 4, 1)],
    )
    .await
    .unwrap();

    let user_rows = inv
        .recent_vpn_stats_for_user(&UserId("u1".into()), 0)
        .await
        .unwrap();
    assert!(
        user_rows.is_empty(),
        "since_hours=0 must return zero rows for user, got: {user_rows:?}"
    );

    let server_rows = inv
        .recent_vpn_stats_for_server(&ServerId("s1".into()), 0)
        .await
        .unwrap();
    assert!(
        server_rows.is_empty(),
        "since_hours=0 must return zero rows for server, got: {server_rows:?}"
    );
}

// 6. Both recent_* methods sort newest-first.
#[tokio::test]
async fn recent_methods_sort_newest_first() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("s1")).await.unwrap();
    inv.add_user(&user("u1")).await.unwrap();

    // Three separate ticks, separated by enough wall-clock to make
    // the ordering deterministic in TEXT-sorted ISO-8601.
    for i in 0u64..3 {
        inv.record_vpn_stats(&ServerId("s1".into()), &[ud(Some("u1"), i + 1, 0, 0)])
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    let user_rows = inv
        .recent_vpn_stats_for_user(&UserId("u1".into()), 24)
        .await
        .unwrap();
    assert_eq!(user_rows.len(), 3);
    for w in user_rows.windows(2) {
        assert!(
            w[0].ts >= w[1].ts,
            "user rows must be newest-first; got {:?} then {:?}",
            w[0].ts,
            w[1].ts
        );
    }

    let server_rows = inv
        .recent_vpn_stats_for_server(&ServerId("s1".into()), 24)
        .await
        .unwrap();
    assert_eq!(server_rows.len(), 3);
    for w in server_rows.windows(2) {
        assert!(
            w[0].ts >= w[1].ts,
            "server rows must be newest-first; got {:?} then {:?}",
            w[0].ts,
            w[1].ts
        );
    }
}

// 7. user_id has NO foreign key — recording a row for a user that
//    doesn't exist in `users` table must SUCCEED (forensics survive
//    rename/delete).
#[tokio::test]
async fn record_vpn_stats_for_unknown_user_succeeds_no_fk_on_user_id() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("s1")).await.unwrap();
    // Note: NOT adding "ghost" to users.

    inv.record_vpn_stats(&ServerId("s1".into()), &[ud(Some("ghost"), 7, 8, 1)])
        .await
        .expect("user_id has no FK; row must persist even for unknown user");

    let rows = inv
        .recent_vpn_stats_for_user(&UserId("ghost".into()), 24)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].user_id, Some(UserId("ghost".into())));
}

// 8. Expected-failure path: server_id has FK — recording for a server
//    that does NOT exist must fail.
#[tokio::test]
async fn record_vpn_stats_for_unknown_server_fails() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    // Deliberately do not add "ghost-server".

    let res = inv
        .record_vpn_stats(&ServerId("ghost-server".into()), &[ud(None, 1, 2, 1)])
        .await;
    assert!(
        res.is_err(),
        "FK on server_id must reject inserts for unknown server, got: {res:?}"
    );
}

// 9. CASCADE: removing a server drops its vpn_connection_stats rows.
#[tokio::test]
async fn remove_server_cascades_vpn_connection_stats() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("s1")).await.unwrap();
    inv.add_server(&server("s2")).await.unwrap();
    inv.add_user(&user("u1")).await.unwrap();

    inv.record_vpn_stats(
        &ServerId("s1".into()),
        &[ud(Some("u1"), 1, 2, 1), ud(None, 3, 4, 1)],
    )
    .await
    .unwrap();
    inv.record_vpn_stats(&ServerId("s2".into()), &[ud(Some("u1"), 5, 6, 1)])
        .await
        .unwrap();

    // Sanity: u1 has rows from BOTH servers.
    let pre = inv
        .recent_vpn_stats_for_user(&UserId("u1".into()), 24)
        .await
        .unwrap();
    assert_eq!(pre.len(), 2);

    inv.remove_server(&ServerId("s1".into())).await.unwrap();

    let s1_rows = inv
        .recent_vpn_stats_for_server(&ServerId("s1".into()), 24)
        .await
        .unwrap();
    assert!(
        s1_rows.is_empty(),
        "CASCADE must drop all stats rows for s1, got: {s1_rows:?}"
    );
    let post_user = inv
        .recent_vpn_stats_for_user(&UserId("u1".into()), 24)
        .await
        .unwrap();
    assert_eq!(
        post_user.len(),
        1,
        "after dropping s1, u1 must only have the s2 row left"
    );
    assert_eq!(post_user[0].server_id, ServerId("s2".into()));
}

// 10. purge_vpn_stats_older_than removes only old rows; returns the
//     correct count; recent rows survive (boundary).
#[tokio::test]
async fn purge_vpn_stats_older_than_boundary() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("s1")).await.unwrap();
    inv.add_user(&user("u1")).await.unwrap();

    // A "recent" row written by record_vpn_stats (ts = now).
    inv.record_vpn_stats(&ServerId("s1".into()), &[ud(Some("u1"), 1, 2, 1)])
        .await
        .unwrap();

    // Purging anything older than 30 days must remove ZERO rows since
    // our only row is brand new.
    let removed = inv.purge_vpn_stats_older_than(30).await.unwrap();
    assert_eq!(
        removed, 0,
        "no rows should match 'older than 30 days' when the only row is now"
    );
    let still_there = inv
        .recent_vpn_stats_for_user(&UserId("u1".into()), 24)
        .await
        .unwrap();
    assert_eq!(
        still_there.len(),
        1,
        "recent row must survive purge_vpn_stats_older_than(30)"
    );

    // Purging "older than 0 days" must remove the recent row (ts < now-0
    // only false in the limit; spec says strictly older — check for ALL
    // existing rows). The conservative interpretation: days=0 sweeps
    // every row whose ts < now, which is all of them after a tiny sleep.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let removed_all = inv.purge_vpn_stats_older_than(0).await.unwrap();
    assert_eq!(
        removed_all, 1,
        "purge with days=0 must drop the single existing row, got removed={removed_all}"
    );
    let after = inv
        .recent_vpn_stats_for_user(&UserId("u1".into()), 24)
        .await
        .unwrap();
    assert!(
        after.is_empty(),
        "after purging everything, the user query must return empty"
    );
}

// 11. record_vpn_stats is atomic: when it succeeds, EVERY delta is
//     visible. (We can't easily force a mid-tx failure without injecting
//     impl details, so we assert all-or-nothing on the happy path: a
//     batch of N deltas yields exactly N rows readable post-call.)
#[tokio::test]
async fn record_vpn_stats_atomicity_all_deltas_visible() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("s1")).await.unwrap();
    for uid in ["u1", "u2", "u3"] {
        inv.add_user(&user(uid)).await.unwrap();
    }

    inv.record_vpn_stats(
        &ServerId("s1".into()),
        &[
            ud(Some("u1"), 1, 1, 1),
            ud(Some("u2"), 2, 2, 1),
            ud(Some("u3"), 3, 3, 1),
            ud(None, 6, 6, 3),
        ],
    )
    .await
    .unwrap();

    let server_rows = inv
        .recent_vpn_stats_for_server(&ServerId("s1".into()), 24)
        .await
        .unwrap();
    assert_eq!(
        server_rows.len(),
        4,
        "all 4 deltas from one record_vpn_stats call must land atomically"
    );
}
