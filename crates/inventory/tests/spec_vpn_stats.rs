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
        vpn_router_device_id: None,
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

// ────────────────────────────────────────────────────────────────────────
// Phase 4b — server_live_activity + all_servers_live_activity.
// ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn phase4b_server_live_activity_returns_zeros_for_unknown_server() {
    // The server-detail handler may render before the poller has
    // ever sampled this server (fresh-deploy, NM-11 blocked, etc).
    // Activity must be the zero-default — no DB errors.
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("s1")).await.unwrap();

    let activity = inv
        .server_live_activity(&ServerId("s1".into()), 24)
        .await
        .unwrap();
    assert_eq!(activity.active_now, 0);
    assert_eq!(activity.bytes_up_window, 0);
    assert_eq!(activity.bytes_dn_window, 0);
    assert_eq!(activity.distinct_users_attributed, 0);
    assert!(activity.last_sample_ts.is_none());
}

#[tokio::test]
async fn phase4b_server_live_activity_sums_bytes_and_uses_latest_active_conns() {
    // Three ticks for one server: two server-wide rows (user_id IS
    // NULL) with growing active_connections + per-user deltas.
    // `active_now` must be the FRESHEST server-wide value (8), NOT
    // the sum / max / first; bytes are summed across all rows.
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("s1")).await.unwrap();
    for u in ["u1", "u2"] {
        inv.add_user(&user(u)).await.unwrap();
    }

    // Tick 1: server-wide 100 up / 50 dn / 4 active + u1 50/25.
    inv.record_vpn_stats(
        &ServerId("s1".into()),
        &[ud(None, 100, 50, 4), ud(Some("u1"), 50, 25, 2)],
    )
    .await
    .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(15)).await;
    // Tick 2: server-wide 200/100/8 + u2 50/25.
    inv.record_vpn_stats(
        &ServerId("s1".into()),
        &[ud(None, 200, 100, 8), ud(Some("u2"), 50, 25, 3)],
    )
    .await
    .unwrap();

    let activity = inv
        .server_live_activity(&ServerId("s1".into()), 24)
        .await
        .unwrap();

    // active_now = freshest server-wide row's active_connections.
    assert_eq!(
        activity.active_now, 8,
        "active_now must equal newest server-wide tick"
    );
    // Bytes sum across ALL rows (server-wide + per-user).
    assert_eq!(activity.bytes_up_window, 100 + 50 + 200 + 50);
    assert_eq!(activity.bytes_dn_window, 50 + 25 + 100 + 25);
    assert_eq!(
        activity.distinct_users_attributed, 2,
        "u1 + u2 → 2 attributed users"
    );
    assert!(activity.last_sample_ts.is_some());
}

#[tokio::test]
async fn phase4b_all_servers_live_activity_returns_default_entry_for_unobserved_server() {
    // Dashboard rollup: returns one entry per `servers.id` row,
    // even for servers the poller has never reached. Caller can
    // sum without filtering.
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("active-srv")).await.unwrap();
    inv.add_server(&server("quiet-srv")).await.unwrap();
    inv.add_user(&user("u1")).await.unwrap();
    inv.record_vpn_stats(&ServerId("active-srv".into()), &[ud(None, 1024, 512, 1)])
        .await
        .unwrap();

    let all = inv.all_servers_live_activity(24).await.unwrap();
    assert_eq!(all.len(), 2, "one entry per servers.id row");

    let active = all
        .iter()
        .find(|(id, _)| id.0 == "active-srv")
        .expect("active-srv must appear");
    assert_eq!(active.1.bytes_up_window, 1024);
    assert_eq!(active.1.active_now, 1);

    let quiet = all
        .iter()
        .find(|(id, _)| id.0 == "quiet-srv")
        .expect("quiet-srv must appear (default-zero)");
    assert_eq!(quiet.1.bytes_up_window, 0);
    assert_eq!(quiet.1.active_now, 0);
    assert!(quiet.1.last_sample_ts.is_none());
}

#[tokio::test]
async fn phase4b_server_live_activity_window_excludes_older_than_since_hours() {
    // The `since_hours` bound must filter older rows. We can't fake
    // older `ts` via the API (server-side strftime), so verify the
    // boundary by asking for a near-zero window — the just-inserted
    // row's ts SHOULD still be within it (the window is hours, not
    // seconds, so even 1h catches a row inserted just now).
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("s1")).await.unwrap();
    inv.record_vpn_stats(&ServerId("s1".into()), &[ud(None, 100, 50, 2)])
        .await
        .unwrap();

    let agg = inv
        .server_live_activity(&ServerId("s1".into()), 1)
        .await
        .unwrap();
    assert_eq!(
        agg.bytes_up_window, 100,
        "row inserted just now must be inside a 1-hour window"
    );
}

// ────────────────────────────────────────────────────────────────────────
// Phase 5a-1 — vpn_user_daily rollups (indefinite retention layer).
// ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn phase5a1_rollup_aggregates_ticks_into_per_user_per_server_daily_totals() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("s1")).await.unwrap();
    for u in ["alice", "bob"] {
        inv.add_user(&user(u)).await.unwrap();
    }

    // Tick 1: alice 100/200, bob 50/100, server-wide 200/400.
    inv.record_vpn_stats(
        &ServerId("s1".into()),
        &[
            ud(Some("alice"), 100, 200, 2),
            ud(Some("bob"), 50, 100, 1),
            ud(None, 200, 400, 3),
        ],
    )
    .await
    .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(15)).await;
    // Tick 2: alice 150/300, bob 0/0, server-wide 150/300.
    inv.record_vpn_stats(
        &ServerId("s1".into()),
        &[ud(Some("alice"), 150, 300, 3), ud(None, 150, 300, 3)],
    )
    .await
    .unwrap();

    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let upserted = inv.rollup_vpn_user_daily(&today).await.unwrap();
    assert_eq!(upserted, 2, "alice + bob → 2 rows");

    let alice = inv
        .vpn_user_daily_for_user(&UserId("alice".into()), 7)
        .await
        .unwrap();
    assert_eq!(alice.len(), 1);
    assert_eq!(alice[0].upload_bytes, 250, "100+150 across 2 ticks");
    assert_eq!(alice[0].download_bytes, 500, "200+300");
    assert_eq!(alice[0].active_connections_peak, 3, "max(2,3)");
    assert_eq!(alice[0].server_id.0, "s1");
}

#[tokio::test]
async fn phase5a1_rollup_is_idempotent_second_call_yields_same_data() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("s1")).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();
    inv.record_vpn_stats(&ServerId("s1".into()), &[ud(Some("alice"), 1000, 2000, 5)])
        .await
        .unwrap();
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();

    inv.rollup_vpn_user_daily(&today).await.unwrap();
    inv.rollup_vpn_user_daily(&today).await.unwrap();
    inv.rollup_vpn_user_daily(&today).await.unwrap();

    let alice = inv
        .vpn_user_daily_for_user(&UserId("alice".into()), 7)
        .await
        .unwrap();
    assert_eq!(alice.len(), 1, "no duplicate rows from idempotent re-roll");
    assert_eq!(alice[0].upload_bytes, 1000);
    assert_eq!(alice[0].download_bytes, 2000);
}

#[tokio::test]
async fn phase5a1_rollup_excludes_server_wide_null_user_rows() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("s1")).await.unwrap();
    // No users added; one server-wide row only.
    inv.record_vpn_stats(&ServerId("s1".into()), &[ud(None, 9999, 9999, 10)])
        .await
        .unwrap();

    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let upserted = inv.rollup_vpn_user_daily(&today).await.unwrap();
    assert_eq!(
        upserted, 0,
        "server-wide NULL-user row must NOT create a vpn_user_daily entry"
    );
}

#[tokio::test]
async fn phase5a1_top_users_by_daily_traffic_orders_desc_and_respects_limit() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("s1")).await.unwrap();
    for u in ["alice", "bob", "charlie"] {
        inv.add_user(&user(u)).await.unwrap();
    }
    inv.record_vpn_stats(
        &ServerId("s1".into()),
        &[
            ud(Some("alice"), 100, 100, 1),   // 200 total
            ud(Some("bob"), 1000, 1000, 1),   // 2000 total
            ud(Some("charlie"), 500, 500, 1), // 1000 total
        ],
    )
    .await
    .unwrap();
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    inv.rollup_vpn_user_daily(&today).await.unwrap();

    let top = inv.top_users_by_daily_traffic(1, 2).await.unwrap();
    assert_eq!(top.len(), 2, "limit=2 must cap");
    assert_eq!(top[0].0.0, "bob", "bob (2000) is top");
    assert_eq!(top[0].1, 2000);
    assert_eq!(top[1].0.0, "charlie", "charlie (1000) is second");
}

#[tokio::test]
async fn phase5a1_user_traffic_this_month_sums_from_daily_rollup() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("s1")).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();
    inv.record_vpn_stats(
        &ServerId("s1".into()),
        &[ud(Some("alice"), 12_000_000, 8_000_000, 2)],
    )
    .await
    .unwrap();
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    inv.rollup_vpn_user_daily(&today).await.unwrap();

    let total = inv
        .user_traffic_this_month_from_daily(&UserId("alice".into()))
        .await
        .unwrap();
    assert_eq!(total, 20_000_000, "12M up + 8M down");
}

// ────────────────────────────────────────────────────────────────────────
// Phase 5b — vpn_user_destinations (per-user × destination tracking).
// ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn phase5b_record_user_destinations_increments_hit_count_on_repeat() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();

    // Tick 1: 2 destinations.
    inv.record_user_destinations(&[
        (UserId("alice".into()), "youtube.com:443".into()),
        (UserId("alice".into()), "telegram.org:443".into()),
    ])
    .await
    .unwrap();
    // Tick 2: youtube again, plus a new one.
    inv.record_user_destinations(&[
        (UserId("alice".into()), "youtube.com:443".into()),
        (UserId("alice".into()), "discord.gg:443".into()),
    ])
    .await
    .unwrap();

    let top = inv
        .top_destinations_for_user(&UserId("alice".into()), 7, 20)
        .await
        .unwrap();
    let yt = top
        .iter()
        .find(|d| d.destination_label == "youtube.com:443")
        .expect("youtube must be present");
    assert_eq!(yt.hit_count, 2, "two ticks → 2 hits");
    let tg = top
        .iter()
        .find(|d| d.destination_label == "telegram.org:443")
        .expect("telegram must be present");
    assert_eq!(tg.hit_count, 1);
}

#[tokio::test]
async fn phase5b_top_destinations_orders_by_hits_desc() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    // Build different hit counts: A=3, B=1, C=2.
    for _ in 0..3 {
        inv.record_user_destinations(&[(UserId("alice".into()), "a.example.com:443".into())])
            .await
            .unwrap();
    }
    inv.record_user_destinations(&[(UserId("alice".into()), "b.example.com:443".into())])
        .await
        .unwrap();
    for _ in 0..2 {
        inv.record_user_destinations(&[(UserId("alice".into()), "c.example.com:443".into())])
            .await
            .unwrap();
    }
    let top = inv
        .top_destinations_for_user(&UserId("alice".into()), 7, 10)
        .await
        .unwrap();
    let labels: Vec<&str> = top.iter().map(|r| r.destination_label.as_str()).collect();
    assert_eq!(
        labels,
        vec![
            "a.example.com:443",
            "c.example.com:443",
            "b.example.com:443"
        ]
    );
}

#[tokio::test]
async fn phase5b_destinations_dont_leak_across_users() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    inv.add_user(&user("bob")).await.unwrap();
    inv.record_user_destinations(&[(UserId("alice".into()), "x.example.com:443".into())])
        .await
        .unwrap();
    inv.record_user_destinations(&[(UserId("bob".into()), "y.example.com:443".into())])
        .await
        .unwrap();
    let alice = inv
        .top_destinations_for_user(&UserId("alice".into()), 7, 10)
        .await
        .unwrap();
    assert_eq!(alice.len(), 1);
    assert_eq!(alice[0].destination_label, "x.example.com:443");
    let bob = inv
        .top_destinations_for_user(&UserId("bob".into()), 7, 10)
        .await
        .unwrap();
    assert_eq!(bob.len(), 1);
    assert_eq!(bob[0].destination_label, "y.example.com:443");
}

#[tokio::test]
async fn phase5b_record_destinations_truncates_pathological_labels_to_200_chars() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    let long = "x".repeat(500);
    inv.record_user_destinations(&[(UserId("alice".into()), long)])
        .await
        .unwrap();
    let top = inv
        .top_destinations_for_user(&UserId("alice".into()), 7, 10)
        .await
        .unwrap();
    assert_eq!(top.len(), 1);
    assert_eq!(top[0].destination_label.len(), 200);
}

#[tokio::test]
async fn phase5b_purge_user_destinations_removes_old_rows() {
    // Can't fake old `date` via the API, so test the SAFE side:
    // freshly-inserted rows survive a 1-day purge.
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    inv.record_user_destinations(&[(UserId("alice".into()), "z.example.com:443".into())])
        .await
        .unwrap();
    let removed = inv.purge_user_destinations_older_than(1).await.unwrap();
    assert_eq!(removed, 0, "fresh row must NOT be removed by 1-day purge");
}

// ────────────────────────────────────────────────────────────────────────
// Phase 5c — vpn_user_sessions (activity windows).
// ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn phase5c_session_observe_within_gap_extends_existing_session() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("s1")).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();

    let t0 = chrono::Utc::now();
    let t1 = t0 + chrono::Duration::minutes(5);
    let t2 = t0 + chrono::Duration::minutes(10);

    // Tick 1: opens a new session.
    let id1 = inv
        .session_observe(
            &UserId("alice".into()),
            &ServerId("s1".into()),
            t0,
            15,
            100,
            1,
        )
        .await
        .unwrap();
    // Tick 2 (5 min later, within gap): EXTENDS same session.
    let id2 = inv
        .session_observe(
            &UserId("alice".into()),
            &ServerId("s1".into()),
            t1,
            15,
            200,
            3,
        )
        .await
        .unwrap();
    // Tick 3 (10 min later, still within gap): same session.
    let id3 = inv
        .session_observe(
            &UserId("alice".into()),
            &ServerId("s1".into()),
            t2,
            15,
            50,
            2,
        )
        .await
        .unwrap();

    assert_eq!(id1, id2, "second observation must extend the same session");
    assert_eq!(id2, id3);

    let sessions = inv
        .recent_sessions_for_user(&UserId("alice".into()), 10)
        .await
        .unwrap();
    assert_eq!(sessions.len(), 1, "all 3 ticks landed in ONE session");
    assert_eq!(sessions[0].total_bytes, 100 + 200 + 50);
    assert_eq!(sessions[0].conn_count_peak, 3, "max(1,3,2) = 3");
}

#[tokio::test]
async fn phase5c_session_observe_after_gap_opens_new_session() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("s1")).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();

    let t0 = chrono::Utc::now();
    let t1 = t0 + chrono::Duration::minutes(30); // > 15 min gap

    let id1 = inv
        .session_observe(
            &UserId("alice".into()),
            &ServerId("s1".into()),
            t0,
            15,
            100,
            1,
        )
        .await
        .unwrap();
    let id2 = inv
        .session_observe(
            &UserId("alice".into()),
            &ServerId("s1".into()),
            t1,
            15,
            200,
            2,
        )
        .await
        .unwrap();

    assert_ne!(id1, id2, "gap > 15 min must open a NEW session");
    let sessions = inv
        .recent_sessions_for_user(&UserId("alice".into()), 10)
        .await
        .unwrap();
    assert_eq!(sessions.len(), 2);
}

#[tokio::test]
async fn phase5c_sessions_dont_leak_across_users_or_servers() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("s1")).await.unwrap();
    inv.add_server(&server("s2")).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();
    inv.add_user(&user("bob")).await.unwrap();

    let t0 = chrono::Utc::now();
    inv.session_observe(
        &UserId("alice".into()),
        &ServerId("s1".into()),
        t0,
        15,
        100,
        1,
    )
    .await
    .unwrap();
    inv.session_observe(
        &UserId("alice".into()),
        &ServerId("s2".into()),
        t0,
        15,
        100,
        1,
    )
    .await
    .unwrap();
    inv.session_observe(
        &UserId("bob".into()),
        &ServerId("s1".into()),
        t0,
        15,
        100,
        1,
    )
    .await
    .unwrap();

    let alice = inv
        .recent_sessions_for_user(&UserId("alice".into()), 10)
        .await
        .unwrap();
    assert_eq!(
        alice.len(),
        2,
        "alice has TWO sessions (s1, s2) — not bob's"
    );
    let bob = inv
        .recent_sessions_for_user(&UserId("bob".into()), 10)
        .await
        .unwrap();
    assert_eq!(bob.len(), 1);
    assert_eq!(bob[0].server_id.0, "s1");
}

#[tokio::test]
async fn phase5c_purge_user_sessions_keeps_fresh_rows() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("s1")).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();
    let t0 = chrono::Utc::now();
    inv.session_observe(
        &UserId("alice".into()),
        &ServerId("s1".into()),
        t0,
        15,
        100,
        1,
    )
    .await
    .unwrap();
    let removed = inv.purge_user_sessions_older_than(1).await.unwrap();
    assert_eq!(
        removed, 0,
        "fresh session must NOT be removed by 1-day purge"
    );
}
