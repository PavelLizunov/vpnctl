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

/// Like `server`, but with an explicit Marzban-style traffic
/// multiplier so the usage-coefficient weighting can be exercised.
fn server_coeff(id: &str, usage_coefficient: f64) -> Server {
    Server {
        usage_coefficient,
        ..server(id)
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
        disabled: false,
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
    // Multibyte label: "中" is 3 bytes, so byte index 200 lands MID-codepoint.
    // The pre-#32 `&dest[..200]` byte-slice would PANIC here; char-boundary
    // truncation (`.chars().take(200)`) must not — this makes the test
    // discriminating rather than tautological (an ASCII "x".repeat would cut
    // cleanly at byte 200 and pass even against the buggy byte-slice).
    let long = "中".repeat(250); // 750 bytes, 250 chars
    assert!(
        !long.is_char_boundary(200),
        "test premise: byte 200 must be mid-codepoint"
    );
    inv.record_user_destinations(&[(UserId("alice".into()), long)])
        .await
        .unwrap(); // must NOT panic
    let top = inv
        .top_destinations_for_user(&UserId("alice".into()), 7, 10)
        .await
        .unwrap();
    assert_eq!(top.len(), 1);
    // Truncated to 200 CHARS (not 200 bytes) on a valid char boundary.
    assert_eq!(top[0].destination_label.chars().count(), 200);
    assert_eq!(top[0].destination_label, "中".repeat(200));
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

// ────────────────────────────────────────────────────────────────────────
// Round-4 — usage_coefficient (Marzban traffic multiplier) is APPLIED to
// traffic accounting. Previously stored/displayed but inert (×1 always).
// ────────────────────────────────────────────────────────────────────────

// user_traffic_this_month weights raw-tick bytes by the server's
// usage_coefficient: N bytes on a ×2 node → 2N reported; ×1 node → N
// (identity, no change for existing deployments).
#[tokio::test]
async fn user_traffic_this_month_applies_usage_coefficient() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server_coeff("double", 2.0)).await.unwrap();
    inv.add_server(&server_coeff("single", 1.0)).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();
    inv.add_user(&user("bob")).await.unwrap();

    // alice: 1_000_000 raw bytes on the ×2 node → 2_000_000 weighted.
    inv.record_vpn_stats(
        &ServerId("double".into()),
        &[ud(Some("alice"), 600_000, 400_000, 1)],
    )
    .await
    .unwrap();
    // bob: 1_000_000 raw bytes on the ×1 node → 1_000_000 (identity).
    inv.record_vpn_stats(
        &ServerId("single".into()),
        &[ud(Some("bob"), 600_000, 400_000, 1)],
    )
    .await
    .unwrap();

    let alice = inv
        .user_traffic_this_month(&UserId("alice".into()))
        .await
        .unwrap();
    let bob = inv
        .user_traffic_this_month(&UserId("bob".into()))
        .await
        .unwrap();
    assert_eq!(alice, 2_000_000, "1M raw bytes on a ×2 node counts as 2M");
    assert_eq!(bob, 1_000_000, "×1 node is the identity — unchanged");
}

// users_traffic_vs_limit weights month-to-date usage by coefficient: a
// user UNDER their raw-byte limit but OVER it once weighted is reported
// at the weighted (over-limit) figure.
#[tokio::test]
async fn users_traffic_vs_limit_weights_by_coefficient() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server_coeff("double", 2.0)).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();

    // 1_500_000 raw bytes on a ×2 node → 3_000_000 weighted.
    inv.record_vpn_stats(
        &ServerId("double".into()),
        &[ud(Some("alice"), 1_000_000, 500_000, 1)],
    )
    .await
    .unwrap();
    // Limit = 2_000_000: raw usage (1.5M) is UNDER it, weighted (3M) is OVER.
    inv.set_user_traffic_limit(&UserId("alice".into()), Some(2_000_000), Some(80))
        .await
        .unwrap();

    let rows = inv.users_traffic_vs_limit().await.unwrap();
    let alice = rows
        .iter()
        .find(|r| r.0.0 == "alice")
        .expect("alice has a configured limit so she must appear");
    let (_, used, lim, _) = alice;
    assert_eq!(*lim, 2_000_000);
    assert_eq!(*used, 3_000_000, "1.5M raw × coeff 2.0 = 3M weighted");
    assert!(
        *used > *lim,
        "weighted usage must exceed the limit (raw bytes alone would not)"
    );
}

// top_users_by_traffic ranks by COEFFICIENT-WEIGHTED bytes: a ×2 user
// outranks an equal-raw-bytes ×1 user.
#[tokio::test]
async fn top_users_by_traffic_ranks_by_weighted_bytes() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server_coeff("double", 2.0)).await.unwrap();
    inv.add_server(&server_coeff("single", 1.0)).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();
    inv.add_user(&user("bob")).await.unwrap();

    // Equal RAW bytes (1_000_000 each), but alice is on the ×2 node.
    inv.record_vpn_stats(
        &ServerId("double".into()),
        &[ud(Some("alice"), 500_000, 500_000, 1)],
    )
    .await
    .unwrap();
    inv.record_vpn_stats(
        &ServerId("single".into()),
        &[ud(Some("bob"), 500_000, 500_000, 1)],
    )
    .await
    .unwrap();

    let top = inv.top_users_by_traffic(24, 10).await.unwrap();
    assert_eq!(top.len(), 2);
    assert_eq!(
        top[0].user_id.0, "alice",
        "alice (×2 → 2M weighted) must outrank bob (×1 → 1M) despite equal raw bytes"
    );
    assert_eq!(top[0].total_bytes, 2_000_000, "alice weighted total");
    // 2026-06-16 — upload / download are now summed separately for the
    // three-column dashboard tile, each weighted, and total == up + down.
    assert_eq!(top[0].upload_bytes, 1_000_000, "alice weighted upload (×2)");
    assert_eq!(top[0].download_bytes, 1_000_000, "alice weighted download (×2)");
    assert_eq!(
        top[0].upload_bytes + top[0].download_bytes,
        top[0].total_bytes,
        "total must equal upload + download exactly"
    );
    assert_eq!(top[1].user_id.0, "bob");
    assert_eq!(top[1].total_bytes, 1_000_000, "bob ×1 identity");
    assert_eq!(top[1].upload_bytes, 500_000, "bob ×1 upload");
    assert_eq!(top[1].download_bytes, 500_000, "bob ×1 download");
}

// top_users_by_daily_traffic (vpn_user_daily path) is weighted the same
// way as the raw-tick path: a ×2 user outranks an equal-raw-bytes ×1 user.
#[tokio::test]
async fn top_users_by_daily_traffic_ranks_by_weighted_bytes() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server_coeff("double", 2.0)).await.unwrap();
    inv.add_server(&server_coeff("single", 1.0)).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();
    inv.add_user(&user("bob")).await.unwrap();

    inv.record_vpn_stats(
        &ServerId("double".into()),
        &[ud(Some("alice"), 500_000, 500_000, 1)],
    )
    .await
    .unwrap();
    inv.record_vpn_stats(
        &ServerId("single".into()),
        &[ud(Some("bob"), 500_000, 500_000, 1)],
    )
    .await
    .unwrap();
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    inv.rollup_vpn_user_daily(&today).await.unwrap();

    let top = inv.top_users_by_daily_traffic(1, 10).await.unwrap();
    assert_eq!(top.len(), 2);
    assert_eq!(
        top[0].0.0, "alice",
        "alice (×2 → 2M) outranks bob (×1 → 1M) on the daily-rollup path too"
    );
    assert_eq!(top[0].1, 2_000_000);
    assert_eq!(top[1].0.0, "bob");
    assert_eq!(top[1].1, 1_000_000);
}

// attribution_stall_servers: a server is "stalled" iff, within the
// window, its MAX(active_connections) >= min_active AND it attributed
// ZERO distinct users (every stats row had a NULL user_id). Servers with
// at least one attributed user, or below the active floor, are excluded.
#[tokio::test]
async fn attribution_stall_servers_flags_only_active_unattributed_nodes() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    for s in ["stall", "ok", "idle"] {
        inv.add_server(&server(s)).await.unwrap();
    }
    inv.add_user(&user("alice")).await.unwrap();

    // "stall": 10 active conns, only a server-wide (NULL-user) row → 0
    // attributed users. This is the silent-break signature.
    inv.record_vpn_stats(&ServerId("stall".into()), &[ud(None, 1000, 2000, 10)])
        .await
        .unwrap();
    // "ok": same 10 active conns, but a real user IS attributed → healthy.
    inv.record_vpn_stats(
        &ServerId("ok".into()),
        &[ud(None, 1000, 2000, 10), ud(Some("alice"), 5, 5, 3)],
    )
    .await
    .unwrap();
    // "idle": 0 attributed users, but only 2 active conns (< floor of 5)
    // → a near-idle node must NOT be flagged.
    inv.record_vpn_stats(&ServerId("idle".into()), &[ud(None, 10, 10, 2)])
        .await
        .unwrap();

    let stalled = inv.attribution_stall_servers(60, 5).await.unwrap();
    let ids: Vec<&str> = stalled.iter().map(|s| s.0.as_str()).collect();
    assert_eq!(
        ids,
        vec!["stall"],
        "only the active-but-unattributed node must be flagged; got {ids:?}"
    );
}

// attribution_stall_servers honours the time window: rows older than the
// window are ignored entirely, so a node whose only (unattributed) rows
// fall outside the window is NOT flagged.
#[tokio::test]
async fn attribution_stall_servers_ignores_rows_outside_window() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("stall")).await.unwrap();
    inv.record_vpn_stats(&ServerId("stall".into()), &[ud(None, 1000, 2000, 10)])
        .await
        .unwrap();

    // A 0-minute window excludes the just-written row (ts <= now), so the
    // node falls out of the candidate set.
    let stalled = inv.attribution_stall_servers(0, 5).await.unwrap();
    assert!(
        stalled.is_empty(),
        "rows at/after the window edge must be excluded; got {stalled:?}"
    );
}

// ────────────────────────────────────────────────────────────────────
// vpn_user_source_ips (2026-06-14) — per-user × source-IP tracking.
// Mirrors the vpn_user_destinations spec above.
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn source_ips_increment_hit_count_on_repeat() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    // Tick 1: two IPs.
    inv.record_user_source_ips(&[
        (UserId("alice".into()), "1.2.3.4".into()),
        (UserId("alice".into()), "5.6.7.8".into()),
    ])
    .await
    .unwrap();
    // Tick 2: first IP again + a new one.
    inv.record_user_source_ips(&[
        (UserId("alice".into()), "1.2.3.4".into()),
        (UserId("alice".into()), "9.9.9.9".into()),
    ])
    .await
    .unwrap();
    let top = inv
        .top_source_ips_for_user(&UserId("alice".into()), 7, 20)
        .await
        .unwrap();
    assert_eq!(top.len(), 3, "three distinct IPs total");
    let a = top
        .iter()
        .find(|r| r.source_ip == "1.2.3.4")
        .expect("1.2.3.4 present");
    assert_eq!(a.hit_count, 2, "two ticks → 2 hits");
    let b = top
        .iter()
        .find(|r| r.source_ip == "5.6.7.8")
        .expect("5.6.7.8 present");
    assert_eq!(b.hit_count, 1);
}

#[tokio::test]
async fn top_source_ips_orders_by_hits_desc() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    // A=3, B=1, C=2 hits → expect A, C, B.
    for _ in 0..3 {
        inv.record_user_source_ips(&[(UserId("alice".into()), "10.0.0.1".into())])
            .await
            .unwrap();
    }
    inv.record_user_source_ips(&[(UserId("alice".into()), "10.0.0.2".into())])
        .await
        .unwrap();
    for _ in 0..2 {
        inv.record_user_source_ips(&[(UserId("alice".into()), "10.0.0.3".into())])
            .await
            .unwrap();
    }
    let top = inv
        .top_source_ips_for_user(&UserId("alice".into()), 7, 10)
        .await
        .unwrap();
    let ips: Vec<&str> = top.iter().map(|r| r.source_ip.as_str()).collect();
    assert_eq!(ips, vec!["10.0.0.1", "10.0.0.3", "10.0.0.2"]);
}

#[tokio::test]
async fn source_ips_skip_empty_ip_and_unknown_user() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    // Empty IP (real user) → skipped; unknown user (real IP) →
    // FK-guarded skip; the one valid pair survives.
    inv.record_user_source_ips(&[
        (UserId("alice".into()), String::new()),
        (UserId("ghost".into()), "1.1.1.1".into()),
        (UserId("alice".into()), "2.2.2.2".into()),
    ])
    .await
    .unwrap();
    let alice = inv
        .top_source_ips_for_user(&UserId("alice".into()), 7, 10)
        .await
        .unwrap();
    assert_eq!(alice.len(), 1, "only the non-empty IP for a real user");
    assert_eq!(alice[0].source_ip, "2.2.2.2");
    let ghost = inv
        .top_source_ips_for_user(&UserId("ghost".into()), 7, 10)
        .await
        .unwrap();
    assert!(ghost.is_empty(), "unknown user must never get a row");
}

#[tokio::test]
async fn source_ips_dont_leak_across_users() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    inv.add_user(&user("bob")).await.unwrap();
    inv.record_user_source_ips(&[(UserId("alice".into()), "1.1.1.1".into())])
        .await
        .unwrap();
    inv.record_user_source_ips(&[(UserId("bob".into()), "2.2.2.2".into())])
        .await
        .unwrap();
    let alice = inv
        .top_source_ips_for_user(&UserId("alice".into()), 7, 10)
        .await
        .unwrap();
    assert_eq!(alice.len(), 1);
    assert_eq!(alice[0].source_ip, "1.1.1.1");
    let bob = inv
        .top_source_ips_for_user(&UserId("bob".into()), 7, 10)
        .await
        .unwrap();
    assert_eq!(bob.len(), 1);
    assert_eq!(bob[0].source_ip, "2.2.2.2");
}

#[tokio::test]
async fn purge_user_source_ips_keeps_todays_rows() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    inv.record_user_source_ips(&[(UserId("alice".into()), "1.1.1.1".into())])
        .await
        .unwrap();
    // 30-day retention must not touch today's row.
    let removed = inv.purge_user_source_ips_older_than(30).await.unwrap();
    assert_eq!(removed, 0, "today's rows are within a 30-day window");
    let top = inv
        .top_source_ips_for_user(&UserId("alice".into()), 7, 10)
        .await
        .unwrap();
    assert_eq!(top.len(), 1, "row survives the retention sweep");
}

// geo_labels_for_ips — newest NON-NULL geo wins; un-asked IPs absent.
#[tokio::test]
async fn geo_labels_for_ips_picks_newest_nonnull_geo() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    // 1.2.3.4: an enriched row, then a later NULL-geo row — the
    // lookup must still surface DE (newest row WITH geo).
    inv.log_sub_access_rich(
        &UserId("alice".into()),
        "1.2.3.4",
        None,
        200,
        0,
        None,
        None,
        None,
        Some("DE"),
        Some("AS3320 DTAG"),
        None,
        None,
    )
    .await
    .unwrap();
    inv.log_sub_access_rich(
        &UserId("alice".into()),
        "1.2.3.4",
        None,
        200,
        0,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .await
    .unwrap();
    inv.log_sub_access_rich(
        &UserId("alice".into()),
        "9.9.9.9",
        None,
        200,
        0,
        None,
        None,
        None,
        Some("US"),
        Some("AS15169 Google"),
        None,
        None,
    )
    .await
    .unwrap();
    let map = inv
        .geo_labels_for_ips(&["1.2.3.4".into(), "9.9.9.9".into(), "8.8.8.8".into()])
        .await
        .unwrap();
    assert_eq!(
        map.get("1.2.3.4"),
        Some(&(Some("DE".to_string()), Some("AS3320 DTAG".to_string()))),
        "newest non-NULL geo wins over a later un-enriched row"
    );
    assert_eq!(
        map.get("9.9.9.9"),
        Some(&(Some("US".to_string()), Some("AS15169 Google".to_string())))
    );
    assert!(
        !map.contains_key("8.8.8.8"),
        "an IP with no sub_access_log rows is absent from the map"
    );
}
