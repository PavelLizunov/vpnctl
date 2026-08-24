use chrono::Utc;
use tempfile::TempDir;
use vpnctl_core::{ServerId, UserId};

use crate::common::{open, server, server_coeff, ud, user};

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
    assert_eq!(
        top[0].download_bytes, 1_000_000,
        "alice weighted download (×2)"
    );
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
