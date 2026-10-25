use chrono::Utc;
use tempfile::TempDir;
use vpnctl_core::{ServerId, UserId};

use crate::common::{open, raw_pool, server, server_coeff, ud, user};

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

#[tokio::test]
async fn recent_for_user_excludes_server_wide_rows() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("s1")).await.unwrap();
    inv.add_user(&user("u1")).await.unwrap();

    inv.record_vpn_stats(
        &ServerId("s1".into()),
        &[ud(Some("u1"), 10, 20, 1), ud(None, 999, 888, 7)],
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

#[tokio::test]
async fn recent_methods_sort_newest_first() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("s1")).await.unwrap();
    inv.add_user(&user("u1")).await.unwrap();

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

#[tokio::test]
async fn record_vpn_stats_for_unknown_user_succeeds_no_fk_on_user_id() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("s1")).await.unwrap();

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

#[tokio::test]
async fn record_vpn_stats_for_unknown_server_fails() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    let res = inv
        .record_vpn_stats(&ServerId("ghost-server".into()), &[ud(None, 1, 2, 1)])
        .await;
    assert!(
        res.is_err(),
        "FK on server_id must reject inserts for unknown server, got: {res:?}"
    );
}

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

#[tokio::test]
async fn purge_vpn_stats_older_than_boundary() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("s1")).await.unwrap();
    inv.add_user(&user("u1")).await.unwrap();

    inv.record_vpn_stats(&ServerId("s1".into()), &[ud(Some("u1"), 1, 2, 1)])
        .await
        .unwrap();

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

#[tokio::test]
async fn raw_retention_preserves_the_longest_calendar_month_and_limit_usage() {
    use chrono::NaiveDate;
    use vpnctl_inventory::VPN_STATS_RETENTION_DAYS;

    for year in [2024, 2025] {
        for month in 1..=12 {
            let start = NaiveDate::from_ymd_opt(year, month, 1).unwrap();
            let end = if month == 12 {
                NaiveDate::from_ymd_opt(year + 1, 1, 1).unwrap()
            } else {
                NaiveDate::from_ymd_opt(year, month + 1, 1).unwrap()
            };
            assert!(i64::from(VPN_STATS_RETENTION_DAYS) > (end - start).num_days());
        }
    }

    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server_coeff("s1", 2.0)).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();
    let uid = UserId("alice".into());
    inv.set_user_traffic_limit(&uid, Some(1_000), Some(80))
        .await
        .unwrap();
    let pool = raw_pool(&dir).await;
    for offset in ["start of month", "-31 days", "-33 days"] {
        sqlx::query(
            "INSERT INTO vpn_connection_stats
             (ts, server_id, user_id, upload_bytes, download_bytes, active_connections)
             VALUES (strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1, '+1 second'), 's1', 'alice', 400, 100, 0)",
        )
        .bind(offset)
        .execute(&pool)
        .await
        .unwrap();
    }
    let before = inv.user_traffic_this_month(&uid).await.unwrap();
    let limits_before = inv.users_traffic_vs_limit().await.unwrap();
    assert_eq!(before, 1_000);
    assert_eq!(limits_before[0].1, 1_000);

    assert_eq!(
        inv.purge_vpn_stats_older_than(VPN_STATS_RETENTION_DAYS)
            .await
            .unwrap(),
        1
    );
    let retained: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vpn_connection_stats")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(retained, 2, "even the 31-day-old row must survive");
    assert_eq!(inv.user_traffic_this_month(&uid).await.unwrap(), before);
    assert_eq!(inv.users_traffic_vs_limit().await.unwrap(), limits_before);
}

#[tokio::test]
async fn server_live_activity_expires_counts_without_losing_window_bytes() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let sid = ServerId("s1".into());
    inv.add_server(&server("s1")).await.unwrap();
    inv.record_vpn_stats(&sid, &[ud(None, 100, 200, 7)])
        .await
        .unwrap();
    let pool = raw_pool(&dir).await;
    sqlx::query(
        "UPDATE vpn_connection_stats
         SET ts = strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-11 minutes')",
    )
    .execute(&pool)
    .await
    .unwrap();

    let stale = inv.server_live_activity(&sid, 24, 600).await.unwrap();
    assert_eq!(stale.active_now, None);
    assert_eq!((stale.bytes_up_window, stale.bytes_dn_window), (100, 200));
    assert!(stale.last_sample_ts.is_some());
    assert_eq!(
        inv.server_live_activity(&sid, 24, 900)
            .await
            .unwrap()
            .active_now,
        Some(7)
    );

    inv.record_vpn_stats(&sid, &[ud(None, 0, 0, 0)])
        .await
        .unwrap();
    assert_eq!(
        inv.server_live_activity(&sid, 24, 600)
            .await
            .unwrap()
            .active_now,
        Some(0)
    );
}

#[tokio::test]
async fn server_live_activity_uses_last_insert_when_sample_timestamps_match() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let sid = ServerId("s1".into());
    inv.add_server(&server("s1")).await.unwrap();
    inv.record_vpn_stats(&sid, &[ud(None, 0, 0, 7), ud(None, 0, 0, 0)])
        .await
        .unwrap();
    let pool = raw_pool(&dir).await;
    sqlx::query("UPDATE vpn_connection_stats SET ts = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        inv.server_live_activity(&sid, 24, 600)
            .await
            .unwrap()
            .active_now,
        Some(0)
    );
}

#[tokio::test]
async fn phase4b_server_live_activity_returns_zeros_for_unknown_server() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("s1")).await.unwrap();

    let activity = inv
        .server_live_activity(&ServerId("s1".into()), 24, 600)
        .await
        .unwrap();
    assert_eq!(activity.active_now, None);
    assert_eq!(activity.bytes_up_window, 0);
    assert_eq!(activity.bytes_dn_window, 0);
    assert_eq!(activity.distinct_users_attributed, 0);
    assert!(activity.last_sample_ts.is_none());
}

#[tokio::test]
async fn phase4b_server_live_activity_sums_bytes_and_uses_latest_active_conns() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("s1")).await.unwrap();
    for u in ["u1", "u2"] {
        inv.add_user(&user(u)).await.unwrap();
    }

    inv.record_vpn_stats(
        &ServerId("s1".into()),
        &[ud(None, 100, 50, 4), ud(Some("u1"), 50, 25, 2)],
    )
    .await
    .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(15)).await;
    inv.record_vpn_stats(
        &ServerId("s1".into()),
        &[ud(None, 200, 100, 8), ud(Some("u2"), 50, 25, 3)],
    )
    .await
    .unwrap();

    let activity = inv
        .server_live_activity(&ServerId("s1".into()), 24, 600)
        .await
        .unwrap();

    assert_eq!(
        activity.active_now,
        Some(8),
        "active_now must equal newest server-wide tick"
    );
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
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("active-srv")).await.unwrap();
    inv.add_server(&server("quiet-srv")).await.unwrap();
    inv.add_user(&user("u1")).await.unwrap();
    inv.record_vpn_stats(&ServerId("active-srv".into()), &[ud(None, 1024, 512, 1)])
        .await
        .unwrap();

    let all = inv.all_servers_live_activity(24, 600).await.unwrap();
    assert_eq!(all.len(), 2, "one entry per servers.id row");

    let active = all
        .iter()
        .find(|(id, _)| id.0 == "active-srv")
        .expect("active-srv must appear");
    assert_eq!(active.1.bytes_up_window, 1024);
    assert_eq!(active.1.active_now, Some(1));

    let quiet = all
        .iter()
        .find(|(id, _)| id.0 == "quiet-srv")
        .expect("quiet-srv must appear (default-zero)");
    assert_eq!(quiet.1.bytes_up_window, 0);
    assert_eq!(quiet.1.active_now, None);
    assert!(quiet.1.last_sample_ts.is_none());
}

#[tokio::test]
async fn phase4b_server_live_activity_window_excludes_older_than_since_hours() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("s1")).await.unwrap();
    inv.record_vpn_stats(&ServerId("s1".into()), &[ud(None, 100, 50, 2)])
        .await
        .unwrap();

    let agg = inv
        .server_live_activity(&ServerId("s1".into()), 1, 600)
        .await
        .unwrap();
    assert_eq!(
        agg.bytes_up_window, 100,
        "row inserted just now must be inside a 1-hour window"
    );
}

#[tokio::test]
async fn user_traffic_this_month_applies_usage_coefficient() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server_coeff("double", 2.0)).await.unwrap();
    inv.add_server(&server_coeff("single", 1.0)).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();
    inv.add_user(&user("bob")).await.unwrap();

    inv.record_vpn_stats(
        &ServerId("double".into()),
        &[ud(Some("alice"), 600_000, 400_000, 1)],
    )
    .await
    .unwrap();
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

#[tokio::test]
async fn traffic_limit_reports_only_actual_changes_including_saturation() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let uid = UserId("alice".into());
    inv.add_user(&user("alice")).await.unwrap();
    for (limit, threshold, changed) in [
        (Some(100), Some(80), true),
        (Some(100), Some(80), false),
        (Some(100), Some(75), true),
        (Some(u64::MAX), Some(75), true),
        (Some(i64::MAX as u64), Some(75), false),
        (None, None, true),
        (None, None, false),
    ] {
        assert_eq!(
            inv.set_user_traffic_limit(&uid, limit, threshold)
                .await
                .unwrap(),
            changed
        );
    }
    assert!(
        inv.set_user_traffic_limit(&UserId("missing".into()), None, None)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn concurrent_identical_traffic_limit_updates_report_one_mutation() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let uid = UserId("alice".into());
    inv.add_user(&user("alice")).await.unwrap();
    let (a, b) = tokio::join!(
        inv.set_user_traffic_limit(&uid, Some(100), Some(80)),
        inv.set_user_traffic_limit(&uid, Some(100), Some(80)),
    );
    assert_ne!(a.unwrap(), b.unwrap());
}

#[tokio::test]
async fn users_traffic_vs_limit_weights_by_coefficient() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server_coeff("double", 2.0)).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();

    inv.record_vpn_stats(
        &ServerId("double".into()),
        &[ud(Some("alice"), 1_000_000, 500_000, 1)],
    )
    .await
    .unwrap();
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

#[tokio::test]
async fn top_users_by_traffic_ranks_by_weighted_bytes() {
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

    let top = inv.top_users_by_traffic(24, 10).await.unwrap();
    assert_eq!(top.len(), 2);
    assert_eq!(
        top[0].user_id.0, "alice",
        "alice (×2 → 2M weighted) must outrank bob (×1 → 1M) despite equal raw bytes"
    );
    assert_eq!(top[0].total_bytes, 2_000_000, "alice weighted total");
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

#[tokio::test]
async fn attribution_stall_servers_flags_only_active_unattributed_nodes() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    for s in ["stall", "ok", "idle"] {
        inv.add_server(&server(s)).await.unwrap();
    }
    inv.add_user(&user("alice")).await.unwrap();

    inv.record_vpn_stats(&ServerId("stall".into()), &[ud(None, 1000, 2000, 10)])
        .await
        .unwrap();
    inv.record_vpn_stats(
        &ServerId("ok".into()),
        &[ud(None, 1000, 2000, 10), ud(Some("alice"), 5, 5, 3)],
    )
    .await
    .unwrap();
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

#[tokio::test]
async fn attribution_stall_servers_ignores_rows_outside_window() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("stall")).await.unwrap();
    inv.record_vpn_stats(&ServerId("stall".into()), &[ud(None, 1000, 2000, 10)])
        .await
        .unwrap();

    let stalled = inv.attribution_stall_servers(0, 5).await.unwrap();
    assert!(
        stalled.is_empty(),
        "rows at/after the window edge must be excluded; got {stalled:?}"
    );
}
