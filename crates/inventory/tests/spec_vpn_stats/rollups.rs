use tempfile::TempDir;
use vpnctl_core::{ServerId, UserId};

use crate::common::{open, raw_pool, server, server_coeff, ud, user};

#[tokio::test]
async fn recent_fleet_stats_collapse_users_per_chart_bucket_without_losing_bytes() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("s1")).await.unwrap();

    let deltas: Vec<_> = (0..200)
        .map(|i| ud(Some("user"), i + 1, 2, i as u32))
        .collect();
    inv.record_vpn_stats(&ServerId("s1".into()), &deltas)
        .await
        .unwrap();

    let rows = inv.recent_vpn_stats_fleet(24, 24).await.unwrap();
    assert_eq!(
        rows.len(),
        1,
        "dashboard cardinality must be poll minutes, not per-user rows"
    );
    assert_eq!(rows[0].server_id, ServerId("s1".into()));
    assert_eq!(rows[0].user_id, None);
    assert_eq!(rows[0].upload_bytes, 20_100);
    assert_eq!(rows[0].download_bytes, 400);
    assert_eq!(rows[0].active_connections, 199);

    inv.record_vpn_stats(&ServerId("s1".into()), &[ud(None, 5, 6, 300)])
        .await
        .unwrap();
    let rows = inv.recent_vpn_stats_fleet(24, 24).await.unwrap();
    assert_eq!(rows.len(), 1, "same-hour ticks must UPSERT one bucket");
    assert_eq!(rows[0].upload_bytes, 20_105);
    assert_eq!(rows[0].download_bytes, 406);
    assert_eq!(rows[0].active_connections, 300);
    assert!(inv.recent_vpn_stats_fleet(24, 0).await.is_err());
}

#[tokio::test]
async fn weighted_fleet_traffic_by_server_returns_one_scaled_total_per_server() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server_coeff("s1", 2.0)).await.unwrap();
    inv.record_vpn_stats(
        &ServerId("s1".into()),
        &[ud(Some("user"), 10, 20, 1), ud(None, 4, 6, 1)],
    )
    .await
    .unwrap();

    let rows = inv.weighted_vpn_traffic_by_server(24).await.unwrap();
    assert_eq!(rows, vec![(ServerId("s1".into()), 80)]);
    assert!(
        inv.weighted_vpn_traffic_by_server(0)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn phase5a1_rollup_aggregates_ticks_into_per_user_per_server_daily_totals() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("s1")).await.unwrap();
    for u in ["alice", "bob"] {
        inv.add_user(&user(u)).await.unwrap();
    }

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
            ud(Some("alice"), 100, 100, 1),
            ud(Some("bob"), 1000, 1000, 1),
            ud(Some("charlie"), 500, 500, 1),
        ],
    )
    .await
    .unwrap();
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    inv.rollup_vpn_user_daily(&today).await.unwrap();

    let top = inv.top_users_by_daily_traffic(1, 2).await.unwrap();
    assert_eq!(top.len(), 2, "limit=2 must cap");
    assert_eq!(top[0].user_id.0, "bob", "bob (2000) is top");
    assert_eq!(top[0].upload_bytes, 1000);
    assert_eq!(top[0].download_bytes, 1000);
    assert_eq!(top[0].total_bytes, 2000);
    assert_eq!(top[1].user_id.0, "charlie", "charlie (1000) is second");
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
        top[0].user_id.0, "alice",
        "alice (×2 → 2M) outranks bob (×1 → 1M) on the daily-rollup path too"
    );
    assert_eq!(top[0].upload_bytes, 1_000_000);
    assert_eq!(top[0].download_bytes, 1_000_000);
    assert_eq!(top[0].total_bytes, 2_000_000);
    assert_eq!(top[1].user_id.0, "bob");
    assert_eq!(top[1].total_bytes, 1_000_000);
}

#[tokio::test]
async fn user_traffic_this_month_from_daily_applies_multi_server_coefficients() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server_coeff("s_double", 2.0))
        .await
        .unwrap();
    inv.add_server(&server_coeff("s_half", 0.5)).await.unwrap();
    inv.add_server(&server_coeff("s_default", 1.0))
        .await
        .unwrap();
    inv.add_server(&server_coeff("s_zero", 0.0)).await.unwrap();

    inv.add_user(&user("alice")).await.unwrap();
    inv.add_user(&user("bob")).await.unwrap();
    inv.add_user(&user("zero_user")).await.unwrap();

    inv.record_vpn_stats(
        &ServerId("s_double".into()),
        &[ud(Some("alice"), 600_000, 400_000, 1)],
    )
    .await
    .unwrap();
    inv.record_vpn_stats(
        &ServerId("s_half".into()),
        &[ud(Some("alice"), 100_000, 300_000, 1)],
    )
    .await
    .unwrap();
    inv.record_vpn_stats(
        &ServerId("s_default".into()),
        &[ud(Some("alice"), 50_000, 50_000, 1)],
    )
    .await
    .unwrap();
    inv.record_vpn_stats(
        &ServerId("s_zero".into()),
        &[ud(Some("alice"), 250_000, 250_000, 1)],
    )
    .await
    .unwrap();

    inv.record_vpn_stats(
        &ServerId("s_default".into()),
        &[ud(Some("zero_user"), 0, 0, 1)],
    )
    .await
    .unwrap();

    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    inv.rollup_vpn_user_daily(&today).await.unwrap();

    let alice_total = inv
        .user_traffic_this_month_from_daily(&UserId("alice".into()))
        .await
        .unwrap();
    assert_eq!(alice_total, 2_300_000);

    let bob_total = inv
        .user_traffic_this_month_from_daily(&UserId("bob".into()))
        .await
        .unwrap();
    assert_eq!(bob_total, 0);

    let zero_total = inv
        .user_traffic_this_month_from_daily(&UserId("zero_user".into()))
        .await
        .unwrap();
    assert_eq!(zero_total, 0);
}

#[tokio::test]
async fn planted_mutation_monthly_daily_rollup_fails_if_unweighted() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server_coeff("double", 2.0)).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();

    inv.record_vpn_stats(
        &ServerId("double".into()),
        &[ud(Some("alice"), 500_000, 500_000, 1)],
    )
    .await
    .unwrap();

    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    inv.rollup_vpn_user_daily(&today).await.unwrap();

    let total = inv
        .user_traffic_this_month_from_daily(&UserId("alice".into()))
        .await
        .unwrap();

    let raw_unweighted_total = 1_000_000;
    let expected_weighted_total = 2_000_000;

    assert_eq!(total, expected_weighted_total);
    assert_ne!(
        total, raw_unweighted_total,
        "planted mutation: unweighted daily monthly sum (1M) must not match weighted result (2M)"
    );
}

#[tokio::test]
async fn rollup_survives_raw_rows_of_a_deleted_user() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("s1")).await.unwrap();
    for u in ["alice", "bob"] {
        inv.add_user(&user(u)).await.unwrap();
    }
    inv.record_vpn_stats(
        &ServerId("s1".into()),
        &[ud(Some("alice"), 10, 20, 1), ud(Some("bob"), 30, 40, 1)],
    )
    .await
    .unwrap();
    inv.remove_user(&UserId("alice".into())).await.unwrap();

    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let upserted = inv
        .rollup_vpn_user_daily(&today)
        .await
        .expect("a deleted user's raw rows must not abort the whole day's rollup");
    assert_eq!(upserted, 1, "only bob is rolled up");
    let bob = inv
        .vpn_user_daily_for_user(&UserId("bob".into()), 7)
        .await
        .unwrap();
    assert_eq!(bob.len(), 1);
    assert_eq!(bob[0].upload_bytes, 30);
}

#[tokio::test]
async fn retention_catches_up_multiple_missed_days_before_purging() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let pool = raw_pool(&dir).await;
    inv.add_server(&server("s1")).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();
    let uid = UserId("alice".into());

    for days in [40, 39, 38, 2] {
        let date: String = sqlx::query_scalar("SELECT date('now', ?1)")
            .bind(format!("-{days} days"))
            .fetch_one(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO vpn_connection_stats
             (ts, server_id, user_id, upload_bytes, download_bytes, active_connections)
             VALUES (?1 || 'T01:00:00.000Z', 's1', 'alice', 10, 20, 1)",
        )
        .bind(&date)
        .execute(&pool)
        .await
        .unwrap();
        if days == 40 {
            inv.rollup_vpn_user_daily(&date).await.unwrap();
        }
        sqlx::query(
            "INSERT INTO vpn_connection_stats
             (ts, server_id, user_id, upload_bytes, download_bytes, active_connections)
             VALUES (?1 || 'T23:00:00.000Z', 's1', 'alice', 30, 40, 3)",
        )
        .bind(&date)
        .execute(&pool)
        .await
        .unwrap();
    }

    // Startup catch-up completes retained missed days; the purge completes
    // the days it deletes.
    inv.catch_up_vpn_daily_rollups().await.unwrap();
    assert_eq!(inv.purge_vpn_stats_older_than(32).await.unwrap(), 6);
    let daily = inv.vpn_user_daily_for_user(&uid, 90).await.unwrap();
    assert_eq!(daily.len(), 4, "partial and missing days must all catch up");
    for row in &daily {
        assert_eq!(row.upload_bytes, 40);
        assert_eq!(row.download_bytes, 60);
        assert_eq!(row.active_connections_peak, 3);
        inv.rollup_vpn_user_daily(&row.date).await.unwrap();
    }
    assert_eq!(inv.vpn_user_daily_for_user(&uid, 90).await.unwrap(), daily);
    let audits = inv.recent_audit(100).await.unwrap().len();
    assert_eq!(inv.purge_vpn_stats_older_than(32).await.unwrap(), 0);
    assert_eq!(inv.recent_audit(100).await.unwrap().len(), audits);
}

#[tokio::test]
async fn retention_keeps_raw_rows_when_rollup_fails() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let pool = raw_pool(&dir).await;
    inv.add_server(&server("s1")).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();
    sqlx::query(
        "INSERT INTO vpn_connection_stats
         (ts, server_id, user_id, upload_bytes, download_bytes, active_connections)
         VALUES ('2000-01-01T12:00:00.000Z', 's1', 'alice', 10, 20, 1)",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER reject_daily BEFORE INSERT ON vpn_user_daily
         BEGIN SELECT RAISE(ABORT, 'rollup unavailable'); END",
    )
    .execute(&pool)
    .await
    .unwrap();
    let audits = inv.recent_audit(100).await.unwrap().len();

    assert!(inv.purge_vpn_stats_older_than(32).await.is_err());
    let raw: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vpn_connection_stats")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(raw, 1, "a failed rollup must never allow raw purge");
    assert_eq!(inv.recent_audit(100).await.unwrap().len(), audits);
}

#[tokio::test]
async fn all_history_includes_old_daily_rows_without_double_counting_raw_days() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let pool = raw_pool(&dir).await;
    inv.add_server(&server("s1")).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();
    inv.add_user(&user("bob")).await.unwrap();
    let uid = UserId("alice".into());
    sqlx::query(
        "INSERT INTO vpn_user_daily
         (date, user_id, server_id, upload_bytes, download_bytes, active_connections_peak)
         VALUES ('2000-01-01', 'alice', 's1', 100, 200, 2),
                ('2000-01-01', 'bob', 's1', 900, 900, 9)",
    )
    .execute(&pool)
    .await
    .unwrap();
    inv.record_vpn_stats(&ServerId("s1".into()), &[ud(Some("alice"), 10, 20, 1)])
        .await
        .unwrap();
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    inv.rollup_vpn_user_daily(&today).await.unwrap();

    let recent = inv.recent_vpn_stats_for_user(&uid, 24).await.unwrap();
    assert_eq!(
        recent.len(),
        1,
        "bounded windows must still read raw ticks only"
    );
    assert_eq!(recent[0].upload_bytes, 10);
    let all = inv.recent_vpn_stats_for_user(&uid, u32::MAX).await.unwrap();
    assert_eq!(all.len(), 2);
    assert_eq!(all.iter().map(|r| r.upload_bytes).sum::<u64>(), 110);
    assert_eq!(all.iter().map(|r| r.download_bytes).sum::<u64>(), 220);
    assert!(all.iter().all(|r| r.user_id.as_ref() == Some(&uid)));
    let top = inv.top_users_by_daily_traffic(u32::MAX, 10).await.unwrap();
    assert_eq!(
        top.len(),
        2,
        "all-history ranking must include old daily rows"
    );
    assert_eq!(top[0].user_id.0, "bob");
    assert_eq!(top[1].total_bytes, 330);
}

#[tokio::test]
async fn fleet_all_history_includes_hourly_rows_older_than_thirty_months() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let pool = raw_pool(&dir).await;
    inv.add_server(&server("s1")).await.unwrap();
    sqlx::query(
        "INSERT INTO vpn_server_hourly
         (hour, server_id, upload_bytes, download_bytes, active_connections_peak, last_sample_ts)
         VALUES ('2000-01-01T12:00:00.000Z', 's1', 100, 200, 2, '2000-01-01T12:00:00.000Z')",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(inv.recent_vpn_stats_fleet(24, 1).await.unwrap().is_empty());
    let all = inv.recent_vpn_stats_fleet(u32::MAX, 720).await.unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].upload_bytes, 100);
    assert_eq!(all[0].download_bytes, 200);
}

#[tokio::test]
async fn rollup_preserves_totals_of_a_day_partially_purged_by_legacy_retention() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let pool = raw_pool(&dir).await;
    inv.add_server(&server("s1")).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();
    sqlx::query(
        "INSERT INTO vpn_connection_stats
         (ts, server_id, user_id, upload_bytes, download_bytes, active_connections)
         VALUES ('2000-01-01T01:00:00.000Z', 's1', 'alice', 10, 20, 3),
                ('2000-01-01T23:00:00.000Z', 's1', 'alice', 30, 40, 1)",
    )
    .execute(&pool)
    .await
    .unwrap();
    inv.rollup_vpn_user_daily("2000-01-01").await.unwrap();
    sqlx::query("DELETE FROM vpn_connection_stats WHERE ts < '2000-01-01T12:00:00.000Z'")
        .execute(&pool)
        .await
        .unwrap();

    assert_eq!(inv.purge_vpn_stats_older_than(32).await.unwrap(), 1);
    let totals: (i64, i64, i64) = sqlx::query_as(
        "SELECT upload_bytes, download_bytes, active_connections_peak
         FROM vpn_user_daily WHERE user_id = 'alice' AND date = '2000-01-01'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        totals,
        (40, 60, 3),
        "partial raw rows cannot replace a complete day"
    );
}
