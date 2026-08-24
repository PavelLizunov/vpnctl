use tempfile::TempDir;
use vpnctl_core::{ServerId, UserId};

use crate::common::{open, server, server_coeff, ud, user};

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
        top[0].user_id.0, "alice",
        "alice (×2 → 2M) outranks bob (×1 → 1M) on the daily-rollup path too"
    );
    assert_eq!(top[0].upload_bytes, 1_000_000);
    assert_eq!(top[0].download_bytes, 1_000_000);
    assert_eq!(top[0].total_bytes, 2_000_000);
    assert_eq!(top[1].user_id.0, "bob");
    assert_eq!(top[1].total_bytes, 1_000_000);
}

// AUD-013 regression: user_traffic_this_month_from_daily applies usage_coefficient
// across multiple servers, preserving zero and default multiplier semantics.
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

    // Alice on multiple servers:
    // s_double:  600_000 up + 400_000 down = 1_000_000 raw -> 2_000_000 weighted
    // s_half:    100_000 up + 300_000 down = 400_000 raw   -> 200_000 weighted
    // s_default:  50_000 up +  50_000 down = 100_000 raw   -> 100_000 weighted
    // s_zero:    250_000 up + 250_000 down = 500_000 raw   -> 0 weighted
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

    // zero_user with 0 bytes:
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
    // 2_000_000 + 200_000 + 100_000 + 0 = 2_300_000
    assert_eq!(alice_total, 2_300_000);

    // Bob has no rows at all -> returns 0
    let bob_total = inv
        .user_traffic_this_month_from_daily(&UserId("bob".into()))
        .await
        .unwrap();
    assert_eq!(bob_total, 0);

    // zero_user has 0 byte rows -> returns 0
    let zero_total = inv
        .user_traffic_this_month_from_daily(&UserId("zero_user".into()))
        .await
        .unwrap();
    assert_eq!(zero_total, 0);
}

// Planted mutation test: verifies that omitting usage_coefficient (e.g. raw SUM)
// fails against weighted daily rollup monthly totals.
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
