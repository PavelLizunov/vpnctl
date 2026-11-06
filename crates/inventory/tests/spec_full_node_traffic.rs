#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Independent contract tests written from docs/specs/full-node-traffic.md only.

use chrono::{DateTime, Utc};
use sqlx::{SqlitePool, sqlite::SqliteConnectOptions};
use std::sync::atomic::{AtomicU64, Ordering};
use tempfile::TempDir;
use vpnctl_core::{Server, ServerId};
use vpnctl_inventory::{
    ServerTrafficLimit, SqliteInventory, SqliteInventoryError, server_traffic_period,
};

const HOUR: i64 = 3_600;
const DAY: i64 = 86_400;
const GIB: u64 = 1 << 30;

fn timestamp(value: &str) -> i64 {
    DateTime::parse_from_rfc3339(value).unwrap().timestamp()
}

fn datetime(value: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(value, 0).unwrap()
}

fn fixture_server(id: &ServerId) -> Server {
    Server {
        id: id.clone(),
        address: if id.0 == "traffic-spec-server" {
            "192.0.2.10"
        } else {
            "192.0.2.11"
        }
        .into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![],
        enabled_protocols: vec![],
        trusted_host_fingerprint: None,
        hoster: "spec-fixture".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

struct Fixture {
    inv: SqliteInventory,
    db: SqlitePool,
    sid: ServerId,
    sequence: AtomicU64,
    _directory: TempDir,
}

impl Fixture {
    async fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("inventory.sqlite3");
        let inv = SqliteInventory::open(&path).await.unwrap();
        let sid = ServerId("traffic-spec-server".into());
        inv.add_server(&fixture_server(&sid)).await.unwrap();
        let db = SqlitePool::connect_with(SqliteConnectOptions::new().filename(&path))
            .await
            .unwrap();
        Self {
            inv,
            db,
            sid,
            sequence: AtomicU64::new(0),
            _directory: directory,
        }
    }

    async fn observe(&self, at: i64, iface: &str, rx: i64, tx: i64) {
        self.raw_observation(
            &self.sid,
            &datetime(at).to_rfc3339(),
            Some(iface),
            Some(rx),
            Some(tx),
        )
        .await;
    }

    async fn raw_observation(
        &self,
        sid: &ServerId,
        at: &str,
        iface: Option<&str>,
        rx: Option<i64>,
        tx: Option<i64>,
    ) {
        let seq = self.sequence.fetch_add(1, Ordering::Relaxed);
        sqlx::query(
            "INSERT INTO node_health \
             (sample_id, ts, server_id, nic_iface, nic_rx_bytes, nic_tx_bytes) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(format!("traffic-spec-{seq}"))
        .bind(at)
        .bind(&sid.0)
        .bind(iface)
        .bind(rx)
        .bind(tx)
        .execute(&self.db)
        .await
        .unwrap();
    }

    async fn literal_counters(&self, at: i64, rx: &str, tx: &str) {
        let seq = self.sequence.fetch_add(1, Ordering::Relaxed);
        // rx/tx are fixed SQL literals supplied by the tests, never live input.
        let statement = format!(
            "INSERT INTO node_health \
             (sample_id, ts, server_id, nic_iface, nic_rx_bytes, nic_tx_bytes) \
             VALUES (?, ?, ?, 'eth0', {rx}, {tx})"
        );
        sqlx::query(&statement)
            .bind(format!("traffic-spec-{seq}"))
            .bind(datetime(at).to_rfc3339())
            .bind(&self.sid.0)
            .execute(&self.db)
            .await
            .unwrap();
    }

    async fn many_observations(&self, at: i64, count: i64) {
        sqlx::query(
            "WITH RECURSIVE observations(n) AS \
             (VALUES(0) UNION ALL SELECT n + 1 FROM observations WHERE n + 1 < ?) \
             INSERT INTO node_health \
             (sample_id, ts, server_id, nic_iface, nic_rx_bytes, nic_tx_bytes) \
             SELECT 'many-' || n, ?, ?, 'eth0', n, n * 2 FROM observations",
        )
        .bind(count)
        .bind(datetime(at).to_rfc3339())
        .bind(&self.sid.0)
        .execute(&self.db)
        .await
        .unwrap();
    }

    async fn audit_count(&self) -> usize {
        self.inv
            .recent_audit(1_000)
            .await
            .unwrap()
            .iter()
            .filter(|entry| entry.action == "server.traffic_limit.set")
            .count()
    }

    async fn reject_audit_writes(&self) {
        sqlx::query(
            "CREATE TRIGGER reject_traffic_limit_audit BEFORE INSERT ON audit_log \
             WHEN NEW.action = 'server.traffic_limit.set' \
             BEGIN SELECT RAISE(ABORT, 'spec audit failure'); END",
        )
        .execute(&self.db)
        .await
        .unwrap();
    }

    async fn day(&self, now: i64, rx_delta: u64, tx_delta: u64) {
        for hour in 0..=24_u64 {
            let rx = 7_000_000_000_000 + rx_delta * hour / 24;
            let tx = 8_000_000_000_000 + tx_delta * hour / 24;
            self.observe(now - DAY + hour as i64 * HOUR, "eth0", rx as i64, tx as i64)
                .await;
        }
    }
}

#[tokio::test]
async fn nic_usage_sums_observed_deltas_and_reports_the_actual_window() {
    let f = Fixture::new().await;
    let start = timestamp("2025-01-01T00:00:00Z");
    f.observe(start, "eth0", 10_000, 20_000).await;
    f.observe(start + HOUR, "eth0", 10_100, 20_250).await;
    f.observe(start + 2 * HOUR, "eth0", 10_180, 20_300).await;

    let usage = f
        .inv
        .node_nic_usage(&f.sid, start, start + 2 * HOUR, HOUR as u64)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (usage.rx_bytes, usage.tx_bytes, usage.total_bytes),
        (180, 300, 480)
    );
    assert_eq!((usage.samples, usage.observed_hours), (3, 3));
    assert_eq!(usage.first_sample_ts, datetime(start));
    assert_eq!(usage.last_sample_ts, datetime(start + 2 * HOUR));
    assert!(!usage.interrupted);
    assert!(usage.complete);
    assert_eq!(usage.clone(), usage);
}

#[tokio::test]
async fn nic_usage_excludes_pre_window_samples_and_isolates_servers() {
    let f = Fixture::new().await;
    let start = timestamp("2025-01-01T00:00:00Z");
    let other = ServerId("other-traffic-spec-server".into());
    f.inv.add_server(&fixture_server(&other)).await.unwrap();
    f.observe(start - 1, "eth0", 0, 0).await;
    f.observe(start, "eth0", 1_000, 2_000).await;
    f.raw_observation(
        &other,
        &datetime(start).to_rfc3339(),
        Some("eth0"),
        Some(0),
        Some(0),
    )
    .await;
    f.observe(start + 60, "eth0", 1_010, 2_020).await;
    f.raw_observation(
        &other,
        &datetime(start + 60).to_rfc3339(),
        Some("eth0"),
        Some(1_000_000),
        Some(2_000_000),
    )
    .await;

    let usage = f
        .inv
        .node_nic_usage(&f.sid, start, start + 60, 60)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (usage.rx_bytes, usage.tx_bytes, usage.total_bytes),
        (10, 20, 30)
    );
    assert_eq!(usage.samples, 2);
    assert!(usage.complete);
    assert!(
        f.inv
            .node_nic_usage(&ServerId("missing".into()), start, start + 60, 60)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn nic_usage_counts_each_reset_counter_without_recounting_the_other_direction() {
    let f = Fixture::new().await;
    let start = timestamp("2025-01-01T00:00:00Z");
    for (offset, rx, tx) in [
        (0, 100, 200),
        (1, 150, 250),
        (2, 5, 260),
        (3, 15, 7),
        (4, 25, 17),
    ] {
        f.observe(start + offset, "eth0", rx, tx).await;
    }
    let usage = f
        .inv
        .node_nic_usage(&f.sid, start, start + 4, 1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (usage.rx_bytes, usage.tx_bytes, usage.total_bytes),
        (75, 77, 152)
    );
    assert!(usage.interrupted);
    assert!(!usage.complete);
}

#[tokio::test]
async fn nic_interface_change_sets_a_new_baseline_without_counting_its_lifetime() {
    let f = Fixture::new().await;
    let start = timestamp("2025-01-01T00:00:00Z");
    for (offset, iface, rx, tx) in [
        (0, "eth0", 100, 200),
        (1, "eth0", 130, 240),
        (2, "ens3", 10_000, 30_000),
        (3, "ens3", 10_050, 30_060),
    ] {
        f.observe(start + offset, iface, rx, tx).await;
    }
    let usage = f
        .inv
        .node_nic_usage(&f.sid, start, start + 3, 1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (usage.rx_bytes, usage.tx_bytes, usage.total_bytes),
        (80, 100, 180)
    );
    assert_eq!(usage.samples, 4);
    assert!(usage.interrupted);
    assert!(!usage.complete);
}

#[tokio::test]
async fn nic_gap_boundary_is_inclusive_and_larger_gaps_are_partial() {
    for (gap, interrupted) in [(60, false), (61, true)] {
        let f = Fixture::new().await;
        let start = timestamp("2025-01-01T00:00:00Z");
        f.observe(start, "eth0", 100, 200).await;
        f.observe(start + gap, "eth0", 110, 220).await;
        let usage = f
            .inv
            .node_nic_usage(&f.sid, start, start + gap, 60)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(usage.total_bytes, 30);
        assert_eq!(usage.interrupted, interrupted, "gap {gap}");
        assert_eq!(usage.complete, !interrupted, "gap {gap}");
    }
}

#[tokio::test]
async fn nic_complete_coverage_checks_both_window_edges_inclusively() {
    let start = timestamp("2025-01-01T00:00:00Z");
    for (first, last, complete) in [(60, 180, true), (61, 180, false), (60, 179, false)] {
        let f = Fixture::new().await;
        for offset in first..=last {
            f.observe(start + offset, "eth0", offset, 2 * offset).await;
        }
        let usage = f
            .inv
            .node_nic_usage(&f.sid, start, start + 240, 60)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(usage.complete, complete, "first={first}, last={last}");
        assert!(!usage.interrupted);
        assert_eq!(usage.first_sample_ts, datetime(start + first));
        assert_eq!(usage.last_sample_ts, datetime(start + last));
        assert_eq!(usage.total_bytes, ((last - first) * 3) as u64);
    }
}

#[tokio::test]
async fn nic_null_only_health_rows_are_skipped_and_valid_sample_gaps_still_count() {
    let start = timestamp("2025-01-01T00:00:00Z");
    for (last, interrupted) in [(60, false), (61, true)] {
        let f = Fixture::new().await;
        f.observe(start, "eth0", 100, 200).await;
        f.raw_observation(&f.sid, &datetime(start + 30).to_rfc3339(), None, None, None)
            .await;
        f.raw_observation(
            &f.sid,
            &datetime(start + 31).to_rfc3339(),
            Some("eth0"),
            None,
            None,
        )
        .await;
        f.observe(start + last, "eth0", 110, 220).await;
        let usage = f
            .inv
            .node_nic_usage(&f.sid, start, start + last, 60)
            .await
            .unwrap()
            .unwrap();
        assert_eq!((usage.samples, usage.total_bytes), (2, 30));
        assert_eq!(usage.interrupted, interrupted);
    }
}

#[tokio::test]
async fn nic_requires_two_usable_observations_but_accepts_measured_zero() {
    let f = Fixture::new().await;
    let start = timestamp("2025-01-01T00:00:00Z");
    assert!(
        f.inv
            .node_nic_usage(&f.sid, start, start + 60, 60)
            .await
            .unwrap()
            .is_none()
    );
    f.raw_observation(&f.sid, &datetime(start).to_rfc3339(), None, None, None)
        .await;
    assert!(
        f.inv
            .node_nic_usage(&f.sid, start, start + 60, 60)
            .await
            .unwrap()
            .is_none()
    );
    f.observe(start, "eth0", 1_000, 2_000).await;
    assert!(
        f.inv
            .node_nic_usage(&f.sid, start, start + 60, 60)
            .await
            .unwrap()
            .is_none()
    );
    f.observe(start + 60, "eth0", 1_000, 2_000).await;
    let usage = f
        .inv
        .node_nic_usage(&f.sid, start, start + 60, 60)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(usage.total_bytes, 0);
    assert!(usage.complete);
}

#[tokio::test]
async fn nic_observed_hours_are_distinct_utc_hours_not_sample_count_or_local_offset() {
    let f = Fixture::new().await;
    let start = timestamp("2025-01-01T00:00:00Z");
    f.raw_observation(
        &f.sid,
        "2025-01-01T02:00:00+02:00",
        Some("eth0"),
        Some(0),
        Some(0),
    )
    .await;
    f.observe(start + 30, "eth0", 1, 2).await;
    f.observe(start + HOUR - 1, "eth0", 2, 4).await;
    f.observe(start + HOUR, "eth0", 3, 6).await;
    let usage = f
        .inv
        .node_nic_usage(&f.sid, start, start + HOUR, HOUR as u64)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(usage.samples, 4);
    assert_eq!(usage.observed_hours, 2);
    assert_eq!(usage.total_bytes, 9);
}

#[tokio::test]
async fn nic_accepts_equal_timestamps_but_rejects_backwards_collection_sequence() {
    let start = timestamp("2025-01-01T00:00:00Z");
    let f = Fixture::new().await;
    f.observe(start, "eth0", 100, 200).await;
    f.observe(start, "eth0", 110, 220).await;
    let usage = f
        .inv
        .node_nic_usage(&f.sid, start, start + 1, 1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((usage.total_bytes, usage.observed_hours), (30, 1));

    let f = Fixture::new().await;
    f.observe(start, "eth0", 100, 200).await;
    f.observe(start + 60, "eth0", 110, 220).await;
    f.observe(start + 30, "eth0", 120, 240).await;
    assert!(
        f.inv
            .node_nic_usage(&f.sid, start, start + 60, 60)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn nic_partial_missing_and_negative_counters_or_missing_interface_are_unavailable() {
    let start = timestamp("2025-01-01T00:00:00Z");
    for (iface, rx, tx) in [
        (Some("eth0"), None, Some(10)),
        (Some("eth0"), Some(10), None),
        (Some("eth0"), Some(-1), Some(10)),
        (Some("eth0"), Some(10), Some(-1)),
        (None, Some(10), Some(10)),
    ] {
        let f = Fixture::new().await;
        f.observe(start, "eth0", 0, 0).await;
        f.raw_observation(&f.sid, &datetime(start + 30).to_rfc3339(), iface, rx, tx)
            .await;
        f.observe(start + 60, "eth0", 100, 200).await;
        assert!(
            f.inv
                .node_nic_usage(&f.sid, start, start + 60, 60)
                .await
                .unwrap()
                .is_none(),
            "iface={iface:?}, rx={rx:?}, tx={tx:?}"
        );
    }
}

#[tokio::test]
async fn nic_non_integer_counters_are_unavailable_in_either_direction() {
    let start = timestamp("2025-01-01T00:00:00Z");
    for (rx, tx) in [
        ("1.5", "10"),
        ("10", "2.5"),
        ("'invalid'", "10"),
        ("10", "'invalid'"),
    ] {
        let f = Fixture::new().await;
        f.observe(start, "eth0", 0, 0).await;
        f.literal_counters(start + 30, rx, tx).await;
        f.observe(start + 60, "eth0", 100, 200).await;
        assert!(
            f.inv
                .node_nic_usage(&f.sid, start, start + 60, 60)
                .await
                .unwrap()
                .is_none(),
            "rx={rx}, tx={tx}"
        );
    }
}

#[tokio::test]
async fn nic_malformed_and_future_timestamps_are_unavailable() {
    let start = timestamp("2025-01-01T00:00:00Z");
    for at in [
        "not-a-timestamp",
        "2025-02-30T00:00:00Z",
        "2025-01-01T00:01:01Z",
    ] {
        let f = Fixture::new().await;
        f.observe(start, "eth0", 0, 0).await;
        f.observe(start + 60, "eth0", 100, 200).await;
        f.raw_observation(&f.sid, at, Some("eth0"), Some(110), Some(220))
            .await;
        assert!(
            f.inv
                .node_nic_usage(&f.sid, start, start + 60, 60)
                .await
                .unwrap()
                .is_none(),
            "timestamp={at}"
        );
    }
}

#[tokio::test]
async fn nic_counter_accumulation_and_rx_plus_tx_overflow_are_unavailable() {
    let start = timestamp("2025-01-01T00:00:00Z");
    for counters in [
        vec![
            (0, 0),
            (i64::MAX, 0),
            (0, 0),
            (i64::MAX, 0),
            (0, 0),
            (i64::MAX, 0),
        ],
        vec![
            (0, 0),
            (0, i64::MAX),
            (0, 0),
            (0, i64::MAX),
            (0, 0),
            (0, i64::MAX),
        ],
        vec![(0, 0), (i64::MAX, i64::MAX), (0, 0), (1, 1)],
    ] {
        let f = Fixture::new().await;
        for (offset, (rx, tx)) in counters.iter().enumerate() {
            f.observe(start + offset as i64, "eth0", *rx, *tx).await;
        }
        assert!(
            f.inv
                .node_nic_usage(&f.sid, start, start + 10, 10)
                .await
                .unwrap()
                .is_none()
        );
    }
}

#[tokio::test]
async fn nic_row_bound_accepts_one_hundred_thousand_and_rejects_one_more() {
    let start = timestamp("2025-01-01T00:00:00Z");
    for count in [100_000, 100_001] {
        let f = Fixture::new().await;
        f.many_observations(start, count).await;
        let usage = f
            .inv
            .node_nic_usage(&f.sid, start, start + 1, 1)
            .await
            .unwrap();
        if count == 100_000 {
            let usage = usage.unwrap();
            assert_eq!(usage.samples, 100_000);
            assert_eq!(
                (usage.rx_bytes, usage.tx_bytes, usage.total_bytes),
                (99_999, 199_998, 299_997)
            );
        } else {
            assert!(usage.is_none());
        }
    }
}

#[tokio::test]
async fn nic_window_argument_boundaries_are_validated() {
    let f = Fixture::new().await;
    let start = timestamp("2025-01-01T00:00:00Z");
    f.observe(start, "eth0", 0, 0).await;
    f.observe(start + 40 * DAY, "eth0", 1, 2).await;
    assert_eq!(
        f.inv
            .node_nic_usage(&f.sid, start, start + 40 * DAY, (40 * DAY) as u64)
            .await
            .unwrap()
            .unwrap()
            .total_bytes,
        3
    );
    for (from, now, gap) in [
        (start, start, 1),
        (start + 1, start, 1),
        (start, start + 40 * DAY + 1, 1),
        (start, start + 1, 0),
        (i64::MIN, i64::MAX, 1),
    ] {
        assert!(
            matches!(
                f.inv.node_nic_usage(&f.sid, from, now, gap).await,
                Err(SqliteInventoryError::Invalid(_))
            ),
            "from={from}, now={now}, gap={gap}"
        );
    }
}

#[tokio::test]
async fn daily_activity_returns_full_rx_plus_tx_at_each_category_boundary() {
    let now = timestamp("2025-01-02T00:00:00Z");
    for (rx, tx) in [
        (0, 0),
        (25 * GIB - 1, 0),
        (GIB, 24 * GIB),
        (100 * GIB - 1, 0),
        (30 * GIB, 70 * GIB),
    ] {
        let f = Fixture::new().await;
        f.day(now, rx, tx).await;
        assert_eq!(
            f.inv
                .node_activity_bytes(&f.sid, now, HOUR as u64)
                .await
                .unwrap(),
            Some(rx + tx),
            "rx={rx}, tx={tx}"
        );
    }
}

#[tokio::test]
async fn daily_activity_requires_twenty_distinct_hours_but_permits_late_start_history() {
    let now = timestamp("2025-01-02T00:00:00Z");
    for count in [19, 20] {
        let f = Fixture::new().await;
        for index in 0..count {
            f.observe(
                now - (count - 1 - index) * HOUR,
                "eth0",
                index * 10,
                index * 20,
            )
            .await;
        }
        let result = f
            .inv
            .node_activity_bytes(&f.sid, now, HOUR as u64)
            .await
            .unwrap();
        if count == 19 {
            assert!(result.is_none());
        } else {
            assert_eq!(result, Some(570));
            let usage = f
                .inv
                .node_nic_usage(&f.sid, now - DAY, now, HOUR as u64)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(usage.observed_hours, 20);
            assert!(!usage.complete);
            assert!(!usage.interrupted);
        }
    }
}

#[tokio::test]
async fn daily_activity_many_samples_in_fewer_than_twenty_hours_are_unknown() {
    let f = Fixture::new().await;
    let now = timestamp("2025-01-02T00:00:00Z");
    for index in 0..=120 {
        f.observe(now - 120 + index, "eth0", index * 10, index * 20)
            .await;
    }
    assert!(
        f.inv
            .node_activity_bytes(&f.sid, now, HOUR as u64)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn daily_activity_no_data_one_sample_and_zero_max_age_are_unknown() {
    let f = Fixture::new().await;
    let now = timestamp("2025-01-02T00:00:00Z");
    assert!(
        f.inv
            .node_activity_bytes(&f.sid, now, HOUR as u64)
            .await
            .unwrap()
            .is_none()
    );
    f.observe(now, "eth0", 100, 200).await;
    assert!(
        f.inv
            .node_activity_bytes(&f.sid, now, HOUR as u64)
            .await
            .unwrap()
            .is_none()
    );

    let f = Fixture::new().await;
    f.day(now, 100, 200).await;
    assert!(
        f.inv
            .node_activity_bytes(&f.sid, now, 0)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        f.inv
            .node_activity_bytes(&ServerId("missing".into()), now, HOUR as u64)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn daily_activity_freshness_accepts_exact_max_age_and_rejects_one_second_older() {
    let now = timestamp("2025-01-02T00:00:00Z");
    for age in [HOUR, HOUR + 1] {
        let f = Fixture::new().await;
        for hour in 0..=23 {
            let at = if hour == 23 {
                now - age
            } else {
                now - DAY + hour * HOUR
            };
            f.observe(at, "eth0", 100 + hour * 3, 200 + hour * 5).await;
        }
        assert_eq!(
            f.inv
                .node_activity_bytes(&f.sid, now, HOUR as u64)
                .await
                .unwrap(),
            if age == HOUR { Some(184) } else { None },
            "age={age}"
        );
    }
}

#[tokio::test]
async fn daily_activity_is_unknown_after_a_counter_gap_reset_or_interface_change() {
    let now = timestamp("2025-01-02T00:00:00Z");
    for interruption in ["gap", "reset", "interface"] {
        let f = Fixture::new().await;
        for hour in 0..=24 {
            if interruption == "gap" && hour == 12 {
                continue;
            }
            let iface = if interruption == "interface" && hour >= 12 {
                "ens3"
            } else {
                "eth0"
            };
            let rx = if interruption == "reset" && hour == 12 {
                1
            } else {
                10_000 + hour * 10
            };
            f.observe(now - DAY + hour * HOUR, iface, rx, 20_000 + hour * 20)
                .await;
        }
        assert!(
            f.inv
                .node_activity_bytes(&f.sid, now, HOUR as u64)
                .await
                .unwrap()
                .is_none(),
            "interruption={interruption}"
        );
    }
}

#[tokio::test]
async fn daily_activity_skips_health_only_rows_but_invalid_nic_data_is_unknown() {
    let now = timestamp("2025-01-02T00:00:00Z");
    let f = Fixture::new().await;
    f.day(now, 100, 200).await;
    f.raw_observation(&f.sid, &datetime(now).to_rfc3339(), None, None, None)
        .await;
    assert_eq!(
        f.inv
            .node_activity_bytes(&f.sid, now, HOUR as u64)
            .await
            .unwrap(),
        Some(300)
    );

    for (rx, tx) in [(None, Some(10)), (Some(10), None), (Some(-1), Some(10))] {
        let f = Fixture::new().await;
        f.day(now, 100, 200).await;
        f.raw_observation(&f.sid, &datetime(now).to_rfc3339(), Some("eth0"), rx, tx)
            .await;
        assert!(
            f.inv
                .node_activity_bytes(&f.sid, now, HOUR as u64)
                .await
                .unwrap()
                .is_none()
        );
    }
    let f = Fixture::new().await;
    f.day(now, 100, 200).await;
    f.raw_observation(&f.sid, "malformed", Some("eth0"), Some(10), Some(20))
        .await;
    assert!(
        f.inv
            .node_activity_bytes(&f.sid, now, HOUR as u64)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn daily_activity_uses_only_the_last_twenty_four_hours_and_its_server() {
    let f = Fixture::new().await;
    let now = timestamp("2025-01-02T00:00:00Z");
    let other = ServerId("activity-other-server".into());
    f.inv.add_server(&fixture_server(&other)).await.unwrap();
    f.observe(now - DAY - 1, "old-interface", 1, 2).await;
    f.day(now, 100, 200).await;
    for hour in 0..=24 {
        f.raw_observation(
            &other,
            &datetime(now - DAY + hour * HOUR).to_rfc3339(),
            Some("eth0"),
            Some(hour * 1_000_000),
            Some(hour * 2_000_000),
        )
        .await;
    }
    assert_eq!(
        f.inv
            .node_activity_bytes(&f.sid, now, HOUR as u64)
            .await
            .unwrap(),
        Some(300)
    );
    assert_eq!(
        f.inv
            .node_activity_bytes(&other, now, HOUR as u64)
            .await
            .unwrap(),
        Some(72_000_000)
    );
}

fn limit(limit_bytes: u64, direction: &str, reset_day: u8, warning_pct: u8) -> ServerTrafficLimit {
    ServerTrafficLimit {
        limit_bytes,
        direction: direction.into(),
        reset_day,
        warning_pct,
    }
}

#[tokio::test]
async fn traffic_limits_round_trip_every_direction_and_accepted_numeric_boundaries() {
    let f = Fixture::new().await;
    assert_eq!(f.inv.get_server_traffic_limit(&f.sid).await.unwrap(), None);
    for (index, setting) in [
        limit(1, "rx", 1, 1),
        limit(i64::MAX as u64, "tx", 31, 100),
        limit(4_000_000_000_000, "both", 15, 80),
    ]
    .into_iter()
    .enumerate()
    {
        assert!(
            f.inv
                .set_server_traffic_limit(&f.sid, Some(&setting), "spec-operator")
                .await
                .unwrap()
        );
        assert_eq!(
            f.inv.get_server_traffic_limit(&f.sid).await.unwrap(),
            Some(setting.clone())
        );
        assert_eq!(f.audit_count().await, index + 1);
    }
    assert!(
        f.inv
            .set_server_traffic_limit(&f.sid, None, "spec-operator")
            .await
            .unwrap()
    );
    assert_eq!(f.inv.get_server_traffic_limit(&f.sid).await.unwrap(), None);
    assert_eq!(f.audit_count().await, 4);
}

#[tokio::test]
async fn traffic_limit_clear_and_identical_save_are_noops_without_audit_writes() {
    let f = Fixture::new().await;
    assert!(
        !f.inv
            .set_server_traffic_limit(&f.sid, None, "spec-operator")
            .await
            .unwrap()
    );
    assert_eq!(f.audit_count().await, 0);
    let setting = limit(1_000_000_000, "both", 1, 80);
    assert!(
        f.inv
            .set_server_traffic_limit(&f.sid, Some(&setting), "spec-operator")
            .await
            .unwrap()
    );
    f.reject_audit_writes().await;
    assert!(
        !f.inv
            .set_server_traffic_limit(&f.sid, Some(&setting), "different-spec-operator")
            .await
            .unwrap()
    );
    assert_eq!(
        f.inv.get_server_traffic_limit(&f.sid).await.unwrap(),
        Some(setting)
    );
    assert_eq!(f.audit_count().await, 1);

    let f = Fixture::new().await;
    f.reject_audit_writes().await;
    assert!(
        !f.inv
            .set_server_traffic_limit(&f.sid, None, "spec-operator")
            .await
            .unwrap()
    );
    assert_eq!(f.audit_count().await, 0);
}

#[tokio::test]
async fn traffic_limit_changing_each_non_byte_field_is_a_real_audited_mutation() {
    let f = Fixture::new().await;
    for (index, setting) in [
        limit(1_000, "rx", 1, 80),
        limit(1_000, "tx", 1, 80),
        limit(1_000, "tx", 31, 80),
        limit(1_000, "tx", 31, 90),
    ]
    .into_iter()
    .enumerate()
    {
        assert!(
            f.inv
                .set_server_traffic_limit(&f.sid, Some(&setting), "spec-operator")
                .await
                .unwrap()
        );
        assert_eq!(
            f.inv.get_server_traffic_limit(&f.sid).await.unwrap(),
            Some(setting)
        );
        assert_eq!(f.audit_count().await, index + 1);
    }
}

#[tokio::test]
async fn traffic_limit_invalid_values_do_not_replace_settings_or_add_audit_rows() {
    let f = Fixture::new().await;
    let original = limit(1_000_000_000, "both", 15, 80);
    f.inv
        .set_server_traffic_limit(&f.sid, Some(&original), "spec-operator")
        .await
        .unwrap();
    let mut invalid = vec![
        limit(0, "both", 1, 80),
        limit(i64::MAX as u64 + 1, "both", 1, 80),
        limit(u64::MAX, "both", 1, 80),
    ];
    for direction in ["", "RX", "rx ", "unknown"] {
        invalid.push(limit(1, direction, 1, 80));
    }
    for day in [0, 32, u8::MAX] {
        invalid.push(limit(1, "both", day, 80));
    }
    for pct in [0, 101, u8::MAX] {
        invalid.push(limit(1, "both", 1, pct));
    }
    for setting in invalid {
        assert!(
            matches!(
                f.inv
                    .set_server_traffic_limit(&f.sid, Some(&setting), "spec-operator")
                    .await,
                Err(SqliteInventoryError::Invalid(_))
            ),
            "setting={setting:?}"
        );
        assert_eq!(
            f.inv.get_server_traffic_limit(&f.sid).await.unwrap(),
            Some(original.clone())
        );
        assert_eq!(f.audit_count().await, 1);
    }
}

#[tokio::test]
async fn traffic_limit_missing_server_gets_none_and_rejects_save_or_clear() {
    let f = Fixture::new().await;
    let missing = ServerId("missing-traffic-limit-server".into());
    let setting = limit(1, "rx", 1, 1);
    assert!(
        f.inv
            .get_server_traffic_limit(&missing)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        f.inv
            .set_server_traffic_limit(&missing, Some(&setting), "spec-operator")
            .await
            .is_err()
    );
    assert!(
        f.inv
            .set_server_traffic_limit(&missing, None, "spec-operator")
            .await
            .is_err()
    );
    assert_eq!(f.audit_count().await, 0);
    assert!(
        f.inv
            .get_server_traffic_limit(&f.sid)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn traffic_limits_are_isolated_by_server() {
    let f = Fixture::new().await;
    let other = ServerId("other-traffic-limit-server".into());
    f.inv.add_server(&fixture_server(&other)).await.unwrap();
    let first = limit(1_000, "rx", 31, 1);
    let second = limit(2_000, "tx", 1, 100);
    f.inv
        .set_server_traffic_limit(&f.sid, Some(&first), "spec-operator")
        .await
        .unwrap();
    assert!(
        f.inv
            .get_server_traffic_limit(&other)
            .await
            .unwrap()
            .is_none()
    );
    f.inv
        .set_server_traffic_limit(&other, Some(&second), "spec-operator")
        .await
        .unwrap();
    assert_eq!(
        f.inv.get_server_traffic_limit(&f.sid).await.unwrap(),
        Some(first.clone())
    );
    assert_eq!(
        f.inv.get_server_traffic_limit(&other).await.unwrap(),
        Some(second)
    );
    f.inv
        .set_server_traffic_limit(&other, None, "spec-operator")
        .await
        .unwrap();
    assert_eq!(
        f.inv.get_server_traffic_limit(&f.sid).await.unwrap(),
        Some(first)
    );
    assert_eq!(f.audit_count().await, 3);
}

#[tokio::test]
async fn traffic_limit_audit_failure_rolls_back_initial_save_replacement_and_clear() {
    let f = Fixture::new().await;
    let original = limit(1_000, "rx", 1, 80);
    f.reject_audit_writes().await;
    assert!(
        f.inv
            .set_server_traffic_limit(&f.sid, Some(&original), "spec-operator")
            .await
            .is_err()
    );
    assert!(
        f.inv
            .get_server_traffic_limit(&f.sid)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(f.audit_count().await, 0);

    let f = Fixture::new().await;
    f.inv
        .set_server_traffic_limit(&f.sid, Some(&original), "spec-operator")
        .await
        .unwrap();
    f.reject_audit_writes().await;
    let replacement = limit(2_000, "tx", 31, 90);
    assert!(
        f.inv
            .set_server_traffic_limit(&f.sid, Some(&replacement), "spec-operator")
            .await
            .is_err()
    );
    assert_eq!(
        f.inv.get_server_traffic_limit(&f.sid).await.unwrap(),
        Some(original.clone())
    );
    assert!(
        f.inv
            .set_server_traffic_limit(&f.sid, None, "spec-operator")
            .await
            .is_err()
    );
    assert_eq!(
        f.inv.get_server_traffic_limit(&f.sid).await.unwrap(),
        Some(original)
    );
    assert_eq!(f.audit_count().await, 1);
}

#[test]
fn monthly_period_start_is_inclusive_and_next_reset_is_exclusive() {
    for (now, day, from, next) in [
        (
            "2025-01-01T00:00:00Z",
            1,
            "2025-01-01T00:00:00Z",
            "2025-02-01T00:00:00Z",
        ),
        (
            "2025-01-31T23:59:59Z",
            1,
            "2025-01-01T00:00:00Z",
            "2025-02-01T00:00:00Z",
        ),
        (
            "2025-02-14T23:59:59Z",
            15,
            "2025-01-15T00:00:00Z",
            "2025-02-15T00:00:00Z",
        ),
        (
            "2025-02-15T00:00:00Z",
            15,
            "2025-02-15T00:00:00Z",
            "2025-03-15T00:00:00Z",
        ),
        (
            "2025-12-31T00:00:00Z",
            31,
            "2025-12-31T00:00:00Z",
            "2026-01-31T00:00:00Z",
        ),
        (
            "2026-01-30T23:59:59Z",
            31,
            "2025-12-31T00:00:00Z",
            "2026-01-31T00:00:00Z",
        ),
        (
            "1969-12-31T23:59:59Z",
            1,
            "1969-12-01T00:00:00Z",
            "1970-01-01T00:00:00Z",
        ),
    ] {
        let now = timestamp(now);
        let actual = server_traffic_period(now, day).unwrap();
        assert_eq!(actual, (timestamp(from), timestamp(next)));
        assert!(actual.0 <= now && now < actual.1);
    }
}

#[test]
fn monthly_period_clamps_each_month_without_a_sticky_february_reset() {
    for (now, day, from, next) in [
        (
            "2025-01-31T00:00:00Z",
            31,
            "2025-01-31T00:00:00Z",
            "2025-02-28T00:00:00Z",
        ),
        (
            "2025-02-27T23:59:59Z",
            31,
            "2025-01-31T00:00:00Z",
            "2025-02-28T00:00:00Z",
        ),
        (
            "2025-02-28T00:00:00Z",
            31,
            "2025-02-28T00:00:00Z",
            "2025-03-31T00:00:00Z",
        ),
        (
            "2025-03-30T23:59:59Z",
            31,
            "2025-02-28T00:00:00Z",
            "2025-03-31T00:00:00Z",
        ),
        (
            "2025-03-31T00:00:00Z",
            31,
            "2025-03-31T00:00:00Z",
            "2025-04-30T00:00:00Z",
        ),
        (
            "2025-04-30T00:00:00Z",
            31,
            "2025-04-30T00:00:00Z",
            "2025-05-31T00:00:00Z",
        ),
        (
            "2025-02-28T00:00:00Z",
            29,
            "2025-02-28T00:00:00Z",
            "2025-03-29T00:00:00Z",
        ),
        (
            "2024-02-29T00:00:00Z",
            30,
            "2024-02-29T00:00:00Z",
            "2024-03-30T00:00:00Z",
        ),
    ] {
        assert_eq!(
            server_traffic_period(timestamp(now), day).unwrap(),
            (timestamp(from), timestamp(next)),
            "now={now}, reset_day={day}"
        );
    }
}

#[test]
fn monthly_period_observes_leap_year_and_century_calendar_boundaries() {
    for (now, from, next) in [
        (
            "2024-01-31T00:00:00Z",
            "2024-01-31T00:00:00Z",
            "2024-02-29T00:00:00Z",
        ),
        (
            "2024-02-28T23:59:59Z",
            "2024-01-31T00:00:00Z",
            "2024-02-29T00:00:00Z",
        ),
        (
            "2024-02-29T00:00:00Z",
            "2024-02-29T00:00:00Z",
            "2024-03-31T00:00:00Z",
        ),
        (
            "1900-02-28T00:00:00Z",
            "1900-02-28T00:00:00Z",
            "1900-03-31T00:00:00Z",
        ),
        (
            "2000-02-29T00:00:00Z",
            "2000-02-29T00:00:00Z",
            "2000-03-31T00:00:00Z",
        ),
    ] {
        assert_eq!(
            server_traffic_period(timestamp(now), 31).unwrap(),
            (timestamp(from), timestamp(next)),
            "now={now}"
        );
    }
}

#[test]
fn monthly_period_rejects_invalid_days_and_unrepresentable_timestamps() {
    let now = timestamp("2025-01-01T00:00:00Z");
    for day in [0, 32, u8::MAX] {
        assert!(matches!(
            server_traffic_period(now, day),
            Err(SqliteInventoryError::Invalid(_))
        ));
    }
    for now in [i64::MIN, i64::MAX] {
        assert!(matches!(
            server_traffic_period(now, 1),
            Err(SqliteInventoryError::Invalid(_))
        ));
    }
}
