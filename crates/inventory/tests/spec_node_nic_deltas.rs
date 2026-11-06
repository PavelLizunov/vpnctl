#![allow(clippy::unwrap_used, clippy::expect_used)]

use chrono::{DateTime, Utc};
use sqlx::{SqlitePool, sqlite::SqliteConnectOptions};
use tempfile::TempDir;
use vpnctl_core::{Server, ServerId};
use vpnctl_inventory::{NodeNicDelta, NodeNicUsage, SqliteInventory, SqliteInventoryError};

const START: i64 = 1_700_000_000;

struct Fixture {
    inv: SqliteInventory,
    pool: SqlitePool,
    sid: ServerId,
    _dir: TempDir,
}

impl Fixture {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nic-deltas.sqlite");
        let inv = SqliteInventory::open(&path).await.unwrap();
        let sid = ServerId("nic-delta-spec-node".to_owned());
        inv.add_server(&Server {
            id: sid.clone(),
            address: "192.0.2.1".to_owned(),
            ssh_port: 22,
            ssh_user: "root".to_owned(),
            kernels: Vec::new(),
            enabled_protocols: Vec::new(),
            trusted_host_fingerprint: None,
            hoster: "synthetic".to_owned(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
        let pool = SqlitePool::connect_with(SqliteConnectOptions::new().filename(&path))
            .await
            .unwrap();
        Self {
            inv,
            pool,
            sid,
            _dir: dir,
        }
    }

    async fn sample(
        &self,
        id: usize,
        ts: &str,
        iface: Option<&str>,
        rx: Option<i64>,
        tx: Option<i64>,
    ) {
        sqlx::query(
            "INSERT INTO node_health \
             (sample_id, server_id, ts, nic_iface, nic_rx_bytes, nic_tx_bytes) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(format!("sample-{id}"))
        .bind(&self.sid.0)
        .bind(ts)
        .bind(iface)
        .bind(rx)
        .bind(tx)
        .execute(&self.pool)
        .await
        .unwrap();
    }

    async fn nic(&self, id: usize, seconds: i64, iface: &str, rx: i64, tx: i64) {
        self.sample(
            id,
            &at(seconds).to_rfc3339(),
            Some(iface),
            Some(rx),
            Some(tx),
        )
        .await;
    }

    async fn usage(&self, seconds: i64, max_gap: u64) -> Option<NodeNicUsage> {
        self.inv
            .node_nic_usage(&self.sid, START, START + seconds, max_gap)
            .await
            .unwrap()
    }
}

fn at(seconds: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(START + seconds, 0).unwrap()
}

fn delta(seconds: i64, rx_bytes: u64, tx_bytes: u64) -> NodeNicDelta {
    NodeNicDelta {
        ts: at(seconds),
        rx_bytes,
        tx_bytes,
    }
}

fn assert_conserved(usage: &NodeNicUsage) {
    assert_eq!(
        usage.deltas.iter().map(|d| d.rx_bytes).sum::<u64>(),
        usage.rx_bytes
    );
    assert_eq!(
        usage.deltas.iter().map(|d| d.tx_bytes).sum::<u64>(),
        usage.tx_bytes
    );
    assert_eq!(usage.rx_bytes + usage.tx_bytes, usage.total_bytes);
    assert_eq!(usage.deltas.len(), usage.samples - 1);
}

#[tokio::test]
async fn consecutive_deltas_use_later_timestamps_and_conserve_totals() {
    fn assert_traits<T: Clone + std::fmt::Debug + PartialEq + Eq>() {}
    assert_traits::<NodeNicDelta>();

    let f = Fixture::new().await;
    f.nic(0, 0, "eth0", 100, 200).await;
    f.nic(1, 30, "eth0", 130, 240).await;
    f.nic(2, 60, "eth0", 130, 240).await;
    f.nic(3, 120, "eth0", 180, 300).await;

    let usage = f.usage(120, 60).await.unwrap();
    assert_eq!(
        usage.deltas,
        vec![delta(30, 30, 40), delta(60, 0, 0), delta(120, 50, 60)]
    );
    assert_eq!(
        (usage.rx_bytes, usage.tx_bytes, usage.total_bytes),
        (80, 100, 180)
    );
    assert_eq!(usage.samples, 4);
    assert_eq!(usage.first_sample_ts, at(0));
    assert_eq!(usage.last_sample_ts, at(120));
    assert!(!usage.interrupted);
    assert!(usage.complete);
    assert_conserved(&usage);
}

#[tokio::test]
async fn measured_zero_has_an_available_zero_delta() {
    let f = Fixture::new().await;
    f.nic(0, 0, "eth0", 0, 0).await;
    f.nic(1, 60, "eth0", 0, 0).await;

    let usage = f.usage(60, 60).await.unwrap();
    assert_eq!(usage.deltas, vec![delta(60, 0, 0)]);
    assert_eq!(usage.total_bytes, 0);
    assert!(!usage.interrupted);
    assert!(usage.complete);
    assert_conserved(&usage);
}

#[tokio::test]
async fn each_reset_direction_counts_only_its_new_counter() {
    let f = Fixture::new().await;
    f.nic(0, 0, "eth0", 1_000, 2_000).await;
    f.nic(1, 30, "eth0", 10, 2_100).await;
    f.nic(2, 60, "eth0", 50, 5).await;
    f.nic(3, 90, "eth0", 3, 2).await;

    let usage = f.usage(90, 60).await.unwrap();
    assert_eq!(
        usage.deltas,
        vec![delta(30, 10, 100), delta(60, 40, 5), delta(90, 3, 2)]
    );
    assert_eq!((usage.rx_bytes, usage.tx_bytes), (53, 107));
    assert!(usage.interrupted);
    assert!(!usage.complete);
    assert_conserved(&usage);
}

#[tokio::test]
async fn interface_change_emits_zero_and_establishes_a_new_baseline() {
    let f = Fixture::new().await;
    f.nic(0, 0, "eth0", 100, 200).await;
    f.nic(1, 30, "eth1", 5_000, 9_000).await;
    f.nic(2, 60, "eth1", 5_005, 9_008).await;

    let usage = f.usage(60, 60).await.unwrap();
    assert_eq!(usage.deltas, vec![delta(30, 0, 0), delta(60, 5, 8)]);
    assert_eq!((usage.rx_bytes, usage.tx_bytes), (5, 8));
    assert!(usage.interrupted);
    assert!(!usage.complete);
    assert_conserved(&usage);
}

#[tokio::test]
async fn health_only_null_rows_emit_nothing_and_do_not_disturb_valid_pairs() {
    let f = Fixture::new().await;
    f.sample(0, &at(0).to_rfc3339(), None, None, None).await;
    f.nic(1, 0, "eth0", 100, 200).await;
    f.sample(2, &at(30).to_rfc3339(), None, None, None).await;
    f.nic(3, 60, "eth0", 110, 220).await;

    let usage = f.usage(60, 60).await.unwrap();
    assert_eq!(usage.deltas, vec![delta(60, 10, 20)]);
    assert_eq!(usage.samples, 2);
    assert!(!usage.interrupted);
    assert!(usage.complete);
    assert_conserved(&usage);
}

#[tokio::test]
async fn gaps_are_between_usable_samples_even_when_health_rows_fill_the_gap() {
    let f = Fixture::new().await;
    f.nic(0, 0, "eth0", 100, 200).await;
    for (id, seconds) in [(1, 30), (2, 60), (3, 90)] {
        f.sample(id, &at(seconds).to_rfc3339(), None, None, None)
            .await;
    }
    f.nic(4, 120, "eth0", 110, 220).await;

    let usage = f.usage(120, 60).await.unwrap();
    assert_eq!(usage.deltas, vec![delta(120, 10, 20)]);
    assert_eq!(usage.samples, 2);
    assert!(usage.interrupted);
    assert!(!usage.complete);
    assert_conserved(&usage);
}

#[tokio::test]
async fn readings_before_start_do_not_establish_the_window_baseline() {
    let f = Fixture::new().await;
    f.nic(0, -1, "eth0", 1, 2).await;
    f.nic(1, 0, "eth0", 100, 200).await;
    f.nic(2, 60, "eth0", 110, 220).await;

    let usage = f.usage(60, 60).await.unwrap();
    assert_eq!(usage.deltas, vec![delta(60, 10, 20)]);
    assert_eq!(usage.samples, 2);
    assert_eq!(usage.first_sample_ts, at(0));
    assert_conserved(&usage);
}

#[tokio::test]
async fn missing_or_single_usable_sample_is_unavailable() {
    let f = Fixture::new().await;
    assert!(f.usage(60, 60).await.is_none());
    f.sample(0, &at(0).to_rfc3339(), None, None, None).await;
    assert!(f.usage(60, 60).await.is_none());
    f.nic(1, 60, "eth0", 0, 0).await;
    assert!(f.usage(60, 60).await.is_none());
}

#[tokio::test]
async fn invalid_counters_or_missing_interface_discard_the_whole_vector() {
    for defect in [
        "nic_rx_bytes = NULL",
        "nic_tx_bytes = NULL",
        "nic_rx_bytes = -1",
        "nic_tx_bytes = -1",
        "nic_rx_bytes = 1.5",
        "nic_tx_bytes = 1.5",
        "nic_rx_bytes = 'invalid'",
        "nic_tx_bytes = 'invalid'",
        "nic_iface = NULL",
    ] {
        let f = Fixture::new().await;
        f.nic(0, 0, "eth0", 10, 20).await;
        f.nic(1, 60, "eth0", 20, 40).await;
        f.nic(2, 120, "eth0", 30, 60).await;
        sqlx::query(&format!(
            "UPDATE node_health SET {defect} WHERE sample_id = 'sample-2'"
        ))
        .execute(&f.pool)
        .await
        .unwrap();
        assert!(f.usage(120, 60).await.is_none(), "{defect}");
    }
}

#[tokio::test]
async fn malformed_future_or_backwards_timestamps_discard_the_whole_vector() {
    for invalid_ts in [
        "not-a-timestamp".to_owned(),
        at(121).to_rfc3339(),
        at(30).to_rfc3339(),
    ] {
        let f = Fixture::new().await;
        f.nic(0, 0, "eth0", 10, 20).await;
        f.nic(1, 60, "eth0", 20, 40).await;
        f.sample(2, &invalid_ts, Some("eth0"), Some(30), Some(60))
            .await;
        assert!(f.usage(120, 60).await.is_none(), "{invalid_ts}");
    }
}

#[tokio::test]
async fn rx_tx_or_combined_overflow_discards_the_whole_vector() {
    let max = i64::MAX;
    for counters in [
        vec![(0, 0), (max, 0), (0, 0), (max, 0), (0, 0), (max, 0)],
        vec![(0, 0), (0, max), (0, 0), (0, max), (0, 0), (0, max)],
        vec![(0, 0), (max, max), (0, 0), (1, 1)],
    ] {
        let f = Fixture::new().await;
        for (id, &(rx, tx)) in counters.iter().enumerate() {
            f.nic(id, i64::try_from(id).unwrap() * 30, "eth0", rx, tx)
                .await;
        }
        assert!(f.usage(180, 60).await.is_none());
    }
}

#[tokio::test]
async fn excessive_sample_count_is_unavailable() {
    let f = Fixture::new().await;
    sqlx::query(
        "WITH RECURSIVE n(value) AS \
         (VALUES (0) UNION ALL SELECT value + 1 FROM n WHERE value < 100000) \
         INSERT INTO node_health \
         (sample_id, server_id, ts, nic_iface, nic_rx_bytes, nic_tx_bytes) \
         SELECT printf('bulk-%d', value), ?, ?, 'eth0', value, value FROM n",
    )
    .bind(&f.sid.0)
    .bind(at(0).to_rfc3339())
    .execute(&f.pool)
    .await
    .unwrap();
    assert!(f.usage(60, 60).await.is_none());
}

#[tokio::test]
async fn invalid_window_arguments_return_an_error() {
    let f = Fixture::new().await;
    for (start, now, max_gap) in [
        (START, START, 60),
        (START + 1, START, 60),
        (START, START + 40 * 86_400 + 1, 60),
        (START, START + 60, 0),
    ] {
        assert!(
            matches!(
                f.inv.node_nic_usage(&f.sid, start, now, max_gap).await,
                Err(SqliteInventoryError::Invalid(_))
            ),
            "start={start}, now={now}, max_gap={max_gap}"
        );
    }
}
