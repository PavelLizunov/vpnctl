//! Spec for `SqliteInventory::ack_all_unacked_alerts` — the «ack all
//! (N)» bulk-clear used by the operator-facing /admin/alerts feed.
//! Written from spec only — impl NOT consulted.
//!
//! Critical contract: rows that are ALREADY acked must keep their
//! ORIGINAL `acked_at` timestamp — the bulk-ack must not overwrite
//! history with `now`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use tempfile::TempDir;
use vpnctl_core::{KernelId, Server, ServerId};
use vpnctl_inventory::SqliteInventory;

async fn open(dir: &TempDir) -> SqliteInventory {
    SqliteInventory::open(&dir.path().join("inventory.db"))
        .await
        .expect("open")
}

fn srv(id: &str) -> Server {
    Server {
        id: ServerId(id.into()),
        address: "1.1.1.1".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

/// Seed N fresh-unacked rows of distinct `kind` values on `s1`.
/// Returns their ids in insertion order.
async fn seed_unacked(inv: &SqliteInventory, n: usize) -> Vec<i64> {
    let mut ids = Vec::with_capacity(n);
    for i in 0..n {
        let kind = format!("server.kind.{i}");
        let id = inv
            .insert_alert(
                &kind,
                Some(&ServerId("s1".into())),
                "warning",
                "seeded",
                None,
            )
            .await
            .expect("insert_alert");
        ids.push(id);
    }
    ids
}

// 1. Empty case — Ok(0), no mutation.
#[tokio::test]
async fn ack_all_on_empty_table_returns_zero_and_leaves_table_empty() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    let n = inv.ack_all_unacked_alerts().await.unwrap();
    assert_eq!(n, 0, "empty table ⇒ 0 rows affected");

    let rows = inv.recent_alerts(100, true).await.unwrap();
    assert!(rows.is_empty(), "no rows must have been created: {rows:?}");
    assert_eq!(
        inv.unacked_alert_count().await.unwrap(),
        0,
        "unacked count stays 0"
    );
}

// 2. All-unacked case — 5 rows → Ok(5), all acked.
#[tokio::test]
async fn ack_all_with_five_unacked_returns_five_and_acks_every_row() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("s1")).await.unwrap();

    let ids = seed_unacked(&inv, 5).await;
    assert_eq!(
        inv.unacked_alert_count().await.unwrap(),
        5,
        "sanity: 5 unacked before bulk ack"
    );

    let n = inv.ack_all_unacked_alerts().await.unwrap();
    assert_eq!(n, 5, "must report exactly the 5 rows affected, got {n}");

    let history = inv.recent_alerts(100, true).await.unwrap();
    assert_eq!(history.len(), 5, "all 5 rows must still exist");
    for row in &history {
        assert!(
            row.acked_at.is_some(),
            "row id={} must be acked, got acked_at={:?}",
            row.id,
            row.acked_at
        );
    }
    // Sanity: ids round-trip.
    let mut got: Vec<i64> = history.iter().map(|r| r.id).collect();
    got.sort();
    let mut want = ids.clone();
    want.sort();
    assert_eq!(got, want, "id set must round-trip");
}

// 3. Mixed case — 3 unacked + 2 already-acked. Bulk ack must affect
//    only the 3 unacked; the 2 already-acked rows MUST keep their
//    ORIGINAL `acked_at` value, NOT get overwritten with `now`.
#[tokio::test]
async fn ack_all_preserves_existing_ack_timestamps_on_already_acked_rows() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("s1")).await.unwrap();

    // Two rows we ack right now — these are the «historical» rows
    // whose timestamps must NOT be overwritten by the bulk ack.
    let pre_acked = seed_unacked(&inv, 2).await;
    for id in &pre_acked {
        assert!(
            inv.ack_alert(*id).await.unwrap(),
            "sanity: row id={id} must be ackable"
        );
    }

    // Snapshot the originals' acked_at values immediately after they
    // were acked.
    let originals: Vec<(i64, chrono::DateTime<chrono::Utc>)> = inv
        .recent_alerts(100, true)
        .await
        .unwrap()
        .into_iter()
        .filter(|r| pre_acked.contains(&r.id))
        .map(|r| (r.id, r.acked_at.expect("pre-acked row must have acked_at")))
        .collect();
    assert_eq!(originals.len(), 2, "must have captured both pre-acked ts");

    // Sleep long enough that strftime('%Y-%m-%dT%H:%M:%fZ','now')
    // would advance — millis resolution, so 50ms is plenty.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Add the 3 fresh-unacked rows on top.
    let unacked = seed_unacked(&inv, 3).await;
    assert_eq!(
        inv.unacked_alert_count().await.unwrap(),
        3,
        "sanity: exactly 3 unacked at this point"
    );

    // The bulk ack.
    let n = inv.ack_all_unacked_alerts().await.unwrap();
    assert_eq!(
        n, 3,
        "must affect ONLY the 3 unacked rows, not the 2 already-acked"
    );

    let after = inv.recent_alerts(100, true).await.unwrap();
    // The 2 originals must still carry their captured timestamps —
    // identity-equal, NOT just within some tolerance of `now`.
    for (orig_id, orig_ts) in &originals {
        let row = after
            .iter()
            .find(|r| r.id == *orig_id)
            .unwrap_or_else(|| panic!("row id={orig_id} disappeared"));
        let current = row
            .acked_at
            .unwrap_or_else(|| panic!("row id={orig_id} lost its acked_at"));
        assert_eq!(
            current, *orig_ts,
            "row id={orig_id} acked_at was overwritten by bulk ack \
             (orig={orig_ts}, now={current}) — bulk ack must NOT touch \
             already-acked rows"
        );
    }
    // The 3 freshly-acked rows now have an acked_at >= the originals'
    // (sanity that the bulk ack actually wrote them).
    for new_id in &unacked {
        let row = after
            .iter()
            .find(|r| r.id == *new_id)
            .unwrap_or_else(|| panic!("row id={new_id} disappeared"));
        let ts = row
            .acked_at
            .unwrap_or_else(|| panic!("freshly-bulk-acked row id={new_id} has no acked_at"));
        let orig_ts = originals[0].1;
        assert!(
            ts >= orig_ts,
            "freshly bulk-acked id={new_id} acked_at={ts} must be \
             >= the pre-acked originals' ts={orig_ts}"
        );
    }
}

// 4. Idempotency — first call returns N, second returns exactly 0.
#[tokio::test]
async fn ack_all_is_idempotent_second_call_returns_exactly_zero() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("s1")).await.unwrap();

    seed_unacked(&inv, 4).await;

    let first = inv.ack_all_unacked_alerts().await.unwrap();
    assert_eq!(first, 4, "first bulk ack must report 4");

    let second = inv.ack_all_unacked_alerts().await.unwrap();
    assert_eq!(
        second, 0,
        "second bulk ack must report exactly 0 — there's nothing left \
         unacked, got {second}"
    );
}

// 5. After bulk ack, `unacked_alert_count()` returns 0.
#[tokio::test]
async fn ack_all_drains_unacked_count_to_zero() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("s1")).await.unwrap();

    seed_unacked(&inv, 7).await;
    assert_eq!(
        inv.unacked_alert_count().await.unwrap(),
        7,
        "sanity: 7 unacked before bulk ack"
    );

    let n = inv.ack_all_unacked_alerts().await.unwrap();
    assert_eq!(n, 7);

    assert_eq!(
        inv.unacked_alert_count().await.unwrap(),
        0,
        "unacked_alert_count must report 0 after bulk ack"
    );
}
