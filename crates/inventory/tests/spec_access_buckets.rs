//! Spec for `SqliteInventory::sub_access_buckets` — time-bucketed
//! aggregation of `sub_access_log` for the abuse-signal sparkline UI.
//! Written against public API spec only; impl NOT consulted.
//! Contract: empty→[], same-hour collapses (hits/distinct_ips), ASC
//! by bucket_start, day-bucket collapses same-date, only "hour"/"day"
//! valid, since_hours=0 excludes all (strict `> now`), zero-hit
//! buckets NEVER returned (caller fills gaps).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use tempfile::TempDir;
use vpnctl_core::{User, UserId};
use vpnctl_inventory::SqliteInventory;

fn db_path(dir: &TempDir) -> PathBuf {
    dir.path().join("inventory.db")
}

async fn open(dir: &TempDir) -> SqliteInventory {
    SqliteInventory::open(&db_path(dir)).await.expect("open")
}

fn user(id: &str) -> User {
    User {
        id: UserId(id.to_string()),
        uuid: format!("uuid-of-{id}"),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    }
}

/// Second pool against same DB — `log_sub_access` only writes server-now,
/// so deterministic multi-hour timestamps need raw SQL injection. FKs ON
/// to mirror prod (else orphan inserts would silently succeed).
async fn raw_pool(dir: &TempDir) -> sqlx::SqlitePool {
    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", db_path(dir).display()))
        .await
        .unwrap();
    sqlx::query("PRAGMA foreign_keys = ON")
        .execute(&pool)
        .await
        .unwrap();
    pool
}

/// Inject ts = now + `offset` (e.g. `"-2 hours"`) in same ISO `T`-form
/// as `log_sub_access` (per format-mismatch lesson in `spec_sub_access.rs`).
/// Absolute-timestamp variant — anchors rows at an explicit UTC time
/// so date-bucket tests can't straddle midnight (caught 2026-07-10 at
/// 00:3x UTC: `-1h/-2h/-3h` offsets landed on two dates → flake).
async fn inject_at_abs(pool: &sqlx::SqlitePool, uid: &str, ip: &str, ts: &str) {
    sqlx::query(
        "INSERT INTO sub_access_log (ts, user_id, ip, status, bytes)
         VALUES (?1, ?2, ?3, 200, 100)",
    )
    .bind(ts)
    .bind(uid)
    .bind(ip)
    .execute(pool)
    .await
    .unwrap();
}

async fn inject_at(pool: &sqlx::SqlitePool, uid: &str, ip: &str, offset: &str) {
    sqlx::query(
        "INSERT INTO sub_access_log (ts, user_id, ip, status, bytes)
         VALUES (strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1), ?2, ?3, 200, 100)",
    )
    .bind(offset)
    .bind(uid)
    .bind(ip)
    .execute(pool)
    .await
    .unwrap();
}

#[tokio::test]
async fn empty_table_returns_empty_vec() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let buckets = inv.sub_access_buckets("hour", 24).await.unwrap();
    assert!(buckets.is_empty(), "no rows → no buckets");
}

#[tokio::test]
async fn two_rows_in_same_hour_collapse_into_one_bucket_same_ip() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    let raw = raw_pool(&dir).await;
    // Sub-second offsets: with `-5 minutes` / `-10 minutes` this test
    // flaked any time it ran in the first 10 minutes of an hour
    // (caught at 20:08 UTC: -5m=20:03, -10m=19:58 → two hours, not
    // one). The spec is "two rows in the same hour"; sub-second
    // offsets honour that without depending on which minute we run.
    inject_at(&raw, "alice", "1.1.1.1", "-1 seconds").await;
    inject_at(&raw, "alice", "1.1.1.1", "-2 seconds").await;
    raw.close().await;

    let buckets = inv.sub_access_buckets("hour", 24).await.unwrap();
    assert_eq!(buckets.len(), 1, "same hour → one bucket");
    assert_eq!(buckets[0].hits, 2, "both rows counted");
    assert_eq!(buckets[0].distinct_ips, 1, "same IP → distinct=1");
}

#[tokio::test]
async fn distinct_ips_counts_unique_addresses_within_a_bucket() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    let raw = raw_pool(&dir).await;
    // Sub-second offsets (same fix pattern as
    // `two_rows_in_same_hour_collapse_into_one_bucket_same_ip` above):
    // `-3 minutes` / `-4 minutes` flaked on GitHub CI run 25961428447
    // at 2026-05-16T12:03:14Z — the second offset crossed back into
    // the previous hour, producing 2 buckets instead of the asserted 1.
    // Spec is "two rows in same hour"; sub-second offsets satisfy it
    // without depending on the current minute-of-hour.
    inject_at(&raw, "alice", "1.1.1.1", "-1 seconds").await;
    inject_at(&raw, "alice", "2.2.2.2", "-2 seconds").await;
    raw.close().await;

    let buckets = inv.sub_access_buckets("hour", 24).await.unwrap();
    assert_eq!(buckets.len(), 1);
    assert_eq!(buckets[0].hits, 2);
    assert_eq!(buckets[0].distinct_ips, 2, "two IPs → distinct=2");
}

#[tokio::test]
async fn rows_in_different_hours_produce_two_buckets_oldest_first() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    let raw = raw_pool(&dir).await;
    // Insert NEWER first so ASC ordering isn't satisfied by accident.
    inject_at(&raw, "alice", "1.1.1.1", "-30 minutes").await;
    inject_at(&raw, "alice", "2.2.2.2", "-3 hours").await;
    raw.close().await;

    let buckets = inv.sub_access_buckets("hour", 24).await.unwrap();
    assert_eq!(buckets.len(), 2, "two distinct hours → two buckets");
    assert!(
        buckets[0].bucket_start < buckets[1].bucket_start,
        "ASC: oldest first, got {:?} then {:?}",
        buckets[0].bucket_start,
        buckets[1].bucket_start,
    );
    assert_eq!(buckets[0].hits, 1);
    assert_eq!(buckets[1].hits, 1);
}

#[tokio::test]
async fn day_bucket_collapses_rows_from_same_date() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    let raw = raw_pool(&dir).await;
    // Yesterday noon — one calendar date no matter what time it is
    // now (relative -1h/-2h/-3h offsets straddle midnight when the
    // suite runs at 00:00-03:00 UTC).
    let base = (chrono::Utc::now() - chrono::Duration::days(1))
        .date_naive()
        .and_hms_opt(12, 0, 0)
        .unwrap();
    for (i, ip) in ["1.1.1.1", "2.2.2.2", "3.3.3.3"].iter().enumerate() {
        let ts = (base + chrono::Duration::minutes(i as i64))
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();
        inject_at_abs(&raw, "alice", ip, &ts).await;
    }
    raw.close().await;

    let buckets = inv.sub_access_buckets("day", 48).await.unwrap();
    assert_eq!(buckets.len(), 1, "same date → one day bucket");
    assert_eq!(buckets[0].hits, 3);
    assert_eq!(buckets[0].distinct_ips, 3);
}

#[tokio::test]
async fn unknown_bucket_kind_returns_err() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    for bad in ["minute", "week", "", "HOUR", "Day"] {
        let res = inv.sub_access_buckets(bad, 24).await;
        assert!(res.is_err(), "bucket={bad:?} must be rejected");
    }
}

#[tokio::test]
async fn since_hours_zero_excludes_all_rows() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    inv.log_sub_access(&UserId("alice".into()), "9.9.9.9", None, 200, 100)
        .await
        .unwrap();

    let buckets = inv.sub_access_buckets("hour", 0).await.unwrap();
    assert!(
        buckets.is_empty(),
        "since_hours=0 → strict `ts > now` excludes everything, got {}",
        buckets.len(),
    );
}

#[tokio::test]
async fn zero_hit_hours_between_active_buckets_are_not_returned() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    let raw = raw_pool(&dir).await;
    // Hits at ~1h and ~5h ago; the three middle hours have no rows.
    inject_at(&raw, "alice", "1.1.1.1", "-1 hour").await;
    inject_at(&raw, "alice", "2.2.2.2", "-5 hours").await;
    raw.close().await;

    let buckets = inv.sub_access_buckets("hour", 24).await.unwrap();
    assert_eq!(
        buckets.len(),
        2,
        "only hours WITH hits appear — got {} (impl filling gaps?)",
        buckets.len(),
    );
    for b in &buckets {
        assert!(b.hits >= 1, "every returned bucket must have ≥1 hit");
    }
}
