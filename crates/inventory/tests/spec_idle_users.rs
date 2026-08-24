//! Spec for `SqliteInventory::idle_users` — backs the dashboard A2
//! «idle users · revoke candidates» panel. Written from spec only —
//! impl NOT consulted at test-writer time.
//!
//! Contract: returns `(UserId, Option<DateTime<Utc>>)` for users whose
//! most recent `sub_access_log` row (with `is_vpn_egress=0`) is older
//! than `days` days, OR who have never appeared in the access log
//! at all (`last_seen = None`). Sorted oldest-first with NULL first,
//! with deterministic secondary tie-breaker by `u.id ASC`.
//!
//! Test strategy: `sub_access_log` rows can be populated via standard
//! `log_sub_access` or deterministically injected via `raw_pool` with
//! explicit ISO timestamps / SQLite relative offsets for stress-safe
//! timing.

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

/// Raw pool against the test DB for stress-safe deterministic timestamp injection.
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

/// Inject sub_access_log row with an explicit RFC3339 timestamp.
async fn inject_sub_access_at(pool: &sqlx::SqlitePool, uid: &str, ip: &str, ts: &str) {
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

/// Inject sub_access_log row with a relative SQLite offset (e.g. `"-30 days"`).
async fn inject_sub_access_offset(pool: &sqlx::SqlitePool, uid: &str, ip: &str, offset: &str) {
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

fn user(id: &str, suffix: u32) -> User {
    User {
        id: UserId(id.into()),
        uuid: format!("00000000-0000-0000-0000-{suffix:012}"),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    }
}

#[tokio::test]
async fn empty_inventory_returns_empty() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let got = inv.idle_users(30, 50).await.unwrap();
    assert!(got.is_empty(), "empty inventory → no idle users");
}

#[tokio::test]
async fn user_with_no_access_rows_is_idle_with_none_last_seen() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("ghost", 1)).await.unwrap();
    let got = inv.idle_users(30, 50).await.unwrap();
    assert_eq!(got.len(), 1, "the one never-seen user must surface");
    assert_eq!(got[0].0.0, "ghost");
    assert!(
        got[0].1.is_none(),
        "never-seen user must have last_seen = None"
    );
}

#[tokio::test]
async fn user_seen_recently_is_excluded_at_30_day_threshold() {
    // Hit happened «now» → NOT idle on the 30-day threshold.
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("active", 2)).await.unwrap();
    inv.log_sub_access(
        &UserId("active".into()),
        "203.0.113.1",
        Some("curl"),
        200,
        0,
    )
    .await
    .unwrap();
    let got = inv.idle_users(30, 50).await.unwrap();
    assert!(
        got.is_empty(),
        "0-day-old hit is < 30-day threshold; user must not appear: got {got:?}"
    );
}

#[tokio::test]
async fn user_with_any_hit_is_idle_at_zero_day_threshold_with_some_last_seen() {
    // threshold=0 → cutoff = now → ANY existing row (<= now) makes user idle.
    // last_seen must be Some(...) (NOT None — that's the never-seen
    // branch).
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("dormant", 3)).await.unwrap();
    let pool = raw_pool(&dir).await;
    inject_sub_access_offset(&pool, "dormant", "203.0.113.2", "-1 hour").await;

    let got = inv.idle_users(0, 50).await.unwrap();
    assert_eq!(got.len(), 1, "the seen-but-stale user must surface");
    assert_eq!(got[0].0.0, "dormant");
    assert!(
        got[0].1.is_some(),
        "seen user must have last_seen = Some(...), got {got:?}"
    );
}

#[tokio::test]
async fn never_seen_user_sorts_before_seen_user() {
    // Both must appear (threshold=0 captures everything). Sort
    // contract: NULL-last-seen first, then seen rows by ts ASC.
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("ghost", 4)).await.unwrap();
    inv.add_user(&user("dormant", 5)).await.unwrap();
    let pool = raw_pool(&dir).await;
    inject_sub_access_offset(&pool, "dormant", "203.0.113.3", "-1 hour").await;

    let got = inv.idle_users(0, 50).await.unwrap();
    let ids: Vec<&str> = got.iter().map(|(u, _)| u.0.as_str()).collect();
    assert_eq!(
        ids,
        vec!["ghost", "dormant"],
        "never-seen (ghost) must precede seen (dormant)"
    );
}

#[tokio::test]
async fn limit_caps_returned_row_count() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    for n in 0..5 {
        inv.add_user(&user(&format!("u{n}"), 100 + n))
            .await
            .unwrap();
    }
    let got = inv.idle_users(30, 2).await.unwrap();
    assert_eq!(got.len(), 2, "limit=2 must cap the row count");
}

#[tokio::test]
async fn equal_last_seen_users_sort_deterministically_by_user_id() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("charlie", 10)).await.unwrap();
    inv.add_user(&user("alice", 11)).await.unwrap();
    inv.add_user(&user("bob", 12)).await.unwrap();

    let pool = raw_pool(&dir).await;
    let fixed_ts = "2026-01-01T12:00:00.000Z";
    inject_sub_access_at(&pool, "charlie", "1.1.1.1", fixed_ts).await;
    inject_sub_access_at(&pool, "alice", "1.1.1.2", fixed_ts).await;
    inject_sub_access_at(&pool, "bob", "1.1.1.3", fixed_ts).await;

    let got = inv.idle_users(30, 50).await.unwrap();
    assert_eq!(got.len(), 3);
    let ids: Vec<&str> = got.iter().map(|(u, _)| u.0.as_str()).collect();
    assert_eq!(
        ids,
        vec!["alice", "bob", "charlie"],
        "equal timestamps must be deterministically tie-broken by user_id ASC"
    );
}

#[tokio::test]
async fn multiple_never_seen_users_sort_deterministically_by_user_id() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("zeta", 20)).await.unwrap();
    inv.add_user(&user("alpha", 21)).await.unwrap();
    inv.add_user(&user("beta", 22)).await.unwrap();

    let got = inv.idle_users(30, 50).await.unwrap();
    assert_eq!(got.len(), 3);
    let ids: Vec<&str> = got.iter().map(|(u, _)| u.0.as_str()).collect();
    assert_eq!(
        ids,
        vec!["alpha", "beta", "zeta"],
        "multiple NULL last_seen users must sort by user_id ASC"
    );
}

#[tokio::test]
async fn exact_cutoff_timestamp_is_included_in_idle_users() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("border", 30)).await.unwrap();

    let pool = raw_pool(&dir).await;
    // Exactly 30 days ago
    inject_sub_access_offset(&pool, "border", "1.1.1.1", "-30 days").await;

    let got = inv.idle_users(30, 50).await.unwrap();
    assert_eq!(
        got.len(),
        1,
        "row at exactly the 30-day cutoff must be included (<= condition)"
    );
    assert_eq!(got[0].0.0, "border");
}
