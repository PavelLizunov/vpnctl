//! Spec for `SqliteInventory::idle_users` — backs the dashboard A2
//! «idle users · revoke candidates» panel. Written from spec only —
//! impl NOT consulted at test-writer time.
//!
//! Contract: returns `(UserId, Option<DateTime<Utc>>)` for users whose
//! most recent `sub_access_log` row (with `is_vpn_egress=0`) is older
//! than `days` days, OR who have never appeared in the access log
//! at all (`last_seen = None`). Sorted oldest-first with NULL first.
//!
//! Test strategy: we can't easily backdate `sub_access_log` rows
//! (the writer always stamps `now` via SCHEMA DEFAULT). So:
//!
//!   * Use `days = 30` (production threshold) for «recently seen»
//!     tests — recent hits stay out of the idle list.
//!   * Use `days = 0` for the «any seen counts as idle» branch — a
//!     hit timestamp written a few microseconds ago IS `< now` so
//!     the user IS classified idle.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use tempfile::TempDir;
use vpnctl_core::{User, UserId};
use vpnctl_inventory::SqliteInventory;

async fn open(dir: &TempDir) -> SqliteInventory {
    SqliteInventory::open(&dir.path().join("inventory.db"))
        .await
        .expect("open")
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
    // threshold=0 → cutoff = now → ANY existing row makes user idle.
    // last_seen must be Some(...) (NOT None — that's the never-seen
    // branch).
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("dormant", 3)).await.unwrap();
    inv.log_sub_access(
        &UserId("dormant".into()),
        "203.0.113.2",
        Some("curl"),
        200,
        0,
    )
    .await
    .unwrap();
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
    inv.log_sub_access(
        &UserId("dormant".into()),
        "203.0.113.3",
        Some("curl"),
        200,
        0,
    )
    .await
    .unwrap();
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
