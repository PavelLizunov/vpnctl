//! Spec for Track-2 rate-limit bans on `SqliteInventory`. Public API
//! + `migrations/0005_sub_rate_bans.sql` schema only — impl NOT read.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use tempfile::TempDir;

use vpnctl_inventory::SqliteInventory;

fn db_path(dir: &TempDir) -> PathBuf {
    dir.path().join("inventory.db")
}

async fn open(dir: &TempDir) -> SqliteInventory {
    SqliteInventory::open(&db_path(dir)).await.expect("open")
}

#[tokio::test]
async fn add_then_is_banned_returns_some_with_ttl_near_requested() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_ban("ip", "192.0.2.1", 3600, "burst").await.unwrap();

    let secs = inv
        .is_banned("ip", "192.0.2.1")
        .await
        .unwrap()
        .expect("rule 1: after add_ban ttl=3600, is_banned must be Some");
    assert!(
        (3590..=3600).contains(&secs),
        "rule 1: is_banned must report ~ttl_secs remaining, got {secs}s \
         outside (3590..=3600)"
    );
}

#[tokio::test]
async fn is_banned_returns_none_when_no_row_matches() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    let res = inv.is_banned("ip", "203.0.113.99").await.unwrap();
    assert!(res.is_none(), "rule 2: no row → None, got {res:?}");
}

#[tokio::test]
async fn is_banned_isolates_kinds() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_ban("ip", "192.0.2.5", 600, "ip-burst")
        .await
        .unwrap();

    let cross = inv.is_banned("token", "192.0.2.5").await.unwrap();
    assert!(
        cross.is_none(),
        "rule 3: ip-key under token kind MUST be None — \
         per-axis isolation broken, got {cross:?}"
    );

    let same = inv.is_banned("ip", "192.0.2.5").await.unwrap();
    assert!(
        same.is_some(),
        "rule 3 sanity: same-axis lookup must still return Some"
    );
}

#[tokio::test]
async fn overlapping_bans_report_soonest_expiry() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    // Same key, two bans — short ttl second so it's clearly the soonest
    // even with sub-second clock drift between inserts.
    inv.add_ban("token", "tok-abc", 9000, "long").await.unwrap();
    inv.add_ban("token", "tok-abc", 60, "short").await.unwrap();

    let remaining = inv
        .is_banned("token", "tok-abc")
        .await
        .unwrap()
        .expect("rule 4: at least one ban active");
    assert!(
        (50..=60).contains(&remaining),
        "rule 4: soonest of (60s, 9000s) wins — got {remaining}s, expected ~60s"
    );
}

#[tokio::test]
async fn zero_ttl_row_is_purged_even_if_is_banned_races() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_ban("ip", "198.51.100.7", 0, "").await.unwrap();
    // Rule 5: is_banned for zero-ttl may return None OR Some — accept either.
    let _ = inv.is_banned("ip", "198.51.100.7").await.unwrap();

    let removed = inv.purge_expired_bans().await.unwrap();
    assert!(
        removed >= 1,
        "rule 5: purge_expired_bans MUST drop the zero-ttl row, removed={removed}"
    );

    let after = inv.is_banned("ip", "198.51.100.7").await.unwrap();
    assert!(
        after.is_none(),
        "rule 5: after purge, is_banned must be None, got {after:?}"
    );
}

#[tokio::test]
async fn add_ban_with_invalid_kind_returns_err() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    let res = inv.add_ban("invalid", "anything", 60, "x").await;
    assert!(
        res.is_err(),
        "rule 6: kind not in ('ip','token') MUST be rejected by SQL CHECK"
    );
}

#[tokio::test]
async fn active_bans_lists_all_kinds_newest_first() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_ban("ip", "10.0.0.1", 600, "first").await.unwrap();
    inv.add_ban("token", "tok-1", 600, "second").await.unwrap();
    inv.add_ban("ip", "10.0.0.2", 600, "third").await.unwrap();

    let bans = inv.active_bans().await.unwrap();
    assert_eq!(bans.len(), 3, "rule 7: all 3 must list, got {}", bans.len());

    // Newest-first — last-inserted reason='third' must be index 0.
    assert_eq!(
        bans[0].reason, "third",
        "rule 7: must be created_at DESC; got {:?} first",
        bans[0].reason
    );
    assert_eq!(bans[1].reason, "second", "rule 7: middle row order");
    assert_eq!(bans[2].reason, "first", "rule 7: oldest row last");

    assert_eq!(bans[0].kind, "ip");
    assert_eq!(bans[0].key, "10.0.0.2");
    assert_eq!(bans[1].kind, "token");
    assert_eq!(bans[1].key, "tok-1");

    let now = chrono::Utc::now();
    for b in &bans {
        let age = (now - b.created_at).num_seconds().abs();
        assert!(
            age < 5,
            "rule 7: created_at near now, {age}s drift id={}",
            b.id
        );
        assert!(
            b.until_ts > b.created_at,
            "rule 7: until_ts > created_at on id={}",
            b.id
        );
    }
}

#[tokio::test]
async fn purge_returns_zero_when_nothing_expired() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_ban("ip", "10.0.0.50", 3600, "fresh").await.unwrap();

    let removed = inv.purge_expired_bans().await.unwrap();
    assert_eq!(removed, 0, "rule 8: nothing expired → 0, got {removed}");

    assert!(
        inv.is_banned("ip", "10.0.0.50").await.unwrap().is_some(),
        "rule 8 sanity: long-ttl ban survives a no-op purge"
    );
}

#[tokio::test]
async fn purge_returns_count_of_dropped_rows() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_ban("ip", "10.0.0.10", 0, "ea").await.unwrap();
    inv.add_ban("token", "tok-x", 0, "eb").await.unwrap();
    inv.add_ban("ip", "10.0.0.99", 7200, "fresh").await.unwrap();

    let removed = inv.purge_expired_bans().await.unwrap();
    assert_eq!(
        removed, 2,
        "rule 8: purge MUST return dropped-row count (2), got {removed}"
    );

    let active = inv.active_bans().await.unwrap();
    assert_eq!(active.len(), 1, "rule 8: only fresh ban remains");
    assert_eq!(active[0].reason, "fresh");
}
