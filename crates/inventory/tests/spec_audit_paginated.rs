//! Spec for `SqliteInventory::recent_audit_paginated` — impl NOT
//! consulted. Rules 1-8 from the test-writer brief.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use serde_json::json;
use tempfile::TempDir;

use vpnctl_inventory::SqliteInventory;

fn db_path(dir: &TempDir) -> PathBuf {
    dir.path().join("inventory.db")
}

async fn open(dir: &TempDir) -> SqliteInventory {
    SqliteInventory::open(&db_path(dir)).await.expect("open")
}

/// 5-row corpus. Insertion order = id order; last inserted is newest.
async fn seed_mixed(inv: &SqliteInventory) {
    inv.audit("admin", "server.deploy", Some("srv-1"), None)
        .await
        .unwrap();
    inv.audit(
        "admin",
        "user.add",
        Some("alice"),
        Some(&json!({"src": "web"})),
    )
    .await
    .unwrap();
    inv.audit("admin-bot", "user.add", Some("bob"), None)
        .await
        .unwrap();
    inv.audit("admin", "grant.add", Some("alice/srv-1"), None)
        .await
        .unwrap();
    inv.audit("admin", "user.delete", Some("alice"), None)
        .await
        .unwrap();
}

// Rule 1: no filters + limit > rows → all rows, newest-first (id DESC).
#[tokio::test]
async fn no_filters_returns_all_rows_newest_first() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    seed_mixed(&inv).await;

    let rows = inv
        .recent_audit_paginated(10, 0, None, None, None)
        .await
        .unwrap();
    assert_eq!(rows.len(), 5, "rule 1: limit=10 > 5 → all 5 rows");
    let actions: Vec<_> = rows.iter().map(|r| r.action.as_str()).collect();
    assert_eq!(
        actions,
        vec![
            "user.delete",
            "grant.add",
            "user.add",
            "user.add",
            "server.deploy"
        ],
        "rule 1: ordering MUST be id DESC"
    );
    for pair in rows.windows(2) {
        assert!(
            pair[0].id > pair[1].id,
            "rule 1: ids must strictly decrease"
        );
    }
}

// Rule 2: limit + offset slice; limit beyond count is not an error.
#[tokio::test]
async fn limit_and_offset_slice_window() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.audit("admin", "a", None, None).await.unwrap();
    inv.audit("admin", "b", None, None).await.unwrap();
    inv.audit("admin", "c", None, None).await.unwrap();

    let p1 = inv
        .recent_audit_paginated(2, 0, None, None, None)
        .await
        .unwrap();
    assert_eq!(p1.len(), 2, "rule 2: limit=2 caps to 2");
    assert_eq!(p1[0].action, "c", "rule 2: page1[0]=newest");
    assert_eq!(p1[1].action, "b", "rule 2: page1[1]=2nd-newest");

    let p2 = inv
        .recent_audit_paginated(2, 2, None, None, None)
        .await
        .unwrap();
    assert_eq!(p2.len(), 1, "rule 2: only 1 row left after offset=2");
    assert_eq!(p2[0].action, "a", "rule 2: page2 = oldest 'a'");

    let past = inv
        .recent_audit_paginated(100, 10, None, None, None)
        .await
        .unwrap();
    assert!(past.is_empty(), "rule 2: offset past end → empty Vec");
}

// Rule 3: actor_filter is EXACT — "admin-bot" MUST NOT match "admin".
#[tokio::test]
async fn actor_filter_is_exact_match_not_like() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    seed_mixed(&inv).await;

    let rows = inv
        .recent_audit_paginated(50, 0, Some("admin"), None, None)
        .await
        .unwrap();
    assert_eq!(
        rows.len(),
        4,
        "rule 3: 4 admin rows; got {} (LIKE-matched bot?)",
        rows.len()
    );
    for r in &rows {
        assert_eq!(
            r.actor, "admin",
            "rule 3: every actor MUST be exactly 'admin'"
        );
    }
}

// Rule 4: action_prefix matches LIKE 'prefix%' only.
#[tokio::test]
async fn action_prefix_matches_only_starting_with_prefix() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    seed_mixed(&inv).await;

    let rows = inv
        .recent_audit_paginated(50, 0, None, Some("user."), None)
        .await
        .unwrap();
    assert_eq!(rows.len(), 3, "rule 4: 3 user.* rows expected");
    for r in &rows {
        assert!(
            r.action.starts_with("user."),
            "rule 4: {:?} must START WITH 'user.'",
            r.action
        );
    }
    assert!(
        rows.iter().all(|r| r.action != "grant.add"),
        "rule 4: 'grant.add' MUST NOT appear under 'user.' prefix"
    );
}

// Rule 5: combined filters AND together — both predicates must hold.
#[tokio::test]
async fn combined_filters_intersect() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    seed_mixed(&inv).await;

    let rows = inv
        .recent_audit_paginated(50, 0, Some("admin"), Some("user."), None)
        .await
        .unwrap();
    assert_eq!(
        rows.len(),
        2,
        "rule 5: AND filter → 2 rows, got {}",
        rows.len()
    );
    let actions: Vec<_> = rows.iter().map(|r| r.action.as_str()).collect();
    assert_eq!(
        actions,
        vec!["user.delete", "user.add"],
        "rule 5: newest-first AND-filtered"
    );
    for r in &rows {
        assert_eq!(r.actor, "admin", "rule 5: actor predicate must hold");
        assert!(
            r.action.starts_with("user."),
            "rule 5: action predicate must hold"
        );
    }
}

// Rule 6: action_prefix=Some("") is degenerate-but-legal → matches all.
#[tokio::test]
async fn empty_action_prefix_matches_all_rows() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    seed_mixed(&inv).await;

    let rows = inv
        .recent_audit_paginated(50, 0, None, Some(""), None)
        .await
        .unwrap();
    assert_eq!(
        rows.len(),
        5,
        "rule 6: empty prefix MUST match every row, got {}",
        rows.len()
    );
}

// Rule 7: empty table + any filter combo → Ok(vec![]).
#[tokio::test]
async fn empty_table_with_filters_returns_empty_ok() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    let combos: &[(Option<&str>, Option<&str>)] = &[
        (None, None),
        (Some("admin"), None),
        (None, Some("user.")),
        (Some("admin"), Some("user.")),
    ];
    for (actor, prefix) in combos {
        let rows = inv
            .recent_audit_paginated(10, 0, *actor, *prefix, None)
            .await
            .unwrap();
        assert!(
            rows.is_empty(),
            "rule 7: empty table actor={:?} prefix={:?} → empty, got {}",
            actor,
            prefix,
            rows.len()
        );
    }
}

// Rule 8: limit=0 → Ok(vec![]) even when rows exist.
#[tokio::test]
async fn limit_zero_returns_empty_vec() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    seed_mixed(&inv).await;

    let rows = inv
        .recent_audit_paginated(0, 0, None, None, None)
        .await
        .unwrap();
    assert!(
        rows.is_empty(),
        "rule 8: limit=0 MUST return empty Vec, got {}",
        rows.len()
    );
}
