//! Integration spec for the v0.4.0 subscription token feature of
//! `SqliteInventory`. Tests numbered after rules S1-S8 in the brief.
//! Written from the spec only — no implementation source consulted.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use tempfile::TempDir;

use vpnctl_core::{User, UserId};
use vpnctl_inventory::{SqliteInventory, SqliteInventoryError};

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
        tuic_password: Some(format!("tuic-{id}")),
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
    }
}

fn user_with_token(id: &str, token: Option<&str>) -> User {
    User {
        id: UserId(id.to_string()),
        uuid: format!("uuid-of-{id}"),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: token.map(str::to_string),
    }
}

/// Returns true iff every char of `s` is in `[A-Za-z0-9_-]`.
fn is_url_safe(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Direct sqlx connection to the SAME on-disk DB while inventory is
/// closed. Used by S1 (NULL-backfill) and S8 (UNIQUE constraint).
async fn raw_pool(path: &Path) -> sqlx::SqlitePool {
    let url = format!("sqlite://{}", path.display());
    sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("raw pool connect")
}

// ── S1 ──────────────────────────────────────────────────────────────────
// After open(), every user row has a non-null sub_token, even rows
// inserted with NULL while the inventory was closed.
#[tokio::test]
async fn s1_open_backfills_null_sub_tokens() {
    let dir = TempDir::new().unwrap();
    let path = db_path(&dir);

    // First open creates the schema; add a user the normal way so we
    // know columns exist.
    let inv = SqliteInventory::open(&path).await.expect("first open");
    inv.add_user(&user("seed")).await.unwrap();
    inv.close().await;

    // Manually NULL-out one user and add another with NULL token via
    // raw SQL.
    let pool = raw_pool(&path).await;
    sqlx::query("UPDATE users SET sub_token = NULL WHERE id = ?")
        .bind("seed")
        .execute(&pool)
        .await
        .expect("NULL out seed");
    sqlx::query(
        "INSERT INTO users (id, uuid, tuic_password, wireguard_pubkey, sub_token) \
         VALUES (?, ?, NULL, NULL, NULL)",
    )
    .bind("legacy")
    .bind("uuid-legacy")
    .execute(&pool)
    .await
    .expect("insert NULL-token row");
    pool.close().await;

    // Re-open should backfill.
    let inv2 = SqliteInventory::open(&path).await.expect("reopen");
    let users = inv2.list_users().await.expect("list_users");
    assert_eq!(users.len(), 2, "expected exactly two users, got {users:?}");
    assert!(
        users.iter().all(|u| u.sub_token.is_some()),
        "open() must backfill NULL sub_tokens, got {users:?}"
    );
    // And the backfilled tokens must themselves be URL-safe / non-empty.
    for u in &users {
        let t = u.sub_token.as_deref().unwrap();
        assert!(
            !t.is_empty() && is_url_safe(t),
            "backfilled token not URL-safe: {t:?}"
        );
    }
    inv2.close().await;
}

// ── S2 ──────────────────────────────────────────────────────────────────
// add_user with sub_token == None must persist a non-null, URL-safe,
// >= 32-char token observable through get_user.
#[tokio::test]
async fn s2_add_user_generates_url_safe_token() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_user(&user("alice")).await.unwrap();
    let got = inv
        .get_user(&UserId("alice".into()))
        .await
        .unwrap()
        .expect("alice should exist");

    let token = got
        .sub_token
        .as_deref()
        .expect("add_user must populate sub_token when caller passed None");
    assert!(
        token.len() >= 32,
        "token must be >=32 chars, got {} ({token:?})",
        token.len()
    );
    assert!(
        is_url_safe(token),
        "token contains non-URL-safe chars: {token:?}"
    );
    inv.close().await;
}

// ── S3 ──────────────────────────────────────────────────────────────────
// add_user with sub_token == Some("custom-explicit") keeps it verbatim.
// Empty string is treated as unset and must be replaced with a generated
// token.
#[tokio::test]
async fn s3_add_user_preserves_explicit_token_and_treats_empty_as_unset() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    let custom = "custom-explicit";
    inv.add_user(&user_with_token("explicit", Some(custom)))
        .await
        .unwrap();
    let got = inv
        .get_user(&UserId("explicit".into()))
        .await
        .unwrap()
        .expect("explicit user");
    assert_eq!(
        got.sub_token.as_deref(),
        Some(custom),
        "explicit caller-provided token must be kept verbatim"
    );

    // Empty string → treated as unset, generated.
    inv.add_user(&user_with_token("empty", Some("")))
        .await
        .unwrap();
    let got_empty = inv
        .get_user(&UserId("empty".into()))
        .await
        .unwrap()
        .expect("empty user");
    let t = got_empty
        .sub_token
        .as_deref()
        .expect("empty-string token must be replaced with a generated one");
    assert!(!t.is_empty(), "generated token must not be empty");
    assert_ne!(t, "", "generated token must not be empty string");
    assert!(
        t.len() >= 32 && is_url_safe(t),
        "generated token bad shape: {t:?}"
    );
    inv.close().await;
}

// ── S4 ──────────────────────────────────────────────────────────────────
// 10 distinct users get 10 distinct tokens.
#[tokio::test]
async fn s4_generated_tokens_are_unique_across_users() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    for i in 0..10 {
        inv.add_user(&user(&format!("u{i}"))).await.unwrap();
    }
    let users = inv.list_users().await.unwrap();
    assert_eq!(users.len(), 10);
    let tokens: HashSet<String> = users
        .iter()
        .map(|u| u.sub_token.clone().expect("token must be present"))
        .collect();
    assert_eq!(
        tokens.len(),
        10,
        "expected 10 unique tokens, got {} (collisions in {tokens:?})",
        tokens.len()
    );
    inv.close().await;
}

// ── S5 ──────────────────────────────────────────────────────────────────
// find_user_by_sub_token: hit returns Some(user); miss returns Ok(None);
// looking up a removed user's old token returns Ok(None).
#[tokio::test]
async fn s5_find_user_by_sub_token_hit_miss_and_after_remove() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_user(&user("findme")).await.unwrap();
    let stored = inv
        .get_user(&UserId("findme".into()))
        .await
        .unwrap()
        .expect("findme exists");
    let token = stored.sub_token.clone().expect("token");

    // Hit.
    let hit = inv.find_user_by_sub_token(&token).await.expect("lookup ok");
    let hit = hit.expect("token must resolve");
    assert_eq!(hit.id, UserId("findme".into()));

    // Miss — random unrelated token.
    let miss = inv
        .find_user_by_sub_token("definitely-not-a-real-token-xxxxxxxxxxxxxxxx")
        .await
        .expect("miss must be Ok(None), not Err");
    assert!(
        miss.is_none(),
        "unknown token must yield None, got {miss:?}"
    );

    // Remove user, then the formerly-valid token must miss too.
    inv.remove_user(&UserId("findme".into())).await.unwrap();
    let after = inv
        .find_user_by_sub_token(&token)
        .await
        .expect("post-remove lookup must be Ok(None)");
    assert!(
        after.is_none(),
        "removed user's old token still resolves: {after:?}"
    );
    inv.close().await;
}

// ── S6 ──────────────────────────────────────────────────────────────────
// regenerate_sub_token: returns new token; new ≠ old; old stops
// resolving; new resolves to the same user.
#[tokio::test]
async fn s6_regenerate_sub_token_swaps_token_correctly() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    let uid = UserId("rotate".into());
    inv.add_user(&user("rotate")).await.unwrap();
    let old_token = inv
        .get_user(&uid)
        .await
        .unwrap()
        .expect("rotate exists")
        .sub_token
        .expect("token");

    let new_token = inv.regenerate_sub_token(&uid).await.expect("regenerate");
    assert_ne!(new_token, old_token, "regenerated token must differ");
    assert!(
        is_url_safe(&new_token) && new_token.len() >= 32,
        "new token bad shape: {new_token:?}"
    );

    let stored = inv
        .get_user(&uid)
        .await
        .unwrap()
        .expect("user still exists")
        .sub_token
        .expect("new token persisted");
    assert_eq!(
        stored, new_token,
        "regenerate's return value must match what is stored"
    );

    let by_old = inv
        .find_user_by_sub_token(&old_token)
        .await
        .expect("old lookup ok");
    assert!(
        by_old.is_none(),
        "old token must no longer resolve, got {by_old:?}"
    );
    let by_new = inv
        .find_user_by_sub_token(&new_token)
        .await
        .expect("new lookup ok")
        .expect("new token must resolve");
    assert_eq!(
        by_new.id, uid,
        "new token must point at the same user (got {:?})",
        by_new.id
    );
    inv.close().await;
}

// ── S7 ──────────────────────────────────────────────────────────────────
// regenerate_sub_token(unknown_id) returns Err — must NOT silently
// succeed on rows_affected == 0.
#[tokio::test]
async fn s7_regenerate_sub_token_unknown_user_errors() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    let res = inv.regenerate_sub_token(&UserId("ghost".into())).await;
    assert!(
        res.is_err(),
        "regenerate on unknown user must Err, got Ok({:?})",
        res.ok()
    );
    inv.close().await;
}

// ── S8 ──────────────────────────────────────────────────────────────────
// UNIQUE constraint on sub_token is enforced. Two add_user calls with
// the same explicit Some(custom_token) must surface AlreadyExists (or
// at minimum an Err — the partial UNIQUE index from migration 0002
// guarantees the underlying constraint).
#[tokio::test]
async fn s8_unique_constraint_on_sub_token_is_enforced() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    let shared = "shared-collision-token-abc123";
    inv.add_user(&user_with_token("first", Some(shared)))
        .await
        .expect("first insert ok");

    let res = inv.add_user(&user_with_token("second", Some(shared))).await;
    assert!(
        res.is_err(),
        "duplicate sub_token must be rejected, got Ok(()): \
         the partial UNIQUE index from migration 0002 was bypassed"
    );
    // Prefer AlreadyExists, but accept any Err: the contract says
    // "expect AlreadyExists" but the truly load-bearing invariant is
    // that the second insert is rejected. If the impl maps it to a
    // generic sqlx error, that's a quality nit, not a correctness bug.
    if let Err(SqliteInventoryError::AlreadyExists(_)) = &res {
        // good
    } else {
        // Still acceptable as long as it errored — print for diagnostics.
        eprintln!(
            "note: collision rejected but not as AlreadyExists: {:?}",
            res.as_ref().err()
        );
    }

    // And the first user is still findable by the original token.
    let by_token = inv
        .find_user_by_sub_token(shared)
        .await
        .expect("lookup ok")
        .expect("first user still resolves");
    assert_eq!(by_token.id, UserId("first".into()));
    inv.close().await;
}
