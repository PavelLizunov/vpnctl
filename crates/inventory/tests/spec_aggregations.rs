//! Spec for `count_servers`, `count_users`, `count_grants`,
//! `users_count_per_server` on `SqliteInventory`. Written from the spec
//! only — impl NOT consulted.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;
use std::path::PathBuf;

use tempfile::TempDir;

use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
use vpnctl_inventory::SqliteInventory;

fn db_path(dir: &TempDir) -> PathBuf {
    dir.path().join("inventory.db")
}

async fn open(dir: &TempDir) -> SqliteInventory {
    SqliteInventory::open(&db_path(dir)).await.expect("open")
}

fn server(id: &str) -> Server {
    Server {
        id: ServerId(id.to_string()),
        address: format!("{id}.example.com"),
        ssh_port: 22,
        ssh_user: "root".to_string(),
        kernels: vec![KernelId("sing-box".to_string())],
        enabled_protocols: vec![ProtocolId("vless+reality".to_string())],
        trusted_host_fingerprint: None,
        hoster: "generic".to_string(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

fn user(id: &str) -> User {
    User {
        id: UserId(id.to_string()),
        uuid: format!("uuid-of-{id}"),
        tuic_password: Some(format!("tuic-{id}")),
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None, // inventory may backfill on add
    }
}

// 1. Empty inventory: every aggregator returns the zero value.
#[tokio::test]
async fn empty_inventory_all_aggregations_are_zero() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    assert_eq!(inv.count_servers().await.unwrap(), 0, "count_servers");
    assert_eq!(inv.count_users().await.unwrap(), 0, "count_users");
    assert_eq!(inv.count_grants().await.unwrap(), 0, "count_grants");

    let map = inv.users_count_per_server().await.unwrap();
    assert!(
        map.is_empty(),
        "users_count_per_server must be empty on an empty DB, got: {map:?}"
    );
}

// 2. count_servers / count_users / count_grants give exact totals.
#[tokio::test]
async fn populated_inventory_counts_are_exact() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    // Seed: 3 servers, 2 users.
    for sid in ["s1", "s2", "s3"] {
        inv.add_server(&server(sid)).await.unwrap();
    }
    for uid in ["u1", "u2"] {
        inv.add_user(&user(uid)).await.unwrap();
    }

    // Grants: u1→s1, u1→s2, u2→s1. (Total 3 grants. s3 gets none.)
    inv.grant(&UserId("u1".into()), &ServerId("s1".into()))
        .await
        .unwrap();
    inv.grant(&UserId("u1".into()), &ServerId("s2".into()))
        .await
        .unwrap();
    inv.grant(&UserId("u2".into()), &ServerId("s1".into()))
        .await
        .unwrap();

    assert_eq!(inv.count_servers().await.unwrap(), 3, "3 servers seeded");
    assert_eq!(inv.count_users().await.unwrap(), 2, "2 users seeded");
    assert_eq!(inv.count_grants().await.unwrap(), 3, "3 grants seeded");
}

// 3. users_count_per_server: exact shape + zero-grant servers absent.
#[tokio::test]
async fn users_count_per_server_exact_shape_omits_zero_grant_servers() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    // s1 will have 2 users, s2 will have 1 user, s3 will have 0 users.
    for sid in ["s1", "s2", "s3"] {
        inv.add_server(&server(sid)).await.unwrap();
    }
    for uid in ["u1", "u2"] {
        inv.add_user(&user(uid)).await.unwrap();
    }
    inv.grant(&UserId("u1".into()), &ServerId("s1".into()))
        .await
        .unwrap();
    inv.grant(&UserId("u2".into()), &ServerId("s1".into()))
        .await
        .unwrap();
    inv.grant(&UserId("u1".into()), &ServerId("s2".into()))
        .await
        .unwrap();

    let map = inv.users_count_per_server().await.unwrap();

    let mut want: HashMap<ServerId, i64> = HashMap::new();
    want.insert(ServerId("s1".into()), 2);
    want.insert(ServerId("s2".into()), 1);
    // s3 deliberately absent: spec says zero-grant servers MUST NOT appear.

    assert_eq!(map, want, "exact map shape mismatch");
    assert!(
        !map.contains_key(&ServerId("s3".into())),
        "s3 has zero grants and MUST be absent from the map, got: {map:?}"
    );
    assert_eq!(map.len(), 2, "map must contain only the 2 granted servers");
}

// 4. remove_user — cascade is visible in count_grants and the per-server map.
#[tokio::test]
async fn remove_user_cascade_is_reflected_in_aggregations() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_server(&server("s1")).await.unwrap();
    inv.add_server(&server("s2")).await.unwrap();
    inv.add_user(&user("u1")).await.unwrap();
    inv.add_user(&user("u2")).await.unwrap();

    // u1 → {s1, s2}, u2 → {s1}. Grants total = 3.
    inv.grant(&UserId("u1".into()), &ServerId("s1".into()))
        .await
        .unwrap();
    inv.grant(&UserId("u1".into()), &ServerId("s2".into()))
        .await
        .unwrap();
    inv.grant(&UserId("u2".into()), &ServerId("s1".into()))
        .await
        .unwrap();

    // Sanity (pre-cascade).
    assert_eq!(inv.count_grants().await.unwrap(), 3);
    let before = inv.users_count_per_server().await.unwrap();
    assert_eq!(before.get(&ServerId("s1".into())).copied(), Some(2));
    assert_eq!(before.get(&ServerId("s2".into())).copied(), Some(1));

    // Remove u1 — cascades 2 grant rows (u1→s1 and u1→s2).
    inv.remove_user(&UserId("u1".into())).await.unwrap();

    // count_users decreases.
    assert_eq!(
        inv.count_users().await.unwrap(),
        1,
        "u1 removal must decrement count_users"
    );
    // count_grants reflects cascade immediately.
    assert_eq!(
        inv.count_grants().await.unwrap(),
        1,
        "FK CASCADE must remove u1's 2 grants, leaving only u2→s1"
    );

    let after = inv.users_count_per_server().await.unwrap();
    let mut want: HashMap<ServerId, i64> = HashMap::new();
    want.insert(ServerId("s1".into()), 1); // only u2 left
    // s2 had only u1 → now zero grants → MUST drop out of the map.
    assert_eq!(
        after, want,
        "after removing u1, s2 should disappear (0 grants) and s1 should be 1"
    );
    assert!(
        !after.contains_key(&ServerId("s2".into())),
        "s2 went to zero grants and MUST disappear from the map, got: {after:?}"
    );
}

// 5. remove_server — same FK CASCADE story for grants.server_id.
#[tokio::test]
async fn remove_server_cascade_is_reflected_in_aggregations() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_server(&server("s1")).await.unwrap();
    inv.add_server(&server("s2")).await.unwrap();
    inv.add_user(&user("u1")).await.unwrap();
    inv.add_user(&user("u2")).await.unwrap();

    // Grants: u1→s1, u2→s1, u1→s2. Total 3.
    inv.grant(&UserId("u1".into()), &ServerId("s1".into()))
        .await
        .unwrap();
    inv.grant(&UserId("u2".into()), &ServerId("s1".into()))
        .await
        .unwrap();
    inv.grant(&UserId("u1".into()), &ServerId("s2".into()))
        .await
        .unwrap();

    // Pre-cascade sanity.
    assert_eq!(inv.count_servers().await.unwrap(), 2);
    assert_eq!(inv.count_grants().await.unwrap(), 3);

    // Drop s1 — should cascade 2 grant rows (u1→s1 and u2→s1).
    inv.remove_server(&ServerId("s1".into())).await.unwrap();

    assert_eq!(
        inv.count_servers().await.unwrap(),
        1,
        "remove_server must decrement count_servers"
    );
    assert_eq!(
        inv.count_grants().await.unwrap(),
        1,
        "FK CASCADE on servers→grants must remove s1's 2 grants, leaving u1→s2"
    );

    let after = inv.users_count_per_server().await.unwrap();
    let mut want: HashMap<ServerId, i64> = HashMap::new();
    want.insert(ServerId("s2".into()), 1);
    assert_eq!(
        after, want,
        "s1 must be entirely absent post-remove; s2 still has u1"
    );
    assert!(
        !after.contains_key(&ServerId("s1".into())),
        "s1 was removed and MUST NOT appear in users_count_per_server, got: {after:?}"
    );

    // Spec note: "Must NOT include grants for servers that no longer
    // exist (FK CASCADE deletes the grant row when its server is removed,
    // so this is naturally satisfied — but the test should confirm it)."
    // The two assertions above (count_grants == 1 AND s1 absent from map)
    // jointly confirm that no orphan grant rows survived.
}

// 6. Counts are live (not cached) — each mutation is observable; revoke
//    drops the server out of the per-server map.
#[tokio::test]
async fn counts_are_live_not_cached() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    assert_eq!(inv.count_servers().await.unwrap(), 0);
    assert_eq!(inv.count_users().await.unwrap(), 0);

    inv.add_server(&server("s1")).await.unwrap();
    assert_eq!(
        inv.count_servers().await.unwrap(),
        1,
        "count_servers must observe the new row"
    );

    inv.add_user(&user("u1")).await.unwrap();
    assert_eq!(
        inv.count_users().await.unwrap(),
        1,
        "count_users must observe the new row"
    );

    // Grant + revoke — count_grants must round-trip back to zero.
    inv.grant(&UserId("u1".into()), &ServerId("s1".into()))
        .await
        .unwrap();
    assert_eq!(inv.count_grants().await.unwrap(), 1);
    inv.revoke(&UserId("u1".into()), &ServerId("s1".into()))
        .await
        .unwrap();
    assert_eq!(
        inv.count_grants().await.unwrap(),
        0,
        "revoke must be visible in count_grants"
    );

    // Per-server map must drop s1 (0 grants).
    let map = inv.users_count_per_server().await.unwrap();
    assert!(
        !map.contains_key(&ServerId("s1".into())),
        "after revoke, s1 has zero grants and must drop out of the map"
    );
    assert!(
        map.is_empty(),
        "no other servers exist, map must be empty: {map:?}"
    );
}
