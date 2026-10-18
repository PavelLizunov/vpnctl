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
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    }
}

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

#[tokio::test]
async fn populated_inventory_counts_are_exact() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    for sid in ["s1", "s2", "s3"] {
        inv.add_server(&server(sid)).await.unwrap();
    }
    for uid in ["u1", "u2"] {
        inv.add_user(&user(uid)).await.unwrap();
    }

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

#[tokio::test]
async fn users_count_per_server_exact_shape_omits_zero_grant_servers() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

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

    assert_eq!(map, want, "exact map shape mismatch");
    assert!(
        !map.contains_key(&ServerId("s3".into())),
        "s3 has zero grants and MUST be absent from the map, got: {map:?}"
    );
    assert_eq!(map.len(), 2, "map must contain only the 2 granted servers");
}

#[tokio::test]
async fn remove_user_cascade_is_reflected_in_aggregations() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_server(&server("s1")).await.unwrap();
    inv.add_server(&server("s2")).await.unwrap();
    inv.add_user(&user("u1")).await.unwrap();
    inv.add_user(&user("u2")).await.unwrap();

    inv.grant(&UserId("u1".into()), &ServerId("s1".into()))
        .await
        .unwrap();
    inv.grant(&UserId("u1".into()), &ServerId("s2".into()))
        .await
        .unwrap();
    inv.grant(&UserId("u2".into()), &ServerId("s1".into()))
        .await
        .unwrap();

    assert_eq!(inv.count_grants().await.unwrap(), 3);
    let before = inv.users_count_per_server().await.unwrap();
    assert_eq!(before.get(&ServerId("s1".into())).copied(), Some(2));
    assert_eq!(before.get(&ServerId("s2".into())).copied(), Some(1));

    inv.remove_user(&UserId("u1".into())).await.unwrap();

    assert_eq!(
        inv.count_users().await.unwrap(),
        1,
        "u1 removal must decrement count_users"
    );
    assert_eq!(
        inv.count_grants().await.unwrap(),
        1,
        "FK CASCADE must remove u1's 2 grants, leaving only u2→s1"
    );

    let after = inv.users_count_per_server().await.unwrap();
    let mut want: HashMap<ServerId, i64> = HashMap::new();
    want.insert(ServerId("s1".into()), 1);
    assert_eq!(
        after, want,
        "after removing u1, s2 should disappear (0 grants) and s1 should be 1"
    );
    assert!(
        !after.contains_key(&ServerId("s2".into())),
        "s2 went to zero grants and MUST disappear from the map, got: {after:?}"
    );
}

#[tokio::test]
async fn remove_server_cascade_is_reflected_in_aggregations() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.add_server(&server("s1")).await.unwrap();
    inv.add_server(&server("s2")).await.unwrap();
    inv.add_user(&user("u1")).await.unwrap();
    inv.add_user(&user("u2")).await.unwrap();

    inv.grant(&UserId("u1".into()), &ServerId("s1".into()))
        .await
        .unwrap();
    inv.grant(&UserId("u2".into()), &ServerId("s1".into()))
        .await
        .unwrap();
    inv.grant(&UserId("u1".into()), &ServerId("s2".into()))
        .await
        .unwrap();

    assert_eq!(inv.count_servers().await.unwrap(), 2);
    assert_eq!(inv.count_grants().await.unwrap(), 3);

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
}

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
