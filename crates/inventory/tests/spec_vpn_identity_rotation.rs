#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use sha2::{Digest, Sha256};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use tempfile::TempDir;
use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
use vpnctl_inventory::{AuditEntry, SqliteInventory};

const OLD: &str = "11111111-aaaa-4111-8111-111111111111";
const NEW: &str = "22222222-bbbb-4222-8222-222222222222";
const OTHER: &str = "33333333-cccc-4333-8333-333333333333";
const OVERRIDE: &str = "44444444-dddd-4444-8444-444444444444";
const ACTOR: &str = "fixture-operator";

fn fingerprint(uuid: &str) -> String {
    format!("{:x}", Sha256::digest(uuid.to_ascii_lowercase()))
}

fn user(id: &str, uuid: &str) -> User {
    User {
        id: UserId(id.into()),
        uuid: uuid.into(),
        tuic_password: Some(format!("{id}-fixture-tuic")),
        wireguard_pubkey: Some(format!("{id}-fixture-wireguard-public")),
        wireguard_private: Some(format!("{id}-fixture-wireguard-private")),
        sub_token: Some(format!("{id}-fixture-subscription")),
        vpn_router_device_id: None,
        disabled: false,
    }
}

async fn add_server(inv: &SqliteInventory, id: &str) -> ServerId {
    let id = ServerId(id.into());
    inv.add_server(&Server {
        address: format!("{}.example.test", id.0),
        id: id.clone(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("vless+reality".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();
    id
}

async fn audit(inv: &SqliteInventory) -> Vec<AuditEntry> {
    inv.recent_audit(50).await.unwrap()
}

async fn raw_pool(path: &Path) -> sqlx::SqlitePool {
    SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(SqliteConnectOptions::new().filename(path))
        .await
        .unwrap()
}

#[tokio::test]
async fn rotation_remains_pending_after_restart_until_the_new_revision_is_applied() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("inv.db");
    let inv = SqliteInventory::open(&path).await.unwrap();
    let alice = user("alice", OLD);
    inv.add_user(&alice).await.unwrap();
    let server = add_server(&inv, "edge").await;
    inv.grant(&alice.id, &server).await.unwrap();
    let old_revision = inv.deploy_input_revision(&server).await.unwrap();
    let success = serde_json::json!({});
    assert!(
        inv.audit_deploy_if_revision(ACTOR, &server, &old_revision, &success)
            .await
            .unwrap()
    );
    assert!(!inv.server_pending_deploy(&server).await.unwrap());

    inv.rotate_user_uuid(&alice.id, &fingerprint(OLD), NEW, ACTOR)
        .await
        .unwrap();
    drop(inv);
    let reopened = SqliteInventory::open(&path).await.unwrap();
    let servers = std::slice::from_ref(&server);
    assert!(reopened.server_pending_deploy(&server).await.unwrap());
    assert_eq!(
        reopened
            .servers_pending_deploy_for_user(&alice.id, servers)
            .await
            .unwrap(),
        servers
    );
    assert!(
        !reopened
            .audit_deploy_if_revision(ACTOR, &server, &old_revision, &success)
            .await
            .unwrap()
    );
    assert!(reopened.server_pending_deploy(&server).await.unwrap());

    let new_revision = reopened.deploy_input_revision(&server).await.unwrap();
    assert!(
        reopened
            .audit_deploy_if_revision(ACTOR, &server, &new_revision, &success)
            .await
            .unwrap()
    );
    assert!(!reopened.server_pending_deploy(&server).await.unwrap());
    assert!(
        reopened
            .servers_pending_deploy_for_user(&alice.id, servers)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn rotation_preserves_credentials_and_updates_only_matching_grant_overrides() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("inv.db");
    let inv = SqliteInventory::open(&path).await.unwrap();
    let device_id = "0123456789abcdef0123456789abcdef";
    let alice = user("alice", OLD);
    inv.add_user(&alice).await.unwrap();
    inv.set_vpn_router_device_id(&alice.id, device_id)
        .await
        .unwrap();
    let before = inv.get_user(&alice.id).await.unwrap().unwrap();
    assert_eq!(before.tuic_password, alice.tuic_password);
    assert_eq!(before.wireguard_pubkey, alice.wireguard_pubkey);
    assert_eq!(before.wireguard_private, alice.wireguard_private);

    let inherited = add_server(&inv, "inherited").await;
    let matching = add_server(&inv, "matching").await;
    let distinct = add_server(&inv, "distinct").await;
    let unrelated = add_server(&inv, "unrelated").await;
    for server in [&inherited, &matching, &distinct] {
        inv.grant(&alice.id, server).await.unwrap();
    }
    inv.set_grant_client_uuid(&alice.id, &matching, OLD)
        .await
        .unwrap();
    inv.set_grant_client_uuid(&alice.id, &distinct, OVERRIDE)
        .await
        .unwrap();
    let prior_audit_count = audit(&inv).await.len();

    let old_fingerprint = fingerprint(OLD);
    let servers = inv
        .rotate_user_uuid(&alice.id, &old_fingerprint, NEW, ACTOR)
        .await
        .unwrap();
    assert_eq!(servers.len(), 3);
    for server in [&inherited, &matching, &distinct] {
        assert!(servers.contains(server));
    }
    assert!(!servers.contains(&unrelated));

    // The original subscription still resolves to the account and its new identity.
    let stored = inv
        .find_user_by_sub_token(before.sub_token.as_deref().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.id, before.id);
    assert_eq!(stored.uuid, NEW);
    assert_eq!(stored.sub_token, before.sub_token);
    assert_eq!(stored.vpn_router_device_id.as_deref(), Some(device_id));
    assert_eq!(stored.tuic_password, before.tuic_password);
    assert_eq!(stored.wireguard_pubkey, before.wireguard_pubkey);
    assert_eq!(stored.wireguard_private, before.wireguard_private);
    assert_eq!(stored.disabled, before.disabled);
    assert_eq!(inv.count_grants().await.unwrap(), 3);

    let pool = raw_pool(&path).await;
    for (server, stored_override, effective_uuid) in [
        (&inherited, None, NEW),
        (&matching, Some(NEW), NEW),
        (&distinct, Some(OVERRIDE), OVERRIDE),
    ] {
        let client_uuid: Option<String> = sqlx::query_scalar(
            "SELECT client_uuid FROM grants WHERE user_id = ? AND server_id = ?",
        )
        .bind(&alice.id.0)
        .bind(&server.0)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(client_uuid.as_deref(), stored_override);
        assert_eq!(
            inv.client_uuid_for(&alice.id, server)
                .await
                .unwrap()
                .as_deref(),
            Some(effective_uuid)
        );
    }
    assert!(inv.known_user_uuids().await.unwrap().contains(OLD));

    let entries = audit(&inv).await;
    assert_eq!(entries.len(), prior_audit_count + 1);
    let entry = &entries[0];
    assert_eq!(entry.action, "user.uuid.rotate");
    assert_eq!(entry.actor, ACTOR);
    assert_eq!(entry.target.as_deref(), Some("alice"));
    let payload = entry.payload.as_ref().unwrap();
    let counts = payload.as_object().unwrap();
    assert!(counts.values().all(|value| value.as_u64().is_some()));
    assert!(counts.values().any(|value| value.as_u64() == Some(3)));
    assert!(counts.values().any(|value| value.as_u64() == Some(1)));
    let serialized = payload.to_string();
    for value in [OLD, NEW, OVERRIDE, &old_fingerprint] {
        assert!(!serialized.contains(value));
    }

    let replay = inv
        .rotate_user_uuid(&alice.id, &old_fingerprint, NEW, ACTOR)
        .await
        .unwrap();
    assert_eq!(replay.len(), servers.len());
    assert!(servers.iter().all(|server| replay.contains(server)));
    assert_eq!(audit(&inv).await.len(), entries.len());
}

#[tokio::test]
async fn invalid_stale_active_and_retired_uuid_requests_leave_inventory_unchanged() {
    let dir = TempDir::new().unwrap();
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    let alice = user("alice", OLD);
    let bob = user("bob", OTHER);
    inv.add_user(&alice).await.unwrap();
    inv.add_user(&bob).await.unwrap();
    let server = add_server(&inv, "shared").await;
    inv.grant(&alice.id, &server).await.unwrap();
    inv.grant(&bob.id, &server).await.unwrap();
    inv.set_grant_client_uuid(&bob.id, &server, OVERRIDE)
        .await
        .unwrap();
    inv.rotate_user_uuid(&alice.id, &fingerprint(OLD), NEW, ACTOR)
        .await
        .unwrap();

    let current = fingerprint(NEW);
    let stale = fingerprint(OLD);
    let available = "55555555-eeee-4555-8555-555555555555";
    let uppercase = available.to_ascii_uppercase();
    let prior_uuids = inv.known_user_uuids().await.unwrap();
    let prior_audit_count = audit(&inv).await.len();
    for (expected, replacement) in [
        ("not-sha256", available),
        (stale.as_str(), available),
        (current.as_str(), "not-a-uuid"),
        (current.as_str(), uppercase.as_str()),
        (current.as_str(), OTHER),
        (current.as_str(), OVERRIDE),
        (current.as_str(), OLD),
    ] {
        assert!(
            inv.rotate_user_uuid(&alice.id, expected, replacement, ACTOR)
                .await
                .is_err(),
            "unexpected success for fixture rotation to {replacement}"
        );
    }
    assert_eq!(inv.get_user(&alice.id).await.unwrap().unwrap().uuid, NEW);
    assert_eq!(inv.get_user(&bob.id).await.unwrap().unwrap().uuid, OTHER);
    assert_eq!(inv.count_grants().await.unwrap(), 2);
    for (id, uuid) in [(&alice.id, NEW), (&bob.id, OVERRIDE)] {
        assert_eq!(
            inv.client_uuid_for(id, &server).await.unwrap().as_deref(),
            Some(uuid)
        );
    }
    assert_eq!(inv.known_user_uuids().await.unwrap(), prior_uuids);
    assert_eq!(audit(&inv).await.len(), prior_audit_count);
}

#[tokio::test]
async fn failed_audit_insert_rolls_back_uuid_grant_and_retirement() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("inv.db");
    let inv = SqliteInventory::open(&path).await.unwrap();
    let alice = user("alice", OLD);
    let server = add_server(&inv, "matching").await;
    inv.add_user(&alice).await.unwrap();
    inv.grant(&alice.id, &server).await.unwrap();
    inv.set_grant_client_uuid(&alice.id, &server, OLD)
        .await
        .unwrap();
    let pool = raw_pool(&path).await;
    sqlx::query(
        "CREATE TRIGGER fail_rotation_audit BEFORE INSERT ON audit_log
         WHEN NEW.action = 'user.uuid.rotate'
         BEGIN SELECT RAISE(ABORT, 'fixture audit failure'); END",
    )
    .execute(&pool)
    .await
    .unwrap();
    let prior_audit_count = audit(&inv).await.len();

    assert!(
        inv.rotate_user_uuid(&alice.id, &fingerprint(OLD), NEW, ACTOR)
            .await
            .is_err()
    );
    assert_eq!(inv.get_user(&alice.id).await.unwrap().unwrap().uuid, OLD);
    assert_eq!(
        inv.client_uuid_for(&alice.id, &server)
            .await
            .unwrap()
            .as_deref(),
        Some(OLD)
    );
    let retired: Vec<String> = sqlx::query_scalar("SELECT uuid FROM retired_user_uuids")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert!(retired.is_empty());
    assert_eq!(audit(&inv).await.len(), prior_audit_count);
}
