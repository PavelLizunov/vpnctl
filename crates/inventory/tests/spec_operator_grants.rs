//! Spec for operator grant management, revocations, per-grant protocol overrides,
//! and audit trail invariants (including no-op audit suppression).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use tempfile::TempDir;
use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
use vpnctl_inventory::{SqliteInventory, SqliteInventoryError};

async fn open(dir: &TempDir) -> SqliteInventory {
    SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .expect("open inventory db")
}

fn srv(id: &str, protocols: &[&str]) -> Server {
    Server {
        id: ServerId(id.into()),
        address: format!("{id}.example.com"),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: protocols.iter().map(|p| ProtocolId((*p).into())).collect(),
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

fn usr(id: &str) -> User {
    User {
        id: UserId(id.into()),
        uuid: format!("global-uuid-of-{id}"),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    }
}

async fn count_audit_by_action(inv: &SqliteInventory, action: &str) -> usize {
    inv.recent_audit(1000)
        .await
        .unwrap()
        .into_iter()
        .filter(|a| a.action == action)
        .count()
}

#[tokio::test]
async fn grant_and_revoke_lifecycle() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    let server_id = ServerId("srv-eu".into());
    let user_id = UserId("alice".into());

    inv.add_server(&srv("srv-eu", &["vless+reality", "tuic-v5"]))
        .await
        .unwrap();
    inv.add_user(&usr("alice")).await.unwrap();

    assert_eq!(inv.count_grants().await.unwrap(), 0);
    assert!(inv.users_for_server(&server_id).await.unwrap().is_empty());
    assert!(inv.servers_for_user(&user_id).await.unwrap().is_empty());

    // Grant access
    inv.grant(&user_id, &server_id).await.unwrap();

    assert_eq!(inv.count_grants().await.unwrap(), 1);
    let users = inv.users_for_server(&server_id).await.unwrap();
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].id, user_id);

    let servers = inv.servers_for_user(&user_id).await.unwrap();
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0].id, server_id);

    let per_server_counts = inv.users_count_per_server().await.unwrap();
    assert_eq!(per_server_counts.get(&server_id).copied(), Some(1));

    // Revoke access
    inv.revoke(&user_id, &server_id).await.unwrap();

    assert_eq!(inv.count_grants().await.unwrap(), 0);
    assert!(inv.users_for_server(&server_id).await.unwrap().is_empty());
    assert!(inv.servers_for_user(&user_id).await.unwrap().is_empty());
}

#[tokio::test]
async fn grant_and_revoke_are_idempotent() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    let server_id = ServerId("srv-us".into());
    let user_id = UserId("bob".into());

    inv.add_server(&srv("srv-us", &["vless+reality"]))
        .await
        .unwrap();
    inv.add_user(&usr("bob")).await.unwrap();

    // First grant
    inv.grant(&user_id, &server_id).await.unwrap();
    assert_eq!(inv.count_grants().await.unwrap(), 1);

    // Duplicate grant is a no-op and succeeds
    inv.grant(&user_id, &server_id).await.unwrap();
    assert_eq!(inv.count_grants().await.unwrap(), 1);

    // First revoke
    inv.revoke(&user_id, &server_id).await.unwrap();
    assert_eq!(inv.count_grants().await.unwrap(), 0);

    // Duplicate revoke is a no-op and succeeds
    inv.revoke(&user_id, &server_id).await.unwrap();
    assert_eq!(inv.count_grants().await.unwrap(), 0);
}

#[tokio::test]
async fn grant_rejects_non_existent_user() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    let server_id = ServerId("srv-1".into());
    let ghost_user = UserId("ghost".into());

    inv.add_server(&srv("srv-1", &["vless+reality"]))
        .await
        .unwrap();

    let err = inv.grant(&ghost_user, &server_id).await.unwrap_err();
    match err {
        SqliteInventoryError::Invalid(msg) => {
            assert!(
                msg.contains("no such user ghost"),
                "unexpected error: {msg}"
            );
        }
        other => panic!("expected Invalid error, got {other:?}"),
    }
}

#[tokio::test]
async fn protocol_override_toggle_and_visibility() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    let server_id = ServerId("srv-node".into());
    let user_id = UserId("carol".into());
    let proto_vless = ProtocolId("vless+reality".into());
    let proto_tuic = ProtocolId("tuic-v5".into());

    inv.add_server(&srv("srv-node", &["vless+reality", "tuic-v5"]))
        .await
        .unwrap();
    inv.add_user(&usr("carol")).await.unwrap();
    inv.grant(&user_id, &server_id).await.unwrap();

    // Initially both protocols visible
    let visible_init = inv
        .visible_protocols_for_subscription(&user_id, &server_id)
        .await
        .unwrap();
    assert_eq!(visible_init, vec![proto_tuic.clone(), proto_vless.clone()]);

    // Disable tuic-v5 for this user on this server
    inv.set_grant_protocol_override(&user_id, &server_id, &proto_tuic, true)
        .await
        .unwrap();

    let overrides = inv
        .list_protocol_overrides_for_user(&user_id)
        .await
        .unwrap();
    assert_eq!(
        overrides.get(&(server_id.clone(), proto_tuic.clone())),
        Some(&true)
    );

    let visible_after = inv
        .visible_protocols_for_subscription(&user_id, &server_id)
        .await
        .unwrap();
    assert_eq!(visible_after, vec![proto_vless.clone()]);

    // Re-enable tuic-v5 by removing the override
    inv.set_grant_protocol_override(&user_id, &server_id, &proto_tuic, false)
        .await
        .unwrap();

    let overrides_cleared = inv
        .list_protocol_overrides_for_user(&user_id)
        .await
        .unwrap();
    assert!(overrides_cleared.is_empty());

    let visible_restored = inv
        .visible_protocols_for_subscription(&user_id, &server_id)
        .await
        .unwrap();
    assert_eq!(
        visible_restored,
        vec![proto_tuic.clone(), proto_vless.clone()]
    );
}

#[tokio::test]
async fn protocol_override_fails_without_existing_grant() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    let server_id = ServerId("srv-node".into());
    let user_id = UserId("dave".into());
    let proto_vless = ProtocolId("vless+reality".into());

    inv.add_server(&srv("srv-node", &["vless+reality"]))
        .await
        .unwrap();
    inv.add_user(&usr("dave")).await.unwrap();

    // No grant exists yet
    let err = inv
        .set_grant_protocol_override(&user_id, &server_id, &proto_vless, true)
        .await
        .unwrap_err();

    match err {
        SqliteInventoryError::Invalid(msg) => {
            assert!(
                msg.contains("no grant for (dave, srv-node)"),
                "unexpected error: {msg}"
            );
        }
        other => panic!("expected Invalid error, got {other:?}"),
    }
}

#[tokio::test]
async fn protocol_override_noop_audit_suppression() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    let server_id = ServerId("srv-node".into());
    let user_id = UserId("eve".into());
    let proto_vless = ProtocolId("vless+reality".into());

    inv.add_server(&srv("srv-node", &["vless+reality"]))
        .await
        .unwrap();
    inv.add_user(&usr("eve")).await.unwrap();
    inv.grant(&user_id, &server_id).await.unwrap();

    assert_eq!(
        count_audit_by_action(&inv, "grant.protocol.set_override").await,
        0
    );

    // 1. Setting disabled=false when no override exists should be a no-op (0 audit rows)
    inv.set_grant_protocol_override(&user_id, &server_id, &proto_vless, false)
        .await
        .unwrap();
    assert_eq!(
        count_audit_by_action(&inv, "grant.protocol.set_override").await,
        0,
        "no-op delete must not write audit log"
    );

    // 2. Setting disabled=true mutates state -> writes exactly 1 audit row
    inv.set_grant_protocol_override(&user_id, &server_id, &proto_vless, true)
        .await
        .unwrap();
    assert_eq!(
        count_audit_by_action(&inv, "grant.protocol.set_override").await,
        1,
        "mutation must write exactly 1 audit row"
    );

    // Verify audit entry payload and target
    let recent = inv.recent_audit(10).await.unwrap();
    let entry = recent
        .iter()
        .find(|a| a.action == "grant.protocol.set_override")
        .expect("audit row present");
    assert_eq!(entry.actor, "admin");
    assert_eq!(entry.target.as_deref(), Some("eve"));
    let payload = entry.payload.as_ref().expect("payload present");
    assert_eq!(payload["user_id"], serde_json::json!("eve"));
    assert_eq!(payload["server_id"], serde_json::json!("srv-node"));
    assert_eq!(payload["protocol_id"], serde_json::json!("vless+reality"));
    assert_eq!(payload["disabled"], serde_json::json!(true));

    // 3. Setting disabled=true again on an already disabled override -> no-op (still 1 audit row)
    inv.set_grant_protocol_override(&user_id, &server_id, &proto_vless, true)
        .await
        .unwrap();
    assert_eq!(
        count_audit_by_action(&inv, "grant.protocol.set_override").await,
        1,
        "no-op re-disable must NOT write another audit row"
    );

    // 4. Setting disabled=false mutates state back -> writes 2nd audit row
    inv.set_grant_protocol_override(&user_id, &server_id, &proto_vless, false)
        .await
        .unwrap();
    assert_eq!(
        count_audit_by_action(&inv, "grant.protocol.set_override").await,
        2,
        "clearing override mutates state and must write audit row"
    );

    let recent_after = inv.recent_audit(10).await.unwrap();
    let entry_after = &recent_after[0];
    assert_eq!(entry_after.action, "grant.protocol.set_override");
    let payload_after = entry_after.payload.as_ref().expect("payload present");
    assert_eq!(payload_after["disabled"], serde_json::json!(false));
}

#[tokio::test]
async fn revoke_cascades_and_removes_protocol_overrides() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    let server_id = ServerId("srv-node".into());
    let user_id = UserId("frank".into());
    let proto_vless = ProtocolId("vless+reality".into());
    let proto_tuic = ProtocolId("tuic-v5".into());

    inv.add_server(&srv("srv-node", &["vless+reality", "tuic-v5"]))
        .await
        .unwrap();
    inv.add_user(&usr("frank")).await.unwrap();
    inv.grant(&user_id, &server_id).await.unwrap();

    inv.set_grant_protocol_override(&user_id, &server_id, &proto_vless, true)
        .await
        .unwrap();
    inv.set_grant_protocol_override(&user_id, &server_id, &proto_tuic, true)
        .await
        .unwrap();

    let overrides = inv
        .list_protocol_overrides_for_user(&user_id)
        .await
        .unwrap();
    assert_eq!(overrides.len(), 2);

    // Revoking grant should cascade and delete associated overrides
    inv.revoke(&user_id, &server_id).await.unwrap();

    let overrides_after = inv
        .list_protocol_overrides_for_user(&user_id)
        .await
        .unwrap();
    assert!(
        overrides_after.is_empty(),
        "FK ON DELETE CASCADE must remove protocol overrides on grant revoke"
    );
}
