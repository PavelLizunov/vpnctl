#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use tempfile::TempDir;
use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
use vpnctl_inventory::{ServerRole, SqliteInventory, SqliteInventoryError};

async fn open(dir: &TempDir) -> SqliteInventory {
    SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .expect("open")
}

fn srv(id: &str) -> Server {
    Server {
        id: ServerId(id.into()),
        address: format!("{id}.example.com"),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("vless+reality".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

fn usr(id: &str) -> User {
    User {
        id: UserId(id.into()),
        uuid: format!("uuid-{id}"),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    }
}

async fn audit_count(inv: &SqliteInventory, action: &str) -> usize {
    inv.recent_audit(1000)
        .await
        .unwrap()
        .into_iter()
        .filter(|a| a.action == action)
        .count()
}

#[tokio::test]
async fn default_server_role_is_vpn_exit() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let s = srv("node-1");
    inv.add_server(&s).await.unwrap();

    let role1 = inv.get_server_role(&s.id).await.unwrap();
    assert_eq!(role1, ServerRole::VpnExit);

    let role2 = inv.get_role(&s.id).await.unwrap();
    assert_eq!(role2, ServerRole::VpnExit);
}

#[tokio::test]
async fn set_role_updates_value_and_writes_audit_log() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let s = srv("node-workload");
    inv.add_server(&s).await.unwrap();

    assert_eq!(audit_count(&inv, "server.role.set").await, 0);

    inv.set_server_role(&s.id, ServerRole::WorkloadOnly)
        .await
        .unwrap();

    assert_eq!(
        inv.get_server_role(&s.id).await.unwrap(),
        ServerRole::WorkloadOnly
    );
    assert_eq!(audit_count(&inv, "server.role.set").await, 1);

    let entries = inv.recent_audit(10).await.unwrap();
    let audit_entry = entries
        .iter()
        .find(|e| e.action == "server.role.set")
        .expect("found audit entry");
    assert_eq!(audit_entry.target, Some("node-workload".into()));

    let payload = audit_entry.payload.as_ref().expect("payload");
    assert_eq!(payload["old"], "vpn-exit");
    assert_eq!(payload["new"], "workload-only");
}

#[tokio::test]
async fn set_role_no_op_audit_suppression() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let s = srv("node-suppress");
    inv.add_server(&s).await.unwrap();

    inv.set_role(&s.id, ServerRole::VpnExit).await.unwrap();
    assert_eq!(audit_count(&inv, "server.role.set").await, 0);

    inv.set_role(&s.id, ServerRole::WorkloadOnly).await.unwrap();
    assert_eq!(audit_count(&inv, "server.role.set").await, 1);

    inv.set_role(&s.id, ServerRole::WorkloadOnly).await.unwrap();
    assert_eq!(audit_count(&inv, "server.role.set").await, 1);
}

#[tokio::test]
async fn routing_policy_updates_jump_via_and_audits_only_changes() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let mut target = srv("target");
    let mut jump = srv("jump");
    for server in [&mut target, &mut jump] {
        server.trusted_host_fingerprint =
            Some("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into());
        inv.add_server(server).await.unwrap();
    }

    for _ in 0..2 {
        inv.set_server_routing_policy_as("admin", &target.id, ServerRole::VpnExit, Some(&jump.id))
            .await
            .unwrap();
    }
    assert_eq!(
        inv.get_server(&target.id).await.unwrap().unwrap().jump_via,
        Some(jump.id.clone())
    );
    assert_eq!(audit_count(&inv, "server.routing_policy.set").await, 1);

    for _ in 0..2 {
        inv.set_server_routing_policy_as("admin", &target.id, ServerRole::VpnExit, None)
            .await
            .unwrap();
    }
    assert!(
        inv.get_server(&target.id)
            .await
            .unwrap()
            .unwrap()
            .jump_via
            .is_none()
    );
    assert_eq!(audit_count(&inv, "server.routing_policy.set").await, 2);
    assert_eq!(audit_count(&inv, "server.jump_via.set").await, 0);
}

#[tokio::test]
async fn list_fleet_servers_filters_workload_only() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    let s1 = srv("exit-1");
    let s2 = srv("exit-2");
    let s3 = srv("workload-1");

    inv.add_server(&s1).await.unwrap();
    inv.add_server(&s2).await.unwrap();
    inv.add_server(&s3).await.unwrap();

    inv.set_role(&s3.id, ServerRole::WorkloadOnly)
        .await
        .unwrap();

    let all_servers = inv.list_servers().await.unwrap();
    assert_eq!(all_servers.len(), 3);

    let fleet_servers = inv.list_fleet_servers().await.unwrap();
    assert_eq!(fleet_servers.len(), 2);
    let fleet_ids: Vec<String> = fleet_servers.into_iter().map(|s| s.id.0).collect();
    assert_eq!(fleet_ids, vec!["exit-1", "exit-2"]);
}

#[tokio::test]
async fn grant_rejects_workload_only_server() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    let u = usr("alice");
    let s = srv("workload-node");

    inv.add_user(&u).await.unwrap();
    inv.add_server(&s).await.unwrap();

    inv.set_role(&s.id, ServerRole::WorkloadOnly).await.unwrap();

    let err = inv.grant(&u.id, &s.id).await.unwrap_err();
    match err {
        SqliteInventoryError::Invalid(msg) => {
            assert!(
                msg.contains("workload-only"),
                "expected workload-only error, got: {msg}"
            );
        }
        other => panic!("expected SqliteInventoryError::Invalid, got: {other:?}"),
    }
}

#[tokio::test]
async fn role_transition_rejects_existing_grants() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    let u = usr("bob");
    let s = srv("exit-node");

    inv.add_user(&u).await.unwrap();
    inv.add_server(&s).await.unwrap();

    inv.grant(&u.id, &s.id).await.unwrap();

    let err = inv
        .set_role(&s.id, ServerRole::WorkloadOnly)
        .await
        .unwrap_err();
    match err {
        SqliteInventoryError::Invalid(msg) => {
            assert!(
                msg.contains("existing grant"),
                "expected existing grants error, got: {msg}"
            );
        }
        other => panic!("expected SqliteInventoryError::Invalid, got: {other:?}"),
    }

    assert_eq!(inv.get_role(&s.id).await.unwrap(), ServerRole::VpnExit);

    inv.revoke(&u.id, &s.id).await.unwrap();
    inv.set_role(&s.id, ServerRole::WorkloadOnly).await.unwrap();
    assert_eq!(inv.get_role(&s.id).await.unwrap(), ServerRole::WorkloadOnly);
}

#[tokio::test]
async fn subscription_servers_for_user_filters_workload_only() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    let u = usr("charlie");
    let s1 = srv("vpn-1");
    let s2 = srv("vpn-2");

    inv.add_user(&u).await.unwrap();
    inv.add_server(&s1).await.unwrap();
    inv.add_server(&s2).await.unwrap();

    inv.grant(&u.id, &s1.id).await.unwrap();
    inv.grant(&u.id, &s2.id).await.unwrap();

    let sub_servers = inv.subscription_servers_for_user(&u.id).await.unwrap();
    assert_eq!(sub_servers.len(), 2);
    let ids: Vec<String> = sub_servers.into_iter().map(|s| s.id.0).collect();
    assert_eq!(ids, vec!["vpn-1", "vpn-2"]);
}

#[tokio::test]
async fn server_role_unknown_server_returns_invalid() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    let unknown_id = ServerId("nonexistent".into());

    let get_err = inv.get_role(&unknown_id).await.unwrap_err();
    assert!(matches!(get_err, SqliteInventoryError::Invalid(_)));

    let set_err = inv
        .set_role(&unknown_id, ServerRole::WorkloadOnly)
        .await
        .unwrap_err();
    assert!(matches!(set_err, SqliteInventoryError::Invalid(_)));
}
