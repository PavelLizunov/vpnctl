#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use tempfile::TempDir;
use vpnctl_core::{KernelId, ProtocolId, Server, ServerId};
use vpnctl_inventory::{ServerRole, SqliteInventory};

async fn open(dir: &TempDir) -> SqliteInventory {
    SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .expect("open inventory")
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

async fn count_audit_by_action(inv: &SqliteInventory, action: &str) -> usize {
    inv.recent_audit(1000)
        .await
        .unwrap()
        .into_iter()
        .filter(|a| a.action == action)
        .count()
}

#[tokio::test]
async fn happy_set_get_clear_client_detour() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    let s1 = ServerId("s1".into());
    let s2 = ServerId("s2".into());

    inv.add_server(&srv("s1")).await.unwrap();
    inv.add_server(&srv("s2")).await.unwrap();

    let initial = inv.client_detour_via(&s1).await.unwrap();
    assert_eq!(initial, None);

    assert_eq!(
        count_audit_by_action(&inv, "server.client_detour.set").await,
        0
    );

    inv.set_client_detour_via_as("admin", &s1, Some(&s2))
        .await
        .unwrap();

    let after_set = inv.client_detour_via(&s1).await.unwrap();
    assert_eq!(after_set, Some(s2.clone()));

    assert_eq!(
        count_audit_by_action(&inv, "server.client_detour.set").await,
        1
    );

    let audits = inv.recent_audit(10).await.unwrap();
    let set_audit = audits
        .iter()
        .find(|a| a.action == "server.client_detour.set")
        .expect("audit row present");
    assert_eq!(set_audit.actor, "admin");
    assert_eq!(set_audit.target.as_deref(), Some("s1"));

    inv.set_client_detour_via_as("admin", &s1, None)
        .await
        .unwrap();

    let after_clear = inv.client_detour_via(&s1).await.unwrap();
    assert_eq!(after_clear, None);

    assert_eq!(
        count_audit_by_action(&inv, "server.client_detour.set").await,
        2
    );
}

#[tokio::test]
async fn no_op_audit_suppression() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    let s1 = ServerId("s1".into());
    let s2 = ServerId("s2".into());

    inv.add_server(&srv("s1")).await.unwrap();
    inv.add_server(&srv("s2")).await.unwrap();

    inv.set_client_detour_via_as("admin", &s1, None)
        .await
        .unwrap();
    assert_eq!(
        count_audit_by_action(&inv, "server.client_detour.set").await,
        0
    );

    inv.set_client_detour_via_as("admin", &s1, Some(&s2))
        .await
        .unwrap();
    assert_eq!(
        count_audit_by_action(&inv, "server.client_detour.set").await,
        1
    );

    inv.set_client_detour_via_as("admin", &s1, Some(&s2))
        .await
        .unwrap();
    assert_eq!(
        count_audit_by_action(&inv, "server.client_detour.set").await,
        1
    );

    inv.set_client_detour_via_as("admin", &s1, None)
        .await
        .unwrap();
    assert_eq!(
        count_audit_by_action(&inv, "server.client_detour.set").await,
        2
    );

    inv.set_client_detour_via_as("admin", &s1, None)
        .await
        .unwrap();
    assert_eq!(
        count_audit_by_action(&inv, "server.client_detour.set").await,
        2
    );
}

#[tokio::test]
async fn unknown_target_or_upstream_rejected() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    let s1 = ServerId("s1".into());
    let unknown = ServerId("unknown".into());

    inv.add_server(&srv("s1")).await.unwrap();

    let res = inv
        .set_client_detour_via_as("admin", &unknown, Some(&s1))
        .await;
    assert!(res.is_err(), "unknown target must be rejected");

    let res = inv
        .set_client_detour_via_as("admin", &s1, Some(&unknown))
        .await;
    assert!(res.is_err(), "unknown upstream must be rejected");

    let got = inv.client_detour_via(&unknown).await.unwrap();
    assert_eq!(got, None);
}

#[tokio::test]
async fn workload_only_server_rejected() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    let s1 = ServerId("s1".into());
    let s2 = ServerId("s2".into());

    inv.add_server(&srv("s1")).await.unwrap();
    inv.add_server(&srv("s2")).await.unwrap();

    inv.set_server_role(&s2, ServerRole::WorkloadOnly)
        .await
        .unwrap();

    let res = inv.set_client_detour_via_as("admin", &s1, Some(&s2)).await;
    assert!(
        res.is_err(),
        "workload-only upstream server must be rejected"
    );

    inv.set_server_role(&s1, ServerRole::WorkloadOnly)
        .await
        .unwrap();
    inv.set_server_role(&s2, ServerRole::VpnExit).await.unwrap();

    let res = inv.set_client_detour_via_as("admin", &s1, Some(&s2)).await;
    assert!(res.is_err(), "workload-only target server must be rejected");
}

#[tokio::test]
async fn self_cycle_and_nested_rejections() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    let s1 = ServerId("s1".into());
    let s2 = ServerId("s2".into());
    let s3 = ServerId("s3".into());

    inv.add_server(&srv("s1")).await.unwrap();
    inv.add_server(&srv("s2")).await.unwrap();
    inv.add_server(&srv("s3")).await.unwrap();

    let res = inv.set_client_detour_via_as("admin", &s1, Some(&s1)).await;
    assert!(res.is_err(), "self-reference detour must be rejected");

    inv.set_client_detour_via_as("admin", &s1, Some(&s2))
        .await
        .unwrap();

    let res = inv.set_client_detour_via_as("admin", &s2, Some(&s1)).await;
    assert!(res.is_err(), "cycle detour s2 -> s1 must be rejected");

    let res = inv.set_client_detour_via_as("admin", &s3, Some(&s1)).await;
    assert!(res.is_err(), "nested chain s3 -> s1 -> s2 must be rejected");

    let res = inv.set_client_detour_via_as("admin", &s2, Some(&s3)).await;
    assert!(res.is_err(), "nested chain s1 -> s2 -> s3 must be rejected");
}

#[tokio::test]
async fn role_transition_rejected_while_server_participates_in_detour() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let target = ServerId("target".into());
    let entry = ServerId("entry".into());
    inv.add_server(&srv("target")).await.unwrap();
    inv.add_server(&srv("entry")).await.unwrap();
    inv.set_client_detour_via_as("admin", &target, Some(&entry))
        .await
        .unwrap();

    assert!(
        inv.set_server_role(&target, ServerRole::WorkloadOnly)
            .await
            .is_err(),
        "chained target must remain vpn-exit"
    );
    assert!(
        inv.set_server_role(&entry, ServerRole::WorkloadOnly)
            .await
            .is_err(),
        "entry server must remain vpn-exit"
    );
    assert_eq!(
        inv.get_server_role(&target).await.unwrap(),
        ServerRole::VpnExit
    );
    assert_eq!(
        inv.get_server_role(&entry).await.unwrap(),
        ServerRole::VpnExit
    );
}

#[tokio::test]
async fn deleting_client_entry_is_rejected_without_clearing_target_policies() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let entry = ServerId("entry".into());
    inv.add_server(&srv("entry")).await.unwrap();
    for target in ["target-a", "target-b"] {
        inv.add_server(&srv(target)).await.unwrap();
        inv.set_client_detour_via_as("admin", &ServerId(target.into()), Some(&entry))
            .await
            .unwrap();
    }
    let before = inv.recent_audit(100).await.unwrap().len();
    let err = inv.remove_server(&entry).await.unwrap_err().to_string();
    assert!(err.contains("entry") && err.contains("target-a, target-b"));
    assert!(inv.get_server(&entry).await.unwrap().is_some());
    assert_eq!(inv.recent_audit(100).await.unwrap().len(), before);
    for target in ["target-a", "target-b"] {
        let target = ServerId(target.into());
        assert_eq!(
            inv.client_detour_via(&target).await.unwrap(),
            Some(entry.clone())
        );
        inv.remove_server(&target).await.unwrap();
    }
    inv.remove_server(&entry).await.unwrap();
    assert!(inv.get_server(&entry).await.unwrap().is_none());
}
