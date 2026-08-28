//! Spec tests for `client_detour_via` and `set_client_detour_via_as`.
//!
//! Written strictly from `docs/specs/client-detour.md` and test construction patterns.

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

    // Initially no client detour set
    let initial = inv.client_detour_via(&s1).await.unwrap();
    assert_eq!(initial, None);

    assert_eq!(count_audit_by_action(&inv, "server.client_detour.set").await, 0);

    // Set s1 client detour to s2
    inv.set_client_detour_via_as("admin", &s1, Some(&s2))
        .await
        .unwrap();

    let after_set = inv.client_detour_via(&s1).await.unwrap();
    assert_eq!(after_set, Some(s2.clone()));

    assert_eq!(count_audit_by_action(&inv, "server.client_detour.set").await, 1);

    let audits = inv.recent_audit(10).await.unwrap();
    let set_audit = audits
        .iter()
        .find(|a| a.action == "server.client_detour.set")
        .expect("audit row present");
    assert_eq!(set_audit.actor, "admin");
    assert_eq!(set_audit.target.as_deref(), Some("s1"));

    // Clear s1 client detour
    inv.set_client_detour_via_as("admin", &s1, None)
        .await
        .unwrap();

    let after_clear = inv.client_detour_via(&s1).await.unwrap();
    assert_eq!(after_clear, None);

    assert_eq!(count_audit_by_action(&inv, "server.client_detour.set").await, 2);
}

#[tokio::test]
async fn no_op_audit_suppression() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    let s1 = ServerId("s1".into());
    let s2 = ServerId("s2".into());

    inv.add_server(&srv("s1")).await.unwrap();
    inv.add_server(&srv("s2")).await.unwrap();

    // 1. Clearing when already None -> no-op (0 audit rows)
    inv.set_client_detour_via_as("admin", &s1, None)
        .await
        .unwrap();
    assert_eq!(count_audit_by_action(&inv, "server.client_detour.set").await, 0);

    // 2. Setting s1 -> s2 mutates -> 1 audit row
    inv.set_client_detour_via_as("admin", &s1, Some(&s2))
        .await
        .unwrap();
    assert_eq!(count_audit_by_action(&inv, "server.client_detour.set").await, 1);

    // 3. Setting s1 -> s2 again -> no-op (still 1 audit row)
    inv.set_client_detour_via_as("admin", &s1, Some(&s2))
        .await
        .unwrap();
    assert_eq!(count_audit_by_action(&inv, "server.client_detour.set").await, 1);

    // 4. Clearing s1 -> None mutates -> 2 audit rows
    inv.set_client_detour_via_as("admin", &s1, None)
        .await
        .unwrap();
    assert_eq!(count_audit_by_action(&inv, "server.client_detour.set").await, 2);

    // 5. Clearing s1 -> None again -> no-op (still 2 audit rows)
    inv.set_client_detour_via_as("admin", &s1, None)
        .await
        .unwrap();
    assert_eq!(count_audit_by_action(&inv, "server.client_detour.set").await, 2);
}

#[tokio::test]
async fn unknown_target_or_upstream_rejected() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    let s1 = ServerId("s1".into());
    let unknown = ServerId("unknown".into());

    inv.add_server(&srv("s1")).await.unwrap();

    // Unknown target server
    let res = inv
        .set_client_detour_via_as("admin", &unknown, Some(&s1))
        .await;
    assert!(res.is_err(), "unknown target must be rejected");

    // Unknown upstream server
    let res = inv
        .set_client_detour_via_as("admin", &s1, Some(&unknown))
        .await;
    assert!(res.is_err(), "unknown upstream must be rejected");

    // Querying unknown server
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

    // Make s2 workload-only
    inv.set_server_role(&s2, ServerRole::WorkloadOnly)
        .await
        .unwrap();

    // Upstream is workload-only -> reject
    let res = inv
        .set_client_detour_via_as("admin", &s1, Some(&s2))
        .await;
    assert!(
        res.is_err(),
        "workload-only upstream server must be rejected"
    );

    // Make s1 workload-only and s2 vpn-exit
    inv.set_server_role(&s1, ServerRole::WorkloadOnly)
        .await
        .unwrap();
    inv.set_server_role(&s2, ServerRole::VpnExit)
        .await
        .unwrap();

    // Target is workload-only -> reject
    let res = inv
        .set_client_detour_via_as("admin", &s1, Some(&s2))
        .await;
    assert!(
        res.is_err(),
        "workload-only target server must be rejected"
    );
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

    // 1. Self-reference: s1 -> s1
    let res = inv
        .set_client_detour_via_as("admin", &s1, Some(&s1))
        .await;
    assert!(res.is_err(), "self-reference detour must be rejected");

    // Set s1 -> s2
    inv.set_client_detour_via_as("admin", &s1, Some(&s2))
        .await
        .unwrap();

    // 2. Direct cycle: s2 -> s1 (since s1 -> s2)
    let res = inv
        .set_client_detour_via_as("admin", &s2, Some(&s1))
        .await;
    assert!(res.is_err(), "cycle detour s2 -> s1 must be rejected");

    // 3. Nested chain (downstream detour): s3 -> s1 when s1 -> s2
    let res = inv
        .set_client_detour_via_as("admin", &s3, Some(&s1))
        .await;
    assert!(
        res.is_err(),
        "nested chain s3 -> s1 -> s2 must be rejected"
    );

    // 4. Nested chain (upstream detour): s2 -> s3 when s1 -> s2
    let res = inv
        .set_client_detour_via_as("admin", &s2, Some(&s3))
        .await;
    assert!(
        res.is_err(),
        "nested chain s1 -> s2 -> s3 must be rejected"
    );
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
    assert_eq!(inv.get_server_role(&target).await.unwrap(), ServerRole::VpnExit);
    assert_eq!(inv.get_server_role(&entry).await.unwrap(), ServerRole::VpnExit);
}

#[tokio::test]
async fn on_delete_set_null() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    let s1 = ServerId("s1".into());
    let s2 = ServerId("s2".into());

    inv.add_server(&srv("s1")).await.unwrap();
    inv.add_server(&srv("s2")).await.unwrap();

    inv.set_client_detour_via_as("admin", &s1, Some(&s2))
        .await
        .unwrap();
    assert_eq!(inv.client_detour_via(&s1).await.unwrap(), Some(s2.clone()));

    // Delete s2 (upstream)
    inv.remove_server(&s2).await.unwrap();

    // s1 must survive, but its detour is SET NULL
    let s1_server = inv.get_server(&s1).await.unwrap();
    assert!(s1_server.is_some(), "s1 must survive deletion of s2");

    let s1_detour = inv.client_detour_via(&s1).await.unwrap();
    assert_eq!(
        s1_detour, None,
        "client detour must be SET NULL when upstream server s2 is deleted"
    );
}
