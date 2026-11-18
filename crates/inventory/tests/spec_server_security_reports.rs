#![allow(clippy::unwrap_used)]

use tempfile::TempDir;
use vpnctl_core::{KernelId, ProtocolId, Server, ServerId};
use vpnctl_inventory::{SqliteInventory, sqlite::ServerSecurityReport};

async fn open(dir: &TempDir) -> SqliteInventory {
    SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap()
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

fn report(revision: i64, route: &str, json: &str) -> ServerSecurityReport {
    ServerSecurityReport {
        route_fingerprint: route.into(),
        revision,
        report_json: json.into(),
    }
}

fn assert_report(actual: &ServerSecurityReport, expected: &ServerSecurityReport) {
    assert_eq!(actual.revision, expected.revision);
    assert_eq!(actual.route_fingerprint, expected.route_fingerprint);
    assert_eq!(actual.report_json, expected.report_json);
}

#[tokio::test]
async fn newest_security_report_is_returned_after_reopening_inventory() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let id = add_server(&inv, "alpha").await;
    let unchecked = add_server(&inv, "unchecked").await;
    assert!(inv.server_security_report(&id).await.unwrap().is_none());
    assert!(inv.server_security_reports().await.unwrap().is_empty());

    let first = report(1_700_000_000_000_001, "old-route", r#"{"items":[1]}"#);
    let newest = report(1_700_000_000_000_003, "new-route", r#"{"items":[2]}"#);
    let late = report(1_700_000_000_000_002, "late-route", r#"{"items":[3]}"#);
    for report in [&first, &newest, &late] {
        inv.record_server_security_report(&id, report)
            .await
            .unwrap();
    }
    drop(inv);

    let reopened = open(&dir).await;
    let by_id = reopened.server_security_report(&id).await.unwrap().unwrap();
    assert_report(&by_id, &newest);
    let fleet = reopened.server_security_reports().await.unwrap();
    assert_eq!(fleet.len(), 1);
    assert_report(fleet.get(&id).unwrap(), &newest);
    assert!(
        reopened
            .server_security_report(&unchecked)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn recording_security_report_for_absent_server_is_noop() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let missing = ServerId("missing".into());
    let report = report(1_700_000_000_000_001, "missing-route", r#"{"items":[]}"#);

    inv.record_server_security_report(&missing, &report)
        .await
        .unwrap();
    assert!(
        inv.server_security_report(&missing)
            .await
            .unwrap()
            .is_none()
    );
    assert!(inv.server_security_reports().await.unwrap().is_empty());

    let added = add_server(&inv, "missing").await;
    assert!(inv.server_security_report(&added).await.unwrap().is_none());
}

#[tokio::test]
async fn removing_server_removes_only_its_report_even_if_id_is_reused() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let alpha = add_server(&inv, "alpha").await;
    let beta = add_server(&inv, "beta").await;
    let alpha_report = report(1_700_000_000_000_003, "alpha-route", r#"{"items":[1]}"#);
    let beta_report = report(1_700_000_000_000_001, "beta-route", r#"{"items":[]}"#);
    inv.record_server_security_report(&alpha, &alpha_report)
        .await
        .unwrap();
    inv.record_server_security_report(&beta, &beta_report)
        .await
        .unwrap();
    let before = inv.server_security_reports().await.unwrap();
    assert_eq!(before.len(), 2);
    assert_report(before.get(&alpha).unwrap(), &alpha_report);
    assert_report(before.get(&beta).unwrap(), &beta_report);

    inv.remove_server(&alpha).await.unwrap();

    assert!(inv.server_security_report(&alpha).await.unwrap().is_none());
    let after = inv.server_security_reports().await.unwrap();
    assert_eq!(after.len(), 1);
    assert_report(after.get(&beta).unwrap(), &beta_report);

    add_server(&inv, "alpha").await;
    assert!(inv.server_security_report(&alpha).await.unwrap().is_none());
}
