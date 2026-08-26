//! Complete spec for server deletion cascading to dependent tables and foreign keys:
//! - `protocol_assurance_samples` CASCADE on DELETE
//! - `node_health` CASCADE on DELETE
//! - `service_quality_samples` CASCADE on DELETE
//! - `admin_alerts` CASCADE on DELETE
//! - `servers.jump_via` SET NULL on DELETE
//!
//! Written from specs and SQLite foreign key constraints.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chrono::{Duration, Utc};
use tempfile::TempDir;
use vpnctl_core::{KernelId, ProtocolId, Server, ServerId};
use vpnctl_inventory::{
    AssuranceStage, AssuranceState, ProtocolAssuranceSample, ServiceQualitySample, SqliteInventory,
};

async fn open(dir: &TempDir) -> SqliteInventory {
    SqliteInventory::open(&dir.path().join("inventory.db"))
        .await
        .expect("open inventory")
}

fn srv(id: &str, jump_via: Option<ServerId>) -> Server {
    Server {
        id: ServerId(id.into()),
        address: format!("192.0.2.{}", id.len()),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("hysteria2".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via,
        usage_coefficient: 1.0,
    }
}

fn assurance_sample(server_id: &str, protocol: &str) -> ProtocolAssuranceSample {
    ProtocolAssuranceSample {
        ts: Utc::now(),
        server_id: ServerId(server_id.into()),
        protocol_id: ProtocolId(protocol.into()),
        client_kind: "external-runner".into(),
        stage: AssuranceStage::Handshake,
        state: AssuranceState::Verified,
        latency_ms: Some(42),
        failure_code: None,
    }
}

fn quality_sample(server_id: &str) -> ServiceQualitySample {
    ServiceQualitySample {
        ts: Utc::now() - Duration::minutes(1),
        server_id: ServerId(server_id.into()),
        vantage: "vpnctld control host".into(),
        target_count: 2,
        available_targets: 2,
        attempts: 6,
        successes: 6,
        tcp_rtt_ms: vec![30, 35, 40],
        control_attempts: 2,
        control_successes: 2,
        control_rtt_ms: vec![10, 12],
        icmp_attempts: Some(3),
        icmp_successes: Some(3),
        icmp_rtt_ms: Some(vec![28, 32]),
    }
}

#[allow(clippy::too_many_arguments)]
async fn rec_health(inv: &SqliteInventory, sid: &str) {
    inv.record_node_health(
        &ServerId(sid.into()),
        Some(true),
        Some(true),
        Some(200),
        Some(2000),
        Some(512),
        Some(1024),
        Some(15),
        Some("[\"tcp/443\"]"),
        Some(1024),
        Some("{\"sing-box\":\"1.13.12\"}"),
        Some("eth0"),
        Some(5000),
        Some(10000),
        Some(0),
    )
    .await
    .expect("record node health");
}

#[tokio::test]
async fn remove_server_cascades_protocol_assurance_samples() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    let s1 = ServerId("s1".into());
    let s2 = ServerId("s2".into());
    inv.add_server(&srv("s1", None)).await.unwrap();
    inv.add_server(&srv("s2", None)).await.unwrap();

    inv.record_protocol_assurance_sample(&assurance_sample("s1", "hysteria2"))
        .await
        .unwrap();
    inv.record_protocol_assurance_sample(&assurance_sample("s2", "hysteria2"))
        .await
        .unwrap();

    assert_eq!(
        inv.latest_protocol_assurance_for_server(&s1)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        inv.latest_protocol_assurance_for_server(&s2)
            .await
            .unwrap()
            .len(),
        1
    );

    inv.remove_server(&s1).await.unwrap();

    let s1_samples = inv.latest_protocol_assurance_for_server(&s1).await.unwrap();
    assert!(
        s1_samples.is_empty(),
        "protocol assurance samples for s1 must be deleted on CASCADE"
    );

    let s2_samples = inv.latest_protocol_assurance_for_server(&s2).await.unwrap();
    assert_eq!(
        s2_samples.len(),
        1,
        "protocol assurance samples for s2 must remain intact"
    );
}

#[tokio::test]
async fn remove_server_cascades_node_health() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    let s1 = ServerId("s1".into());
    let s2 = ServerId("s2".into());
    inv.add_server(&srv("s1", None)).await.unwrap();
    inv.add_server(&srv("s2", None)).await.unwrap();

    rec_health(&inv, "s1").await;
    rec_health(&inv, "s2").await;

    assert!(inv.latest_node_health(&s1).await.unwrap().is_some());
    assert!(inv.latest_node_health(&s2).await.unwrap().is_some());

    inv.remove_server(&s1).await.unwrap();

    assert!(
        inv.latest_node_health(&s1).await.unwrap().is_none(),
        "node_health rows for s1 must be deleted on CASCADE"
    );
    assert!(
        inv.recent_node_health_for_server(&s1, 10)
            .await
            .unwrap()
            .is_empty()
    );

    assert!(
        inv.latest_node_health(&s2).await.unwrap().is_some(),
        "node_health rows for s2 must survive"
    );
    assert_eq!(
        inv.recent_node_health_for_server(&s2, 10)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn remove_server_cascades_quality_samples() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    let s1 = ServerId("s1".into());
    let s2 = ServerId("s2".into());
    inv.add_server(&srv("s1", None)).await.unwrap();
    inv.add_server(&srv("s2", None)).await.unwrap();

    inv.record_service_quality_sample(&quality_sample("s1"))
        .await
        .unwrap();
    inv.record_service_quality_sample(&quality_sample("s2"))
        .await
        .unwrap();

    assert_eq!(
        inv.service_quality_samples_for_server(&s1, 24)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        inv.service_quality_samples_for_server(&s2, 24)
            .await
            .unwrap()
            .len(),
        1
    );

    inv.remove_server(&s1).await.unwrap();

    let s1_quality = inv
        .service_quality_samples_for_server(&s1, 24)
        .await
        .unwrap();
    assert!(
        s1_quality.is_empty(),
        "service quality samples for s1 must be deleted on CASCADE"
    );

    let s2_quality = inv
        .service_quality_samples_for_server(&s2, 24)
        .await
        .unwrap();
    assert_eq!(
        s2_quality.len(),
        1,
        "service quality samples for s2 must survive"
    );
}

#[tokio::test]
async fn remove_server_cascades_alerts() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    let s1 = ServerId("s1".into());
    let s2 = ServerId("s2".into());
    inv.add_server(&srv("s1", None)).await.unwrap();
    inv.add_server(&srv("s2", None)).await.unwrap();

    inv.insert_alert(
        "server.offline",
        Some(&s1),
        "critical",
        "Server s1 is down",
        None,
    )
    .await
    .unwrap();

    inv.insert_alert(
        "server.high_load",
        Some(&s2),
        "warning",
        "Server s2 load is high",
        None,
    )
    .await
    .unwrap();

    inv.insert_alert("system.license", None, "info", "System wide alert", None)
        .await
        .unwrap();

    let alerts_before = inv.recent_alerts(50, true).await.unwrap();
    assert_eq!(alerts_before.len(), 3);

    inv.remove_server(&s1).await.unwrap();

    let alerts_after = inv.recent_alerts(50, true).await.unwrap();
    assert_eq!(alerts_after.len(), 2);

    let s1_alerts_remaining: Vec<_> = alerts_after
        .iter()
        .filter(|a| a.server_id.as_ref() == Some(&s1))
        .collect();
    assert!(
        s1_alerts_remaining.is_empty(),
        "alerts referencing s1 must be deleted on CASCADE"
    );

    let s2_alerts_remaining: Vec<_> = alerts_after
        .iter()
        .filter(|a| a.server_id.as_ref() == Some(&s2))
        .collect();
    assert_eq!(
        s2_alerts_remaining.len(),
        1,
        "alerts referencing s2 must remain"
    );

    let system_alerts: Vec<_> = alerts_after
        .iter()
        .filter(|a| a.server_id.is_none())
        .collect();
    assert_eq!(system_alerts.len(), 1, "global alerts must remain");
}

#[tokio::test]
async fn remove_server_sets_jump_via_null_on_dependent_servers() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    let bastion = ServerId("bastion".into());
    let edge = ServerId("edge".into());

    inv.add_server(&srv("bastion", None)).await.unwrap();
    inv.add_server(&srv("edge", Some(bastion.clone())))
        .await
        .unwrap();

    let edge_before = inv
        .get_server(&edge)
        .await
        .unwrap()
        .expect("edge server must exist");
    assert_eq!(
        edge_before.jump_via,
        Some(bastion.clone()),
        "edge server must initially reference bastion via jump_via"
    );

    inv.remove_server(&bastion).await.unwrap();

    assert!(
        inv.get_server(&bastion).await.unwrap().is_none(),
        "bastion server must be deleted"
    );

    let edge_after = inv
        .get_server(&edge)
        .await
        .unwrap()
        .expect("edge server must survive bastion deletion");
    assert_eq!(
        edge_after.jump_via, None,
        "edge server jump_via must be SET NULL when jump target is removed"
    );
}

#[tokio::test]
async fn complete_server_cascade_all_in_one() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    let s1 = ServerId("s1".into());
    let s2 = ServerId("s2".into());

    // 1. Add servers with jump_via dependency (s2 -> s1)
    inv.add_server(&srv("s1", None)).await.unwrap();
    inv.add_server(&srv("s2", Some(s1.clone()))).await.unwrap();

    // 2. Add protocol assurance samples
    inv.record_protocol_assurance_sample(&assurance_sample("s1", "hysteria2"))
        .await
        .unwrap();
    inv.record_protocol_assurance_sample(&assurance_sample("s2", "hysteria2"))
        .await
        .unwrap();

    // 3. Add node health rows
    rec_health(&inv, "s1").await;
    rec_health(&inv, "s2").await;

    // 4. Add quality samples
    inv.record_service_quality_sample(&quality_sample("s1"))
        .await
        .unwrap();
    inv.record_service_quality_sample(&quality_sample("s2"))
        .await
        .unwrap();

    // 5. Add alerts
    inv.insert_alert("server.offline", Some(&s1), "critical", "s1 down", None)
        .await
        .unwrap();
    inv.insert_alert("server.offline", Some(&s2), "critical", "s2 down", None)
        .await
        .unwrap();

    // Verify all s1 records exist prior to removal
    assert!(
        !inv.latest_protocol_assurance_for_server(&s1)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(inv.latest_node_health(&s1).await.unwrap().is_some());
    assert!(
        !inv.service_quality_samples_for_server(&s1, 24)
            .await
            .unwrap()
            .is_empty()
    );

    // Delete s1
    inv.remove_server(&s1).await.unwrap();

    // Verify s1 is deleted
    assert!(inv.get_server(&s1).await.unwrap().is_none());

    // Verify protocol assurance cascade
    assert!(
        inv.latest_protocol_assurance_for_server(&s1)
            .await
            .unwrap()
            .is_empty(),
        "protocol_assurance_samples for s1 must be empty after cascade"
    );
    assert_eq!(
        inv.latest_protocol_assurance_for_server(&s2)
            .await
            .unwrap()
            .len(),
        1,
        "protocol_assurance_samples for s2 must remain"
    );

    // Verify node health cascade
    assert!(
        inv.latest_node_health(&s1).await.unwrap().is_none(),
        "latest_node_health for s1 must be None after cascade"
    );
    assert!(
        inv.recent_node_health_for_server(&s1, 10)
            .await
            .unwrap()
            .is_empty(),
        "recent_node_health for s1 must be empty after cascade"
    );
    assert!(
        inv.latest_node_health(&s2).await.unwrap().is_some(),
        "latest_node_health for s2 must remain"
    );

    // Verify quality cascade
    assert!(
        inv.service_quality_samples_for_server(&s1, 24)
            .await
            .unwrap()
            .is_empty(),
        "quality samples for s1 must be empty after cascade"
    );
    assert_eq!(
        inv.service_quality_samples_for_server(&s2, 24)
            .await
            .unwrap()
            .len(),
        1,
        "quality samples for s2 must remain"
    );

    // Verify alerts cascade
    let alerts = inv.recent_alerts(50, true).await.unwrap();
    assert!(
        alerts.iter().all(|a| a.server_id.as_ref() != Some(&s1)),
        "no alerts referencing s1 should exist after cascade"
    );
    assert!(
        alerts.iter().any(|a| a.server_id.as_ref() == Some(&s2)),
        "alerts referencing s2 must remain"
    );

    // Verify jump_via SET NULL
    let s2_srv = inv.get_server(&s2).await.unwrap().expect("s2 must survive");
    assert_eq!(
        s2_srv.jump_via, None,
        "s2 jump_via must be SET NULL after s1 removal"
    );
}
