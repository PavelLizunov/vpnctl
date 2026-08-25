#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use chrono::{Duration, Utc};
use tempfile::TempDir;
use vpnctl_core::{KernelId, ProtocolId, Server, ServerId};
use vpnctl_inventory::{AssuranceStage, AssuranceState, ProtocolAssuranceSample, SqliteInventory};

fn server() -> Server {
    Server {
        id: ServerId("s1".into()),
        address: "192.0.2.1".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("hysteria2".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

fn sample(state: AssuranceState, minute: i64) -> ProtocolAssuranceSample {
    ProtocolAssuranceSample {
        ts: Utc::now() + Duration::minutes(minute),
        server_id: ServerId("s1".into()),
        protocol_id: ProtocolId("hysteria2".into()),
        client_kind: "external-runner".into(),
        stage: AssuranceStage::Handshake,
        state,
        latency_ms: Some(123),
        failure_code: (state != AssuranceState::Verified).then(|| "handshake_timeout".into()),
    }
}

#[tokio::test]
async fn latest_sample_wins_per_protocol_across_client_kinds() {
    let tmp = TempDir::new().unwrap();
    let inv = SqliteInventory::open(&tmp.path().join("inv.db"))
        .await
        .unwrap();
    inv.add_server(&server()).await.unwrap();
    inv.record_protocol_assurance_sample(&sample(AssuranceState::Blocked, -1))
        .await
        .unwrap();
    let mut latest = sample(AssuranceState::Verified, 0);
    latest.client_kind = "xray".into();
    inv.record_protocol_assurance_sample(&latest).await.unwrap();

    let rows = inv
        .latest_protocol_assurance_for_server(&ServerId("s1".into()))
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].state, AssuranceState::Verified);
    assert_eq!(rows[0].stage, AssuranceStage::Handshake);
    assert_eq!(rows[0].client_kind, "xray");
}

#[tokio::test]
async fn deleting_server_cascades_assurance_rows() {
    let tmp = TempDir::new().unwrap();
    let inv = SqliteInventory::open(&tmp.path().join("inv.db"))
        .await
        .unwrap();
    inv.add_server(&server()).await.unwrap();
    inv.record_protocol_assurance_sample(&sample(AssuranceState::Blocked, 0))
        .await
        .unwrap();
    inv.remove_server(&ServerId("s1".into())).await.unwrap();
    let rows = inv
        .latest_protocol_assurance_for_server(&ServerId("s1".into()))
        .await
        .unwrap();
    assert!(rows.is_empty());
}

#[tokio::test]
async fn consecutive_failure_count_stops_at_recovery() {
    let tmp = TempDir::new().unwrap();
    let inv = SqliteInventory::open(&tmp.path().join("inv.db"))
        .await
        .unwrap();
    inv.add_server(&server()).await.unwrap();
    for minute in 0..3 {
        inv.record_protocol_assurance_sample(&sample(AssuranceState::Blocked, minute))
            .await
            .unwrap();
    }
    assert_eq!(
        inv.consecutive_protocol_assurance_failures(
            &ServerId("s1".into()),
            &ProtocolId("hysteria2".into()),
            3,
        )
        .await
        .unwrap(),
        3
    );
    inv.record_protocol_assurance_sample(&sample(AssuranceState::Verified, 4))
        .await
        .unwrap();
    assert_eq!(
        inv.consecutive_protocol_assurance_failures(
            &ServerId("s1".into()),
            &ProtocolId("hysteria2".into()),
            3,
        )
        .await
        .unwrap(),
        0
    );
}

#[tokio::test]
async fn database_rejects_unbounded_failure_code() {
    let tmp = TempDir::new().unwrap();
    let inv = SqliteInventory::open(&tmp.path().join("inv.db"))
        .await
        .unwrap();
    inv.add_server(&server()).await.unwrap();
    let mut row = sample(AssuranceState::Blocked, 0);
    row.failure_code = Some("x".repeat(129));
    assert!(inv.record_protocol_assurance_sample(&row).await.is_err());
}
