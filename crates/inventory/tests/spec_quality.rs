#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use chrono::{Duration, Utc};
use tempfile::TempDir;
use vpnctl_core::{KernelId, Server, ServerId};
use vpnctl_inventory::{ServiceQualitySample, SqliteInventory};

fn server(id: &str) -> Server {
    Server {
        id: ServerId(id.into()),
        address: "203.0.113.10".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("xray".into())],
        enabled_protocols: vec![],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

fn sample(server_id: &str, age: Duration) -> ServiceQualitySample {
    ServiceQualitySample {
        ts: Utc::now() - age,
        server_id: ServerId(server_id.into()),
        vantage: "192.168.0.236 · vpnctld control host".into(),
        target_count: 2,
        available_targets: 1,
        attempts: 6,
        successes: 5,
        tcp_rtt_ms: vec![40, 45, 50, 55, 60],
        control_attempts: 3,
        control_successes: 3,
        control_rtt_ms: vec![10, 11, 12],
        icmp_attempts: Some(3),
        icmp_successes: Some(2),
        icmp_rtt_ms: Some(vec![39, 44]),
    }
}

async fn open() -> (TempDir, SqliteInventory) {
    let dir = TempDir::new().expect("tempdir");
    let inv = SqliteInventory::open(&dir.path().join("inventory.db"))
        .await
        .expect("open inventory");
    (dir, inv)
}

#[tokio::test]
async fn migration_and_sample_roundtrip_preserve_tcp_and_optional_icmp() {
    let (_dir, inv) = open().await;
    inv.add_server(&server("de")).await.expect("add server");
    let expected = sample("de", Duration::minutes(5));
    inv.record_service_quality_sample(&expected)
        .await
        .expect("record sample");

    let rows = inv
        .service_quality_samples_for_server(&ServerId("de".into()), 24)
        .await
        .expect("read samples");
    assert_eq!(rows.len(), 1);
    let actual = &rows[0];
    assert_eq!(actual.server_id, expected.server_id);
    assert_eq!(actual.vantage, expected.vantage);
    assert_eq!(actual.tcp_rtt_ms, expected.tcp_rtt_ms);
    assert_eq!(actual.control_attempts, 3);
    assert_eq!(actual.control_successes, 3);
    assert_eq!(actual.control_rtt_ms, vec![10, 11, 12]);
    assert_eq!(actual.icmp_attempts, Some(3));
    assert_eq!(actual.icmp_successes, Some(2));
    assert_eq!(actual.icmp_rtt_ms, Some(vec![39, 44]));
}

#[tokio::test]
async fn windows_are_rolling_and_too_few_samples_stay_unknown() {
    let (_dir, inv) = open().await;
    inv.add_server(&server("de")).await.expect("add server");
    inv.record_service_quality_sample(&sample("de", Duration::hours(23)))
        .await
        .expect("recent");
    inv.record_service_quality_sample(&sample("de", Duration::hours(25)))
        .await
        .expect("old");

    let score = inv
        .service_quality_for_server(&ServerId("de".into()), 24, 12)
        .await
        .expect("score");
    assert_eq!(score.sample_count, 1);
    assert_eq!(score.score, None);
    assert_eq!(score.availability_pct, Some(50.0));
}

#[tokio::test]
async fn foreign_key_and_retention_contracts_hold() {
    let (_dir, inv) = open().await;
    assert!(
        inv.record_service_quality_sample(&sample("missing", Duration::zero()))
            .await
            .is_err(),
        "quality row must not outlive or invent a server"
    );

    inv.add_server(&server("de")).await.expect("add server");
    inv.record_service_quality_sample(&sample("de", Duration::days(8)))
        .await
        .expect("old sample");
    inv.record_service_quality_sample(&sample("de", Duration::days(1)))
        .await
        .expect("recent sample");
    assert_eq!(
        inv.purge_service_quality_older_than(7)
            .await
            .expect("purge"),
        1
    );
    assert_eq!(
        inv.service_quality_samples_for_server(&ServerId("de".into()), 24 * 30)
            .await
            .expect("remaining")
            .len(),
        1
    );
}
