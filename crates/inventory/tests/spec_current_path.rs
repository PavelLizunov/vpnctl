#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use chrono::{DateTime, Duration, Utc};
use serde_json::Value;
use tempfile::TempDir;
use vpnctl_core::{KernelId, Server, ServerId, User, UserId};
use vpnctl_inventory::{
    ServicePathIncident, ServicePathState, ServicePathStatus, ServiceQualitySample,
    SqliteInventory, VpnStatsDelta,
};

const PATH: &str = "office-network:tcp-population-a";
const GAP: u64 = 120;

fn at(seconds: i64) -> DateTime<Utc> {
    "2020-01-02T12:00:00Z".parse::<DateTime<Utc>>().unwrap() + Duration::seconds(seconds)
}

fn sid(id: &str) -> ServerId {
    ServerId(id.into())
}

fn server(id: &str) -> Server {
    Server {
        id: sid(id),
        address: "198.51.100.41".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

fn user(id: &str) -> User {
    User {
        id: UserId(id.into()),
        uuid: format!("fixture-{id}"),
        tuic_password: Some("fixture-private-password".into()),
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: Some(format!("fixture-private-subscription-{id}")),
        vpn_router_device_id: None,
        disabled: false,
    }
}

async fn open(dir: &TempDir) -> SqliteInventory {
    SqliteInventory::open(&dir.path().join("inventory.db"))
        .await
        .unwrap()
}

async fn fixture() -> (TempDir, SqliteInventory) {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("one")).await.unwrap();
    (dir, inv)
}

fn sample(server: &str, seconds: i64, successes: u32, available: u32) -> ServiceQualitySample {
    ServiceQualitySample {
        ts: at(seconds),
        server_id: sid(server),
        vantage: "Office measurement network".into(),
        target_count: 2,
        available_targets: available,
        attempts: 6,
        successes,
        tcp_rtt_ms: vec![20; usize::try_from(successes).unwrap()],
        control_attempts: 3,
        control_successes: 3,
        control_rtt_ms: vec![10; 3],
        icmp_attempts: Some(3),
        icmp_successes: Some(3),
        icmp_rtt_ms: Some(vec![10; 3]),
    }
}

async fn record(inv: &SqliteInventory, seconds: i64, successes: u32, available: u32) {
    inv.record_service_path(&sample("one", seconds, successes, available), PATH, GAP)
        .await
        .unwrap();
}

async fn state(inv: &SqliteInventory, seconds: i64) -> ServicePathState {
    inv.current_service_path(&sid("one"), at(seconds), GAP)
        .await
        .unwrap()
        .expect("recorded path")
}

async fn incidents(inv: &SqliteInventory) -> Vec<ServicePathIncident> {
    inv.service_path_incidents(&sid("one"), 100).await.unwrap()
}

async fn audit_count(inv: &SqliteInventory) -> usize {
    inv.recent_audit_paginated(10_000, 0, None, None, None, None)
        .await
        .unwrap()
        .len()
}

fn json_has_string(value: &Value, expected: &str) -> bool {
    match value {
        Value::String(actual) => actual == expected,
        Value::Array(values) => values.iter().any(|value| json_has_string(value, expected)),
        Value::Object(fields) => fields
            .iter()
            .any(|(key, value)| key == expected || json_has_string(value, expected)),
        _ => false,
    }
}

fn json_has_number(value: &Value, expected: u64) -> bool {
    match value {
        Value::Number(actual) => actual.as_u64() == Some(expected),
        Value::Array(values) => values.iter().any(|value| json_has_number(value, expected)),
        Value::Object(fields) => fields
            .values()
            .any(|value| json_has_number(value, expected)),
        _ => false,
    }
}

#[tokio::test]
async fn empty_state_and_full_success_need_no_confirmation_episode() {
    let (_dir, inv) = fixture().await;
    let before = audit_count(&inv).await;
    assert!(
        inv.current_service_path(&sid("one"), at(0), GAP)
            .await
            .unwrap()
            .is_none()
    );
    assert!(incidents(&inv).await.is_empty());
    assert!(
        inv.service_path_incidents(&sid("missing"), 10)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(audit_count(&inv).await, before);

    record(&inv, 0, 6, 2).await;
    let current = state(&inv, 0).await;
    assert_eq!(current.status, ServicePathStatus::Available);
    assert_eq!(current.vantage, "Office measurement network");
    assert_eq!(current.checked_at, at(0));
    assert_eq!(current.last_success_at, Some(at(0)));
    assert!(incidents(&inv).await.is_empty());
    assert!(audit_count(&inv).await > before);
    assert!(inv.recent_alerts(100, true).await.unwrap().is_empty());
}

#[tokio::test]
async fn failure_confirmation_partial_deterioration_and_recovery_have_exact_bounds() {
    let (_dir, inv) = fixture().await;
    record(&inv, 0, 6, 2).await;
    record(&inv, 60, 0, 0).await;
    assert_eq!(state(&inv, 60).await.status, ServicePathStatus::Degraded);
    let first = incidents(&inv).await.remove(0);
    assert_eq!(first.last_success_at, Some(at(0)));
    assert_eq!(first.first_failure_at, at(60));
    assert_eq!(first.confirmed_at, None);
    assert_eq!(first.first_recovery_at, None);
    assert_eq!(first.recovered_at, None);
    assert_eq!(first.vantage, "Office measurement network");
    assert!(inv.recent_alerts(100, true).await.unwrap().is_empty());

    record(&inv, 120, 0, 0).await;
    assert_eq!(
        state(&inv, 120).await.status,
        ServicePathStatus::Unreachable
    );
    assert_eq!(incidents(&inv).await[0].confirmed_at, Some(at(120)));
    record(&inv, 180, 2, 1).await;
    assert_eq!(state(&inv, 180).await.status, ServicePathStatus::Degraded);
    assert_eq!(incidents(&inv).await[0].confirmed_at, Some(at(120)));
    record(&inv, 240, 6, 2).await;
    assert_eq!(state(&inv, 240).await.status, ServicePathStatus::Recovering);
    assert_eq!(incidents(&inv).await[0].first_recovery_at, Some(at(240)));
    assert_eq!(incidents(&inv).await[0].recovered_at, None);
    record(&inv, 300, 6, 2).await;
    assert_eq!(state(&inv, 300).await.status, ServicePathStatus::Available);
    let closed = incidents(&inv).await.remove(0);
    assert_eq!(closed.id, first.id);
    assert_eq!(closed.first_failure_at, first.first_failure_at);
    assert_eq!(closed.last_success_at, Some(at(0)));
    assert_eq!(closed.confirmed_at, Some(at(120)));
    assert_eq!(closed.first_recovery_at, Some(at(240)));
    assert_eq!(closed.recovered_at, Some(at(300)));
    assert_eq!(closed.diagnostics, first.diagnostics);
}

#[tokio::test]
async fn partial_rounds_interrupt_confirmation_and_also_open_episodes() {
    let (_dir, inv) = fixture().await;
    record(&inv, 0, 3, 1).await;
    assert_eq!(state(&inv, 0).await.status, ServicePathStatus::Degraded);
    assert_eq!(incidents(&inv).await[0].first_failure_at, at(0));
    record(&inv, 60, 0, 0).await;
    record(&inv, 120, 3, 1).await;
    record(&inv, 180, 0, 0).await;
    assert_eq!(state(&inv, 180).await.status, ServicePathStatus::Degraded);
    assert_eq!(incidents(&inv).await[0].confirmed_at, None);
    record(&inv, 240, 0, 0).await;
    assert_eq!(
        state(&inv, 240).await.status,
        ServicePathStatus::Unreachable
    );
    assert_eq!(incidents(&inv).await.len(), 1);
    assert_eq!(incidents(&inv).await[0].confirmed_at, Some(at(240)));
}

#[tokio::test]
async fn successful_attempts_do_not_hide_an_unavailable_target() {
    let (_dir, inv) = fixture().await;
    record(&inv, 0, 6, 1).await;
    assert_eq!(state(&inv, 0).await.status, ServicePathStatus::Degraded);
    assert_eq!(incidents(&inv).await.len(), 1);
    assert_eq!(incidents(&inv).await[0].last_success_at, None);
}

#[tokio::test]
async fn no_tcp_targets_or_attempts_are_unknown_even_with_successful_controls() {
    let (_dir, inv) = fixture().await;
    let mut no_tcp = sample("one", 0, 0, 0);
    no_tcp.target_count = 0;
    no_tcp.attempts = 0;
    inv.record_service_path(&no_tcp, PATH, GAP).await.unwrap();
    assert_eq!(state(&inv, 0).await.status, ServicePathStatus::Unknown);
    assert!(incidents(&inv).await.is_empty());

    no_tcp.ts = at(60);
    no_tcp.target_count = 2;
    inv.record_service_path(&no_tcp, PATH, GAP).await.unwrap();
    assert_eq!(state(&inv, 60).await.status, ServicePathStatus::Unknown);
    assert!(incidents(&inv).await.is_empty());
    assert!(inv.recent_alerts(100, true).await.unwrap().is_empty());
}

#[tokio::test]
async fn unknown_breaks_both_streaks_and_cannot_close_an_episode() {
    let (_dir, inv) = fixture().await;
    record(&inv, 0, 0, 0).await;
    let mut unknown = sample("one", 60, 0, 0);
    unknown.attempts = 0;
    inv.record_service_path(&unknown, PATH, GAP).await.unwrap();
    record(&inv, 120, 0, 0).await;
    assert_eq!(incidents(&inv).await[0].confirmed_at, None);
    record(&inv, 180, 0, 0).await;
    record(&inv, 240, 6, 2).await;
    assert_eq!(incidents(&inv).await[0].first_recovery_at, Some(at(240)));
    unknown.ts = at(300);
    inv.record_service_path(&unknown, PATH, GAP).await.unwrap();
    assert_eq!(state(&inv, 300).await.status, ServicePathStatus::Unknown);
    assert_eq!(incidents(&inv).await[0].confirmed_at, Some(at(180)));
    assert_eq!(incidents(&inv).await[0].first_recovery_at, None);
    assert_eq!(incidents(&inv).await[0].recovered_at, None);
    record(&inv, 360, 6, 2).await;
    assert_eq!(state(&inv, 360).await.status, ServicePathStatus::Recovering);
    assert_eq!(incidents(&inv).await[0].first_recovery_at, Some(at(360)));
    record(&inv, 420, 6, 2).await;
    assert_eq!(incidents(&inv).await[0].recovered_at, Some(at(420)));
}

#[tokio::test]
async fn recovery_streak_restarts_after_partial_or_full_failure() {
    let (_dir, inv) = fixture().await;
    record(&inv, 0, 0, 0).await;
    record(&inv, 60, 6, 2).await;
    record(&inv, 120, 2, 1).await;
    assert_eq!(incidents(&inv).await[0].first_recovery_at, None);
    record(&inv, 180, 6, 2).await;
    assert_eq!(incidents(&inv).await[0].first_recovery_at, Some(at(180)));
    record(&inv, 240, 0, 0).await;
    assert_eq!(incidents(&inv).await[0].first_recovery_at, None);
    record(&inv, 300, 6, 2).await;
    assert_eq!(state(&inv, 300).await.status, ServicePathStatus::Recovering);
    assert_eq!(incidents(&inv).await[0].first_recovery_at, Some(at(300)));
    record(&inv, 360, 6, 2).await;
    assert_eq!(incidents(&inv).await[0].recovered_at, Some(at(360)));
}

#[tokio::test]
async fn stale_or_backwards_reads_are_unknown_without_mutation() {
    let (_dir, inv) = fixture().await;
    record(&inv, 0, 0, 0).await;
    record(&inv, 60, 0, 0).await;
    let before = audit_count(&inv).await;
    let incident = incidents(&inv).await.remove(0);
    assert_eq!(
        state(&inv, 180).await.status,
        ServicePathStatus::Unreachable
    );
    assert_eq!(state(&inv, 181).await.status, ServicePathStatus::Unknown);
    assert_eq!(state(&inv, 59).await.status, ServicePathStatus::Unknown);
    let stored = state(&inv, 60).await;
    assert_eq!(stored.status, ServicePathStatus::Unreachable);
    assert_eq!(stored.checked_at, at(60));
    let after = incidents(&inv).await.remove(0);
    assert_eq!(after.id, incident.id);
    assert_eq!(after.confirmed_at, incident.confirmed_at);
    assert_eq!(after.diagnostics, incident.diagnostics);
    assert_eq!(after.recovered_at, None);
    assert_eq!(audit_count(&inv).await, before);
    assert_eq!(
        inv.current_service_path(&sid("one"), at(60), 0)
            .await
            .unwrap()
            .unwrap()
            .status,
        ServicePathStatus::Unreachable
    );
}

#[tokio::test]
async fn duplicate_and_out_of_order_rounds_cannot_advance_streaks_or_audit() {
    let (_dir, inv) = fixture().await;
    record(&inv, 60, 0, 0).await;
    let before = audit_count(&inv).await;
    record(&inv, 60, 0, 0).await;
    record(&inv, 30, 0, 0).await;
    record(&inv, 60, 6, 2).await;
    assert_eq!(state(&inv, 60).await.status, ServicePathStatus::Degraded);
    assert_eq!(state(&inv, 60).await.checked_at, at(60));
    assert_eq!(incidents(&inv).await[0].confirmed_at, None);
    assert_eq!(audit_count(&inv).await, before);
    record(&inv, 120, 0, 0).await;
    record(&inv, 180, 6, 2).await;
    let before = audit_count(&inv).await;
    record(&inv, 180, 6, 2).await;
    assert_eq!(state(&inv, 180).await.status, ServicePathStatus::Recovering);
    assert_eq!(incidents(&inv).await[0].recovered_at, None);
    assert_eq!(audit_count(&inv).await, before);
}

#[tokio::test]
async fn gap_boundary_is_inclusive_but_larger_gaps_break_confirmation_and_recovery() {
    let (_dir, inv) = fixture().await;
    record(&inv, 0, 0, 0).await;
    record(&inv, 120, 0, 0).await;
    assert_eq!(
        state(&inv, 120).await.status,
        ServicePathStatus::Unreachable
    );
    record(&inv, 240, 6, 2).await;
    record(&inv, 361, 6, 2).await;
    assert_eq!(state(&inv, 361).await.status, ServicePathStatus::Recovering);
    assert_eq!(incidents(&inv).await[0].first_recovery_at, Some(at(361)));
    assert_eq!(incidents(&inv).await[0].recovered_at, None);
    record(&inv, 481, 6, 2).await;
    assert_eq!(state(&inv, 481).await.status, ServicePathStatus::Available);

    record(&inv, 602, 0, 0).await;
    assert_eq!(incidents(&inv).await[0].last_success_at, None);
    record(&inv, 723, 0, 0).await;
    assert_eq!(state(&inv, 723).await.status, ServicePathStatus::Degraded);
    assert_eq!(incidents(&inv).await[0].confirmed_at, None);
    record(&inv, 843, 0, 0).await;
    assert_eq!(incidents(&inv).await[0].confirmed_at, Some(at(843)));
    assert_eq!(incidents(&inv).await.len(), 2);
}

#[tokio::test]
async fn target_identities_vantages_and_servers_keep_independent_open_episodes() {
    let (_dir, inv) = fixture().await;
    inv.add_server(&server("two")).await.unwrap();
    record(&inv, 0, 0, 0).await;
    let original_id = incidents(&inv).await[0].id;
    let mut second_path = sample("one", 60, 6, 2);
    second_path.vantage = "Different measurement network".into();
    inv.record_service_path(&second_path, "other-network:population-b", GAP)
        .await
        .unwrap();
    assert_eq!(state(&inv, 60).await.status, ServicePathStatus::Available);
    assert_eq!(state(&inv, 60).await.vantage, second_path.vantage);
    assert_eq!(incidents(&inv).await[0].id, original_id);
    assert_eq!(incidents(&inv).await[0].recovered_at, None);

    inv.record_service_path(&sample("two", 60, 0, 0), PATH, GAP)
        .await
        .unwrap();
    record(&inv, 120, 0, 0).await;
    assert_eq!(
        state(&inv, 120).await.status,
        ServicePathStatus::Unreachable
    );
    assert_eq!(
        inv.current_service_path(&sid("two"), at(120), GAP)
            .await
            .unwrap()
            .unwrap()
            .status,
        ServicePathStatus::Degraded
    );
    second_path.ts = at(180);
    inv.record_service_path(&second_path, "other-network:population-b", GAP)
        .await
        .unwrap();
    assert_eq!(state(&inv, 180).await.status, ServicePathStatus::Available);
    assert_eq!(incidents(&inv).await[0].confirmed_at, Some(at(120)));
    assert_eq!(incidents(&inv).await[0].recovered_at, None);

    inv.record_service_path(
        &sample("one", 240, 0, 0),
        "office-network:population-c",
        GAP,
    )
    .await
    .unwrap();
    assert_eq!(state(&inv, 240).await.status, ServicePathStatus::Degraded);
    let rows = incidents(&inv).await;
    assert_eq!(rows.len(), 2);
    assert_ne!(rows[0].id, original_id);
    assert_eq!(rows[0].confirmed_at, None);
    assert_eq!(rows[1].id, original_id);
    assert_eq!(rows[1].recovered_at, None);
}

#[tokio::test]
async fn reopen_preserves_episode_snapshot_streak_and_duplicate_protection() {
    let (dir, inv) = fixture().await;
    record(&inv, 0, 6, 2).await;
    record(&inv, 60, 0, 0).await;
    let original = incidents(&inv).await.remove(0);
    drop(inv);
    let inv = open(&dir).await;
    let before = audit_count(&inv).await;
    record(&inv, 60, 0, 0).await;
    assert_eq!(audit_count(&inv).await, before);
    record(&inv, 120, 0, 0).await;
    assert_eq!(
        state(&inv, 120).await.status,
        ServicePathStatus::Unreachable
    );
    record(&inv, 180, 6, 2).await;
    drop(inv);
    let inv = open(&dir).await;
    record(&inv, 240, 6, 2).await;
    let closed = incidents(&inv).await.remove(0);
    assert_eq!(closed.id, original.id);
    assert_eq!(closed.diagnostics, original.diagnostics);
    assert_eq!(closed.recovered_at, Some(at(240)));
    record(&inv, 300, 0, 0).await;
    let rows = incidents(&inv).await;
    assert_eq!(rows.len(), 2);
    assert_ne!(rows[0].id, original.id);
    assert_eq!(rows[0].first_failure_at, at(300));
    assert_eq!(rows[0].last_success_at, Some(at(240)));
    assert_eq!(rows[1].recovered_at, Some(at(240)));
}

#[tokio::test]
async fn invalid_input_fails_atomically_without_incidents_alerts_or_audit() {
    let (_dir, inv) = fixture().await;
    let base = sample("one", 0, 0, 0);
    let mut invalid = vec![];
    let mut row = base.clone();
    row.available_targets = row.target_count + 1;
    invalid.push((row, PATH, GAP));
    let mut row = base.clone();
    row.successes = row.attempts + 1;
    invalid.push((row, PATH, GAP));
    let mut row = base.clone();
    row.control_successes = row.control_attempts + 1;
    invalid.push((row, PATH, GAP));
    let mut row = base.clone();
    row.icmp_successes = Some(row.icmp_attempts.unwrap() + 1);
    invalid.push((row, PATH, GAP));
    let mut row = base.clone();
    row.vantage.clear();
    invalid.push((row, PATH, GAP));
    let mut row = base.clone();
    row.vantage = " \t ".into();
    invalid.push((row, PATH, GAP));
    let mut row = base.clone();
    row.ts = Utc::now() + Duration::days(1);
    invalid.push((row, PATH, GAP));
    let mut row = base.clone();
    row.server_id = sid("missing");
    invalid.push((row, PATH, GAP));
    invalid.push((base.clone(), "", GAP));
    invalid.push((base.clone(), " \t ", GAP));
    invalid.push((base, PATH, 0));
    let before = audit_count(&inv).await;
    for (row, path, gap) in invalid {
        assert!(inv.record_service_path(&row, path, gap).await.is_err());
        assert!(
            inv.current_service_path(&sid("one"), at(0), GAP)
                .await
                .unwrap()
                .is_none()
        );
        assert!(incidents(&inv).await.is_empty());
        assert!(inv.recent_alerts(100, true).await.unwrap().is_empty());
        assert_eq!(audit_count(&inv).await, before);
    }
}

#[tokio::test]
async fn confirmed_alert_is_exactly_once_even_after_ack_and_recovery_is_one_shot() {
    let (_dir, inv) = fixture().await;
    record(&inv, 0, 0, 0).await;
    record(&inv, 60, 0, 0).await;
    let episode = incidents(&inv).await.remove(0);
    let kind = format!("server.path.unavailable.{}", episode.id);
    let alerts = inv.recent_alerts(100, true).await.unwrap();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].kind, kind);
    assert_eq!(alerts[0].server_id, Some(sid("one")));
    assert_eq!(alerts[0].severity, "warning");
    assert_eq!(alerts[0].acked_at, None);
    let opening_id = alerts[0].id;
    inv.ack_alert(opening_id).await.unwrap();
    record(&inv, 120, 0, 0).await;
    record(&inv, 180, 0, 0).await;
    assert_eq!(inv.recent_alerts(100, true).await.unwrap().len(), 1);
    assert!(inv.recent_alerts(100, false).await.unwrap().is_empty());
    assert_eq!(incidents(&inv).await[0].id, episode.id);
    assert_eq!(incidents(&inv).await[0].confirmed_at, Some(at(60)));
    record(&inv, 240, 6, 2).await;
    record(&inv, 300, 6, 2).await;
    let alerts = inv.recent_alerts(100, true).await.unwrap();
    assert_eq!(alerts.len(), 2, "one opening and one recovery event");
    assert!(alerts.iter().all(|alert| alert.acked_at.is_some()));
    assert_eq!(alerts.iter().filter(|alert| alert.kind == kind).count(), 1);
    assert!(alerts.iter().any(|alert| alert.id == opening_id));
    let recovery_kind = format!("server.path.recovered.{}", episode.id);
    assert_eq!(
        alerts
            .iter()
            .filter(|alert| alert.kind == recovery_kind)
            .count(),
        1
    );
    record(&inv, 360, 6, 2).await;
    let before = audit_count(&inv).await;
    record(&inv, 360, 6, 2).await;
    assert_eq!(inv.recent_alerts(100, true).await.unwrap().len(), 2);
    assert_eq!(audit_count(&inv).await, before);
    record(&inv, 420, 0, 0).await;
    record(&inv, 480, 0, 0).await;
    let next = incidents(&inv).await.remove(0);
    assert_ne!(next.id, episode.id);
    let alerts = inv.recent_alerts(100, true).await.unwrap();
    assert_eq!(alerts.len(), 3);
    assert_eq!(
        inv.recent_alerts(100, false).await.unwrap()[0].kind,
        format!("server.path.unavailable.{}", next.id)
    );
}

#[tokio::test]
async fn confirmed_recovery_automatically_acknowledges_an_open_warning() {
    let (_dir, inv) = fixture().await;
    record(&inv, 0, 0, 0).await;
    record(&inv, 60, 0, 0).await;
    assert_eq!(inv.recent_alerts(100, false).await.unwrap().len(), 1);
    record(&inv, 120, 6, 2).await;
    assert_eq!(inv.recent_alerts(100, false).await.unwrap().len(), 1);
    record(&inv, 180, 6, 2).await;
    assert!(inv.recent_alerts(100, false).await.unwrap().is_empty());
    let alerts = inv.recent_alerts(100, true).await.unwrap();
    assert_eq!(alerts.len(), 2);
    assert!(alerts.iter().all(|alert| alert.acked_at.is_some()));
}

#[tokio::test]
async fn incident_history_is_newest_first_and_limits_are_clamped() {
    let (_dir, inv) = fixture().await;
    for episode in 0..102 {
        let start = episode * 180;
        record(&inv, start, 1, 1).await;
        record(&inv, start + 60, 6, 2).await;
        record(&inv, start + 120, 6, 2).await;
    }
    let all = inv
        .service_path_incidents(&sid("one"), i64::MAX)
        .await
        .unwrap();
    assert_eq!(all.len(), 100);
    assert_eq!(all[0].first_failure_at, at(101 * 180));
    assert_eq!(all[99].first_failure_at, at(2 * 180));
    for pair in all.windows(2) {
        assert!(pair[0].first_failure_at > pair[1].first_failure_at);
    }
    for limit in [-10, 0, 1] {
        let rows = inv
            .service_path_incidents(&sid("one"), limit)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, all[0].id);
    }
}

async fn stats_at(
    inv: &SqliteInventory,
    pool: &sqlx::SqlitePool,
    id: &str,
    seconds: i64,
    bytes: (u64, u64),
) {
    inv.add_user(&user(id)).await.unwrap();
    inv.record_vpn_stats(
        &sid("one"),
        &[VpnStatsDelta {
            user_id: Some(UserId(id.into())),
            upload_bytes: bytes.0,
            download_bytes: bytes.1,
            active_connections: 3,
        }],
    )
    .await
    .unwrap();
    sqlx::query("UPDATE vpn_connection_stats SET ts = ?1 WHERE user_id = ?2")
        .bind(at(seconds).to_rfc3339())
        .bind(id)
        .execute(pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn first_deterioration_freezes_users_windows_transition_health_and_audit_evidence() {
    let (dir, inv) = fixture().await;
    let pool = sqlx::SqlitePool::connect(&format!(
        "sqlite://{}",
        dir.path().join("inventory.db").display()
    ))
    .await
    .unwrap();
    stats_at(&inv, &pool, "recent-user", -300, (101, 202)).await;
    stats_at(&inv, &pool, "older-user", -2400, (303, 404)).await;
    stats_at(&inv, &pool, "transition-user", 30, (505, 606)).await;
    stats_at(&inv, &pool, "expired-user", -3660, (707, 808)).await;
    inv.record_node_health(
        &sid("one"),
        Some(false),
        Some(true),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .await
    .unwrap();
    sqlx::query("UPDATE node_health SET ts = ?1 WHERE server_id = 'one'")
        .bind(at(-30).to_rfc3339())
        .execute(&pool)
        .await
        .unwrap();
    inv.audit("admin", "server.fixture-change", Some("one"), None)
        .await
        .unwrap();
    sqlx::query("UPDATE audit_log SET ts = ?1 WHERE action = 'server.fixture-change'")
        .bind(at(-60).to_rfc3339())
        .execute(&pool)
        .await
        .unwrap();
    record(&inv, 0, 6, 2).await;
    record(&inv, 60, 0, 0).await;
    let original = incidents(&inv).await.remove(0);
    for id in ["recent-user", "older-user", "transition-user"] {
        assert!(json_has_string(&original.diagnostics, id), "missing {id}");
    }
    assert!(!json_has_string(&original.diagnostics, "expired-user"));
    for bytes in [101, 202, 303, 404] {
        assert!(json_has_number(&original.diagnostics, bytes));
    }
    assert!(json_has_string(
        &original.diagnostics,
        "server.fixture-change"
    ));
    let encoded = original.diagnostics.to_string();
    assert!(encoded.contains("2020-01-02T11:59:30"));
    for forbidden in [
        "198.51.100.41",
        "fixture-private-password",
        "fixture-private-subscription",
        "fixture-recent-user",
    ] {
        assert!(!encoded.contains(forbidden), "snapshot leaked {forbidden}");
    }

    stats_at(&inv, &pool, "late-user", 90, (909, 1001)).await;
    stats_at(&inv, &pool, "late-backfilled-user", -120, (1101, 1202)).await;
    record(&inv, 120, 0, 0).await;
    assert_eq!(incidents(&inv).await[0].diagnostics, original.diagnostics);
    record(&inv, 180, 6, 2).await;
    record(&inv, 240, 6, 2).await;
    assert_eq!(incidents(&inv).await[0].diagnostics, original.diagnostics);
    drop(inv);
    let inv = open(&dir).await;
    assert_eq!(incidents(&inv).await[0].diagnostics, original.diagnostics);
    pool.close().await;
}

#[tokio::test]
async fn unknown_prior_success_uses_the_first_failure_as_the_snapshot_cutoff() {
    let (dir, inv) = fixture().await;
    let pool = sqlx::SqlitePool::connect(&format!(
        "sqlite://{}",
        dir.path().join("inventory.db").display()
    ))
    .await
    .unwrap();
    stats_at(&inv, &pool, "before-first-failure", 60, (1701, 1802)).await;
    record(&inv, 0, 6, 2).await;
    record(&inv, 181, 0, 0).await;
    let first = incidents(&inv).await.remove(0);
    assert_eq!(first.last_success_at, None);
    assert!(json_has_string(&first.diagnostics, "before-first-failure"));
    assert!(json_has_number(&first.diagnostics, 1701));
    assert!(json_has_number(&first.diagnostics, 1802));
    pool.close().await;
}

#[tokio::test]
async fn recovery_event_delivery_survives_restart_and_is_reserved_once() {
    let (_dir, inv) = fixture().await;
    record(&inv, 0, 0, 0).await;
    record(&inv, 60, 0, 0).await;
    record(&inv, 120, 6, 2).await;
    record(&inv, 180, 6, 2).await;
    let now = Utc::now() + Duration::minutes(6);
    let pending = inv.pending_alert_telegram_deliveries(now).await.unwrap();
    assert_eq!(pending.len(), 1);
    assert!(pending[0].kind.starts_with("server.path.recovered."));
    assert!(pending[0].acked_at.is_some());
    assert!(
        inv.claim_alert_telegram_delivery(pending[0].id, now, true)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        inv.claim_alert_telegram_delivery(pending[0].id, now, true)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        inv.pending_alert_telegram_deliveries(now)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn unrepresentable_evidence_window_fails_without_mutation() {
    let (_dir, inv) = fixture().await;
    let mut row = sample("one", 0, 0, 0);
    row.ts = DateTime::<Utc>::MIN_UTC + Duration::seconds(1);
    let before = audit_count(&inv).await;
    assert!(inv.record_service_path(&row, PATH, GAP).await.is_err());
    assert!(incidents(&inv).await.is_empty());
    assert_eq!(audit_count(&inv).await, before);
    assert!(
        inv.current_service_path(&sid("one"), at(0), GAP)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn fractional_second_over_gap_cannot_confirm_failure() {
    let (_dir, inv) = fixture().await;
    record(&inv, 0, 0, 0).await;
    let mut row = sample("one", 120, 0, 0);
    row.ts += Duration::nanoseconds(1);
    inv.record_service_path(&row, PATH, GAP).await.unwrap();
    assert_eq!(
        inv.current_service_path(&sid("one"), row.ts, GAP)
            .await
            .unwrap()
            .unwrap()
            .status,
        ServicePathStatus::Degraded
    );
    assert!(incidents(&inv).await[0].confirmed_at.is_none());
}
