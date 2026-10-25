#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::Duration;

use chrono::{TimeZone, Utc};
use tempfile::TempDir;
use vpnctl_core::{Server, ServerId, User, UserId};
use vpnctl_inventory::{NodeHealthRow, SqliteInventory};

use super::diff::*;
use super::fingerprint_drift::*;
use super::poller::*;
use super::remediation::*;
use super::specialized_checks::*;

#[allow(clippy::too_many_arguments)]
fn row(
    mins_ago: i64,
    sb: Option<bool>,
    f2b: Option<bool>,
    disk_u: Option<u64>,
    disk_t: Option<u64>,
    mem_a: Option<u64>,
    mem_t: Option<u64>,
    log_b: Option<u64>,
) -> NodeHealthRow {
    NodeHealthRow {
        sample_seq: None,
        sample_id: None,
        ts: Utc.with_ymd_and_hms(2026, 5, 17, 22, 0, 0).unwrap()
            - chrono::Duration::minutes(mins_ago),
        server_id: ServerId("test".into()),
        sing_box_active: sb,
        fail2ban_active: f2b,
        disk_used_mib: disk_u,
        disk_total_mib: disk_t,
        mem_available_mib: mem_a,
        mem_total_mib: mem_t,
        load_1min_x100: None,
        listening_ports_json: None,
        sing_box_log_bytes: log_b,
        kernel_versions_json: None,
        nic_iface: None,
        nic_rx_bytes: None,
        nic_tx_bytes: None,
        sing_box_nrestarts: None,
    }
}

fn row_nr(mins_ago: i64, nr: Option<u64>) -> NodeHealthRow {
    let mut r = row(mins_ago, Some(true), None, None, None, None, None, None);
    r.sing_box_nrestarts = nr;
    r
}

#[test]
fn diff_rows_singbox_down_fires_critical() {
    let prev = row(10, Some(true), None, None, None, None, None, None);
    let cur = row(0, Some(false), None, None, None, None, None, None);
    let evs = diff_rows(&prev, &cur);
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].kind, "server.singbox.down");
    assert_eq!(evs[0].severity, "critical");
    assert!(evs[0].summary.contains("sing-box"));
}

#[test]
fn diff_rows_singbox_up_fires_info() {
    let prev = row(10, Some(false), None, None, None, None, None, None);
    let cur = row(0, Some(true), None, None, None, None, None, None);
    let evs = diff_rows(&prev, &cur);
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].kind, "server.singbox.up");
    assert_eq!(evs[0].severity, "info");
    assert_eq!(
        evs[0].resolves,
        Some("server.singbox.down"),
        "recovery must name the paired condition it closes"
    );
}

#[test]
fn diff_rows_nrestarts_increase_fires_warning() {
    let prev = row_nr(10, Some(2));
    let cur = row_nr(0, Some(5));
    let evs = diff_rows(&prev, &cur);
    assert_eq!(evs.len(), 1, "exactly one restart alert: {evs:?}");
    assert_eq!(evs[0].kind, "server.singbox.restarted");
    assert_eq!(evs[0].severity, "warning");
    assert_eq!(
        evs[0].resolves, None,
        "a restart is a discrete event, not a condition"
    );
    assert!(
        evs[0].summary.contains("3 time(s)"),
        "summary must carry the delta: {}",
        evs[0].summary
    );
    assert_eq!(evs[0].payload["prior"], 2);
    assert_eq!(evs[0].payload["current"], 5);
    assert_eq!(evs[0].payload["delta"], 3);
}

#[test]
fn diff_rows_nrestarts_first_observation_is_silent() {
    let prev = row_nr(10, None);
    let cur = row_nr(0, Some(4));
    assert!(
        diff_rows(&prev, &cur).is_empty(),
        "first observation of a counter must not alert"
    );
}

#[test]
fn diff_rows_nrestarts_preexisting_high_counter_is_silent() {
    let prev = row_nr(10, Some(5));
    let cur = row_nr(0, Some(5));
    assert!(
        diff_rows(&prev, &cur).is_empty(),
        "equal readings (no increase) must not alert"
    );
}

#[test]
fn diff_rows_nrestarts_reset_after_reboot_is_silent() {
    let prev = row_nr(10, Some(5));
    let cur = row_nr(0, Some(0));
    assert!(
        diff_rows(&prev, &cur).is_empty(),
        "a counter reset (decrease) must not alert"
    );
}

#[test]
fn diff_rows_nrestarts_both_absent_is_silent() {
    let prev = row_nr(10, None);
    let cur = row_nr(0, None);
    assert!(diff_rows(&prev, &cur).is_empty());
}

#[test]
fn diff_rows_resolves_pairing_is_complete() {
    let fire = |prev: NodeHealthRow, cur: NodeHealthRow| diff_rows(&prev, &cur);
    let cases: Vec<(Vec<AlertEvent>, &str, Option<&str>)> = vec![
        (
            fire(
                row(10, Some(true), None, None, None, None, None, None),
                row(0, Some(false), None, None, None, None, None, None),
            ),
            "server.singbox.down",
            None,
        ),
        (
            fire(
                row(10, None, Some(true), None, None, None, None, None),
                row(0, None, Some(false), None, None, None, None, None),
            ),
            "server.fail2ban.down",
            None,
        ),
        (
            fire(
                row(10, None, Some(false), None, None, None, None, None),
                row(0, None, Some(true), None, None, None, None, None),
            ),
            "server.fail2ban.up",
            Some("server.fail2ban.down"),
        ),
        (
            fire(
                row(10, None, None, Some(80), Some(100), None, None, None),
                row(0, None, None, Some(95), Some(100), None, None, None),
            ),
            "server.disk.pressure",
            None,
        ),
        (
            fire(
                row(10, None, None, Some(95), Some(100), None, None, None),
                row(0, None, None, Some(80), Some(100), None, None, None),
            ),
            "server.disk.recovered",
            Some("server.disk.pressure"),
        ),
    ];
    for (evs, kind, resolves) in cases {
        let ev = evs
            .iter()
            .find(|e| e.kind == kind)
            .unwrap_or_else(|| panic!("{kind} did not fire"));
        assert_eq!(ev.resolves, resolves, "pairing wrong for {kind}");
    }
}

#[test]
fn diff_rows_no_change_emits_nothing() {
    let prev = row(
        10,
        Some(true),
        Some(true),
        Some(50),
        Some(100),
        Some(80),
        Some(100),
        None,
    );
    let cur = row(
        0,
        Some(true),
        Some(true),
        Some(50),
        Some(100),
        Some(80),
        Some(100),
        None,
    );
    assert!(diff_rows(&prev, &cur).is_empty());
}

#[test]
fn diff_rows_disk_pressure_crosses_90_fires() {
    let prev = row(10, None, None, Some(89), Some(100), None, None, None);
    let cur = row(0, None, None, Some(91), Some(100), None, None, None);
    let evs = diff_rows(&prev, &cur);
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].kind, "server.disk.pressure");
    assert_eq!(evs[0].severity, "warning");
}

#[test]
fn diff_rows_disk_hysteresis_no_flap_at_88_pct() {
    let prev = row(10, None, None, Some(91), Some(100), None, None, None);
    let cur = row(0, None, None, Some(88), Some(100), None, None, None);
    assert!(diff_rows(&prev, &cur).is_empty());
}

#[test]
fn diff_rows_disk_recovered_under_85_fires_info() {
    let prev = row(10, None, None, Some(91), Some(100), None, None, None);
    let cur = row(0, None, None, Some(84), Some(100), None, None, None);
    let evs = diff_rows(&prev, &cur);
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].kind, "server.disk.recovered");
    assert_eq!(evs[0].severity, "info");
}

#[test]
fn diff_rows_disk_gradual_recovery_crosses_85_fires_info() {
    let prev = row(10, None, None, Some(88), Some(100), None, None, None);
    let cur = row(0, None, None, Some(84), Some(100), None, None, None);
    let evs = diff_rows(&prev, &cur);
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].kind, "server.disk.recovered");
    assert_eq!(evs[0].resolves, Some("server.disk.pressure"));
}

#[test]
fn diff_rows_mem_pressure_crosses_95_fires() {
    let prev = row(10, None, None, None, None, Some(6), Some(100), None);
    let cur = row(0, None, None, None, None, Some(4), Some(100), None);
    let evs = diff_rows(&prev, &cur);
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].kind, "server.mem.pressure");
}

#[test]
fn diff_rows_mem_gradual_recovery_crosses_90_fires_info() {
    let prev = row(10, None, None, None, None, Some(8), Some(100), None);
    let cur = row(0, None, None, None, None, Some(11), Some(100), None);
    let evs = diff_rows(&prev, &cur);
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].kind, "server.mem.recovered");
    assert_eq!(evs[0].resolves, Some("server.mem.pressure"));
}

#[test]
fn diff_rows_singbox_log_crosses_500mib_fires() {
    let prev = row(
        10,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(400 * 1024 * 1024),
    );
    let cur = row(
        0,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(600 * 1024 * 1024),
    );
    let evs = diff_rows(&prev, &cur);
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].kind, "server.singbox.log.too_big");
}

#[test]
fn diff_rows_singbox_log_already_large_still_fires() {
    let prev = row(
        10,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(600 * 1024 * 1024),
    );
    let cur = row(
        0,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(700 * 1024 * 1024),
    );
    let evs = diff_rows(&prev, &cur);
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].kind, "server.singbox.log.too_big");
}

#[test]
fn diff_rows_singbox_log_rotation_fires_recovery() {
    let prev = row(
        10,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(600 * 1024 * 1024),
    );
    let cur = row(
        0,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(20 * 1024 * 1024),
    );
    let evs = diff_rows(&prev, &cur);
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].kind, "server.singbox.log.recovered");
    assert_eq!(
        evs[0].resolves,
        Some("server.singbox.log.too_big"),
        "log rotation must close the open too-big alert"
    );
}

#[test]
fn diff_rows_steady_small_log_emits_level_recovery() {
    let prev = row(
        10,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(100 * 1024 * 1024),
    );
    let cur = row(
        0,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(20 * 1024 * 1024),
    );
    let evs = diff_rows(&prev, &cur);
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].kind, "server.singbox.log.recovered");
    assert_eq!(evs[0].resolves, Some("server.singbox.log.too_big"));
}

#[test]
fn diff_rows_unknown_prior_emits_nothing() {
    let prev = row(10, None, None, None, None, None, None, None);
    let cur = row(0, Some(false), None, None, None, None, None, None);
    assert!(diff_rows(&prev, &cur).is_empty());
}

#[test]
fn diff_rows_multi_signal_combines() {
    let prev = row(10, Some(true), None, Some(80), Some(100), None, None, None);
    let cur = row(0, Some(false), None, Some(95), Some(100), None, None, None);
    let evs = diff_rows(&prev, &cur);
    let kinds: Vec<&str> = evs.iter().map(|e| e.kind).collect();
    assert!(kinds.contains(&"server.singbox.down"));
    assert!(kinds.contains(&"server.disk.pressure"));
}

#[test]
fn bytes_as_gib_formats_one_decimal() {
    assert_eq!(bytes_as_gib_text(2_147_483_648), "2.0 GiB");
    assert_eq!(bytes_as_gib_text(1_610_612_736), "1.5 GiB");
    assert_eq!(bytes_as_gib_text(0), "0.0 GiB");
}

async fn fresh_inv() -> (TempDir, SqliteInventory) {
    let dir = TempDir::new().unwrap();
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    (dir, inv)
}

fn user_with_id(id: &str) -> User {
    User {
        id: UserId(id.into()),
        uuid: format!("00000000-0000-0000-0000-{:012}", 7),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    }
}

fn probeable_server(id: &str) -> Server {
    Server {
        id: ServerId(id.into()),
        address: "127.0.0.1".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![vpnctl_core::KernelId("sing-box".into())],
        enabled_protocols: vec![],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

async fn record_singbox_health(inv: &SqliteInventory, server_id: &ServerId, active: bool) {
    inv.record_node_health(
        server_id,
        Some(active),
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
        None,
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;
}

#[tokio::test]
async fn scan_once_detects_service_down_before_extra_steady_samples() {
    let (_dir, inv) = fresh_inv().await;
    let server = probeable_server("extra-samples");
    inv.add_server(&server).await.unwrap();
    for active in [true, false, false, false] {
        record_singbox_health(&inv, &server.id, active).await;
    }

    scan_once(&inv).await.unwrap();
    let alerts = inv.recent_alerts(10, false).await.unwrap();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].kind, "server.singbox.down");
    assert_eq!(alerts[0].severity, "critical");

    scan_once(&inv).await.unwrap();
    assert_eq!(inv.recent_alerts(10, true).await.unwrap().len(), 1);
    record_singbox_health(&inv, &server.id, true).await;
    record_singbox_health(&inv, &server.id, true).await;
    scan_once(&inv).await.unwrap();
    assert!(inv.recent_alerts(10, false).await.unwrap().is_empty());
    assert_eq!(inv.recent_alerts(10, true).await.unwrap().len(), 2);
}

#[tokio::test]
async fn scan_once_dedupes_restart_source_after_inventory_reopen() {
    let (dir, inv) = fresh_inv().await;
    let server = probeable_server("restart-source");
    inv.add_server(&server).await.unwrap();
    for nrestarts in [2, 4] {
        inv.record_node_health(
            &server.id,
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
            Some(nrestarts),
        )
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    scan_once(&inv).await.unwrap();
    scan_once(&inv).await.unwrap();
    inv.close().await;

    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    scan_once(&inv).await.unwrap();
    let alerts = inv.recent_alerts(10, true).await.unwrap();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].kind, "server.singbox.restarted");
    assert!(alerts[0].acked_at.is_some());
    assert_eq!(
        inv.recent_audit(20)
            .await
            .unwrap()
            .iter()
            .filter(|a| a.action == "alert.fire")
            .count(),
        1,
        "a replay must not write an audit row"
    );
}

async fn record_singbox_log_health(inv: &SqliteInventory, server_id: &ServerId, bytes: u64) {
    inv.record_node_health(
        server_id,
        Some(true),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(bytes),
        None,
        None,
        None,
        None,
        None,
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;
}

#[tokio::test]
async fn scan_once_does_not_reopen_acknowledged_steady_large_log() {
    let (_dir, inv) = fresh_inv().await;
    let server = probeable_server("logs");
    inv.add_server(&server).await.unwrap();

    record_singbox_log_health(&inv, &server.id, 600 * 1024 * 1024).await;
    record_singbox_log_health(&inv, &server.id, 700 * 1024 * 1024).await;
    scan_once(&inv).await.unwrap();
    let alert = inv
        .recent_alerts(10, true)
        .await
        .unwrap()
        .into_iter()
        .find(|a| a.kind == "server.singbox.log.too_big")
        .expect("steady-high bootstrap must fire once");
    assert!(inv.ack_alert(alert.id).await.unwrap());

    record_singbox_log_health(&inv, &server.id, 800 * 1024 * 1024).await;
    scan_once(&inv).await.unwrap();
    assert_eq!(
        inv.recent_alerts(10, true).await.unwrap().len(),
        1,
        "the same high spell must stay acknowledged until recovery"
    );
}

#[tokio::test]
async fn scan_once_recovers_stranded_large_log_after_two_small_samples() {
    let (_dir, inv) = fresh_inv().await;
    let server = probeable_server("logs-race");
    inv.add_server(&server).await.unwrap();

    record_singbox_log_health(&inv, &server.id, 600 * 1024 * 1024).await;
    record_singbox_log_health(&inv, &server.id, 700 * 1024 * 1024).await;
    scan_once(&inv).await.unwrap();

    record_singbox_log_health(&inv, &server.id, 20 * 1024 * 1024).await;
    record_singbox_log_health(&inv, &server.id, 30 * 1024 * 1024).await;
    scan_once(&inv).await.unwrap();

    let history = inv.recent_alerts(10, true).await.unwrap();
    let condition = history
        .iter()
        .find(|a| a.kind == "server.singbox.log.too_big")
        .unwrap();
    assert!(condition.acked_at.is_some(), "the stale warning must close");
    assert_eq!(
        history
            .iter()
            .filter(|a| a.kind == "server.singbox.log.recovered")
            .count(),
        1
    );

    scan_once(&inv).await.unwrap();
    assert_eq!(
        inv.recent_alerts(10, true)
            .await
            .unwrap()
            .iter()
            .filter(|a| a.kind == "server.singbox.log.recovered")
            .count(),
        1,
        "level recovery must remain idempotent"
    );
}

#[tokio::test]
async fn scan_once_suppresses_orphan_small_log_recovery() {
    let (_dir, inv) = fresh_inv().await;
    let server = probeable_server("logs-orphan");
    inv.add_server(&server).await.unwrap();

    record_singbox_log_health(&inv, &server.id, 20 * 1024 * 1024).await;
    record_singbox_log_health(&inv, &server.id, 30 * 1024 * 1024).await;
    scan_once(&inv).await.unwrap();

    assert!(
        inv.recent_alerts(10, true).await.unwrap().is_empty(),
        "a healthy log with no warning history must stay quiet"
    );
}

#[tokio::test]
async fn scan_once_records_recovery_after_condition_is_manually_acknowledged() {
    let (_dir, inv) = fresh_inv().await;
    let server = probeable_server("srv");
    inv.add_server(&server).await.unwrap();

    record_singbox_health(&inv, &server.id, true).await;
    record_singbox_health(&inv, &server.id, false).await;
    scan_once(&inv).await.unwrap();
    let down = inv
        .recent_alerts(10, true)
        .await
        .unwrap()
        .into_iter()
        .find(|alert| alert.kind == "server.singbox.down")
        .unwrap();
    assert!(
        inv.ack_alert(down.id).await.unwrap(),
        "manual ack must change state"
    );

    record_singbox_health(&inv, &server.id, true).await;
    scan_once(&inv).await.unwrap();
    let history = inv.recent_alerts(10, true).await.unwrap();
    let recovery = history
        .iter()
        .find(|alert| alert.kind == "server.singbox.up")
        .unwrap_or_else(|| panic!("manual ack must not suppress recovery: {history:?}"));
    assert!(
        recovery.acked_at.is_some(),
        "recovery rows are historical only"
    );
    assert_eq!(history.len(), 2, "one condition and one recovery expected");

    scan_once(&inv).await.unwrap();
    assert_eq!(
        inv.recent_alerts(10, true).await.unwrap().len(),
        2,
        "a handled recovery must not repeat on a later scan"
    );
}

#[tokio::test]
async fn scan_once_skips_orphan_recovery_boundary_without_condition_history() {
    let (_dir, inv) = fresh_inv().await;
    let server = probeable_server("orphan");
    inv.add_server(&server).await.unwrap();

    record_singbox_health(&inv, &server.id, false).await;
    record_singbox_health(&inv, &server.id, true).await;
    scan_once(&inv).await.unwrap();
    assert!(
        inv.recent_alerts(10, true).await.unwrap().is_empty(),
        "an orphan recovery boundary must remain quiet"
    );
}

#[tokio::test]
async fn scan_once_fires_repeated_service_down_without_recovery_history() {
    let (_dir, inv) = fresh_inv().await;
    let server = probeable_server("srv-down-repeat");
    inv.add_server(&server).await.unwrap();

    record_singbox_health(&inv, &server.id, true).await;
    record_singbox_health(&inv, &server.id, false).await;
    scan_once(&inv).await.unwrap();
    let alerts = inv.recent_alerts(10, true).await.unwrap();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].kind, "server.singbox.down");
    assert!(inv.ack_alert(alerts[0].id).await.unwrap());

    record_singbox_health(&inv, &server.id, true).await;

    record_singbox_health(&inv, &server.id, false).await;
    scan_once(&inv).await.unwrap();
    let history = inv.recent_alerts(10, true).await.unwrap();
    let down_alerts: Vec<_> = history
        .iter()
        .filter(|a| a.kind == "server.singbox.down")
        .collect();
    assert_eq!(
        down_alerts.len(),
        2,
        "second outage must fire despite lack of recovery row"
    );
}

#[tokio::test]
async fn scan_once_fires_repeated_disk_pressure_without_recovery_history() {
    let (_dir, inv) = fresh_inv().await;
    let server = probeable_server("srv-disk-repeat");
    inv.add_server(&server).await.unwrap();

    inv.record_node_health(
        &server.id,
        Some(true),
        None,
        Some(80),
        Some(100),
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
    tokio::time::sleep(Duration::from_millis(10)).await;
    inv.record_node_health(
        &server.id,
        Some(true),
        None,
        Some(92),
        Some(100),
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
    tokio::time::sleep(Duration::from_millis(10)).await;
    scan_once(&inv).await.unwrap();

    let alerts = inv.recent_alerts(10, true).await.unwrap();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].kind, "server.disk.pressure");
    assert!(inv.ack_alert(alerts[0].id).await.unwrap());

    inv.record_node_health(
        &server.id,
        Some(true),
        None,
        Some(87),
        Some(100),
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
    tokio::time::sleep(Duration::from_millis(10)).await;

    inv.record_node_health(
        &server.id,
        Some(true),
        None,
        Some(95),
        Some(100),
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
    tokio::time::sleep(Duration::from_millis(10)).await;
    scan_once(&inv).await.unwrap();

    let history = inv.recent_alerts(10, true).await.unwrap();
    let disk_alerts: Vec<_> = history
        .iter()
        .filter(|a| a.kind == "server.disk.pressure")
        .collect();
    assert_eq!(
        disk_alerts.len(),
        2,
        "second disk pressure must fire without recovery row"
    );
}

#[tokio::test]
async fn scan_once_fires_restart_alert_with_prior_down_history() {
    let (_dir, inv) = fresh_inv().await;
    let server = probeable_server("srv-restart");
    inv.add_server(&server).await.unwrap();

    record_singbox_health(&inv, &server.id, true).await;
    record_singbox_health(&inv, &server.id, false).await;
    scan_once(&inv).await.unwrap();
    let alerts = inv.recent_alerts(10, true).await.unwrap();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].kind, "server.singbox.down");
    assert!(inv.ack_alert(alerts[0].id).await.unwrap());

    inv.record_node_health(
        &server.id,
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
        Some(2),
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;

    inv.record_node_health(
        &server.id,
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
        Some(4),
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;
    scan_once(&inv).await.unwrap();

    let history = inv.recent_alerts(10, true).await.unwrap();
    let restart_alert = history
        .iter()
        .find(|a| a.kind == "server.singbox.restarted")
        .expect("restart alert must fire even with prior down history");
    assert_eq!(restart_alert.severity, "warning");
    assert!(
        restart_alert.acked_at.is_some(),
        "a restart is a one-shot event and must not stay open"
    );
    assert_eq!(
        restart_alert
            .payload_json
            .as_deref()
            .map(|p| p.contains("\"active\":true")),
        Some(true)
    );

    tokio::time::sleep(Duration::from_millis(10)).await;
    inv.record_node_health(
        &server.id,
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
        Some(5),
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;
    scan_once(&inv).await.unwrap();
    let restarts = inv
        .recent_alerts(10, true)
        .await
        .unwrap()
        .into_iter()
        .filter(|a| a.kind == "server.singbox.restarted")
        .count();
    assert_eq!(restarts, 2, "the next crash must fire its own alert");
}

#[tokio::test]
async fn check_user_traffic_limits_skips_users_under_threshold() {
    let (_dir, inv) = fresh_inv().await;
    inv.add_user(&user_with_id("u")).await.unwrap();
    inv.set_user_traffic_limit(
        &UserId("u".into()),
        Some(100 * 1024 * 1024 * 1024),
        Some(80),
    )
    .await
    .unwrap();
    check_user_traffic_limits(&inv).await.unwrap();
    let alerts = inv.recent_alerts(10, true).await.unwrap();
    assert!(
        alerts.is_empty(),
        "user under threshold must not produce an alert; got {alerts:?}"
    );
}

#[tokio::test]
async fn check_user_traffic_limits_auto_recovers_when_usage_drops_below() {
    let (_dir, inv) = fresh_inv().await;
    inv.add_server(&vpnctl_core::Server {
        id: ServerId("dummy".into()),
        address: "127.0.0.1".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![vpnctl_core::KernelId("sing-box".into())],
        enabled_protocols: vec![],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();
    inv.add_user(&user_with_id("rocky")).await.unwrap();
    inv.set_user_traffic_limit(&UserId("rocky".into()), Some(100), Some(50))
        .await
        .unwrap();
    inv.record_vpn_stats(
        &ServerId("dummy".into()),
        &[vpnctl_inventory::VpnStatsDelta {
            user_id: Some(UserId("rocky".into())),
            upload_bytes: 50,
            download_bytes: 40,
            active_connections: 0,
        }],
    )
    .await
    .unwrap();
    check_user_traffic_limits(&inv).await.unwrap();
    let unacked_before: Vec<_> = inv
        .recent_alerts(10, true)
        .await
        .unwrap()
        .into_iter()
        .filter(|a| a.acked_at.is_none())
        .collect();
    assert_eq!(unacked_before.len(), 1, "tick 1 must fire one alert");

    inv.set_user_traffic_limit(&UserId("rocky".into()), Some(1_000_000), Some(50))
        .await
        .unwrap();
    check_user_traffic_limits(&inv).await.unwrap();
    let unacked_after: Vec<_> = inv
        .recent_alerts(10, true)
        .await
        .unwrap()
        .into_iter()
        .filter(|a| a.acked_at.is_none())
        .collect();
    assert!(
        unacked_after.is_empty(),
        "tick 2 must auto-ack the open alert; got: {unacked_after:?}"
    );
}

#[tokio::test]
async fn check_attribution_stall_fires_then_auto_recovers() {
    let (_dir, inv) = fresh_inv().await;
    let de = vpnctl_core::Server {
        id: ServerId("de".into()),
        address: "127.0.0.1".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![vpnctl_core::KernelId("sing-box".into())],
        enabled_protocols: vec![],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    };
    inv.add_server(&de).await.unwrap();
    inv.add_user(&user_with_id("alice")).await.unwrap();
    let servers = vec![de.clone()];

    inv.record_vpn_stats(
        &ServerId("de".into()),
        &[vpnctl_inventory::VpnStatsDelta {
            user_id: None,
            upload_bytes: 1000,
            download_bytes: 2000,
            active_connections: 10,
        }],
    )
    .await
    .unwrap();
    check_attribution_stall(&inv, &servers).await.unwrap();
    let fired: Vec<_> = inv
        .recent_alerts(10, true)
        .await
        .unwrap()
        .into_iter()
        .filter(|a| a.acked_at.is_none() && a.kind == "server.attribution.stalled")
        .collect();
    assert_eq!(
        fired.len(),
        1,
        "tick 1: a node with conns but 0 attributed users must fire exactly one stall alert; got {fired:?}"
    );

    inv.record_vpn_stats(
        &ServerId("de".into()),
        &[vpnctl_inventory::VpnStatsDelta {
            user_id: Some(UserId("alice".into())),
            upload_bytes: 10,
            download_bytes: 20,
            active_connections: 3,
        }],
    )
    .await
    .unwrap();
    check_attribution_stall(&inv, &servers).await.unwrap();
    let still_open: Vec<_> = inv
        .recent_alerts(10, true)
        .await
        .unwrap()
        .into_iter()
        .filter(|a| a.acked_at.is_none() && a.kind == "server.attribution.stalled")
        .collect();
    assert!(
        still_open.is_empty(),
        "tick 2: attribution resumed → the open stall alert must auto-ack; got {still_open:?}"
    );
}

#[tokio::test]
async fn check_sub_fetch_without_traffic_resolves_stale_open_alert() {
    let (_dir, inv) = fresh_inv().await;
    inv.insert_alert_if_no_unacked("user.sub_no_traffic:ghost", None, "warning", "stale", None)
        .await
        .unwrap();
    let open_before = inv
        .recent_alerts(10, true)
        .await
        .unwrap()
        .into_iter()
        .filter(|a| a.acked_at.is_none() && a.kind == "user.sub_no_traffic:ghost")
        .count();
    assert_eq!(open_before, 1, "alert is open before the sweep");

    check_sub_fetch_without_traffic(&inv).await.unwrap();

    let open_after = inv
        .recent_alerts(10, true)
        .await
        .unwrap()
        .into_iter()
        .filter(|a| a.acked_at.is_none() && a.kind == "user.sub_no_traffic:ghost")
        .count();
    assert_eq!(
        open_after, 0,
        "a stale open sub-stall alert must auto-resolve when its user is no longer in violation"
    );
}

#[test]
fn pin_is_present_true_when_pinned_ed25519_among_served_keys() {
    let pinned = "SHA256:Jl4XlKj9/e2igS3EoZmKshf5x6UqkWRjqoEavJaizp4";
    let served = vec![
        "SHA256:szQm1QS8dN6awI29eG1hLbKah/156RmJV1EpNFqlNwc".to_string(),
        "SHA256:Jl4XlKj9/e2igS3EoZmKshf5x6UqkWRjqoEavJaizp4".to_string(),
    ];
    assert!(pin_is_present(pinned, &served));
}

#[test]
fn pin_is_present_false_when_pinned_key_absent_from_partial_scan() {
    let pinned = "SHA256:Jl4XlKj9/e2igS3EoZmKshf5x6UqkWRjqoEavJaizp4";
    let served = vec!["SHA256:szQm1QS8dN6awI29eG1hLbKah/156RmJV1EpNFqlNwc".to_string()];
    assert!(!pin_is_present(pinned, &served));
}

#[test]
fn pin_is_present_false_on_empty_served_set() {
    assert!(!pin_is_present("SHA256:whatever", &[]));
}

#[test]
fn pin_is_present_true_on_genuine_single_key_match() {
    let pinned = "SHA256:Jl4XlKj9/e2igS3EoZmKshf5x6UqkWRjqoEavJaizp4";
    let served = vec![pinned.to_string()];
    assert!(pin_is_present(pinned, &served));
}

#[test]
fn pin_is_present_accepts_equivalent_variants() {
    let canonical = "SHA256:Jl4XlKj9/e2igS3EoZmKshf5x6UqkWRjqoEavJaizp4";
    let padded = "SHA256:Jl4XlKj9/e2igS3EoZmKshf5x6UqkWRjqoEavJaizp4=";
    let url_safe = "SHA256:Jl4XlKj9_e2igS3EoZmKshf5x6UqkWRjqoEavJaizp4";
    let url_safe_padded = "SHA256:Jl4XlKj9_e2igS3EoZmKshf5x6UqkWRjqoEavJaizp4=";

    assert!(pin_is_present(canonical, &[padded.to_string()]));
    assert!(pin_is_present(canonical, &[url_safe.to_string()]));
    assert!(pin_is_present(canonical, &[url_safe_padded.to_string()]));

    assert!(pin_is_present(padded, &[canonical.to_string()]));
    assert!(pin_is_present(padded, &[url_safe.to_string()]));

    assert!(pin_is_present(url_safe, &[canonical.to_string()]));
    assert!(pin_is_present(url_safe_padded, &[canonical.to_string()]));
}

#[test]
fn pin_is_present_rejects_real_mismatch_even_with_variants() {
    let pin_a = "SHA256:Jl4XlKj9/e2igS3EoZmKshf5x6UqkWRjqoEavJaizp4";
    let served_b_canonical = "SHA256:szQm1QS8dN6awI29eG1hLbKah/156RmJV1EpNFqlNwc";
    let served_b_padded = "SHA256:szQm1QS8dN6awI29eG1hLbKah/156RmJV1EpNFqlNwc=";
    let served_b_url_safe = "SHA256:szQm1QS8dN6awI29eG1hLbKah_156RmJV1EpNFqlNwc";

    assert!(!pin_is_present(pin_a, &[served_b_canonical.to_string()]));
    assert!(!pin_is_present(pin_a, &[served_b_padded.to_string()]));
    assert!(!pin_is_present(pin_a, &[served_b_url_safe.to_string()]));
}

#[test]
fn pin_is_present_rejects_malformed_fingerprints() {
    let valid = "SHA256:Jl4XlKj9/e2igS3EoZmKshf5x6UqkWRjqoEavJaizp4";
    assert!(!pin_is_present(valid, &["not-a-fingerprint".to_string()]));
    assert!(!pin_is_present("not-a-fingerprint", &[valid.to_string()]));
    assert!(!pin_is_present(valid, &["MD5:aa:bb:cc".to_string()]));
    assert!(!pin_is_present("MD5:aa:bb:cc", &[valid.to_string()]));
}

#[test]
fn decide_drift_matched_when_a_later_scan_returns_the_pin() {
    let pinned = "SHA256:Jl4XlKj9/e2igS3EoZmKshf5x6UqkWRjqoEavJaizp4";
    let attempts = vec![
        Some(vec![
            "SHA256:szQm1QS8dN6awI29eG1hLbKah/156RmJV1EpNFqlNwc".to_string(),
        ]),
        Some(vec![
            "SHA256:szQm1QS8dN6awI29eG1hLbKah/156RmJV1EpNFqlNwc".to_string(),
            pinned.to_string(),
        ]),
    ];
    assert_eq!(decide_drift(pinned, &attempts), DriftDecision::Matched);
}

#[test]
fn decide_drift_inconclusive_when_every_scan_failed() {
    let attempts: Vec<Option<Vec<String>>> = vec![None, None, None];
    assert_eq!(
        decide_drift("SHA256:whatever", &attempts),
        DriftDecision::Inconclusive
    );
}

#[test]
fn decide_drift_matched_when_observed_contains_padded_equivalent() {
    let pinned = "SHA256:Jl4XlKj9/e2igS3EoZmKshf5x6UqkWRjqoEavJaizp4";
    let padded = "SHA256:Jl4XlKj9/e2igS3EoZmKshf5x6UqkWRjqoEavJaizp4=";
    let attempts = vec![Some(vec![padded.to_string()])];
    assert_eq!(decide_drift(pinned, &attempts), DriftDecision::Matched);
}

#[test]
fn decide_drift_matched_when_observed_contains_url_safe_equivalent() {
    let pinned = "SHA256:Jl4XlKj9/e2igS3EoZmKshf5x6UqkWRjqoEavJaizp4";
    let url_safe = "SHA256:Jl4XlKj9_e2igS3EoZmKshf5x6UqkWRjqoEavJaizp4";
    let attempts = vec![Some(vec![url_safe.to_string()])];
    assert_eq!(decide_drift(pinned, &attempts), DriftDecision::Matched);
}

#[test]
fn decide_drift_matched_when_pinned_is_url_safe_and_observed_is_canonical() {
    let pinned = "SHA256:Jl4XlKj9_e2igS3EoZmKshf5x6UqkWRjqoEavJaizp4=";
    let canonical = "SHA256:Jl4XlKj9/e2igS3EoZmKshf5x6UqkWRjqoEavJaizp4";
    let attempts = vec![Some(vec![canonical.to_string()])];
    assert_eq!(decide_drift(pinned, &attempts), DriftDecision::Matched);
}

#[test]
fn decide_drift_unions_observed_keys_deduplicating_equivalent_variants() {
    let pinned = "SHA256:OLDoldOLDoldOLDoldOLDoldOLDoldOLDoldOLDoldOL";
    let new_canonical = "SHA256:Jl4XlKj9/e2igS3EoZmKshf5x6UqkWRjqoEavJaizp4";
    let new_padded = "SHA256:Jl4XlKj9/e2igS3EoZmKshf5x6UqkWRjqoEavJaizp4=";
    let new_url_safe = "SHA256:Jl4XlKj9_e2igS3EoZmKshf5x6UqkWRjqoEavJaizp4";
    let attempts = vec![
        Some(vec![new_canonical.to_string()]),
        Some(vec![new_padded.to_string(), new_url_safe.to_string()]),
    ];
    assert_eq!(
        decide_drift(pinned, &attempts),
        DriftDecision::Drift {
            observed: vec![new_canonical.to_string()]
        }
    );
}

#[test]
fn decide_drift_fires_when_pin_absent_from_every_successful_scan() {
    let pinned = "SHA256:OLDoldOLDoldOLDoldOLDoldOLDoldOLDoldOLDoldOL";
    let newkey = "SHA256:NEWnewNEWnewNEWnewNEWnewNEWnewNEWnewNEWnewNE";
    let attempts = vec![
        Some(vec![newkey.to_string()]),
        None,
        Some(vec![newkey.to_string()]),
    ];
    assert_eq!(
        decide_drift(pinned, &attempts),
        DriftDecision::Drift {
            observed: vec![newkey.to_string()]
        }
    );
}

#[test]
fn decide_drift_unions_observed_keys_across_scans_without_dupes() {
    let pinned = "SHA256:PINpinPINpinPINpinPINpinPINpinPINpinPINpinPI";
    let attempts = vec![
        Some(vec!["SHA256:aaa".to_string(), "SHA256:bbb".to_string()]),
        Some(vec!["SHA256:bbb".to_string(), "SHA256:ccc".to_string()]),
    ];
    assert_eq!(
        decide_drift(pinned, &attempts),
        DriftDecision::Drift {
            observed: vec![
                "SHA256:aaa".to_string(),
                "SHA256:bbb".to_string(),
                "SHA256:ccc".to_string()
            ]
        }
    );
}

#[tokio::test]
async fn check_fingerprint_drift_skips_servers_without_pin() {
    let (_dir, inv) = fresh_inv().await;
    let s = vpnctl_core::Server {
        id: ServerId("no-pin".into()),
        address: "192.0.2.99".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![vpnctl_core::KernelId("sing-box".into())],
        enabled_protocols: vec![],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    };
    inv.add_server(&s).await.unwrap();
    let servers = vec![s];
    check_fingerprint_drift(&inv, &servers).await.unwrap();
    let alerts = inv.recent_alerts(10, true).await.unwrap();
    assert!(
        alerts.is_empty(),
        "no pin → no drift check → no alert; got: {alerts:?}"
    );
}

#[tokio::test]
async fn check_fingerprint_drift_skips_jump_targets() {
    let (_dir, inv) = fresh_inv().await;
    let s = vpnctl_core::Server {
        id: ServerId("jumper".into()),
        address: "192.0.2.99".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![vpnctl_core::KernelId("sing-box".into())],
        enabled_protocols: vec![],
        trusted_host_fingerprint: Some("SHA256:abcdefghij".into()),
        hoster: "generic".into(),
        jump_via: Some(ServerId("bastion".into())),
        usage_coefficient: 1.0,
    };
    let servers = vec![s];
    check_fingerprint_drift(&inv, &servers).await.unwrap();
    let alerts = inv.recent_alerts(10, true).await.unwrap();
    assert!(
        alerts.is_empty(),
        "jump-via target must be skipped; got: {alerts:?}"
    );
}

#[tokio::test]
async fn fingerprint_drift_recovery_acks_open_alert_for_same_kind_and_server() {
    let (_dir, inv) = fresh_inv().await;
    inv.add_server(&vpnctl_core::Server {
        id: ServerId("srv".into()),
        address: "203.0.113.10".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![vpnctl_core::KernelId("sing-box".into())],
        enabled_protocols: vec![],
        trusted_host_fingerprint: Some("SHA256:original".into()),
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();
    let kind = "server.fingerprint.drift:srv";
    let opened = inv
        .insert_alert_if_no_unacked(
            kind,
            Some(&ServerId("srv".into())),
            "warning",
            "drift",
            None,
        )
        .await
        .unwrap();
    assert!(opened.is_some(), "seed must insert one open alert");
    let acked = inv
        .ack_open_alerts(kind, Some(&ServerId("srv".into())))
        .await
        .unwrap();
    assert_eq!(acked, 1, "recovery must ack exactly the one open alert");
    let acked_again = inv
        .ack_open_alerts(kind, Some(&ServerId("srv".into())))
        .await
        .unwrap();
    assert_eq!(acked_again, 0, "second ack must be no-op");
}

#[tokio::test]
async fn check_user_traffic_limits_fires_once_per_condition() {
    let (_dir, inv) = fresh_inv().await;
    inv.add_server(&vpnctl_core::Server {
        id: ServerId("dummy".into()),
        address: "127.0.0.1".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![vpnctl_core::KernelId("sing-box".into())],
        enabled_protocols: vec![],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();
    inv.add_user(&user_with_id("heavy")).await.unwrap();
    inv.set_user_traffic_limit(&UserId("heavy".into()), Some(100), Some(50))
        .await
        .unwrap();
    inv.record_vpn_stats(
        &ServerId("dummy".into()),
        &[vpnctl_inventory::VpnStatsDelta {
            user_id: Some(UserId("heavy".into())),
            upload_bytes: 50,
            download_bytes: 40,
            active_connections: 0,
        }],
    )
    .await
    .unwrap();
    check_user_traffic_limits(&inv).await.unwrap();
    let alerts1 = inv.recent_alerts(10, true).await.unwrap();
    assert_eq!(alerts1.len(), 1, "must fire one alert on threshold cross");
    assert_eq!(alerts1[0].kind, "user.traffic_limit:heavy");
    assert_eq!(alerts1[0].severity, "warning");
    check_user_traffic_limits(&inv).await.unwrap();
    let alerts2 = inv.recent_alerts(10, true).await.unwrap();
    assert_eq!(
        alerts2.len(),
        1,
        "second scan must not fire duplicate alert; got {alerts2:?}"
    );
}

#[test]
fn remediation_plan_is_fixed_and_only_covers_approved_conditions() {
    assert_eq!(
        Remediation::for_kind("server.singbox.down"),
        Some(Remediation::RestartSingbox)
    );
    assert_eq!(
        Remediation::for_kind("server.fail2ban.down"),
        Some(Remediation::StartFail2ban)
    );
    assert_eq!(
        Remediation::for_kind("server.disk.pressure"),
        Some(Remediation::CleanDisk)
    );
    assert_eq!(
        Remediation::for_kind("server.singbox.log.too_big"),
        Some(Remediation::RotateSingboxLog)
    );
    assert_eq!(Remediation::for_kind("server.mem.pressure"), None);

    let disk = Remediation::CleanDisk.command();
    assert!(disk.contains("logrotate -f /etc/logrotate.d/sing-box"));
    assert!(disk.contains("journalctl --vacuum-time=14d"));
    assert!(disk.contains("apt-get clean"));
    assert!(disk.contains(r#"[ "$pct" -lt 85 ]"#));
    assert!(!disk.contains("rm -"));
}

#[test]
fn remediation_requires_a_verified_healthy_probe() {
    let mut probe = crate::node_probe::Probe {
        sing_box_active: Some(true),
        fail2ban_active: Some(true),
        disk_used_mib: Some(84),
        disk_total_mib: Some(100),
        sing_box_log_bytes: Some(SINGBOX_LOG_TRIGGER_BYTES - 1),
        ..Default::default()
    };
    assert!(Remediation::RestartSingbox.verified_by(&probe));
    assert!(Remediation::StartFail2ban.verified_by(&probe));
    assert!(Remediation::CleanDisk.verified_by(&probe));
    assert!(Remediation::RotateSingboxLog.verified_by(&probe));

    probe.sing_box_active = Some(false);
    probe.fail2ban_active = None;
    probe.disk_used_mib = Some(85);
    probe.sing_box_log_bytes = Some(SINGBOX_LOG_TRIGGER_BYTES);
    assert!(!Remediation::RestartSingbox.verified_by(&probe));
    assert!(!Remediation::StartFail2ban.verified_by(&probe));
    assert!(!Remediation::CleanDisk.verified_by(&probe));
    assert!(!Remediation::RotateSingboxLog.verified_by(&probe));
}

#[tokio::test]
async fn scan_retries_busy_remediation_without_duplicate_alerts() {
    let (_dir, inv) = fresh_inv().await;
    let server = probeable_server("remediation-retry");
    inv.add_server(&server).await.unwrap();
    record_singbox_health(&inv, &server.id, true).await;
    record_singbox_health(&inv, &server.id, false).await;
    let held = crate::wizard_bootstrap::DeployGuard::try_acquire(&server.id.0).unwrap();
    let mut attempts = std::collections::HashMap::new();

    scan_once_inner(&inv, true, &mut attempts).await.unwrap();
    let alerts = inv.recent_alerts(10, false).await.unwrap();
    assert_eq!(alerts.len(), 1);
    let alert_id = alerts[0].id;
    let first_attempt = attempts[&alert_id];

    scan_once_inner(&inv, true, &mut attempts).await.unwrap();
    assert_eq!(attempts[&alert_id], first_attempt, "retry is rate limited");

    let expired = std::time::Instant::now() - REMEDIATION_RETRY_INTERVAL;
    attempts.insert(alert_id, expired);
    // Retry even after the original transition leaves retained history.
    inv.purge_node_health_older_than(0).await.unwrap();
    record_singbox_health(&inv, &server.id, false).await;
    scan_once_inner(&inv, true, &mut attempts).await.unwrap();
    assert!(attempts[&alert_id] > expired, "open alert must be retried");
    assert_eq!(inv.recent_alerts(10, true).await.unwrap().len(), 1);
    let audit = inv.recent_audit(20).await.unwrap();
    assert_eq!(audit.iter().filter(|a| a.action == "alert.fire").count(), 1);
    assert!(!audit.iter().any(|a| a.action == "server.auto_remediate"));

    drop(held);
    let prepared = prepare_remediation(&inv, &server.id, Remediation::RestartSingbox).await;
    assert!(
        prepared.is_some(),
        "released node lock must allow remediation"
    );
    drop(prepared);
    record_singbox_health(&inv, &server.id, true).await;
    attempts.insert(alert_id, expired);
    scan_once_inner(&inv, true, &mut attempts).await.unwrap();
    assert_eq!(inv.unacked_alert_count().await.unwrap(), 0);
    assert!(
        !inv.recent_audit(20)
            .await
            .unwrap()
            .iter()
            .any(|a| a.action == "server.auto_remediate"),
        "recovered health must prevent a stale remote action"
    );
}

#[tokio::test]
async fn remediation_skips_a_busy_node_without_waiting() {
    let (_dir, inv) = fresh_inv().await;
    let server = probeable_server("remediation-busy");
    inv.add_server(&server).await.unwrap();
    record_singbox_health(&inv, &server.id, false).await;
    let held = crate::wizard_bootstrap::DeployGuard::try_acquire(&server.id.0).unwrap();

    assert!(
        prepare_remediation(&inv, &server.id, Remediation::RestartSingbox)
            .await
            .is_none()
    );
    let result = tokio::time::timeout(
        Duration::from_millis(100),
        auto_remediate_alert(
            &inv,
            &server,
            1,
            "server.singbox.down",
            Remediation::RestartSingbox,
            "test server",
        ),
    )
    .await
    .expect("busy remediation must not wait for the deploy lock");
    assert!(!result);
    drop(held);
    let _cli_lock = vpnctl_inventory::NodeOperationLock::try_acquire(&server.id.0)
        .unwrap()
        .unwrap();
    assert!(
        prepare_remediation(&inv, &server.id, Remediation::RestartSingbox)
            .await
            .is_none()
    );
    assert!(inv.recent_audit(10).await.unwrap().is_empty());
}

#[tokio::test]
async fn remediation_rechecks_disabled_kernel_after_deploy() {
    let (_dir, inv) = fresh_inv().await;
    let stale_server = probeable_server("remediation-disabled");
    inv.add_server(&stale_server).await.unwrap();
    record_singbox_health(&inv, &stale_server.id, false).await;
    let held = crate::wizard_bootstrap::DeployGuard::try_acquire(&stale_server.id.0).unwrap();
    inv.remove_server_kernel(&stale_server.id, &vpnctl_core::KernelId("sing-box".into()))
        .await
        .unwrap();
    // Another enabled kernel must not make sing-box eligible for a restart.
    inv.add_server_kernel(&stale_server.id, &vpnctl_core::KernelId("xray".into()))
        .await
        .unwrap();
    drop(held);

    assert!(
        prepare_remediation(&inv, &stale_server.id, Remediation::RestartSingbox)
            .await
            .is_none()
    );
    assert!(
        !auto_remediate_alert(
            &inv,
            &stale_server,
            1,
            "server.singbox.down",
            Remediation::RestartSingbox,
            "test server",
        )
        .await
    );
    assert!(inv.recent_audit(10).await.unwrap().is_empty());
    assert!(crate::wizard_bootstrap::DeployGuard::try_acquire(&stale_server.id.0).is_some());
}

#[tokio::test]
async fn remediation_rechecks_recovered_condition_after_deploy() {
    let (_dir, inv) = fresh_inv().await;
    let server = probeable_server("remediation-recovered");
    inv.add_server(&server).await.unwrap();
    record_singbox_health(&inv, &server.id, false).await;
    let held = crate::wizard_bootstrap::DeployGuard::try_acquire(&server.id.0).unwrap();
    record_singbox_health(&inv, &server.id, true).await;
    drop(held);

    assert!(
        prepare_remediation(&inv, &server.id, Remediation::RestartSingbox)
            .await
            .is_none()
    );
    assert!(
        !auto_remediate_alert(
            &inv,
            &server,
            1,
            "server.singbox.down",
            Remediation::RestartSingbox,
            "test server",
        )
        .await
    );
    assert!(inv.recent_audit(10).await.unwrap().is_empty());
}

#[tokio::test]
async fn remediation_skips_unknown_health() {
    let (_dir, inv) = fresh_inv().await;
    let server = probeable_server("remediation-unknown");
    inv.add_server(&server).await.unwrap();
    assert!(
        prepare_remediation(&inv, &server.id, Remediation::RestartSingbox)
            .await
            .is_none()
    );
    assert!(inv.recent_audit(10).await.unwrap().is_empty());
}

#[test]
fn remediation_checks_current_condition_thresholds() {
    let mut current = row(
        0,
        Some(false),
        Some(false),
        Some(90),
        Some(100),
        None,
        None,
        Some(SINGBOX_LOG_TRIGGER_BYTES),
    );
    for plan in [
        Remediation::RestartSingbox,
        Remediation::StartFail2ban,
        Remediation::CleanDisk,
        Remediation::RotateSingboxLog,
    ] {
        assert!(plan.condition_holds(&current));
    }
    current.sing_box_active = Some(true);
    current.fail2ban_active = None;
    current.disk_used_mib = Some(89);
    current.sing_box_log_bytes = Some(SINGBOX_LOG_TRIGGER_BYTES - 1);
    for plan in [
        Remediation::RestartSingbox,
        Remediation::StartFail2ban,
        Remediation::CleanDisk,
        Remediation::RotateSingboxLog,
    ] {
        assert!(!plan.condition_holds(&current));
    }
}

#[tokio::test]
async fn remediation_holds_deploy_guard_and_uses_current_server() {
    let (_dir, inv) = fresh_inv().await;
    let server = probeable_server("remediation-current");
    inv.add_server(&server).await.unwrap();
    record_singbox_health(&inv, &server.id, false).await;
    inv.update_server_address(&server.id, "192.0.2.42", 2222, "admin")
        .await
        .unwrap();

    let (guard, current) = prepare_remediation(&inv, &server.id, Remediation::RestartSingbox)
        .await
        .expect("enabled kernel with a current failure is eligible");
    assert_eq!(current.address, "192.0.2.42");
    assert_eq!(current.ssh_port, 2222);
    assert_eq!(current.ssh_user, "admin");
    assert!(crate::wizard_bootstrap::DeployGuard::try_acquire(&server.id.0).is_none());
    assert!(
        vpnctl_inventory::NodeOperationLock::try_acquire(&server.id.0)
            .unwrap()
            .is_none()
    );
    drop(guard);
    assert!(crate::wizard_bootstrap::DeployGuard::try_acquire(&server.id.0).is_some());
}

#[tokio::test]
async fn scan_once_ack_then_rescan_identical_pair_does_not_reopen() {
    let (_dir, inv) = fresh_inv().await;
    let server = probeable_server("srv-ack-rescan");
    inv.add_server(&server).await.unwrap();

    record_singbox_health(&inv, &server.id, true).await;
    record_singbox_health(&inv, &server.id, false).await;

    scan_once(&inv).await.unwrap();
    let unacked = inv.recent_alerts(10, false).await.unwrap();
    assert_eq!(unacked.len(), 1);
    assert_eq!(unacked[0].kind, "server.singbox.down");

    let payload: serde_json::Value =
        serde_json::from_str(unacked[0].payload_json.as_deref().unwrap()).unwrap();
    let src_ev = payload
        .get("_source_event")
        .and_then(|v| v.as_str())
        .expect("alert payload must carry _source_event string");
    let parts: Vec<&str> = src_ev.split(':').collect();
    assert_eq!(parts.len(), 2);
    assert!(!parts[0].is_empty());
    assert!(!parts[1].is_empty());
    assert_ne!(parts[0], parts[1]);

    assert!(inv.ack_alert(unacked[0].id).await.unwrap());
    assert_eq!(inv.unacked_alert_count().await.unwrap(), 0);

    scan_once(&inv).await.unwrap();
    assert_eq!(
        inv.unacked_alert_count().await.unwrap(),
        0,
        "rescan of identical sample pair must not reopen acknowledged alert"
    );
    let all_alerts = inv.recent_alerts(10, true).await.unwrap();
    assert_eq!(
        all_alerts.len(),
        1,
        "history must retain only the single acknowledged alert"
    );
}

#[tokio::test]
async fn scan_once_new_recovery_down_pair_reopens_alert() {
    let (_dir, inv) = fresh_inv().await;
    let server = probeable_server("srv-reopen-pair");
    inv.add_server(&server).await.unwrap();

    record_singbox_health(&inv, &server.id, true).await;
    record_singbox_health(&inv, &server.id, false).await;
    scan_once(&inv).await.unwrap();

    let alerts = inv.recent_alerts(10, false).await.unwrap();
    assert_eq!(alerts.len(), 1);
    let first_payload: serde_json::Value =
        serde_json::from_str(alerts[0].payload_json.as_deref().unwrap()).unwrap();
    let first_src_ev = first_payload["_source_event"].as_str().unwrap().to_string();
    assert!(inv.ack_alert(alerts[0].id).await.unwrap());

    record_singbox_health(&inv, &server.id, true).await;
    scan_once(&inv).await.unwrap();

    record_singbox_health(&inv, &server.id, false).await;
    scan_once(&inv).await.unwrap();

    let unacked = inv.recent_alerts(10, false).await.unwrap();
    assert_eq!(
        unacked.len(),
        1,
        "new outage pair must reopen an unacked alert"
    );
    assert_eq!(unacked[0].kind, "server.singbox.down");
    let second_payload: serde_json::Value =
        serde_json::from_str(unacked[0].payload_json.as_deref().unwrap()).unwrap();
    let second_src_ev = second_payload["_source_event"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(
        first_src_ev, second_src_ev,
        "distinct sample transitions must have distinct _source_event"
    );

    let history = inv.recent_alerts(10, true).await.unwrap();
    let down_alerts: Vec<_> = history
        .iter()
        .filter(|a| a.kind == "server.singbox.down")
        .collect();
    assert_eq!(
        down_alerts.len(),
        2,
        "history must have both distinct down alerts"
    );
    assert_ne!(down_alerts[0].id, down_alerts[1].id);
}

#[test]
fn one_shot_push_cooldown_counts_from_last_push_not_last_event() {
    use super::poller::claim_one_shot_push;
    let map = std::sync::Mutex::new(std::collections::HashMap::new());
    let t0 = chrono::Utc::now();
    let at = |mins: i64| t0 + chrono::Duration::minutes(mins);
    assert!(
        claim_one_shot_push(&map, "srv\0k", at(0)),
        "first crash pushes"
    );
    assert!(
        !claim_one_shot_push(&map, "srv\0k", at(10)),
        "crash inside window is throttled"
    );
    assert!(
        !claim_one_shot_push(&map, "srv\0k", at(20)),
        "still throttled"
    );
    assert!(
        claim_one_shot_push(&map, "srv\0k", at(31)),
        "a crash loop pushes again once the window since the last PUSH expires"
    );
    assert!(
        claim_one_shot_push(&map, "other\0k", at(31)),
        "servers are independent"
    );
}
