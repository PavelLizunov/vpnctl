#![allow(clippy::unwrap_used)]

use std::collections::BTreeSet;

use vpnctl_core::ServerId;
use vpnctl_inventory::SqliteInventory;

use super::*;

#[tokio::test]
async fn purge_old_on_empty_inv_returns_zero() {
    let tmp = tempfile::tempdir().unwrap();
    let inv = SqliteInventory::open(&tmp.path().join("inv.db"))
        .await
        .unwrap();
    let dropped = purge_old(&inv, 30).await.unwrap();
    assert_eq!(dropped, 0);
}

fn sid(s: &str) -> ServerId {
    ServerId(s.into())
}

fn ok_probe() -> ProbeOutcome {
    ProbeOutcome::Ok(crate::node_probe::Probe::default())
}
fn ssh_fail() -> ProbeOutcome {
    ProbeOutcome::SshFailed("boom".into())
}

#[tokio::test]
async fn unreachable_alert_recovers_with_fresh_fail_state() {
    let tmp = tempfile::tempdir().unwrap();
    let inv = SqliteInventory::open(&tmp.path().join("inv.db"))
        .await
        .unwrap();
    let server = vpnctl_core::Server {
        id: sid("restart-recovery"),
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
    inv.add_server(&server).await.unwrap();
    dispatch_alerts(
        &inv,
        &server,
        &ssh_fail(),
        &mut FailState::with_threshold(1),
    )
    .await;
    assert!(
        inv.has_unacked_alert("server.unreachable", Some(&server.id))
            .await
            .unwrap()
    );

    let mut restarted = FailState::with_threshold(1);
    dispatch_alerts(&inv, &server, &ok_probe(), &mut restarted).await;
    dispatch_alerts(&inv, &server, &ok_probe(), &mut restarted).await;

    assert!(
        !inv.has_unacked_alert("server.unreachable", Some(&server.id))
            .await
            .unwrap()
    );
    let audit = inv.recent_audit(20).await.unwrap();
    assert_eq!(
        audit
            .iter()
            .filter(|a| a.action == "alert.auto_ack")
            .count(),
        1
    );
    assert_eq!(inv.recent_alerts(10, true).await.unwrap().len(), 1);
}

#[test]
fn fail_state_below_threshold_emits_no_change() {
    let mut st = FailState::with_threshold(3);
    assert_eq!(
        st.observe(&sid("a"), &ssh_fail()),
        UnreachableTransition::NoChange
    );
    assert_eq!(
        st.observe(&sid("a"), &ssh_fail()),
        UnreachableTransition::NoChange,
        "still below threshold"
    );
}

#[test]
fn fail_state_at_threshold_emits_became_unreachable_once() {
    let mut st = FailState::with_threshold(3);
    st.observe(&sid("a"), &ssh_fail());
    st.observe(&sid("a"), &ssh_fail());
    let third = st.observe(&sid("a"), &ssh_fail());
    assert_eq!(
        third,
        UnreachableTransition::BecameUnreachable {
            consecutive_failures: 3,
            threshold: 3,
        }
    );
    assert_eq!(
        st.observe(&sid("a"), &ssh_fail()),
        UnreachableTransition::StillUnreachable {
            consecutive_failures: 4,
            threshold: 3,
        },
        "already-fired + still-failing must emit StillUnreachable, not BecameUnreachable"
    );
}

#[test]
fn fail_state_recovers_after_fire() {
    let mut st = FailState::with_threshold(2);
    st.observe(&sid("a"), &ssh_fail());
    st.observe(&sid("a"), &ssh_fail());
    assert_eq!(
        st.observe(&sid("a"), &ok_probe()),
        UnreachableTransition::Recovered
    );
    assert_eq!(
        st.observe(&sid("a"), &ok_probe()),
        UnreachableTransition::NoChange
    );
}

#[test]
fn fail_state_subthreshold_recovery_does_not_fire_or_ack() {
    let mut st = FailState::with_threshold(3);
    st.observe(&sid("a"), &ssh_fail());
    assert_eq!(
        st.observe(&sid("a"), &ok_probe()),
        UnreachableTransition::NoChange
    );
}

#[test]
fn fail_state_isolates_per_server() {
    let mut st = FailState::with_threshold(2);
    st.observe(&sid("a"), &ssh_fail());
    assert_eq!(
        st.observe(&sid("a"), &ssh_fail()),
        UnreachableTransition::BecameUnreachable {
            consecutive_failures: 2,
            threshold: 2,
        }
    );
    assert_eq!(
        st.observe(&sid("b"), &ssh_fail()),
        UnreachableTransition::NoChange
    );
    assert_eq!(
        st.observe(&sid("b"), &ok_probe()),
        UnreachableTransition::NoChange
    );
}

#[test]
fn fail_state_skipped_and_no_key_do_not_count() {
    let mut st = FailState::with_threshold(2);
    st.observe(&sid("a"), &ssh_fail());
    assert_eq!(
        st.observe(&sid("a"), &ProbeOutcome::Skipped),
        UnreachableTransition::NoChange
    );
    assert_eq!(
        st.observe(&sid("a"), &ProbeOutcome::NoDeployKey),
        UnreachableTransition::NoChange
    );
    assert_eq!(
        st.observe(&sid("a"), &ssh_fail()),
        UnreachableTransition::BecameUnreachable {
            consecutive_failures: 2,
            threshold: 2,
        }
    );
}

#[test]
fn fail_state_full_fire_recover_refire_cycle() {
    let mut st = FailState::with_threshold(2);
    st.observe(&sid("a"), &ssh_fail());
    assert!(matches!(
        st.observe(&sid("a"), &ssh_fail()),
        UnreachableTransition::BecameUnreachable { .. }
    ));
    assert_eq!(
        st.observe(&sid("a"), &ok_probe()),
        UnreachableTransition::Recovered
    );
    st.observe(&sid("a"), &ssh_fail());
    let second = st.observe(&sid("a"), &ssh_fail());
    assert_eq!(
        second,
        UnreachableTransition::BecameUnreachable {
            consecutive_failures: 2,
            threshold: 2,
        },
        "post-recovery re-fire must emit BecameUnreachable again"
    );
}

#[test]
fn fail_state_zero_threshold_clamps_to_one() {
    let mut st = FailState::with_threshold(0);
    assert_eq!(
        st.observe(&sid("a"), &ssh_fail()),
        UnreachableTransition::BecameUnreachable {
            consecutive_failures: 1,
            threshold: 1,
        }
    );
}

#[test]
fn listening_ports_json_round_trip() {
    let mut s: BTreeSet<(String, u16)> = BTreeSet::new();
    s.insert(("tcp".into(), 443));
    s.insert(("udp".into(), 8443));
    s.insert(("tcp".into(), 22));
    let v: Vec<String> = s.iter().map(|(p, n)| format!("{p}/{n}")).collect();
    let json = serde_json::to_string(&v).unwrap();
    assert_eq!(json, r#"["tcp/22","tcp/443","udp/8443"]"#);
}
