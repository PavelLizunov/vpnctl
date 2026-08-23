use std::collections::BTreeSet;

use vpnctl_core::ServerId;
use vpnctl_inventory::SqliteInventory;

use super::*;

/// `purge_old` is a thin pass-through; this test asserts the
/// signature compiles and returns `Ok(0)` on a fresh tempdir
/// inventory (no rows = nothing to drop).
#[tokio::test]
async fn purge_old_on_empty_inv_returns_zero() {
    let tmp = tempfile::tempdir().unwrap();
    let inv = SqliteInventory::open(&tmp.path().join("inv.db"))
        .await
        .unwrap();
    let dropped = purge_old(&inv, 30).await.unwrap();
    assert_eq!(dropped, 0);
}

// ─── FailState consecutive-failure detector ──────────────

fn sid(s: &str) -> ServerId {
    ServerId(s.into())
}

fn ok_probe() -> ProbeOutcome {
    ProbeOutcome::Ok(crate::node_probe::Probe::default())
}
fn ssh_fail() -> ProbeOutcome {
    ProbeOutcome::SshFailed("boom".into())
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
    // Fourth tick still failing — must NOT re-emit BecameUnreachable
    // (that's a one-time edge), but now emits StillUnreachable so the
    // caller re-asserts the idempotent insert — re-opening the alert
    // if the operator acked it while the server is still down.
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
    // Now a success.
    assert_eq!(
        st.observe(&sid("a"), &ok_probe()),
        UnreachableTransition::Recovered
    );
    // Further successes are no-change.
    assert_eq!(
        st.observe(&sid("a"), &ok_probe()),
        UnreachableTransition::NoChange
    );
}

#[test]
fn fail_state_subthreshold_recovery_does_not_fire_or_ack() {
    // Counter at 1 (threshold 3) → recovery → NoChange because
    // the operator never saw a fire-alert; nothing to ack.
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
    // Fail A twice → fire.
    st.observe(&sid("a"), &ssh_fail());
    assert_eq!(
        st.observe(&sid("a"), &ssh_fail()),
        UnreachableTransition::BecameUnreachable {
            consecutive_failures: 2,
            threshold: 2,
        }
    );
    // B is independent; one failure doesn't fire.
    assert_eq!(
        st.observe(&sid("b"), &ssh_fail()),
        UnreachableTransition::NoChange
    );
    // B success doesn't ack A's open alert.
    assert_eq!(
        st.observe(&sid("b"), &ok_probe()),
        UnreachableTransition::NoChange
    );
}

#[test]
fn fail_state_skipped_and_no_key_do_not_count() {
    let mut st = FailState::with_threshold(2);
    st.observe(&sid("a"), &ssh_fail());
    // Skipped tick (e.g. kernel changed mid-poll) does NOT
    // increment the counter, but also does NOT reset it.
    assert_eq!(
        st.observe(&sid("a"), &ProbeOutcome::Skipped),
        UnreachableTransition::NoChange
    );
    assert_eq!(
        st.observe(&sid("a"), &ProbeOutcome::NoDeployKey),
        UnreachableTransition::NoChange
    );
    // The next failure crosses the threshold.
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
    // Regression for: «forgot to reset counter on recovery» and
    // «forgot to reset fired flag on recovery». Either bug leaves
    // the second fire stuck: variant b — counter stays at the
    // post-fire value, next failure jumps straight back over
    // threshold but `fired` is still true so no event; variant c
    // — counter resets but `fired` stays true, never re-fires.
    // The 1-tick assertions in fail_state_recovers_after_fire
    // don't catch either; only this full cycle does.
    let mut st = FailState::with_threshold(2);
    // Fire #1.
    st.observe(&sid("a"), &ssh_fail());
    assert!(matches!(
        st.observe(&sid("a"), &ssh_fail()),
        UnreachableTransition::BecameUnreachable { .. }
    ));
    // Recover (acks the open alert).
    assert_eq!(
        st.observe(&sid("a"), &ok_probe()),
        UnreachableTransition::Recovered
    );
    // Re-fire: two more failures must produce a SECOND
    // BecameUnreachable with counter=2 (NOT 3 or 4 — counter
    // was reset).
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
    // Zero would mean "fire on every failure" — operator-hostile.
    let mut st = FailState::with_threshold(0);
    assert_eq!(
        st.observe(&sid("a"), &ssh_fail()),
        UnreachableTransition::BecameUnreachable {
            consecutive_failures: 1,
            threshold: 1,
        }
    );
}

/// Sanity: serializing the listening-ports set to JSON matches
/// the on-disk format documented in `0007_node_health.sql`
/// (sorted JSON array of `"proto/port"` strings).
#[test]
fn listening_ports_json_round_trip() {
    let mut s: BTreeSet<(String, u16)> = BTreeSet::new();
    s.insert(("tcp".into(), 443));
    s.insert(("udp".into(), 8443));
    s.insert(("tcp".into(), 22));
    let v: Vec<String> = s.iter().map(|(p, n)| format!("{p}/{n}")).collect();
    let json = serde_json::to_string(&v).unwrap();
    // BTreeSet sorts by (proto, port) lex: tcp/22 < tcp/443 < udp/8443.
    assert_eq!(json, r#"["tcp/22","tcp/443","udp/8443"]"#);
}
