//! Spec for `insert_alert_if_no_unacked` and `ack_open_alerts` on
//! `SqliteInventory`. Written from spec only — impl NOT consulted.
//! `insert_alert`/`ack_alert` have their own coverage; not tested here.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use tempfile::TempDir;
use vpnctl_core::{KernelId, Server, ServerId};
use vpnctl_inventory::SqliteInventory;

async fn open(dir: &TempDir) -> SqliteInventory {
    SqliteInventory::open(&dir.path().join("inventory.db"))
        .await
        .expect("open")
}

fn srv(id: &str) -> Server {
    Server {
        id: ServerId(id.into()),
        address: "1.1.1.1".into(),
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

fn sid(s: &str) -> ServerId {
    ServerId(s.into())
}

/// Shorthand for the dedup-aware insert. severity/summary are stable
/// junk — they don't participate in the (kind, server_id) dedup key.
async fn fire(inv: &SqliteInventory, kind: &str, server: Option<&ServerId>) -> Option<i64> {
    inv.insert_alert_if_no_unacked(kind, server, "warning", "x", None)
        .await
        .expect("insert_alert_if_no_unacked must not error")
}

#[tokio::test]
async fn protocol_assurance_alerts_dedupe_per_protocol_kind() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("s1")).await.unwrap();
    let server = sid("s1");

    assert!(fire(&inv, "protocol.assurance.failed.hysteria2", Some(&server)).await.is_some());
    assert!(fire(&inv, "protocol.assurance.failed.hysteria2", Some(&server)).await.is_none());
    assert!(fire(&inv, "protocol.assurance.failed.vless+reality", Some(&server)).await.is_some());
}

// ─── insert_alert_if_no_unacked ──────────────────────────────────────

// 1. Happy path: first call with a fresh (kind, server_id) → Some(id).
#[tokio::test]
async fn insert_if_no_unacked_first_call_returns_some_id() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("s1")).await.unwrap();

    let res = fire(&inv, "server.singbox.down", Some(&sid("s1"))).await;
    assert!(
        matches!(res, Some(id) if id > 0),
        "first call must return Some(positive_id), got {res:?}"
    );
}

// 2. Dedup: second call before ack returns Ok(None) — NOT an Err.
#[tokio::test]
async fn insert_if_no_unacked_second_call_before_ack_returns_none() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("s1")).await.unwrap();

    let first = fire(&inv, "server.singbox.down", Some(&sid("s1"))).await;
    assert!(first.is_some(), "sanity: first call inserted");

    // Full form to assert Ok(None), not just None-via-helper.
    let second = inv
        .insert_alert_if_no_unacked(
            "server.singbox.down",
            Some(&sid("s1")),
            "critical",
            "different summary, same identity",
            Some(r#"{"tick":2}"#),
        )
        .await;
    assert!(
        matches!(second, Ok(None)),
        "second call must be Ok(None), NOT Err — got {second:?}"
    );
}

// 3. Ack-then-refire: after acking, next call inserts a NEW row.
#[tokio::test]
async fn insert_if_no_unacked_refires_after_ack() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("s1")).await.unwrap();

    let first_id = fire(&inv, "server.singbox.down", Some(&sid("s1")))
        .await
        .expect("first insert");
    assert_eq!(
        inv.ack_open_alerts("server.singbox.down", Some(&sid("s1")))
            .await
            .unwrap(),
        1,
        "ack_open_alerts must report the one open row"
    );
    let second_id = fire(&inv, "server.singbox.down", Some(&sid("s1")))
        .await
        .expect("after ack, must insert a NEW row");
    assert_ne!(second_id, first_id, "re-fire id must differ from acked row");
}

// 4. Two callers of (A, X) dedupe: first returns Some, second None.
#[tokio::test]
async fn two_callers_same_kind_same_server_dedupe() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("s1")).await.unwrap();
    let a = fire(&inv, "server.disk.pressure", Some(&sid("s1"))).await;
    let b = fire(&inv, "server.disk.pressure", Some(&sid("s1"))).await;
    assert!(a.is_some(), "first call must insert: {a:?}");
    assert!(b.is_none(), "second call must dedupe: {b:?}");
}

// 5. (A, X) and (A, Y) are distinct scopes and do NOT dedupe.
#[tokio::test]
async fn different_server_id_does_not_dedupe() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("s1")).await.unwrap();
    inv.add_server(&srv("s2")).await.unwrap();
    let on_s1 = fire(&inv, "server.singbox.down", Some(&sid("s1")))
        .await
        .expect("(A, s1) inserts");
    let on_s2 = fire(&inv, "server.singbox.down", Some(&sid("s2")))
        .await
        .expect("(A, s2) must NOT dedupe against (A, s1)");
    assert_ne!(on_s1, on_s2, "different server_id ⇒ different rows");
}

// 6. (A, X) and (B, X) are distinct scopes and do NOT dedupe.
#[tokio::test]
async fn different_kind_does_not_dedupe() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("s1")).await.unwrap();
    let disk = fire(&inv, "server.disk.pressure", Some(&sid("s1")))
        .await
        .expect("disk pressure inserts");
    let singbox = fire(&inv, "server.singbox.down", Some(&sid("s1")))
        .await
        .expect("singbox down on same server must NOT dedupe");
    assert_ne!(disk, singbox, "different kinds ⇒ separate identities");
}

// 7. (A, None) and (A, Some(x)) are distinct identities; no dedupe.
#[tokio::test]
async fn none_and_some_server_id_do_not_dedupe() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("s1")).await.unwrap();
    let global = fire(&inv, "vpnctld.disk.pressure", None)
        .await
        .expect("(A, None) inserts");
    let per_server = fire(&inv, "vpnctld.disk.pressure", Some(&sid("s1")))
        .await
        .expect("(A, Some(s1)) must NOT dedupe against (A, None)");
    assert_ne!(global, per_server, "NULL is distinct from Some(x)");
}

// 8. Two (A, None) global callers DO dedupe — NULL-equals-NULL here.
#[tokio::test]
async fn two_none_callers_dedupe_against_each_other() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let a = fire(&inv, "vpnctld.disk.pressure", None).await;
    let b = fire(&inv, "vpnctld.disk.pressure", None).await;
    assert!(a.is_some(), "first global call must insert: {a:?}");
    assert!(b.is_none(), "second global call must dedupe: {b:?}");
}

// ─── ack_open_alerts ─────────────────────────────────────────────────

// 9. ack_open_alerts on an empty table is idempotent: returns Ok(0).
#[tokio::test]
async fn ack_open_on_empty_table_returns_zero() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("s1")).await.unwrap();
    let n = inv
        .ack_open_alerts("server.singbox.down", Some(&sid("s1")))
        .await
        .unwrap();
    assert_eq!(n, 0, "nothing to ack on empty table");
}

// 10. After firing: ack returns Ok(1) then Ok(0) (idempotent).
#[tokio::test]
async fn ack_open_after_fire_returns_one_then_zero() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("s1")).await.unwrap();
    fire(&inv, "server.singbox.down", Some(&sid("s1")))
        .await
        .expect("seed insert");
    let first = inv
        .ack_open_alerts("server.singbox.down", Some(&sid("s1")))
        .await
        .unwrap();
    assert_eq!(first, 1, "first ack must affect exactly the open row");
    let second = inv
        .ack_open_alerts("server.singbox.down", Some(&sid("s1")))
        .await
        .unwrap();
    assert_eq!(second, 0, "second ack must be a no-op");
}

// 11. Strict scope: ack_open_alerts(A, X) does NOT touch (B, X),
//     (A, Y) or (A, None).
#[tokio::test]
async fn ack_open_scope_isolation_kind_server_and_null() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("s1")).await.unwrap();
    inv.add_server(&srv("s2")).await.unwrap();

    // Target row + three decoys that must remain unacked.
    fire(&inv, "server.singbox.down", Some(&sid("s1")))
        .await
        .expect("target");
    fire(&inv, "server.disk.pressure", Some(&sid("s1")))
        .await
        .expect("decoy B,s1");
    fire(&inv, "server.singbox.down", Some(&sid("s2")))
        .await
        .expect("decoy A,s2");
    fire(&inv, "server.singbox.down", None)
        .await
        .expect("decoy A,None");
    assert_eq!(
        inv.unacked_alert_count().await.unwrap(),
        4,
        "sanity: 4 open before ack"
    );

    let n = inv
        .ack_open_alerts("server.singbox.down", Some(&sid("s1")))
        .await
        .unwrap();
    assert_eq!(n, 1, "ack_open_alerts(A, s1) must touch exactly one row");
    assert_eq!(
        inv.unacked_alert_count().await.unwrap(),
        3,
        "exactly three decoys must remain unacked"
    );

    // Acking each decoy must still report 1 (proving previous ack did
    // NOT collateral-sweep them).
    let ack = |kind: &'static str, srv: Option<ServerId>| {
        let inv = inv.clone();
        async move { inv.ack_open_alerts(kind, srv.as_ref()).await.unwrap() }
    };
    assert_eq!(
        ack("server.disk.pressure", Some(sid("s1"))).await,
        1,
        "(B, s1) still open"
    );
    assert_eq!(
        ack("server.singbox.down", Some(sid("s2"))).await,
        1,
        "(A, s2) still open"
    );
    assert_eq!(
        ack("server.singbox.down", None).await,
        1,
        "(A, None) still open"
    );
}

// 12b. Regression for «predicate flipped to acked_at IS NOT NULL»:
//      seed an ALREADY-ACKED row of the target (kind, server_id),
//      then verify insert_alert_if_no_unacked still fires (returns
//      Some(_)) — proving the dedup gate only counts UNACKED rows,
//      not the full history. Without this test, flipping `acked_at
//      IS NULL` to `acked_at IS NOT NULL` (or dropping the clause
//      entirely) would silently change semantics without test
//      failure on the default-NULL-column happy path.
#[tokio::test]
async fn insert_if_no_unacked_ignores_already_acked_history() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("s1")).await.unwrap();

    // Seed-and-ack: one historical row that was raised and dismissed.
    let prev = fire(&inv, "server.singbox.down", Some(&sid("s1")))
        .await
        .expect("seed insert");
    assert!(
        inv.ack_alert(prev).await.unwrap(),
        "seed row must have been ackable"
    );

    // Now fire again. The PARTIAL-UNIQUE / NOT-EXISTS gate must
    // ignore the acked history row.
    let next = fire(&inv, "server.singbox.down", Some(&sid("s1"))).await;
    assert!(
        next.is_some(),
        "insert_if_no_unacked must fire when the only prior row is acked, got {next:?}"
    );
    assert_ne!(
        next.unwrap(),
        prev,
        "the new row must be distinct from the historical one"
    );
}

// 12. After ack_open_alerts, the acked row is hidden from
//     recent_alerts(_, false) but visible in recent_alerts(_, true).
#[tokio::test]
async fn ack_open_hides_from_unacked_feed_but_keeps_history() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("s1")).await.unwrap();

    fire(&inv, "server.singbox.down", Some(&sid("s1")))
        .await
        .expect("seed");
    assert_eq!(
        inv.ack_open_alerts("server.singbox.down", Some(&sid("s1")))
            .await
            .unwrap(),
        1
    );

    let only_unacked = inv.recent_alerts(50, false).await.unwrap();
    assert!(
        only_unacked.iter().all(|a| a.kind != "server.singbox.down"),
        "acked row must NOT appear in unacked feed: {only_unacked:?}"
    );
    let with_history = inv.recent_alerts(50, true).await.unwrap();
    assert!(
        with_history.iter().any(|a| a.kind == "server.singbox.down"
            && a.server_id.as_ref().map(|s| s.0.as_str()) == Some("s1")
            && a.acked_at.is_some()),
        "acked row must remain visible in include_acked=true view: {with_history:?}"
    );
}

// ─── telegram_message_id (edit-on-recover) ───────────────────────────

// 13. set_alert_telegram_message_id round-trips; latest_alert_message_id
//     finds the most-recent matching (kind, server) message id and is
//     scoped strictly by kind + server.
#[tokio::test]
async fn telegram_message_id_round_trip_and_recovery_lookup() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("de")).await.unwrap();
    let de = sid("de");

    let id = fire(&inv, "server.unreachable", Some(&de))
        .await
        .expect("fresh insert");
    // Before recording a message id, the recovery lookup finds nothing
    // (the column is NULL) → caller would send a fresh recovery message.
    assert_eq!(
        inv.latest_alert_message_id("server.unreachable", Some(&de))
            .await
            .unwrap(),
        None
    );
    inv.set_alert_telegram_message_id(id, "4242").await.unwrap();
    // Now the original 🔴 message can be located for the 🟢 edit.
    assert_eq!(
        inv.latest_alert_message_id("server.unreachable", Some(&de))
            .await
            .unwrap()
            .as_deref(),
        Some("4242")
    );
    // Strict scope: wrong kind / wrong server → None.
    assert_eq!(
        inv.latest_alert_message_id("server.singbox.down", Some(&de))
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        inv.latest_alert_message_id("server.unreachable", Some(&sid("fi")))
            .await
            .unwrap(),
        None
    );
}

// 14. Global vs server-scoped latest_alert_message_id isolation:
//     server_id = None must match ONLY global (server_id IS NULL) alerts,
//     and server_id = Some(id) must match ONLY that specific server.
#[tokio::test]
async fn latest_alert_message_id_global_vs_server_scoped_isolation() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("de")).await.unwrap();
    inv.add_server(&srv("fi")).await.unwrap();
    let de = sid("de");
    let fi = sid("fi");

    // Case 1: Only server-scoped alert exists with a message id.
    // A query for a global alert (server_id = None) must NOT match the server alert.
    let srv_id = fire(&inv, "disk.pressure", Some(&de))
        .await
        .expect("server alert insert");
    inv.set_alert_telegram_message_id(srv_id, "msg-de-1")
        .await
        .unwrap();

    assert_eq!(
        inv.latest_alert_message_id("disk.pressure", None)
            .await
            .unwrap(),
        None,
        "global lookup must not see server-scoped alert"
    );
    assert_eq!(
        inv.latest_alert_message_id("disk.pressure", Some(&de))
            .await
            .unwrap()
            .as_deref(),
        Some("msg-de-1")
    );
    assert_eq!(
        inv.latest_alert_message_id("disk.pressure", Some(&fi))
            .await
            .unwrap(),
        None
    );

    // Case 2: Global alert added afterwards with a newer message id.
    // Global lookup matches global alert; server lookup matches server alert.
    let global_id = fire(&inv, "disk.pressure", None)
        .await
        .expect("global alert insert");
    inv.set_alert_telegram_message_id(global_id, "msg-global-1")
        .await
        .unwrap();

    assert_eq!(
        inv.latest_alert_message_id("disk.pressure", None)
            .await
            .unwrap()
            .as_deref(),
        Some("msg-global-1"),
        "global lookup must find the global alert message id"
    );
    assert_eq!(
        inv.latest_alert_message_id("disk.pressure", Some(&de))
            .await
            .unwrap()
            .as_deref(),
        Some("msg-de-1"),
        "server lookup must still find server alert despite newer global alert"
    );
    assert_eq!(
        inv.latest_alert_message_id("disk.pressure", Some(&fi))
            .await
            .unwrap(),
        None
    );
}

// 15. _source_event string payload historical dedupe across ack:
//     A string _source_event deduplicates historically even after the alert is acked.
#[tokio::test]
async fn source_event_string_dedupes_historically_across_ack() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("s1")).await.unwrap();
    let s1 = sid("s1");

    let payload_ev1 = serde_json::json!({"_source_event": "evt-alpha"}).to_string();
    let id1 = inv
        .insert_alert_if_no_unacked(
            "health.down",
            Some(&s1),
            "critical",
            "down evt-alpha",
            Some(&payload_ev1),
        )
        .await
        .unwrap()
        .expect("first insert with string _source_event");
    assert!(id1 > 0);

    // Unacked duplicate is suppressed.
    let dup = inv
        .insert_alert_if_no_unacked(
            "health.down",
            Some(&s1),
            "critical",
            "down evt-alpha retry",
            Some(&payload_ev1),
        )
        .await
        .unwrap();
    assert_eq!(dup, None);

    // Ack the first alert.
    assert!(inv.ack_alert(id1).await.unwrap());

    // Rescan / resubmit of SAME source event after ack is STILL suppressed across history.
    let rescan = inv
        .insert_alert_if_no_unacked(
            "health.down",
            Some(&s1),
            "critical",
            "down evt-alpha rescan",
            Some(&payload_ev1),
        )
        .await
        .unwrap();
    assert_eq!(
        rescan, None,
        "identical string _source_event must not reopen after ack"
    );

    // New string source event reopens and inserts.
    let payload_ev2 = serde_json::json!({"_source_event": "evt-beta"}).to_string();
    let id2 = inv
        .insert_alert_if_no_unacked(
            "health.down",
            Some(&s1),
            "critical",
            "down evt-beta",
            Some(&payload_ev2),
        )
        .await
        .unwrap()
        .expect("different string _source_event must insert");
    assert_ne!(id1, id2);
}

// 16. Non-string _source_event (numeric / boolean) uses ordinary unacked-only semantics:
//     Numeric and boolean payloads dedupe while unacked, but refire legitimately after ack.
#[tokio::test]
async fn source_event_numeric_and_boolean_use_ordinary_unacked_semantics() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("s1")).await.unwrap();
    let s1 = sid("s1");

    // --- Numeric payload ---
    let num_payload = serde_json::json!({"_source_event": 42}).to_string();
    let num_id1 = inv
        .insert_alert_if_no_unacked(
            "numeric.event",
            Some(&s1),
            "warning",
            "num 1",
            Some(&num_payload),
        )
        .await
        .unwrap()
        .expect("first numeric payload insert");

    // Unacked duplicate is suppressed.
    let num_dup = inv
        .insert_alert_if_no_unacked(
            "numeric.event",
            Some(&s1),
            "warning",
            "num dup",
            Some(&num_payload),
        )
        .await
        .unwrap();
    assert_eq!(num_dup, None);

    // Ack numeric alert.
    assert!(inv.ack_alert(num_id1).await.unwrap());

    // After ack, re-firing with the SAME numeric payload succeeds (ordinary unacked semantics).
    let num_id2 = inv
        .insert_alert_if_no_unacked(
            "numeric.event",
            Some(&s1),
            "warning",
            "num 2",
            Some(&num_payload),
        )
        .await
        .unwrap()
        .expect("numeric payload must refire after ack");
    assert_ne!(num_id1, num_id2);

    // --- Boolean payload ---
    let bool_payload = serde_json::json!({"_source_event": true}).to_string();
    let bool_id1 = inv
        .insert_alert_if_no_unacked(
            "bool.event",
            Some(&s1),
            "warning",
            "bool 1",
            Some(&bool_payload),
        )
        .await
        .unwrap()
        .expect("first bool payload insert");

    // Unacked duplicate is suppressed.
    let bool_dup = inv
        .insert_alert_if_no_unacked(
            "bool.event",
            Some(&s1),
            "warning",
            "bool dup",
            Some(&bool_payload),
        )
        .await
        .unwrap();
    assert_eq!(bool_dup, None);

    // Ack boolean alert.
    assert!(inv.ack_alert(bool_id1).await.unwrap());

    // After ack, re-firing with the SAME boolean payload succeeds (ordinary unacked semantics).
    let bool_id2 = inv
        .insert_alert_if_no_unacked(
            "bool.event",
            Some(&s1),
            "warning",
            "bool 2",
            Some(&bool_payload),
        )
        .await
        .unwrap()
        .expect("boolean payload must refire after ack");
    assert_ne!(bool_id1, bool_id2);
}

// ─── has_unacked_alert ────────────────────────────────────────────────

#[tokio::test]
async fn has_unacked_alert_tracks_open_alerts_and_respects_scope() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("s1")).await.unwrap();
    inv.add_server(&srv("s2")).await.unwrap();
    let s1 = sid("s1");
    let s2 = sid("s2");

    // Empty DB: no unacked alerts
    assert!(
        !inv.has_unacked_alert("server.quality.degraded", Some(&s1))
            .await
            .unwrap()
    );
    assert!(
        !inv.has_unacked_alert("server.quality.degraded", None)
            .await
            .unwrap()
    );

    // Insert alert for s1
    let id1 = inv
        .insert_alert_if_no_unacked(
            "server.quality.degraded",
            Some(&s1),
            "warning",
            "s1 bad",
            None,
        )
        .await
        .unwrap()
        .expect("insert s1 alert");

    assert!(
        inv.has_unacked_alert("server.quality.degraded", Some(&s1))
            .await
            .unwrap()
    );
    assert!(
        !inv.has_unacked_alert("server.quality.degraded", Some(&s2))
            .await
            .unwrap()
    );
    assert!(
        !inv.has_unacked_alert("server.singbox.down", Some(&s1))
            .await
            .unwrap()
    );
    assert!(
        !inv.has_unacked_alert("server.quality.degraded", None)
            .await
            .unwrap()
    );

    // Ack s1 alert
    assert!(inv.ack_alert(id1).await.unwrap());
    assert!(
        !inv.has_unacked_alert("server.quality.degraded", Some(&s1))
            .await
            .unwrap()
    );

    // Global alert (server_id = None)
    let id_global = inv
        .insert_alert_if_no_unacked("backup.failed", None, "critical", "backup err", None)
        .await
        .unwrap()
        .expect("insert global alert");

    assert!(inv.has_unacked_alert("backup.failed", None).await.unwrap());
    assert!(
        !inv.has_unacked_alert("backup.failed", Some(&s1))
            .await
            .unwrap()
    );

    // Ack global alert
    assert!(inv.ack_alert(id_global).await.unwrap());
    assert!(!inv.has_unacked_alert("backup.failed", None).await.unwrap());
}
