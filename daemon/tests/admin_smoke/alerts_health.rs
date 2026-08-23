use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{KernelId, ProtocolId, Registry, Server, ServerId, User, UserId};
use vpnctl_inventory::SqliteInventory;
use vpnctl_kernels::SingBox;
use vpnctl_protocols::{TuicV5, VlessReality};
use vpnctld::{AppState, router};

use super::common::*;

// ────────────────────────────────────────────────────────────────────────
//  Phase Track-1 (back-pressure) — bounded mpsc + writer task
//
//  Caught by retroactive review-agent (review #3) AND security-review
//  (security #2) on 2026-05-14: the original Track-1 wired access
//  logging via `tokio::spawn` per request, fire-and-forget. An
//  attacker holding ONE valid sub-token could DoS the daemon by
//  spawning unbounded background tasks until the SQLite pool / memory
//  saturated.
//
//  The fix moves the work off the request path entirely: requests
//  `try_send` a record into a bounded mpsc channel; one dedicated
//  writer task drains it. Channel-full → record dropped + warn-log;
//  HTTP response stays 200.
//
//  These tests pin the contract end-to-end through the public
//  `/sub/<token>` handler.
// ────────────────────────────────────────────────────────────────────────

/// A single `/sub/<token>` hit lands one row in `sub_access_log`.
/// Validates the writer task drains the channel into the inventory
/// in the same way the old direct-await did.
#[tokio::test]
async fn sub_access_writer_persists_one_hit() {
    use http_body_util::BodyExt;
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await;
    // Token of u0 (open() backfilled it).
    let token = s
        .inv
        .get_user(&UserId("u0".into()))
        .await
        .unwrap()
        .unwrap()
        .sub_token
        .unwrap();

    // Snapshot the inv handle for later assertion (state.inv is moved
    // into the router).
    let inv = s.inv.clone();
    let app = router(s);

    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/sub/{token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let _ = resp.into_body().collect().await.unwrap();

    // The writer task is async — give it a moment to drain. In practice
    // sub-millisecond, but we sleep long enough that flaky CI doesn't
    // trip. The contract says the row WILL eventually land, not that
    // it is synchronous with the response.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let rows = inv
        .recent_sub_access(&UserId("u0".into()), 5)
        .await
        .unwrap();
    assert_eq!(
        rows.len(),
        1,
        "writer task must drain exactly one row from one /sub hit"
    );
    assert_eq!(rows[0].status, 200);
    // ConnectInfo absent in `oneshot` → recorded as 0.0.0.0 per the
    // sub.rs fallback (already pinned by the warn-once test).
    assert_eq!(rows[0].ip, "0.0.0.0");
}

/// Module-level back-pressure contract: when the channel is full,
/// `access_log::try_enqueue` returns false and drops the record
/// (instead of panicking, blocking, or growing memory unbounded).
/// Production capacity is 1024; this test forces a tiny channel via
/// the public type to make the boundary observable in milliseconds.
#[tokio::test]
async fn access_log_back_pressure_drops_records_when_full() {
    use tokio::sync::mpsc;
    use vpnctld::access_log::{AccessLogRecord, try_enqueue};

    // Tiny channel: 2 slots. Build it directly instead of using
    // `spawn_writer` — a writer would drain too fast for the test to
    // reliably observe the full state. Without a writer, every
    // try_enqueue past the second one MUST return false.
    let (tx, _rx) = mpsc::channel::<AccessLogRecord>(2);

    let mk = |ip: &str| AccessLogRecord {
        user_id: UserId("u0".into()),
        ip: ip.to_string(),
        ua: None,
        status: 200,
        bytes: 100,
        accept_language: None,
        http_version: None,
        device_class: None,
        geo_country: None,
        geo_asn: None,
        tls_ja3: None,
        tls_ja4: None,
    };

    // First two enqueues fill the buffer → both return true.
    assert!(
        try_enqueue(&tx, mk("1.1.1.1")),
        "first enqueue must succeed"
    );
    assert!(
        try_enqueue(&tx, mk("2.2.2.2")),
        "second enqueue must succeed"
    );
    // Third enqueue with no drainer → channel full → dropped.
    assert!(
        !try_enqueue(&tx, mk("3.3.3.3")),
        "third enqueue must FAIL with back-pressure (no drainer running)"
    );
    // Fourth too — same drop path; the contract is "drop, don't panic".
    assert!(
        !try_enqueue(&tx, mk("4.4.4.4")),
        "fourth enqueue must FAIL — back-pressure must not panic, must not block, must not grow unbounded"
    );
}

// ────────────────────────────────────────────────────────────────────────
//  Phase Track-1.1 — retention scheduler smoke test
//
//  The full purge contract is in `crates/inventory/tests/spec_sub_access.rs`
//  (`purge_removes_rows_older_than_cutoff_only` etc.). This test only
//  pins that the scheduler actually spawns a runnable task — without
//  it the user-detail page's "auto-purged after 30 days" promise was
//  inert (rows would accumulate forever).
// ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn retention_purger_spawns_a_runnable_task() {
    let dir = TempDir::new().unwrap();
    let inv = vpnctl_inventory::SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();

    // Spawn the purger and immediately abort — we don't want the loop
    // to actually tick (the interval is 1h). A spawn that compiled and
    // returned a JoinHandle proves the wiring works; the purge body
    // itself is fully tested in spec_sub_access.
    let handle = vpnctld::spawn_retention_purger_for_test(inv);
    handle.abort();
    let result = handle.await;
    assert!(
        matches!(&result, Err(e) if e.is_cancelled()),
        "expected aborted JoinHandle; got {result:?}"
    );
}

#[tokio::test]
async fn node_probe_poller_spawns_a_runnable_task() {
    // Phase H chunk 4 smoke test — mirrors retention_purger above.
    // Proves `spawn_node_probe_poller` compiles, returns a real
    // tokio task, and lets `abort()` cancel cleanly. The probe body
    // (parser, SSH client, inventory INSERT) is fully exercised by
    // `crate::node_probe::tests` + `spec_node_health`.
    let dir = TempDir::new().unwrap();
    let inv = vpnctl_inventory::SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    let handle = vpnctld::spawn_node_probe_poller_for_test(inv);
    handle.abort();
    let result = handle.await;
    assert!(
        matches!(&result, Err(e) if e.is_cancelled()),
        "expected aborted JoinHandle; got {result:?}"
    );
}

#[tokio::test]
async fn health_monitor_spawns_a_runnable_task() {
    // Phase G smoke test — same shape as the two pollers above.
    // diff_rows + scan_once are unit-tested in
    // `daemon::health_monitor::tests`; this just proves the spawn
    // wires up cleanly under tokio.
    let dir = TempDir::new().unwrap();
    let inv = vpnctl_inventory::SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    let handle = vpnctld::spawn_health_monitor_for_test(inv);
    handle.abort();
    let result = handle.await;
    assert!(
        matches!(&result, Err(e) if e.is_cancelled()),
        "expected aborted JoinHandle; got {result:?}"
    );
}

#[tokio::test]
async fn admin_alerts_empty_state_renders_with_copy_contract() {
    // Phase G — bare alerts page on an empty inventory. Should render
    // the editorial empty-state with the canonical "no unacked alerts"
    // copy + a link to "show all" (so the operator can confirm history
    // even when there's nothing actionable).
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/alerts")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "expected 200 alerts page");
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();

    assert!(
        html.contains("no unacked alerts"),
        "expected empty-state copy 'no unacked alerts'"
    );
    assert!(html.contains("show all"), "expected link to acked history");
    // Nav entry is wired.
    assert!(
        html.contains(r#"href="/admin/alerts""#),
        "expected nav entry to /admin/alerts"
    );
    // Phase G chunk 2 deck-copy extension — page now advertises the
    // new detector categories so the operator knows what will show
    // up here. Catches drift on either the «unreachable hosts»
    // or «locked myself out» substring.
    assert!(
        html.contains("health monitor") && html.contains("sub-access analyzer"),
        "headrow tooltip must explain both alert sources (v2 5a)"
    );
}

#[tokio::test]
async fn admin_alerts_renders_unreachable_kind_row() {
    // Phase G chunk 2 — seed an unreachable-kind alert row and verify
    // the feed renders it with the expected kind label + severity.
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    let inv = st.inv.clone();
    inv.add_server(&vpnctl_core::Server {
        id: vpnctl_core::ServerId("stg".into()),
        address: "1.1.1.1".into(),
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
    inv.insert_alert(
        "server.unreachable",
        Some(&vpnctl_core::ServerId("stg".into())),
        "warning",
        "3 consecutive SSH probes failed",
        Some(r#"{"consecutive_failures":3,"threshold":3}"#),
    )
    .await
    .unwrap();

    let app = router(st);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/alerts")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        html.contains("server.unreachable"),
        "feed must render the kind: {html:?}"
    );
    assert!(
        html.contains("Node unreachable") && html.contains("probes failed in a row"),
        "feed must render the localized title + body (not the stored English summary): {html:?}"
    );
}

/// R3 2026-07-10 — the sub_access family table shows a COMPACT detail
/// (source IP + range kind + client) instead of the full localized
/// sentence repeated on every row. The boilerplate stays on hover.
#[tokio::test]
async fn alerts_sub_access_row_shows_compact_ip_detail_not_boilerplate() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .insert_alert(
            "sub_access.suspicious_local_ip:brat",
            None,
            "warning",
            "local-loop fetch · user=brat · ip=192.168.0.210 [LAN] · ua=Hiddify",
            Some(r#"{"user_id":"brat","ip":"192.168.0.210","ip_kind":"LAN","device_class":"Hiddify"}"#),
        )
        .await
        .unwrap();

    let html = fetch_html(router(s), "/admin/alerts").await;
    // The varying datum — the source IP — renders as its own cell.
    assert!(
        html.contains("192.168.0.210"),
        "sub_access row must surface the source IP"
    );
    assert!(html.contains("[LAN]"), "range-kind tag must render");
    assert!(html.contains("Hiddify"), "client label must render");
    // The 30-word boilerplate must NOT be in the visible cell (it stays
    // on the row's title= hover only).
    assert!(
        !html.contains("the logged client IP will be wrong"),
        "verbose boilerplate must not repeat in the visible detail cell"
    );
    // The full sentence still lives in the hover title.
    assert!(
        html.contains(r#"title="local-loop fetch"#),
        "the stored summary must remain available on hover"
    );
}

#[tokio::test]
async fn dispatch_alerts_banned_self_writes_row_with_payload() {
    // Phase G chunk 2 — full integration of the banned-self detector:
    // build a Probe with fail2ban_self_banned=Some(true), call the
    // public `dispatch_alerts` free fn (the same one the poller
    // loop calls), then hit /admin/alerts and assert the rendered
    // row contains the operator-relevant fields from the payload
    // (our_ip + summary text). Catches any typo in the payload key
    // names, the summary template, or the kind string.
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    let inv = st.inv.clone();
    let server = vpnctl_core::Server {
        id: vpnctl_core::ServerId("stg".into()),
        address: "1.1.1.1".into(),
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

    // Build a Probe in the «banned-self» state: our IP appears in
    // the fail2ban-banned set.
    let probe = vpnctld::node_probe::Probe {
        probe_source_ip: Some("192.168.0.236".into()),
        fail2ban_banned_ips: Some(vec!["192.168.0.236".into(), "1.2.3.4".into()]),
        fail2ban_self_banned: Some(true),
        ..Default::default()
    };

    let mut fail_state = vpnctld::node_probe_poller::FailState::new();
    vpnctld::node_probe_poller::dispatch_alerts(
        &inv,
        &server,
        &vpnctld::node_probe_poller::ProbeOutcome::Ok(probe),
        &mut fail_state,
    )
    .await;

    // Row was written.
    let alerts = inv.recent_alerts(10, false).await.unwrap();
    assert_eq!(
        alerts.len(),
        1,
        "dispatch_alerts must write exactly one row for self_banned=Some(true)"
    );
    assert_eq!(alerts[0].kind, "server.fail2ban.banned_self");
    assert_eq!(alerts[0].severity, "critical");

    // Payload survived through to the rendering path.
    let app = router(st);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/alerts")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        html.contains("server.fail2ban.banned_self"),
        "feed must render the kind"
    );
    assert!(
        html.contains("192.168.0.236"),
        "feed must render our IP from the summary template"
    );
}

#[tokio::test]
async fn dispatch_alerts_recovery_auto_acks_open_unreachable() {
    // Phase G chunk 2 — full integration of the recovery path:
    // drive FailState through the consecutive-failure threshold so
    // dispatch_alerts fires `server.unreachable`, then drive an
    // Ok outcome and assert the row is auto-acked (no longer in
    // the unacked feed) AND an `alert.auto_ack` audit row landed.
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    let inv = st.inv.clone();
    let server = vpnctl_core::Server {
        id: vpnctl_core::ServerId("stg".into()),
        address: "1.1.1.1".into(),
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

    let mut fail_state = vpnctld::node_probe_poller::FailState::with_threshold(2);

    // 2 failures → BecameUnreachable → row written.
    for _ in 0..2 {
        vpnctld::node_probe_poller::dispatch_alerts(
            &inv,
            &server,
            &vpnctld::node_probe_poller::ProbeOutcome::SshFailed("connect timeout".into()),
            &mut fail_state,
        )
        .await;
    }
    assert_eq!(
        inv.recent_alerts(10, false).await.unwrap().len(),
        1,
        "2 consecutive failures with threshold=2 must fire one row"
    );

    // Recovery → row auto-acked → unacked feed empty.
    vpnctld::node_probe_poller::dispatch_alerts(
        &inv,
        &server,
        &vpnctld::node_probe_poller::ProbeOutcome::Ok(vpnctld::node_probe::Probe::default()),
        &mut fail_state,
    )
    .await;
    assert_eq!(
        inv.recent_alerts(10, false).await.unwrap().len(),
        0,
        "recovery must auto-ack the open unreachable row"
    );
    // History view still shows it (with acked_at set).
    let history = inv.recent_alerts(10, true).await.unwrap();
    assert_eq!(history.len(), 1);
    assert!(history[0].acked_at.is_some(), "row must be marked acked");
}

#[tokio::test]
async fn dispatch_alerts_reopens_after_manual_ack_while_still_down() {
    // Regression for the kg 2026-05-31 incident: operator acks the
    // `server.unreachable` alert while the server is STILL down. The
    // old state machine left FailState.fired=true and emitted NoChange
    // for every later failing tick, so the acked alert NEVER re-fired
    // (only a recovery reset `fired`). The StillUnreachable transition
    // now re-asserts the idempotent insert each down-tick → the next
    // failing probe after an ack re-opens a fresh alert.
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    let inv = st.inv.clone();
    let server = vpnctl_core::Server {
        id: vpnctl_core::ServerId("kg".into()),
        address: "213.155.9.39".into(),
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
    let mut fail_state = vpnctld::node_probe_poller::FailState::with_threshold(2);
    let fail = || vpnctld::node_probe_poller::ProbeOutcome::SshFailed("connect timeout".into());

    // 2 failures (threshold=2) → fire one unacked row.
    for _ in 0..2 {
        vpnctld::node_probe_poller::dispatch_alerts(&inv, &server, &fail(), &mut fail_state).await;
    }
    let open = inv.recent_alerts(10, false).await.unwrap();
    assert_eq!(open.len(), 1, "threshold crossing fires one row");

    // A 3rd still-down tick while the alert is OPEN+unacked must NOT
    // create a duplicate (partial-UNIQUE dedup).
    vpnctld::node_probe_poller::dispatch_alerts(&inv, &server, &fail(), &mut fail_state).await;
    assert_eq!(
        inv.recent_alerts(10, false).await.unwrap().len(),
        1,
        "still-down tick must NOT duplicate an already-open alert"
    );

    // Operator ACKS the alert (web «ack» button) — but the server is
    // still down.
    assert!(inv.ack_alert(open[0].id).await.unwrap());
    assert_eq!(
        inv.recent_alerts(10, false).await.unwrap().len(),
        0,
        "ack clears it from the unacked feed"
    );

    // Next still-down probe → MUST re-open (the bug: it stayed silent).
    vpnctld::node_probe_poller::dispatch_alerts(&inv, &server, &fail(), &mut fail_state).await;
    assert_eq!(
        inv.recent_alerts(10, false).await.unwrap().len(),
        1,
        "a still-down server must RE-FIRE after a manual ack (kg incident fix)"
    );
}

#[tokio::test]
async fn dispatch_alerts_auto_suppress_sets_and_clears_with_optin() {
    // Migration 0030: with the per-server opt-in ON, crossing the
    // unreachable threshold flags the server suppressed (render skips
    // it); recovery clears it. With opt-in OFF, failures never suppress.
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    let inv = st.inv.clone();
    let mk = |id: &str| vpnctl_core::Server {
        id: vpnctl_core::ServerId(id.into()),
        address: format!("{id}.example.com"),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![vpnctl_core::KernelId("sing-box".into())],
        enabled_protocols: vec![],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    };
    let opted = mk("optin");
    let plain = mk("plain");
    inv.add_server(&opted).await.unwrap();
    inv.add_server(&plain).await.unwrap();
    inv.set_server_auto_suppress(&opted.id, true).await.unwrap();

    let fail = || vpnctld::node_probe_poller::ProbeOutcome::SshFailed("timeout".into());
    let mut fs = vpnctld::node_probe_poller::FailState::with_threshold(2);

    // 2 failures each → opted crosses threshold.
    for _ in 0..2 {
        vpnctld::node_probe_poller::dispatch_alerts(&inv, &opted, &fail(), &mut fs).await;
        vpnctld::node_probe_poller::dispatch_alerts(&inv, &plain, &fail(), &mut fs).await;
    }
    assert!(
        inv.is_server_auto_suppressed(&opted.id).await.unwrap(),
        "opted-in server must be suppressed after the threshold"
    );
    assert!(
        !inv.is_server_auto_suppressed(&plain.id).await.unwrap(),
        "opt-in OFF server must NEVER be auto-suppressed"
    );

    // Recovery on the opted server → suppression lifted.
    vpnctld::node_probe_poller::dispatch_alerts(
        &inv,
        &opted,
        &vpnctld::node_probe_poller::ProbeOutcome::Ok(vpnctld::node_probe::Probe::default()),
        &mut fs,
    )
    .await;
    assert!(
        !inv.is_server_auto_suppressed(&opted.id).await.unwrap(),
        "recovery must auto-restore the server to the subscription"
    );
}

#[tokio::test]
async fn dispatch_alerts_auto_restore_survives_daemon_restart() {
    // review-agent critical: suppressed_at persists in the DB, but the
    // in-memory FailState resets on a daemon restart. A server suppressed
    // before the restart, then recovering, would never hit the
    // `Recovered` transition (fired=false post-restart) — so the clear
    // must be tied to the Ok OUTCOME, not the transition. Simulate:
    // pre-suppressed server + FRESH FailState + one Ok probe → restored.
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    let inv = st.inv.clone();
    let server = vpnctl_core::Server {
        id: vpnctl_core::ServerId("fi".into()),
        address: "84.19.3.104".into(),
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
    // Pre-restart state: opted in + already suppressed.
    inv.set_server_auto_suppress(&server.id, true)
        .await
        .unwrap();
    inv.set_server_suppressed(&server.id, true).await.unwrap();
    assert!(inv.is_server_auto_suppressed(&server.id).await.unwrap());

    // FRESH FailState = post-restart (fired/counter wiped). A single Ok
    // probe returns NoChange from observe() (nothing was being tracked),
    // yet the outcome-based clear must still restore the server.
    let mut fresh = vpnctld::node_probe_poller::FailState::with_threshold(2);
    vpnctld::node_probe_poller::dispatch_alerts(
        &inv,
        &server,
        &vpnctld::node_probe_poller::ProbeOutcome::Ok(vpnctld::node_probe::Probe::default()),
        &mut fresh,
    )
    .await;
    assert!(
        !inv.is_server_auto_suppressed(&server.id).await.unwrap(),
        "a successful probe must clear suppression even with no Recovered transition (restart-safe)"
    );
}

#[tokio::test]
async fn admin_alerts_renders_banned_self_kind_row() {
    // Phase G chunk 2 — seed a fail2ban banned-self alert row and
    // verify the feed renders it with the critical severity class.
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    let inv = st.inv.clone();
    inv.add_server(&vpnctl_core::Server {
        id: vpnctl_core::ServerId("stg".into()),
        address: "1.1.1.1".into(),
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
    inv.insert_alert(
        "server.fail2ban.banned_self",
        Some(&vpnctl_core::ServerId("stg".into())),
        "critical",
        "daemon's outbound IP 192.168.0.236 is in fail2ban's banned list for sshd",
        Some(r#"{"our_ip":"192.168.0.236","ban_count_other":0}"#),
    )
    .await
    .unwrap();

    let app = router(st);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/alerts")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        html.contains("server.fail2ban.banned_self"),
        "feed must render the kind"
    );
    assert!(
        html.contains("192.168.0.236"),
        "feed must render the IP from the summary"
    );
}

#[tokio::test]
async fn admin_alerts_ack_unknown_id_returns_redirect_not_500() {
    // Phase G ack idempotency contract — every valid path through
    // `alert_ack` redirects, never 500s. Three branches:
    //   * id <= 0  → early redirect (negative-id guard).
    //   * id > 0 but no such row → ack_alert returns false → redirect.
    //   * id > 0 and row exists → ack + audit + redirect (covered
    //     by full-lifecycle test when Phase G chunk 2 ships).
    // This test exercises the first two — both paths must return a
    // redirect, not a 4xx/5xx. The empty inventory means no row
    // matches id=999.
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    for (uri, label) in [
        ("/admin/alerts/999/ack", "unknown id"),
        ("/admin/alerts/0/ack", "id=0 guard"),
    ] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("Origin", "http://127.0.0.1")
                    .header("Host", "127.0.0.1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            resp.status() == StatusCode::SEE_OTHER
                || resp.status() == StatusCode::FOUND
                || resp.status() == StatusCode::TEMPORARY_REDIRECT,
            "{label}: expected redirect, got {:?}",
            resp.status()
        );
    }
}

// ────────────────────────────────────────────────────────────────────────
//  Phase F — monitoring page + stats JSON endpoint
//
//  Pin the SSR shape (KPIs + sparkline SVG dimensions) and the JSON
//  endpoint response shape. Sparkline content depends on inventory
//  state at test time, so we assert shape (svg width/height/stroke,
//  KPI labels) rather than pixel values.
// ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn admin_monitoring_renders_fleet_health() {
    // Design v2 3a — monitoring is the fleet-health surface: six
    // status tiles, per-node uptime + trend tables, the monitor's
    // REAL thresholds, probe failures and the GeoIP line. The former
    // sub-access analytics are gone from the page (the JSON API at
    // /api/v1/stats/sub-access stays — pinned by its own test).
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    // One health row (mem 75% > the 70 heat watermark) so the tiles,
    // uptime table and trend table all have real cells.
    s.inv
        .record_node_health(
            &ServerId("s0".into()),
            Some(true),
            Some(true),
            Some(4096),
            Some(20480),
            Some(2048),
            Some(8192),
            Some(120),
            None,
            Some(1_048_576),
            Some(r#"{"sing-box":"1.13.12"}"#),
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

    let app = router(s);
    let html = fetch_html(app, "/admin/monitoring").await;

    // Headrow: Fleet health h1 + the manual sweep button (POST form).
    assert!(html.contains("Fleet"), "Fleet health h1 missing");
    assert!(
        html.contains(r#"action="/admin/monitoring/probe-all""#),
        "probe-all POST form missing"
    );
    // Six-tile strip renders with the fleet up-count.
    assert!(
        html.contains("ed-status-strip") && html.contains("1 / 1 up"),
        "fleet tile must show 1 / 1 up"
    );
    // Mem peak 75% crosses the 70 heat watermark → warm tile.
    assert!(
        html.contains(r#"class="ed-status-tile warn""#),
        "mem-peak tile above 70% must render warm"
    );
    // Uptime table: dense grid with the server link + 100% (1 up probe).
    assert!(
        html.contains(r#"class="ed-grid__id" href="/admin/servers/s0""#),
        "uptime row must link the server"
    );
    // Thresholds table shows the monitor's REAL constants.
    assert!(
        html.contains("mem_used_pct") && html.contains("95%"),
        "threshold table must show the real mem trigger (95%)"
    );
    assert!(
        html.contains("disk_used_pct") && html.contains("90%"),
        "threshold table must show the real disk trigger (90%)"
    );
    assert!(
        html.contains("singbox_log_mib") && html.contains("500"),
        "threshold table must show the 500 MiB log trigger"
    );
    // GeoIP line renders (files absent in test env → «missing») and
    // points at Settings instead of a state-changing GET.
    assert!(
        html.contains("/admin/settings/system#geoip"),
        "GeoIP line must link to the Settings System tab"
    );
    // The old sub-access analytics are gone.
    assert!(
        !html.contains("hits · 24h") && !html.contains("Hourly hits"),
        "sub-access KPIs must be gone from the monitoring page"
    );
}

#[tokio::test]
async fn api_stats_sub_access_returns_well_formed_json() {
    use http_body_util::BodyExt;
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await;
    s.inv
        .log_sub_access(&UserId("u0".into()), "1.1.1.1", None, 200, 500)
        .await
        .unwrap();
    let app = router(s);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/stats/sub-access")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(ct.starts_with("application/json"), "ct: {ct}");

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["bucket"], "hour", "default bucket=hour");
    assert_eq!(v["since_hours"], 24, "default since_hours=24");
    let buckets = v["buckets"].as_array().expect("buckets array");
    assert!(!buckets.is_empty(), "should have at least one bucket");
    assert_eq!(buckets[0]["hits"], 1);
    assert_eq!(buckets[0]["distinct_ips"], 1);
    assert!(buckets[0]["ts"].is_string(), "ts must be ISO-8601 string");
}

#[tokio::test]
async fn api_stats_sub_access_rejects_invalid_bucket() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/stats/sub-access?bucket=fortnight")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "unknown bucket kind must be 400"
    );
}

#[tokio::test]
async fn admin_dashboard_shows_limit_alerts_when_user_over_threshold() {
    use chrono::Utc;
    use vpnctl_core::{KernelId, Server, ServerId, User, UserId};
    use vpnctl_inventory::VpnStatsDelta;
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_user(&User {
            id: UserId("heavy".into()),
            uuid: "uuid-h".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    s.inv
        .add_server(&Server {
            id: ServerId("sb".into()),
            address: "203.0.113.7".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    // 1 GiB cap, 80% threshold; record 900 MiB usage → 87% → alert.
    s.inv
        .set_user_traffic_limit(&UserId("heavy".into()), Some(1_073_741_824), Some(80))
        .await
        .unwrap();
    let deltas = vec![VpnStatsDelta {
        user_id: Some(UserId("heavy".into())),
        upload_bytes: 500 * 1024 * 1024,
        download_bytes: 400 * 1024 * 1024,
        active_connections: 1,
    }];
    s.inv
        .record_vpn_stats(&ServerId("sb".into()), &deltas)
        .await
        .unwrap();
    // Suppress unused-import warning (Utc was for record_vpn_stats_at
    // signature; record_vpn_stats stamps internally).
    let _ = Utc::now();
    // Dashboard 1b: limit crossings no longer get a dedicated card —
    // the health-monitor fires a `user.traffic_limit:<uid>` alert
    // (Bundle 4) and the dashboard surfaces it through the health
    // feed. Seed the alert row the monitor would have written.
    s.inv
        .insert_alert_if_no_unacked(
            "user.traffic_limit:heavy",
            None,
            "warning",
            "heavy at 87% of monthly limit",
            None,
        )
        .await
        .unwrap();
    let app = router(s);
    let html = fetch_html(app, "/admin/").await;
    assert!(
        html.contains("Health feed"),
        "health feed missing on dashboard"
    );
    assert!(
        html.contains("user.traffic_limit"),
        "feed row must name the limit-alert kind"
    );
    assert!(
        html.contains(r#"href="/admin/users/heavy""#),
        "user-scoped alert must link the user from the kind suffix"
    );
}

#[tokio::test]
async fn track_1_3_suspicious_local_ip_fires_for_localhost_with_unknown_ua() {
    // Pavel's exact scenario: a row with `ip = 127.0.0.1` AND a UA
    // outside the allowlist MUST raise the alert.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await;
    let inv = s.inv.clone();
    enqueue_one_and_drain(&s, "u0", "127.0.0.1", Some("v2rayN / Windows")).await;

    let alerts = inv.recent_alerts(10, false).await.unwrap();
    let suspicious: Vec<_> = alerts
        .iter()
        .filter(|a| a.kind.starts_with("sub_access.suspicious_local_ip:"))
        .collect();
    assert_eq!(
        suspicious.len(),
        1,
        "exactly one suspicious-local-ip alert must fire for u0 + 127.0.0.1 + non-allowlisted UA"
    );
    let a = suspicious[0];
    assert_eq!(a.kind, "sub_access.suspicious_local_ip:u0");
    assert_eq!(a.severity, "warning");
    assert!(
        a.summary.contains("127.0.0.1"),
        "summary must surface the IP, got {}",
        a.summary
    );
    assert!(
        a.summary.contains("loopback"),
        "summary must surface the IP-kind label, got {}",
        a.summary
    );
    // Payload MUST NOT carry any user-secrets (sub_token, uuid,
    // wireguard_private, tuic_password). Pin via raw substring
    // search on the JSON.
    let payload_str = a.payload_json.as_deref().unwrap_or("").to_string();
    for secret in &["sub_token", "wireguard_private", "tuic_password", "uuid"] {
        assert!(
            !payload_str.contains(secret),
            "alert payload must not leak `{secret}`, got: {payload_str}"
        );
    }
}

#[tokio::test]
async fn track_1_3_suspicious_local_ip_phase6_monitor_canary_is_exempt() {
    // The /etc/cron.d/phase6-monitor canary hits localhost every
    // day at 09:00 UTC. Its UA is tagged `phase6-monitor/1.0`,
    // which `parse_ua_short` collapses to `"phase6-monitor (canary)"`.
    // That's the SINGLE allowlist entry — must NOT trigger.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await;
    let inv = s.inv.clone();
    enqueue_one_and_drain(&s, "u0", "127.0.0.1", Some("phase6-monitor (canary)")).await;
    let n = inv.unacked_alert_count().await.unwrap();
    assert_eq!(
        n, 0,
        "phase6-monitor canary on localhost must NOT raise the alert (allowlist)"
    );
}

#[tokio::test]
async fn track_1_3_suspicious_local_ip_public_ip_never_fires() {
    // Symmetric: a Public IP (8.8.8.8) must NOT fire regardless of
    // UA. Pins the `IpKind::Public` arm so a future expansion of
    // `classify_ip` (e.g. adding CGNAT 100.64/10) can't accidentally
    // flag real external clients.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await;
    let inv = s.inv.clone();
    enqueue_one_and_drain(&s, "u0", "8.8.8.8", Some("v2rayN / Windows")).await;
    let n = inv.unacked_alert_count().await.unwrap();
    assert_eq!(n, 0, "public IP must NEVER raise the alert");
}

#[tokio::test]
async fn track_1_3_suspicious_local_ip_dedup_is_per_user() {
    // Fire two suspicious rows for u0 + one for u1 → exactly 2
    // unacked alerts (one per user). The partial UNIQUE index on
    // (kind, COALESCE(server_id,'__GLOBAL__')) WHERE acked_at IS NULL
    // gives each user their own dedup bucket via the
    // `:<user_id>` suffix in the kind string.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 2, &[]).await;
    let inv = s.inv.clone();
    enqueue_one_and_drain(&s, "u0", "127.0.0.1", Some("v2rayN / Windows")).await;
    enqueue_one_and_drain(&s, "u0", "192.168.0.5", Some("curl")).await;
    enqueue_one_and_drain(&s, "u1", "10.0.0.7", Some("curl")).await;
    let alerts = inv.recent_alerts(10, false).await.unwrap();
    let suspicious: std::collections::HashSet<String> = alerts
        .iter()
        .filter(|a| a.kind.starts_with("sub_access.suspicious_local_ip:"))
        .map(|a| a.kind.clone())
        .collect();
    assert_eq!(
        suspicious.len(),
        2,
        "expected 2 per-user buckets, got: {suspicious:?}"
    );
    assert!(suspicious.contains("sub_access.suspicious_local_ip:u0"));
    assert!(suspicious.contains("sub_access.suspicious_local_ip:u1"));
}

// ── Bulk-ack alerts ─────────────────────────────────────────────────
//
// New `/admin/alerts/ack-all` POST + companion «ack all (N)» button
// on the alerts page header. Three tests:
//   1. Endpoint POST drains the table + writes 1 audit row
//   2. Page renders the «ack all (N)» button when unacked_total > 0
//   3. Page OMITS the button when unacked_total = 0 (don't invite misclick)

#[tokio::test]
async fn alerts_ack_all_endpoint_drains_unacked_and_redirects() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    // Seed 4 unacked + 1 already-acked.
    for i in 0..4 {
        st.inv
            .insert_alert(
                &format!("test.suspicious_local_ip:user{i}"),
                None,
                "warning",
                "test alert seeded by admin_smoke",
                Some("{}"),
            )
            .await
            .unwrap();
    }
    let pre_acked_id = st
        .inv
        .insert_alert("test.already_acked", None, "info", "pre-acked", None)
        .await
        .unwrap();
    let _ = st.inv.ack_alert(pre_acked_id).await.unwrap();
    assert_eq!(
        st.inv.unacked_alert_count().await.unwrap(),
        4,
        "preconditions: 4 unacked + 1 acked"
    );

    let app = router(st.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/alerts/ack-all")
                // CSRF middleware requires Origin == Host on mutating POSTs.
                .header("Origin", "http://127.0.0.1")
                .header("Host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // POST-redirect-GET — same convention as per-row ack.
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        resp.headers()
            .get(axum::http::header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/admin/alerts"),
        "must 303 back to the alerts feed"
    );
    // Post-condition: all unacked drained, but the pre-acked count
    // remains untouched (acked_at preserved — that's the inventory
    // spec contract).
    assert_eq!(
        st.inv.unacked_alert_count().await.unwrap(),
        0,
        "ack-all must drain unacked count to 0"
    );
    // Audit row must exist with action=alerts.ack_all and count=4
    // (the 4 newly-acked rows, NOT 5 — pre-acked wasn't re-touched).
    let audit = st.inv.recent_audit(20).await.unwrap();
    let row = audit
        .iter()
        .find(|e| e.action == "alerts.ack_all")
        .expect("audit must contain alerts.ack_all row");
    let payload = row.payload.as_ref().expect("payload required");
    assert_eq!(
        payload.get("count").and_then(|v| v.as_u64()),
        Some(4),
        "audit count must equal the rows actually touched (4), not the table size (5)"
    );
}

#[tokio::test]
async fn alerts_ack_all_endpoint_noop_when_nothing_unacked_writes_no_audit() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    // Empty table — POST should 303, drain 0, and NOT pollute audit_log.
    let pre_audit_count = st.inv.recent_audit(200).await.unwrap().len();
    let app = router(st.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/alerts/ack-all")
                .header("Origin", "http://127.0.0.1")
                .header("Host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let post_audit_count = st.inv.recent_audit(200).await.unwrap().len();
    assert_eq!(
        post_audit_count, pre_audit_count,
        "no-op ack-all must NOT write an audit row (audit-on-actual-mutation contract)"
    );
}

/// Alerts-cleanup 2026-06-10: the feed renders OPEN rows first,
/// severity-ranked (critical above info regardless of age), shows the
/// human title + what-to-do hint for known kinds, and collapses 3+
/// open suspicious-local-ip rows into one <details> group.
#[tokio::test]
async fn alerts_page_orders_titles_hints_and_collapses_spam() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    seed(&st.inv, 1, 0, &[]).await; // s0 for server-scoped alerts
    let sid = ServerId("s0".into());
    // Old info row first (lower id), then a critical — chronological
    // order would put info on top; severity order must flip them.
    st.inv
        .insert_alert(
            "server.fail2ban.up",
            Some(&sid),
            "info",
            "fail2ban recovered",
            None,
        )
        .await
        .unwrap();
    st.inv
        .insert_alert(
            "server.singbox.down",
            Some(&sid),
            "critical",
            "sing-box is no longer active",
            None,
        )
        .await
        .unwrap();
    // 3 suspicious rows → collapse threshold.
    for u in ["ua", "ub", "uc"] {
        st.inv
            .insert_alert(
                &format!("sub_access.suspicious_local_ip:{u}"),
                None,
                "warning",
                &format!("local-loop fetch · user={u}"),
                None,
            )
            .await
            .unwrap();
    }
    let html = fetch_html(router(st), "/admin/alerts").await;

    // v2 5a — family grouping: the node/fleet section renders the
    // localized titles (alert_text::render_alert), the sub_access
    // section carries the spam cluster.
    assert!(
        html.contains("sing-box down"),
        "critical localized title must render"
    );
    assert!(html.contains("fail2ban recovered"), "info row must render");
    assert!(
        html.contains("sub_access · 3"),
        "sub_access family section must count its 3 rows"
    );
    // What-to-do hint for the open critical — the localized render action.
    assert!(
        html.contains("reapplies the config"),
        "open critical must carry its localized what-to-do hint"
    );
    // v2 5a — the family grouping replaced the <details> collapse:
    // each suspicious row stays a first-class table row inside the
    // sub_access section, subject linked.
    assert!(
        html.contains(r#"href="/admin/users/ua""#) && html.contains(r#"href="/admin/users/uc""#),
        "per-user rows must link their subjects inside the sub_access section"
    );
}

/// Alerts-cleanup 2026-06-10 end-to-end: a recovery observed by
/// scan_once must CLOSE the paired open condition alert, land the
/// recovery row born-acked, and audit the auto-ack. The pieces
/// (diff_rows pairing, insert_alert_acked) are unit-tested; this pins
/// the dispatch wiring between them.
#[tokio::test]
async fn scan_once_auto_resolves_paired_alert_on_recovery() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    seed(&st.inv, 1, 0, &[]).await; // s0, sing-box kernel → probeable
    let sid = ServerId("s0".into());
    // Open condition alert, as the down-transition would have left it.
    st.inv
        .insert_alert(
            "server.singbox.down",
            Some(&sid),
            "critical",
            "sing-box is no longer active",
            None,
        )
        .await
        .unwrap();
    // Two probe rows: prev = down, cur = up (insertion order — newest
    // row wins the recent_node_health_for_server sort).
    let probe = |active: bool| {
        let inv = st.inv.clone();
        let sid = sid.clone();
        async move {
            inv.record_node_health(
                &sid,
                Some(active),
                Some(true),
                Some(1000),
                Some(20480),
                Some(500),
                Some(960),
                Some(1),
                None,
                Some(1024),
                None,
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();
        }
    };
    probe(false).await;
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    probe(true).await;

    vpnctld::health_monitor::scan_once(&st.inv).await.unwrap();

    // Paired down alert auto-acked; recovery row exists born-acked.
    assert_eq!(
        st.inv.unacked_alert_count().await.unwrap(),
        0,
        "recovery must close the open down alert and not open a new one"
    );
    let all = st.inv.recent_alerts(20, true).await.unwrap();
    let up = all
        .iter()
        .find(|a| a.kind == "server.singbox.up")
        .expect("recovery row must be recorded");
    assert!(up.acked_at.is_some(), "recovery row must be born-acked");
    // Auto-ack audited (convention from node_probe_poller).
    assert!(
        st.inv
            .recent_audit(50)
            .await
            .unwrap()
            .iter()
            .any(|e| e.action == "alert.auto_ack"
                && e.payload
                    .as_ref()
                    .is_some_and(|p| p["kind"] == "server.singbox.down")),
        "auto-resolve must write an alert.auto_ack audit row"
    );
}

/// The alerts page labels an oversized sing-box log as auto-resolving
/// "on rotate". Pin that promise through the real scan/DB dispatch path:
/// a size drop below 500 MiB must close the warning and leave a born-acked
/// recovery event in history.
#[tokio::test]
async fn scan_once_auto_resolves_singbox_log_alert_after_rotation() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    seed(&st.inv, 1, 0, &[]).await;
    let sid = ServerId("s0".into());
    st.inv
        .insert_alert(
            "server.singbox.log.too_big",
            Some(&sid),
            "warning",
            "sing-box log size crossed 500 MiB",
            None,
        )
        .await
        .unwrap();

    for bytes in [600 * 1024 * 1024, 20 * 1024 * 1024] {
        st.inv
            .record_node_health(
                &sid,
                Some(true),
                Some(true),
                Some(1000),
                Some(20480),
                Some(500),
                Some(960),
                Some(1),
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
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    vpnctld::health_monitor::scan_once(&st.inv).await.unwrap();

    assert_eq!(
        st.inv.unacked_alert_count().await.unwrap(),
        0,
        "log rotation must close the open too-big alert"
    );
    let all = st.inv.recent_alerts(20, true).await.unwrap();
    let recovered = all
        .iter()
        .find(|a| a.kind == "server.singbox.log.recovered")
        .expect("log recovery row must be recorded");
    assert!(
        recovered.acked_at.is_some(),
        "log recovery row must be born-acked"
    );
}

/// Crossing only the recovery boundary must not invent a green event when
/// no pressure alert was open. This is the normal startup case for a node
/// whose disk moves 88% → 84% without ever reaching the 90% trigger.
#[tokio::test]
async fn scan_once_does_not_record_orphan_hysteresis_recovery() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    seed(&st.inv, 1, 0, &[]).await;
    let sid = ServerId("s0".into());

    for disk_used_mib in [88, 84] {
        st.inv
            .record_node_health(
                &sid,
                Some(true),
                Some(true),
                Some(disk_used_mib),
                Some(100),
                Some(50),
                Some(100),
                Some(1),
                None,
                Some(1024),
                None,
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    vpnctld::health_monitor::scan_once(&st.inv).await.unwrap();

    assert!(
        st.inv.recent_alerts(20, true).await.unwrap().is_empty(),
        "a recovery boundary without an open condition must stay quiet"
    );
}

/// Alerts-cleanup 2026-06-10: `insert_alert_acked` rows are history-
/// only — they must not raise the unacked count and must not be
/// blocked by the partial UNIQUE open-dedup index.
#[tokio::test]
async fn insert_alert_acked_is_history_only() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    seed(&st.inv, 1, 0, &[]).await;
    let sid = ServerId("s0".into());
    let before = st.inv.unacked_alert_count().await.unwrap();
    st.inv
        .insert_alert_acked(
            "server.disk.recovered",
            Some(&sid),
            "info",
            "disk back under 85%",
            None,
        )
        .await
        .unwrap();
    // Twice — dedup index only covers open rows; history rows stack.
    st.inv
        .insert_alert_acked(
            "server.disk.recovered",
            Some(&sid),
            "info",
            "disk back under 85%",
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        st.inv.unacked_alert_count().await.unwrap(),
        before,
        "born-acked rows must not appear in the open feed"
    );
    let all = st.inv.recent_alerts(50, true).await.unwrap();
    assert_eq!(
        all.iter()
            .filter(|a| a.kind == "server.disk.recovered")
            .count(),
        2,
        "both history rows must persist (no dedup on acked)"
    );
}

#[tokio::test]
async fn alerts_page_renders_ack_all_button_when_unacked_total_nonzero() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    // Seed 2 unacked alerts so the count chip + button must render.
    for i in 0..2 {
        st.inv
            .insert_alert(
                &format!("test.something:{i}"),
                None,
                "warning",
                "smoke seed",
                None,
            )
            .await
            .unwrap();
    }
    let app = router(st);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/alerts")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        html.contains(r#"action="/admin/alerts/ack-all""#),
        "page must include a form POSTing to /admin/alerts/ack-all"
    );
    // Button label includes the count «(2)» so the operator knows
    // how many rows the click affects before submitting.
    assert!(
        html.contains("ack all") && html.contains("(2)"),
        "button must show «ack all (2)» with the current unacked count"
    );
    // CSP-safe guard: the confirm message rides in a `data-confirm`
    // attribute (admin.js attaches the confirm() dialog). An inline
    // `onsubmit` would be blocked by `script-src 'self'` and the guard
    // would silently never run.
    assert!(
        html.contains("data-confirm="),
        "ack-all form must carry a data-confirm attribute for admin.js"
    );
    assert!(
        !html.contains("onsubmit="),
        "no inline onsubmit on the alerts page (CSP script-src 'self' blocks it)"
    );
}

#[tokio::test]
async fn alerts_page_ack_all_uses_data_confirm_not_inline_js() {
    // The ack-all confirm rides in a `data-confirm` attribute wired by
    // admin.js, NOT an inline `onsubmit` (CSP `script-src 'self'` would
    // block the latter, letting ack-all fire on a single click). maud
    // HTML-escapes the attribute value and admin.js reads it back via
    // getAttribute — there is no JS-string-literal layer, so translator
    // apostrophes («don't») can never break the dialog.
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    st.inv
        .insert_alert("test.x", None, "warning", "x", None)
        .await
        .unwrap();
    let app = router(st);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/alerts")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    // The English confirm copy must appear as a data-confirm value.
    assert!(
        html.contains(r#"data-confirm="Ack all unacked alerts?"#),
        "ack-all form must carry the confirm message in data-confirm"
    );
    assert!(
        !html.contains("onsubmit="),
        "ack-all must not use an inline onsubmit handler (CSP-blocked)"
    );
}

#[tokio::test]
async fn alerts_page_omits_ack_all_button_when_no_unacked() {
    // Quiet feed should NOT render an «ack all (0)» button — the
    // count would be 0 and clicking would be a no-op invitation
    // for misclicks.
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    let app = router(st);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/alerts")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        !html.contains(r#"action="/admin/alerts/ack-all""#),
        "ack-all form must NOT render when unacked_total = 0"
    );
}

/// v2 5a gap-close — the sub_access family header carries a group-ack
/// button that acks the whole family via the prefix route.
#[tokio::test]
async fn v2_alerts_sub_access_family_group_ack() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    for u in ["a", "b", "c"] {
        s.inv
            .insert_alert(
                &format!("sub_access.suspicious_local_ip:{u}"),
                None,
                "warning",
                "loop",
                None,
            )
            .await
            .unwrap();
    }
    let html = fetch_html(router(s.clone()), "/admin/alerts").await;
    assert!(
        html.contains(r#"action="/admin/alerts/ack-family/sub_access.""#),
        "sub_access family must expose a group-ack form"
    );
    assert!(
        html.contains("ack all ") && html.contains("(3)"),
        "group-ack button must show the unacked family count"
    );
    // The prefix route acks the whole family.
    let n = s
        .inv
        .ack_unacked_by_kind_prefix("sub_access.")
        .await
        .unwrap();
    assert_eq!(n, 3, "prefix ack must clear all 3 family rows");
    assert_eq!(
        s.inv.unacked_alert_count().await.unwrap(),
        0,
        "no unacked alerts remain after the family ack"
    );
}

/// v2 5a — the family-ack route rejects an arbitrary prefix (can't be
/// abused to ack a single crafted kind).
#[tokio::test]
async fn v2_alerts_ack_family_rejects_unknown_prefix() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let resp = router(s)
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/alerts/ack-family/user.traffic_limit"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
