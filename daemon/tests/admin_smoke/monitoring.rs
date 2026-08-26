//! Admin UI smoke tests for /admin/monitoring and probe-all endpoints.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{KernelId, ProtocolId, Server, ServerId};
use vpnctld::router;

use super::common::*;

// ────────────────────────────────────────────────────────────────────────
//  POST /admin/monitoring/probe-all
//
//  Design v2 3a: «probe all now» manual probe sweep button on the
//  monitoring page. Sequential SSH probe across all servers in inventory,
//  audits with action "monitoring.probe_all" and payload `{"servers": N}`,
//  and redirects back to /admin/monitoring via 303 See Other.
// ────────────────────────────────────────────────────────────────────────

/// POST /admin/monitoring/probe-all without same-origin headers must be
/// rejected by CSRF middleware with 403 Forbidden.
#[tokio::test]
async fn probe_all_csrf_rejection_missing_or_mismatched_origin() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    // 1. Missing Origin + Host headers entirely
    let req = Request::builder()
        .method("POST")
        .uri("/admin/monitoring/probe-all")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "POST without origin/host must return 403"
    );
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let s = String::from_utf8_lossy(&body);
    assert!(
        s.contains("vpnctl admin: csrf"),
        "CSRF rejection body must match contract: {s}"
    );

    // 2. Mismatched Origin vs Host header (cross-site attempt)
    let req = Request::builder()
        .method("POST")
        .uri("/admin/monitoring/probe-all")
        .header("host", SAME_ORIGIN_HOST)
        .header("origin", "http://evil.attacker.example")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "cross-origin POST must return 403"
    );
}

/// GET /admin/monitoring/probe-all is not a valid method (route is POST-only)
/// and must return 405 Method Not Allowed.
#[tokio::test]
async fn probe_all_rejects_get_method() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    let req = Request::builder()
        .method("GET")
        .uri("/admin/monitoring/probe-all")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::METHOD_NOT_ALLOWED,
        "GET /admin/monitoring/probe-all must return 405"
    );
}

/// POST /admin/monitoring/probe-all on an empty inventory executes cleanly,
/// records an audit entry with `servers: 0`, and redirects to /admin/monitoring.
#[tokio::test]
async fn probe_all_empty_inventory_no_op() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    let app = router(s);

    let req = add_same_origin(
        Request::builder()
            .method("POST")
            .uri("/admin/monitoring/probe-all"),
    )
    .body(Body::empty())
    .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "probe-all must return 303 See Other redirect"
    );
    assert_eq!(
        resp.headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap(),
        "/admin/monitoring",
        "Location header must point to /admin/monitoring"
    );

    // Audit verification
    let audits = inv.recent_audit(10).await.unwrap();
    let probe_audits: Vec<_> = audits
        .into_iter()
        .filter(|a| a.action == "monitoring.probe_all")
        .collect();
    assert_eq!(probe_audits.len(), 1, "must record exactly one audit entry");
    let entry = &probe_audits[0];
    assert_eq!(entry.actor, "admin");
    assert_eq!(entry.target, None);
    assert_eq!(
        entry.payload.as_ref(),
        Some(&serde_json::json!({ "servers": 0 })),
        "audit payload must specify 0 servers"
    );
}

/// POST /admin/monitoring/probe-all triggers sweep across all servers in
/// inventory, records audit row with the count of probed servers, and redirects.
#[tokio::test]
async fn probe_all_triggers_sweep_and_audits_server_count() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 3, 0, &[]).await;
    let inv = s.inv.clone();
    let app = router(s);

    let req = add_same_origin(
        Request::builder()
            .method("POST")
            .uri("/admin/monitoring/probe-all"),
    )
    .body(Body::empty())
    .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "probe-all must 303 redirect"
    );
    assert_eq!(
        resp.headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap(),
        "/admin/monitoring"
    );

    // Verify audit record
    let audits = inv.recent_audit(10).await.unwrap();
    let probe_audits: Vec<_> = audits
        .into_iter()
        .filter(|a| a.action == "monitoring.probe_all")
        .collect();
    assert_eq!(probe_audits.len(), 1);
    let entry = &probe_audits[0];
    assert_eq!(entry.actor, "admin");
    assert_eq!(entry.target, None);
    assert_eq!(
        entry.payload.as_ref(),
        Some(&serde_json::json!({ "servers": 3 })),
        "audit payload must record 3 servers"
    );

    // Verify monitoring page continues to render 200 OK after the sweep
    let html = fetch_html(app, "/admin/monitoring").await;
    assert!(
        html.contains("Fleet"),
        "monitoring page must render successfully"
    );
    assert!(html.contains(r#"action="/admin/monitoring/probe-all""#));
}

/// POST /admin/monitoring/probe-all handles heterogeneous server configurations
/// (e.g. sing-box, caddy/naive) without error or panic.
#[tokio::test]
async fn probe_all_handles_heterogeneous_server_topologies() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;

    // Server 1: standard sing-box server
    s.inv
        .add_server(&Server {
            id: ServerId("s0-singbox".into()),
            address: "10.0.0.1".into(),
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

    // Server 2: naive/caddy server (non-sing-box kernel)
    s.inv
        .add_server(&Server {
            id: ServerId("s1-naive".into()),
            address: "10.0.0.2".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("caddy".into())],
            enabled_protocols: vec![ProtocolId("naive".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();

    let inv = s.inv.clone();
    let app = router(s);

    let req = add_same_origin(
        Request::builder()
            .method("POST")
            .uri("/admin/monitoring/probe-all"),
    )
    .body(Body::empty())
    .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        resp.headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap(),
        "/admin/monitoring"
    );

    let audits = inv.recent_audit(10).await.unwrap();
    let probe_audits: Vec<_> = audits
        .into_iter()
        .filter(|a| a.action == "monitoring.probe_all")
        .collect();
    assert_eq!(probe_audits.len(), 1);
    assert_eq!(
        probe_audits[0].payload.as_ref(),
        Some(&serde_json::json!({ "servers": 2 })),
        "audit payload must count both servers"
    );
}

/// Multiple invocations of POST /admin/monitoring/probe-all sequentially
/// record distinct audit entries per invocation.
#[tokio::test]
async fn probe_all_sequential_invocations_audit_each_run() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    let inv = s.inv.clone();

    // First invocation
    let resp1 = router(s.clone())
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/monitoring/probe-all"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp1.status(), StatusCode::SEE_OTHER);

    // Second invocation
    let resp2 = router(s)
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/monitoring/probe-all"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp2.status(), StatusCode::SEE_OTHER);

    let audits = inv.recent_audit(10).await.unwrap();
    let probe_audits: Vec<_> = audits
        .into_iter()
        .filter(|a| a.action == "monitoring.probe_all")
        .collect();
    assert_eq!(
        probe_audits.len(),
        2,
        "each probe-all run must write its own audit entry"
    );
}
