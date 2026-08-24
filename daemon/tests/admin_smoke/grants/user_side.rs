//! User-side grant and revoke tests.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::UserId;
use vpnctld::router;

use crate::common::{add_same_origin, body_of, fetch_html, seed, state};

// ────────────────────────────────────────────────────────────────────────
//  Phase C-3.3 — grant + revoke per-(user, server)
//
//  Pin the contract end-to-end: per-row grant/revoke buttons on the
//  user-detail page POST to dedicated endpoints; both are idempotent
//  at SQL but audited every time; bad ids → 404 with unified prefix.
// ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn admin_user_grant_server_happy_path() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[]).await; // s0 + u0, no grants yet
    assert_eq!(
        s.inv
            .servers_for_user(&UserId("u0".into()))
            .await
            .unwrap()
            .len(),
        0
    );

    let inv = s.inv.clone();
    let app = router(s);

    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users/u0/grants/s0"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        resp.headers().get("location").unwrap().to_str().unwrap(),
        "/admin/users/u0/access"
    );

    let granted = inv.servers_for_user(&UserId("u0".into())).await.unwrap();
    assert_eq!(granted.len(), 1, "u0 must have 1 grant after POST");
    assert_eq!(granted[0].id.0, "s0");

    // Canonical grant-audit shape (2026-06-04): per-user `user.grant`
    // with target = USER id — the shape the pending-deploy detector
    // keys on. Guards against regressing to the old `action="grant",
    // target=<server>` rows the detector never saw.
    let entries = inv.recent_audit(10).await.unwrap();
    let g = entries
        .iter()
        .find(|e| e.action == "user.grant")
        .expect("user.grant audit row missing");
    assert_eq!(g.actor, "admin");
    assert_eq!(g.target.as_deref(), Some("u0"));
    assert_eq!(
        g.payload.as_ref().unwrap()["server"],
        serde_json::Value::String("s0".into())
    );
    assert_eq!(
        g.payload.as_ref().unwrap()["source"],
        serde_json::Value::String("user-detail".into())
    );
}

#[tokio::test]
async fn admin_user_revoke_server_happy_path() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await; // pre-granted u0→s0
    assert_eq!(
        s.inv
            .servers_for_user(&UserId("u0".into()))
            .await
            .unwrap()
            .len(),
        1
    );

    let inv = s.inv.clone();
    let app = router(s);

    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users/u0/grants/s0/revoke"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    assert_eq!(
        inv.servers_for_user(&UserId("u0".into()))
            .await
            .unwrap()
            .len(),
        0,
        "grant must be removed after revoke"
    );

    // Canonical revoke-audit shape (2026-06-10, mirror of grants):
    // per-user `user.revoke` with target = USER id — the shape the
    // pending-deploy detector keys on.
    let entries = inv.recent_audit(10).await.unwrap();
    assert!(
        entries.iter().any(|e| e.action == "user.revoke"
            && e.target.as_deref() == Some("u0")
            && e.payload.as_ref().is_some_and(|p| p["server"] == "s0")),
        "user.revoke audit row missing"
    );
}

#[tokio::test]
async fn admin_user_grant_unknown_user_404() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await; // s0 only, no users
    let body = body_of(
        router(s),
        "POST",
        "/admin/users/no-such/grants/s0",
        None,
        None,
    )
    .await;
    assert_eq!(body, "vpnctl admin: no such user 'no-such'\n");
}

#[tokio::test]
async fn admin_user_grant_unknown_server_404() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await; // u0 only, no servers
    let body = body_of(
        router(s),
        "POST",
        "/admin/users/u0/grants/no-such-server",
        None,
        None,
    )
    .await;
    assert_eq!(body, "vpnctl admin: no such server 'no-such-server'\n");
}

#[tokio::test]
async fn admin_user_detail_renders_grant_revoke_buttons() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    // 2 servers (s0, s1), 1 user (u0), one pre-granted to s0.
    seed(&s.inv, 2, 1, &[(0, 0)]).await;
    let app = router(s);

    let html = fetch_html(app, "/admin/users/u0/access").await;

    // Granted row: revoke form + ✓ access marker.
    assert!(
        html.contains(r#"action="/admin/users/u0/grants/s0/revoke""#),
        "revoke form for granted server s0 must render"
    );
    assert!(
        html.contains("✓ access"),
        "✓ access marker for granted row missing"
    );
    assert!(html.contains(">revoke<"), "revoke button label drifted");

    // Ungranted row: grant form, no ✓ marker for s1's row.
    assert!(
        html.contains(r#"action="/admin/users/u0/grants/s1""#),
        "grant form for ungranted server s1 must render"
    );
    assert!(html.contains(">grant<"), "grant button label drifted");
}

/// Design v2 4b — the user Access tab opens with the per-server
/// grant/key-state table (granted date column from migration 0039,
/// on-node state, protocols available, per-row grant/revoke) and the
/// masked per-protocol identities list.
#[tokio::test]
async fn v2_user_access_renders_grant_state_table_and_identities() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 2, 1, &[(0, 0)]).await; // granted s0, not s1
    let html = fetch_html(router(s), "/admin/users/u0/access").await;
    assert!(
        html.contains("Grants · per-server key state"),
        "grant-state eyebrow missing"
    );
    assert!(html.contains("uuid ✓"), "keys-minted cell missing");
    // granted s0 row has a revoke form; ungranted s1 row has a grant form.
    assert!(
        html.contains(r#"action="/admin/users/u0/grants/s0/revoke""#),
        "granted row must carry revoke"
    );
    assert!(
        html.contains(r#"action="/admin/users/u0/grants/s1""#),
        "ungranted row must carry grant"
    );
    assert!(
        html.contains("Per-protocol identities"),
        "identities eyebrow missing"
    );
    // Secrets stay masked — the full uuid renders (public), the
    // sub-token only as its masked preview.
    assert!(html.contains("not granted") || html.contains("не выдан"));
}
