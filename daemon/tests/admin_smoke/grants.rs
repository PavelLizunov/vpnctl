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

/// REGRESSION (review 2026-06-04): a grant made through ANY real
/// handler must be visible to the pending-deploy detector even after
/// the server already has a deploy baseline. The handlers used to
/// write `action="grant", target=<server>` (and bulk only a summary
/// row) — invisible to `servers_pending_deploy_for_user`, which keys
/// on `user.grant` + target=<user>. So a grant made AFTER the
/// server's first deploy never raised the «config not yet deployed»
/// banner and the node silently missed the user's UUID.
///
/// Seeded users carry ZERO audit rows (raw `inv.add_user`), so the
/// only possible user-mutation timestamp is the one the handler under
/// test writes — if it regresses to the old shape, the detector sees
/// no mutations and the assertions fail.
#[tokio::test]
async fn grants_via_real_handlers_mark_server_pending_deploy() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    seed(&inv, 3, 3, &[]).await; // s0..s2 + u0..u2, no grants yet

    // Deploy BASELINE first — the regression only bites once a
    // `server.deploy` row exists (before that the "no deploy ever"
    // branch masks the missing user.grant rows).
    for sid in ["s0", "s1", "s2"] {
        inv.audit("admin", "server.deploy", Some(sid), None)
            .await
            .unwrap();
    }
    // Audit ts has millisecond precision; guarantee the grants below
    // land strictly AFTER the baseline rows.
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    let app = router(s);

    // 1. user-detail grant handler.
    app.clone()
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
    let pending = inv
        .servers_pending_deploy_for_user(&UserId("u0".into()), &[ServerId("s0".into())])
        .await
        .unwrap();
    assert_eq!(
        pending,
        vec![ServerId("s0".into())],
        "user-detail grant must mark s0 pending-deploy"
    );

    // 2. server-detail grant handler.
    app.clone()
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/s1/grants/u1"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    let pending = inv
        .servers_pending_deploy_for_user(&UserId("u1".into()), &[ServerId("s1".into())])
        .await
        .unwrap();
    assert_eq!(
        pending,
        vec![ServerId("s1".into())],
        "server-detail grant must mark s1 pending-deploy"
    );

    // 3. bulk grant-all handler (writes per-user rows for NEW grants).
    app.clone()
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/s2/grants/_grant-all"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    let pending = inv
        .servers_pending_deploy_for_user(&UserId("u2".into()), &[ServerId("s2".into())])
        .await
        .unwrap();
    assert_eq!(
        pending,
        vec![ServerId("s2".into())],
        "bulk grant-all must mark s2 pending-deploy for each newly-granted user"
    );

    // 4. Idempotency contract (review-agent): RE-running a grant (or
    // grant-all) must NOT write fresh user.grant rows — a no-op
    // re-grant would otherwise falsely re-mark the server pending
    // after the operator's next deploy.
    let count_user_grants = |entries: &[vpnctl_inventory::AuditEntry]| {
        entries.iter().filter(|e| e.action == "user.grant").count()
    };
    let before = count_user_grants(&inv.recent_audit(100).await.unwrap());
    for uri in [
        "/admin/users/u0/grants/s0",
        "/admin/servers/s1/grants/u1",
        "/admin/servers/s2/grants/_grant-all",
    ] {
        app.clone()
            .oneshot(
                add_same_origin(Request::builder().method("POST").uri(uri))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
    }
    let after = count_user_grants(&inv.recent_audit(100).await.unwrap());
    assert_eq!(
        before, after,
        "idempotent re-grants must not add user.grant rows (false pending-deploy)"
    );
}

/// REGRESSION (audit 2026-06-10, re-scoped 2026-07-10) — a REVOKE
/// through any real handler must stay visible to the pending-deploy
/// detectors. The handlers used to write `action="revoke",
/// target=<server>` (bulk only a summary), invisible to the detectors
/// — so a revoked UUID stayed live on the node with no warning
/// anywhere. Post-scoping the contract is: the REVOKED server is
/// flagged by the SERVER-side detector (`server_pending_deploy`,
/// membership changed since last deploy), while the user's REMAINING
/// servers stay quiet — their configs didn't change, and the old
/// coarse any-mutation-flags-everything reading produced a permanent
/// phantom banner after every grant/revoke (design review 2026-07-10).
#[tokio::test]
async fn revokes_via_real_handlers_flag_only_the_revoked_server() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    // u0 granted s0+s1; u1 granted s1+s2 (raw seed → zero audit rows).
    seed(&inv, 3, 2, &[(0, 0), (0, 1), (1, 1), (1, 2)]).await;
    for sid in ["s0", "s1", "s2"] {
        inv.audit("admin", "server.deploy", Some(sid), None)
            .await
            .unwrap();
    }
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    let app = router(s);

    // 1. user-detail revoke: u0 loses s0 → the REVOKED server flags on
    //    the server-side detector; the untouched remaining server (s1)
    //    stays quiet on the per-user surface.
    app.clone()
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
    assert!(
        inv.server_pending_deploy(&ServerId("s0".into()))
            .await
            .unwrap(),
        "revoked server must flag on the server-side detector"
    );
    let pending = inv
        .servers_pending_deploy_for_user(&UserId("u0".into()), &[ServerId("s1".into())])
        .await
        .unwrap();
    assert!(
        pending.is_empty(),
        "revoke of s0 must NOT flag the untouched s1 (scoped detector), got {pending:?}"
    );

    // 2. server-detail revoke: same contract from the other handler.
    app.clone()
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/s1/grants/u1/revoke"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        inv.server_pending_deploy(&ServerId("s1".into()))
            .await
            .unwrap(),
        "revoked server must flag on the server-side detector (server-detail path)"
    );
    let pending = inv
        .servers_pending_deploy_for_user(&UserId("u1".into()), &[ServerId("s2".into())])
        .await
        .unwrap();
    assert!(
        pending.is_empty(),
        "revoke of s1 must NOT flag the untouched s2 (scoped detector), got {pending:?}"
    );

    // 3. Canonical row shape + idempotency: re-revoking writes nothing.
    let count_revokes = |entries: &[vpnctl_inventory::AuditEntry]| {
        entries.iter().filter(|e| e.action == "user.revoke").count()
    };
    let entries = inv.recent_audit(100).await.unwrap();
    let r = entries
        .iter()
        .find(|e| e.action == "user.revoke" && e.target.as_deref() == Some("u0"))
        .expect("user.revoke row with target=USER id missing");
    assert_eq!(r.payload.as_ref().unwrap()["server"], "s0");
    let before = count_revokes(&entries);
    for uri in [
        "/admin/users/u0/grants/s0/revoke",
        "/admin/servers/s1/grants/u1/revoke",
    ] {
        app.clone()
            .oneshot(
                add_same_origin(Request::builder().method("POST").uri(uri))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
    }
    let after = count_revokes(&inv.recent_audit(100).await.unwrap());
    assert_eq!(
        before, after,
        "idempotent re-revokes must not add user.revoke rows"
    );

    // 4. server-detail revoke of an UNKNOWN user must 404 (the grant
    // twin always had the existence check; revoke silently 303'd).
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/s1/grants/no-such-user/revoke"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
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

#[tokio::test]
async fn admin_server_grant_user_persists_and_redirects_to_server() {
    use vpnctl_core::{KernelId, Server, ServerId, User, UserId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
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
    s.inv
        .add_user(&User {
            id: UserId("alice".into()),
            uuid: "uuid-a".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    let app = router(s);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/sb/grants/alice"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    // Redirect target should be the SERVER page, not the user page.
    let loc = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert_eq!(loc, "/admin/servers/sb/grants");
    // Mutation landed.
    let users_on_server = inv.users_for_server(&ServerId("sb".into())).await.unwrap();
    assert!(users_on_server.iter().any(|u| u.id.0 == "alice"));
}

// ────────────────────────────────────────────────────────────────────────
// NM-10 — protocol visibility UI (server-detail hide/unhide chip +
// user-detail per-protocol delivery grid). Backend handlers landed in
// cd71cf9; these tests pin the corresponding UI surfaces so a future
// HTML refactor can't silently drop the toggle. Each test exercises a
// distinct rule: hidden-chip render, visible-chip render, POST mutation
// round-trip, per-grant grid presence, server-hidden read-only marker,
// override-blocks-render check, ungranted-server-suppression.

#[tokio::test]
async fn nm10_server_detail_visible_protocol_shows_hide_button() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("hidesrv".into()),
            address: "203.0.113.10".into(),
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
    let html = fetch_html(router(s), "/admin/servers/hidesrv/protocols").await;
    // Visible (hidden=0) protocol: shows "✓ on" without the "· hidden"
    // suffix AND offers a hide button (no unhide).
    assert!(
        html.contains("✓ on") && !html.contains("✓ on · hidden"),
        "visible enabled protocol should show plain ✓ on marker"
    );
    assert!(
        html.contains(r#"/admin/servers/hidesrv/protocols/vless%2Breality/hide"#),
        "visible protocol must offer a hide button (POST /hide)"
    );
    assert!(
        !html.contains(r#"/admin/servers/hidesrv/protocols/vless%2Breality/unhide"#),
        "visible protocol must NOT offer an unhide button"
    );
}

#[tokio::test]
async fn nm10_server_detail_hidden_protocol_shows_unhide_button() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("hidesrv".into()),
            address: "203.0.113.10".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![ProtocolId("tuic-v5".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    s.inv
        .set_server_protocol_hidden(
            &ServerId("hidesrv".into()),
            &ProtocolId("tuic-v5".into()),
            true,
        )
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/servers/hidesrv/protocols").await;
    assert!(
        html.contains("✓ on · hidden"),
        "hidden protocol must surface the · hidden suffix on its status chip"
    );
    assert!(
        html.contains(r#"/admin/servers/hidesrv/protocols/tuic-v5/unhide"#),
        "hidden protocol must offer an unhide button (POST /unhide)"
    );
    assert!(
        !html.contains(r#"/admin/servers/hidesrv/protocols/tuic-v5/hide""#),
        "hidden protocol must NOT offer a redundant hide button"
    );
}

#[tokio::test]
async fn nm10_server_detail_post_hide_persists_and_redirects() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    s.inv
        .add_server(&Server {
            id: ServerId("hsrv".into()),
            address: "203.0.113.11".into(),
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
    let app = router(s);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/hsrv/protocols/vless%2Breality/hide"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(
        location, "/admin/servers/hsrv/protocols#enabled-protocols",
        "303 must redirect back to /admin/servers/{{id}}#enabled-protocols so the browser scrolls the operator back to the section they just clicked in (Pavel 2026-05-20: «каждый раз когда я жму disable меня выкидывает в верх страницы»)"
    );
    assert!(
        inv.is_server_protocol_hidden(
            &ServerId("hsrv".into()),
            &ProtocolId("vless+reality".into())
        )
        .await
        .unwrap(),
        "hidden flag must persist after POST /hide"
    );
    let audit = inv.recent_audit(5).await.unwrap();
    assert!(
        audit
            .iter()
            .any(|a| a.action == "server.protocol.set_hidden"),
        "POST /hide must write an audit row"
    );
}

#[tokio::test]
async fn nm10_user_detail_per_protocol_grid_renders_for_granted_server() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_user(&User {
            id: UserId("alice".into()),
            uuid: "00000000-0000-0000-0000-000000000001".to_string(),
            sub_token: Some("t1".into()),
            wireguard_pubkey: None,
            wireguard_private: None,
            tuic_password: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    s.inv
        .add_server(&Server {
            id: ServerId("gridsrv".into()),
            address: "203.0.113.12".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![
                ProtocolId("vless+reality".into()),
                ProtocolId("tuic-v5".into()),
            ],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    s.inv
        .grant(&UserId("alice".into()), &ServerId("gridsrv".into()))
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/users/alice/access").await;
    assert!(
        html.contains("Per-protocol delivery"),
        "grid heading must appear under the granted server's row"
    );
    // Default state = delivered + block button per protocol.
    assert!(
        html.contains("✓ delivered"),
        "default delivery state should be ✓ delivered"
    );
    assert!(
        html.contains(r#"/admin/users/alice/grants/gridsrv/protocols/vless%2Breality/disable"#),
        "vless+reality must have a disable (block) form"
    );
    assert!(
        html.contains(r#"/admin/users/alice/grants/gridsrv/protocols/tuic-v5/disable"#),
        "tuic-v5 must have a disable (block) form"
    );
}

#[tokio::test]
async fn nm10_user_detail_grid_hides_when_server_not_granted() {
    // Ungranted server should NOT render the per-protocol grid —
    // overrides would refuse with Invalid anyway, and surfacing the
    // buttons creates a confusing "click does nothing" UX.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_user(&User {
            id: UserId("bob".into()),
            uuid: "00000000-0000-0000-0000-000000000002".to_string(),
            sub_token: Some("t2".into()),
            wireguard_pubkey: None,
            wireguard_private: None,
            tuic_password: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    s.inv
        .add_server(&Server {
            id: ServerId("notgranted".into()),
            address: "203.0.113.13".into(),
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
    // No grant() call.
    let html = fetch_html(router(s), "/admin/users/bob/access").await;
    assert!(
        !html.contains(r#"/admin/users/bob/grants/notgranted/protocols/vless%2Breality/disable"#),
        "ungranted server must NOT expose the per-protocol disable form"
    );
}

#[tokio::test]
async fn nm10_user_detail_grid_marks_server_hidden_readonly() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_user(&User {
            id: UserId("carol".into()),
            uuid: "00000000-0000-0000-0000-000000000003".to_string(),
            sub_token: Some("t3".into()),
            wireguard_pubkey: None,
            wireguard_private: None,
            tuic_password: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    s.inv
        .add_server(&Server {
            id: ServerId("hidsrv".into()),
            address: "203.0.113.14".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![ProtocolId("tuic-v5".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    s.inv
        .grant(&UserId("carol".into()), &ServerId("hidsrv".into()))
        .await
        .unwrap();
    s.inv
        .set_server_protocol_hidden(
            &ServerId("hidsrv".into()),
            &ProtocolId("tuic-v5".into()),
            true,
        )
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/users/carol/access").await;
    // Server-hidden + no override → read-only label, NO block button.
    assert!(
        html.contains("server-hidden (read-only here)"),
        "server-hidden protocol must surface read-only marker in the grid"
    );
    assert!(
        !html.contains(r#"/admin/users/carol/grants/hidsrv/protocols/tuic-v5/disable"#),
        "server-hidden + no override should suppress the block button (would be a redundant override)"
    );
}

#[tokio::test]
async fn nm10_user_detail_grid_shows_user_blocked_marker_and_unblock_form() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_user(&User {
            id: UserId("dave".into()),
            uuid: "00000000-0000-0000-0000-000000000004".to_string(),
            sub_token: Some("t4".into()),
            wireguard_pubkey: None,
            wireguard_private: None,
            tuic_password: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    s.inv
        .add_server(&Server {
            id: ServerId("dsrv".into()),
            address: "203.0.113.15".into(),
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
    s.inv
        .grant(&UserId("dave".into()), &ServerId("dsrv".into()))
        .await
        .unwrap();
    s.inv
        .set_grant_protocol_override(
            &UserId("dave".into()),
            &ServerId("dsrv".into()),
            &ProtocolId("vless+reality".into()),
            true,
        )
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/users/dave/access").await;
    assert!(
        html.contains("✗ user-blocked"),
        "user-blocked override must surface the ✗ marker"
    );
    assert!(
        html.contains(r#"/admin/users/dave/grants/dsrv/protocols/vless%2Breality/enable"#),
        "user-blocked protocol must offer an unblock (enable) button"
    );
    assert!(
        !html.contains(r#"/admin/users/dave/grants/dsrv/protocols/vless%2Breality/disable"#),
        "user-blocked protocol must NOT redundantly offer a block button"
    );
}

#[tokio::test]
async fn nm10_user_detail_post_block_persists_and_redirects() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    s.inv
        .add_user(&User {
            id: UserId("erin".into()),
            uuid: "00000000-0000-0000-0000-000000000005".to_string(),
            sub_token: Some("t5".into()),
            wireguard_pubkey: None,
            wireguard_private: None,
            tuic_password: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    s.inv
        .add_server(&Server {
            id: ServerId("esrv".into()),
            address: "203.0.113.16".into(),
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
    s.inv
        .grant(&UserId("erin".into()), &ServerId("esrv".into()))
        .await
        .unwrap();
    let app = router(s);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users/erin/grants/esrv/protocols/vless%2Breality/disable"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(
        location, "/admin/users/erin/access#server-access",
        "303 must redirect back to /admin/users/{{uid}}#server-access so the browser scrolls the operator back to the per-protocol grid they just clicked in"
    );
    let overrides = inv
        .list_protocol_overrides_for_user(&UserId("erin".into()))
        .await
        .unwrap();
    assert!(
        overrides
            .get(&(ServerId("esrv".into()), ProtocolId("vless+reality".into())))
            .copied()
            .unwrap_or(false),
        "POST /disable must insert a disabled override"
    );
    // Auditable-write invariant (CLAUDE.md): every inventory mutation
    // writes one audit_log row. Mirrors the parallel assert on the
    // server-hide test above.
    let audit = inv.recent_audit(5).await.unwrap();
    assert!(
        audit
            .iter()
            .any(|a| a.action == "grant.protocol.set_override"),
        "POST /disable must write a grant.protocol.set_override audit row, got: {:?}",
        audit.iter().map(|a| &a.action).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn nm10_user_detail_grid_renders_both_axes_branch() {
    // The "server-hidden + user-blocked" branch (line 7501 in admin.rs)
    // is the only label where BOTH axes deny the protocol. A regression
    // collapsing the branch into "server-hidden (read-only)" would lose
    // the "unblock (user)" button — the operator's only path to clear
    // a stale per-user override on a server-hidden protocol. This test
    // pins that label + the unblock-user form so the branch can't be
    // silently deleted.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_user(&User {
            id: UserId("frank".into()),
            uuid: "00000000-0000-0000-0000-000000000006".to_string(),
            sub_token: Some("t6".into()),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    s.inv
        .add_server(&Server {
            id: ServerId("fsrv".into()),
            address: "203.0.113.17".into(),
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
    s.inv
        .grant(&UserId("frank".into()), &ServerId("fsrv".into()))
        .await
        .unwrap();
    // Set BOTH axes — server-hide AND user-block. Canonical render
    // omits via OR-semantics; UI must surface both flags so the
    // operator's mental model matches.
    s.inv
        .set_server_protocol_hidden(
            &ServerId("fsrv".into()),
            &ProtocolId("vless+reality".into()),
            true,
        )
        .await
        .unwrap();
    s.inv
        .set_grant_protocol_override(
            &UserId("frank".into()),
            &ServerId("fsrv".into()),
            &ProtocolId("vless+reality".into()),
            true,
        )
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/users/frank/access").await;
    assert!(
        html.contains("server-hidden + user-blocked"),
        "both-axes-deny branch must render the compound label"
    );
    assert!(
        html.contains(r#"/admin/users/frank/grants/fsrv/protocols/vless%2Breality/enable"#),
        "both-axes branch must STILL offer the unblock-user form (operator clears the user-axis here; server-axis on server detail)"
    );
}

#[tokio::test]
async fn nm10_user_detail_grid_iterates_table_not_in_memory_enabled_protocols() {
    // Defensive: the grid iterates `hidden_map.keys()` (the
    // `server_protocols` table rows) rather than the in-memory
    // `Server.enabled_protocols` cache, so OR-semantics resolution
    // matches `visible_protocols_for_subscription` BYTE-for-BYTE
    // even in the (rare/impossible-in-production) case where the
    // cache and table diverge. This test exercises the happy path:
    // a server with two protocols renders both rows in alphabetical
    // order matching the canonical query's ORDER BY.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_user(&User {
            id: UserId("gina".into()),
            uuid: "00000000-0000-0000-0000-000000000007".to_string(),
            sub_token: Some("t7".into()),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    s.inv
        .add_server(&Server {
            id: ServerId("gsrv".into()),
            address: "203.0.113.18".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            // Out of order on purpose — render should still sort.
            enabled_protocols: vec![
                ProtocolId("tuic-v5".into()),
                ProtocolId("vless+reality".into()),
            ],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    s.inv
        .grant(&UserId("gina".into()), &ServerId("gsrv".into()))
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/users/gina/access").await;
    let tuic_pos = html.find("tuic-v5").expect("tuic row present");
    let vless_pos = html.find("vless+reality").expect("vless row present");
    assert!(
        tuic_pos < vless_pos,
        "grid rows must be alphabetically sorted by protocol_id to match visible_protocols_for_subscription ORDER BY"
    );
}

// ─── NM-12: DPI-risk chips on server-detail + user-detail grid ───────
//
// Pavel 2026-05-20: «давай начнём с того что ты уберёшь чтото плохие
// протоколы и пометишь их в ui как плохие и можешь даже шрифт меньше
// сделать у них». Risk tier comes from the registry — no inventory
// state. These tests pin the chip text, the colour-driving class, the
// smaller-font branch for Weak rows, and the explainer tooltip.

#[tokio::test]
async fn nm12_server_detail_renders_dpi_strong_chip_for_vless_reality() {
    // Strong tier should produce a "DPI: strong" chip on the row.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("strongsrv".into()),
            address: "203.0.113.20".into(),
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
    let html = fetch_html(router(s), "/admin/servers/strongsrv/protocols").await;
    assert!(
        html.contains("DPI: strong"),
        "vless+reality row must surface its Strong DPI-risk chip"
    );
    // Tooltip carries the explainer ("Active-probe-resistant: ...").
    assert!(
        html.contains("Active-probe-resistant"),
        "Strong tier tooltip must explain the active-probe defence"
    );
}

#[tokio::test]
async fn nm12_server_detail_renders_dpi_weak_chip_and_smaller_font_for_wireguard() {
    // Weak tier produces "DPI: weak" chip AND the row gets
    // font-size: 11px (visual de-emphasis). The test pins BOTH so a
    // regression that drops the font shrink would fail loudly.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("weaksrv".into()),
            address: "203.0.113.21".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("amneziawg".into())],
            enabled_protocols: vec![ProtocolId("wireguard".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/servers/weaksrv/protocols").await;
    assert!(
        html.contains("DPI: weak"),
        "wireguard row must surface its Weak DPI-risk chip"
    );
    assert!(
        html.contains("font-size: 11px"),
        "Weak protocol row must shrink the name to 11px (Pavel: «шрифт меньше у них»)"
    );
    // Explainer mentions the specific fingerprint so the operator
    // understands WHY it's Weak — and the chip-tooltip lookup table
    // never silently changes.
    assert!(
        html.contains("0x01 handshake tag") || html.contains("WireGuard"),
        "Weak tier tooltip must explain the trivial fingerprint (raw-WG 0x01 tag)"
    );
}

#[tokio::test]
async fn nm12_server_detail_renders_dpi_chip_for_every_known_protocol() {
    // Spec: every registered protocol must produce SOME chip. A
    // future protocol added without overriding dpi_risk() still
    // gets `Moderate` (the default), so the chip set is exhaustive.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("allsrv".into()),
            address: "203.0.113.22".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![
                KernelId("amneziawg".into()),
                KernelId("sing-box".into()),
                KernelId("wgturn".into()),
            ],
            // Empty enabled_protocols — the server-detail still lists
            // every protocol in the registry with [enable] buttons,
            // and the chip should render alongside the name.
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/servers/allsrv/protocols").await;
    // Tier distribution across the FULL production registry (the test
    // `state` mirrors `build_registry` — naive + dns-tunnel + vless-ws
    // + vless+xhttp included):
    //   Strong:   vless+reality, wgturn, naive,
    //             vless-ws, vless+xhttp            (5)
    //   Moderate: tuic-v5, anytls, dns-tunnel      (3)
    //   Weak:     shadowsocks-2022, wireguard,
    //             trojan, hysteria2                (4)
    //   ────────────────────────────────────────────
    //   total                                      (12)
    let strong_count = html.matches("DPI: strong").count();
    let moderate_count = html.matches("DPI: moderate").count();
    let weak_count = html.matches("DPI: weak").count();
    assert_eq!(
        strong_count, 5,
        "expected 5 Strong chips (vless+reality, wgturn, naive, vless-ws, vless+xhttp), got {strong_count}"
    );
    assert_eq!(
        moderate_count, 3,
        "expected 3 Moderate chips (tuic-v5, anytls, dns-tunnel), got {moderate_count}"
    );
    assert_eq!(
        weak_count, 4,
        "expected 4 Weak chips (shadowsocks-2022, wireguard, trojan, hysteria2), got {weak_count}"
    );
}

#[tokio::test]
async fn nm12_server_detail_renders_dpi_moderate_chip_for_tuic_v5() {
    // After the review-agent re-tier (Trojan/Hysteria2 → Weak), only
    // tuic-v5 and anytls are Moderate. This test pins that tuic-v5
    // actually carries the Moderate chip — without it the
    // Strong/Weak tests would happily pass even if the Moderate arm
    // of `border_css()` / `text_css()` were broken.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("modsrv".into()),
            address: "203.0.113.24".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![ProtocolId("tuic-v5".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/servers/modsrv/protocols").await;
    assert!(
        html.contains("DPI: moderate"),
        "tuic-v5 row must surface its Moderate DPI-risk chip"
    );
    // Moderate uses --rule + --mute (not the green/red palette); the
    // tooltip wording is distinct from Strong/Weak.
    assert!(
        html.contains("Recognisable on careful active probing"),
        "Moderate tier tooltip must explain the careful-probe boundary"
    );
}

#[tokio::test]
async fn nm12_server_detail_hidden_weak_protocol_still_shows_chip() {
    // The chip is informational about the wire format, not about
    // current visibility. Hiding a Weak protocol (NM-10) does NOT
    // erase the DPI: weak chip — the operator still needs to see
    // WHY they hid it. A regression that suppresses the chip on
    // hidden rows would silently strip the most important context.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("hwsrv".into()),
            address: "203.0.113.25".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![ProtocolId("shadowsocks-2022".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    s.inv
        .set_server_protocol_hidden(
            &ServerId("hwsrv".into()),
            &ProtocolId("shadowsocks-2022".into()),
            true,
        )
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/servers/hwsrv/protocols").await;
    assert!(
        html.contains("DPI: weak"),
        "hidden Weak protocol must STILL show the chip — chip is about the wire format, not visibility"
    );
    assert!(
        html.contains("✓ on · hidden"),
        "hidden status marker must also appear alongside the chip"
    );
}

#[tokio::test]
async fn nm12_unknown_protocol_in_server_renders_no_chip_defensively() {
    // Defensive: if a server's `enabled_protocols` row references a
    // ProtocolId the registry doesn't know about (impossible in
    // production — registry is seeded at boot — but possible during
    // an interrupted migration / dev-time table edit), the render
    // path falls back to `risk = None` and emits NO chip rather
    // than panicking.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("unksrv".into()),
            address: "203.0.113.26".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            // Empty enabled_protocols — server-detail still lists
            // every registry protocol with [enable] buttons; none
            // of THEM are unknown, so we don't see the None branch
            // here. To exercise it we'd need a synthetic registry,
            // which the test stub doesn't expose. So this test
            // instead pins the inverse property: every protocol id
            // emitted by the rendered HTML carries a chip. If the
            // chip ever silently drops on a known-good row this
            // count goes out of sync.
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/servers/unksrv/protocols").await;
    // 12 registered protocols → 12 chips (Strong + Moderate + Weak
    // sum). If the chip-or-no-chip decision branches on something
    // OTHER than "registry knows this id", the count drifts.
    let total_chips = html.matches("DPI: strong").count()
        + html.matches("DPI: moderate").count()
        + html.matches("DPI: weak").count();
    assert_eq!(
        total_chips, 12,
        "12 registered protocols must each carry exactly one chip on a server with all kernels — got {total_chips}"
    );
}

#[tokio::test]
async fn nm12_user_detail_grid_renders_dpi_chip_and_weak_shrinks_to_10px() {
    // Same chip shows up in the user-detail per-protocol delivery
    // sub-grid, but at the smaller layout (9px chip, 10px Weak vs
    // 11px Moderate/Strong) so it fits the dense row.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_user(&User {
            id: UserId("hank".into()),
            uuid: "00000000-0000-0000-0000-000000000008".to_string(),
            sub_token: Some("t8".into()),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    s.inv
        .add_server(&Server {
            id: ServerId("hsrv".into()),
            address: "203.0.113.23".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("amneziawg".into()), KernelId("sing-box".into())],
            // Mix Strong (vless+reality) and Weak (wireguard,
            // shadowsocks-2022) so both font branches exercise.
            enabled_protocols: vec![
                ProtocolId("vless+reality".into()),
                ProtocolId("wireguard".into()),
                ProtocolId("shadowsocks-2022".into()),
            ],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    s.inv
        .grant(&UserId("hank".into()), &ServerId("hsrv".into()))
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/users/hank/access").await;
    assert!(
        html.contains("DPI: strong") && html.contains("DPI: weak"),
        "grid must render risk chips matching the protocol tiers"
    );
    // Grid font-size: 10px for Weak rows, 11px otherwise. Assert
    // the 10px branch fires (would not be present without a Weak
    // protocol in the row set).
    assert!(
        html.contains("font-size: 10px"),
        "Weak protocol row in user-detail grid must shrink to 10px"
    );
}

// ─── NM-12 follow-up: scroll-preserve via Location fragment ──────────
//
// Pavel 2026-05-20: «каждый раз когда я жму disable меня выкидывает
// в верх страницы». PRG (Post/Redirect/Get) loses the operator's
// scroll position when the redirect target is a bare path — the
// browser GETs the page and resets to top. Fix: every visibility-
// toggle handler appends `#enabled-protocols` (server-detail) or
// `#server-access` (user-detail) to the Location header, and the
// section heading carries the matching `id=`. Browser scrolls to
// the anchor instead of the top.
//
// These tests pin BOTH halves of the contract so a regression
// removing the fragment OR the id would fail.

#[tokio::test]
async fn nm12_followup_server_detail_section_carries_enabled_protocols_anchor() {
    // The redirects all assume an anchor element with
    // id="enabled-protocols" exists on the server-detail page.
    // Without the id the fragment redirect lands at the top of
    // the page anyway (browsers silently ignore unmatched
    // fragments). This pins the markup half of the contract.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("anchsrv".into()),
            address: "203.0.113.27".into(),
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
    let html = fetch_html(router(s), "/admin/servers/anchsrv/protocols").await;
    assert!(
        html.contains(r#"id="enabled-protocols""#),
        "server-detail must carry an id=\"enabled-protocols\" anchor for the visibility-toggle handlers to scroll back into"
    );
}

#[tokio::test]
async fn nm12_followup_user_detail_section_carries_server_access_anchor() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_user(&User {
            id: UserId("ivy".into()),
            uuid: "00000000-0000-0000-0000-000000000009".to_string(),
            sub_token: Some("t9".into()),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/users/ivy/access").await;
    assert!(
        html.contains(r#"id="server-access""#),
        "user-detail must carry an id=\"server-access\" anchor for the grant-toggle handlers to scroll back into"
    );
}

#[tokio::test]
async fn nm12_followup_server_protocol_unhide_redirects_with_fragment() {
    // server_protocol_hide is already covered by
    // nm10_server_detail_post_hide_persists_and_redirects (updated
    // to assert the fragment). Unhide is the symmetric handler —
    // pin it separately so a copy-paste regression deleting the
    // fragment from only one of the two would fail.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    s.inv
        .add_server(&Server {
            id: ServerId("uhsrv".into()),
            address: "203.0.113.28".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![ProtocolId("tuic-v5".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    inv.set_server_protocol_hidden(
        &ServerId("uhsrv".into()),
        &ProtocolId("tuic-v5".into()),
        true,
    )
    .await
    .unwrap();
    let app = router(s);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/uhsrv/protocols/tuic-v5/unhide"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(loc, "/admin/servers/uhsrv/protocols#enabled-protocols");
}

#[tokio::test]
async fn nm12_followup_grant_protocol_enable_redirects_with_fragment() {
    // grant_protocol_disable already covered by
    // nm10_user_detail_post_block_persists_and_redirects (updated
    // to assert the fragment). Enable is the symmetric handler.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    s.inv
        .add_user(&User {
            id: UserId("ji".into()),
            uuid: "00000000-0000-0000-0000-000000000010".to_string(),
            sub_token: Some("t10".into()),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    s.inv
        .add_server(&Server {
            id: ServerId("jsrv".into()),
            address: "203.0.113.29".into(),
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
    inv.grant(&UserId("ji".into()), &ServerId("jsrv".into()))
        .await
        .unwrap();
    inv.set_grant_protocol_override(
        &UserId("ji".into()),
        &ServerId("jsrv".into()),
        &ProtocolId("vless+reality".into()),
        true,
    )
    .await
    .unwrap();
    let app = router(s);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users/ji/grants/jsrv/protocols/vless%2Breality/enable"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(loc, "/admin/users/ji/access#server-access");
}

#[tokio::test]
async fn nm12_followup_legacy_server_disable_protocol_also_carries_fragment() {
    // The pre-existing `server_disable_protocol` handler (NOT part
    // of NM-10 — it removes the protocol from `enabled_protocols`
    // entirely, requires a `deploy` to take effect on the node)
    // also gets the fragment so the operator stays anchored after
    // a click on the [disable] (not [hide]) button. This is the
    // button Pavel was actually using when he reported the scroll
    // bug — pinning it separately so we never lose the fix.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("lsrv".into()),
            address: "203.0.113.30".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![ProtocolId("tuic-v5".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let app = router(s);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/lsrv/protocols/tuic-v5/disable"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(loc, "/admin/servers/lsrv/protocols#enabled-protocols");
}

#[tokio::test]
async fn nm12_followup_servers_list_reflects_hidden_state() {
    // Pavel 2026-05-20: «нужно сделаить на /admin/servers чтоб это
    // отобразилось, сейчас показано что там все протоколы, хотя я
    // сделал hide». Pre-fix the server-card on /admin/servers
    // rendered `Server.enabled_protocols` straight (in-memory
    // cache, no awareness of `server_protocols.hidden`). Post-fix
    // it splits visible vs hidden via the new bulk matrix and
    // renders them in two distinct rows.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("lpsrv".into()),
            address: "203.0.113.40".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            // 3 enabled: vless+reality (visible), tuic-v5 + anytls
            // (will be hidden below).
            enabled_protocols: vec![
                ProtocolId("vless+reality".into()),
                ProtocolId("tuic-v5".into()),
                ProtocolId("anytls".into()),
            ],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    s.inv
        .set_server_protocol_hidden(
            &ServerId("lpsrv".into()),
            &ProtocolId("tuic-v5".into()),
            true,
        )
        .await
        .unwrap();
    s.inv
        .set_server_protocol_hidden(
            &ServerId("lpsrv".into()),
            &ProtocolId("anytls".into()),
            true,
        )
        .await
        .unwrap();

    let html = fetch_html(router(s), "/admin/servers").await;

    // Densify 2a: visible protocols render in the dense-table cell; the
    // hidden ones live ONLY inside the "+N hidden" flag's title (still
    // listening on the node, just not emitted to subscriptions — NM-10/12).
    let visible_seg = html
        .split(r#"<span class="ed-grid__flag""#)
        .next()
        .expect("page renders");
    assert!(
        visible_seg.contains("vless+reality"),
        "visible protocol list must show vless+reality"
    );
    assert!(
        !visible_seg.contains("tuic-v5") && !visible_seg.contains("anytls"),
        "hidden protocols must NOT appear in the visible list (only in the flag title)"
    );
    // The +N hidden flag renders, names the hidden protocols in its title,
    // and shows the count.
    assert!(
        html.contains(r#"class="ed-grid__flag""#),
        "a +N hidden flag must render for the server with hidden protocols"
    );
    assert!(
        html.contains("tuic-v5") && html.contains("anytls"),
        "hidden protocols must be surfaced (in the flag title)"
    );
    assert!(html.contains("+2"), "flag must show the hidden count (+2)");
}

#[tokio::test]
async fn nm12_followup_servers_list_no_hidden_row_when_all_visible() {
    // Symmetric: when no protocol is hidden on a server, the
    // `dt { "hidden" }` row must NOT render — keeps the card
    // compact for the happy-path operator. A regression that
    // always emits the row (even with 0 hidden) would clutter
    // the list page.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("vsrv".into()),
            address: "203.0.113.41".into(),
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
    let html = fetch_html(router(s), "/admin/servers").await;
    // The hidden dt label only appears when there's at least one
    // hidden protocol. Search for the literal `<dt style="color:
    // var(--acc);">hidden</dt>` substring.
    assert!(
        !html.contains(r#"<dt style="color: var(--acc);">hidden</dt>"#),
        "no protocols are hidden — the hidden dt row must NOT render"
    );
}

#[tokio::test]
async fn nm12_followup_legacy_server_enable_protocol_also_carries_fragment() {
    // Symmetric to the [disable] test above.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("esrv2".into()),
            address: "203.0.113.31".into(),
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
    let app = router(s);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/esrv2/protocols/anytls/enable"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(loc, "/admin/servers/esrv2/protocols#enabled-protocols");
}

// ── D1 — default-grant-all-servers on user create ───────────────────
//
// Pre-2026-05-22 POST /admin/users created a user with ZERO grants,
// then operator had to drill into each server. New default: a
// `grant_all=1` checkbox (checked by default in the form) triggers
// a bulk grant immediately after add_user. Two tests pin the contract:
//   1. grant_all=1 (default) → user is granted on every registered server.
//   2. grant_all omitted → user is granted on ZERO servers (pre-D1
//      behavior preserved for explicit opt-out).

#[tokio::test]
async fn user_create_with_grant_all_grants_every_registered_server() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    // Seed 2 servers so we can assert the grant count is 2 (not 0, not 1).
    for sid_s in ["alpha", "bravo"] {
        st.inv
            .add_server(&Server {
                id: ServerId(sid_s.into()),
                address: format!("203.0.113.{}", if sid_s == "alpha" { 1 } else { 2 }),
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
    }
    let app = router(st.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/users")
                .header("Origin", "http://127.0.0.1")
                .header("Host", "127.0.0.1")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("id=newbie&grant_all=1"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    // Both servers must now have a grant for `newbie`.
    let granted_servers = st
        .inv
        .servers_for_user(&vpnctl_core::UserId("newbie".into()))
        .await
        .unwrap();
    let mut granted_ids: Vec<String> = granted_servers.iter().map(|s| s.id.0.clone()).collect();
    granted_ids.sort();
    assert_eq!(
        granted_ids,
        vec!["alpha".to_string(), "bravo".to_string()],
        "grant_all=1 must grant access on EVERY registered server"
    );
}

#[tokio::test]
async fn user_create_without_grant_all_grants_zero_servers() {
    // Explicit opt-out: form posts WITHOUT grant_all field at all.
    // Old behaviour preserved — user created with zero grants.
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    st.inv
        .add_server(&Server {
            id: ServerId("solo".into()),
            address: "203.0.113.5".into(),
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
    let app = router(st.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/users")
                .header("Origin", "http://127.0.0.1")
                .header("Host", "127.0.0.1")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("id=optout"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let granted = st
        .inv
        .servers_for_user(&vpnctl_core::UserId("optout".into()))
        .await
        .unwrap();
    assert!(
        granted.is_empty(),
        "user created without grant_all checkbox must have zero grants; got: {granted:?}"
    );
}

#[tokio::test]
async fn user_create_with_grant_all_renders_checked_checkbox_in_form() {
    // The form on /admin/users must render the checkbox CHECKED by
    // default so the operator's «one click» path produces a granted
    // user.
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/users")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    // The form must include the checkbox + it must be checked.
    assert!(
        html.contains(r#"name="grant_all""#),
        "user form must include grant_all checkbox"
    );
    assert!(
        html.contains(r#"checked="checked""#) || html.contains("checked=\"checked\""),
        "checkbox must default to CHECKED — found no checked attribute in the form"
    );
}

// ── B2 — bulk grant/revoke on /admin/servers/<id> ──────────────────
//
// Grant-all: no confirm, idempotent, grants every ungranted user.
// Revoke-all: requires confirm=<server-id>, revokes every granted.

#[tokio::test]
async fn server_grant_all_users_grants_every_ungranted() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    st.inv
        .add_server(&Server {
            id: ServerId("srv".into()),
            address: "203.0.113.20".into(),
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
    for (idx, id) in ["alice", "bob", "carol"].iter().enumerate() {
        st.inv
            .add_user(&User {
                id: UserId((*id).into()),
                uuid: format!("00000000-0000-0000-0000-{:012}", 90 + idx),
                tuic_password: None,
                wireguard_pubkey: None,
                wireguard_private: None,
                sub_token: None,
                vpn_router_device_id: None,
                disabled: false,
            })
            .await
            .unwrap();
    }
    let app = router(st.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/servers/srv/grants/_grant-all")
                .header("Origin", "http://127.0.0.1")
                .header("Host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let granted = st
        .inv
        .users_for_server(&ServerId("srv".into()))
        .await
        .unwrap();
    let mut ids: Vec<String> = granted.iter().map(|u| u.id.0.clone()).collect();
    ids.sort();
    assert_eq!(ids, vec!["alice", "bob", "carol"]);
    // Summary audit row must have been written.
    let audit = st.inv.recent_audit(20).await.unwrap();
    let row = audit
        .iter()
        .find(|e| e.action == "server.grants.bulk_grant")
        .expect("bulk_grant audit row required");
    let payload = row.payload.as_ref().unwrap();
    assert_eq!(payload["granted"].as_u64(), Some(3));
    assert_eq!(payload["already_granted"].as_u64(), Some(0));
    assert_eq!(payload["failed"].as_u64(), Some(0));
    // Audit-finding follow-up (2026-05-23): disabled users skipped.
    // None of the 3 seeded users are disabled → counter is 0.
    assert_eq!(payload["skipped_disabled"].as_u64(), Some(0));
}

#[tokio::test]
async fn server_grant_all_skips_disabled_users() {
    // Audit-finding follow-up (2026-05-23, b4608d2 review): bulk
    // grant must NOT silently grant access to soft-paused users
    // (B1.user mental-model preservation).
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    st.inv
        .add_server(&Server {
            id: ServerId("srv".into()),
            address: "203.0.113.30".into(),
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
    st.inv
        .add_user(&User {
            id: UserId("alive".into()),
            uuid: "00000000-0000-0000-0000-000000000201".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    st.inv
        .add_user(&User {
            id: UserId("paused".into()),
            uuid: "00000000-0000-0000-0000-000000000202".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: true,
        })
        .await
        .unwrap();
    let app = router(st.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/servers/srv/grants/_grant-all")
                .header("Origin", "http://127.0.0.1")
                .header("Host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let granted = st
        .inv
        .users_for_server(&ServerId("srv".into()))
        .await
        .unwrap();
    let ids: Vec<String> = granted.iter().map(|u| u.id.0.clone()).collect();
    assert_eq!(ids, vec!["alive"], "paused user must NOT be granted");
    let audit = st.inv.recent_audit(20).await.unwrap();
    let row = audit
        .iter()
        .find(|e| e.action == "server.grants.bulk_grant")
        .expect("audit row required");
    let payload = row.payload.as_ref().unwrap();
    assert_eq!(payload["granted"].as_u64(), Some(1));
    assert_eq!(payload["skipped_disabled"].as_u64(), Some(1));
}

#[tokio::test]
async fn server_revoke_all_users_requires_confirm_match() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    st.inv
        .add_server(&Server {
            id: ServerId("srv".into()),
            address: "203.0.113.21".into(),
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
    st.inv
        .add_user(&User {
            id: UserId("u".into()),
            uuid: "00000000-0000-0000-0000-000000000088".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    st.inv
        .grant(&UserId("u".into()), &ServerId("srv".into()))
        .await
        .unwrap();
    let app = router(st.clone());

    // Wrong confirm → 400, grant survives.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/servers/srv/grants/_revoke-all")
                .header("Origin", "http://127.0.0.1")
                .header("Host", "127.0.0.1")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("confirm=WRONG"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let still_granted = st
        .inv
        .users_for_server(&ServerId("srv".into()))
        .await
        .unwrap();
    assert_eq!(still_granted.len(), 1, "wrong-confirm must NOT revoke");

    // Correct confirm → 303, grant gone, summary audit row.
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/servers/srv/grants/_revoke-all")
                .header("Origin", "http://127.0.0.1")
                .header("Host", "127.0.0.1")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("confirm=srv"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let after = st
        .inv
        .users_for_server(&ServerId("srv".into()))
        .await
        .unwrap();
    assert!(
        after.is_empty(),
        "correct confirm must revoke; got {after:?}"
    );
    let audit = st.inv.recent_audit(20).await.unwrap();
    let row = audit
        .iter()
        .find(|e| e.action == "server.grants.bulk_revoke")
        .expect("bulk_revoke audit row required");
    assert_eq!(row.payload.as_ref().unwrap()["revoked"].as_u64(), Some(1));
}

#[tokio::test]
async fn server_detail_revoke_all_uses_data_confirm_prompt_not_inline_js() {
    // The revoke-all (destructive typed-confirm) form must wire its
    // prompt via data-attributes for admin.js, NOT an inline onsubmit —
    // CSP `script-src 'self'` blocks inline handlers, which left the
    // hidden `confirm` field empty and the POST rejected (the live bug
    // on `kg` 2026-06-06: "bulk-revoke confirm mismatch: form sent ''").
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    st.inv
        .add_server(&Server {
            id: ServerId("srv".into()),
            address: "203.0.113.22".into(),
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
    st.inv
        .add_user(&User {
            id: UserId("u".into()),
            uuid: "00000000-0000-0000-0000-000000000099".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    st.inv
        .grant(&UserId("u".into()), &ServerId("srv".into()))
        .await
        .unwrap();
    let app = router(st);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/servers/srv/grants")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    // The revoke-all form must POST to the bulk endpoint…
    assert!(
        html.contains(r#"action="/admin/servers/srv/grants/_revoke-all""#),
        "revoke-all form must render (one granted user seeded)"
    );
    // …carry the typed-confirm data-attributes admin.js consumes…
    assert!(
        html.contains("data-confirm-prompt="),
        "revoke-all must carry data-confirm-prompt for admin.js"
    );
    assert!(
        html.contains(r#"data-confirm-match="srv""#),
        "revoke-all must require typing the server id (data-confirm-match)"
    );
    // …keep the hidden confirm field admin.js populates + backend checks…
    assert!(
        html.contains(r#"name="confirm""#),
        "revoke-all must keep the hidden confirm field"
    );
    // …and use NO inline onsubmit (CSP script-src 'self' blocks it).
    assert!(
        !html.contains("onsubmit="),
        "revoke-all must not use an inline onsubmit handler"
    );
}

#[tokio::test]
async fn grant_from_user_detail_dispatches_auto_deploy_of_that_server_only() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    seed(&inv, 2, 1, &[]).await; // s0 + s1 + u0, no grants
    let app = router(s);

    app.clone()
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

    let rows = wait_for_autodeploy_rows(&inv, 1).await;
    let row = &rows[0];
    assert_eq!(row.action, "user.autodeploy");
    assert_eq!(row.target.as_deref(), Some("u0"));
    let payload = row.payload.as_ref().unwrap();
    assert_eq!(payload["trigger"], "user.grant");
    assert_eq!(
        payload["servers"],
        serde_json::json!(["s0"]),
        "auto-deploy must target ONLY the granted server, not the whole fleet"
    );
    assert_eq!(
        payload["ok"], false,
        "with no deploy key the autodeploy row must record the failure, \
         not pretend the node was updated"
    );

    // Idempotent re-grant is a no-op mutation → must NOT restart the node.
    app.oneshot(
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
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(
        count_autodeploy_rows(&inv).await,
        1,
        "no-op re-grant must not dispatch a second auto-deploy"
    );
}

#[tokio::test]
async fn revoke_from_user_detail_dispatches_auto_deploy_only_on_actual_revoke() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    seed(&inv, 2, 1, &[(0, 0)]).await; // u0 granted s0; s1 ungranted
    let app = router(s);

    // Revoking a NOT-granted pair is a no-op → no deploy.
    app.clone()
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users/u0/grants/s1/revoke"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(
        count_autodeploy_rows(&inv).await,
        0,
        "no-op revoke must not dispatch an auto-deploy"
    );

    // A real revoke dispatches a deploy of the revoked server so the
    // UUID actually leaves the node's users[].
    app.oneshot(
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
    let rows = wait_for_autodeploy_rows(&inv, 1).await;
    let payload = rows[0].payload.as_ref().unwrap();
    assert_eq!(rows[0].target.as_deref(), Some("u0"));
    assert_eq!(payload["trigger"], "user.revoke");
    assert_eq!(payload["servers"], serde_json::json!(["s0"]));
}

#[tokio::test]
async fn grant_and_revoke_from_server_detail_dispatch_auto_deploy() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    seed(&inv, 1, 1, &[]).await;
    let app = router(s);

    app.clone()
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/s0/grants/u0"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    let rows = wait_for_autodeploy_rows(&inv, 1).await;
    assert_eq!(rows[0].payload.as_ref().unwrap()["trigger"], "user.grant");
    assert_eq!(rows[0].target.as_deref(), Some("u0"));

    app.oneshot(
        add_same_origin(
            Request::builder()
                .method("POST")
                .uri("/admin/servers/s0/grants/u0/revoke"),
        )
        .body(Body::empty())
        .unwrap(),
    )
    .await
    .unwrap();
    let rows = wait_for_autodeploy_rows(&inv, 2).await;
    assert!(
        rows.iter()
            .any(|r| r.payload.as_ref().unwrap()["trigger"] == "user.revoke"),
        "server-detail revoke must dispatch an auto-deploy"
    );
}

#[tokio::test]
async fn bulk_grant_all_dispatches_one_auto_deploy_for_the_whole_batch() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    seed(&inv, 1, 3, &[]).await; // 3 users → still ONE deploy of s0
    let app = router(s);

    app.clone()
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/s0/grants/_grant-all"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    let rows = wait_for_autodeploy_rows(&inv, 1).await;
    let payload = rows[0].payload.as_ref().unwrap();
    assert_eq!(
        rows[0].action, "server.autodeploy",
        "server-targeted bulk autodeploy must stay out of the user.* namespace"
    );
    assert_eq!(rows[0].target.as_deref(), Some("s0"));
    assert_eq!(payload["trigger"], "server.grants.bulk_grant");
    assert_eq!(payload["servers"], serde_json::json!(["s0"]));
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(
        count_autodeploy_rows(&inv).await,
        1,
        "bulk grant of 3 users must dispatch exactly ONE deploy of the server"
    );

    // Fully-granted re-run grants 0 → no deploy.
    app.oneshot(
        add_same_origin(
            Request::builder()
                .method("POST")
                .uri("/admin/servers/s0/grants/_grant-all"),
        )
        .body(Body::empty())
        .unwrap(),
    )
    .await
    .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(
        count_autodeploy_rows(&inv).await,
        1,
        "no-op bulk re-grant must not dispatch another deploy"
    );
}

#[tokio::test]
async fn bulk_revoke_all_dispatches_one_auto_deploy() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    seed(&inv, 1, 2, &[(0, 0), (1, 0)]).await;
    let app = router(s);

    app.oneshot(
        add_same_origin(
            Request::builder()
                .method("POST")
                .uri("/admin/servers/s0/grants/_revoke-all")
                .header("content-type", "application/x-www-form-urlencoded"),
        )
        .body(Body::from("confirm=s0"))
        .unwrap(),
    )
    .await
    .unwrap();
    let rows = wait_for_autodeploy_rows(&inv, 1).await;
    let payload = rows[0].payload.as_ref().unwrap();
    assert_eq!(rows[0].action, "server.autodeploy");
    assert_eq!(rows[0].target.as_deref(), Some("s0"));
    assert_eq!(payload["trigger"], "server.grants.bulk_revoke");
    assert_eq!(payload["servers"], serde_json::json!(["s0"]));
}

#[tokio::test]
async fn user_create_grant_all_dispatches_auto_deploy_across_granted_servers() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    seed(&inv, 2, 0, &[]).await;
    let app = router(s);

    app.oneshot(
        add_same_origin(
            Request::builder()
                .method("POST")
                .uri("/admin/users")
                .header("content-type", "application/x-www-form-urlencoded"),
        )
        .body(Body::from("id=newbie&grant_all=1"))
        .unwrap(),
    )
    .await
    .unwrap();
    let rows = wait_for_autodeploy_rows(&inv, 1).await;
    let payload = rows[0].payload.as_ref().unwrap();
    assert_eq!(rows[0].target.as_deref(), Some("newbie"));
    assert_eq!(payload["trigger"], "user.create.grant_all");
    let mut servers: Vec<String> = payload["servers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    servers.sort();
    assert_eq!(
        servers,
        vec!["s0".to_string(), "s1".to_string()],
        "grant-all must dispatch ONE deploy pass covering every granted server"
    );
}

/// The payload the auto-deploy pushes: after a grant lands through the
/// real handler, the node config the redeploy pipeline renders (same
/// `users_for_server` → `render_config` chain as
/// `wizard_bootstrap::redeploy_pipeline`) must carry the user's UUID in
/// `inbounds[*].users[]` — the exact bytes whose absence caused the
/// «connects but no internet» failure.
#[tokio::test]
async fn granted_user_uuid_lands_in_rendered_node_config() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    let registry = Arc::clone(&s.registry);
    seed(&inv, 1, 1, &[]).await;
    let app = router(s);

    let sid = ServerId("s0".into());
    let server = inv.get_server(&sid).await.unwrap().unwrap();
    let (secrets, _minted) = vpnctl_inventory::bootstrap_server_secrets(&inv, &server, &registry)
        .await
        .unwrap();
    let render = |users: &[User]| -> serde_json::Value {
        let kernel = registry.kernel(&KernelId("sing-box".into())).unwrap();
        let protocols: Vec<&dyn vpnctl_core::Protocol> = server
            .enabled_protocols
            .iter()
            .filter_map(|p| registry.protocol(p))
            .collect();
        let ctx = vpnctl_core::RenderCtx::new(&server, &secrets);
        let bytes = kernel.render_config(&ctx, users, &protocols).unwrap();
        serde_json::from_slice(&bytes).unwrap()
    };
    let uuids_in = |cfg: &serde_json::Value| -> Vec<String> {
        cfg["inbounds"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|ib| ib["users"].as_array().cloned().unwrap_or_default())
            .filter_map(|u| u["uuid"].as_str().map(str::to_string))
            .collect()
    };

    // Before the grant: users_for_server is empty → no UUID in users[].
    let users = inv.users_for_server(&sid).await.unwrap();
    assert!(users.is_empty());
    assert!(uuids_in(&render(&users)).is_empty());

    // Grant through the real handler…
    app.oneshot(
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

    // …and the config the auto-deploy would push now carries the UUID.
    let users = inv.users_for_server(&sid).await.unwrap();
    let uuids = uuids_in(&render(&users));
    assert_eq!(
        uuids,
        vec!["00000000-0000-0000-0000-000000000000".to_string()],
        "granted user's UUID must be present in the rendered inbounds[*].users[]"
    );
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

/// v2 3d gap-close — the Grants tab renders clickable sort links and the
/// `?grant_sort=` param drives the row order.
#[tokio::test]
async fn v2_server_grants_sort_links_render() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 2, &[(0, 0), (1, 0)]).await; // s0 granted to u0,u1
    let html = fetch_html(router(s), "/admin/servers/s0/grants?grant_sort=traffic").await;
    assert!(
        html.contains("sort:") || html.contains("сортировка:"),
        "sort label missing"
    );
    assert!(
        html.contains("grant_sort=presence") && html.contains("grant_sort=id"),
        "sort links for the other keys must render"
    );
    // The active key renders as unlinked bold text (no href for traffic).
    assert!(
        !html.contains("grant_sort=traffic\""),
        "the active sort key must not link to itself"
    );
}
