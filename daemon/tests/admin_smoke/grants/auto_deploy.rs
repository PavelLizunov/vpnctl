//! Pending deploy detector and auto-deploy dispatch tests for grants/revokes.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{KernelId, ServerId, User, UserId};
use vpnctld::router;

use crate::common::{
    add_same_origin, count_autodeploy_rows, seed, state, wait_for_autodeploy_rows,
};

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
    wait_for_autodeploy_rows(&inv, 1).await;
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
    wait_for_autodeploy_rows(&inv, 2).await;
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
    wait_for_autodeploy_rows(&inv, 3).await;
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
    // Auto-deploy tasks from the three real grant handlers run in the
    // background and also write audit rows. Wait for those tasks before
    // taking the idempotency baseline so their delayed rows cannot race
    // this assertion on fast/slow CI runners.
    wait_for_autodeploy_rows(&inv, 3).await;
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
