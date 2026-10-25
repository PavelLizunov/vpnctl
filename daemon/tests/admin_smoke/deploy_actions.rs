use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
use vpnctld::router;
use vpnctld::wizard_bootstrap::DeployGuard;

use crate::common::*;

fn test_server(id: &str, address: &str) -> Server {
    Server {
        id: ServerId(id.into()),
        address: address.into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("vless+reality".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

async fn response_body_string(resp: Response) -> String {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn deploy_all_sse_terminal_ok_on_empty_inventory() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let app = router(s);

    let sse_uri = ticketed_sse_uri(&app, "/admin/servers/deploy-all/sse").await;
    let resp = app
        .oneshot(Request::builder().uri(sse_uri).body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.starts_with("text/event-stream"),
        "expected text/event-stream content type, got: {ct}"
    );

    let body = response_body_string(resp).await;

    assert!(
        body.contains("event: step"),
        "stream must emit step events: {body}"
    );
    assert!(
        body.contains("done — deployed all 0 server(s)."),
        "stream must summarize empty fleet deploy: {body}"
    );
    assert!(
        body.contains("event: ok"),
        "empty fleet deploy must conclude with terminal ok event: {body}"
    );
    assert!(
        body.contains(r#""server_id":"all""#),
        "terminal ok payload must reference all servers: {body}"
    );
}

#[tokio::test]
async fn deploy_all_sse_terminal_error_on_missing_deploy_key() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;

    s.inv
        .add_server(&test_server("da-all-err-1", "198.51.100.10"))
        .await
        .unwrap();
    s.inv
        .add_server(&test_server("da-all-err-2", "198.51.100.11"))
        .await
        .unwrap();

    let app = router(s);
    let sse_uri = ticketed_sse_uri(&app, "/admin/servers/deploy-all/sse").await;
    let resp = app
        .oneshot(Request::builder().uri(sse_uri).body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_body_string(resp).await;

    assert!(
        body.contains("event: step"),
        "must emit step lines for attempted servers: {body}"
    );
    assert!(
        body.contains("✗ da-all-err-1") || body.contains("da-all-err-1: deploy skipped"),
        "da-all-err-1 failure must be reported: {body}"
    );
    assert!(
        body.contains("✗ da-all-err-2") || body.contains("da-all-err-2: deploy skipped"),
        "da-all-err-2 failure must be reported: {body}"
    );
    assert!(
        body.contains("event: error"),
        "deploy-all must emit terminal error event on failures: {body}"
    );
    assert!(
        body.contains("failed: da-all-err-1, da-all-err-2"),
        "summary must name failed servers: {body}"
    );
}

#[tokio::test]
async fn deploy_all_sse_waits_for_in_flight_deploy() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;

    let server_id = "da-all-lock-srv";
    s.inv
        .add_server(&test_server(server_id, "198.51.100.12"))
        .await
        .unwrap();

    let guard = DeployGuard::try_acquire(server_id).expect("must acquire deploy permit");
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        drop(guard);
    });

    let app = router(s);
    let sse_uri = ticketed_sse_uri(&app, "/admin/servers/deploy-all/sse").await;
    let resp = app
        .oneshot(Request::builder().uri(sse_uri).body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_body_string(resp).await;
    assert!(
        body.contains("another deploy is running on da-all-lock-srv; waiting for it to finish"),
        "must say it waits for the running deploy: {body}"
    );
    assert!(
        !body.contains("deploy already running"),
        "must not fail while the other deploy finishes: {body}"
    );
}

#[tokio::test]
async fn deploy_all_sse_refuses_unticketed_trigger() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let app = router(s);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/servers/deploy-all/sse")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = response_body_string(resp).await;
    assert!(
        body.contains("start ticket missing or expired"),
        "forbidden response body must state reason: {body}"
    );
}

#[tokio::test]
async fn sse_ticket_issue_is_csrf_checked_and_single_use() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    let cross = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/sse-ticket")
                .header("host", SAME_ORIGIN_HOST)
                .header("origin", "http://attacker.example")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("path=/admin/servers/deploy-all/sse"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        cross.status(),
        StatusCode::FORBIDDEN,
        "a foreign Origin must not obtain a start ticket"
    );

    let other_path = body_of(
        app.clone(),
        "POST",
        "/admin/sse-ticket",
        Some("application/x-www-form-urlencoded"),
        Some("path=/admin/users"),
    )
    .await;
    assert!(
        other_path.contains("not a ticketed admin action"),
        "only operation SSE paths get tickets: {other_path}"
    );

    let uri = ticketed_sse_uri(&app, "/admin/servers/deploy-all/sse").await;
    let first = app
        .clone()
        .oneshot(Request::builder().uri(&uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let replay = app
        .oneshot(Request::builder().uri(&uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(
        replay.status(),
        StatusCode::FORBIDDEN,
        "a ticket must start one operation only"
    );
}

#[tokio::test]
async fn user_deploy_pending_sse_terminal_ok_when_nothing_pending() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;

    s.inv
        .add_user(&User {
            id: UserId("da-user-nopending".into()),
            uuid: "00000000-0000-0000-0000-000000000001".into(),
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
    let sse_uri = ticketed_sse_uri(&app, "/admin/users/da-user-nopending/deploy-pending/sse").await;
    let resp = app
        .oneshot(Request::builder().uri(sse_uri).body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.starts_with("text/event-stream"),
        "expected text/event-stream, got: {ct}"
    );

    let body = response_body_string(resp).await;

    assert!(
        body.contains("event: ok"),
        "nothing pending must immediately emit terminal ok: {body}"
    );
    assert!(
        body.contains("nothing pending — every granted server already carries this user's config"),
        "terminal ok message must explain nothing pending: {body}"
    );
}

#[tokio::test]
async fn user_deploy_pending_sse_terminal_error_when_pending_server_fails() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;

    let user_id = UserId("da-user-pend-err".into());
    let srv_id = ServerId("da-srv-pend-err".into());

    s.inv
        .add_server(&test_server(&srv_id.0, "198.51.100.20"))
        .await
        .unwrap();
    s.inv
        .add_user(&User {
            id: user_id.clone(),
            uuid: "00000000-0000-0000-0000-000000000002".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();

    s.inv.grant(&user_id, &srv_id).await.unwrap();
    s.inv
        .audit("admin", "user.grant", Some(&user_id.0), None)
        .await
        .unwrap();

    let pending = s
        .inv
        .servers_pending_deploy_for_user(&user_id, std::slice::from_ref(&srv_id))
        .await
        .unwrap();
    assert_eq!(pending, vec![srv_id.clone()]);

    let app = router(s);
    let sse_uri = ticketed_sse_uri(&app, "/admin/users/da-user-pend-err/deploy-pending/sse").await;
    let resp = app
        .oneshot(Request::builder().uri(sse_uri).body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_body_string(resp).await;

    assert!(
        body.contains("── deploying da-srv-pend-err ──"),
        "must scope deploy to the pending server: {body}"
    );
    assert!(
        body.contains("event: error"),
        "missing deploy key must cause terminal error event: {body}"
    );
    assert!(
        body.contains("failed: da-srv-pend-err"),
        "terminal error message must report failure: {body}"
    );
}

#[tokio::test]
async fn user_deploy_pending_sse_waits_for_in_flight_deploy() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;

    let user_id = UserId("da-user-pend-lock".into());
    let srv_id = ServerId("da-srv-pend-lock".into());

    s.inv
        .add_server(&test_server(&srv_id.0, "198.51.100.21"))
        .await
        .unwrap();
    s.inv
        .add_user(&User {
            id: user_id.clone(),
            uuid: "00000000-0000-0000-0000-000000000003".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();

    s.inv.grant(&user_id, &srv_id).await.unwrap();
    s.inv
        .audit("admin", "user.grant", Some(&user_id.0), None)
        .await
        .unwrap();

    let guard = DeployGuard::try_acquire(&srv_id.0).expect("must acquire deploy permit");
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        drop(guard);
    });

    let app = router(s);
    let sse_uri = ticketed_sse_uri(&app, "/admin/users/da-user-pend-lock/deploy-pending/sse").await;
    let resp = app
        .oneshot(Request::builder().uri(sse_uri).body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_body_string(resp).await;
    assert!(
        body.contains("another deploy is running on da-srv-pend-lock; waiting for it to finish"),
        "must say it waits for the running deploy: {body}"
    );
    assert!(
        !body.contains("deploy already running"),
        "must not fail while the other deploy finishes: {body}"
    );
}

#[tokio::test]
async fn user_deploy_pending_sse_idempotent_after_server_deploy() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;

    let user_id = UserId("da-user-idemp".into());
    let srv_id = ServerId("da-srv-idemp".into());

    s.inv
        .add_server(&test_server(&srv_id.0, "198.51.100.22"))
        .await
        .unwrap();
    s.inv
        .add_user(&User {
            id: user_id.clone(),
            uuid: "00000000-0000-0000-0000-000000000004".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();

    s.inv.grant(&user_id, &srv_id).await.unwrap();
    s.inv
        .audit("admin", "user.grant", Some(&user_id.0), None)
        .await
        .unwrap();

    let pending_before = s
        .inv
        .servers_pending_deploy_for_user(&user_id, std::slice::from_ref(&srv_id))
        .await
        .unwrap();
    assert_eq!(pending_before, vec![srv_id.clone()]);

    s.inv
        .audit("admin", "server.deploy", Some(&srv_id.0), None)
        .await
        .unwrap();

    let pending_after = s
        .inv
        .servers_pending_deploy_for_user(&user_id, std::slice::from_ref(&srv_id))
        .await
        .unwrap();
    assert!(
        pending_after.is_empty(),
        "server must no longer be pending after deploy audit"
    );

    let app1 = router(s.clone());
    let sse_uri = ticketed_sse_uri(&app1, "/admin/users/da-user-idemp/deploy-pending/sse").await;
    let resp1 = app1
        .oneshot(Request::builder().uri(sse_uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp1.status(), StatusCode::OK);
    let body1 = response_body_string(resp1).await;
    assert!(body1.contains("event: ok"));
    assert!(body1.contains("nothing pending"));

    let app2 = router(s);
    let sse_uri = ticketed_sse_uri(&app2, "/admin/users/da-user-idemp/deploy-pending/sse").await;
    let resp2 = app2
        .oneshot(Request::builder().uri(sse_uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);
    let body2 = response_body_string(resp2).await;
    assert!(body2.contains("event: ok"));
    assert!(body2.contains("nothing pending"));
}

#[tokio::test]
async fn user_deploy_pending_sse_unknown_user_404s() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let app = router(s);

    let sse_uri = ticketed_sse_uri(&app, "/admin/users/no-such-user-999/deploy-pending/sse").await;
    let resp = app
        .oneshot(Request::builder().uri(sse_uri).body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn user_deploy_pending_sse_refuses_cross_origin_trigger() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;

    s.inv
        .add_user(&User {
            id: UserId("da-user-csrf".into()),
            uuid: "00000000-0000-0000-0000-000000000005".into(),
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
            Request::builder()
                .uri("/admin/users/da-user-csrf/deploy-pending/sse")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn server_deploy_sse_unknown_server_404s() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let app = router(s);

    let sse_uri = ticketed_sse_uri(&app, "/admin/servers/no-such-srv/deploy/sse").await;
    let resp = app
        .oneshot(Request::builder().uri(sse_uri).body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn server_deploy_sse_refuses_cross_origin() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&test_server("da-srv-csrf", "198.51.100.23"))
        .await
        .unwrap();

    let app = router(s);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/servers/da-srv-csrf/deploy/sse")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn server_deploy_sse_waits_for_in_flight_deploy() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let srv_id = "da-srv-single-lock";
    s.inv
        .add_server(&test_server(srv_id, "198.51.100.24"))
        .await
        .unwrap();

    let guard = DeployGuard::try_acquire(srv_id).expect("acquire lock");
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        drop(guard);
    });

    let app = router(s);
    let sse_uri = ticketed_sse_uri(&app, &format!("/admin/servers/{srv_id}/deploy/sse")).await;
    let resp = app
        .oneshot(Request::builder().uri(sse_uri).body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_body_string(resp).await;
    assert!(
        body.contains("another deploy is running on da-srv-single-lock; waiting for it to finish"),
        "must say it waits for the running deploy: {body}"
    );
    assert!(
        !body.contains("deploy already running"),
        "must not fail while the other deploy finishes: {body}"
    );
}

#[tokio::test]
async fn server_update_kernels_sse_unknown_server_404s() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let app = router(s);

    let sse_uri =
        ticketed_sse_uri(&app, "/admin/servers/no-such-server-uk/update-kernels/sse").await;
    let resp = app
        .oneshot(Request::builder().uri(sse_uri).body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn server_update_kernels_sse_refuses_cross_origin() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&test_server("da-uk-csrf", "198.51.100.30"))
        .await
        .unwrap();

    let app = router(s);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/servers/da-uk-csrf/update-kernels/sse")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn server_update_kernels_sse_lock_reports_error_when_deploy_or_update_in_flight() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let srv_id = "da-uk-lock";
    s.inv
        .add_server(&test_server(srv_id, "198.51.100.32"))
        .await
        .unwrap();

    let _guard = DeployGuard::try_acquire(srv_id).expect("must acquire deploy permit");

    let app = router(s);
    let sse_uri =
        ticketed_sse_uri(&app, &format!("/admin/servers/{srv_id}/update-kernels/sse")).await;
    let resp = app
        .oneshot(Request::builder().uri(sse_uri).body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_body_string(resp).await;
    assert!(body.contains("event: error"));
    assert!(body.contains("deploy/update already running for server 'da-uk-lock'"));
}

#[tokio::test]
async fn servers_update_kernels_all_sse_terminal_ok_on_empty_fleet() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let app = router(s);

    let sse_uri = ticketed_sse_uri(&app, "/admin/servers/update-kernels-all/sse").await;
    let resp = app
        .oneshot(Request::builder().uri(sse_uri).body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.starts_with("text/event-stream"),
        "expected text/event-stream, got: {ct}"
    );

    let body = response_body_string(resp).await;
    assert!(body.contains("done — updated kernels on 0/0 servers."));
    assert!(body.contains("event: ok"));
    assert!(body.contains(r#""server_id":"all""#));
}

#[tokio::test]
async fn servers_update_kernels_all_sse_reports_failures_in_stream_steps() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;

    s.inv
        .add_server(&test_server("da-uk-all-1", "198.51.100.41"))
        .await
        .unwrap();
    s.inv
        .add_server(&test_server("da-uk-all-2", "198.51.100.42"))
        .await
        .unwrap();

    let app = router(s);
    let sse_uri = ticketed_sse_uri(&app, "/admin/servers/update-kernels-all/sse").await;
    let resp = app
        .oneshot(Request::builder().uri(sse_uri).body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_body_string(resp).await;

    assert!(body.contains("✗ da-uk-all-1") || body.contains("da-uk-all-1: update skipped"));
    assert!(body.contains("✗ da-uk-all-2") || body.contains("da-uk-all-2: update skipped"));
    assert!(
        body.contains("done — updated kernels on 0/2 servers; failed: da-uk-all-1, da-uk-all-2")
    );
    assert!(body.contains("event: error"));
    assert!(!body.contains("event: ok"));
}

#[tokio::test]
async fn servers_update_kernels_all_sse_lock_reports_error_when_server_locked() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;

    let srv_id = "da-uk-all-lock";
    s.inv
        .add_server(&test_server(srv_id, "198.51.100.43"))
        .await
        .unwrap();

    let _guard = DeployGuard::try_acquire(srv_id).expect("must acquire deploy permit");

    let app = router(s);
    let sse_uri = ticketed_sse_uri(&app, "/admin/servers/update-kernels-all/sse").await;
    let resp = app
        .oneshot(Request::builder().uri(sse_uri).body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_body_string(resp).await;

    assert!(body.contains("deploy/update already running for server 'da-uk-all-lock'"));
    assert!(body.contains("failed: da-uk-all-lock"));
    assert!(body.contains("event: error"));
    assert!(!body.contains("event: ok"));
}

#[tokio::test]
async fn servers_update_kernels_all_sse_refuses_cross_origin() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let app = router(s);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/servers/update-kernels-all/sse")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
