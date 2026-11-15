use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;
use vpnctl_core::{KernelId, ProtocolId, Server, ServerId};

use super::common::state;

#[tokio::test]
async fn private_checks_use_inventory_ports_and_same_origin() {
    let dir = tempfile::tempdir().unwrap();
    let state = state(&dir).await;
    let sid = ServerId("<test>".into());
    state
        .inv
        .add_server(&Server {
            id: sid.clone(),
            address: "127.0.0.1".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![
                ProtocolId("vless+reality".into()),
                ProtocolId("hysteria2".into()),
            ],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    state
        .inv
        .set_server_secret(&sid, "vless.listen_port", "12345")
        .await
        .unwrap();
    let app = vpnctld::router(state);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/monitoring/private-checks")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("&lt;test&gt;"));
    assert!(!body.contains("<test>"));
    assert!(body.contains("12345"));
    assert!(body.contains("hysteria2"));
    assert!(body.contains("Not checked"));
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/monitoring/private-checks")
                .header("host", "local.test")
                .header("origin", "http://evil.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/monitoring/private-checks")
                .header("host", "local.test")
                .header("origin", "http://local.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
}
