#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "admin_smoke/common.rs"]
#[allow(dead_code)]
mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::BodyExt;
use tower::ServiceExt;
use vpnctl_core::{KernelId, ProtocolId, Server, ServerId};

const PATH: &str = "/admin/monitoring/private-checks";

#[tokio::test]
async fn manual_private_sweep_requires_admin_and_same_origin() {
    const CHILD: &str = "VPNCTL_PRIVATE_SOURCES_SPEC_CHILD";
    const USER: &str = "private-sources-spec";
    const PASSWORD: &str = "test-only-not-a-deployed-password";
    if std::env::var_os(CHILD).is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "manual_private_sweep_requires_admin_and_same_origin",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("VPNCTLD_ADMIN_USER", USER)
            .env("VPNCTLD_ADMIN_PASSWORD", PASSWORD)
            .status()
            .unwrap();
        assert!(status.success(), "isolated private sources spec failed");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let state = common::state(&dir).await;
    state
        .inv
        .add_server(&Server {
            id: ServerId("udp-target".into()),
            address: "127.0.0.1".into(),
            ssh_port: 1,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![ProtocolId("hysteria2".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let app = vpnctld::router(state);
    let auth = format!("Basic {}", STANDARD.encode(format!("{USER}:{PASSWORD}")));

    for method in ["GET", "POST"] {
        for credentials in [None, Some("Basic invalid")] {
            let mut req = common::add_same_origin(Request::builder().method(method).uri(PATH));
            if let Some(credentials) = credentials {
                req = req.header("authorization", credentials);
            }
            let response = app
                .clone()
                .oneshot(req.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{method}");
        }
    }
    for origin in [None, Some("http://evil.attacker.example")] {
        let mut req = Request::builder()
            .method("POST")
            .uri(PATH)
            .header("authorization", &auth)
            .header("host", common::SAME_ORIGIN_HOST);
        if let Some(origin) = origin {
            req = req.header("origin", origin);
        }
        let response = app
            .clone()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    let response = app
        .clone()
        .oneshot(
            common::add_same_origin(Request::builder().method("POST").uri(PATH))
                .header("authorization", &auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(response.status().is_success() || response.status().is_redirection());

    let response = app
        .oneshot(
            Request::builder()
                .uri(PATH)
                .header("authorization", auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(html.contains("udp-target"));
    assert!(html.contains("hysteria2"));
}
