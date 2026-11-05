#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "admin_smoke/common.rs"]
#[allow(dead_code)]
mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

const PATH: &str = "/admin/monitoring/private-checks";

// Isolate the admin credentials from other tests in the same process.
#[tokio::test]
async fn private_checks_admin_auth_csrf_and_empty_state() {
    const CHILD: &str = "VPNCTL_PRIVATE_CHECKS_SPEC_CHILD";
    const USER: &str = "private-checks-spec";
    const PASSWORD: &str = "test-only-not-a-deployed-password";
    if std::env::var_os(CHILD).is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "private_checks_admin_auth_csrf_and_empty_state",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("VPNCTLD_ADMIN_USER", USER)
            .env("VPNCTLD_ADMIN_PASSWORD", PASSWORD)
            .status()
            .unwrap();
        assert!(status.success(), "isolated private checks spec failed");
        return;
    }

    let dir = TempDir::new().unwrap();
    let app = vpnctld::router(common::state(&dir).await);
    let auth = format!("Basic {}", STANDARD.encode(format!("{USER}:{PASSWORD}")));

    for method in ["GET", "POST"] {
        for credentials in [None, Some("Basic invalid")] {
            let mut req = common::add_same_origin(Request::builder().method(method).uri(PATH));
            if let Some(credentials) = credentials {
                req = req.header("authorization", credentials);
            }
            let resp = app
                .clone()
                .oneshot(req.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::UNAUTHORIZED,
                "{method} must require admin credentials"
            );
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
        let resp = app
            .clone()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "POST must enforce admin CSRF protection"
        );
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(String::from_utf8_lossy(&body).contains("vpnctl admin: csrf"));
    }

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(PATH)
                .header("authorization", &auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8(body.to_vec()).unwrap().to_lowercase();
    assert!(
        [
            "no server",
            "no servers",
            "нет сервер",
            "серверов нет",
            "сервер не добавлен",
            "серверы не добавлены"
        ]
        .iter()
        .any(|s| html.contains(s)),
        "empty inventory must be explained on the page: {html}"
    );
    assert!(
        [
            "no result",
            "not checked",
            "not yet",
            "нет результат",
            "результатов нет",
            "ещё не",
            "еще не",
            "не провер"
        ]
        .iter()
        .any(|s| html.contains(s)),
        "initial lack of results must be explained on the page: {html}"
    );

    let req = common::add_same_origin(Request::builder().method("POST").uri(PATH))
        .header("authorization", auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert!(
        resp.status().is_success() || resp.status().is_redirection(),
        "authenticated same-origin POST must be accepted; got {}",
        resp.status()
    );
}
