use super::common::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;
use vpnctl_core::ServerId;
use vpnctl_inventory::{SshAccessCheck, SshAccessFailure, SshAccessRoute, SshAccessState};

#[tokio::test]
async fn direct_ssh_failure_and_jump_success_remain_separate_in_list_and_detail() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    seed(&st.inv, 2, 0, &[]).await;
    let pool =
        sqlx::SqlitePool::connect(&format!("sqlite://{}", dir.path().join("inv.db").display()))
            .await
            .unwrap();
    sqlx::query("UPDATE servers SET jump_via='s1' WHERE id='s0'")
        .execute(&pool)
        .await
        .unwrap();
    let target = st
        .inv
        .get_server(&ServerId("s0".into()))
        .await
        .unwrap()
        .unwrap();
    let jump = st
        .inv
        .get_server(&ServerId("s1".into()))
        .await
        .unwrap()
        .unwrap();
    let at = chrono::Utc::now() - chrono::Duration::seconds(2);
    st.inv
        .record_ssh_access(
            &target,
            SshAccessRoute::Direct,
            None,
            &SshAccessCheck {
                state: SshAccessState::Unavailable,
                failure: Some(SshAccessFailure::Timeout),
                checked_at: at,
            },
        )
        .await
        .unwrap();
    st.inv
        .record_ssh_access(
            &target,
            SshAccessRoute::Jump,
            Some(&jump),
            &SshAccessCheck {
                state: SshAccessState::Available,
                failure: None,
                checked_at: at,
            },
        )
        .await
        .unwrap();
    let app = vpnctld::router(st);
    for path in ["/admin/servers", "/admin/servers/s0/status"] {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
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
        assert!(body.contains("data-ssh-route=\"direct\""));
        assert!(body.contains("data-ssh-state=\"unavailable\""));
        assert!(body.contains("data-ssh-route=\"jump\""));
        assert!(body.contains("data-ssh-state=\"available\""));
        assert!(body.contains("Connection timed out"));
    }
}

#[tokio::test]
async fn ssh_empty_states_and_recheck_are_web_driven_in_both_languages() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    seed(&st.inv, 1, 0, &[]).await;
    let app = vpnctld::router(st);
    for (cookie, title, direct, jump, unknown, missing, button) in [
        (
            "vpnctl_lang=en",
            "SSH access",
            "Direct",
            "Via jump server",
            "Not verified",
            "Not configured",
            "Check SSH access",
        ),
        (
            "vpnctl_lang=ru",
            "SSH-доступ",
            "Напрямую",
            "Через jump-сервер",
            "Не проверен",
            "Не настроен",
            "Проверить SSH-доступ",
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/admin/servers/s0/status")
                    .header("cookie", cookie)
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
        for text in [
            title,
            direct,
            jump,
            unknown,
            missing,
            button,
            "/admin/servers/s0/ssh-check",
            "/admin/servers/s0/setup#routing-policy",
        ] {
            assert!(body.contains(text), "missing {text}");
        }
        assert!(!body.contains("data-ssh-state=\"available\""));
    }
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/servers/s0/ssh-check")
                .header("host", "localhost")
                .header("origin", "http://localhost")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response.headers()["location"],
        "/admin/servers/s0/status#ssh-access"
    );
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/servers/missing/ssh-check")
                .header("host", "localhost")
                .header("origin", "http://localhost")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
