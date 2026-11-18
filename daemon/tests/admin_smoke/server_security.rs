use axum::body::Body;
use axum::http::{Request, StatusCode, header, request::Builder};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use tempfile::TempDir;
use tower::ServiceExt;
use vpnctld::router;

use crate::common::{SAME_ORIGIN_HOST, add_same_origin, fetch_html, naive_server, seed, state};

const FLEET: &str = "/admin/monitoring/security";
const DETAIL: &str = "/admin/servers/s0/security";
const CHECK: &str = "/admin/servers/s0/security/check";
const APPLY: &str = "/admin/servers/s0/security/apply";
const SELECTED_PACKAGES: &str =
    "revision=1700000000000000&package=openssl&package=ca-certificates&confirm=yes";

fn post(path: &str) -> Builder {
    Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
}

fn assert_security_heading(html: &str) {
    assert!(
        (1..=6).any(|level| {
            let start = format!("<h{level}");
            let end = format!("</h{level}>");
            html.split(&start).skip(1).any(|heading| {
                heading
                    .split_once('>')
                    .and_then(|(_, heading)| heading.split_once(&end))
                    .is_some_and(|(heading, _)| heading.contains("Security updates"))
            })
        }),
        "expected a 'Security updates' heading"
    );
}

#[tokio::test]
async fn fleet_security_summary_describes_debian_and_ubuntu_coverage() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    let html = fetch_html(router(s), FLEET).await;

    assert_security_heading(&html);
    assert!(
        html.contains("Review pending Debian and Ubuntu security updates across your servers.")
    );
    assert!(
        html.contains(DETAIL),
        "the summary must link to the server report"
    );
}

#[tokio::test]
async fn fleet_security_route_preserves_overview_for_server_named_security() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv.add_server(&naive_server("security")).await.unwrap();
    let html = fetch_html(router(s), "/admin/servers/security").await;

    assert!(html.contains("Live status"));
}

#[tokio::test]
async fn server_without_security_report_shows_not_checked_and_no_install_action() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    let html = fetch_html(router(s), DETAIL).await;

    assert_security_heading(&html);
    assert!(html.contains("Not checked"));
    assert!(
        html.contains(CHECK),
        "the operator must be able to check the server"
    );
    assert!(
        !html.contains(APPLY),
        "the operator must not be offered installation before a report"
    );
}

#[tokio::test]
async fn security_report_for_unknown_server_is_not_found() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    let response = router(s)
        .oneshot(
            Request::builder()
                .uri("/admin/servers/unknown-server/security")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn security_install_requires_confirmation_and_at_least_one_package() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    let app = router(s);

    for body in [
        "revision=1700000000000000&package=openssl",
        "revision=1700000000000000&package=openssl&confirm=no",
        "revision=1700000000000000&confirm=yes",
        "revision=1700000000000000&package=&confirm=yes",
    ] {
        let response = app
            .clone()
            .oneshot(add_same_origin(post(APPLY)).body(Body::from(body)).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{body}");
    }
}

#[tokio::test]
async fn security_install_with_selected_packages_rejects_missing_report() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    let app = router(s);

    let response = app
        .clone()
        .oneshot(
            add_same_origin(post(APPLY))
                .body(Body::from(SELECTED_PACKAGES))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let html = fetch_html(app, DETAIL).await;
    assert!(html.contains("Not checked"));
    assert!(!html.contains(APPLY));
}

#[tokio::test]
async fn security_routes_require_auth_and_check_redirects_only_from_same_origin() {
    const CHILD: &str = "VPNCTL_SECURITY_UPDATES_AUTH_SMOKE_CHILD";
    const USER: &str = "security-updates-smoke";
    const PASSWORD: &str = "test-only-not-a-deployed-password";
    let dir = TempDir::new().unwrap();
    if std::env::var_os(CHILD).is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "server_security::security_routes_require_auth_and_check_redirects_only_from_same_origin",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("VPNCTLD_ADMIN_USER", USER)
            .env("VPNCTLD_ADMIN_PASSWORD", PASSWORD)
            .env("VPNCTLD_DEPLOY_KEY", dir.path().join("absent-deploy-key"))
            .status()
            .unwrap();
        assert!(status.success(), "isolated security updates smoke failed");
        return;
    }

    let s = state(&dir).await;
    let server = naive_server("s0");
    s.inv.add_server(&server).await.unwrap();
    let app = router(s);
    let auth = format!("Basic {}", STANDARD.encode(format!("{USER}:{PASSWORD}")));

    for (method, path, body) in [
        ("GET", FLEET, ""),
        ("GET", DETAIL, ""),
        ("POST", CHECK, ""),
        ("POST", APPLY, SELECTED_PACKAGES),
    ] {
        let request = add_same_origin(post(path).method(method));
        let response = app
            .clone()
            .oneshot(request.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {path}"
        );
        assert!(response.headers().contains_key(header::WWW_AUTHENTICATE));
    }

    for (path, body) in [(CHECK, ""), (APPLY, SELECTED_PACKAGES)] {
        for origin in [None, Some("http://foreign.example")] {
            let mut request = post(path)
                .header(header::AUTHORIZATION, &auth)
                .header(header::HOST, SAME_ORIGIN_HOST);
            if let Some(origin) = origin {
                request = request.header(header::ORIGIN, origin);
            }
            let response = app
                .clone()
                .oneshot(request.body(Body::from(body)).unwrap())
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "{path} {origin:?}"
            );
        }
    }

    let response = app
        .oneshot(
            add_same_origin(post(CHECK))
                .header(header::AUTHORIZATION, &auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()[header::LOCATION], DETAIL);
}
