//! Phase A smoke: GET /admin/ renders the editorial shell.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::Registry;
use vpnctl_inventory::SqliteInventory;
use vpnctl_kernels::SingBox;
use vpnctl_protocols::{TuicV5, VlessReality};
use vpnctld::{AppState, router};

async fn state(dir: &TempDir) -> AppState {
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    let mut reg = Registry::new();
    reg.register_kernel(Box::new(SingBox::new())).unwrap();
    reg.register_protocol(Box::new(VlessReality::new()))
        .unwrap();
    reg.register_protocol(Box::new(TuicV5::new())).unwrap();
    AppState {
        inv,
        registry: Arc::new(reg),
    }
}

#[tokio::test]
async fn admin_root_renders_editorial_shell() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "expected 200, got {:?}",
        resp.status()
    );
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();

    // The chrome was rendered.
    assert!(html.contains("ed-mast"), "missing masthead in html");
    assert!(html.contains("ed-mast__nav-inline"), "missing nav");
    assert!(html.contains("Tweaks"), "missing tweaks panel");
    assert!(html.contains("vpnctl"), "missing wordmark text");
    // The page-root class should default to bare "ed" (no theme/accent
    // cookies set in this test).
    assert!(
        html.contains(r#"class="ed""#),
        "expected default page class \"ed\", got: {}",
        &html[..html.len().min(400)]
    );
}

#[tokio::test]
async fn admin_assets_admin_css_served() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/assets/admin.css")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert!(body.len() > 10_000, "css too small: {} bytes", body.len());
    assert!(std::str::from_utf8(&body).unwrap().contains("--paper"));
}

#[tokio::test]
async fn admin_tweak_theme_sets_cookie_and_redirects() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/tweak/theme")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("referer", "/admin/")
                .body(Body::from("value=foxed"))
                .unwrap(),
        )
        .await
        .unwrap();
    // Redirect with Set-Cookie.
    assert!(
        resp.status() == StatusCode::SEE_OTHER || resp.status() == StatusCode::TEMPORARY_REDIRECT,
        "expected 303/307, got {:?}",
        resp.status()
    );
    let cookie = resp
        .headers()
        .get("set-cookie")
        .expect("set-cookie missing")
        .to_str()
        .unwrap();
    assert!(cookie.contains("vpnctl_theme=foxed"));
    assert!(cookie.contains("Path=/admin"));
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("SameSite=Lax"));
}

#[tokio::test]
async fn admin_tweak_rejects_unknown_value() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/tweak/theme")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("value=neon"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn admin_respects_theme_and_accent_cookies() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/")
                .header("cookie", "vpnctl_theme=foxed; vpnctl_accent=plum")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        html.contains("ed-foxed") && html.contains("ed-acc-plum"),
        "expected ed-foxed AND ed-acc-plum on root, got class extract: {}",
        html.split("class=\"")
            .nth(1)
            .unwrap_or("?")
            .split('"')
            .next()
            .unwrap_or("?")
    );
}
