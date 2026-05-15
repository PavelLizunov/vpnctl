//! End-to-end tests of the /sub/<token> endpoint against the REAL
//! `vpnctld::router()` (no shim — addresses critical review-finding
//! that shim-tests cannot detect regressions in the production handler).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{KernelId, ProtocolId, Registry, Server, ServerId, User, UserId};
use vpnctl_inventory::SqliteInventory;
use vpnctl_kernels::SingBox;
use vpnctl_protocols::{TuicV5, VlessReality};
use vpnctld::{AppState, router};

async fn seed(dir: &TempDir) -> (AppState, String) {
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .expect("open db");
    let mut reg = Registry::new();
    reg.register_kernel(Box::new(SingBox::new())).unwrap();
    reg.register_protocol(Box::new(VlessReality::new()))
        .unwrap();
    reg.register_protocol(Box::new(TuicV5::new())).unwrap();

    let server = Server {
        id: ServerId("srv".into()),
        address: "10.0.0.1".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernel: KernelId("sing-box".into()),
        enabled_protocols: vec![
            ProtocolId("vless+reality".into()),
            ProtocolId("tuic-v5".into()),
        ],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    };
    inv.add_server(&server).await.unwrap();
    inv.set_server_secret(&server.id, "vless.public_key", "PUB_TEST")
        .await
        .unwrap();
    inv.set_server_secret(&server.id, "vless.short_id", "12345678")
        .await
        .unwrap();

    let user = User {
        id: UserId("alice".into()),
        uuid: "uuid-alice".into(),
        tuic_password: Some("pw-alice".into()),
        wireguard_pubkey: None,
        sub_token: None,
    };
    inv.add_user(&user).await.unwrap();
    inv.grant(&user.id, &server.id).await.unwrap();
    let token = inv
        .get_user(&user.id)
        .await
        .unwrap()
        .unwrap()
        .sub_token
        .unwrap();

    let (state, _writer) = vpnctld::make_app_state_for_tests(inv, Arc::new(reg));
    (state, token)
}

#[tokio::test]
async fn health_returns_200_ok() {
    let dir = TempDir::new().unwrap();
    let (state, _) = seed(&dir).await;
    let app = router(state);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["status"], "ok");
    assert!(v["version"].is_string());
}

#[tokio::test]
async fn sub_unknown_token_returns_404() {
    let dir = TempDir::new().unwrap();
    let (state, _) = seed(&dir).await;
    let app = router(state);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/sub/definitely-not-a-real-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn sub_valid_token_returns_full_envelope_with_tags() {
    let dir = TempDir::new().unwrap();
    let (state, token) = seed(&dir).await;
    let app = router(state);

    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/sub/{token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&body).unwrap();

    // Real envelope has `log`, `route`, AND outbounds with selector +
    // direct + block. Shim-test would have missed this.
    assert!(v["log"].is_object());
    assert!(v["route"].is_object());
    let outbounds = v["outbounds"].as_array().unwrap();
    // Expected: [selector, srv-vless+reality, srv-tuic-v5, direct, block] = 5
    assert_eq!(outbounds.len(), 5, "outbounds: {outbounds:?}");
    assert_eq!(outbounds[0]["type"], "selector");
    assert_eq!(outbounds[0]["tag"], "proxy");
    assert_eq!(outbounds[outbounds.len() - 2]["type"], "direct");
    assert_eq!(outbounds[outbounds.len() - 1]["type"], "block");

    let serialised = std::str::from_utf8(&body).unwrap();
    assert!(serialised.contains("uuid-alice"));
    assert!(serialised.contains("pw-alice"));
}

#[tokio::test]
async fn sub_token_for_user_with_no_grants_yields_only_direct_block() {
    let dir = TempDir::new().unwrap();
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    let mut reg = Registry::new();
    reg.register_kernel(Box::new(SingBox::new())).unwrap();
    reg.register_protocol(Box::new(VlessReality::new()))
        .unwrap();
    reg.register_protocol(Box::new(TuicV5::new())).unwrap();
    let user = User {
        id: UserId("solo".into()),
        uuid: "uuid-solo".into(),
        tuic_password: Some("pw".into()),
        wireguard_pubkey: None,
        sub_token: None,
    };
    inv.add_user(&user).await.unwrap();
    let token = inv
        .get_user(&user.id)
        .await
        .unwrap()
        .unwrap()
        .sub_token
        .unwrap();

    let (state, _writer) = vpnctld::make_app_state_for_tests(inv, Arc::new(reg));
    let app = router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/sub/{token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&body).unwrap();
    let outbounds = v["outbounds"].as_array().unwrap();
    // No selector when no grants — but `direct` and `block` always present.
    assert_eq!(outbounds.len(), 2, "outbounds: {outbounds:?}");
    assert_eq!(outbounds[0]["type"], "direct");
    assert_eq!(outbounds[1]["type"], "block");
}
