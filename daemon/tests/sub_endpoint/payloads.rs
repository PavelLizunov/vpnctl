use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header::CONTENT_TYPE};
use http_body_util::BodyExt;
use serde_json::Value;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{KernelId, ProtocolId, Registry, Server, ServerId, User, UserId};
use vpnctl_inventory::SqliteInventory;
use vpnctl_kernels::SingBox;
use vpnctl_protocols::{TuicV5, VlessReality, WireGuard};
use vpnctld::router;

use super::common::seed;

#[tokio::test]
async fn health_returns_stable_runtime_contract() {
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
    assert_eq!(
        resp.headers().get(CONTENT_TYPE).unwrap(),
        "application/json"
    );
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    // Stable contract: `version` stays plain SemVer (machine-readable,
    // greppable); `build` carries provenance `<semver>+<short-git-sha>`
    // so the deployed commit is identifiable without breaking scripts
    // that parse `version`.
    let expected = format!(
        r#"{{"status":"ok","version":"{}","build":"{}"}}"#,
        env!("CARGO_PKG_VERSION"),
        vpnctl_core::build_version()
    );
    assert_eq!(body.as_ref(), expected.as_bytes());
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

/// Sibling of the protocol exclusion tests for WireGuard.
/// WireGuard's `client_config()` is an INTERNAL `{ type: "wireguard",
/// interface, peer }` object (the wg-quick / AmneziaWG shape), NOT a
/// valid sing-box outbound — sing-box's wireguard outbound is a flat
/// `server` / `server_port` / `private_key` / `peer_public_key` object.
/// Pre-fix the protocol inherited the default `appears_in_sing_box_sub()
/// == true`, so a mixed server leaked this internal object into the /sub
/// envelope and sing-box / Hiddify dropped EVERY route. This pins the
/// exclusion end-to-end through the real router: the valid vless outbound
/// survives, the wireguard internal object does not.
#[tokio::test]
async fn sub_skips_wireguard_protocol_in_sing_box_envelope() {
    let dir = TempDir::new().unwrap();
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    let mut reg = Registry::new();
    reg.register_kernel(Box::new(SingBox::new())).unwrap();
    reg.register_protocol(Box::new(VlessReality::new()))
        .unwrap();
    // Register wireguard so the registry lookup succeeds — the WHOLE
    // point is to verify the handler then SKIPS its client_config rather
    // than emitting the internal `{"type":"wireguard", interface, peer}`.
    reg.register_protocol(Box::new(WireGuard::new())).unwrap();

    // Server with BOTH protocols enabled. Without the filter, the sub
    // envelope would carry the internal wireguard object and sing-box
    // would refuse the entire config.
    let server = Server {
        id: ServerId("mixed".into()),
        address: "10.0.0.52".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![
            ProtocolId("vless+reality".into()),
            ProtocolId("wireguard".into()),
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
    // WireGuard server pubkey present so that, IF the filter were
    // missing, client_config WOULD render (proving the test isn't
    // vacuously passing because of a missing-secret skip).
    inv.set_server_secret(
        &server.id,
        "wireguard.server_public_key",
        "Qhh7nQwL+0fH3iZ8VAEcvVNlEMU8r9SiH3LzAh6Kj3o=",
    )
    .await
    .unwrap();

    let user = User {
        id: UserId("u1".into()),
        uuid: "uuid-u1".into(),
        tuic_password: None,
        wireguard_pubkey: Some("qXFvJL5KLmM3Of9hVo5GmJ4n0LB9rWYfV4ZE1XGZJks=".into()),
        wireguard_private: Some("0000000000000000000000000000000000000000000=".into()),
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
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
    let outbounds = v["outbounds"].as_array().expect("outbounds is array");

    // No outbound may carry the internal wireguard object.
    for ob in outbounds {
        let ty = ob["type"].as_str().unwrap_or("");
        assert_ne!(
            ty, "wireguard",
            "wireguard internal object leaked into sing-box sub envelope: {ob:?}. \
             /sub handler must filter via Protocol::appears_in_sing_box_sub()."
        );
    }
    // And the legit vless+reality outbound IS present.
    let has_vless = outbounds
        .iter()
        .any(|ob| ob["type"].as_str() == Some("vless"));
    assert!(
        has_vless,
        "vless+reality outbound is missing — filter dropped too much: {outbounds:?}"
    );
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
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
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

/// Baseline security response headers (X-Content-Type-Options: nosniff,
/// X-Frame-Options: DENY, Referrer-Policy: no-referrer) must be attached to
/// public API and subscription endpoints for defense-in-depth against MIME
/// sniffing, framing, and leaking secret subscription tokens / device IDs.
#[tokio::test]
async fn public_endpoints_carry_security_response_headers() {
    let dir = TempDir::new().unwrap();
    let (state, _token) = seed(&dir).await;
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

    assert_eq!(
        resp.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );
    assert_eq!(resp.headers().get("x-frame-options").unwrap(), "DENY");
    assert_eq!(
        resp.headers().get("referrer-policy").unwrap(),
        "no-referrer"
    );

    let dir2 = TempDir::new().unwrap();
    let (state2, token2) = seed(&dir2).await;
    let app2 = router(state2);
    let resp = app2
        .oneshot(
            Request::builder()
                .uri(format!("/sub/{token2}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );
    assert_eq!(resp.headers().get("x-frame-options").unwrap(), "DENY");
    assert_eq!(
        resp.headers().get("referrer-policy").unwrap(),
        "no-referrer"
    );
}
