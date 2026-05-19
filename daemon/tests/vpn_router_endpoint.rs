//! End-to-end tests of the ninitux compatibility endpoint
//! `GET /api/v1/app/config/{device_id}` against the real `vpnctld::router()`.
//!
//! Covers:
//!   * HTTP 200 ALWAYS — anti-fingerprinting against probes that would
//!     otherwise tell a missing device_id from a valid one via the
//!     status code.
//!   * UA-based content negotiation: VPN clients get `text/plain`
//!     raw base64; browsers / curl / custom apps get the JSON wrapper.
//!   * Malformed device_id (non-32-hex) returns the SAME shape as a
//!     valid-but-unregistered device — never leaks via status code or
//!     body length.
//!   * JSON wrapper byte-shape: keys appear in declared order
//!     (`status, app, version, update_available, config, check_interval,
//!     timestamp`), compact (no whitespace), `config: null` literal
//!     when missing.
//!   * Base64 decodes to newline-joined vless:// URIs in the order
//!     `servers_for_user` returned (deterministic).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use http_body_util::BodyExt;
use serde_json::Value;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{KernelId, ProtocolId, Registry, Server, ServerId, User, UserId};
use vpnctl_inventory::SqliteInventory;
use vpnctl_kernels::SingBox;
use vpnctl_protocols::VlessReality;
use vpnctld::{AppState, router};

const TEST_DEVICE_ID: &str = "a92b915032b48a2ed45ef72f4171e5f4";
const ALT_DEVICE_ID: &str = "deadbeefdeadbeefdeadbeefdeadbeef";

async fn seed_state(dir: &TempDir) -> AppState {
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    let mut reg = Registry::new();
    reg.register_kernel(Box::new(SingBox::new())).unwrap();
    reg.register_protocol(Box::new(VlessReality::new()))
        .unwrap();

    // Two servers — confirms the handler iterates over multiple
    // granted servers + builds one URI per server in deterministic
    // order. Both carry the vless+reality secrets; one server (`stg`)
    // is granted but has NO vless.public_key — should be skipped
    // silently, not crash the whole response.
    for sid in ["vps-de-01", "vps-is-01"] {
        let server = Server {
            id: ServerId(sid.into()),
            address: format!("{sid}.example.com"),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![ProtocolId("vless+reality".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        };
        inv.add_server(&server).await.unwrap();
        inv.set_server_secret(&server.id, "vless.public_key", &format!("PUB_{sid}"))
            .await
            .unwrap();
        inv.set_server_secret(&server.id, "vless.short_id", "12345678")
            .await
            .unwrap();
    }

    // Server with NO vless secrets — should be silently skipped by the
    // handler (no public_key → no URI rendered for this server).
    let bare_server = Server {
        id: ServerId("bare".into()),
        address: "bare.example.com".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("vless+reality".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    };
    inv.add_server(&bare_server).await.unwrap();

    let user = User {
        id: UserId("tester-1".into()),
        uuid: "11111111-2222-3333-4444-555555555555".into(),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
    };
    inv.add_user(&user).await.unwrap();
    inv.set_vpn_router_device_id(&user.id, TEST_DEVICE_ID)
        .await
        .unwrap();
    inv.grant(&user.id, &ServerId("vps-de-01".into()))
        .await
        .unwrap();
    inv.grant(&user.id, &ServerId("vps-is-01".into()))
        .await
        .unwrap();
    inv.grant(&user.id, &ServerId("bare".into())).await.unwrap();

    let (state, _writer) = vpnctld::make_app_state_for_tests(inv, Arc::new(reg));
    state
}

async fn get(app: axum::Router, path: &str, user_agent: &str) -> (StatusCode, Vec<u8>, String) {
    let resp = app
        .oneshot(
            Request::builder()
                .uri(path)
                .header("user-agent", user_agent)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, body.to_vec(), ct)
}

#[tokio::test]
async fn vpn_router_valid_device_id_browser_ua_returns_json_wrapper() {
    let dir = TempDir::new().unwrap();
    let state = seed_state(&dir).await;
    let app = router(state);

    let (status, body, ct) = get(
        app,
        &format!("/api/v1/app/config/{TEST_DEVICE_ID}"),
        "Mozilla/5.0 Firefox/138.0",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(ct.starts_with("application/json"), "ct={ct}");

    let v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["status"], "ok");
    assert_eq!(v["app"], "vpn-router");
    assert_eq!(v["version"], "2.4.1");
    assert_eq!(v["update_available"], false);
    assert_eq!(v["check_interval"], 3600);
    assert!(v["timestamp"].is_u64());
    // config: base64 of two vless:// URIs (de-01, is-01), bare server skipped.
    let cfg = v["config"].as_str().unwrap();
    let decoded = BASE64_STANDARD.decode(cfg).unwrap();
    let s = std::str::from_utf8(&decoded).unwrap();
    let lines: Vec<&str> = s.split('\n').collect();
    assert_eq!(lines.len(), 2, "expected 2 vless URIs, got: {s}");
    // Order is determined by `servers_for_user` which `ORDER BY g.server_id`.
    assert!(
        lines[0].contains("@vps-de-01.example.com:443"),
        "first URI = vps-de-01: {}",
        lines[0]
    );
    assert!(
        lines[1].contains("@vps-is-01.example.com:443"),
        "second URI = vps-is-01: {}",
        lines[1]
    );
    // Both URIs use the user's global uuid (no per-server override
    // pinned in this test).
    for line in &lines {
        assert!(line.contains("11111111-2222-3333-4444-555555555555"));
    }
    // Fragment has stripped server tag + port + client_name.
    assert!(lines[0].contains("#de-01%20443%20tester-1"));
    assert!(lines[1].contains("#is-01%20443%20tester-1"));
}

#[tokio::test]
async fn vpn_router_valid_device_id_vpn_client_ua_returns_raw_base64() {
    let dir = TempDir::new().unwrap();
    let state = seed_state(&dir).await;
    let app = router(state);

    let (status, body, ct) = get(
        app,
        &format!("/api/v1/app/config/{TEST_DEVICE_ID}"),
        "v2rayN/6.62",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(ct.starts_with("text/plain"), "ct={ct}");

    // No JSON wrapper — body IS the base64 string (and only the base64).
    let body_str = std::str::from_utf8(&body).unwrap();
    assert!(!body_str.starts_with('{'));
    let decoded = BASE64_STANDARD.decode(body_str).unwrap();
    let s = std::str::from_utf8(&decoded).unwrap();
    assert!(s.starts_with("vless://"));
    assert_eq!(s.matches('\n').count(), 1, "two URIs separated by \\n");
}

#[tokio::test]
async fn vpn_router_unregistered_device_browser_ua_returns_device_not_registered() {
    let dir = TempDir::new().unwrap();
    let state = seed_state(&dir).await;
    let app = router(state);

    let (status, body, ct) = get(
        app,
        &format!("/api/v1/app/config/{ALT_DEVICE_ID}"),
        "Mozilla/5.0",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "MUST be 200 — anti-fingerprinting");
    assert!(ct.starts_with("application/json"));
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["status"], "device_not_registered");
    assert_eq!(v["app"], "vpn-router");
    assert!(v["config"].is_null(), "config: null literal expected");
}

#[tokio::test]
async fn vpn_router_unregistered_device_vpn_client_ua_returns_empty_body() {
    let dir = TempDir::new().unwrap();
    let state = seed_state(&dir).await;
    let app = router(state);

    let (status, body, ct) = get(
        app,
        &format!("/api/v1/app/config/{ALT_DEVICE_ID}"),
        "Hiddify/1.5.3",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(ct.starts_with("text/plain"));
    assert!(
        body.is_empty(),
        "empty raw body for unregistered + VPN client UA"
    );
}

#[tokio::test]
async fn vpn_router_malformed_device_id_returns_device_not_registered_shape() {
    let dir = TempDir::new().unwrap();
    let state = seed_state(&dir).await;
    // Build the router ONCE and clone it per iteration — axum's
    // `Router` is `Clone` and each oneshot consumes a copy. Building
    // a fresh state per iteration would try to re-insert the same
    // servers into the shared inv.db file and fail with AlreadyExists.
    let app = router(state);

    // Too-short, contains non-hex, completely arbitrary — all must
    // yield the same response as an unregistered device. NEVER 404 /
    // 400 (probes would distinguish those from 200).
    for bad in [
        "notahex",
        "deadbeef",                                                 // 8 hex (too short)
        "DEADBEEFDEADBEEFDEADBEEFDEADBEEF",                         // 32 chars but UPPERCASE
        "g0000000000000000000000000000000",                         // 32 chars but invalid hex
        "a92b915032b48a2ed45ef72f4171e5f4a92b915032b48a2ed45ef72f", // too long
    ] {
        let req = Request::builder()
            .uri(format!("/api/v1/app/config/{bad}"))
            .header("user-agent", "Mozilla/5.0")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "bad={bad:?}");
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            v["status"], "device_not_registered",
            "bad={bad:?} body={body:?}"
        );
        assert!(v["config"].is_null(), "bad={bad:?}");
    }
}

#[tokio::test]
async fn vpn_router_response_key_order_matches_ninitux_pydantic() {
    let dir = TempDir::new().unwrap();
    let state = seed_state(&dir).await;
    let app = router(state);

    let (_, body, _) = get(
        app,
        &format!("/api/v1/app/config/{TEST_DEVICE_ID}"),
        "Mozilla/5.0",
    )
    .await;
    let body_str = std::str::from_utf8(&body).unwrap();
    // Find positions of each key — they MUST be in declared order.
    let keys = [
        "\"status\"",
        "\"app\"",
        "\"version\"",
        "\"update_available\"",
        "\"config\"",
        "\"check_interval\"",
        "\"timestamp\"",
    ];
    let positions: Vec<_> = keys
        .iter()
        .map(|k| {
            body_str
                .find(k)
                .unwrap_or_else(|| panic!("key {k} missing from response: {body_str}"))
        })
        .collect();
    for window in positions.windows(2) {
        assert!(
            window[0] < window[1],
            "keys out of order: {positions:?} for {body_str}"
        );
    }
    // And no whitespace between key/value (compact JSON, matching
    // fastapi's `separators=(",", ":")`).
    assert!(
        !body_str.contains(": "),
        "compact JSON expected: {body_str}"
    );
    assert!(
        !body_str.contains(", "),
        "compact JSON expected: {body_str}"
    );
}

#[tokio::test]
async fn vpn_router_per_server_uuid_override_lands_in_uri() {
    // When `grants.client_uuid` is overridden (Phase 1 + 2), the
    // vless URI emitted by this endpoint MUST use that override —
    // not the user's global uuid. This pins the Phase 2 ↔ Phase 3
    // wiring.
    let dir = TempDir::new().unwrap();
    let state = seed_state(&dir).await;

    state
        .inv
        .set_grant_client_uuid(
            &UserId("tester-1".into()),
            &ServerId("vps-de-01".into()),
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        )
        .await
        .unwrap();

    let app = router(state);
    let (status, body, _) = get(
        app,
        &format!("/api/v1/app/config/{TEST_DEVICE_ID}"),
        "Mozilla/5.0",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let v: Value = serde_json::from_slice(&body).unwrap();
    let cfg = v["config"].as_str().unwrap();
    let decoded = BASE64_STANDARD.decode(cfg).unwrap();
    let s = std::str::from_utf8(&decoded).unwrap();

    // The de-01 URI uses the overridden uuid; the is-01 URI uses
    // the user's global uuid (no override pinned there).
    assert!(
        s.contains("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@vps-de-01.example.com"),
        "de-01 should use override uuid: {s}"
    );
    assert!(
        s.contains("vless://11111111-2222-3333-4444-555555555555@vps-is-01.example.com"),
        "is-01 should fall back to global uuid: {s}"
    );
}
