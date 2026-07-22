//! End-to-end tests of the /sub/<token> endpoint against the REAL
//! `vpnctld::router()` (no shim — addresses critical review-finding
//! that shim-tests cannot detect regressions in the production handler).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

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
        kernels: vec![KernelId("sing-box".into())],
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
        wireguard_private: None,
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
    (state, token)
}

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
    let expected = format!(
        r#"{{"status":"ok","version":"{}"}}"#,
        env!("CARGO_PKG_VERSION")
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

/// Regression for Pavel's 2026-05-19 question «wgturn находится
/// внутри обычной подписки, это не будет проблемой? он же не
/// поддерживается в рамках sing-box?» — confirmed bug: pre-fix,
/// the /sub handler iterated server.enabled_protocols and called
/// `client_config` on every one, including wgturn. Wgturn's
/// `client_config` returned `{ "type": "wgturn" }` which sing-box
/// has no parser for → whole envelope unusable.
///
/// Post-fix: the Protocol trait grew `appears_in_sing_box_sub()`
/// (default true; wgturn overrides to false), and the sub handler
/// filters on it. This test pins the contract end-to-end through
/// the real router.
#[tokio::test]
async fn sub_skips_wgturn_protocol_in_sing_box_envelope() {
    use vpnctl_protocols::WgTurn;
    let dir = TempDir::new().unwrap();
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    let mut reg = Registry::new();
    reg.register_kernel(Box::new(SingBox::new())).unwrap();
    reg.register_protocol(Box::new(VlessReality::new()))
        .unwrap();
    // Register wgturn so the registry lookup succeeds — the WHOLE
    // point of the test is to verify that the handler then SKIPS
    // its client_config rather than emitting `{"type":"wgturn"}`.
    reg.register_protocol(Box::new(WgTurn::new())).unwrap();

    // Server with BOTH protocols enabled. Without the filter, the
    // sub envelope would carry a wgturn outbound and sing-box would
    // refuse the entire config.
    let server = Server {
        id: ServerId("mixed".into()),
        address: "10.0.0.50".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![
            ProtocolId("vless+reality".into()),
            ProtocolId("wgturn".into()),
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
        id: UserId("u1".into()),
        uuid: "uuid-u1".into(),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
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

    // No outbound should have type=wgturn.
    for ob in outbounds {
        let ty = ob["type"].as_str().unwrap_or("");
        assert_ne!(
            ty, "wgturn",
            "wgturn outbound leaked into sing-box sub envelope: {ob:?}. \
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

/// Sibling of `sub_skips_wgturn_protocol_in_sing_box_envelope` for
/// dns-tunnel. dns-tunnel is ALSO a non-sing-box two-process bundle
/// (`appears_in_sing_box_sub() == false` — slipstream-client + loopback
/// VLESS), so a `type: "dns-tunnel"` object in the /sub envelope would
/// make the whole config unparseable and sing-box / Hiddify would drop
/// EVERY route (including the working VLESS one). This pins the
/// exclusion end-to-end through the real router: surfacing dns-tunnel
/// elsewhere (the per-user Flow E card / CLI `vpnctl sub`) must NOT leak
/// it into the strict sing-box base64/JSON sub.
#[tokio::test]
async fn sub_skips_dns_tunnel_protocol_in_sing_box_envelope() {
    use vpnctl_protocols::DnsTunnel;
    let dir = TempDir::new().unwrap();
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    let mut reg = Registry::new();
    reg.register_kernel(Box::new(SingBox::new())).unwrap();
    reg.register_protocol(Box::new(VlessReality::new()))
        .unwrap();
    // Register dns-tunnel so the registry lookup succeeds — the WHOLE
    // point is to verify the handler then SKIPS its client_config
    // rather than emitting `{"type":"dns-tunnel"}`.
    reg.register_protocol(Box::new(DnsTunnel::new())).unwrap();

    // Server with BOTH protocols enabled. Without the filter, the sub
    // envelope would carry a dns-tunnel outbound and sing-box would
    // refuse the entire config.
    let server = Server {
        id: ServerId("mixed".into()),
        address: "10.0.0.51".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![
            ProtocolId("vless+reality".into()),
            ProtocolId("dns-tunnel".into()),
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
    // dns-tunnel share-link secrets — present so that, IF the filter
    // were missing, the protocol WOULD render (proving the test isn't
    // vacuously passing because of a missing-secret skip).
    inv.set_server_secret(&server.id, "dns-tunnel:domain", "t.example.com")
        .await
        .unwrap();
    inv.set_server_secret(
        &server.id,
        "dns-tunnel:fingerprint",
        "47:1E:87:8F:3E:48:C8:1C",
    )
    .await
    .unwrap();

    let user = User {
        id: UserId("u1".into()),
        uuid: "uuid-u1".into(),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
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
    let serialised = std::str::from_utf8(&body).unwrap();
    // The custom scheme must never appear in the sing-box envelope.
    assert!(
        !serialised.contains("dns-tunnel"),
        "dns-tunnel leaked into the sing-box sub envelope: {serialised}"
    );
    let v: Value = serde_json::from_slice(&body).unwrap();
    let outbounds = v["outbounds"].as_array().expect("outbounds is array");
    for ob in outbounds {
        let ty = ob["type"].as_str().unwrap_or("");
        assert_ne!(
            ty, "dns-tunnel",
            "dns-tunnel outbound leaked into sing-box sub envelope: {ob:?}. \
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

/// dns-tunnel must ALSO stay out of the V2Ray-family base64 sub. That
/// path (`resolve_v2ray_subscription`) hard-allowlists schemes
/// (vless/vmess/trojan/ss/ssr/tuic/hy2/anytls); a `dns-tunnel://` line
/// would either be dropped or crash a strict importer. This pins that a
/// v2rayNG-shaped UA pulling the same mixed server gets the vless URI
/// and NOT the `dns-tunnel://` link.
#[tokio::test]
async fn v2ray_sub_excludes_dns_tunnel_share_link() {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use vpnctl_protocols::DnsTunnel;

    let dir = TempDir::new().unwrap();
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    let mut reg = Registry::new();
    reg.register_kernel(Box::new(SingBox::new())).unwrap();
    reg.register_protocol(Box::new(VlessReality::new()))
        .unwrap();
    reg.register_protocol(Box::new(DnsTunnel::new())).unwrap();

    let server = Server {
        id: ServerId("mixed".into()),
        address: "10.0.0.52".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![
            ProtocolId("vless+reality".into()),
            ProtocolId("dns-tunnel".into()),
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
    inv.set_server_secret(&server.id, "dns-tunnel:domain", "t.example.com")
        .await
        .unwrap();
    inv.set_server_secret(
        &server.id,
        "dns-tunnel:fingerprint",
        "47:1E:87:8F:3E:48:C8:1C",
    )
    .await
    .unwrap();

    let user = User {
        id: UserId("u1".into()),
        uuid: "uuid-u1".into(),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
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
                .header("user-agent", "v2rayNG/1.9.0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let b64 = std::str::from_utf8(&body).unwrap();
    let decoded = BASE64_STANDARD.decode(b64.trim()).unwrap();
    let lines = std::str::from_utf8(&decoded).unwrap();
    assert!(
        lines.contains("vless://"),
        "v2ray sub must carry the vless URI: {lines}"
    );
    assert!(
        !lines.contains("dns-tunnel"),
        "dns-tunnel:// leaked into the V2Ray base64 sub: {lines}"
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

// ────────────────────────────────────────────────────────────────────────
//  Phase Track-2 — rate limit on /sub/<token>
//
//  Pin the throttle contract end-to-end through the public router:
//  given a tight bucket (capacity=2, no refill), the 3rd request
//  inside the burst window must come back 429 with `Retry-After`.
//  The 1st and 2nd must succeed normally.
// ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn sub_rate_limit_returns_429_after_burst() {
    use std::sync::Arc;
    use std::time::Duration;
    use vpnctl_inventory::SqliteInventory;
    use vpnctl_kernels::SingBox;
    use vpnctl_protocols::{TuicV5, VlessReality};
    use vpnctld::rate_limit::RateLimiter;

    // Build the same inventory shape as `seed()` but with a custom
    // rate limiter (capacity=2, refill=0/sec → no recovery during
    // the test window). Also need a deterministic token.
    let dir = TempDir::new().unwrap();
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    let mut reg = vpnctl_core::Registry::new();
    reg.register_kernel(Box::new(SingBox::new())).unwrap();
    reg.register_protocol(Box::new(VlessReality::new()))
        .unwrap();
    reg.register_protocol(Box::new(TuicV5::new())).unwrap();

    let server = vpnctl_core::Server {
        id: vpnctl_core::ServerId("srv".into()),
        address: "10.0.0.1".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![vpnctl_core::KernelId("sing-box".into())],
        enabled_protocols: vec![
            vpnctl_core::ProtocolId("vless+reality".into()),
            vpnctl_core::ProtocolId("tuic-v5".into()),
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
    let user = vpnctl_core::User {
        id: vpnctl_core::UserId("alice".into()),
        uuid: "uuid-alice".into(),
        tuic_password: Some("pw-alice".into()),
        wireguard_pubkey: None,
        wireguard_private: None,
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

    // Tight limiter: capacity=2, refill=0/sec → 3rd request in the
    // burst window MUST be denied. Idle TTL doesn't matter for the
    // test (we don't wait that long).
    let limiter = Arc::new(RateLimiter::new(2.0, 0.0, Duration::from_secs(60)));
    let (state, _writer) = vpnctld::make_app_state_with_rate_limiter(inv, Arc::new(reg), limiter);
    let app = router(state);

    // First two requests succeed (200) — they fill the per-IP and
    // per-token buckets each from cap=2 to 0.
    for n in 1..=2 {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/sub/{token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "request {n} must succeed (within burst)"
        );
    }

    // Third request: per-IP bucket is empty → 429 + Retry-After.
    // (Per-token bucket is also empty, but per-IP is checked first.)
    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/sub/{token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "3rd request must be throttled (cap=2 burst exhausted)"
    );
    let retry_after = resp
        .headers()
        .get("retry-after")
        .expect("Retry-After header missing on 429")
        .to_str()
        .unwrap();
    assert!(
        retry_after.parse::<u64>().is_ok(),
        "Retry-After must be a u64 second count, got {retry_after:?}"
    );
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let body_str = std::str::from_utf8(&body).unwrap();
    assert!(
        body_str.contains("rate limited"),
        "429 body must say 'rate limited', got {body_str:?}"
    );
}

// ────────────────────────────────────────────────────────────────────────
//  Phase Track-2 chunk 2 — persistent auto-ban after K consecutive 429s
//
//  E2E pin: with capacity=1, refill=0/sec, K=10, the 1st request
//  succeeds, the next 10 are 429 (filling the denial counter to 10),
//  and AT THAT POINT a row lands in `sub_rate_bans` for the source IP.
//  Subsequent requests now get ip-ban responses, not bucket-ip 429.
// ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn sub_persistent_ban_lands_after_k_consecutive_429s() {
    use std::sync::Arc;
    use std::time::Duration;
    use vpnctl_inventory::SqliteInventory;
    use vpnctl_kernels::SingBox;
    use vpnctl_protocols::{TuicV5, VlessReality};
    use vpnctld::rate_limit::{K_DENIALS_TO_BAN, RateLimiter};

    let dir = TempDir::new().unwrap();
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    let mut reg = vpnctl_core::Registry::new();
    reg.register_kernel(Box::new(SingBox::new())).unwrap();
    reg.register_protocol(Box::new(VlessReality::new()))
        .unwrap();
    reg.register_protocol(Box::new(TuicV5::new())).unwrap();

    let server = vpnctl_core::Server {
        id: vpnctl_core::ServerId("srv".into()),
        address: "10.0.0.1".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![vpnctl_core::KernelId("sing-box".into())],
        enabled_protocols: vec![vpnctl_core::ProtocolId("vless+reality".into())],
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
    let user = vpnctl_core::User {
        id: vpnctl_core::UserId("alice".into()),
        uuid: "uuid-alice".into(),
        tuic_password: Some("pw-alice".into()),
        wireguard_pubkey: None,
        wireguard_private: None,
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

    // Tight limiter: capacity=1, refill=0 → 1 burst, then every
    // subsequent request 429s. `oneshot()` rigs do NOT install
    // ConnectInfo, so the per-IP gate is skipped (handler's
    // `if let Some(addr) = peer_ip` branch is false); the per-TOKEN
    // gate runs and is what we actually exercise here. The ban
    // therefore lands as kind="token", key=<token>.
    let limiter = Arc::new(RateLimiter::new(1.0, 0.0, Duration::from_secs(60)));
    let inv_clone = inv.clone();
    let (state, _writer) = vpnctld::make_app_state_with_rate_limiter(inv, Arc::new(reg), limiter);
    let app = router(state);

    // 1st request: 200 (cap=1).
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/sub/{token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "first request must succeed");

    // Drive the next K_DENIALS_TO_BAN requests — all should 429. The
    // K-th 429 is what triggers the ban write inside the handler.
    for n in 1..=K_DENIALS_TO_BAN {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/sub/{token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "denial #{n} must be 429"
        );
    }

    // After K consecutive 429s the ban table MUST contain a row for
    // this token with kind=token and a 24h-ish TTL.
    let bans = inv_clone.active_bans().await.unwrap();
    let tok_ban = bans
        .iter()
        .find(|b| b.kind == "token" && b.key == token)
        .expect("persistent ban row missing after K consecutive 429s");
    let ttl_secs = (tok_ban.until_ts - chrono::Utc::now()).num_seconds();
    assert!(
        ttl_secs > 23 * 3600 && ttl_secs <= 24 * 3600,
        "ban TTL must be ~24h, got {ttl_secs}s"
    );
    assert!(
        tok_ban.reason.contains("consecutive 429"),
        "ban reason should mention escalation cause, got {:?}",
        tok_ban.reason
    );

    // Subsequent request now hits the ban check (BEFORE the bucket).
    // The body should identify the gate as "token-ban", not "token" —
    // a different gate name lets the operator distinguish bucket-
    // throttle from persistent-ban during incident response.
    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/sub/{token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let s = std::str::from_utf8(&body).unwrap();
    assert!(
        s.contains("token-ban"),
        "post-ban response body must say 'token-ban', got {s:?}"
    );
}

// ────────────────────────────────────────────────────────────────────────
//  Abuse-control hardening (fix/sub-gate-hardening)
//
//  Fix #1: the V2Ray-family render branch used to short-circuit to 200
//  BEFORE the per-token ban check and the per-token rate-limit gate
//  (those lived only in the sing-box arm). Since V2rayTun / v2rayNG /
//  Shadowrocket are the dominant production clients, a token ban and the
//  URL-sharing throttle were effectively no-ops for most traffic. The
//  gates now run on the resolved user/token BEFORE dispatching on UA.
// ────────────────────────────────────────────────────────────────────────

/// Build a minimal seeded inventory + state with a tunable rate limiter,
/// returning the inventory clone (for direct ban inserts / assertions),
/// the state, and the user's `/sub` token. Mirrors the inline setup the
/// other rate-limit tests duplicate, factored out for the new cases.
async fn seed_with_limiter(
    dir: &TempDir,
    limiter: Arc<vpnctld::rate_limit::RateLimiter>,
) -> (SqliteInventory, AppState, String) {
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
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
        kernels: vec![KernelId("sing-box".into())],
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
        wireguard_private: None,
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

    let inv_clone = inv.clone();
    let (state, _writer) = vpnctld::make_app_state_with_rate_limiter(inv, Arc::new(reg), limiter);
    (inv_clone, state, token)
}

/// Fix #1 — a TOKEN ban must be enforced even when the request carries a
/// V2Ray-family UA. Before the fix, the v2ray branch returned a 200
/// base64 subscription, completely bypassing `is_banned("token")`. Now a
/// banned token + v2rayNG UA must come back 429 `token-ban`, NOT 200.
#[tokio::test]
async fn v2ray_branch_enforces_token_ban() {
    use base64::Engine;
    use std::time::Duration;
    use vpnctld::rate_limit::RateLimiter;

    let dir = TempDir::new().unwrap();
    // Generous limiter so the bucket can NEVER be the thing that denies —
    // we want to prove the BAN is what blocks the v2ray request.
    let limiter = Arc::new(RateLimiter::new(100.0, 1.0, Duration::from_secs(60)));
    let (inv, state, token) = seed_with_limiter(&dir, limiter).await;

    // Pre-install a persistent token ban (as the escalation path would).
    inv.add_ban(
        "token",
        &token,
        vpnctld::rate_limit::DEFAULT_BAN_TTL_SECS,
        "test: pre-banned token",
    )
    .await
    .unwrap();

    let app = router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/sub/{token}"))
                .header("user-agent", "v2rayNG/1.9.0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "a v2ray-UA request for a banned token MUST be 429, not a 200 subscription"
    );
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let s = std::str::from_utf8(&body).unwrap();
    assert!(
        s.contains("token-ban"),
        "v2ray-UA banned-token response must say 'token-ban', got {s:?}"
    );
    // And it must NOT have leaked a base64 subscription.
    assert!(
        !s.contains("vless://")
            && base64::engine::general_purpose::STANDARD
                .decode(s.trim())
                .is_err(),
        "v2ray-UA banned-token response must not be a base64 subscription, got {s:?}"
    );
}

/// Fix #1 — the per-TOKEN rate-limit gate must also apply on the v2ray
/// branch. With a 1-token bucket and no refill, the first v2ray-UA
/// request succeeds (200) and the second must be throttled (429 `token`),
/// rather than the bucket being ignored entirely on the v2ray path.
#[tokio::test]
async fn v2ray_branch_enforces_token_rate_limit() {
    use std::time::Duration;
    use vpnctld::rate_limit::RateLimiter;

    let dir = TempDir::new().unwrap();
    // capacity=1, refill=0 → exactly one v2ray request gets through.
    let limiter = Arc::new(RateLimiter::new(1.0, 0.0, Duration::from_secs(60)));
    let (_inv, state, token) = seed_with_limiter(&dir, limiter).await;
    let app = router(state);

    // First v2ray-UA request: burns the single per-token token → 200.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/sub/{token}"))
                .header("user-agent", "v2rayNG/1.9.0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "first v2ray request must succeed within the burst"
    );

    // Second v2ray-UA request: per-token bucket empty → 429 `token`.
    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/sub/{token}"))
                .header("user-agent", "v2rayNG/1.9.0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "second v2ray request must be throttled by the per-token bucket"
    );
    let retry_after = resp
        .headers()
        .get("retry-after")
        .expect("Retry-After header missing on v2ray per-token 429")
        .to_str()
        .unwrap()
        .to_owned();
    assert!(
        retry_after.parse::<u64>().is_ok(),
        "Retry-After must be a u64 second count, got {retry_after:?}"
    );
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let s = std::str::from_utf8(&body).unwrap();
    assert!(
        s.contains("rate limited") && s.contains("token"),
        "v2ray-UA throttle must be a per-token 429, got {s:?}"
    );
}

/// Fix #1 regression — the un-banned, under-limit v2ray happy path MUST
/// still return a 200 base64 subscription after the restructure. This is
/// the dominant production case; the gate move must not break it.
#[tokio::test]
async fn v2ray_branch_happy_path_still_returns_base64_subscription() {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use std::time::Duration;
    use vpnctld::rate_limit::RateLimiter;

    let dir = TempDir::new().unwrap();
    let limiter = Arc::new(RateLimiter::new(100.0, 1.0, Duration::from_secs(60)));
    let (_inv, state, token) = seed_with_limiter(&dir, limiter).await;
    let app = router(state);

    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/sub/{token}"))
                .header("user-agent", "v2rayNG/1.9.0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let b64 = std::str::from_utf8(&body).unwrap();
    let decoded = BASE64_STANDARD.decode(b64.trim()).unwrap();
    let lines = std::str::from_utf8(&decoded).unwrap();
    assert!(
        lines.contains("vless://"),
        "un-banned under-limit v2ray sub must carry the vless URI: {lines}"
    );
}

/// Fix #1 — the existing sing-box token-ban behaviour must stay green:
/// a banned token with a sing-box / default (no) UA still returns 429
/// `token-ban`. This is the non-v2ray sibling of
/// `v2ray_branch_enforces_token_ban`.
#[tokio::test]
async fn singbox_branch_still_enforces_token_ban() {
    use std::time::Duration;
    use vpnctld::rate_limit::RateLimiter;

    let dir = TempDir::new().unwrap();
    let limiter = Arc::new(RateLimiter::new(100.0, 1.0, Duration::from_secs(60)));
    let (inv, state, token) = seed_with_limiter(&dir, limiter).await;
    inv.add_ban(
        "token",
        &token,
        vpnctld::rate_limit::DEFAULT_BAN_TTL_SECS,
        "test: pre-banned token",
    )
    .await
    .unwrap();

    let app = router(state);
    // No UA → falls through to the sing-box JSON path.
    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/sub/{token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let s = std::str::from_utf8(&body).unwrap();
    assert!(
        s.contains("token-ban"),
        "sing-box banned-token response must say 'token-ban', got {s:?}"
    );
}
