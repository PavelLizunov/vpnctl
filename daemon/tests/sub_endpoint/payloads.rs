use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header::CONTENT_TYPE};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use http_body_util::BodyExt;
use serde_json::Value;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{KernelId, ProtocolId, Registry, Server, ServerId, User, UserId};
use vpnctl_inventory::SqliteInventory;
use vpnctl_kernels::SingBox;
use vpnctl_protocols::{DnsTunnel, TuicV5, VlessReality, WgTurn, WireGuard};
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

/// Sibling of the wgturn / dns-tunnel exclusion tests for WireGuard.
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

/// dns-tunnel must ALSO stay out of the V2Ray-family base64 sub. That
/// path (`resolve_v2ray_subscription`) hard-allowlists schemes
/// (vless/vmess/trojan/ss/ssr/tuic/hy2/anytls); a `dns-tunnel://` line
/// would either be dropped or crash a strict importer. This pins that a
/// v2rayNG-shaped UA pulling the same mixed server gets the vless URI
/// and NOT the `dns-tunnel://` link.
#[tokio::test]
async fn v2ray_sub_excludes_dns_tunnel_share_link() {
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

/// Baseline security response headers (X-Content-Type-Options: nosniff and
/// X-Frame-Options: DENY) must be attached to public API and subscription
/// endpoints for defense-in-depth against MIME sniffing and framing.
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
}
