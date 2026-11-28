use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;
use vpnctl_core::{ProtocolId, ServerId, UserId};
use vpnctld::{AppState, router};

use crate::common::{TEST_DEVICE_ID, get, seed_state};

#[path = "../fixtures/tls.rs"]
mod tls;

const RAW_UA: &str = "VPNRouter/2.4.1 v2rayN/6.62";
const CAPS: &str = "trusttunnel-v1, mieru-v1";
const CLIENT_UUID: &str = "01234567-2222-4333-8444-555555555555";
const PIN_KEY: &str = "observed.tls.cert_public_key_sha256";

async fn state(dir: &TempDir) -> AppState {
    let mut state = seed_state(dir).await;
    state.registry = Arc::new(vpnctl_kernels::build_registry().unwrap());
    state.rate_limiter = Arc::new(vpnctld::rate_limit::RateLimiter::new(
        100.0,
        0.0,
        Duration::from_secs(60),
    ));
    state
}

async fn enable_native(state: &AppState) -> ServerId {
    let sid = ServerId("de".into());
    for id in ["trusttunnel", "mieru"] {
        state
            .inv
            .add_server_protocol(&sid, &ProtocolId(id.into()))
            .await
            .unwrap();
    }
    sid
}

async fn body(state: &AppState, ua: &str, capability: &str) -> Vec<u8> {
    let mut req = Request::builder()
        .uri(format!("/api/v1/app/config/{TEST_DEVICE_ID}"))
        .header("user-agent", ua);
    if !capability.is_empty() {
        req = req.header("X-VPNRouter-Capabilities", capability);
    }
    let response = router(state.clone())
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec()
}

async fn profiles(state: &AppState, cap: &str) -> Vec<String> {
    let decoded =
        String::from_utf8(STANDARD.decode(body(state, RAW_UA, cap).await).unwrap()).unwrap();
    decoded
        .lines()
        .filter(|line| line.starts_with("trusttunnel://") || line.starts_with("mieru://"))
        .map(str::to_string)
        .collect()
}

#[tokio::test]
async fn native_profiles_are_independently_gated_and_preserve_legacy_bytes() {
    let dir = TempDir::new().unwrap();
    let state = state(&dir).await;
    let token = state
        .inv
        .regenerate_sub_token(&UserId("tester-1".into()))
        .await
        .unwrap();
    let sid = ServerId("de".into());
    state
        .inv
        .set_grant_client_uuid(&UserId("tester-1".into()), &sid, CLIENT_UUID)
        .await
        .unwrap();
    let stock = format!("/sub/{token}?format=sing-box");
    let (status, baseline_stock, _) = get(router(state.clone()), &stock, "sing-box/1.14.4").await;
    assert_eq!(status, StatusCode::OK);
    let baseline = body(&state, RAW_UA, "").await;
    assert!(!baseline.is_empty());

    enable_native(&state).await;
    let pin = "ab".repeat(32);
    state
        .inv
        .set_server_secret(&sid, PIN_KEY, &pin.to_ascii_uppercase())
        .await
        .unwrap();
    for capability in ["", "trusttunnel-v10, mieru-v10"] {
        assert_eq!(body(&state, RAW_UA, capability).await, baseline);
    }
    assert_eq!(body(&state, "v2rayN/6.62", CAPS).await, baseline);

    let trusttunnel = format!(
        "trusttunnel://tester-1:{CLIENT_UUID}@de.example.com:8444?sni=de.example.com&quic=0&udp=1&pk_sha256={pin}#Germany%20TrustTunnel%20~tester-1"
    );
    let mieru = format!(
        "mieru://tester-1:{CLIENT_UUID}@de.example.com:8445?transport=tcp&multiplexing=middle&handshake=standard#Germany%20Mieru%20~tester-1"
    );
    assert_eq!(
        profiles(&state, "trusttunnel-v1").await,
        std::slice::from_ref(&trusttunnel)
    );
    assert_eq!(
        profiles(&state, "mieru-v1").await,
        std::slice::from_ref(&mieru)
    );
    assert_eq!(profiles(&state, CAPS).await, [trusttunnel, mieru]);

    let (status, with_native, _) = get(router(state.clone()), &stock, "sing-box/1.14.4").await;
    assert_eq!(status, StatusCode::OK);
    let json: serde_json::Value = serde_json::from_slice(&with_native).unwrap();
    assert!(
        json["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .all(|outbound| {
                !matches!(outbound["type"].as_str(), Some("trusttunnel" | "mieru"))
            })
    );
    assert_eq!(with_native, baseline_stock);
}

#[tokio::test]
async fn native_profiles_require_visible_direct_grants() {
    let dir = TempDir::new().unwrap();
    let state = state(&dir).await;
    let sid = enable_native(&state).await;
    let user = UserId("tester-1".into());
    let trusttunnel = ProtocolId("trusttunnel".into());
    let mieru = ProtocolId("mieru".into());
    state
        .inv
        .set_server_secret(&sid, PIN_KEY, &"ab".repeat(32))
        .await
        .unwrap();
    assert_eq!(profiles(&state, CAPS).await.len(), 2);

    state
        .inv
        .set_server_protocol_hidden(&sid, &trusttunnel, true)
        .await
        .unwrap();
    state
        .inv
        .set_grant_protocol_override(&user, &sid, &mieru, true)
        .await
        .unwrap();
    assert!(profiles(&state, CAPS).await.is_empty());
    state
        .inv
        .set_server_protocol_hidden(&sid, &trusttunnel, false)
        .await
        .unwrap();
    state
        .inv
        .set_grant_protocol_override(&user, &sid, &mieru, false)
        .await
        .unwrap();

    state
        .inv
        .set_client_detour_via_as("test", &sid, Some(&ServerId("is".into())))
        .await
        .unwrap();
    assert!(
        profiles(&state, "detour-v1, trusttunnel-v1, mieru-v1")
            .await
            .is_empty()
    );
    state
        .inv
        .set_client_detour_via_as("test", &sid, None)
        .await
        .unwrap();
    state
        .inv
        .set_server_auto_suppress(&sid, true)
        .await
        .unwrap();
    state.inv.set_server_suppressed(&sid, true).await.unwrap();
    assert!(profiles(&state, CAPS).await.is_empty());
    state.inv.set_server_suppressed(&sid, false).await.unwrap();
    assert_eq!(profiles(&state, CAPS).await.len(), 2);

    state.inv.revoke(&user, &sid).await.unwrap();
    assert!(profiles(&state, CAPS).await.is_empty());
}

#[tokio::test]
async fn trusttunnel_issues_only_pinned_managed_tls_or_complete_custom_tls() {
    let dir = TempDir::new().unwrap();
    let state = state(&dir).await;
    let sid = enable_native(&state).await;
    assert!(profiles(&state, "trusttunnel-v1").await.is_empty());
    state
        .inv
        .set_server_secret(&sid, PIN_KEY, "invalid")
        .await
        .unwrap();
    assert!(profiles(&state, "trusttunnel-v1").await.is_empty());
    state
        .inv
        .set_server_secret(&sid, "trusttunnel.domain", "fixture.example.com")
        .await
        .unwrap();
    assert!(profiles(&state, "trusttunnel-v1").await.is_empty());

    let certificate = tls::pem("CERTIFICATE", tls::TLS_CERTIFICATE_DER);
    let key = tls::pem("PRIVATE KEY", tls::TLS_KEY_DER);
    for (setting, value) in [
        ("trusttunnel.certificate", certificate),
        ("trusttunnel.key", key),
    ] {
        state
            .inv
            .set_server_secret(&sid, setting, &value)
            .await
            .unwrap();
    }
    assert_eq!(
        profiles(&state, "trusttunnel-v1").await,
        [
            "trusttunnel://tester-1:11111111-2222-3333-4444-555555555555@fixture.example.com:8444?sni=fixture.example.com&quic=0&udp=1#Germany%20TrustTunnel%20~tester-1"
        ]
    );
}

#[tokio::test]
async fn sing_box_omits_inbounds_without_eligible_grants() {
    use vpnctl_core::{Kernel, RenderCtx};

    let dir = TempDir::new().unwrap();
    let state = state(&dir).await;
    let sid = enable_native(&state).await;
    let mieru = ProtocolId("mieru".into());
    let trusttunnel = ProtocolId("trusttunnel".into());
    let user = UserId("tester-1".into());
    state
        .inv
        .set_grant_protocol_override(&user, &sid, &mieru, true)
        .await
        .unwrap();

    let server = state.inv.get_server(&sid).await.unwrap().unwrap();
    let secrets = state.inv.list_server_secrets(&sid).await.unwrap();
    let users = state.inv.users_for_server(&sid).await.unwrap();
    let protocols = [
        state.registry.protocol(&mieru).unwrap(),
        state.registry.protocol(&trusttunnel).unwrap(),
    ];
    let unchecked = RenderCtx::new(&server, &secrets);
    assert!(
        vpnctl_kernels::SingBox::new()
            .render_config(&unchecked, &users, &protocols)
            .is_err()
    );

    let ctx = RenderCtx::new(&server, &secrets)
        .with_protocol_denials(state.inv.enabled_protocol_denials(&sid).await.unwrap());
    let config = vpnctl_kernels::SingBox::new()
        .render_config(&ctx, &users, &protocols)
        .unwrap();
    let config: serde_json::Value = serde_json::from_slice(&config).unwrap();
    let inbounds = config["inbounds"].as_array().unwrap();
    assert_eq!(inbounds.len(), 1);
    assert_eq!(inbounds[0]["type"], "trusttunnel");
    assert_eq!(inbounds[0]["users"][0]["username"], "tester-1");

    let config = vpnctl_kernels::SingBox::new()
        .render_config(&ctx, &[], &protocols)
        .unwrap();
    let config: serde_json::Value = serde_json::from_slice(&config).unwrap();
    assert_eq!(config["inbounds"], serde_json::json!([]));
}
