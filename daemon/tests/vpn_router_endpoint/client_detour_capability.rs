//! Client detour capability tests for `GET /api/v1/app/config/{device_id}`.
//!
//! Spec: `docs/specs/vpnrouter-chain-app-config.md`

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use http_body_util::BodyExt;
use serde_json::Value;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{ProtocolId, ServerId, UserId};
use vpnctld::router;

use super::common::{TEST_DEVICE_ID, seed_state};

async fn get_with_headers(
    app: axum::Router,
    path: &str,
    user_agent: &str,
    capability: Option<&str>,
) -> (StatusCode, Vec<u8>, String) {
    let mut req = Request::builder()
        .uri(path)
        .header("user-agent", user_agent);
    if let Some(cap) = capability {
        req = req.header("X-VPNRouter-Capabilities", cap);
    }
    let resp = app.oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
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

fn config_blob(body: &[u8]) -> String {
    let body_str = std::str::from_utf8(body).unwrap();
    if body_str.trim_start().starts_with('{') {
        let v: Value = serde_json::from_slice(body).unwrap();
        v.get("config")
            .and_then(|c| c.as_str())
            .unwrap_or("")
            .to_string()
    } else {
        body_str.to_string()
    }
}

fn decode_config_lines(body: &[u8]) -> Vec<String> {
    let b64 = config_blob(body);
    if b64.is_empty() {
        return vec![];
    }
    let decoded = BASE64_STANDARD.decode(b64.as_bytes()).unwrap();
    let s = String::from_utf8(decoded).unwrap();
    if s.is_empty() {
        vec![]
    } else {
        s.split('\n').map(str::to_owned).collect()
    }
}

#[tokio::test]
async fn old_vpnrouter_without_capability_header_omits_target() {
    let dir = TempDir::new().unwrap();
    let state = seed_state(&dir).await;
    state
        .inv
        .set_client_detour_via_as("test", &ServerId("de".into()), Some(&ServerId("is".into())))
        .await
        .unwrap();
    let app = router(state);

    let (status, body, _) = get_with_headers(
        app,
        &format!("/api/v1/app/config/{TEST_DEVICE_ID}"),
        "VPNRouter/1.0",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let lines = decode_config_lines(&body);
    assert!(
        lines.iter().any(|l| l.contains("@is.example.com")),
        "entry must be present: {lines:?}"
    );
    assert!(
        !lines.iter().any(|l| l.contains("@de.example.com")),
        "target must be omitted without capability header: {lines:?}"
    );
    assert!(
        !lines.iter().any(|l| l.contains("outbound=")),
        "metadata must be omitted without capability header: {lines:?}"
    );
}

#[tokio::test]
async fn generic_ua_with_capability_header_omits_target() {
    let dir = TempDir::new().unwrap();
    let state = seed_state(&dir).await;
    state
        .inv
        .set_client_detour_via_as("test", &ServerId("de".into()), Some(&ServerId("is".into())))
        .await
        .unwrap();
    let app = router(state);

    let (status, body, _) = get_with_headers(
        app,
        &format!("/api/v1/app/config/{TEST_DEVICE_ID}"),
        "v2rayN/6.62",
        Some("detour-v1"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let lines = decode_config_lines(&body);
    assert!(
        lines.iter().any(|l| l.contains("@is.example.com")),
        "entry must be present: {lines:?}"
    );
    assert!(
        !lines.iter().any(|l| l.contains("@de.example.com")),
        "target must be omitted for generic UA: {lines:?}"
    );
    assert!(
        !lines.iter().any(|l| l.contains("outbound=")),
        "metadata must be omitted for generic UA: {lines:?}"
    );
}

#[tokio::test]
async fn capability_token_in_repeated_header_is_accepted() {
    let dir = TempDir::new().unwrap();
    let state = seed_state(&dir).await;
    state
        .inv
        .set_client_detour_via_as("test", &ServerId("de".into()), Some(&ServerId("is".into())))
        .await
        .unwrap();
    let app = router(state);
    let req = Request::builder()
        .uri(format!("/api/v1/app/config/{TEST_DEVICE_ID}"))
        .header("user-agent", "VPNRouter/1.0")
        .header("X-VPNRouter-Capabilities", "future-v1")
        .header("X-VPNRouter-Capabilities", "detour-v1")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let lines = decode_config_lines(&body);

    assert!(lines.iter().any(|line| line.contains("detour=is")));
}

#[tokio::test]
async fn capability_aware_vpnrouter_gets_entry_and_target_with_outbound_detour() {
    let dir = TempDir::new().unwrap();
    let state = seed_state(&dir).await;
    state
        .inv
        .set_client_detour_via_as("test", &ServerId("de".into()), Some(&ServerId("is".into())))
        .await
        .unwrap();
    let app = router(state);

    let (status, body, _) = get_with_headers(
        app,
        &format!("/api/v1/app/config/{TEST_DEVICE_ID}"),
        "VPNRouter/1.0",
        Some("detour-v1"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let lines = decode_config_lines(&body);
    let entry = lines
        .iter()
        .find(|l| l.contains("@is.example.com"))
        .expect("entry URI present");
    let target = lines
        .iter()
        .find(|l| l.contains("@de.example.com"))
        .expect("target URI present");

    assert!(
        entry.contains("outbound=is"),
        "entry must carry outbound=is: {entry}"
    );
    assert!(
        !entry.contains("detour="),
        "entry must not carry detour: {entry}"
    );
    assert!(
        target.contains("outbound=de"),
        "target must carry outbound=de: {target}"
    );
    assert!(
        target.contains("detour=is"),
        "target must carry detour=is: {target}"
    );
}

#[tokio::test]
async fn no_chain_capability_response_byte_equals_response_without_capability() {
    let dir = TempDir::new().unwrap();
    let state = seed_state(&dir).await;

    let (status1, body1, _) = get_with_headers(
        router(state.clone()),
        &format!("/api/v1/app/config/{TEST_DEVICE_ID}"),
        "VPNRouter/1.0",
        None,
    )
    .await;
    assert_eq!(status1, StatusCode::OK);

    let (status2, body2, _) = get_with_headers(
        router(state),
        &format!("/api/v1/app/config/{TEST_DEVICE_ID}"),
        "VPNRouter/1.0",
        Some("detour-v1"),
    )
    .await;
    assert_eq!(status2, StatusCode::OK);

    assert_eq!(
        config_blob(&body1),
        config_blob(&body2),
        "base64 config blobs must be byte-equal when no chain exists"
    );
}

#[tokio::test]
async fn target_omitted_when_upstream_grant_missing() {
    let dir = TempDir::new().unwrap();
    let state = seed_state(&dir).await;
    state
        .inv
        .set_client_detour_via_as("test", &ServerId("de".into()), Some(&ServerId("is".into())))
        .await
        .unwrap();
    state
        .inv
        .revoke(&UserId("tester-1".into()), &ServerId("is".into()))
        .await
        .unwrap();
    let app = router(state);

    let (status, body, _) = get_with_headers(
        app,
        &format!("/api/v1/app/config/{TEST_DEVICE_ID}"),
        "VPNRouter/1.0",
        Some("detour-v1"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let lines = decode_config_lines(&body);
    assert!(
        !lines.iter().any(|l| l.contains("@de.example.com")),
        "target must be omitted when entry grant missing: {lines:?}"
    );
}

#[tokio::test]
async fn target_omitted_when_upstream_vless_hidden() {
    let dir = TempDir::new().unwrap();
    let state = seed_state(&dir).await;
    state
        .inv
        .set_client_detour_via_as("test", &ServerId("de".into()), Some(&ServerId("is".into())))
        .await
        .unwrap();
    state
        .inv
        .set_server_protocol_hidden(
            &ServerId("is".into()),
            &ProtocolId("vless+reality".into()),
            true,
        )
        .await
        .unwrap();
    let app = router(state);

    let (status, body, _) = get_with_headers(
        app,
        &format!("/api/v1/app/config/{TEST_DEVICE_ID}"),
        "VPNRouter/1.0",
        Some("detour-v1"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let lines = decode_config_lines(&body);
    assert!(
        !lines.iter().any(|l| l.contains("@de.example.com")),
        "target must be omitted when entry protocol hidden: {lines:?}"
    );
}

#[tokio::test]
async fn target_omitted_when_upstream_vless_denied() {
    let dir = TempDir::new().unwrap();
    let state = seed_state(&dir).await;
    state
        .inv
        .set_client_detour_via_as("test", &ServerId("de".into()), Some(&ServerId("is".into())))
        .await
        .unwrap();
    state
        .inv
        .set_grant_protocol_override(
            &UserId("tester-1".into()),
            &ServerId("is".into()),
            &ProtocolId("vless+reality".into()),
            true,
        )
        .await
        .unwrap();
    let app = router(state);

    let (status, body, _) = get_with_headers(
        app,
        &format!("/api/v1/app/config/{TEST_DEVICE_ID}"),
        "VPNRouter/1.0",
        Some("detour-v1"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let lines = decode_config_lines(&body);
    assert!(
        !lines.iter().any(|l| l.contains("@de.example.com")),
        "target must be omitted when entry protocol denied: {lines:?}"
    );
}

#[tokio::test]
async fn target_omitted_when_upstream_unusable() {
    let dir = TempDir::new().unwrap();
    let state = seed_state(&dir).await;
    state
        .inv
        .set_client_detour_via_as(
            "test",
            &ServerId("de".into()),
            Some(&ServerId("bare".into())),
        )
        .await
        .unwrap();
    let app = router(state);

    let (status, body, _) = get_with_headers(
        app,
        &format!("/api/v1/app/config/{TEST_DEVICE_ID}"),
        "VPNRouter/1.0",
        Some("detour-v1"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let lines = decode_config_lines(&body);
    assert!(
        !lines.iter().any(|l| l.contains("@de.example.com")),
        "target must be omitted when entry is unusable/missing secrets: {lines:?}"
    );
}
