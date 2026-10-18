use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use http_body_util::BodyExt;
use serde_json::Value;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{ServerId, UserId};
use vpnctld::router;

use super::common::{ALT_DEVICE_ID, TEST_DEVICE_ID, de_in_subscription, get, seed_state};

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
    let cfg = v["config"].as_str().unwrap();
    let decoded = BASE64_STANDARD.decode(cfg).unwrap();
    let s = std::str::from_utf8(&decoded).unwrap();
    let lines: Vec<&str> = s.split('\n').collect();
    assert_eq!(lines.len(), 2, "expected 2 vless URIs, got: {s}");
    assert!(
        lines[0].contains("@de.example.com:443"),
        "first URI = de: {}",
        lines[0]
    );
    assert!(
        lines[1].contains("@is.example.com:443"),
        "second URI = is: {}",
        lines[1]
    );
    for line in &lines {
        assert!(line.contains("11111111-2222-3333-4444-555555555555"));
    }
    assert!(lines[0].contains("#Germany%20VLESS%20~tester-1"));
    assert!(lines[1].contains("#Iceland%20VLESS%20~tester-1"));
}

#[tokio::test]
async fn vpn_router_omits_chained_target_from_uri_config() {
    let dir = TempDir::new().unwrap();
    let state = seed_state(&dir).await;
    state
        .inv
        .set_client_detour_via_as("test", &ServerId("de".into()), Some(&ServerId("is".into())))
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
    let decoded = BASE64_STANDARD
        .decode(v["config"].as_str().unwrap())
        .unwrap();
    let config = std::str::from_utf8(&decoded).unwrap();

    assert!(
        config.contains("@is.example.com:443"),
        "entry missing: {config}"
    );
    assert!(
        !config.contains("@de.example.com:443"),
        "chained target leaked as a direct URI: {config}"
    );
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
    let app = router(state);

    for bad in [
        "notahex",
        "deadbeef",
        "DEADBEEFDEADBEEFDEADBEEFDEADBEEF",
        "g0000000000000000000000000000000",
        "a92b915032b48a2ed45ef72f4171e5f4a92b915032b48a2ed45ef72f",
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
    let dir = TempDir::new().unwrap();
    let state = seed_state(&dir).await;

    state
        .inv
        .set_grant_client_uuid(
            &UserId("tester-1".into()),
            &ServerId("de".into()),
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

    assert!(
        s.contains("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@de.example.com"),
        "de-01 should use override uuid: {s}"
    );
    assert!(
        s.contains("vless://11111111-2222-3333-4444-555555555555@is.example.com"),
        "is-01 should fall back to global uuid: {s}"
    );
}

#[tokio::test]
async fn vpn_router_per_device_id_throttles_after_burst() {
    let dir = TempDir::new().unwrap();
    let state = seed_state(&dir).await;
    let path = format!("/api/v1/app/config/{TEST_DEVICE_ID}");

    let mut statuses = Vec::new();
    for _ in 0..7 {
        let (status, _b, _ct) = get(router(state.clone()), &path, "curl/8.0").await;
        statuses.push(status);
    }

    let ok = statuses.iter().filter(|s| **s == StatusCode::OK).count();
    let throttled = statuses
        .iter()
        .filter(|s| **s == StatusCode::TOO_MANY_REQUESTS)
        .count();
    assert_eq!(ok, 5, "default burst capacity is 5; statuses={statuses:?}");
    assert!(
        throttled >= 1,
        "requests past the burst must 429; statuses={statuses:?}"
    );
}

#[tokio::test]
async fn vpn_router_auto_suppressed_server_drops_from_subscription() {
    let dir = TempDir::new().unwrap();
    let state = seed_state(&dir).await;
    let de = ServerId("de".into());
    state.inv.set_server_auto_suppress(&de, true).await.unwrap();
    state.inv.set_server_suppressed(&de, true).await.unwrap();
    assert!(
        !de_in_subscription(router(state.clone())).await,
        "suppressed de must be absent from the subscription"
    );
}

#[tokio::test]
async fn vpn_router_cleared_suppression_returns_server() {
    let dir = TempDir::new().unwrap();
    let state = seed_state(&dir).await;
    let de = ServerId("de".into());
    state.inv.set_server_auto_suppress(&de, true).await.unwrap();
    state.inv.set_server_suppressed(&de, true).await.unwrap();
    state.inv.set_server_suppressed(&de, false).await.unwrap();
    assert!(
        de_in_subscription(router(state.clone())).await,
        "cleared suppression returns de to the subscription"
    );
}
