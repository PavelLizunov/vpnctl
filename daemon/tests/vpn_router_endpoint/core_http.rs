//! HTTP layer, negotiation, serialization, and throttling tests for vpn_router_endpoint.

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
    // config: base64 of two vless:// URIs (de-01, is-01), bare server skipped.
    let cfg = v["config"].as_str().unwrap();
    let decoded = BASE64_STANDARD.decode(cfg).unwrap();
    let s = std::str::from_utf8(&decoded).unwrap();
    let lines: Vec<&str> = s.split('\n').collect();
    assert_eq!(lines.len(), 2, "expected 2 vless URIs, got: {s}");
    // Order is determined by `servers_for_user` which `ORDER BY g.server_id`.
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
    // Both URIs use the user's global uuid (no per-server override
    // pinned in this test).
    for line in &lines {
        assert!(line.contains("11111111-2222-3333-4444-555555555555"));
    }
    // Fragment has stripped server tag + port + client_name.
    assert!(lines[0].contains("#Germany%20VLESS%20~tester-1"));
    assert!(lines[1].contains("#Iceland%20VLESS%20~tester-1"));
}

#[tokio::test]
async fn vpn_router_omits_chained_target_from_uri_config() {
    let dir = TempDir::new().unwrap();
    let state = seed_state(&dir).await;
    state
        .inv
        .set_client_detour_via_as(
            "test",
            &ServerId("de".into()),
            Some(&ServerId("is".into())),
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
    let decoded = BASE64_STANDARD.decode(v["config"].as_str().unwrap()).unwrap();
    let config = std::str::from_utf8(&decoded).unwrap();

    assert!(config.contains("@is.example.com:443"), "entry missing: {config}");
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

    // The de-01 URI uses the overridden uuid; the is-01 URI uses
    // the user's global uuid (no override pinned there).
    assert!(
        s.contains("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@de.example.com"),
        "de-01 should use override uuid: {s}"
    );
    assert!(
        s.contains("vless://11111111-2222-3333-4444-555555555555@is.example.com"),
        "is-01 should fall back to global uuid: {s}"
    );
}

/// Item-3 rate-limit: the per-`device_id` bucket throttles a single
/// device hammering the endpoint. The oneshot rig injects no
/// ConnectInfo (real_ip = None → per-IP axis skipped via
/// `ip_to_throttle`), so this isolates the per-device_id axis — THE
/// per-user limit. Default capacity is 5 → 5×200 then 429.
#[tokio::test]
async fn vpn_router_per_device_id_throttles_after_burst() {
    let dir = TempDir::new().unwrap();
    let state = seed_state(&dir).await;
    let path = format!("/api/v1/app/config/{TEST_DEVICE_ID}");

    let mut statuses = Vec::new();
    for _ in 0..7 {
        // Fresh router each call (oneshot consumes it) but SAME state →
        // SAME Arc<RateLimiter>, so the per-device_id bucket persists.
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

/// Migration 0030: an auto-suppressed server (opt-in ON + suppressed_at
/// set) is dropped from the rendered subscription.
#[tokio::test]
async fn vpn_router_auto_suppressed_server_drops_from_subscription() {
    let dir = TempDir::new().unwrap();
    let state = seed_state(&dir).await;
    let de = ServerId("de".into());
    // All writes BEFORE the single fetch (no post-fetch write to race
    // the access-log writer).
    state.inv.set_server_auto_suppress(&de, true).await.unwrap();
    state.inv.set_server_suppressed(&de, true).await.unwrap();
    assert!(
        !de_in_subscription(router(state.clone())).await,
        "suppressed de must be absent from the subscription"
    );
}

/// Migration 0030: clearing suppression (recovery) returns the server.
#[tokio::test]
async fn vpn_router_cleared_suppression_returns_server() {
    let dir = TempDir::new().unwrap();
    let state = seed_state(&dir).await;
    let de = ServerId("de".into());
    // Suppress then clear — both before the fetch.
    state.inv.set_server_auto_suppress(&de, true).await.unwrap();
    state.inv.set_server_suppressed(&de, true).await.unwrap();
    state.inv.set_server_suppressed(&de, false).await.unwrap();
    assert!(
        de_in_subscription(router(state.clone())).await,
        "cleared suppression returns de to the subscription"
    );
}
