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
use vpnctl_kernels::{Caddy, SingBox};
use vpnctl_protocols::{Hysteria2, Naive, VlessReality};
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
    // Post-2026-05-20 rename: server IDs are ISO country codes.
    // `country_display_name` in vpn_router.rs maps these to user-facing
    // labels (de→Germany, is→Iceland). Tests use the new IDs end-to-end.
    for sid in ["de", "is"] {
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
        vpn_router_device_id: None,
        disabled: false,
    };
    inv.add_user(&user).await.unwrap();
    inv.set_vpn_router_device_id(&user.id, TEST_DEVICE_ID)
        .await
        .unwrap();
    inv.grant(&user.id, &ServerId("de".into())).await.unwrap();
    inv.grant(&user.id, &ServerId("is".into())).await.unwrap();
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

/// Helper: does `de` appear in the rendered subscription (raw base64
/// / VPN-client UA path)? All inventory mutations MUST happen before
/// calling this — the per-request access-log writer is a background
/// task, and interleaving an audited inventory write after a fetch
/// races it into a WAL read→write-upgrade SQLITE_BUSY.
async fn de_in_subscription(app: axum::Router) -> bool {
    let (status, body, _ct) = get(
        app,
        &format!("/api/v1/app/config/{TEST_DEVICE_ID}"),
        "v2rayN/6.62",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let decoded = BASE64_STANDARD.decode(&body).unwrap();
    let s = String::from_utf8(decoded).unwrap();
    s.split('\n').any(|l| l.contains("@de.example.com"))
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

// ── Part B: naive delivery into the ninitux endpoint ────────────────────

const NAIVE_DEVICE_ID: &str = "b1b2b3b4b5b6b7b8b9b0b1b2b3b4b5b6";

/// Seed a state where naive is a first-class citizen: SingBox+Caddy kernels
/// and Vless+Naive protocols registered, a vless server `de`, a naive
/// server `cdn` (Caddy kernel, `naive` enabled, `naive.domain` provisioned),
/// and a user granted on BOTH. The user carries a `tuic_password` because
/// the pre-Part-A naive `share_link` reads it (Part A swaps this to a
/// dedicated `naive_password`; this test moves with that change).
async fn seed_state_with_naive(dir: &TempDir) -> AppState {
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    let mut reg = Registry::new();
    reg.register_kernel(Box::new(SingBox::new())).unwrap();
    reg.register_kernel(Box::new(Caddy::new())).unwrap();
    reg.register_protocol(Box::new(VlessReality::new()))
        .unwrap();
    reg.register_protocol(Box::new(Naive::new())).unwrap();

    // vless server
    let de = Server {
        id: ServerId("de".into()),
        address: "de.example.com".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("vless+reality".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    };
    inv.add_server(&de).await.unwrap();
    inv.set_server_secret(&de.id, "vless.public_key", "PUB_de")
        .await
        .unwrap();
    inv.set_server_secret(&de.id, "vless.short_id", "12345678")
        .await
        .unwrap();

    // naive server — Caddy kernel, naive protocol, ACME domain provisioned.
    let cdn = Server {
        id: ServerId("cdn".into()),
        address: "cdn.example.com".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("caddy".into())],
        enabled_protocols: vec![ProtocolId("naive".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    };
    inv.add_server(&cdn).await.unwrap();
    inv.set_server_secret(&cdn.id, "naive.domain", "cdn.example.com")
        .await
        .unwrap();

    let user = User {
        id: UserId("tester-1".into()),
        uuid: "11111111-2222-3333-4444-555555555555".into(),
        tuic_password: Some("NAIVE_TEST_PW".into()),
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    };
    inv.add_user(&user).await.unwrap();
    inv.set_vpn_router_device_id(&user.id, NAIVE_DEVICE_ID)
        .await
        .unwrap();
    inv.grant(&user.id, &ServerId("de".into())).await.unwrap();
    inv.grant(&user.id, &ServerId("cdn".into())).await.unwrap();

    let (state, _writer) = vpnctld::make_app_state_for_tests(inv, Arc::new(reg));
    state
}

/// Decode the raw-base64 (VPN-client UA) subscription into its lines.
async fn subscription_lines(app: axum::Router, device_id: &str) -> Vec<String> {
    let (status, body, _ct) = get(
        app,
        &format!("/api/v1/app/config/{device_id}"),
        "v2rayN/6.62",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let decoded = BASE64_STANDARD.decode(&body).unwrap();
    let s = String::from_utf8(decoded).unwrap();
    s.split('\n').map(str::to_owned).collect()
}

/// A naive-granted user gets the naive URI — and it lands STRICTLY AFTER
/// every vless line (two-pass render). The userinfo carries the user id +
/// credential and the host is the ACME domain.
#[tokio::test]
async fn vpn_router_naive_uri_appended_after_all_vless() {
    let dir = TempDir::new().unwrap();
    let state = seed_state_with_naive(&dir).await;
    let lines = subscription_lines(router(state), NAIVE_DEVICE_ID).await;

    assert_eq!(lines.len(), 2, "expected 1 vless + 1 naive: {lines:?}");
    assert!(
        lines[0].starts_with("vless://") && lines[0].contains("@de.example.com"),
        "vless must be first: {lines:?}"
    );
    let naive = lines.last().unwrap();
    assert!(
        naive.starts_with("naive+https://"),
        "naive must be last: {lines:?}"
    );
    assert!(
        naive.contains("tester-1:NAIVE_TEST_PW@cdn.example.com"),
        "naive userinfo + ACME host: {naive}"
    );
    // The naive line never precedes a vless line — guards the two-pass order.
    let first_naive = lines
        .iter()
        .position(|l| l.starts_with("naive+https://"))
        .unwrap();
    let last_vless = lines
        .iter()
        .rposition(|l| l.starts_with("vless://"))
        .unwrap();
    assert!(
        first_naive > last_vless,
        "every vless precedes every naive: {lines:?}"
    );
}

/// Kill-switch: hiding naive on the server (NM-10) drops it from the
/// subscription on the very next request — and the vless lines are
/// untouched. This is the instant, redeploy-free abort path.
#[tokio::test]
async fn vpn_router_hidden_naive_excluded_vless_intact() {
    let dir = TempDir::new().unwrap();
    let state = seed_state_with_naive(&dir).await;
    // All mutations BEFORE the fetch (access-log writer race, see above).
    state
        .inv
        .set_server_protocol_hidden(&ServerId("cdn".into()), &ProtocolId("naive".into()), true)
        .await
        .unwrap();
    let lines = subscription_lines(router(state), NAIVE_DEVICE_ID).await;

    assert!(
        !lines.iter().any(|l| l.starts_with("naive+https://")),
        "hidden naive must be absent: {lines:?}"
    );
    assert!(
        lines.iter().any(|l| l.contains("@de.example.com")),
        "vless must remain after hiding naive: {lines:?}"
    );
}

/// Opt-in by grant: a user NOT granted on the naive server gets a
/// vless-only blob — byte-identical to the pre-Part-B output. Proves naive
/// cannot break vless for the fleet default (un-opted users).
#[tokio::test]
async fn vpn_router_user_without_naive_grant_gets_no_naive() {
    let dir = TempDir::new().unwrap();
    let state = seed_state_with_naive(&dir).await;
    // Revoke the naive grant BEFORE the fetch → user granted only on de.
    state
        .inv
        .revoke(&UserId("tester-1".into()), &ServerId("cdn".into()))
        .await
        .unwrap();
    let lines = subscription_lines(router(state), NAIVE_DEVICE_ID).await;

    // Byte-integrity: EXACTLY the de vless line, unchanged shape (uuid,
    // host:port, fragment). Proves the naive append path didn't perturb a
    // single byte of the vless output for an un-opted user — the operator's
    // hard requirement.
    assert_eq!(lines.len(), 1, "exactly the de vless line: {lines:?}");
    assert!(
        !lines[0].starts_with("naive+https://"),
        "ungranted user must get no naive line: {lines:?}"
    );
    assert!(
        lines[0].starts_with("vless://11111111-2222-3333-4444-555555555555@de.example.com:443"),
        "de vless uuid/host/port intact: {}",
        lines[0]
    );
    assert!(
        lines[0].contains("#Germany%20VLESS%20~tester-1"),
        "de vless fragment intact: {}",
        lines[0]
    );
}

/// A user granted ONLY on the naive server (no vless grant) gets a
/// single-line naive-only blob — `make_config_blob` doesn't choke on the
/// vless-empty case and naive renders standalone.
#[tokio::test]
async fn vpn_router_naive_only_user_gets_naive_line() {
    let dir = TempDir::new().unwrap();
    let state = seed_state_with_naive(&dir).await;
    // Revoke the vless grant → user granted only on cdn (naive).
    state
        .inv
        .revoke(&UserId("tester-1".into()), &ServerId("de".into()))
        .await
        .unwrap();
    let lines = subscription_lines(router(state), NAIVE_DEVICE_ID).await;

    assert_eq!(lines.len(), 1, "exactly the naive line: {lines:?}");
    assert!(
        lines[0].starts_with("naive+https://") && lines[0].contains("@cdn.example.com"),
        "naive-only blob: {lines:?}"
    );
}

/// Injection defence end-to-end: a `naive.domain` carrying a newline +
/// forged `vless://` line is REJECTED by the share_link guard → the naive
/// render errors → the handler logs + serves vless-only. The forged line
/// NEVER reaches the blob, and the legitimate vless line is untouched.
#[tokio::test]
async fn vpn_router_malformed_naive_domain_no_injection_vless_intact() {
    let dir = TempDir::new().unwrap();
    let state = seed_state_with_naive(&dir).await;
    // Overwrite the cdn domain with an injection payload BEFORE the fetch.
    state
        .inv
        .set_server_secret(
            &ServerId("cdn".into()),
            "naive.domain",
            "evil.com\nvless://forged@9.9.9.9:443?inject=1",
        )
        .await
        .unwrap();
    let lines = subscription_lines(router(state), NAIVE_DEVICE_ID).await;

    assert!(
        !lines.iter().any(|l| l.contains("forged")),
        "no forged line may reach the blob: {lines:?}"
    );
    assert!(
        !lines.iter().any(|l| l.starts_with("naive+https://")),
        "the rejected naive server emits no link: {lines:?}"
    );
    // The legitimate de vless line is served unchanged.
    assert_eq!(lines.len(), 1, "vless-only after naive rejected: {lines:?}");
    assert!(
        lines[0].contains("@de.example.com:443"),
        "vless intact: {lines:?}"
    );
}

// ── Extra protocols: hysteria2 (UDP/8444 + Salamander obfs) ──────────────

const HY2_DEVICE_ID: &str = "c1c2c3c4c5c6c7c8c9c0c1c2c3c4c5c6";

/// SingBox kernel + Vless & Hysteria2 protocols; a vless server `de` and a
/// hysteria2 server `hy` with a Salamander obfs password provisioned. User
/// granted on both, with a `tuic_password` (hy2's per-user auth secret).
async fn seed_state_with_hy2(dir: &TempDir) -> AppState {
    seed_hy2_opts(dir, Some("HY2_TEST_PW"), true).await
}

async fn seed_hy2_opts(dir: &TempDir, tuic_password: Option<&str>, obfs: bool) -> AppState {
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    let mut reg = Registry::new();
    reg.register_kernel(Box::new(SingBox::new())).unwrap();
    reg.register_protocol(Box::new(VlessReality::new()))
        .unwrap();
    reg.register_protocol(Box::new(Hysteria2::new())).unwrap();

    let de = Server {
        id: ServerId("de".into()),
        address: "de.example.com".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("vless+reality".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    };
    inv.add_server(&de).await.unwrap();
    inv.set_server_secret(&de.id, "vless.public_key", "PUB_de")
        .await
        .unwrap();
    inv.set_server_secret(&de.id, "vless.short_id", "12345678")
        .await
        .unwrap();

    let hy = Server {
        id: ServerId("hy".into()),
        address: "hy.example.com".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("hysteria2".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    };
    inv.add_server(&hy).await.unwrap();
    // Salamander obfs minted (when requested) → share-link carries obfs params.
    if obfs {
        inv.set_server_secret(&hy.id, "hysteria2.obfs.password", "OBFSPW123")
            .await
            .unwrap();
    }

    let user = User {
        id: UserId("tester-1".into()),
        uuid: "11111111-2222-3333-4444-555555555555".into(),
        tuic_password: tuic_password.map(str::to_string),
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    };
    inv.add_user(&user).await.unwrap();
    inv.set_vpn_router_device_id(&user.id, HY2_DEVICE_ID)
        .await
        .unwrap();
    inv.grant(&user.id, &ServerId("de".into())).await.unwrap();
    inv.grant(&user.id, &ServerId("hy".into())).await.unwrap();

    let (state, _writer) = vpnctld::make_app_state_for_tests(inv, Arc::new(reg));
    state
}

/// hysteria2 renders AFTER vless, in the official `hysteria2://` URI form,
/// and carries the Salamander obfs params when the server secret is minted
/// (this is what makes it DPI-resistant — the whole point of the protocol).
#[tokio::test]
async fn vpn_router_hysteria2_uri_appended_after_vless_with_obfs() {
    let dir = TempDir::new().unwrap();
    let state = seed_state_with_hy2(&dir).await;
    let lines = subscription_lines(router(state), HY2_DEVICE_ID).await;

    assert_eq!(lines.len(), 2, "expected 1 vless + 1 hysteria2: {lines:?}");
    assert!(
        lines[0].starts_with("vless://") && lines[0].contains("@de.example.com"),
        "vless must be first: {lines:?}"
    );
    let hy2 = lines.last().unwrap();
    assert!(
        hy2.starts_with("hysteria2://") && hy2.contains("@hy.example.com:8444/"),
        "hysteria2 last, official scheme + UDP port: {lines:?}"
    );
    assert!(
        hy2.contains("obfs=salamander") && hy2.contains("obfs-password="),
        "Salamander obfs params present (DPI-resistant): {hy2}"
    );
    assert!(hy2.ends_with("#tester-1"), "fragment: {hy2}");
}

/// Kill-switch parity with naive: hiding hysteria2 (NM-10) drops it from the
/// subscription on the next request, vless untouched.
#[tokio::test]
async fn vpn_router_hidden_hysteria2_excluded_vless_intact() {
    let dir = TempDir::new().unwrap();
    let state = seed_state_with_hy2(&dir).await;
    state
        .inv
        .set_server_protocol_hidden(
            &ServerId("hy".into()),
            &ProtocolId("hysteria2".into()),
            true,
        )
        .await
        .unwrap();
    let lines = subscription_lines(router(state), HY2_DEVICE_ID).await;

    assert!(
        !lines.iter().any(|l| l.starts_with("hysteria2://")),
        "hidden hysteria2 must be absent: {lines:?}"
    );
    assert!(
        lines.iter().any(|l| l.contains("@de.example.com")),
        "vless must remain: {lines:?}"
    );
}

/// hysteria2's per-user auth is `tuic_password`; a user without one is
/// SKIPPED (share_link errs → failure-isolated) and their vless stays
/// byte-intact. This is the fleet-default case (most migrated users have no
/// tuic_password) — proves an extra protocol can't break their vless.
#[tokio::test]
async fn vpn_router_hysteria2_without_tuic_password_skipped_vless_intact() {
    let dir = TempDir::new().unwrap();
    let state = seed_hy2_opts(&dir, None, true).await;
    let lines = subscription_lines(router(state), HY2_DEVICE_ID).await;
    assert_eq!(
        lines.len(),
        1,
        "vless-only when the user has no tuic_password: {lines:?}"
    );
    assert!(
        !lines.iter().any(|l| l.starts_with("hysteria2://")),
        "no hy2 line for a credential-less user: {lines:?}"
    );
    assert!(
        lines[0].starts_with("vless://") && lines[0].contains("@de.example.com:443"),
        "vless intact: {lines:?}"
    );
}

/// `require_secret = None`: hysteria2 renders even with NO obfs secret — a
/// bare `hysteria2://` (no `obfs=` params). Pins that the hy2 path does NOT
/// gate on a server secret the way naive gates on `naive.domain`.
#[tokio::test]
async fn vpn_router_hysteria2_without_obfs_secret_emits_bare_uri() {
    let dir = TempDir::new().unwrap();
    let state = seed_hy2_opts(&dir, Some("PW"), false).await;
    let lines = subscription_lines(router(state), HY2_DEVICE_ID).await;
    let hy2 = lines
        .iter()
        .find(|l| l.starts_with("hysteria2://"))
        .expect("hy2 must render even without an obfs secret");
    assert!(
        !hy2.contains("obfs="),
        "no obfs params when the secret is absent: {hy2}"
    );
    assert!(
        hy2.contains("@hy.example.com:8444/"),
        "still a valid hysteria2 endpoint: {hy2}"
    );
}

/// Multi-extra ordering: a user granted vless + naive + hysteria2 gets the
/// blob partitioned as [vless.., naive+https.., hysteria2://] — vless first
/// (byte-stable), then the extras in EXTRA_PROTOCOLS declaration order. Pins
/// the order against a future reorder of that const.
#[tokio::test]
async fn vpn_router_vless_then_naive_then_hysteria2_order() {
    let dir = TempDir::new().unwrap();
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    let mut reg = Registry::new();
    reg.register_kernel(Box::new(SingBox::new())).unwrap();
    reg.register_kernel(Box::new(Caddy::new())).unwrap();
    reg.register_protocol(Box::new(VlessReality::new()))
        .unwrap();
    reg.register_protocol(Box::new(Naive::new())).unwrap();
    reg.register_protocol(Box::new(Hysteria2::new())).unwrap();

    let mk = |id: &str, proto: &str, kernel: &str| Server {
        id: ServerId(id.into()),
        address: format!("{id}.example.com"),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId(kernel.into())],
        enabled_protocols: vec![ProtocolId(proto.into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    };
    let de = mk("de", "vless+reality", "sing-box");
    inv.add_server(&de).await.unwrap();
    inv.set_server_secret(&de.id, "vless.public_key", "PUB_de")
        .await
        .unwrap();
    inv.set_server_secret(&de.id, "vless.short_id", "12345678")
        .await
        .unwrap();
    let cdn = mk("cdn", "naive", "caddy");
    inv.add_server(&cdn).await.unwrap();
    inv.set_server_secret(&cdn.id, "naive.domain", "cdn.example.com")
        .await
        .unwrap();
    let hy = mk("hy", "hysteria2", "sing-box");
    inv.add_server(&hy).await.unwrap();

    let user = User {
        id: UserId("tester-1".into()),
        uuid: "11111111-2222-3333-4444-555555555555".into(),
        tuic_password: Some("PW".into()),
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    };
    inv.add_user(&user).await.unwrap();
    inv.set_vpn_router_device_id(&user.id, HY2_DEVICE_ID)
        .await
        .unwrap();
    for s in ["de", "cdn", "hy"] {
        inv.grant(&user.id, &ServerId(s.into())).await.unwrap();
    }

    let (state, _w) = vpnctld::make_app_state_for_tests(inv, Arc::new(reg));
    let lines = subscription_lines(router(state), HY2_DEVICE_ID).await;
    assert_eq!(lines.len(), 3, "vless + naive + hy2: {lines:?}");
    assert!(lines[0].starts_with("vless://"), "vless first: {lines:?}");
    assert!(
        lines[1].starts_with("naive+https://"),
        "naive second: {lines:?}"
    );
    assert!(
        lines[2].starts_with("hysteria2://"),
        "hysteria2 third: {lines:?}"
    );
}
