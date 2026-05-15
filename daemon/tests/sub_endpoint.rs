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
        kernel: vpnctl_core::KernelId("sing-box".into()),
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
        kernel: vpnctl_core::KernelId("sing-box".into()),
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
