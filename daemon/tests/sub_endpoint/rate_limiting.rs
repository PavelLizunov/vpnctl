use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_inventory::SqliteInventory;
use vpnctl_kernels::SingBox;
use vpnctl_protocols::{TuicV5, VlessReality};
use vpnctld::rate_limit::{DEFAULT_BAN_TTL_SECS, K_DENIALS_TO_BAN, RateLimiter};
use vpnctld::router;

use super::common::seed_with_limiter;

#[tokio::test]
async fn sub_rate_limit_returns_429_after_burst() {
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

    let limiter = Arc::new(RateLimiter::new(2.0, 0.0, Duration::from_secs(60)));
    let (state, _writer) = vpnctld::make_app_state_with_rate_limiter(inv, Arc::new(reg), limiter);
    let app = router(state);

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

#[tokio::test]
async fn sub_persistent_ban_lands_after_k_consecutive_429s_with_redacted_audit() {
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

    let limiter = Arc::new(RateLimiter::new(1.0, 0.0, Duration::from_secs(60)));
    let inv_clone = inv.clone();
    let (state, _writer) = vpnctld::make_app_state_with_rate_limiter(inv, Arc::new(reg), limiter);
    let app = router(state);

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

    let audit = inv_clone.recent_audit(100).await.unwrap();
    let row = audit
        .iter()
        .find(|row| {
            row.action == "rate.ban.add"
                && row.payload.as_ref().is_some_and(|p| p["kind"] == "token")
        })
        .expect("token ban must be audited");
    let n = token.chars().count();
    let expected = format!(
        "{}…{} ({n} chars)",
        token.chars().take(4).collect::<String>(),
        token.chars().skip(n - 4).collect::<String>()
    );
    assert_eq!(row.target.as_deref(), Some(expected.as_str()));
    assert!(
        !format!("{audit:?}").contains(&token),
        "audit must not contain a bearer token"
    );

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

#[tokio::test]
async fn sub_token_ban_audit_fully_redacts_short_tokens() {
    let dir = TempDir::new().unwrap();
    let limiter = Arc::new(RateLimiter::new(1.0, 0.0, Duration::from_secs(60)));
    let (inv, state, _) = seed_with_limiter(&dir, limiter).await;
    let user = vpnctl_core::User {
        id: vpnctl_core::UserId("short-token-user".into()),
        uuid: "uuid-short-token-user".into(),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: Some("short".into()),
        vpn_router_device_id: None,
        disabled: false,
    };
    inv.add_user(&user).await.unwrap();
    inv.grant(&user.id, &vpnctl_core::ServerId("srv".into()))
        .await
        .unwrap();
    let app = router(state);
    for n in 0..=K_DENIALS_TO_BAN {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/sub/short")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            if n == 0 {
                StatusCode::OK
            } else {
                StatusCode::TOO_MANY_REQUESTS
            }
        );
    }
    assert!(inv.is_banned("token", "short").await.unwrap().is_some());
    let audit = inv.recent_audit(100).await.unwrap();
    let row = audit
        .iter()
        .find(|row| row.action == "rate.ban.add")
        .unwrap();
    assert_eq!(row.target.as_deref(), Some("<redacted>"));
    assert!(!format!("{row:?}").contains("short"));
}

#[tokio::test]
async fn v2ray_branch_enforces_token_ban() {
    let dir = TempDir::new().unwrap();
    let limiter = Arc::new(RateLimiter::new(100.0, 1.0, Duration::from_secs(60)));
    let (inv, state, token) = seed_with_limiter(&dir, limiter).await;

    inv.add_ban(
        "token",
        &token,
        DEFAULT_BAN_TTL_SECS,
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
    assert!(
        !s.contains("vless://") && BASE64_STANDARD.decode(s.trim()).is_err(),
        "v2ray-UA banned-token response must not be a base64 subscription, got {s:?}"
    );
}

#[tokio::test]
async fn v2ray_branch_enforces_token_rate_limit() {
    let dir = TempDir::new().unwrap();
    let limiter = Arc::new(RateLimiter::new(1.0, 0.0, Duration::from_secs(60)));
    let (_inv, state, token) = seed_with_limiter(&dir, limiter).await;
    let app = router(state);

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

#[tokio::test]
async fn v2ray_branch_happy_path_still_returns_base64_subscription() {
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

#[tokio::test]
async fn singbox_branch_still_enforces_token_ban() {
    let dir = TempDir::new().unwrap();
    let limiter = Arc::new(RateLimiter::new(100.0, 1.0, Duration::from_secs(60)));
    let (inv, state, token) = seed_with_limiter(&dir, limiter).await;
    inv.add_ban(
        "token",
        &token,
        DEFAULT_BAN_TTL_SECS,
        "test: pre-banned token",
    )
    .await
    .unwrap();

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
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let s = std::str::from_utf8(&body).unwrap();
    assert!(
        s.contains("token-ban"),
        "sing-box banned-token response must say 'token-ban', got {s:?}"
    );
}

#[tokio::test]
async fn sub_egress_ip_exempt_from_per_ip_ban() {
    let dir = TempDir::new().unwrap();
    let limiter = Arc::new(RateLimiter::new(1.0, 0.0, Duration::from_secs(60)));
    let (inv, state, token) = seed_with_limiter(&dir, limiter).await;
    let egress: SocketAddr = "10.0.0.1:40000".parse().unwrap();
    let app = router(state);

    let mut saw_ip_gate = false;
    let mut saw_token_gate = false;
    for _ in 0..(K_DENIALS_TO_BAN + 5) {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/sub/{token}"))
                    .extension(ConnectInfo(egress))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        if resp.status() == StatusCode::TOO_MANY_REQUESTS {
            let body = resp.into_body().collect().await.unwrap().to_bytes();
            let s = std::str::from_utf8(&body).unwrap();
            if s.contains("(ip)") {
                saw_ip_gate = true;
            }
            if s.contains("token") {
                saw_token_gate = true;
            }
        }
    }

    assert!(
        !saw_ip_gate,
        "egress source must never be throttled by the shared per-IP gate"
    );
    assert!(
        saw_token_gate,
        "egress source must still be protected by the per-token gate"
    );

    let bans = inv.active_bans().await.unwrap();
    assert!(
        !bans.iter().any(|b| b.kind == "ip" && b.key == "10.0.0.1"),
        "egress IP must never be persisted to the shared per-IP ban table: {bans:?}"
    );
}

#[tokio::test]
async fn sub_untrusted_ip_still_escalates_to_per_ip_ban() {
    let dir = TempDir::new().unwrap();
    let limiter = Arc::new(RateLimiter::new(1.0, 0.0, Duration::from_secs(60)));
    let (inv, state, _token) = seed_with_limiter(&dir, limiter).await;
    let client: SocketAddr = "203.0.113.9:40000".parse().unwrap();
    let app = router(state);

    let mut saw_ip_gate = false;
    for _ in 0..(K_DENIALS_TO_BAN + 5) {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/sub/definitely-not-a-real-token")
                    .extension(ConnectInfo(client))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        if resp.status() == StatusCode::TOO_MANY_REQUESTS {
            let body = resp.into_body().collect().await.unwrap().to_bytes();
            let s = std::str::from_utf8(&body).unwrap();
            if s.contains("(ip)") {
                saw_ip_gate = true;
            }
        }
    }

    assert!(
        saw_ip_gate,
        "untrusted source must still be throttled by the per-IP gate"
    );
    let bans = inv.active_bans().await.unwrap();
    assert!(
        bans.iter()
            .any(|b| b.kind == "ip" && b.key == "203.0.113.9"),
        "untrusted IP must still escalate to the persistent per-IP ban: {bans:?}"
    );
}
