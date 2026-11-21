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
use vpnctl_protocols::{TuicV5, VlessReality, WireGuard};
use vpnctld::router;

use super::common::seed;

fn empty_singbox_bytes() -> Vec<u8> {
    serde_json::json!({
        "log": {"level": "info", "timestamp": true},
        "outbounds": [
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"}
        ],
        "route": {
            "rules": [{"protocol": "dns", "outbound": "block"}],
            "final": "block", "auto_detect_interface": true
        }
    })
    .to_string()
    .into_bytes()
}

#[tokio::test]
async fn confirmed_tcp_outage_hides_routes_and_recovery_restores_exact_response_bytes() {
    use base64::Engine;
    use chrono::{Duration, Utc};
    use vpnctl_inventory::ServiceQualitySample;

    for format in ["uri", "default", "stock", "mihomo", "app"] {
        let dir = TempDir::new().unwrap();
        let (state, token) = seed(&dir).await;
        let inv = &state.inv;
        let sid = ServerId("srv".into());
        let uid = UserId("alice".into());
        let original_user = inv.get_user(&uid).await.unwrap().unwrap();
        let secrets = inv.list_server_secrets(&sid).await.unwrap();
        let mut healthy = inv.get_server(&sid).await.unwrap().unwrap();
        healthy.id = ServerId("healthy".into());
        healthy.address = "198.51.100.52".into();
        inv.add_server(&healthy).await.unwrap();
        for (key, value) in &secrets {
            inv.set_server_secret(&healthy.id, key, value)
                .await
                .unwrap();
        }
        inv.grant(&uid, &healthy.id).await.unwrap();
        inv.set_server_auto_suppress(&sid, true).await.unwrap();
        let device = "f1f2f3f4f5f6f7f8f9f0f1f2f3f4f5f6";
        inv.set_vpn_router_device_id(&uid, device).await.unwrap();
        let (path, ua) = match format {
            "uri" => (format!("/sub/{token}"), "v2rayN/7.0"),
            "default" => (format!("/sub/{token}"), "sing-box/1.14"),
            "stock" => (format!("/sub/{token}?format=sing-box"), "sing-box/1.14"),
            "mihomo" => (format!("/api/v1/sub/{token}"), "clash.meta/1.19"),
            _ => (format!("/api/v1/app/config/{device}"), "v2rayN/7.0"),
        };
        let fetch = || async {
            let response = router(state.clone())
                .oneshot(
                    Request::builder()
                        .uri(&path)
                        .header("user-agent", ua)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{format}");
            response.into_body().collect().await.unwrap().to_bytes()
        };
        let readable = |body: &[u8]| {
            String::from_utf8(
                base64::engine::general_purpose::STANDARD
                    .decode(body)
                    .unwrap_or_else(|_| body.to_vec()),
            )
            .unwrap()
        };
        let before = fetch().await;
        assert!(readable(&before).contains("10.0.0.1"), "{format}");
        let base = Utc::now() - Duration::seconds(60);
        for (offset, successes) in [(0, 0), (10, 0), (20, 3), (30, 3)] {
            let sample = ServiceQualitySample {
                ts: base + Duration::seconds(offset),
                server_id: sid.clone(),
                vantage: "fixture measurement network".into(),
                target_count: 1,
                available_targets: u32::from(successes > 0),
                attempts: 3,
                successes,
                tcp_rtt_ms: vec![10; successes as usize],
                control_attempts: 3,
                control_successes: 3,
                control_rtt_ms: vec![10; 3],
                icmp_attempts: None,
                icmp_successes: None,
                icmp_rtt_ms: None,
            };
            inv.record_service_path(&sample, "fixture:tcp-vpn-port", 120)
                .await
                .unwrap();
            let body = fetch().await;
            if matches!(offset, 10 | 20) {
                assert_ne!(body, before, "confirmed outage must change {format} bytes");
                assert!(
                    !readable(&body).contains("10.0.0.1"),
                    "hidden route leaked in {format}"
                );
                assert!(
                    readable(&body).contains("198.51.100.52"),
                    "healthy route disappeared from {format}"
                );
            } else {
                assert_eq!(
                    body, before,
                    "unchanged/restored {format} must match every byte"
                );
            }
        }
        let current_user = inv.get_user(&uid).await.unwrap().unwrap();
        assert_eq!(current_user.uuid, original_user.uuid);
        assert_eq!(current_user.sub_token, original_user.sub_token);
        assert_eq!(current_user.tuic_password, original_user.tuic_password);
        assert_eq!(inv.list_server_secrets(&sid).await.unwrap(), secrets);
        assert_eq!(inv.users_for_server(&sid).await.unwrap().len(), 1);
        assert_eq!(inv.users_for_server(&healthy.id).await.unwrap().len(), 1);
    }
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
    state
        .inv
        .set_server_secret(
            &ServerId("srv".into()),
            "observed.tls.cert_public_key_sha256",
            &"cd".repeat(32),
        )
        .await
        .unwrap();
    let app = router(state);

    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/sub/{token}"))
                .header("user-agent", "SingBox/1.14.0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&body).unwrap();

    assert!(v["log"].is_object());
    assert!(v["route"].is_object());
    let outbounds = v["outbounds"].as_array().unwrap();
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
async fn sub_skips_wireguard_protocol_in_sing_box_envelope() {
    let dir = TempDir::new().unwrap();
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    let mut reg = Registry::new();
    reg.register_kernel(Box::new(SingBox::new())).unwrap();
    reg.register_protocol(Box::new(VlessReality::new()))
        .unwrap();
    reg.register_protocol(Box::new(WireGuard::new())).unwrap();

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

    for ob in outbounds {
        let ty = ob["type"].as_str().unwrap_or("");
        assert_ne!(
            ty, "wireguard",
            "wireguard internal object leaked into sing-box sub envelope: {ob:?}. \
             /sub handler must filter via Protocol::appears_in_sing_box_sub()."
        );
    }
    let has_vless = outbounds
        .iter()
        .any(|ob| ob["type"].as_str() == Some("vless"));
    assert!(
        has_vless,
        "vless+reality outbound is missing — filter dropped too much: {outbounds:?}"
    );
}

#[tokio::test]
async fn sub_token_for_user_with_no_grants_fails_closed_byte_equal() {
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
    for query in ["", "?format=sing-box"] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/sub/{token}{query}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), empty_singbox_bytes().as_slice());
    }
}

#[tokio::test]
async fn disabled_user_singbox_fails_closed_byte_equal() {
    let dir = TempDir::new().unwrap();
    let (state, token) = seed(&dir).await;
    state
        .inv
        .set_user_disabled_audited(&UserId("alice".into()), true, "test")
        .await
        .unwrap();
    let app = router(state);

    for query in ["", "?format=sing-box"] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/sub/{token}{query}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), empty_singbox_bytes().as_slice());
    }
}

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
    assert_eq!(
        resp.headers().get("referrer-policy").unwrap(),
        "no-referrer"
    );

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
    assert_eq!(
        resp.headers().get("referrer-policy").unwrap(),
        "no-referrer"
    );
}

#[tokio::test]
async fn ss2022_mode_preserves_legacy_http_bytes_and_revokes_rendered_users() {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    use vpnctl_core::RenderCtx;

    async fn fetch(state: &vpnctld::AppState, path: &str) -> Vec<u8> {
        let response = router(state.clone())
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header("user-agent", "v2rayN/6.62")
                    .body(Body::empty())
                    .unwrap(),
            )
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

    let dir = TempDir::new().unwrap();
    let (mut state, token) = seed(&dir).await;
    state.registry = Arc::new(vpnctl_kernels::build_registry().unwrap());
    // Sixteen fetches of one token: lift the per-token limit for this test.
    state.rate_limiter = Arc::new(vpnctld::rate_limit::RateLimiter::new(
        1000.0,
        1000.0,
        std::time::Duration::from_secs(60),
    ));
    let sid = ServerId("srv".into());
    let uid = UserId("alice".into());
    let pid = ProtocolId("shadowsocks-2022".into());
    state.inv.add_server_protocol(&sid, &pid).await.unwrap();
    state
        .inv
        .set_server_secret(&sid, "ss2022.psk", "AAECAwQFBgcICQoLDA0ODw==")
        .await
        .unwrap();
    state
        .inv
        .set_grant_client_uuid(&uid, &sid, "00000000-0000-0000-0000-000000000001")
        .await
        .unwrap();
    let device = "0123456789abcdef0123456789abcdef";
    state
        .inv
        .set_vpn_router_device_id(&uid, device)
        .await
        .unwrap();
    let paths = [
        format!("/sub/{token}"),
        format!("/sub/{token}?format=sing-box"),
        format!("/api/v1/sub/{token}"),
        format!("/api/v1/app/config/{device}"),
    ];
    let mut baseline = Vec::new();
    for path in &paths {
        baseline.push(fetch(&state, path).await);
    }
    let legacy_links = String::from_utf8(B64.decode(&baseline[0]).unwrap()).unwrap();
    assert!(legacy_links.lines().any(|line| line.as_bytes()
        == b"ss://2022-blake3-aes-128-gcm:AAECAwQFBgcICQoLDA0ODw==@10.0.0.1:8388/#alice"));
    let legacy_json = String::from_utf8(baseline[1].clone()).unwrap();
    assert!(legacy_json.contains(r#"{"method":"2022-blake3-aes-128-gcm","password":"AAECAwQFBgcICQoLDA0ODw==","server":"10.0.0.1","server_port":8388,"tag":"SRV SS-22 ~alice","type":"shadowsocks"}"#));
    // Explicit shared mode must preserve the entire response on all four surfaces.
    for mode in ["shared", "multi-user", "shared"] {
        state
            .inv
            .set_server_secrets_audited(&sid, "test", "server.secret.set", &[("ss2022.mode", mode)])
            .await
            .unwrap();
        for (index, path) in paths.iter().enumerate() {
            let actual = fetch(&state, path).await;
            let expected = if mode == "multi-user" && index == 0 {
                B64.encode(legacy_links.replace(
                    "AAECAwQFBgcICQoLDA0ODw==@",
                    "AAECAwQFBgcICQoLDA0ODw==%3AGjw%2FMOzkwdF8pDO05jE0+g==@",
                ))
                .into_bytes()
            } else if mode == "multi-user" && index == 1 {
                legacy_json
                    .replace(
                        r#""password":"AAECAwQFBgcICQoLDA0ODw==""#,
                        r#""password":"AAECAwQFBgcICQoLDA0ODw==:Gjw/MOzkwdF8pDO05jE0+g==""#,
                    )
                    .into_bytes()
            } else {
                baseline[index].clone()
            };
            assert_eq!(actual, expected, "{path}, mode {mode}");
        }
    }
    // Deploy consumes the same inventory-filtered, per-server UUID user list.
    state
        .inv
        .set_server_secrets_audited(
            &sid,
            "test",
            "server.secret.set",
            &[("ss2022.mode", "multi-user")],
        )
        .await
        .unwrap();
    state
        .inv
        .set_server_secret(&sid, "ss2022.no_users_psk", "BAUGBwgJCgsMDQ4PEBESEw==")
        .await
        .unwrap();
    let server = state.inv.get_server(&sid).await.unwrap().unwrap();
    let secrets = state.inv.list_server_secrets(&sid).await.unwrap();
    let ctx = RenderCtx::new(&server, &secrets);
    let protocol = state.registry.protocol(&pid).unwrap();
    let users = state.inv.users_for_server(&sid).await.unwrap();
    assert_eq!(
        protocol.server_inbound(&ctx, &users).unwrap()["users"],
        serde_json::json!([
            {"name": "alice", "password": "Gjw/MOzkwdF8pDO05jE0+g=="},
        ])
    );
    state
        .inv
        .set_user_disabled_audited(&uid, true, "test")
        .await
        .unwrap();
    let users = state.inv.users_for_server(&sid).await.unwrap();
    assert_eq!(
        protocol.server_inbound(&ctx, &users).unwrap()["users"],
        serde_json::json!([{"name": "vpnctl-no-users", "password": "BAUGBwgJCgsMDQ4PEBESEw=="}])
    );
    state
        .inv
        .set_user_disabled_audited(&uid, false, "test")
        .await
        .unwrap();
    state.inv.remove_user(&uid).await.unwrap();
    let users = state.inv.users_for_server(&sid).await.unwrap();
    assert_eq!(
        protocol.server_inbound(&ctx, &users).unwrap()["users"],
        serde_json::json!([{"name": "vpnctl-no-users", "password": "BAUGBwgJCgsMDQ4PEBESEw=="}])
    );
}

#[tokio::test]
async fn stock_vmess_subscription_relabels_duplicate_tags_and_honors_visibility() {
    let dir = TempDir::new().unwrap();
    let (mut state, _) = seed(&dir).await;
    state.registry = Arc::new(vpnctl_kernels::build_registry().unwrap());
    let inv = &state.inv;
    let protocol = ProtocolId("vmess".into());
    let uid = UserId("vmess-fixture".into());
    let mut user = inv
        .get_user(&UserId("alice".into()))
        .await
        .unwrap()
        .unwrap();
    user.id = uid.clone();
    user.uuid = "00000000-0000-4000-8000-000000000042".into();
    user.sub_token = None;
    inv.add_user(&user).await.unwrap();
    let token = inv
        .get_user(&uid)
        .await
        .unwrap()
        .unwrap()
        .sub_token
        .unwrap();
    let mut server = inv
        .get_server(&ServerId("srv".into()))
        .await
        .unwrap()
        .unwrap();
    server.enabled_protocols = vec![protocol.clone()];
    for (id, address) in [("vmess-a", "192.0.2.10"), ("vmess-b", "192.0.2.11")] {
        server.id = ServerId(id.into());
        server.address = address.into();
        inv.add_server(&server).await.unwrap();
        inv.set_server_secret(&server.id, "vmess.domain", &format!("{id}.example.com"))
            .await
            .unwrap();
        inv.set_server_display_name(&server.id, Some("Shared"))
            .await
            .unwrap();
        inv.grant(&uid, &server.id).await.unwrap();
    }

    let fetch = || {
        let state = state.clone();
        let token = token.clone();
        async move {
            let response = router(state)
                .oneshot(
                    Request::builder()
                        .uri(format!("/sub/{token}?format=sing-box"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let json: Value =
                serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                    .unwrap();
            json["outbounds"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|entry| entry["type"] == "vmess")
                .cloned()
                .collect::<Vec<Value>>()
        }
    };

    let visible = fetch().await;
    assert_eq!(visible.len(), 2);
    assert_ne!(visible[0]["tag"], visible[1]["tag"]);
    assert!(visible.iter().all(|entry| entry["alter_id"] == 0));

    let hop = ServerId("srv".into());
    inv.grant(&uid, &hop).await.unwrap();
    inv.set_client_detour_via_as("test", &ServerId("vmess-a".into()), Some(&hop))
        .await
        .unwrap();
    let after_detour = fetch().await;
    let chained = after_detour
        .iter()
        .find(|outbound| outbound["server"] == "vmess-a.example.com")
        .unwrap();
    assert!(
        chained["detour"]
            .as_str()
            .is_some_and(|tag| tag.contains("VLESS"))
    );

    inv.set_server_protocol_hidden(&ServerId("vmess-a".into()), &protocol, true)
        .await
        .unwrap();
    let visible = fetch().await;
    assert_eq!(visible.len(), 1);
    assert_eq!(visible[0]["server"], "vmess-b.example.com");

    inv.set_grant_protocol_override(&uid, &ServerId("vmess-b".into()), &protocol, true)
        .await
        .unwrap();
    assert!(fetch().await.is_empty());
}
