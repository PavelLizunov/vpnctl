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
