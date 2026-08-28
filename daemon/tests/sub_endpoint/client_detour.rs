use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::response::Response;
use base64::Engine;
use http_body_util::BodyExt;
use serde_json::Value;
use tempfile::TempDir;
use tokio::task::JoinHandle;
use tower::ServiceExt;
use vpnctl_core::{KernelId, ProtocolId, Registry, Server, ServerId, User, UserId};
use vpnctl_inventory::SqliteInventory;
use vpnctl_kernels::SingBox;
use vpnctl_protocols::{VlessReality, VlessXhttp};
use vpnctld::{AppState, router};

async fn seed(dir: &TempDir, grant_entry: bool) -> (AppState, String, JoinHandle<()>) {
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    let mut registry = Registry::new();
    registry.register_kernel(Box::new(SingBox::new())).unwrap();
    registry
        .register_protocol(Box::new(VlessReality::new()))
        .unwrap();
    registry
        .register_protocol(Box::new(VlessXhttp::new()))
        .unwrap();

    for (id, address) in [("is", "198.51.100.10"), ("s5", "198.51.100.50")] {
        let server = Server {
            id: ServerId(id.into()),
            address: address.into(),
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
        inv.set_server_secret(&server.id, "vless.public_key", &format!("PUB_{id}"))
            .await
            .unwrap();
        inv.set_server_secret(&server.id, "vless.short_id", "12345678")
            .await
            .unwrap();
    }

    let user = User {
        id: UserId("alice".into()),
        uuid: "11111111-2222-3333-4444-555555555555".into(),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    };
    inv.add_user(&user).await.unwrap();
    inv.grant(&user.id, &ServerId("s5".into())).await.unwrap();
    if grant_entry {
        inv.grant(&user.id, &ServerId("is".into())).await.unwrap();
    }
    inv.set_client_detour_via_as("test", &ServerId("s5".into()), Some(&ServerId("is".into())))
        .await
        .unwrap();

    let token = inv
        .get_user(&user.id)
        .await
        .unwrap()
        .unwrap()
        .sub_token
        .unwrap();
    let (state, writer) = vpnctld::make_app_state_for_tests(inv, Arc::new(registry));
    (state, token, writer)
}

async fn get_sub_response(state: AppState, uri: &str, user_agent: Option<&str>) -> Response {
    let mut request = Request::builder().uri(uri);
    if let Some(ua) = user_agent {
        request = request.header(header::USER_AGENT, ua);
    }
    router(state)
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

async fn get_sub_at(state: AppState, uri: &str, user_agent: Option<&str>) -> (StatusCode, Vec<u8>) {
    let response = get_sub_response(state, uri, user_agent).await;
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, body.to_vec())
}

async fn get_sub(state: AppState, token: &str, user_agent: Option<&str>) -> (StatusCode, Vec<u8>) {
    get_sub_at(state, &format!("/sub/{token}"), user_agent).await
}

#[tokio::test]
async fn singbox_subscription_chains_s5_through_iceland() {
    let dir = TempDir::new().unwrap();
    let (state, token, _writer) = seed(&dir, true).await;
    let (status, body) = get_sub(state, &token, None).await;
    assert_eq!(status, StatusCode::OK);

    let config: Value = serde_json::from_slice(&body).unwrap();
    let outbounds = config["outbounds"].as_array().unwrap();
    let entry = outbounds
        .iter()
        .find(|outbound| outbound["server"] == "198.51.100.10")
        .expect("Iceland entry outbound");
    let target = outbounds
        .iter()
        .find(|outbound| outbound["server"] == "198.51.100.50")
        .expect("S5 target outbound");

    assert_eq!(entry["tag"], "Iceland VLESS ~alice");
    assert_eq!(target["tag"], "S5 VLESS ~alice");
    assert_eq!(target["detour"], entry["tag"]);
}

#[tokio::test]
async fn explicit_singbox_format_overrides_hiddify_ua() {
    let dir = TempDir::new().unwrap();
    let (state, token, _writer) = seed(&dir, true).await;
    let uri = format!("/sub/{token}?format=sing-box");
    let response = get_sub_response(state, &uri, Some("HiddifyNext/1.0.0")).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    let body = response.into_body().collect().await.unwrap().to_bytes();

    let config: Value = serde_json::from_slice(&body).unwrap();
    let outbounds = config["outbounds"].as_array().unwrap();
    let entry = outbounds
        .iter()
        .find(|outbound| outbound["server"] == "198.51.100.10")
        .unwrap();
    let target = outbounds
        .iter()
        .find(|outbound| outbound["server"] == "198.51.100.50")
        .unwrap();
    assert_eq!(target["detour"], entry["tag"]);
}

#[tokio::test]
async fn ordinary_hiddify_and_singbox_ua_bytes_stay_unchanged() {
    let dir = TempDir::new().unwrap();
    let (state, token, _writer) = seed(&dir, true).await;
    let (_, hiddify) = get_sub(state.clone(), &token, Some("HiddifyNext/1.0.0")).await;
    let (_, singbox) = get_sub(state, &token, Some("sing-box/1.13.19")).await;
    assert_eq!(hiddify, singbox);

    let links = base64::engine::general_purpose::STANDARD
        .decode(hiddify)
        .unwrap();
    let links = std::str::from_utf8(&links).unwrap();
    assert!(links.contains("@198.51.100.10:443"));
    assert!(!links.contains("@198.51.100.50:443"));
}

#[tokio::test]
async fn explicit_stock_format_filters_xhttp_without_changing_legacy_json() {
    let dir = TempDir::new().unwrap();
    let (state, token, _writer) = seed(&dir, true).await;
    state
        .inv
        .add_server_protocol(&ServerId("s5".into()), &ProtocolId("vless+xhttp".into()))
        .await
        .unwrap();
    state
        .inv
        .set_server_secret(
            &ServerId("s5".into()),
            "vlessxhttp.path",
            "stock-filter-test",
        )
        .await
        .unwrap();

    let (_, legacy_body) = get_sub(state.clone(), &token, None).await;
    let legacy: Value = serde_json::from_slice(&legacy_body).unwrap();
    assert!(
        legacy["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|outbound| { outbound["transport"]["type"] == "xhttp" })
    );

    let uri = format!("/sub/{token}?format=sing-box");
    let (_, stock_body) = get_sub_at(state, &uri, None).await;
    let stock: Value = serde_json::from_slice(&stock_body).unwrap();
    let outbounds = stock["outbounds"].as_array().unwrap();
    assert!(
        outbounds
            .iter()
            .all(|outbound| outbound["transport"]["type"] != "xhttp")
    );
    assert!(
        outbounds
            .iter()
            .any(|outbound| outbound["server"] == "198.51.100.50")
    );
}

#[tokio::test]
async fn invalid_format_is_rejected_after_token_resolution() {
    for query in ["format=v2ray", "format=sing-box&format=sing-box"] {
        let dir = TempDir::new().unwrap();
        let (state, token, _writer) = seed(&dir, true).await;
        let uri = format!("/sub/{token}?{query}");
        let (status, _) = get_sub_at(state, &uri, None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn invalid_format_does_not_bypass_token_resolution() {
    let dir = TempDir::new().unwrap();
    let (state, _token, _writer) = seed(&dir, true).await;
    let (status, _) = get_sub_at(state, "/sub/not-a-token?format=invalid", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn singbox_subscription_omits_target_when_entry_is_not_granted() {
    let dir = TempDir::new().unwrap();
    let (state, token, _writer) = seed(&dir, false).await;
    let (status, body) = get_sub(state, &token, None).await;
    assert_eq!(status, StatusCode::OK);

    let config: Value = serde_json::from_slice(&body).unwrap();
    let outbounds = config["outbounds"].as_array().unwrap();
    assert_eq!(outbounds.len(), 2, "only direct and block: {outbounds:?}");
    assert!(
        outbounds
            .iter()
            .all(|outbound| outbound["server"] != "198.51.100.50"),
        "S5 must not fall back to a direct outbound"
    );
}

#[tokio::test]
async fn singbox_subscription_omits_target_when_entry_protocol_is_hidden() {
    let dir = TempDir::new().unwrap();
    let (state, token, _writer) = seed(&dir, true).await;
    state
        .inv
        .set_server_protocol_hidden(
            &ServerId("is".into()),
            &ProtocolId("vless+reality".into()),
            true,
        )
        .await
        .unwrap();
    let (status, body) = get_sub(state, &token, None).await;
    assert_eq!(status, StatusCode::OK);

    let config: Value = serde_json::from_slice(&body).unwrap();
    let outbounds = config["outbounds"].as_array().unwrap();
    assert_eq!(outbounds.len(), 2, "only direct and block: {outbounds:?}");
}

#[tokio::test]
async fn singbox_subscription_omits_target_when_entry_protocol_is_denied_for_user() {
    let dir = TempDir::new().unwrap();
    let (state, token, _writer) = seed(&dir, true).await;
    state
        .inv
        .set_grant_protocol_override(
            &UserId("alice".into()),
            &ServerId("is".into()),
            &ProtocolId("vless+reality".into()),
            true,
        )
        .await
        .unwrap();
    let (status, body) = get_sub(state, &token, None).await;
    assert_eq!(status, StatusCode::OK);

    let config: Value = serde_json::from_slice(&body).unwrap();
    let outbounds = config["outbounds"].as_array().unwrap();
    assert_eq!(outbounds.len(), 2, "only direct and block: {outbounds:?}");
}

#[tokio::test]
async fn v2ray_subscription_omits_chained_target_uri() {
    let dir = TempDir::new().unwrap();
    let (state, token, _writer) = seed(&dir, true).await;
    let (status, body) = get_sub(state, &token, Some("v2rayN/6.62")).await;
    assert_eq!(status, StatusCode::OK);

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(body)
        .unwrap();
    let links = std::str::from_utf8(&decoded).unwrap();
    assert!(
        links.contains("@198.51.100.10:443"),
        "entry missing: {links}"
    );
    assert!(
        !links.contains("@198.51.100.50:443"),
        "S5 leaked as a direct URI: {links}"
    );
}

#[tokio::test]
async fn clearing_detour_restores_original_subscription_bytes() {
    let dir = TempDir::new().unwrap();
    let (state, token, writer) = seed(&dir, true).await;
    let inv = state.inv.clone();
    let registry = Arc::clone(&state.registry);
    state
        .inv
        .set_client_detour_via_as("test", &ServerId("s5".into()), None)
        .await
        .unwrap();
    let (_, before) = get_sub(state.clone(), &token, None).await;
    writer.abort();
    assert!(writer.await.unwrap_err().is_cancelled());

    state
        .inv
        .set_client_detour_via_as("test", &ServerId("s5".into()), Some(&ServerId("is".into())))
        .await
        .unwrap();
    state
        .inv
        .set_client_detour_via_as("test", &ServerId("s5".into()), None)
        .await
        .unwrap();
    let (state, _writer) = vpnctld::make_app_state_for_tests(inv, registry);
    let (_, after) = get_sub(state, &token, None).await;

    assert_eq!(
        before, after,
        "detour clear must restore exact legacy bytes"
    );
}
