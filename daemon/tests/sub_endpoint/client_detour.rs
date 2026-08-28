use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use http_body_util::BodyExt;
use serde_json::Value;
use tempfile::TempDir;
use tower::ServiceExt;
use vpnctl_core::{KernelId, ProtocolId, Registry, Server, ServerId, User, UserId};
use vpnctl_inventory::SqliteInventory;
use vpnctl_kernels::SingBox;
use vpnctl_protocols::VlessReality;
use vpnctld::{AppState, router};

async fn seed(dir: &TempDir, grant_entry: bool) -> (AppState, String) {
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    let mut registry = Registry::new();
    registry.register_kernel(Box::new(SingBox::new())).unwrap();
    registry
        .register_protocol(Box::new(VlessReality::new()))
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
    inv.set_client_detour_via_as(
        "test",
        &ServerId("s5".into()),
        Some(&ServerId("is".into())),
    )
    .await
    .unwrap();

    let token = inv
        .get_user(&user.id)
        .await
        .unwrap()
        .unwrap()
        .sub_token
        .unwrap();
    let (state, _writer) = vpnctld::make_app_state_for_tests(inv, Arc::new(registry));
    (state, token)
}

async fn get_sub(state: AppState, token: &str, user_agent: Option<&str>) -> (StatusCode, Vec<u8>) {
    let mut request = Request::builder().uri(format!("/sub/{token}"));
    if let Some(ua) = user_agent {
        request = request.header(header::USER_AGENT, ua);
    }
    let response = router(state)
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, body.to_vec())
}

#[tokio::test]
async fn singbox_subscription_chains_s5_through_iceland() {
    let dir = TempDir::new().unwrap();
    let (state, token) = seed(&dir, true).await;
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
async fn singbox_subscription_omits_target_when_entry_is_not_granted() {
    let dir = TempDir::new().unwrap();
    let (state, token) = seed(&dir, false).await;
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
    let (state, token) = seed(&dir, true).await;
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
async fn v2ray_subscription_omits_chained_target_uri() {
    let dir = TempDir::new().unwrap();
    let (state, token) = seed(&dir, true).await;
    let (status, body) = get_sub(state, &token, Some("v2rayN/6.62")).await;
    assert_eq!(status, StatusCode::OK);

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(body)
        .unwrap();
    let links = std::str::from_utf8(&decoded).unwrap();
    assert!(links.contains("@198.51.100.10:443"), "entry missing: {links}");
    assert!(
        !links.contains("@198.51.100.50:443"),
        "S5 leaked as a direct URI: {links}"
    );
}

#[tokio::test]
async fn clearing_detour_restores_original_subscription_bytes() {
    let dir = TempDir::new().unwrap();
    let (state, token) = seed(&dir, true).await;
    state
        .inv
        .set_client_detour_via_as("test", &ServerId("s5".into()), None)
        .await
        .unwrap();
    let (_, before) = get_sub(state.clone(), &token, None).await;

    state
        .inv
        .set_client_detour_via_as(
            "test",
            &ServerId("s5".into()),
            Some(&ServerId("is".into())),
        )
        .await
        .unwrap();
    state
        .inv
        .set_client_detour_via_as("test", &ServerId("s5".into()), None)
        .await
        .unwrap();
    let (_, after) = get_sub(state, &token, None).await;

    assert_eq!(before, after, "detour clear must restore exact legacy bytes");
}
