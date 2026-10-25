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
use vpnctl_protocols::{Hysteria2, Naive, TuicV5, VlessReality, VlessWs, VlessXhttp};
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
    registry.register_protocol(Box::new(Naive::new())).unwrap();
    registry
        .register_protocol(Box::new(VlessWs::new()))
        .unwrap();
    registry
        .register_protocol(Box::new(Hysteria2::new()))
        .unwrap();
    registry.register_protocol(Box::new(TuicV5::new())).unwrap();

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
        tuic_password: Some("pw-alice".into()),
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

async fn set_protocols(state: &AppState, server_id: &str, protocols: &[&str]) {
    let sid = ServerId(server_id.into());
    let server = state.inv.get_server(&sid).await.unwrap().unwrap();
    for pid in &server.enabled_protocols {
        state.inv.remove_server_protocol(&sid, pid).await.unwrap();
    }
    for pid in protocols {
        state
            .inv
            .add_server_protocol(&sid, &ProtocolId((*pid).into()))
            .await
            .unwrap();
    }
    for (key, value) in [
        ("naive.domain", "entry.example.com"),
        ("vlessws.domain", "entry.example.com"),
        ("vlessws.path", "testpath"),
        ("vlessxhttp.path", "testpath"),
    ] {
        state.inv.set_server_secret(&sid, key, value).await.unwrap();
    }
}

#[tokio::test]
async fn udp_targets_skip_tcp_only_entries_and_never_fall_back_direct() {
    for target_pid in ["hysteria2", "tuic-v5"] {
        for entry_pid in ["naive"] {
            let dir = TempDir::new().unwrap();
            let (state, token, _writer) = seed(&dir, true).await;
            set_protocols(&state, "s5", &[target_pid]).await;
            set_protocols(&state, "is", &[entry_pid, "vless+reality"]).await;
            let (status, body) = get_sub(state.clone(), &token, None).await;
            assert_eq!(status, StatusCode::OK);
            let config: Value = serde_json::from_slice(&body).unwrap();
            let outbounds = config["outbounds"].as_array().unwrap();
            assert!(
                outbounds
                    .iter()
                    .any(|o| o["tag"]
                        == format!("Iceland {} ~alice", entry_pid.to_ascii_uppercase()))
            );
            let target = outbounds
                .iter()
                .find(|o| o["server"] == "198.51.100.50")
                .unwrap();
            assert_eq!(target["detour"], "Iceland VLESS ~alice");

            set_protocols(&state, "is", &[entry_pid]).await;
            let (status, omitted) = get_sub(state.clone(), &token, None).await;
            assert_eq!(status, StatusCode::OK);
            let config: Value = serde_json::from_slice(&omitted).unwrap();
            assert!(
                !config["outbounds"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|o| { o["server"] == "198.51.100.50" })
            );
            state
                .inv
                .set_server_protocol_hidden(
                    &ServerId("s5".into()),
                    &ProtocolId(target_pid.into()),
                    true,
                )
                .await
                .unwrap();
            let (_, hidden) = get_sub(state.clone(), &token, None).await;
            assert_eq!(
                omitted, hidden,
                "omitted target must not affect any response bytes"
            );

            set_protocols(&state, "s5", &["vless+reality"]).await;
            let (_, body) = get_sub(state, &token, None).await;
            let config: Value = serde_json::from_slice(&body).unwrap();
            let target = config["outbounds"]
                .as_array()
                .unwrap()
                .iter()
                .find(|o| o["server"] == "198.51.100.50")
                .unwrap();
            assert_eq!(
                target["detour"],
                format!("Iceland {} ~alice", entry_pid.to_ascii_uppercase())
            );
        }
    }
}

#[tokio::test]
async fn udp_targets_accept_vless_over_ws_and_xhttp_entries() {
    for entry_pid in ["vless-ws", "vless+xhttp"] {
        let dir = TempDir::new().unwrap();
        let (state, token, _writer) = seed(&dir, true).await;
        set_protocols(&state, "s5", &["hysteria2"]).await;
        set_protocols(&state, "is", &[entry_pid]).await;
        let (status, body) = get_sub(state, &token, None).await;
        assert_eq!(status, StatusCode::OK);
        let config: Value = serde_json::from_slice(&body).unwrap();
        let target = config["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["server"] == "198.51.100.50")
            .unwrap_or_else(|| panic!("{entry_pid} entry must carry the UDP target"));
        assert_eq!(
            target["detour"],
            format!("Iceland {} ~alice", entry_pid.to_ascii_uppercase())
        );
    }
}

#[tokio::test]
async fn udp_entry_keeps_every_byte_except_the_target_detour() {
    for entry_pid in ["hysteria2", "tuic-v5"] {
        let dir = TempDir::new().unwrap();
        let (state, token, _writer) = seed(&dir, true).await;
        set_protocols(&state, "is", &[entry_pid]).await;
        set_protocols(&state, "s5", &["hysteria2"]).await;
        let target_id = ServerId("s5".into());
        state
            .inv
            .set_client_detour_via_as("test", &target_id, None)
            .await
            .unwrap();
        let (_, direct) = get_sub(state.clone(), &token, None).await;
        let mut expected: Value = serde_json::from_slice(&direct).unwrap();
        let tag = if entry_pid == "hysteria2" {
            "Iceland HY2 ~alice"
        } else {
            "Iceland TUIC ~alice"
        };
        let target = expected["outbounds"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|o| o["server"] == "198.51.100.50")
            .unwrap();
        target["detour"] = serde_json::json!(tag);
        state
            .inv
            .set_client_detour_via_as("test", &target_id, Some(&ServerId("is".into())))
            .await
            .unwrap();
        let (status, chained) = get_sub(state, &token, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(chained, expected.to_string().as_bytes());
    }
}

#[tokio::test]
async fn compatible_udp_detour_keeps_legacy_response_byte_equal() {
    for target_pid in ["hysteria2", "tuic-v5"] {
        let dir = TempDir::new().unwrap();
        let (state, token, _writer) = seed(&dir, true).await;
        set_protocols(&state, "s5", &[target_pid]).await;
        let (_, body) = get_sub(state.clone(), &token, None).await;
        let (status, stock) =
            get_sub_at(state, &format!("/sub/{token}?format=sing-box"), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, stock);
        let (tag, target) = if target_pid == "hysteria2" {
            (
                "S5 HY2 ~alice",
                serde_json::json!({
                    "type": "hysteria2", "tag": "S5 HY2 ~alice",
                    "server": "198.51.100.50", "server_port": 8444, "password": "pw-alice",
                    "tls": {"enabled": true, "insecure": true, "alpn": ["h3"]},
                    "detour": "Iceland VLESS ~alice"
                }),
            )
        } else {
            (
                "S5 TUIC ~alice",
                serde_json::json!({
                    "type": "tuic", "tag": "S5 TUIC ~alice",
                    "server": "198.51.100.50", "server_port": 8443, "password": "pw-alice",
                    "uuid": "11111111-2222-3333-4444-555555555555",
                    "congestion_control": "bbr", "udp_relay_mode": "native",
                    "tls": {"enabled": true, "insecure": true, "alpn": ["h3"]},
                    "detour": "Iceland VLESS ~alice"
                }),
            )
        };
        let expected = serde_json::json!({
            "log": {"level": "info", "timestamp": true},
            "outbounds": [
                {"type": "selector", "tag": "proxy", "outbounds": ["Iceland VLESS ~alice", tag],
                 "default": "Iceland VLESS ~alice"},
                {
                    "type": "vless", "tag": "Iceland VLESS ~alice",
                    "server": "198.51.100.10", "server_port": 443,
                    "uuid": "11111111-2222-3333-4444-555555555555",
                    "flow": "xtls-rprx-vision", "packet_encoding": "xudp",
                    "tls": {
                        "enabled": true, "server_name": "yahoo.com",
                        "utls": {"enabled": true, "fingerprint": "randomized"},
                        "reality": {"enabled": true, "public_key": "PUB_is", "short_id": "12345678"}
                    }
                }, target,
                {"type": "direct", "tag": "direct"}, {"type": "block", "tag": "block"}
            ],
            "route": {"rules": [{"protocol": "dns", "outbound": "direct"}],
                      "final": "proxy", "auto_detect_interface": true}
        });
        assert_eq!(body, expected.to_string().as_bytes());
    }
}

#[tokio::test]
async fn mihomo_udp_detour_ignores_tcp_only_entry_byte_equal() {
    let dir = TempDir::new().unwrap();
    let (state, token, _writer) = seed(&dir, true).await;
    set_protocols(&state, "s5", &["hysteria2"]).await;
    let uri = format!("/sub/{token}?format=mihomo");
    let (status, original) = get_sub_at(state.clone(), &uri, None).await;
    assert_eq!(status, StatusCode::OK);
    let config: Value = serde_saphyr::from_str(std::str::from_utf8(&original).unwrap()).unwrap();
    let target = config["proxies"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["server"] == "198.51.100.50")
        .unwrap();
    assert_eq!(target["dialer-proxy"], "Iceland VLESS ~alice");
    set_protocols(&state, "is", &["vless+xhttp", "vless+reality"]).await;
    let (_, actual) = get_sub_at(state.clone(), &uri, None).await;
    assert_eq!(actual, original);
    set_protocols(&state, "is", &["vless+xhttp"]).await;
    let (_, body) = get_sub_at(state, &uri, None).await;
    let config: Value = serde_saphyr::from_str(std::str::from_utf8(&body).unwrap()).unwrap();
    assert!(config["proxies"].as_array().unwrap().is_empty());
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
    assert_eq!(
        config["route"]["final"], "block",
        "with no proxy outbound left, route.final must not name a missing `proxy` tag"
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

#[tokio::test]
async fn duplicate_display_names_keep_tags_and_references_unique_byte_equal() {
    for format in ["", "?format=sing-box", "?format=mihomo"] {
        let dir = TempDir::new().unwrap();
        let (state, token, _writer) = seed(&dir, true).await;
        let mut unique = state
            .inv
            .get_server(&ServerId("is".into()))
            .await
            .unwrap()
            .unwrap();
        unique.id = ServerId("zz".into());
        unique.address = "198.51.100.99".into();
        state.inv.add_server(&unique).await.unwrap();
        state
            .inv
            .set_server_secret(&unique.id, "vless.public_key", "PUB_zz")
            .await
            .unwrap();
        state
            .inv
            .set_server_secret(&unique.id, "vless.short_id", "12345678")
            .await
            .unwrap();
        state
            .inv
            .grant(&UserId("alice".into()), &unique.id)
            .await
            .unwrap();
        let uri = format!("/sub/{token}{format}");
        let (status, original) = get_sub_at(state.clone(), &uri, None).await;
        assert_eq!(status, StatusCode::OK);
        let original = String::from_utf8(original).unwrap();
        assert!(original.contains("Iceland VLESS ~alice"));
        assert!(original.contains("S5 VLESS ~alice"));
        assert!(original.contains("ZZ VLESS ~alice"));
        for id in ["is", "s5"] {
            state
                .inv
                .set_server_display_name(&ServerId(id.into()), Some("Shared"))
                .await
                .unwrap();
        }
        let (status, actual) = get_sub_at(state.clone(), &uri, None).await;
        assert_eq!(status, StatusCode::OK);
        let expected = original
            .replace("Iceland VLESS ~alice", "Shared VLESS ~alice (is)")
            .replace("S5 VLESS ~alice", "Shared VLESS ~alice (s5)");
        // Full response equality also pins the selector/group, detour, and ZZ bytes.
        assert_eq!(actual, expected.as_bytes(), "{format}");
        let value: Value = if format == "?format=mihomo" {
            serde_saphyr::from_str(std::str::from_utf8(&actual).unwrap()).unwrap()
        } else {
            serde_json::from_slice(&actual).unwrap()
        };
        if format == "?format=mihomo" {
            let proxies = value["proxies"].as_array().unwrap();
            assert_eq!(proxies.len(), 3);
            assert_eq!(proxies[0]["name"], "Shared VLESS ~alice (is)");
            assert_eq!(proxies[1]["name"], "Shared VLESS ~alice (s5)");
            assert_eq!(proxies[1]["dialer-proxy"], proxies[0]["name"]);
            assert_eq!(
                value["proxy-groups"][0]["proxies"]
                    .as_array()
                    .unwrap()
                    .len(),
                3
            );
        } else {
            let outbounds = value["outbounds"].as_array().unwrap();
            assert_eq!(outbounds[1]["tag"], "Shared VLESS ~alice (is)");
            assert_eq!(outbounds[2]["tag"], "Shared VLESS ~alice (s5)");
            assert_eq!(outbounds[2]["detour"], outbounds[1]["tag"]);
            assert_eq!(outbounds[0]["outbounds"].as_array().unwrap().len(), 3);
        }
        for _ in 0..2 {
            let (status, repeated) = get_sub_at(state.clone(), &uri, None).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(actual, repeated, "deterministic bytes: {format}");
        }
        for id in ["is", "s5"] {
            state
                .inv
                .set_server_display_name(&ServerId(id.into()), None)
                .await
                .unwrap();
        }
        let (status, restored) = get_sub_at(state, &uri, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(restored, original.as_bytes(), "unique names: {format}");
    }
}

#[tokio::test]
async fn unique_singbox_tags_keep_legacy_response_byte_equal() {
    let dir = TempDir::new().unwrap();
    let (state, token, _writer) = seed(&dir, true).await;
    let (status, actual) = get_sub(state.clone(), &token, None).await;
    assert_eq!(status, StatusCode::OK);
    let expected = serde_json::json!({
        "log": {"level": "info", "timestamp": true},
        "outbounds": [
            {
                "type": "selector", "tag": "proxy",
                "outbounds": ["Iceland VLESS ~alice", "S5 VLESS ~alice"],
                "default": "Iceland VLESS ~alice"
            },
            {
                "type": "vless", "tag": "Iceland VLESS ~alice",
                "server": "198.51.100.10", "server_port": 443,
                "uuid": "11111111-2222-3333-4444-555555555555",
                "flow": "xtls-rprx-vision", "packet_encoding": "xudp",
                "tls": {
                    "enabled": true, "server_name": "yahoo.com",
                    "utls": {"enabled": true, "fingerprint": "randomized"},
                    "reality": {"enabled": true, "public_key": "PUB_is", "short_id": "12345678"}
                }
            },
            {
                "type": "vless", "tag": "S5 VLESS ~alice",
                "server": "198.51.100.50", "server_port": 443,
                "uuid": "11111111-2222-3333-4444-555555555555",
                "flow": "xtls-rprx-vision", "packet_encoding": "xudp",
                "detour": "Iceland VLESS ~alice",
                "tls": {
                    "enabled": true, "server_name": "yahoo.com",
                    "utls": {"enabled": true, "fingerprint": "randomized"},
                    "reality": {"enabled": true, "public_key": "PUB_s5", "short_id": "12345678"}
                }
            },
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"}
        ],
        "route": {
            "rules": [{"protocol": "dns", "outbound": "direct"}],
            "final": "proxy", "auto_detect_interface": true
        }
    });
    assert_eq!(actual, expected.to_string().as_bytes());
    let (status, stock) = get_sub_at(state, &format!("/sub/{token}?format=sing-box"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(stock, expected.to_string().as_bytes());
}

#[tokio::test]
async fn omitted_target_name_collision_keeps_direct_subscription_byte_equal() {
    for format in ["?format=sing-box", "?format=mihomo"] {
        let dir = TempDir::new().unwrap();
        let (state, token, _writer) = seed(&dir, true).await;
        let mut missing_entry = state
            .inv
            .get_server(&ServerId("is".into()))
            .await
            .unwrap()
            .unwrap();
        missing_entry.id = ServerId("ungranted-entry".into());
        state.inv.add_server(&missing_entry).await.unwrap();
        state
            .inv
            .set_client_detour_via_as("test", &ServerId("s5".into()), Some(&missing_entry.id))
            .await
            .unwrap();
        let uri = format!("/sub/{token}{format}");
        let (status, before) = get_sub_at(state.clone(), &uri, None).await;
        assert_eq!(status, StatusCode::OK);
        state
            .inv
            .set_server_display_name(&ServerId("s5".into()), Some("Iceland"))
            .await
            .unwrap();
        let (status, after) = get_sub_at(state, &uri, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            after, before,
            "omitted target must not rename the entry: {format}"
        );
    }
}
