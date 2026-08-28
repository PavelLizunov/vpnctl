use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::Value;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{KernelId, ProtocolId, Registry, Server, ServerId, User, UserId};
use vpnctl_inventory::SqliteInventory;
use vpnctl_kernels::SingBox;
use vpnctl_protocols::{Hysteria2, TuicV5, VlessReality, VlessXhttp, WireGuard};
use vpnctld::router;

async fn setup_mihomo_env(dir: &TempDir) -> (vpnctld::AppState, String, SqliteInventory) {
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    let mut reg = Registry::new();
    reg.register_kernel(Box::new(SingBox::new())).unwrap();
    reg.register_protocol(Box::new(VlessReality::new()))
        .unwrap();
    reg.register_protocol(Box::new(VlessXhttp::new())).unwrap();
    reg.register_protocol(Box::new(Hysteria2::new())).unwrap();
    reg.register_protocol(Box::new(TuicV5::new())).unwrap();
    reg.register_protocol(Box::new(WireGuard::new())).unwrap();

    let server_direct = Server {
        id: ServerId("srv-direct".into()),
        address: "198.51.100.10".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![
            ProtocolId("vless+reality".into()),
            ProtocolId("vless+xhttp".into()),
            ProtocolId("hysteria2".into()),
            ProtocolId("tuic-v5".into()),
            ProtocolId("wireguard".into()),
        ],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    };
    inv.add_server(&server_direct).await.unwrap();
    inv.set_server_secret(&server_direct.id, "vless.public_key", "PUB_DIRECT")
        .await
        .unwrap();
    inv.set_server_secret(&server_direct.id, "vless.short_id", "12345678")
        .await
        .unwrap();
    inv.set_server_secret(&server_direct.id, "vlessxhttp.path", "secretpath")
        .await
        .unwrap();
    inv.set_server_secret(&server_direct.id, "hysteria2.obfs.password", "obfs-pass")
        .await
        .unwrap();

    let server_entry = Server {
        id: ServerId("srv-entry".into()),
        address: "198.51.100.20".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        // Unsupported TUIC sorts before VLESS deliberately: Mihomo must
        // still choose this server's usable VLESS outbound as chain entry.
        enabled_protocols: vec![
            ProtocolId("tuic-v5".into()),
            ProtocolId("vless+reality".into()),
        ],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    };
    inv.add_server(&server_entry).await.unwrap();
    inv.set_server_secret(&server_entry.id, "vless.public_key", "PUB_ENTRY")
        .await
        .unwrap();
    inv.set_server_secret(&server_entry.id, "vless.short_id", "87654321")
        .await
        .unwrap();

    let server_target = Server {
        id: ServerId("srv-target".into()),
        address: "198.51.100.30".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("vless+reality".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    };
    inv.add_server(&server_target).await.unwrap();
    inv.set_server_secret(&server_target.id, "vless.public_key", "PUB_TARGET")
        .await
        .unwrap();
    inv.set_server_secret(&server_target.id, "vless.short_id", "11223344")
        .await
        .unwrap();

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
    inv.grant(&user.id, &server_direct.id).await.unwrap();
    inv.grant(&user.id, &server_entry.id).await.unwrap();
    inv.grant(&user.id, &server_target.id).await.unwrap();

    inv.set_client_detour_via_as("test", &server_target.id, Some(&server_entry.id))
        .await
        .unwrap();

    let token = inv
        .get_user(&user.id)
        .await
        .unwrap()
        .unwrap()
        .sub_token
        .unwrap();

    let inv_clone = inv.clone();
    let (state, writer) = vpnctld::make_app_state_for_tests(inv, Arc::new(reg));
    writer.abort();
    (state, token, inv_clone)
}

async fn request_sub(
    state: vpnctld::AppState,
    uri: &str,
    user_agent: Option<&str>,
) -> (StatusCode, header::HeaderMap, Vec<u8>) {
    let mut req = Request::builder().uri(uri);
    if let Some(ua) = user_agent {
        req = req.header(header::USER_AGENT, ua);
    }
    let resp = router(state)
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, headers, body.to_vec())
}

#[tokio::test]
async fn happy_vless_hysteria2_and_chain() {
    let dir = TempDir::new().unwrap();
    let (state, token, _) = setup_mihomo_env(&dir).await;

    let uri = format!("/sub/{token}?format=mihomo");
    let (status, headers, body) = request_sub(state, &uri, None).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers.get(header::CONTENT_TYPE).unwrap(), "text/yaml");

    let yaml_str = std::str::from_utf8(&body).expect("UTF-8 body");
    assert!(
        !yaml_str.trim_start().starts_with('{'),
        "Mihomo endpoint must return block YAML, not a JSON wrapper"
    );
    let val: Value = serde_saphyr::from_str(yaml_str).expect("parse Mihomo YAML");

    let proxies = val["proxies"].as_array().expect("proxies array");
    assert!(!proxies.is_empty(), "proxies must not be empty");

    // VLESS proxy mapping assertion
    let vless = proxies
        .iter()
        .find(|p| p["type"] == "vless" && p["server"] == "198.51.100.10")
        .expect("VLESS proxy on 198.51.100.10");

    assert_eq!(vless["type"], "vless");
    assert_eq!(vless["server"], "198.51.100.10");
    assert!(vless["port"].is_number());
    assert_eq!(vless["uuid"], "11111111-2222-3333-4444-555555555555");
    assert_eq!(vless["flow"], "xtls-rprx-vision");
    assert_eq!(vless["network"], "tcp");
    assert_eq!(vless["udp"], true);
    assert_eq!(vless["tls"], true);
    assert!(vless["servername"].is_string());
    assert_eq!(vless["client-fingerprint"], "random");
    assert!(vless["reality-opts"].is_object());
    assert!(
        vless["reality-opts"]["public-key"].is_string()
            || vless["reality-opts"]["public_key"].is_string()
    );
    assert_eq!(vless["packet-encoding"], "xudp");

    // Hysteria2 proxy mapping assertion
    let hy2 = proxies
        .iter()
        .find(|p| p["type"] == "hysteria2" && p["server"] == "198.51.100.10")
        .expect("Hysteria2 proxy on 198.51.100.10");

    assert_eq!(hy2["type"], "hysteria2");
    assert_eq!(hy2["server"], "198.51.100.10");
    assert!(hy2["port"].is_number());
    assert_eq!(hy2["password"], "pw-alice");
    assert!(hy2["alpn"].is_array());
    assert_eq!(hy2["skip-cert-verify"], true);

    // Chained VLESS target proxy assertion (srv-target chained via srv-entry)
    let entry_proxy = proxies
        .iter()
        .find(|p| p["server"] == "198.51.100.20")
        .expect("entry proxy on 198.51.100.20");

    let chained_target = proxies
        .iter()
        .find(|p| p["server"] == "198.51.100.30")
        .expect("chained target proxy on 198.51.100.30");

    assert_eq!(
        chained_target["dialer-proxy"], entry_proxy["name"],
        "chained target must specify dialer-proxy naming direct upstream"
    );

    // proxy-groups assertion
    let groups = val["proxy-groups"].as_array().expect("proxy-groups array");
    let vpn_group = groups
        .iter()
        .find(|g| g["name"] == "VPN")
        .expect("VPN proxy group");
    assert_eq!(vpn_group["type"], "select");

    let group_proxies = vpn_group["proxies"].as_array().expect("VPN group proxies");
    assert!(
        group_proxies.contains(&entry_proxy["name"]),
        "VPN group must contain entry proxy name"
    );

    // rules assertion
    let rules = val["rules"].as_array().expect("rules array");
    assert!(
        rules.iter().any(|r| r == "MATCH,VPN"),
        "rules must contain MATCH,VPN"
    );
}

#[tokio::test]
async fn public_alias_content_type_and_ua_override() {
    let dir1 = TempDir::new().unwrap();
    let (state1, token1, _) = setup_mihomo_env(&dir1).await;
    let dir2 = TempDir::new().unwrap();
    let (state2, token2, _) = setup_mihomo_env(&dir2).await;
    let dir3 = TempDir::new().unwrap();
    let (state3, token3, _) = setup_mihomo_env(&dir3).await;
    let dir4 = TempDir::new().unwrap();
    let (state4, token4, _) = setup_mihomo_env(&dir4).await;

    let uri1 = format!("/sub/{token1}?format=mihomo");
    let uri2 = format!("/api/v1/sub/{token2}?format=mihomo");
    let uri3_no_query = format!("/api/v1/sub/{token3}");
    let uri4_singbox = format!("/api/v1/sub/{token4}?format=sing-box");

    let (status1, headers1, body1) = request_sub(state1, &uri1, None).await;
    let (status2, headers2, body2) = request_sub(state2, &uri2, None).await;
    let (status3, headers3, body3) = request_sub(state3, &uri3_no_query, None).await;
    let (status4, headers4, _) = request_sub(state4, &uri4_singbox, None).await;

    assert_eq!(status1, StatusCode::OK);
    assert_eq!(status2, StatusCode::OK);
    assert_eq!(status3, StatusCode::OK);
    assert_eq!(status4, StatusCode::OK);
    assert_eq!(headers1.get(header::CONTENT_TYPE).unwrap(), "text/yaml");
    assert_eq!(headers2.get(header::CONTENT_TYPE).unwrap(), "text/yaml");
    assert_eq!(headers3.get(header::CONTENT_TYPE).unwrap(), "text/yaml");
    assert_eq!(
        headers4.get(header::CONTENT_TYPE).unwrap(),
        "application/json",
        "explicit sing-box selector must override the public Mihomo default"
    );
    assert_eq!(
        body1, body2,
        "public alias /api/v1/sub and /sub must return identical body"
    );
    assert_eq!(
        body2, body3,
        "public alias /api/v1/sub without query must return byte-identical Mihomo YAML body as explicit ?format=mihomo"
    );

    let yaml_str3 = std::str::from_utf8(&body3).expect("UTF-8 body");
    let _: Value = serde_saphyr::from_str(yaml_str3)
        .expect("public alias /api/v1/sub without query must parse as Mihomo YAML");

    assert_eq!(headers1.get("x-content-type-options").unwrap(), "nosniff");
    assert_eq!(headers1.get("x-frame-options").unwrap(), "DENY");

    for ua in [
        "sing-box/1.13.0",
        "HiddifyNext/1.0.0",
        "v2rayN/6.62",
        "ClashMeta/1.18.0",
        "Mihomo/1.18.0",
        "mihoro",
    ] {
        let dir_ua = TempDir::new().unwrap();
        let (state_ua, token_ua, _) = setup_mihomo_env(&dir_ua).await;
        let uri_ua = format!("/sub/{token_ua}?format=mihomo");
        let (status, headers, body) = request_sub(state_ua, &uri_ua, Some(ua)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers.get(header::CONTENT_TYPE).unwrap(),
            "text/yaml",
            "explicit format=mihomo must override UA '{ua}' with text/yaml"
        );
        let yaml_str = std::str::from_utf8(&body).unwrap();
        let _: Value = serde_saphyr::from_str(yaml_str)
            .expect("explicit format=mihomo body must parse as Mihomo YAML regardless of UA");

        // Also assert that Mihomo-like UA does not matter on the public route /api/v1/sub/{token} without query
        let dir_pub_ua = TempDir::new().unwrap();
        let (state_pub_ua, token_pub_ua, _) = setup_mihomo_env(&dir_pub_ua).await;
        let uri_pub_no_query = format!("/api/v1/sub/{token_pub_ua}");
        let (status_pub, headers_pub, body_pub) =
            request_sub(state_pub_ua, &uri_pub_no_query, Some(ua)).await;
        assert_eq!(status_pub, StatusCode::OK);
        assert_eq!(
            headers_pub.get(header::CONTENT_TYPE).unwrap(),
            "text/yaml",
            "public route /api/v1/sub without query must return text/yaml regardless of UA '{ua}'"
        );
        assert_eq!(
            body_pub, body1,
            "public route /api/v1/sub without query with UA '{ua}' must return byte-identical Mihomo YAML body"
        );
    }

    for ua in ["Mihomo/1.18.0", "ClashMeta/1.18.0"] {
        let dir_ua = TempDir::new().unwrap();
        let (state_ua, token_ua, _) = setup_mihomo_env(&dir_ua).await;
        let uri_no_fmt = format!("/sub/{token_ua}");
        let (status, headers, _) = request_sub(state_ua, &uri_no_fmt, Some(ua)).await;
        assert_eq!(status, StatusCode::OK);
        assert_ne!(
            headers.get(header::CONTENT_TYPE).unwrap(),
            "text/yaml",
            "Mihomo-like UA without the explicit selector must keep legacy /sub behavior"
        );
    }
}

#[tokio::test]
async fn chain_same_server_address_entry_and_target() {
    let dir = TempDir::new().unwrap();
    let (state, token, inv) = setup_mihomo_env(&dir).await;
    let shared_address = "198.51.100.20";
    inv.update_server_address(&ServerId("srv-target".into()), shared_address, 22, "root")
        .await
        .unwrap();

    let uri = format!("/api/v1/sub/{token}");
    let (status, headers, body) = request_sub(state, &uri, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers.get(header::CONTENT_TYPE).unwrap(), "text/yaml");

    let yaml = std::str::from_utf8(&body).expect("UTF-8 body");
    let val: Value = serde_saphyr::from_str(yaml).expect("parse Mihomo YAML");
    let proxies = val["proxies"].as_array().expect("proxies array");
    assert_eq!(
        proxies
            .iter()
            .filter(|proxy| proxy["server"] == shared_address)
            .count(),
        2,
        "same-address entry and target must both remain"
    );

    let entry = proxies
        .iter()
        .find(|proxy| proxy["reality-opts"]["public-key"] == "PUB_ENTRY")
        .expect("entry proxy");
    let target = proxies
        .iter()
        .find(|proxy| proxy["reality-opts"]["public-key"] == "PUB_TARGET")
        .expect("target proxy");
    assert_eq!(target["dialer-proxy"], entry["name"]);
}

#[tokio::test]
async fn chain_missing_self_and_nested_fail_closed() {
    // 1. Missing upstream
    {
        let dir = TempDir::new().unwrap();
        let inv = SqliteInventory::open(&dir.path().join("inv.db"))
            .await
            .unwrap();
        let mut reg = Registry::new();
        reg.register_kernel(Box::new(SingBox::new())).unwrap();
        reg.register_protocol(Box::new(VlessReality::new()))
            .unwrap();

        let srv_entry = Server {
            id: ServerId("srv-entry".into()),
            address: "198.51.100.20".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![ProtocolId("vless+reality".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        };
        let srv_target = Server {
            id: ServerId("srv-target".into()),
            address: "198.51.100.30".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![ProtocolId("vless+reality".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        };
        inv.add_server(&srv_entry).await.unwrap();
        inv.add_server(&srv_target).await.unwrap();
        inv.set_server_secret(&srv_entry.id, "vless.public_key", "PUB_ENTRY")
            .await
            .unwrap();
        inv.set_server_secret(&srv_entry.id, "vless.short_id", "12345678")
            .await
            .unwrap();
        inv.set_server_secret(&srv_target.id, "vless.public_key", "PUB_TARGET")
            .await
            .unwrap();
        inv.set_server_secret(&srv_target.id, "vless.short_id", "12345678")
            .await
            .unwrap();

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
        inv.grant(&user.id, &srv_target.id).await.unwrap();
        inv.set_client_detour_via_as("test", &srv_target.id, Some(&srv_entry.id))
            .await
            .unwrap();

        let token = inv
            .get_user(&user.id)
            .await
            .unwrap()
            .unwrap()
            .sub_token
            .unwrap();
        let (state, _writer) = vpnctld::make_app_state_for_tests(inv, Arc::new(reg));

        let uri = format!("/sub/{token}?format=mihomo");
        let (status, _, body) = request_sub(state, &uri, None).await;
        assert_eq!(status, StatusCode::OK);

        let yaml_str = std::str::from_utf8(&body).unwrap();
        let val: Value = serde_saphyr::from_str(yaml_str).unwrap();
        let proxies = val["proxies"].as_array().unwrap();

        assert!(
            proxies.iter().all(|p| p["server"] != "198.51.100.30"),
            "target proxy on 198.51.100.30 must be omitted when upstream is missing/ungranted"
        );
    }

    // 2. Self upstream
    {
        let dir = TempDir::new().unwrap();
        let inv = SqliteInventory::open(&dir.path().join("inv.db"))
            .await
            .unwrap();
        let mut reg = Registry::new();
        reg.register_kernel(Box::new(SingBox::new())).unwrap();
        reg.register_protocol(Box::new(VlessReality::new()))
            .unwrap();

        let srv = Server {
            id: ServerId("srv-self".into()),
            address: "198.51.100.40".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![ProtocolId("vless+reality".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        };
        inv.add_server(&srv).await.unwrap();
        inv.set_server_secret(&srv.id, "vless.public_key", "PUB_SELF")
            .await
            .unwrap();
        inv.set_server_secret(&srv.id, "vless.short_id", "12345678")
            .await
            .unwrap();

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
        inv.grant(&user.id, &srv.id).await.unwrap();
        assert!(
            inv.set_client_detour_via_as("test", &srv.id, Some(&srv.id))
                .await
                .is_err(),
            "inventory must refuse self-referential client detour"
        );
    }

    // 3. Nested upstream
    {
        let dir = TempDir::new().unwrap();
        let inv = SqliteInventory::open(&dir.path().join("inv.db"))
            .await
            .unwrap();
        let mut reg = Registry::new();
        reg.register_kernel(Box::new(SingBox::new())).unwrap();
        reg.register_protocol(Box::new(VlessReality::new()))
            .unwrap();

        let srv_a = Server {
            id: ServerId("srv-a".into()),
            address: "198.51.100.61".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![ProtocolId("vless+reality".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        };
        let srv_b = Server {
            id: ServerId("srv-b".into()),
            address: "198.51.100.62".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![ProtocolId("vless+reality".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        };
        let srv_c = Server {
            id: ServerId("srv-c".into()),
            address: "198.51.100.63".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![ProtocolId("vless+reality".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        };
        inv.add_server(&srv_a).await.unwrap();
        inv.add_server(&srv_b).await.unwrap();
        inv.add_server(&srv_c).await.unwrap();

        for srv in [&srv_a, &srv_b, &srv_c] {
            inv.set_server_secret(&srv.id, "vless.public_key", "PUB")
                .await
                .unwrap();
            inv.set_server_secret(&srv.id, "vless.short_id", "12345678")
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
        inv.grant(&user.id, &srv_a.id).await.unwrap();
        inv.grant(&user.id, &srv_b.id).await.unwrap();
        inv.grant(&user.id, &srv_c.id).await.unwrap();

        inv.set_client_detour_via_as("test", &srv_b.id, Some(&srv_a.id))
            .await
            .unwrap();
        assert!(
            inv.set_client_detour_via_as("test", &srv_c.id, Some(&srv_b.id))
                .await
                .is_err(),
            "inventory must refuse nested client detours"
        );

        let token = inv
            .get_user(&user.id)
            .await
            .unwrap()
            .unwrap()
            .sub_token
            .unwrap();
        let (state, _writer) = vpnctld::make_app_state_for_tests(inv, Arc::new(reg));

        let uri = format!("/sub/{token}?format=mihomo");
        let (status, _, body) = request_sub(state, &uri, None).await;
        assert_eq!(status, StatusCode::OK);

        let yaml_str = std::str::from_utf8(&body).unwrap();
        let val: Value = serde_saphyr::from_str(yaml_str).unwrap();
        let proxies = val["proxies"].as_array().unwrap();

        let srv_c_proxy = proxies
            .iter()
            .find(|p| p["server"] == "198.51.100.63")
            .expect("srv-c proxy");
        assert!(
            srv_c_proxy.get("dialer-proxy").is_none(),
            "srv-c must not have a dialer-proxy because nested detour was refused"
        );
    }
}

#[tokio::test]
async fn visibility_and_unsupported_filtering() {
    let dir = TempDir::new().unwrap();
    let (state, token, inv) = setup_mihomo_env(&dir).await;

    let uri = format!("/sub/{token}?format=mihomo");
    let (status, _, body) = request_sub(state.clone(), &uri, None).await;
    assert_eq!(status, StatusCode::OK);

    let yaml_str = std::str::from_utf8(&body).unwrap();
    let val: Value = serde_saphyr::from_str(yaml_str).unwrap();
    let proxies = val["proxies"].as_array().unwrap();

    for p in proxies {
        let ty = p["type"].as_str().unwrap_or("");
        assert_ne!(
            ty, "tuic",
            "tuic-v5 protocol must be absent in Mihomo subscription"
        );
        assert_ne!(
            ty, "wireguard",
            "wireguard protocol must be absent in Mihomo subscription"
        );
    }

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    inv.set_server_protocol_hidden(
        &ServerId("srv-direct".into()),
        &ProtocolId("vless+reality".into()),
        true,
    )
    .await
    .unwrap();

    let (status, _, body) = request_sub(state.clone(), &uri, None).await;
    assert_eq!(status, StatusCode::OK);
    let yaml_str = std::str::from_utf8(&body).unwrap();
    let val: Value = serde_saphyr::from_str(yaml_str).unwrap();
    let proxies = val["proxies"].as_array().unwrap();

    assert!(
        !proxies
            .iter()
            .any(|p| p["type"] == "vless" && p["server"] == "198.51.100.10"),
        "hidden VLESS protocol must be absent from proxies"
    );

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    inv.set_grant_protocol_override(
        &UserId("alice".into()),
        &ServerId("srv-direct".into()),
        &ProtocolId("hysteria2".into()),
        true,
    )
    .await
    .unwrap();

    let (status, _, body) = request_sub(state.clone(), &uri, None).await;
    assert_eq!(status, StatusCode::OK);
    let yaml_str = std::str::from_utf8(&body).unwrap();
    let val: Value = serde_saphyr::from_str(yaml_str).unwrap();
    let proxies = val["proxies"].as_array().unwrap();

    assert!(
        !proxies
            .iter()
            .any(|p| p["type"] == "hysteria2" && p["server"] == "198.51.100.10"),
        "denied Hysteria2 protocol must be absent from proxies"
    );

    inv.set_server_auto_suppress(&ServerId("srv-entry".into()), true)
        .await
        .unwrap();
    inv.set_server_suppressed(&ServerId("srv-entry".into()), true)
        .await
        .unwrap();
    let (status, _, body) = request_sub(state, &format!("/sub/{token}?format=mihomo"), None).await;
    assert_eq!(status, StatusCode::OK);
    let yaml = std::str::from_utf8(&body).unwrap();
    let val: Value = serde_saphyr::from_str(yaml).unwrap();
    let proxies = val["proxies"].as_array().unwrap();
    assert!(
        proxies
            .iter()
            .all(|p| { p["server"] != "198.51.100.20" && p["server"] != "198.51.100.30" }),
        "suppressed entry and its chained target must both be absent"
    );
}

#[tokio::test]
async fn disabled_no_grant_user_and_unknown_token() {
    // 1. Unknown token keeps the shared 404 response on the public route.
    {
        let dir = TempDir::new().unwrap();
        let (state, _, _) = setup_mihomo_env(&dir).await;
        let (status, headers, body) = request_sub(state, "/api/v1/sub/unknown-token", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body, b"unknown token\n");
        assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
        assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
    }

    // 2. Invalid selectors keep the shared byte-exact 400 response.
    {
        let dir = TempDir::new().unwrap();
        let (state, token, _) = setup_mihomo_env(&dir).await;
        let uri = format!("/api/v1/sub/{token}?format=bogus");
        let (status, _, body) = request_sub(state, &uri, None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, b"invalid format selector\n");
    }

    // 3. Disabled user gets valid YAML with empty proxies and VPN group selecting DIRECT
    {
        let dir = TempDir::new().unwrap();
        let inv = SqliteInventory::open(&dir.path().join("inv.db"))
            .await
            .unwrap();
        let mut reg = Registry::new();
        reg.register_kernel(Box::new(SingBox::new())).unwrap();
        reg.register_protocol(Box::new(VlessReality::new()))
            .unwrap();

        let srv = Server {
            id: ServerId("srv1".into()),
            address: "198.51.100.1".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![ProtocolId("vless+reality".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        };
        inv.add_server(&srv).await.unwrap();

        let user = User {
            id: UserId("disabled_user".into()),
            uuid: "22222222-2222-2222-2222-222222222222".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: true,
        };
        inv.add_user(&user).await.unwrap();
        inv.grant(&user.id, &srv.id).await.unwrap();

        let token = inv
            .get_user(&user.id)
            .await
            .unwrap()
            .unwrap()
            .sub_token
            .unwrap();
        let (state, _writer) = vpnctld::make_app_state_for_tests(inv, Arc::new(reg));

        let uri = format!("/api/v1/sub/{token}");
        let (status, headers, body) = request_sub(state, &uri, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers.get(header::CONTENT_TYPE).unwrap(), "text/yaml");

        let yaml_str = std::str::from_utf8(&body).unwrap();
        let val: Value = serde_saphyr::from_str(yaml_str).unwrap();

        let proxies = val["proxies"].as_array().expect("proxies array");
        assert!(
            proxies.is_empty(),
            "disabled user must have empty proxies array"
        );

        let groups = val["proxy-groups"].as_array().expect("proxy-groups array");
        let vpn_group = groups
            .iter()
            .find(|g| g["name"] == "VPN")
            .expect("VPN group");
        assert_eq!(vpn_group["type"], "select");
        let g_proxies = vpn_group["proxies"].as_array().expect("VPN group proxies");
        assert_eq!(g_proxies, &vec![Value::String("DIRECT".into())]);

        let rules = val["rules"].as_array().expect("rules array");
        assert!(rules.iter().any(|r| r == "MATCH,VPN"));
    }

    // 4. User with no grants gets valid YAML with empty proxies and VPN group selecting DIRECT
    {
        let dir = TempDir::new().unwrap();
        let inv = SqliteInventory::open(&dir.path().join("inv.db"))
            .await
            .unwrap();
        let mut reg = Registry::new();
        reg.register_kernel(Box::new(SingBox::new())).unwrap();
        reg.register_protocol(Box::new(VlessReality::new()))
            .unwrap();

        let user = User {
            id: UserId("no_grants".into()),
            uuid: "33333333-3333-3333-3333-333333333333".into(),
            tuic_password: None,
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

        let uri = format!("/api/v1/sub/{token}");
        let (status, headers, body) = request_sub(state, &uri, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers.get(header::CONTENT_TYPE).unwrap(), "text/yaml");

        let yaml_str = std::str::from_utf8(&body).unwrap();
        let val: Value = serde_saphyr::from_str(yaml_str).unwrap();

        let proxies = val["proxies"].as_array().expect("proxies array");
        assert!(
            proxies.is_empty(),
            "no-grant user must have empty proxies array"
        );

        let groups = val["proxy-groups"].as_array().expect("proxy-groups array");
        let vpn_group = groups
            .iter()
            .find(|g| g["name"] == "VPN")
            .expect("VPN group");
        assert_eq!(vpn_group["type"], "select");
        let g_proxies = vpn_group["proxies"].as_array().expect("VPN group proxies");
        assert_eq!(g_proxies, &vec![Value::String("DIRECT".into())]);

        let rules = val["rules"].as_array().expect("rules array");
        assert!(rules.iter().any(|r| r == "MATCH,VPN"));
    }
}

#[tokio::test]
async fn legacy_endpoints_stay_unchanged() {
    let dir = TempDir::new().unwrap();
    let (state, token, _) = setup_mihomo_env(&dir).await;

    let uri_no_query = format!("/sub/{token}");
    let (status1, headers1, body1) = request_sub(state.clone(), &uri_no_query, None).await;
    assert_eq!(status1, StatusCode::OK);
    assert_ne!(
        headers1
            .get(header::CONTENT_TYPE)
            .map(|v| v.to_str().unwrap()),
        Some("text/yaml"),
        "legacy /sub response must not be text/yaml"
    );

    let uri_singbox = format!("/sub/{token}?format=sing-box");
    let (status2, headers2, body2) = request_sub(state, &uri_singbox, None).await;
    assert_eq!(status2, StatusCode::OK);
    assert_eq!(
        headers2.get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );

    let json_val: Value = serde_json::from_slice(&body2).expect("parse JSON");
    assert!(json_val["outbounds"].is_array());

    assert_ne!(body1, body2);
}
