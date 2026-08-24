//! Shared test fixtures and helpers for vpn_router_endpoint integration tests.

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
use vpnctl_kernels::{AmneziaWg, Caddy, SingBox, Xray};
use vpnctl_protocols::{DnsTunnel, Hysteria2, Naive, VlessReality, VlessXhttp, WireGuard};
use vpnctld::AppState;

pub(crate) const TEST_DEVICE_ID: &str = "a92b915032b48a2ed45ef72f4171e5f4";
pub(crate) const ALT_DEVICE_ID: &str = "deadbeefdeadbeefdeadbeefdeadbeef";
pub(crate) const NAIVE_DEVICE_ID: &str = "b1b2b3b4b5b6b7b8b9b0b1b2b3b4b5b6";
pub(crate) const HY2_DEVICE_ID: &str = "c1c2c3c4c5c6c7c8c9c0c1c2c3c4c5c6";
pub(crate) const PAIR_DEVICE_ID: &str = "d1d2d3d4d5d6d7d8d9d0d1d2d3d4d5d6";
pub(crate) const DNST_DEVICE_ID: &str = "c1c2c3c4c5c6c7c8c9c0c1c2c3c4c5c6";
pub(crate) const DNST_FP: &str =
    "47:1E:87:8F:3E:48:C8:1C:5F:BF:30:2E:B8:A8:3A:05:72:0D:B9:77:A2:11:81:09:E6:E5:EF:92:C4:66:7B:92";
pub(crate) const AWG_DEVICE_ID: &str = "0123456789abcdef0123456789abcdef";
pub(crate) const XHTTP_DEVICE_ID: &str = "abcdef0123456789abcdef0123456789";

pub(crate) async fn seed_state(dir: &TempDir) -> AppState {
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

pub(crate) async fn get(
    app: axum::Router,
    path: &str,
    user_agent: &str,
) -> (StatusCode, Vec<u8>, String) {
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

/// Helper: does `de` appear in the rendered subscription (raw base64
/// / VPN-client UA path)? All inventory mutations MUST happen before
/// calling this — the per-request access-log writer is a background
/// task, and interleaving an audited inventory write after a fetch
/// races it into a WAL read→write-upgrade SQLITE_BUSY.
pub(crate) async fn de_in_subscription(app: axum::Router) -> bool {
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

/// Seed a state where naive is a first-class citizen: SingBox+Caddy kernels
/// and Vless+Naive protocols registered, a vless server `de`, a naive
/// server `cdn` (Caddy kernel, `naive` enabled, `naive.domain` provisioned),
/// and a user granted on BOTH. The user carries a `tuic_password` because
/// the pre-Part-A naive `share_link` reads it (Part A swaps this to a
/// dedicated `naive_password`; this test moves with that change).
pub(crate) async fn seed_state_with_naive(dir: &TempDir) -> AppState {
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
    // Operator label → must surface in the rendered URI fragment.
    inv.set_server_display_name(&cdn.id, Some("Latvia"))
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
pub(crate) async fn subscription_lines(app: axum::Router, device_id: &str) -> Vec<String> {
    subscription_lines_for_ua(app, device_id, "v2rayN/6.62").await
}

/// Like `subscription_lines` but with a caller-chosen UA, handling BOTH
/// response shapes: a v2ray-family UA gets raw base64; the `VPNRouter` UA
/// gets the JSON wrapper (`{"config":"<base64>"}`) — extract `config` first.
pub(crate) async fn subscription_lines_for_ua(
    app: axum::Router,
    device_id: &str,
    ua: &str,
) -> Vec<String> {
    let (status, body, _ct) = get(app, &format!("/api/v1/app/config/{device_id}"), ua).await;
    assert_eq!(status, StatusCode::OK);
    let body_str = String::from_utf8(body).unwrap();
    let b64 = if body_str.trim_start().starts_with('{') {
        let v: Value = serde_json::from_str(&body_str).unwrap();
        v.get("config")
            .and_then(|c| c.as_str())
            .unwrap_or("")
            .to_string()
    } else {
        body_str
    };
    let decoded = BASE64_STANDARD.decode(b64.as_bytes()).unwrap();
    String::from_utf8(decoded)
        .unwrap()
        .split('\n')
        .map(str::to_owned)
        .collect()
}

/// SingBox kernel + Vless & Hysteria2 protocols; a vless server `de` and a
/// hysteria2 server `hy` with a Salamander obfs password provisioned. User
/// granted on both, with a `tuic_password` (hy2's per-user auth secret).
pub(crate) async fn seed_state_with_hy2(dir: &TempDir) -> AppState {
    seed_hy2_opts(dir, Some("HY2_TEST_PW"), true).await
}

pub(crate) async fn seed_hy2_opts(
    dir: &TempDir,
    tuic_password: Option<&str>,
    obfs: bool,
) -> AppState {
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
    // Operator label → must surface in the rendered URI fragment.
    inv.set_server_display_name(&hy.id, Some("Latvia"))
        .await
        .unwrap();
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

/// One physical node with BOTH naive and hysteria2 enabled — the co-location
/// case the `pair=` tag exists for (so a client can carry UDP, which naive
/// can't, over the HY2 on the same node).
pub(crate) async fn seed_state_with_paired_node(dir: &TempDir) -> AppState {
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

    let cdn = Server {
        id: ServerId("cdn".into()),
        address: "213.155.15.93".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("caddy".into()), KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("naive".into()), ProtocolId("hysteria2".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    };
    inv.add_server(&cdn).await.unwrap();
    inv.set_server_secret(&cdn.id, "naive.domain", "cdn.example.com")
        .await
        .unwrap();
    inv.set_server_secret(&cdn.id, "hysteria2.obfs.password", "OBFS")
        .await
        .unwrap();
    inv.set_server_display_name(&cdn.id, Some("Latvia"))
        .await
        .unwrap();
    // UDP pairing opt-in (UX-3) — without it no `pair=` tag is emitted.
    inv.set_server_udp_pair_enabled(&cdn.id, true)
        .await
        .unwrap();

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
    inv.set_vpn_router_device_id(&user.id, PAIR_DEVICE_ID)
        .await
        .unwrap();
    inv.grant(&user.id, &ServerId("cdn".into())).await.unwrap();

    let (state, _w) = vpnctld::make_app_state_for_tests(inv, Arc::new(reg));
    state
}

/// Seed a vless server `de` + a dns-tunnel server `tun`
/// (sing-box+dns-tunnel kernels, `dns-tunnel` enabled, domain +
/// fingerprint provisioned), with a user granted on BOTH.
pub(crate) async fn seed_state_with_dns_tunnel(dir: &TempDir) -> AppState {
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    let mut reg = Registry::new();
    reg.register_kernel(Box::new(SingBox::new())).unwrap();
    reg.register_kernel(Box::new(vpnctl_kernels::DnsTunnel::new()))
        .unwrap();
    reg.register_protocol(Box::new(VlessReality::new()))
        .unwrap();
    reg.register_protocol(Box::new(DnsTunnel::new())).unwrap();

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

    let tun = Server {
        id: ServerId("tun".into()),
        address: "tun.example.com".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("dns-tunnel".into())],
        enabled_protocols: vec![ProtocolId("dns-tunnel".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    };
    inv.add_server(&tun).await.unwrap();
    inv.set_server_secret(&tun.id, "dns-tunnel:domain", "tunnel.example.org")
        .await
        .unwrap();
    inv.set_server_secret(&tun.id, "dns-tunnel:fingerprint", DNST_FP)
        .await
        .unwrap();
    inv.set_server_display_name(&tun.id, Some("Iceland"))
        .await
        .unwrap();

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
    inv.set_vpn_router_device_id(&user.id, DNST_DEVICE_ID)
        .await
        .unwrap();
    inv.grant(&user.id, &ServerId("de".into())).await.unwrap();
    inv.grant(&user.id, &ServerId("tun".into())).await.unwrap();

    let (state, _writer) = vpnctld::make_app_state_for_tests(inv, Arc::new(reg));
    state
}

pub(crate) async fn seed_state_with_awg(dir: &TempDir) -> AppState {
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    let mut reg = Registry::new();
    reg.register_kernel(Box::new(SingBox::new())).unwrap();
    reg.register_kernel(Box::new(AmneziaWg::new())).unwrap();
    reg.register_protocol(Box::new(VlessReality::new()))
        .unwrap();
    reg.register_protocol(Box::new(WireGuard::new())).unwrap();

    // vless server — proves vless stays first + intact.
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

    // amneziawg server — wireguard protocol + per-server obfs + server key.
    let aw = Server {
        id: ServerId("aw".into()),
        address: "203.0.113.50".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("amneziawg".into())],
        enabled_protocols: vec![ProtocolId("wireguard".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    };
    inv.add_server(&aw).await.unwrap();
    for (k, v) in [
        (
            "wireguard.server_public_key",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        ),
        ("amneziawg.jc", "7"),
        ("amneziawg.jmin", "60"),
        ("amneziawg.jmax", "140"),
        ("amneziawg.s1", "30"),
        ("amneziawg.s2", "90"),
        ("amneziawg.h1", "1111111111"),
        ("amneziawg.h2", "2022222222"),
        ("amneziawg.h3", "333333333"),
        ("amneziawg.h4", "444444444"),
    ] {
        inv.set_server_secret(&aw.id, k, v).await.unwrap();
    }
    inv.set_server_display_name(&aw.id, Some("Iceland"))
        .await
        .unwrap();

    let user = User {
        id: UserId("tester-1".into()),
        uuid: "11111111-2222-3333-4444-555555555555".into(),
        tuic_password: None,
        wireguard_pubkey: Some("qXFvJL5KLmM3Of9hVo5GmJ4n0LB9rWYfV4ZE1XGZJks=".into()),
        wireguard_private: Some("0000000000000000000000000000000000000000000=".into()),
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    };
    inv.add_user(&user).await.unwrap();
    inv.set_vpn_router_device_id(&user.id, AWG_DEVICE_ID)
        .await
        .unwrap();
    inv.grant(&user.id, &ServerId("de".into())).await.unwrap();
    inv.grant(&user.id, &ServerId("aw".into())).await.unwrap();

    let (state, _writer) = vpnctld::make_app_state_for_tests(inv, Arc::new(reg));
    state
}

pub(crate) async fn seed_state_with_xhttp(dir: &TempDir) -> AppState {
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    let mut reg = Registry::new();
    reg.register_kernel(Box::new(SingBox::new())).unwrap();
    reg.register_kernel(Box::new(Xray::new())).unwrap();
    reg.register_protocol(Box::new(VlessReality::new()))
        .unwrap();
    reg.register_protocol(Box::new(VlessXhttp::new())).unwrap();

    // vless+reality server (proves vless stays first).
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

    // xray server serving vless+xhttp (reuses the reality secrets + path).
    let xr = Server {
        id: ServerId("xr".into()),
        address: "203.0.113.60".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("xray".into())],
        enabled_protocols: vec![ProtocolId("vless+xhttp".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    };
    inv.add_server(&xr).await.unwrap();
    for (k, v) in [
        ("vless.public_key", "PUB_xr"),
        ("vless.private_key", "PRIV_xr"),
        ("vless.short_id", "abcdef12"),
        ("vless.sni", "yahoo.com"),
        ("vlessxhttp.path", "somepath"),
    ] {
        inv.set_server_secret(&xr.id, k, v).await.unwrap();
    }
    inv.set_server_display_name(&xr.id, Some("Iceland"))
        .await
        .unwrap();

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
    inv.set_vpn_router_device_id(&user.id, XHTTP_DEVICE_ID)
        .await
        .unwrap();
    inv.grant(&user.id, &ServerId("de".into())).await.unwrap();
    inv.grant(&user.id, &ServerId("xr".into())).await.unwrap();

    let (state, _writer) = vpnctld::make_app_state_for_tests(inv, Arc::new(reg));
    state
}
