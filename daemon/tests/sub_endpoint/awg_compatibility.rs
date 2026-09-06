//! Mixed-server compatibility through the real HTTP router, not renderer fragments.
//! Only enabled-protocol rows change between captures: keys, grants, user, token,
//! device ID, registry and secret map are shared. Never normalize response bytes.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::BodyExt;
use serde_json::Value;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{KernelId, ProtocolId, Registry, RenderCtx, Server, ServerId, User, UserId};
use vpnctl_inventory::{SqliteInventory, bootstrap_server_secrets};
use vpnctl_kernels::SingBox;
use vpnctl_protocols::{
    AmneziaWg2, AmneziaWg3, Hysteria2, TuicV5, VlessReality, VlessXhttp, WireGuard,
};
use vpnctld::{AppState, router};

const SERVER_ID: &str = "awg-compat";
const LEGACY_PROTOCOLS: [&str; 5] = [
    "vless+reality",
    "vless+xhttp",
    "hysteria2",
    "tuic-v5",
    "wireguard",
];

async fn seed(dir: &TempDir) -> (AppState, String, String) {
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    // Local extension only: common::seed and other suites keep their registry.
    let mut registry = Registry::new();
    registry.register_kernel(Box::new(SingBox::new())).unwrap();
    registry
        .register_protocol(Box::new(VlessReality::new()))
        .unwrap();
    registry
        .register_protocol(Box::new(VlessXhttp::new()))
        .unwrap();
    registry
        .register_protocol(Box::new(Hysteria2::new()))
        .unwrap();
    registry.register_protocol(Box::new(TuicV5::new())).unwrap();
    registry
        .register_protocol(Box::new(WireGuard::new()))
        .unwrap();
    registry
        .register_protocol(Box::new(AmneziaWg2::new()))
        .unwrap();
    registry
        .register_protocol(Box::new(AmneziaWg3::new()))
        .unwrap();

    let mut server = Server {
        id: ServerId(SERVER_ID.into()),
        address: "203.0.113.7".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: LEGACY_PROTOCOLS
            .iter()
            .map(|id| ProtocolId((*id).into()))
            .collect(),
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    };
    inv.add_server(&server).await.unwrap();

    let (private, public) = vpnctl_crypto::gen_wireguard_keypair();
    let user = User {
        id: UserId("awg-compat-user".into()),
        uuid: vpnctl_crypto::gen_uuid(),
        tuic_password: Some(vpnctl_crypto::gen_password(32).unwrap()),
        wireguard_pubkey: Some(public),
        wireguard_private: Some(private),
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    };
    inv.add_user(&user).await.unwrap();
    let device_id = vpnctl_crypto::gen_vpn_router_device_id().unwrap();
    inv.set_vpn_router_device_id(&user.id, &device_id)
        .await
        .unwrap();
    inv.grant(&user.id, &server.id).await.unwrap();
    let token = inv
        .get_user(&user.id)
        .await
        .unwrap()
        .unwrap()
        .sub_token
        .unwrap();

    // Bootstrap every protocol BEFORE the baseline, without enabling AWG in DB.
    // This generates valid synthetic server keypairs and version parameters once.
    server.enabled_protocols.extend([
        ProtocolId("amneziawg2".into()),
        ProtocolId("amneziawg3".into()),
    ]);
    let (secrets, _) = bootstrap_server_secrets(&inv, &server, &registry)
        .await
        .unwrap();
    let peers = [user];
    let ctx = RenderCtx::with_peers(&server, &secrets, &peers);
    for id in ["amneziawg2", "amneziawg3"] {
        // Check fixture material using the grant-aware download context.
        // This does not establish renderability in /sub's peerless context;
        // raw-byte tests below verify observable compatibility, not which
        // exclusion mechanism was responsible.
        assert!(
            registry
                .protocol(&ProtocolId(id.into()))
                .unwrap()
                .client_config(&ctx, &peers[0])
                .is_ok(),
            "{id} fixture must be renderable before testing exclusion"
        );
    }

    // Ten HTTP captures share this fixture. Keep the real limiter active with
    // a bounded test budget instead of exhausting its production burst limit.
    let limiter = Arc::new(vpnctld::rate_limit::RateLimiter::new(
        100.0,
        0.0,
        std::time::Duration::from_secs(60),
    ));
    let (state, writer) =
        vpnctld::make_app_state_with_rate_limiter(inv, Arc::new(registry), limiter);
    // Existing Mihomo fixture does the same: avoid access-log writes racing the
    // intentional inventory mutation between requests. No rendering is mocked.
    writer.abort();
    let _ = writer.await;
    (state, token, device_id)
}

async fn body(state: &AppState, uri: &str, ua: Option<&str>, content_type: &str) -> Vec<u8> {
    let mut request = Request::builder().uri(uri);
    if let Some(ua) = ua {
        request = request.header(header::USER_AGENT, ua);
    }
    let response = router(state.clone())
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    // Fixed endpoint names only: never put bearer paths or response secrets in
    // helper diagnostics. Collect the raw body unchanged even on HTTP failure.
    let endpoint = if uri.starts_with("/api/v1/app/config/") {
        "app-config"
    } else {
        "sub"
    };
    let status = response.status();
    let actual_content_type = response.headers()[header::CONTENT_TYPE]
        .to_str()
        .unwrap()
        .to_owned();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        status,
        StatusCode::OK,
        "{endpoint}: unexpected status ({} raw response bytes)",
        bytes.len()
    );
    assert!(
        actual_content_type.starts_with(content_type),
        "{endpoint}: unexpected content type"
    );
    bytes.to_vec()
}

async fn assert_legacy_bytes_unchanged(added: &[&str]) {
    let dir = TempDir::new().unwrap();
    let (state, token, device_id) = seed(&dir).await;
    let cases = [
        (format!("/sub/{token}"), None, "application/json"),
        (
            format!("/sub/{token}?format=sing-box"),
            None,
            "application/json",
        ),
        (format!("/sub/{token}"), Some("v2rayN/6.62"), "text/plain"),
        (format!("/sub/{token}?format=mihomo"), None, "text/yaml"),
        // The existing supported device route has a raw-base64 UA branch.
        // Its browser JSON wrapper contains a live timestamp; deliberately do
        // not extract/normalize that wrapper or claim whole-wrapper coverage.
        (
            format!("/api/v1/app/config/{device_id}"),
            Some("v2rayN/6.62"),
            "text/plain",
        ),
    ];
    let mut before = Vec::new();
    for (uri, ua, content_type) in &cases {
        before.push(body(&state, uri, *ua, content_type).await);
    }

    // Non-empty, format-specific baseline guards. Parsing is ONLY a guard;
    // equality below always compares the original body bytes, without sorting,
    // decoding/re-encoding, filtering dates, replacing tokens, or reserialization.
    for (index, has_xhttp) in [(0, true), (1, false)] {
        let config: Value = serde_json::from_slice(&before[index]).unwrap();
        let outbounds = config["outbounds"].as_array().unwrap();
        for kind in ["vless", "hysteria2", "tuic"] {
            assert!(outbounds.iter().any(|outbound| outbound["type"] == kind));
        }
        assert_eq!(
            outbounds
                .iter()
                .any(|outbound| outbound["transport"]["type"] == "xhttp"),
            has_xhttp
        );
    }
    assert_ne!(
        before[0], before[1],
        "stock format must exercise XHTTP filtering"
    );
    for index in [2, 4] {
        let decoded = STANDARD.decode(&before[index]).unwrap();
        let links = std::str::from_utf8(&decoded).unwrap();
        assert!(links.contains("vless://"));
        assert!(links.contains("@203.0.113.7:"));
        assert!(
            links.lines().count() >= 2,
            "must exercise a mixed legacy URI list"
        );
    }
    let yaml: Value = serde_saphyr::from_str(std::str::from_utf8(&before[3]).unwrap()).unwrap();
    let proxies = yaml["proxies"].as_array().unwrap();
    for kind in ["vless", "hysteria2"] {
        assert!(proxies.iter().any(|proxy| proxy["type"] == kind));
    }

    let server_id = ServerId(SERVER_ID.into());
    for id in added {
        assert_eq!(
            state
                .inv
                .add_server_protocol(&server_id, &ProtocolId((*id).into()))
                .await
                .unwrap(),
            1
        );
    }
    let enabled = state.inv.list_server_protocols(&server_id).await.unwrap();
    assert_eq!(enabled.len(), LEGACY_PROTOCOLS.len() + added.len());
    for id in LEGACY_PROTOCOLS.iter().chain(added.iter()) {
        assert!(enabled.contains(&ProtocolId((*id).into())));
    }
    for (index, (uri, ua, content_type)) in cases.iter().enumerate() {
        let after = body(&state, uri, *ua, content_type).await;
        assert_eq!(
            before[index], after,
            "raw HTTP case {index} changed after enabling {added:?}"
        );
    }
}

#[tokio::test]
async fn enabling_awg2_preserves_legacy_http_bytes() {
    assert_legacy_bytes_unchanged(&["amneziawg2"]).await;
}

#[tokio::test]
async fn enabling_awg3_preserves_legacy_http_bytes() {
    assert_legacy_bytes_unchanged(&["amneziawg3"]).await;
}

#[tokio::test]
async fn enabling_both_awg_versions_preserves_legacy_http_bytes() {
    assert_legacy_bytes_unchanged(&["amneziawg2", "amneziawg3"]).await;
}
