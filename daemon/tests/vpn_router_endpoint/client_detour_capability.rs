use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use serde_json::Value;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{ProtocolId, ServerId, UserId};
use vpnctl_inventory::ServiceQualitySample;
use vpnctld::router;

use super::common::{TEST_DEVICE_ID, seed_state};

async fn get_with_headers(
    app: axum::Router,
    path: &str,
    user_agent: &str,
    capability: Option<&str>,
) -> (StatusCode, Vec<u8>, String) {
    let mut req = Request::builder()
        .uri(path)
        .header("user-agent", user_agent);
    if let Some(cap) = capability {
        req = req.header("X-VPNRouter-Capabilities", cap);
    }
    let resp = app.oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
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

fn config_blob(body: &[u8]) -> String {
    let body_str = std::str::from_utf8(body).unwrap();
    if body_str.trim_start().starts_with('{') {
        let v: Value = serde_json::from_slice(body).unwrap();
        v.get("config")
            .and_then(|c| c.as_str())
            .unwrap_or("")
            .to_string()
    } else {
        body_str.to_string()
    }
}

fn decode_config_lines(body: &[u8]) -> Vec<String> {
    let b64 = config_blob(body);
    if b64.is_empty() {
        return vec![];
    }
    let decoded = BASE64_STANDARD.decode(b64.as_bytes()).unwrap();
    let s = String::from_utf8(decoded).unwrap();
    if s.is_empty() {
        vec![]
    } else {
        s.split('\n').map(str::to_owned).collect()
    }
}

#[tokio::test]
async fn old_vpnrouter_without_capability_header_omits_target() {
    let dir = TempDir::new().unwrap();
    let state = seed_state(&dir).await;
    state
        .inv
        .set_client_detour_via_as("test", &ServerId("de".into()), Some(&ServerId("is".into())))
        .await
        .unwrap();
    let app = router(state);

    let (status, body, _) = get_with_headers(
        app,
        &format!("/api/v1/app/config/{TEST_DEVICE_ID}"),
        "VPNRouter/1.0",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let lines = decode_config_lines(&body);
    assert!(
        lines.iter().any(|l| l.contains("@is.example.com")),
        "entry must be present: {lines:?}"
    );
    assert!(
        !lines.iter().any(|l| l.contains("@de.example.com")),
        "target must be omitted without capability header: {lines:?}"
    );
    assert!(
        !lines.iter().any(|l| l.contains("outbound=")),
        "metadata must be omitted without capability header: {lines:?}"
    );
}

#[tokio::test]
async fn generic_ua_with_capability_header_omits_target() {
    let dir = TempDir::new().unwrap();
    let state = seed_state(&dir).await;
    state
        .inv
        .set_client_detour_via_as("test", &ServerId("de".into()), Some(&ServerId("is".into())))
        .await
        .unwrap();
    let app = router(state);

    let (status, body, _) = get_with_headers(
        app,
        &format!("/api/v1/app/config/{TEST_DEVICE_ID}"),
        "v2rayN/6.62",
        Some("detour-v1"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let lines = decode_config_lines(&body);
    assert!(
        lines.iter().any(|l| l.contains("@is.example.com")),
        "entry must be present: {lines:?}"
    );
    assert!(
        !lines.iter().any(|l| l.contains("@de.example.com")),
        "target must be omitted for generic UA: {lines:?}"
    );
    assert!(
        !lines.iter().any(|l| l.contains("outbound=")),
        "metadata must be omitted for generic UA: {lines:?}"
    );
}

#[tokio::test]
async fn capability_token_in_repeated_header_is_accepted() {
    let dir = TempDir::new().unwrap();
    let state = seed_state(&dir).await;
    state
        .inv
        .set_client_detour_via_as("test", &ServerId("de".into()), Some(&ServerId("is".into())))
        .await
        .unwrap();
    let app = router(state);
    let req = Request::builder()
        .uri(format!("/api/v1/app/config/{TEST_DEVICE_ID}"))
        .header("user-agent", "VPNRouter/1.0")
        .header("X-VPNRouter-Capabilities", "future-v1")
        .header("X-VPNRouter-Capabilities", "detour-v1")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let lines = decode_config_lines(&body);

    assert!(lines.iter().any(|line| line.contains("detour=is")));
}

#[tokio::test]
async fn capability_aware_vpnrouter_gets_entry_and_target_with_outbound_detour() {
    let dir = TempDir::new().unwrap();
    let state = seed_state(&dir).await;
    state
        .inv
        .set_client_detour_via_as("test", &ServerId("de".into()), Some(&ServerId("is".into())))
        .await
        .unwrap();
    let app = router(state);

    let (status, body, _) = get_with_headers(
        app,
        &format!("/api/v1/app/config/{TEST_DEVICE_ID}"),
        "VPNRouter/1.0",
        Some("detour-v1"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let lines = decode_config_lines(&body);
    let entry = lines
        .iter()
        .find(|l| l.contains("@is.example.com"))
        .expect("entry URI present");
    let target = lines
        .iter()
        .find(|l| l.contains("@de.example.com"))
        .expect("target URI present");

    assert!(
        entry.contains("outbound=is"),
        "entry must carry outbound=is: {entry}"
    );
    assert!(
        !entry.contains("detour="),
        "entry must not carry detour: {entry}"
    );
    assert!(
        target.contains("outbound=de"),
        "target must carry outbound=de: {target}"
    );
    assert!(
        target.contains("detour=is"),
        "target must carry detour=is: {target}"
    );
}

#[tokio::test]
async fn confirmed_target_tcp_outage_preserves_only_the_capability_aware_detour() {
    let dir = TempDir::new().unwrap();
    let state = seed_state(&dir).await;
    let inv = &state.inv;
    let target_id = ServerId("de".into());
    let entry_id = ServerId("is".into());
    inv.set_client_detour_via_as("test", &target_id, Some(&entry_id))
        .await
        .unwrap();
    let confirm_direct_outage = async |server_id: &ServerId| {
        inv.set_server_auto_suppress(server_id, true).await.unwrap();
        let base = Utc::now() - Duration::seconds(60);
        for offset in [0, 10] {
            let sample = ServiceQualitySample {
                ts: base + Duration::seconds(offset),
                server_id: server_id.clone(),
                vantage: "fixture measurement network".into(),
                target_count: 1,
                available_targets: 0,
                attempts: 3,
                successes: 0,
                tcp_rtt_ms: vec![],
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
        }
        assert!(inv.is_server_auto_suppressed(server_id).await.unwrap());
    };
    confirm_direct_outage(&target_id).await;

    let path = format!("/api/v1/app/config/{TEST_DEVICE_ID}");
    let fetch = async |user_agent, capability| {
        let (status, body, _) =
            get_with_headers(router(state.clone()), &path, user_agent, capability).await;
        assert_eq!(status, StatusCode::OK);
        decode_config_lines(&body)
    };
    let metadata = |line: &str| {
        let uri = url::Url::parse(line).unwrap();
        let mut fields: Vec<_> = uri
            .query_pairs()
            .filter(|(key, _)| matches!(key.as_ref(), "detour" | "outbound"))
            .map(|(key, value)| format!("{key}={value}"))
            .collect();
        fields.sort_unstable();
        fields
    };

    let lines = fetch("VPNRouter/1.0", Some("detour-v1")).await;
    assert_eq!(lines.len(), 2, "{lines:?}");
    let entry = lines
        .iter()
        .find(|line| line.contains("@is.example.com:443?"))
        .expect("direct entry URI is present");
    let target = lines
        .iter()
        .find(|line| line.contains("@de.example.com:443?"))
        .expect("target URI is present through its entry");
    assert_eq!(metadata(entry), ["outbound=is"]);
    assert_eq!(metadata(target), ["detour=is", "outbound=de"]);

    for (ua, capability) in [("VPNRouter/1.0", None), ("v2rayN/6.62", Some("detour-v1"))] {
        let lines = fetch(ua, capability).await;
        assert_eq!(lines.len(), 1, "{ua}: {lines:?}");
        assert!(lines[0].contains("@is.example.com:443?"));
        assert!(metadata(&lines[0]).is_empty());
    }

    confirm_direct_outage(&entry_id).await;
    assert!(fetch("VPNRouter/1.0", Some("detour-v1")).await.is_empty());

    inv.set_server_suppressed(&entry_id, false).await.unwrap();
    inv.set_client_detour_via_as("test", &target_id, None)
        .await
        .unwrap();
    let lines = fetch("VPNRouter/1.0", Some("detour-v1")).await;
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("@is.example.com:443?"));
    assert!(metadata(&lines[0]).is_empty());
    assert!(inv.is_server_auto_suppressed(&target_id).await.unwrap());
}

#[tokio::test]
async fn no_chain_capability_response_byte_equals_response_without_capability() {
    let dir = TempDir::new().unwrap();
    let state = seed_state(&dir).await;

    let (status1, body1, _) = get_with_headers(
        router(state.clone()),
        &format!("/api/v1/app/config/{TEST_DEVICE_ID}"),
        "VPNRouter/1.0",
        None,
    )
    .await;
    assert_eq!(status1, StatusCode::OK);

    let (status2, body2, _) = get_with_headers(
        router(state),
        &format!("/api/v1/app/config/{TEST_DEVICE_ID}"),
        "VPNRouter/1.0",
        Some("detour-v1"),
    )
    .await;
    assert_eq!(status2, StatusCode::OK);

    assert_eq!(
        config_blob(&body1),
        config_blob(&body2),
        "base64 config blobs must be byte-equal when no chain exists"
    );
}

#[tokio::test]
async fn target_omitted_when_upstream_grant_missing() {
    let dir = TempDir::new().unwrap();
    let state = seed_state(&dir).await;
    state
        .inv
        .set_client_detour_via_as("test", &ServerId("de".into()), Some(&ServerId("is".into())))
        .await
        .unwrap();
    state
        .inv
        .revoke(&UserId("tester-1".into()), &ServerId("is".into()))
        .await
        .unwrap();
    let app = router(state);

    let (status, body, _) = get_with_headers(
        app,
        &format!("/api/v1/app/config/{TEST_DEVICE_ID}"),
        "VPNRouter/1.0",
        Some("detour-v1"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let lines = decode_config_lines(&body);
    assert!(
        !lines.iter().any(|l| l.contains("@de.example.com")),
        "target must be omitted when entry grant missing: {lines:?}"
    );
}

#[tokio::test]
async fn target_omitted_when_upstream_vless_hidden() {
    let dir = TempDir::new().unwrap();
    let state = seed_state(&dir).await;
    state
        .inv
        .set_client_detour_via_as("test", &ServerId("de".into()), Some(&ServerId("is".into())))
        .await
        .unwrap();
    state
        .inv
        .set_server_protocol_hidden(
            &ServerId("is".into()),
            &ProtocolId("vless+reality".into()),
            true,
        )
        .await
        .unwrap();
    let app = router(state);

    let (status, body, _) = get_with_headers(
        app,
        &format!("/api/v1/app/config/{TEST_DEVICE_ID}"),
        "VPNRouter/1.0",
        Some("detour-v1"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let lines = decode_config_lines(&body);
    assert!(
        !lines.iter().any(|l| l.contains("@de.example.com")),
        "target must be omitted when entry protocol hidden: {lines:?}"
    );
}

#[tokio::test]
async fn target_omitted_when_upstream_vless_denied() {
    let dir = TempDir::new().unwrap();
    let state = seed_state(&dir).await;
    state
        .inv
        .set_client_detour_via_as("test", &ServerId("de".into()), Some(&ServerId("is".into())))
        .await
        .unwrap();
    state
        .inv
        .set_grant_protocol_override(
            &UserId("tester-1".into()),
            &ServerId("is".into()),
            &ProtocolId("vless+reality".into()),
            true,
        )
        .await
        .unwrap();
    let app = router(state);

    let (status, body, _) = get_with_headers(
        app,
        &format!("/api/v1/app/config/{TEST_DEVICE_ID}"),
        "VPNRouter/1.0",
        Some("detour-v1"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let lines = decode_config_lines(&body);
    assert!(
        !lines.iter().any(|l| l.contains("@de.example.com")),
        "target must be omitted when entry protocol denied: {lines:?}"
    );
}

#[tokio::test]
async fn target_omitted_when_upstream_unusable() {
    let dir = TempDir::new().unwrap();
    let state = seed_state(&dir).await;
    state
        .inv
        .set_client_detour_via_as(
            "test",
            &ServerId("de".into()),
            Some(&ServerId("bare".into())),
        )
        .await
        .unwrap();
    let app = router(state);

    let (status, body, _) = get_with_headers(
        app,
        &format!("/api/v1/app/config/{TEST_DEVICE_ID}"),
        "VPNRouter/1.0",
        Some("detour-v1"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let lines = decode_config_lines(&body);
    assert!(
        !lines.iter().any(|l| l.contains("@de.example.com")),
        "target must be omitted when entry is unusable/missing secrets: {lines:?}"
    );
}

#[tokio::test]
async fn vmess_capability_uses_existing_subscription_and_visible_vless_hop() {
    use std::sync::Arc;
    use vpnctl_core::{KernelId, Server};

    let dir = TempDir::new().unwrap();
    let mut state = seed_state(&dir).await;
    state.registry = Arc::new(vpnctl_kernels::build_registry().unwrap());
    state.rate_limiter = Arc::new(vpnctld::rate_limit::RateLimiter::new(
        100.0,
        0.0,
        std::time::Duration::from_secs(60),
    ));
    let pid = ProtocolId("vmess".into());
    let exit = ServerId("ws-exit".into());
    let entry = ServerId("de".into());
    let uid = UserId("tester-1".into());

    let fetch = |ua: &'static str, cap: Option<&'static str>| {
        let state = state.clone();
        async move {
            let path = format!("/api/v1/app/config/{TEST_DEVICE_ID}");
            let (status, body, _) = get_with_headers(router(state), &path, ua, cap).await;
            assert_eq!(status, StatusCode::OK);
            decode_config_lines(&body)
        }
    };
    let legacy = fetch("VPNRouter/2.51", Some("detour-v1")).await;
    let generic = fetch("v2rayN/6.62", Some("detour-v1, vmess-v1")).await;

    state
        .inv
        .add_server(&Server {
            id: exit.clone(),
            address: "192.0.2.77".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![pid.clone()],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    state.inv.grant(&uid, &exit).await.unwrap();
    state
        .inv
        .set_server_display_name(&exit, Some("WS Exit"))
        .await
        .unwrap();
    for (key, value) in [
        ("vmess.domain", "ws.example.com"),
        ("vmess.preferred_entry", "de"),
    ] {
        state
            .inv
            .set_server_secret(&exit, key, value)
            .await
            .unwrap();
    }

    assert_eq!(fetch("VPNRouter/2.51", Some("detour-v1")).await, legacy);
    assert_eq!(
        fetch("v2rayN/6.62", Some("detour-v1, vmess-v1")).await,
        generic
    );
    let profiles = |lines: &[String]| {
        lines
            .iter()
            .filter_map(|line| line.strip_prefix("vmess://"))
            .map(|data| {
                serde_json::from_slice::<Value>(&BASE64_STANDARD.decode(data).unwrap()).unwrap()
            })
            .collect::<Vec<_>>()
    };
    let direct = profiles(&fetch("VPNRouter/2.51", Some("vmess-v1")).await);
    assert_eq!(direct.len(), 1);
    assert_eq!(direct[0]["add"], "ws.example.com");
    assert_eq!(direct[0]["ps"], "WS Exit VMess ~tester-1");
    assert_eq!(direct[0]["scy"], "aes-128-gcm");
    assert_eq!(direct[0]["net"], "ws");
    assert_eq!(direct[0]["sni"], "ws.example.com");
    assert!(direct[0].get("detour").is_none());

    let opts = Some("detour-v1, vmess-v1");
    let lines = fetch("VPNRouter/2.51", opts).await;
    let chained = profiles(&lines);
    assert_eq!(chained.len(), 2);
    assert_eq!(chained[0]["add"], "192.0.2.77");
    assert_eq!(chained[0]["sni"], "ws.example.com");
    assert_eq!(chained[0]["host"], "ws.example.com");
    assert_eq!(chained[0]["path"], "/vmess");
    assert_eq!(chained[0]["detour"], "de");
    assert_eq!(chained[0]["outbound"], "vmess-ws-exit");
    assert_eq!(chained[1], direct[0]);
    assert!(
        lines
            .iter()
            .any(|line| line.contains("@de.example.com") && line.contains("&outbound=de#"))
    );

    state
        .inv
        .set_server_protocol_hidden(&entry, &ProtocolId("vless+reality".into()), true)
        .await
        .unwrap();
    assert_eq!(profiles(&fetch("VPNRouter/2.51", opts).await), direct);

    state
        .inv
        .set_client_detour_via_as("test", &exit, Some(&entry))
        .await
        .unwrap();
    assert!(profiles(&fetch("VPNRouter/2.51", opts).await).is_empty());

    state
        .inv
        .set_client_detour_via_as("test", &exit, None)
        .await
        .unwrap();
    assert_eq!(profiles(&fetch("VPNRouter/2.51", opts).await), direct);

    state
        .inv
        .set_grant_protocol_override(&uid, &exit, &pid, true)
        .await
        .unwrap();
    assert!(profiles(&fetch("VPNRouter/2.51", opts).await).is_empty());
}
