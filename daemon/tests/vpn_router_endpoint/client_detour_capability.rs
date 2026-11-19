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
