use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header, request::Builder};
use axum::response::Response;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use tempfile::TempDir;
use tower::ServiceExt;
use vpnctl_core::{KernelId, ProtocolId, ServerId};
use vpnctld::{AppState, router};

use crate::common::{SAME_ORIGIN_HOST, add_same_origin, naive_server, state};

const PATH: &str = "/admin/servers/s0/dnstt-config";
const LOCATION: &str = "/admin/servers/s0/protocols#dnstt";
const CONFIG: &str = "domain=tunnel.example.org&resolver=192.0.2.53";

async fn fixture(dir: &TempDir, address: &str) -> AppState {
    let mut app_state = state(dir).await;
    app_state.registry = Arc::new(vpnctl_kernels::build_registry().unwrap());
    let mut server = naive_server("s0");
    server.address = address.into();
    server.kernels = vec![KernelId("dnstt".into())];
    server.enabled_protocols = vec![ProtocolId("dnstt".into())];
    app_state.inv.add_server(&server).await.unwrap();
    app_state
}

fn request() -> Builder {
    Request::builder()
        .method("POST")
        .uri(PATH)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
}

async fn post(state: &AppState, form: &str) -> Response {
    router(state.clone())
        .oneshot(
            add_same_origin(request())
                .body(Body::from(form.to_owned()))
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn dnstt_config_normalizes_domain_and_audits_only_changed_keys() {
    let dir = TempDir::new().unwrap();
    let state = fixture(&dir, "203.0.113.6").await;
    let server = ServerId("s0".into());
    let baseline = state.inv.recent_audit(100).await.unwrap().len();

    let response = post(
        &state,
        "domain=%20%09Tunnel.Example.ORG.%20&resolver=192.0.2.53",
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()[header::LOCATION], LOCATION);

    let settings = state.inv.list_server_secrets(&server).await.unwrap();
    assert_eq!(
        settings.get("dnstt.domain").map(String::as_str),
        Some("tunnel.example.org")
    );
    assert_eq!(
        settings.get("dnstt.resolver").map(String::as_str),
        Some("192.0.2.53")
    );
    assert_eq!(settings.len(), 2);
    let audit = state.inv.recent_audit(100).await.unwrap();
    assert_eq!(audit.len(), baseline + 1);
    assert_eq!(audit[0].action, "server.dnstt.set");
    assert_eq!(audit[0].target.as_deref(), Some("s0"));
    let payload = audit[0].payload.as_ref().unwrap();
    assert!(
        *payload == serde_json::json!({"keys": ["dnstt.domain", "dnstt.resolver"]})
            || *payload == serde_json::json!({"keys": ["dnstt.resolver", "dnstt.domain"]})
    );

    let response = post(&state, CONFIG).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()[header::LOCATION], LOCATION);
    assert_eq!(
        state.inv.list_server_secrets(&server).await.unwrap(),
        settings
    );
    let after = state.inv.recent_audit(100).await.unwrap();
    assert_eq!(after.len(), audit.len());
    assert_eq!(after[0].id, audit[0].id);

    let response = post(&state, "domain=tunnel.example.org&resolver=192.0.2.54").await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let audit = state.inv.recent_audit(100).await.unwrap();
    assert_eq!(audit.len(), after.len() + 1);
    assert_eq!(audit[0].action, "server.dnstt.set");
    assert_eq!(
        audit[0].payload,
        Some(serde_json::json!({"keys": ["dnstt.resolver"]}))
    );
}

#[tokio::test]
async fn dnstt_config_rejects_invalid_fields_without_mutating_settings() {
    let dir = TempDir::new().unwrap();
    let state = fixture(&dir, "203.0.113.6").await;
    let server = ServerId("s0".into());
    state
        .inv
        .set_server_secret(&server, "dnstt.domain", "old.example.org")
        .await
        .unwrap();
    state
        .inv
        .set_server_secret(&server, "dnstt.resolver", "192.0.2.54")
        .await
        .unwrap();
    let before = state.inv.list_server_secrets(&server).await.unwrap();
    let baseline = state.inv.recent_audit(100).await.unwrap().len();

    let long_label = format!("domain={}.example.org&resolver=192.0.2.53", "a".repeat(64));
    for form in [
        "domain=tunnel..example.org&resolver=192.0.2.53",
        "domain=t%C3%BCnnel.example.org&resolver=192.0.2.53",
        long_label.as_str(),
        "domain=tunnel.example.org&resolver=192.0.2.999",
        "domain=tunnel.example.org&resolver=2001%3Adb8%3A%3A53",
        "domain=tunnel.example.org&resolver=192.0.2.53%3A53",
    ] {
        assert_eq!(
            post(&state, form).await.status(),
            StatusCode::BAD_REQUEST,
            "{form}"
        );
        assert_eq!(
            state.inv.list_server_secrets(&server).await.unwrap(),
            before
        );
        assert_eq!(state.inv.recent_audit(100).await.unwrap().len(), baseline);
    }
}

#[tokio::test]
async fn dnstt_config_requires_a_literal_ipv4_server_address() {
    for address in ["node.example.org", "2001:db8::6"] {
        let dir = TempDir::new().unwrap();
        let state = fixture(&dir, address).await;
        let server = ServerId("s0".into());
        let before = state.inv.list_server_secrets(&server).await.unwrap();
        let baseline = state.inv.recent_audit(100).await.unwrap().len();

        assert_eq!(
            post(&state, CONFIG).await.status(),
            StatusCode::BAD_REQUEST,
            "{address}"
        );
        assert_eq!(
            state.inv.list_server_secrets(&server).await.unwrap(),
            before
        );
        assert_eq!(state.inv.recent_audit(100).await.unwrap().len(), baseline);
    }
}

#[tokio::test]
async fn dnstt_config_requires_admin_auth_and_same_origin() {
    const CHILD: &str = "VPNCTL_DNSTT_CONFIG_AUTH_SMOKE_CHILD";
    const USER: &str = "dnstt-test-operator";
    const PASSWORD: &str = "fixture-only-password";
    if std::env::var_os(CHILD).is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "server_detail::dnstt_settings::dnstt_config_requires_admin_auth_and_same_origin",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("VPNCTLD_ADMIN_USER", USER)
            .env("VPNCTLD_ADMIN_PASSWORD", PASSWORD)
            .status()
            .unwrap();
        assert!(status.success(), "isolated DNSTT auth smoke failed");
        return;
    }

    let dir = TempDir::new().unwrap();
    let state = fixture(&dir, "203.0.113.6").await;
    let server = ServerId("s0".into());
    let before = state.inv.list_server_secrets(&server).await.unwrap();
    let baseline = state.inv.recent_audit(100).await.unwrap().len();
    let app = router(state.clone());
    let auth = format!("Basic {}", STANDARD.encode(format!("{USER}:{PASSWORD}")));

    let response = app
        .clone()
        .oneshot(add_same_origin(request()).body(Body::from(CONFIG)).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response.headers().contains_key(header::WWW_AUTHENTICATE));

    let response = app
        .clone()
        .oneshot(
            request()
                .header(header::AUTHORIZATION, &auth)
                .header(header::HOST, SAME_ORIGIN_HOST)
                .header(header::ORIGIN, "http://foreign.example")
                .body(Body::from(CONFIG))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        state.inv.list_server_secrets(&server).await.unwrap(),
        before
    );
    assert_eq!(state.inv.recent_audit(100).await.unwrap().len(), baseline);

    let response = app
        .oneshot(
            add_same_origin(request())
                .header(header::AUTHORIZATION, &auth)
                .body(Body::from(CONFIG))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()[header::LOCATION], LOCATION);
}
