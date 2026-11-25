use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header, request::Builder};
use axum::response::Response;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use tempfile::TempDir;
use tower::ServiceExt;
use vpnctl_core::{KernelId, ProtocolId, ServerId};
use vpnctld::{AppState, router};

use crate::common::{SAME_ORIGIN_HOST, add_same_origin, fetch_html, naive_server, state};

const PATH: &str = "/admin/servers/s0/turnrelay-config";
const LOCATION: &str = "/admin/servers/s0/protocols#turnrelay";
const VALID: &str = "listen_port=53492&mode=dtls&turn_server=turn.example.org%3A3478&turn_username=turn-user&turn_password=fixture-pass&connections=2&udp=true&publish=vless%2Breality&publish_targets=%2A";

async fn fixture(dir: &TempDir) -> AppState {
    let mut app_state = state(dir).await;
    app_state.registry = Arc::new(vpnctl_kernels::build_registry().unwrap());
    let mut server = naive_server("s0");
    server.kernels = vec![KernelId("turnrelay".into())];
    server.enabled_protocols = vec![ProtocolId("turnrelay".into())];
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
async fn turnrelay_config_saves_locked_fields_and_audits_changes_only() {
    let dir = TempDir::new().unwrap();
    let state = fixture(&dir).await;
    let server = ServerId("s0".into());
    let baseline = state.inv.recent_audit(100).await.unwrap().len();

    let response = post(&state, VALID).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()[header::LOCATION], LOCATION);
    let settings = state.inv.list_server_secrets(&server).await.unwrap();
    for (key, value) in [
        ("turnrelay.listen_port", "53492"),
        ("turnrelay.mode", "dtls"),
        ("turnrelay.turn_server", "turn.example.org:3478"),
        ("turnrelay.turn_username", "turn-user"),
        ("turnrelay.turn_password", "fixture-pass"),
        ("turnrelay.connections", "2"),
        ("turnrelay.udp", "true"),
        ("turnrelay.publish", "vless+reality"),
        ("turnrelay.publish_targets", "*"),
    ] {
        assert_eq!(settings.get(key).map(String::as_str), Some(value), "{key}");
    }
    let audit = state.inv.recent_audit(100).await.unwrap();
    assert_eq!(audit.len(), baseline + 1);
    assert_eq!(audit[0].action, "server.turnrelay.set");
    assert_eq!(audit[0].target.as_deref(), Some("s0"));
    assert_eq!(
        audit[0].payload,
        Some(serde_json::json!({
            "keys": [
                "turnrelay.listen_port",
                "turnrelay.mode",
                "turnrelay.turn_server",
                "turnrelay.turn_username",
                "turnrelay.turn_password",
                "turnrelay.connections",
                "turnrelay.udp",
                "turnrelay.publish",
                "turnrelay.publish_targets",
            ]
        }))
    );

    let response = post(&state, VALID).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        state.inv.list_server_secrets(&server).await.unwrap(),
        settings
    );
    let after = state.inv.recent_audit(100).await.unwrap();
    assert_eq!(after.len(), audit.len());
    assert_eq!(after[0].id, audit[0].id);

    let changed = VALID.replace("turn_password=fixture-pass", "turn_password=rotated-pass");
    let response = post(&state, &changed).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let audit = state.inv.recent_audit(100).await.unwrap();
    assert_eq!(audit.len(), after.len() + 1);
    assert_eq!(
        audit[0].payload,
        Some(serde_json::json!({"keys": ["turnrelay.turn_password"]}))
    );
}

#[tokio::test]
async fn turnrelay_config_rejects_invalid_fields_without_mutating_settings() {
    for (form, label) in [
        (
            VALID.replace("listen_port=53492", "listen_port=0"),
            "port 0",
        ),
        (
            VALID.replace("listen_port=53492", "listen_port=65536"),
            "port overflow",
        ),
        (VALID.replace("mode=dtls", "mode=wrap"), "mode"),
        (
            VALID.replace(
                "turn_server=turn.example.org%3A3478",
                "turn_server=turn.example.org",
            ),
            "turn server",
        ),
        (
            VALID.replace("connections=2", "connections=0"),
            "connections 0",
        ),
        (
            VALID.replace("connections=2", "connections=61"),
            "connections 61",
        ),
        (
            VALID.replace("publish=vless%2Breality", "publish=vmess"),
            "publish",
        ),
        (
            VALID.replace("publish_targets=%2A", "publish_targets=bad%20target"),
            "targets",
        ),
        (
            VALID.replace("turn_username=turn-user", "turn_username="),
            "username",
        ),
        (
            VALID.replace("turn_password=fixture-pass", "turn_password="),
            "password",
        ),
    ] {
        let dir = TempDir::new().unwrap();
        let state = fixture(&dir).await;
        let server = ServerId("s0".into());
        let before = state.inv.list_server_secrets(&server).await.unwrap();
        let baseline = state.inv.recent_audit(100).await.unwrap().len();
        assert_eq!(
            post(&state, &form).await.status(),
            StatusCode::BAD_REQUEST,
            "{label}"
        );
        assert_eq!(
            state.inv.list_server_secrets(&server).await.unwrap(),
            before,
            "{label}"
        );
        assert_eq!(
            state.inv.recent_audit(100).await.unwrap().len(),
            baseline,
            "{label}"
        );
    }
}

#[tokio::test]
async fn turnrelay_config_rejects_ports_reserved_on_the_server() {
    let dir = TempDir::new().unwrap();
    let state = fixture(&dir).await;
    let server = ServerId("s0".into());
    state
        .inv
        .set_reserved_ports(&server, &[53492])
        .await
        .unwrap();
    let before = state.inv.list_server_secrets(&server).await.unwrap();
    assert_eq!(post(&state, VALID).await.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        state.inv.list_server_secrets(&server).await.unwrap(),
        before
    );

    let free = VALID.replace("listen_port=53492", "listen_port=6000");
    assert_eq!(post(&state, &free).await.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        state
            .inv
            .list_server_secrets(&server)
            .await
            .unwrap()
            .get("turnrelay.listen_port")
            .map(String::as_str),
        Some("6000")
    );
}

#[tokio::test]
async fn turnrelay_settings_section_renders_without_leaking_the_turn_password() {
    let dir = TempDir::new().unwrap();
    let state = fixture(&dir).await;
    assert_eq!(post(&state, VALID).await.status(), StatusCode::SEE_OTHER);
    let html = fetch_html(router(state), "/admin/servers/s0/protocols").await;
    assert!(html.contains(r#"action="/admin/servers/s0/turnrelay-config""#));
    assert!(html.contains(r#"name="turn_server""#));
    assert!(html.contains(r#"name="publish_targets""#));
    assert!(html.contains(r#"name="connections""#));
    assert!(!html.contains("fixture-pass"));
}

#[tokio::test]
async fn turnrelay_config_requires_admin_auth_and_same_origin() {
    const CHILD: &str = "VPNCTL_TURNRELAY_CONFIG_AUTH_SMOKE_CHILD";
    const USER: &str = "turnrelay-test-operator";
    const PASSWORD: &str = "fixture-only-password";
    if std::env::var_os(CHILD).is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "server_detail::turnrelay_settings::turnrelay_config_requires_admin_auth_and_same_origin",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("VPNCTLD_ADMIN_USER", USER)
            .env("VPNCTLD_ADMIN_PASSWORD", PASSWORD)
            .status()
            .unwrap();
        assert!(status.success(), "isolated TurnRelay auth smoke failed");
        return;
    }

    let dir = TempDir::new().unwrap();
    let state = fixture(&dir).await;
    let server = ServerId("s0".into());
    let before = state.inv.list_server_secrets(&server).await.unwrap();
    let baseline = state.inv.recent_audit(100).await.unwrap().len();
    let app = router(state.clone());
    let auth = format!("Basic {}", STANDARD.encode(format!("{USER}:{PASSWORD}")));

    let response = app
        .clone()
        .oneshot(add_same_origin(request()).body(Body::from(VALID)).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(PATH)
                .header(header::HOST, SAME_ORIGIN_HOST)
                .header(header::ORIGIN, "http://foreign.example")
                .header(header::AUTHORIZATION, &auth)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(VALID))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = app
        .oneshot(
            add_same_origin(request())
                .header(header::AUTHORIZATION, &auth)
                .body(Body::from(VALID))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_ne!(
        state.inv.list_server_secrets(&server).await.unwrap(),
        before
    );
    assert_eq!(
        state.inv.recent_audit(100).await.unwrap().len(),
        baseline + 1
    );
    assert_eq!(SAME_ORIGIN_HOST, "test.example");
}
