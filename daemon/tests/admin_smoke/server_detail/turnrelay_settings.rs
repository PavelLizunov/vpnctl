use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header, request::Builder};
use axum::response::Response;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use tempfile::TempDir;
use tower::ServiceExt;
use vpnctl_core::{KernelId, ProtocolId, RenderCtx, ServerId};
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
async fn turnrelay_section_renders_only_for_turnrelay_servers() {
    let dir = TempDir::new().unwrap();
    let mut plain = state(&dir).await;
    plain.registry = Arc::new(vpnctl_kernels::build_registry().unwrap());
    plain.inv.add_server(&naive_server("s0")).await.unwrap();
    let html = fetch_html(router(plain), "/admin/servers/s0/protocols").await;
    assert!(
        !html.contains(r#"action="/admin/servers/s0/turnrelay-config""#),
        "non-TurnRelay server must not render the TurnRelay settings form"
    );

    let dir = TempDir::new().unwrap();
    let mut kernel_only = state(&dir).await;
    kernel_only.registry = Arc::new(vpnctl_kernels::build_registry().unwrap());
    let mut server = naive_server("s0");
    server.kernels = vec![KernelId("turnrelay".into())];
    server.enabled_protocols.clear();
    kernel_only.inv.add_server(&server).await.unwrap();
    let html = fetch_html(router(kernel_only), "/admin/servers/s0/protocols").await;
    assert!(
        html.contains(r#"action="/admin/servers/s0/turnrelay-config""#),
        "a server carrying the TurnRelay kernel must expose the settings form"
    );
}

#[tokio::test]
async fn turnrelay_config_rejects_cross_protocol_udp_port_collisions() {
    use vpnctl_core::Server;

    let dir = TempDir::new().unwrap();
    let mut app_state = state(&dir).await;
    app_state.registry = Arc::new(vpnctl_kernels::build_registry().unwrap());
    let server = Server {
        id: ServerId("s0".into()),
        address: "192.0.2.10".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into()), KernelId("turnrelay".into())],
        enabled_protocols: vec![
            ProtocolId("hysteria2".into()),
            ProtocolId("turnrelay".into()),
        ],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    };
    app_state.inv.add_server(&server).await.unwrap();
    let before = app_state
        .inv
        .list_server_secrets(&ServerId("s0".into()))
        .await
        .unwrap();

    let collision = VALID.replace("listen_port=53492", "listen_port=8444");
    let response = post(&app_state, &collision).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        app_state
            .inv
            .list_server_secrets(&ServerId("s0".into()))
            .await
            .unwrap(),
        before,
        "a colliding UDP port must not be saved"
    );
}

#[tokio::test]
async fn service_active_requires_a_valid_certificate_fingerprint() {
    let dir = TempDir::new().unwrap();
    let state = fixture(&dir).await;
    let server_id = ServerId("s0".into());
    assert_eq!(post(&state, VALID).await.status(), StatusCode::SEE_OTHER);
    state
        .inv
        .set_server_secret(&server_id, "turnrelay.password", "exit-secret")
        .await
        .unwrap();
    let server = state.inv.get_server(&server_id).await.unwrap().unwrap();
    let secrets = state.inv.list_server_secrets(&server_id).await.unwrap();
    let digest =
        vpnctl_protocols::turnrelay_applied_digest(&RenderCtx::new(&server, &secrets)).unwrap();
    state
        .inv
        .set_server_secret(&server_id, "observed.turnrelay.applied", &digest)
        .await
        .unwrap();
    state
        .inv
        .record_node_health(
            &server_id,
            Some(true),
            Some(true),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(r#"{"turnrelay":{"active":true}}"#),
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

    let html = fetch_html(router(state.clone()), "/admin/servers/s0/protocols").await;
    assert!(!html.contains("Service active"));
    assert!(html.contains("Pending deploy"));

    state
        .inv
        .set_server_secret(
            &server_id,
            "observed.turnrelay.cert_sha256",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .await
        .unwrap();
    let html = fetch_html(router(state), "/admin/servers/s0/protocols").await;
    assert!(html.contains("Service active"));
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

async fn post_form(state: &AppState, uri: &str, form: &str) -> Response {
    router(state.clone())
        .oneshot(
            add_same_origin(Request::builder().method("POST").uri(uri))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form.to_owned()))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn add_turnrelay_node(state: &AppState, id: &str, address: &str, kind: &str) -> ServerId {
    let mut server = naive_server(id);
    server.address = address.to_owned();
    server.kernels = vec![KernelId(kind.into())];
    server.enabled_protocols.clear();
    state.inv.add_server(&server).await.unwrap();
    server.id
}

#[tokio::test]
async fn managed_turnrelay_wires_least_loaded_entries_and_syncs_allowlists() {
    let dir = TempDir::new().unwrap();
    let mut state = state(&dir).await;
    state.registry = Arc::new(vpnctl_kernels::build_registry().unwrap());
    let entry_a = add_turnrelay_node(&state, "entry-a", "192.0.2.11", "turnrelay-relay").await;
    let entry_b = add_turnrelay_node(&state, "entry-b", "192.0.2.12", "turnrelay-relay").await;
    let exit_a = add_turnrelay_node(&state, "exit-a", "198.51.100.21", "turnrelay").await;
    let exit_b = add_turnrelay_node(&state, "exit-b", "198.51.100.22", "turnrelay").await;
    let enable_a = "/admin/servers/exit-a/protocols/turnrelay/enable";

    let response = post_form(&state, enable_a, "").await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let rejected = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&rejected).contains("Enable turnrelay-relay"));

    // Reverse creation order so the first selection exercises the ID tie-break.
    for id in [&entry_b, &entry_a] {
        assert_eq!(
            post_form(
                &state,
                &format!("/admin/servers/{id}/protocols/turnrelay-relay/enable"),
                ""
            )
            .await
            .status(),
            StatusCode::SEE_OTHER
        );
        let credentials = state.inv.list_server_secrets(id).await.unwrap();
        assert_eq!(credentials["turnrelay_relay.username"].len(), 16);
        assert_eq!(credentials["turnrelay_relay.password"].len(), 32);
        assert!(
            credentials
                .get("turnrelay_relay.allowed_exits")
                .is_none_or(String::is_empty)
        );
    }
    for (exit, entry, server, ip) in [
        (&exit_a, &entry_a, "192.0.2.11:53491", "198.51.100.21"),
        (&exit_b, &entry_b, "192.0.2.12:53491", "198.51.100.22"),
    ] {
        assert_eq!(
            post_form(
                &state,
                &format!("/admin/servers/{exit}/protocols/turnrelay/enable"),
                ""
            )
            .await
            .status(),
            StatusCode::SEE_OTHER
        );
        let settings = state.inv.list_server_secrets(exit).await.unwrap();
        let relay = state.inv.list_server_secrets(entry).await.unwrap();
        assert_eq!(settings["turnrelay.relay_server_id"], entry.0);
        assert_eq!(settings["turnrelay.turn_server"], server);
        assert_eq!(
            settings["turnrelay.turn_username"],
            relay["turnrelay_relay.username"]
        );
        assert_eq!(
            settings["turnrelay.turn_password"],
            relay["turnrelay_relay.password"]
        );
        assert_eq!(settings["turnrelay.publish"], "vless+reality");
        assert_eq!(relay["turnrelay_relay.allowed_exits"], ip);
    }

    assert_eq!(
        post_form(
            &state,
            "/admin/servers/exit-a/turnrelay-config",
            "relay_server_id=entry-b&udp=true"
        )
        .await
        .status(),
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        state.inv.list_server_secrets(&entry_a).await.unwrap()["turnrelay_relay.allowed_exits"],
        ""
    );
    assert_eq!(
        state.inv.list_server_secrets(&entry_b).await.unwrap()["turnrelay_relay.allowed_exits"],
        "198.51.100.21,198.51.100.22"
    );

    assert_eq!(
        post_form(
            &state,
            "/admin/servers/entry-b/turnrelay-relay-config",
            "listen_port=54491"
        )
        .await
        .status(),
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        state.inv.list_server_secrets(&exit_a).await.unwrap()["turnrelay.turn_server"],
        "192.0.2.12:54491"
    );
    assert_eq!(
        state.inv.list_server_secrets(&exit_b).await.unwrap()["turnrelay.turn_server"],
        "192.0.2.12:54491"
    );

    assert_eq!(
        post_form(
            &state,
            "/admin/servers/exit-b/protocols/turnrelay/disable",
            ""
        )
        .await
        .status(),
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        state.inv.list_server_secrets(&entry_b).await.unwrap()["turnrelay_relay.allowed_exits"],
        "198.51.100.21"
    );
}

#[tokio::test]
async fn manual_turnrelay_endpoint_is_preserved_and_badges_include_both_topologies() {
    let dir = TempDir::new().unwrap();
    let mut state = state(&dir).await;
    state.registry = Arc::new(vpnctl_kernels::build_registry().unwrap());
    let entry = add_turnrelay_node(&state, "entry-a", "192.0.2.11", "turnrelay-relay").await;
    let exit = add_turnrelay_node(&state, "exit-a", "198.51.100.21", "turnrelay").await;
    let upstream = naive_server("detour-a");
    state.inv.add_server(&upstream).await.unwrap();
    for (id, name) in [
        (&entry, "Managed Gate"),
        (&exit, "Exit Cloud"),
        (&upstream.id, "Detour Gate"),
    ] {
        state
            .inv
            .set_server_display_name(id, Some(name))
            .await
            .unwrap();
    }
    assert_eq!(
        post_form(&state, "/admin/servers/exit-a/turnrelay-config", VALID)
            .await
            .status(),
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        post_form(
            &state,
            "/admin/servers/entry-a/protocols/turnrelay-relay/enable",
            ""
        )
        .await
        .status(),
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        post_form(
            &state,
            "/admin/servers/exit-a/protocols/turnrelay/enable",
            ""
        )
        .await
        .status(),
        StatusCode::SEE_OTHER
    );
    let manual = state.inv.list_server_secrets(&exit).await.unwrap();
    assert_eq!(manual["turnrelay.turn_server"], "turn.example.org:3478");
    assert_eq!(manual["turnrelay.turn_password"], "fixture-pass");
    assert!(!manual.contains_key("turnrelay.relay_server_id"));

    assert_eq!(
        post_form(
            &state,
            "/admin/servers/exit-a/turnrelay-config",
            "relay_server_id=entry-a"
        )
        .await
        .status(),
        StatusCode::SEE_OTHER
    );
    state
        .inv
        .set_client_detour_via_as("test", &entry, Some(&upstream.id))
        .await
        .unwrap();

    let app = router(state);
    for (locale, entry_text, exit_text) in [("en", "ENTRY", "EXIT"), ("ru", "ВХОД", "ВЫХОД")]
    {
        for path in ["/admin/", "/admin/servers", "/admin/servers/entry-a"] {
            let html = crate::common::fetch_html_with_cookie(
                app.clone(),
                path,
                &format!("vpnctl_lang={locale}"),
            )
            .await;
            assert!(
                html.contains(&format!("ed-role-badge--entry\">{entry_text}<")),
                "{path}"
            );
            assert!(
                html.contains(&format!("ed-role-badge--exit\">{exit_text}<")),
                "{path}"
            );
            assert!(html.contains("→ Exit Cloud"), "{path}");
            assert!(html.contains("← Detour Gate"), "{path}");
        }
        let html = crate::common::fetch_html_with_cookie(
            app.clone(),
            "/admin/servers/exit-a/protocols",
            &format!("vpnctl_lang={locale}"),
        )
        .await;
        assert!(html.contains("← Managed Gate"));
        assert!(html.contains(r#"name="relay_server_id""#));
        assert!(html.contains(r#"<option value="entry-a" selected>Managed Gate</option>"#));
    }
}

#[tokio::test]
async fn enabling_entry_uses_existing_host_matched_exit_and_keeps_manual_settings() {
    let dir = TempDir::new().unwrap();
    let mut state = state(&dir).await;
    state.registry = Arc::new(vpnctl_kernels::build_registry().unwrap());
    let entry = add_turnrelay_node(&state, "entry-a", "192.0.2.11", "turnrelay-relay").await;
    let exit = add_turnrelay_node(&state, "exit-a", "198.51.100.21", "turnrelay").await;
    let manual = VALID.replace("turn.example.org%3A3478", "192.0.2.11%3A53491");
    for (path, form) in [
        ("/admin/servers/exit-a/turnrelay-config", manual.as_str()),
        ("/admin/servers/exit-a/protocols/turnrelay/enable", ""),
        (
            "/admin/servers/entry-a/protocols/turnrelay-relay/enable",
            "",
        ),
    ] {
        assert_eq!(
            post_form(&state, path, form).await.status(),
            StatusCode::SEE_OTHER,
            "{path}"
        );
    }

    let relay = state.inv.list_server_secrets(&entry).await.unwrap();
    assert_eq!(relay["turnrelay_relay.allowed_exits"], "198.51.100.21");
    let html = fetch_html(router(state.clone()), "/admin/servers/entry-a/protocols").await;
    assert!(html.contains("TURNRELAY RELAY (ENTRY)"));
    assert!(html.contains("→ EXIT-A"));
    assert!(html.contains(&format!(
        "value=\"{}\" readonly",
        relay["turnrelay_relay.username"]
    )));
    assert!(!html.contains(&relay["turnrelay_relay.password"]));

    assert_eq!(
        post_form(
            &state,
            "/admin/servers/entry-a/turnrelay-relay-config",
            "listen_port=55491"
        )
        .await
        .status(),
        StatusCode::SEE_OTHER
    );
    let settings = state.inv.list_server_secrets(&exit).await.unwrap();
    assert_eq!(settings["turnrelay.turn_server"], "192.0.2.11:53491");
    assert_eq!(settings["turnrelay.turn_password"], "fixture-pass");
}
