#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Contract tests for the per-server desktop subscription policy.
//!
//! A server can be pinned to the exact VPNRouter desktop core build. While the
//! pin is set, the node must stay out of every ordinary subscription surface
//! and must reach `/api/v1/app/config/{device_id}` only for a granted device
//! whose VPNRouter identity headers match the pin exactly. Clearing the pin
//! returns the node to ordinary behaviour.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use http_body_util::BodyExt;
use serde_json::Value;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{KernelId, ProtocolId, Registry, Server, ServerId, User, UserId};
use vpnctl_inventory::SqliteInventory;
use vpnctl_kernels::SingBox;
use vpnctl_protocols::VlessReality;
use vpnctld::rate_limit::RateLimiter;
use vpnctld::{AppState, router};

const DEVICE_ID: &str = "a92b915032b48a2ed45ef72f4171e5f4";
const OPEN_ONLY_DEVICE_ID: &str = "deadbeefdeadbeefdeadbeefdeadbeef";
const REQUIRED_CORE: &str = "1.14.4-vpnctl.3";
const LOCKED_SERVER: &str = "desk-locked";
const OPEN_SERVER: &str = "desk-open";
const LOCKED_HOST: &str = "desk-locked.example.com";
const OPEN_HOST: &str = "desk-open.example.com";
const PLATFORM_HEADER: &str = "x-vpnrouter-platform";
const CORE_HEADER: &str = "x-vpnrouter-core-version";
const SAME_ORIGIN_HOST: &str = "test.example";
const USER_AGENT_HEADER: &str = "user-agent";
const DESKTOP_UA: &str = "VPNRouter";
const BROWSER_UA: &str = "Mozilla/5.0 Firefox/138.0";
const LEGACY_UA: &str = "v2rayN/6.62";

/// Policy input the admin form must refuse. Each value is malformed for a
/// managed core version; the empty string is the documented clear operation
/// and is covered separately.
const INVALID_CORES: [&str; 5] = [
    "not-a-version",
    "1.14.4",
    "1.14.4-vpnctl",
    "1.14.4-vpnctl.x",
    "3000000000.0.0-vpnctl.3",
];

type Headers<'a> = Vec<(&'a str, &'a str)>;

async fn seed(dir: &TempDir) -> (AppState, String) {
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    let mut registry = Registry::new();
    registry.register_kernel(Box::new(SingBox::new())).unwrap();
    registry
        .register_protocol(Box::new(VlessReality::new()))
        .unwrap();

    for server_id in [LOCKED_SERVER, OPEN_SERVER] {
        let server = Server {
            id: ServerId(server_id.into()),
            address: format!("{server_id}.example.com"),
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
        inv.set_server_secret(&server.id, "vless.public_key", &format!("PUB_{server_id}"))
            .await
            .unwrap();
        inv.set_server_secret(&server.id, "vless.short_id", "12345678")
            .await
            .unwrap();
    }

    let granted = User {
        id: UserId("desktop-tester".into()),
        uuid: "11111111-2222-3333-4444-555555555555".into(),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    };
    inv.add_user(&granted).await.unwrap();
    inv.set_vpn_router_device_id(&granted.id, DEVICE_ID)
        .await
        .unwrap();
    for server_id in [LOCKED_SERVER, OPEN_SERVER] {
        inv.grant(&granted.id, &ServerId(server_id.into()))
            .await
            .unwrap();
    }

    // Registered device with a grant on the unrestricted node only. The policy
    // node must never appear for it, no matter how exact its identity headers.
    let open_only = User {
        id: UserId("desktop-open-only".into()),
        uuid: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".into(),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    };
    inv.add_user(&open_only).await.unwrap();
    inv.set_vpn_router_device_id(&open_only.id, OPEN_ONLY_DEVICE_ID)
        .await
        .unwrap();
    inv.grant(&open_only.id, &ServerId(OPEN_SERVER.into()))
        .await
        .unwrap();

    let sub_token = inv
        .get_user(&granted.id)
        .await
        .unwrap()
        .unwrap()
        .sub_token
        .unwrap();

    let limiter = Arc::new(RateLimiter::new(100.0, 0.0, Duration::from_secs(60)));
    let (state, _writer) =
        vpnctld::make_app_state_with_rate_limiter(inv, Arc::new(registry), limiter);
    (state, sub_token)
}

fn form_encode(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'_' | b'~' => {
                encoded.push(char::from(byte));
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

async fn post_core_version(
    state: &AppState,
    server: &str,
    core_version: &str,
) -> (StatusCode, Option<String>) {
    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/admin/servers/{server}/desktop-subscription"))
                .header(header::HOST, SAME_ORIGIN_HOST)
                .header(header::ORIGIN, format!("http://{SAME_ORIGIN_HOST}"))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "core_version={}",
                    form_encode(core_version)
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    (status, location)
}

fn assert_setup_redirect(status: StatusCode, location: Option<String>, server: &str) {
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "saving the desktop core must redirect"
    );
    let location = location.expect("303 must carry a Location header");
    let path = location
        .split(['?', '#'])
        .next()
        .unwrap_or(location.as_str());
    assert_eq!(
        path,
        format!("/admin/servers/{server}/setup"),
        "saving the desktop core must land on the server setup page"
    );
}

async fn pin_locked(state: &AppState) {
    let (status, location) = post_core_version(state, LOCKED_SERVER, REQUIRED_CORE).await;
    assert_setup_redirect(status, location, LOCKED_SERVER);
}

async fn get_with_headers(
    state: &AppState,
    path: &str,
    headers: &[(&str, &str)],
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut request = Request::builder().uri(path);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = router(state.clone())
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let response_headers = response.headers().clone();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, response_headers, body.to_vec())
}

async fn app_config(
    state: &AppState,
    device_id: &str,
    headers: &[(&str, &str)],
) -> (StatusCode, Vec<u8>) {
    let (status, _headers, body) =
        get_with_headers(state, &format!("/api/v1/app/config/{device_id}"), headers).await;
    (status, body)
}

fn desktop_identity(platform: &str) -> Vec<(&str, &str)> {
    vec![
        (USER_AGENT_HEADER, DESKTOP_UA),
        (PLATFORM_HEADER, platform),
        (CORE_HEADER, REQUIRED_CORE),
    ]
}

/// Reads the base64 link list out of an app-config response, accepting both
/// the raw (VPN client UA) and JSON-wrapped (browser UA) shapes.
fn app_config_lines(body: &[u8]) -> Vec<String> {
    let raw = std::str::from_utf8(body).expect("app config body must be utf-8");
    let encoded = if raw.trim_start().starts_with('{') {
        let value: Value = serde_json::from_str(raw).expect("app config wrapper must be JSON");
        value
            .get("config")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    } else {
        raw.trim().to_owned()
    };
    let decoded = BASE64_STANDARD
        .decode(encoded.as_bytes())
        .unwrap_or_else(|_| encoded.clone().into_bytes());
    String::from_utf8(decoded)
        .expect("decoded app config must be utf-8")
        .lines()
        .map(str::to_owned)
        .collect()
}

fn server_visible(lines: &[String], server: &str) -> bool {
    let host = format!("{server}.example.com");
    lines.iter().any(|line| line.contains(&host))
}

fn assert_server_presence(lines: &[String], server: &str, expected: bool, context: &str) {
    assert_eq!(
        server_visible(lines, server),
        expected,
        "{context}: unexpected presence for {server} in {lines:?}"
    );
}

async fn assert_app_config_presence(
    state: &AppState,
    device_id: &str,
    headers: &[(&str, &str)],
    locked_visible: bool,
    context: &str,
) {
    let (status, body) = app_config(state, device_id, headers).await;
    assert_eq!(status, StatusCode::OK, "{context}");
    let lines = app_config_lines(&body);
    assert_server_presence(&lines, OPEN_SERVER, true, context);
    assert_server_presence(&lines, LOCKED_SERVER, locked_visible, context);
}

async fn sub_text(state: &AppState, uri: &str, user_agent: &str) -> (StatusCode, String) {
    let (status, headers, body) =
        get_with_headers(state, uri, &[(USER_AGENT_HEADER, user_agent)]).await;
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let raw = String::from_utf8(body).expect("subscription body must be utf-8");
    if content_type.starts_with("text/plain") {
        if let Ok(decoded) = BASE64_STANDARD.decode(raw.trim().as_bytes()) {
            if let Ok(text) = String::from_utf8(decoded) {
                return (status, text);
            }
        }
    }
    (status, raw)
}

async fn legacy_open_link(state: &AppState, token: &str) -> String {
    let (status, text) = sub_text(state, &format!("/sub/{token}"), LEGACY_UA).await;
    assert_eq!(status, StatusCode::OK);
    text.lines()
        .find(|line| line.contains(OPEN_HOST))
        .unwrap_or_else(|| panic!("unrestricted node missing from legacy /sub: {text}"))
        .to_owned()
}

#[derive(Debug)]
struct SubSurface {
    label: &'static str,
    uri: String,
    user_agent: &'static str,
}

/// Every ordinary subscription surface the operator can hand out. None of
/// them may ever carry a server pinned to the desktop core.
fn subscription_surfaces(token: &str) -> Vec<SubSurface> {
    vec![
        SubSurface {
            label: "legacy /sub links",
            uri: format!("/sub/{token}"),
            user_agent: LEGACY_UA,
        },
        SubSurface {
            label: "/sub links for the VPNRouter user agent",
            uri: format!("/sub/{token}"),
            user_agent: DESKTOP_UA,
        },
        SubSurface {
            label: "/sub?format=sing-box",
            uri: format!("/sub/{token}?format=sing-box"),
            user_agent: LEGACY_UA,
        },
        SubSurface {
            label: "/sub?format=mihomo",
            uri: format!("/sub/{token}?format=mihomo"),
            user_agent: LEGACY_UA,
        },
        SubSurface {
            label: "/api/v1/sub (mihomo)",
            uri: format!("/api/v1/sub/{token}"),
            user_agent: LEGACY_UA,
        },
        SubSurface {
            label: "/api/v1/sub?format=sing-box",
            uri: format!("/api/v1/sub/{token}?format=sing-box"),
            user_agent: LEGACY_UA,
        },
        SubSurface {
            label: "/api/v1/sub?format=mihomo",
            uri: format!("/api/v1/sub/{token}?format=mihomo"),
            user_agent: LEGACY_UA,
        },
    ]
}

#[tokio::test]
async fn desktop_core_setting_is_saved_and_redirects_to_setup() {
    let dir = TempDir::new().unwrap();
    let (state, _token) = seed(&dir).await;

    pin_locked(&state).await;

    assert_app_config_presence(
        &state,
        DEVICE_ID,
        &desktop_identity("windows"),
        true,
        "pinned server must reach the matching desktop identity",
    )
    .await;
}

#[tokio::test]
async fn desktop_identity_admits_the_policy_server_on_every_supported_platform() {
    let dir = TempDir::new().unwrap();
    let (state, _token) = seed(&dir).await;
    pin_locked(&state).await;

    for platform in ["windows", "macos", "linux"] {
        assert_app_config_presence(
            &state,
            DEVICE_ID,
            &desktop_identity(platform),
            true,
            platform,
        )
        .await;
    }
}

#[tokio::test]
async fn desktop_identity_mismatches_hide_only_the_policy_server() {
    let dir = TempDir::new().unwrap();
    let (state, _token) = seed(&dir).await;
    pin_locked(&state).await;

    let mismatches: Vec<(&str, Headers<'_>)> = vec![
        (
            "missing platform and core headers",
            vec![(USER_AGENT_HEADER, DESKTOP_UA)],
        ),
        (
            "missing platform header",
            vec![
                (USER_AGENT_HEADER, DESKTOP_UA),
                (CORE_HEADER, REQUIRED_CORE),
            ],
        ),
        (
            "missing core version header",
            vec![
                (USER_AGENT_HEADER, DESKTOP_UA),
                (PLATFORM_HEADER, "windows"),
            ],
        ),
        (
            "old core version",
            vec![
                (USER_AGENT_HEADER, DESKTOP_UA),
                (PLATFORM_HEADER, "windows"),
                (CORE_HEADER, "1.14.4-vpnctl.2"),
            ],
        ),
        (
            "different core version",
            vec![
                (USER_AGENT_HEADER, DESKTOP_UA),
                (PLATFORM_HEADER, "windows"),
                (CORE_HEADER, "1.15.0-vpnctl.3"),
            ],
        ),
        (
            "android platform",
            vec![
                (USER_AGENT_HEADER, DESKTOP_UA),
                (PLATFORM_HEADER, "android"),
                (CORE_HEADER, REQUIRED_CORE),
            ],
        ),
        (
            "unsupported platform",
            vec![
                (USER_AGENT_HEADER, DESKTOP_UA),
                (PLATFORM_HEADER, "ios"),
                (CORE_HEADER, REQUIRED_CORE),
            ],
        ),
        (
            "duplicate platform header",
            vec![
                (USER_AGENT_HEADER, DESKTOP_UA),
                (PLATFORM_HEADER, "windows"),
                (PLATFORM_HEADER, "windows"),
                (CORE_HEADER, REQUIRED_CORE),
            ],
        ),
        (
            "duplicate core version header",
            vec![
                (USER_AGENT_HEADER, DESKTOP_UA),
                (PLATFORM_HEADER, "windows"),
                (CORE_HEADER, REQUIRED_CORE),
                (CORE_HEADER, REQUIRED_CORE),
            ],
        ),
        (
            "browser user agent",
            vec![
                (USER_AGENT_HEADER, BROWSER_UA),
                (PLATFORM_HEADER, "windows"),
                (CORE_HEADER, REQUIRED_CORE),
            ],
        ),
        (
            "generic VPN client user agent",
            vec![
                (USER_AGENT_HEADER, LEGACY_UA),
                (PLATFORM_HEADER, "windows"),
                (CORE_HEADER, REQUIRED_CORE),
            ],
        ),
    ];

    for (label, headers) in &mismatches {
        assert_app_config_presence(&state, DEVICE_ID, headers, false, label).await;
    }
}

#[tokio::test]
async fn desktop_identity_does_not_bypass_grants() {
    let dir = TempDir::new().unwrap();
    let (state, _token) = seed(&dir).await;
    pin_locked(&state).await;

    let granted = state
        .inv
        .subscription_servers_for_user(&UserId("desktop-tester".into()))
        .await
        .unwrap();
    assert!(granted.iter().any(|server| server.id.0 == LOCKED_SERVER));

    assert_app_config_presence(
        &state,
        DEVICE_ID,
        &desktop_identity("windows"),
        true,
        "granted desktop device",
    )
    .await;
    assert_app_config_presence(
        &state,
        OPEN_ONLY_DEVICE_ID,
        &desktop_identity("macos"),
        false,
        "device without a grant on the pinned server",
    )
    .await;
}

#[tokio::test]
async fn invalid_core_version_is_rejected_without_creating_a_policy() {
    let dir = TempDir::new().unwrap();
    let (state, token) = seed(&dir).await;

    for invalid in INVALID_CORES {
        let (status, _location) = post_core_version(&state, LOCKED_SERVER, invalid).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "core version {invalid:?} must be rejected"
        );

        let (status, text) = sub_text(&state, &format!("/sub/{token}"), LEGACY_UA).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            text.contains(LOCKED_HOST),
            "rejected version {invalid:?} must not create a policy"
        );
        assert!(text.contains(OPEN_HOST));
    }

    let browser: Headers<'_> = vec![(USER_AGENT_HEADER, BROWSER_UA)];
    let (status, body) = app_config(&state, DEVICE_ID, &browser).await;
    assert_eq!(status, StatusCode::OK);
    let lines = app_config_lines(&body);
    assert_server_presence(
        &lines,
        LOCKED_SERVER,
        true,
        "rejected versions leave the server ordinary",
    );
}

#[tokio::test]
async fn invalid_core_version_does_not_change_an_existing_policy() {
    let dir = TempDir::new().unwrap();
    let (state, token) = seed(&dir).await;
    pin_locked(&state).await;

    let identity = desktop_identity("windows");
    let (status, body) = app_config(&state, DEVICE_ID, &identity).await;
    assert_eq!(status, StatusCode::OK);
    let before = app_config_lines(&body);

    for invalid in INVALID_CORES {
        let (status, _location) = post_core_version(&state, LOCKED_SERVER, invalid).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "core version {invalid:?} must be rejected"
        );

        let (status, body) = app_config(&state, DEVICE_ID, &identity).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            app_config_lines(&body),
            before,
            "rejected version {invalid:?} must not mutate the existing policy"
        );
    }

    let (status, text) = sub_text(&state, &format!("/sub/{token}"), LEGACY_UA).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !text.contains(LOCKED_HOST),
        "the original policy must still hide the node from ordinary /sub"
    );
}

#[tokio::test]
async fn ordinary_subscription_formats_exclude_the_policy_server() {
    let dir = TempDir::new().unwrap();
    let (state, token) = seed(&dir).await;
    let surfaces = subscription_surfaces(&token);

    for surface in &surfaces {
        let (status, text) = sub_text(&state, &surface.uri, surface.user_agent).await;
        assert_eq!(status, StatusCode::OK, "{}", surface.label);
        assert!(
            text.contains(LOCKED_HOST),
            "{} baseline must render the future policy server",
            surface.label
        );
        assert!(
            text.contains(OPEN_HOST),
            "{} baseline must render the unrestricted server",
            surface.label
        );
    }
    let open_link_before = legacy_open_link(&state, &token).await;

    pin_locked(&state).await;

    for surface in &surfaces {
        let (status, text) = sub_text(&state, &surface.uri, surface.user_agent).await;
        assert_eq!(status, StatusCode::OK, "{}", surface.label);
        assert!(
            !text.contains(LOCKED_HOST),
            "{} must exclude the desktop-only server",
            surface.label
        );
        assert!(
            text.contains(OPEN_HOST),
            "{} must keep the unrestricted server",
            surface.label
        );
    }
    assert_eq!(
        legacy_open_link(&state, &token).await,
        open_link_before,
        "unrestricted node bytes must not change when a policy is added"
    );
}

#[tokio::test]
async fn empty_core_version_clears_the_desktop_policy() {
    let dir = TempDir::new().unwrap();
    let (state, token) = seed(&dir).await;
    let open_link_before_policy = legacy_open_link(&state, &token).await;

    pin_locked(&state).await;

    let (status, text) = sub_text(&state, &format!("/sub/{token}"), LEGACY_UA).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !text.contains(LOCKED_HOST),
        "a pinned server must leave ordinary /sub before the policy is cleared"
    );

    let (status, location) = post_core_version(&state, LOCKED_SERVER, "").await;
    assert_setup_redirect(status, location, LOCKED_SERVER);

    let (status, text) = sub_text(&state, &format!("/sub/{token}"), LEGACY_UA).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        text.contains(LOCKED_HOST),
        "clearing the policy must return the node to ordinary /sub"
    );
    assert!(text.contains(OPEN_HOST));
    assert_eq!(
        legacy_open_link(&state, &token).await,
        open_link_before_policy,
        "clearing must not alter the unrestricted node from its pre-policy bytes"
    );

    let browser: Headers<'_> = vec![(USER_AGENT_HEADER, BROWSER_UA)];
    assert_app_config_presence(
        &state,
        DEVICE_ID,
        &browser,
        true,
        "cleared policy returns the node to ordinary browser app config",
    )
    .await;

    let ua_only: Headers<'_> = vec![(USER_AGENT_HEADER, DESKTOP_UA)];
    assert_app_config_presence(
        &state,
        DEVICE_ID,
        &ua_only,
        true,
        "cleared policy no longer requires the desktop identity headers",
    )
    .await;

    assert_app_config_presence(
        &state,
        DEVICE_ID,
        &desktop_identity("linux"),
        true,
        "cleared policy still serves the desktop identity",
    )
    .await;
}
