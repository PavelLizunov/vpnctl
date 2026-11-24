//! Independent HTTP contract tests for
//! `POST /api/v1/assistant/vpnrouter/source-diagnosis`.
//!
//! Derived only from `docs/specs/vpnrouter-source-diagnosis.md` and the public
//! NINA/VPNRouter transport contract. The tests drive the public daemon router
//! over HTTP and never inspect the handler implementation.
//!
//! Each test runs in a child copy of this test binary so gateway configuration
//! is process-local. The child removes every inherited `VPNCTLD_*` setting
//! before the router is built, so ambient deployment configuration cannot
//! change the contract under test.
//!
//! CI also provisions a root-owned synthetic catalog for the registered-build test.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::Json;
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, RETRY_AFTER};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::Response;
use axum::routing::post;
use serde_json::{Value, json};
use tempfile::TempDir;
use tower::ServiceExt;
use vpnctl_core::{User, UserId};
use vpnctl_inventory::SqliteInventory;

const PATH: &str = "/api/v1/assistant/vpnrouter/source-diagnosis";
const STEP_PATH: &str = "/api/v1/assistant/vpnrouter/step";
const PLAN_PATH: &str = "/api/v1/assistant/vpnrouter/plan";
const IDENTITY: &str = "x-vpnctl-identity";

const CHILD_ENV: &str = "VPNCTL_SOURCE_DIAGNOSIS_SPEC_CHILD";
const SENTINEL_ENV: &str = "VPNCTL_SOURCE_DIAGNOSIS_SPEC_SENTINEL";
const GATEWAY_URL_ENV: &str = "VPNCTLD_VPNROUTER_GATEWAY_URL";
const GATEWAY_MODEL_ENV: &str = "VPNCTLD_VPNROUTER_GATEWAY_MODEL";
const GATEWAY_KEY_ENV: &str = "VPNCTLD_VPNROUTER_GATEWAY_KEY_FILE";
const MODEL: &str = "synthetic-source-diagnosis-model";
const GATEWAY_KEY: &str = "synthetic-source-diagnosis-gateway-key";

const COMMIT_A: &str = "0123456789abcdef0123456789abcdef01234567";
const COMMIT_B: &str = "fedcba9876543210fedcba9876543210fedcba98";

/// Run the current test in an isolated process with a controlled gateway.
///
/// Returns `Some` in the parent after the child passed, and `None` in the
/// child where the test body continues. `Gateway::Fixture` starts a loopback
/// upstream before the child starts and keeps it alive for assertions.
async fn isolate(test: &'static str, gateway: Gateway) -> Option<ParentRun> {
    isolate_with_catalog(test, gateway, None).await
}

async fn isolate_with_catalog(
    test: &'static str,
    gateway: Gateway,
    catalog: Option<&std::ffi::OsStr>,
) -> Option<ParentRun> {
    if std::env::var_os(CHILD_ENV).is_some() {
        if let Some(path) = std::env::var_os(SENTINEL_ENV) {
            std::fs::write(path, b"ran").expect("write child sentinel");
        }
        return None;
    }

    let sentinel_directory = tempfile::tempdir().expect("sentinel directory");
    let sentinel = sentinel_directory.path().join("ran");
    let mut command = Command::new(std::env::current_exe().expect("current test binary"));
    command.args(["--include-ignored", "--exact", test, "--nocapture"]);
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("VPNCTLD_") {
            command.env_remove(key);
        }
    }
    if let Some(catalog) = catalog {
        command.env("VPNCTLD_VPNROUTER_SOURCE_CATALOG", catalog);
    }
    command.env(CHILD_ENV, "1");
    command.env(SENTINEL_ENV, &sentinel);

    let mut key_directory = None;
    let upstream = match gateway {
        Gateway::Missing => None,
        Gateway::Fixture(responses) => {
            let upstream = Upstream::start(responses).await;
            command.env(
                GATEWAY_URL_ENV,
                format!("{}/synthetic/chat/completions", upstream.base_url),
            );
            write_key(&mut command, &mut key_directory);
            Some(upstream)
        }
    };

    let status = tokio::task::spawn_blocking(move || {
        let _key_directory = key_directory;
        command.status()
    })
    .await
    .expect("join isolated contract test")
    .expect("run isolated contract test");
    assert!(status.success(), "isolated contract test {test} failed");
    assert!(
        sentinel.exists(),
        "isolated contract test {test} did not run"
    );
    Some(ParentRun { upstream })
}

fn write_key(command: &mut Command, directory: &mut Option<TempDir>) {
    let dir = tempfile::tempdir().expect("gateway key directory");
    let path = dir.path().join("gateway.key");
    std::fs::write(&path, GATEWAY_KEY).expect("write gateway key");
    command.env(GATEWAY_MODEL_ENV, MODEL);
    command.env(GATEWAY_KEY_ENV, path);
    *directory = Some(dir);
}

enum Gateway {
    Missing,
    Fixture(Vec<(StatusCode, Value)>),
}

struct ParentRun {
    upstream: Option<Upstream>,
}

struct Upstream {
    base_url: String,
    requests: Arc<Mutex<Vec<(HeaderMap, Value)>>>,
    server: tokio::task::JoinHandle<()>,
}

impl Upstream {
    async fn start(responses: Vec<(StatusCode, Value)>) -> Self {
        assert!(!responses.is_empty());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let index = Arc::new(AtomicUsize::new(0));
        let app = Router::new().route(
            "/synthetic/chat/completions",
            post({
                let requests = Arc::clone(&requests);
                let responses = responses.clone();
                let index = Arc::clone(&index);
                move |headers: HeaderMap, Json(payload): Json<Value>| {
                    let requests = Arc::clone(&requests);
                    let responses = responses.clone();
                    let index = Arc::clone(&index);
                    async move {
                        let position = index.fetch_add(1, Ordering::SeqCst);
                        let (status, body) = responses[position.min(responses.len() - 1)].clone();
                        requests.lock().unwrap().push((headers, payload));
                        (status, Json(body))
                    }
                }
            }),
        );
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self {
            base_url,
            requests,
            server,
        }
    }

    fn requests(&self) -> Vec<(HeaderMap, Value)> {
        self.requests.lock().unwrap().clone()
    }
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.server.abort();
    }
}

struct Fixture {
    app: Router,
    inventory: SqliteInventory,
    writer: tokio::task::JoinHandle<()>,
    _directory: TempDir,
}

impl Fixture {
    async fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let inventory = SqliteInventory::open(&directory.path().join("inventory.db"))
            .await
            .unwrap();
        let registry = Arc::new(vpnctl_kernels::build_registry().unwrap());
        let (state, writer) = vpnctld::make_app_state_for_tests(inventory.clone(), registry);
        Self {
            app: vpnctld::router(state),
            inventory,
            writer,
            _directory: directory,
        }
    }

    async fn user(&self, number: u32, disabled: bool) -> User {
        let user = User {
            id: UserId(format!("source-spec-{number}")),
            uuid: format!("00000000-0000-4000-8000-{number:012}"),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: Some(format!("synthetic-source-subscription-{number}")),
            vpn_router_device_id: Some(format!("{number:032x}")),
            disabled,
        };
        self.inventory.add_user(&user).await.unwrap();
        user
    }

    async fn send(&self, request: Request<Body>) -> Response {
        self.app.clone().oneshot(request).await.unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.writer.abort();
    }
}

fn credentials(user: &User) -> [(&'static str, &str); 2] {
    [
        ("subscription", user.sub_token.as_deref().unwrap()),
        ("device", user.vpn_router_device_id.as_deref().unwrap()),
    ]
}

fn request_at(path: &str, identity: &str, credential: &str, body: String) -> Request<Body> {
    Request::post(path)
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, format!("Bearer {credential}"))
        .header(IDENTITY, identity)
        .body(Body::from(body))
        .unwrap()
}

fn request(identity: &str, credential: &str, body: String) -> Request<Body> {
    request_at(PATH, identity, credential, body)
}

async fn send(fixture: &Fixture, request: Request<Body>) -> (StatusCode, HeaderMap, String) {
    let response = fixture.send(request).await;
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    (status, headers, String::from_utf8(bytes.to_vec()).unwrap())
}

fn assert_no_store(headers: &HeaderMap) {
    let value = headers.get(CACHE_CONTROL).expect("Cache-Control header");
    assert!(
        value
            .to_str()
            .unwrap()
            .split(',')
            .any(|part| part.trim() == "no-store"),
        "Cache-Control: {value:?}"
    );
}

fn assert_json(text: &str, expected: &Value) {
    assert_eq!(
        &serde_json::from_str::<Value>(text).unwrap(),
        expected,
        "body: {text}"
    );
}

fn assert_error(
    status: StatusCode,
    headers: &HeaderMap,
    text: &str,
    expected_status: StatusCode,
    code: &str,
) {
    assert_eq!(status, expected_status, "body: {text}");
    assert_no_store(headers);
    assert_json(text, &json!({"error": code}));
}

fn valid_body() -> Value {
    json!({
        "schema": 1,
        "locale": "ru",
        "version": "2.51.0-r2",
        "commit": COMMIT_A,
        "platform": "windows",
        "arch": "x64",
        "crash": {
            "fatal": true,
            "fault": "io",
            "area": "settings",
            "signal": "none"
        }
    })
}

fn unknown_build() -> Value {
    json!({"schema": 1, "result": {"operation": "unknown_build"}})
}

fn set(mut body: Value, field: &str, value: Value) -> Value {
    body[field] = value;
    body
}

fn remove(mut body: Value, field: &str) -> Value {
    body.as_object_mut().unwrap().remove(field);
    body
}

fn remove_crash(mut body: Value, field: &str) -> Value {
    body["crash"].as_object_mut().unwrap().remove(field);
    body
}

async fn expect_bad_request(fixture: &Fixture, number: u32, case: &str, body: String) {
    let user = fixture.user(number, false).await;
    let [(identity, credential), _] = credentials(&user);
    let (status, headers, text) = send(fixture, request(identity, credential, body)).await;
    assert_error(
        status,
        &headers,
        &text,
        StatusCode::BAD_REQUEST,
        "invalid_report",
    );
    assert!(!text.contains(credential), "{case}: credential leaked");
}

async fn expect_unknown_build(fixture: &Fixture, number: u32, case: &str, body: Value) {
    let user = fixture.user(number, false).await;
    let [(identity, credential), _] = credentials(&user);
    let (status, headers, text) =
        send(fixture, request(identity, credential, body.to_string())).await;
    assert_eq!(status, StatusCode::OK, "{case}: {text}");
    assert_no_store(&headers);
    assert_json(&text, &unknown_build());
    assert!(!text.contains(credential), "{case}: credential leaked");
}

fn source_reply() -> Value {
    json!({
        "operation": "source_diagnosis",
        "hypothesis": "The settings screen failed while reading the connection configuration.",
        "basis": "The classified evidence points at the settings area with an I/O fault.",
        "confidence": "low",
        "check": "review_settings",
        "citations": [{
            "path": "VPNRouter.Core/Services/Settings.cs",
            "first": 15,
            "last": 15
        }]
    })
}

fn completion(content: &Value) -> Value {
    json!({"choices": [{"message": {"content": content.to_string()}}]})
}

fn completion_response(content: &Value) -> (StatusCode, Value) {
    (StatusCode::OK, completion(content))
}

fn step_body() -> Value {
    json!({
        "schema": 2,
        "locale": "en",
        "goal": "Enable VPN",
        "connected": false,
        "busy": false,
        "simple": true,
        "controls": [
            {"id": 1, "name": "SmpToggleConnectCommand", "kind": "press"}
        ]
    })
}

fn plan_body() -> Value {
    json!({
        "schema": 1,
        "locale": "en",
        "goal": "Route only Chrome through the VPN.",
        "target_available": true
    })
}

#[tokio::test]
async fn valid_subscription_and_device_credentials_reach_the_unknown_build_result() {
    if let Some(run) = isolate(
        "valid_subscription_and_device_credentials_reach_the_unknown_build_result",
        Gateway::Fixture(vec![completion_response(&source_reply())]),
    )
    .await
    {
        assert!(run.upstream.unwrap().requests().is_empty());
        return;
    }

    let fixture = Fixture::new().await;
    let user = fixture.user(0x101, false).await;
    let body = valid_body().to_string();

    for (identity, credential) in credentials(&user) {
        let (status, headers, text) =
            send(&fixture, request(identity, credential, body.clone())).await;
        assert_eq!(status, StatusCode::OK, "{identity}: {text}");
        assert_no_store(&headers);
        assert_json(&text, &unknown_build());
        assert!(!text.contains(credential));
    }
}

#[tokio::test]
async fn malformed_unknown_and_duplicate_credentials_are_unauthorized() {
    if let Some(run) = isolate(
        "malformed_unknown_and_duplicate_credentials_are_unauthorized",
        Gateway::Fixture(vec![completion_response(&source_reply())]),
    )
    .await
    {
        assert!(run.upstream.unwrap().requests().is_empty());
        return;
    }

    let fixture = Fixture::new().await;
    let user = fixture.user(0x102, false).await;
    let [(identity, credential), _] = credentials(&user);
    let body = valid_body().to_string();
    let unknown = "synthetic-unknown-source-diagnosis-credential";

    let cases = vec![
        (
            "missing identity",
            Request::post(PATH)
                .header(CONTENT_TYPE, "application/json")
                .header(AUTHORIZATION, format!("Bearer {credential}"))
                .body(Body::from(body.clone()))
                .unwrap(),
        ),
        (
            "missing authorization",
            Request::post(PATH)
                .header(CONTENT_TYPE, "application/json")
                .header(IDENTITY, identity)
                .body(Body::from(body.clone()))
                .unwrap(),
        ),
        (
            "empty bearer",
            Request::post(PATH)
                .header(CONTENT_TYPE, "application/json")
                .header(AUTHORIZATION, "Bearer ")
                .header(IDENTITY, identity)
                .body(Body::from(body.clone()))
                .unwrap(),
        ),
        (
            "bearer without a space",
            Request::post(PATH)
                .header(CONTENT_TYPE, "application/json")
                .header(AUTHORIZATION, "Bearer")
                .header(IDENTITY, identity)
                .body(Body::from(body.clone()))
                .unwrap(),
        ),
        (
            "wrong authorization scheme",
            Request::post(PATH)
                .header(CONTENT_TYPE, "application/json")
                .header(AUTHORIZATION, format!("Basic {credential}"))
                .header(IDENTITY, identity)
                .body(Body::from(body.clone()))
                .unwrap(),
        ),
        (
            "unknown credential",
            Request::post(PATH)
                .header(CONTENT_TYPE, "application/json")
                .header(AUTHORIZATION, format!("Bearer {unknown}"))
                .header(IDENTITY, identity)
                .body(Body::from(body.clone()))
                .unwrap(),
        ),
        (
            "unknown identity",
            Request::post(PATH)
                .header(CONTENT_TYPE, "application/json")
                .header(AUTHORIZATION, format!("Bearer {credential}"))
                .header(IDENTITY, "admin")
                .body(Body::from(body.clone()))
                .unwrap(),
        ),
        (
            "duplicate authorization",
            Request::post(PATH)
                .header(CONTENT_TYPE, "application/json")
                .header(AUTHORIZATION, format!("Bearer {credential}"))
                .header(AUTHORIZATION, format!("Bearer {unknown}"))
                .header(IDENTITY, identity)
                .body(Body::from(body.clone()))
                .unwrap(),
        ),
        (
            "duplicate identity",
            Request::post(PATH)
                .header(CONTENT_TYPE, "application/json")
                .header(AUTHORIZATION, format!("Bearer {credential}"))
                .header(IDENTITY, identity)
                .header(IDENTITY, "device")
                .body(Body::from(body))
                .unwrap(),
        ),
    ];

    for (case, request) in cases {
        let (status, headers, text) = send(&fixture, request).await;
        assert_error(
            status,
            &headers,
            &text,
            StatusCode::UNAUTHORIZED,
            "unauthorized",
        );
        assert!(!text.contains(credential), "{case}: credential leaked");
    }
}

#[tokio::test]
async fn disabled_accounts_are_forbidden_for_both_identity_forms() {
    if let Some(run) = isolate(
        "disabled_accounts_are_forbidden_for_both_identity_forms",
        Gateway::Fixture(vec![completion_response(&source_reply())]),
    )
    .await
    {
        assert!(run.upstream.unwrap().requests().is_empty());
        return;
    }

    let fixture = Fixture::new().await;
    let user = fixture.user(0x103, true).await;
    let body = valid_body().to_string();

    for (identity, credential) in credentials(&user) {
        let (status, headers, text) =
            send(&fixture, request(identity, credential, body.clone())).await;
        assert_error(
            status,
            &headers,
            &text,
            StatusCode::FORBIDDEN,
            "subscription_disabled",
        );
        assert!(!text.contains(credential));
    }
}

#[tokio::test]
async fn strict_request_shape_rejects_extra_missing_and_mistyped_fields() {
    if let Some(run) = isolate(
        "strict_request_shape_rejects_extra_missing_and_mistyped_fields",
        Gateway::Fixture(vec![completion_response(&source_reply())]),
    )
    .await
    {
        assert!(run.upstream.unwrap().requests().is_empty());
        return;
    }

    let fixture = Fixture::new().await;
    let valid = valid_body();
    let mut extra_nested = valid.clone();
    extra_nested["crash"]["stack"] = json!("synthetic-private-stack");

    let cases = vec![
        (
            "extra goal",
            set(valid.clone(), "goal", json!("open settings")),
        ),
        (
            "extra path",
            set(valid.clone(), "path", json!("/tmp/report.txt")),
        ),
        (
            "extra url",
            set(valid.clone(), "url", json!("https://example.test/report")),
        ),
        (
            "extra account",
            set(valid.clone(), "account", json!("synthetic-account")),
        ),
        (
            "extra raw report",
            set(valid.clone(), "raw_report", json!("synthetic")),
        ),
        ("extra tool", set(valid.clone(), "tool", json!("shell"))),
        (
            "extra command",
            set(valid.clone(), "command", json!("whoami")),
        ),
        ("missing schema", remove(valid.clone(), "schema")),
        ("missing locale", remove(valid.clone(), "locale")),
        ("missing version", remove(valid.clone(), "version")),
        ("missing commit", remove(valid.clone(), "commit")),
        ("missing platform", remove(valid.clone(), "platform")),
        ("missing arch", remove(valid.clone(), "arch")),
        ("missing crash", remove(valid.clone(), "crash")),
        ("schema string", set(valid.clone(), "schema", json!("1"))),
        ("schema zero", set(valid.clone(), "schema", json!(0))),
        ("schema two", set(valid.clone(), "schema", json!(2))),
        ("schema negative", set(valid.clone(), "schema", json!(-1))),
        ("locale number", set(valid.clone(), "locale", json!(1))),
        ("version number", set(valid.clone(), "version", json!(2.51))),
        ("version null", set(valid.clone(), "version", Value::Null)),
        ("commit number", set(valid.clone(), "commit", json!(123))),
        ("commit null", set(valid.clone(), "commit", Value::Null)),
        ("platform null", set(valid.clone(), "platform", Value::Null)),
        (
            "platform array",
            set(valid.clone(), "platform", json!(["windows"])),
        ),
        ("arch null", set(valid.clone(), "arch", Value::Null)),
        ("arch boolean", set(valid.clone(), "arch", json!(true))),
        ("crash string", set(valid.clone(), "crash", json!("fatal"))),
        ("crash null", set(valid.clone(), "crash", Value::Null)),
        ("crash array", set(valid.clone(), "crash", json!([]))),
        ("crash boolean", set(valid.clone(), "crash", json!(true))),
        (
            "crash fatal string",
            set(
                valid.clone(),
                "crash",
                json!({"fatal": "true", "fault": "io", "area": "settings", "signal": "none"}),
            ),
        ),
        (
            "crash fatal number",
            set(
                valid.clone(),
                "crash",
                json!({"fatal": 1, "fault": "io", "area": "settings", "signal": "none"}),
            ),
        ),
        ("missing crash fatal", remove_crash(valid.clone(), "fatal")),
        ("missing crash fault", remove_crash(valid.clone(), "fault")),
        ("missing crash area", remove_crash(valid.clone(), "area")),
        (
            "missing crash signal",
            remove_crash(valid.clone(), "signal"),
        ),
        ("extra crash field", extra_nested),
        ("top-level array", json!([])),
        ("top-level string", json!("source diagnosis")),
        ("top-level null", Value::Null),
        ("top-level number", json!(7)),
    ];

    for (index, (case, body)) in cases.into_iter().enumerate() {
        expect_bad_request(&fixture, 0x200 + index as u32, case, body.to_string()).await;
    }
}

#[tokio::test]
async fn enum_fields_accept_only_the_documented_values() {
    if let Some(run) = isolate(
        "enum_fields_accept_only_the_documented_values",
        Gateway::Fixture(vec![completion_response(&source_reply())]),
    )
    .await
    {
        assert!(run.upstream.unwrap().requests().is_empty());
        return;
    }

    let fixture = Fixture::new().await;
    let base = valid_body();

    let faults = [
        "unknown",
        "null_reference",
        "invalid_operation",
        "io",
        "access_denied",
        "out_of_memory",
        "network",
        "configuration",
        "native",
    ];
    let areas = ["unknown", "ui", "startup", "routing", "settings"];
    let signals = ["none", "proxy_unreachable", "tun_busy", "stop_unconfirmed"];

    let mut accepted = vec![
        ("locale en", set(base.clone(), "locale", json!("en"))),
        ("locale ru", set(base.clone(), "locale", json!("ru"))),
        (
            "platform windows",
            set(base.clone(), "platform", json!("windows")),
        ),
        (
            "platform linux",
            set(base.clone(), "platform", json!("linux")),
        ),
        (
            "platform macos",
            set(base.clone(), "platform", json!("macos")),
        ),
        ("arch x64", set(base.clone(), "arch", json!("x64"))),
        ("arch arm64", set(base.clone(), "arch", json!("arm64"))),
    ];
    for fault in faults {
        accepted.push((
            "fault",
            set(
                base.clone(),
                "crash",
                json!({"fatal": true, "fault": fault, "area": "settings", "signal": "none"}),
            ),
        ));
    }
    for area in areas {
        accepted.push((
            "area",
            set(
                base.clone(),
                "crash",
                json!({"fatal": true, "fault": "io", "area": area, "signal": "none"}),
            ),
        ));
    }
    for signal in signals {
        accepted.push((
            "signal",
            set(
                base.clone(),
                "crash",
                json!({"fatal": true, "fault": "io", "area": "settings", "signal": signal}),
            ),
        ));
    }

    for (index, (case, body)) in accepted.into_iter().enumerate() {
        expect_unknown_build(&fixture, 0x300 + index as u32, case, body).await;
    }

    let rejected = vec![
        ("locale de", set(base.clone(), "locale", json!("de"))),
        ("locale uppercase", set(base.clone(), "locale", json!("EN"))),
        ("locale empty", set(base.clone(), "locale", json!(""))),
        (
            "platform android",
            set(base.clone(), "platform", json!("android")),
        ),
        (
            "platform capitalized",
            set(base.clone(), "platform", json!("Windows")),
        ),
        ("platform empty", set(base.clone(), "platform", json!(""))),
        ("arch x86", set(base.clone(), "arch", json!("x86"))),
        ("arch x86_64", set(base.clone(), "arch", json!("x86_64"))),
        ("arch uppercase", set(base.clone(), "arch", json!("X64"))),
        (
            "fault segfault",
            set(
                base.clone(),
                "crash",
                json!({"fatal": true, "fault": "segfault", "area": "settings", "signal": "none"}),
            ),
        ),
        (
            "fault uppercase",
            set(
                base.clone(),
                "crash",
                json!({"fatal": true, "fault": "IO", "area": "settings", "signal": "none"}),
            ),
        ),
        (
            "fault empty",
            set(
                base.clone(),
                "crash",
                json!({"fatal": true, "fault": "", "area": "settings", "signal": "none"}),
            ),
        ),
        (
            "area daemon",
            set(
                base.clone(),
                "crash",
                json!({"fatal": true, "fault": "io", "area": "daemon", "signal": "none"}),
            ),
        ),
        (
            "area capitalized",
            set(
                base.clone(),
                "crash",
                json!({"fatal": true, "fault": "io", "area": "Settings", "signal": "none"}),
            ),
        ),
        (
            "area empty",
            set(
                base.clone(),
                "crash",
                json!({"fatal": true, "fault": "io", "area": "", "signal": "none"}),
            ),
        ),
        (
            "signal stopped",
            set(
                base.clone(),
                "crash",
                json!({"fatal": true, "fault": "io", "area": "settings", "signal": "stopped"}),
            ),
        ),
        (
            "signal capitalized",
            set(
                base.clone(),
                "crash",
                json!({"fatal": true, "fault": "io", "area": "settings", "signal": "None"}),
            ),
        ),
        (
            "signal empty",
            set(
                base.clone(),
                "crash",
                json!({"fatal": true, "fault": "io", "area": "settings", "signal": ""}),
            ),
        ),
    ];

    for (index, (case, body)) in rejected.into_iter().enumerate() {
        expect_bad_request(&fixture, 0x400 + index as u32, case, body.to_string()).await;
    }
}

#[tokio::test]
async fn connection_evidence_replaces_crash_for_unregistered_builds() {
    if let Some(run) = isolate(
        "connection_evidence_replaces_crash_for_unregistered_builds",
        Gateway::Fixture(vec![completion_response(&source_reply())]),
    )
    .await
    {
        assert!(run.upstream.unwrap().requests().is_empty());
        return;
    }

    let fixture = Fixture::new().await;
    let base = valid_body();
    let with_connection =
        |connection: Value| set(remove(base.clone(), "crash"), "connection", connection);

    for (index, code) in [
        "startup_timeout",
        "readiness_timeout",
        "unexpected_stop",
        "tun_busy",
    ]
    .into_iter()
    .enumerate()
    {
        expect_unknown_build(
            &fixture,
            0x6a0 + index as u32,
            code,
            with_connection(json!(code)),
        )
        .await;
    }

    let rejected = vec![
        ("neither evidence field", remove(base.clone(), "crash")),
        (
            "crash and connection",
            set(base.clone(), "connection", json!("startup_timeout")),
        ),
        ("connection null", with_connection(Value::Null)),
        (
            "connection null with crash",
            set(base.clone(), "connection", Value::Null),
        ),
        (
            "crash null with connection",
            set(
                set(base.clone(), "crash", Value::Null),
                "connection",
                json!("tun_busy"),
            ),
        ),
        (
            "connection object",
            with_connection(json!({"code": "startup_timeout"})),
        ),
        (
            "connection free text",
            with_connection(json!("engine startup timed out")),
        ),
        (
            "connection unknown code",
            with_connection(json!("engine_stopped")),
        ),
        ("connection empty", with_connection(json!(""))),
        (
            "connection capitalized",
            with_connection(json!("Startup_Timeout")),
        ),
    ];

    for (index, (case, body)) in rejected.into_iter().enumerate() {
        expect_bad_request(&fixture, 0x6b0 + index as u32, case, body.to_string()).await;
    }
}

#[tokio::test]
async fn version_commit_and_identifier_fields_are_bounded() {
    if let Some(run) = isolate(
        "version_commit_and_identifier_fields_are_bounded",
        Gateway::Fixture(vec![completion_response(&source_reply())]),
    )
    .await
    {
        assert!(run.upstream.unwrap().requests().is_empty());
        return;
    }

    let fixture = Fixture::new().await;
    let base = valid_body();

    for (index, version) in ["1.0.0", "2.51.0", "2.51.0-r2", "10.20.30-r1"]
        .into_iter()
        .enumerate()
    {
        expect_unknown_build(
            &fixture,
            0x500 + index as u32,
            version,
            set(base.clone(), "version", json!(version)),
        )
        .await;
    }

    for (index, commit) in [COMMIT_A, COMMIT_B].into_iter().enumerate() {
        expect_unknown_build(
            &fixture,
            0x510 + index as u32,
            commit,
            set(base.clone(), "commit", json!(commit)),
        )
        .await;
    }

    let invalid_versions = vec![
        ("empty", String::new()),
        ("two components", "2.51".to_string()),
        ("four components", "2.51.0.1".to_string()),
        ("leading v", "v2.51.0".to_string()),
        ("release candidate", "2.51.0-rc1".to_string()),
        ("missing revision", "2.51.0-r".to_string()),
        ("negative revision", "2.51.0-r-1".to_string()),
        ("uppercase revision", "2.51.0-R2".to_string()),
        ("empty component", "2..0".to_string()),
        ("negative component", "-1.2.3".to_string()),
        ("whitespace", " 2.51.0".to_string()),
        ("newline", "2.51.0\n".to_string()),
        ("directional control", "2.51.0\u{202e}".to_string()),
        ("overlong", "1".repeat(200)),
    ];
    for (index, (case, version)) in invalid_versions.into_iter().enumerate() {
        expect_bad_request(
            &fixture,
            0x520 + index as u32,
            case,
            set(base.clone(), "version", json!(version)).to_string(),
        )
        .await;
    }

    let invalid_commits = vec![
        ("empty", String::new()),
        ("short", COMMIT_A[..39].to_string()),
        ("long", format!("{COMMIT_A}0")),
        ("uppercase", COMMIT_A.to_uppercase()),
        (
            "non hex",
            "0123456789abcdef0123456789abcdef0123456g".to_string(),
        ),
        ("space", format!("{COMMIT_A} ")),
        ("newline", format!("{COMMIT_A}\n")),
        ("unicode", "é".repeat(40)),
    ];
    for (index, (case, commit)) in invalid_commits.into_iter().enumerate() {
        expect_bad_request(
            &fixture,
            0x540 + index as u32,
            case,
            set(base.clone(), "commit", json!(commit)).to_string(),
        )
        .await;
    }
}

#[tokio::test]
async fn body_limit_is_exactly_2048_bytes() {
    if let Some(run) = isolate(
        "body_limit_is_exactly_2048_bytes",
        Gateway::Fixture(vec![completion_response(&source_reply())]),
    )
    .await
    {
        assert!(run.upstream.unwrap().requests().is_empty());
        return;
    }

    let fixture = Fixture::new().await;
    let user = fixture.user(0x560, false).await;
    let [(identity, credential), _] = credentials(&user);
    let compact = valid_body().to_string();
    assert!(compact.len() < 2048);

    let at_limit = format!("{compact:<2048}");
    assert_eq!(at_limit.len(), 2048);
    let (status, headers, text) = send(&fixture, request(identity, credential, at_limit)).await;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_no_store(&headers);
    assert_json(&text, &unknown_build());

    let over_limit = format!("{compact:<2049}");
    assert_eq!(over_limit.len(), 2049);
    let (status, headers, text) = send(&fixture, request(identity, credential, over_limit)).await;
    assert_error(
        status,
        &headers,
        &text,
        StatusCode::PAYLOAD_TOO_LARGE,
        "report_too_large",
    );

    let (status, headers, text) =
        send(&fixture, request(identity, credential, String::new())).await;
    assert_error(
        status,
        &headers,
        &text,
        StatusCode::BAD_REQUEST,
        "invalid_report",
    );
}

#[tokio::test]
async fn malformed_json_and_non_object_documents_are_rejected() {
    if let Some(run) = isolate(
        "malformed_json_and_non_object_documents_are_rejected",
        Gateway::Fixture(vec![completion_response(&source_reply())]),
    )
    .await
    {
        assert!(run.upstream.unwrap().requests().is_empty());
        return;
    }

    let fixture = Fixture::new().await;
    let valid = valid_body().to_string();
    let cases = [
        ("empty", String::new()),
        ("space", " ".to_string()),
        ("open brace", "{".to_string()),
        ("open bracket", "[".to_string()),
        ("null", "null".to_string()),
        ("empty array", "[]".to_string()),
        ("string", "\"source diagnosis\"".to_string()),
        ("number", "42".to_string()),
        ("empty object", "{}".to_string()),
        ("trailing text", format!("{valid}x")),
        ("truncated", valid[..valid.len() / 2].to_string()),
    ];

    for (index, (case, body)) in cases.into_iter().enumerate() {
        expect_bad_request(&fixture, 0x570 + index as u32, case, body).await;
    }
}

#[tokio::test]
async fn unregistered_versions_commits_platforms_and_architectures_are_unknown_build() {
    if let Some(run) = isolate(
        "unregistered_versions_commits_platforms_and_architectures_are_unknown_build",
        Gateway::Fixture(vec![completion_response(&source_reply())]),
    )
    .await
    {
        assert!(run.upstream.unwrap().requests().is_empty());
        return;
    }

    let fixture = Fixture::new().await;
    let base = valid_body();
    let cases = vec![
        ("base", base.clone()),
        (
            "version 2.51.0",
            set(base.clone(), "version", json!("2.51.0")),
        ),
        (
            "version 2.50.0",
            set(base.clone(), "version", json!("2.50.0")),
        ),
        ("commit B", set(base.clone(), "commit", json!(COMMIT_B))),
        (
            "linux x64",
            set(
                set(base.clone(), "platform", json!("linux")),
                "arch",
                json!("x64"),
            ),
        ),
        (
            "linux arm64",
            set(
                set(base.clone(), "platform", json!("linux")),
                "arch",
                json!("arm64"),
            ),
        ),
        (
            "macos arm64",
            set(
                set(base.clone(), "platform", json!("macos")),
                "arch",
                json!("arm64"),
            ),
        ),
        ("locale en", set(base.clone(), "locale", json!("en"))),
        (
            "fault unknown",
            set(
                base.clone(),
                "crash",
                json!({"fatal": true, "fault": "unknown", "area": "unknown", "signal": "none"}),
            ),
        ),
        (
            "startup routing tun_busy",
            set(
                base.clone(),
                "crash",
                json!({"fatal": true, "fault": "network", "area": "startup", "signal": "tun_busy"}),
            ),
        ),
    ];

    for (index, (case, body)) in cases.into_iter().enumerate() {
        expect_unknown_build(&fixture, 0x600 + index as u32, case, body).await;
    }

    let user = fixture.user(0x620, false).await;
    for (identity, credential) in credentials(&user) {
        let (status, headers, text) = send(
            &fixture,
            request(identity, credential, valid_body().to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{identity}: {text}");
        assert_no_store(&headers);
        assert_json(&text, &unknown_build());
    }
}

#[tokio::test]
async fn same_version_with_different_commits_is_not_assumed_known() {
    if let Some(run) = isolate(
        "same_version_with_different_commits_is_not_assumed_known",
        Gateway::Fixture(vec![completion_response(&source_reply())]),
    )
    .await
    {
        assert!(run.upstream.unwrap().requests().is_empty());
        return;
    }

    let fixture = Fixture::new().await;
    let base = valid_body();

    for (index, commit) in [COMMIT_A, COMMIT_B].into_iter().enumerate() {
        expect_unknown_build(
            &fixture,
            0x630 + index as u32,
            commit,
            set(
                set(base.clone(), "version", json!("2.51.0-r2")),
                "commit",
                json!(commit),
            ),
        )
        .await;
    }
}

#[tokio::test]
async fn unknown_build_does_not_require_a_configured_gateway() {
    if let Some(_run) = isolate(
        "unknown_build_does_not_require_a_configured_gateway",
        Gateway::Missing,
    )
    .await
    {
        return;
    }

    let fixture = Fixture::new().await;
    let user = fixture.user(0x640, false).await;
    let [(identity, credential), _] = credentials(&user);
    let (status, headers, text) = send(
        &fixture,
        request(identity, credential, valid_body().to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_no_store(&headers);
    assert_json(&text, &unknown_build());
}

#[tokio::test]
async fn both_identity_forms_share_one_source_diagnosis_account_quota() {
    if let Some(run) = isolate(
        "both_identity_forms_share_one_source_diagnosis_account_quota",
        Gateway::Fixture(vec![completion_response(&source_reply())]),
    )
    .await
    {
        assert!(run.upstream.unwrap().requests().is_empty());
        return;
    }

    let fixture = Fixture::new().await;
    let user = fixture.user(0x650, false).await;
    let identities = credentials(&user);
    let body = valid_body().to_string();

    // The spec requires a distinct bounded account quota but does not pin the
    // count. The existing VPNRouter assistant convention is six per minute, so
    // exhaustion within 32 requests proves a bounded bucket without hard-coding
    // the exact limit.
    let mut successes = 0;
    let mut limited = false;
    for index in 0..32 {
        let (identity, credential) = identities[index % 2];
        let (status, headers, text) =
            send(&fixture, request(identity, credential, body.clone())).await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            assert_error(
                status,
                &headers,
                &text,
                StatusCode::TOO_MANY_REQUESTS,
                "quota_exceeded",
            );
            assert!(headers.contains_key(RETRY_AFTER));
            limited = true;
            break;
        }
        assert_eq!(status, StatusCode::OK, "{identity}: {text}");
        assert_no_store(&headers);
        assert_json(&text, &unknown_build());
        successes += 1;
    }

    assert!(successes >= 1, "the first source diagnosis must be allowed");
    assert!(
        limited,
        "source diagnosis must enforce a bounded account quota"
    );

    for (identity, credential) in identities {
        let (status, headers, text) =
            send(&fixture, request(identity, credential, body.clone())).await;
        assert_error(
            status,
            &headers,
            &text,
            StatusCode::TOO_MANY_REQUESTS,
            "quota_exceeded",
        );
        assert!(headers.contains_key(RETRY_AFTER));
    }
}

#[tokio::test]
async fn source_diagnosis_has_a_separate_account_quota_from_step() {
    if let Some(run) = isolate(
        "source_diagnosis_has_a_separate_account_quota_from_step",
        Gateway::Fixture(vec![(StatusCode::INTERNAL_SERVER_ERROR, json!({}))]),
    )
    .await
    {
        assert!((2..=33).contains(&run.upstream.unwrap().requests().len()));
        return;
    }

    let fixture = Fixture::new().await;
    let user_a = fixture.user(0x660, false).await;
    let user_b = fixture.user(0x661, false).await;
    let step = step_body().to_string();
    let source = valid_body().to_string();

    let [(identity, credential), _] = credentials(&user_a);
    let mut step_limited = false;
    for _ in 0..32 {
        let (status, headers, text) = send(
            &fixture,
            request_at(STEP_PATH, identity, credential, step.clone()),
        )
        .await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            assert_error(status, &headers, &text, status, "quota_exceeded");
            step_limited = true;
            break;
        }
        assert_eq!(status, StatusCode::BAD_GATEWAY, "{text}");
        assert_no_store(&headers);
    }
    assert!(step_limited, "step must reach its account limit");

    let (status, headers, text) =
        send(&fixture, request(identity, credential, source.clone())).await;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_no_store(&headers);
    assert_json(&text, &unknown_build());

    // An unknown build is still an authorized request, so it must consume the
    // endpoint account quota before any provider path is reachable.
    let [(identity, credential), _] = credentials(&user_b);
    let mut limited = false;
    for _ in 0..32 {
        let (status, headers, text) =
            send(&fixture, request(identity, credential, source.clone())).await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            assert_error(
                status,
                &headers,
                &text,
                StatusCode::TOO_MANY_REQUESTS,
                "quota_exceeded",
            );
            limited = true;
            break;
        }
        assert_eq!(status, StatusCode::OK, "{text}");
    }
    assert!(
        limited,
        "source diagnosis must enforce a bounded account quota"
    );

    let (status, headers, text) =
        send(&fixture, request_at(STEP_PATH, identity, credential, step)).await;
    assert_eq!(
        status,
        StatusCode::BAD_GATEWAY,
        "source diagnosis quota must not consume the step bucket: {text}"
    );
    assert_no_store(&headers);
}

#[tokio::test]
async fn step_and_plan_keep_their_existing_public_contracts() {
    let responses = vec![
        completion_response(&json!({"operation": "finish"})),
        completion_response(&json!({
            "operation": "clarify",
            "reason": "unsupported_goal"
        })),
    ];
    if let Some(run) = isolate(
        "step_and_plan_keep_their_existing_public_contracts",
        Gateway::Fixture(responses),
    )
    .await
    {
        assert_eq!(run.upstream.unwrap().requests().len(), 2);
        return;
    }

    let fixture = Fixture::new().await;
    let user = fixture.user(0x670, false).await;
    let [(identity, credential), _] = credentials(&user);

    let (status, headers, text) = send(
        &fixture,
        request_at(STEP_PATH, identity, credential, step_body().to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_no_store(&headers);
    assert_json(
        &text,
        &json!({"schema": 2, "result": {"operation": "finish"}}),
    );

    let (status, headers, text) = send(
        &fixture,
        request_at(PLAN_PATH, identity, credential, plan_body().to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_no_store(&headers);
    assert_json(
        &text,
        &json!({"schema": 1, "result": {"operation": "clarify", "reason": "unsupported_goal"}}),
    );
}

#[tokio::test]
async fn step_and_plan_reject_the_source_diagnosis_request_shape() {
    if let Some(run) = isolate(
        "step_and_plan_reject_the_source_diagnosis_request_shape",
        Gateway::Fixture(vec![completion_response(&source_reply())]),
    )
    .await
    {
        assert!(run.upstream.unwrap().requests().is_empty());
        return;
    }

    let fixture = Fixture::new().await;
    let user = fixture.user(0x680, false).await;
    let [(identity, credential), _] = credentials(&user);

    for path in [STEP_PATH, PLAN_PATH] {
        let (status, headers, text) = send(
            &fixture,
            request_at(path, identity, credential, valid_body().to_string()),
        )
        .await;
        assert_error(
            status,
            &headers,
            &text,
            StatusCode::BAD_REQUEST,
            "invalid_report",
        );
    }
}

#[tokio::test]
async fn source_diagnosis_rejects_non_json_content_and_unusual_methods() {
    if let Some(run) = isolate(
        "source_diagnosis_rejects_non_json_content_and_unusual_methods",
        Gateway::Fixture(vec![completion_response(&source_reply())]),
    )
    .await
    {
        assert!(run.upstream.unwrap().requests().is_empty());
        return;
    }

    let fixture = Fixture::new().await;
    let user = fixture.user(0x690, false).await;
    let [(identity, credential), _] = credentials(&user);
    let body = valid_body().to_string();

    let (status, headers, text) = send(
        &fixture,
        Request::post(PATH)
            .header(CONTENT_TYPE, "text/plain")
            .header(AUTHORIZATION, format!("Bearer {credential}"))
            .header(IDENTITY, identity)
            .body(Body::from(body.clone()))
            .unwrap(),
    )
    .await;
    assert_error(
        status,
        &headers,
        &text,
        StatusCode::BAD_REQUEST,
        "invalid_report",
    );

    for method in ["GET", "PUT", "DELETE"] {
        let (status, _headers, _text) = send(
            &fixture,
            Request::builder()
                .method(method)
                .uri(PATH)
                .header(CONTENT_TYPE, "application/json")
                .header(AUTHORIZATION, format!("Bearer {credential}"))
                .header(IDENTITY, identity)
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "{method}");
    }
}

#[tokio::test]
#[ignore = "CI provisions a root-owned catalog under /run"]
async fn registered_build_uses_trusted_catalog_from_env() {
    let catalog = std::env::var_os("VPNCTL_TEST_TRUSTED_SOURCE_CATALOG")
        .expect("set the provisioned test catalog path");
    let model = source_reply();
    if let Some(run) = isolate_with_catalog(
        "registered_build_uses_trusted_catalog_from_env",
        Gateway::Fixture(vec![completion_response(&model)]),
        Some(&catalog),
    )
    .await
    {
        let requests = run.upstream.unwrap().requests();
        assert_eq!(requests.len(), 1);
        let prompt: Value =
            serde_json::from_str(requests[0].1["messages"][1]["content"].as_str().unwrap())
                .unwrap();
        assert_eq!(
            prompt["sources"],
            json!([{
                "path": "VPNRouter.Core/Services/Settings.cs",
                "first": 15, "last": 15, "text": "return ReadSettings();"
            }])
        );
        return;
    }
    let fixture = Fixture::new().await;
    let user = fixture.user(0x701, false).await;
    let [(kind, credential), _] = credentials(&user);
    let (status, headers, text) = send(
        &fixture,
        request(kind, credential, valid_body().to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_no_store(&headers);
    let mut expected = model;
    expected["citations"][0]["commit"] = json!(COMMIT_A);
    assert_json(&text, &json!({"schema": 1, "result": expected}));
}
