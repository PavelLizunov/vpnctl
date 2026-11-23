#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::{Arc, mpsc};

use axum::body::{Body, to_bytes};
use axum::http::header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, RETRY_AFTER};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::Response;
use axum::{Json, Router, routing::post};
use serde_json::{Value, json};
use tower::ServiceExt;
use vpnctl_core::{User, UserId};
use vpnctl_inventory::SqliteInventory;

use super::nina_assistant::Gateway;
use super::vpnrouter_assistant::router;

const IDENTITY: &str = "x-vpnctl-identity";
const PATH: &str = "/api/v1/assistant/vpnrouter/plan";
const STEP_PATH: &str = "/api/v1/assistant/vpnrouter/step";
const MODEL: &str = "synthetic-vpnrouter-model";
const GATEWAY_KEY: &str = "synthetic-vpnrouter-server-key";

struct Fixture {
    app: Router,
    inventory: SqliteInventory,
    writer: tokio::task::JoinHandle<()>,
    _directory: tempfile::TempDir,
}

impl Fixture {
    async fn new(gateway: Option<Gateway>) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let inventory = SqliteInventory::open(&directory.path().join("inventory.db"))
            .await
            .unwrap();
        let registry = Arc::new(crate::app::build_registry().unwrap());
        let (state, writer) = crate::app::make_app_state_for_tests(inventory.clone(), registry);
        Self {
            app: router(gateway).with_state(state),
            inventory,
            writer,
            _directory: directory,
        }
    }

    async fn user(&self, number: u32, disabled: bool) -> User {
        let user = User {
            id: UserId(format!("synthetic-vpnrouter-user-{number}")),
            uuid: vpnctl_crypto::gen_uuid(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: Some(format!("synthetic-vpnrouter-subscription_{number}")),
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

struct Upstream {
    requests: mpsc::Receiver<(HeaderMap, Value)>,
    server: tokio::task::JoinHandle<()>,
}

impl Upstream {
    async fn start(status: StatusCode, body: Value) -> (Self, Gateway) {
        let (record, requests) = mpsc::channel();
        let app = Router::new().route(
            "/synthetic/chat/completions",
            post(move |headers: HeaderMap, Json(payload): Json<Value>| {
                let record = record.clone();
                let body = body.clone();
                async move {
                    record.send((headers, payload)).unwrap();
                    (status, Json(body))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!(
            "http://{}/synthetic/chat/completions",
            listener.local_addr().unwrap()
        );
        let gateway = Gateway::new(&endpoint, MODEL, GATEWAY_KEY).unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (Self { requests, server }, gateway)
    }
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.server.abort();
    }
}

fn plan_body(locale: &str, goal: &str, target_available: bool) -> Value {
    json!({
        "schema": 1,
        "locale": locale,
        "goal": goal,
        "target_available": target_available
    })
}

fn completion(inner: &Value) -> Value {
    json!({"choices": [{"message": {"content": inner.to_string()}}]})
}

fn credentials(user: &User) -> [(&str, &str); 2] {
    [
        ("subscription", user.sub_token.as_deref().unwrap()),
        ("device", user.vpn_router_device_id.as_deref().unwrap()),
    ]
}

fn request(identity: &str, credential: &str, body: String) -> Request<Body> {
    request_at(PATH, identity, credential, body)
}

fn request_at(path: &str, identity: &str, credential: &str, body: String) -> Request<Body> {
    Request::post(path)
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, format!("Bearer {credential}"))
        .header(IDENTITY, identity)
        .body(Body::from(body))
        .unwrap()
}

fn assert_no_store(response: &Response) {
    let value = response.headers().get(CACHE_CONTROL).unwrap();
    assert!(
        value
            .to_str()
            .unwrap()
            .split(',')
            .any(|part| part.trim() == "no-store")
    );
}

async fn response_text(response: Response) -> String {
    let bytes = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

fn assert_upstream_request(headers: &HeaderMap, payload: &Value, expected: &Value, user: &User) {
    assert_eq!(
        headers.get(AUTHORIZATION).unwrap().to_str().unwrap(),
        format!("Bearer {GATEWAY_KEY}")
    );
    assert_eq!(payload["model"], json!(MODEL));

    let messages = payload["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0]["role"], "system");
    assert!(!messages[0]["content"].as_str().unwrap().trim().is_empty());
    assert_eq!(messages[1]["role"], "user");

    let forwarded: Value = serde_json::from_str(messages[1]["content"].as_str().unwrap()).unwrap();
    assert_eq!(&forwarded, expected);

    let wire = payload.to_string();
    for private in [
        user.id.0.as_str(),
        user.sub_token.as_deref().unwrap(),
        user.vpn_router_device_id.as_deref().unwrap(),
    ] {
        assert!(!wire.contains(private));
        assert!(
            !headers
                .values()
                .any(|value| value.to_str().is_ok_and(|value| value.contains(private)))
        );
    }
}

async fn assert_valid_result(inner: Value, target_available: bool, locale: &str, expected: Value) {
    let (upstream, gateway) = Upstream::start(StatusCode::OK, completion(&inner)).await;
    let fixture = Fixture::new(Some(gateway)).await;
    let user = fixture.user(0xcd, false).await;
    let [(identity, credential), _] = credentials(&user);
    let body = plan_body(locale, "Clarify the app.", target_available);

    let response = fixture
        .send(request(identity, credential, body.to_string()))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_no_store(&response);
    assert_eq!(
        serde_json::from_str::<Value>(&response_text(response).await).unwrap(),
        expected
    );

    let (headers, payload) = upstream.requests.try_recv().unwrap();
    assert_upstream_request(&headers, &payload, &body, &user);
    assert!(upstream.requests.try_recv().is_err());
}

async fn assert_bad_model(upstream_body: Value, target_available: bool) {
    let (upstream, gateway) = Upstream::start(StatusCode::OK, upstream_body).await;

    let fixture = Fixture::new(Some(gateway)).await;
    let user = fixture.user(0xce, false).await;
    let [(identity, credential), _] = credentials(&user);
    let body = plan_body("en", "Route only Chrome through the VPN.", target_available);

    let response = fixture
        .send(request(identity, credential, body.to_string()))
        .await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let text = response_text(response).await;
    assert!(!text.contains(credential));
    assert!(!text.contains(GATEWAY_KEY));
    assert!(upstream.requests.try_recv().is_ok());
}

#[tokio::test]
async fn valid_plan_reaches_the_model_for_both_identities() {
    let (upstream, gateway) = Upstream::start(
        StatusCode::OK,
        completion(&json!({"operation": "route_only_app"})),
    )
    .await;
    let fixture = Fixture::new(Some(gateway)).await;
    let user = fixture.user(0xab, false).await;
    let goal = "Route only\tChrome\nthrough the VPN.";
    let expected = json!({"schema": 1, "result": {"operation": "route_only_app"}});

    for (index, (identity, credential)) in credentials(&user).into_iter().enumerate() {
        let locale = if index == 0 { "en" } else { "ru" };
        let body = plan_body(locale, goal, true);
        let response = fixture
            .send(request(identity, credential, body.to_string()))
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_no_store(&response);
        let text = response_text(response).await;
        assert!(!text.contains(credential));
        assert!(!text.contains(GATEWAY_KEY));
        assert_eq!(serde_json::from_str::<Value>(&text).unwrap(), expected);

        let (headers, payload) = upstream.requests.try_recv().unwrap();
        assert_upstream_request(&headers, &payload, &body, &user);
    }

    assert!(upstream.requests.try_recv().is_err());
}

#[tokio::test]
async fn disabled_accounts_are_forbidden_for_both_identities() {
    let (upstream, gateway) = Upstream::start(
        StatusCode::OK,
        completion(&json!({"operation": "route_only_app"})),
    )
    .await;
    let fixture = Fixture::new(Some(gateway)).await;
    let user = fixture.user(0xbc, true).await;
    let body = plan_body("en", "Route only Chrome through the VPN.", true);

    for (identity, credential) in credentials(&user) {
        let response = fixture
            .send(request(identity, credential, body.to_string()))
            .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_no_store(&response);
    }
    assert!(upstream.requests.try_recv().is_err());
}

#[tokio::test]
async fn both_identity_forms_share_the_six_request_account_quota() {
    let (upstream, gateway) = Upstream::start(
        StatusCode::OK,
        completion(&json!({"operation": "route_only_app"})),
    )
    .await;
    let fixture = Fixture::new(Some(gateway)).await;
    let user = fixture.user(0xab, false).await;
    let body = plan_body("en", "Route only Chrome through the VPN.", true);
    let identities = credentials(&user);

    for (identity, credential) in identities.into_iter().cycle().take(6) {
        let response = fixture
            .send(request(identity, credential, body.to_string()))
            .await;
        assert_eq!(response.status(), StatusCode::OK);
    }
    for (identity, credential) in identities {
        let response = fixture
            .send(request(identity, credential, body.to_string()))
            .await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_no_store(&response);
        let retry = response.headers()[RETRY_AFTER].to_str().unwrap();
        assert!(!retry.trim().is_empty());
    }
    assert_eq!(upstream.requests.try_iter().count(), 6);
}

#[tokio::test]
async fn body_limit_is_exactly_2048_bytes() {
    let (upstream, gateway) = Upstream::start(
        StatusCode::OK,
        completion(&json!({"operation": "route_only_app"})),
    )
    .await;
    let fixture = Fixture::new(Some(gateway)).await;
    let user = fixture.user(0xab, false).await;
    let [(identity, credential), _] = credentials(&user);
    let compact = plan_body("en", "Route only Chrome through the VPN.", true).to_string();
    assert!(compact.len() < 2048);

    let at_limit = format!("{compact:<2048}");
    assert_eq!(at_limit.len(), 2048);
    let response = fixture.send(request(identity, credential, at_limit)).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_no_store(&response);

    let over_limit = format!("{compact:<2049}");
    assert_eq!(over_limit.len(), 2049);
    let response = fixture
        .send(request(identity, credential, over_limit))
        .await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

    assert_eq!(upstream.requests.try_iter().count(), 1);
}

#[tokio::test]
async fn invalid_plan_requests_are_rejected_before_the_model() {
    let (upstream, gateway) = Upstream::start(
        StatusCode::OK,
        completion(&json!({"operation": "route_only_app"})),
    )
    .await;
    let fixture = Fixture::new(Some(gateway)).await;
    let valid = plan_body("en", "Route only Chrome through the VPN.", true);

    let mut unknown_field = valid.clone();
    unknown_field["app"] = json!("chrome");
    let mut missing_target = valid.clone();
    missing_target
        .as_object_mut()
        .unwrap()
        .remove("target_available");
    let mut wrong_schema = valid.clone();
    wrong_schema["schema"] = json!(2);
    let mut wrong_locale = valid.clone();
    wrong_locale["locale"] = json!("de");
    let mut wrong_target_type = valid.clone();
    wrong_target_type["target_available"] = json!("true");
    let mut empty_goal = valid.clone();
    empty_goal["goal"] = json!("");
    let mut long_goal = valid.clone();
    long_goal["goal"] = json!("a".repeat(769));
    let mut control_goal = valid.clone();
    control_goal["goal"] = json!("Route\u{0007}only Chrome.");
    let mut direction_goal = valid.clone();
    direction_goal["goal"] = json!("\u{202e}Route only Chrome.");

    for (index, (case, body)) in [
        ("unknown field", unknown_field),
        ("missing target", missing_target),
        ("wrong schema", wrong_schema),
        ("wrong locale", wrong_locale),
        ("wrong target type", wrong_target_type),
        ("empty goal", empty_goal),
        ("long goal", long_goal),
        ("control character", control_goal),
        ("directional control", direction_goal),
    ]
    .into_iter()
    .enumerate()
    {
        let user = fixture.user(0x100 + index as u32, false).await;
        let [(identity, credential), _] = credentials(&user);
        let response = fixture
            .send(request(identity, credential, body.to_string()))
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{case}");
    }
    assert!(upstream.requests.try_recv().is_err());
}

#[tokio::test]
async fn goal_bounds_use_trimmed_utf8_bytes() {
    let (upstream, gateway) = Upstream::start(
        StatusCode::OK,
        completion(&json!({"operation": "route_only_app"})),
    )
    .await;
    let fixture = Fixture::new(Some(gateway)).await;
    let user = fixture.user(0xab, false).await;
    let [(identity, credential), _] = credentials(&user);
    let max_goal = "\u{e9}".repeat(384);
    assert_eq!(max_goal.len(), 768);

    for goal in [max_goal.clone(), format!("  {max_goal}  ")] {
        let expected = plan_body("en", &max_goal, true);
        let response = fixture
            .send(request(
                identity,
                credential,
                plan_body("en", &goal, true).to_string(),
            ))
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let (headers, payload) = upstream.requests.try_recv().unwrap();
        assert_upstream_request(&headers, &payload, &expected, &user);
    }

    for invalid in [
        "a".repeat(769),
        "\u{e9}".repeat(385),
        String::from(" \t\n "),
    ] {
        let response = fixture
            .send(request(
                identity,
                credential,
                plan_body("en", &invalid, true).to_string(),
            ))
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn goal_cannot_echo_the_caller_credential() {
    let (upstream, gateway) = Upstream::start(
        StatusCode::OK,
        completion(&json!({"operation": "route_only_app"})),
    )
    .await;
    let fixture = Fixture::new(Some(gateway)).await;
    let user = fixture.user(0xab, false).await;

    for (identity, credential) in credentials(&user) {
        let goal = format!("Route only {credential} through the VPN.");
        let response = fixture
            .send(request(
                identity,
                credential,
                plan_body("en", &goal, true).to_string(),
            ))
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    assert!(upstream.requests.try_recv().is_err());
}

#[tokio::test]
async fn valid_clarifications_return_the_typed_result() {
    assert_valid_result(
        json!({"operation": "clarify", "reason": "app_selection"}),
        false,
        "en",
        json!({"schema": 1, "result": {"operation": "clarify", "reason": "app_selection"}}),
    )
    .await;
    assert_valid_result(
        json!({"operation": "clarify", "reason": "unsupported_goal"}),
        true,
        "ru",
        json!({"schema": 1, "result": {"operation": "clarify", "reason": "unsupported_goal"}}),
    )
    .await;
}

#[tokio::test]
async fn invalid_model_results_are_rejected() {
    assert_bad_model(completion(&json!({"operation": "route_only_app"})), false).await;
    assert_bad_model(
        completion(&json!({"operation": "route_only_app", "extra": "synthetic"})),
        true,
    )
    .await;
    assert_bad_model(completion(&json!({"operation": "apply_everything"})), true).await;
    assert_bad_model(completion(&json!({"operation": "clarify"})), true).await;
    assert_bad_model(
        completion(&json!({"operation": "clarify", "reason": "unsupported_goal", "extra": true})),
        true,
    )
    .await;
    assert_bad_model(
        completion(&json!({"operation": "clarify", "reason": "not_a_reason"})),
        true,
    )
    .await;
    assert_bad_model(
        json!({"choices": [{"message": {"content": "not json"}}]}),
        true,
    )
    .await;
}

#[tokio::test]
async fn provider_failures_are_hidden() {
    const PRIVATE_ERROR: &str = "synthetic-private-vpnrouter-upstream-error";
    let (upstream, gateway) = Upstream::start(
        StatusCode::INTERNAL_SERVER_ERROR,
        json!({"error": PRIVATE_ERROR}),
    )
    .await;
    let fixture = Fixture::new(Some(gateway)).await;
    let user = fixture.user(0xab, false).await;
    let [(identity, credential), _] = credentials(&user);
    let body = plan_body("en", "Route only Chrome through the VPN.", true);

    let response = fixture
        .send(request(identity, credential, body.to_string()))
        .await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let text = response_text(response).await;
    assert!(!text.contains(PRIVATE_ERROR));
    assert!(!text.contains(credential));
    assert!(!text.contains(GATEWAY_KEY));
    assert!(upstream.requests.try_recv().is_ok());
}

#[tokio::test]
async fn a_valid_request_without_a_gateway_is_unavailable() {
    let fixture = Fixture::new(None).await;
    let user = fixture.user(0xab, false).await;
    let [(identity, credential), _] = credentials(&user);
    let body = plan_body("en", "Route only Chrome through the VPN.", true);

    let response = fixture
        .send(request(identity, credential, body.to_string()))
        .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let text = response_text(response).await;
    assert!(!text.contains(credential));
    assert!(!text.contains(GATEWAY_KEY));
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
            {"id": 1, "name": "SmpToggleConnectCommand", "kind": "press"},
            {"id": 2, "name": "ChangeMode", "kind": "toggle", "active": false},
            {"id": 3, "name": "ServerRow", "kind": "select", "active": false},
            {"id": 4, "name": "SearchField", "kind": "text"},
            {"id": 32, "name": "SettingsMenu", "kind": "expand"}
        ]
    })
}

#[tokio::test]
async fn step_requires_an_enabled_subscription_or_device_identity() {
    let (upstream, gateway) =
        Upstream::start(StatusCode::OK, completion(&json!({"operation": "finish"}))).await;
    let fixture = Fixture::new(Some(gateway)).await;
    let disabled = fixture.user(0xd1, true).await;
    let body = step_body().to_string();
    for (identity, credential) in credentials(&disabled) {
        let response = fixture
            .send(request_at(STEP_PATH, identity, credential, body.clone()))
            .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_no_store(&response);

        let mut missing = request_at(STEP_PATH, identity, credential, body.clone());
        missing.headers_mut().remove(AUTHORIZATION);
        let response = fixture.send(missing).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_no_store(&response);
    }
    assert!(upstream.requests.try_recv().is_err());
}

#[tokio::test]
async fn step_forwards_only_the_public_request_and_returns_a_typed_action_for_both_identities() {
    let action = json!({"operation": "act", "id": 2, "value": true});
    let (upstream, gateway) = Upstream::start(StatusCode::OK, completion(&action)).await;
    let fixture = Fixture::new(Some(gateway)).await;
    let user = fixture.user(0xd2, false).await;
    let mut body = step_body();
    body["goal"] = json!("Change the mode");
    body["controls"] = json!([{"id": 2, "name": "ChangeMode", "kind": "toggle", "active": false}]);
    body["previous"] = json!("SettingsMenu");
    for (identity, credential) in credentials(&user) {
        let response = fixture
            .send(request_at(
                STEP_PATH,
                identity,
                credential,
                body.to_string(),
            ))
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_no_store(&response);
        let text = response_text(response).await;
        assert!(!text.contains(credential));
        assert!(!text.contains(GATEWAY_KEY));
        assert_eq!(
            serde_json::from_str::<Value>(&text).unwrap(),
            json!({"schema": 2, "result": action})
        );

        let (headers, payload) = upstream.requests.try_recv().unwrap();
        assert_upstream_request(&headers, &payload, &body, &user);
    }
    assert!(upstream.requests.try_recv().is_err());
}

async fn assert_step_result(action: Value, status: StatusCode) {
    let (upstream, gateway) = Upstream::start(StatusCode::OK, completion(&action)).await;
    let fixture = Fixture::new(Some(gateway)).await;
    let user = fixture.user(0xd3, false).await;
    let [_, (identity, credential)] = credentials(&user);
    let response = fixture
        .send(request_at(
            STEP_PATH,
            identity,
            credential,
            step_body().to_string(),
        ))
        .await;
    assert_eq!(response.status(), status, "model reply: {action}");
    assert_no_store(&response);
    let text = response_text(response).await;
    assert!(!text.contains(credential));
    assert!(!text.contains(GATEWAY_KEY));
    if status == StatusCode::OK {
        assert_eq!(
            serde_json::from_str::<Value>(&text).unwrap(),
            json!({"schema": 2, "result": action})
        );
    }
    assert_eq!(upstream.requests.try_iter().count(), 1);
}

#[tokio::test]
async fn step_accepts_the_advertised_action_types_and_exact_terminal_replies() {
    for reply in [
        json!({"operation": "act", "id": 1}),
        json!({"operation": "act", "id": 2, "value": false}),
        json!({"operation": "act", "id": 3}),
        json!({"operation": "act", "id": 4, "value": "\u{e9}".repeat(192)}),
        json!({"operation": "act", "id": 32}),
        json!({"operation": "finish"}),
        json!({"operation": "clarify"}),
    ] {
        assert_step_result(reply, StatusCode::OK).await;
    }
}

#[tokio::test]
async fn step_rejects_unadvertised_controls_and_invalid_action_values() {
    for reply in [
        json!({"operation": "act", "id": 31}),
        json!({"operation": "act", "id": 1, "value": true}),
        json!({"operation": "act", "id": 1, "value": null}),
        json!({"operation": "act", "id": 2}),
        json!({"operation": "act", "id": 2, "value": "true"}),
        json!({"operation": "act", "id": 3, "value": false}),
        json!({"operation": "act", "id": 4, "value": false}),
        json!({"operation": "act", "id": 4, "value": "\u{e9}".repeat(193)}),
        json!({"operation": "act", "id": 4, "value": "\ttext"}),
        json!({"operation": "act", "id": 4, "value": "\u{202e}text"}),
        json!({"operation": "act", "id": 32, "value": 1}),
        json!({"operation": "act", "id": "1"}),
        json!({"operation": "act", "id": 1, "target": "another-control"}),
        json!({"operation": "finish", "id": 1}),
        json!({"operation": "clarify", "reason": "unknown-control"}),
        json!({"operation": "route_only_app"}),
    ] {
        assert_step_result(reply, StatusCode::BAD_GATEWAY).await;
    }
}

#[tokio::test]
async fn step_checks_the_inventory_before_forwarding_and_keeps_v1_on_plan() {
    let (upstream, gateway) =
        Upstream::start(StatusCode::OK, completion(&json!({"operation": "finish"}))).await;
    let fixture = Fixture::new(Some(gateway)).await;
    let user = fixture.user(0xd4, false).await;
    let [(identity, credential), _] = credentials(&user);

    for (path, body) in [
        (STEP_PATH, plan_body("en", "Enable VPN", true)),
        (PATH, step_body()),
    ] {
        let response = fixture
            .send(request_at(path, identity, credential, body.to_string()))
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path}");
        assert_no_store(&response);
    }

    for (field, value) in [
        ("busy", json!("false")),
        ("previous", json!("Settings Menu")),
        (
            "raw_fields",
            json!({"SearchField": "synthetic-private-text"}),
        ),
    ] {
        let mut body = step_body();
        body[field] = value;
        let response = fixture
            .send(request_at(
                STEP_PATH,
                identity,
                credential,
                body.to_string(),
            ))
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{field}");
        assert_no_store(&response);
    }

    for (field, value) in [
        ("id", json!(0)),
        ("id", json!(2)),
        ("id", json!(33)),
        ("kind", json!("unadvertised-kind")),
        ("name", json!("")),
        ("name", json!("a".repeat(73))),
        ("name", json!("settings/menu")),
        ("value", json!("synthetic-private-field-text")),
    ] {
        let mut body = step_body();
        body["controls"][0][field] = value;
        let response = fixture
            .send(request_at(
                STEP_PATH,
                identity,
                credential,
                body.to_string(),
            ))
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{field}");
        assert_no_store(&response);
    }

    assert!(upstream.requests.try_recv().is_err());
}

#[tokio::test]
async fn step_body_limit_is_exactly_2048_bytes() {
    let (upstream, gateway) =
        Upstream::start(StatusCode::OK, completion(&json!({"operation": "finish"}))).await;
    let fixture = Fixture::new(Some(gateway)).await;
    let user = fixture.user(0xd5, false).await;
    let [(identity, credential), _] = credentials(&user);
    let compact = step_body().to_string();
    assert!(compact.len() < 2048);

    for (length, status) in [
        (2048, StatusCode::OK),
        (2049, StatusCode::PAYLOAD_TOO_LARGE),
    ] {
        let body = format!("{compact:<length$}");
        assert_eq!(body.len(), length);
        let response = fixture
            .send(request_at(STEP_PATH, identity, credential, body))
            .await;
        assert_eq!(response.status(), status);
        assert_no_store(&response);
    }
    assert_eq!(upstream.requests.try_iter().count(), 1);
}

#[tokio::test]
async fn step_and_plan_share_the_account_quota_across_identity_forms() {
    let (upstream, gateway) =
        Upstream::start(StatusCode::OK, completion(&json!({"operation": "finish"}))).await;
    let fixture = Fixture::new(Some(gateway)).await;
    let user = fixture.user(0xd6, false).await;
    let [(subscription, token), (device, device_id)] = credentials(&user);
    let body = step_body();
    for _ in 0..6 {
        let response = fixture
            .send(request_at(STEP_PATH, device, device_id, body.to_string()))
            .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    let response = fixture
        .send(request(
            subscription,
            token,
            plan_body("en", "Enable VPN", true).to_string(),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_no_store(&response);
    assert!(response.headers().contains_key(RETRY_AFTER));
    assert_eq!(upstream.requests.try_iter().count(), 6);
}

#[tokio::test]
async fn step_does_not_echo_an_escaped_gateway_credential() {
    let secret = format!(
        r"\u{:04x}{}",
        u32::from(GATEWAY_KEY.as_bytes()[0]),
        &GATEWAY_KEY[1..]
    );
    let content = format!(r#"{{"operation":"act","id":4,"value":"{secret}"}}"#);
    let (upstream, gateway) = Upstream::start(
        StatusCode::OK,
        json!({"choices": [{"message": {"content": content}}]}),
    )
    .await;
    let fixture = Fixture::new(Some(gateway)).await;
    let user = fixture.user(0xdf, false).await;
    let [(identity, credential), _] = credentials(&user);
    let response = fixture
        .send(request_at(
            STEP_PATH,
            identity,
            credential,
            step_body().to_string(),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_no_store(&response);
    assert!(!response_text(response).await.contains(GATEWAY_KEY));
    assert!(upstream.requests.try_recv().is_ok());
}

fn crash_observation() -> Value {
    json!({
        "fatal": true,
        "fault": "null_reference",
        "area": "startup",
        "signal": "none"
    })
}

fn crash_step_body() -> Value {
    let mut body = step_body();
    body["controls"] = json!([]);
    body["crash"] = crash_observation();
    body
}

fn diagnosis_reply(summary: &str) -> Value {
    json!({"operation": "diagnosis", "summary": summary})
}

async fn step_model_reply(body: Value, reply: Value, status: StatusCode) -> String {
    let (upstream, gateway) = Upstream::start(StatusCode::OK, completion(&reply)).await;
    let fixture = Fixture::new(Some(gateway)).await;
    let user = fixture.user(0xe8, false).await;
    let [_, (identity, credential)] = credentials(&user);
    let response = fixture
        .send(request_at(
            STEP_PATH,
            identity,
            credential,
            body.to_string(),
        ))
        .await;
    assert_eq!(response.status(), status, "model reply: {reply}");
    assert_no_store(&response);
    let text = response_text(response).await;
    assert!(!text.contains(credential));
    assert!(!text.contains(GATEWAY_KEY));
    assert_eq!(upstream.requests.try_iter().count(), 1);
    text
}

async fn assert_crash_step_bad_request(case: &str, body: Value) {
    let (upstream, gateway) = Upstream::start(
        StatusCode::OK,
        completion(&diagnosis_reply("Synthetic unused diagnosis.")),
    )
    .await;
    let fixture = Fixture::new(Some(gateway)).await;
    let user = fixture.user(0xe9, false).await;
    let [_, (identity, credential)] = credentials(&user);
    let response = fixture
        .send(request_at(
            STEP_PATH,
            identity,
            credential,
            body.to_string(),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{case}");
    assert_no_store(&response);
    let text = response_text(response).await;
    assert!(!text.contains(credential));
    assert!(!text.contains(GATEWAY_KEY));
    assert!(upstream.requests.try_recv().is_err(), "{case}");
}

#[tokio::test]
async fn step_accepts_crash_diagnosis_for_both_identities_and_forwards_the_evidence() {
    let summary = "The VPN service stopped after a routing failure.";
    let reply = diagnosis_reply(summary);
    let (upstream, gateway) = Upstream::start(StatusCode::OK, completion(&reply)).await;
    let fixture = Fixture::new(Some(gateway)).await;
    let user = fixture.user(0xe0, false).await;
    let body = crash_step_body();
    let expected = json!({"schema": 2, "result": reply});

    for (identity, credential) in credentials(&user) {
        let response = fixture
            .send(request_at(
                STEP_PATH,
                identity,
                credential,
                body.to_string(),
            ))
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_no_store(&response);
        let text = response_text(response).await;
        assert!(!text.contains(credential));
        assert!(!text.contains(GATEWAY_KEY));
        assert_eq!(serde_json::from_str::<Value>(&text).unwrap(), expected);

        let (headers, payload) = upstream.requests.try_recv().unwrap();
        assert_upstream_request(&headers, &payload, &body, &user);
    }
    assert!(upstream.requests.try_recv().is_err());
}

#[tokio::test]
async fn step_accepts_every_advertised_crash_value() {
    let summary = "Synthetic crash diagnosis.";
    let reply = diagnosis_reply(summary);
    let (upstream, gateway) = Upstream::start(StatusCode::OK, completion(&reply)).await;
    let fixture = Fixture::new(Some(gateway)).await;
    let expected = json!({"schema": 2, "result": reply});
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
    let mut cases = vec![(false, "unknown", "unknown", "none")];
    cases.extend(faults.iter().map(|fault| (true, *fault, "unknown", "none")));
    cases.extend(areas.iter().map(|area| (true, "unknown", *area, "none")));
    cases.extend(
        signals
            .iter()
            .map(|signal| (true, "unknown", "unknown", *signal)),
    );

    for (index, (fatal, fault, area, signal)) in cases.into_iter().enumerate() {
        let mut body = step_body();
        body["controls"] = json!([]);
        body["crash"] = json!({"fatal": fatal, "fault": fault, "area": area, "signal": signal});
        let user = fixture.user(0x200 + index as u32, false).await;
        let [_, (identity, credential)] = credentials(&user);
        let response = fixture
            .send(request_at(
                STEP_PATH,
                identity,
                credential,
                body.to_string(),
            ))
            .await;
        assert_eq!(response.status(), StatusCode::OK, "{fault}/{area}/{signal}");
        assert_no_store(&response);
        let text = response_text(response).await;
        assert_eq!(serde_json::from_str::<Value>(&text).unwrap(), expected);

        let (headers, payload) = upstream.requests.try_recv().unwrap();
        assert_upstream_request(&headers, &payload, &body, &user);
    }
    assert!(upstream.requests.try_recv().is_err());
}

#[tokio::test]
async fn step_rejects_invalid_crash_observations_before_the_model() {
    let mut unknown_nested = crash_step_body();
    unknown_nested["crash"]["backtrace"] = json!("synthetic-private-backtrace");

    let mut unknown_fault = crash_step_body();
    unknown_fault["crash"]["fault"] = json!("segfault");

    let mut unknown_area = crash_step_body();
    unknown_area["crash"]["area"] = json!("daemon");

    let mut unknown_signal = crash_step_body();
    unknown_signal["crash"]["signal"] = json!("stopped");

    let mut uppercase_fault = crash_step_body();
    uppercase_fault["crash"]["fault"] = json!("IO");

    let mut wrong_fatal = crash_step_body();
    wrong_fatal["crash"]["fatal"] = json!("true");

    let mut missing_fatal = crash_step_body();
    missing_fatal["crash"]
        .as_object_mut()
        .unwrap()
        .remove("fatal");

    let mut missing_fault = crash_step_body();
    missing_fault["crash"]
        .as_object_mut()
        .unwrap()
        .remove("fault");

    let mut missing_area = crash_step_body();
    missing_area["crash"]
        .as_object_mut()
        .unwrap()
        .remove("area");

    let mut missing_signal = crash_step_body();
    missing_signal["crash"]
        .as_object_mut()
        .unwrap()
        .remove("signal");

    let mut scalar_crash = step_body();
    scalar_crash["controls"] = json!([]);
    scalar_crash["crash"] = json!(true);

    let mut non_empty_controls = step_body();
    non_empty_controls["crash"] = crash_observation();

    let mut crash_with_previous = crash_step_body();
    crash_with_previous["previous"] = json!("SettingsMenu");

    let mut missing_controls = crash_step_body();
    missing_controls.as_object_mut().unwrap().remove("controls");

    for (case, body) in [
        ("unknown nested field", unknown_nested),
        ("unknown fault", unknown_fault),
        ("unknown area", unknown_area),
        ("unknown signal", unknown_signal),
        ("case-sensitive fault", uppercase_fault),
        ("wrong fatal type", wrong_fatal),
        ("missing fatal", missing_fatal),
        ("missing fault", missing_fault),
        ("missing area", missing_area),
        ("missing signal", missing_signal),
        ("scalar crash", scalar_crash),
        ("non-empty controls", non_empty_controls),
        ("previous with crash", crash_with_previous),
        ("missing controls", missing_controls),
    ] {
        assert_crash_step_bad_request(case, body).await;
    }
}

#[tokio::test]
async fn step_rejects_diagnosis_without_crash_evidence() {
    step_model_reply(
        step_body(),
        diagnosis_reply("Synthetic uncorroborated diagnosis."),
        StatusCode::BAD_GATEWAY,
    )
    .await;
}

#[tokio::test]
async fn step_rejects_non_diagnosis_replies_with_crash_evidence() {
    for reply in [
        json!({"operation": "act", "id": 1}),
        json!({"operation": "act", "id": 2, "value": true}),
        json!({"operation": "finish"}),
        json!({"operation": "clarify"}),
    ] {
        step_model_reply(crash_step_body(), reply, StatusCode::BAD_GATEWAY).await;
    }
}

#[tokio::test]
async fn step_accepts_diagnosis_summary_within_the_byte_bound() {
    for summary in ["a".to_string(), "a".repeat(384), "\u{e9}".repeat(192)] {
        let text =
            step_model_reply(crash_step_body(), diagnosis_reply(&summary), StatusCode::OK).await;
        assert_eq!(
            serde_json::from_str::<Value>(&text).unwrap(),
            json!({"schema": 2, "result": {"operation": "diagnosis", "summary": summary}})
        );
    }
}

#[tokio::test]
async fn step_rejects_invalid_diagnosis_summaries() {
    let long_utf8 = format!("{}a", "\u{e9}".repeat(192));
    assert_eq!(long_utf8.len(), 385);

    for summary in [
        String::new(),
        " \t\n ".to_string(),
        "a".repeat(385),
        long_utf8,
        "diagnosis\u{0007}synthetic".to_string(),
        "diagnosis\nsynthetic".to_string(),
        "\u{202e}diagnosis".to_string(),
    ] {
        step_model_reply(
            crash_step_body(),
            diagnosis_reply(&summary),
            StatusCode::BAD_GATEWAY,
        )
        .await;
    }

    for reply in [
        json!({"operation": "diagnosis"}),
        json!({"operation": "diagnosis", "summary": 7}),
        json!({"operation": "diagnosis", "summary": "Synthetic.", "fatal": true}),
        json!({"operation": "diagnosis", "summary": "Synthetic.", "extra": "synthetic"}),
    ] {
        step_model_reply(crash_step_body(), reply, StatusCode::BAD_GATEWAY).await;
    }
}

#[tokio::test]
async fn step_diagnosis_summary_cannot_echo_account_credentials() {
    for (index, number) in [0xe9_u32, 0xea].into_iter().enumerate() {
        let subscription = format!("synthetic-vpnrouter-subscription_{number}");
        let device = format!("{number:032x}");
        let summary = if index == 0 {
            format!("Synthetic diagnosis for {subscription}.")
        } else {
            format!("Synthetic diagnosis for {device}.")
        };
        let (upstream, gateway) =
            Upstream::start(StatusCode::OK, completion(&diagnosis_reply(&summary))).await;
        let fixture = Fixture::new(Some(gateway)).await;
        let user = fixture.user(number, false).await;
        let [subscription_pair, device_pair] = credentials(&user);
        let (identity, credential) = if index == 0 {
            subscription_pair
        } else {
            device_pair
        };

        let response = fixture
            .send(request_at(
                STEP_PATH,
                identity,
                credential,
                crash_step_body().to_string(),
            ))
            .await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY, "{summary}");
        assert_no_store(&response);
        let text = response_text(response).await;
        assert!(!text.contains(summary.as_str()));
        assert!(!text.contains(subscription.as_str()));
        assert!(!text.contains(device.as_str()));
        assert!(!text.contains(credential));
        assert!(!text.contains(GATEWAY_KEY));
        assert_eq!(upstream.requests.try_iter().count(), 1);
    }
}

#[tokio::test]
async fn step_diagnosis_summary_cannot_echo_the_gateway_credential() {
    let summary = format!("Synthetic diagnosis for {GATEWAY_KEY}.");
    let text = step_model_reply(
        crash_step_body(),
        diagnosis_reply(&summary),
        StatusCode::BAD_GATEWAY,
    )
    .await;
    assert!(!text.contains(GATEWAY_KEY));
}

#[tokio::test]
async fn step_diagnosis_summary_cannot_hide_the_gateway_credential() {
    let secret = format!(
        r"\u{:04x}{}",
        u32::from(GATEWAY_KEY.as_bytes()[0]),
        &GATEWAY_KEY[1..]
    );
    let content = format!(r#"{{"operation":"diagnosis","summary":"{secret}"}}"#);
    let (upstream, gateway) = Upstream::start(
        StatusCode::OK,
        json!({"choices": [{"message": {"content": content}}]}),
    )
    .await;
    let fixture = Fixture::new(Some(gateway)).await;
    let user = fixture.user(0xeb, false).await;
    let [_, (identity, credential)] = credentials(&user);
    let response = fixture
        .send(request_at(
            STEP_PATH,
            identity,
            credential,
            crash_step_body().to_string(),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_no_store(&response);
    assert!(!response_text(response).await.contains(GATEWAY_KEY));
    assert_eq!(upstream.requests.try_iter().count(), 1);
}

#[tokio::test]
async fn step_keeps_existing_actions_without_crash_evidence() {
    for reply in [
        json!({"operation": "act", "id": 1}),
        json!({"operation": "finish"}),
        json!({"operation": "clarify"}),
    ] {
        let body = step_body();
        let text = step_model_reply(body, reply.clone(), StatusCode::OK).await;
        assert_eq!(
            serde_json::from_str::<Value>(&text).unwrap(),
            json!({"schema": 2, "result": reply})
        );
    }
}
