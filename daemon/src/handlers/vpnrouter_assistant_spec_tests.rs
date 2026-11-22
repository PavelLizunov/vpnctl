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
    Request::post(PATH)
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
