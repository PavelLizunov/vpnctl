#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::sync::{Arc, mpsc};

use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, RETRY_AFTER};
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode};
use axum::response::Response;
use axum::{Json, Router, routing::post};
use serde_json::{Value, json};
use tower::ServiceExt;
use vpnctl_core::{User, UserId};
use vpnctl_inventory::SqliteInventory;

use super::nina_assistant::{Gateway, router};

const IDENTITY: &str = "x-vpnctl-identity";
const MODEL: &str = "synthetic-diagnostic-model";
const GATEWAY_KEY: &str = "synthetic-server-key";
const EXPLANATION: &str = "DNS resolved, but HTTPS to YouTube failed.";

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
            id: UserId(format!("synthetic-user-{number}")),
            uuid: vpnctl_crypto::gen_uuid(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: Some(format!("synthetic-subscription_{number}")),
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

fn report() -> Value {
    json!({
        "schema": 1,
        "state": "active",
        "enabled": null,
        "checks": [
            { "id": "dns.youtube", "ok": true },
            { "id": "dns.discord", "ok": true },
            { "id": "dns.control", "ok": true },
            { "id": "https.youtube", "ok": false },
            { "id": "https.discord", "ok": true },
            { "id": "public_ipv4", "ok": true }
        ]
    })
}

fn completion() -> Value {
    json!({"choices": [{"message": {"content": EXPLANATION}}]})
}

fn credentials(user: &User) -> [(&str, &str); 2] {
    [
        ("subscription", user.sub_token.as_deref().unwrap()),
        ("device", user.vpn_router_device_id.as_deref().unwrap()),
    ]
}

fn request(identity: &str, credential: &str, body: String) -> Request<Body> {
    Request::post("/api/v1/assistant/diagnose")
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, format!("Bearer {credential}"))
        .header(IDENTITY, identity)
        .body(Body::from(body))
        .unwrap()
}

async fn response_text(response: Response) -> String {
    let bytes = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[test]
fn gateway_accepts_https_and_limits_plain_http_to_loopback() {
    assert!(
        Gateway::new(
            "https://synthetic.example.test/diagnose",
            MODEL,
            GATEWAY_KEY
        )
        .is_ok()
    );
    assert!(Gateway::new("http://127.0.0.1:8080/diagnose", MODEL, GATEWAY_KEY).is_ok());
    assert!(Gateway::new("http://192.0.2.1/diagnose", MODEL, GATEWAY_KEY).is_err());
}

#[tokio::test]
async fn both_credentials_return_an_explanation_and_forward_only_the_report() {
    let (upstream, gateway) = Upstream::start(StatusCode::OK, completion()).await;
    let fixture = Fixture::new(Some(gateway)).await;
    let user = fixture.user(0xab, false).await;
    let report = report();
    let report_json = report.to_string();
    let body = format!("{report_json:<2048}");

    for (identity, credential) in credentials(&user) {
        let response = fixture
            .send(request(identity, credential, body.clone()))
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let cache_control = response.headers()[CACHE_CONTROL].to_str().unwrap();
        assert!(
            cache_control
                .split(',')
                .any(|part| part.trim() == "no-store")
        );
        let result: Value = serde_json::from_str(&response_text(response).await).unwrap();
        assert_eq!(result, json!({"schema": 1, "explanation": EXPLANATION}));

        let (headers, payload) = upstream.requests.try_recv().unwrap();
        assert_eq!(
            headers[AUTHORIZATION].to_str().unwrap(),
            format!("Bearer {GATEWAY_KEY}")
        );
        assert_eq!(payload["model"], MODEL);
        let messages = payload["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0]["role"], "system");
        assert!(!messages[0]["content"].as_str().unwrap().trim().is_empty());
        assert_eq!(messages[1]["role"], "user");
        let forwarded: Value =
            serde_json::from_str(messages[1]["content"].as_str().unwrap()).unwrap();
        assert_eq!(forwarded, report);
        for private in [
            user.id.0.as_str(),
            user.sub_token.as_deref().unwrap(),
            user.vpn_router_device_id.as_deref().unwrap(),
        ] {
            assert!(!payload.to_string().contains(private));
            assert!(
                !headers
                    .values()
                    .any(|value| { value.to_str().is_ok_and(|value| value.contains(private)) })
            );
        }
    }
}

#[tokio::test]
async fn authentication_denies_missing_malformed_unknown_and_disabled_credentials() {
    let fixture = Fixture::new(None).await;
    let user = fixture.user(0xab, false).await;
    let disabled = fixture.user(0xbc, true).await;
    let [(subscription, token), (device, device_id)] = credentials(&user);
    let body = report().to_string();
    let mut absent_bearer = request(subscription, token, body.clone());
    absent_bearer.headers_mut().remove(AUTHORIZATION);
    let mut absent_identity = request(subscription, token, body.clone());
    absent_identity.headers_mut().remove(IDENTITY);
    let mut wrong_scheme = request(subscription, token, body.clone());
    wrong_scheme.headers_mut().insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Basic {token}")).unwrap(),
    );
    let mut duplicate_bearer = request(subscription, token, body.clone());
    duplicate_bearer.headers_mut().append(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
    );
    let mut duplicate_identity = request(subscription, token, body.clone());
    duplicate_identity
        .headers_mut()
        .append(IDENTITY, HeaderValue::from_static("subscription"));
    let oversized_token = format!("synthetic-{}", "a".repeat(247));

    for (case, denied) in [
        ("missing bearer", absent_bearer),
        ("missing identity", absent_identity),
        ("wrong scheme", wrong_scheme),
        ("duplicate bearer", duplicate_bearer),
        ("duplicate identity", duplicate_identity),
        ("unknown identity", request("account", token, body.clone())),
        (
            "invalid token",
            request(subscription, "synthetic.bad", body.clone()),
        ),
        (
            "oversized token",
            request(subscription, &oversized_token, body.clone()),
        ),
        (
            "unknown token",
            request(subscription, "synthetic-unknown", body.clone()),
        ),
        (
            "uppercase device ID",
            request(device, &device_id.to_uppercase(), body.clone()),
        ),
        (
            "unknown device ID",
            request(device, "000000000000000000000000000000cd", body.clone()),
        ),
        (
            "wrong credential type",
            request(device, token, body.clone()),
        ),
    ] {
        assert_eq!(
            fixture.send(denied).await.status(),
            StatusCode::UNAUTHORIZED,
            "{case}"
        );
    }
    for (identity, credential) in credentials(&disabled) {
        assert_eq!(
            fixture
                .send(request(identity, credential, body.clone()))
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(
        fixture
            .send(request(subscription, token, body))
            .await
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
async fn both_credentials_share_six_requests_without_consuming_another_users_quota() {
    let (upstream, gateway) = Upstream::start(StatusCode::OK, completion()).await;
    let fixture = Fixture::new(Some(gateway)).await;
    let user = fixture.user(0xab, false).await;
    let other_user = fixture.user(0xbc, false).await;
    let body = report().to_string();
    let identities = credentials(&user);

    for (identity, credential) in identities.into_iter().cycle().take(6) {
        let response = fixture
            .send(request(identity, credential, body.clone()))
            .await;
        assert_eq!(response.status(), StatusCode::OK);
    }
    for (identity, credential) in identities {
        let response = fixture
            .send(request(identity, credential, body.clone()))
            .await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(
            !response.headers()[RETRY_AFTER]
                .to_str()
                .unwrap()
                .trim()
                .is_empty()
        );
    }
    let [(identity, credential), _] = credentials(&other_user);
    assert_eq!(
        fixture
            .send(request(identity, credential, body))
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(upstream.requests.try_iter().count(), 7);
}

#[tokio::test]
async fn unauthenticated_requests_are_limited_by_their_peer() {
    let fixture = Fixture::new(None).await;
    for index in 0..=120 {
        let mut request = request("subscription", "synthetic-unknown", "{}".into());
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([192, 0, 2, 1], 1234))));
        let response = fixture.send(request).await;
        if index < 120 {
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        } else {
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
            assert!(response.headers().contains_key(RETRY_AFTER));
        }
    }
}

#[tokio::test]
async fn invalid_reports_and_oversized_json_never_reach_the_gateway() {
    let (upstream, gateway) = Upstream::start(StatusCode::OK, completion()).await;
    let fixture = Fixture::new(Some(gateway)).await;
    let valid = report();
    let mut invalid = Vec::new();
    for (key, value) in [
        ("schema", json!(2)),
        ("state", json!("invalid")),
        ("enabled", json!("true")),
        ("extra", json!("synthetic-extra-field")),
    ] {
        let mut body = valid.clone();
        body[key] = value;
        invalid.push((key, body));
    }
    for (case, check) in [
        ("duplicate ID", json!({"id": "dns.discord", "ok": true})),
        ("unknown ID", json!({"id": "dns.other", "ok": true})),
        ("nonboolean result", json!({"id": "dns.youtube", "ok": 1})),
        (
            "extra check field",
            json!({"id": "dns.youtube", "ok": true, "host": "synthetic.example.test"}),
        ),
    ] {
        let mut body = valid.clone();
        body["checks"][0] = check;
        invalid.push((case, body));
    }
    let mut missing_check = valid.clone();
    missing_check["checks"].as_array_mut().unwrap().pop();
    invalid.push(("missing check", missing_check));
    let mut missing_enabled = valid.clone();
    missing_enabled.as_object_mut().unwrap().remove("enabled");
    invalid.push(("missing enabled", missing_enabled));

    for (number, (case, body)) in (1..).zip(invalid) {
        let user = fixture.user(number, false).await;
        let [(identity, credential), _] = credentials(&user);
        let response = fixture
            .send(request(identity, credential, body.to_string()))
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{case}");
    }
    let user = fixture.user(0xab, false).await;
    let [(identity, credential), _] = credentials(&user);
    let report_json = valid.to_string();
    let response = fixture
        .send(request(
            identity,
            credential,
            format!("{report_json:<2049}"),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(upstream.requests.try_recv().is_err());
}

#[tokio::test]
async fn gateway_errors_preserve_throttling_and_hide_the_upstream_body() {
    const PRIVATE_ERROR: &str = "synthetic-private-upstream-error";
    for (upstream_status, client_status) in [
        (StatusCode::TOO_MANY_REQUESTS, StatusCode::TOO_MANY_REQUESTS),
        (StatusCode::UNAUTHORIZED, StatusCode::BAD_GATEWAY),
        (StatusCode::INTERNAL_SERVER_ERROR, StatusCode::BAD_GATEWAY),
        (StatusCode::OK, StatusCode::BAD_GATEWAY),
    ] {
        let (upstream, gateway) =
            Upstream::start(upstream_status, json!({"error": PRIVATE_ERROR})).await;
        let fixture = Fixture::new(Some(gateway)).await;
        let user = fixture.user(0xab, false).await;
        let [(identity, credential), _] = credentials(&user);
        let response = fixture
            .send(request(identity, credential, report().to_string()))
            .await;
        assert_eq!(
            response.status(),
            client_status,
            "upstream {upstream_status}"
        );
        assert!(!response_text(response).await.contains(PRIVATE_ERROR));
        assert!(upstream.requests.try_recv().is_ok());
    }
}

#[tokio::test]
async fn a_successful_explanation_is_bounded() {
    let content = "a".repeat(4097);
    let (_upstream, gateway) = Upstream::start(
        StatusCode::OK,
        json!({"choices": [{"message": {"content": content}}]}),
    )
    .await;
    let fixture = Fixture::new(Some(gateway)).await;
    let user = fixture.user(0xab, false).await;
    let [(identity, credential), _] = credentials(&user);
    let response = fixture
        .send(request(identity, credential, report().to_string()))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let result: Value = serde_json::from_str(&response_text(response).await).unwrap();
    assert_eq!(result["schema"], 1);
    let explanation = result["explanation"].as_str().unwrap();
    assert!((1..=4096).contains(&explanation.len()));
}
