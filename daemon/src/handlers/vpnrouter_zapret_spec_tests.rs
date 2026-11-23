#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, mpsc};

use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
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
const PATH: &str = "/api/v1/assistant/vpnrouter/zapret/next";
const PLAN_PATH: &str = "/api/v1/assistant/vpnrouter/plan";
const MODEL: &str = "synthetic-vpnrouter-model";
const GATEWAY_KEY: &str = "synthetic-vpnrouter-server-key";
const NULL_CHOICE: &str = r#"{"profile":null}"#;

struct Fixture {
    app: Router,
    inventory: SqliteInventory,
    writer: tokio::task::JoinHandle<()>,
    _directory: tempfile::TempDir,
}

impl Fixture {
    async fn new(upstream: Option<&Upstream>) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let inventory = SqliteInventory::open(&directory.path().join("inventory.db"))
            .await
            .unwrap();
        let registry = Arc::new(crate::app::build_registry().unwrap());
        let (state, writer) = crate::app::make_app_state_for_tests(inventory.clone(), registry);
        let app = router(upstream.map(Upstream::gateway)).with_state(state);
        Self {
            app,
            inventory,
            writer,
            _directory: directory,
        }
    }

    async fn user(&self, number: u32, disabled: bool) -> User {
        let user = User {
            id: UserId(format!("synthetic-zapret-user-{number}")),
            uuid: vpnctl_crypto::gen_uuid(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: Some(format!("synthetic-subscription-{number}")),
            vpn_router_device_id: Some(format!("d{number:031x}")),
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
    endpoint: String,
    requests: mpsc::Receiver<(HeaderMap, Value)>,
    server: tokio::task::JoinHandle<()>,
}

impl Upstream {
    async fn start(replies: impl IntoIterator<Item = &'static str>) -> Self {
        let replies = Arc::new(Mutex::new(replies.into_iter().collect::<VecDeque<_>>()));
        let (record, requests) = mpsc::channel();
        let app = Router::new().route(
            "/synthetic/chat/completions",
            post(move |headers: HeaderMap, Json(payload): Json<Value>| {
                let replies = Arc::clone(&replies);
                let record = record.clone();
                async move {
                    record.send((headers, payload)).unwrap();
                    let content = replies.lock().unwrap().pop_front().unwrap_or(NULL_CHOICE);
                    Json(json!({"choices": [{"message": {"content": content}}]}))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!(
            "http://{}/synthetic/chat/completions",
            listener.local_addr().unwrap()
        );
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self {
            endpoint,
            requests,
            server,
        }
    }

    fn gateway(&self) -> Gateway {
        Gateway::new(&self.endpoint, MODEL, GATEWAY_KEY).unwrap()
    }
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.server.abort();
    }
}

fn pick_body(target: &str, candidates: &[&str], attempts: Value) -> Value {
    json!({"schema": 1, "target": target, "candidates": candidates, "attempts": attempts})
}

fn attempt(profile: &str, target_ok: bool, controls_ok: bool) -> Value {
    json!({"profile": profile, "target_ok": target_ok, "controls_ok": controls_ok})
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
    assert!(
        response.headers()[CACHE_CONTROL]
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

#[tokio::test]
async fn both_identities_reach_the_gateway_with_only_the_typed_pick_request() {
    let upstream = Upstream::start([r#"{"profile":"fragment-2"}"#, NULL_CHOICE]).await;
    let fixture = Fixture::new(Some(&upstream)).await;
    let user = fixture.user(1, false).await;
    let [subscription, device] = credentials(&user);
    let attempts = json!([
        attempt("old-a", false, true),
        attempt("old-b", true, false),
        attempt("old-c", false, false),
        attempt("old-d", false, true),
    ]);
    let discord_body = pick_body(
        "discord_gateway",
        &[
            "a",
            "basic",
            "abcdefghijklmnopqrstuvwxyz012345",
            "fragment-2",
            "safe",
        ],
        attempts,
    );
    let youtube_body = pick_body("youtube_media", &["safe"], json!([]));

    for ((identity, credential), body, profile) in [
        (subscription, discord_body, json!("fragment-2")),
        (device, youtube_body, Value::Null),
    ] {
        let response = fixture
            .send(request(identity, credential, body.to_string()))
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_no_store(&response);
        let response = response_text(response).await;
        assert_eq!(
            serde_json::from_str::<Value>(&response).unwrap(),
            json!({"schema": 1, "profile": profile})
        );

        let (headers, payload) = upstream.requests.try_recv().unwrap();
        assert_eq!(
            headers.get(AUTHORIZATION).unwrap().to_str().unwrap(),
            format!("Bearer {GATEWAY_KEY}")
        );
        assert!(!headers.contains_key(IDENTITY));
        assert_eq!(payload["model"], MODEL);
        let messages = payload["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0]["role"], "system");
        assert!(!messages[0]["content"].as_str().unwrap().trim().is_empty());
        assert_eq!(messages[1]["role"], "user");
        assert_eq!(
            serde_json::from_str::<Value>(messages[1]["content"].as_str().unwrap()).unwrap(),
            body
        );

        let wire = payload.to_string();
        for private in [user.id.0.as_str(), subscription.1, device.1] {
            assert!(!wire.contains(private));
            assert!(!response.contains(private));
            assert!(
                !headers
                    .values()
                    .any(|value| value.to_str().is_ok_and(|value| value.contains(private)))
            );
        }
        assert!(!response.contains(GATEWAY_KEY));
    }
    assert!(upstream.requests.try_recv().is_err());
}

#[tokio::test]
async fn malformed_pick_requests_are_rejected_before_the_gateway() {
    let upstream = Upstream::start([]).await;
    let fixture = Fixture::new(Some(&upstream)).await;
    let valid = pick_body("discord_gateway", &["safe"], json!([]));
    let mut cases = Vec::new();
    for (case, key, value) in [
        ("unsupported schema", "schema", json!(2)),
        ("unsupported target", "target", json!("discord")),
        ("unknown field", "extra", json!(true)),
        ("empty candidates", "candidates", json!([])),
        (
            "too many candidates",
            "candidates",
            json!(["a", "b", "c", "d", "e", "f"]),
        ),
        ("repeated candidates", "candidates", json!(["safe", "safe"])),
        ("wrong candidate type", "candidates", json!([true])),
        (
            "too many attempts",
            "attempts",
            json!([
                attempt("a", false, true),
                attempt("b", false, true),
                attempt("c", false, true),
                attempt("d", false, true),
                attempt("e", false, true)
            ]),
        ),
        (
            "repeated attempts",
            "attempts",
            json!([attempt("old", false, true), attempt("old", true, false)]),
        ),
        (
            "attempt overlaps candidates",
            "attempts",
            json!([attempt("safe", false, true)]),
        ),
        (
            "invalid attempt profile",
            "attempts",
            json!([attempt("Old", false, true)]),
        ),
        (
            "unknown attempt field",
            "attempts",
            json!([{"profile":"old","target_ok":true,"controls_ok":true,"extra":true}]),
        ),
        (
            "missing attempt field",
            "attempts",
            json!([{"profile":"old","target_ok":true}]),
        ),
        (
            "wrong attempt field type",
            "attempts",
            json!([{"profile":"old","target_ok":"true","controls_ok":true}]),
        ),
    ] {
        let mut body = valid.clone();
        body[key] = value;
        cases.push((case, body.to_string()));
    }
    for id in [
        "",
        "9alpha",
        "Alpha",
        "with_underscore",
        "façade",
        "abcdefghijklmnopqrstuvwxyz0123456",
    ] {
        let body = pick_body("discord_gateway", &[id], json!([]));
        cases.push(("invalid candidate profile", body.to_string()));
    }
    cases.extend([
        ("missing attempts", r#"{"schema":1,"target":"discord_gateway","candidates":["safe"]}"#.into()),
        ("duplicate request field", r#"{"schema":1,"schema":1,"target":"discord_gateway","candidates":["safe"],"attempts":[]}"#.into()),
        ("duplicate attempt field", r#"{"schema":1,"target":"discord_gateway","candidates":["safe"],"attempts":[{"profile":"old","target_ok":false,"target_ok":false,"controls_ok":true}]}"#.into()),
    ]);

    for (index, (case, body)) in cases.into_iter().enumerate() {
        let user = fixture.user(index as u32, false).await;
        let [(identity, credential), _] = credentials(&user);
        let response = fixture
            .send(request(identity, credential, body.clone()))
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{case}: {body}");
        assert_no_store(&response);
    }
    assert!(upstream.requests.try_recv().is_err());
}

#[tokio::test]
async fn a_profile_id_cannot_carry_the_callers_credential() {
    let upstream = Upstream::start([]).await;
    let fixture = Fixture::new(Some(&upstream)).await;
    let user = fixture.user(1, false).await;

    for (identity, credential) in credentials(&user) {
        for body in [
            pick_body("discord_gateway", &[credential], json!([])),
            pick_body(
                "discord_gateway",
                &["safe"],
                json!([attempt(credential, false, true)]),
            ),
        ] {
            let response = fixture
                .send(request(identity, credential, body.to_string()))
                .await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_no_store(&response);
            assert!(!response_text(response).await.contains(credential));
        }
    }
    assert!(upstream.requests.try_recv().is_err());
}

#[tokio::test]
async fn the_gateway_must_return_one_explicit_choice_from_the_remaining_candidates() {
    let replies = [
        r#"{"profile":"unlisted"}"#,
        r#"{"profile":"already-tried"}"#,
        r#"{}"#,
        r#"{"profile":"safe","extra":true}"#,
        r#"{"profile":"safe","profile":"safe"}"#,
        r#"{"profile":true}"#,
    ];
    let upstream = Upstream::start(replies).await;
    let fixture = Fixture::new(Some(&upstream)).await;
    let user = fixture.user(1, false).await;
    let [(identity, credential), _] = credentials(&user);
    let body = pick_body(
        "youtube_media",
        &["safe"],
        json!([attempt("already-tried", false, true)]),
    )
    .to_string();

    for reply in replies {
        let response = fixture
            .send(request(identity, credential, body.clone()))
            .await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY, "{reply}");
        assert_no_store(&response);
        let response = response_text(response).await;
        assert!(!response.contains(credential));
        assert!(!response.contains(GATEWAY_KEY));
    }
    assert_eq!(upstream.requests.try_iter().count(), replies.len());
}

#[tokio::test]
async fn authorization_rejects_unknown_and_disabled_identities() {
    let upstream = Upstream::start([]).await;
    let fixture = Fixture::new(Some(&upstream)).await;
    let user = fixture.user(1, true).await;
    let body = pick_body("discord_gateway", &["safe"], json!([])).to_string();
    let [subscription, device] = credentials(&user);

    for ((identity, credential), expected) in [
        (subscription, StatusCode::FORBIDDEN),
        (device, StatusCode::FORBIDDEN),
        (
            ("subscription", "synthetic-unknown-subscription"),
            StatusCode::UNAUTHORIZED,
        ),
        (
            ("device", "d0000000000000000000000000000002"),
            StatusCode::UNAUTHORIZED,
        ),
    ] {
        let response = fixture
            .send(request(identity, credential, body.clone()))
            .await;
        assert_eq!(response.status(), expected);
        assert_no_store(&response);
        assert!(!response_text(response).await.contains(credential));
    }
    assert!(upstream.requests.try_recv().is_err());
}

#[tokio::test]
async fn accepts_exactly_2048_request_bytes_and_rejects_one_more() {
    let upstream = Upstream::start([NULL_CHOICE]).await;
    let fixture = Fixture::new(Some(&upstream)).await;
    let user = fixture.user(1, false).await;
    let [(identity, credential), _] = credentials(&user);
    let mut body = pick_body("discord_gateway", &["safe"], json!([])).to_string();
    body.push_str(&" ".repeat(2048 - body.len()));

    let response = fixture
        .send(request(identity, credential, body.clone()))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_no_store(&response);

    body.push(' ');
    let response = fixture.send(request(identity, credential, body)).await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_no_store(&response);
    assert_eq!(upstream.requests.try_iter().count(), 1);
}

#[tokio::test]
async fn account_quota_is_shared_by_credentials_and_independent_of_the_plan_route() {
    let upstream = Upstream::start(
        [NULL_CHOICE; 6]
            .into_iter()
            .chain([r#"{"operation":"route_only_app"}"#]),
    )
    .await;
    let fixture = Fixture::new(Some(&upstream)).await;
    let user = fixture.user(1, false).await;
    let identities = credentials(&user);
    let body = pick_body("discord_gateway", &["safe"], json!([])).to_string();

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
        assert_no_store(&response);
        assert!(response.headers().contains_key(RETRY_AFTER));
    }

    let [(identity, credential), _] = identities;
    let mut plan = request(
        identity,
        credential,
        json!({"schema":1,"locale":"en","goal":"Route only Chrome through the VPN.","target_available":true})
            .to_string(),
    );
    *plan.uri_mut() = PLAN_PATH.parse().unwrap();
    assert_eq!(fixture.send(plan).await.status(), StatusCode::OK);
    assert_eq!(upstream.requests.try_iter().count(), 7);
}

#[tokio::test]
async fn ip_quota_is_independent_of_the_plan_route_and_other_peers() {
    let fixture = Fixture::new(None).await;
    let peer_request = |path: &str, last_octet: u8| {
        let mut request = request("subscription", "synthetic-unknown", "{}".into());
        *request.uri_mut() = path.parse().unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from((
                [192, 0, 2, last_octet],
                1234,
            ))));
        request
    };
    for _ in 0..120 {
        let response = fixture.send(peer_request(PATH, 1)).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    let response = fixture.send(peer_request(PATH, 1)).await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_no_store(&response);
    assert!(response.headers().contains_key(RETRY_AFTER));

    for (path, peer) in [(PLAN_PATH, 1), (PATH, 2)] {
        let response = fixture.send(peer_request(path, peer)).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
