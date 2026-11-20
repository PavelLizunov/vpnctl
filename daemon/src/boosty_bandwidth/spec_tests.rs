#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Spec tests for the Boosty-tier per-user speed policy.
//!
//! These drive the real admin router and a scoped localhost roster mock. They
//! only assert the public HTTP contract, inventory secrets, audit rows and the
//! deploy queue.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::{Body, to_bytes};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, Request, StatusCode, header};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post as post_route};
use axum::{Extension, Router};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tower::ServiceExt;
use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
use vpnctl_inventory::SqliteInventory;

use crate::app::AppState;

const DEFAULT_KEY: &str = "sing-box.user_bandwidth_mbps";
const OVERRIDES_KEY: &str = "sing-box.user_bandwidth_overrides_mbps";
const APPLY_AUDIT: &str = "server.user_bandwidth.set";
const BLOG: &str = "fixture";
const FORM: &str = "mbps=40&boosty_blog=fixture&tier_11=80&tier_22=160";

#[derive(Clone, Debug)]
struct RosterMock {
    items: Vec<Value>,
    captured_at: String,
    complete: bool,
    stale: bool,
    duplicate_page: bool,
    mixed_page: bool,
    page_size: usize,
}

impl RosterMock {
    fn valid() -> Self {
        Self {
            items: fixture_items(),
            captured_at: chrono::Utc::now().to_rfc3339(),
            complete: true,
            stale: false,
            duplicate_page: false,
            mixed_page: false,
            page_size: 2,
        }
    }

    fn stale() -> Self {
        Self {
            stale: true,
            ..Self::valid()
        }
    }

    fn incomplete() -> Self {
        Self {
            complete: false,
            ..Self::valid()
        }
    }

    fn duplicate() -> Self {
        Self {
            duplicate_page: true,
            ..Self::valid()
        }
    }

    fn mixed() -> Self {
        Self {
            mixed_page: true,
            ..Self::valid()
        }
    }
}

fn fixture_items() -> Vec<Value> {
    // Levels 11 and 22 deliberately share the same display name. 303 is paid
    // but unlinked, 404 is linked but inactive, and 505 is linked but free.
    vec![
        roster_item("101", "11", "Shared tier", true, 30_000),
        roster_item("202", "22", "Shared tier", true, 60_000),
        roster_item("303", "11", "Shared tier", true, 30_000),
        roster_item("404", "11", "Shared tier", false, 30_000),
        roster_item("505", "11", "Shared tier", true, 0),
    ]
}

fn roster_item(id: &str, level_id: &str, level_name: &str, active: bool, price: u32) -> Value {
    json!({
        "id": id,
        "name": format!("Subscriber <{id}>"),
        "levelId": level_id,
        "level": level_name,
        "priceMinor": price,
        "active": active,
        "paid": price != 0,
        "nextPaymentAt": null,
    })
}

#[derive(Debug)]
struct MockServer {
    url: String,
    captured_at: String,
    reply_requests: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl MockServer {
    async fn start(roster: RosterMock) -> Self {
        let captured_at = roster.captured_at.clone();
        let reply_requests = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route("/api/v1/roster", get(serve_roster))
            .route("/api/v1/overview", get(serve_overview))
            .route("/api/v1/users", get(serve_people))
            .route("/api/v1/records", get(serve_records))
            .route("/api/v1/inbox", get(serve_dialogs))
            .route("/api/v1/inbox/dialogs/{id}", get(serve_conversation))
            .route("/api/v1/inbox/replies/{id}", get(serve_inbox_check))
            .route("/api/v1/automation", get(serve_delivery))
            .route("/api/sync", post_route(serve_author_refresh))
            .route("/api/inbox/sync", post_route(serve_conversation_refresh))
            .route("/api/inbox/draft", post_route(serve_inbox_draft))
            .route("/api/inbox/reply", post_route(serve_inbox_reply))
            .route("/api/inbox/reconcile", post_route(serve_inbox_reconcile))
            .route("/api/inbox/abandon", post_route(serve_inbox_abandon))
            .layer(Extension(Arc::clone(&reply_requests)))
            .with_state(Arc::new(roster));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self {
            url: format!("http://{addr}/api/v1/roster"),
            captured_at,
            reply_requests,
            task,
        }
    }
}

async fn serve_overview() -> Json<Value> {
    Json(json!({
        "roster": {
            "total": 42, "paidCount": 12, "freeCount": 24,
            "estimatedMonthlyMinor": 120000, "currency": "RUB",
            "capturedAt": "2026-11-20T12:00:00Z"
        },
        "summaries": [{
            "currency": "RUB", "details": {
                "balanceMinor": 250000, "providerPrivate": "fixture-overview-private"
            }
        }],
        "moneyTotals": [], "sources": []
    }))
}

async fn serve_people(
    Query(query): Query<HashMap<String, String>>,
) -> Result<Json<Value>, StatusCode> {
    if query.contains_key("view") {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(Json(json!({"items":[{
        "id":"101", "name":"Example <person>", "level":"Fixture 1",
        "active":true, "paid":true, "present":true,
        "raw":{"token":"fixture-people-private"}
    }], "total":1})))
}

async fn serve_records(
    Query(query): Query<HashMap<String, String>>,
) -> Result<Json<Value>, StatusCode> {
    if query.get("view").map(String::as_str) != Some("money")
        || query.get("source").map(String::as_str) != Some("donations")
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(Json(json!({"items":[{
        "source":"donations", "title":"Fixture donation", "currency":"RUB",
        "amountMinor":12550, "details":{"transfer":"fixture-record-private"}
    }], "total":1})))
}

async fn serve_dialogs(
    Query(query): Query<HashMap<String, String>>,
) -> Result<Json<Value>, StatusCode> {
    if query.contains_key("handoff") {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(Json(
        json!({"blog":"fixture","items":[{"id":"12","name":"Fixture conversation","unreadCount":2,"needsOwner":true}], "total":1}),
    ))
}

async fn serve_conversation(
    Path(id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> Result<Json<Value>, StatusCode> {
    if query.get("cached").map(String::as_str) != Some("1") {
        return Err(StatusCode::BAD_REQUEST);
    }
    let pending = (id == "13").then(|| json!({
        "requestId":"auto-fixture-1","dialogId":"13","status":"unknown","text":"Fixture automatic reply"
    }));
    Ok(Json(json!({
        "blog":"fixture", "dialog":{"id":id,"name":"Fixture conversation","canWrite":true},
        "messages":[{"id":"11","direction":"incoming","text":"Fixture message <body>"}],
        "beforeCursor":"11", "pendingReply":pending,
        "providerPrivate":{"text":"fixture-pending-reply-private"}
    })))
}

async fn serve_inbox_draft(Json(body): Json<Value>) -> Response {
    if body != json!({"blog":"fixture","dialogId":"12","topic":"android"}) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    Json(json!({"text":"Fixture draft","raw":"fixture-private-draft"})).into_response()
}

async fn serve_inbox_reply(
    Extension(reply_requests): Extension<Arc<AtomicUsize>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    reply_requests.fetch_add(1, Ordering::Relaxed);
    let expected_text = if body["requestId"] == "fixture-send-long" {
        "я".repeat(8_000)
    } else {
        "Fixture answer".into()
    };
    if body["blog"] != "fixture"
        || body["dialogId"] != "12"
        || body["text"].as_str() != Some(expected_text.as_str())
        || !matches!(
            body["requestId"].as_str(),
            Some("fixture-send-1" | "fixture-send-long" | "fixture-send-rejected")
        )
        || headers
            .get("x-boosty-request")
            .is_none_or(|value| value != "1")
        || headers.contains_key(header::COOKIE)
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if body["requestId"] == "fixture-send-rejected" {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error":{"notDispatched":true,"message":"fixture-private-rejection"}})),
        )
            .into_response();
    }
    Json(json!({"reply":{"requestId":body["requestId"],"dialogId":"12","status":"unknown","text":"fixture-private-receipt"}})).into_response()
}

async fn serve_inbox_check(
    Path(id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    if id != "auto-fixture-1"
        || query.len() != 3
        || query.get("cached").map(String::as_str) != Some("1")
        || query.get("blog").map(String::as_str) != Some("fixture")
        || query.get("dialogId").map(String::as_str) != Some("13")
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    automatic_receipt("sending")
}

async fn serve_inbox_reconcile(Json(body): Json<Value>) -> Response {
    automatic_action(&body, "unknown")
}

async fn serve_inbox_abandon(Json(body): Json<Value>) -> Response {
    automatic_action(&body, "cancelled")
}

fn automatic_action(body: &Value, status: &str) -> Response {
    if body["blog"] != "fixture"
        || body["dialogId"] != "13"
        || body["requestId"] != "auto-fixture-1"
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    automatic_receipt(status)
}

fn automatic_receipt(status: &str) -> Response {
    Json(json!({"reply":{"requestId":"auto-fixture-1","dialogId":"13","status":status,"text":"fixture-private-auto-receipt"}})).into_response()
}

async fn serve_delivery(
    Query(query): Query<HashMap<String, String>>,
) -> Result<Json<Value>, StatusCode> {
    if query.get("cached").map(String::as_str) != Some("1") {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(Json(json!({
        "enabled":true, "autoDeliver":false, "telegramConfigured":true,
        "vpnConfigured":true, "jobs":{"items":[{
            "name":"Fixture delivery", "deliveryState":"prepared", "telegramState":"sent",
            "privateMessage":"fixture-delivery-private"
        }], "total":1}
    })))
}

async fn serve_conversation_refresh(headers: HeaderMap, Json(body): Json<Value>) -> Response {
    if body != json!({"dialogId":"12"}) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    serve_author_refresh(headers).await
}

async fn serve_author_refresh(headers: HeaderMap) -> Response {
    if headers
        .get("x-boosty-request")
        .is_none_or(|value| value != "1")
        || headers.contains_key(header::COOKIE)
        || headers.contains_key(header::AUTHORIZATION)
        || headers.contains_key(header::ORIGIN)
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    Json(json!({"ok":true})).into_response()
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve_roster(
    State(roster): State<Arc<RosterMock>>,
    Query(query): Query<HashMap<String, String>>,
) -> Json<Value> {
    let offset: usize = query
        .get("offset")
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(0);
    let start = if roster.duplicate_page && offset > 0 {
        0
    } else {
        offset.min(roster.items.len())
    };
    let items: Vec<Value> = roster
        .items
        .iter()
        .skip(start)
        .take(roster.page_size)
        .cloned()
        .collect();
    let mixed = roster.mixed_page && offset > 0;
    Json(json!({
        "schemaVersion": 1,
        "blog": BLOG,
        "capturedAt": if mixed {
            (chrono::DateTime::parse_from_rfc3339(&roster.captured_at).unwrap() - chrono::TimeDelta::seconds(1)).to_rfc3339()
        } else {
            roster.captured_at.clone()
        },
        "complete": roster.complete,
        "stale": roster.stale,
        "total": roster.items.len(),
        "offset": offset,
        "items": items,
    }))
}

#[derive(Debug)]
struct Fixture {
    state: AppState,
    _dir: TempDir,
    _writer: JoinHandle<()>,
}

async fn fixture(roster_url: impl Into<Arc<str>>) -> Fixture {
    let dir = TempDir::new().unwrap();
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    seed(&inv).await;
    let (mut state, writer) =
        crate::app::make_app_state_for_tests(inv, Arc::new(crate::app::build_registry().unwrap()));
    state.boosty_roster_url = roster_url.into();
    Fixture {
        state,
        _dir: dir,
        _writer: writer,
    }
}

async fn seed(inv: &SqliteInventory) {
    for id in ["s0", "s1"] {
        inv.add_server(&Server {
            id: ServerId(id.into()),
            address: "127.0.0.1".into(),
            ssh_port: closed_port(),
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![ProtocolId("vless+reality".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    }
    for (id, subscriber) in [("u101", 101), ("u202", 202), ("u404", 404), ("u505", 505)] {
        let uid = UserId(id.into());
        inv.add_user(&User {
            id: uid.clone(),
            uuid: format!("00000000-0000-0000-0000-{subscriber:012}"),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
        inv.link_boosty_subscriber(&uid, subscriber).await.unwrap();
        inv.grant(&uid, &ServerId("s0".into())).await.unwrap();
    }
    // Drain the grant mutations so the fixtures start with an empty queue.
    inv.audit("test", "server.deploy", Some("s0"), None)
        .await
        .unwrap();
    inv.audit("test", "server.deploy", Some("s1"), None)
        .await
        .unwrap();
}

fn closed_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn post_form(state: &AppState, path: &str, body: &str) -> Response {
    let request = Request::builder()
        .method("POST")
        .uri(path)
        .header("host", "test.example")
        .header("origin", "http://test.example")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body.to_owned()))
        .unwrap();
    crate::app::router(state.clone())
        .oneshot(request)
        .await
        .unwrap()
}

async fn post(state: &AppState, body: &str) -> (StatusCode, String) {
    let response = post_form(state, "/admin/servers/s0/user-bandwidth", body).await;
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

async fn get_html(state: &AppState, path: &str) -> String {
    let response = get_page(state, path, "test.example").await;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

async fn get_page(state: &AppState, path: &str, host: &str) -> Response {
    let request = Request::builder()
        .uri(path)
        .header(header::HOST, host)
        .body(Body::empty())
        .unwrap();
    crate::app::router(state.clone())
        .oneshot(request)
        .await
        .unwrap()
}

#[tokio::test]
async fn boosty_admin_renders_native_data_and_keeps_the_legacy_view() {
    let mock = MockServer::start(RosterMock::valid()).await;
    let mut f = fixture(mock.url.clone()).await;
    let legacy = get_html(&f.state, "/admin/boosty").await;
    assert!(legacy.contains("boosty-settings-form"));
    assert!(
        legacy.contains("Linking requires an active paid subscriber and an unlinked VPN account.")
    );

    let url = "https://test.example:9443/";
    f.state.boosty_dashboard_url = Some(url.parse().unwrap());
    let response = get_page(&f.state, "/admin/boosty", "test.example").await;
    assert_eq!(response.status(), StatusCode::OK);
    let csp = response.headers()[header::CONTENT_SECURITY_POLICY]
        .to_str()
        .unwrap();
    assert!(csp.contains("frame-ancestors 'none';"));
    assert!(!csp.contains("frame-src"));
    let html = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let html = std::str::from_utf8(&html).unwrap();
    for needle in [
        "id=\"boosty-author-dashboard\"",
        "href=\"https://test.example:9443/\"",
        "href=\"/admin/boosty?view=sync\"",
        "VPN accounts and sync",
        "Estimated monthly subscriptions",
        "1200.00 RUB",
    ] {
        assert!(html.contains(needle), "{needle}");
    }
    assert!(!html.contains("boosty-settings-form"));
    assert!(!html.contains("<iframe"));
    assert!(!html.contains("fixture-overview-private"));

    let people = get_html(&f.state, "/admin/boosty?view=people").await;
    assert!(people.contains("Example &lt;person&gt;"));
    assert!(people.contains("/admin/users/u101"));
    assert!(!people.contains("fixture-people-private"));
    assert!(!people.contains("<iframe"));
    assert!(
        get_html(&f.state, "/admin/boosty?view=sync")
            .await
            .contains("boosty-settings-form")
    );
}

#[tokio::test]
async fn author_refresh_requires_the_admin_origin_and_uses_the_loopback_service() {
    let mock = MockServer::start(RosterMock::valid()).await;
    let mut f = fixture(mock.url.clone()).await;
    f.state.boosty_dashboard_url = Some("https://test.example:9443/".parse().unwrap());
    let path = "/admin/boosty/author/refresh";
    let response = post_form(&f.state, path, "").await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()[header::LOCATION], "/admin/boosty");
    let request = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::HOST, "test.example")
        .header(header::ORIGIN, "https://foreign.example")
        .body(Body::empty())
        .unwrap();
    let response = crate::app::router(f.state.clone())
        .oneshot(request)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let conversation_path = "/admin/boosty/author/refresh-conversation";
    let response = post_form(&f.state, conversation_path, "dialog_id=12").await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response.headers()[header::LOCATION],
        "/admin/boosty?view=messages&dialog=12"
    );
    let response = post_form(&f.state, conversation_path, "dialog_id=..%2Fsync").await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn author_views_render_filtered_data_and_omit_fields_outside_their_contract() {
    let mock = MockServer::start(RosterMock::valid()).await;
    let mut f = fixture(mock.url.clone()).await;
    f.state.boosty_dashboard_url = Some("https://test.example:9443/".parse().unwrap());
    for (path, needed, excluded) in [
        (
            "/admin/boosty?view=money&source=donations",
            "125.50 RUB",
            "fixture-record-private",
        ),
        (
            "/admin/boosty?view=messages",
            "Fixture conversation",
            "fixture-pending-reply-private",
        ),
        (
            "/admin/boosty?view=messages&dialog=12",
            "Fixture message &lt;body&gt;",
            "fixture-pending-reply-private",
        ),
        (
            "/admin/boosty?view=automation",
            "Fixture delivery",
            "fixture-delivery-private",
        ),
    ] {
        let html = get_html(&f.state, path).await;
        assert!(html.contains(needed), "{path}: missing {needed}");
        assert!(
            !html.contains(excluded),
            "{path}: exposed fields outside the contract"
        );
        assert!(!html.contains("<iframe"), "{path}: native author view");
    }
}

#[tokio::test]
async fn native_inbox_renders_the_composer_and_streams_only_explicit_same_origin_actions() {
    let mock = MockServer::start(RosterMock::valid()).await;
    let mut f = fixture(mock.url.clone()).await;
    f.state.boosty_dashboard_url = Some("https://test.example:9443/".parse().unwrap());
    let html = get_html(&f.state, "/admin/boosty?view=messages&dialog=12&handoff=1").await;
    for control in [
        "boosty-inbox-compose",
        "Prepare draft",
        "boosty-inbox.js",
        "Needs your reply",
    ] {
        assert!(html.contains(control), "missing {control}");
    }
    assert!(!html.contains(":9443/#messages"));
    let stale = get_html(
        &f.state,
        "/admin/boosty?view=messages&dialog=12&blog=previous",
    )
    .await;
    assert!(stale.contains("This link points to a different Boosty account."));
    assert!(!stale.contains("boosty-inbox-compose"));
    let automatic = get_html(&f.state, "/admin/boosty?view=messages&dialog=13").await;
    assert!(automatic.contains("data-request-id=\"auto-fixture-1\""));
    assert!(automatic.contains("id=\"boosty-inbox-pending\">"));

    let app = crate::app::router(f.state.clone());
    let endpoint = "/admin/boosty/inbox/action";
    let draft = json!({"operation":"draft","blog":"fixture","dialogId":"12","topic":"android"});
    let send = json!({"operation":"send","blog":"fixture","dialogId":"12","requestId":"fixture-send-1","text":"Fixture answer"});
    let long = json!({"operation":"send","blog":"fixture","dialogId":"12","requestId":"fixture-send-long","text":"я".repeat(8_000)});
    let failed = json!({"operation":"send","blog":"fixture","dialogId":"12","requestId":"fixture-send-rejected","text":"Fixture answer"});
    let request = |value: &Value, origin: &str| {
        Request::builder()
            .method("POST")
            .uri(endpoint)
            .header(header::HOST, "test.example")
            .header(header::ORIGIN, origin)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::COOKIE, "other-fixture-cookie=present")
            .body(Body::from(value.to_string()))
            .unwrap()
    };
    let rejected = app
        .clone()
        .oneshot(request(&send, "https://foreign.example"))
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::FORBIDDEN);
    let auto = json!({"operation":"send","blog":"fixture","dialogId":"13","requestId":"auto-fixture-1","text":"Fixture answer"});
    let rejected = app
        .clone()
        .oneshot(request(&auto, "https://test.example"))
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
    let auto_action = |operation: &str| json!({"operation":operation,"blog":"fixture","dialogId":"13","requestId":"auto-fixture-1"});
    let check = auto_action("check");
    let reconcile = auto_action("reconcile");
    let close = auto_action("abandon");
    for (action, expected, private) in [
        (
            &check,
            "\"status\":\"sending\"",
            "fixture-private-auto-receipt",
        ),
        (
            &reconcile,
            "\"status\":\"unknown\"",
            "fixture-private-auto-receipt",
        ),
        (
            &close,
            "\"status\":\"cancelled\"",
            "fixture-private-auto-receipt",
        ),
        (&draft, "Fixture draft", "fixture-private-draft"),
        (&send, "\"status\":\"unknown\"", "fixture-private-receipt"),
        (&long, "\"status\":\"unknown\"", "fixture-private-receipt"),
        (
            &failed,
            "\"status\":409,\"not_dispatched\":true",
            "fixture-private-rejection",
        ),
    ] {
        let response = app
            .clone()
            .oneshot(request(action, "https://test.example"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "text/event-stream"
        );
        let stream = to_bytes(response.into_body(), 65_536).await.unwrap();
        let stream = std::str::from_utf8(&stream).unwrap();
        assert!(stream.contains(expected), "{stream}");
        assert!(!stream.contains(private));
    }
    assert_eq!(mock.reply_requests.load(Ordering::Relaxed), 3);
}

#[tokio::test]
async fn dashboard_roster_links_an_existing_vpn_account_for_tier_application() {
    let mock = MockServer::start(RosterMock::valid()).await;
    let mut f = fixture(mock.url.clone()).await;
    f.state.boosty_dashboard_url = Some("https://test.example:9443/".parse().unwrap());
    let uid = UserId("existing-vpn-account".into());
    f.state
        .inv
        .add_user(&User {
            id: uid.clone(),
            uuid: "00000000-0000-0000-0000-000000000303".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    f.state
        .inv
        .grant(&uid, &ServerId("s0".into()))
        .await
        .unwrap();
    let sync = get_html(&f.state, "/admin/boosty?view=sync").await;
    assert!(sync.contains("Subscriber &lt;303&gt;"));
    assert!(sync.contains("existing-vpn-account"));
    assert!(!sync.contains("Subscriber &lt;404&gt;"));
    let path = "/admin/boosty/link";
    for bad_form in [
        "user=existing-vpn-account&subscriber_id=404&boosty_blog=fixture",
        "user=existing-vpn-account&subscriber_id=303&boosty_blog=other",
    ] {
        let response = post_form(&f.state, path, bad_form).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    let stale = MockServer::start(RosterMock::stale()).await;
    f.state.boosty_roster_url = stale.url.clone().into();
    let form = "user=existing-vpn-account&subscriber_id=303&boosty_blog=fixture";
    let response = post_form(&f.state, path, form).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        f.state
            .inv
            .list_boosty_links()
            .await
            .unwrap()
            .iter()
            .all(|(id, _)| id != &uid)
    );
    f.state.boosty_roster_url = mock.url.clone().into();
    let response = post_form(&f.state, path, form).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response.headers()[header::LOCATION],
        "/admin/boosty?view=sync"
    );
    assert!(
        f.state
            .inv
            .list_boosty_links()
            .await
            .unwrap()
            .contains(&(uid, 303))
    );
    let (status, body) = post(&f.state, FORM).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    let raw = secret(&f.state, OVERRIDES_KEY).await.unwrap();
    assert_eq!(
        overrides(&raw),
        json!({"u101": 80, "u202": 160, "existing-vpn-account": 80})
    );
}

async fn secret(state: &AppState, key: &str) -> Option<String> {
    state
        .inv
        .get_server_secret(&ServerId("s0".into()), key)
        .await
        .unwrap()
}

async fn apply_audits(state: &AppState) -> usize {
    state
        .inv
        .recent_audit(200)
        .await
        .unwrap()
        .iter()
        .filter(|row| row.action == APPLY_AUDIT)
        .count()
}

async fn pending(state: &AppState, server: &str) -> bool {
    state
        .inv
        .server_pending_deploy(&ServerId(server.into()))
        .await
        .unwrap()
}

fn overrides(raw: &str) -> Value {
    serde_json::from_str(raw).unwrap()
}

#[tokio::test]
async fn fresh_roster_applies_explicit_linked_paid_rates_and_retry_is_a_no_op() {
    let mock = MockServer::start(RosterMock::valid()).await;
    let f = fixture(mock.url.clone()).await;
    assert!(!pending(&f.state, "s0").await);

    let (status, body) = post(&f.state, FORM).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "body: {body}");
    assert_eq!(
        secret(&f.state, DEFAULT_KEY).await.as_deref(),
        Some("40"),
        "the uniform default rate must be saved"
    );
    let raw = secret(&f.state, OVERRIDES_KEY)
        .await
        .expect("the override map must be saved");
    assert_eq!(
        overrides(&raw),
        json!({"u101": 80, "u202": 160}),
        "only explicitly linked, active, paid accounts get overrides; \
         same-label levels stay separate"
    );
    assert_eq!(apply_audits(&f.state).await, 1);
    assert!(pending(&f.state, "s0").await);
    assert!(
        !pending(&f.state, "s1").await,
        "applying on s0 must not queue s1"
    );

    // Drain the deploy and repeat the exact same form.
    f.state
        .inv
        .audit("test", "server.deploy", Some("s0"), None)
        .await
        .unwrap();
    assert!(!pending(&f.state, "s0").await);
    let (status, body) = post(&f.state, FORM).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "body: {body}");
    assert_eq!(
        apply_audits(&f.state).await,
        1,
        "an unchanged reapply must not audit again"
    );
    assert_eq!(
        secret(&f.state, OVERRIDES_KEY).await.as_deref(),
        Some(raw.as_str())
    );
    assert!(!pending(&f.state, "s0").await);
}

#[tokio::test]
async fn stale_incomplete_duplicate_and_mixed_rosters_leave_policy_untouched() {
    let mut f = fixture("http://127.0.0.1:1/api/v1/roster").await;

    for (label, roster, detail) in [
        ("stale", RosterMock::stale(), "no fresh complete roster"),
        (
            "incomplete",
            RosterMock::incomplete(),
            "no fresh complete roster",
        ),
        ("duplicate", RosterMock::duplicate(), "inconsistent roster"),
        ("mixed", RosterMock::mixed(), "inconsistent roster"),
    ] {
        let mock = MockServer::start(roster).await;
        f.state.boosty_roster_url = mock.url.clone().into();
        let (status, body) = post(&f.state, FORM).await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{label} roster must be rejected, body: {body}"
        );
        assert!(body.contains(detail), "{label} response: {body}");
        assert_eq!(secret(&f.state, DEFAULT_KEY).await, None, "{label}");
        assert_eq!(secret(&f.state, OVERRIDES_KEY).await, None, "{label}");
        assert_eq!(apply_audits(&f.state).await, 0, "{label}");
        assert!(!pending(&f.state, "s0").await, "{label}");
        assert!(!pending(&f.state, "s1").await, "{label}");
    }

    let mock = MockServer::start(RosterMock::valid()).await;
    f.state.boosty_roster_url = mock.url.clone().into();
    let (status, body) = post(&f.state, "mbps=40&boosty_blog=other&tier_11=80&tier_22=160").await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a roster for another blog must be rejected, body: {body}"
    );
    assert!(body.contains("active Boosty account changed"));
    assert_eq!(secret(&f.state, DEFAULT_KEY).await, None);
    assert_eq!(secret(&f.state, OVERRIDES_KEY).await, None);
    assert_eq!(apply_audits(&f.state).await, 0);
    assert!(!pending(&f.state, "s0").await);
}

#[tokio::test]
async fn protocols_view_shows_live_boosty_tiers_and_the_waiting_state() {
    let mock = MockServer::start(RosterMock::valid()).await;
    let mut f = fixture(mock.url.clone()).await;

    let (status, body) = post(&f.state, FORM).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "body: {body}");

    let html = get_html(&f.state, "/admin/servers/s0/protocols").await;
    for needle in [
        "Speed by Boosty tier",
        "Apply Boosty rates",
        "tier_11",
        "tier_22",
        "Shared tier #11",
        "Shared tier #22",
        BLOG,
    ] {
        assert!(
            html.contains(needle),
            "protocols tab must contain {needle:?}"
        );
    }
    assert!(
        html.contains(&mock.captured_at[..10]),
        "protocols tab must show the fresh roster timestamp {:?}",
        &mock.captured_at[..10]
    );

    f.state.boosty_roster_url = format!("http://127.0.0.1:{}/api/v1/roster", closed_port()).into();
    let html = get_html(&f.state, "/admin/servers/s0/protocols").await;
    assert!(
        html.contains("Waiting for a fresh roster from the Boosty dashboard."),
        "an unavailable roster must render the waiting state"
    );
}
