#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Spec tests for the Boosty-tier per-user speed policy.
//!
//! These drive the real admin router and a scoped localhost roster mock. They
//! only assert the public HTTP contract, inventory secrets, audit rows and the
//! deploy queue.

use std::collections::HashMap;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{Query, State};
use axum::http::{Request, StatusCode};
use axum::response::Json;
use axum::routing::get;
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
    task: JoinHandle<()>,
}

impl MockServer {
    async fn start(roster: RosterMock) -> Self {
        let captured_at = roster.captured_at.clone();
        let app = Router::new()
            .route("/api/v1/roster", get(serve_roster))
            .with_state(Arc::new(roster));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self {
            url: format!("http://{addr}/api/v1/roster"),
            captured_at,
            task,
        }
    }
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

async fn post(state: &AppState, body: &str) -> (StatusCode, String) {
    let request = Request::builder()
        .method("POST")
        .uri("/admin/servers/s0/user-bandwidth")
        .header("host", "test.example")
        .header("origin", "http://test.example")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body.to_owned()))
        .unwrap();
    let response = crate::app::router(state.clone())
        .oneshot(request)
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

async fn get_html(state: &AppState, path: &str) -> String {
    let request = Request::builder().uri(path).body(Body::empty()).unwrap();
    let response = crate::app::router(state.clone())
        .oneshot(request)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
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
