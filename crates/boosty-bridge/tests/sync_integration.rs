//! End-to-end sync test: a mock Boosty roster + a temp inventory, driven
//! through `sync_once`, asserting the `disabled` flips and the surfaced
//! new-subscriber. Proves the fetch → reconcile → apply plumbing.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use boosty_api::api_client::ApiClient;
use serde_json::json;
use vpnctl_boosty_bridge::{ApplyMode, build_client, sync_from_settings_at, sync_once};
use vpnctl_core::{User, UserId};
use vpnctl_inventory::{BoostySettings, SqliteInventory};

fn subscriber(id: i64, name: &str, status: &str) -> serde_json::Value {
    json!({
        "id": id,
        "name": name,
        "email": "",
        "hasAvatar": false,
        "avatarUrl": "",
        "isOfficial": false,
        "isBlackListed": false,
        "isFeePaid": false,
        "canWrite": true,
        "subscribed": true,
        "status": status,
        "onTime": 1_700_000_000,
        "price": 0,
        "payments": 0,
        "level": {
            "id": 1,
            "name": "L",
            "price": 0,
            "currencyPrices": {},
            "createdAt": 1,
            "ownerId": 1,
            "deleted": false,
            "isHidden": false,
            "isLimited": false,
            "isArchived": false,
            "flags": { "isHidden": false, "isLimited": false, "isArchived": false },
            "data": []
        }
    })
}

fn user(id: &str, disabled: bool) -> User {
    User {
        id: UserId(id.into()),
        uuid: format!("uuid-{id}"),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled,
    }
}

#[tokio::test]
async fn full_sync_enables_disables_and_surfaces_new() {
    let mut server = mockito::Server::new_async().await;

    let body = json!({
        "data": [
            subscriber(100, "Alice", "active"),   // linked to disabled alice → enable
            subscriber(200, "Bob", "inactive"),   // linked to enabled bob   → disable
            subscriber(300, "Carol", "active"),   // unlinked active          → surface
        ],
        "total": 3, "limit": 100, "offset": 0
    })
    .to_string();

    let _m = server
        .mock("GET", "/v1/blog/ninitux/subscribers")
        .match_query(mockito::Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(body)
        .create_async()
        .await;

    let client = ApiClient::new(reqwest::Client::new(), server.url());

    let dir = tempfile::tempdir().unwrap();
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    inv.add_user(&user("alice", true)).await.unwrap();
    inv.add_user(&user("bob", false)).await.unwrap();
    inv.link_boosty_subscriber(&UserId("alice".into()), 100)
        .await
        .unwrap();
    inv.link_boosty_subscriber(&UserId("bob".into()), 200)
        .await
        .unwrap();

    let report = sync_once(&client, &inv, "ninitux", ApplyMode::Full)
        .await
        .unwrap();

    assert_eq!(report.total_subscribers, 3);
    assert_eq!(report.active_subscribers, 2);
    assert_eq!(report.linked, 2);
    assert_eq!(report.enabled, vec!["alice"]);
    assert_eq!(report.disabled, vec!["bob"]);
    assert_eq!(report.new_subscribers.len(), 1);
    assert_eq!(report.new_subscribers[0].subscriber_id, 300);
    assert!(report.errors.is_empty(), "{:?}", report.errors);

    // The flips actually landed in the DB.
    let users = inv.list_users().await.unwrap();
    let alice = users.iter().find(|u| u.id.0 == "alice").unwrap();
    let bob = users.iter().find(|u| u.id.0 == "bob").unwrap();
    assert!(!alice.disabled, "alice re-enabled");
    assert!(bob.disabled, "bob disabled");

    // Audit rows written for the actual state changes.
    let audits = inv.recent_audit(20).await.unwrap();
    assert!(
        audits
            .iter()
            .any(|a| a.action == "boosty.enable" && a.target.as_deref() == Some("alice"))
    );
    assert!(
        audits
            .iter()
            .any(|a| a.action == "boosty.disable" && a.target.as_deref() == Some("bob"))
    );
}

#[tokio::test]
async fn enable_only_mode_leaves_lapsed_pending() {
    let mut server = mockito::Server::new_async().await;
    let body = json!({
        "data": [ subscriber(200, "Bob", "inactive") ],
        "total": 1, "limit": 100, "offset": 0
    })
    .to_string();
    let _m = server
        .mock("GET", "/v1/blog/ninitux/subscribers")
        .match_query(mockito::Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(body)
        .create_async()
        .await;

    let client = ApiClient::new(reqwest::Client::new(), server.url());
    let dir = tempfile::tempdir().unwrap();
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    inv.add_user(&user("bob", false)).await.unwrap();
    inv.link_boosty_subscriber(&UserId("bob".into()), 200)
        .await
        .unwrap();

    let report = sync_once(&client, &inv, "ninitux", ApplyMode::EnableOnly)
        .await
        .unwrap();

    // EnableOnly must NOT disable — bob stays enabled, surfaced as pending.
    assert_eq!(report.lapsed_pending, vec!["bob"]);
    assert!(report.disabled.is_empty());
    let users = inv.list_users().await.unwrap();
    assert!(!users[0].disabled, "EnableOnly must not disable bob");
}

/// AC-A1: Boosty invalidates the old refresh token at refresh time, so the
/// rotated value must be persisted even when the sync itself fails AFTER a
/// successful refresh — otherwise the next pass authenticates with a
/// consumed token and the bridge bricks itself.
#[tokio::test]
async fn rotated_refresh_token_persisted_even_when_roster_fetch_fails() {
    let mut server = mockito::Server::new_async().await;
    let _refresh = server
        .mock("POST", "/oauth/token/")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"access_token":"acc2","refresh_token":"ref2","expires_in":3600}"#)
        .create_async()
        .await;
    let _subs = server
        .mock("GET", "/v1/blog/ninitux/subscribers")
        .match_query(mockito::Matcher::Any)
        .with_status(500)
        .create_async()
        .await;

    let dir = tempfile::tempdir().unwrap();
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    let settings = BoostySettings {
        enabled: true,
        blog_url: Some("ninitux".into()),
        access_token: None,
        refresh_token: Some("ref1".into()),
        device_id: Some("dev".into()),
        poll_interval_secs: 3600,
        auto_disable_lapsed: false,
    };
    inv.set_boosty_settings(&settings).await.unwrap();

    let result = sync_from_settings_at(&inv, &settings, ApplyMode::DryRun, &server.url()).await;
    assert!(result.is_err(), "roster 500 must fail the pass");

    let after = inv.get_boosty_settings().await.unwrap();
    assert_eq!(
        after.refresh_token.as_deref(),
        Some("ref2"),
        "rotated token must be persisted despite the failed sync"
    );
}

/// AC-A4: with BOTH credential kinds configured the refresh flow must win —
/// a static access token expires within ~an hour and would kill the bridge
/// on its first expiry.
#[tokio::test]
async fn build_client_prefers_refresh_flow_when_both_creds_set() {
    let settings = BoostySettings {
        access_token: Some("static-acc".into()),
        refresh_token: Some("ref1".into()),
        device_id: Some("dev".into()),
        ..Default::default()
    };
    // No network happens: configuring the refresh flow is lazy.
    let client = build_client(&settings, "http://127.0.0.1:1").await.unwrap();
    assert_eq!(
        client.refresh_token().await.as_deref(),
        Some("ref1"),
        "client must be in refresh mode, not static-bearer mode"
    );
}

/// AC-A2: a server that accepts the TCP connection and then never responds
/// must not hang the sync forever — the client carries a total request
/// timeout (reqwest's default is NO timeout; this pins the regression).
/// Runtime ~30s (the configured request timeout) — deliberate.
#[tokio::test]
async fn hung_server_times_out_instead_of_hanging_forever() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // Accept connections and hold them open, never writing a byte.
    let _hold = tokio::spawn(async move {
        let mut held = Vec::new();
        loop {
            if let Ok((sock, _)) = listener.accept().await {
                held.push(sock);
            }
        }
    });

    let dir = tempfile::tempdir().unwrap();
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    let settings = BoostySettings {
        blog_url: Some("b".into()),
        refresh_token: Some("r".into()),
        device_id: Some("d".into()),
        ..Default::default()
    };

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        sync_from_settings_at(
            &inv,
            &settings,
            ApplyMode::DryRun,
            &format!("http://{addr}"),
        ),
    )
    .await;
    match result {
        Ok(inner) => assert!(inner.is_err(), "sync against a silent server must error"),
        Err(_) => panic!("sync must time out well before 60s — request timeout not wired?"),
    }
}
