//! End-to-end sync test: a mock Boosty roster + a temp inventory, driven
//! through `sync_once`, asserting the `disabled` flips and the surfaced
//! new-subscriber. Proves the fetch → reconcile → apply plumbing.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use boosty_api::api_client::ApiClient;
use serde_json::json;
use vpnctl_boosty_bridge::{ApplyMode, sync_once};
use vpnctl_core::{User, UserId};
use vpnctl_inventory::SqliteInventory;

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
