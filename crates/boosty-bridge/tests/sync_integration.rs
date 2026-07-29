//! End-to-end sync test: a mock Boosty roster + a temp inventory, driven
//! through `sync_once`, asserting the `disabled` flips and the surfaced
//! new-subscriber. Proves the fetch → reconcile → apply plumbing.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use boosty_api::api_client::ApiClient;
use serde_json::json;
use vpnctl_boosty_bridge::{
    ApplyMode, build_client, sync_from_settings_at, sync_once, sync_once_with_policy,
};
use vpnctl_core::{KernelId, Server, ServerId, User, UserId};
use vpnctl_inventory::{BoostySettings, SqliteInventory};

/// A PAID subscriber (level price 200) — the default in these tests, since
/// the paid-only gate now decides VPN-eligibility.
fn subscriber(id: i64, name: &str, status: &str) -> serde_json::Value {
    subscriber_priced(id, name, status, 200.0, "Пингвин-одиночка")
}

/// A subscriber on the free "Follower" level (level price 0) — VPN-excluded.
fn subscriber_with_off_time(id: i64, name: &str, off_time: i64) -> serde_json::Value {
    let mut value = subscriber(id, name, "inactive");
    value["offTime"] = json!(off_time);
    value
}

fn follower(id: i64, name: &str, status: &str) -> serde_json::Value {
    subscriber_priced(id, name, status, 0.0, "Follower")
}

fn subscriber_priced(
    id: i64,
    name: &str,
    status: &str,
    level_price: f64,
    level_name: &str,
) -> serde_json::Value {
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
        "price": level_price,
        "payments": 0,
        "level": {
            "id": 1,
            "name": level_name,
            "price": level_price,
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

fn vpn_server(id: &str) -> Server {
    Server {
        id: ServerId(id.into()),
        address: format!("{id}.example.com"),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
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

/// BB-2 (operator policy 2026-07-10, paid tiers only): a free "Follower"
/// (level price 0) is never surfaced as a new subscriber to link, even when
/// active — and is counted in `excluded_unpaid`. A paid active subscriber
/// on the same roster still surfaces.
#[tokio::test]
async fn free_followers_are_excluded_from_vpn() {
    let mut server = mockito::Server::new_async().await;
    let body = json!({
        "data": [
            subscriber(300, "Payer", "active"),     // paid + active → surface
            follower(400, "Freeloader", "active"),  // free + active → excluded
            follower(500, "ExFree", "inactive"),    // free + inactive → ignored
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

    let report = sync_once(&client, &inv, "ninitux", ApplyMode::Full)
        .await
        .unwrap();

    assert_eq!(
        report.active_subscribers, 1,
        "only the paid payer is eligible"
    );
    assert_eq!(
        report.excluded_unpaid, 1,
        "one active free follower excluded"
    );
    assert_eq!(report.new_subscribers.len(), 1);
    assert_eq!(report.new_subscribers[0].subscriber_id, 300);
    assert!(
        report
            .new_subscribers
            .iter()
            .all(|s| s.subscriber_id != 400),
        "free follower must NOT be surfaced to link"
    );
}

/// BB-2 downgrade semantics: a LINKED user whose subscriber drops to the
/// free "Follower" level (still status active, price 0) is treated as
/// lapsed — disabled in Full mode. A paid subscriber keeps `active_count`
/// above zero so the zero-eligible fail-safe does NOT engage (this is a
/// single downgrade, not a fleet-wide anomaly).
#[tokio::test]
async fn linked_user_downgraded_to_free_is_disabled() {
    let mut server = mockito::Server::new_async().await;
    let body = json!({
        "data": [
            follower(600, "Downgraded", "active"),    // carol linked here → now free
            subscriber(700, "StillPaying", "active"), // keeps a paid-active on the roster
        ],
        "total": 2, "limit": 100, "offset": 0
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
    inv.add_user(&user("carol", false)).await.unwrap();
    inv.link_boosty_subscriber(&UserId("carol".into()), 600)
        .await
        .unwrap();

    let report = sync_once(&client, &inv, "ninitux", ApplyMode::Full)
        .await
        .unwrap();

    assert_eq!(
        report.disabled,
        vec!["carol"],
        "downgrade to free = disable"
    );
    assert!(
        report.suppressed_disables.is_empty(),
        "fail-safe must not engage when a paid subscriber remains"
    );
    let users = inv.list_users().await.unwrap();
    let carol = users.iter().find(|u| u.id.0 == "carol").unwrap();
    assert!(carol.disabled, "carol disabled after downgrade to free");
}

/// BB-2 fractional price (the model doc says fractional prices occur live):
/// a level.price of 0.5 is paid → eligible → surfaced.
#[tokio::test]
async fn fractional_paid_price_is_eligible() {
    let mut server = mockito::Server::new_async().await;
    let body = json!({
        "data": [ subscriber_priced(800, "Centsub", "active", 0.5, "Promo") ],
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

    let report = sync_once(&client, &inv, "ninitux", ApplyMode::Full)
        .await
        .unwrap();
    assert_eq!(report.active_subscribers, 1, "0.5 price is paid → eligible");
    assert_eq!(report.excluded_unpaid, 0);
    assert_eq!(report.new_subscribers.len(), 1);
    assert_eq!(report.new_subscribers[0].subscriber_id, 800);
}

/// BB-2 × EnableOnly (the poller's default mode): a linked user whose
/// subscriber is a free follower is NOT auto-disabled — it surfaces as
/// `lapsed_pending` for the operator to confirm, exactly like any lapse.
/// A paid subscriber keeps the zero-eligible fail-safe from engaging.
#[tokio::test]
async fn linked_free_follower_under_enable_only_is_pending_not_disabled() {
    let mut server = mockito::Server::new_async().await;
    let body = json!({
        "data": [
            follower(600, "Freeloader", "active"),    // dave linked here
            subscriber(700, "StillPaying", "active"), // keeps active_count > 0
        ],
        "total": 2, "limit": 100, "offset": 0
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
    inv.add_user(&user("dave", false)).await.unwrap();
    inv.link_boosty_subscriber(&UserId("dave".into()), 600)
        .await
        .unwrap();

    let report = sync_once(&client, &inv, "ninitux", ApplyMode::EnableOnly)
        .await
        .unwrap();
    assert_eq!(
        report.lapsed_pending,
        vec!["dave"],
        "free-tier linked → pending"
    );
    assert!(
        report.disabled.is_empty(),
        "EnableOnly must not auto-disable"
    );
    let users = inv.list_users().await.unwrap();
    let dave = users.iter().find(|u| u.id.0 == "dave").unwrap();
    assert!(!dave.disabled, "dave stays enabled until operator confirms");
}

/// BB-2 fail-safe: a NON-empty roster where every ACTIVE subscriber is free
/// (the signature of a Boosty price-serialization quirk, or every payer
/// downgrading at once) must NOT mass-disable a linked payer in Full mode —
/// the disable is suppressed for the operator to confirm. A genuinely
/// all-*inactive* roster is a real lapse and is NOT covered here (see
/// `enable_only_mode_leaves_lapsed_pending`).
#[tokio::test]
async fn all_active_free_roster_suppresses_disable_of_linked_payer() {
    let mut server = mockito::Server::new_async().await;
    let body = json!({
        "data": [
            follower(600, "NowFree", "active"),      // carol linked here
            follower(601, "AlsoFree", "active"),     // still no paid-active
        ],
        "total": 2, "limit": 100, "offset": 0
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
    inv.add_user(&user("carol", false)).await.unwrap();
    inv.link_boosty_subscriber(&UserId("carol".into()), 600)
        .await
        .unwrap();

    let report = sync_once(&client, &inv, "ninitux", ApplyMode::Full)
        .await
        .unwrap();

    assert!(
        report.disabled.is_empty(),
        "must NOT disable on zero-eligible anomaly"
    );
    assert_eq!(report.suppressed_disables, vec!["carol"]);
    let users = inv.list_users().await.unwrap();
    let carol = users.iter().find(|u| u.id.0 == "carol").unwrap();
    assert!(
        !carol.disabled,
        "carol kept enabled pending operator confirm"
    );
}

/// AC-C1: an EMPTY roster (typo'd blog_url — Boosty happily 200s with zero
/// data for an unknown blog) must not mass-disable every linked user, even
/// in Full mode. The would-be disables land in `suppressed_disables`.
#[tokio::test]
async fn empty_roster_suppresses_disables() {
    let mut server = mockito::Server::new_async().await;
    let body = json!({ "data": [], "total": 0, "limit": 100, "offset": 0 }).to_string();
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

    let report = sync_once(&client, &inv, "ninitux", ApplyMode::Full)
        .await
        .unwrap();

    assert!(report.disabled.is_empty(), "{report:?}");
    assert!(report.lapsed_pending.is_empty(), "{report:?}");
    assert_eq!(report.suppressed_disables, vec!["bob"]);
    let users = inv.list_users().await.unwrap();
    assert!(!users[0].disabled, "empty roster must not disable bob");
}

/// AC-C2 (the spec's fail-safe rule): an API error aborts the pass with
/// ZERO inventory writes — nothing flipped, no audit rows.
#[tokio::test]
async fn api_error_aborts_with_zero_writes() {
    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("GET", "/v1/blog/ninitux/subscribers")
        .match_query(mockito::Matcher::Any)
        .with_status(500)
        .create_async()
        .await;

    let client = ApiClient::new(reqwest::Client::new(), server.url());
    let dir = tempfile::tempdir().unwrap();
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    inv.add_user(&user("bob", false)).await.unwrap();
    inv.add_user(&user("alice", true)).await.unwrap();
    inv.link_boosty_subscriber(&UserId("bob".into()), 200)
        .await
        .unwrap();
    inv.link_boosty_subscriber(&UserId("alice".into()), 100)
        .await
        .unwrap();

    let res = sync_once(&client, &inv, "ninitux", ApplyMode::Full).await;
    assert!(res.is_err(), "500 must abort the pass");

    let users = inv.list_users().await.unwrap();
    let bob = users.iter().find(|u| u.id.0 == "bob").unwrap();
    let alice = users.iter().find(|u| u.id.0 == "alice").unwrap();
    assert!(!bob.disabled, "bob untouched");
    assert!(alice.disabled, "alice untouched");
    let audits = inv.recent_audit(20).await.unwrap();
    assert!(audits.is_empty(), "no writes on API error: {audits:?}");
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
        grace_days: 14,
        auto_create_users: false,
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

#[tokio::test]
async fn full_mode_waits_fourteen_days_before_disabling() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let mut server = mockito::Server::new_async().await;
    let body = json!({
        "data": [
            subscriber_with_off_time(100, "Grace", now - 13 * 86_400),
            subscriber_with_off_time(200, "Expired", now - 15 * 86_400),
        ],
        "total": 2, "limit": 100, "offset": 0
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
    inv.add_user(&user("grace", false)).await.unwrap();
    inv.add_user(&user("expired", false)).await.unwrap();
    inv.link_boosty_subscriber(&UserId("grace".into()), 100)
        .await
        .unwrap();
    inv.link_boosty_subscriber(&UserId("expired".into()), 200)
        .await
        .unwrap();

    let report = sync_once_with_policy(&client, &inv, "ninitux", ApplyMode::Full, 14, false)
        .await
        .unwrap();

    assert_eq!(report.grace_pending, vec!["grace"]);
    assert_eq!(report.disabled, vec!["expired"]);
    assert!(
        !inv.get_user(&UserId("grace".into()))
            .await
            .unwrap()
            .unwrap()
            .disabled
    );
    assert!(
        inv.get_user(&UserId("expired".into()))
            .await
            .unwrap()
            .unwrap()
            .disabled
    );
}

#[tokio::test]
async fn new_paid_subscriber_gets_complete_user_and_every_server() {
    let mut server = mockito::Server::new_async().await;
    let body = json!({
        "data": [subscriber(321, "New payer", "active")],
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
    inv.add_server(&vpn_server("de")).await.unwrap();
    inv.add_server(&vpn_server("fi")).await.unwrap();

    let report = sync_once_with_policy(&client, &inv, "ninitux", ApplyMode::EnableOnly, 14, true)
        .await
        .unwrap();

    assert_eq!(report.provisioned, vec!["boosty-321"]);
    assert!(report.new_subscribers.is_empty());
    let created = inv
        .get_user(&UserId("boosty-321".into()))
        .await
        .unwrap()
        .unwrap();
    assert!(created.tuic_password.is_some());
    assert!(created.wireguard_pubkey.is_some());
    assert!(created.wireguard_private.is_some());
    assert!(created.sub_token.is_some());
    assert!(created.vpn_router_device_id.is_some());
    assert_eq!(
        inv.servers_for_user(&created.id).await.unwrap().len(),
        2,
        "every current server is granted"
    );
    let audit = inv
        .recent_audit(10)
        .await
        .unwrap()
        .into_iter()
        .find(|a| a.action == "boosty.provision")
        .unwrap();
    let payload = audit.payload.unwrap().to_string();
    assert!(payload.contains("\"servers_granted\":2"));
    assert!(!payload.contains("password"));
    assert!(!payload.contains("private"));
    assert!(!payload.contains("token"));
}

#[tokio::test]
async fn concurrent_syncs_cannot_create_two_users_for_one_subscriber() {
    let mut server = mockito::Server::new_async().await;
    let body = json!({
        "data": [subscriber(654, "Concurrent payer", "active")],
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

    let client_a = ApiClient::new(reqwest::Client::new(), server.url());
    let client_b = ApiClient::new(reqwest::Client::new(), server.url());
    let dir = tempfile::tempdir().unwrap();
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();

    let (a, b) = tokio::join!(
        sync_once_with_policy(&client_a, &inv, "ninitux", ApplyMode::EnableOnly, 14, true),
        sync_once_with_policy(&client_b, &inv, "ninitux", ApplyMode::EnableOnly, 14, true),
    );
    assert!(a.is_ok(), "{a:?}");
    assert!(b.is_ok(), "{b:?}");
    let links = inv.list_boosty_links().await.unwrap();
    assert_eq!(
        links
            .iter()
            .filter(|(_, subscriber_id)| *subscriber_id == 654)
            .count(),
        1
    );
    assert_eq!(
        inv.list_users()
            .await
            .unwrap()
            .iter()
            .filter(|u| u.id.0.starts_with("boosty-654"))
            .count(),
        1
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
