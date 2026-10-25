#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use boosty_api::api_client::ApiClient;
use serde_json::json;
use vpnctl_boosty_bridge::{
    ApplyMode, build_client, sync_from_settings_at, sync_once, sync_once_with_policy,
};
use vpnctl_core::{KernelId, Server, ServerId, User, UserId};
use vpnctl_inventory::{BoostySettings, SqliteInventory};

fn subscriber(id: i64, name: &str, status: &str) -> serde_json::Value {
    subscriber_priced(id, name, status, 200.0, "Пингвин-одиночка")
}

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
            subscriber(100, "Alice", "active"),
            subscriber(200, "Bob", "inactive"),
            subscriber(300, "Carol", "active"),
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

    let users = inv.list_users().await.unwrap();
    let alice = users.iter().find(|u| u.id.0 == "alice").unwrap();
    let bob = users.iter().find(|u| u.id.0 == "bob").unwrap();
    assert!(!alice.disabled, "alice re-enabled");
    assert!(bob.disabled, "bob disabled");

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

    assert_eq!(report.lapsed_pending, vec!["bob"]);
    assert!(report.disabled.is_empty());
    let users = inv.list_users().await.unwrap();
    assert!(!users[0].disabled, "EnableOnly must not disable bob");
}

#[tokio::test]
async fn free_followers_are_excluded_from_vpn() {
    let mut server = mockito::Server::new_async().await;
    let body = json!({
        "data": [
            subscriber(300, "Payer", "active"),
            follower(400, "Freeloader", "active"),
            follower(500, "ExFree", "inactive"),
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

#[tokio::test]
async fn linked_user_downgraded_to_free_is_disabled() {
    let mut server = mockito::Server::new_async().await;
    let body = json!({
        "data": [
            follower(600, "Downgraded", "active"),
            subscriber(700, "StillPaying", "active"),
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

#[tokio::test]
async fn linked_free_follower_under_enable_only_is_pending_not_disabled() {
    let mut server = mockito::Server::new_async().await;
    let body = json!({
        "data": [
            follower(600, "Freeloader", "active"),
            subscriber(700, "StillPaying", "active"),
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

#[tokio::test]
async fn all_active_free_roster_disables_only_confirmed_downgrades() {
    let mut server = mockito::Server::new_async().await;
    let body = json!({
        "data": [
            follower(600, "NowFree", "active"),
            follower(601, "AlsoFree", "active"),
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
    inv.add_user(&user("missing", false)).await.unwrap();
    inv.link_boosty_subscriber(&UserId("missing".into()), 602)
        .await
        .unwrap();

    let report = sync_once(&client, &inv, "ninitux", ApplyMode::Full)
        .await
        .unwrap();

    assert_eq!(report.disabled, vec!["carol"]);
    assert_eq!(report.suppressed_disables, vec!["missing"]);
    let users = inv.list_users().await.unwrap();
    let carol = users.iter().find(|u| u.id.0 == "carol").unwrap();
    assert!(
        carol.disabled,
        "confirmed downgrade must disable the last payer"
    );
    assert!(
        !users.iter().find(|u| u.id.0 == "missing").unwrap().disabled,
        "an absent subscriber stays protected in the same sync"
    );
}

#[tokio::test]
async fn confirmed_free_downgrade_waits_for_grace_then_disables_once() {
    let mut server = mockito::Server::new_async().await;
    let body = json!({
        "data": [follower(600, "NowFree", "active")],
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
    let uid = UserId("carol".into());
    inv.add_user(&user("carol", false)).await.unwrap();
    inv.link_boosty_subscriber(&uid, 600).await.unwrap();

    let first = sync_once_with_policy(&client, &inv, "ninitux", ApplyMode::Full, 14, false)
        .await
        .unwrap();
    assert_eq!(first.grace_pending, vec!["carol"]);
    assert!(first.disabled.is_empty());
    assert!(first.suppressed_disables.is_empty());
    assert!(!inv.get_user(&uid).await.unwrap().unwrap().disabled);
    assert!(
        inv.recent_audit(20)
            .await
            .unwrap()
            .iter()
            .all(|row| row.action != "boosty.disable")
    );

    inv.observe_boosty_lapse(&uid, Some(first.observed_at - 15 * 86_400))
        .await
        .unwrap();
    let expired = sync_once_with_policy(&client, &inv, "ninitux", ApplyMode::Full, 14, false)
        .await
        .unwrap();
    assert_eq!(expired.disabled, vec!["carol"]);
    assert!(expired.grace_pending.is_empty());
    assert!(expired.suppressed_disables.is_empty());
    assert!(expired.errors.is_empty());
    assert!(inv.get_user(&uid).await.unwrap().unwrap().disabled);

    let retry = sync_once_with_policy(&client, &inv, "ninitux", ApplyMode::Full, 14, false)
        .await
        .unwrap();
    assert!(retry.disabled.is_empty());
    let audits = inv.recent_audit(20).await.unwrap();
    assert_eq!(
        audits
            .iter()
            .filter(|row| row.action == "boosty.disable" && row.target.as_deref() == Some("carol"))
            .count(),
        1
    );
}

#[tokio::test]
async fn zero_paid_roster_suppresses_disable_of_absent_subscriber() {
    let mut server = mockito::Server::new_async().await;
    let body = json!({
        "data": [follower(601, "FreeFollower", "active")],
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
    let uid = UserId("carol".into());
    inv.add_user(&user("carol", false)).await.unwrap();
    inv.link_boosty_subscriber(&uid, 600).await.unwrap();
    inv.observe_boosty_lapse(&uid, Some(1)).await.unwrap();

    let report = sync_once_with_policy(&client, &inv, "ninitux", ApplyMode::Full, 14, false)
        .await
        .unwrap();
    assert!(report.disabled.is_empty());
    assert!(report.grace_pending.is_empty());
    assert_eq!(report.suppressed_disables, vec!["carol"]);
    assert!(!inv.get_user(&uid).await.unwrap().unwrap().disabled);
    assert!(
        inv.recent_audit(20)
            .await
            .unwrap()
            .iter()
            .all(|row| row.action != "boosty.disable")
    );
}

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
    assert!(
        inv.recent_audit(20)
            .await
            .unwrap()
            .iter()
            .all(|row| row.action != "boosty.disable")
    );
}

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

#[tokio::test]
async fn refresh_rotation_survives_cancellation_while_roster_is_pending() {
    use std::sync::{Arc, Mutex, mpsc};
    use std::time::Duration;

    for recover_bearer in [false, true] {
        let mut server = mockito::Server::new_async().await;
        let _bearer_failure = if recover_bearer {
            Some(
                server
                    .mock("GET", "/v1/blog/ninitux/subscribers")
                    .match_query(mockito::Matcher::Any)
                    .match_header("authorization", "Bearer expired-access")
                    .with_status(401)
                    .create_async()
                    .await,
            )
        } else {
            None
        };
        let refresh = server
            .mock("POST", "/oauth/token/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"access_token":"new-access","refresh_token":"new-refresh","expires_in":3600}"#,
            )
            .create_async()
            .await;
        let roster_started = Arc::new(tokio::sync::Notify::new());
        let started = Arc::clone(&roster_started);
        let (release, wait) = mpsc::channel();
        let wait = Mutex::new(wait);
        let roster = server
            .mock("GET", "/v1/blog/ninitux/subscribers")
            .match_query(mockito::Matcher::Any)
            .match_header("authorization", "Bearer new-access")
            .with_status(200)
            .with_chunked_body(move |_| {
                started.notify_one();
                let _ = wait.lock().unwrap().recv_timeout(Duration::from_secs(5));
                Ok(())
            })
            .create_async()
            .await;

        let dir = tempfile::tempdir().unwrap();
        let inv = SqliteInventory::open(&dir.path().join("inv.db"))
            .await
            .unwrap();
        let settings = BoostySettings {
            blog_url: Some("ninitux".into()),
            access_token: recover_bearer.then(|| "expired-access".into()),
            refresh_token: Some("old-refresh".into()),
            device_id: Some("device".into()),
            ..Default::default()
        };
        inv.set_boosty_settings(&settings).await.unwrap();
        let base_url = server.url();
        let saved_refresh = {
            let sync = sync_from_settings_at(&inv, &settings, ApplyMode::DryRun, &base_url);
            tokio::pin!(sync);
            tokio::select! {
                result = &mut sync => panic!("sync finished before roster was released: {result:?}"),
                started = tokio::time::timeout(Duration::from_secs(5), roster_started.notified()) => {
                    started.expect("roster request must start");
                }
            }
            inv.get_boosty_settings().await.unwrap().refresh_token
            // Dropping the pending sync models the admin request timeout.
        };
        release.send(()).unwrap();
        assert_eq!(saved_refresh.as_deref(), Some("new-refresh"));
        let reopened = SqliteInventory::open(&dir.path().join("inv.db"))
            .await
            .unwrap();
        assert_eq!(
            reopened
                .get_boosty_settings()
                .await
                .unwrap()
                .refresh_token
                .as_deref(),
            Some("new-refresh")
        );
        refresh.assert_async().await;
        roster.assert_async().await;
    }
}

#[tokio::test]
async fn build_client_prefers_bearer_flow_when_both_creds_set() {
    let settings = BoostySettings {
        access_token: Some("static-acc".into()),
        refresh_token: Some("ref1".into()),
        device_id: Some("dev".into()),
        ..Default::default()
    };
    let client = build_client(&settings, "http://127.0.0.1:1").await.unwrap();
    assert_eq!(
        client.refresh_token().await.as_deref(),
        None,
        "client must be in bearer mode initially"
    );
}

#[tokio::test]
async fn build_client_uses_refresh_flow_when_only_refresh_creds_set() {
    let settings = BoostySettings {
        access_token: None,
        refresh_token: Some("ref1".into()),
        device_id: Some("dev".into()),
        ..Default::default()
    };
    let client = build_client(&settings, "http://127.0.0.1:1").await.unwrap();
    assert_eq!(
        client.refresh_token().await.as_deref(),
        Some("ref1"),
        "client must be in refresh mode when only refresh credentials exist"
    );
}

#[tokio::test]
async fn build_bearer_and_refresh_client_constructors() {
    let bearer = vpnctl_boosty_bridge::build_bearer_client("acc123", "http://127.0.0.1:1")
        .await
        .unwrap();
    assert_eq!(bearer.refresh_token().await.as_deref(), None);

    let refresh =
        vpnctl_boosty_bridge::build_refresh_client("ref123", "dev123", "http://127.0.0.1:1")
            .await
            .unwrap();
    assert_eq!(refresh.refresh_token().await.as_deref(), Some("ref123"));
}

#[tokio::test]
async fn sync_from_settings_recovers_via_refresh_flow_on_bearer_401() {
    let mut server = mockito::Server::new_async().await;
    let m_unauth = server
        .mock("GET", "/v1/blog/ninitux/subscribers")
        .match_query(mockito::Matcher::Any)
        .match_header("authorization", "Bearer dead-acc")
        .with_status(401)
        .create_async()
        .await;

    let refresh_body = json!({
        "access_token": "new-acc",
        "refresh_token": "new-ref",
        "expires_in": 3600
    })
    .to_string();
    let m_refresh = server
        .mock("POST", "/oauth/token/")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(refresh_body)
        .create_async()
        .await;

    let roster_body = json!({
        "data": [subscriber_priced(100, "Alice", "active", 500.0, "Tier1")],
        "total": 1, "limit": 100, "offset": 0
    })
    .to_string();
    let m_subscribers = server
        .mock("GET", "/v1/blog/ninitux/subscribers")
        .match_query(mockito::Matcher::Any)
        .match_header("authorization", "Bearer new-acc")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(roster_body)
        .create_async()
        .await;

    let dir = tempfile::TempDir::new().unwrap();
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    let settings = BoostySettings {
        enabled: true,
        blog_url: Some("ninitux".into()),
        access_token: Some("dead-acc".into()),
        refresh_token: Some("old-ref".into()),
        device_id: Some("dev-1".into()),
        ..Default::default()
    };
    inv.set_boosty_settings(&settings).await.unwrap();

    let report = sync_from_settings_at(&inv, &settings, ApplyMode::DryRun, &server.url())
        .await
        .expect("sync must recover via refresh flow on bearer 401");

    assert_eq!(report.active_subscribers, 1);
    m_unauth.assert_async().await;
    m_refresh.assert_async().await;
    m_subscribers.assert_async().await;

    let after = inv.get_boosty_settings().await.unwrap();
    assert_eq!(after.refresh_token.as_deref(), Some("new-ref"));
    assert_eq!(
        after.access_token, None,
        "stale access token must be cleared after recovery"
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

#[tokio::test]
async fn hung_server_times_out_instead_of_hanging_forever() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
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
