//! Contract tests for the Boosty-bridge inventory methods
//! (migration 0040): user↔subscriber links + singleton settings.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use tempfile::TempDir;
use vpnctl_core::{KernelId, Server, ServerId, User, UserId};
use vpnctl_inventory::{BoostySettings, SqliteInventory};

async fn open(dir: &TempDir) -> SqliteInventory {
    SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap()
}

fn user(id: &str) -> User {
    User {
        id: UserId(id.into()),
        uuid: format!("uuid-{id}"),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    }
}

fn server(id: &str) -> Server {
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
async fn link_then_list_and_unlink() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();

    assert!(inv.list_boosty_links().await.unwrap().is_empty());

    let changed = inv
        .link_boosty_subscriber(&UserId("alice".into()), 12345)
        .await
        .unwrap();
    assert!(changed, "first link is a mutation");
    let links = inv.list_boosty_links().await.unwrap();
    assert_eq!(links, vec![(UserId("alice".into()), 12345)]);
    assert_eq!(
        inv.observe_boosty_lapse(&UserId("alice".into()), Some(200))
            .await
            .unwrap(),
        Some(200)
    );
    assert_eq!(
        inv.observe_boosty_lapse(&UserId("alice".into()), Some(300))
            .await
            .unwrap(),
        Some(200),
        "the earliest lapse observation is retained"
    );
    assert_eq!(
        inv.observe_boosty_lapse(&UserId("alice".into()), None)
            .await
            .unwrap(),
        None,
        "a paid recovery clears the lapse spell"
    );

    let changed = inv
        .unlink_boosty_subscriber(&UserId("alice".into()))
        .await
        .unwrap();
    assert!(changed, "unlink of a linked user is a mutation");
    assert!(inv.list_boosty_links().await.unwrap().is_empty());

    // Second unlink is a no-op — callers must not audit it.
    let changed = inv
        .unlink_boosty_subscriber(&UserId("alice".into()))
        .await
        .unwrap();
    assert!(!changed, "unlink of an unlinked user is a no-op");
}

#[tokio::test]
async fn one_subscriber_can_link_many_users() {
    // BB-4 (migration 0041): one paying person's several devices
    // (demonnot-1..5) are separate vpnctl users gated by ONE Boosty
    // subscription. Linking a second user to the same subscriber must
    // SUCCEED (was rejected pre-0041).
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    inv.add_user(&user("bob")).await.unwrap();

    let a = inv
        .link_boosty_subscriber(&UserId("alice".into()), 999)
        .await
        .unwrap();
    let b = inv
        .link_boosty_subscriber(&UserId("bob".into()), 999)
        .await
        .unwrap();
    assert!(a && b, "both users link to the same subscriber");

    // Both appear in the link set, sharing subscriber 999.
    let links = inv.list_boosty_links().await.unwrap();
    assert_eq!(
        links,
        vec![(UserId("alice".into()), 999), (UserId("bob".into()), 999),]
    );

    // Re-linking a user to the SAME subscriber is a no-op success —
    // callers must not audit it.
    let changed = inv
        .link_boosty_subscriber(&UserId("alice".into()), 999)
        .await
        .unwrap();
    assert!(!changed, "same-pair re-link is a no-op");

    // Unlinking one leaves the other linked.
    inv.unlink_boosty_subscriber(&UserId("alice".into()))
        .await
        .unwrap();
    assert_eq!(
        inv.list_boosty_links().await.unwrap(),
        vec![(UserId("bob".into()), 999)]
    );
}

#[tokio::test]
async fn last_report_round_trip() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    // Nothing stored yet.
    assert!(inv.boosty_last_report().await.unwrap().is_none());

    inv.set_boosty_last_report(r#"{"total_subscribers":3}"#)
        .await
        .unwrap();
    let (json, ts) = inv.boosty_last_report().await.unwrap().unwrap();
    assert!(json.contains("total_subscribers"), "{json}");
    assert!(!ts.is_empty(), "sync timestamp recorded");
}

#[tokio::test]
async fn link_unknown_user_errors() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let err = inv
        .link_boosty_subscriber(&UserId("ghost".into()), 1)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("no such user"), "{err}");
}

#[tokio::test]
async fn settings_round_trip_and_refresh_rotation() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    // Seeded default row: disabled, no creds.
    let d = inv.get_boosty_settings().await.unwrap();
    assert!(!d.enabled);
    assert_eq!(d.blog_url, None);

    let s = BoostySettings {
        enabled: true,
        blog_url: Some("ninitux".into()),
        access_token: Some("acc".into()),
        refresh_token: Some("ref1".into()),
        device_id: Some("dev".into()),
        poll_interval_secs: 1800,
        auto_disable_lapsed: true,
        grace_days: 21,
        auto_create_users: true,
    };
    inv.set_boosty_settings(&s).await.unwrap();

    let got = inv.get_boosty_settings().await.unwrap();
    assert!(got.enabled);
    assert_eq!(got.blog_url.as_deref(), Some("ninitux"));
    assert_eq!(got.access_token.as_deref(), Some("acc"));
    assert_eq!(got.poll_interval_secs, 1800);
    assert!(got.auto_disable_lapsed);
    assert_eq!(got.grace_days, 21);
    assert!(got.auto_create_users);

    // Rotation persists only the refresh token.
    inv.set_boosty_refresh_token("ref2").await.unwrap();
    let after = inv.get_boosty_settings().await.unwrap();
    assert_eq!(after.refresh_token.as_deref(), Some("ref2"));
    assert_eq!(
        after.access_token.as_deref(),
        Some("acc"),
        "other fields untouched"
    );
}

#[tokio::test]
async fn boosty_user_and_all_server_grants_are_created_atomically() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("de")).await.unwrap();
    inv.add_server(&server("fi")).await.unwrap();

    let mut created = user("boosty-123");
    created.tuic_password = Some("tuic-secret".into());
    created.wireguard_pubkey = Some("wg-public".into());
    created.wireguard_private = Some("wg-private".into());
    created.vpn_router_device_id = Some("0123456789abcdef0123456789abcdef".into());
    let grants = inv.add_boosty_user(&created, 123).await.unwrap();

    assert_eq!(grants, 2);
    assert_eq!(
        inv.list_boosty_links().await.unwrap(),
        vec![(UserId("boosty-123".into()), 123)]
    );
    assert_eq!(
        inv.servers_for_user(&UserId("boosty-123".into()))
            .await
            .unwrap()
            .len(),
        2
    );
    let stored = inv
        .get_user(&UserId("boosty-123".into()))
        .await
        .unwrap()
        .unwrap();
    assert!(stored.sub_token.is_some());
    assert_eq!(stored.wireguard_private.as_deref(), Some("wg-private"));

    assert!(
        inv.add_boosty_user(&created, 123).await.is_err(),
        "a duplicate cannot add partial grants"
    );
}
