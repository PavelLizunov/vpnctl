//! Spec for the abuse-origins "Subscription origins" inventory methods
//! on `SqliteInventory`. Written against the public API + the schema in
//! `migrations/0003_sub_access_log.sql` (+ 0019 rich metadata, 0021
//! vpn-egress) only — impl NOT consulted.
//!
//! Methods under test:
//!   - `sub_access_by_country(user, days)`
//!   - `sub_access_by_asn(user, days, limit)`
//!   - `sub_access_by_ip(user, days, limit)`
//!   - `sub_access_device_fingerprint(user, days)`
//!
//! Behaviour contract every test pins:
//!   1. Scoped to ONE user (`user_id = ?`), so a NULL-user (deleted)
//!      row and another user's rows never leak in.
//!   2. `is_vpn_egress = 1` rows (src IP = one of our own VPN servers)
//!      are excluded from every breakdown.
//!   3. Distinct-IP / distinct-ASN counts dedup correctly.
//!   4. Ordering: country/ASN by fetches DESC, IP by last_seen DESC.
//!   5. `limit` caps the by-ASN / by-IP rows.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use tempfile::TempDir;

use vpnctl_core::{KernelId, Server, ServerId, User, UserId};
use vpnctl_inventory::SqliteInventory;

fn db_path(dir: &TempDir) -> PathBuf {
    dir.path().join("inventory.db")
}

async fn open(dir: &TempDir) -> SqliteInventory {
    SqliteInventory::open(&db_path(dir)).await.expect("open")
}

fn user(id: &str) -> User {
    User {
        id: UserId(id.to_string()),
        uuid: format!("uuid-of-{id}"),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    }
}

async fn add_test_server(inv: &SqliteInventory, id: &str, address: &str) {
    inv.add_server(&Server {
        id: ServerId(id.into()),
        address: address.into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: Vec::new(),
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .expect("add_server");
}

/// Log one rich row with just (ip, country, asn, device_class, ua, ja4).
#[allow(clippy::too_many_arguments)]
async fn log(
    inv: &SqliteInventory,
    uid: &str,
    ip: &str,
    country: Option<&str>,
    asn: Option<&str>,
    device_class: Option<&str>,
    ua: Option<&str>,
    ja4: Option<&str>,
) {
    inv.log_sub_access_rich(
        &UserId(uid.into()),
        ip,
        ua,
        200,
        100,
        None,
        None,
        device_class,
        country,
        asn,
        None,
        ja4,
    )
    .await
    .unwrap();
}

// ── empty-user states ────────────────────────────────────────────────

#[tokio::test]
async fn origins_empty_user_returns_empty_breakdowns_and_zero_fingerprint() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    let u = UserId("alice".into());

    assert!(inv.sub_access_by_country(&u, 30).await.unwrap().is_empty());
    assert!(inv.sub_access_by_asn(&u, 30, 10).await.unwrap().is_empty());
    assert!(inv.sub_access_by_ip(&u, 30, 15).await.unwrap().is_empty());
    let fp = inv.sub_access_device_fingerprint(&u, 30).await.unwrap();
    assert_eq!(fp.distinct_device_classes, 0);
    assert_eq!(fp.distinct_ja4, 0);
    assert_eq!(fp.distinct_uas, 0);
}

// ── by country ───────────────────────────────────────────────────────

#[tokio::test]
async fn by_country_groups_orders_and_counts_distinct_ips_and_asns() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();

    // US: 3 fetches, 2 distinct IPs, 2 distinct ASNs.
    log(
        &inv,
        "alice",
        "1.1.1.1",
        Some("US"),
        Some("AS1 A"),
        None,
        None,
        None,
    )
    .await;
    log(
        &inv,
        "alice",
        "1.1.1.1",
        Some("US"),
        Some("AS1 A"),
        None,
        None,
        None,
    )
    .await;
    log(
        &inv,
        "alice",
        "2.2.2.2",
        Some("US"),
        Some("AS2 B"),
        None,
        None,
        None,
    )
    .await;
    // DE: 1 fetch, 1 IP, 1 ASN.
    log(
        &inv,
        "alice",
        "3.3.3.3",
        Some("DE"),
        Some("AS3 C"),
        None,
        None,
        None,
    )
    .await;
    // NULL country: 1 fetch.
    log(
        &inv,
        "alice",
        "4.4.4.4",
        None,
        Some("AS4 D"),
        None,
        None,
        None,
    )
    .await;

    let rows = inv
        .sub_access_by_country(&UserId("alice".into()), 30)
        .await
        .unwrap();
    // 3 groups: US, DE, and the NULL-country group.
    assert_eq!(rows.len(), 3, "US + DE + NULL = 3 country groups");
    // Ordered by fetches DESC: US (3) first.
    assert_eq!(rows[0].country.as_deref(), Some("US"));
    assert_eq!(rows[0].fetches, 3);
    assert_eq!(rows[0].ips, 2, "1.1.1.1 (×2) + 2.2.2.2 = 2 distinct IPs");
    assert_eq!(rows[0].asns, 2, "AS1 + AS2 = 2 distinct ASNs");
    // The NULL-country group is present (rendered "(unknown)" by the UI).
    assert!(
        rows.iter().any(|r| r.country.is_none() && r.fetches == 1),
        "NULL-country group must survive as its own row"
    );
}

#[tokio::test]
async fn by_country_excludes_egress_and_other_users() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    inv.add_user(&user("bob")).await.unwrap();
    add_test_server(&inv, "de", "10.20.30.40").await;

    // alice real client in US.
    log(
        &inv,
        "alice",
        "1.1.1.1",
        Some("US"),
        Some("AS1 A"),
        None,
        None,
        None,
    )
    .await;
    // alice egress (src IP = server) in DE — must NOT appear.
    log(
        &inv,
        "alice",
        "10.20.30.40",
        Some("DE"),
        Some("AS9 X"),
        None,
        None,
        None,
    )
    .await;
    // bob's row in FR — must NOT leak into alice's breakdown.
    log(
        &inv,
        "bob",
        "8.8.8.8",
        Some("FR"),
        Some("AS8 Y"),
        None,
        None,
        None,
    )
    .await;

    let rows = inv
        .sub_access_by_country(&UserId("alice".into()), 30)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1, "only alice's real US row");
    assert_eq!(rows[0].country.as_deref(), Some("US"));
}

// ── by ASN ───────────────────────────────────────────────────────────

#[tokio::test]
async fn by_asn_top_n_ordered_by_fetches_with_country_and_distinct_ips() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();

    // AS-MTS: 3 fetches across 2 IPs, country RU.
    log(
        &inv,
        "alice",
        "1.1.1.1",
        Some("RU"),
        Some("AS8359 MTS PJSC"),
        None,
        None,
        None,
    )
    .await;
    log(
        &inv,
        "alice",
        "1.1.1.1",
        Some("RU"),
        Some("AS8359 MTS PJSC"),
        None,
        None,
        None,
    )
    .await;
    log(
        &inv,
        "alice",
        "1.1.1.2",
        Some("RU"),
        Some("AS8359 MTS PJSC"),
        None,
        None,
        None,
    )
    .await;
    // AS-Google: 1 fetch, US.
    log(
        &inv,
        "alice",
        "8.8.8.8",
        Some("US"),
        Some("AS15169 GOOGLE"),
        None,
        None,
        None,
    )
    .await;

    let rows = inv
        .sub_access_by_asn(&UserId("alice".into()), 30, 10)
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    // Ordered by fetches DESC: MTS (3) first.
    assert_eq!(rows[0].asn.as_deref(), Some("AS8359 MTS PJSC"));
    assert_eq!(rows[0].fetches, 3);
    assert_eq!(rows[0].ips, 2, "1.1.1.1 (×2) + 1.1.1.2 = 2 distinct IPs");
    assert_eq!(rows[0].country.as_deref(), Some("RU"));
}

#[tokio::test]
async fn by_asn_respects_limit() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    for i in 0..5 {
        let asn = format!("AS{i} Net{i}");
        log(
            &inv,
            "alice",
            &format!("9.9.9.{i}"),
            Some("US"),
            Some(&asn),
            None,
            None,
            None,
        )
        .await;
    }
    let rows = inv
        .sub_access_by_asn(&UserId("alice".into()), 30, 2)
        .await
        .unwrap();
    assert_eq!(rows.len(), 2, "limit=2 caps the by-ASN rows");
}

// ── by IP ────────────────────────────────────────────────────────────

#[tokio::test]
async fn by_ip_orders_by_last_seen_desc_with_first_last_seen_and_counts() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();

    // Two IPs; second-inserted is more recent → must sort first.
    log(
        &inv,
        "alice",
        "1.1.1.1",
        Some("US"),
        Some("AS1 A"),
        None,
        None,
        None,
    )
    .await;
    log(
        &inv,
        "alice",
        "1.1.1.1",
        Some("US"),
        Some("AS1 A"),
        None,
        None,
        None,
    )
    .await;
    // ensure a strictly later timestamp for the second IP
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    log(
        &inv,
        "alice",
        "2.2.2.2",
        Some("DE"),
        Some("AS2 B"),
        None,
        None,
        None,
    )
    .await;

    let rows = inv
        .sub_access_by_ip(&UserId("alice".into()), 30, 15)
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    // Newest-last-seen first → 2.2.2.2.
    assert_eq!(rows[0].ip, "2.2.2.2");
    assert_eq!(rows[0].country.as_deref(), Some("DE"));
    assert_eq!(rows[0].asn.as_deref(), Some("AS2 B"));
    // 1.1.1.1 has 2 fetches; first_seen != last_seen possible but both
    // are non-empty ISO strings.
    let one = rows.iter().find(|r| r.ip == "1.1.1.1").unwrap();
    assert_eq!(one.fetches, 2);
    assert!(!one.first_seen.is_empty() && !one.last_seen.is_empty());
    assert!(
        one.first_seen <= one.last_seen,
        "first_seen must be <= last_seen (ISO strings sort lexicographically)"
    );
}

#[tokio::test]
async fn by_ip_excludes_egress_and_respects_limit() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    add_test_server(&inv, "de", "10.20.30.40").await;

    log(
        &inv,
        "alice",
        "10.20.30.40",
        Some("DE"),
        Some("AS9 X"),
        None,
        None,
        None,
    )
    .await; // egress
    for i in 0..4 {
        log(
            &inv,
            "alice",
            &format!("5.5.5.{i}"),
            Some("US"),
            Some("AS1 A"),
            None,
            None,
            None,
        )
        .await;
    }

    let rows = inv
        .sub_access_by_ip(&UserId("alice".into()), 30, 2)
        .await
        .unwrap();
    assert_eq!(rows.len(), 2, "limit=2 + egress excluded");
    assert!(
        rows.iter().all(|r| r.ip != "10.20.30.40"),
        "egress IP must never appear in the by-IP breakdown"
    );
}

// ── device fingerprint ───────────────────────────────────────────────

#[tokio::test]
async fn device_fingerprint_counts_distinct_class_ja4_ua_excluding_nulls_and_egress() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    add_test_server(&inv, "de", "10.20.30.40").await;

    // Two distinct device classes, two distinct UAs, one JA4 + one NULL JA4.
    log(
        &inv,
        "alice",
        "1.1.1.1",
        Some("US"),
        Some("AS1 A"),
        Some("Hiddify"),
        Some("Hiddify/1"),
        Some("ja4-aaa"),
    )
    .await;
    log(
        &inv,
        "alice",
        "2.2.2.2",
        Some("US"),
        Some("AS1 A"),
        Some("v2rayNG"),
        Some("v2rayNG/2"),
        None,
    )
    .await;
    // duplicate device_class/ua — must not inflate distinct counts.
    log(
        &inv,
        "alice",
        "3.3.3.3",
        Some("US"),
        Some("AS1 A"),
        Some("Hiddify"),
        Some("Hiddify/1"),
        Some("ja4-aaa"),
    )
    .await;
    // egress row with a NEW device class — must be excluded.
    log(
        &inv,
        "alice",
        "10.20.30.40",
        Some("DE"),
        Some("AS9 X"),
        Some("EgressOnly"),
        Some("Egress/9"),
        Some("ja4-zzz"),
    )
    .await;

    let fp = inv
        .sub_access_device_fingerprint(&UserId("alice".into()), 30)
        .await
        .unwrap();
    assert_eq!(
        fp.distinct_device_classes, 2,
        "Hiddify + v2rayNG; EgressOnly excluded, dup not double-counted"
    );
    assert_eq!(fp.distinct_uas, 2, "two distinct UAs, egress excluded");
    assert_eq!(
        fp.distinct_ja4, 1,
        "one real ja4 (NULL ignored, egress ja4 excluded)"
    );
}

#[tokio::test]
async fn device_fingerprint_excludes_deleted_user_null_rows() {
    // A since-deleted user's rows carry NULL user_id. They must not be
    // attributed to anyone via `user_id = ?`.
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("ghost")).await.unwrap();
    log(
        &inv,
        "ghost",
        "1.1.1.1",
        Some("US"),
        Some("AS1 A"),
        Some("Hiddify"),
        Some("Hiddify/1"),
        None,
    )
    .await;

    let raw = sqlx::SqlitePool::connect(&format!("sqlite://{}", db_path(&dir).display()))
        .await
        .unwrap();
    sqlx::query("PRAGMA foreign_keys = ON")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id = 'ghost'")
        .execute(&raw)
        .await
        .unwrap();
    raw.close().await;

    // Re-add a fresh user with the SAME id — its breakdown must be empty
    // (the orphaned NULL-user rows must not re-attach by id equality).
    inv.add_user(&user("ghost")).await.unwrap();
    let fp = inv
        .sub_access_device_fingerprint(&UserId("ghost".into()), 30)
        .await
        .unwrap();
    assert_eq!(fp.distinct_device_classes, 0);
    assert_eq!(fp.distinct_uas, 0);
    let countries = inv
        .sub_access_by_country(&UserId("ghost".into()), 30)
        .await
        .unwrap();
    assert!(
        countries.is_empty(),
        "NULL-user rows must not attribute to a re-created same-id user"
    );
}
