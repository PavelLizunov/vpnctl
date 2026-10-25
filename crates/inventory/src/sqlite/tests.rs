#![allow(clippy::unwrap_used, clippy::expect_used)]

mod wg_addressing;

use super::*;
use serde_json::json;
use tempfile::tempdir;
use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};

async fn fresh() -> SqliteInventory {
    let dir = Box::leak(Box::new(tempdir().expect("tempdir")));
    let path = dir.path().join("inv.db");
    SqliteInventory::open(&path).await.expect("open inventory")
}

fn sample_server(id: &str) -> Server {
    Server {
        id: ServerId(id.into()),
        address: "1.2.3.4".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![
            ProtocolId("vless+reality".into()),
            ProtocolId("tuic-v5".into()),
        ],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

fn sample_user(id: &str) -> User {
    User {
        id: UserId(id.into()),
        uuid: format!("uuid-{id}"),
        tuic_password: Some(format!("pw-{id}")),
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    }
}

#[tokio::test]
async fn billing_renew_rejects_concurrent_tariff_edits_with_same_due_date() {
    use sqlx::sqlite::SqlitePoolOptions;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    for edit in [
        "amount_cents = 2000",
        "billing_cycle = 'annual'",
        "currency = 'USD'",
        "auto_renew = 0",
        "billing_url = 'https://example.com/billing'",
        "notes = 'changed tariff'",
    ] {
        let mut inv = fresh().await;
        let server = sample_server("billing-race");
        inv.add_server(&server).await.unwrap();
        inv.set_server_billing(
            &server.id,
            &ServerBillingInput {
                due_date: "2026-10-01".into(),
                billing_cycle: BillingCycle::Monthly,
                amount_cents: 1000,
                currency: "EUR".into(),
                auto_renew: true,
                billing_url: None,
                notes: None,
                initial_payments_count: None,
            },
        )
        .await
        .unwrap();

        let checkouts = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&checkouts);
        let options = (*inv.pool.connect_options()).clone();
        inv.pool = SqlitePoolOptions::new()
            .min_connections(1)
            .max_connections(1)
            .before_acquire(move |conn, _| {
                let checkout = counter.fetch_add(1, Ordering::SeqCst);
                Box::pin(async move {
                    // Checkout 4 starts the transaction after the billing and two currency reads.
                    if checkout == 3 {
                        sqlx::query(&format!(
                            "UPDATE server_billing SET {edit} WHERE server_id = 'billing-race'"
                        ))
                        .execute(&mut *conn)
                        .await?;
                    }
                    Ok(true)
                })
            })
            .connect_with(options)
            .await
            .unwrap();
        checkouts.store(0, Ordering::SeqCst);

        let renewed = inv
            .advance_server_billing_cycle_guarded(&server.id, "2026-10-01", false)
            .await
            .unwrap();
        assert!(renewed.is_none(), "stale tariff must be rejected: {edit}");
        assert!(
            inv.list_server_payments(&server.id)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            inv.get_server_billing(&server.id)
                .await
                .unwrap()
                .unwrap()
                .due_date,
            "2026-10-01"
        );
        assert!(
            inv.recent_audit(100)
                .await
                .unwrap()
                .iter()
                .all(|a| !a.action.starts_with("server.billing.advance"))
        );
    }
}

#[test]
fn network_key_ipv4_collapses_to_16() {
    assert_eq!(network_key("91.79.36.72"), "91.79");
    assert_eq!(network_key("91.79.37.1"), "91.79");
    assert_ne!(network_key("91.80.1.1"), "91.79");
    assert_eq!(
        network_key("193.143.64.226"),
        network_key("193.143.65.192"),
        "adjacent TBANK mobile pools are one ISP-scale network"
    );
}

#[test]
fn network_key_ipv6_privacy_addresses_in_one_64_collapse() {
    let a = network_key("2001:db8:abcd:0012::1");
    let b = network_key("2001:db8:abcd:0012:7334:1111:2222:3333");
    let c = network_key("2001:db8:abcd:0012:9f00:aaaa:bbbb:cccc");
    assert_eq!(a, b, "two privacy addrs in one /64 must share a key");
    assert_eq!(b, c, "a third privacy addr in the same /64 too");
    assert_ne!(network_key("2001:db8:abcd:0013::1"), a);
}

#[test]
fn network_key_malformed_input_stays_safe() {
    assert_eq!(network_key("not-an-ip"), "not-an-ip");
    assert_eq!(network_key(""), "");
    assert_eq!(network_key("999.999.1.1"), "999.999.1.1");
}

#[test]
fn canonical_ip_text_collapses_equivalent_ipv6_spellings() {
    assert_eq!(canonical_ip_text("2001:0db8:0:0::1"), "2001:db8::1");
}

#[tokio::test]
async fn migrations_apply_and_tables_exist() -> Result<()> {
    let inv = fresh().await;
    assert!(inv.list_servers().await?.is_empty());
    Ok(())
}

async fn pre_0013_pool(path: &std::path::Path) -> Result<sqlx::SqlitePool> {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            sqlx::sqlite::SqliteConnectOptions::new()
                .filename(path)
                .create_if_missing(true),
        )
        .await?;
    let legacy = sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(
            migrator()
                .iter()
                .filter(|migration| migration.version < 13)
                .cloned()
                .collect(),
        ),
        ..sqlx::migrate::Migrator::DEFAULT
    };
    legacy.run(&pool).await?;
    Ok(pool)
}

#[tokio::test]
async fn pre_0013_duplicate_alerts_open_restore_and_verify() -> Result<()> {
    for operation in ["open", "restore", "verify"] {
        let dir = tempdir().unwrap();
        let path = dir.path().join("legacy.db");
        let pool = pre_0013_pool(&path).await?;
        sqlx::query(
            "INSERT INTO servers (id, address, ssh_user, hoster)
             VALUES ('legacy', '192.0.2.1', 'root', 'generic')",
        )
        .execute(&pool)
        .await?;
        for server_id in [None, Some("legacy")] {
            for (created_at, acked_at) in [
                ("2026-01-03T00:00:00Z", None),
                ("2026-01-01T00:00:00Z", None),
                ("2026-01-03T00:00:00Z", None),
                ("2026-01-04T00:00:00Z", Some("2026-01-05T00:00:00Z")),
            ] {
                sqlx::query(
                    "INSERT INTO admin_alerts (kind, server_id, summary, created_at, acked_at)
                     VALUES ('test.duplicate', ?1, 'test alert', ?2, ?3)",
                )
                .bind(server_id)
                .bind(created_at)
                .bind(acked_at)
                .execute(&pool)
                .await?;
            }
        }
        pool.close().await;
        let target = if operation == "restore" {
            let target = dir.path().join("restored.db");
            crate::backup::restore_from(&path, &target).await?;
            target
        } else {
            if operation == "verify" {
                let before = std::fs::read(&path).unwrap();
                let report = crate::backup::verify_snapshot(&path).await?;
                assert_ne!(report.overall, crate::backup::CheckStatus::Fail);
                assert_eq!(std::fs::read(&path).unwrap(), before);
            }
            path
        };
        let inv = SqliteInventory::open(&target).await?;
        let open: Vec<i64> =
            sqlx::query_scalar("SELECT id FROM admin_alerts WHERE acked_at IS NULL ORDER BY id")
                .fetch_all(inv.pool())
                .await?;
        assert_eq!(open, vec![3, 7], "{operation}");
        let audit: String = sqlx::query_scalar(
            "SELECT payload FROM audit_log WHERE action = 'migration.admin_alerts.deduplicate'",
        )
        .fetch_one(inv.pool())
        .await?;
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&audit)?,
            json!({ "acked": 4 })
        );
        let acked: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM admin_alerts WHERE acked_at = '2026-01-05T00:00:00Z'",
        )
        .fetch_one(inv.pool())
        .await?;
        assert_eq!(acked, 2);
        let duplicate = sqlx::query(
            "INSERT INTO admin_alerts (kind, summary) VALUES ('test.duplicate', 'test alert')",
        )
        .execute(inv.pool())
        .await;
        assert!(duplicate.is_err(), "0013 must still enforce uniqueness");
        inv.close().await;
        let reopened = SqliteInventory::open(&target).await?;
        let audits: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'migration.admin_alerts.deduplicate'",
        )
        .fetch_one(reopened.pool())
        .await?;
        assert_eq!(audits, 1, "reopen must not audit a no-op");
        reopened.close().await;
    }
    Ok(())
}

#[tokio::test]
async fn pre_0013_unique_alerts_do_not_write_deduplication_audit() -> Result<()> {
    let dir = tempdir().unwrap();
    let path = dir.path().join("legacy.db");
    let pool = pre_0013_pool(&path).await?;
    sqlx::query("INSERT INTO admin_alerts (kind, summary) VALUES ('test.unique', 'test alert')")
        .execute(&pool)
        .await?;
    pool.close().await;
    let inv = SqliteInventory::open(&path).await?;
    let audits: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'migration.admin_alerts.deduplicate'",
    )
    .fetch_one(inv.pool())
    .await?;
    assert_eq!(audits, 0);
    Ok(())
}

#[tokio::test]
async fn sub_fetch_without_traffic_flags_regression_then_clears() -> Result<()> {
    let inv = fresh().await;
    inv.add_server(&sample_server("s1")).await?;
    for u in [
        "oleg",
        "newbie",
        "healthy",
        "justfetched",
        "lanfetch",
        "controlfetch",
        "v6localfetch",
    ] {
        inv.add_user(&sample_user(u)).await?;
    }

    async fn fetch(inv: &SqliteInventory, uid: &str, ip: &str, mins_ago: i64) {
        sqlx::query(
            "INSERT INTO sub_access_log
                    (ts, user_id, ip, ua, status, bytes, is_vpn_egress)
                 VALUES (strftime('%Y-%m-%dT%H:%M:%fZ','now',?1), ?2,
                         ?3, 'Happ/1', 200, 900, 0)",
        )
        .bind(format!("-{mins_ago} minutes"))
        .bind(uid)
        .bind(ip)
        .execute(&inv.pool)
        .await
        .unwrap();
    }
    async fn traffic(inv: &SqliteInventory, uid: &str, offset: &str) {
        sqlx::query(
            "INSERT INTO vpn_connection_stats
                    (ts, server_id, user_id, upload_bytes, download_bytes, active_connections)
                 VALUES (strftime('%Y-%m-%dT%H:%M:%fZ','now',?1), 's1', ?2, 1000, 2000, 1)",
        )
        .bind(offset)
        .bind(uid)
        .execute(&inv.pool)
        .await
        .unwrap();
    }

    fetch(&inv, "oleg", "198.51.100.7", 60).await;
    traffic(&inv, "oleg", "-2 days").await;
    fetch(&inv, "newbie", "198.51.100.7", 60).await;
    fetch(&inv, "healthy", "198.51.100.7", 60).await;
    traffic(&inv, "healthy", "-2 days").await;
    traffic(&inv, "healthy", "-5 minutes").await;
    fetch(&inv, "justfetched", "198.51.100.7", 10).await;
    traffic(&inv, "justfetched", "-2 days").await;
    for (uid, ip) in [
        ("lanfetch", "192.168.0.200"),
        ("controlfetch", OUR_EGRESS_CONTROL_IPS[0]),
        ("v6localfetch", "fd12:3456::1"),
    ] {
        fetch(&inv, uid, ip, 60).await;
        traffic(&inv, uid, "-2 days").await;
    }

    let flagged = inv.sub_fetch_without_traffic_users(45, 360, 7).await?;
    let ids: Vec<&str> = flagged.iter().map(|u| u.user_id.0.as_str()).collect();
    assert_eq!(
        ids,
        ["oleg"],
        "only the previously-active, past-grace, silent-since-fetch user fires"
    );
    assert!(flagged[0].last_traffic.is_some(), "last_traffic populated");
    assert!(
        flagged[0].fetch_age_minutes >= 45,
        "age past grace: {}",
        flagged[0].fetch_age_minutes
    );

    traffic(&inv, "oleg", "+0 minutes").await;
    let after = inv.sub_fetch_without_traffic_users(45, 360, 7).await?;
    assert!(
        after.is_empty(),
        "oleg clears once traffic resumes: {after:?}"
    );
    Ok(())
}

#[tokio::test]
async fn open_alert_subjects_filters_by_prefix_and_unacked() -> Result<()> {
    let inv = fresh().await;
    inv.insert_alert_if_no_unacked("user.sub_no_traffic:oleg", None, "warning", "s", None)
        .await?;
    inv.insert_alert_if_no_unacked("user.sub_no_traffic:masha", None, "warning", "s", None)
        .await?;
    inv.insert_alert_if_no_unacked("user.traffic_limit:bob", None, "warning", "s", None)
        .await?;
    inv.ack_open_alerts("user.sub_no_traffic:masha", None)
        .await?;

    let mut subs = inv
        .open_alert_subjects_with_kind_prefix("user.sub_no_traffic:")
        .await?;
    subs.sort();
    assert_eq!(
        subs,
        vec!["oleg".to_string()],
        "only the open, exact-prefix subject (suffix stripped) is returned"
    );
    Ok(())
}

#[tokio::test]
async fn top_source_ips_excludes_all_infra_ip_classes() -> Result<()> {
    let inv = fresh().await;
    inv.add_server(&sample_server("s1")).await?;
    let mut v6_server = sample_server("s2");
    v6_server.address = "2001:0db8:0:0::1".into();
    inv.add_server(&v6_server).await?;
    inv.add_user(&sample_user("u")).await?;
    inv.record_user_source_ips(&[
        (UserId("u".into()), "203.0.113.9".into()),
        (UserId("u".into()), "172.32.5.5".into()),
        (UserId("u".into()), "1.2.3.4".into()),
        (UserId("u".into()), "83.97.108.34".into()),
        (UserId("u".into()), "192.168.0.200".into()),
        (UserId("u".into()), "10.5.5.5".into()),
        (UserId("u".into()), "172.20.5.5".into()),
        (UserId("u".into()), "127.0.0.1".into()),
        (UserId("u".into()), "169.254.9.9".into()),
        (UserId("u".into()), "::1".into()),
        (UserId("u".into()), "fe80::1".into()),
        (UserId("u".into()), "fd12:3456::1".into()),
        (UserId("u".into()), "2001:0db8:0:0::1".into()),
        (UserId("u".into()), "2001:db8::99".into()),
    ])
    .await?;
    let mut ips: Vec<String> = inv
        .top_source_ips_for_user(&UserId("u".into()), 30, 50)
        .await?
        .into_iter()
        .map(|r| r.source_ip)
        .collect();
    ips.sort();
    assert_eq!(
        ips,
        vec![
            "172.32.5.5".to_string(),
            "2001:db8::99".to_string(),
            "203.0.113.9".to_string(),
        ],
        "only public clients survive; server/control/LAN/loopback/link-local/ULA all dropped"
    );
    Ok(())
}

#[tokio::test]
async fn ip_concurrency_records_daily_peak_max() -> Result<()> {
    let inv = fresh().await;
    inv.add_user(&sample_user("u")).await?;
    inv.record_user_ip_concurrency(&[(UserId("u".into()), 1)])
        .await?;
    inv.record_user_ip_concurrency(&[(UserId("u".into()), 3)])
        .await?;
    inv.record_user_ip_concurrency(&[(UserId("u".into()), 2)])
        .await?;
    assert_eq!(
        inv.ip_concurrency_peak_for_user(&UserId("u".into()), 30)
            .await?,
        3
    );
    inv.record_user_ip_concurrency(&[(UserId("ghost".into()), 9)])
        .await?;
    assert_eq!(
        inv.ip_concurrency_peak_for_user(&UserId("ghost".into()), 30)
            .await?,
        0
    );
    Ok(())
}

#[tokio::test]
async fn sharing_signals_gathers_concurrency_and_impossible_travel() -> Result<()> {
    let inv = fresh().await;
    inv.add_user(&sample_user("sharer")).await?;
    inv.add_user(&sample_user("solo")).await?;

    async fn fetch(inv: &SqliteInventory, uid: &str, ip: &str, cc: &str, asn: &str, mins: i64) {
        sqlx::query(
            "INSERT INTO sub_access_log
                    (ts, user_id, ip, ua, status, bytes, device_class,
                     geo_country, geo_asn, is_vpn_egress)
                 VALUES (strftime('%Y-%m-%dT%H:%M:%fZ','now',?1), ?2, ?3, 'cli', 200, 100,
                         'Shadowrocket', ?4, ?5, 0)",
        )
        .bind(format!("-{mins} minutes"))
        .bind(uid)
        .bind(ip)
        .bind(cc)
        .bind(asn)
        .execute(&inv.pool)
        .await
        .unwrap();
    }
    fetch(&inv, "sharer", "203.0.113.10", "US", "AS1", 200).await;
    fetch(&inv, "sharer", "198.51.100.20", "DE", "AS2", 185).await;
    fetch(&inv, "solo", "203.0.113.30", "RU", "AS3", 100).await;

    inv.record_user_ip_concurrency(&[(UserId("sharer".into()), 3)])
        .await?;
    inv.record_user_ip_concurrency(&[(UserId("solo".into()), 1)])
        .await?;

    let sigs = inv.sharing_signals_all_users(30, 2.0).await?;
    let find = |u: &str| sigs.iter().find(|s| s.user_id.0 == u).cloned();
    let sharer = find("sharer").expect("sharer present");
    let solo = find("solo").expect("solo present");

    assert_eq!(
        sharer.typical_concurrent_nets, 3,
        "one observed day makes its peak the P75"
    );
    assert_eq!(
        sharer.impossible_travel_hops, 1,
        "US→DE in 15 min = one impossible-travel hop"
    );
    assert_eq!(sharer.distinct_countries, 2);
    assert_eq!(sharer.distinct_asns, 2);

    assert_eq!(
        solo.typical_concurrent_nets, 1,
        "solo never had two nets at once"
    );
    assert_eq!(solo.impossible_travel_hops, 0, "solo single country");
    Ok(())
}

#[tokio::test]
async fn sharing_signals_uses_typical_concurrency_not_one_outlier_day() -> Result<()> {
    let inv = fresh().await;
    inv.add_user(&sample_user("normal-mobile")).await?;

    for (days_ago, peak) in [1, 1, 1, 2, 2, 2, 2, 4].into_iter().enumerate() {
        sqlx::query(
            "INSERT INTO vpn_user_ip_concurrency
                     (user_id, date, peak_concurrent_ips)
                 VALUES (?1, date('now', ?2), ?3)",
        )
        .bind("normal-mobile")
        .bind(format!("-{days_ago} days"))
        .bind(peak)
        .execute(&inv.pool)
        .await?;
    }

    let sigs = inv.sharing_signals_all_users(30, 2.0).await?;
    let normal = sigs
        .iter()
        .find(|s| s.user_id.0 == "normal-mobile")
        .expect("user with concurrency samples present");
    assert_eq!(normal.typical_concurrent_nets, 2);
    Ok(())
}

#[tokio::test]
async fn migration_creates_vcs_ts_index() -> Result<()> {
    let inv = fresh().await;
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT name FROM sqlite_master \
             WHERE type = 'index' AND name = 'idx_vcs_ts'",
    )
    .fetch_optional(inv.pool())
    .await?;
    assert_eq!(
        row.map(|r| r.0).as_deref(),
        Some("idx_vcs_ts"),
        "migration 0032 must create idx_vcs_ts on vpn_connection_stats(ts)"
    );
    Ok(())
}

#[tokio::test]
async fn migration_0033_adds_column_and_audit_index() -> Result<()> {
    let inv = fresh().await;
    let cols: Vec<(String,)> = sqlx::query_as(
        "SELECT name FROM pragma_table_info('node_health') \
             WHERE name = 'kernel_versions_json'",
    )
    .fetch_all(inv.pool())
    .await?;
    assert_eq!(
        cols.len(),
        1,
        "0033 must add node_health.kernel_versions_json"
    );
    let idx: Option<(String,)> = sqlx::query_as(
        "SELECT name FROM sqlite_master \
             WHERE type = 'index' AND name = 'idx_audit_payload_server'",
    )
    .fetch_optional(inv.pool())
    .await?;
    assert_eq!(
        idx.map(|r| r.0).as_deref(),
        Some("idx_audit_payload_server"),
        "0033 must create idx_audit_payload_server on audit_log(json_extract(payload,'$.server_id'))"
    );
    Ok(())
}

#[tokio::test]
async fn migration_0051_adds_stable_identity_constraints() -> Result<()> {
    let inv = fresh().await;
    let cols: Vec<(String, i64, i64)> = sqlx::query_as(
        "SELECT name, \"notnull\", pk FROM pragma_table_info('node_health') \
         WHERE name IN ('sample_seq', 'sample_id') ORDER BY name",
    )
    .fetch_all(inv.pool())
    .await?;
    assert_eq!(
        cols,
        vec![("sample_id".into(), 1, 0), ("sample_seq".into(), 0, 1)],
        "0051 must add sample_id NOT NULL and sample_seq primary key"
    );

    let idx: Option<(String,)> = sqlx::query_as(
        "SELECT name FROM sqlite_master \
         WHERE type = 'index' AND name = 'idx_node_health_sample_id'",
    )
    .fetch_optional(inv.pool())
    .await?;
    assert_eq!(
        idx.map(|r| r.0).as_deref(),
        Some("idx_node_health_sample_id"),
        "0051 must create idx_node_health_sample_id unique index"
    );
    Ok(())
}

#[tokio::test]
async fn open_sets_synchronous_normal() -> Result<()> {
    let inv = fresh().await;
    let (sync_mode,): (i64,) = sqlx::query_as("PRAGMA synchronous")
        .fetch_one(inv.pool())
        .await?;
    assert_eq!(
        sync_mode, 1,
        "expected PRAGMA synchronous = 1 (NORMAL), got {sync_mode}"
    );
    Ok(())
}

#[tokio::test]
async fn server_roundtrip() -> Result<()> {
    let inv = fresh().await;
    inv.add_server(&sample_server("s1")).await?;
    let got = inv.get_server(&ServerId("s1".into())).await?.unwrap();
    assert_eq!(got.address, "1.2.3.4");
    assert_eq!(got.enabled_protocols.len(), 2);
    assert!(got.enabled_protocols.iter().any(|p| p.0 == "vless+reality"));
    Ok(())
}

#[tokio::test]
async fn concurrent_registration_rejects_the_same_canonical_address() -> Result<()> {
    for (left_address, right_address) in [
        ("192.0.2.1", "192.0.2.1"),
        ("2001:0db8:0:0:0:0:0:1", "2001:db8::1"),
        ("LOCALHOST", "localhost"),
    ] {
        let inv = fresh().await;
        let mut left = sample_server("left");
        left.address = left_address.into();
        let mut right = sample_server("right");
        right.address = right_address.into();

        // Hold the writer so both registrations start before either can insert.
        let writer = inv.pool.begin_with("BEGIN IMMEDIATE").await?;
        let registrations = async {
            tokio::join!(
                inv.register_server(&left, "admin"),
                inv.register_server(&right, "cli"),
            )
        };
        tokio::pin!(registrations);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), &mut registrations)
                .await
                .is_err()
        );
        writer.commit().await?;
        let (left_result, right_result) = registrations.await;
        let results = [left_result, right_result];
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        let error = results.into_iter().find_map(|result| result.err()).unwrap();
        assert!(matches!(error, SqliteInventoryError::AlreadyExists(_)));
        let servers = inv.list_servers().await?;
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].kernels.len(), 1);
        assert_eq!(servers[0].enabled_protocols.len(), 2);
        assert_eq!(
            servers[0].address,
            if servers[0].id == left.id {
                left_address
            } else {
                right_address
            }
        );
        let audit = inv.recent_audit(10).await?;
        assert_eq!(
            audit.len(),
            1,
            "rejected registration must not write an audit"
        );
        assert_eq!(audit[0].action, "server.register");
        assert_eq!(audit[0].target.as_deref(), Some(servers[0].id.0.as_str()));
    }
    Ok(())
}

#[tokio::test]
async fn registration_rejects_duplicate_id_without_another_audit() -> Result<()> {
    let inv = fresh().await;
    let server = sample_server("existing");
    inv.register_server(&server, "admin").await?;
    let mut duplicate = server.clone();
    duplicate.address = "192.0.2.2".into();
    let error = inv.register_server(&duplicate, "cli").await.unwrap_err();
    assert!(
        matches!(error, SqliteInventoryError::AlreadyExists(ref what) if what == "server existing")
    );
    assert_eq!(inv.count_servers().await?, 1);
    assert_eq!(inv.recent_audit(10).await?.len(), 1);
    assert_eq!(
        inv.get_server(&server.id).await?.unwrap().address,
        server.address
    );
    Ok(())
}

#[tokio::test]
async fn registration_rolls_back_when_audit_fails() -> Result<()> {
    let inv = fresh().await;
    sqlx::query(
        "CREATE TRIGGER reject_registration_audit BEFORE INSERT ON audit_log
         WHEN NEW.action = 'server.register'
         BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END",
    )
    .execute(inv.pool())
    .await?;
    assert!(
        inv.register_server(&sample_server("rollback"), "admin")
            .await
            .is_err()
    );
    assert_eq!(inv.count_servers().await?, 0);
    for table in [
        "server_kernels",
        "server_protocols",
        "server_resolved_addresses",
    ] {
        let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(inv.pool())
            .await?;
        assert_eq!(count, 0, "registration must roll back {table}");
    }
    assert!(inv.recent_audit(10).await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn ssh_user_update_and_audit_are_one_mutation() -> Result<()> {
    let inv = fresh().await;
    inv.add_server(&sample_server("ssh-user")).await?;
    assert!(
        inv.update_server_ssh_user_audited(
            &ServerId("ssh-user".into()),
            "root",
            "debian",
            "sshpass",
        )
        .await?
    );
    let server = inv.get_server(&ServerId("ssh-user".into())).await?.unwrap();
    assert_eq!(server.ssh_user, "debian");
    let audit = inv.audit_for_server("ssh-user", 10).await?;
    assert!(audit.iter().any(|row| {
        row.action == "server.ssh_user.update"
            && row.payload.as_ref().is_some_and(|payload| {
                payload.get("old_ssh_user").and_then(|v| v.as_str()) == Some("root")
                    && payload.get("ssh_user").and_then(|v| v.as_str()) == Some("debian")
            })
    }));
    Ok(())
}

#[tokio::test]
async fn duplicate_server_returns_already_exists() -> Result<()> {
    let inv = fresh().await;
    inv.add_server(&sample_server("dup")).await?;
    let err = inv.add_server(&sample_server("dup")).await.unwrap_err();
    assert!(
        matches!(err, SqliteInventoryError::AlreadyExists(ref s) if s == "server dup"),
        "expected AlreadyExists(\"server dup\"), got {err:?}"
    );
    Ok(())
}

#[tokio::test]
async fn duplicate_user_returns_already_exists() -> Result<()> {
    let inv = fresh().await;
    inv.add_user(&sample_user("alice")).await?;
    let err = inv.add_user(&sample_user("alice")).await.unwrap_err();
    assert!(
        matches!(err, SqliteInventoryError::AlreadyExists(ref s) if s == "user alice"),
        "expected AlreadyExists(\"user alice\"), got {err:?}"
    );
    Ok(())
}

#[tokio::test]
async fn fingerprint_update_persists() -> Result<()> {
    let inv = fresh().await;
    inv.add_server(&sample_server("s")).await?;
    let valid = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    inv.update_trusted_fingerprint(&ServerId("s".into()), valid)
        .await?;
    let got = inv.get_server(&ServerId("s".into())).await?.unwrap();
    assert_eq!(got.trusted_host_fingerprint.as_deref(), Some(valid));
    Ok(())
}

#[tokio::test]
async fn fingerprint_update_rejects_garbage() -> Result<()> {
    let inv = fresh().await;
    inv.add_server(&sample_server("s")).await?;
    for bad in ["", "abc", "MD5:xxx", "SHA256:short", "SHA256:!!!!"] {
        let err = inv
            .update_trusted_fingerprint(&ServerId("s".into()), bad)
            .await
            .unwrap_err();
        assert!(
            matches!(err, SqliteInventoryError::Invalid(_)),
            "input {bad:?} should be rejected with Invalid, got {err:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn server_secrets_upsert() -> Result<()> {
    let inv = fresh().await;
    inv.add_server(&sample_server("s")).await?;
    let sid = ServerId("s".into());
    inv.set_server_secret(&sid, "reality_private", "PRIV1")
        .await?;
    inv.set_server_secret(&sid, "reality_private", "PRIV2")
        .await?;
    let got = inv.get_server_secret(&sid, "reality_private").await?;
    assert_eq!(got.as_deref(), Some("PRIV2"));
    Ok(())
}

#[tokio::test]
async fn grants_and_users_for_server() -> Result<()> {
    let inv = fresh().await;
    inv.add_server(&sample_server("srv")).await?;
    inv.add_user(&sample_user("alice")).await?;
    inv.add_user(&sample_user("bob")).await?;
    inv.grant(&UserId("alice".into()), &ServerId("srv".into()))
        .await?;
    inv.grant(&UserId("bob".into()), &ServerId("srv".into()))
        .await?;
    let users = inv.users_for_server(&ServerId("srv".into())).await?;
    assert_eq!(users.len(), 2);

    inv.revoke(&UserId("alice".into()), &ServerId("srv".into()))
        .await?;
    let users = inv.users_for_server(&ServerId("srv".into())).await?;
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].id.0, "bob");
    Ok(())
}

#[tokio::test]
async fn users_for_server_excludes_disabled_users() -> Result<()> {
    let inv = fresh().await;
    inv.add_server(&sample_server("srv")).await?;
    inv.add_user(&sample_user("alice")).await?;
    inv.add_user(&sample_user("bob")).await?;
    inv.grant(&UserId("alice".into()), &ServerId("srv".into()))
        .await?;
    inv.grant(&UserId("bob".into()), &ServerId("srv".into()))
        .await?;
    let initial = inv.users_for_server(&ServerId("srv".into())).await?;
    assert_eq!(initial.len(), 2);
    assert!(!initial[0].disabled);
    assert!(!initial[1].disabled);

    assert!(inv.set_user_disabled(&UserId("alice".into()), true).await?);
    let users = inv.users_for_server(&ServerId("srv".into())).await?;
    assert_eq!(
        users.len(),
        1,
        "disabled user must be excluded from the node config slice"
    );
    assert_eq!(users[0].id.0, "bob");
    assert!(!users[0].disabled);

    assert!(
        inv.set_user_disabled(&UserId("alice".into()), false)
            .await?
    );
    let reenabled = inv.users_for_server(&ServerId("srv".into())).await?;
    assert_eq!(
        reenabled.len(),
        2,
        "re-enabled user must return to the node config slice"
    );
    assert!(!reenabled[0].disabled);
    assert!(!reenabled[1].disabled);
    Ok(())
}

#[tokio::test]
async fn cascade_delete_user_removes_grants() -> Result<()> {
    let inv = fresh().await;
    inv.add_server(&sample_server("srv")).await?;
    inv.add_user(&sample_user("alice")).await?;
    inv.grant(&UserId("alice".into()), &ServerId("srv".into()))
        .await?;
    inv.remove_user(&UserId("alice".into())).await?;
    let users = inv.users_for_server(&ServerId("srv".into())).await?;
    assert!(users.is_empty());
    Ok(())
}

#[tokio::test]
async fn known_user_uuids_keep_disabled_revoked_and_deleted_uuids() -> Result<()> {
    let inv = fresh().await;
    let srv = ServerId("srv".into());
    inv.add_server(&sample_server("srv")).await?;
    for id in ["alice", "bob", "carol"] {
        inv.add_user(&sample_user(id)).await?;
        inv.grant(&UserId(id.into()), &srv).await?;
    }
    let bob_override = "11111111-2222-4333-8444-555555555555";
    let carol_override = "66666666-7777-4888-9999-aaaaaaaaaaaa";
    inv.set_grant_client_uuid(&UserId("bob".into()), &srv, bob_override)
        .await?;
    inv.set_grant_client_uuid(&UserId("carol".into()), &srv, carol_override)
        .await?;

    let alice_old = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff";
    inv.set_grant_client_uuid(&UserId("alice".into()), &srv, alice_old)
        .await?;
    inv.set_grant_client_uuid(
        &UserId("alice".into()),
        &srv,
        "12345678-1234-4234-8234-123456789abc",
    )
    .await?;
    inv.set_user_disabled(&UserId("alice".into()), true).await?;
    inv.revoke(&UserId("bob".into()), &srv).await?;
    inv.remove_user(&UserId("carol".into())).await?;

    let known = inv.known_user_uuids().await?;
    for uuid in [
        "uuid-alice",
        alice_old,
        "uuid-bob",
        bob_override,
        "uuid-carol",
        carol_override,
    ] {
        assert!(known.contains(uuid), "{uuid} must stay known: {known:?}");
    }
    assert!(!known.contains("never-seen"));
    Ok(())
}

#[tokio::test]
async fn list_all_server_protocols_with_hidden_returns_full_matrix() -> Result<()> {
    let inv = fresh().await;

    inv.add_server(&sample_server("alpha")).await?;
    inv.set_server_protocol_hidden(
        &ServerId("alpha".into()),
        &ProtocolId("tuic-v5".into()),
        true,
    )
    .await?;

    inv.add_server(&sample_server("beta")).await?;
    inv.add_server_protocol(&ServerId("beta".into()), &ProtocolId("anytls".into()))
        .await?;
    inv.set_server_protocol_hidden(&ServerId("beta".into()), &ProtocolId("anytls".into()), true)
        .await?;

    let matrix = inv.list_all_server_protocols_with_hidden().await?;

    assert_eq!(
        matrix.len(),
        5,
        "matrix should hold 5 entries (2 alpha + 3 beta), got {}",
        matrix.len()
    );
    assert_eq!(
        matrix
            .get(&(ServerId("alpha".into()), ProtocolId("vless+reality".into())))
            .copied(),
        Some(false),
        "alpha.vless+reality must be visible"
    );
    assert_eq!(
        matrix
            .get(&(ServerId("alpha".into()), ProtocolId("tuic-v5".into())))
            .copied(),
        Some(true),
        "alpha.tuic-v5 must be hidden"
    );
    assert_eq!(
        matrix
            .get(&(ServerId("beta".into()), ProtocolId("tuic-v5".into())))
            .copied(),
        Some(false),
        "beta.tuic-v5 must be visible (NOT hidden — only anytls is)"
    );
    assert_eq!(
        matrix
            .get(&(ServerId("beta".into()), ProtocolId("anytls".into())))
            .copied(),
        Some(true),
        "beta.anytls must be hidden"
    );
    Ok(())
}

#[tokio::test]
async fn list_all_server_protocols_with_hidden_empty_on_fresh_inventory() -> Result<()> {
    let inv = fresh().await;
    let matrix = inv.list_all_server_protocols_with_hidden().await?;
    assert!(
        matrix.is_empty(),
        "empty inventory must produce empty matrix, got {} entries",
        matrix.len()
    );
    Ok(())
}

#[tokio::test]
async fn audit_log_records_and_lists() -> Result<()> {
    let inv = fresh().await;
    inv.audit(
        "cli",
        "server.create",
        Some("srv"),
        Some(&json!({"address": "1.2.3.4"})),
    )
    .await?;
    inv.audit("cli", "user.add", Some("alice"), None).await?;

    let log = inv.recent_audit(10).await?;
    assert_eq!(log.len(), 2);
    assert_eq!(log[0].action, "user.add");
    assert_eq!(log[1].action, "server.create");
    assert_eq!(
        log[1]
            .payload
            .as_ref()
            .and_then(|v| v.get("address"))
            .and_then(|v| v.as_str()),
        Some("1.2.3.4")
    );
    Ok(())
}

#[tokio::test]
async fn record_user_destinations_truncates_multibyte_label_without_panic() -> Result<()> {
    let inv = fresh().await;
    inv.add_user(&sample_user("alice")).await?;

    let mut dest = String::from("a");
    dest.push_str(&"😀".repeat(60));
    assert!(dest.len() > 200, "label must exceed 200 bytes");
    assert!(
        !dest.is_char_boundary(200),
        "byte 200 must land mid-codepoint to exercise the panic path",
    );

    inv.record_user_destinations(&[(UserId("alice".into()), dest.clone())])
        .await?;

    let rows = inv
        .top_destinations_for_user(&UserId("alice".into()), 1, 10)
        .await?;
    assert_eq!(rows.len(), 1, "the valid pair must have landed");
    let stored = &rows[0].destination_label;
    assert!(
        stored.chars().count() <= 200,
        "label capped at 200 chars, got {} chars",
        stored.chars().count(),
    );
    assert!(
        dest.starts_with(stored.as_str()),
        "stored label must be a char-boundary prefix of the input",
    );
    Ok(())
}

#[tokio::test]
async fn record_user_destinations_skips_unknown_user_without_aborting_batch() -> Result<()> {
    let inv = fresh().await;
    inv.add_user(&sample_user("alice")).await?;
    inv.add_user(&sample_user("bob")).await?;

    let pairs = vec![
        (UserId("alice".into()), "youtube.com:443".to_string()),
        (UserId("ghost".into()), "discord.com:443".to_string()),
        (UserId("bob".into()), "telegram.org:443".to_string()),
    ];

    inv.record_user_destinations(&pairs).await?;

    let alice = inv
        .top_destinations_for_user(&UserId("alice".into()), 1, 10)
        .await?;
    let bob = inv
        .top_destinations_for_user(&UserId("bob".into()), 1, 10)
        .await?;
    let ghost = inv
        .top_destinations_for_user(&UserId("ghost".into()), 1, 10)
        .await?;

    assert_eq!(alice.len(), 1, "alice's valid row must have landed");
    assert_eq!(alice[0].destination_label, "youtube.com:443");
    assert_eq!(bob.len(), 1, "bob's valid row must have landed");
    assert_eq!(bob[0].destination_label, "telegram.org:443");
    assert!(
        ghost.is_empty(),
        "the FK-violating ghost row must be skipped"
    );
    Ok(())
}

#[tokio::test]
async fn set_grant_client_uuid_same_value_writes_no_audit_row() -> Result<()> {
    let inv = fresh().await;
    inv.add_server(&sample_server("srv")).await?;
    inv.add_user(&sample_user("alice")).await?;
    inv.grant(&UserId("alice".into()), &ServerId("srv".into()))
        .await?;

    let uuid = "11111111-1111-4111-8111-111111111111";
    inv.set_grant_client_uuid(&UserId("alice".into()), &ServerId("srv".into()), uuid)
        .await?;

    let audit_after_first: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM audit_log WHERE action = 'grant.set_client_uuid'")
            .fetch_one(inv.pool())
            .await?;
    assert_eq!(
        audit_after_first.0, 1,
        "first set must write exactly one audit row"
    );

    inv.set_grant_client_uuid(&UserId("alice".into()), &ServerId("srv".into()), uuid)
        .await?;

    let audit_after_second: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM audit_log WHERE action = 'grant.set_client_uuid'")
            .fetch_one(inv.pool())
            .await?;
    assert_eq!(
        audit_after_second.0, 1,
        "re-writing the same client_uuid must NOT add a second audit row"
    );

    let uuid2 = "22222222-2222-4222-8222-222222222222";
    inv.set_grant_client_uuid(&UserId("alice".into()), &ServerId("srv".into()), uuid2)
        .await?;
    let audit_after_change: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM audit_log WHERE action = 'grant.set_client_uuid'")
            .fetch_one(inv.pool())
            .await?;
    assert_eq!(
        audit_after_change.0, 2,
        "a real value change must still emit an audit row"
    );

    inv.add_user(&sample_user("bob")).await?;
    let err = inv
        .set_grant_client_uuid(&UserId("bob".into()), &ServerId("srv".into()), uuid)
        .await;
    assert!(
        err.is_err(),
        "setting client_uuid without a grant must still error"
    );
    Ok(())
}

#[tokio::test]
async fn grant_rejects_effective_uuid_collision() -> Result<()> {
    let inv = fresh().await;
    inv.add_server(&sample_server("de")).await?;
    let shared = "b25684c3-90d6-454a-a911-4e0abba568b0";
    let mut aaa = sample_user("aaa");
    aaa.uuid = shared.into();
    inv.add_user(&aaa).await?;
    inv.add_user(&sample_user("bbb")).await?;

    inv.grant(&UserId("bbb".into()), &ServerId("de".into()))
        .await?;
    inv.set_grant_client_uuid(&UserId("bbb".into()), &ServerId("de".into()), shared)
        .await?;

    let err = inv
        .grant(&UserId("aaa".into()), &ServerId("de".into()))
        .await;
    assert!(
        matches!(err, Err(SqliteInventoryError::AlreadyExists(_))),
        "expected AlreadyExists collision, got {err:?}"
    );
    assert!(
        inv.client_uuid_for(&UserId("aaa".into()), &ServerId("de".into()))
            .await?
            .is_none(),
        "rejected grant must not create a grant row"
    );
    Ok(())
}

#[tokio::test]
async fn grant_allows_unique_uuid_and_is_idempotent() -> Result<()> {
    let inv = fresh().await;
    inv.add_server(&sample_server("de")).await?;
    inv.add_user(&sample_user("alice")).await?;
    inv.add_user(&sample_user("bob")).await?;
    inv.grant(&UserId("alice".into()), &ServerId("de".into()))
        .await?;
    inv.grant(&UserId("bob".into()), &ServerId("de".into()))
        .await?;
    inv.grant(&UserId("alice".into()), &ServerId("de".into()))
        .await?;
    assert_eq!(inv.users_for_server(&ServerId("de".into())).await?.len(), 2);
    inv.assert_no_uuid_collisions(&ServerId("de".into()))
        .await?;
    Ok(())
}

#[tokio::test]
async fn set_grant_client_uuid_rejects_collision() -> Result<()> {
    let inv = fresh().await;
    inv.add_server(&sample_server("de")).await?;
    inv.add_user(&sample_user("alice")).await?;
    inv.add_user(&sample_user("bob")).await?;
    inv.grant(&UserId("alice".into()), &ServerId("de".into()))
        .await?;
    inv.grant(&UserId("bob".into()), &ServerId("de".into()))
        .await?;

    let u = "11111111-1111-4111-8111-111111111111";
    inv.set_grant_client_uuid(&UserId("alice".into()), &ServerId("de".into()), u)
        .await?;
    let err = inv
        .set_grant_client_uuid(&UserId("bob".into()), &ServerId("de".into()), u)
        .await;
    assert!(
        matches!(err, Err(SqliteInventoryError::AlreadyExists(_))),
        "expected AlreadyExists, got {err:?}"
    );
    assert_eq!(
        inv.client_uuid_for(&UserId("bob".into()), &ServerId("de".into()))
            .await?,
        Some("uuid-bob".into()),
    );
    inv.set_grant_client_uuid(&UserId("alice".into()), &ServerId("de".into()), u)
        .await?;
    inv.assert_no_uuid_collisions(&ServerId("de".into()))
        .await?;
    Ok(())
}

#[tokio::test]
async fn assert_no_uuid_collisions_catches_manual_edit() -> Result<()> {
    let inv = fresh().await;
    inv.add_server(&sample_server("de")).await?;
    inv.add_user(&sample_user("alice")).await?;
    inv.add_user(&sample_user("bob")).await?;
    inv.grant(&UserId("alice".into()), &ServerId("de".into()))
        .await?;
    inv.grant(&UserId("bob".into()), &ServerId("de".into()))
        .await?;
    inv.assert_no_uuid_collisions(&ServerId("de".into()))
        .await?;

    sqlx::query(
        "UPDATE grants SET client_uuid = 'uuid-alice' WHERE user_id='bob' AND server_id='de'",
    )
    .execute(&inv.pool)
    .await?;
    let err = inv.assert_no_uuid_collisions(&ServerId("de".into())).await;
    assert!(
        matches!(err, Err(SqliteInventoryError::Invalid(_))),
        "planted collision must fail the deploy assertion, got {err:?}"
    );

    sqlx::query("UPDATE users SET disabled = 1 WHERE id='bob'")
        .execute(&inv.pool)
        .await?;
    inv.assert_no_uuid_collisions(&ServerId("de".into()))
        .await?;
    Ok(())
}

#[tokio::test]
async fn grant_unknown_user_errors() -> Result<()> {
    let inv = fresh().await;
    inv.add_server(&sample_server("de")).await?;
    let err = inv
        .grant(&UserId("ghost".into()), &ServerId("de".into()))
        .await;
    assert!(
        matches!(err, Err(SqliteInventoryError::Invalid(_))),
        "granting a non-existent user must error, got {err:?}"
    );
    Ok(())
}

#[tokio::test]
async fn deploy_input_revision_changes_with_render_inputs() -> Result<()> {
    let inv = fresh().await;
    let server = sample_server("s1");
    inv.add_server(&server).await?;
    let initial = inv.deploy_input_revision(&server.id).await?;
    assert_eq!(initial, inv.deploy_input_revision(&server.id).await?);

    inv.set_server_secret(&server.id, "vless.short_id", "deadbeef")
        .await?;
    let with_secret = inv.deploy_input_revision(&server.id).await?;
    assert_ne!(initial, with_secret);
    assert!(
        !inv.audit_deploy_if_revision(
            "admin",
            &server.id,
            &initial,
            &serde_json::json!({"test": true}),
        )
        .await?
    );
    assert!(
        inv.audit_deploy_if_revision(
            "admin",
            &server.id,
            &with_secret,
            &serde_json::json!({"test": true}),
        )
        .await?
    );

    let user = sample_user("u");
    inv.add_user(&user).await?;
    inv.grant(&user.id, &server.id).await?;
    assert_ne!(with_secret, inv.deploy_input_revision(&server.id).await?);
    Ok(())
}

#[tokio::test]
async fn session_observe_skips_unknown_user() -> Result<()> {
    let inv = fresh().await;
    inv.add_server(&sample_server("srv")).await?;
    inv.add_user(&sample_user("alice")).await?;
    let now = chrono::Utc::now();

    let ghost_id = inv
        .session_observe(
            &UserId("ghost".into()),
            &ServerId("srv".into()),
            now,
            15,
            0,
            1,
        )
        .await?;
    assert_eq!(ghost_id, 0, "unknown user must insert no session row");

    let ghost_sessions = inv
        .recent_sessions_for_user(&UserId("ghost".into()), 10)
        .await?;
    assert!(
        ghost_sessions.is_empty(),
        "no session row may exist for an unknown user"
    );

    let alice_id = inv
        .session_observe(
            &UserId("alice".into()),
            &ServerId("srv".into()),
            now,
            15,
            0,
            1,
        )
        .await?;
    assert!(alice_id > 0, "a known user's session must record");
    let alice_sessions = inv
        .recent_sessions_for_user(&UserId("alice".into()), 10)
        .await?;
    assert_eq!(
        alice_sessions.len(),
        1,
        "the known user's session must land"
    );
    Ok(())
}

#[tokio::test]
async fn insert_alert_if_no_unacked_source_event_and_ordinary_semantics() -> Result<()> {
    let inv = fresh().await;
    let srv = ServerId("srv1".into());
    inv.add_server(&sample_server("srv1")).await?;

    let id1 = inv
        .insert_alert_if_no_unacked("ordinary.down", Some(&srv), "warning", "down 1", None)
        .await?
        .expect("first ordinary alert must insert");
    assert!(id1 > 0);

    let dup = inv
        .insert_alert_if_no_unacked("ordinary.down", Some(&srv), "warning", "down 1 dup", None)
        .await?;
    assert_eq!(dup, None);

    assert!(inv.ack_alert(id1).await?);

    let id2 = inv
        .insert_alert_if_no_unacked("ordinary.down", Some(&srv), "warning", "down 2", None)
        .await?
        .expect("ordinary alert must refire after ack");
    assert_ne!(id1, id2);

    let payload_ev1 = serde_json::json!({"_source_event": "10:11"}).to_string();
    let id3 = inv
        .insert_alert_if_no_unacked(
            "health.down",
            Some(&srv),
            "critical",
            "down sample 10->11",
            Some(&payload_ev1),
        )
        .await?
        .expect("first source-event alert must insert");
    assert!(id3 > 0);

    let dup_ev1 = inv
        .insert_alert_if_no_unacked(
            "health.down",
            Some(&srv),
            "critical",
            "down sample 10->11 duplicate",
            Some(&payload_ev1),
        )
        .await?;
    assert_eq!(dup_ev1, None);

    assert!(inv.ack_alert(id3).await?);

    let rescan_same = inv
        .insert_alert_if_no_unacked(
            "health.down",
            Some(&srv),
            "critical",
            "down sample 10->11 rescan",
            Some(&payload_ev1),
        )
        .await?;
    assert_eq!(
        rescan_same, None,
        "rescan of identical source event must not reopen"
    );

    let payload_ev2 = serde_json::json!({"_source_event": "12:13"}).to_string();
    let id4 = inv
        .insert_alert_if_no_unacked(
            "health.down",
            Some(&srv),
            "critical",
            "down sample 12->13 new",
            Some(&payload_ev2),
        )
        .await?
        .expect("new source event must reopen");
    assert_ne!(id3, id4);

    let payload_num = serde_json::json!({"_source_event": 42}).to_string();
    let id_num1 = inv
        .insert_alert_if_no_unacked(
            "metric.spike",
            Some(&srv),
            "warning",
            "spike 42",
            Some(&payload_num),
        )
        .await?
        .expect("first numeric alert must insert");
    let dup_num = inv
        .insert_alert_if_no_unacked(
            "metric.spike",
            Some(&srv),
            "warning",
            "spike 42 dup",
            Some(&payload_num),
        )
        .await?;
    assert_eq!(dup_num, None);
    assert!(inv.ack_alert(id_num1).await?);
    let id_num2 = inv
        .insert_alert_if_no_unacked(
            "metric.spike",
            Some(&srv),
            "warning",
            "spike 42 refire",
            Some(&payload_num),
        )
        .await?
        .expect("numeric payload must refire after ack");
    assert_ne!(id_num1, id_num2);

    let payload_bool = serde_json::json!({"_source_event": true}).to_string();
    let id_bool1 = inv
        .insert_alert_if_no_unacked(
            "state.flag",
            Some(&srv),
            "warning",
            "flag true",
            Some(&payload_bool),
        )
        .await?
        .expect("first bool alert must insert");
    let dup_bool = inv
        .insert_alert_if_no_unacked(
            "state.flag",
            Some(&srv),
            "warning",
            "flag true dup",
            Some(&payload_bool),
        )
        .await?;
    assert_eq!(dup_bool, None);
    assert!(inv.ack_alert(id_bool1).await?);
    let id_bool2 = inv
        .insert_alert_if_no_unacked(
            "state.flag",
            Some(&srv),
            "warning",
            "flag true refire",
            Some(&payload_bool),
        )
        .await?
        .expect("bool payload must refire after ack");
    assert_ne!(id_bool1, id_bool2);

    let global_ev1 = serde_json::json!({"_source_event": "global-err-1"}).to_string();
    let id_g1 = inv
        .insert_alert_if_no_unacked(
            "global.down",
            None,
            "critical",
            "global down 1",
            Some(&global_ev1),
        )
        .await?
        .expect("first global alert with string _source_event must insert");
    assert!(inv.ack_alert(id_g1).await?);
    let dup_g1 = inv
        .insert_alert_if_no_unacked(
            "global.down",
            None,
            "critical",
            "global down 1 rescan",
            Some(&global_ev1),
        )
        .await?;
    assert_eq!(
        dup_g1, None,
        "global alert with identical string _source_event must not reopen after ack"
    );

    Ok(())
}

#[tokio::test]
async fn revoke_rolls_back_both_delete_and_audit_on_failure() -> Result<()> {
    for trigger in [
        "CREATE TRIGGER fail_revoke_audit BEFORE INSERT ON audit_log
         WHEN NEW.action = 'user.revoke'
         BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END",
        "CREATE TRIGGER fail_revoke_delete BEFORE DELETE ON grants
         BEGIN SELECT RAISE(ABORT, 'delete unavailable'); END",
    ] {
        let inv = fresh().await;
        let user = sample_user("alice");
        let server = sample_server("srv");
        inv.add_user(&user).await?;
        inv.add_server(&server).await?;
        inv.grant(&user.id, &server.id).await?;
        sqlx::query(trigger).execute(&inv.pool).await?;

        assert!(
            inv.revoke_audited(&user.id, &server.id, "admin", "test")
                .await
                .is_err()
        );
        assert_eq!(inv.count_grants().await?, 1);
        assert!(inv.recent_audit(10).await?.is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn concurrent_revokes_audit_one_mutation_and_mark_server_pending() -> Result<()> {
    let inv = fresh().await;
    let user = sample_user("alice");
    let server = sample_server("srv");
    inv.add_user(&user).await?;
    inv.add_server(&server).await?;
    inv.grant(&user.id, &server.id).await?;
    inv.audit("admin", "server.deploy", Some(&server.id.0), None)
        .await?;
    assert!(!inv.server_pending_deploy(&server.id).await?);

    let (first, second) = tokio::join!(
        inv.revoke_audited(&user.id, &server.id, "admin", "test"),
        inv.revoke_audited(&user.id, &server.id, "admin", "test"),
    );
    assert_ne!(first?, second?, "only one request deletes the grant");
    assert_eq!(inv.count_grants().await?, 0);
    assert!(inv.server_pending_deploy(&server.id).await?);
    // The unaudited-call-site compatibility wrapper must also avoid no-op rows.
    inv.revoke(&user.id, &server.id).await?;
    let rows = inv.recent_audit(10).await?;
    let revokes: Vec<_> = rows.iter().filter(|r| r.action == "user.revoke").collect();
    assert_eq!(revokes.len(), 1);
    assert_eq!(revokes[0].actor, "admin");
    assert_eq!(revokes[0].target.as_deref(), Some("alice"));
    assert_eq!(revokes[0].payload.as_ref().unwrap()["server"], "srv");
    assert_eq!(revokes[0].payload.as_ref().unwrap()["source"], "test");
    Ok(())
}

#[tokio::test]
async fn subscription_render_inputs_match_individual_lookups() -> Result<()> {
    let inv = fresh().await;
    let user = sample_user("reader");
    let peer = sample_user("peer");
    inv.add_user(&user).await?;
    inv.add_user(&peer).await?;
    for id in ["a", "b", "c"] {
        let mut server = sample_server(id);
        server
            .enabled_protocols
            .push(ProtocolId("wireguard".into()));
        inv.add_server(&server).await?;
        inv.grant(&user.id, &server.id).await?;
        inv.grant(&peer.id, &server.id).await?;
        inv.set_server_secret(&server.id, "vless.public_key", id)
            .await?;
    }
    let a = ServerId("a".into());
    let b = ServerId("b".into());
    inv.set_grant_client_uuid(&user.id, &a, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        .await?;
    inv.set_server_display_name(&a, Some("Custom label"))
        .await?;
    inv.set_server_udp_pair_enabled(&a, true).await?;
    inv.set_server_protocol_hidden(&a, &ProtocolId("tuic-v5".into()), true)
        .await?;
    inv.set_grant_protocol_override(&user.id, &b, &ProtocolId("tuic-v5".into()), true)
        .await?;
    inv.set_client_detour_via_as("test", &ServerId("c".into()), Some(&a))
        .await?;
    inv.set_server_auto_suppress(&b, true).await?;
    inv.set_server_suppressed(&b, true).await?;
    let inputs = inv.subscription_render_inputs(&user.id, true).await?;
    assert_eq!(
        inputs
            .iter()
            .map(|i| i.server.id.0.as_str())
            .collect::<Vec<_>>(),
        ["a", "b", "c"]
    );
    for input in inputs {
        let id = &input.server.id;
        assert_eq!(input.suppressed, inv.is_server_auto_suppressed(id).await?);
        assert_eq!(input.detour_via, inv.client_detour_via(id).await?);
        assert_eq!(input.display_name, inv.server_display_name(id).await?);
        assert_eq!(input.udp_pair, inv.is_server_udp_pair_enabled(id).await?);
        assert_eq!(
            Some(input.client_uuid),
            inv.client_uuid_for(&user.id, id).await?
        );
        assert_eq!(
            input.visible,
            inv.visible_protocols_for_subscription(&user.id, id).await?
        );
        assert_eq!(input.secrets, inv.list_server_secrets(id).await?);
        let expected = inv.users_for_server(id).await?;
        assert_eq!(
            serde_json::to_value(&input.peers)?,
            serde_json::to_value(expected)?
        );
    }
    assert!(
        inv.subscription_render_inputs(&user.id, false)
            .await?
            .iter()
            .all(|i| i.peers.is_empty())
    );
    assert!(
        inv.subscription_render_inputs(&UserId("absent".into()), true)
            .await?
            .is_empty()
    );
    sqlx::query("DROP TABLE server_secrets")
        .execute(inv.pool())
        .await?;
    assert!(
        inv.subscription_render_inputs(&user.id, false)
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn server_address_lookups_ignore_access_log_and_do_not_need_a_write_lock() -> Result<()> {
    let inv = fresh().await;
    inv.add_server(&sample_server("node")).await?;
    sqlx::query("ALTER TABLE sub_access_log RENAME TO unused_access_log")
        .execute(inv.pool())
        .await?;
    sqlx::query("CREATE VIEW sub_access_log AS SELECT * FROM missing_access_log")
        .execute(inv.pool())
        .await?;
    let tx = inv.pool().begin_with("BEGIN IMMEDIATE").await?;
    assert_eq!(
        inv.server_id_for_address("1.2.3.4").await?.as_deref(),
        Some("node")
    );
    assert!(inv.is_known_server_address("1.2.3.4").await?);
    assert_eq!(inv.server_id_for_address("192.0.2.1").await?, None);
    tx.rollback().await?;
    Ok(())
}

#[tokio::test]
async fn telegram_delivery_claim_is_exclusive_and_success_without_message_id_is_final() {
    let inv = fresh().await;
    let id = inv
        .insert_alert("test.delivery", None, "warning", "test", None)
        .await
        .unwrap();
    let now = chrono::Utc::now();
    let audit_before: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_log")
        .fetch_one(inv.pool())
        .await
        .unwrap();
    let (first, second) = tokio::join!(
        inv.claim_alert_telegram_delivery(id, now, false),
        inv.claim_alert_telegram_delivery(id, now, false),
    );
    let claims = [first.unwrap(), second.unwrap()];
    assert_eq!(claims.iter().filter(|claim| **claim == Some(1)).count(), 1);
    assert_eq!(claims.iter().filter(|claim| claim.is_none()).count(), 1);
    assert!(
        inv.claim_alert_telegram_delivery(id, now, true)
            .await
            .unwrap()
            .is_none()
    );
    inv.record_alert_telegram_delivery(id, None).await.unwrap();
    let state: (i64, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT telegram_attempts, telegram_delivered_at, telegram_next_attempt_at FROM admin_alerts WHERE id = ?1",
    ).bind(id).fetch_one(inv.pool()).await.unwrap();
    assert_eq!(state.0, 1);
    assert!(state.1.is_some());
    assert!(state.2.is_none());
    inv.record_alert_telegram_delivery(id, None).await.unwrap();
    inv.defer_alert_telegram_delivery(id, now).await.unwrap();
    assert!(
        inv.pending_alert_telegram_deliveries(now + chrono::Duration::hours(1))
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        inv.expire_alert_telegram_deliveries(now + chrono::Duration::hours(25))
            .await
            .unwrap(),
        0
    );
    let audit_after: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_log")
        .fetch_one(inv.pool())
        .await
        .unwrap();
    assert_eq!(audit_before, audit_after);
    assert!(
        inv.claim_alert_telegram_delivery(-1, now, false)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn telegram_pending_delivery_recovers_abandoned_claims_and_skips_closed_alerts() {
    let inv = fresh().await;
    let id = inv
        .insert_alert("test.delivery", None, "warning", "test", None)
        .await
        .unwrap();
    let created = inv.recent_alerts(1, false).await.unwrap()[0].created_at;
    assert!(
        inv.pending_alert_telegram_deliveries(created + chrono::Duration::seconds(299))
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        inv.pending_alert_telegram_deliveries(created + chrono::Duration::minutes(5))
            .await
            .unwrap()[0]
            .id,
        id
    );
    assert_eq!(
        inv.claim_alert_telegram_delivery(id, created, false)
            .await
            .unwrap(),
        Some(1)
    );
    assert_eq!(
        inv.claim_alert_telegram_delivery(id, created + chrono::Duration::minutes(5), true)
            .await
            .unwrap(),
        Some(2)
    );
    inv.ack_alert(id).await.unwrap();
    assert!(
        inv.pending_alert_telegram_deliveries(created + chrono::Duration::minutes(10))
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        inv.claim_alert_telegram_delivery(id, created + chrono::Duration::minutes(10), true)
            .await
            .unwrap()
            .is_none()
    );
    // Keep the existing immediate push for acknowledged one-shot notifications.
    let one_shot = inv
        .insert_alert_acked("test.event", None, "info", "event", None)
        .await
        .unwrap();
    assert_eq!(
        inv.claim_alert_telegram_delivery(one_shot, created, false)
            .await
            .unwrap(),
        Some(1)
    );
}

#[tokio::test]
async fn telegram_delivery_expiry_records_the_exact_24_hour_boundary_once() {
    let inv = fresh().await;
    let id = inv
        .insert_alert("test.delivery", None, "warning", "test", None)
        .await
        .unwrap();
    let created = inv.recent_alerts(1, false).await.unwrap()[0].created_at;
    let deadline = created + chrono::Duration::hours(24);
    assert_eq!(
        inv.expire_alert_telegram_deliveries(deadline - chrono::Duration::seconds(1))
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        inv.expire_alert_telegram_deliveries(deadline)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        inv.expire_alert_telegram_deliveries(deadline)
            .await
            .unwrap(),
        0
    );
    let state: (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT telegram_gave_up_at, telegram_next_attempt_at FROM admin_alerts WHERE id = ?1",
    )
    .bind(id)
    .fetch_one(inv.pool())
    .await
    .unwrap();
    assert_eq!(state.0.as_deref(), Some(deadline.to_rfc3339().as_str()));
    assert!(state.1.is_none());
    assert!(
        inv.claim_alert_telegram_delivery(id, created, false)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(inv.unacked_alert_count().await.unwrap(), 1);
}

#[tokio::test]
async fn telegram_delivery_migration_preserves_existing_message_ids() {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::raw_sql(
        "CREATE TABLE admin_alerts (
            id INTEGER PRIMARY KEY, created_at TEXT NOT NULL, acked_at TEXT, telegram_message_id TEXT
         );
         INSERT INTO admin_alerts VALUES (1, '2026-10-01T00:00:00.000Z', NULL, '123');
         INSERT INTO admin_alerts VALUES (2, '2026-10-01T00:00:00.000Z', NULL, NULL);",
    ).execute(&pool).await.unwrap();
    sqlx::raw_sql(include_str!(
        "../../migrations/0069_alert_delivery_state.sql"
    ))
    .execute(&pool)
    .await
    .unwrap();
    let states: Vec<(i64, Option<String>, Option<String>, i64)> = sqlx::query_as(
        "SELECT id, telegram_message_id, telegram_delivered_at, telegram_attempts FROM admin_alerts ORDER BY id",
    ).fetch_all(&pool).await.unwrap();
    assert_eq!(
        states,
        vec![
            (
                1,
                Some("123".into()),
                Some("2026-10-01T00:00:00.000Z".into()),
                0
            ),
            (2, None, None, 0),
        ]
    );
}
