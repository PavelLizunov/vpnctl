#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use tempfile::TempDir;

use vpnctl_core::{User, UserId};
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

#[tokio::test]
async fn empty_user_has_no_access_rows_and_zero_distinct_ips() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();

    let rows = inv
        .recent_sub_access(&UserId("alice".into()), 50)
        .await
        .unwrap();
    assert!(rows.is_empty(), "no log rows yet, got {} rows", rows.len());

    let n = inv
        .distinct_ips_for_user(&UserId("alice".into()), 24)
        .await
        .unwrap();
    assert_eq!(n, 0, "no logs → 0 distinct IPs");
}

#[tokio::test]
async fn logged_row_appears_in_recent_with_correct_fields() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();

    inv.log_sub_access(
        &UserId("alice".into()),
        "192.0.2.7",
        Some("Hiddify/Android/2.5.0"),
        200,
        1234,
    )
    .await
    .unwrap();

    let rows = inv
        .recent_sub_access(&UserId("alice".into()), 50)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.user_id, "alice");
    assert_eq!(row.ip, "192.0.2.7");
    assert_eq!(row.ua.as_deref(), Some("Hiddify/Android/2.5.0"));
    assert_eq!(row.status, 200);
    assert_eq!(row.bytes, 1234);
    let now = chrono::Utc::now();
    let age = (now - row.ts).num_seconds().abs();
    assert!(age < 5, "ts should be within 5s of now, got {age}s old");
}

#[tokio::test]
async fn distinct_ips_counts_unique_addresses_only() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("bob")).await.unwrap();

    for ip in ["192.0.2.1", "192.0.2.1", "198.51.100.5"] {
        inv.log_sub_access(&UserId("bob".into()), ip, None, 200, 100)
            .await
            .unwrap();
    }

    let n = inv
        .distinct_ips_for_user(&UserId("bob".into()), 24)
        .await
        .unwrap();
    assert_eq!(n, 2, "duplicate IPs must collapse to 1");
}

#[tokio::test]
async fn distinct_ips_per_user_does_not_leak_across_users() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    inv.add_user(&user("bob")).await.unwrap();

    inv.log_sub_access(&UserId("alice".into()), "1.1.1.1", None, 200, 100)
        .await
        .unwrap();
    inv.log_sub_access(&UserId("alice".into()), "1.1.1.2", None, 200, 100)
        .await
        .unwrap();
    inv.log_sub_access(&UserId("bob".into()), "9.9.9.9", None, 200, 100)
        .await
        .unwrap();

    let alice = inv
        .distinct_ips_for_user(&UserId("alice".into()), 24)
        .await
        .unwrap();
    let bob = inv
        .distinct_ips_for_user(&UserId("bob".into()), 24)
        .await
        .unwrap();
    assert_eq!(alice, 2, "alice has 2 distinct IPs");
    assert_eq!(bob, 1, "bob has 1 distinct IP — NOT alice's 2");
}

#[tokio::test]
async fn recent_returns_newest_first_and_respects_limit() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();

    for i in 0..5 {
        inv.log_sub_access(
            &UserId("alice".into()),
            &format!("10.0.0.{i}"),
            None,
            200,
            100,
        )
        .await
        .unwrap();
    }

    let limited = inv
        .recent_sub_access(&UserId("alice".into()), 3)
        .await
        .unwrap();
    assert_eq!(limited.len(), 3, "limit must cap rows returned");
    assert_eq!(limited[0].ip, "10.0.0.4");
    assert_eq!(limited[1].ip, "10.0.0.3");
    assert_eq!(limited[2].ip, "10.0.0.2");
}

#[tokio::test]
async fn log_against_unknown_user_fails_via_fk() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    let res = inv
        .log_sub_access(&UserId("ghost".into()), "1.2.3.4", None, 200, 0)
        .await;
    assert!(
        res.is_err(),
        "logging against a non-existent user must error (FK enforcement) — \
         otherwise we silently log orphan rows"
    );
}

#[tokio::test]
async fn purge_removes_rows_older_than_cutoff_only() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();

    inv.log_sub_access(&UserId("alice".into()), "10.0.0.1", None, 200, 100)
        .await
        .unwrap();

    let removed = inv.purge_sub_access_older_than(1).await.unwrap();
    assert_eq!(removed, 0, "fresh row must NOT be removed by 1-day purge");
    let after = inv
        .recent_sub_access(&UserId("alice".into()), 50)
        .await
        .unwrap();
    assert_eq!(after.len(), 1, "fresh row must still be there");
}

#[tokio::test]
async fn distinct_ips_window_filter_includes_fresh_excludes_old() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();

    inv.log_sub_access(&UserId("alice".into()), "1.1.1.1", None, 200, 100)
        .await
        .unwrap();

    let hour = inv
        .distinct_ips_for_user(&UserId("alice".into()), 1)
        .await
        .unwrap();
    assert_eq!(hour, 1, "fresh row must be inside the 1-hour window");

    let day = inv
        .distinct_ips_for_user(&UserId("alice".into()), 24)
        .await
        .unwrap();
    assert_eq!(day, 1, "fresh row must be inside the 24-hour window");

    let raw = sqlx::SqlitePool::connect(&format!("sqlite://{}", db_path(&dir).display()))
        .await
        .unwrap();
    sqlx::query("PRAGMA foreign_keys = ON")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO sub_access_log (ts, user_id, ip, status, bytes)
         VALUES (strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-25 hours'),
                 'alice', '2.2.2.2', 200, 100)",
    )
    .execute(&raw)
    .await
    .unwrap();
    raw.close().await;

    let day_after_old = inv
        .distinct_ips_for_user(&UserId("alice".into()), 24)
        .await
        .unwrap();
    assert_eq!(
        day_after_old, 1,
        "row 25h old must be EXCLUDED by 24h window"
    );

    let two_days = inv
        .distinct_ips_for_user(&UserId("alice".into()), 48)
        .await
        .unwrap();
    assert_eq!(
        two_days, 2,
        "row 25h old must be INCLUDED by 48h window (both IPs visible)"
    );
}

#[tokio::test]
async fn distinct_ips_window_filter_handles_same_day_rows_correctly() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();

    let raw = sqlx::SqlitePool::connect(&format!("sqlite://{}", db_path(&dir).display()))
        .await
        .unwrap();
    sqlx::query("PRAGMA foreign_keys = ON")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO sub_access_log (ts, user_id, ip, status, bytes)
         VALUES (strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-30 minutes'),
                 'alice', '3.3.3.3', 200, 100)",
    )
    .execute(&raw)
    .await
    .unwrap();
    raw.close().await;

    let n = inv
        .distinct_ips_for_user(&UserId("alice".into()), 0)
        .await
        .unwrap();
    assert_eq!(
        n, 0,
        "row 30 min old must be EXCLUDED by 0-hour window — \
         was the timestamp-format bug from retroactive review-agent."
    );
}

#[tokio::test]
async fn deleting_user_keeps_their_access_rows_with_null_user_id() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    inv.log_sub_access(&UserId("alice".into()), "9.9.9.9", None, 200, 100)
        .await
        .unwrap();

    let raw = sqlx::SqlitePool::connect(&format!("sqlite://{}", db_path(&dir).display()))
        .await
        .unwrap();
    sqlx::query("PRAGMA foreign_keys = ON")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id = 'alice'")
        .execute(&raw)
        .await
        .unwrap();

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sub_access_log WHERE ip = '9.9.9.9' AND user_id IS NULL",
    )
    .fetch_one(&raw)
    .await
    .unwrap();
    assert_eq!(
        count, 1,
        "row must SURVIVE user delete with user_id NULLed (was the \
         CASCADE→SET NULL fix in migration 0004)"
    );

    let n = inv
        .distinct_ips_for_user(&UserId("alice".into()), 24)
        .await
        .unwrap();
    assert_eq!(
        n, 0,
        "deleted user's orphaned rows must not show up in \
         distinct_ips_for_user — it filters by `user_id = ?1`"
    );
    raw.close().await;
}

#[tokio::test]
async fn log_sub_access_rich_round_trips_all_track_1_2_columns() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();

    inv.log_sub_access_rich(
        &UserId("alice".into()),
        "8.8.8.8",
        Some("Hiddify/Android/2.5.0"),
        200,
        4096,
        Some("ru-RU,ru;q=0.9,en;q=0.8"),
        Some("HTTP/2.0"),
        Some("Hiddify"),
        Some("US"),
        Some("AS15169 GOOGLE"),
        None,
        None,
    )
    .await
    .unwrap();

    let rows = inv
        .recent_sub_access(&UserId("alice".into()), 5)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1, "exactly one row");
    let r = &rows[0];
    assert_eq!(
        r.accept_language.as_deref(),
        Some("ru-RU,ru;q=0.9,en;q=0.8")
    );
    assert_eq!(r.http_version.as_deref(), Some("HTTP/2.0"));
    assert_eq!(r.device_class.as_deref(), Some("Hiddify"));
    assert_eq!(r.geo_country.as_deref(), Some("US"));
    assert_eq!(r.geo_asn.as_deref(), Some("AS15169 GOOGLE"));
    assert!(r.tls_ja3.is_none());
    assert!(r.tls_ja4.is_none());
}

#[tokio::test]
async fn log_sub_access_rich_round_trips_tls_fingerprint_columns() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();

    inv.log_sub_access_rich(
        &UserId("alice".into()),
        "203.0.113.7",
        Some("Hiddify/iOS/2.5.0"),
        200,
        4096,
        None,
        None,
        None,
        None,
        None,
        Some("769,49195-49199,0-23-65281,29-23-24,0"),
        Some("t13d1516h2_8daaf6152771_b186095e22b6"),
    )
    .await
    .unwrap();

    let r = &inv
        .recent_sub_access(&UserId("alice".into()), 5)
        .await
        .unwrap()[0];
    assert_eq!(
        r.tls_ja3.as_deref(),
        Some("769,49195-49199,0-23-65281,29-23-24,0")
    );
    assert_eq!(
        r.tls_ja4.as_deref(),
        Some("t13d1516h2_8daaf6152771_b186095e22b6")
    );
}

#[tokio::test]
async fn recent_sub_access_renders_null_for_pre_migration_rows() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();

    inv.log_sub_access(&UserId("alice".into()), "1.2.3.4", None, 200, 0)
        .await
        .unwrap();

    let rows = inv
        .recent_sub_access(&UserId("alice".into()), 5)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].accept_language.is_none());
    assert!(rows[0].http_version.is_none());
    assert!(rows[0].device_class.is_none());
    assert!(rows[0].geo_country.is_none());
    assert!(rows[0].geo_asn.is_none());
}

async fn add_test_server(inv: &SqliteInventory, id: &str, address: &str) {
    use vpnctl_core::{KernelId, Server, ServerId};
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

#[tokio::test]
async fn phase4a_trigger_marks_inserted_row_as_egress_when_ip_matches_server() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    add_test_server(&inv, "de", "10.20.30.40").await;

    inv.log_sub_access(&UserId("alice".into()), "10.20.30.40", None, 200, 0)
        .await
        .unwrap();
    inv.log_sub_access(&UserId("alice".into()), "8.8.8.8", None, 200, 0)
        .await
        .unwrap();

    let rows = inv
        .recent_sub_access(&UserId("alice".into()), 5)
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    let egress: Vec<bool> = rows.iter().map(|r| r.is_vpn_egress).collect();
    assert_eq!(
        egress,
        vec![false, true],
        "trigger must mark the VPN-egress row"
    );
}

#[tokio::test]
async fn phase4a_recent_sub_access_filtered_with_include_egress_false_hides_egress_rows() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    add_test_server(&inv, "de", "10.20.30.40").await;

    inv.log_sub_access(&UserId("alice".into()), "10.20.30.40", None, 200, 0)
        .await
        .unwrap();
    inv.log_sub_access(&UserId("alice".into()), "8.8.8.8", None, 200, 0)
        .await
        .unwrap();

    let real_only = inv
        .recent_sub_access_filtered(&UserId("alice".into()), 50, false)
        .await
        .unwrap();
    assert_eq!(
        real_only.len(),
        1,
        "include_egress=false must return only the real-client row"
    );
    assert_eq!(real_only[0].ip, "8.8.8.8");
    assert!(!real_only[0].is_vpn_egress);

    let all = inv
        .recent_sub_access_filtered(&UserId("alice".into()), 50, true)
        .await
        .unwrap();
    assert_eq!(all.len(), 2, "include_egress=true must return everything");
}

#[tokio::test]
async fn phase4a_sub_access_aggregates_distinguishes_real_vs_egress_and_distinct_dims() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    add_test_server(&inv, "de", "10.20.30.40").await;

    inv.log_sub_access_rich(
        &UserId("alice".into()),
        "8.8.8.8",
        None,
        200,
        100,
        None,
        None,
        None,
        Some("US"),
        Some("AS15169 Google"),
        None,
        None,
    )
    .await
    .unwrap();
    inv.log_sub_access_rich(
        &UserId("alice".into()),
        "8.8.8.8",
        None,
        200,
        100,
        None,
        None,
        None,
        Some("US"),
        Some("AS15169 Google"),
        None,
        None,
    )
    .await
    .unwrap();
    inv.log_sub_access_rich(
        &UserId("alice".into()),
        "5.5.5.5",
        None,
        200,
        50,
        None,
        None,
        None,
        Some("FI"),
        Some("AS1234 Telia"),
        None,
        None,
    )
    .await
    .unwrap();
    inv.log_sub_access_rich(
        &UserId("alice".into()),
        "10.20.30.40",
        None,
        200,
        9999,
        None,
        None,
        None,
        Some("DE"),
        Some("AS14956 Cloudzy"),
        None,
        None,
    )
    .await
    .unwrap();

    let agg = inv
        .sub_access_aggregates_for_user(&UserId("alice".into()), 30)
        .await
        .unwrap();
    assert_eq!(agg.total_rows, 3, "egress row excluded from total_rows");
    assert_eq!(agg.egress_rows, 1, "egress count must be exact");
    assert_eq!(agg.distinct_ips, 2, "8.8.8.8 (×2) + 5.5.5.5 = 2 distinct");
    assert_eq!(agg.distinct_countries, 2, "US + FI; DE was egress");
    assert_eq!(agg.distinct_asns, 2);
    assert_eq!(agg.total_bytes, 250, "100+100+50; egress 9999 excluded");
    assert!(agg.last_seen.is_some());
    assert!(agg.first_seen.is_some());
}

#[tokio::test]
async fn tt3_aggregates_distinct_ips_excludes_proxy_masked_but_keeps_row_and_recency() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("brat")).await.unwrap();

    for ip in ["8.8.8.8", "1.1.1.1"] {
        inv.log_sub_access(&UserId("brat".into()), ip, None, 200, 100)
            .await
            .unwrap();
    }
    for ip in ["192.168.0.210", "10.0.0.5"] {
        inv.log_sub_access(&UserId("brat".into()), ip, None, 200, 100)
            .await
            .unwrap();
    }

    let agg = inv
        .sub_access_aggregates_for_user(&UserId("brat".into()), 30)
        .await
        .unwrap();
    assert_eq!(agg.total_rows, 4, "all 4 non-egress pulls count as fetches");
    assert_eq!(
        agg.distinct_ips, 2,
        "only the two public clients are distinct; .210 + 10.x are proxy-masked"
    );
    assert!(agg.last_seen.is_some());
}

#[tokio::test]
async fn tt3_distinct_country_asn_gated_on_real_client_like_distinct_ips() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("brat")).await.unwrap();

    inv.log_sub_access_rich(
        &UserId("brat".into()),
        "8.8.8.8",
        None,
        200,
        100,
        None,
        None,
        None,
        Some("US"),
        Some("AS15169 Google"),
        None,
        None,
    )
    .await
    .unwrap();
    inv.log_sub_access_rich(
        &UserId("brat".into()),
        "83.97.108.34",
        None,
        200,
        100,
        None,
        None,
        None,
        Some("NL"),
        Some("AS0000 Homelab"),
        None,
        None,
    )
    .await
    .unwrap();

    let agg = inv
        .sub_access_aggregates_for_user(&UserId("brat".into()), 30)
        .await
        .unwrap();
    assert_eq!(agg.distinct_ips, 1, "only 8.8.8.8; control egress excluded");
    assert_eq!(
        agg.distinct_countries, 1,
        "US only — the control egress's NL must NOT inflate the sub-label"
    );
    assert_eq!(
        agg.distinct_asns, 1,
        "AS15169 only — the control egress's ASN must NOT inflate the sub-label"
    );
}

#[tokio::test]
async fn phase4a_sub_access_aggregates_for_empty_user_returns_zeroes_and_none_timestamps() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();

    let agg = inv
        .sub_access_aggregates_for_user(&UserId("alice".into()), 30)
        .await
        .unwrap();
    assert_eq!(agg.total_rows, 0);
    assert_eq!(agg.egress_rows, 0);
    assert_eq!(agg.distinct_ips, 0);
    assert!(agg.last_seen.is_none());
    assert!(agg.first_seen.is_none());
}

#[tokio::test]
async fn phase4a_backfill_marks_pre_migration_rows_when_server_address_already_known() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    add_test_server(&inv, "de", "10.20.30.40").await;

    inv.log_sub_access(&UserId("alice".into()), "10.20.30.40", None, 200, 0)
        .await
        .unwrap();
    inv.log_sub_access(&UserId("alice".into()), "1.1.1.1", None, 200, 0)
        .await
        .unwrap();

    let rows = inv
        .recent_sub_access(&UserId("alice".into()), 50)
        .await
        .unwrap();
    let flagged: Vec<&str> = rows
        .iter()
        .filter(|r| r.is_vpn_egress)
        .map(|r| r.ip.as_str())
        .collect();
    assert_eq!(
        flagged,
        vec!["10.20.30.40"],
        "exactly the server IP is flagged"
    );
}

#[tokio::test]
async fn phase4a_add_server_retroactively_flags_existing_rows_for_new_address() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();

    inv.log_sub_access(&UserId("alice".into()), "10.20.30.40", None, 200, 0)
        .await
        .unwrap();
    inv.log_sub_access(&UserId("alice".into()), "8.8.8.8", None, 200, 0)
        .await
        .unwrap();
    let before = inv
        .recent_sub_access(&UserId("alice".into()), 10)
        .await
        .unwrap();
    assert!(
        before.iter().all(|r| !r.is_vpn_egress),
        "no rows should be flagged before the server is registered"
    );

    add_test_server(&inv, "de", "10.20.30.40").await;

    let after = inv
        .recent_sub_access(&UserId("alice".into()), 10)
        .await
        .unwrap();
    let flagged: Vec<&str> = after
        .iter()
        .filter(|r| r.is_vpn_egress)
        .map(|r| r.ip.as_str())
        .collect();
    assert_eq!(
        flagged,
        vec!["10.20.30.40"],
        "after add_server, exactly the matching historical row must be flagged"
    );
}

#[tokio::test]
async fn phase4c_users_for_source_ips_groups_by_ip_with_top_user_first() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    inv.add_user(&user("bob")).await.unwrap();

    for _ in 0..3 {
        inv.log_sub_access(&UserId("alice".into()), "8.8.8.8", None, 200, 100)
            .await
            .unwrap();
    }
    inv.log_sub_access(&UserId("bob".into()), "8.8.8.8", None, 200, 100)
        .await
        .unwrap();
    inv.log_sub_access(&UserId("alice".into()), "1.1.1.1", None, 200, 100)
        .await
        .unwrap();

    let result = inv
        .users_for_source_ips(&["8.8.8.8".to_string()], 7)
        .await
        .unwrap();

    let users = result.get("8.8.8.8").expect("8.8.8.8 must have entries");
    assert_eq!(users.len(), 2);
    assert_eq!(users[0].0.0, "alice");
    assert_eq!(users[0].1, 3);
    assert_eq!(users[1].0.0, "bob");
    assert_eq!(users[1].1, 1);
    assert!(!result.contains_key("1.1.1.1"));
}

#[tokio::test]
async fn phase4c_users_for_source_ips_empty_ips_returns_empty_map() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let result = inv.users_for_source_ips(&[], 7).await.unwrap();
    assert!(result.is_empty());
}

#[tokio::test]
async fn phase4c_users_for_source_ips_excludes_vpn_egress_rows() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();
    add_test_server(&inv, "de", "10.20.30.40").await;

    inv.log_sub_access(&UserId("alice".into()), "10.20.30.40", None, 200, 100)
        .await
        .unwrap();

    let result = inv
        .users_for_source_ips(&["10.20.30.40".to_string()], 7)
        .await
        .unwrap();
    let users = result.get("10.20.30.40").cloned().unwrap_or_default();
    assert!(
        users.is_empty(),
        "egress-flagged rows must NOT contribute to source-IP correlation"
    );
}

#[tokio::test]
async fn proxy_masked_stats_counts_reserved_ip_rows() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("brat")).await.unwrap();
    for ip in ["8.8.8.8", "1.1.1.1", "9.9.9.9"] {
        inv.log_sub_access(&UserId("brat".into()), ip, None, 200, 100)
            .await
            .unwrap();
    }
    for ip in ["192.168.0.210", "192.168.0.210", "10.0.0.5"] {
        inv.log_sub_access(&UserId("brat".into()), ip, None, 200, 100)
            .await
            .unwrap();
    }

    let s = inv
        .sub_access_proxy_masked_stats(&UserId("brat".into()), 30)
        .await
        .unwrap();
    assert_eq!(s.window_rows, 6, "all 6 non-egress rows are in the window");
    assert_eq!(s.masked_rows, 3, "the two .210 + one 10.x are proxy-masked");
    assert!(s.masked_min_ts.is_some() && s.masked_max_ts.is_some());

    inv.add_user(&user("clean")).await.unwrap();
    inv.log_sub_access(&UserId("clean".into()), "203.0.113.7", None, 200, 100)
        .await
        .unwrap();
    let clean = inv
        .sub_access_proxy_masked_stats(&UserId("clean".into()), 30)
        .await
        .unwrap();
    assert_eq!(clean.window_rows, 1);
    assert_eq!(clean.masked_rows, 0, "a public IP is never masked");
}
