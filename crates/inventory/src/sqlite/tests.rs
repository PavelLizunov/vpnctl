#![allow(clippy::unwrap_used, clippy::expect_used)]

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
        sub_token: None, // inventory will generate one
        vpn_router_device_id: None,
        disabled: false,
    }
}

#[test]
fn network_key_ipv4_collapses_to_16() {
    // Adjacent /24 carrier pools collapse into one ISP-scale /16.
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
    // The 2026-07-29 fix: rotating IPv6 privacy addresses share their
    // top 64 bits, so they MUST collapse to one key (the old verbatim
    // behaviour made one phone look like many distinct networks).
    let a = network_key("2001:db8:abcd:0012::1");
    let b = network_key("2001:db8:abcd:0012:7334:1111:2222:3333");
    let c = network_key("2001:db8:abcd:0012:9f00:aaaa:bbbb:cccc");
    assert_eq!(a, b, "two privacy addrs in one /64 must share a key");
    assert_eq!(b, c, "a third privacy addr in the same /64 too");
    // A different /64 stays distinct.
    assert_ne!(network_key("2001:db8:abcd:0013::1"), a);
}

#[test]
fn network_key_malformed_input_stays_safe() {
    // Garbage neither panics nor merges with a real prefix — it stays
    // its own single verbatim bucket.
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
    // If we can list servers without error, migration ran.
    assert!(inv.list_servers().await?.is_empty());
    Ok(())
}

// sub_fetch_without_traffic_users — the «subscription updated but no
// traffic followed» detector query (2026-06-16). Raw inserts with
// explicit `ts` offsets because the public record helpers stamp `now`.
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

    // A real (non-egress) `/sub` fetch `mins_ago` in the past. IP differs
    // from the server address (1.2.3.4) so the is_vpn_egress trigger
    // leaves the row at 0.
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
    // Attributed traffic at an explicit strftime offset ("-2 days",
    // "-5 minutes", "+0 minutes").
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

    // oleg — FIRES: active 2d ago, fetched 60m ago, silent since.
    fetch(&inv, "oleg", "198.51.100.7", 60).await;
    traffic(&inv, "oleg", "-2 days").await;
    // newbie — NO fire: fetched but never had any traffic (setup problem,
    // not a regression).
    fetch(&inv, "newbie", "198.51.100.7", 60).await;
    // healthy — NO fire: active before AND traffic 5m ago (after fetch).
    fetch(&inv, "healthy", "198.51.100.7", 60).await;
    traffic(&inv, "healthy", "-2 days").await;
    traffic(&inv, "healthy", "-5 minutes").await;
    // justfetched — NO fire: fetched only 10m ago, still inside the grace.
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

    // Resolve: oleg now passes traffic AFTER the fetch → drops out.
    traffic(&inv, "oleg", "+0 minutes").await;
    let after = inv.sub_fetch_without_traffic_users(45, 360, 7).await?;
    assert!(
        after.is_empty(),
        "oleg clears once traffic resumes: {after:?}"
    );
    Ok(())
}

// open_alert_subjects_with_kind_prefix — backs the per-user auto-resolve
// sweep. Must return only UNACKED subjects of the EXACT prefix.
#[tokio::test]
async fn open_alert_subjects_filters_by_prefix_and_unacked() -> Result<()> {
    let inv = fresh().await;
    inv.insert_alert_if_no_unacked("user.sub_no_traffic:oleg", None, "warning", "s", None)
        .await?;
    inv.insert_alert_if_no_unacked("user.sub_no_traffic:masha", None, "warning", "s", None)
        .await?;
    // different prefix — must be ignored even though it's open.
    inv.insert_alert_if_no_unacked("user.traffic_limit:bob", None, "warning", "s", None)
        .await?;
    // ack masha → must drop from the open set.
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

// top_source_ips_for_user must hide every flavour of OUR infra
// (2026-06-16): VPN server addresses (node-hop transient source), the
// control egress, AND RFC1918 / loopback / link-local (homelab LAN).
// A real 172.32+ client (just outside the private /12) must survive —
// guards the GLOB char-range boundaries.
#[tokio::test]
async fn top_source_ips_excludes_all_infra_ip_classes() -> Result<()> {
    let inv = fresh().await;
    inv.add_server(&sample_server("s1")).await?; // address 1.2.3.4
    let mut v6_server = sample_server("s2");
    v6_server.address = "2001:0db8:0:0::1".into();
    inv.add_server(&v6_server).await?;
    inv.add_user(&sample_user("u")).await?;
    inv.record_user_source_ips(&[
        (UserId("u".into()), "203.0.113.9".into()), // real client — KEEP
        (UserId("u".into()), "172.32.5.5".into()),  // public (>172.31) — KEEP
        (UserId("u".into()), "1.2.3.4".into()),     // == server s1 address
        (UserId("u".into()), "83.97.108.34".into()), // control egress const
        (UserId("u".into()), "192.168.0.200".into()), // LAN (claude-chat host)
        (UserId("u".into()), "10.5.5.5".into()),    // RFC1918 10/8
        (UserId("u".into()), "172.20.5.5".into()),  // RFC1918 172.16-31
        (UserId("u".into()), "127.0.0.1".into()),   // loopback
        (UserId("u".into()), "169.254.9.9".into()), // link-local
        (UserId("u".into()), "::1".into()),         // IPv6 loopback
        (UserId("u".into()), "fe80::1".into()),     // IPv6 link-local
        (UserId("u".into()), "fd12:3456::1".into()), // IPv6 ULA
        (UserId("u".into()), "2001:0db8:0:0::1".into()), // equivalent s2 address
        (UserId("u".into()), "2001:db8::99".into()), // public IPv6 — KEEP
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

// IP-concurrency: per-day peak is the MAX across snapshots; unknown
// users are FK-guard-skipped silently.
#[tokio::test]
async fn ip_concurrency_records_daily_peak_max() -> Result<()> {
    let inv = fresh().await;
    inv.add_user(&sample_user("u")).await?;
    // snapshots this day: 1, then 3, then 2 distinct IPs → peak 3.
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
    // since-deleted / unknown user → silently skipped, peak stays 0.
    inv.record_user_ip_concurrency(&[(UserId("ghost".into()), 9)])
        .await?;
    assert_eq!(
        inv.ip_concurrency_peak_for_user(&UserId("ghost".into()), 30)
            .await?,
        0
    );
    Ok(())
}

// sharing_signals_all_users gathers the two NEW signals — peak
// concurrency (simultaneity) + country-level impossible travel — plus
// the sub_access diversity, all keyed by user.
#[tokio::test]
async fn sharing_signals_gathers_concurrency_and_impossible_travel() -> Result<()> {
    let inv = fresh().await;
    inv.add_user(&sample_user("sharer")).await?;
    inv.add_user(&sample_user("solo")).await?;

    // Two `/sub` fetches for `sharer` from DIFFERENT countries 15 min
    // apart (public IPs, non-egress) → exactly one impossible-travel hop.
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
    // solo — single country, single fetch (no impossible travel).
    fetch(&inv, "solo", "203.0.113.30", "RU", "AS3", 100).await;

    // Concurrency: sharer hit 3 simultaneous IPs once; solo only ever 1.
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

    // demonnot-3 shape: mostly 1–2 simultaneous networks with one old
    // four-network carrier hand-over. Absolute MAX returned 4 (65 pts)
    // for a month; P75 correctly returns the normal value 2 (25 pts).
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

// 0032: the fleet-dashboard ts index must exist after migrations so
// `recent_vpn_stats_fleet` can range-scan the window instead of
// full-scanning + temp-sorting the whole table.
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

// 0033 (PR-Q): the additive nullable kernel-version column must
// exist on node_health AND the per-server audit expression index
// must exist, so `audit_for_server` gets a MULTI-INDEX OR plan
// instead of a full SCAN of the unbounded audit_log.
#[tokio::test]
async fn migration_0033_adds_column_and_audit_index() -> Result<()> {
    let inv = fresh().await;
    // New nullable column present (PRAGMA table_info lists it).
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
    // New expression index present.
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

// 0051: node_health must have stable identity and monotonic sequence columns.
#[tokio::test]
async fn migration_0051_adds_stable_identity_constraints() -> Result<()> {
    let inv = fresh().await;
    let cols: Vec<(String, i64, i64)> = sqlx::query_as(
        "SELECT name, notnull, pk FROM pragma_table_info('node_health') \
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

// open() must set synchronous=NORMAL (1). FULL (2) is the SQLite
// default and was stalling unrelated writers under WAL checkpoint
// pressure; NORMAL is WAL-safe. A connection drawn from the pool must
// observe the pragma applied at connect time.
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
    // 43-char unpadded SHA-256 base64 (russh's natural format).
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
        .await?; // upsert
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
    // (B) disable = real revoke: a disabled user must drop out of the
    // node-config slice (grant kept) so a redeploy removes them from
    // sing-box; re-enable puts them back.
    let inv = fresh().await;
    inv.add_server(&sample_server("srv")).await?;
    inv.add_user(&sample_user("alice")).await?;
    inv.add_user(&sample_user("bob")).await?;
    inv.grant(&UserId("alice".into()), &ServerId("srv".into()))
        .await?;
    inv.grant(&UserId("bob".into()), &ServerId("srv".into()))
        .await?;
    assert_eq!(
        inv.users_for_server(&ServerId("srv".into())).await?.len(),
        2
    );

    assert!(inv.set_user_disabled(&UserId("alice".into()), true).await?);
    let users = inv.users_for_server(&ServerId("srv".into())).await?;
    assert_eq!(
        users.len(),
        1,
        "disabled user must be excluded from the node config slice"
    );
    assert_eq!(users[0].id.0, "bob");

    assert!(
        inv.set_user_disabled(&UserId("alice".into()), false)
            .await?
    );
    assert_eq!(
        inv.users_for_server(&ServerId("srv".into())).await?.len(),
        2,
        "re-enabled user must return to the node config slice"
    );
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
async fn list_all_server_protocols_with_hidden_returns_full_matrix() -> Result<()> {
    // Pavel 2026-05-20 follow-up: the /admin/servers list page
    // needs the (server, protocol) → hidden matrix in ONE round
    // trip. Per-server bulk helper would N+1 over the inventory.
    // This test exercises the multi-server happy path: 2 servers,
    // 3 protocols each, 2 of them hidden across the matrix.
    let inv = fresh().await;

    // Server A: vless+reality + tuic-v5 (sample_server defaults)
    // → hide tuic-v5.
    inv.add_server(&sample_server("alpha")).await?;
    inv.set_server_protocol_hidden(
        &ServerId("alpha".into()),
        &ProtocolId("tuic-v5".into()),
        true,
    )
    .await?;

    // Server B: vless+reality + tuic-v5, both visible. Plus we
    // add anytls then hide it — exercises the
    // add_server_protocol + set_server_protocol_hidden path.
    inv.add_server(&sample_server("beta")).await?;
    inv.add_server_protocol(&ServerId("beta".into()), &ProtocolId("anytls".into()))
        .await?;
    inv.set_server_protocol_hidden(&ServerId("beta".into()), &ProtocolId("anytls".into()), true)
        .await?;

    let matrix = inv.list_all_server_protocols_with_hidden().await?;

    // Total entries: alpha (2) + beta (3) = 5.
    assert_eq!(
        matrix.len(),
        5,
        "matrix should hold 5 entries (2 alpha + 3 beta), got {}",
        matrix.len()
    );
    // Spot-check the 4 distinctive cells.
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
    // Defensive: no servers, no protocols → empty map. The
    // /admin/servers caller relies on this for the "no servers
    // yet" empty-state to render without panicking.
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
    // recent_audit orders by id DESC, so user.add comes first.
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

// ── Phase 5b destination-writer robustness ──────────────────────────

#[tokio::test]
async fn record_user_destinations_truncates_multibyte_label_without_panic() -> Result<()> {
    // A destination label whose byte-200 lands mid-codepoint must
    // NOT panic the writer (the old `&dest[..200]` slice did — and
    // that panic propagates uncaught through `clash_poller`,
    // permanently aborting the whole poll task). Build a label
    // where byte 200 is inside a 4-byte emoji: leading ASCII 'a'
    // (1 byte) + repeated 😀 (4 bytes each) → boundaries at 1+4k,
    // and 200 ≡ 3 (mod 4) from offset 1 → NOT a char boundary.
    let inv = fresh().await;
    inv.add_user(&sample_user("alice")).await?;

    let mut dest = String::from("a");
    dest.push_str(&"😀".repeat(60)); // 1 + 240 = 241 bytes, 61 chars
    assert!(dest.len() > 200, "label must exceed 200 bytes");
    assert!(
        !dest.is_char_boundary(200),
        "byte 200 must land mid-codepoint to exercise the panic path",
    );

    // Must not panic.
    inv.record_user_destinations(&[(UserId("alice".into()), dest.clone())])
        .await?;

    let rows = inv
        .top_destinations_for_user(&UserId("alice".into()), 1, 10)
        .await?;
    assert_eq!(rows.len(), 1, "the valid pair must have landed");
    let stored = &rows[0].destination_label;
    // Stored truncated on a CHAR boundary (so it round-trips as
    // valid UTF-8) and capped at ≤ 200 chars.
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
    // The user_id comes from the log-scrape attribution map (a raw
    // username), NOT validated against `users`. A pair for a
    // since-deleted user would raise an FK error and (under `?`)
    // roll back the WHOLE tx, losing every user's destinations for
    // the tick. The writer's `WHERE EXISTS (… users …)` pre-filter
    // must skip ONLY the offending row; the valid pairs in the same
    // batch must still land.
    let inv = fresh().await;
    inv.add_user(&sample_user("alice")).await?;
    inv.add_user(&sample_user("bob")).await?;

    let pairs = vec![
        (UserId("alice".into()), "youtube.com:443".to_string()),
        // "ghost" was never added → FK violation on insert.
        (UserId("ghost".into()), "discord.com:443".to_string()),
        (UserId("bob".into()), "telegram.org:443".to_string()),
    ];

    // No error must bubble — the batch is not rolled back.
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

// ── set_grant_client_uuid no-op audit suppression ───────────────────

#[tokio::test]
async fn set_grant_client_uuid_same_value_writes_no_audit_row() -> Result<()> {
    // SQLite's rows_affected() counts matched-not-changed rows, so a
    // plain `UPDATE … WHERE user=? AND server=?` re-writing the SAME
    // uuid still passes the `>0` guard and emits a no-op
    // `grant.set_client_uuid` audit row (old == new). The
    // `AND client_uuid IS NOT ?` no-op gate must make a same-value
    // write affect 0 rows and skip the audit, mirroring
    // set_user_disabled / set_server_protocol_hidden.
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

    // Re-write the SAME value → no-op, no new audit row.
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

    // A genuine change still audits (regression guard).
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

    // Setting client_uuid on a (user, server) with no grant must
    // still error (the no-op gate must not mask the missing grant).
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

// ── effective-uuid uniqueness guard (HANDOFF §4.1) ───────────────────

#[tokio::test]
async fn grant_rejects_effective_uuid_collision() -> Result<()> {
    // Reconstruct the main-brat@de pathology: user `bbb`'s per-server
    // client_uuid override equals user `aaa`'s GLOBAL uuid. Granting
    // `aaa` to the same server must be rejected (aaa's effective uuid
    // would equal bbb's override).
    let inv = fresh().await;
    inv.add_server(&sample_server("de")).await?;
    let shared = "b25684c3-90d6-454a-a911-4e0abba568b0";
    let mut aaa = sample_user("aaa");
    aaa.uuid = shared.into();
    inv.add_user(&aaa).await?;
    inv.add_user(&sample_user("bbb")).await?; // global uuid "uuid-bbb"

    // bbb granted on de, then bbb's de override set to aaa's global uuid
    // (allowed: aaa has no grant on de yet, so nothing collides at this
    // point — this sets up the precondition).
    inv.grant(&UserId("bbb".into()), &ServerId("de".into()))
        .await?;
    inv.set_grant_client_uuid(&UserId("bbb".into()), &ServerId("de".into()), shared)
        .await?;

    // Granting aaa (global uuid == shared) on de must now be rejected.
    let err = inv
        .grant(&UserId("aaa".into()), &ServerId("de".into()))
        .await;
    assert!(
        matches!(err, Err(SqliteInventoryError::AlreadyExists(_))),
        "expected AlreadyExists collision, got {err:?}"
    );
    // …and the rejected grant must not have leaked a row.
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
    inv.add_user(&sample_user("alice")).await?; // uuid-alice
    inv.add_user(&sample_user("bob")).await?; // uuid-bob (distinct)
    inv.grant(&UserId("alice".into()), &ServerId("de".into()))
        .await?;
    inv.grant(&UserId("bob".into()), &ServerId("de".into()))
        .await?;
    // re-grant is a no-op, NOT an error
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
    // bob tries to take the same client_uuid → rejected
    let err = inv
        .set_grant_client_uuid(&UserId("bob".into()), &ServerId("de".into()), u)
        .await;
    assert!(
        matches!(err, Err(SqliteInventoryError::AlreadyExists(_))),
        "expected AlreadyExists, got {err:?}"
    );
    // bob's override didn't land — he still resolves to his global uuid
    assert_eq!(
        inv.client_uuid_for(&UserId("bob".into()), &ServerId("de".into()))
            .await?,
        Some("uuid-bob".into()),
    );
    // alice can still re-set her OWN value (self-excluded, idempotent)
    inv.set_grant_client_uuid(&UserId("alice".into()), &ServerId("de".into()), u)
        .await?;
    inv.assert_no_uuid_collisions(&ServerId("de".into()))
        .await?;
    Ok(())
}

#[tokio::test]
async fn assert_no_uuid_collisions_catches_manual_edit() -> Result<()> {
    // A manual sqlite3 edit / buggy import that bypasses the write-time
    // guards must still be caught by the fail-closed pre-deploy assertion.
    let inv = fresh().await;
    inv.add_server(&sample_server("de")).await?;
    inv.add_user(&sample_user("alice")).await?;
    inv.add_user(&sample_user("bob")).await?;
    inv.grant(&UserId("alice".into()), &ServerId("de".into()))
        .await?;
    inv.grant(&UserId("bob".into()), &ServerId("de".into()))
        .await?;
    inv.assert_no_uuid_collisions(&ServerId("de".into()))
        .await?; // clean

    // raw UPDATE: force bob's de override to alice's global uuid
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

    // disabling bob removes him from the rendered slice → assertion clean
    // again (a non-shipping latent duplicate must not block the deploy).
    sqlx::query("UPDATE users SET disabled = 1 WHERE id='bob'")
        .execute(&inv.pool)
        .await?;
    inv.assert_no_uuid_collisions(&ServerId("de".into()))
        .await?;
    Ok(())
}

#[tokio::test]
async fn grant_unknown_user_errors() -> Result<()> {
    // The new grant() looks the user up to compute its effective uuid; a
    // non-existent user must fail loudly (Invalid), not insert an orphan.
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

// ── session_observe FK gate ─────────────────────────────────────────

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
    // user_id comes from the log-scrape attribution map (a raw
    // username), NOT validated against `users`. With foreign_keys=ON
    // and vpn_user_sessions.user_id NOT NULL REFERENCES users(id), an
    // INSERT for a since-deleted user raises FK error 787. The
    // `WHERE EXISTS (… users …)` gate must skip it cleanly: no error
    // bubbles, no row inserted, and a valid user's session still
    // records.
    let inv = fresh().await;
    inv.add_server(&sample_server("srv")).await?;
    inv.add_user(&sample_user("alice")).await?;
    let now = chrono::Utc::now();

    // Unknown user → no FK error, nothing inserted (rowid 0 sentinel).
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

    // Valid user still records.
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

    // 1. Ordinary caller without _source_event
    let id1 = inv
        .insert_alert_if_no_unacked("ordinary.down", Some(&srv), "warning", "down 1", None)
        .await?
        .expect("first ordinary alert must insert");
    assert!(id1 > 0);

    // Duplicate unacked ordinary alert -> suppressed
    let dup = inv
        .insert_alert_if_no_unacked("ordinary.down", Some(&srv), "warning", "down 1 dup", None)
        .await?;
    assert_eq!(dup, None);

    // Ack ordinary alert
    assert!(inv.ack_alert(id1).await?);

    // After ack, ordinary alert refires legitimately
    let id2 = inv
        .insert_alert_if_no_unacked("ordinary.down", Some(&srv), "warning", "down 2", None)
        .await?
        .expect("ordinary alert must refire after ack");
    assert_ne!(id1, id2);

    // 2. Alert with _source_event
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

    // Duplicate unacked before ack -> suppressed
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

    // Ack the source-event alert
    assert!(inv.ack_alert(id3).await?);

    // Rescan / resubmit of SAME source event after ack -> still suppressed across all history
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

    // New source event -> reopens and inserts
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

    // 3. Numeric _source_event payload (uses ordinary unacked-only semantics)
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
    // Refires after ack because non-string _source_event does not dedupe historically
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

    // 4. Boolean _source_event payload (uses ordinary unacked-only semantics)
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
    // Refires after ack
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

    // 5. Global alert (server_id = None) with string _source_event historical dedupe
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
