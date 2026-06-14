//! Spec for the PR-Q informativeness query layer on `SqliteInventory`:
//! `top_users_by_traffic_for_server`, `user_traffic_by_server`,
//! `audit_for_server`, `user_lifecycle`, `kernel_versions_fleet`,
//! `alerts_by_kind_severity`, `today_digest`, `likely_shared_summary`.
//! Written from the spec only — impl NOT consulted beyond signatures.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use tempfile::TempDir;

use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
use vpnctl_inventory::{SqliteInventory, VpnStatsDelta};

fn db_path(dir: &TempDir) -> PathBuf {
    dir.path().join("inventory.db")
}

async fn open(dir: &TempDir) -> SqliteInventory {
    SqliteInventory::open(&db_path(dir)).await.expect("open")
}

fn server(id: &str) -> Server {
    Server {
        id: ServerId(id.to_string()),
        address: format!("{id}.example.com"),
        ssh_port: 22,
        ssh_user: "root".to_string(),
        kernels: vec![KernelId("sing-box".to_string())],
        enabled_protocols: vec![ProtocolId("vless+reality".to_string())],
        trusted_host_fingerprint: None,
        hoster: "generic".to_string(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

fn server_coeff(id: &str, usage_coefficient: f64) -> Server {
    Server {
        usage_coefficient,
        ..server(id)
    }
}

fn user(id: &str) -> User {
    User {
        id: UserId(id.to_string()),
        uuid: format!("uuid-{id}"),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    }
}

fn ud(uid: Option<&str>, up: u64, down: u64, conns: u32) -> VpnStatsDelta {
    VpnStatsDelta {
        user_id: uid.map(|s| UserId(s.to_string())),
        upload_bytes: up,
        download_bytes: down,
        active_connections: conns,
    }
}

// ── Q-4a top_users_by_traffic_for_server ─────────────────────────────

#[tokio::test]
async fn q4a_empty_returns_empty() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("s1")).await.unwrap();
    let got = inv
        .top_users_by_traffic_for_server(&ServerId("s1".into()), 24, 10)
        .await
        .unwrap();
    assert!(got.is_empty(), "no stats yet: {got:?}");
}

#[tokio::test]
async fn q4a_scoped_to_server_and_weighted_by_coefficient() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server_coeff("double", 2.0)).await.unwrap();
    inv.add_server(&server("single")).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();
    inv.add_user(&user("bob")).await.unwrap();

    // alice has traffic on BOTH servers; bob only on `single`. The
    // per-server query for `double` must see only alice's `double` row,
    // weighted ×2.
    inv.record_vpn_stats(
        &ServerId("double".into()),
        &[ud(Some("alice"), 100_000, 100_000, 1)],
    )
    .await
    .unwrap();
    inv.record_vpn_stats(
        &ServerId("single".into()),
        &[
            ud(Some("alice"), 500_000, 500_000, 1),
            ud(Some("bob"), 1_000_000, 0, 1),
        ],
    )
    .await
    .unwrap();
    // Server-wide rollup row (user_id NULL) must be EXCLUDED.
    inv.record_vpn_stats(&ServerId("double".into()), &[ud(None, 9, 9, 1)])
        .await
        .unwrap();

    let on_double = inv
        .top_users_by_traffic_for_server(&ServerId("double".into()), 24, 10)
        .await
        .unwrap();
    assert_eq!(on_double.len(), 1, "only alice has per-user rows on double");
    assert_eq!(on_double[0].0.0, "alice");
    assert_eq!(
        on_double[0].1, 400_000,
        "200_000 raw × 2.0 coefficient = 400_000"
    );

    // On `single`, bob (1M raw, ×1) outranks alice (1M raw, ×1) only by
    // tie — both 1M; assert both present and ranking is by total.
    let on_single = inv
        .top_users_by_traffic_for_server(&ServerId("single".into()), 24, 10)
        .await
        .unwrap();
    assert_eq!(on_single.len(), 2);
    let alice = on_single.iter().find(|(u, _)| u.0 == "alice").unwrap();
    let bob = on_single.iter().find(|(u, _)| u.0 == "bob").unwrap();
    assert_eq!(alice.1, 1_000_000, "alice on single: 1M raw ×1");
    assert_eq!(bob.1, 1_000_000, "bob on single: 1M raw ×1");
}

#[tokio::test]
async fn q4a_limit_is_respected() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("s1")).await.unwrap();
    for (i, uid) in ["u1", "u2", "u3"].iter().enumerate() {
        inv.add_user(&user(uid)).await.unwrap();
        inv.record_vpn_stats(
            &ServerId("s1".into()),
            &[ud(Some(uid), (i as u64 + 1) * 1000, 0, 1)],
        )
        .await
        .unwrap();
    }
    let top2 = inv
        .top_users_by_traffic_for_server(&ServerId("s1".into()), 24, 2)
        .await
        .unwrap();
    assert_eq!(top2.len(), 2, "limit caps at 2");
    assert_eq!(top2[0].0.0, "u3", "heaviest first");
    assert_eq!(top2[1].0.0, "u2");
}

// ── Q-4b user_traffic_by_server ──────────────────────────────────────

#[tokio::test]
async fn q4b_groups_per_server_with_up_down_and_weighting() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server_coeff("double", 2.0)).await.unwrap();
    inv.add_server(&server("single")).await.unwrap();
    inv.add_user(&user("alice")).await.unwrap();

    inv.record_vpn_stats(
        &ServerId("double".into()),
        &[ud(Some("alice"), 100, 200, 1)],
    )
    .await
    .unwrap();
    inv.record_vpn_stats(&ServerId("single".into()), &[ud(Some("alice"), 10, 20, 1)])
        .await
        .unwrap();

    let by_server = inv
        .user_traffic_by_server(&UserId("alice".into()), 24)
        .await
        .unwrap();
    assert_eq!(by_server.len(), 2, "two servers carried alice's traffic");
    let on_double = by_server.iter().find(|(s, _, _)| s.0 == "double").unwrap();
    let on_single = by_server.iter().find(|(s, _, _)| s.0 == "single").unwrap();
    assert_eq!(on_double.1, 200, "double up: 100 × 2.0");
    assert_eq!(on_double.2, 400, "double down: 200 × 2.0");
    assert_eq!(on_single.1, 10, "single up: ×1");
    assert_eq!(on_single.2, 20, "single down: ×1");
    // Ordered by total (up+down) desc → double first.
    assert_eq!(by_server[0].0.0, "double");
}

#[tokio::test]
async fn q4b_empty_for_user_with_no_traffic() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("ghost")).await.unwrap();
    let got = inv
        .user_traffic_by_server(&UserId("ghost".into()), 24)
        .await
        .unwrap();
    assert!(got.is_empty());
}

// ── Q-4c audit_for_server ────────────────────────────────────────────

#[tokio::test]
async fn q4c_matches_target_or_payload_server_id_newest_first() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    // Row 1: server is the audit target.
    inv.audit("admin", "server.create", Some("srv1"), None)
        .await
        .unwrap();
    // Row 2: server referenced only in the JSON payload (deploy row).
    inv.audit(
        "admin",
        "server.deploy",
        Some("deploy-job-77"),
        Some(&serde_json::json!({"server_id": "srv1", "kernel": "sing-box"})),
    )
    .await
    .unwrap();
    // Row 3: a DIFFERENT server — must NOT match.
    inv.audit("admin", "server.create", Some("srv2"), None)
        .await
        .unwrap();

    let rows = inv.audit_for_server("srv1", 50).await.unwrap();
    assert_eq!(rows.len(), 2, "target match + payload match, not srv2");
    // Newest-first by id: the deploy row (id 2) before the create (id 1).
    assert_eq!(rows[0].action, "server.deploy");
    assert_eq!(rows[1].action, "server.create");
    assert!(
        rows.iter()
            .all(|r| r.action != "server.create" || r.target.as_deref() == Some("srv1"))
    );
}

#[tokio::test]
async fn q4c_limit_and_empty() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    for _ in 0..5 {
        inv.audit("admin", "server.restart", Some("srv1"), None)
            .await
            .unwrap();
    }
    let limited = inv.audit_for_server("srv1", 3).await.unwrap();
    assert_eq!(limited.len(), 3, "limit caps results");
    let none = inv.audit_for_server("nope", 50).await.unwrap();
    assert!(none.is_empty());
}

// ── Q-4d user_lifecycle ──────────────────────────────────────────────

#[tokio::test]
async fn q4d_reports_created_at_last_fetch_and_age() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice")).await.unwrap();

    // No sub fetch yet → last_sub_fetch None, age_days 0 (just created).
    let lc0 = inv.user_lifecycle(&UserId("alice".into())).await.unwrap();
    assert!(lc0.last_sub_fetch.is_none(), "no /sub hit yet");
    assert_eq!(lc0.age_days, 0, "created just now → 0 whole days");

    // A real /sub fetch updates last_sub_fetch.
    inv.log_sub_access(&UserId("alice".into()), "1.2.3.4", None, 200, 100)
        .await
        .unwrap();
    let lc1 = inv.user_lifecycle(&UserId("alice".into())).await.unwrap();
    assert!(
        lc1.last_sub_fetch.is_some(),
        "last_sub_fetch set after a real fetch"
    );
}

#[tokio::test]
async fn q4d_unknown_user_errors() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let res = inv.user_lifecycle(&UserId("ghost".into())).await;
    assert!(res.is_err(), "no such user must Err, got {res:?}");
}

// ── Q-4e kernel_versions_fleet ───────────────────────────────────────

#[tokio::test]
async fn q4e_latest_json_per_server() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&server("s1")).await.unwrap();
    inv.add_server(&server("s2")).await.unwrap();
    inv.add_server(&server("s3")).await.unwrap();

    // s1: two rows — newest wins.
    inv.record_node_health(
        &ServerId("s1".into()),
        Some(true),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(r#"{"sing-box":"1.13.0"}"#),
    )
    .await
    .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    inv.record_node_health(
        &ServerId("s1".into()),
        Some(true),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(r#"{"sing-box":"1.13.12","caddy":"2.8.4"}"#),
    )
    .await
    .unwrap();
    // s2: a row with NULL versions (old node / partial probe).
    inv.record_node_health(
        &ServerId("s2".into()),
        Some(true),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .await
    .unwrap();
    // s3: no probes at all → absent from the result.

    let mut fleet = inv.kernel_versions_fleet().await.unwrap();
    fleet.sort_by(|a, b| a.0.0.cmp(&b.0.0));
    assert_eq!(fleet.len(), 2, "s3 has no rows → not present");
    assert_eq!(fleet[0].0.0, "s1");
    assert_eq!(
        fleet[0].1.as_deref(),
        Some(r#"{"sing-box":"1.13.12","caddy":"2.8.4"}"#),
        "newest row's JSON for s1"
    );
    assert_eq!(fleet[1].0.0, "s2");
    assert_eq!(fleet[1].1, None, "s2 latest row has NULL versions");
}

#[tokio::test]
async fn q4e_empty_fleet() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    assert!(inv.kernel_versions_fleet().await.unwrap().is_empty());
}

// ── Q-4f alerts_by_kind_severity ─────────────────────────────────────

#[tokio::test]
async fn q4f_groups_unacked_by_kind_and_severity() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    // The unique-unacked constraint (0013) is on (kind, server_id), so
    // to get TWO unacked `disk.full` rows we put them on two servers.
    for s in ["s1", "s2", "s3"] {
        inv.add_server(&server(s)).await.unwrap();
    }
    let s1 = ServerId("s1".into());
    let s2 = ServerId("s2".into());
    let s3 = ServerId("s3".into());

    inv.insert_alert("disk.full", Some(&s1), "critical", "x", None)
        .await
        .unwrap();
    inv.insert_alert("disk.full", Some(&s2), "critical", "y", None)
        .await
        .unwrap();
    // Same kind, different severity → its own group.
    inv.insert_alert("disk.full", Some(&s3), "warning", "z", None)
        .await
        .unwrap();
    let acked = inv
        .insert_alert("mem.high", Some(&s1), "warning", "w", None)
        .await
        .unwrap();
    // Ack one alert — it must drop out of the breakdown.
    inv.ack_alert(acked).await.unwrap();

    let mut groups = inv.alerts_by_kind_severity().await.unwrap();
    groups.sort();
    assert_eq!(
        groups,
        vec![
            ("disk.full".to_string(), "critical".to_string(), 2),
            ("disk.full".to_string(), "warning".to_string(), 1),
        ],
        "acked mem.high excluded; disk.full split by severity"
    );
}

#[tokio::test]
async fn q4f_empty_when_no_unacked() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    assert!(inv.alerts_by_kind_severity().await.unwrap().is_empty());
}

// ── Q-4g today_digest ────────────────────────────────────────────────

#[tokio::test]
async fn q4g_buckets_today_audit_actions() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    inv.audit("admin", "user.create", Some("u1"), None)
        .await
        .unwrap();
    inv.audit("admin", "user.create", Some("u2"), None)
        .await
        .unwrap();
    inv.audit("admin", "server.grant", Some("u1"), None)
        .await
        .unwrap();
    inv.audit("admin", "protocol.revoke", Some("u1"), None)
        .await
        .unwrap();
    inv.audit("admin", "server.deploy", Some("s1"), None)
        .await
        .unwrap();
    // An unrelated action must not land in any bucket.
    inv.audit("admin", "user.disable", Some("u1"), None)
        .await
        .unwrap();

    let d = inv.today_digest().await.unwrap();
    assert_eq!(d.users_added, 2, "two user.create");
    assert_eq!(d.grants_changed, 2, "*.grant + *.revoke");
    assert_eq!(d.deploys, 1, "one server.deploy");
}

#[tokio::test]
async fn q4g_excludes_pre_midnight_rows() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    // Inject a row dated 2 days ago through a second pool to the same DB
    // file (the public `audit` always stamps now); the midnight cutoff
    // must exclude it. Same raw-pool back-door pattern as spec_sub_access.
    let raw = sqlx::SqlitePool::connect(&format!("sqlite://{}", db_path(&dir).display()))
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO audit_log (ts, actor, action, target) \
         VALUES (strftime('%Y-%m-%dT%H:%M:%fZ','now','-2 days'), 'admin', 'user.create', 'old')",
    )
    .execute(&raw)
    .await
    .unwrap();
    raw.close().await;
    inv.audit("admin", "user.create", Some("fresh"), None)
        .await
        .unwrap();

    let d = inv.today_digest().await.unwrap();
    assert_eq!(d.users_added, 1, "only today's user.create counts");
}

// ── Q-4h likely_shared_summary ───────────────────────────────────────

#[tokio::test]
async fn q4h_flags_users_over_asn_threshold() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("sharer")).await.unwrap();
    inv.add_user(&user("solo")).await.unwrap();

    // sharer: 3 distinct ASNs / 3 IPs / 2 countries — over threshold.
    let sharer = UserId("sharer".into());
    for (ip, asn, country) in [
        ("1.1.1.1", "AS111 A", "US"),
        ("2.2.2.2", "AS222 B", "DE"),
        ("3.3.3.3", "AS333 C", "US"),
    ] {
        inv.log_sub_access_rich(
            &sharer,
            ip,
            Some("Hiddify"),
            200,
            1024,
            None,
            None,
            None,
            Some(country),
            Some(asn),
            None,
            None,
        )
        .await
        .unwrap();
    }

    // solo: only one ASN — below the threshold of 3.
    inv.log_sub_access_rich(
        &UserId("solo".into()),
        "9.9.9.9",
        Some("Hiddify"),
        200,
        1024,
        None,
        None,
        None,
        Some("US"),
        Some("AS999 Solo"),
        None,
        None,
    )
    .await
    .unwrap();

    let flagged = inv.likely_shared_summary(3).await.unwrap();
    assert_eq!(flagged.len(), 1, "only sharer crosses 3 distinct ASNs");
    let (uid, ips, asns, countries) = &flagged[0];
    assert_eq!(uid.0, "sharer");
    assert_eq!(*ips, 3, "3 distinct IPs");
    assert_eq!(*asns, 3, "3 distinct ASNs");
    assert_eq!(*countries, 2, "US + DE = 2 distinct countries");
}

#[tokio::test]
async fn q4h_excludes_vpn_egress_rows() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("u")).await.unwrap();
    // Register a server whose address is the egress IP; the
    // sub_access_log trigger marks rows from that IP is_vpn_egress=1.
    inv.add_server(&server("egress-node")).await.unwrap();
    let egress_ip = "egress-node.example.com";

    // Two real-client ASNs (below threshold 3 on their own).
    inv.log_sub_access_rich(
        &UserId("u".into()),
        "1.1.1.1",
        Some("x"),
        200,
        100,
        None,
        None,
        None,
        Some("US"),
        Some("AS1 One"),
        None,
        None,
    )
    .await
    .unwrap();
    inv.log_sub_access_rich(
        &UserId("u".into()),
        "2.2.2.2",
        Some("x"),
        200,
        100,
        None,
        None,
        None,
        Some("DE"),
        Some("AS2 Two"),
        None,
        None,
    )
    .await
    .unwrap();
    // Two egress rows with NEW distinct ASNs — if these were counted,
    // the user would cross threshold 3. They must be EXCLUDED.
    for asn in ["AS3 Three", "AS4 Four"] {
        inv.log_sub_access_rich(
            &UserId("u".into()),
            egress_ip,
            Some("x"),
            200,
            100,
            None,
            None,
            None,
            Some("FR"),
            Some(asn),
            None,
            None,
        )
        .await
        .unwrap();
    }

    // With egress excluded, only 2 distinct real ASNs → below 3.
    let flagged3 = inv.likely_shared_summary(3).await.unwrap();
    assert!(
        flagged3.is_empty(),
        "egress ASNs must NOT count → 2 real ASNs is below 3"
    );
    // At threshold 2 the user shows with exactly the 2 REAL ASNs.
    let flagged2 = inv.likely_shared_summary(2).await.unwrap();
    assert_eq!(flagged2.len(), 1);
    assert_eq!(flagged2[0].1, 2, "2 distinct real IPs (egress excluded)");
    assert_eq!(flagged2[0].2, 2, "2 distinct real ASNs (egress excluded)");
    assert_eq!(
        flagged2[0].3, 2,
        "2 distinct real countries (egress excluded)"
    );
}
