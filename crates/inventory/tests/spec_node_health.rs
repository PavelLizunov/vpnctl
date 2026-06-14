//! Spec for `record_node_health`, `recent_node_health_for_server`,
//! `latest_node_health`, `purge_node_health_older_than` on
//! `SqliteInventory`. Written from spec only — impl NOT consulted.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use chrono::Utc;
use tempfile::TempDir;

use vpnctl_core::{KernelId, Server, ServerId};
use vpnctl_inventory::{NodeHealthRow, SqliteInventory};

fn db_path(dir: &TempDir) -> PathBuf {
    dir.path().join("inventory.db")
}

async fn open(dir: &TempDir) -> SqliteInventory {
    SqliteInventory::open(&db_path(dir)).await.expect("open")
}

fn srv(id: &str) -> Server {
    Server {
        id: ServerId(id.into()),
        address: "1.1.1.1".into(),
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

#[allow(clippy::too_many_arguments)]
async fn rec(
    inv: &SqliteInventory,
    sid: &str,
    sba: Option<bool>,
    fba: Option<bool>,
    du: Option<u64>,
    dt: Option<u64>,
    ma: Option<u64>,
    mt: Option<u64>,
    l: Option<u32>,
    ports: Option<&str>,
    log_bytes: Option<u64>,
) {
    inv.record_node_health(
        &ServerId(sid.into()),
        sba,
        fba,
        du,
        dt,
        ma,
        mt,
        l,
        ports,
        log_bytes,
        None, // kernel_versions_json — covered by the dedicated PR-Q test
    )
    .await
    .expect("record_node_health");
}

// 1. Empty inventory: recent_* and latest_* return empty / None.
#[tokio::test]
async fn empty_inventory_returns_empty_and_none() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("s1")).await.unwrap();

    let rows = inv
        .recent_node_health_for_server(&ServerId("s1".into()), 24)
        .await
        .unwrap();
    assert!(rows.is_empty(), "no rows yet: {rows:?}");

    let latest = inv
        .latest_node_health(&ServerId("s1".into()))
        .await
        .unwrap();
    assert!(latest.is_none(), "expected None, got {latest:?}");
}

// 2. Single insert with all fields populated; read-back roundtrips
//    and ts is approx now.
#[tokio::test]
async fn single_insert_roundtrips_all_fields_and_ts_is_now() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("s1")).await.unwrap();

    let before = Utc::now();
    rec(
        &inv,
        "s1",
        Some(true),
        Some(false),
        Some(10_240),
        Some(102_400),
        Some(2_048),
        Some(4_096),
        Some(57),
        Some(r#"["tcp/22","tcp/443","udp/8443"]"#),
        Some(1_234_567),
    )
    .await;
    let after = Utc::now();

    let rows = inv
        .recent_node_health_for_server(&ServerId("s1".into()), 24)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    let r = &rows[0];
    assert_eq!(r.server_id, ServerId("s1".into()));
    assert_eq!(r.sing_box_active, Some(true));
    assert_eq!(r.fail2ban_active, Some(false));
    assert_eq!(r.disk_used_mib, Some(10_240));
    assert_eq!(r.disk_total_mib, Some(102_400));
    assert_eq!(r.mem_available_mib, Some(2_048));
    assert_eq!(r.mem_total_mib, Some(4_096));
    assert_eq!(r.load_1min_x100, Some(57));
    assert_eq!(
        r.listening_ports_json.as_deref(),
        Some(r#"["tcp/22","tcp/443","udp/8443"]"#)
    );
    assert_eq!(r.sing_box_log_bytes, Some(1_234_567));
    let slack = chrono::Duration::seconds(5);
    assert!(
        r.ts >= before - slack && r.ts <= after + slack,
        "ts approx now; ts={}, before={before}, after={after}",
        r.ts
    );
}

// 3. Partial-fields probe: some Option::None survives as NULL → None.
#[tokio::test]
async fn partial_fields_none_preserved_on_read() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("s1")).await.unwrap();

    rec(
        &inv,
        "s1",
        Some(true),
        None, // fail2ban parser failed
        Some(1),
        None, // disk total parser failed
        None,
        Some(8_192),
        Some(100),
        None, // ports parser failed
        Some(0),
    )
    .await;

    let r = inv
        .latest_node_health(&ServerId("s1".into()))
        .await
        .unwrap()
        .expect("one row");
    assert_eq!(r.sing_box_active, Some(true));
    assert_eq!(r.fail2ban_active, None);
    assert_eq!(r.disk_used_mib, Some(1));
    assert_eq!(r.disk_total_mib, None);
    assert_eq!(r.mem_available_mib, None);
    assert_eq!(r.mem_total_mib, Some(8_192));
    assert_eq!(r.load_1min_x100, Some(100));
    assert_eq!(r.listening_ports_json, None);
    assert_eq!(r.sing_box_log_bytes, Some(0));
}

// 4. All-None probe still persists a row (worst-case tick).
#[tokio::test]
async fn all_none_probe_still_inserts_one_row() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("s1")).await.unwrap();

    rec(
        &inv, "s1", None, None, None, None, None, None, None, None, None,
    )
    .await;

    let rows = inv
        .recent_node_health_for_server(&ServerId("s1".into()), 24)
        .await
        .unwrap();
    assert_eq!(
        rows.len(),
        1,
        "all-None probe must still persist a row, got: {rows:?}"
    );
    let r = &rows[0];
    assert_eq!(r.sing_box_active, None);
    assert_eq!(r.fail2ban_active, None);
    assert_eq!(r.disk_used_mib, None);
    assert_eq!(r.disk_total_mib, None);
    assert_eq!(r.mem_available_mib, None);
    assert_eq!(r.mem_total_mib, None);
    assert_eq!(r.load_1min_x100, None);
    assert_eq!(r.listening_ports_json, None);
    assert_eq!(r.sing_box_log_bytes, None);
}

// 5. Newest-first ordering across 3 ticks (50ms apart, ISO-8601 millis).
#[tokio::test]
async fn recent_returns_newest_first() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("s1")).await.unwrap();

    for i in 0u64..3 {
        rec(
            &inv,
            "s1",
            Some(true),
            Some(true),
            Some(i),
            Some(100),
            None,
            None,
            None,
            None,
            None,
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    let rows = inv
        .recent_node_health_for_server(&ServerId("s1".into()), 24)
        .await
        .unwrap();
    assert_eq!(rows.len(), 3);
    for w in rows.windows(2) {
        assert!(
            w[0].ts >= w[1].ts,
            "newest-first violated: {:?} then {:?}",
            w[0].ts,
            w[1].ts
        );
    }
}

// 6. latest_* returns single newest row.
#[tokio::test]
async fn latest_returns_single_newest_row() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("s1")).await.unwrap();

    rec(
        &inv,
        "s1",
        Some(true),
        Some(true),
        Some(1),
        Some(10),
        None,
        None,
        None,
        None,
        None,
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    rec(
        &inv,
        "s1",
        Some(true),
        Some(true),
        Some(2),
        Some(20),
        None,
        None,
        None,
        None,
        None,
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    rec(
        &inv,
        "s1",
        Some(true),
        Some(true),
        Some(3),
        Some(30),
        None,
        None,
        None,
        None,
        None,
    )
    .await;

    let r: NodeHealthRow = inv
        .latest_node_health(&ServerId("s1".into()))
        .await
        .unwrap()
        .expect("latest must be Some");
    assert_eq!(r.disk_used_mib, Some(3), "must be the newest write");
    assert_eq!(r.disk_total_mib, Some(30));
}

// 7. since_hours=0 excludes everything (strict ts > now-0).
#[tokio::test]
async fn since_hours_zero_excludes_everything() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("s1")).await.unwrap();
    rec(
        &inv,
        "s1",
        Some(true),
        Some(true),
        Some(1),
        Some(10),
        None,
        None,
        None,
        None,
        None,
    )
    .await;

    let rows = inv
        .recent_node_health_for_server(&ServerId("s1".into()), 0)
        .await
        .unwrap();
    assert!(
        rows.is_empty(),
        "since_hours=0 must exclude everything, got: {rows:?}"
    );
}

// 8. since_hours=1 includes a freshly-written row (well within 30s).
#[tokio::test]
async fn since_hours_one_includes_30s_old_row() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("s1")).await.unwrap();
    rec(
        &inv,
        "s1",
        Some(true),
        None,
        Some(1),
        Some(10),
        None,
        None,
        None,
        None,
        None,
    )
    .await;

    let rows = inv
        .recent_node_health_for_server(&ServerId("s1".into()), 1)
        .await
        .unwrap();
    assert_eq!(
        rows.len(),
        1,
        "fresh row (~ms old) must be inside 1-hour window, got: {rows:?}"
    );
}

// 9. FK enforcement: insert for unknown server must fail.
#[tokio::test]
async fn record_for_unknown_server_fails_fk() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    // Deliberately do NOT add "ghost".

    let res = inv
        .record_node_health(
            &ServerId("ghost".into()),
            Some(true),
            Some(true),
            Some(1),
            Some(10),
            Some(1),
            Some(10),
            Some(50),
            Some("[]"),
            Some(0),
            None,
        )
        .await;
    assert!(
        res.is_err(),
        "FK on server_id must reject unknown server, got: {res:?}"
    );
}

// 10. CASCADE: removing a server drops its node_health rows.
#[tokio::test]
async fn remove_server_cascades_node_health() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("s1")).await.unwrap();
    inv.add_server(&srv("s2")).await.unwrap();

    rec(
        &inv,
        "s1",
        Some(true),
        Some(true),
        Some(1),
        Some(10),
        None,
        None,
        None,
        None,
        None,
    )
    .await;
    rec(
        &inv,
        "s2",
        Some(true),
        Some(true),
        Some(2),
        Some(20),
        None,
        None,
        None,
        None,
        None,
    )
    .await;

    inv.remove_server(&ServerId("s1".into())).await.unwrap();

    let s1_rows = inv
        .recent_node_health_for_server(&ServerId("s1".into()), 24)
        .await
        .unwrap();
    assert!(
        s1_rows.is_empty(),
        "CASCADE must drop s1's rows, got: {s1_rows:?}"
    );
    let s2_rows = inv
        .recent_node_health_for_server(&ServerId("s2".into()), 24)
        .await
        .unwrap();
    assert_eq!(s2_rows.len(), 1, "s2's rows must survive");
}

// 11. purge boundary: recent kept, old dropped, return count is right.
//     Then purge(0) sweeps everything.
#[tokio::test]
async fn purge_boundary_and_purge_zero_sweeps_all() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("s1")).await.unwrap();

    rec(
        &inv,
        "s1",
        Some(true),
        None,
        Some(1),
        Some(10),
        None,
        None,
        None,
        None,
        None,
    )
    .await;

    // Anything older than 30 days must remove ZERO rows.
    let removed = inv.purge_node_health_older_than(30).await.unwrap();
    assert_eq!(
        removed, 0,
        "no rows older than 30d when only row is brand new"
    );
    let still_there = inv
        .recent_node_health_for_server(&ServerId("s1".into()), 24)
        .await
        .unwrap();
    assert_eq!(still_there.len(), 1, "recent row must survive 30d purge");

    // purge(0) → everything older than now ⇒ all current rows go.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let removed_all = inv.purge_node_health_older_than(0).await.unwrap();
    assert_eq!(
        removed_all, 1,
        "purge(0) must drop the existing row, got removed={removed_all}"
    );
    let after = inv
        .recent_node_health_for_server(&ServerId("s1".into()), 24)
        .await
        .unwrap();
    assert!(after.is_empty(), "after purge(0), no rows left");
}

// 12. listening_ports_json roundtrips byte-for-byte verbatim (TEXT).
#[tokio::test]
async fn listening_ports_json_roundtrips_verbatim() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("s1")).await.unwrap();

    // Note: deliberately weird whitespace + ordering — the column is
    // TEXT and the spec says "returned verbatim", so we must NOT
    // round-trip through a JSON parser that would re-canonicalise it.
    let raw = r#"[  "tcp/22" ,"udp/8443","tcp/443"]"#;
    rec(
        &inv,
        "s1",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(raw),
        None,
    )
    .await;

    let r = inv
        .latest_node_health(&ServerId("s1".into()))
        .await
        .unwrap()
        .expect("one row");
    assert_eq!(
        r.listening_ports_json.as_deref(),
        Some(raw),
        "listening_ports_json must roundtrip byte-for-byte verbatim"
    );
}

// 13. PR-Q: kernel_versions_json roundtrips verbatim; NULL stays NULL
//     for old rows / partial probes (the nullable column is additive).
#[tokio::test]
async fn kernel_versions_json_roundtrips_and_nullable() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("s1")).await.unwrap();

    // Row WITH versions.
    let kv = r#"{"sing-box":"1.13.12","caddy":"2.8.4"}"#;
    inv.record_node_health(
        &ServerId("s1".into()),
        Some(true),
        Some(true),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(kv),
    )
    .await
    .unwrap();

    let r = inv
        .latest_node_health(&ServerId("s1".into()))
        .await
        .unwrap()
        .expect("one row");
    assert_eq!(
        r.kernel_versions_json.as_deref(),
        Some(kv),
        "kernel_versions_json must roundtrip verbatim"
    );

    // Row WITHOUT versions (partial probe / old node) → stays NULL.
    rec(
        &inv,
        "s1",
        Some(true),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .await;
    let latest = inv
        .latest_node_health(&ServerId("s1".into()))
        .await
        .unwrap()
        .expect("one row");
    assert_eq!(
        latest.kernel_versions_json, None,
        "a probe with no versions persists NULL, not an empty object"
    );
}
