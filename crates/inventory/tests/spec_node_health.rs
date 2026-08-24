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
        None, // nic_iface
        None, // nic_rx_bytes
        None, // nic_tx_bytes
        None, // sing_box_nrestarts — covered by the dedicated restart test
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
            None,
            None,
            None,
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
        None,
        None,
        None,
        None,
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
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
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

// 14. Migration 0042: sing_box_nrestarts roundtrips; NULL stays NULL for
//     rows without a reading (non-systemd host / partial probe). The
//     health monitor relies on NULL-vs-Some to skip first-observation.
#[tokio::test]
async fn sing_box_nrestarts_roundtrips_and_nullable() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("s1")).await.unwrap();

    // Row WITH a counter reading.
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
        None,
        None,
        None,
        None,
        Some(7),
    )
    .await
    .unwrap();
    let r = inv
        .latest_node_health(&ServerId("s1".into()))
        .await
        .unwrap()
        .expect("one row");
    assert_eq!(
        r.sing_box_nrestarts,
        Some(7),
        "sing_box_nrestarts must roundtrip the monotonic counter"
    );

    // Row WITHOUT a reading (rec helper passes None) → stays NULL, NOT 0.
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
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
        latest.sing_box_nrestarts, None,
        "a probe with no NRestarts reading persists NULL, not zero"
    );
}

// 15. New writes mint valid UUID sample_id; recent/latest expose it.
#[tokio::test]
async fn sample_id_roundtrips_as_valid_uuid_and_orders_consistently() {
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

    let rows = inv
        .recent_node_health_for_server(&ServerId("s1".into()), 24)
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);

    let sid0 = rows[0].sample_id.as_deref().expect("sample_id populated");
    let sid1 = rows[1].sample_id.as_deref().expect("sample_id populated");
    assert!(
        vpnctl_crypto::is_valid_uuid(sid0),
        "new sample_id must be valid UUID: {sid0}"
    );
    assert!(
        vpnctl_crypto::is_valid_uuid(sid1),
        "new sample_id must be valid UUID: {sid1}"
    );
    assert_ne!(sid0, sid1, "distinct writes must have distinct sample IDs");

    let latest = inv
        .latest_node_health(&ServerId("s1".into()))
        .await
        .unwrap()
        .expect("latest row");
    assert_eq!(latest.sample_id.as_deref(), Some(sid0));
}

// 16. Migration 0051 backfills legacy rows deterministically with stable legacy IDs
//     and enforces unique index constraint.
#[tokio::test]
async fn migration_0051_backfills_legacy_sample_ids_and_enforces_uniqueness() {
    use std::path::Path;
    use std::str::FromStr;

    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("migration_test.db");

    // Apply migrations up to 0050 into a temporary migration folder
    let migrations_temp_dir = TempDir::new().unwrap();
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
    for entry in std::fs::read_dir(&src_dir).unwrap().filter_map(|e| e.ok()) {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.ends_with(".sql") && name.as_str() < "0051" {
            std::fs::copy(entry.path(), migrations_temp_dir.path().join(&name)).unwrap();
        }
    }

    let opts = sqlx::sqlite::SqliteConnectOptions::from_str(db_path.to_str().unwrap())
        .unwrap()
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .foreign_keys(true);
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .unwrap();

    let migrator = sqlx::migrate::Migrator::new(migrations_temp_dir.path())
        .await
        .unwrap();
    migrator.run(&pool).await.unwrap();

    // Insert server and legacy node_health rows without sample_id
    sqlx::query("INSERT INTO servers (id, address, ssh_port, ssh_user, hoster) VALUES ('s1', '1.1.1.1', 22, 'root', 'generic')")
        .execute(&pool)
        .await
        .unwrap();

    sqlx::query(
        "INSERT INTO node_health (ts, server_id, sing_box_active, disk_used_mib)
         VALUES ('2026-01-01T00:00:00.000Z', 's1', 1, 10),
                ('2026-01-01T00:10:00.000Z', 's1', 1, 20)",
    )
    .execute(&pool)
    .await
    .unwrap();

    // Apply migration 0051
    let m51_sql = std::fs::read_to_string(src_dir.join("0051_node_health_sample_id.sql")).unwrap();
    sqlx::raw_sql(&m51_sql).execute(&pool).await.unwrap();

    // Check backfilled sample IDs
    let sample_ids: Vec<(String,)> =
        sqlx::query_as("SELECT sample_id FROM node_health ORDER BY ts ASC")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(sample_ids.len(), 2);
    assert!(
        sample_ids[0].0.starts_with("legacy-"),
        "backfill must prefix legacy-: {}",
        sample_ids[0].0
    );
    assert!(
        sample_ids[1].0.starts_with("legacy-"),
        "backfill must prefix legacy-: {}",
        sample_ids[1].0
    );
    assert_ne!(
        sample_ids[0].0, sample_ids[1].0,
        "legacy IDs must be distinct"
    );

    // Omitting sample_id must fail the NOT NULL constraint.
    let null_err = sqlx::query(
        "INSERT INTO node_health (ts, server_id) VALUES ('2026-01-01T00:15:00.000Z', 's1')",
    )
    .execute(&pool)
    .await;
    assert!(null_err.is_err(), "sample_id must be required by schema");

    // Inserting a duplicate sample_id must fail unique constraint
    let dup_err = sqlx::query(
        "INSERT INTO node_health (sample_id, ts, server_id) VALUES (?1, '2026-01-01T00:20:00.000Z', 's1')",
    )
    .bind(&sample_ids[0].0)
    .execute(&pool)
    .await;
    assert!(
        dup_err.is_err(),
        "duplicate sample_id must be rejected by unique index"
    );

    pool.close().await;
}

// 17. Sample IDs persist and stay unchanged across SQLite VACUUM.
#[tokio::test]
async fn sample_ids_persist_across_vacuum() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("s1")).await.unwrap();

    for i in 1..=5 {
        rec(
            &inv,
            "s1",
            Some(true),
            Some(true),
            Some(i * 10),
            Some(100),
            None,
            None,
            None,
            None,
            None,
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(15)).await;
    }

    let before_rows = inv
        .recent_node_health_for_server(&ServerId("s1".into()), 24)
        .await
        .unwrap();
    assert_eq!(before_rows.len(), 5);
    let before_ids: Vec<String> = before_rows
        .iter()
        .map(|r| r.sample_id.clone().unwrap())
        .collect();

    // Run VACUUM via a raw pool
    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", db_path(&dir).display()))
        .await
        .unwrap();
    sqlx::raw_sql("VACUUM;").execute(&pool).await.unwrap();
    pool.close().await;

    let after_rows = inv
        .recent_node_health_for_server(&ServerId("s1".into()), 24)
        .await
        .unwrap();
    assert_eq!(after_rows.len(), 5);
    let after_ids: Vec<String> = after_rows
        .iter()
        .map(|r| r.sample_id.clone().unwrap())
        .collect();

    assert_eq!(
        before_ids, after_ids,
        "sample IDs and ordering must be completely stable across VACUUM"
    );
}

// 18. Sample IDs persist across VACUUM INTO / backup restore.
#[tokio::test]
async fn sample_ids_persist_across_vacuum_into_and_restore() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("s1")).await.unwrap();

    for i in 1..=3 {
        rec(
            &inv,
            "s1",
            Some(true),
            Some(true),
            Some(i * 50),
            Some(500),
            None,
            None,
            None,
            None,
            None,
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(15)).await;
    }

    let orig_rows = inv
        .recent_node_health_for_server(&ServerId("s1".into()), 24)
        .await
        .unwrap();
    let orig_ids: Vec<String> = orig_rows
        .iter()
        .map(|r| r.sample_id.clone().unwrap())
        .collect();

    let backup_path = dir.path().join("backup_restore.db");
    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", db_path(&dir).display()))
        .await
        .unwrap();
    sqlx::raw_sql(&format!("VACUUM INTO '{}';", backup_path.to_str().unwrap()))
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;

    // Open restored DB
    let restored_inv = SqliteInventory::open(&backup_path).await.unwrap();
    let restored_rows = restored_inv
        .recent_node_health_for_server(&ServerId("s1".into()), 24)
        .await
        .unwrap();
    let restored_ids: Vec<String> = restored_rows
        .iter()
        .map(|r| r.sample_id.clone().unwrap())
        .collect();

    assert_eq!(
        orig_ids, restored_ids,
        "restored database must preserve identical sample IDs"
    );
}

// 19. Retention deletion / new inserts cannot reuse old sample IDs.
#[tokio::test]
async fn sample_ids_retention_deletion_and_new_inserts_cannot_reuse() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_server(&srv("s1")).await.unwrap();

    rec(
        &inv,
        "s1",
        Some(true),
        Some(true),
        Some(10),
        Some(100),
        None,
        None,
        None,
        None,
        None,
    )
    .await;
    let r1 = inv
        .latest_node_health(&ServerId("s1".into()))
        .await
        .unwrap()
        .unwrap();
    let sid1 = r1.sample_id.expect("sample_id 1");

    // Purge all rows
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    inv.purge_node_health_older_than(0).await.unwrap();
    let empty_rows = inv
        .recent_node_health_for_server(&ServerId("s1".into()), 24)
        .await
        .unwrap();
    assert!(empty_rows.is_empty());

    // Insert new row
    rec(
        &inv,
        "s1",
        Some(true),
        Some(true),
        Some(20),
        Some(100),
        None,
        None,
        None,
        None,
        None,
    )
    .await;
    let r2 = inv
        .latest_node_health(&ServerId("s1".into()))
        .await
        .unwrap()
        .unwrap();
    let sid2 = r2.sample_id.expect("sample_id 2");

    assert_ne!(
        sid1, sid2,
        "new insert after deletion cannot reuse deleted sample_id"
    );
}
