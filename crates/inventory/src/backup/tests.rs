#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crate::sqlite::SqliteInventory;

#[test]
fn snapshot_filename_round_trips_through_parser() {
    let at = chrono::DateTime::parse_from_rfc3339("2026-05-17T18:45:12.345Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let name = snapshot_filename_at(at);
    assert!(name.starts_with("inv.db.2026-05-17T18-45-12"));
    assert!(name.ends_with(".bak"));
    let parsed = parse_snapshot_filename(&name).unwrap();
    assert!(parsed.starts_with("2026-05-17T18:45:12"));
}

#[test]
fn parse_snapshot_filename_returns_none_for_non_vpnctl_files() {
    assert!(parse_snapshot_filename("inv.db").is_none());
    assert!(parse_snapshot_filename("random.bak").is_none());
    assert!(parse_snapshot_filename("inv.db.bak").is_none());
    assert!(parse_snapshot_filename("inv.db.notes.txt").is_none());
}

#[tokio::test]
async fn snapshot_now_creates_file_and_lists() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("inv.db");
    let inv = SqliteInventory::open(&db).await.unwrap();
    let backup_dir = dir.path().join("backups");
    let snap = snapshot_now(&inv, &backup_dir).await.unwrap();
    assert!(snap.exists(), "snapshot file should exist at {snap:?}");
    assert!(snap.metadata().unwrap().len() > 0);

    let list = list_snapshots(&backup_dir).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].path, snap);
    assert!(list[0].created.is_some());
    assert!(list[0].size_bytes > 0);
}

#[tokio::test]
async fn snapshot_refuses_to_overwrite_existing_file() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("inv.db");
    let inv = SqliteInventory::open(&db).await.unwrap();
    let backup_dir = dir.path().join("backups");
    std::fs::create_dir_all(&backup_dir).unwrap();
    let target = backup_dir.join("inv.db.2026-01-01T00-00-00.000Z.bak");
    std::fs::write(&target, b"pre-existing").unwrap();
    // VACUUM INTO refuses to overwrite. Caller would have used
    // a fresh timestamp to avoid this; the test pins the safety
    // net. The exact wording is SQLite's choice — we accept
    // anything sqlx surfaces as an error (rather than silently
    // overwriting which is the actual safety risk).
    let err = snapshot_to(&inv, &target).await;
    assert!(
        err.is_err(),
        "snapshot_to MUST refuse to clobber an existing file"
    );
    // Verify the original file is intact (sqlite didn't half-write).
    assert_eq!(
        std::fs::read(&target).unwrap(),
        b"pre-existing",
        "existing snapshot file must be untouched on collision"
    );
}

#[tokio::test]
async fn prune_keeps_recent_hourly_and_per_day_per_month() {
    let dir = tempfile::tempdir().unwrap();
    let backup_dir = dir.path().to_path_buf();
    // Seed 50 snapshots: every 15 minutes for ~12 hours, then a
    // few daily-spaced and a few monthly-spaced ones farther
    // back. Cheap empty files — we don't care about content.
    let mut at = chrono::DateTime::parse_from_rfc3339("2026-05-17T12:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    for _ in 0..48 {
        let name = snapshot_filename_at(at);
        std::fs::write(backup_dir.join(name), b"x").unwrap();
        at -= chrono::Duration::minutes(15);
    }
    for d in 1..=10 {
        let day = chrono::DateTime::parse_from_rfc3339(&format!("2026-05-{:02}T03:00:00Z", d))
            .unwrap()
            .with_timezone(&chrono::Utc);
        std::fs::write(backup_dir.join(snapshot_filename_at(day)), b"x").unwrap();
    }
    for m in 1..=6 {
        let mo = chrono::DateTime::parse_from_rfc3339(&format!("2026-{:02}-01T00:00:00Z", m))
            .unwrap()
            .with_timezone(&chrono::Utc);
        std::fs::write(backup_dir.join(snapshot_filename_at(mo)), b"x").unwrap();
    }

    let policy = Retention {
        keep_hourly: 4,
        keep_daily: 3,
        keep_monthly: 2,
    };
    let removed = prune_snapshots(&backup_dir, policy).unwrap();
    let remaining = list_snapshots(&backup_dir).unwrap();
    assert!(
        remaining.len() <= policy.keep_hourly + policy.keep_daily + policy.keep_monthly,
        "kept {} > cap {}",
        remaining.len(),
        policy.keep_hourly + policy.keep_daily + policy.keep_monthly
    );
    assert!(removed > 0, "should have removed some old snapshots");
}

// ponytail: unix-only — restore_from renames tmp over db_path; POSIX
// allows rename over a just-closed SQLite path, NTFS refuses it (async
// close + lingering -wal/-shm handles). vpnctld is Linux-only in prod,
// so this asserts POSIX fs semantics. Skipped on Windows so the local
// dev gate passes; still runs on Linux + CI.
#[cfg(unix)]
#[tokio::test]
async fn restore_swaps_db_when_snapshot_valid() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("inv.db");
    let inv = SqliteInventory::open(&db).await.unwrap();
    // Mark the live DB with a known server so we can prove restore happened.
    use vpnctl_core::{KernelId, ProtocolId, Server, ServerId};
    inv.add_server(&Server {
        id: ServerId("live-only".into()),
        address: "203.0.113.99".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("vless+reality".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();
    // Take the snapshot. At this point the snapshot has 'live-only'.
    let snap = snapshot_now(&inv, dir.path()).await.unwrap();
    // Add another server — this MUST NOT be in the restored DB.
    inv.add_server(&Server {
        id: ServerId("after-snapshot".into()),
        address: "203.0.113.100".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("vless+reality".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();
    // Close the live pool BEFORE restoring (mimics "daemon stopped").
    drop(inv);
    // Restore.
    restore_from(&snap, &db).await.unwrap();
    // Re-open and confirm the post-snapshot server is GONE.
    let restored = SqliteInventory::open(&db).await.unwrap();
    let servers = restored.list_servers().await.unwrap();
    let ids: std::collections::HashSet<String> = servers.into_iter().map(|s| s.id.0).collect();
    assert!(
        ids.contains("live-only"),
        "restored DB must contain pre-snapshot row"
    );
    assert!(
        !ids.contains("after-snapshot"),
        "restored DB must NOT contain post-snapshot row"
    );
}

#[tokio::test]
async fn restore_rejects_non_sqlite_file() {
    let dir = tempfile::tempdir().unwrap();
    let bogus = dir.path().join("not-a-db.bak");
    std::fs::write(&bogus, b"hello not a database").unwrap();
    let target = dir.path().join("inv.db");
    let err = restore_from(&bogus, &target).await.unwrap_err();
    assert!(
        format!("{err}").contains("not a valid SQLite file")
            || format!("{err}").to_lowercase().contains("malformed")
            || format!("{err}").to_lowercase().contains("sqlite"),
        "expected validation error, got: {err}"
    );
    // db_path must NOT have been created if validation failed.
    assert!(
        !target.exists(),
        "restore must not create target on validation failure"
    );
}

// ── Phase 5c — verify_snapshot tests ─────────────────────────────────

#[tokio::test]
async fn verify_snapshot_reports_ok_on_freshly_minted_snapshot() {
    use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("inv.db");
    let inv = SqliteInventory::open(&db).await.unwrap();
    // Seed: 1 user + 1 server + 1 grant + sub_token. This is the
    // minimum «would actually restore into something usable» shape.
    inv.add_user(&User {
        id: UserId("alice".into()),
        uuid: "11111111-1111-1111-1111-111111111111".into(),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    })
    .await
    .unwrap();
    inv.regenerate_sub_token(&UserId("alice".into()))
        .await
        .unwrap();
    inv.add_server(&Server {
        id: ServerId("de".into()),
        address: "1.2.3.4".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("vless+reality".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();
    inv.grant(&UserId("alice".into()), &ServerId("de".into()))
        .await
        .unwrap();

    let snap = snapshot_now(&inv, dir.path()).await.unwrap();
    let report = verify_snapshot(&snap).await.unwrap();

    assert_eq!(report.overall, CheckStatus::Ok, "{report:?}");
    assert_eq!(report.user_count, 1);
    assert_eq!(report.server_count, 1);
    assert_eq!(report.grant_count, 1);
    assert_eq!(report.users_with_sub_token, 1);
    assert!(report.schema_migrations_applied > 0);
    assert!(report.snapshot_size_bytes > 0);
    // Snapshot just minted → age must be tiny (single-digit seconds).
    assert!(
        report.snapshot_age_seconds.unwrap_or(i64::MAX) < 60,
        "freshly minted snapshot should be < 1min old, got {:?}",
        report.snapshot_age_seconds
    );
    // Every per-check entry must be Ok.
    for c in &report.checks {
        assert_eq!(
            c.status,
            CheckStatus::Ok,
            "check {:?} should be Ok on fresh snapshot",
            c.name
        );
    }
}

#[tokio::test]
async fn verify_snapshot_warns_when_grants_empty() {
    use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("inv.db");
    let inv = SqliteInventory::open(&db).await.unwrap();
    // User + server but NO grants — restore would succeed but
    // the user would have access to nothing. Both presence checks
    // are Ok; only `grants_present` should Warn → overall=Warn.
    inv.add_user(&User {
        id: UserId("alice".into()),
        uuid: "11111111-1111-1111-1111-111111111111".into(),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    })
    .await
    .unwrap();
    inv.add_server(&Server {
        id: ServerId("de".into()),
        address: "1.2.3.4".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("vless+reality".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();
    let snap = snapshot_now(&inv, dir.path()).await.unwrap();
    let report = verify_snapshot(&snap).await.unwrap();
    assert_eq!(report.overall, CheckStatus::Warn, "{report:?}");
    let grants_check = report
        .checks
        .iter()
        .find(|c| c.name == "grants_present")
        .expect("grants_present check must be present");
    assert_eq!(grants_check.status, CheckStatus::Warn);
}

#[tokio::test]
async fn verify_snapshot_fails_on_empty_db() {
    // Empty SQLite file = `sqlite_master` empty = the «backup
    // pulled before migrations ran» bug class.
    let dir = tempfile::tempdir().unwrap();
    let empty = dir.path().join("empty.db.bak");
    // Touch a syntactically-valid empty SQLite file by opening
    // a fresh sqlx connection and immediately dropping it.
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            sqlx::sqlite::SqliteConnectOptions::new()
                .filename(&empty)
                .create_if_missing(true),
        )
        .await
        .unwrap();
    pool.close().await;
    let report = verify_snapshot(&empty).await.unwrap();
    assert_eq!(report.overall, CheckStatus::Fail, "{report:?}");
    let master_check = report
        .checks
        .iter()
        .find(|c| c.name == "sqlite_master_non_empty")
        .expect("sqlite_master_non_empty check must be present");
    assert_eq!(master_check.status, CheckStatus::Fail);
    // Early-out: no metric checks should have run.
    assert!(
        report
            .checks
            .iter()
            .all(|c| c.name == "sqlite_master_non_empty"),
        "empty-master report must short-circuit; got {:?}",
        report.checks
    );
}

#[tokio::test]
async fn verify_snapshot_errors_on_missing_file() {
    // The function reserves Err for «could not even RUN» —
    // file-not-found qualifies.
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("nope.bak");
    let err = verify_snapshot(&missing).await.unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("stat snapshot"),
        "missing-file error should mention stat, got: {msg}"
    );
}

#[tokio::test]
async fn verify_snapshot_errors_on_non_sqlite_file() {
    // Mirrors restore's input validation — `verify_snapshot`
    // must reject the same garbage with the same precision.
    let dir = tempfile::tempdir().unwrap();
    let bogus = dir.path().join("not-a-db.bak");
    std::fs::write(&bogus, b"hello not a database").unwrap();
    let err = verify_snapshot(&bogus).await.unwrap_err();
    let msg = format!("{err}").to_lowercase();
    assert!(
        msg.contains("sqlite") || msg.contains("malformed"),
        "expected sqlite-validation error, got: {msg}"
    );
}

#[tokio::test]
async fn verify_snapshot_fails_when_snapshot_is_from_newer_binary() {
    // Schema-drift detection for the «we tried to restore a
    // backup made by a NEWER vpnctld binary than the one we're
    // running» case. sqlx's migrator refuses to run when the
    // snapshot's `_sqlx_migrations` includes a version number
    // the binary's embedded migrator doesn't know about — this
    // is the exact bug class operators would hit during a
    // post-incident downgrade. Verify the failure surfaces as a
    // `schema_migrations_match_binary` Fail (NOT silently
    // swallowed into Ok).
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("inv.db");
    let inv = SqliteInventory::open(&db).await.unwrap();
    let snap = snapshot_now(&inv, dir.path()).await.unwrap();
    // Inject a fake future migration row. The binary's migrator
    // will reject it with «migration <N+1> was previously applied
    // but is missing in the resolved migrations».
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(sqlx::sqlite::SqliteConnectOptions::new().filename(&snap))
        .await
        .unwrap();
    let max_version: i64 =
        sqlx::query_scalar("SELECT COALESCE(MAX(version), 0) FROM _sqlx_migrations")
            .fetch_one(&pool)
            .await
            .unwrap();
    sqlx::query(
        "INSERT INTO _sqlx_migrations
         (version, description, installed_on, success, checksum, execution_time)
         VALUES (?, 'fake_future_migration', '2030-01-01T00:00:00Z', 1, X'00', 0)",
    )
    .bind(max_version + 1)
    .execute(&pool)
    .await
    .unwrap();
    pool.close().await;

    let report = verify_snapshot(&snap).await.unwrap();
    let mig_check = report
        .checks
        .iter()
        .find(|c| c.name == "schema_migrations_match_binary")
        .expect("schema_migrations_match_binary check must be present");
    assert_eq!(
        mig_check.status,
        CheckStatus::Fail,
        "snapshot from newer binary should Fail at migration replay, got: {mig_check:?}"
    );
    assert!(
        mig_check.detail.contains("migration replay failed"),
        "Fail detail should explain it was a migration replay failure, got: {}",
        mig_check.detail
    );
    // Overall must be Fail (this is the «cannot restore» branch).
    assert_eq!(report.overall, CheckStatus::Fail);
    // Early-return: data-presence checks should NOT have run.
    assert!(
        !report
            .checks
            .iter()
            .any(|c| c.name == "users_present" || c.name == "servers_present"),
        "data checks must short-circuit on migration failure; got {:?}",
        report.checks
    );
}

#[test]
fn check_status_label_is_lowercase_for_html_class_compatibility() {
    // Pinned because the admin UI uses the label as a CSS class
    // (`.self-test-check--ok / --warn / --fail`).
    assert_eq!(CheckStatus::Ok.label(), "ok");
    assert_eq!(CheckStatus::Warn.label(), "warn");
    assert_eq!(CheckStatus::Fail.label(), "fail");
}
