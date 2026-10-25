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
    let err = snapshot_to(&inv, &target).await;
    assert!(
        err.is_err(),
        "snapshot_to MUST refuse to clobber an existing file"
    );
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

#[cfg(unix)]
#[tokio::test]
async fn restore_swaps_db_when_snapshot_valid() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("inv.db");
    let inv = SqliteInventory::open(&db).await.unwrap();
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
    let snap = snapshot_now(&inv, dir.path()).await.unwrap();
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
    drop(inv);
    restore_from(&snap, &db).await.unwrap();
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
    assert!(
        !target.exists(),
        "restore must not create target on validation failure"
    );
}

async fn populated_snapshot() -> (tempfile::TempDir, std::path::PathBuf) {
    use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("inv.db");
    let inv = SqliteInventory::open(&db).await.unwrap();
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
    (dir, snap)
}

#[tokio::test]
async fn verify_snapshot_reports_ok_on_freshly_minted_snapshot() {
    let (_dir, snap) = populated_snapshot().await;
    let report = verify_snapshot(&snap).await.unwrap();
    for name in ["integrity_check", "foreign_key_check"] {
        assert!(report.checks.iter().any(|c| c.name == name));
    }

    assert_eq!(report.overall, CheckStatus::Ok, "{report:?}");
    assert_eq!(report.user_count, 1);
    assert_eq!(report.server_count, 1);
    assert_eq!(report.grant_count, 1);
    assert_eq!(report.users_with_sub_token, 1);
    assert!(report.schema_migrations_applied > 0);
    assert!(report.snapshot_size_bytes > 0);
    assert!(
        report.snapshot_age_seconds.unwrap_or(i64::MAX) < 60,
        "freshly minted snapshot should be < 1min old, got {:?}",
        report.snapshot_age_seconds
    );
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
    let dir = tempfile::tempdir().unwrap();
    let empty = dir.path().join("empty.db.bak");
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
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("inv.db");
    let inv = SqliteInventory::open(&db).await.unwrap();
    let snap = snapshot_now(&inv, dir.path()).await.unwrap();
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
    assert_eq!(report.overall, CheckStatus::Fail);
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
    assert_eq!(CheckStatus::Ok.label(), "ok");
    assert_eq!(CheckStatus::Warn.label(), "warn");
    assert_eq!(CheckStatus::Fail.label(), "fail");
}

#[tokio::test]
async fn restore_rejects_foreign_sqlite_without_replacing_target() {
    for schema in [
        "CREATE TABLE foreign_data (id INTEGER)",
        "CREATE TABLE users (id TEXT); CREATE TABLE servers (id TEXT)",
        "CREATE TABLE _sqlx_migrations (version INTEGER)",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let snapshot = dir.path().join("foreign.db");
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .connect_with(
                sqlx::sqlite::SqliteConnectOptions::new()
                    .filename(&snapshot)
                    .create_if_missing(true),
            )
            .await
            .unwrap();
        sqlx::raw_sql(schema).execute(&pool).await.unwrap();
        pool.close().await;
        let target = dir.path().join("inv.db");
        std::fs::write(&target, b"original target").unwrap();
        let err = restore_from(&snapshot, &target).await.unwrap_err();
        assert!(err.to_string().contains("not a vpnctl backup"), "{err}");
        assert_eq!(std::fs::read(&target).unwrap(), b"original target");
        assert!(!dir.path().join("inv.db.restore.tmp").exists());
    }
}

#[tokio::test]
async fn verify_snapshot_fails_on_foreign_key_violations_without_changing_snapshot() {
    for column in ["user_id", "server_id"] {
        let (_dir, snap) = populated_snapshot().await;
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(
                sqlx::sqlite::SqliteConnectOptions::new()
                    .filename(&snap)
                    .foreign_keys(false),
            )
            .await
            .unwrap();
        sqlx::query(&format!("UPDATE grants SET {column} = 'missing-parent'"))
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
        let before = std::fs::read(&snap).unwrap();

        let report = verify_snapshot(&snap).await.unwrap();
        let check = report
            .checks
            .iter()
            .find(|c| c.name == "foreign_key_check")
            .expect("foreign_key_check must be present");
        assert_eq!(check.status, CheckStatus::Fail, "{report:?}");
        assert_eq!(report.overall, CheckStatus::Fail, "{report:?}");
        assert_eq!(report.user_count, 1);
        assert_eq!(report.server_count, 1);
        assert_eq!(report.grant_count, 1);
        assert_eq!(std::fs::read(&snap).unwrap(), before);
    }
}

#[tokio::test]
async fn verify_snapshot_fails_on_integrity_violation_without_changing_snapshot() {
    let (_dir, snap) = populated_snapshot().await;
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(sqlx::sqlite::SqliteConnectOptions::new().filename(&snap))
        .await
        .unwrap();
    sqlx::raw_sql(
        "CREATE TABLE integrity_probe (value INTEGER CHECK (value > 0));
         PRAGMA ignore_check_constraints = ON;
         INSERT INTO integrity_probe VALUES (-1)",
    )
    .execute(&pool)
    .await
    .unwrap();
    pool.close().await;
    let before = std::fs::read(&snap).unwrap();

    let report = verify_snapshot(&snap).await.unwrap();
    let check = report
        .checks
        .iter()
        .find(|c| c.name == "integrity_check")
        .expect("integrity_check must be present");
    assert_eq!(check.status, CheckStatus::Fail, "{report:?}");
    assert_eq!(report.overall, CheckStatus::Fail, "{report:?}");
    assert_eq!(report.user_count, 1);
    assert_eq!(report.server_count, 1);
    assert_eq!(std::fs::read(&snap).unwrap(), before);
}

#[test]
fn backup_dir_from_env_honors_override_and_default() {
    const EXPECTED: &str = "VPNCTL_TEST_EXPECTED_BACKUP_DIR";
    if let Some(expected) = std::env::var_os(EXPECTED) {
        assert_eq!(backup_dir_from_env(), std::path::PathBuf::from(expected));
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let custom = dir.path().join("custom backups");
    for value in [
        None,
        Some(custom.as_os_str()),
        Some(std::ffi::OsStr::new("")),
    ] {
        let expected = value.unwrap_or_else(|| std::ffi::OsStr::new(DEFAULT_BACKUP_DIR));
        let mut child = std::process::Command::new(std::env::current_exe().unwrap());
        child
            .args([
                "--exact",
                "backup::tests::backup_dir_from_env_honors_override_and_default",
                "--nocapture",
            ])
            .env(EXPECTED, expected);
        match value {
            Some(value) => child.env("VPNCTLD_BACKUP_DIR", value),
            None => child.env_remove("VPNCTLD_BACKUP_DIR"),
        };
        assert!(child.status().unwrap().success());
    }
}
