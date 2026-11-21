#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::{path::Path, path::PathBuf};

use sqlx::{
    Row, SqlitePool,
    migrate::Migrate,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use tempfile::TempDir;
use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
use vpnctl_inventory::{
    ServerTrafficLimit, ServicePathStatus, ServiceQualitySample, SqliteInventory,
};

const REINDEX_ACTION: &str = "migration.server_traffic.reindex";
const USERS: [&str; 3] = ["fixture-alpha", "fixture-beta", "fixture-gamma"];

#[path = "support/legacy_70.rs"]
mod legacy_70;
use legacy_70::{frozen_checksum, install_legacy_70};

#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow)]
struct MigrationMarker {
    version: i64,
    description: String,
    installed_on: String,
    success: bool,
    checksum: Vec<u8>,
    execution_time: i64,
}

#[derive(Debug, PartialEq, Eq)]
struct DatabaseSnapshot {
    schema: Vec<(String, String, String, Option<String>)>,
    tables: Vec<(String, Vec<Vec<String>>)>,
}

struct Fixture {
    dir: TempDir,
}

fn server_id() -> ServerId {
    ServerId("fixture-server".into())
}

fn server() -> Server {
    Server {
        id: server_id(),
        address: "198.51.100.54".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("vless+reality".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

fn user(id: &str) -> User {
    User {
        id: UserId(id.into()),
        uuid: format!("fixture-global-uuid-{id}"),
        tuic_password: Some(format!("fixture-tuic-password-{id}")),
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: Some(format!("fixture-subscription-{id}")),
        vpn_router_device_id: None,
        disabled: false,
    }
}

fn grant_uuid(index: usize) -> String {
    format!("12345678-1234-1234-1234-{index:012}")
}

fn quota() -> ServerTrafficLimit {
    ServerTrafficLimit {
        limit_bytes: 4_000_000_000_000,
        direction: "both".into(),
        reset_day: 15,
        warning_pct: 80,
    }
}

async fn connect(path: &Path) -> SqlitePool {
    SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(path)
                .create_if_missing(true)
                .foreign_keys(true),
        )
        .await
        .unwrap()
}

async fn marker(pool: &SqlitePool, version: i64) -> MigrationMarker {
    sqlx::query_as(
        "SELECT version, description, installed_on, success, checksum, execution_time
         FROM _sqlx_migrations WHERE version = ?1",
    )
    .bind(version)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn reindex_count(pool: &SqlitePool) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action = ?1")
        .bind(REINDEX_ACTION)
        .fetch_one(pool)
        .await
        .unwrap()
}

fn quoted_identifier(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

async fn table_names(pool: &SqlitePool) -> Vec<String> {
    sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
        .fetch_all(pool)
        .await
        .unwrap()
}

async fn table_contents(pool: &SqlitePool, table: &str) -> Vec<Vec<String>> {
    let info = sqlx::query(&format!("PRAGMA table_info({})", quoted_identifier(table)))
        .fetch_all(pool)
        .await
        .unwrap();
    let columns: Vec<String> = info
        .iter()
        .map(|row| {
            let name: String = row.get("name");
            format!("quote({})", quoted_identifier(&name))
        })
        .collect();
    assert!(!columns.is_empty());
    let query = format!(
        "SELECT {} FROM {}",
        columns.join(", "),
        quoted_identifier(table)
    );
    let rows = sqlx::query(&query).fetch_all(pool).await.unwrap();
    let mut contents: Vec<Vec<String>> = rows
        .iter()
        .map(|row| {
            (0..columns.len())
                .map(|index| row.get::<String, _>(index))
                .collect()
        })
        .collect();
    contents.sort();
    contents
}

async fn snapshot(pool: &SqlitePool) -> DatabaseSnapshot {
    let schema =
        sqlx::query_as("SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name")
            .fetch_all(pool)
            .await
            .unwrap();
    let mut tables = vec![];
    for table in table_names(pool).await {
        let contents = table_contents(pool, &table).await;
        tables.push((table, contents));
    }
    DatabaseSnapshot { schema, tables }
}

async fn retained_contents(pool: &SqlitePool) -> Vec<(String, Vec<Vec<String>>)> {
    let mut tables = vec![];
    for table in table_names(pool).await {
        if table == "_sqlx_migrations"
            || table.starts_with("sqlite_")
            || table.starts_with("corp_policy_")
            || table.starts_with("service_path_")
            || table == "ssh_access_checks"
            || table == "server_security_reports"
            || table == "new_server_bandwidth_default"
        {
            continue;
        }
        let contents = table_contents(pool, &table).await;
        tables.push((table, contents));
    }
    tables
}

async fn assert_current_migrations(pool: &SqlitePool) {
    let rows: Vec<(i64, String, bool)> = sqlx::query_as(
        "SELECT version, description, success FROM _sqlx_migrations
         WHERE version BETWEEN 70 AND 72 ORDER BY version",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0], (70, "server traffic limits".into(), true));
    assert_eq!(rows[1], (71, "corp policy".into(), true));
    assert_eq!(rows[2].0, 72);
    assert!(rows[2].2);
    assert_eq!(marker(pool, 70).await.checksum, frozen_checksum());
    let tables = table_names(pool).await;
    for table in [
        "corp_policy_settings",
        "server_traffic_limits",
        "service_path_states",
        "service_path_incidents",
        "ssh_access_checks",
    ] {
        assert!(tables.iter().any(|name| name == table), "missing {table}");
    }
    assert_eq!(reindex_count(pool).await, 0);
    assert!(table_contents(pool, "ssh_access_checks").await.is_empty());
    for table in ["server_security_reports", "new_server_bandwidth_default"] {
        let contents = table_contents(pool, table).await;
        assert!(contents.is_empty(), "unexpected rows in {table}");
    }
}

impl Fixture {
    async fn new() -> Self {
        let f = Self {
            dir: TempDir::new().unwrap(),
        };
        let pool = f.pool().await;
        install_legacy_70(&pool).await;
        sqlx::query(
            "UPDATE _sqlx_migrations SET installed_on = '2026-01-02T03:04:05Z',
             execution_time = 1234567 WHERE version = 70",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO servers (id, address, ssh_user, hoster)
             VALUES (?1, ?2, 'root', 'generic')",
        )
        .bind(server_id().0)
        .bind(server().address)
        .execute(&pool)
        .await
        .unwrap();
        for (index, id) in USERS.iter().enumerate() {
            let expected = user(id);
            sqlx::query(
                "INSERT INTO users
                    (id, uuid, tuic_password, sub_token, disabled, monthly_bandwidth_limit_bytes)
                 VALUES (?1, ?2, ?3, ?4, 0, 987654321)",
            )
            .bind(id)
            .bind(expected.uuid)
            .bind(expected.tuic_password)
            .bind(expected.sub_token)
            .execute(&pool)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO grants (user_id, server_id, client_uuid, wg_octet, granted_at)
                 VALUES (?1, ?2, ?3, ?4, '2026-01-02T03:04:05Z')",
            )
            .bind(id)
            .bind(server_id().0)
            .bind(grant_uuid(index))
            .bind(i64::try_from(index).unwrap() + 17)
            .execute(&pool)
            .await
            .unwrap();
        }
        sqlx::query(
            "INSERT INTO server_secrets (server_id, key, value)
             VALUES (?1, 'fixture.identity.secret', 'fixture-secret-value')",
        )
        .bind(server_id().0)
        .execute(&pool)
        .await
        .unwrap();
        let limit = quota();
        sqlx::query(
            "INSERT INTO server_traffic_limits
                (server_id, limit_bytes, direction, reset_day, warning_pct)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(server_id().0)
        .bind(i64::try_from(limit.limit_bytes).unwrap())
        .bind(limit.direction)
        .bind(i64::from(limit.reset_day))
        .bind(i64::from(limit.warning_pct))
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(marker(&pool, 70).await.checksum, frozen_checksum());
        let tables = table_names(&pool).await;
        assert!(!tables.iter().any(|name| name.starts_with("corp_policy_")));
        assert!(!tables.iter().any(|name| name.starts_with("service_path_")));
        pool.close().await;
        f
    }

    fn path(&self) -> PathBuf {
        self.dir.path().join("inventory.db")
    }

    async fn pool(&self) -> SqlitePool {
        connect(&self.path()).await
    }

    async fn assert_identities(&self, inv: &SqliteInventory) {
        let stored = inv.get_server(&server_id()).await.unwrap().unwrap();
        assert_eq!(stored.id, server_id());
        assert_eq!(stored.address, server().address);
        let grants = inv.users_for_server(&server_id()).await.unwrap();
        assert_eq!(grants.len(), USERS.len());
        for (index, id) in USERS.iter().enumerate() {
            let stored = inv.get_user(&UserId((*id).into())).await.unwrap().unwrap();
            let expected = user(id);
            assert_eq!(stored.uuid, expected.uuid);
            assert_eq!(stored.sub_token, expected.sub_token);
            assert_eq!(stored.tuic_password, expected.tuic_password);
            assert_eq!(stored.disabled, expected.disabled);
            assert_eq!(
                inv.client_uuid_for(&UserId((*id).into()), &server_id())
                    .await
                    .unwrap(),
                Some(grant_uuid(index))
            );
            assert!(grants.iter().any(|peer| peer.id == stored.id));
        }
        assert_eq!(
            inv.get_server_secret(&server_id(), "fixture.identity.secret")
                .await
                .unwrap()
                .as_deref(),
            Some("fixture-secret-value")
        );
    }

    async fn assert_failed_open_unchanged(&self) {
        let pool = self.pool().await;
        let before = snapshot(&pool).await;
        assert!(SqliteInventory::open(&self.path()).await.is_err());
        assert_eq!(snapshot(&pool).await, before);
        assert_eq!(reindex_count(&pool).await, 0);
        pool.close().await;
    }
}

#[tokio::test]
async fn frozen_production_70_upgrades_normally_without_rewriting_any_legacy_data() {
    let f = Fixture::new().await;
    let pool = f.pool().await;
    let before = retained_contents(&pool).await;
    let original_70 = marker(&pool, 70).await;
    pool.close().await;
    let mut upgraded_snapshot = None;
    for _ in 0..3 {
        let inv = SqliteInventory::open(&f.path()).await.unwrap();
        f.assert_identities(&inv).await;
        assert_eq!(
            inv.get_server_traffic_limit(&server_id()).await.unwrap(),
            Some(quota())
        );
        assert!(inv.corp_record().await.unwrap().is_none());
        let pool = f.pool().await;
        assert_current_migrations(&pool).await;
        assert_eq!(marker(&pool, 70).await, original_70);
        assert_eq!(retained_contents(&pool).await, before);
        let current = snapshot(&pool).await;
        if let Some(expected) = &upgraded_snapshot {
            assert_eq!(&current, expected);
        } else {
            upgraded_snapshot = Some(current);
        }
        pool.close().await;
        inv.close().await;
    }
}

#[tokio::test]
async fn current_main_71_upgrades_path_history_preserving_both_published_migration_records() {
    let f = Fixture::new().await;
    let pool = f.pool().await;
    let published = sqlx::migrate!("./migrations");
    let migration = published
        .iter()
        .find(|migration| migration.version == 71)
        .unwrap();
    {
        let mut connection = pool.acquire().await.unwrap();
        connection.apply(migration).await.unwrap();
    }
    let original_70 = marker(&pool, 70).await;
    let original_71 = marker(&pool, 71).await;
    let before = retained_contents(&pool).await;
    pool.close().await;
    let inv = SqliteInventory::open(&f.path()).await.unwrap();
    f.assert_identities(&inv).await;
    let pool = f.pool().await;
    assert_current_migrations(&pool).await;
    assert_eq!(marker(&pool, 70).await, original_70);
    assert_eq!(marker(&pool, 71).await, original_71);
    assert_eq!(retained_contents(&pool).await, before);
    pool.close().await;
    inv.close().await;
}

#[tokio::test]
async fn unknown_production_70_checksum_fails_without_any_schema_or_data_changes() {
    let f = Fixture::new().await;
    let pool = f.pool().await;
    let mut checksum = frozen_checksum();
    *checksum.first_mut().unwrap() ^= 0xff;
    sqlx::query("UPDATE _sqlx_migrations SET checksum = ?1 WHERE version = 70")
        .bind(checksum)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
    f.assert_failed_open_unchanged().await;
}

#[tokio::test]
async fn conflicting_71_metadata_fails_without_reindexing_or_changing_existing_identities() {
    let f = Fixture::new().await;
    let pool = f.pool().await;
    sqlx::query(
        "INSERT INTO _sqlx_migrations
            (version, description, installed_on, success, checksum, execution_time)
         VALUES (71, 'server traffic limits', '2026-01-02T03:04:05Z', 1, ?1, 7654321)",
    )
    .bind(frozen_checksum())
    .execute(&pool)
    .await
    .unwrap();
    pool.close().await;
    f.assert_failed_open_unchanged().await;
}

#[tokio::test]
async fn unsuccessful_production_70_marker_fails_without_history_or_identity_changes() {
    let f = Fixture::new().await;
    let pool = f.pool().await;
    sqlx::query("UPDATE _sqlx_migrations SET success = 0 WHERE version = 70")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
    f.assert_failed_open_unchanged().await;
}

#[tokio::test]
async fn restoring_frozen_production_70_preserves_its_metadata_quotas_and_all_identities() {
    let f = Fixture::new().await;
    let source = f.pool().await;
    let before = retained_contents(&source).await;
    let original_70 = marker(&source, 70).await;
    let snapshot_path = f.dir.path().join("production-format-snapshot.db");
    sqlx::query("VACUUM INTO ?1")
        .bind(snapshot_path.to_str().unwrap())
        .execute(&source)
        .await
        .unwrap();
    source.close().await;
    let restored_dir = TempDir::new().unwrap();
    let destination = restored_dir.path().join("inventory.db");
    assert!(!destination.exists());
    vpnctl_inventory::restore_from(&snapshot_path, &destination)
        .await
        .unwrap();
    let restored_pool = connect(&destination).await;
    assert_current_migrations(&restored_pool).await;
    assert_eq!(marker(&restored_pool, 70).await, original_70);
    assert_eq!(retained_contents(&restored_pool).await, before);
    let restored_snapshot = snapshot(&restored_pool).await;
    restored_pool.close().await;
    for _ in 0..2 {
        let inv = SqliteInventory::open(&destination).await.unwrap();
        f.assert_identities(&inv).await;
        assert_eq!(
            inv.get_server_traffic_limit(&server_id()).await.unwrap(),
            Some(quota())
        );
        let pool = connect(&destination).await;
        assert_eq!(snapshot(&pool).await, restored_snapshot);
        assert_eq!(marker(&pool, 70).await, original_70);
        assert_eq!(reindex_count(&pool).await, 0);
        pool.close().await;
        inv.close().await;
    }
}

#[tokio::test]
async fn fresh_main_inventory_has_published_history_and_can_record_current_tcp_path() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("inventory.db");
    let inv = SqliteInventory::open(&path).await.unwrap();
    inv.add_server(&server()).await.unwrap();
    let round = ServiceQualitySample {
        ts: "2020-01-02T12:00:00Z".parse().unwrap(),
        server_id: server_id(),
        vantage: "Fixture measurement network".into(),
        target_count: 1,
        available_targets: 1,
        attempts: 1,
        successes: 1,
        tcp_rtt_ms: vec![20],
        control_attempts: 0,
        control_successes: 0,
        control_rtt_ms: vec![],
        icmp_attempts: None,
        icmp_successes: None,
        icmp_rtt_ms: None,
    };
    inv.record_service_path(&round, "fixture-network:tcp-population", 120)
        .await
        .unwrap();
    let current = inv
        .current_service_path(&server_id(), round.ts, 120)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current.status, ServicePathStatus::Available);
    assert_eq!(current.vantage, round.vantage);
    assert_eq!(current.checked_at, round.ts);
    assert_eq!(current.last_success_at, Some(round.ts));
    let pool = connect(&path).await;
    assert_current_migrations(&pool).await;
    pool.close().await;
    inv.close().await;
}
