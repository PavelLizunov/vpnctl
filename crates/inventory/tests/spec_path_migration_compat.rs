#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::PathBuf;

use sqlx::{Row, SqlitePool};
use tempfile::TempDir;
use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
use vpnctl_inventory::{ServerTrafficLimit, SqliteInventory};

const REINDEX_ACTION: &str = "migration.server_traffic.reindex";
const USERS: [&str; 3] = ["fixture-alpha", "fixture-beta", "fixture-gamma"];

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
    corporate_70: MigrationMarker,
    traffic_71: MigrationMarker,
    path_72: MigrationMarker,
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
            || table == "audit_log"
            || table.starts_with("sqlite_")
            || table.starts_with("corp_policy_")
            || table.starts_with("service_path_")
        {
            continue;
        }
        let contents = table_contents(pool, &table).await;
        tables.push((table, contents));
    }
    tables
}

impl Fixture {
    async fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let inv = SqliteInventory::open(&dir.path().join("inventory.db"))
            .await
            .unwrap();
        inv.add_server(&server()).await.unwrap();
        for (index, id) in USERS.iter().enumerate() {
            inv.add_user(&user(id)).await.unwrap();
            inv.grant(&UserId((*id).into()), &server_id())
                .await
                .unwrap();
            inv.set_grant_client_uuid(&UserId((*id).into()), &server_id(), &grant_uuid(index))
                .await
                .unwrap();
        }
        inv.set_server_secret(
            &server_id(),
            "fixture.identity.secret",
            "fixture-secret-value",
        )
        .await
        .unwrap();
        inv.set_server_traffic_limit(&server_id(), Some(&quota()), "spec-operator")
            .await
            .unwrap();
        inv.close().await;
        let pool = Self::pool_at(&dir).await;
        let corporate_70 = marker(&pool, 70).await;
        let traffic_71 = marker(&pool, 71).await;
        let path_72 = marker(&pool, 72).await;
        assert_eq!(traffic_71.description, "server traffic limits");
        assert!(traffic_71.success);
        assert_eq!(reindex_count(&pool).await, 0);
        pool.close().await;
        Self {
            dir,
            corporate_70,
            traffic_71,
            path_72,
        }
    }

    fn path(&self) -> PathBuf {
        self.dir.path().join("inventory.db")
    }

    async fn pool_at(dir: &TempDir) -> SqlitePool {
        let pool = SqlitePool::connect(&format!(
            "sqlite://{}",
            dir.path().join("inventory.db").display()
        ))
        .await
        .unwrap();
        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&pool)
            .await
            .unwrap();
        pool
    }

    async fn pool(&self) -> SqlitePool {
        Self::pool_at(&self.dir).await
    }

    async fn remove_path_schema(pool: &SqlitePool) {
        sqlx::raw_sql(
            "DROP TABLE service_path_states;
             DROP TABLE service_path_incidents;
             DELETE FROM _sqlx_migrations WHERE version = 72;",
        )
        .execute(pool)
        .await
        .unwrap();
    }

    async fn legacy(&self, keep_collision: bool) {
        let pool = self.pool().await;
        Self::remove_path_schema(&pool).await;
        sqlx::raw_sql(
            "DROP TRIGGER corp_bound_user_deleted;
             DROP TRIGGER corp_bound_user_disabled;
             DROP TABLE corp_policy_sessions;
             DROP TABLE corp_policy_egress;
             DROP TABLE corp_policy_revisions;
             DROP TABLE corp_policy_settings;
             DELETE FROM _sqlx_migrations WHERE version = 70;",
        )
        .execute(&pool)
        .await
        .unwrap();
        if keep_collision {
            sqlx::query(
                "INSERT INTO _sqlx_migrations
                    (version, description, installed_on, success, checksum, execution_time)
                 SELECT 70, description, installed_on, success, checksum, execution_time
                 FROM _sqlx_migrations WHERE version = 71",
            )
            .execute(&pool)
            .await
            .unwrap();
        } else {
            sqlx::query("UPDATE _sqlx_migrations SET version = 70 WHERE version = 71")
                .execute(&pool)
                .await
                .unwrap();
        }
        let legacy = marker(&pool, 70).await;
        let mut expected = self.traffic_71.clone();
        expected.version = 70;
        assert_eq!(legacy, expected);
        pool.close().await;
    }

    async fn main_format(&self) {
        let pool = self.pool().await;
        Self::remove_path_schema(&pool).await;
        sqlx::raw_sql(
            "DROP TABLE server_traffic_limits;
             DELETE FROM _sqlx_migrations WHERE version = 71;",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(marker(&pool, 70).await, self.corporate_70);
        pool.close().await;
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

    async fn assert_current_migrations(&self, pool: &SqlitePool) {
        for expected in [&self.corporate_70, &self.traffic_71, &self.path_72] {
            let actual = marker(pool, expected.version).await;
            assert_eq!(actual.description, expected.description);
            assert_eq!(actual.checksum, expected.checksum);
            assert!(actual.success);
        }
        let tables = table_names(pool).await;
        for table in [
            "corp_policy_settings",
            "server_traffic_limits",
            "service_path_states",
            "service_path_incidents",
        ] {
            assert!(tables.iter().any(|name| name == table), "missing {table}");
        }
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
async fn legacy_production_70_moves_once_preserving_quotas_and_all_existing_identities() {
    let f = Fixture::new().await;
    f.legacy(false).await;
    let pool = f.pool().await;
    let before = retained_contents(&pool).await;
    let legacy = marker(&pool, 70).await;
    let original_audits = table_contents(&pool, "audit_log").await.len();
    pool.close().await;

    for _ in 0..3 {
        let inv = SqliteInventory::open(&f.path()).await.unwrap();
        f.assert_identities(&inv).await;
        assert_eq!(
            inv.get_server_traffic_limit(&server_id()).await.unwrap(),
            Some(quota())
        );
        let pool = f.pool().await;
        f.assert_current_migrations(&pool).await;
        let mut moved = legacy.clone();
        moved.version = 71;
        assert_eq!(marker(&pool, 71).await, moved);
        assert_eq!(retained_contents(&pool).await, before);
        assert_eq!(reindex_count(&pool).await, 1);
        assert_eq!(
            table_contents(&pool, "audit_log").await.len(),
            original_audits + 1
        );
        pool.close().await;
        inv.close().await;
    }
}

#[tokio::test]
async fn main_format_70_applies_normal_migrations_without_a_compatibility_audit() {
    let f = Fixture::new().await;
    f.main_format().await;
    for _ in 0..2 {
        let inv = SqliteInventory::open(&f.path()).await.unwrap();
        f.assert_identities(&inv).await;
        assert_eq!(
            inv.get_server_traffic_limit(&server_id()).await.unwrap(),
            None
        );
        let pool = f.pool().await;
        f.assert_current_migrations(&pool).await;
        assert_eq!(marker(&pool, 70).await, f.corporate_70);
        assert_eq!(reindex_count(&pool).await, 0);
        pool.close().await;
        inv.close().await;
    }
}

#[tokio::test]
async fn legacy_marker_with_an_unknown_checksum_fails_without_any_schema_or_data_changes() {
    let f = Fixture::new().await;
    f.legacy(false).await;
    let pool = f.pool().await;
    let mut checksum = f.traffic_71.checksum.clone();
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
async fn legacy_70_and_existing_71_collision_fails_without_any_schema_or_data_changes() {
    let f = Fixture::new().await;
    f.legacy(true).await;
    f.assert_failed_open_unchanged().await;
}

#[tokio::test]
async fn matching_traffic_checksum_with_wrong_description_is_not_a_recognized_legacy_marker() {
    let f = Fixture::new().await;
    f.legacy(false).await;
    let pool = f.pool().await;
    sqlx::query(
        "UPDATE _sqlx_migrations SET description = 'unknown legacy feature' WHERE version = 70",
    )
    .execute(&pool)
    .await
    .unwrap();
    pool.close().await;
    f.assert_failed_open_unchanged().await;
}

#[tokio::test]
async fn unsuccessful_legacy_marker_is_not_reindexed() {
    let f = Fixture::new().await;
    f.legacy(false).await;
    let pool = f.pool().await;
    sqlx::query("UPDATE _sqlx_migrations SET success = 0 WHERE version = 70")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
    f.assert_failed_open_unchanged().await;
}

#[tokio::test]
async fn restoring_a_production_format_snapshot_reindexes_once_and_preserves_all_identities() {
    let f = Fixture::new().await;
    f.legacy(false).await;
    let source = f.pool().await;
    let before = retained_contents(&source).await;
    let mut moved = marker(&source, 70).await;
    moved.version = 71;
    let original_audits = table_contents(&source, "audit_log").await.len();
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
    let restored_pool = Fixture::pool_at(&restored_dir).await;
    f.assert_current_migrations(&restored_pool).await;
    assert_eq!(marker(&restored_pool, 71).await, moved);
    assert_eq!(retained_contents(&restored_pool).await, before);
    assert_eq!(reindex_count(&restored_pool).await, 1);
    assert_eq!(
        table_contents(&restored_pool, "audit_log").await.len(),
        original_audits + 1
    );
    restored_pool.close().await;

    for _ in 0..2 {
        let inv = SqliteInventory::open(&destination).await.unwrap();
        f.assert_identities(&inv).await;
        assert_eq!(
            inv.get_server_traffic_limit(&server_id()).await.unwrap(),
            Some(quota())
        );
        let pool = Fixture::pool_at(&restored_dir).await;
        assert_eq!(marker(&pool, 71).await, moved);
        assert_eq!(reindex_count(&pool).await, 1);
        assert_eq!(retained_contents(&pool).await, before);
        assert_eq!(
            table_contents(&pool, "audit_log").await.len(),
            original_audits + 1
        );
        pool.close().await;
        inv.close().await;
    }
}
