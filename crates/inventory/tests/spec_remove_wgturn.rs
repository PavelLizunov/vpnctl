//! Integration tests for migration `0049_remove_wgturn.sql`.
//!
//! Invariants pinned:
//! 1. Migration audits each actually affected server (active protocols, kernels, or overrides)
//!    exactly once with `actor = 'system'`, `action = 'protocol.remove_wgturn'`, `target = server_id`,
//!    and a payload recording counts of removed entities and retained server secrets.
//! 2. Deletes all `wgturn` grant protocol overrides, `wgturn` server protocols,
//!    and `wgturn` server kernels.
//! 3. Preserves all `wgturn:*` server secrets as rollback material.
//! 4. Preserves all non-WgTurn protocols, kernels, secrets, and overrides.
//! 5. Preserves pre-existing audit log history.
//! 6. Emits zero audit rows on an empty database, on a database without WgTurn,
//!    or on a server with only stale secrets.
//! 7. Respects foreign keys and SQLite constraints.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use tempfile::TempDir;
use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
use vpnctl_inventory::SqliteInventory;

async fn apply_migrations_up_to_0048(pool: &sqlx::SqlitePool) {
    let migrations_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
    let mut entries: Vec<_> = std::fs::read_dir(migrations_dir)
        .expect("read migrations dir")
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            name.ends_with(".sql") && !name.starts_with("0049")
        })
        .collect();

    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let sql = std::fs::read_to_string(entry.path()).expect("read migration file");
        sqlx::raw_sql(&sql)
            .execute(pool)
            .await
            .unwrap_or_else(|e| panic!("failed executing migration {:?}: {e}", entry.path()));
    }
}

async fn apply_migration_0049(pool: &sqlx::SqlitePool) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("migrations")
        .join("0049_remove_wgturn.sql");
    let sql = std::fs::read_to_string(&path).expect("read migration 0049");
    sqlx::raw_sql(&sql)
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("failed executing migration 0049: {e}"));
}

async fn create_raw_pool(db_path: &Path) -> sqlx::SqlitePool {
    use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
    use std::str::FromStr;

    let opts = SqliteConnectOptions::from_str(db_path.to_str().unwrap())
        .unwrap()
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .foreign_keys(true);

    SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .unwrap()
}

#[tokio::test]
async fn migration_0049_removes_wgturn_and_audits_affected_servers_only() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test_migration.db");
    let pool = create_raw_pool(&db_path).await;

    // Apply migrations up to 0048
    apply_migrations_up_to_0048(&pool).await;

    // Seed servers:
    // s1: fully populated with wgturn + non-wgturn
    // s2: non-wgturn only
    // s3: only wgturn:vk_link secret (no wgturn protocol/kernel/override) -> stale secret only, no audit
    // s4: only wgturn protocol
    // s5: only wgturn kernel
    // s6: only wgturn override
    // s7: clean server
    let seed_sql = r#"
        INSERT INTO servers (id, address, ssh_port, ssh_user, hoster) VALUES
            ('s1', '1.1.1.1', 22, 'root', 'generic'),
            ('s2', '2.2.2.2', 22, 'root', 'generic'),
            ('s3', '3.3.3.3', 22, 'root', 'generic'),
            ('s4', '4.4.4.4', 22, 'root', 'generic'),
            ('s5', '5.5.5.5', 22, 'root', 'generic'),
            ('s6', '6.6.6.6', 22, 'root', 'generic'),
            ('s7', '7.7.7.7', 22, 'root', 'generic');

        INSERT INTO users (id, uuid) VALUES
            ('u1', '00000000-0000-0000-0000-000000000001'),
            ('u2', '00000000-0000-0000-0000-000000000002');

        INSERT INTO grants (user_id, server_id) VALUES
            ('u1', 's1'),
            ('u2', 's2'),
            ('u1', 's6');

        INSERT INTO server_protocols (server_id, protocol_id, hidden) VALUES
            ('s1', 'wgturn', 0),
            ('s1', 'vless+reality', 0),
            ('s2', 'tuic-v5', 0),
            ('s4', 'wgturn', 1);

        INSERT INTO server_kernels (server_id, kernel_id) VALUES
            ('s1', 'wgturn'),
            ('s1', 'sing-box'),
            ('s2', 'sing-box'),
            ('s5', 'wgturn');

        INSERT INTO server_secrets (server_id, key, value) VALUES
            ('s1', 'wgturn:server_wg_private', 'privkey'),
            ('s1', 'wgturn:server_wg_public', 'pubkey'),
            ('s1', 'wgturn:vk_link', 'https://vk.com/call/join/123'),
            ('s1', 'reality:short_id', 'abcd'),
            ('s2', 'tuic:token', 'tok123'),
            ('s3', 'wgturn:vk_link', 'https://vk.com/call/join/old');

        INSERT INTO grant_protocol_overrides (user_id, server_id, protocol_id, state) VALUES
            ('u1', 's1', 'wgturn', 'disabled'),
            ('u1', 's1', 'vless+reality', 'disabled'),
            ('u2', 's2', 'tuic-v5', 'disabled'),
            ('u1', 's6', 'wgturn', 'disabled');

        INSERT INTO audit_log (actor, action, target, payload) VALUES
            ('admin', 'server.create', 's1', '{"initial":true}');
    "#;

    sqlx::raw_sql(seed_sql).execute(&pool).await.unwrap();

    // Run migration 0049
    apply_migration_0049(&pool).await;

    // Check audit_log
    #[derive(sqlx::FromRow, Debug)]
    struct AuditRow {
        actor: String,
        action: String,
        target: Option<String>,
        payload: Option<String>,
    }

    let audit_rows: Vec<AuditRow> =
        sqlx::query_as("SELECT actor, action, target, payload FROM audit_log ORDER BY id ASC")
            .fetch_all(&pool)
            .await
            .unwrap();

    // 1 pre-existing row + 4 affected servers (s1, s4, s5, s6) = 5 rows
    assert_eq!(
        audit_rows.len(),
        5,
        "expected 5 audit rows, got {audit_rows:?}"
    );

    // Historical audit row is preserved
    assert_eq!(audit_rows[0].actor, "admin");
    assert_eq!(audit_rows[0].action, "server.create");
    assert_eq!(audit_rows[0].target.as_deref(), Some("s1"));

    // Check affected servers
    let wgturn_audits: Vec<&AuditRow> = audit_rows
        .iter()
        .filter(|r| r.action == "protocol.remove_wgturn")
        .collect();
    assert_eq!(wgturn_audits.len(), 4);

    for r in &wgturn_audits {
        assert_eq!(r.actor, "system");
        let target = r.target.as_deref().unwrap();
        let payload: serde_json::Value =
            serde_json::from_str(r.payload.as_deref().unwrap()).unwrap();

        assert_eq!(payload["server_id"], target);

        match target {
            "s1" => {
                assert_eq!(payload["grant_overrides"], 1);
                assert_eq!(payload["server_protocols"], 1);
                assert_eq!(payload["server_kernels"], 1);
                assert_eq!(payload["retained_server_secrets"], 3);
            }
            "s4" => {
                assert_eq!(payload["grant_overrides"], 0);
                assert_eq!(payload["server_protocols"], 1);
                assert_eq!(payload["server_kernels"], 0);
                assert_eq!(payload["retained_server_secrets"], 0);
            }
            "s5" => {
                assert_eq!(payload["grant_overrides"], 0);
                assert_eq!(payload["server_protocols"], 0);
                assert_eq!(payload["server_kernels"], 1);
                assert_eq!(payload["retained_server_secrets"], 0);
            }
            "s6" => {
                assert_eq!(payload["grant_overrides"], 1);
                assert_eq!(payload["server_protocols"], 0);
                assert_eq!(payload["server_kernels"], 0);
                assert_eq!(payload["retained_server_secrets"], 0);
            }
            other => panic!("unexpected audited server: {other}"),
        }
    }

    // Unaffected servers (s2, s7) and stale-secret-only servers (s3) must NOT be audited
    assert!(
        wgturn_audits
            .iter()
            .all(|r| r.target.as_deref() != Some("s2")
                && r.target.as_deref() != Some("s3")
                && r.target.as_deref() != Some("s7")),
        "s2, s3, and s7 must not be audited"
    );

    // Verify active WgTurn bindings are deleted
    let wgturn_protocols: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM server_protocols WHERE protocol_id = 'wgturn'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(wgturn_protocols.0, 0);

    let wgturn_kernels: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM server_kernels WHERE kernel_id = 'wgturn'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(wgturn_kernels.0, 0);

    let wgturn_overrides: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM grant_protocol_overrides WHERE protocol_id = 'wgturn'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(wgturn_overrides.0, 0);

    // Verify wgturn:* secrets ARE PRESERVED as rollback material
    let wgturn_secrets: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM server_secrets WHERE key LIKE 'wgturn:%'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(wgturn_secrets.0, 4);

    // Verify non-WgTurn data is preserved
    #[derive(sqlx::FromRow, Debug, PartialEq, Eq)]
    struct ProtoRow {
        server_id: String,
        protocol_id: String,
    }
    let remaining_protocols: Vec<ProtoRow> = sqlx::query_as(
        "SELECT server_id, protocol_id FROM server_protocols ORDER BY server_id, protocol_id",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        remaining_protocols,
        vec![
            ProtoRow {
                server_id: "s1".into(),
                protocol_id: "vless+reality".into(),
            },
            ProtoRow {
                server_id: "s2".into(),
                protocol_id: "tuic-v5".into(),
            },
        ]
    );

    #[derive(sqlx::FromRow, Debug, PartialEq, Eq)]
    struct KernelRow {
        server_id: String,
        kernel_id: String,
    }
    let remaining_kernels: Vec<KernelRow> = sqlx::query_as(
        "SELECT server_id, kernel_id FROM server_kernels ORDER BY server_id, kernel_id",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        remaining_kernels,
        vec![
            KernelRow {
                server_id: "s1".into(),
                kernel_id: "sing-box".into(),
            },
            KernelRow {
                server_id: "s2".into(),
                kernel_id: "sing-box".into(),
            },
        ]
    );

    #[derive(sqlx::FromRow, Debug, PartialEq, Eq)]
    struct SecretRow {
        server_id: String,
        key: String,
    }
    let remaining_secrets: Vec<SecretRow> =
        sqlx::query_as("SELECT server_id, key FROM server_secrets ORDER BY server_id, key")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(
        remaining_secrets,
        vec![
            SecretRow {
                server_id: "s1".into(),
                key: "reality:short_id".into(),
            },
            SecretRow {
                server_id: "s1".into(),
                key: "wgturn:server_wg_private".into(),
            },
            SecretRow {
                server_id: "s1".into(),
                key: "wgturn:server_wg_public".into(),
            },
            SecretRow {
                server_id: "s1".into(),
                key: "wgturn:vk_link".into(),
            },
            SecretRow {
                server_id: "s2".into(),
                key: "tuic:token".into(),
            },
            SecretRow {
                server_id: "s3".into(),
                key: "wgturn:vk_link".into(),
            },
        ]
    );

    #[derive(sqlx::FromRow, Debug, PartialEq, Eq)]
    struct OverrideRow {
        user_id: String,
        server_id: String,
        protocol_id: String,
    }
    let remaining_overrides: Vec<OverrideRow> = sqlx::query_as(
        "SELECT user_id, server_id, protocol_id FROM grant_protocol_overrides ORDER BY user_id, protocol_id",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        remaining_overrides,
        vec![
            OverrideRow {
                user_id: "u1".into(),
                server_id: "s1".into(),
                protocol_id: "vless+reality".into(),
            },
            OverrideRow {
                user_id: "u2".into(),
                server_id: "s2".into(),
                protocol_id: "tuic-v5".into(),
            },
        ]
    );

    // Foreign key check
    let fk_violations: Vec<(String,)> = sqlx::query_as("PRAGMA foreign_key_check")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert!(
        fk_violations.is_empty(),
        "foreign key violations detected: {fk_violations:?}"
    );

    pool.close().await;
}

#[tokio::test]
async fn migration_0049_no_audit_on_empty_db() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("empty.db");

    let inv = SqliteInventory::open(&db_path).await.unwrap();

    let count = inv.recent_audit(100).await.unwrap().len();
    assert_eq!(count, 0, "empty database must have 0 audit log entries");

    inv.close().await;
}

#[tokio::test]
async fn migration_0049_no_audit_on_db_without_wgturn() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("no_wgturn.db");
    let pool = create_raw_pool(&db_path).await;

    apply_migrations_up_to_0048(&pool).await;

    let seed_sql = r#"
        INSERT INTO servers (id, address, ssh_port, ssh_user, hoster) VALUES
            ('s1', '1.1.1.1', 22, 'root', 'generic');
        INSERT INTO users (id, uuid) VALUES
            ('u1', '00000000-0000-0000-0000-000000000001');
        INSERT INTO grants (user_id, server_id) VALUES
            ('u1', 's1');
        INSERT INTO server_protocols (server_id, protocol_id, hidden) VALUES
            ('s1', 'vless+reality', 0);
        INSERT INTO server_kernels (server_id, kernel_id) VALUES
            ('s1', 'sing-box');
        INSERT INTO server_secrets (server_id, key, value) VALUES
            ('s1', 'reality:short_id', '1234');
        INSERT INTO grant_protocol_overrides (user_id, server_id, protocol_id, state) VALUES
            ('u1', 's1', 'vless+reality', 'disabled');
        INSERT INTO audit_log (actor, action, target, payload) VALUES
            ('admin', 'server.create', 's1', '{}');
    "#;
    sqlx::raw_sql(seed_sql).execute(&pool).await.unwrap();

    apply_migration_0049(&pool).await;

    let audit_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM audit_log WHERE action = 'protocol.remove_wgturn'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        audit_count.0, 0,
        "no-wgturn database must emit zero remove_wgturn audit rows"
    );

    let total_audit: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_log")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(total_audit.0, 1, "pre-existing audit row must be preserved");

    pool.close().await;
}

#[tokio::test]
async fn sqlite_inventory_open_and_crud_works_post_migration() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("inventory_crud.db");

    let inv = SqliteInventory::open(&db_path).await.unwrap();

    let srv = Server {
        id: ServerId("srv1".into()),
        address: "192.0.2.1".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("vless+reality".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    };
    inv.add_server(&srv).await.unwrap();

    let usr = User {
        id: UserId("user1".into()),
        uuid: "11111111-1111-1111-1111-111111111111".into(),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    };
    inv.add_user(&usr).await.unwrap();
    inv.grant(&usr.id, &srv.id).await.unwrap();

    let visible = inv
        .visible_protocols_for_subscription(&usr.id, &srv.id)
        .await
        .unwrap();
    assert_eq!(visible, vec![ProtocolId("vless+reality".into())]);

    inv.close().await;
}
