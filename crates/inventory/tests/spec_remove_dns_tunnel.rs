//! Integration tests for migration `0050_remove_dns_tunnel.sql`.
//!
//! Invariants pinned:
//! 1. Migration audits each actually affected server (active protocols, kernels, or overrides)
//!    exactly once with `actor = 'system'`, `action = 'protocol.remove_dns_tunnel'`, `target = server_id`,
//!    and a payload recording counts of removed entities and retained server secrets.
//! 2. Deletes all `dns-tunnel` grant protocol overrides, `dns-tunnel` server protocols,
//!    and `dns-tunnel` server kernels.
//! 3. Preserves all `dns-tunnel:*` server secrets as rollback material.
//! 4. Preserves all non-DNS protocols, kernels, secrets, and overrides.
//! 5. Preserves pre-existing audit log history.
//! 6. Emits zero audit rows on an empty database, on a database without dns-tunnel,
//!    or on a server with only stale secrets.
//! 7. Respects foreign keys and SQLite constraints.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use tempfile::TempDir;
use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
use vpnctl_inventory::SqliteInventory;

async fn apply_migrations_up_to_0049(pool: &sqlx::SqlitePool) {
    let migrations_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
    let mut entries: Vec<_> = std::fs::read_dir(migrations_dir)
        .expect("read migrations dir")
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            name.ends_with(".sql") && name.as_str() < "0050"
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

async fn apply_migration_0050(pool: &sqlx::SqlitePool) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("migrations")
        .join("0050_remove_dns_tunnel.sql");
    let sql = std::fs::read_to_string(&path).expect("read migration 0050");
    sqlx::raw_sql(&sql)
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("failed executing migration 0050: {e}"));
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
async fn migration_0050_removes_dns_tunnel_and_audits_affected_servers_only() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test_migration.db");
    let pool = create_raw_pool(&db_path).await;

    // Apply migrations up to 0049
    apply_migrations_up_to_0049(&pool).await;

    // Seed servers:
    // s1: fully populated with dns-tunnel + non-dns
    // s2: non-dns only
    // s3: only dns-tunnel:domain secret (no dns-tunnel protocol/kernel/override) -> stale secret only, no audit
    // s4: only dns-tunnel protocol
    // s5: only dns-tunnel kernel
    // s6: only dns-tunnel override
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
            ('s1', 'dns-tunnel', 0),
            ('s1', 'vless+reality', 0),
            ('s2', 'tuic-v5', 0),
            ('s4', 'dns-tunnel', 1);

        INSERT INTO server_kernels (server_id, kernel_id) VALUES
            ('s1', 'dns-tunnel'),
            ('s1', 'sing-box'),
            ('s2', 'sing-box'),
            ('s5', 'dns-tunnel');

        INSERT INTO server_secrets (server_id, key, value) VALUES
            ('s1', 'dns-tunnel:domain', 'dt.example.com'),
            ('s1', 'dns-tunnel:fingerprint', 'AB:CD:EF'),
            ('s1', 'dns-tunnel:authoritative', '1'),
            ('s1', 'reality:short_id', 'abcd'),
            ('s2', 'tuic:token', 'tok123'),
            ('s3', 'dns-tunnel:domain', 'old.example.com');

        INSERT INTO grant_protocol_overrides (user_id, server_id, protocol_id, state) VALUES
            ('u1', 's1', 'dns-tunnel', 'disabled'),
            ('u1', 's1', 'vless+reality', 'disabled'),
            ('u2', 's2', 'tuic-v5', 'disabled'),
            ('u1', 's6', 'dns-tunnel', 'disabled');

        INSERT INTO audit_log (actor, action, target, payload) VALUES
            ('admin', 'server.create', 's1', '{"initial":true}');
    "#;

    sqlx::raw_sql(seed_sql).execute(&pool).await.unwrap();

    // Run migration 0050
    apply_migration_0050(&pool).await;

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
    let dns_tunnel_audits: Vec<&AuditRow> = audit_rows
        .iter()
        .filter(|r| r.action == "protocol.remove_dns_tunnel")
        .collect();
    assert_eq!(dns_tunnel_audits.len(), 4);

    for r in &dns_tunnel_audits {
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
        dns_tunnel_audits
            .iter()
            .all(|r| r.target.as_deref() != Some("s2")
                && r.target.as_deref() != Some("s3")
                && r.target.as_deref() != Some("s7")),
        "s2, s3, and s7 must not be audited"
    );

    // Verify active dns-tunnel bindings are deleted
    let dns_tunnel_protocols: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM server_protocols WHERE protocol_id = 'dns-tunnel'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(dns_tunnel_protocols.0, 0);

    let dns_tunnel_kernels: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM server_kernels WHERE kernel_id = 'dns-tunnel'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(dns_tunnel_kernels.0, 0);

    let dns_tunnel_overrides: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM grant_protocol_overrides WHERE protocol_id = 'dns-tunnel'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(dns_tunnel_overrides.0, 0);

    // Verify dns-tunnel:* secrets ARE PRESERVED as rollback material
    let dns_tunnel_secrets: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM server_secrets WHERE key LIKE 'dns-tunnel:%'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(dns_tunnel_secrets.0, 4);

    // Verify non-DNS data is preserved
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
                key: "dns-tunnel:authoritative".into(),
            },
            SecretRow {
                server_id: "s1".into(),
                key: "dns-tunnel:domain".into(),
            },
            SecretRow {
                server_id: "s1".into(),
                key: "dns-tunnel:fingerprint".into(),
            },
            SecretRow {
                server_id: "s1".into(),
                key: "reality:short_id".into(),
            },
            SecretRow {
                server_id: "s2".into(),
                key: "tuic:token".into(),
            },
            SecretRow {
                server_id: "s3".into(),
                key: "dns-tunnel:domain".into(),
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
async fn migration_0050_no_audit_on_empty_db() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("empty.db");

    let inv = SqliteInventory::open(&db_path).await.unwrap();

    let count = inv.recent_audit(100).await.unwrap().len();
    assert_eq!(count, 0, "empty database must have 0 audit log entries");

    inv.close().await;
}

#[tokio::test]
async fn migration_0050_no_audit_on_db_without_dns_tunnel() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("no_dns_tunnel.db");
    let pool = create_raw_pool(&db_path).await;

    apply_migrations_up_to_0049(&pool).await;

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

    apply_migration_0050(&pool).await;

    let audit_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'protocol.remove_dns_tunnel'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        audit_count.0, 0,
        "no-dns database must emit zero remove_dns_tunnel audit rows"
    );

    let total_audit: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_log")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(total_audit.0, 1, "pre-existing audit row must be preserved");

    pool.close().await;
}

#[tokio::test]
async fn sqlite_inventory_open_applies_embedded_0050_and_crud_works() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("inventory_applied_0050.db");

    // 1. Create DB and apply migrations 0001..=0049 via sqlx::migrate::Migrator
    // so _sqlx_migrations is properly tracked
    {
        let migrations_temp_dir = TempDir::new().unwrap();
        let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
        for entry in std::fs::read_dir(src_dir).unwrap().filter_map(|e| e.ok()) {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".sql") && name.as_str() < "0050" {
                std::fs::copy(entry.path(), migrations_temp_dir.path().join(&name)).unwrap();
            }
        }

        let pool = create_raw_pool(&db_path).await;
        let migrator = sqlx::migrate::Migrator::new(migrations_temp_dir.path())
            .await
            .unwrap();
        migrator.run(&pool).await.unwrap();

        let seed_sql = r#"
            INSERT INTO servers (id, address, ssh_port, ssh_user, hoster) VALUES
                ('s_dns', '10.0.0.1', 22, 'root', 'generic');
            INSERT INTO users (id, uuid) VALUES
                ('u_dns', '00000000-0000-0000-0000-000000000099');
            INSERT INTO grants (user_id, server_id) VALUES
                ('u_dns', 's_dns');
            INSERT INTO server_protocols (server_id, protocol_id, hidden) VALUES
                ('s_dns', 'dns-tunnel', 0),
                ('s_dns', 'vless+reality', 0);
            INSERT INTO server_kernels (server_id, kernel_id) VALUES
                ('s_dns', 'dns-tunnel'),
                ('s_dns', 'sing-box');
            INSERT INTO server_secrets (server_id, key, value) VALUES
                ('s_dns', 'dns-tunnel:domain', 'dt.example.com'),
                ('s_dns', 'reality:short_id', 'abcd');
            INSERT INTO grant_protocol_overrides (user_id, server_id, protocol_id, state) VALUES
                ('u_dns', 's_dns', 'dns-tunnel', 'disabled');
        "#;
        sqlx::raw_sql(seed_sql).execute(&pool).await.unwrap();
        pool.close().await;
    }

    // 2. Open via SqliteInventory::open — runs embedded MIGRATOR including 0050
    let inv = SqliteInventory::open(&db_path).await.unwrap();

    // Verify dns-tunnel was removed from active protocols/kernels
    let server = inv
        .get_server(&ServerId("s_dns".into()))
        .await
        .unwrap()
        .expect("server exists");
    assert_eq!(
        server.enabled_protocols,
        vec![ProtocolId("vless+reality".into())]
    );
    assert_eq!(server.kernels, vec![KernelId("sing-box".into())]);

    // Retained secret is preserved
    let secret = inv
        .get_server_secret(&ServerId("s_dns".into()), "dns-tunnel:domain")
        .await
        .unwrap();
    assert_eq!(secret.as_deref(), Some("dt.example.com"));

    // Verify audit entry
    let audit = inv.audit_for_server("s_dns", 10).await.unwrap();
    let dt_audit = audit
        .iter()
        .find(|a| a.action == "protocol.remove_dns_tunnel")
        .expect("remove_dns_tunnel audit row exists");
    assert_eq!(dt_audit.actor, "system");
    let payload = dt_audit.payload.as_ref().unwrap();
    assert_eq!(payload["grant_overrides"], 1);
    assert_eq!(payload["server_protocols"], 1);
    assert_eq!(payload["server_kernels"], 1);
    assert_eq!(payload["retained_server_secrets"], 1);

    // 3. Perform CRUD operations to ensure DB is fully operational
    let new_srv = Server {
        id: ServerId("srv2".into()),
        address: "192.0.2.2".into(),
        ssh_port: 2222,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("vless+reality".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    };
    inv.add_server(&new_srv).await.unwrap();

    let new_usr = User {
        id: UserId("user2".into()),
        uuid: "22222222-2222-2222-2222-222222222222".into(),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    };
    inv.add_user(&new_usr).await.unwrap();

    let fetched_srv = inv.get_server(&new_srv.id).await.unwrap().unwrap();
    assert_eq!(fetched_srv.id, new_srv.id);

    let fetched_usr = inv.get_user(&new_usr.id).await.unwrap().unwrap();
    assert_eq!(fetched_usr.id, new_usr.id);

    inv.grant(&new_usr.id, &new_srv.id).await.unwrap();
    let visible = inv
        .visible_protocols_for_subscription(&new_usr.id, &new_srv.id)
        .await
        .unwrap();
    assert_eq!(visible, vec![ProtocolId("vless+reality".into())]);

    inv.set_server_display_name(&new_srv.id, Some("New Server"))
        .await
        .unwrap();
    assert_eq!(
        inv.server_display_name(&new_srv.id)
            .await
            .unwrap()
            .as_deref(),
        Some("New Server")
    );

    inv.revoke(&new_usr.id, &new_srv.id).await.unwrap();
    inv.remove_user(&new_usr.id).await.unwrap();
    assert!(inv.get_user(&new_usr.id).await.unwrap().is_none());
    inv.remove_server(&new_srv.id).await.unwrap();
    assert!(inv.get_server(&new_srv.id).await.unwrap().is_none());

    inv.close().await;
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
