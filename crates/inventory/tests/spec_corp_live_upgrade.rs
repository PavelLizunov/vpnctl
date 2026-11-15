#[path = "support/legacy_70.rs"]
mod legacy_70;

#[allow(clippy::unwrap_used, clippy::expect_used)]
mod live_upgrade {
    use std::path::Path;

    use sqlx::{
        SqlitePool,
        sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    };
    use vpnctl_core::{ServerId, UserId};
    use vpnctl_inventory::{
        CorpCredentials, CorpReaderToken, CorpSetup, CorpSigningKey, SqliteInventory,
    };

    use super::legacy_70::{frozen_checksum, install_legacy_70};

    const USER: &str = "synthetic-corp-user";
    const SERVER: &str = "synthetic-legacy-server";

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

    async fn legacy_70(path: &Path) -> SqlitePool {
        let pool = connect(path).await;
        install_legacy_70(&pool).await;

        sqlx::raw_sql(
            "INSERT INTO users (id, uuid, sub_token, disabled, monthly_bandwidth_limit_bytes) \
             VALUES ('synthetic-corp-user', '11111111-2222-4333-8444-555555555555', \
                     'synthetic-legacy-subscription-token-unchanged', 0, 987654321); \
             INSERT INTO servers (id, address, ssh_user, hoster) \
             VALUES ('synthetic-legacy-server', '192.0.2.71', 'root', 'generic'); \
             INSERT INTO grants (user_id, server_id, client_uuid, wg_octet, granted_at) \
             VALUES ('synthetic-corp-user', 'synthetic-legacy-server', \
                     'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', 17, '2026-01-02T03:04:05Z'); \
             INSERT INTO server_traffic_limits \
             (server_id, limit_bytes, direction, reset_day, warning_pct) \
             VALUES ('synthetic-legacy-server', 1234567890123, 'both', 31, 87); \
             INSERT INTO vpn_connection_stats \
             (ts, server_id, user_id, upload_bytes, download_bytes, active_connections) \
             VALUES ('2026-01-02T03:04:05Z', 'synthetic-legacy-server', \
                     'synthetic-corp-user', 12345, 67890, 3);",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM sqlite_master WHERE name = 'corp_policy_settings'"
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            0
        );
        pool
    }

    async fn legacy_rows(pool: &SqlitePool) -> Vec<String> {
        let mut rows = Vec::new();
        for query in [
            "SELECT json_object('id', id, 'uuid', uuid, 'token', sub_token, \
             'disabled', disabled, 'limit', monthly_bandwidth_limit_bytes, \
             'threshold', traffic_alert_threshold_pct, 'created', created_at) FROM users ORDER BY id",
            "SELECT json_object('id', id, 'address', address, 'port', ssh_port, \
             'user', ssh_user, 'hoster', hoster, 'created', created_at, 'updated', updated_at) \
             FROM servers ORDER BY id",
            "SELECT json_object('user', user_id, 'server', server_id, 'uuid', client_uuid, \
             'octet', wg_octet, 'created', created_at, 'granted', granted_at) \
             FROM grants ORDER BY user_id, server_id",
            "SELECT json_object('server', server_id, 'limit', limit_bytes, 'direction', direction, \
             'day', reset_day, 'warning', warning_pct) FROM server_traffic_limits ORDER BY server_id",
            "SELECT json_object('ts', ts, 'server', server_id, 'user', user_id, \
             'up', upload_bytes, 'down', download_bytes, 'active', active_connections) \
             FROM vpn_connection_stats ORDER BY ts, server_id, user_id",
        ] {
            rows.extend(
                sqlx::query_scalar::<_, String>(query)
                    .fetch_all(pool)
                    .await
                    .unwrap(),
            );
        }
        rows
    }

    async fn assert_migration_boundary(pool: &SqlitePool) {
        let migrations: Vec<(i64, bool, Vec<u8>)> = sqlx::query_as(
            "SELECT version, success, checksum FROM _sqlx_migrations \
             WHERE version BETWEEN 70 AND 71 ORDER BY version",
        )
        .fetch_all(pool)
        .await
        .unwrap();
        assert_eq!(migrations.len(), 2);
        assert_eq!(migrations[0], (70, true, frozen_checksum()));
        assert_eq!(migrations[1].0, 71);
        assert!(migrations[1].1);
        // These are the frozen production quota columns, not inferred Corp schema.
        sqlx::query(
            "SELECT server_id, limit_bytes, direction, reset_day, warning_pct \
             FROM server_traffic_limits LIMIT 0",
        )
        .execute(pool)
        .await
        .unwrap();
        let bindings: i64 = sqlx::query_scalar("SELECT count(*) FROM corp_policy_settings")
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(bindings, 0);
    }

    fn setup() -> CorpSetup {
        CorpSetup {
            user_id: UserId(USER.into()),
            policy_id: "synthetic-policy".into(),
            credentials: CorpCredentials {
                password_phc: "$argon2id$v=19$m=65536,t=3,p=1$c3ludGhldGlj$c3ludGhldGlj".into(),
                reader_tokens: vec![CorpReaderToken {
                    id: "synthetic-reader".into(),
                    token: "synthetic-reader-token-01234567890123456789".into(),
                }],
                signing_keys: vec![CorpSigningKey {
                    id: "synthetic-key".into(),
                    pkcs8: "c3ludGhldGljLXByaXZhdGU=".into(),
                    spki: "c3ludGhldGljLXB1YmxpYw==".into(),
                }],
                active_key_id: "synthetic-key".into(),
            },
        }
    }

    #[tokio::test]
    async fn legacy_70_upgrade_adds_unbound_corp_without_changing_legacy_data() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("legacy.db");
        let pool = legacy_70(&path).await;
        let before = legacy_rows(&pool).await;
        assert_eq!(before.len(), 5);
        let inventory = SqliteInventory::open(&path).await.unwrap();
        assert!(inventory.corp_record().await.unwrap().is_none());
        assert_migration_boundary(&pool).await;
        assert_eq!(legacy_rows(&pool).await, before);
        let user = inventory
            .get_user(&UserId(USER.into()))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            user.sub_token.as_deref(),
            Some("synthetic-legacy-subscription-token-unchanged")
        );
        let quota = inventory
            .get_server_traffic_limit(&ServerId(SERVER.into()))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(quota.limit_bytes, 1234567890123);
        assert_eq!(quota.direction, "both");
        assert_eq!((quota.reset_day, quota.warning_pct), (31, 87));
        pool.close().await;
    }

    #[tokio::test]
    async fn fresh_open_installs_both_production_quota_and_unbound_corp_migrations() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("fresh.db");
        let inventory = SqliteInventory::open(&path).await.unwrap();
        assert!(inventory.corp_record().await.unwrap().is_none());
        let pool = connect(&path).await;
        assert_migration_boundary(&pool).await;
        pool.close().await;
    }

    #[tokio::test]
    async fn upgraded_corp_setup_starts_disabled_at_revision_zero_and_survives_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("reopen.db");
        let pool = legacy_70(&path).await;
        let before = legacy_rows(&pool).await;
        let inventory = SqliteInventory::open(&path).await.unwrap();
        assert_migration_boundary(&pool).await;
        let input = setup();
        let status = inventory.create_corp(&input, "spec-test").await.unwrap();
        assert!(!status.enabled);
        assert_eq!(status.revision, 0);
        assert_eq!((status.auth_generation, status.config_version), (1, 1));
        assert_eq!(status.user_id, UserId(USER.into()));
        assert_eq!(status.policy_id, input.policy_id);
        assert_eq!(status.active_key_id, input.credentials.active_key_id);
        assert!(inventory.corp_verified_egress().await.unwrap().is_empty());
        assert!(inventory.corp_history(100).await.unwrap().is_empty());
        let history_before: Vec<(i64, Vec<u8>)> =
            sqlx::query_as("SELECT version, checksum FROM _sqlx_migrations ORDER BY version")
                .fetch_all(&pool)
                .await
                .unwrap();
        let audits_before: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log")
            .fetch_one(&pool)
            .await
            .unwrap();
        drop(inventory);
        pool.close().await;

        let reopened = SqliteInventory::open(&path).await.unwrap();
        let record = reopened.corp_record().await.unwrap().unwrap();
        assert!(!record.status.enabled);
        assert_eq!(record.status.revision, 0);
        assert_eq!(
            (record.status.auth_generation, record.status.config_version),
            (1, 1)
        );
        assert_eq!(record.status.user_id, status.user_id);
        assert_eq!(record.status.policy_id, status.policy_id);
        assert_eq!(
            record.credentials.password_phc,
            input.credentials.password_phc
        );
        assert_eq!(
            record.credentials.reader_tokens[0].token,
            input.credentials.reader_tokens[0].token
        );
        assert_eq!(
            record.credentials.signing_keys[0].pkcs8,
            input.credentials.signing_keys[0].pkcs8
        );
        let pool = connect(&path).await;
        let history_after: Vec<(i64, Vec<u8>)> =
            sqlx::query_as("SELECT version, checksum FROM _sqlx_migrations ORDER BY version")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(history_after, history_before);
        assert_eq!(legacy_rows(&pool).await, before);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM audit_log")
                .fetch_one(&pool)
                .await
                .unwrap(),
            audits_before
        );
        pool.close().await;
    }

    #[tokio::test]
    async fn forged_legacy_70_checksum_is_rejected_without_applying_corp() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("forged.db");
        let pool = legacy_70(&path).await;
        let before = legacy_rows(&pool).await;
        let mut forged = frozen_checksum();
        forged[0] ^= 1;
        sqlx::query("UPDATE _sqlx_migrations SET checksum = ? WHERE version = 70")
            .bind(&forged)
            .execute(&pool)
            .await
            .unwrap();
        assert!(SqliteInventory::open(&path).await.is_err());
        let stored: Vec<u8> =
            sqlx::query_scalar("SELECT checksum FROM _sqlx_migrations WHERE version = 70")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(stored, forged);
        assert_eq!(legacy_rows(&pool).await, before);
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM _sqlx_migrations WHERE version = 71"
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            0
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM sqlite_master WHERE name = 'corp_policy_settings'"
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            0
        );
        pool.close().await;
    }
}
