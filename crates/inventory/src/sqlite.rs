//! SQLite-backed inventory.
//!
//! Notes:
//!
//! - Uses `sqlx::query` (runtime-checked) for now to keep bootstrap simple
//!   (no `cargo sqlx prepare` / `.sqlx/` pipeline). When the schema is
//!   stable in v0.3, migrate to `sqlx::query!` for compile-time checking.
//! - Connection options force WAL, FK enforcement, and a 5-second
//!   busy-timeout (PRAGMAs applied via `SqliteConnectOptions`).
//! - Schema lives in `migrations/0001_init.sql` and is embedded into the
//!   binary by `sqlx::migrate!`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{SqlitePool, migrate::Migrator};
use std::collections::HashMap;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;
use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

#[derive(Debug, thiserror::Error)]
pub enum SqliteInventoryError {
    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("migration: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid data in db: {0}")]
    Invalid(String),
    /// Тypизированная ошибка для PRIMARY KEY / UNIQUE — CLI может выдать
    /// дружелюбный текст «already exists» вместо raw SQL message.
    #[error("already exists: {0}")]
    AlreadyExists(String),
    /// Wrapping `std::io::Error` from the crypto layer (RNG failure).
    #[error("io (rng): {0}")]
    CryptoIo(std::io::Error),
}

/// Convert sqlx UNIQUE constraint violations to `AlreadyExists`. Other
/// sqlx errors propagate untouched.
fn map_unique<T>(
    res: std::result::Result<T, sqlx::Error>,
    what: impl std::fmt::Display,
) -> Result<T> {
    match res {
        Ok(v) => Ok(v),
        Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
            Err(SqliteInventoryError::AlreadyExists(what.to_string()))
        }
        Err(e) => Err(e.into()),
    }
}

pub type Result<T> = std::result::Result<T, SqliteInventoryError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: i64,
    pub ts: DateTime<Utc>,
    pub actor: String,
    pub action: String,
    pub target: Option<String>,
    pub payload: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct SqliteInventory {
    pool: SqlitePool,
}

impl SqliteInventory {
    /// Open (or create) DB at `path`, apply pragmas, run migrations.
    pub async fn open(path: &Path) -> Result<Self> {
        let opts =
            SqliteConnectOptions::from_str(path.to_str().ok_or_else(|| {
                SqliteInventoryError::Invalid(format!("non-utf8 path: {path:?}"))
            })?)?
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(5));

        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(opts)
            .await?;

        MIGRATOR.run(&pool).await?;

        // Backfill: every user must have a non-null sub_token after open().
        // Migration 0002 adds the column nullable; we fill it here so the
        // rest of the code can rely on `User.sub_token` being Some.
        backfill_sub_tokens(&pool).await?;

        Ok(Self { pool })
    }

    /// Force-close all pooled connections. Useful in tests.
    pub async fn close(self) {
        self.pool.close().await;
    }

    // ── Servers ─────────────────────────────────────────────────────────

    pub async fn add_server(&self, s: &Server) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let res = sqlx::query(
            "INSERT INTO servers (id, address, ssh_port, ssh_user, kernel, hoster, jump_via, trusted_host_fingerprint, usage_coefficient)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        )
        .bind(&s.id.0)
        .bind(&s.address)
        .bind(i64::from(s.ssh_port))
        .bind(&s.ssh_user)
        .bind(&s.kernel.0)
        .bind(&s.hoster)
        .bind(s.jump_via.as_ref().map(|v| v.0.clone()))
        .bind(&s.trusted_host_fingerprint)
        .bind(s.usage_coefficient)
        .execute(&mut *tx)
        .await;
        map_unique(res, format!("server {}", s.id.0))?;

        for proto in &s.enabled_protocols {
            sqlx::query("INSERT INTO server_protocols (server_id, protocol_id) VALUES (?1, ?2)")
                .bind(&s.id.0)
                .bind(&proto.0)
                .execute(&mut *tx)
                .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    pub async fn get_server(&self, id: &ServerId) -> Result<Option<Server>> {
        let row_opt = sqlx::query(
            "SELECT id, address, ssh_port, ssh_user, kernel, hoster, jump_via, trusted_host_fingerprint, usage_coefficient
             FROM servers WHERE id = ?1",
        )
        .bind(&id.0)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row_opt else { return Ok(None) };

        let server_id: String = row.try_get("id")?;
        let protocols = self
            .list_server_protocols(&ServerId(server_id.clone()))
            .await?;
        let s = Server {
            id: ServerId(server_id),
            address: row.try_get("address")?,
            ssh_port: u16::try_from(row.try_get::<i64, _>("ssh_port")?)
                .map_err(|_| SqliteInventoryError::Invalid("ssh_port out of u16 range".into()))?,
            ssh_user: row.try_get("ssh_user")?,
            kernel: KernelId(row.try_get("kernel")?),
            enabled_protocols: protocols,
            trusted_host_fingerprint: row.try_get("trusted_host_fingerprint")?,
            hoster: row.try_get("hoster")?,
            jump_via: row.try_get::<Option<String>, _>("jump_via")?.map(ServerId),
            usage_coefficient: row.try_get("usage_coefficient")?,
        };
        Ok(Some(s))
    }

    pub async fn list_servers(&self) -> Result<Vec<Server>> {
        // NOTE(perf): N+1 query — one SELECT id, then per-server get_server
        // (which itself does 2 queries). For a homelab with <100 servers
        // this is fine; if it ever matters, switch to a single LEFT JOIN
        // and aggregate protocols in Rust.
        let rows = sqlx::query("SELECT id FROM servers ORDER BY id")
            .fetch_all(&self.pool)
            .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let id: String = r.try_get("id")?;
            if let Some(s) = self.get_server(&ServerId(id)).await? {
                out.push(s);
            }
        }
        Ok(out)
    }

    pub async fn remove_server(&self, id: &ServerId) -> Result<()> {
        sqlx::query("DELETE FROM servers WHERE id = ?1")
            .bind(&id.0)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn update_trusted_fingerprint(&self, id: &ServerId, fp: &str) -> Result<()> {
        // Defensive validation — a malicious or buggy caller could otherwise
        // store an empty / arbitrary value, after which every future connect
        // silently rejects the real host key with a useless error.
        if !is_valid_sha256_fingerprint(fp) {
            return Err(SqliteInventoryError::Invalid(format!(
                "fingerprint must look like 'SHA256:<base64-43>', got {fp:?}"
            )));
        }
        sqlx::query(
            "UPDATE servers SET trusted_host_fingerprint = ?1,
                                 updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE id = ?2",
        )
        .bind(fp)
        .bind(&id.0)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_server_protocols(&self, id: &ServerId) -> Result<Vec<ProtocolId>> {
        let rows = sqlx::query(
            "SELECT protocol_id FROM server_protocols WHERE server_id = ?1 ORDER BY protocol_id",
        )
        .bind(&id.0)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|r| Ok(ProtocolId(r.try_get::<String, _>("protocol_id")?)))
            .collect()
    }

    // ── Server secrets ──────────────────────────────────────────────────

    pub async fn set_server_secret(&self, id: &ServerId, key: &str, value: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO server_secrets (server_id, key, value) VALUES (?1, ?2, ?3)
             ON CONFLICT(server_id, key) DO UPDATE SET value = excluded.value",
        )
        .bind(&id.0)
        .bind(key)
        .bind(value)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_server_secret(&self, id: &ServerId, key: &str) -> Result<Option<String>> {
        let row = sqlx::query("SELECT value FROM server_secrets WHERE server_id = ?1 AND key = ?2")
            .bind(&id.0)
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|r| r.try_get::<String, _>("value"))
            .transpose()
            .map_err(Into::into)
    }

    pub async fn list_server_secrets(&self, id: &ServerId) -> Result<HashMap<String, String>> {
        let rows = sqlx::query("SELECT key, value FROM server_secrets WHERE server_id = ?1")
            .bind(&id.0)
            .fetch_all(&self.pool)
            .await?;
        let mut map = HashMap::with_capacity(rows.len());
        for r in rows {
            map.insert(r.try_get("key")?, r.try_get("value")?);
        }
        Ok(map)
    }

    // ── Users ───────────────────────────────────────────────────────────

    pub async fn add_user(&self, u: &User) -> Result<()> {
        // Ensure every user gets a sub_token. Caller may pre-set one (e.g.
        // when restoring from a snapshot); we generate only if absent.
        let token = match u.sub_token.as_deref() {
            Some(t) if !t.is_empty() => t.to_string(),
            _ => vpnctl_crypto::gen_sub_token().map_err(SqliteInventoryError::CryptoIo)?,
        };
        let res = sqlx::query(
            "INSERT INTO users (id, uuid, tuic_password, wireguard_pubkey, sub_token)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(&u.id.0)
        .bind(&u.uuid)
        .bind(&u.tuic_password)
        .bind(&u.wireguard_pubkey)
        .bind(&token)
        .execute(&self.pool)
        .await;
        map_unique(res, format!("user {}", u.id.0))?;
        Ok(())
    }

    /// Look up a user by their subscription token. Constant-time'ish at the
    /// SQL layer (sqlite scans the unique index), but the caller is the
    /// public daemon — see also `vpnctld` rate-limit middleware.
    pub async fn find_user_by_sub_token(&self, token: &str) -> Result<Option<User>> {
        let row = sqlx::query(
            "SELECT id, uuid, tuic_password, wireguard_pubkey, sub_token
             FROM users WHERE sub_token = ?1",
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await?;
        row.map(row_to_user).transpose()
    }

    /// Regenerate the sub_token for an existing user (rotation). Returns the
    /// new token. Old URL stops working immediately.
    pub async fn regenerate_sub_token(&self, id: &UserId) -> Result<String> {
        let token = vpnctl_crypto::gen_sub_token().map_err(SqliteInventoryError::CryptoIo)?;
        let res = sqlx::query("UPDATE users SET sub_token = ?1 WHERE id = ?2")
            .bind(&token)
            .bind(&id.0)
            .execute(&self.pool)
            .await?;
        if res.rows_affected() == 0 {
            return Err(SqliteInventoryError::Invalid(format!(
                "no such user: {}",
                id.0
            )));
        }
        Ok(token)
    }

    pub async fn get_user(&self, id: &UserId) -> Result<Option<User>> {
        let row = sqlx::query(
            "SELECT id, uuid, tuic_password, wireguard_pubkey, sub_token
             FROM users WHERE id = ?1",
        )
        .bind(&id.0)
        .fetch_optional(&self.pool)
        .await?;
        row.map(row_to_user).transpose()
    }

    pub async fn list_users(&self) -> Result<Vec<User>> {
        let rows = sqlx::query(
            "SELECT id, uuid, tuic_password, wireguard_pubkey, sub_token
             FROM users ORDER BY id",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_user).collect()
    }

    pub async fn remove_user(&self, id: &UserId) -> Result<()> {
        sqlx::query("DELETE FROM users WHERE id = ?1")
            .bind(&id.0)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ── Grants (user × server) ──────────────────────────────────────────

    pub async fn grant(&self, user: &UserId, server: &ServerId) -> Result<()> {
        sqlx::query(
            "INSERT INTO grants (user_id, server_id) VALUES (?1, ?2)
             ON CONFLICT(user_id, server_id) DO NOTHING",
        )
        .bind(&user.0)
        .bind(&server.0)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn revoke(&self, user: &UserId, server: &ServerId) -> Result<()> {
        sqlx::query("DELETE FROM grants WHERE user_id = ?1 AND server_id = ?2")
            .bind(&user.0)
            .bind(&server.0)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn users_for_server(&self, server: &ServerId) -> Result<Vec<User>> {
        let rows = sqlx::query(
            "SELECT u.id, u.uuid, u.tuic_password, u.wireguard_pubkey, u.sub_token
             FROM users u
             INNER JOIN grants g ON g.user_id = u.id
             WHERE g.server_id = ?1
             ORDER BY u.id",
        )
        .bind(&server.0)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_user).collect()
    }

    pub async fn servers_for_user(&self, user: &UserId) -> Result<Vec<Server>> {
        let rows = sqlx::query(
            "SELECT g.server_id FROM grants g WHERE g.user_id = ?1 ORDER BY g.server_id",
        )
        .bind(&user.0)
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let sid: String = r.try_get("server_id")?;
            if let Some(s) = self.get_server(&ServerId(sid)).await? {
                out.push(s);
            }
        }
        Ok(out)
    }

    // ── Audit ───────────────────────────────────────────────────────────

    pub async fn audit(
        &self,
        actor: &str,
        action: &str,
        target: Option<&str>,
        payload: Option<&serde_json::Value>,
    ) -> Result<()> {
        let payload_str = match payload {
            Some(v) => Some(serde_json::to_string(v)?),
            None => None,
        };
        sqlx::query(
            "INSERT INTO audit_log (actor, action, target, payload) VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(actor)
        .bind(action)
        .bind(target)
        .bind(payload_str)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn recent_audit(&self, limit: i64) -> Result<Vec<AuditEntry>> {
        let rows = sqlx::query(
            "SELECT id, ts, actor, action, target, payload
             FROM audit_log ORDER BY id DESC LIMIT ?1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|r| {
                let ts_str: String = r.try_get("ts")?;
                let ts = DateTime::parse_from_rfc3339(&ts_str)
                    .map(|d| d.with_timezone(&Utc))
                    .map_err(|e| {
                        SqliteInventoryError::Invalid(format!("ts not RFC3339 ({ts_str}): {e}"))
                    })?;
                let payload_opt: Option<String> = r.try_get("payload")?;
                let payload = match payload_opt {
                    Some(s) => Some(serde_json::from_str(&s)?),
                    None => None,
                };
                Ok(AuditEntry {
                    id: r.try_get("id")?,
                    ts,
                    actor: r.try_get("actor")?,
                    action: r.try_get("action")?,
                    target: r.try_get("target")?,
                    payload,
                })
            })
            .collect()
    }
}

// Owned `SqliteRow` is what `.map(...)` over `Vec<Row>` gives us — taking by
// reference here would require a `.collect()` round-trip. Accepting by value
// is correct.
/// SSH host fingerprint sanity check — `SHA256:<base64-of-32-bytes>`.
/// We don't try to decode the base64; just enforce the shape so a typo
/// or empty string can't pass.
fn is_valid_sha256_fingerprint(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("SHA256:") else {
        return false;
    };
    // SHA-256 = 32 bytes; padded base64 is 44 chars, unpadded is 43.
    matches!(rest.len(), 43 | 44)
        && rest
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
}

#[allow(clippy::needless_pass_by_value)]
fn row_to_user(r: sqlx::sqlite::SqliteRow) -> Result<User> {
    Ok(User {
        id: UserId(r.try_get("id")?),
        uuid: r.try_get("uuid")?,
        tuic_password: r.try_get("tuic_password")?,
        wireguard_pubkey: r.try_get("wireguard_pubkey")?,
        sub_token: r.try_get("sub_token")?,
    })
}

/// Walk users whose sub_token is NULL after migrate, generate one each.
/// Idempotent — a second call sees no rows.
async fn backfill_sub_tokens(pool: &SqlitePool) -> Result<()> {
    // Wrap in a transaction so two concurrent `open()` calls can't race on
    // the same NULL row. sqlx::Transaction holds an `IMMEDIATE` write lock
    // on first write; the loser blocks until the winner commits, then sees
    // no NULLs and does nothing. On crash mid-loop the txn rolls back —
    // next open retries cleanly, no half-state.
    let mut tx = pool.begin().await?;
    let rows = sqlx::query("SELECT id FROM users WHERE sub_token IS NULL")
        .fetch_all(&mut *tx)
        .await?;
    for r in rows {
        let id: String = r.try_get("id")?;
        let token = vpnctl_crypto::gen_sub_token().map_err(SqliteInventoryError::CryptoIo)?;
        sqlx::query("UPDATE users SET sub_token = ?1 WHERE id = ?2")
            .bind(&token)
            .bind(&id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::tempdir;
    use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};

    async fn fresh() -> SqliteInventory {
        let dir = Box::leak(Box::new(tempdir().expect("tempdir")));
        let path = dir.path().join("inv.db");
        SqliteInventory::open(&path).await.expect("open inventory")
    }

    fn sample_server(id: &str) -> Server {
        Server {
            id: ServerId(id.into()),
            address: "1.2.3.4".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernel: KernelId("sing-box".into()),
            enabled_protocols: vec![
                ProtocolId("vless+reality".into()),
                ProtocolId("tuic-v5".into()),
            ],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        }
    }

    fn sample_user(id: &str) -> User {
        User {
            id: UserId(id.into()),
            uuid: format!("uuid-{id}"),
            tuic_password: Some(format!("pw-{id}")),
            wireguard_pubkey: None,
            sub_token: None, // inventory will generate one
        }
    }

    #[tokio::test]
    async fn migrations_apply_and_tables_exist() -> Result<()> {
        let inv = fresh().await;
        // If we can list servers without error, migration ran.
        assert!(inv.list_servers().await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn server_roundtrip() -> Result<()> {
        let inv = fresh().await;
        inv.add_server(&sample_server("s1")).await?;
        let got = inv.get_server(&ServerId("s1".into())).await?.unwrap();
        assert_eq!(got.address, "1.2.3.4");
        assert_eq!(got.enabled_protocols.len(), 2);
        assert!(got.enabled_protocols.iter().any(|p| p.0 == "vless+reality"));
        Ok(())
    }

    #[tokio::test]
    async fn duplicate_server_returns_already_exists() -> Result<()> {
        let inv = fresh().await;
        inv.add_server(&sample_server("dup")).await?;
        let err = inv.add_server(&sample_server("dup")).await.unwrap_err();
        assert!(
            matches!(err, SqliteInventoryError::AlreadyExists(ref s) if s == "server dup"),
            "expected AlreadyExists(\"server dup\"), got {err:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn duplicate_user_returns_already_exists() -> Result<()> {
        let inv = fresh().await;
        inv.add_user(&sample_user("alice")).await?;
        let err = inv.add_user(&sample_user("alice")).await.unwrap_err();
        assert!(
            matches!(err, SqliteInventoryError::AlreadyExists(ref s) if s == "user alice"),
            "expected AlreadyExists(\"user alice\"), got {err:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn fingerprint_update_persists() -> Result<()> {
        let inv = fresh().await;
        inv.add_server(&sample_server("s")).await?;
        // 43-char unpadded SHA-256 base64 (russh's natural format).
        let valid = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        inv.update_trusted_fingerprint(&ServerId("s".into()), valid)
            .await?;
        let got = inv.get_server(&ServerId("s".into())).await?.unwrap();
        assert_eq!(got.trusted_host_fingerprint.as_deref(), Some(valid));
        Ok(())
    }

    #[tokio::test]
    async fn fingerprint_update_rejects_garbage() -> Result<()> {
        let inv = fresh().await;
        inv.add_server(&sample_server("s")).await?;
        for bad in ["", "abc", "MD5:xxx", "SHA256:short", "SHA256:!!!!"] {
            let err = inv
                .update_trusted_fingerprint(&ServerId("s".into()), bad)
                .await
                .unwrap_err();
            assert!(
                matches!(err, SqliteInventoryError::Invalid(_)),
                "input {bad:?} should be rejected with Invalid, got {err:?}"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn server_secrets_upsert() -> Result<()> {
        let inv = fresh().await;
        inv.add_server(&sample_server("s")).await?;
        let sid = ServerId("s".into());
        inv.set_server_secret(&sid, "reality_private", "PRIV1")
            .await?;
        inv.set_server_secret(&sid, "reality_private", "PRIV2")
            .await?; // upsert
        let got = inv.get_server_secret(&sid, "reality_private").await?;
        assert_eq!(got.as_deref(), Some("PRIV2"));
        Ok(())
    }

    #[tokio::test]
    async fn grants_and_users_for_server() -> Result<()> {
        let inv = fresh().await;
        inv.add_server(&sample_server("srv")).await?;
        inv.add_user(&sample_user("alice")).await?;
        inv.add_user(&sample_user("bob")).await?;
        inv.grant(&UserId("alice".into()), &ServerId("srv".into()))
            .await?;
        inv.grant(&UserId("bob".into()), &ServerId("srv".into()))
            .await?;
        let users = inv.users_for_server(&ServerId("srv".into())).await?;
        assert_eq!(users.len(), 2);

        inv.revoke(&UserId("alice".into()), &ServerId("srv".into()))
            .await?;
        let users = inv.users_for_server(&ServerId("srv".into())).await?;
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].id.0, "bob");
        Ok(())
    }

    #[tokio::test]
    async fn cascade_delete_user_removes_grants() -> Result<()> {
        let inv = fresh().await;
        inv.add_server(&sample_server("srv")).await?;
        inv.add_user(&sample_user("alice")).await?;
        inv.grant(&UserId("alice".into()), &ServerId("srv".into()))
            .await?;
        inv.remove_user(&UserId("alice".into())).await?;
        let users = inv.users_for_server(&ServerId("srv".into())).await?;
        assert!(users.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn audit_log_records_and_lists() -> Result<()> {
        let inv = fresh().await;
        inv.audit(
            "cli",
            "server.create",
            Some("srv"),
            Some(&json!({"address": "1.2.3.4"})),
        )
        .await?;
        inv.audit("cli", "user.add", Some("alice"), None).await?;

        let log = inv.recent_audit(10).await?;
        assert_eq!(log.len(), 2);
        // recent_audit orders by id DESC, so user.add comes first.
        assert_eq!(log[0].action, "user.add");
        assert_eq!(log[1].action, "server.create");
        assert_eq!(
            log[1]
                .payload
                .as_ref()
                .and_then(|v| v.get("address"))
                .and_then(|v| v.as_str()),
            Some("1.2.3.4")
        );
        Ok(())
    }
}
