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

/// One UA-cluster row for the Phase Track-4 fingerprint heuristic.
/// Groups `sub_access_log` rows by User-Agent within the recent
/// window. The classifier ("roaming" vs "shared URL") lives in the
/// admin handler, not here — inventory just exposes raw aggregates.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UaCluster {
    /// User-Agent string. `None` means rows whose UA was missing
    /// (curl scripts, misconfigured clients).
    pub ua: Option<String>,
    /// Distinct IPs that hit /sub with this UA in the window.
    pub distinct_ips: u64,
    /// Distinct /16 networks (first two octets of v4) — the heuristic
    /// signal: one device usually roams within a single ISP /16,
    /// while a shared URL spreads across ASNs and therefore /16s.
    pub distinct_slash16: u64,
    /// Total hits with this UA in the window.
    pub hits: u64,
}

/// One time-bucket of `sub_access_log` aggregated for the Phase F
/// monitoring sparklines. `ts` is the bucket start (ISO-8601, UTC),
/// `hits` is the count of requests in the bucket, `distinct_ips` is
/// `COUNT(DISTINCT ip)` in the bucket. Buckets with zero hits are
/// NOT returned by the query — the renderer fills gaps with zero so
/// the sparkline x-axis stays evenly spaced.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccessBucket {
    pub bucket_start: DateTime<Utc>,
    pub hits: u64,
    pub distinct_ips: u64,
}

/// One row of `sub_access_log` (Phase Track-1) — emitted by the daemon
/// every time `/sub/<token>` is hit, after the token has been resolved.
/// The token itself is never stored, only the resolved `user_id`, so a
/// row alone can't replay the request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubAccessEntry {
    pub id: i64,
    pub ts: DateTime<Utc>,
    pub user_id: String,
    pub ip: String,
    pub ua: Option<String>,
    pub status: u16,
    pub bytes: u64,
}

/// One row of `sub_rate_bans` (Phase Track-2 chunk 2). Persistent
/// auto-bans for `/sub` abuse: after K consecutive 429s for the same
/// (kind, key) the daemon writes a row valid for 24h.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ban {
    pub id: i64,
    pub created_at: DateTime<Utc>,
    pub until_ts: DateTime<Utc>,
    pub kind: String,
    pub key: String,
    pub reason: String,
}

/// One row in `vpn_connection_stats` (Track-3 chunk 2). The poller
/// writes deltas (not totals) per (server, user) on every tick where
/// the delta is non-zero.
///
/// `user_id = None` is the server-wide row for that snapshot — sum
/// of all per-user deltas plus any unattributed traffic from
/// connections that didn't carry a `metadata.user`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VpnStatsRow {
    pub ts: DateTime<Utc>,
    pub server_id: ServerId,
    pub user_id: Option<UserId>,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub active_connections: u32,
}

/// One delta the poller wants to write — produced by the in-memory
/// diff engine in `daemon::clash_poller`. Bundled into a single
/// transaction by `record_vpn_stats` so a tick lands atomically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnStatsDelta {
    /// `None` = server-wide row.
    pub user_id: Option<UserId>,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub active_connections: u32,
}

/// One row in `node_health` (Phase H chunk 2). Daemon-side poller
/// writes one per tick per server. Fields are `Option` to mirror
/// `daemon::node_probe::Probe` — partial-success snapshots
/// (one parser failed, others succeeded) preserve the working
/// metrics instead of throwing the whole row away.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeHealthRow {
    pub ts: DateTime<Utc>,
    pub server_id: ServerId,
    pub sing_box_active: Option<bool>,
    pub fail2ban_active: Option<bool>,
    pub disk_used_mib: Option<u64>,
    pub disk_total_mib: Option<u64>,
    pub mem_available_mib: Option<u64>,
    pub mem_total_mib: Option<u64>,
    pub load_1min_x100: Option<u32>,
    /// JSON array of sorted `"proto/port"` strings (e.g.
    /// `["tcp/443","udp/8443"]`). Parsed on the UI side via
    /// `serde_json::from_str`. Stored as a String so SQL
    /// `LIKE '%/443%'` queries can grep without parsing.
    pub listening_ports_json: Option<String>,
    pub sing_box_log_bytes: Option<u64>,
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
            "INSERT INTO users (id, uuid, tuic_password, wireguard_pubkey, wireguard_private, sub_token)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .bind(&u.id.0)
        .bind(&u.uuid)
        .bind(&u.tuic_password)
        .bind(&u.wireguard_pubkey)
        .bind(&u.wireguard_private)
        .bind(&token)
        .execute(&self.pool)
        .await;
        map_unique(res, format!("user {}", u.id.0))?;
        Ok(())
    }

    /// Look up a user by their subscription token. Constant-time'ish at the
    /// SQL layer (sqlite scans the unique index), but the caller is the
    /// public daemon — see also `vpnctld` rate-limit middleware.
    ///
    /// **Side-channel posture (review-agent #5, security-review #3,
    /// 2026-05-14):** SQLite's index walk + the Rust `String` comparison
    /// inside `bind` are not constant-time. With ~256 bits of entropy
    /// in `sub_token` (43 chars URL-safe base64 = 252 bits) brute force
    /// is infeasible regardless. Timing-based prefix discovery would
    /// matter ONLY if the daemon were exposed externally with no
    /// rate-limit. The deployment is LAN-only today, and Phase Track-2
    /// (per-token rate limit + auto-deny on burst) MUST land before any
    /// external exposure — see CLAUDE.md Roadmap. Do NOT remove this
    /// invariant by exposing the daemon publicly without Track-2.
    pub async fn find_user_by_sub_token(&self, token: &str) -> Result<Option<User>> {
        let row = sqlx::query(
            "SELECT id, uuid, tuic_password, wireguard_pubkey, wireguard_private, sub_token
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
            "SELECT id, uuid, tuic_password, wireguard_pubkey, wireguard_private, sub_token
             FROM users WHERE id = ?1",
        )
        .bind(&id.0)
        .fetch_optional(&self.pool)
        .await?;
        row.map(row_to_user).transpose()
    }

    pub async fn list_users(&self) -> Result<Vec<User>> {
        let rows = sqlx::query(
            "SELECT id, uuid, tuic_password, wireguard_pubkey, wireguard_private, sub_token
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
            "SELECT u.id, u.uuid, u.tuic_password, u.wireguard_pubkey, u.wireguard_private, u.sub_token
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

    // ── Aggregations (read-only, used by daemon dashboard / list views) ──

    /// Cheap row count. `0` on an empty table.
    pub async fn count_servers(&self) -> Result<i64> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM servers")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.try_get("n")?)
    }

    /// Cheap row count. `0` on an empty table.
    pub async fn count_users(&self) -> Result<i64> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM users")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.try_get("n")?)
    }

    /// Cheap row count of (user, server) grant pairs. `0` on empty table.
    pub async fn count_grants(&self) -> Result<i64> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM grants")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.try_get("n")?)
    }

    /// Map of `server_id → number of users granted access to it`. Servers
    /// with no grants are absent (callers default to 0). One query, no N+1
    /// — call this once and look up by ID when rendering a server list.
    pub async fn users_count_per_server(&self) -> Result<HashMap<ServerId, i64>> {
        let rows = sqlx::query("SELECT server_id, COUNT(*) AS n FROM grants GROUP BY server_id")
            .fetch_all(&self.pool)
            .await?;
        let mut out = HashMap::with_capacity(rows.len());
        for r in rows {
            let sid: String = r.try_get("server_id")?;
            let n: i64 = r.try_get("n")?;
            out.insert(ServerId(sid), n);
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

    /// Paginated + filterable audit query — backs Phase D timeline UI.
    ///
    /// Both filter args are optional substrings: `actor_filter = Some("admin")`
    /// matches rows where `actor = 'admin'` (exact match); `action_filter
    /// = Some("user.")` matches rows where `action LIKE 'user.%'`. Pass
    /// `None` to skip a filter axis.
    ///
    /// `limit` and `offset` drive the pagination — caller computes them
    /// from a page number (typically `offset = page * limit`). Newest-
    /// first order matches `recent_audit`.
    ///
    /// Returns at most `limit` rows. The caller decides "is there a next
    /// page?" by asking for one extra row (`limit+1`) and checking the
    /// returned length, OR by issuing a separate `count_audit_filtered`
    /// query (we don't expose one yet — the +1 trick is enough).
    pub async fn recent_audit_paginated(
        &self,
        limit: i64,
        offset: i64,
        actor_filter: Option<&str>,
        action_prefix: Option<&str>,
    ) -> Result<Vec<AuditEntry>> {
        // Build the WHERE clause incrementally. SQLite uses positional
        // `?` placeholders so we don't number them — the bind() calls
        // below run in the same order as the WHERE conditions.
        let mut where_parts: Vec<&str> = Vec::with_capacity(2);
        if actor_filter.is_some() {
            where_parts.push(if where_parts.is_empty() {
                "actor = ?"
            } else {
                "AND actor = ?"
            });
        }
        if action_prefix.is_some() {
            where_parts.push(if where_parts.is_empty() {
                "action LIKE ? ESCAPE '\\'"
            } else {
                "AND action LIKE ? ESCAPE '\\'"
            });
        }
        let where_clause = if where_parts.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_parts.join(" "))
        };
        let sql = format!(
            "SELECT id, ts, actor, action, target, payload
             FROM audit_log
             {where_clause}
             ORDER BY id DESC
             LIMIT ? OFFSET ?"
        );
        let mut q = sqlx::query(&sql);
        if let Some(a) = actor_filter {
            q = q.bind(a);
        }
        if let Some(p) = action_prefix {
            // Append `%` for prefix match — caller passes `"user."` and
            // we turn it into `"user.%"`. LIKE metacharacters in `p`
            // (`%` `_` `\`) are escaped first so an operator typing
            // `?action=user_` matches LITERAL `user_`, not `user.`,
            // and `?action=%` matches literal `%`, not "everything".
            // Pairs with the `ESCAPE '\\'` clause above.
            q = q.bind(format!("{}%", escape_like(p)));
        }
        q = q.bind(limit).bind(offset);
        let rows = q.fetch_all(&self.pool).await?;
        rows.into_iter().map(row_to_audit_entry).collect()
    }

    pub async fn recent_audit(&self, limit: i64) -> Result<Vec<AuditEntry>> {
        let rows = sqlx::query(
            "SELECT id, ts, actor, action, target, payload
             FROM audit_log ORDER BY id DESC LIMIT ?1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_audit_entry).collect()
    }

    // ── Subscription access log (Phase Track-1) ─────────────────────────

    /// Append one row to `sub_access_log`. Called by the `/sub/<token>`
    /// handler AFTER the token has been resolved to a user (so a 404 path
    /// — "unknown token" — does NOT land here; that's intentional, we
    /// don't want to keep a per-attempt log of probing tokens because it
    /// would let an attacker fill the table by spamming garbage).
    ///
    /// Best-effort write. The handler calls this in a fire-and-forget
    /// `tokio::spawn`; if it errors the response has already been sent.
    pub async fn log_sub_access(
        &self,
        user_id: &UserId,
        ip: &str,
        ua: Option<&str>,
        status: u16,
        bytes: u64,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO sub_access_log (user_id, ip, ua, status, bytes)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(&user_id.0)
        .bind(ip)
        .bind(ua)
        // SQLite has no u16 affinity; cast through i64.
        .bind(i64::from(status))
        .bind(i64::try_from(bytes).unwrap_or(i64::MAX))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Number of distinct source IPs that fetched this user's
    /// subscription URL in the last `since_hours` hours. Drives the
    /// "abuse signal" headline on the user-detail page.
    ///
    /// **Timestamp-format invariant (caught by retroactive review-agent
    /// 2026-05-14, was a critical bug):** the cutoff must be produced
    /// in the **same** format as `ts` is written by `log_sub_access` —
    /// ISO `YYYY-MM-DDTHH:MM:SS.fffZ` (note the `T` separator and the
    /// trailing `Z`). `datetime('now', ?)` returns the SQL form
    /// `YYYY-MM-DD HH:MM:SS` (space separator, no millis, no `Z`) and
    /// then SQLite compares both sides as TEXT — the `T` (0x54) is
    /// greater than space (0x20), so every same-day row would compare
    /// as "newer than the cutoff" regardless of its actual time-of-day.
    /// Always wrap with `strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)` so
    /// both sides share the format the row was written in.
    pub async fn distinct_ips_for_user(&self, user_id: &UserId, since_hours: u32) -> Result<u64> {
        let row = sqlx::query(
            "SELECT COUNT(DISTINCT ip) AS n FROM sub_access_log
             WHERE user_id = ?1
               AND ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)",
        )
        .bind(&user_id.0)
        .bind(format!("-{since_hours} hours"))
        .fetch_one(&self.pool)
        .await?;
        let n: i64 = row.try_get("n")?;
        Ok(u64::try_from(n).unwrap_or(0))
    }

    /// Most recent N access rows for one user, newest first. Drives the
    /// recent-activity table on the user-detail page; the limit caps
    /// memory + render cost since chatty clients can rack up thousands
    /// of rows in the retention window.
    pub async fn recent_sub_access(
        &self,
        user_id: &UserId,
        limit: i64,
    ) -> Result<Vec<SubAccessEntry>> {
        let rows = sqlx::query(
            "SELECT id, ts, user_id, ip, ua, status, bytes
             FROM sub_access_log
             WHERE user_id = ?1
             ORDER BY id DESC
             LIMIT ?2",
        )
        .bind(&user_id.0)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_sub_access).collect()
    }

    /// UA-cluster aggregate for the Phase Track-4 fingerprint
    /// heuristic. Groups this user's recent `sub_access_log` rows
    /// by User-Agent and reports per-UA distinct IPs, distinct /16
    /// networks (first two v4 octets), and total hits.
    ///
    /// The /16 count is the key signal: a single roaming device
    /// usually moves within one ISP /16 (Wi-Fi switching subnets,
    /// LTE base stations under the same provider) — so distinct_ips
    /// can be high but distinct_slash16 stays at 1-2. A shared sub
    /// URL hits from many ISPs / countries → distinct_slash16 climbs.
    ///
    /// IPv6 addresses contribute `0` to the /16 count (we don't try
    /// to derive a meaningful network prefix without ASN data); the
    /// `distinct_ips` count still reflects them.
    pub async fn ua_clusters_for_user(
        &self,
        user_id: &UserId,
        since_hours: u32,
    ) -> Result<Vec<UaCluster>> {
        // Pull raw (ua, ip) tuples then aggregate in Rust — SQLite
        // can't extract /16 prefixes natively, and the row count is
        // bounded by the recent window so memory is fine.
        let rows = sqlx::query(
            "SELECT ua, ip FROM sub_access_log
             WHERE user_id = ?1
               AND ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)",
        )
        .bind(&user_id.0)
        .bind(format!("-{since_hours} hours"))
        .fetch_all(&self.pool)
        .await?;

        use std::collections::{HashMap, HashSet};
        // (ua_or_none) → (set of distinct IPs, set of distinct /16, hit count)
        let mut by_ua: HashMap<Option<String>, (HashSet<String>, HashSet<String>, u64)> =
            HashMap::new();
        for r in rows {
            let ua: Option<String> = r.try_get("ua")?;
            let ip: String = r.try_get("ip")?;
            let s16 = ip_slash16(&ip);
            let entry = by_ua.entry(ua).or_default();
            entry.0.insert(ip);
            if let Some(net) = s16 {
                entry.1.insert(net);
            }
            entry.2 += 1;
        }
        let mut out: Vec<UaCluster> = by_ua
            .into_iter()
            .map(|(ua, (ips, s16s, hits))| UaCluster {
                ua,
                distinct_ips: ips.len() as u64,
                distinct_slash16: s16s.len() as u64,
                hits,
            })
            .collect();
        // Sort by hit count DESC so the noisy UAs surface first in
        // the UI.
        out.sort_by_key(|c| std::cmp::Reverse(c.hits));
        Ok(out)
    }

    /// Drop all rows older than `days`. Returns the number of rows
    /// removed so the caller (a periodic task in the daemon) can log
    /// the retention activity.
    ///
    /// See `distinct_ips_for_user` for the timestamp-format invariant;
    /// the same `strftime` wrap applies here so the purge cutoff is
    /// comparable to the ISO timestamps `log_sub_access` writes.
    pub async fn purge_sub_access_older_than(&self, days: u32) -> Result<u64> {
        let res = sqlx::query(
            "DELETE FROM sub_access_log WHERE ts < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1)",
        )
        .bind(format!("-{days} days"))
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    /// Aggregate `sub_access_log` into time buckets for the Phase F
    /// monitoring sparklines. `bucket = "hour"` groups by hourly
    /// truncation, `bucket = "day"` by date. `since_hours` is the
    /// look-back window from now.
    ///
    /// Returns ONE row per bucket that had at least one hit; the
    /// caller fills gaps with zero so the sparkline x-axis stays
    /// evenly spaced. Newest-first sort is NOT used — buckets come
    /// back oldest-first (ASC) so the renderer can walk them
    /// chronologically without re-sorting.
    pub async fn sub_access_buckets(
        &self,
        bucket: &str,
        since_hours: u32,
    ) -> Result<Vec<AccessBucket>> {
        // Bucket grouping format. We REJECT unknown bucket strings
        // rather than silently default — an operator typo should
        // surface as an error, not as a meaningless aggregate.
        let group_fmt = match bucket {
            "hour" => "%Y-%m-%dT%H:00:00.000Z",
            "day" => "%Y-%m-%dT00:00:00.000Z",
            other => {
                return Err(SqliteInventoryError::Invalid(format!(
                    "sub_access_buckets: unknown bucket kind '{other}' (allowed: hour, day)"
                )));
            }
        };
        let rows = sqlx::query(
            "SELECT
                strftime(?1, ts) AS bucket_start,
                COUNT(*) AS hits,
                COUNT(DISTINCT ip) AS distinct_ips
             FROM sub_access_log
             WHERE ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)
             GROUP BY bucket_start
             ORDER BY bucket_start ASC",
        )
        .bind(group_fmt)
        .bind(format!("-{since_hours} hours"))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|r| {
                let ts_str: String = r.try_get("bucket_start")?;
                let ts = DateTime::parse_from_rfc3339(&ts_str)
                    .map(|d| d.with_timezone(&Utc))
                    .map_err(|e| {
                        SqliteInventoryError::Invalid(format!(
                            "bucket_start not RFC3339 ({ts_str}): {e}"
                        ))
                    })?;
                let hits_i: i64 = r.try_get("hits")?;
                let ips_i: i64 = r.try_get("distinct_ips")?;
                Ok(AccessBucket {
                    bucket_start: ts,
                    hits: u64::try_from(hits_i).unwrap_or(0),
                    distinct_ips: u64::try_from(ips_i).unwrap_or(0),
                })
            })
            .collect()
    }

    // ── Persistent rate-limit bans (Phase Track-2 chunk 2) ──────────────

    /// Insert a new ban valid for `ttl_secs` seconds. `kind` MUST be
    /// `"ip"` or `"token"` (the SQL `CHECK` constraint will reject
    /// other values; we don't pre-validate so a typo surfaces as a
    /// loud `Err` instead of a silent skip). Multiple overlapping
    /// bans for the same key are allowed — `is_banned` returns true
    /// if ANY non-expired ban matches, so re-banning is harmless.
    pub async fn add_ban(&self, kind: &str, key: &str, ttl_secs: u64, reason: &str) -> Result<()> {
        // Cap ttl at i64::MAX seconds (~292B years) defensively. The
        // SQL `+N seconds` modifier takes signed values; an unsigned
        // u64 of MAX would silently wrap. Practical max here is the
        // 24h default the daemon writes.
        let ttl_signed: i64 = i64::try_from(ttl_secs).unwrap_or(i64::MAX);
        sqlx::query(
            "INSERT INTO sub_rate_bans (until_ts, kind, key, reason)
             VALUES (
                strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1),
                ?2, ?3, ?4
             )",
        )
        .bind(format!("+{ttl_signed} seconds"))
        .bind(kind)
        .bind(key)
        .bind(reason)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Returns `Some(seconds_until_oldest_ban_expires)` if `(kind,
    /// key)` has any non-expired ban; `None` otherwise. Hot-path
    /// query: the index `idx_sub_rate_bans_kind_key_until` covers
    /// the entire predicate so this is sub-millisecond.
    ///
    /// Returns the SOONEST expiry among all matching bans (so
    /// `Retry-After` reflects the conservative "you'll be unbanned
    /// in this many seconds at the earliest"). If multiple
    /// overlapping bans exist, the oldest one expires first.
    pub async fn is_banned(&self, kind: &str, key: &str) -> Result<Option<u64>> {
        let row_opt = sqlx::query(
            "SELECT MIN(until_ts) AS until FROM sub_rate_bans
             WHERE kind = ?1 AND key = ?2
               AND until_ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
        )
        .bind(kind)
        .bind(key)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row_opt else {
            return Ok(None);
        };
        let until_str: Option<String> = row.try_get("until")?;
        let Some(until_str) = until_str else {
            // No matching rows — MIN() over an empty set returns NULL.
            return Ok(None);
        };
        let until = DateTime::parse_from_rfc3339(&until_str)
            .map(|d| d.with_timezone(&Utc))
            .map_err(|e| {
                SqliteInventoryError::Invalid(format!("ban until_ts malformed: {until_str}: {e}"))
            })?;
        let now = Utc::now();
        let secs = (until - now).num_seconds();
        // Defensive: race between SELECT and the `now` value here
        // could surface as 0 or -1 if the ban just expired.
        Ok(Some(u64::try_from(secs.max(1)).unwrap_or(1)))
    }

    /// List all currently-active bans (any kind). Powers the
    /// admin UI's "Active bans" surface. Sorted newest-first by
    /// `created_at` so the most recent abuse pops to the top.
    pub async fn active_bans(&self) -> Result<Vec<Ban>> {
        // ORDER BY created_at DESC, id DESC — `id DESC` is the stable
        // tiebreaker for inserts that land in the same millisecond
        // (caught by `spec_sub_rate_bans::active_bans_lists_all_kinds_newest_first`
        // flaking on CI). `id` is monotonic on insert (SQLite ROWID),
        // so id DESC == insert-order DESC for ties.
        let rows = sqlx::query(
            "SELECT id, created_at, until_ts, kind, key, reason
             FROM sub_rate_bans
             WHERE until_ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             ORDER BY created_at DESC, id DESC",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_ban).collect()
    }

    /// Drop expired ban rows. Called periodically by the daemon's
    /// rate-limit cleanup task. Returns the number of rows removed
    /// for telemetry.
    pub async fn purge_expired_bans(&self) -> Result<u64> {
        let res = sqlx::query(
            "DELETE FROM sub_rate_bans
             WHERE until_ts <= strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
        )
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    // ──────────────────────────────────────────────────────────────────
    // Track-3 chunk 2 — VPN connection stats (clash-api poller sink)
    //
    // The poller in `daemon::clash_poller` (separate iter / chunk) calls
    // `record_vpn_stats(server_id, deltas)` once per tick. The read
    // surfaces — `recent_vpn_stats_for_user` and
    // `recent_vpn_stats_for_server` — power chunk 3's UI on
    // `/admin/users/<id>` and `/admin/servers/<id>`.
    //
    // Server-wide rows are persisted under `user_id = NULL` so the
    // server-detail page can render bandwidth-vs-time without joining
    // across every per-user row.
    //
    // All deltas for one tick land in a single transaction so a poller
    // crash mid-write doesn't yield a half-attributed snapshot.
    //
    // **Audit-log exemption.** The "every inventory mutation gets one
    // audit_log row" invariant from CLAUDE.md is INTENTIONALLY waived
    // for `vpn_connection_stats`. Rationale: at homelab scale (5
    // servers × 60s tick × 24h × 30d = ~216K poller writes per month
    // before user multiplication), per-tick audit rows would dwarf
    // every other audit entry by 4 orders of magnitude and bury the
    // human-driven mutations the timeline is designed to surface. The
    // table itself IS the audit trail for poller activity (timestamps
    // + per-server + per-user breakdown); a chunk-3 retrospective on
    // /admin/audit can join in a derived "vpn-stats activity" entry
    // if operators ever need it. (Reviewed by independent review-agent
    // on cd61838^..492fdeb burst; documented exemption rather than
    // letting the invariant erode silently.)
    // ──────────────────────────────────────────────────────────────────

    /// Persist one tick's deltas. Empty `deltas` is a no-op (the
    /// poller may decide a quiet node doesn't deserve a row).
    /// Timestamp is `now` on the daemon, NOT pulled from the snapshot
    /// — clash-api doesn't carry a snapshot timestamp, and the
    /// daemon's clock is the only source we trust on the read side.
    pub async fn record_vpn_stats(
        &self,
        server_id: &ServerId,
        deltas: &[VpnStatsDelta],
    ) -> Result<()> {
        if deltas.is_empty() {
            return Ok(());
        }
        let mut tx = self.pool.begin().await?;
        for d in deltas {
            sqlx::query(
                "INSERT INTO vpn_connection_stats
                 (ts, server_id, user_id, upload_bytes, download_bytes, active_connections)
                 VALUES (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), ?1, ?2, ?3, ?4, ?5)",
            )
            .bind(&server_id.0)
            .bind(d.user_id.as_ref().map(|u| u.0.as_str()))
            .bind(i64::try_from(d.upload_bytes).unwrap_or(i64::MAX))
            .bind(i64::try_from(d.download_bytes).unwrap_or(i64::MAX))
            .bind(i64::from(d.active_connections))
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Recent per-user rows across ALL servers in the look-back
    /// window. Newest-first. The UI joins these by server_id to
    /// render a per-server breakdown if needed.
    pub async fn recent_vpn_stats_for_user(
        &self,
        user_id: &UserId,
        since_hours: u32,
    ) -> Result<Vec<VpnStatsRow>> {
        let rows = sqlx::query(
            "SELECT ts, server_id, user_id, upload_bytes, download_bytes, active_connections
             FROM vpn_connection_stats
             WHERE user_id = ?1
               AND ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)
             ORDER BY ts DESC",
        )
        .bind(&user_id.0)
        .bind(format!("-{since_hours} hours"))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_vpn_stats).collect()
    }

    /// Recent server-wide + per-user rows for one server in the
    /// look-back window. Newest-first. The server-detail UI uses
    /// the `user_id IS NULL` rows for the bandwidth sparkline and
    /// the rest for the per-user breakdown.
    pub async fn recent_vpn_stats_for_server(
        &self,
        server_id: &ServerId,
        since_hours: u32,
    ) -> Result<Vec<VpnStatsRow>> {
        let rows = sqlx::query(
            "SELECT ts, server_id, user_id, upload_bytes, download_bytes, active_connections
             FROM vpn_connection_stats
             WHERE server_id = ?1
               AND ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)
             ORDER BY ts DESC",
        )
        .bind(&server_id.0)
        .bind(format!("-{since_hours} hours"))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_vpn_stats).collect()
    }

    /// Drop rows older than `days`. Mirrors `purge_sub_access_older_than`
    /// — chunk 3 will wire this into the existing retention scheduler.
    pub async fn purge_vpn_stats_older_than(&self, days: u32) -> Result<u64> {
        let res = sqlx::query(
            "DELETE FROM vpn_connection_stats
             WHERE ts < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1)",
        )
        .bind(format!("-{days} days"))
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    // ──────────────────────────────────────────────────────────────────
    // Phase H chunk 2 — node telemetry storage (node_probe sink)
    //
    // Same shape + lifecycle as `vpn_connection_stats`:
    //   * Daemon poller calls `record_node_health(server_id, &Probe)`
    //     once per tick per server (chunk 3).
    //   * UI reads via `recent_node_health_for_server(id, since_hours)`.
    //   * Retention purge mirrors the others.
    //
    // **Audit exemption** (same rationale as `record_vpn_stats`):
    // probe writes happen at poller cadence × server count; audit
    // log volume would drown human-driven mutations. The table IS the
    // audit trail for telemetry. Documented exemption — not a silent
    // drift from the "every mutation audited" invariant.
    // ──────────────────────────────────────────────────────────────────

    /// Persist one node probe. `listening_ports_json` is the JSON
    /// serialization of the sorted `(proto, port)` set — caller
    /// builds it from `daemon::node_probe::Probe::listening`. Always
    /// stamps `ts` with daemon-side now; clash-api / probes don't
    /// carry their own timestamp.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_node_health(
        &self,
        server_id: &ServerId,
        sing_box_active: Option<bool>,
        fail2ban_active: Option<bool>,
        disk_used_mib: Option<u64>,
        disk_total_mib: Option<u64>,
        mem_available_mib: Option<u64>,
        mem_total_mib: Option<u64>,
        load_1min_x100: Option<u32>,
        listening_ports_json: Option<&str>,
        sing_box_log_bytes: Option<u64>,
    ) -> Result<()> {
        // SQLite has no BOOLEAN — map Option<bool> → Option<i64>.
        let sb = sing_box_active.map(i64::from);
        let f2b = fail2ban_active.map(i64::from);
        sqlx::query(
            "INSERT INTO node_health
             (ts, server_id, sing_box_active, fail2ban_active,
              disk_used_mib, disk_total_mib,
              mem_available_mib, mem_total_mib,
              load_1min_x100, listening_ports_json, sing_box_log_bytes)
             VALUES (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                     ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        )
        .bind(&server_id.0)
        .bind(sb)
        .bind(f2b)
        .bind(disk_used_mib.and_then(|n| i64::try_from(n).ok()))
        .bind(disk_total_mib.and_then(|n| i64::try_from(n).ok()))
        .bind(mem_available_mib.and_then(|n| i64::try_from(n).ok()))
        .bind(mem_total_mib.and_then(|n| i64::try_from(n).ok()))
        .bind(load_1min_x100.map(i64::from))
        .bind(listening_ports_json)
        .bind(sing_box_log_bytes.and_then(|n| i64::try_from(n).ok()))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Recent rows for one server in the look-back window, newest
    /// first. UI reads this for the server-detail page (chunk 3).
    pub async fn recent_node_health_for_server(
        &self,
        server_id: &ServerId,
        since_hours: u32,
    ) -> Result<Vec<NodeHealthRow>> {
        let rows = sqlx::query(
            "SELECT ts, server_id, sing_box_active, fail2ban_active,
                    disk_used_mib, disk_total_mib,
                    mem_available_mib, mem_total_mib,
                    load_1min_x100, listening_ports_json, sing_box_log_bytes
             FROM node_health
             WHERE server_id = ?1
               AND ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)
             ORDER BY ts DESC",
        )
        .bind(&server_id.0)
        .bind(format!("-{since_hours} hours"))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_node_health).collect()
    }

    /// Most recent single row for a server. Convenience for the
    /// "current state" hero block on the server-detail page —
    /// callers that only need the latest snapshot don't have to
    /// pull a whole 24h Vec just to read the first element.
    pub async fn latest_node_health(&self, server_id: &ServerId) -> Result<Option<NodeHealthRow>> {
        let row_opt = sqlx::query(
            "SELECT ts, server_id, sing_box_active, fail2ban_active,
                    disk_used_mib, disk_total_mib,
                    mem_available_mib, mem_total_mib,
                    load_1min_x100, listening_ports_json, sing_box_log_bytes
             FROM node_health
             WHERE server_id = ?1
             ORDER BY ts DESC
             LIMIT 1",
        )
        .bind(&server_id.0)
        .fetch_optional(&self.pool)
        .await?;
        row_opt.map(row_to_node_health).transpose()
    }

    /// Drop rows older than `days`. Wired by chunk 3 into the
    /// existing retention scheduler.
    pub async fn purge_node_health_older_than(&self, days: u32) -> Result<u64> {
        let res = sqlx::query(
            "DELETE FROM node_health
             WHERE ts < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1)",
        )
        .bind(format!("-{days} days"))
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }
}

/// Extract the `/16` network prefix from a v4 IP literal as a
/// string (`"192.168.0.1"` → `Some("192.168")`). Returns `None`
/// for v6 addresses (no meaningful prefix without ASN data) or
/// malformed strings. Used by the Track-4 UA fingerprint heuristic
/// to count distinct ISP-ish networks per UA.
pub(crate) fn ip_slash16(ip: &str) -> Option<String> {
    // Reject v6 cheaply — colons don't appear in v4 dotted-quad.
    if ip.contains(':') {
        return None;
    }
    let mut parts = ip.split('.');
    let a = parts.next()?;
    let b = parts.next()?;
    let _ = parts.next()?; // third octet must exist (else not v4)
    if a.is_empty() || b.is_empty() {
        return None;
    }
    if !a.bytes().all(|x| x.is_ascii_digit()) || !b.bytes().all(|x| x.is_ascii_digit()) {
        return None;
    }
    Some(format!("{a}.{b}"))
}

/// Escape SQLite LIKE metacharacters (`\`, `%`, `_`) so user-supplied
/// substrings match LITERALLY rather than as patterns. Caller MUST
/// pair this with `ESCAPE '\\'` in the LIKE clause. Without escaping,
/// a filter input of `user_` would match `user.` (the `.` slot is
/// any char per `_`) and `%` would match everything.
pub(crate) fn escape_like(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' | '%' | '_' => {
                out.push('\\');
                out.push(ch);
            }
            other => out.push(other),
        }
    }
    out
}

/// Shared row decoder for audit rows. Used by both `recent_audit` and
/// `recent_audit_paginated` so the field-by-field parsing logic lives
/// in exactly one place.
#[allow(clippy::needless_pass_by_value)]
fn row_to_audit_entry(r: sqlx::sqlite::SqliteRow) -> Result<AuditEntry> {
    let ts_str: String = r.try_get("ts")?;
    let ts = DateTime::parse_from_rfc3339(&ts_str)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|e| {
            SqliteInventoryError::Invalid(format!("audit ts not RFC3339 ({ts_str}): {e}"))
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
}

#[allow(clippy::needless_pass_by_value)]
fn row_to_ban(r: sqlx::sqlite::SqliteRow) -> Result<Ban> {
    let parse_ts = |col: &str, raw: &str| {
        DateTime::parse_from_rfc3339(raw)
            .map(|d| d.with_timezone(&Utc))
            .map_err(|e| {
                SqliteInventoryError::Invalid(format!("ban {col} not RFC3339 ({raw}): {e}"))
            })
    };
    let created_str: String = r.try_get("created_at")?;
    let until_str: String = r.try_get("until_ts")?;
    Ok(Ban {
        id: r.try_get("id")?,
        created_at: parse_ts("created_at", &created_str)?,
        until_ts: parse_ts("until_ts", &until_str)?,
        kind: r.try_get("kind")?,
        key: r.try_get("key")?,
        reason: r.try_get("reason")?,
    })
}

#[allow(clippy::needless_pass_by_value)]
fn row_to_sub_access(r: sqlx::sqlite::SqliteRow) -> Result<SubAccessEntry> {
    let ts_str: String = r.try_get("ts")?;
    let ts = DateTime::parse_from_rfc3339(&ts_str)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|e| {
            SqliteInventoryError::Invalid(format!("sub_access_log ts not RFC3339 ({ts_str}): {e}"))
        })?;
    let status_i: i64 = r.try_get("status")?;
    let bytes_i: i64 = r.try_get("bytes")?;
    Ok(SubAccessEntry {
        id: r.try_get("id")?,
        ts,
        user_id: r.try_get("user_id")?,
        ip: r.try_get("ip")?,
        ua: r.try_get("ua")?,
        // SQLite stores INTEGER, narrow defensively rather than panic.
        status: u16::try_from(status_i).unwrap_or(0),
        bytes: u64::try_from(bytes_i).unwrap_or(0),
    })
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
        wireguard_private: r.try_get("wireguard_private")?,
        sub_token: r.try_get("sub_token")?,
    })
}

#[allow(clippy::needless_pass_by_value)]
fn row_to_node_health(r: sqlx::sqlite::SqliteRow) -> Result<NodeHealthRow> {
    let ts_s: String = r.try_get("ts")?;
    let ts = DateTime::parse_from_rfc3339(&ts_s)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|e| {
            SqliteInventoryError::Invalid(format!("node_health.ts malformed: {ts_s}: {e}"))
        })?;
    let server_id: String = r.try_get("server_id")?;
    let sb_i: Option<i64> = r.try_get("sing_box_active")?;
    let f2b_i: Option<i64> = r.try_get("fail2ban_active")?;
    let disk_u: Option<i64> = r.try_get("disk_used_mib")?;
    let disk_t: Option<i64> = r.try_get("disk_total_mib")?;
    let mem_a: Option<i64> = r.try_get("mem_available_mib")?;
    let mem_t: Option<i64> = r.try_get("mem_total_mib")?;
    let load_i: Option<i64> = r.try_get("load_1min_x100")?;
    let ports: Option<String> = r.try_get("listening_ports_json")?;
    let log_b: Option<i64> = r.try_get("sing_box_log_bytes")?;
    Ok(NodeHealthRow {
        ts,
        server_id: ServerId(server_id),
        sing_box_active: sb_i.map(|n| n != 0),
        fail2ban_active: f2b_i.map(|n| n != 0),
        disk_used_mib: disk_u.and_then(|n| u64::try_from(n).ok()),
        disk_total_mib: disk_t.and_then(|n| u64::try_from(n).ok()),
        mem_available_mib: mem_a.and_then(|n| u64::try_from(n).ok()),
        mem_total_mib: mem_t.and_then(|n| u64::try_from(n).ok()),
        load_1min_x100: load_i.and_then(|n| u32::try_from(n).ok()),
        listening_ports_json: ports,
        sing_box_log_bytes: log_b.and_then(|n| u64::try_from(n).ok()),
    })
}

#[allow(clippy::needless_pass_by_value)]
fn row_to_vpn_stats(r: sqlx::sqlite::SqliteRow) -> Result<VpnStatsRow> {
    let ts_s: String = r.try_get("ts")?;
    let ts = DateTime::parse_from_rfc3339(&ts_s)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|e| {
            SqliteInventoryError::Invalid(format!("vpn_connection_stats.ts malformed: {ts_s}: {e}"))
        })?;
    let server_id: String = r.try_get("server_id")?;
    let user_id_opt: Option<String> = r.try_get("user_id")?;
    let upload_i: i64 = r.try_get("upload_bytes")?;
    let download_i: i64 = r.try_get("download_bytes")?;
    let conns_i: i64 = r.try_get("active_connections")?;
    Ok(VpnStatsRow {
        ts,
        server_id: ServerId(server_id),
        user_id: user_id_opt.map(UserId),
        upload_bytes: u64::try_from(upload_i).unwrap_or(0),
        download_bytes: u64::try_from(download_i).unwrap_or(0),
        active_connections: u32::try_from(conns_i).unwrap_or(0),
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
            wireguard_private: None,
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
