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

/// Expose the embedded `Migrator` to sibling modules — currently
/// `backup::restore_from` uses it to validate that an incoming
/// snapshot's schema is at-or-above the current binary's expected
/// version before atomically swapping it over the live DB.
pub(crate) fn migrator() -> &'static Migrator {
    &MIGRATOR
}

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

/// Phase G — one operator-facing alert row.
///
/// Written by `daemon::health_monitor` when a node_health snapshot
/// crosses a threshold or flips a service state. Stays in the table
/// until the operator explicitly acks via the dashboard / feed page;
/// acked rows enter the 30-day retention window in the existing
/// retention scheduler.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdminAlert {
    pub id: i64,
    pub created_at: DateTime<Utc>,
    pub kind: String,
    pub server_id: Option<ServerId>,
    pub severity: String,
    pub summary: String,
    pub payload_json: Option<String>,
    pub acked_at: Option<DateTime<Utc>>,
}

/// Phase G chunk 3 — Telegram bot transport config. Singleton row.
/// The two main halves (`token`, `chat_id`) are `Option<String>`
/// because the schema allows either to be NULL; the dispatch loop
/// treats either-None as «transport disabled». An «Enable» flow in
/// the Settings UI requires BOTH set.
///
/// **`token` is a SECRET** — same care as `users.wireguard_private`.
/// Never serialise into `audit_log.payload_json` or any
/// operator-visible feed.
///
/// The Settings page renders `••••<last4>` + a «replace» button;
/// the only place the full value goes is the outgoing HTTPS POST
/// to `api.telegram.org`.
///
/// `proxy_via_server_id` (migration 0015) routes the outbound HTTPS
/// through an inventory server via SSH — used when the daemon host
/// can't reach api.telegram.org directly (РФ network blocks, etc).
/// `None` = local curl from the daemon host. Plain TEXT in the
/// schema, NOT an FK, so the operator gets a loud SSH-spawn error
/// if the referenced server is deleted rather than a silent
/// transport-broken state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelegramConfig {
    pub token: Option<String>,
    pub chat_id: Option<String>,
    pub proxy_via_server_id: Option<String>,
}

impl TelegramConfig {
    /// True iff both halves are present — the dispatch loop should
    /// only attempt a send when this is true. The `proxy_via_server_id`
    /// doesn't gate enablement — direct mode is the default and a
    /// missing server reference is independent of «can we Telegram
    /// at all».
    pub fn is_enabled(&self) -> bool {
        self.token.is_some() && self.chat_id.is_some()
    }

    /// Last 4 characters of the token, suitable for «••••<last4>»
    /// rendering on the Settings page. Returns empty string when the
    /// token is absent (caller should branch on `token.is_some()`
    /// first; this is for rendering convenience).
    pub fn token_last4(&self) -> String {
        match &self.token {
            Some(t) if t.len() >= 4 => t[t.len() - 4..].to_string(),
            Some(t) => t.clone(),
            None => String::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SqliteInventory {
    pool: SqlitePool,
}

impl SqliteInventory {
    /// Internal-ish accessor for the underlying `SqlitePool`. Currently
    /// used by the `backup` module to run `VACUUM INTO` (which can't go
    /// through a typed query because the target path isn't bindable).
    /// `pub(crate)` keeps the door closed for external callers — pool
    /// is owned state, not API.
    pub(crate) fn pool(&self) -> &SqlitePool {
        &self.pool
    }

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
            "INSERT INTO servers (id, address, ssh_port, ssh_user, hoster, jump_via, trusted_host_fingerprint, usage_coefficient)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )
        .bind(&s.id.0)
        .bind(&s.address)
        .bind(i64::from(s.ssh_port))
        .bind(&s.ssh_user)
        .bind(&s.hoster)
        .bind(s.jump_via.as_ref().map(|v| v.0.clone()))
        .bind(&s.trusted_host_fingerprint)
        .bind(s.usage_coefficient)
        .execute(&mut *tx)
        .await;
        map_unique(res, format!("server {}", s.id.0))?;

        for kid in &s.kernels {
            sqlx::query("INSERT INTO server_kernels (server_id, kernel_id) VALUES (?1, ?2)")
                .bind(&s.id.0)
                .bind(&kid.0)
                .execute(&mut *tx)
                .await?;
        }

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
            "SELECT id, address, ssh_port, ssh_user, hoster, jump_via, trusted_host_fingerprint, usage_coefficient
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
        let kernels = self
            .list_server_kernels(&ServerId(server_id.clone()))
            .await?;
        let s = Server {
            id: ServerId(server_id),
            address: row.try_get("address")?,
            ssh_port: u16::try_from(row.try_get::<i64, _>("ssh_port")?)
                .map_err(|_| SqliteInventoryError::Invalid("ssh_port out of u16 range".into()))?,
            ssh_user: row.try_get("ssh_user")?,
            kernels,
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

    /// Replace a server's `address` + `ssh_port` + `ssh_user` in
    /// place. Used by the `--overwrite-existing` path of
    /// `vpnctl migrate from-bash` when an operator's earlier
    /// wizard-test created a server row with a stale IP that the
    /// migration needs to correct. Does NOT touch kernels,
    /// protocols, or secrets (those have their own setters); the
    /// scope is intentionally narrow so an accidental call can't
    /// nuke unrelated state.
    pub async fn update_server_address(
        &self,
        id: &ServerId,
        address: &str,
        ssh_port: u16,
        ssh_user: &str,
    ) -> Result<()> {
        if address.is_empty() {
            return Err(SqliteInventoryError::Invalid(
                "address must not be empty".into(),
            ));
        }
        sqlx::query(
            "UPDATE servers SET address = ?1, ssh_port = ?2, ssh_user = ?3,
                                 updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE id = ?4",
        )
        .bind(address)
        .bind(i64::from(ssh_port))
        .bind(ssh_user)
        .bind(&id.0)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn update_trusted_fingerprint(&self, id: &ServerId, fp: &str) -> Result<()> {
        // Defensive validation — a malicious or buggy caller could otherwise
        // store an empty / arbitrary value, after which every future connect
        // silently rejects the real host key with a useless error.
        //
        // Shape check lives in `vpnctl-host-fingerprint` so the CLI, web
        // handler, wizard SSE pipeline, and this final inventory gate all
        // agree on what "valid" means (until 2026-05-18 they did not —
        // the inventory variant rejected URL-safe base64 that the surface
        // validators accepted, producing a confusing late failure).
        if !vpnctl_host_fingerprint::validate_shape(fp) {
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

    /// All kernels this server runs, sorted alphabetically for stable
    /// rendering. Empty Vec is legal in the DB but `validate_server`
    /// rejects it before deploy — see `Registry::validate_server`.
    pub async fn list_server_kernels(&self, id: &ServerId) -> Result<Vec<KernelId>> {
        let rows = sqlx::query(
            "SELECT kernel_id FROM server_kernels WHERE server_id = ?1 ORDER BY kernel_id",
        )
        .bind(&id.0)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| r.try_get::<String, _>("kernel_id").map(KernelId))
            .collect::<std::result::Result<_, _>>()?)
    }

    /// Add a single kernel to a server's runtime set. Idempotent (`ON
    /// CONFLICT DO NOTHING`). Mirrors `add_server_protocol`.
    /// FK constraint on `server_id` surfaces as `Invalid` for unknown
    /// server; kernel id is opaque to the DB (registry validation
    /// happens at deploy time).
    pub async fn add_server_kernel(&self, server: &ServerId, kernel: &KernelId) -> Result<u64> {
        let res = sqlx::query(
            "INSERT INTO server_kernels (server_id, kernel_id) VALUES (?1, ?2)
             ON CONFLICT(server_id, kernel_id) DO NOTHING",
        )
        .bind(&server.0)
        .bind(&kernel.0)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    /// Remove a kernel from a server. Idempotent. Mirrors
    /// `remove_server_protocol`.
    pub async fn remove_server_kernel(&self, server: &ServerId, kernel: &KernelId) -> Result<u64> {
        let res = sqlx::query("DELETE FROM server_kernels WHERE server_id = ?1 AND kernel_id = ?2")
            .bind(&server.0)
            .bind(&kernel.0)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected())
    }

    /// Add a single protocol to a server's `enabled_protocols`.
    /// Idempotent at the SQL layer (`OR IGNORE` on the PK pair) — calling
    /// twice with the same `(server, protocol)` is silent success.
    /// Returns the row-was-actually-inserted count so the caller can
    /// distinguish "already there" from "just added" if it wants to
    /// audit only effective changes (currently web handler audits both).
    /// FK constraint on `server_id` will surface as `Invalid` if the
    /// server doesn't exist; protocol id is opaque to the DB layer
    /// (registry validation happens at deploy time).
    pub async fn add_server_protocol(
        &self,
        server: &ServerId,
        protocol: &ProtocolId,
    ) -> Result<u64> {
        let res = sqlx::query(
            "INSERT INTO server_protocols (server_id, protocol_id) VALUES (?1, ?2)
             ON CONFLICT(server_id, protocol_id) DO NOTHING",
        )
        .bind(&server.0)
        .bind(&protocol.0)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    /// Remove a protocol from a server's `enabled_protocols`. Idempotent:
    /// removing a not-present (server, protocol) is silent success.
    /// Returns the row-was-actually-deleted count for the same audit
    /// reason as `add_server_protocol`.
    pub async fn remove_server_protocol(
        &self,
        server: &ServerId,
        protocol: &ProtocolId,
    ) -> Result<u64> {
        let res =
            sqlx::query("DELETE FROM server_protocols WHERE server_id = ?1 AND protocol_id = ?2")
                .bind(&server.0)
                .bind(&protocol.0)
                .execute(&self.pool)
                .await?;
        Ok(res.rows_affected())
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

    // ── Per-(server, protocol) visibility (migration 0018) ───────────
    //
    // The `hidden` flag suppresses a protocol from EVERY rendered
    // subscription URL (sub.rs + vpn_router.rs filters) while keeping
    // the inbound running on the live node — clients with cached URIs
    // keep working until they re-pull. The render path checks via
    // `visible_protocols_for_subscription` (compound query that joins
    // server_protocols × grant_protocol_overrides); this method is the
    // raw read used by the admin UI's `/admin/servers/<id>` toggles.

    /// Is the (server, protocol) pair flagged `hidden=1`?
    /// `false` if the row exists with `hidden=0` OR if the row is
    /// absent (protocol not enabled on the server at all — nothing
    /// to hide). Use `list_server_protocols` first if you need to
    /// distinguish "not enabled" from "enabled but visible".
    pub async fn is_server_protocol_hidden(
        &self,
        sid: &ServerId,
        pid: &ProtocolId,
    ) -> Result<bool> {
        let row = sqlx::query(
            "SELECT hidden FROM server_protocols WHERE server_id = ?1 AND protocol_id = ?2",
        )
        .bind(&sid.0)
        .bind(&pid.0)
        .fetch_optional(&self.pool)
        .await?;
        // Propagate sqlx Decode errors via `?` — review-agent
        // 2026-05-20 flagged that `.unwrap_or(0)` would silently
        // return `false` (visible) on a broken column type, fail-
        // OPEN on a security-relevant flag.
        match row {
            Some(r) => {
                let h: i64 = r.try_get("hidden")?;
                Ok(h != 0)
            }
            None => Ok(false),
        }
    }

    /// Toggle the `hidden` flag on an existing (server, protocol) row.
    /// Refuses if the row doesn't exist (operator must `add_protocol`
    /// first — hide is a render-suppression, not a protocol enablement).
    /// Writes an audit row inside the same transaction (mirrors the
    /// `set_grant_client_uuid` write-+-audit invariant from CLAUDE.md).
    pub async fn set_server_protocol_hidden(
        &self,
        sid: &ServerId,
        pid: &ProtocolId,
        hidden: bool,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;

        // Read the old value first — needed for the audit payload AND
        // for the "no such row" check.
        let prior = sqlx::query(
            "SELECT hidden FROM server_protocols WHERE server_id = ?1 AND protocol_id = ?2",
        )
        .bind(&sid.0)
        .bind(&pid.0)
        .fetch_optional(&mut *tx)
        .await?;
        let prior_hidden: bool = match prior {
            Some(row) => row.try_get::<i64, _>("hidden")? != 0,
            None => {
                return Err(SqliteInventoryError::Invalid(format!(
                    "no such server_protocols row ({}, {}); enable the protocol first via add_protocol",
                    sid.0, pid.0
                )));
            }
        };

        // No-op short-circuit (review-agent 2026-05-20): if the flag
        // is already at the target value, don't UPDATE and don't
        // pollute audit_log. "One audit row per mutation" invariant
        // means non-mutations write zero rows. Idempotent re-clicks
        // from the UI become silent.
        if prior_hidden == hidden {
            tx.commit().await?;
            return Ok(());
        }

        let new_hidden = i64::from(hidden);
        sqlx::query(
            "UPDATE server_protocols SET hidden = ?1 WHERE server_id = ?2 AND protocol_id = ?3",
        )
        .bind(new_hidden)
        .bind(&sid.0)
        .bind(&pid.0)
        .execute(&mut *tx)
        .await?;

        let payload = serde_json::json!({
            "server_id": sid.0,
            "protocol_id": pid.0,
            "old_hidden": prior_hidden,
            "new_hidden": hidden,
        });
        let payload_str = serde_json::to_string(&payload)?;
        sqlx::query(
            "INSERT INTO audit_log (actor, action, target, payload)
             VALUES (?1, ?2, ?3, ?4)",
        )
        .bind("admin")
        .bind("server_protocol.set_hidden")
        .bind(&sid.0)
        .bind(payload_str)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Set or clear the per-(user, server, protocol) deny override.
    /// `disabled = true` inserts (or no-ops if already disabled).
    /// `disabled = false` deletes the override row (back to inherit-
    /// from-server). FK-fails (returns Invalid) if no grant exists for
    /// (user, server) — operator must grant first via `grant()`. Writes
    /// audit `grant_protocol.set_override`.
    pub async fn set_grant_protocol_override(
        &self,
        uid: &UserId,
        sid: &ServerId,
        pid: &ProtocolId,
        disabled: bool,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;

        // FK precheck — composite FK to grants(user_id, server_id).
        // Without this the INSERT fails with raw `Sqlx(Database(...))`
        // which is harder to handle on the caller side.
        let grant_exists =
            sqlx::query("SELECT 1 FROM grants WHERE user_id = ?1 AND server_id = ?2")
                .bind(&uid.0)
                .bind(&sid.0)
                .fetch_optional(&mut *tx)
                .await?
                .is_some();
        if !grant_exists {
            return Err(SqliteInventoryError::Invalid(format!(
                "no grant for ({}, {}); cannot set per-protocol override without an existing grant",
                uid.0, sid.0
            )));
        }

        // Capture rows_affected so we only write audit on actual
        // mutation (review-agent 2026-05-20 "audit-per-mutation"
        // invariant: re-clicking a disable button must NOT spam
        // the audit_log with no-op rows).
        let rows_affected = if disabled {
            sqlx::query(
                "INSERT INTO grant_protocol_overrides (user_id, server_id, protocol_id, state)
                 VALUES (?1, ?2, ?3, 'disabled')
                 ON CONFLICT(user_id, server_id, protocol_id) DO NOTHING",
            )
            .bind(&uid.0)
            .bind(&sid.0)
            .bind(&pid.0)
            .execute(&mut *tx)
            .await?
            .rows_affected()
        } else {
            sqlx::query(
                "DELETE FROM grant_protocol_overrides WHERE user_id = ?1 AND server_id = ?2 AND protocol_id = ?3",
            )
            .bind(&uid.0)
            .bind(&sid.0)
            .bind(&pid.0)
            .execute(&mut *tx)
            .await?
            .rows_affected()
        };

        if rows_affected == 0 {
            tx.commit().await?;
            return Ok(());
        }

        let payload = serde_json::json!({
            "user_id": uid.0,
            "server_id": sid.0,
            "protocol_id": pid.0,
            "disabled": disabled,
        });
        let payload_str = serde_json::to_string(&payload)?;
        sqlx::query(
            "INSERT INTO audit_log (actor, action, target, payload)
             VALUES (?1, ?2, ?3, ?4)",
        )
        .bind("admin")
        .bind("grant_protocol.set_override")
        .bind(&uid.0)
        .bind(payload_str)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Resolve the protocol set a user's subscription URL should
    /// expose for a given server. Combines both axes of the
    /// visibility model:
    ///
    ///   1. `server_protocols.hidden=1` → excluded
    ///   2. `grant_protocol_overrides.state='disabled'` → excluded
    ///   3. otherwise (row exists in `server_protocols` with
    ///      `hidden=0`, no override) → included
    ///
    /// Order: alphabetical by `protocol_id` for deterministic
    /// rendering (so a re-render with no schema change produces
    /// byte-identical output).
    pub async fn visible_protocols_for_subscription(
        &self,
        uid: &UserId,
        sid: &ServerId,
    ) -> Result<Vec<ProtocolId>> {
        let rows = sqlx::query(
            "SELECT sp.protocol_id
             FROM server_protocols sp
             WHERE sp.server_id = ?2
               AND sp.hidden = 0
               AND NOT EXISTS (
                   SELECT 1 FROM grant_protocol_overrides gpo
                   WHERE gpo.user_id = ?1
                     AND gpo.server_id = sp.server_id
                     AND gpo.protocol_id = sp.protocol_id
                     AND gpo.state = 'disabled'
               )
             ORDER BY sp.protocol_id",
        )
        .bind(&uid.0)
        .bind(&sid.0)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|r| Ok(ProtocolId(r.try_get::<String, _>("protocol_id")?)))
            .collect()
    }

    /// Map of (server_id, protocol_id) → `true` for every disabled
    /// override the user has set. Useful for rendering the admin UI
    /// checkboxes pre-populated. Empty map = no overrides = inherit
    /// every server's visibility verbatim.
    pub async fn list_protocol_overrides_for_user(
        &self,
        uid: &UserId,
    ) -> Result<std::collections::HashMap<(ServerId, ProtocolId), bool>> {
        let rows = sqlx::query(
            "SELECT server_id, protocol_id, state
             FROM grant_protocol_overrides
             WHERE user_id = ?1",
        )
        .bind(&uid.0)
        .fetch_all(&self.pool)
        .await?;
        let mut out = std::collections::HashMap::new();
        for r in rows {
            let sid: String = r.try_get("server_id")?;
            let pid: String = r.try_get("protocol_id")?;
            let state: String = r.try_get("state")?;
            // Only 'disabled' is valid today per the CHECK constraint;
            // future 'force-enabled' would flip the bool.
            out.insert((ServerId(sid), ProtocolId(pid)), state == "disabled");
        }
        Ok(out)
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
            "SELECT id, uuid, tuic_password, wireguard_pubkey, wireguard_private, sub_token, vpn_router_device_id
             FROM users WHERE sub_token = ?1",
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await?;
        row.map(row_to_user).transpose()
    }

    /// Overwrite the user's WireGuard / AmneziaWG keypair atomically.
    /// Both halves set together — guarantees the
    /// `private = Some && public = None` inconsistent state can
    /// never appear via this code path.
    ///
    /// Caller produces the standard-base64 strings (typically via
    /// `vpnctl_crypto::gen_wireguard_keypair()`). No shape validation
    /// here — caller's responsibility (web `user_regen_wireguard`
    /// uses the crypto helper directly; no operator-typed input).
    ///
    /// Returns `Invalid` when no such user (mirrors
    /// `regenerate_sub_token` semantics).
    pub async fn set_user_wireguard_keypair(
        &self,
        id: &UserId,
        pubkey: &str,
        private: &str,
    ) -> Result<()> {
        let res = sqlx::query(
            "UPDATE users SET wireguard_pubkey = ?1, wireguard_private = ?2 WHERE id = ?3",
        )
        .bind(pubkey)
        .bind(private)
        .bind(&id.0)
        .execute(&self.pool)
        .await?;
        if res.rows_affected() == 0 {
            return Err(SqliteInventoryError::Invalid(format!(
                "no such user: {}",
                id.0
            )));
        }
        Ok(())
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
            "SELECT id, uuid, tuic_password, wireguard_pubkey, wireguard_private, sub_token, vpn_router_device_id
             FROM users WHERE id = ?1",
        )
        .bind(&id.0)
        .fetch_optional(&self.pool)
        .await?;
        row.map(row_to_user).transpose()
    }

    pub async fn list_users(&self) -> Result<Vec<User>> {
        let rows = sqlx::query(
            "SELECT id, uuid, tuic_password, wireguard_pubkey, wireguard_private, sub_token, vpn_router_device_id
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

    /// Users granted on `server`, with `uuid` already overridden to the
    /// per-server `grants.client_uuid` if one is set (Phase 1 of the
    /// ninitux merge — see migration `0016_grants_per_server_uuid.sql`).
    ///
    /// Returned `User.uuid` is the value the SERVER expects to see in
    /// VLESS Reality handshakes from this user. It MAY differ between
    /// servers for the same `user.id` once Phase 2 has imported the
    /// per-(user, server) uuids harvested from subscription-server's
    /// `client_server_links` table.
    ///
    /// All OTHER `User` fields (`tuic_password`, `wireguard_pubkey`,
    /// `wireguard_private`, `sub_token`) keep their per-user values —
    /// only `uuid` is per-server. TUIC and WireGuard don't need
    /// per-server differentiation (TUIC carries password + per-user
    /// uuid; WG identifies peers by pubkey not name) so leaving them
    /// global is correct and avoids needless schema bloat.
    pub async fn users_for_server(&self, server: &ServerId) -> Result<Vec<User>> {
        let rows = sqlx::query(
            "SELECT u.id, COALESCE(g.client_uuid, u.uuid) AS uuid, u.tuic_password, u.wireguard_pubkey, u.wireguard_private, u.sub_token, u.vpn_router_device_id
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

    /// Effective VLESS uuid for a (user, server) grant — the value the
    /// server's sing-box would expect in a Reality handshake from this
    /// user. Returns `None` if no grant exists for the pair.
    ///
    /// `COALESCE(grants.client_uuid, users.uuid)`. The override path:
    /// if Phase 2's import has set a per-server `client_uuid` on the
    /// grant (e.g. when ninitux carried a distinct uuid per server for
    /// the same user), that wins; otherwise the user's global uuid is
    /// returned — preserving pre-Phase-1 behaviour byte-for-byte.
    ///
    /// Use this instead of `get_user(id).uuid` when you're about to
    /// render a vless:// share-link OR push a sing-box `inbounds[*].users[*]`
    /// entry for a specific server. The global `users.uuid` is still the
    /// user IDENTITY (used in audit log targets, sub-token lookups, etc),
    /// but it's no longer guaranteed to be the AUTH secret on every
    /// server the user is granted to.
    pub async fn client_uuid_for(
        &self,
        user: &UserId,
        server: &ServerId,
    ) -> Result<Option<String>> {
        let row = sqlx::query(
            "SELECT COALESCE(g.client_uuid, u.uuid) AS uuid
             FROM grants g
             INNER JOIN users u ON u.id = g.user_id
             WHERE g.user_id = ?1 AND g.server_id = ?2",
        )
        .bind(&user.0)
        .bind(&server.0)
        .fetch_optional(&self.pool)
        .await?;
        match row {
            None => Ok(None),
            Some(r) => Ok(Some(r.try_get("uuid")?)),
        }
    }

    /// Set the per-server VLESS uuid override on an existing grant. The
    /// grant must already exist (call `grant` first if not). Idempotent —
    /// setting to the same value is a no-op SQL-wise; setting to a
    /// different value overwrites.
    ///
    /// `client_uuid` MUST be a syntactically valid RFC 4122 UUID
    /// (validated via `vpnctl_crypto::is_valid_uuid`). An empty /
    /// malformed value would silently brick the user on the server
    /// (Reality handshake rejects, no telemetry signals the cause) —
    /// the gate here means a Phase 2 import script that hits one bad
    /// row fails loudly per-row instead of silently degrading.
    ///
    /// Errors:
    ///   * `Invalid` when `client_uuid` doesn't pass the UUID-shape
    ///     check.
    ///   * `Invalid` when the (user, server) pair has no grant row —
    ///     callers should NOT silently create the grant here. The
    ///     Phase 2 import script grants first, then sets the per-server
    ///     uuid as a separate step (so audit log clearly reflects each
    ///     mutation).
    ///
    /// Audit: writes a `grant.set_client_uuid` row with both old + new
    /// uuid values in the payload, so the operator can trace «when did
    /// this user's vps-de-01 uuid change?» in the audit timeline.
    pub async fn set_grant_client_uuid(
        &self,
        user: &UserId,
        server: &ServerId,
        client_uuid: &str,
    ) -> Result<()> {
        if !vpnctl_crypto::is_valid_uuid(client_uuid) {
            return Err(SqliteInventoryError::Invalid(format!(
                "client_uuid {client_uuid:?} is not a valid UUID; refusing to write"
            )));
        }

        // Transaction wraps the SELECT-then-UPDATE so two concurrent
        // callers can't interleave (read old=A, read old=A, write B,
        // write C → audit log loses B as the «intermediate» state).
        // Phase 2's import script is single-threaded so the race
        // window is empty in the primary use-case; the transaction
        // exists for future callers + defence in depth. SQLite's
        // single-writer model already serialises the inner write,
        // so the cost here is just one extra BEGIN/COMMIT round-trip.
        //
        // Audit row is emitted INSIDE the same transaction so an
        // «I changed this» row never survives a write that didn't
        // commit (e.g. FK violation surfaced too late). On UPDATE
        // returning 0 rows we roll back via early-return + tx drop.
        let mut tx = self.pool.begin().await?;

        let old_uuid: Option<String> =
            sqlx::query("SELECT client_uuid FROM grants WHERE user_id = ?1 AND server_id = ?2")
                .bind(&user.0)
                .bind(&server.0)
                .fetch_optional(&mut *tx)
                .await?
                .and_then(|row| {
                    row.try_get::<Option<String>, _>("client_uuid")
                        .ok()
                        .flatten()
                });

        let res = sqlx::query(
            "UPDATE grants SET client_uuid = ?3
             WHERE user_id = ?1 AND server_id = ?2",
        )
        .bind(&user.0)
        .bind(&server.0)
        .bind(client_uuid)
        .execute(&mut *tx)
        .await?;
        if res.rows_affected() == 0 {
            // tx drops without commit → SELECT side-effect is rolled
            // back (snapshot read had no side effect anyway, but the
            // shape stays «atomic from caller's perspective»).
            return Err(SqliteInventoryError::Invalid(format!(
                "no grant for user={} server={}; cannot set client_uuid",
                user.0, server.0
            )));
        }

        // Audit row inside the same transaction. Note: the payload
        // logs both old + new client_uuid in plaintext. The VLESS
        // client_uuid IS the Reality auth secret on the corresponding
        // server, so an admin-audit reader sees that secret. This is
        // acceptable for the LAN-only single-operator deployment
        // (admin gate + actor=admin everywhere), but if vpnctld ever
        // gets multi-tenant or externally-exposed audit, the payload
        // should switch to a short fingerprint (e.g. first 8 chars +
        // sha256 suffix) and the full UUID move to a separate
        // auth-gated detail endpoint.
        let audit_payload = serde_json::json!({
            "server_id": server.0,
            "old_client_uuid": old_uuid,
            "new_client_uuid": client_uuid,
        });
        let payload_str = serde_json::to_string(&audit_payload)?;
        sqlx::query(
            "INSERT INTO audit_log (actor, action, target, payload)
             VALUES (?1, ?2, ?3, ?4)",
        )
        .bind("admin")
        .bind("grant.set_client_uuid")
        .bind(&user.0)
        .bind(&payload_str)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Look up a user by their 32-hex `vpn_router_device_id` — the
    /// canonical lookup key in the ninitux URL format. Returns `None`
    /// when no user carries that device_id (the column is partially
    /// unique so at most one row can match). Backs the
    /// `GET /api/v1/app/config/{device_id}` handler in
    /// `daemon::handlers::vpn_router`.
    ///
    /// Caller is expected to validate the input first via
    /// `vpnctl_crypto::is_valid_vpn_router_device_id` — this method
    /// just runs a parameterised SELECT and returns the row (or None).
    /// Refusing malformed input at the handler keeps the SQL fast-path
    /// uniform regardless of garbage input.
    pub async fn find_user_by_vpn_router_device_id(&self, device_id: &str) -> Result<Option<User>> {
        let row = sqlx::query(
            "SELECT id, uuid, tuic_password, wireguard_pubkey, wireguard_private, sub_token, vpn_router_device_id
             FROM users WHERE vpn_router_device_id = ?1",
        )
        .bind(device_id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(row_to_user).transpose()
    }

    /// Pin a 32-hex `vpn_router_device_id` on an existing user. The
    /// user must already exist (call `add_user` first). Setting the
    /// same value twice is a no-op SQL-wise; setting to a different
    /// value rotates the device_id (rare — happens if subscription-
    /// server's `clients.device_id` for that named client gets
    /// rotated for some reason, then re-imported).
    ///
    /// `device_id` MUST be syntactically valid (32 lowercase hex chars,
    /// validated via `vpnctl_crypto::is_valid_vpn_router_device_id`).
    /// Anything else returns `Invalid`. An empty string is rejected
    /// before the gate, so this method cannot accidentally clear an
    /// existing override — use the dedicated `clear` path if you want
    /// to disconnect a user from the vpn-router endpoint.
    ///
    /// Audit: writes `user.set_vpn_router_device_id` row with old +
    /// new values. Same transaction-wrapped pattern as
    /// `set_grant_client_uuid` — SELECT + UPDATE + INSERT all under
    /// one BEGIN…COMMIT so concurrent callers can't interleave.
    pub async fn set_vpn_router_device_id(&self, user: &UserId, device_id: &str) -> Result<()> {
        if !vpnctl_crypto::is_valid_vpn_router_device_id(device_id) {
            return Err(SqliteInventoryError::Invalid(format!(
                "device_id {device_id:?} is not 32 lowercase hex chars; refusing to write"
            )));
        }

        let mut tx = self.pool.begin().await?;

        let old_device_id: Option<String> =
            sqlx::query("SELECT vpn_router_device_id FROM users WHERE id = ?1")
                .bind(&user.0)
                .fetch_optional(&mut *tx)
                .await?
                .and_then(|row| {
                    row.try_get::<Option<String>, _>("vpn_router_device_id")
                        .ok()
                        .flatten()
                });

        // Map SQLite's UNIQUE constraint violation (a different user
        // already pinned this device_id, blocked by the partial
        // index added in migration 0017) to a clean `AlreadyExists`
        // — same shape as `add_user`'s duplicate-id error. Without
        // this mapping the caller would see a raw sqlx error code
        // 2067 wrapped in `Sqlx(...)`, which is hard to handle.
        let res = map_unique(
            sqlx::query("UPDATE users SET vpn_router_device_id = ?2 WHERE id = ?1")
                .bind(&user.0)
                .bind(device_id)
                .execute(&mut *tx)
                .await,
            format!("vpn_router_device_id {device_id}"),
        )?;
        if res.rows_affected() == 0 {
            return Err(SqliteInventoryError::Invalid(format!(
                "no such user: {}; cannot set vpn_router_device_id",
                user.0
            )));
        }

        // Audit row. device_id is NOT a secret (it's a public lookup
        // key — anyone hitting `https://ninitux.com/api/v1/app/config/<id>`
        // already knows it), so logging both old + new in plaintext is
        // safe for the admin-gated audit feed.
        let audit_payload = serde_json::json!({
            "old_vpn_router_device_id": old_device_id,
            "new_vpn_router_device_id": device_id,
        });
        let payload_str = serde_json::to_string(&audit_payload)?;
        sqlx::query(
            "INSERT INTO audit_log (actor, action, target, payload)
             VALUES (?1, ?2, ?3, ?4)",
        )
        .bind("admin")
        .bind("user.set_vpn_router_device_id")
        .bind(&user.0)
        .bind(&payload_str)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Return a `User` clone with `uuid` swapped to the per-server
    /// VLESS uuid override stored in `grants.client_uuid`. When no
    /// override is set (NULL → COALESCE returns `users.uuid`) the
    /// returned User has the same uuid as the input — the helper is
    /// safe to call unconditionally at render time.
    ///
    /// Use this at every share-link / `client_config` rendering
    /// callsite that has both the `User` (e.g. from `find_user_by_sub_token`)
    /// AND a target `ServerId`. Avoids the three-way clone-and-swap
    /// duplication between `cli/cmd/sub.rs` and `daemon/handlers/sub.rs`
    /// (admin uses the peers-list path, which already has the
    /// override applied by `users_for_server`'s COALESCE — that
    /// callsite keeps its own helper).
    ///
    /// Returns the original user clone (uuid unchanged) when no grant
    /// exists for the pair — same fallback as the inline pattern
    /// being replaced. This is the safe choice: a /sub renderer that
    /// hit an inconsistent state (servers_for_user returned a server
    /// the user got revoked from between calls) still produces a
    /// link rather than crashing the whole response.
    pub async fn user_with_per_server_uuid(&self, user: &User, server: &ServerId) -> Result<User> {
        match self.client_uuid_for(&user.id, server).await? {
            Some(client_uuid) if client_uuid != user.uuid => {
                Ok(user.with_per_server_uuid(&client_uuid))
            }
            _ => Ok(user.clone()),
        }
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

    /// Set or clear a user's monthly bandwidth limit + alert
    /// threshold. Pass `Some(limit)` to set, `None` to clear
    /// (operator decided the user no longer needs a cap). Threshold
    /// is a percent (0..=100); the daemon-side default lives in
    /// `vpnctld::admin::DEFAULT_TRAFFIC_THRESHOLD_PCT`.
    ///
    /// Returns `Invalid` if no such user — matches the existing
    /// `regenerate_sub_token` shape.
    pub async fn set_user_traffic_limit(
        &self,
        id: &UserId,
        limit_bytes: Option<u64>,
        threshold_pct: Option<u8>,
    ) -> Result<()> {
        // Cap threshold_pct at u8 max; SQLite stores as INTEGER so
        // both halves fit comfortably.
        let limit_i64 = limit_bytes.map(|b| i64::try_from(b).unwrap_or(i64::MAX));
        let threshold_i64 = threshold_pct.map(i64::from);
        let res = sqlx::query(
            "UPDATE users
                SET monthly_bandwidth_limit_bytes = ?1,
                    traffic_alert_threshold_pct  = ?2
              WHERE id = ?3",
        )
        .bind(limit_i64)
        .bind(threshold_i64)
        .bind(&id.0)
        .execute(&self.pool)
        .await?;
        if res.rows_affected() == 0 {
            return Err(SqliteInventoryError::Invalid(format!(
                "no such user: {}",
                id.0
            )));
        }
        Ok(())
    }

    /// Read both limit fields for a user. Returns
    /// `(monthly_bandwidth_limit_bytes, traffic_alert_threshold_pct)`
    /// — either or both may be `None` (no limit / use default
    /// threshold). Used by the user-detail page + the daemon-side
    /// alert evaluator.
    pub async fn get_user_traffic_limit(&self, id: &UserId) -> Result<(Option<u64>, Option<u8>)> {
        let row = sqlx::query(
            "SELECT monthly_bandwidth_limit_bytes, traffic_alert_threshold_pct
             FROM users WHERE id = ?1",
        )
        .bind(&id.0)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok((None, None));
        };
        let limit: Option<i64> = row.try_get("monthly_bandwidth_limit_bytes")?;
        let threshold: Option<i64> = row.try_get("traffic_alert_threshold_pct")?;
        let limit_u64 = limit.map(|v| if v < 0 { 0 } else { v as u64 });
        let threshold_u8 = threshold.map(|v| v.clamp(0, 100) as u8);
        Ok((limit_u64, threshold_u8))
    }

    /// Total (upload + download) bytes for a user since the start
    /// of the current calendar month (UTC). `0` when no traffic
    /// has been recorded this month — never errors on "no rows".
    /// SQLite's `strftime('%Y-%m-01T00:00:00Z', 'now')` gives the
    /// month-start anchor; resets automatically on the 1st.
    pub async fn user_traffic_this_month(&self, id: &UserId) -> Result<u64> {
        let row = sqlx::query(
            "SELECT COALESCE(SUM(upload_bytes + download_bytes), 0) AS total
             FROM vpn_connection_stats
             WHERE user_id = ?1
               AND ts >= strftime('%Y-%m-01T00:00:00Z', 'now')",
        )
        .bind(&id.0)
        .fetch_one(&self.pool)
        .await?;
        let total: i64 = row.try_get("total")?;
        Ok(total.max(0) as u64)
    }

    /// Aggregate over every user: their month-to-date traffic +
    /// configured limit + configured threshold (or NULLs).
    /// Returns ONLY users who currently have a configured
    /// `monthly_bandwidth_limit_bytes` — operators without a cap
    /// don't need to appear in the dashboard alert section.
    /// Ordered by usage-as-pct-of-limit DESC so the most-at-risk
    /// account is first.
    pub async fn users_traffic_vs_limit(&self) -> Result<Vec<(UserId, u64, u64, u8)>> {
        // The percentage compare is done in Rust because SQLite
        // integer division would truncate to 0 for "5% of 100GB
        // = 5_000_000_000_000 / 100" before SQLite-3.45's bigint
        // arithmetic; safer + clearer in Rust where we already have
        // u64 + f64.
        let rows = sqlx::query(
            "SELECT u.id,
                    COALESCE(u.traffic_alert_threshold_pct, 80) AS threshold,
                    u.monthly_bandwidth_limit_bytes AS lim,
                    COALESCE(
                        (SELECT SUM(s.upload_bytes + s.download_bytes)
                         FROM vpn_connection_stats s
                         WHERE s.user_id = u.id
                           AND s.ts >= strftime('%Y-%m-01T00:00:00Z', 'now')),
                        0
                    ) AS used
             FROM users u
             WHERE u.monthly_bandwidth_limit_bytes IS NOT NULL",
        )
        .fetch_all(&self.pool)
        .await?;
        let mut out: Vec<(UserId, u64, u64, u8)> = Vec::with_capacity(rows.len());
        for r in rows {
            let id: String = r.try_get("id")?;
            let threshold: i64 = r.try_get("threshold")?;
            let lim: i64 = r.try_get("lim")?;
            let used: i64 = r.try_get("used")?;
            let lim_u = lim.max(0) as u64;
            let used_u = used.max(0) as u64;
            let threshold_u = threshold.clamp(0, 100) as u8;
            out.push((UserId(id), used_u, lim_u, threshold_u));
        }
        // Sort by percent-of-limit DESC (most-at-risk first); ties
        // broken by absolute used DESC for stability.
        out.sort_by(|a, b| {
            let pa = if a.2 == 0 {
                0.0
            } else {
                a.1 as f64 / a.2 as f64
            };
            let pb = if b.2 == 0 {
                0.0
            } else {
                b.1 as f64 / b.2 as f64
            };
            pb.partial_cmp(&pa)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| b.1.cmp(&a.1))
        });
        Ok(out)
    }

    /// Top-N users by total (upload + download) bytes over the
    /// look-back window. Used by the dashboard's heavy-user heatmap
    /// to surface abuse-candidate accounts at a glance. Returns
    /// `(user_id, total_bytes)` sorted DESC; rows with NULL user_id
    /// (server-wide aggregates) are excluded.
    ///
    /// Empty Vec when no per-user traffic has been recorded yet (or
    /// when the poller hasn't run). Caller renders an empty-state.
    pub async fn top_users_by_traffic(
        &self,
        since_hours: u32,
        limit: u32,
    ) -> Result<Vec<(UserId, u64)>> {
        let rows = sqlx::query(
            "SELECT user_id, SUM(upload_bytes + download_bytes) AS total
             FROM vpn_connection_stats
             WHERE user_id IS NOT NULL
               AND ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1)
             GROUP BY user_id
             ORDER BY total DESC
             LIMIT ?2",
        )
        .bind(format!("-{since_hours} hours"))
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let uid: String = r.try_get("user_id")?;
            let total: i64 = r.try_get("total")?;
            out.push((UserId(uid), total.max(0) as u64));
        }
        Ok(out)
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

    // ── Phase G admin_alerts ────────────────────────────────────────────

    /// Insert one alert row. Returns the new row id so the caller can
    /// reference it in an `audit()` payload — every fired alert ALSO
    /// gets an audit_log row with `action='alert.fire'` so the full
    /// timeline view in `/admin/audit` stays coherent.
    ///
    /// `payload_json` is opaque to inventory — callers serialise
    /// whatever structured context they want (thresholds, prior
    /// values, observed timestamp) and pass the resulting JSON
    /// string. NULL = no extra context.
    ///
    /// **Do NOT serialise secrets** (`User.uuid`, `User.sub_token`,
    /// `tuic_password`, `wireguard_private`, etc.) into
    /// `payload_json`. The string is rendered verbatim in the
    /// operator-facing `/admin/alerts` feed AND copied into the
    /// `audit_log` row AND any future webhook payload (Phase G
    /// chunk 3). Stick to thresholds, percentages, prior/current
    /// values, and other operationally-relevant numbers.
    pub async fn insert_alert(
        &self,
        kind: &str,
        server_id: Option<&ServerId>,
        severity: &str,
        summary: &str,
        payload_json: Option<&str>,
    ) -> Result<i64> {
        let res = sqlx::query(
            "INSERT INTO admin_alerts (kind, server_id, severity, summary, payload_json)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(kind)
        .bind(server_id.map(|s| s.0.as_str()))
        .bind(severity)
        .bind(summary)
        .bind(payload_json)
        .execute(&self.pool)
        .await?;
        Ok(res.last_insert_rowid())
    }

    /// Count alerts that haven't been acked yet — backs the dashboard
    /// «N unacked alerts» tile. One indexed SELECT.
    pub async fn unacked_alert_count(&self) -> Result<u64> {
        let row: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM admin_alerts WHERE acked_at IS NULL")
                .fetch_one(&self.pool)
                .await?;
        Ok(u64::try_from(row.0).unwrap_or(0))
    }

    /// Recent alerts, newest first. `include_acked = false` matches the
    /// default feed view (only currently-actionable items); `true`
    /// shows the full history including ones the operator dismissed.
    pub async fn recent_alerts(&self, limit: i64, include_acked: bool) -> Result<Vec<AdminAlert>> {
        let where_clause = if include_acked {
            ""
        } else {
            "WHERE acked_at IS NULL"
        };
        let sql = format!(
            "SELECT id, created_at, kind, server_id, severity, summary,
                    payload_json, acked_at
             FROM admin_alerts
             {where_clause}
             ORDER BY id DESC
             LIMIT ?1"
        );
        let rows = sqlx::query(&sql).bind(limit).fetch_all(&self.pool).await?;
        rows.into_iter().map(row_to_admin_alert).collect()
    }

    /// Mark one alert as acked. Returns `true` if the row existed AND
    /// was unacked (the operator-visible state actually changed),
    /// `false` if the id is unknown OR was already acked (idempotent).
    /// Doesn't error on a duplicate ack — the dashboard tile uses POST
    /// without an Idempotency-Key, so a refresh-after-ack should not
    /// 500.
    pub async fn ack_alert(&self, id: i64) -> Result<bool> {
        let res = sqlx::query(
            "UPDATE admin_alerts
             SET acked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE id = ?1 AND acked_at IS NULL",
        )
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Fire-once-per-condition variant of [`insert_alert`].
    ///
    /// Insert a new alert row ONLY if there is no currently-unacked row
    /// of the same `(kind, server_id)` pair. Returns `Some(new_id)` if
    /// inserted, `None` if a matching unacked row already existed
    /// (idempotent — the caller's tick-driven detection loop can call
    /// this every probe interval without flooding the feed).
    ///
    /// Semantics: a `(kind, server_id)` pair has at most ONE open row
    /// in the unacked view at a time. The operator acks it (or it gets
    /// auto-acked by a recovery transition via [`ack_open_alerts`]),
    /// AFTER which the next firing legitimately creates a fresh row.
    /// This matches the natural state-machine for «is this condition
    /// currently raised?».
    ///
    /// ## Atomicity
    ///
    /// The dedup is enforced at the SQL ENGINE level by the partial
    /// UNIQUE index `idx_admin_alerts_unique_unacked` (migration
    /// 0013), keyed on `(kind, COALESCE(server_id, '__GLOBAL__'))`
    /// filtered to `acked_at IS NULL`. A simple `INSERT OR IGNORE`
    /// is therefore atomic across concurrent writers — there is no
    /// READ-then-WRITE race window the way an `INSERT ... SELECT ...
    /// WHERE NOT EXISTS` formulation would have. Two daemons (or
    /// two sqlx pool connections) firing simultaneously cannot
    /// both succeed; the loser silently no-ops via the IGNORE clause.
    ///
    /// ## Secret-leakage warning (mirrored from [`insert_alert`])
    ///
    /// **Do NOT serialise secrets** (`User.uuid`, `User.sub_token`,
    /// `tuic_password`, `wireguard_private`, etc.) into `payload_json`.
    /// The string is rendered verbatim in the operator-facing
    /// `/admin/alerts` feed AND copied into the audit_log row AND any
    /// future webhook payload (Phase G chunk 3). Stick to thresholds,
    /// percentages, prior/current values, and other operationally-
    /// relevant numbers.
    pub async fn insert_alert_if_no_unacked(
        &self,
        kind: &str,
        server_id: Option<&ServerId>,
        severity: &str,
        summary: &str,
        payload_json: Option<&str>,
    ) -> Result<Option<i64>> {
        let server_id_str = server_id.map(|s| s.0.as_str());
        let res = sqlx::query(
            "INSERT OR IGNORE INTO admin_alerts
                 (kind, server_id, severity, summary, payload_json)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(kind)
        .bind(server_id_str)
        .bind(severity)
        .bind(summary)
        .bind(payload_json)
        .execute(&self.pool)
        .await?;
        if res.rows_affected() == 1 {
            Ok(Some(res.last_insert_rowid()))
        } else {
            Ok(None)
        }
    }

    /// Bulk-ack every currently-unacked alert of the given `(kind,
    /// server_id)` pair. Returns `rows_affected` — `0` if no matching
    /// open row existed (idempotent: the caller's recovery-detection
    /// loop can call this every probe interval without erroring out
    /// when the condition was never raised).
    ///
    /// Companion to [`insert_alert_if_no_unacked`]. The «recovery
    /// silently clears the alert» semantics is intentional — an alert
    /// that auto-clears doesn't need operator attention; the audit_log
    /// row written by the caller preserves the timeline. If the
    /// operator's preference shifts to «recovery emits a new
    /// `*.recovered` info alert», that's a Phase G chunk 3 decision,
    /// not this helper's responsibility.
    ///
    /// ## NULL-equality predicate
    ///
    /// SQLite's regular `=` returns NULL on NULL operands; for the
    /// `server_id IS NULL` global-alert case we use
    /// `((?2 IS NULL AND server_id IS NULL) OR server_id = ?2)` so
    /// NULL matches NULL. The companion [`insert_alert_if_no_unacked`]
    /// achieves the same semantics via the partial UNIQUE index's
    /// `COALESCE(server_id, '__GLOBAL__')` expression — different
    /// mechanism, same observable rule.
    ///
    /// ## Race-vs-concurrent-fire
    ///
    /// If a new firing of the same (kind, server_id) lands between
    /// this UPDATE's row-scan and commit, that new row legitimately
    /// represents the NEXT occurrence — the condition recovered then
    /// re-fired. The new row remains unacked; the operator sees it.
    /// This is the correct semantics for a state-machine that
    /// distinguishes «raised → cleared → raised again».
    pub async fn ack_open_alerts(&self, kind: &str, server_id: Option<&ServerId>) -> Result<u64> {
        let server_id_str = server_id.map(|s| s.0.as_str());
        let res = sqlx::query(
            "UPDATE admin_alerts
             SET acked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE kind = ?1
               AND ((?2 IS NULL AND server_id IS NULL) OR server_id = ?2)
               AND acked_at IS NULL",
        )
        .bind(kind)
        .bind(server_id_str)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    // ── Phase G chunk 3 notification_settings ──────────────────────

    /// Read the singleton notification-transport config. All three
    /// fields are `Option<String>` because each can independently be
    /// NULL in the schema; callers downstream (the dispatch loop, the
    /// Settings UI) decide what to do with partial config.
    ///
    /// Returns `Ok(None)` if the singleton row is somehow missing
    /// (shouldn't happen — migration 0014 seeds it — but defended
    /// against so a corrupted DB doesn't crash-loop the daemon).
    pub async fn get_telegram_config(&self) -> Result<Option<TelegramConfig>> {
        let row = sqlx::query_as::<_, (Option<String>, Option<String>, Option<String>)>(
            "SELECT telegram_bot_token, telegram_chat_id, proxy_via_server_id
             FROM notification_settings WHERE id = 1",
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(
            row.map(|(token, chat_id, proxy_via_server_id)| TelegramConfig {
                token,
                chat_id,
                proxy_via_server_id,
            }),
        )
    }

    /// Atomically set ALL THREE halves of the Telegram config. `None`
    /// for a field clears it. Caller-side validators (the Settings
    /// POST handler) reject the «partial config» state of
    /// (Some(token), None, _) or vice versa before reaching here —
    /// but the DB doesn't enforce it because «clear» is a legitimate
    /// `Set(None, None, None)` call.
    ///
    /// `proxy_via_server_id` is a plain TEXT (no FK to `servers.id`)
    /// — see migration 0015's doc-comment for the rationale (operator
    /// gets a loud SSH-spawn error rather than a silent FK-cascade
    /// NULL when the referenced server is deleted).
    ///
    /// Writes `updated_at` automatically via `strftime`. Does NOT
    /// write to `audit_log` — caller is responsible for the audit
    /// row (with `payload_json` that NEVER includes the token).
    pub async fn set_telegram_config(
        &self,
        token: Option<&str>,
        chat_id: Option<&str>,
        proxy_via_server_id: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE notification_settings
             SET telegram_bot_token  = ?1,
                 telegram_chat_id    = ?2,
                 proxy_via_server_id = ?3,
                 updated_at          = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE id = 1",
        )
        .bind(token)
        .bind(chat_id)
        .bind(proxy_via_server_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Drop ACKED alerts older than `days`. UNACKED alerts are NEVER
    /// auto-purged (an alert that fires once and is forgotten must
    /// still be visible — see migration 0011 doc-comment for the
    /// rationale). Wired into the existing retention scheduler.
    pub async fn purge_acked_alerts_older_than(&self, days: u32) -> Result<u64> {
        let res = sqlx::query(
            "DELETE FROM admin_alerts
             WHERE acked_at IS NOT NULL
               AND acked_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1)",
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
//
// The SHA256 fingerprint shape check that used to live here moved to
// `vpnctl-host-fingerprint::validate_shape` so every surface (CLI / web /
// wizard / this inventory gate) shares one canonical definition.

#[allow(clippy::needless_pass_by_value)]
fn row_to_user(r: sqlx::sqlite::SqliteRow) -> Result<User> {
    Ok(User {
        id: UserId(r.try_get("id")?),
        uuid: r.try_get("uuid")?,
        tuic_password: r.try_get("tuic_password")?,
        wireguard_pubkey: r.try_get("wireguard_pubkey")?,
        wireguard_private: r.try_get("wireguard_private")?,
        sub_token: r.try_get("sub_token")?,
        // Reads the column added by migration 0017. Bare `?` (no
        // turbofish) — same pattern as the other Option<String>
        // columns above. Rust infers `T = Option<String>` from the
        // field type, which routes through sqlx's `Option<T>` Decode
        // impl and handles NULL → `None` correctly. Initial fix
        // used `.ok()` which inferred `T = String` and SQLite
        // decoded NULL as `""` (caught 2026-05-19: `DEVICE_ID =
        // Some("")` instead of `None` made every fresh-user
        // detail page render the ninitux URL with an empty
        // device_id).
        vpn_router_device_id: r.try_get("vpn_router_device_id")?,
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
fn row_to_admin_alert(r: sqlx::sqlite::SqliteRow) -> Result<AdminAlert> {
    let created_at_s: String = r.try_get("created_at")?;
    let created_at = DateTime::parse_from_rfc3339(&created_at_s)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|e| {
            SqliteInventoryError::Invalid(format!(
                "admin_alerts.created_at malformed: {created_at_s}: {e}"
            ))
        })?;
    let acked_at_s: Option<String> = r.try_get("acked_at")?;
    let acked_at = match acked_at_s {
        Some(s) => Some(
            DateTime::parse_from_rfc3339(&s)
                .map(|d| d.with_timezone(&Utc))
                .map_err(|e| {
                    SqliteInventoryError::Invalid(format!(
                        "admin_alerts.acked_at malformed: {s}: {e}"
                    ))
                })?,
        ),
        None => None,
    };
    let server_id_s: Option<String> = r.try_get("server_id")?;
    Ok(AdminAlert {
        id: r.try_get("id")?,
        created_at,
        kind: r.try_get("kind")?,
        server_id: server_id_s.map(ServerId),
        severity: r.try_get("severity")?,
        summary: r.try_get("summary")?,
        payload_json: r.try_get("payload_json")?,
        acked_at,
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
            kernels: vec![KernelId("sing-box".into())],
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
            vpn_router_device_id: None,
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
