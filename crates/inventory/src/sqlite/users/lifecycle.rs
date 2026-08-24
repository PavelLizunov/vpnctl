use super::crud::row_to_user;
use crate::sqlite::base::{SqliteInventory, escape_like};
use crate::sqlite::models::{Result, SqliteInventoryError, UserLifecycle};
use chrono::{DateTime, Utc};
use sqlx::Row;
use vpnctl_core::{ServerId, User, UserId};

impl SqliteInventory {
    /// Design v2 3d — which granted users' key material is NOT yet in
    /// the node's deployed config: their `user.grant` audit row for
    /// this server has a greater monotonic audit id than the last
    /// successful `server.deploy`. Per-user so the banner can NAME
    /// who's affected without relying on timestamp precision.
    pub async fn users_pending_deploy_for_server(
        &self,
        server_id: &ServerId,
    ) -> Result<Vec<UserId>> {
        let rows = sqlx::query(
            "SELECT DISTINCT a.target AS uid FROM audit_log a
             WHERE a.action = 'user.grant'
               AND json_extract(a.payload, '$.server') = ?1
               AND a.target IN (SELECT user_id FROM grants WHERE server_id = ?1)
               AND a.id > COALESCE(
                     (SELECT MAX(d.id) FROM audit_log d
                      WHERE d.target = ?1 AND d.action = 'server.deploy'),
                     0)
             ORDER BY uid",
        )
        .bind(&server_id.0)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|r| Ok(UserId(r.try_get("uid")?)))
            .collect()
    }

    /// Cheap row count. `0` on an empty table.
    pub async fn count_users(&self) -> Result<i64> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM users")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.try_get("n")?)
    }

    /// **Fleet search** (audit A5, shipped 2026-05-23). Substring
    /// match against `users.id`, `users.uuid`, `users.sub_token`,
    /// `users.vpn_router_device_id`. Case-insensitive via
    /// `LOWER(...)`; returns full `User` rows for the hits so the
    /// search results page can render `id` + secondary identifiers
    /// without a second roundtrip. Capped at `limit` so a pathological
    /// `q="a"` doesn't paginate the entire fleet.
    ///
    /// Empty `q` returns empty — search is opt-in, the index page
    /// shouldn't accidentally dump everything.
    pub async fn search_users(&self, q: &str, limit: i64) -> Result<Vec<User>> {
        if q.is_empty() {
            return Ok(Vec::new());
        }
        let pat = format!("%{}%", escape_like(&q.to_lowercase()));
        let rows = sqlx::query(
            "SELECT id, uuid, tuic_password, wireguard_pubkey, wireguard_private, sub_token, vpn_router_device_id, disabled
             FROM users
             WHERE LOWER(id) LIKE ?1 ESCAPE '\\'
                OR LOWER(uuid) LIKE ?1 ESCAPE '\\'
                OR LOWER(COALESCE(sub_token, '')) LIKE ?1 ESCAPE '\\'
                OR LOWER(COALESCE(vpn_router_device_id, '')) LIKE ?1 ESCAPE '\\'
             ORDER BY id
             LIMIT ?2",
        )
        .bind(&pat)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_user).collect()
    }

    /// Count of users with `disabled = 1` (B1.user, migration 0026).
    /// Cheap — backed by the partial `idx_users_disabled_partial`
    /// index which only contains the disabled rows, so this is O(N
    /// disabled), not O(N total). Used by the dashboard's «N paused»
    /// sub-line so disabled users don't fall off the operator's
    /// radar.
    pub async fn count_disabled_users(&self) -> Result<i64> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM users WHERE disabled = 1")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.try_get("n")?)
    }

    /// **Idle users** — list `(user_id, last_seen)` for users whose
    /// most recent `sub_access_log` row is older than `days` days, OR
    /// who have never appeared in the access log at all (last_seen
    /// is `None`).
    ///
    /// Backs the dashboard «Idle users — revoke candidates» panel
    /// (audit A2). Cheap single LEFT-JOIN with one MAX aggregate;
    /// rows are sorted oldest-first (`last_seen ASC NULLS FIRST`)
    /// so the worst offenders appear at the top. Limit caps the
    /// result set so the panel doesn't grow unbounded.
    ///
    /// **`days = 30` is the canonical threshold for the dashboard**
    /// — a roughly-monthly cycle catches «forgotten phone in a
    /// drawer» without being so aggressive it surfaces normal-
    /// vacation users. Operator can pick a different number; the
    /// query is parameterised.
    ///
    /// Pinned by `idle_users_returns_users_with_old_or_no_last_seen`.
    pub async fn idle_users(
        &self,
        days: u32,
        limit: i64,
    ) -> Result<Vec<(UserId, Option<DateTime<Utc>>)>> {
        let cutoff = format!("-{days} days");
        // LEFT JOIN against an aggregate subquery: every user appears
        // exactly once; users with no sub_access_log row get
        // `last_seen = NULL`. WHERE filter keeps only `last_seen IS
        // NULL` (never seen) OR `last_seen < cutoff` (seen but old).
        // Sort `last_seen ASC NULLS FIRST` so never-seen users float
        // to the top alongside the longest-idle ones.
        let rows = sqlx::query(
            "SELECT u.id AS user_id, la.last_seen AS last_seen
             FROM users u
             LEFT JOIN (
                 SELECT user_id, MAX(ts) AS last_seen
                 FROM sub_access_log
                 WHERE is_vpn_egress = 0
                 GROUP BY user_id
             ) la ON la.user_id = u.id
             WHERE la.last_seen IS NULL
                -- `<=` not `<`: a row whose ts equals the cutoff is
                -- «no newer than the threshold» → idle. Also closes
                -- a CI flake: a tight loop on a fast box can write
                -- the access-log row + run idle_users(0) within one
                -- millisecond, leaving ts == cutoff exactly; strict
                -- `<` would have excluded the row and the test
                -- would intermittently fail.
                OR la.last_seen <= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1)
             ORDER BY (la.last_seen IS NOT NULL), la.last_seen ASC, u.id ASC
             LIMIT ?2",
        )
        .bind(&cutoff)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        let mut out: Vec<(UserId, Option<DateTime<Utc>>)> = Vec::with_capacity(rows.len());
        for row in rows {
            let uid: String = row.try_get("user_id")?;
            let last_seen_str: Option<String> = row.try_get("last_seen")?;
            let last_seen = last_seen_str.and_then(|t| {
                DateTime::parse_from_rfc3339(&t)
                    .ok()
                    .map(|d| d.with_timezone(&Utc))
            });
            out.push((UserId(uid), last_seen));
        }
        Ok(out)
    }

    /// **Q-4d** — user lifecycle facts. `users.created_at` exists
    /// (migration 0001) so this reads it directly + the most recent
    /// real `/sub` fetch, and derives `age_days`. Backs the
    /// user-detail header.
    pub async fn user_lifecycle(&self, user: &UserId) -> Result<UserLifecycle> {
        let row = sqlx::query(
            "SELECT u.created_at AS created_at,
                    (SELECT MAX(ts) FROM sub_access_log
                     WHERE user_id = u.id AND is_vpn_egress = 0) AS last_sub_fetch
             FROM users u
             WHERE u.id = ?1",
        )
        .bind(&user.0)
        .fetch_optional(&self.pool)
        .await?;
        let row =
            row.ok_or_else(|| SqliteInventoryError::Invalid(format!("no such user: {}", user.0)))?;
        let created_s: String = row.try_get("created_at")?;
        let created_at = DateTime::parse_from_rfc3339(&created_s)
            .map(|d| d.with_timezone(&Utc))
            .map_err(|e| {
                SqliteInventoryError::Invalid(format!(
                    "users.created_at malformed: {created_s}: {e}"
                ))
            })?;
        let last_s: Option<String> = row.try_get("last_sub_fetch")?;
        let last_sub_fetch = last_s.and_then(|s| {
            DateTime::parse_from_rfc3339(&s)
                .ok()
                .map(|d| d.with_timezone(&Utc))
        });
        // Floored whole days since creation; never negative (a clock
        // skew that put created_at slightly in the future yields 0).
        let age_days = (Utc::now() - created_at).num_days().max(0) as u64;
        Ok(UserLifecycle {
            created_at,
            last_sub_fetch,
            age_days,
        })
    }
}
