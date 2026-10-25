use super::crud::row_to_user;
use crate::sqlite::base::{SqliteInventory, escape_like};
use crate::sqlite::models::{Result, SqliteInventoryError, UserLifecycle};
use chrono::{DateTime, Utc};
use sqlx::Row;
use vpnctl_core::{ServerId, User, UserId};

impl SqliteInventory {
    pub async fn users_pending_deploy_for_server(
        &self,
        server_id: &ServerId,
    ) -> Result<Vec<UserId>> {
        let rows = sqlx::query(
            "SELECT DISTINCT a.target AS uid FROM audit_log a
             WHERE ((a.action = 'user.grant' AND json_extract(a.payload, '$.server') = ?1)
                    OR a.action IN ('user.add', 'user.set_vpn_router_device_id',
                                    'user.disable', 'user.enable', 'user.wireguard.regen',
                                    'user.mint_tuic_password', 'boosty.disable', 'boosty.enable'))
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

    pub async fn count_users(&self) -> Result<i64> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM users")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.try_get("n")?)
    }

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

    pub async fn count_disabled_users(&self) -> Result<i64> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM users WHERE disabled = 1")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.try_get("n")?)
    }

    pub async fn idle_users(
        &self,
        days: u32,
        limit: i64,
    ) -> Result<Vec<(UserId, Option<DateTime<Utc>>)>> {
        let cutoff = format!("-{days} days");
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
        let age_days = (Utc::now() - created_at).num_days().max(0) as u64;
        Ok(UserLifecycle {
            created_at,
            last_sub_fetch,
            age_days,
        })
    }

    pub async fn user_last_seen(&self, user: &UserId) -> Result<Option<DateTime<Utc>>> {
        let row = sqlx::query(
            "SELECT MAX(latest_ts) AS last_seen FROM (
                 SELECT MAX(ts) AS latest_ts FROM sub_access_log WHERE user_id = ?1
                 UNION ALL
                 SELECT MAX(ts) AS latest_ts FROM vpn_connection_stats
                  WHERE user_id = ?1 AND (upload_bytes > 0 OR download_bytes > 0 OR active_connections > 0)
                 UNION ALL
                 SELECT MAX(last_seen) AS latest_ts FROM vpn_user_sessions WHERE user_id = ?1
                 UNION ALL
                 SELECT last_activity_at AS latest_ts FROM users WHERE id = ?1
             )",
        )
        .bind(&user.0)
        .fetch_one(&self.pool)
        .await?;

        let last_seen_str: Option<String> = row.try_get("last_seen")?;
        Ok(last_seen_str.and_then(|s| {
            DateTime::parse_from_rfc3339(&s)
                .ok()
                .map(|d| d.with_timezone(&Utc))
        }))
    }
}
