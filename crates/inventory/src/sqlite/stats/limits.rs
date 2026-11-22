use sqlx::Row;
use vpnctl_core::{ServerId, UserId};

use crate::sqlite::base::SqliteInventory;
use crate::sqlite::models::{HeavyUser, Result, SqliteInventoryError};

impl SqliteInventory {
    pub async fn set_user_traffic_limit(
        &self,
        id: &UserId,
        limit_bytes: Option<u64>,
        threshold_pct: Option<u8>,
    ) -> Result<bool> {
        let limit_i64 = limit_bytes.map(|b| i64::try_from(b).unwrap_or(i64::MAX));
        let threshold_i64 = threshold_pct.map(i64::from);
        let res = sqlx::query(
            "UPDATE users
                SET monthly_bandwidth_limit_bytes = ?1,
                    traffic_alert_threshold_pct  = ?2
              WHERE id = ?3
                AND (monthly_bandwidth_limit_bytes IS NOT ?1
                     OR traffic_alert_threshold_pct IS NOT ?2)",
        )
        .bind(limit_i64)
        .bind(threshold_i64)
        .bind(&id.0)
        .execute(&self.pool)
        .await?;
        let changed = res.rows_affected() != 0;
        if !changed && self.get_user(id).await?.is_none() {
            return Err(SqliteInventoryError::Invalid(format!(
                "no such user: {}",
                id.0
            )));
        }
        Ok(changed)
    }

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

    pub async fn user_traffic_this_month(&self, id: &UserId) -> Result<u64> {
        let row = sqlx::query(
            "SELECT CAST(
                        COALESCE(
                            SUM((s.upload_bytes + s.download_bytes)
                                * COALESCE(sv.usage_coefficient, 1.0)),
                            0
                        ) AS INTEGER
                    ) AS total
             FROM vpn_connection_stats s
             JOIN servers sv ON sv.id = s.server_id
             WHERE s.user_id = ?1
               AND s.ts >= strftime('%Y-%m-01T00:00:00', 'now')",
        )
        .bind(&id.0)
        .fetch_one(&self.pool)
        .await?;
        let total: i64 = row.try_get("total")?;
        Ok(total.max(0) as u64)
    }

    pub async fn users_traffic_vs_limit(&self) -> Result<Vec<(UserId, u64, u64, u8)>> {
        let rows = sqlx::query(
            "SELECT u.id,
                    COALESCE(u.traffic_alert_threshold_pct, 80) AS threshold,
                    u.monthly_bandwidth_limit_bytes AS lim,
                    CAST(
                        COALESCE(
                            (SELECT SUM((s.upload_bytes + s.download_bytes)
                                        * COALESCE(sv.usage_coefficient, 1.0))
                             FROM vpn_connection_stats s
                             JOIN servers sv ON sv.id = s.server_id
                             WHERE s.user_id = u.id
                               AND s.ts >= strftime('%Y-%m-01T00:00:00', 'now')),
                            0
                        ) AS INTEGER
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

    pub async fn top_users_by_traffic(
        &self,
        since_hours: u32,
        limit: u32,
    ) -> Result<Vec<HeavyUser>> {
        let cutoff = (since_hours != u32::MAX).then(|| format!("-{since_hours} hours"));
        let rows = sqlx::query(
            "WITH raw_daily AS (
                 SELECT s.user_id AS user_id,
                        s.server_id AS server_id,
                        substr(s.ts, 1, 10) AS day,
                        SUM(s.upload_bytes) AS upload_bytes,
                        SUM(s.download_bytes) AS download_bytes
                 FROM vpn_connection_stats s
                 WHERE s.user_id IN (SELECT id FROM users)
                   AND (?1 IS NULL
                        OR s.ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1))
                 GROUP BY s.user_id, s.server_id, substr(s.ts, 1, 10)
             ),
             combined AS (
                 SELECT user_id, server_id, upload_bytes, download_bytes FROM raw_daily
                 UNION ALL
                 SELECT d.user_id,
                        d.server_id,
                        MAX(d.upload_bytes - COALESCE(r.upload_bytes, 0), 0),
                        MAX(d.download_bytes - COALESCE(r.download_bytes, 0), 0)
                 FROM vpn_user_daily d
                 LEFT JOIN raw_daily r
                   ON r.user_id = d.user_id
                  AND r.server_id = d.server_id
                  AND r.day = d.date
                 WHERE d.user_id IN (SELECT id FROM users)
                   AND (?1 IS NULL
                        OR d.date > strftime('%Y-%m-%d', 'now', ?1))
                   AND (r.user_id IS NULL
                        OR d.upload_bytes > r.upload_bytes
                        OR d.download_bytes > r.download_bytes)
             )
             SELECT c.user_id AS user_id,
                    CAST(SUM(c.upload_bytes
                             * COALESCE(sv.usage_coefficient, 1.0)) AS INTEGER) AS up_b,
                    CAST(SUM(c.download_bytes
                             * COALESCE(sv.usage_coefficient, 1.0)) AS INTEGER) AS down_b,
                    CAST(SUM((c.upload_bytes + c.download_bytes)
                             * COALESCE(sv.usage_coefficient, 1.0)) AS INTEGER) AS total
             FROM combined c
             JOIN servers sv ON sv.id = c.server_id
             GROUP BY c.user_id
             ORDER BY SUM((c.upload_bytes + c.download_bytes)
                          * COALESCE(sv.usage_coefficient, 1.0)) DESC
             LIMIT ?2",
        )
        .bind(&cutoff)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let uid: String = r.try_get("user_id")?;
            let up = r.try_get::<i64, _>("up_b")?.max(0) as u64;
            let down = r.try_get::<i64, _>("down_b")?.max(0) as u64;
            out.push(HeavyUser {
                user_id: UserId(uid),
                upload_bytes: up,
                download_bytes: down,
                total_bytes: r.try_get::<i64, _>("total")?.max(0) as u64,
            });
        }
        Ok(out)
    }

    pub async fn top_users_by_traffic_for_server(
        &self,
        server: &ServerId,
        since_hours: u32,
        limit: u32,
    ) -> Result<Vec<(UserId, u64)>> {
        let cutoff = (since_hours != u32::MAX).then(|| format!("-{since_hours} hours"));
        let rows = sqlx::query(
            "WITH raw_daily AS (
                 SELECT s.user_id AS user_id,
                        substr(s.ts, 1, 10) AS day,
                        SUM(s.upload_bytes) AS upload_bytes,
                        SUM(s.download_bytes) AS download_bytes
                 FROM vpn_connection_stats s
                 WHERE s.server_id = ?1
                   AND s.user_id IN (SELECT id FROM users)
                   AND (?2 IS NULL
                        OR s.ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2))
                 GROUP BY s.user_id, substr(s.ts, 1, 10)
             ),
             combined AS (
                 SELECT user_id, upload_bytes, download_bytes FROM raw_daily
                 UNION ALL
                 SELECT d.user_id,
                        MAX(d.upload_bytes - COALESCE(r.upload_bytes, 0), 0),
                        MAX(d.download_bytes - COALESCE(r.download_bytes, 0), 0)
                 FROM vpn_user_daily d
                 LEFT JOIN raw_daily r
                   ON r.user_id = d.user_id AND r.day = d.date
                 WHERE d.server_id = ?1
                   AND d.user_id IN (SELECT id FROM users)
                   AND (?2 IS NULL
                        OR d.date > strftime('%Y-%m-%d', 'now', ?2))
                   AND (r.user_id IS NULL
                        OR d.upload_bytes > r.upload_bytes
                        OR d.download_bytes > r.download_bytes)
             )
             SELECT c.user_id AS user_id,
                    CAST(SUM((c.upload_bytes + c.download_bytes)
                             * COALESCE(sv.usage_coefficient, 1.0)) AS INTEGER) AS total
             FROM combined c
             JOIN servers sv ON sv.id = ?1
             GROUP BY c.user_id
             ORDER BY total DESC
             LIMIT ?3",
        )
        .bind(&server.0)
        .bind(&cutoff)
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

    pub async fn user_traffic_by_server(
        &self,
        user: &UserId,
        since_hours: u32,
    ) -> Result<Vec<(ServerId, u64, u64)>> {
        let rows = sqlx::query(
            "SELECT s.server_id AS server_id,
                    CAST(SUM(s.upload_bytes
                             * COALESCE(sv.usage_coefficient, 1.0)) AS INTEGER) AS up_total,
                    CAST(SUM(s.download_bytes
                             * COALESCE(sv.usage_coefficient, 1.0)) AS INTEGER) AS down_total
             FROM vpn_connection_stats s
             JOIN servers sv ON sv.id = s.server_id
             WHERE s.user_id = ?1
               AND s.ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)
             GROUP BY s.server_id
             ORDER BY (up_total + down_total) DESC",
        )
        .bind(&user.0)
        .bind(format!("-{since_hours} hours"))
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let sid: String = r.try_get("server_id")?;
            let up: i64 = r.try_get("up_total")?;
            let down: i64 = r.try_get("down_total")?;
            out.push((ServerId(sid), up.max(0) as u64, down.max(0) as u64));
        }
        Ok(out)
    }
}
