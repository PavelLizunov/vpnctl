use sqlx::{Row, Sqlite, Transaction};
use vpnctl_core::{ServerId, UserId};

use crate::sqlite::base::SqliteInventory;
use crate::sqlite::models::{HeavyUser, Result, VpnUserDailyRow};

#[allow(clippy::needless_pass_by_value)]
fn row_to_vpn_user_daily(r: sqlx::sqlite::SqliteRow) -> Result<VpnUserDailyRow> {
    let date: String = r.try_get("date")?;
    let user_id: String = r.try_get("user_id")?;
    let server_id: String = r.try_get("server_id")?;
    let upload_i: i64 = r.try_get("upload_bytes")?;
    let download_i: i64 = r.try_get("download_bytes")?;
    let peak_i: i64 = r.try_get("active_connections_peak")?;
    let distinct_i: i64 = r.try_get("distinct_source_ips")?;
    Ok(VpnUserDailyRow {
        date,
        user_id: UserId(user_id),
        server_id: ServerId(server_id),
        upload_bytes: upload_i.max(0) as u64,
        download_bytes: download_i.max(0) as u64,
        active_connections_peak: u32::try_from(peak_i.max(0)).unwrap_or(u32::MAX),
        distinct_source_ips: u32::try_from(distinct_i.max(0)).unwrap_or(u32::MAX),
    })
}

async fn rollup_daily(tx: &mut Transaction<'_, Sqlite>, lower: &str, upper: &str) -> Result<u64> {
    // Legacy retention may already have deleted part of an otherwise complete day.
    let res = sqlx::query(
        "INSERT INTO vpn_user_daily
            (date, user_id, server_id, upload_bytes, download_bytes,
             active_connections_peak, distinct_source_ips, last_rolled_up_at)
         SELECT substr(ts, 1, 10), user_id, server_id,
                MAX(SUM(upload_bytes), 0), MAX(SUM(download_bytes), 0),
                MAX(MAX(active_connections), 0), 0,
                strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
         FROM vpn_connection_stats
         WHERE user_id IN (SELECT id FROM users) AND ts >= ?1 AND ts <= ?2
         GROUP BY user_id, server_id, substr(ts, 1, 10)
         ON CONFLICT(user_id, server_id, date) DO UPDATE SET
             upload_bytes = MAX(vpn_user_daily.upload_bytes, excluded.upload_bytes),
             download_bytes = MAX(vpn_user_daily.download_bytes, excluded.download_bytes),
             active_connections_peak = MAX(vpn_user_daily.active_connections_peak,
                                           excluded.active_connections_peak),
             last_rolled_up_at = excluded.last_rolled_up_at
         WHERE vpn_user_daily.upload_bytes < excluded.upload_bytes
            OR vpn_user_daily.download_bytes < excluded.download_bytes
            OR vpn_user_daily.active_connections_peak < excluded.active_connections_peak",
    )
    .bind(lower)
    .bind(upper)
    .execute(&mut **tx)
    .await?;
    let changed = res.rows_affected();
    if changed > 0 {
        sqlx::query(
            "INSERT INTO audit_log (actor, action, payload)
             VALUES ('system', 'stats.daily_rollup', json_object('rows', ?1))",
        )
        .bind(i64::try_from(changed).unwrap_or(i64::MAX))
        .execute(&mut **tx)
        .await?;
    }
    Ok(changed)
}

impl SqliteInventory {
    pub async fn purge_vpn_stats_older_than(&self, days: u32) -> Result<u64> {
        let cutoff_day = chrono::Utc::now().date_naive() - chrono::Days::new(u64::from(days));
        let cutoff = format!("{}T00:00:00.000Z", cutoff_day.format("%Y-%m-%d"));
        let last_purged_day = cutoff_day - chrono::Days::new(1);
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        // Complete the rollup of exactly the days whose raw ticks are deleted
        // below (including days missed during downtime); retained days are
        // rolled up by the scheduler and read from raw rows meanwhile.
        rollup_daily(
            &mut tx,
            "",
            &format!("{}T23:59:59.999Z", last_purged_day.format("%Y-%m-%d")),
        )
        .await?;
        let res = sqlx::query("DELETE FROM vpn_connection_stats WHERE ts < ?1")
            .bind(&cutoff)
            .execute(&mut *tx)
            .await?;
        let removed = res.rows_affected();
        if removed > 0 {
            sqlx::query(
                "INSERT INTO audit_log (actor, action, payload)
                 VALUES ('system', 'stats.purge', json_object('rows', ?1))",
            )
            .bind(i64::try_from(removed).unwrap_or(i64::MAX))
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(removed)
    }

    /// Recompute the daily rollup of every retained raw day. Days are only
    /// missed while the daemon is down, so the daemon runs this once at start
    /// instead of on every hourly purge.
    pub async fn catch_up_vpn_daily_rollups(&self) -> Result<u64> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let upserted = rollup_daily(&mut tx, "", "9999-12-31T23:59:59.999Z").await?;
        tx.commit().await?;
        Ok(upserted)
    }

    pub async fn rollup_vpn_user_daily(&self, date_utc: &str) -> Result<u64> {
        let lower = format!("{date_utc}T00:00:00.000Z");
        let upper = format!("{date_utc}T23:59:59.999Z");
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let upserted = rollup_daily(&mut tx, &lower, &upper).await?;
        tx.commit().await?;
        Ok(upserted)
    }

    pub async fn vpn_user_daily_for_user(
        &self,
        user_id: &UserId,
        days: u32,
    ) -> Result<Vec<VpnUserDailyRow>> {
        let cutoff = format!("-{days} days");
        let rows = sqlx::query(
            "SELECT date, user_id, server_id, upload_bytes,
                    download_bytes, active_connections_peak,
                    distinct_source_ips
             FROM vpn_user_daily
             WHERE user_id = ?1
               AND date >= strftime('%Y-%m-%d', 'now', ?2)
             ORDER BY date DESC, server_id",
        )
        .bind(&user_id.0)
        .bind(&cutoff)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_vpn_user_daily).collect()
    }

    pub async fn top_users_by_daily_traffic(
        &self,
        days: u32,
        limit: u32,
    ) -> Result<Vec<HeavyUser>> {
        let cutoff = (days != u32::MAX).then(|| format!("-{} days", days.saturating_sub(1)));
        let rows = sqlx::query(
            "SELECT d.user_id AS user_id,
                    CAST(SUM(d.upload_bytes
                             * COALESCE(sv.usage_coefficient, 1.0)) AS INTEGER) AS up_b,
                    CAST(SUM(d.download_bytes
                             * COALESCE(sv.usage_coefficient, 1.0)) AS INTEGER) AS down_b
             FROM vpn_user_daily d
             JOIN servers sv ON sv.id = d.server_id
             WHERE d.date >= CASE WHEN ?1 IS NULL THEN ''
                                 ELSE strftime('%Y-%m-%d', 'now', ?1) END
             GROUP BY d.user_id
             ORDER BY SUM((d.upload_bytes + d.download_bytes)
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
                total_bytes: up.saturating_add(down),
            });
        }
        Ok(out)
    }

    pub async fn user_traffic_this_month_from_daily(&self, id: &UserId) -> Result<u64> {
        let row = sqlx::query(
            "SELECT CAST(
                        COALESCE(
                            SUM((d.upload_bytes + d.download_bytes)
                                * COALESCE(sv.usage_coefficient, 1.0)),
                            0
                        ) AS INTEGER
                    ) AS total
             FROM vpn_user_daily d
             JOIN servers sv ON sv.id = d.server_id
             WHERE d.user_id = ?1
               AND d.date >= strftime('%Y-%m-01', 'now')",
        )
        .bind(&id.0)
        .fetch_one(&self.pool)
        .await?;
        let total: i64 = row.try_get("total")?;
        Ok(total.max(0) as u64)
    }
}
