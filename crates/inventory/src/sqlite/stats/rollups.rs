use sqlx::Row;
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

impl SqliteInventory {
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

    pub async fn rollup_vpn_user_daily(&self, date_utc: &str) -> Result<u64> {
        let lower = format!("{date_utc}T00:00:00.000Z");
        let upper = format!("{date_utc}T23:59:59.999Z");

        let rows = sqlx::query(
            "SELECT
                user_id,
                server_id,
                COALESCE(SUM(upload_bytes), 0)        AS up_total,
                COALESCE(SUM(download_bytes), 0)      AS dn_total,
                COALESCE(MAX(active_connections), 0)  AS peak_conns
             FROM vpn_connection_stats
             WHERE user_id IN (SELECT id FROM users)
               AND ts >= ?1
               AND ts <= ?2
             GROUP BY user_id, server_id",
        )
        .bind(&lower)
        .bind(&upper)
        .fetch_all(&self.pool)
        .await?;

        let mut tx = self.pool.begin().await?;
        let mut upserted: u64 = 0;
        for r in rows {
            let user_id: String = r.try_get("user_id")?;
            let server_id: String = r.try_get("server_id")?;
            let up_total: i64 = r.try_get("up_total")?;
            let dn_total: i64 = r.try_get("dn_total")?;
            let peak_conns: i64 = r.try_get("peak_conns")?;
            let res = sqlx::query(
                "INSERT INTO vpn_user_daily
                    (date, user_id, server_id, upload_bytes,
                     download_bytes, active_connections_peak,
                     distinct_source_ips, last_rolled_up_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0,
                     strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
                 ON CONFLICT(user_id, server_id, date) DO UPDATE SET
                     upload_bytes              = excluded.upload_bytes,
                     download_bytes            = excluded.download_bytes,
                     active_connections_peak   = excluded.active_connections_peak,
                     last_rolled_up_at         = excluded.last_rolled_up_at",
            )
            .bind(date_utc)
            .bind(&user_id)
            .bind(&server_id)
            .bind(up_total.max(0))
            .bind(dn_total.max(0))
            .bind(peak_conns.max(0))
            .execute(&mut *tx)
            .await?;
            upserted = upserted.saturating_add(res.rows_affected());
        }
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
        let cutoff = format!("-{} days", days.saturating_sub(1));
        let rows = sqlx::query(
            "SELECT d.user_id AS user_id,
                    CAST(SUM(d.upload_bytes
                             * COALESCE(sv.usage_coefficient, 1.0)) AS INTEGER) AS up_b,
                    CAST(SUM(d.download_bytes
                             * COALESCE(sv.usage_coefficient, 1.0)) AS INTEGER) AS down_b
             FROM vpn_user_daily d
             JOIN servers sv ON sv.id = d.server_id
             WHERE d.date >= strftime('%Y-%m-%d', 'now', ?1)
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
