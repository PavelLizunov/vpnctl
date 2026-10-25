use std::collections::HashMap;

use chrono::{DateTime, Utc};
use sqlx::Row;
use vpnctl_core::{ServerId, UserId};

use crate::sqlite::base::{SqliteInventory, real_client_ip_predicate};
use crate::sqlite::models::{Result, ServerLiveActivity};

impl SqliteInventory {
    pub async fn attribution_stall_servers(
        &self,
        window_minutes: u32,
        min_active: u32,
    ) -> Result<Vec<ServerId>> {
        let rows = sqlx::query(
            "SELECT server_id
             FROM vpn_connection_stats
             WHERE ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1)
             GROUP BY server_id
             HAVING MAX(active_connections) >= ?2
                AND COUNT(DISTINCT CASE WHEN user_id IS NOT NULL THEN user_id END) = 0",
        )
        .bind(format!("-{window_minutes} minutes"))
        .bind(i64::from(min_active))
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| ServerId(r.get::<String, _>("server_id")))
            .collect())
    }

    pub async fn weighted_vpn_traffic_by_server(
        &self,
        since_hours: u32,
    ) -> Result<Vec<(ServerId, u64)>> {
        if since_hours == 0 {
            return Ok(Vec::new());
        }
        let rows = sqlx::query(
            "SELECT
                stats.server_id AS server_id,
                CAST(SUM(
                    (stats.upload_bytes + stats.download_bytes)
                    * COALESCE(servers.usage_coefficient, 1.0)
                ) AS INTEGER) AS total_bytes
             FROM vpn_server_hourly stats
             JOIN servers ON servers.id = stats.server_id
             WHERE stats.hour >= strftime('%Y-%m-%dT%H:00:00.000Z', 'now', ?1)
             GROUP BY stats.server_id",
        )
        .bind(format!("-{} hours", since_hours - 1))
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let server_id: String = row.try_get("server_id")?;
            let total_bytes: i64 = row.try_get("total_bytes")?;
            out.push((ServerId(server_id), total_bytes.max(0) as u64));
        }
        Ok(out)
    }

    pub async fn server_live_activity(
        &self,
        server_id: &ServerId,
        since_hours: u32,
        max_age_secs: u64,
    ) -> Result<ServerLiveActivity> {
        let since = format!("-{since_hours} hours");
        let row = sqlx::query(
            "WITH win AS (
                SELECT upload_bytes, download_bytes, ts, user_id, active_connections
                FROM vpn_connection_stats
                WHERE server_id = ?1
                  AND ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)
            )
            SELECT
                COALESCE((SELECT SUM(upload_bytes)   FROM win), 0) AS bytes_up,
                COALESCE((SELECT SUM(download_bytes) FROM win), 0) AS bytes_dn,
                (SELECT MAX(ts) FROM win)                           AS last_ts,
                (SELECT COUNT(DISTINCT user_id) FROM win WHERE user_id IS NOT NULL) AS attributed,
                (SELECT active_connections FROM vpn_connection_stats
                 WHERE server_id = ?1 AND user_id IS NULL
                   AND ts >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?3)
                 ORDER BY ts DESC, rowid DESC LIMIT 1)              AS active_now",
        )
        .bind(&server_id.0)
        .bind(&since)
        .bind(format!("-{max_age_secs} seconds"))
        .fetch_one(&self.pool)
        .await?;

        let bytes_up: i64 = row.try_get("bytes_up")?;
        let bytes_dn: i64 = row.try_get("bytes_dn")?;
        let last_ts_s: Option<String> = row.try_get("last_ts")?;
        let attributed: i64 = row.try_get("attributed")?;
        let active_now_opt: Option<i64> = row.try_get("active_now")?;
        let active_now = active_now_opt.map(|v| u32::try_from(v.max(0)).unwrap_or(u32::MAX));

        Ok(ServerLiveActivity {
            active_now,
            bytes_up_window: bytes_up.max(0) as u64,
            bytes_dn_window: bytes_dn.max(0) as u64,
            last_sample_ts: last_ts_s.and_then(|t| {
                DateTime::parse_from_rfc3339(&t)
                    .ok()
                    .map(|d| d.with_timezone(&Utc))
            }),
            distinct_users_attributed: u32::try_from(attributed.max(0)).unwrap_or(u32::MAX),
        })
    }

    pub async fn users_for_source_ips(
        &self,
        ips: &[String],
        look_back_days: u32,
    ) -> Result<std::collections::HashMap<String, Vec<(UserId, u64)>>> {
        if ips.is_empty() {
            return Ok(HashMap::new());
        }
        let placeholders = std::iter::repeat_n("?", ips.len())
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT ip, user_id, COUNT(*) AS hits
             FROM sub_access_log
             WHERE ip IN ({placeholders})
               AND is_vpn_egress = 0
               AND {pred}
               AND user_id IS NOT NULL
               AND ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
             GROUP BY ip, user_id
             ORDER BY ip, hits DESC",
            pred = real_client_ip_predicate("ip")
        );
        let cutoff = format!("-{look_back_days} days");
        let mut q = sqlx::query(&sql);
        for ip in ips {
            q = q.bind(ip);
        }
        q = q.bind(&cutoff);
        let rows = q.fetch_all(&self.pool).await?;
        let mut out: HashMap<String, Vec<(UserId, u64)>> = HashMap::new();
        for r in rows {
            let ip: String = r.try_get("ip")?;
            let uid: String = r.try_get("user_id")?;
            let hits: i64 = r.try_get("hits")?;
            out.entry(ip)
                .or_default()
                .push((UserId(uid), hits.max(0) as u64));
        }
        Ok(out)
    }

    pub async fn all_servers_live_activity(
        &self,
        since_hours: u32,
        max_age_secs: u64,
    ) -> Result<Vec<(ServerId, ServerLiveActivity)>> {
        let server_ids = sqlx::query("SELECT id FROM servers ORDER BY id")
            .fetch_all(&self.pool)
            .await?;
        let mut out = Vec::with_capacity(server_ids.len());
        for r in server_ids {
            let id: String = r.try_get("id")?;
            let sid = ServerId(id);
            let activity = self
                .server_live_activity(&sid, since_hours, max_age_secs)
                .await?;
            out.push((sid, activity));
        }
        Ok(out)
    }
}
