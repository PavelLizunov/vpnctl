use chrono::{DateTime, Utc};
use sqlx::Row;
use vpnctl_core::ServerId;

use crate::sqlite::base::SqliteInventory;
use crate::sqlite::models::Result;

impl SqliteInventory {
    /// Observed traffic in the current UTC hour and preceding 23 hour buckets.
    /// Missing, malformed, incomplete or stale telemetry is unavailable.
    pub async fn node_activity_bytes(
        &self,
        server_id: &ServerId,
        now: i64,
        max_age_seconds: u64,
    ) -> Result<Option<u64>> {
        let upper_seconds = now.div_euclid(3600).saturating_mul(3600);
        let Some(lower) =
            DateTime::<Utc>::from_timestamp(upper_seconds.saturating_sub(23 * 3600), 0)
        else {
            return Ok(None);
        };
        let Some(upper) = DateTime::<Utc>::from_timestamp(upper_seconds, 0) else {
            return Ok(None);
        };
        let rows = sqlx::query(
            "SELECT hour, upload_bytes, download_bytes, last_sample_ts
             FROM vpn_server_hourly
             WHERE server_id = ?1 AND hour >= ?2 AND hour <= ?3
             ORDER BY hour LIMIT 25",
        )
        .bind(&server_id.0)
        .bind(lower.format("%Y-%m-%dT%H:00:00.000Z").to_string())
        .bind(upper.format("%Y-%m-%dT%H:00:00.000Z").to_string())
        .fetch_all(&self.pool)
        .await?;
        if !(20..=24).contains(&rows.len()) {
            return Ok(None);
        }
        let mut total = 0u64;
        let mut newest = None;
        for row in rows {
            let values = (
                row.try_get::<String, _>("hour").ok(),
                row.try_get::<i64, _>("upload_bytes").ok(),
                row.try_get::<i64, _>("download_bytes").ok(),
                row.try_get::<String, _>("last_sample_ts").ok(),
            );
            let (Some(hour), Some(up), Some(down), Some(sample)) = values else {
                return Ok(None);
            };
            let (Ok(hour_time), Ok(sample_time), Ok(up), Ok(down)) = (
                DateTime::parse_from_rfc3339(&hour),
                DateTime::parse_from_rfc3339(&sample),
                u64::try_from(up),
                u64::try_from(down),
            ) else {
                return Ok(None);
            };
            if hour_time.format("%Y-%m-%dT%H:00:00.000Z").to_string() != hour
                || sample_time.timestamp() > now
                || sample_time.timestamp() < hour_time.timestamp()
                || sample_time.timestamp() >= hour_time.timestamp().saturating_add(3600)
            {
                return Ok(None);
            }
            let Some(sum) = total.checked_add(up).and_then(|v| v.checked_add(down)) else {
                return Ok(None);
            };
            total = sum;
            newest = Some(newest.map_or(sample_time.timestamp(), |t: i64| {
                t.max(sample_time.timestamp())
            }));
        }
        let age = newest
            .and_then(|t| now.checked_sub(t))
            .and_then(|age| u64::try_from(age).ok());
        Ok(age.filter(|age| *age <= max_age_seconds).map(|_| total))
    }
}
