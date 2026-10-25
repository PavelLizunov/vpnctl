use super::*;
use chrono::{DateTime, Utc};
use sqlx::Row;
use vpnctl_core::{ServerId, UserId};

#[allow(clippy::needless_pass_by_value)]
fn row_to_user_session(r: sqlx::sqlite::SqliteRow) -> Result<VpnUserSessionRow> {
    let id: i64 = r.try_get("id")?;
    let user_id: String = r.try_get("user_id")?;
    let server_id: String = r.try_get("server_id")?;
    let started_at_s: String = r.try_get("started_at")?;
    let last_seen_s: String = r.try_get("last_seen")?;
    let conn_count_peak: i64 = r.try_get("conn_count_peak")?;
    let total_bytes: i64 = r.try_get("total_bytes")?;
    let parse_ts = |s: &str, label: &str| -> Result<DateTime<Utc>> {
        DateTime::parse_from_rfc3339(s)
            .map(|d| d.with_timezone(&Utc))
            .map_err(|e| {
                SqliteInventoryError::Invalid(format!(
                    "vpn_user_sessions.{label} malformed: {s}: {e}"
                ))
            })
    };
    Ok(VpnUserSessionRow {
        id,
        user_id: UserId(user_id),
        server_id: ServerId(server_id),
        started_at: parse_ts(&started_at_s, "started_at")?,
        last_seen: parse_ts(&last_seen_s, "last_seen")?,
        conn_count_peak: u32::try_from(conn_count_peak.max(0)).unwrap_or(u32::MAX),
        total_bytes: total_bytes.max(0) as u64,
    })
}

#[allow(clippy::needless_pass_by_value)]
fn row_to_user_destination(r: sqlx::sqlite::SqliteRow) -> Result<VpnUserDestinationRow> {
    let user_id: String = r.try_get("user_id")?;
    let destination_label: String = r.try_get("destination_label")?;
    let date: String = r.try_get("date")?;
    let hits: i64 = r.try_get("hit_count")?;
    let last_seen_s: String = r.try_get("last_seen")?;
    let last_seen = DateTime::parse_from_rfc3339(&last_seen_s)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|e| {
            SqliteInventoryError::Invalid(format!(
                "vpn_user_destinations.last_seen malformed: {last_seen_s}: {e}"
            ))
        })?;
    Ok(VpnUserDestinationRow {
        user_id: UserId(user_id),
        destination_label,
        date,
        hit_count: hits.max(0) as u64,
        last_seen,
    })
}

#[allow(clippy::needless_pass_by_value)]
fn row_to_user_source_ip(r: sqlx::sqlite::SqliteRow) -> Result<VpnUserSourceIpRow> {
    let user_id: String = r.try_get("user_id")?;
    let source_ip: String = r.try_get("source_ip")?;
    let date: String = r.try_get("date")?;
    let hits: i64 = r.try_get("hit_count")?;
    let last_seen_s: String = r.try_get("last_seen")?;
    let last_seen = DateTime::parse_from_rfc3339(&last_seen_s)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|e| {
            SqliteInventoryError::Invalid(format!(
                "vpn_user_source_ips.last_seen malformed: {last_seen_s}: {e}"
            ))
        })?;
    Ok(VpnUserSourceIpRow {
        user_id: UserId(user_id),
        source_ip,
        date,
        hit_count: hits.max(0) as u64,
        last_seen,
    })
}

impl SqliteInventory {
    pub async fn session_observe(
        &self,
        user_id: &UserId,
        server_id: &ServerId,
        now: DateTime<Utc>,
        gap_minutes: i64,
        bytes_delta: u64,
        conn_count: u32,
    ) -> Result<i64> {
        let cutoff = now - chrono::Duration::minutes(gap_minutes);
        let cutoff_s = cutoff.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        let now_s = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        let maybe_existing: Option<(i64, i64, i64)> = sqlx::query(
            "SELECT id, total_bytes, conn_count_peak
             FROM vpn_user_sessions
             WHERE user_id = ?1 AND server_id = ?2 AND last_seen >= ?3
             ORDER BY last_seen DESC, id DESC
             LIMIT 1",
        )
        .bind(&user_id.0)
        .bind(&server_id.0)
        .bind(&cutoff_s)
        .fetch_optional(&self.pool)
        .await?
        .map(|r| {
            (
                r.try_get::<i64, _>("id").unwrap_or(0),
                r.try_get::<i64, _>("total_bytes").unwrap_or(0),
                r.try_get::<i64, _>("conn_count_peak").unwrap_or(0),
            )
        });

        if let Some((existing_id, prev_bytes, prev_peak)) = maybe_existing {
            let new_bytes = (prev_bytes.max(0) as u64).saturating_add(bytes_delta);
            let new_peak = (prev_peak.max(0) as u32).max(conn_count);
            sqlx::query(
                "UPDATE vpn_user_sessions
                 SET last_seen = ?1, total_bytes = ?2, conn_count_peak = ?3
                 WHERE id = ?4",
            )
            .bind(&now_s)
            .bind(i64::try_from(new_bytes).unwrap_or(i64::MAX))
            .bind(i64::from(new_peak))
            .bind(existing_id)
            .execute(&self.pool)
            .await?;
            Ok(existing_id)
        } else {
            let res = sqlx::query(
                "INSERT INTO vpn_user_sessions
                    (user_id, server_id, started_at, last_seen, conn_count_peak, total_bytes)
                 SELECT ?1, ?2, ?3, ?3, ?4, ?5
                 WHERE EXISTS (SELECT 1 FROM users WHERE id = ?1)",
            )
            .bind(&user_id.0)
            .bind(&server_id.0)
            .bind(&now_s)
            .bind(i64::from(conn_count))
            .bind(i64::try_from(bytes_delta).unwrap_or(i64::MAX))
            .execute(&self.pool)
            .await?;
            if res.rows_affected() == 0 {
                Ok(0)
            } else {
                Ok(res.last_insert_rowid())
            }
        }
    }

    pub async fn recent_sessions_for_user(
        &self,
        user_id: &UserId,
        limit: i64,
    ) -> Result<Vec<VpnUserSessionRow>> {
        let rows = sqlx::query(
            "SELECT id, user_id, server_id, started_at, last_seen,
                    conn_count_peak, total_bytes
             FROM vpn_user_sessions
             WHERE user_id = ?1
             ORDER BY last_seen DESC, id DESC
             LIMIT ?2",
        )
        .bind(&user_id.0)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_user_session).collect()
    }

    pub async fn purge_user_sessions_older_than(&self, days: u32) -> Result<u64> {
        let res = sqlx::query(
            "DELETE FROM vpn_user_sessions
             WHERE started_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1)",
        )
        .bind(format!("-{days} days"))
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    pub async fn record_user_destinations(&self, pairs: &[(UserId, String)]) -> Result<()> {
        if pairs.is_empty() {
            return Ok(());
        }
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        for (user_id, dest) in pairs {
            let dest_truncated: String = dest.chars().take(200).collect();
            sqlx::query(
                "INSERT INTO vpn_user_destinations
                    (user_id, destination_label, date, hit_count, last_seen)
                 SELECT ?1, ?2, strftime('%Y-%m-%d', 'now'), 1,
                        strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE EXISTS (SELECT 1 FROM users WHERE id = ?1)
                 ON CONFLICT(user_id, destination_label, date) DO UPDATE SET
                     hit_count = hit_count + 1,
                     last_seen = excluded.last_seen",
            )
            .bind(&user_id.0)
            .bind(&dest_truncated)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn top_destinations_for_user(
        &self,
        user_id: &UserId,
        days: u32,
        limit: u32,
    ) -> Result<Vec<VpnUserDestinationRow>> {
        let cutoff = format!("-{days} days");
        let rows = sqlx::query(
            "SELECT user_id, destination_label, date, hit_count, last_seen
             FROM (
                SELECT user_id, destination_label,
                       MAX(date)        AS date,
                       SUM(hit_count)   AS hit_count,
                       MAX(last_seen)   AS last_seen
                FROM vpn_user_destinations
                WHERE user_id = ?1
                  AND date >= strftime('%Y-%m-%d', 'now', ?2)
                GROUP BY user_id, destination_label
             )
             ORDER BY hit_count DESC, last_seen DESC, destination_label ASC
             LIMIT ?3",
        )
        .bind(&user_id.0)
        .bind(&cutoff)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_user_destination).collect()
    }

    pub async fn purge_user_destinations_older_than(&self, days: u32) -> Result<u64> {
        let res = sqlx::query(
            "DELETE FROM vpn_user_destinations
             WHERE date < strftime('%Y-%m-%d', 'now', ?1)",
        )
        .bind(format!("-{days} days"))
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    pub async fn record_user_source_ips(&self, pairs: &[(UserId, String)]) -> Result<()> {
        if pairs.is_empty() {
            return Ok(());
        }
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        for (user_id, ip) in pairs {
            if ip.is_empty() {
                continue;
            }
            let canonical_ip = canonical_ip_text(ip);
            sqlx::query(
                "INSERT INTO vpn_user_source_ips
                    (user_id, source_ip, date, hit_count, last_seen)
                 SELECT ?1, ?2, strftime('%Y-%m-%d', 'now'), 1,
                        strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE EXISTS (SELECT 1 FROM users WHERE id = ?1)
                 ON CONFLICT(user_id, source_ip, date) DO UPDATE SET
                     hit_count = hit_count + 1,
                     last_seen = excluded.last_seen",
            )
            .bind(&user_id.0)
            .bind(&canonical_ip)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn record_user_ip_concurrency(&self, peaks: &[(UserId, u32)]) -> Result<()> {
        if peaks.is_empty() {
            return Ok(());
        }
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        for (user_id, n) in peaks {
            if *n == 0 {
                continue;
            }
            sqlx::query(
                "INSERT INTO vpn_user_ip_concurrency
                    (user_id, date, peak_concurrent_ips, updated_at)
                 SELECT ?1, strftime('%Y-%m-%d', 'now'), ?2,
                        strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE EXISTS (SELECT 1 FROM users WHERE id = ?1)
                 ON CONFLICT(user_id, date) DO UPDATE SET
                     peak_concurrent_ips =
                         max(peak_concurrent_ips, excluded.peak_concurrent_ips),
                     updated_at = excluded.updated_at",
            )
            .bind(&user_id.0)
            .bind(i64::from(*n))
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn ip_concurrency_peak_for_user(&self, user_id: &UserId, days: u32) -> Result<u32> {
        let row: Option<(i64,)> = sqlx::query_as(
            "SELECT COALESCE(MAX(peak_concurrent_ips), 0)
             FROM vpn_user_ip_concurrency
             WHERE user_id = ?1
               AND date >= strftime('%Y-%m-%d', 'now', ?2)",
        )
        .bind(&user_id.0)
        .bind(format!("-{days} days"))
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(m,)| m.max(0) as u32).unwrap_or(0))
    }

    pub async fn purge_user_ip_concurrency_older_than(&self, days: u32) -> Result<u64> {
        let res = sqlx::query(
            "DELETE FROM vpn_user_ip_concurrency
             WHERE date < strftime('%Y-%m-%d', 'now', ?1)",
        )
        .bind(format!("-{days} days"))
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    pub async fn top_source_ips_for_user(
        &self,
        user_id: &UserId,
        days: u32,
        limit: u32,
    ) -> Result<Vec<VpnUserSourceIpRow>> {
        let cutoff = format!("-{days} days");
        let sql = format!(
            "SELECT user_id, source_ip, date, hit_count, last_seen
             FROM (
                SELECT user_id, source_ip,
                       MAX(date)        AS date,
                       SUM(hit_count)   AS hit_count,
                       MAX(last_seen)   AS last_seen
                FROM vpn_user_source_ips
                WHERE user_id = ?1
                  AND date >= strftime('%Y-%m-%d', 'now', ?2)
                  AND {pred}
                GROUP BY user_id, source_ip
             )
             ORDER BY hit_count DESC, last_seen DESC, source_ip ASC
             LIMIT ?3",
            pred = real_client_ip_predicate("source_ip")
        );
        let rows = sqlx::query(&sql)
            .bind(&user_id.0)
            .bind(&cutoff)
            .bind(i64::from(limit))
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter().map(row_to_user_source_ip).collect()
    }

    pub async fn purge_user_source_ips_older_than(&self, days: u32) -> Result<u64> {
        let res = sqlx::query(
            "DELETE FROM vpn_user_source_ips
             WHERE date < strftime('%Y-%m-%d', 'now', ?1)",
        )
        .bind(format!("-{days} days"))
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    pub async fn geo_labels_for_ips(
        &self,
        ips: &[String],
    ) -> Result<std::collections::HashMap<String, (Option<String>, Option<String>)>> {
        use std::collections::HashMap;
        if ips.is_empty() {
            return Ok(HashMap::new());
        }
        let placeholders = std::iter::repeat_n("?", ips.len())
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT s.ip AS ip, s.geo_country AS country, s.geo_asn AS asn
             FROM sub_access_log s
             JOIN (
                SELECT ip, MAX(ts) AS mts
                FROM sub_access_log
                WHERE ip IN ({placeholders})
                  AND (geo_country IS NOT NULL OR geo_asn IS NOT NULL)
                GROUP BY ip
             ) j ON j.ip = s.ip AND j.mts = s.ts
             -- Re-assert non-NULL geo on the OUTER row too: when an
             -- enriched and an un-enriched row for the same IP share
             -- the max ts (sub-ms inserts), the join would otherwise
             -- also match the NULL row and a HashMap overwrite could
             -- non-deterministically blank the geo.
             WHERE s.geo_country IS NOT NULL OR s.geo_asn IS NOT NULL"
        );
        let mut q = sqlx::query(&sql);
        for ip in ips {
            q = q.bind(ip);
        }
        let rows = q.fetch_all(&self.pool).await?;
        let mut out: HashMap<String, (Option<String>, Option<String>)> = HashMap::new();
        for r in rows {
            let ip: String = r.try_get("ip")?;
            let country: Option<String> = r.try_get("country")?;
            let asn: Option<String> = r.try_get("asn")?;
            out.insert(ip, (country, asn));
        }
        Ok(out)
    }

    pub async fn lookup_dns_ptr_bulk(
        &self,
        ips: &[String],
    ) -> Result<std::collections::HashMap<String, Option<String>>> {
        use std::collections::HashMap;
        if ips.is_empty() {
            return Ok(HashMap::new());
        }
        let placeholders = std::iter::repeat_n("?", ips.len())
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!("SELECT ip, hostname FROM dns_ptr_cache WHERE ip IN ({placeholders})");
        let mut q = sqlx::query(&sql);
        for ip in ips {
            q = q.bind(ip);
        }
        let rows = q.fetch_all(&self.pool).await?;
        let mut out: HashMap<String, Option<String>> = HashMap::new();
        for r in rows {
            let ip: String = r.try_get("ip")?;
            let hostname: Option<String> = r.try_get("hostname")?;
            out.insert(ip, hostname);
        }
        Ok(out)
    }

    pub async fn upsert_dns_ptr(&self, ip: &str, hostname: Option<&str>) -> Result<()> {
        sqlx::query(
            "INSERT INTO dns_ptr_cache (ip, hostname, resolved_at)
             VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
             ON CONFLICT(ip) DO UPDATE SET
                 hostname    = excluded.hostname,
                 resolved_at = excluded.resolved_at",
        )
        .bind(ip)
        .bind(hostname)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn purge_dns_ptr_older_than(&self, days: u32) -> Result<u64> {
        let res = sqlx::query(
            "DELETE FROM dns_ptr_cache
             WHERE resolved_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1)",
        )
        .bind(format!("-{days} days"))
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }
}
