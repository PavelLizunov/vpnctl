use crate::sqlite::base::{canonical_ip_text, real_client_ip_predicate};
use crate::sqlite::models::{
    AccessBucket, ProxyMaskedStats, SubAccessAggregates, SubAccessEntry, SubAccessEntryInput,
};
use crate::sqlite::{Result, SqliteInventory, SqliteInventoryError};
use chrono::{DateTime, Utc};
use sqlx::Row;
use vpnctl_core::UserId;

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
        status: u16::try_from(status_i).unwrap_or(0),
        bytes: u64::try_from(bytes_i).unwrap_or(0),
        accept_language: r.try_get("accept_language")?,
        http_version: r.try_get("http_version")?,
        device_class: r.try_get("device_class")?,
        geo_country: r.try_get("geo_country")?,
        geo_asn: r.try_get("geo_asn")?,
        tls_ja3: r.try_get("tls_ja3")?,
        tls_ja4: r.try_get("tls_ja4")?,
        is_vpn_egress: r.try_get::<i64, _>("is_vpn_egress").unwrap_or(0) != 0,
    })
}

impl SqliteInventory {
    pub async fn log_sub_access(
        &self,
        user_id: &UserId,
        ip: &str,
        ua: Option<&str>,
        status: u16,
        bytes: u64,
    ) -> Result<()> {
        self.log_sub_access_rich(
            user_id, ip, ua, status, bytes, None, None, None, None, None, None, None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn log_sub_access_rich(
        &self,
        user_id: &UserId,
        ip: &str,
        ua: Option<&str>,
        status: u16,
        bytes: u64,
        accept_language: Option<&str>,
        http_version: Option<&str>,
        device_class: Option<&str>,
        geo_country: Option<&str>,
        geo_asn: Option<&str>,
        tls_ja3: Option<&str>,
        tls_ja4: Option<&str>,
    ) -> Result<()> {
        let entry = SubAccessEntryInput {
            user_id: user_id.clone(),
            ip: ip.to_string(),
            ua: ua.map(str::to_string),
            status,
            bytes,
            accept_language: accept_language.map(str::to_string),
            http_version: http_version.map(str::to_string),
            device_class: device_class.map(str::to_string),
            geo_country: geo_country.map(str::to_string),
            geo_asn: geo_asn.map(str::to_string),
            tls_ja3: tls_ja3.map(str::to_string),
            tls_ja4: tls_ja4.map(str::to_string),
        };
        self.log_sub_access_batch(&[entry]).await
    }

    pub async fn log_sub_access_batch(&self, records: &[SubAccessEntryInput]) -> Result<()> {
        if records.is_empty() {
            return Ok(());
        }
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        for r in records {
            let ip = canonical_ip_text(&r.ip);
            sqlx::query(
                "INSERT INTO sub_access_log
                 (user_id, ip, ua, status, bytes,
                  accept_language, http_version, device_class,
                  geo_country, geo_asn, tls_ja3, tls_ja4)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            )
            .bind(&r.user_id.0)
            .bind(ip)
            .bind(r.ua.as_deref())
            .bind(i64::from(r.status))
            .bind(i64::try_from(r.bytes).unwrap_or(i64::MAX))
            .bind(r.accept_language.as_deref())
            .bind(r.http_version.as_deref())
            .bind(r.device_class.as_deref())
            .bind(r.geo_country.as_deref())
            .bind(r.geo_asn.as_deref())
            .bind(r.tls_ja3.as_deref())
            .bind(r.tls_ja4.as_deref())
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

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

    pub async fn recent_sub_access(
        &self,
        user_id: &UserId,
        limit: i64,
    ) -> Result<Vec<SubAccessEntry>> {
        let rows = sqlx::query(
            "SELECT id, ts, user_id, ip, ua, status, bytes,
                    accept_language, http_version, device_class,
                    geo_country, geo_asn, tls_ja3, tls_ja4,
                    is_vpn_egress
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

    pub async fn recent_sub_access_paged(
        &self,
        user_id: &UserId,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SubAccessEntry>> {
        let rows = sqlx::query(
            "SELECT id, ts, user_id, ip, ua, status, bytes,
                    accept_language, http_version, device_class,
                    geo_country, geo_asn, tls_ja3, tls_ja4,
                    is_vpn_egress
             FROM sub_access_log
             WHERE user_id = ?1
             ORDER BY id DESC
             LIMIT ?2 OFFSET ?3",
        )
        .bind(&user_id.0)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_sub_access).collect()
    }

    pub async fn sub_access_count_for_user(&self, user_id: &UserId) -> Result<u64> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sub_access_log WHERE user_id = ?1")
            .bind(&user_id.0)
            .fetch_one(&self.pool)
            .await?;
        Ok(u64::try_from(row.0).unwrap_or(0))
    }

    pub async fn recent_sub_access_filtered(
        &self,
        user_id: &UserId,
        limit: i64,
        include_egress: bool,
    ) -> Result<Vec<SubAccessEntry>> {
        let sql = if include_egress {
            "SELECT id, ts, user_id, ip, ua, status, bytes,
                    accept_language, http_version, device_class,
                    geo_country, geo_asn, tls_ja3, tls_ja4,
                    is_vpn_egress
             FROM sub_access_log
             WHERE user_id = ?1
             ORDER BY id DESC
             LIMIT ?2"
                .to_string()
        } else {
            format!(
                "SELECT id, ts, user_id, ip, ua, status, bytes,
                        accept_language, http_version, device_class,
                        geo_country, geo_asn, tls_ja3, tls_ja4,
                        is_vpn_egress
                 FROM sub_access_log
                 WHERE user_id = ?1 AND is_vpn_egress = 0 AND {pred}
                 ORDER BY id DESC
                 LIMIT ?2",
                pred = real_client_ip_predicate("ip")
            )
        };
        let rows = sqlx::query(&sql)
            .bind(&user_id.0)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter().map(row_to_sub_access).collect()
    }

    pub async fn sub_access_aggregates_for_user(
        &self,
        user_id: &UserId,
        days: u32,
    ) -> Result<SubAccessAggregates> {
        let cutoff = format!("-{days} days");
        let real = real_client_ip_predicate("ip");
        let sql = format!(
            "SELECT
                COUNT(*) FILTER (WHERE is_vpn_egress = 0)                    AS total_rows,
                COUNT(*) FILTER (WHERE is_vpn_egress = 1)                    AS egress_rows,
                COUNT(DISTINCT CASE WHEN is_vpn_egress = 0 AND ({real}) THEN ip END) AS distinct_ips,
                COUNT(DISTINCT CASE WHEN is_vpn_egress = 0 AND ({real}) AND geo_country IS NOT NULL THEN geo_country END) AS distinct_countries,
                COUNT(DISTINCT CASE WHEN is_vpn_egress = 0 AND ({real}) AND geo_asn IS NOT NULL THEN geo_asn END)         AS distinct_asns,
                COALESCE(SUM(CASE WHEN is_vpn_egress = 0 THEN bytes END), 0) AS total_bytes,
                MAX(ts)                                                      AS last_seen,
                MIN(ts)                                                      AS first_seen
             FROM sub_access_log
             WHERE user_id = ?1
               AND ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)"
        );
        let row = sqlx::query(&sql)
            .bind(&user_id.0)
            .bind(&cutoff)
            .fetch_one(&self.pool)
            .await?;

        let total_rows: i64 = row.try_get("total_rows")?;
        let egress_rows: i64 = row.try_get("egress_rows")?;
        let distinct_ips: i64 = row.try_get("distinct_ips")?;
        let distinct_countries: i64 = row.try_get("distinct_countries")?;
        let distinct_asns: i64 = row.try_get("distinct_asns")?;
        let total_bytes: i64 = row.try_get("total_bytes")?;
        let last_seen_str: Option<String> = row.try_get("last_seen")?;
        let first_seen_str: Option<String> = row.try_get("first_seen")?;

        let parse_ts = |s: Option<String>| -> Option<DateTime<Utc>> {
            s.and_then(|t| {
                DateTime::parse_from_rfc3339(&t)
                    .ok()
                    .map(|d| d.with_timezone(&Utc))
            })
        };

        Ok(SubAccessAggregates {
            total_rows: total_rows.max(0) as u64,
            egress_rows: egress_rows.max(0) as u64,
            distinct_ips: distinct_ips.max(0) as u64,
            distinct_countries: distinct_countries.max(0) as u64,
            distinct_asns: distinct_asns.max(0) as u64,
            total_bytes: total_bytes.max(0) as u64,
            last_seen: parse_ts(last_seen_str),
            first_seen: parse_ts(first_seen_str),
        })
    }

    pub async fn sub_access_proxy_masked_stats(
        &self,
        user_id: &UserId,
        days: u32,
    ) -> Result<ProxyMaskedStats> {
        let real = real_client_ip_predicate("ip");
        let sql = format!(
            "SELECT
                COUNT(*)                                        AS window_rows,
                SUM(CASE WHEN NOT ({real}) THEN 1 ELSE 0 END)   AS masked_rows,
                MIN(CASE WHEN NOT ({real}) THEN ts END)         AS masked_min_ts,
                MAX(CASE WHEN NOT ({real}) THEN ts END)         AS masked_max_ts
             FROM sub_access_log
             WHERE user_id = ?1
               AND is_vpn_egress = 0
               AND ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)"
        );
        let row = sqlx::query(&sql)
            .bind(&user_id.0)
            .bind(format!("-{days} days"))
            .fetch_one(&self.pool)
            .await?;
        let window_rows: i64 = row.try_get("window_rows")?;
        let masked_rows: i64 = row.try_get("masked_rows").unwrap_or(0);
        Ok(ProxyMaskedStats {
            window_rows: window_rows.max(0) as u64,
            masked_rows: masked_rows.max(0) as u64,
            masked_min_ts: row.try_get("masked_min_ts").ok().flatten(),
            masked_max_ts: row.try_get("masked_max_ts").ok().flatten(),
        })
    }

    pub async fn purge_sub_access_older_than(&self, days: u32) -> Result<u64> {
        let res = sqlx::query(
            "DELETE FROM sub_access_log WHERE ts < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1)",
        )
        .bind(format!("-{days} days"))
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    pub async fn sub_access_buckets(
        &self,
        bucket: &str,
        since_hours: u32,
    ) -> Result<Vec<AccessBucket>> {
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
}
