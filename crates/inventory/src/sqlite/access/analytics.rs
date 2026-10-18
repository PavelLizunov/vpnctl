use crate::sqlite::base::{ip_slash16, network_key, real_client_ip_predicate};
use crate::sqlite::models::{
    SharingSignals, SubDeviceFp, SubFetchStallUser, SubOriginAsn, SubOriginCountry, SubOriginIp,
    UaCluster,
};
use crate::sqlite::{Result, SqliteInventory};
use sqlx::Row;
use std::collections::{HashMap, HashSet};
use vpnctl_core::UserId;

fn blank_sharing_signals(user_id: &str) -> SharingSignals {
    SharingSignals {
        user_id: UserId(user_id.to_string()),
        distinct_ips: 0,
        distinct_asns: 0,
        distinct_countries: 0,
        distinct_device_classes: 0,
        typical_concurrent_nets: 0,
        max_daily_nets: 0,
        impossible_travel_hops: 0,
    }
}

impl SqliteInventory {
    pub async fn ua_clusters_for_user(
        &self,
        user_id: &UserId,
        since_hours: u32,
    ) -> Result<Vec<UaCluster>> {
        let rows = sqlx::query(
            "SELECT ua, ip FROM sub_access_log
             WHERE user_id = ?1
               AND ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)",
        )
        .bind(&user_id.0)
        .bind(format!("-{since_hours} hours"))
        .fetch_all(&self.pool)
        .await?;

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
        out.sort_by_key(|c| std::cmp::Reverse(c.hits));
        Ok(out)
    }

    pub async fn likely_shared_summary(
        &self,
        min_asns: u32,
    ) -> Result<Vec<(UserId, u64, u64, u64)>> {
        let sql = format!(
            "SELECT user_id,
                    COUNT(DISTINCT ip) AS distinct_ips,
                    COUNT(DISTINCT CASE WHEN geo_asn IS NOT NULL THEN geo_asn END)
                        AS distinct_asns,
                    COUNT(DISTINCT CASE WHEN geo_country IS NOT NULL THEN geo_country END)
                        AS distinct_countries
             FROM sub_access_log
             WHERE is_vpn_egress = 0
               AND {pred}
               AND user_id IS NOT NULL
               AND user_id != ''
             GROUP BY user_id
             HAVING distinct_asns >= ?1
             ORDER BY distinct_asns DESC, distinct_ips DESC",
            pred = real_client_ip_predicate("ip")
        );
        let rows = sqlx::query(&sql)
            .bind(i64::from(min_asns))
            .fetch_all(&self.pool)
            .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let uid: String = r.try_get("user_id")?;
            let ips: i64 = r.try_get("distinct_ips")?;
            let asns: i64 = r.try_get("distinct_asns")?;
            let countries: i64 = r.try_get("distinct_countries")?;
            out.push((
                UserId(uid),
                ips.max(0) as u64,
                asns.max(0) as u64,
                countries.max(0) as u64,
            ));
        }
        Ok(out)
    }

    pub async fn sharing_signals_all_users(
        &self,
        days: u32,
        impossible_travel_hours: f64,
    ) -> Result<Vec<SharingSignals>> {
        let ts_cut = format!("-{days} days");
        let pred_ip = real_client_ip_predicate("ip");
        let pred_src = real_client_ip_predicate("source_ip");

        let mut acc: HashMap<String, SharingSignals> = HashMap::new();

        let q1 = format!(
            "SELECT user_id,
                    COUNT(DISTINCT ip)            AS d_ips,
                    COUNT(DISTINCT geo_asn)       AS d_asns,
                    COUNT(DISTINCT geo_country)   AS d_countries,
                    COUNT(DISTINCT device_class)  AS d_devcls
             FROM sub_access_log
             WHERE is_vpn_egress = 0 AND {pred_ip}
               AND user_id IS NOT NULL AND user_id != ''
               AND ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1)
             GROUP BY user_id"
        );
        for r in sqlx::query(&q1).bind(&ts_cut).fetch_all(&self.pool).await? {
            let uid: String = r.try_get("user_id")?;
            let s = acc
                .entry(uid.clone())
                .or_insert_with(|| blank_sharing_signals(&uid));
            s.distinct_ips = r.try_get::<i64, _>("d_ips")?.max(0) as u64;
            s.distinct_asns = r.try_get::<i64, _>("d_asns")?.max(0) as u64;
            s.distinct_countries = r.try_get::<i64, _>("d_countries")?.max(0) as u64;
            s.distinct_device_classes = r.try_get::<i64, _>("d_devcls")?.max(0) as u64;
        }

        let q2 = format!(
            "WITH ordered AS (
                SELECT user_id, geo_country AS c, ts,
                       LAG(geo_country) OVER (PARTITION BY user_id ORDER BY ts) AS pc,
                       LAG(ts)          OVER (PARTITION BY user_id ORDER BY ts) AS pts
                FROM sub_access_log
                WHERE is_vpn_egress = 0 AND {pred_ip}
                  AND geo_country IS NOT NULL AND geo_country != ''
                  AND user_id IS NOT NULL AND user_id != ''
                  AND ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1)
             )
             SELECT user_id, COUNT(*) AS hops
             FROM ordered
             WHERE pc IS NOT NULL AND c <> pc
               AND (julianday(replace(ts, 'Z', '')) -
                    julianday(replace(pts, 'Z', ''))) * 24.0 < ?2
             GROUP BY user_id"
        );
        for r in sqlx::query(&q2)
            .bind(&ts_cut)
            .bind(impossible_travel_hours)
            .fetch_all(&self.pool)
            .await?
        {
            let uid: String = r.try_get("user_id")?;
            acc.entry(uid.clone())
                .or_insert_with(|| blank_sharing_signals(&uid))
                .impossible_travel_hops = r.try_get::<i64, _>("hops")?.max(0) as u64;
        }

        for r in sqlx::query(
            "WITH ranked AS (
                 SELECT user_id, peak_concurrent_ips,
                        ROW_NUMBER() OVER (
                            PARTITION BY user_id ORDER BY peak_concurrent_ips
                        ) AS rn,
                        COUNT(*) OVER (PARTITION BY user_id) AS samples
                 FROM vpn_user_ip_concurrency
                 WHERE date >= strftime('%Y-%m-%d', 'now', ?1)
             )
             SELECT user_id, peak_concurrent_ips AS typical
             FROM ranked
             WHERE rn = (3 * samples + 3) / 4",
        )
        .bind(&ts_cut)
        .fetch_all(&self.pool)
        .await?
        {
            let uid: String = r.try_get("user_id")?;
            acc.entry(uid.clone())
                .or_insert_with(|| blank_sharing_signals(&uid))
                .typical_concurrent_nets = r.try_get::<i64, _>("typical")?.max(0) as u32;
        }

        let q4 = format!(
            "SELECT user_id, date, source_ip
             FROM vpn_user_source_ips
             WHERE date >= strftime('%Y-%m-%d', 'now', ?1) AND {pred_src}"
        );
        let mut per_day_nets: HashMap<(String, String), HashSet<String>> = HashMap::new();
        for r in sqlx::query(&q4).bind(&ts_cut).fetch_all(&self.pool).await? {
            let uid: String = r.try_get("user_id")?;
            let date: String = r.try_get("date")?;
            let ip: String = r.try_get("source_ip")?;
            per_day_nets
                .entry((uid, date))
                .or_default()
                .insert(network_key(&ip));
        }
        let mut max_nets: HashMap<String, u32> = HashMap::new();
        for ((uid, _date), nets) in per_day_nets {
            let n = nets.len() as u32;
            let e = max_nets.entry(uid).or_insert(0);
            *e = (*e).max(n);
        }
        for (uid, n) in max_nets {
            acc.entry(uid.clone())
                .or_insert_with(|| blank_sharing_signals(&uid))
                .max_daily_nets = n;
        }

        Ok(acc.into_values().collect())
    }

    pub async fn sub_access_by_country(
        &self,
        user: &UserId,
        days: u32,
    ) -> Result<Vec<SubOriginCountry>> {
        let sql = format!(
            "SELECT geo_country AS country,
                    COUNT(*)                                                AS fetches,
                    COUNT(DISTINCT ip)                                      AS ips,
                    COUNT(DISTINCT CASE WHEN geo_asn IS NOT NULL THEN geo_asn END) AS asns
             FROM sub_access_log
             WHERE user_id = ?1
               AND is_vpn_egress = 0
               AND {pred}
               AND ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)
             GROUP BY geo_country
             ORDER BY fetches DESC",
            pred = real_client_ip_predicate("ip")
        );
        let rows = sqlx::query(&sql)
            .bind(&user.0)
            .bind(format!("-{days} days"))
            .fetch_all(&self.pool)
            .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let country: Option<String> = r.try_get("country")?;
            let fetches: i64 = r.try_get("fetches")?;
            let ips: i64 = r.try_get("ips")?;
            let asns: i64 = r.try_get("asns")?;
            out.push(SubOriginCountry {
                country,
                fetches: fetches.max(0) as u64,
                ips: ips.max(0) as u64,
                asns: asns.max(0) as u64,
            });
        }
        Ok(out)
    }

    pub async fn sub_access_by_asn(
        &self,
        user: &UserId,
        days: u32,
        limit: u32,
    ) -> Result<Vec<SubOriginAsn>> {
        let sql = format!(
            "SELECT geo_asn AS asn,
                    MAX(geo_country)   AS country,
                    COUNT(*)           AS fetches,
                    COUNT(DISTINCT ip) AS ips
             FROM sub_access_log
             WHERE user_id = ?1
               AND is_vpn_egress = 0
               AND {pred}
               AND ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)
             GROUP BY geo_asn
             ORDER BY fetches DESC
             LIMIT ?3",
            pred = real_client_ip_predicate("ip")
        );
        let rows = sqlx::query(&sql)
            .bind(&user.0)
            .bind(format!("-{days} days"))
            .bind(i64::from(limit))
            .fetch_all(&self.pool)
            .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let asn: Option<String> = r.try_get("asn")?;
            let country: Option<String> = r.try_get("country")?;
            let fetches: i64 = r.try_get("fetches")?;
            let ips: i64 = r.try_get("ips")?;
            out.push(SubOriginAsn {
                asn,
                country,
                fetches: fetches.max(0) as u64,
                ips: ips.max(0) as u64,
            });
        }
        Ok(out)
    }

    pub async fn sub_access_by_ip(
        &self,
        user: &UserId,
        days: u32,
        limit: u32,
    ) -> Result<Vec<SubOriginIp>> {
        let sql = format!(
            "SELECT ip,
                    MAX(geo_country) AS country,
                    MAX(geo_asn)     AS asn,
                    COUNT(*)         AS fetches,
                    MIN(ts)          AS first_seen,
                    MAX(ts)          AS last_seen
             FROM sub_access_log
             WHERE user_id = ?1
               AND is_vpn_egress = 0
               AND {pred}
               AND ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)
             GROUP BY ip
             ORDER BY last_seen DESC
             LIMIT ?3",
            pred = real_client_ip_predicate("ip")
        );
        let rows = sqlx::query(&sql)
            .bind(&user.0)
            .bind(format!("-{days} days"))
            .bind(i64::from(limit))
            .fetch_all(&self.pool)
            .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let ip: String = r.try_get("ip")?;
            let country: Option<String> = r.try_get("country")?;
            let asn: Option<String> = r.try_get("asn")?;
            let fetches: i64 = r.try_get("fetches")?;
            let first_seen: String = r.try_get("first_seen")?;
            let last_seen: String = r.try_get("last_seen")?;
            out.push(SubOriginIp {
                ip,
                country,
                asn,
                fetches: fetches.max(0) as u64,
                first_seen,
                last_seen,
            });
        }
        Ok(out)
    }

    pub async fn sub_access_device_fingerprint(
        &self,
        user: &UserId,
        days: u32,
    ) -> Result<SubDeviceFp> {
        let row = sqlx::query(
            "SELECT
                COUNT(DISTINCT device_class) AS distinct_device_classes,
                COUNT(DISTINCT tls_ja4)      AS distinct_ja4,
                COUNT(DISTINCT ua)           AS distinct_uas
             FROM sub_access_log
             WHERE user_id = ?1
               AND is_vpn_egress = 0
               AND ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)",
        )
        .bind(&user.0)
        .bind(format!("-{days} days"))
        .fetch_one(&self.pool)
        .await?;
        let distinct_device_classes: i64 = row.try_get("distinct_device_classes")?;
        let distinct_ja4: i64 = row.try_get("distinct_ja4")?;
        let distinct_uas: i64 = row.try_get("distinct_uas")?;
        Ok(SubDeviceFp {
            distinct_device_classes: distinct_device_classes.max(0) as u64,
            distinct_ja4: distinct_ja4.max(0) as u64,
            distinct_uas: distinct_uas.max(0) as u64,
        })
    }

    pub async fn sub_fetch_without_traffic_users(
        &self,
        grace_minutes: u32,
        lookback_minutes: u32,
        active_days: u32,
    ) -> Result<Vec<SubFetchStallUser>> {
        let sql = format!(
            "WITH last_fetch AS (
                 SELECT user_id, MAX(ts) AS t
                 FROM sub_access_log
                 WHERE user_id IS NOT NULL AND is_vpn_egress = 0 AND status = 200
                   AND {pred}
                 GROUP BY user_id
             )
             SELECT lf.user_id AS user_id,
                    lf.t        AS last_fetch,
                    (SELECT MAX(c.ts) FROM vpn_connection_stats c
                       WHERE c.user_id = lf.user_id
                         AND (c.upload_bytes > 0 OR c.download_bytes > 0)) AS last_traffic,
                    CAST((julianday('now') - julianday(replace(lf.t, 'Z', ''))) * 24 * 60
                         AS INTEGER) AS age_min
             FROM last_fetch lf
             WHERE lf.t <= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1)
               AND lf.t >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)
               AND NOT EXISTS (
                   SELECT 1 FROM vpn_connection_stats c
                   WHERE c.user_id = lf.user_id AND c.ts >= lf.t
                     AND (c.upload_bytes > 0 OR c.download_bytes > 0))
               AND EXISTS (
                   SELECT 1 FROM vpn_connection_stats c2
                   WHERE c2.user_id = lf.user_id
                     AND c2.ts >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?3)
                     AND c2.ts < lf.t
                     AND (c2.upload_bytes > 0 OR c2.download_bytes > 0))
             ORDER BY lf.t ASC",
            pred = real_client_ip_predicate("ip")
        );
        let rows = sqlx::query(&sql)
            .bind(format!("-{grace_minutes} minutes"))
            .bind(format!("-{lookback_minutes} minutes"))
            .bind(format!("-{active_days} days"))
            .fetch_all(&self.pool)
            .await?;
        let mut result = Vec::with_capacity(rows.len());
        for r in rows {
            result.push(SubFetchStallUser {
                user_id: UserId(r.try_get("user_id")?),
                last_fetch: r.try_get("last_fetch")?,
                last_traffic: r.try_get("last_traffic")?,
                fetch_age_minutes: r.try_get("age_min")?,
            });
        }
        Ok(result)
    }
}
