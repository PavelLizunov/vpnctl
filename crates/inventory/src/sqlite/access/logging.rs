use crate::sqlite::base::{canonical_ip_text, real_client_ip_predicate};
use crate::sqlite::models::{AccessBucket, ProxyMaskedStats, SubAccessAggregates, SubAccessEntry};
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
        // SQLite stores INTEGER, narrow defensively rather than panic.
        status: u16::try_from(status_i).unwrap_or(0),
        bytes: u64::try_from(bytes_i).unwrap_or(0),
        // Track-1.2 (migration 0019) — old rows have NULL, try_get
        // maps that to Option::None for Option<String> targets. No
        // defensive code needed.
        accept_language: r.try_get("accept_language")?,
        http_version: r.try_get("http_version")?,
        device_class: r.try_get("device_class")?,
        geo_country: r.try_get("geo_country")?,
        geo_asn: r.try_get("geo_asn")?,
        // Track-1.4 (migration 0020) — same NULL-tolerant pattern.
        tls_ja3: r.try_get("tls_ja3")?,
        tls_ja4: r.try_get("tls_ja4")?,
        // Phase 4a (migration 0021) — INTEGER NOT NULL DEFAULT 0
        // in SQL → bool in Rust. SQLite stores 0/1; `try_get::<i64>`
        // and compare. Always present (NOT NULL with DEFAULT).
        is_vpn_egress: r.try_get::<i64, _>("is_vpn_egress").unwrap_or(0) != 0,
    })
}

impl SqliteInventory {
    // ── Subscription access log (Phase Track-1) ─────────────────────────

    /// Append one row to `sub_access_log`. Called by the `/sub/<token>`
    /// handler AFTER the token has been resolved to a user (so a 404 path
    /// — "unknown token" — does NOT land here; that's intentional, we
    /// don't want to keep a per-attempt log of probing tokens because it
    /// would let an attacker fill the table by spamming garbage).
    ///
    /// Best-effort write. The handler calls this in a fire-and-forget
    /// `tokio::spawn`; if it errors the response has already been sent.
    pub async fn log_sub_access(
        &self,
        user_id: &UserId,
        ip: &str,
        ua: Option<&str>,
        status: u16,
        bytes: u64,
    ) -> Result<()> {
        // Convenience wrapper for tests + old call sites — passes None
        // for the Track-1.2 metadata columns (migration 0019) AND the
        // Track-1.4 TLS fingerprint columns (migration 0020). The
        // production writer task on the access-log channel calls
        // `log_sub_access_rich` directly so it can pass the captured
        // UA / Accept-Language / HTTP version / GeoIP / TLS-JA3/JA4
        // results.
        self.log_sub_access_rich(
            user_id, ip, ua, status, bytes, None, None, None, None, None, None, None,
        )
        .await
    }

    /// Full sub-access logging — accepts all Track-1.2 + Track-1.4
    /// metadata columns (migrations 0019, 0020). Called from the
    /// access-log writer task; handlers populate the captured-from-
    /// request fields and the writer enriches with GeoIP before
    /// passing through here.
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
        let ip = canonical_ip_text(ip);
        sqlx::query(
            "INSERT INTO sub_access_log
             (user_id, ip, ua, status, bytes,
              accept_language, http_version, device_class,
              geo_country, geo_asn, tls_ja3, tls_ja4)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        )
        .bind(&user_id.0)
        .bind(ip)
        .bind(ua)
        // SQLite has no u16 affinity; cast through i64.
        .bind(i64::from(status))
        .bind(i64::try_from(bytes).unwrap_or(i64::MAX))
        .bind(accept_language)
        .bind(http_version)
        .bind(device_class)
        .bind(geo_country)
        .bind(geo_asn)
        .bind(tls_ja3)
        .bind(tls_ja4)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Number of distinct source IPs that fetched this user's
    /// subscription URL in the last `since_hours` hours. Drives the
    /// "abuse signal" headline on the user-detail page.
    ///
    /// **Timestamp-format invariant (caught by retroactive review-agent
    /// 2026-05-14, was a critical bug):** the cutoff must be produced
    /// in the **same** format as `ts` is written by `log_sub_access` —
    /// ISO `YYYY-MM-DDTHH:MM:SS.fffZ` (note the `T` separator and the
    /// trailing `Z`). `datetime('now', ?)` returns the SQL form
    /// `YYYY-MM-DD HH:MM:SS` (space separator, no millis, no `Z`) and
    /// then SQLite compares both sides as TEXT — the `T` (0x54) is
    /// greater than space (0x20), so every same-day row would compare
    /// as "newer than the cutoff" regardless of its actual time-of-day.
    /// Always wrap with `strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)` so
    /// both sides share the format the row was written in.
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

    /// Most recent N access rows for one user, newest first. Drives the
    /// recent-activity table on the user-detail page; the limit caps
    /// memory + render cost since chatty clients can rack up thousands
    /// of rows in the retention window.
    pub async fn recent_sub_access(
        &self,
        user_id: &UserId,
        limit: i64,
    ) -> Result<Vec<SubAccessEntry>> {
        // Default behaviour preserved (returns ALL rows including
        // VPN-egress) so existing callers + spec tests keep their
        // contract. Callers that want the «real IPs only» variant
        // call `recent_sub_access_filtered` (Phase 4a) instead.
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

    /// v2 4c — paginated sub-access rows for the user Activity log.
    /// Newest first; `offset` walks older pages. 25/page in the UI.
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

    /// v2 4c — total sub-access rows for a user (the «of M» count).
    pub async fn sub_access_count_for_user(&self, user_id: &UserId) -> Result<u64> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sub_access_log WHERE user_id = ?1")
            .bind(&user_id.0)
            .fetch_one(&self.pool)
            .await?;
        Ok(u64::try_from(row.0).unwrap_or(0))
    }

    /// Phase 4a — `recent_sub_access` with VPN-egress filter. When
    /// `include_egress = false` (the user-detail page's default),
    /// returns ONLY rows where the src IP is a real client device,
    /// not one of our own VPN server addresses. The `is_vpn_egress`
    /// flag is set by the SQLite trigger added in migration 0021,
    /// so this filter is just a `WHERE is_vpn_egress = 0` predicate
    /// using the partial index `idx_sub_access_log_user_ts_real`.
    pub async fn recent_sub_access_filtered(
        &self,
        user_id: &UserId,
        limit: i64,
        include_egress: bool,
    ) -> Result<Vec<SubAccessEntry>> {
        // `include_egress` widened (2026-06-16) to "show our own infra
        // rows": the default (false) view now hides not just VPN-server
        // egress (`is_vpn_egress = 0`) but ALSO LAN / loopback / control-
        // egress fetches (our curl tests, the claude-chat host at
        // 192.168.0.200, the monitor canary) via `real_client_ip_predicate`.
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

    /// Phase 4a — aggregates over a user's recent `sub_access_log`
    /// rows for the user-detail summary cards (distinct IPs /
    /// countries / ASNs, total bytes, first/last seen, hidden-
    /// egress badge count). `days` bounds the window — Pavel's
    /// chosen UX is 30d for the cards, matching the retention
    /// purger's max window.
    ///
    /// One SQL round-trip; SQLite computes the aggregates over the
    /// already-filtered window so we don't ship raw rows through
    /// Rust just to count distinct values. The `egress_rows`
    /// counter is the only field that includes egress (so the
    /// «N hidden» badge has the right denominator).
    pub async fn sub_access_aggregates_for_user(
        &self,
        user_id: &UserId,
        days: u32,
    ) -> Result<SubAccessAggregates> {
        let cutoff = format!("-{days} days");
        // TT-3 — reconcile the distinct-client tile with the sharing
        // verdict + Source-IP origins, which all count only REAL client
        // IPs. `distinct_ips` AND its sub-label dims `distinct_countries`
        // / `distinct_asns` all apply `real_client_ip_predicate` so the
        // three numbers are drawn from ONE population. Gating only
        // `distinct_ips` self-contradicts: `real` excludes not just
        // RFC1918 (NULL geo) but also VPN-server addresses + the control
        // egress `83.97.108.34` — PUBLIC IPs that DO carry geo — so an
        // ip-gated / geo-ungated tile could read "0 client IPs · 30d"
        // over "1 ASN · 1 country" for a user whose only rows are that
        // control egress. `real` is a hardcoded range predicate (no user
        // input), safe to interpolate.
        //
        // `last_seen`/`first_seen` stay UNFILTERED (MAX/MIN over every
        // row): the tile is labelled "last fetch", and an egress pull
        // (client refreshing over its own tunnel) is a genuine fetch —
        // filtering it would show a staler time and desync last_seen
        // from the unfiltered first_seen. Recency ≠ distinct-client.
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

        // `i64 → u64` via `.max(0) as u64` is a saturating cast —
        // honest about discarding negatives (impossible for
        // COALESCE(SUM, 0) and COUNT(*), but defensive against any
        // future schema bug that lets a sentinel `-1` slip through;
        // the previous `.unwrap_or(0)` form silently swallowed
        // those without telemetry). Review-agent Phase 4a #4.
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

    /// TT-2 — proxy-masked stats for the Activity-tab honesty banner.
    /// Counts, within the `days` window and among real-client-attempt
    /// rows (`is_vpn_egress = 0`), how many carry an IP that is NOT a
    /// real client IP — i.e. a private/reserved/proxy address (the
    /// front proxy .210 that landed because it isn't in
    /// `VPNCTLD_TRUSTED_PROXIES`). Reuses `real_client_ip_predicate` so
    /// the "masked" set is the exact complement of what the verdict
    /// scorer keeps. `masked_min_ts`/`masked_max_ts` bound the banner's
    /// date span. When `window_rows == 0` the caller shows nothing.
    pub async fn sub_access_proxy_masked_stats(
        &self,
        user_id: &UserId,
        days: u32,
    ) -> Result<ProxyMaskedStats> {
        let real = real_client_ip_predicate("ip");
        // `real` is a hardcoded range predicate (no user input); safe to
        // interpolate. `NOT (real)` = the IP is reserved/private/proxy
        // or a known server address.
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

    /// Drop all rows older than `days`. Returns the number of rows
    /// removed so the caller (a periodic task in the daemon) can log
    /// the retention activity.
    ///
    /// See `distinct_ips_for_user` for the timestamp-format invariant;
    /// the same `strftime` wrap applies here so the purge cutoff is
    /// comparable to the ISO timestamps `log_sub_access` writes.
    pub async fn purge_sub_access_older_than(&self, days: u32) -> Result<u64> {
        let res = sqlx::query(
            "DELETE FROM sub_access_log WHERE ts < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1)",
        )
        .bind(format!("-{days} days"))
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    /// Aggregate `sub_access_log` into time buckets for the Phase F
    /// monitoring sparklines. `bucket = "hour"` groups by hourly
    /// truncation, `bucket = "day"` by date. `since_hours` is the
    /// look-back window from now.
    ///
    /// Returns ONE row per bucket that had at least one hit; the
    /// caller fills gaps with zero so the sparkline x-axis stays
    /// evenly spaced. Newest-first sort is NOT used — buckets come
    /// back oldest-first (ASC) so the renderer can walk them
    /// chronologically without re-sorting.
    pub async fn sub_access_buckets(
        &self,
        bucket: &str,
        since_hours: u32,
    ) -> Result<Vec<AccessBucket>> {
        // Bucket grouping format. We REJECT unknown bucket strings
        // rather than silently default — an operator typo should
        // surface as an error, not as a meaningless aggregate.
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
