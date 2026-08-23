use super::*;
use chrono::{DateTime, Utc};
use sqlx::Row;
use vpnctl_core::UserId;

/// All-zero [`SharingSignals`] for `user_id` — the per-user accumulator seed
/// in `sharing_signals_all_users` (each of the four signal queries fills in
/// its own fields).
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

#[allow(clippy::needless_pass_by_value)]
fn row_to_ban(r: sqlx::sqlite::SqliteRow) -> Result<Ban> {
    let parse_ts = |col: &str, raw: &str| {
        DateTime::parse_from_rfc3339(raw)
            .map(|d| d.with_timezone(&Utc))
            .map_err(|e| {
                SqliteInventoryError::Invalid(format!("ban {col} not RFC3339 ({raw}): {e}"))
            })
    };
    let created_str: String = r.try_get("created_at")?;
    let until_str: String = r.try_get("until_ts")?;
    Ok(Ban {
        id: r.try_get("id")?,
        created_at: parse_ts("created_at", &created_str)?,
        until_ts: parse_ts("until_ts", &until_str)?,
        kind: r.try_get("kind")?,
        key: r.try_get("key")?,
        reason: r.try_get("reason")?,
    })
}

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

    // (ProxyMaskedStats struct defined just below SubAccessAggregates.)
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

    /// UA-cluster aggregate for the Phase Track-4 fingerprint
    /// heuristic. Groups this user's recent `sub_access_log` rows
    /// by User-Agent and reports per-UA distinct IPs, distinct /16
    /// networks (first two v4 octets), and total hits.
    ///
    /// The /16 count is the key signal: a single roaming device
    /// usually moves within one ISP /16 (Wi-Fi switching subnets,
    /// LTE base stations under the same provider) — so distinct_ips
    /// can be high but distinct_slash16 stays at 1-2. A shared sub
    /// URL hits from many ISPs / countries → distinct_slash16 climbs.
    ///
    /// IPv6 addresses contribute `0` to the /16 count (we don't try
    /// to derive a meaningful network prefix without ASN data); the
    /// `distinct_ips` count still reflects them.
    pub async fn ua_clusters_for_user(
        &self,
        user_id: &UserId,
        since_hours: u32,
    ) -> Result<Vec<UaCluster>> {
        // Pull raw (ua, ip) tuples then aggregate in Rust — SQLite
        // can't extract /16 prefixes natively, and the row count is
        // bounded by the recent window so memory is fine.
        let rows = sqlx::query(
            "SELECT ua, ip FROM sub_access_log
             WHERE user_id = ?1
               AND ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)",
        )
        .bind(&user_id.0)
        .bind(format!("-{since_hours} hours"))
        .fetch_all(&self.pool)
        .await?;

        use std::collections::{HashMap, HashSet};
        // (ua_or_none) → (set of distinct IPs, set of distinct /16, hit count)
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
        // Sort by hit count DESC so the noisy UAs surface first in
        // the UI.
        out.sort_by_key(|c| std::cmp::Reverse(c.hits));
        Ok(out)
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

    // ── Persistent rate-limit bans (Phase Track-2 chunk 2) ──────────────

    /// Insert a new ban valid for `ttl_secs` seconds. `kind` MUST be
    /// `"ip"` or `"token"` (the SQL `CHECK` constraint will reject
    /// other values; we don't pre-validate so a typo surfaces as a
    /// loud `Err` instead of a silent skip). Multiple overlapping
    /// bans for the same key are allowed — `is_banned` returns true
    /// if ANY non-expired ban matches, so re-banning is harmless.
    pub async fn add_ban(&self, kind: &str, key: &str, ttl_secs: u64, reason: &str) -> Result<()> {
        // Cap ttl at i64::MAX seconds (~292B years) defensively. The
        // SQL `+N seconds` modifier takes signed values; an unsigned
        // u64 of MAX would silently wrap. Practical max here is the
        // 24h default the daemon writes.
        let ttl_signed: i64 = i64::try_from(ttl_secs).unwrap_or(i64::MAX);
        sqlx::query(
            "INSERT INTO sub_rate_bans (until_ts, kind, key, reason)
             VALUES (
                strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1),
                ?2, ?3, ?4
             )",
        )
        .bind(format!("+{ttl_signed} seconds"))
        .bind(kind)
        .bind(key)
        .bind(reason)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Returns `Some(seconds_until_oldest_ban_expires)` if `(kind,
    /// key)` has any non-expired ban; `None` otherwise. Hot-path
    /// query: the index `idx_sub_rate_bans_kind_key_until` covers
    /// the entire predicate so this is sub-millisecond.
    ///
    /// Returns the SOONEST expiry among all matching bans (so
    /// `Retry-After` reflects the conservative "you'll be unbanned
    /// in this many seconds at the earliest"). If multiple
    /// overlapping bans exist, the oldest one expires first.
    pub async fn is_banned(&self, kind: &str, key: &str) -> Result<Option<u64>> {
        let row_opt = sqlx::query(
            "SELECT MIN(until_ts) AS until FROM sub_rate_bans
             WHERE kind = ?1 AND key = ?2
               AND until_ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
        )
        .bind(kind)
        .bind(key)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row_opt else {
            return Ok(None);
        };
        let until_str: Option<String> = row.try_get("until")?;
        let Some(until_str) = until_str else {
            // No matching rows — MIN() over an empty set returns NULL.
            return Ok(None);
        };
        let until = DateTime::parse_from_rfc3339(&until_str)
            .map(|d| d.with_timezone(&Utc))
            .map_err(|e| {
                SqliteInventoryError::Invalid(format!("ban until_ts malformed: {until_str}: {e}"))
            })?;
        let now = Utc::now();
        let secs = (until - now).num_seconds();
        // Defensive: race between SELECT and the `now` value here
        // could surface as 0 or -1 if the ban just expired.
        Ok(Some(u64::try_from(secs.max(1)).unwrap_or(1)))
    }

    /// List all currently-active bans (any kind). Powers the
    /// admin UI's "Active bans" surface. Sorted newest-first by
    /// `created_at` so the most recent abuse pops to the top.
    pub async fn active_bans(&self) -> Result<Vec<Ban>> {
        // ORDER BY created_at DESC, id DESC — `id DESC` is the stable
        // tiebreaker for inserts that land in the same millisecond
        // (caught by `spec_sub_rate_bans::active_bans_lists_all_kinds_newest_first`
        // flaking on CI). `id` is monotonic on insert (SQLite ROWID),
        // so id DESC == insert-order DESC for ties.
        let rows = sqlx::query(
            "SELECT id, created_at, until_ts, kind, key, reason
             FROM sub_rate_bans
             WHERE until_ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             ORDER BY created_at DESC, id DESC",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_ban).collect()
    }

    /// Drop expired ban rows. Called periodically by the daemon's
    /// rate-limit cleanup task. Returns the number of rows removed
    /// for telemetry.
    pub async fn purge_expired_bans(&self) -> Result<u64> {
        let res = sqlx::query(
            "DELETE FROM sub_rate_bans
             WHERE until_ts <= strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
        )
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    /// **Q-4h** — fleet-wide likely-shared-subscription summary. Groups
    /// real (`is_vpn_egress = 0`) `sub_access_log` rows by user and
    /// returns `(user_id, distinct_ips, distinct_asns, distinct_countries)`
    /// for users whose distinct-ASN count is at least `min_asns` — the
    /// "one URL fetched from many networks" signal. Reuses the distinct-
    /// count column logic from `sub_access_aggregates_for_user`. Backs
    /// the dashboard abuse-overview card.
    ///
    /// **abuse-origins fix:** `sub_access_log.user_id` is nullable
    /// (`ON DELETE SET NULL`, migration 0004) — rows from since-deleted
    /// users carry a NULL `user_id` and were silently folded into a
    /// single blank-name group, which the dashboard then rendered as a
    /// nameless row aggregating every deleted user. The
    /// `AND user_id IS NOT NULL AND user_id != ''` predicate drops that
    /// forensic group from this per-user view (the `!= ''` arm is
    /// defensive — no path writes an empty id, but it costs nothing and
    /// guarantees the card never links to `/admin/users/`).
    pub async fn likely_shared_summary(
        &self,
        min_asns: u32,
    ) -> Result<Vec<(UserId, u64, u64, u64)>> {
        // Exclude our own infra IPs (LAN / loopback / server / control)
        // via `real_client_ip_predicate` — otherwise the homelab boxes that
        // fetch many users' subs (192.168.0.200 curl, the monitor) inflate
        // every user's distinct-IP/ASN counts and falsely flag them as
        // "shared". (2026-06-16 — Pavel: «показывает те же цифры».)
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

    /// Gather the raw account-sharing signals for EVERY user over the last
    /// `days` days (2026-06-17 — backs the redesigned sharing-risk scorer
    /// that replaces the bare `distinct_asns >= 3` heuristic). Four
    /// index-backed reads, merged in Rust by user_id (fleet scale is tiny):
    /// (1) sub_access diversity — distinct real-client IPs / ASNs / countries
    /// / device-classes; (2) impossible travel — consecutive `/sub` fetches
    /// whose country changed in under `impossible_travel_hours` (two locations
    /// at once); (3) peak concurrent source IPs — the true-simultaneity signal
    /// from `vpn_user_ip_concurrency`; (4) max distinct connect-from IPs in any
    /// single day.
    /// All sub_access/source-IP reads apply `real_client_ip_predicate` so
    /// our own infra never inflates a user's signals.
    pub async fn sharing_signals_all_users(
        &self,
        days: u32,
        impossible_travel_hours: f64,
    ) -> Result<Vec<SharingSignals>> {
        use sqlx::Row;
        use std::collections::HashMap;
        let ts_cut = format!("-{days} days");
        let pred_ip = real_client_ip_predicate("ip");
        let pred_src = real_client_ip_predicate("source_ip");

        let mut acc: HashMap<String, SharingSignals> = HashMap::new();

        // 1 — sub_access diversity.
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

        // 2 — impossible travel (country change between consecutive fetches
        // faster than `impossible_travel_hours`). LAG yields the previous
        // country + ts per user; the delta is computed in the outer query
        // (Debian-12 SQLite 3.40 julianday can't parse the trailing 'Z').
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

        // 3 — typical simultaneous network count: the 75th percentile of
        // each user's DAILY peaks. The old absolute MAX let one stale
        // connection / carrier hand-over own the score for the full 30-day
        // window. P75 keeps sustained concurrency strong while ignoring a
        // small number of outlier days. SQLite 3.40 has the window functions
        // used here; `(3*n+3)/4` is ceil(0.75*n) with integer arithmetic.
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

        // 4 — max distinct ISP-scale NETWORKS connected from in one day.
        // Raw (user, date, ip) rows are folded with `network_key`, then MAX'd.
        let q4 = format!(
            "SELECT user_id, date, source_ip
             FROM vpn_user_source_ips
             WHERE date >= strftime('%Y-%m-%d', 'now', ?1) AND {pred_src}"
        );
        let mut per_day_nets: HashMap<(String, String), std::collections::HashSet<String>> =
            HashMap::new();
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

    // ── abuse-origins: per-user "Subscription origins" breakdown ───────
    //
    // Four grouped, index-backed reads behind the user-detail
    // "Subscription origins" section. Every one scopes to ONE user's
    // real client fetches:
    //   * `user_id = ?1`     — this user only,
    //   * `is_vpn_egress = 0` — exclude rows where the src IP is one of
    //                           our own VPN servers (full-tunnel egress),
    //   * `ts > <days-ago>`   — bound the window.
    // The partial index `idx_sub_access_log_user_id_real (user_id, id DESC)
    // WHERE is_vpn_egress = 0` covers the `user_id = ?1 AND
    // is_vpn_egress = 0` prefix, so SQLite seeks instead of scanning.
    // NULL `user_id` (since-deleted users) is excluded for free by the
    // `user_id = ?1` equality (SQL `=` never matches NULL).

    /// abuse-origins — group this user's real `/sub` fetches by GeoIP
    /// country over the last `days`. One row per distinct `geo_country`
    /// (NULL countries collapse into one `None` group), ordered by fetch
    /// count DESC. Backs the "by country" table of the origins section.
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

    /// abuse-origins — group this user's real `/sub` fetches by GeoIP
    /// ASN / ISP over the last `days`, returning the top `limit` by fetch
    /// count. `country` is a representative `MAX(geo_country)` for the
    /// group (most ASNs sit in one country). Backs the "by ISP" table.
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

    /// abuse-origins — group this user's real `/sub` fetches by source
    /// IP over the last `days`, returning the top `limit` by most-recent
    /// activity (`MAX(ts)` DESC). `country` / `asn` are the
    /// representative `MAX(…)` for the IP (one IP usually maps to one
    /// network). `first_seen` / `last_seen` are ISO-8601 strings the
    /// renderer reformats via `format_msk_iso`. Backs the "by IP" table.
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

    /// abuse-origins — rough distinct-device proxy for this user over the
    /// last `days`. Counts `DISTINCT` non-NULL `device_class`, `tls_ja4`,
    /// and `ua` across the user's real (`is_vpn_egress = 0`) rows. A
    /// distinct-device count well above a household's device count is a
    /// sharing signal. One round-trip, all three counts in one row.
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
        // `COUNT(DISTINCT col)` already ignores NULLs in SQLite, so a
        // user whose rows have NULL device_class / ja4 contributes 0
        // there — exactly the "unknown, don't claim a device" semantics
        // we want.
        let distinct_device_classes: i64 = row.try_get("distinct_device_classes")?;
        let distinct_ja4: i64 = row.try_get("distinct_ja4")?;
        let distinct_uas: i64 = row.try_get("distinct_uas")?;
        Ok(SubDeviceFp {
            distinct_device_classes: distinct_device_classes.max(0) as u64,
            distinct_ja4: distinct_ja4.max(0) as u64,
            distinct_uas: distinct_uas.max(0) as u64,
        })
    }

    /// Users whose freshly-fetched subscription produced no traffic
    /// (2026-06-16 — backs `health_monitor::check_sub_fetch_without_traffic`).
    ///
    /// Returns previously-active users (had attributed traffic within
    /// `active_days` BEFORE the fetch) whose MOST-RECENT real `/sub` fetch is
    /// between `grace_minutes` and `lookback_minutes` ago AND who have had
    /// ZERO attributed traffic SINCE that fetch. This is the silent signature
    /// of a subscription whose issued config no longer dials (the `fp=chrome`
    /// DPI breakage, a protocol-visibility regression, a broken share-link):
    /// the client re-imports and then never connects, with no server error.
    ///
    /// - `grace_minutes`: a just-fetched user is still importing/setting up;
    ///   don't flag until the fetch is at least this old (no traffic by now is
    ///   the real signal, not impatience).
    /// - `lookback_minutes`: only RECENT re-imports are actionable; also
    ///   bounds how long a never-recovering user keeps re-firing.
    /// - `active_days`: the "was working before" gate — restricts to a
    ///   regression (a known-good user broke), not a brand-new user who never
    ///   connected (their failure is a setup problem, not our regression).
    ///
    /// `julianday(replace(t,'Z',''))` strips the trailing `Z` because the
    /// Debian-12 SQLite (3.40) predates 3.42's native `Z` parsing — without
    /// it `julianday` returns NULL and `fetch_age_minutes` is bogus. The
    /// window-boundary comparisons stay as lexicographic string `<=`/`>=`
    /// against `strftime(...Z)` output, matching every other query here.
    pub async fn sub_fetch_without_traffic_users(
        &self,
        grace_minutes: u32,
        lookback_minutes: u32,
        active_days: u32,
    ) -> Result<Vec<SubFetchStallUser>> {
        use sqlx::Row;
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
        Ok(rows
            .into_iter()
            .map(|r| SubFetchStallUser {
                user_id: UserId(r.get::<String, _>("user_id")),
                last_fetch: r.get::<String, _>("last_fetch"),
                last_traffic: r.get::<Option<String>, _>("last_traffic"),
                fetch_age_minutes: r.get::<i64, _>("age_min"),
            })
            .collect())
    }
}
