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
    // ──────────────────────────────────────────────────────────────────
    // Phase 5c — per-user session windows.
    //
    // Session model: a tick observation of (user, server) either
    // EXTENDS the most-recent OPEN session for that pair (if the
    // gap since its `last_seen` is ≤ SESSION_GAP_MINUTES = 15),
    // or OPENS a new session row. Sessions are never explicitly
    // closed — they just stop being extended; old ones get
    // displayed with `last_seen < now - 15min`.
    // ──────────────────────────────────────────────────────────────────

    /// Either extend the currently-open session for (user, server)
    /// or open a new one, based on the time-since-last_seen vs
    /// the `gap_minutes` budget. Returns the session id touched
    /// for testability.
    ///
    /// `now` is passed in so tests can stub time; production code
    /// passes `Utc::now()`. `bytes_delta` and `conn_count` are
    /// added/maxed into the session's running totals.
    pub async fn session_observe(
        &self,
        user_id: &UserId,
        server_id: &ServerId,
        now: DateTime<Utc>,
        gap_minutes: i64,
        bytes_delta: u64,
        conn_count: u32,
    ) -> Result<i64> {
        // Look up the most-recent session for this (user, server).
        let cutoff = now - chrono::Duration::minutes(gap_minutes);
        let cutoff_s = cutoff.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        let now_s = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        let maybe_existing: Option<(i64, i64, i64)> = sqlx::query(
            "SELECT id, total_bytes, conn_count_peak
             FROM vpn_user_sessions
             WHERE user_id = ?1 AND server_id = ?2 AND last_seen >= ?3
             ORDER BY last_seen DESC
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
            // Gate the INSERT on user existence, SQL-side (mirrors the
            // #32 fix in `record_user_destinations`). `user_id` comes from
            // the log-scrape attribution map (a raw username), NOT
            // validated against `users`. `vpn_user_sessions.user_id` is
            // NOT NULL REFERENCES users(id); with `foreign_keys=ON` an
            // INSERT for a since-deleted user raises FK error 787. The
            // caller loops per-user and logs+continues, so it's currently
            // non-fatal, but it spams the warn-log every tick until the
            // stale user ages out of the scrape. `INSERT … SELECT …
            // WHERE EXISTS (… users …)` skips the unknown user cleanly:
            // 0 rows inserted, no FK error, no log noise.
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
            // 0 rows ⇒ unknown user, nothing inserted. Return 0 rather
            // than `last_insert_rowid()`, which would otherwise echo a
            // stale rowid from an earlier insert on this connection.
            if res.rows_affected() == 0 {
                Ok(0)
            } else {
                Ok(res.last_insert_rowid())
            }
        }
    }

    /// Recent sessions for one user, newest-first. Used by the
    /// user-detail «sessions timeline» on /admin/users/<id>.
    pub async fn recent_sessions_for_user(
        &self,
        user_id: &UserId,
        limit: i64,
    ) -> Result<Vec<VpnUserSessionRow>> {
        // TT-4: ORDER BY last_seen (not started_at) so a currently-open
        // or long-running session — which may have STARTED before newer
        // short ones — can never be buried past the LIMIT. The render
        // tags rows whose last_seen is within one poll interval of now
        // as «live».
        let rows = sqlx::query(
            "SELECT id, user_id, server_id, started_at, last_seen,
                    conn_count_peak, total_bytes
             FROM vpn_user_sessions
             WHERE user_id = ?1
             ORDER BY last_seen DESC
             LIMIT ?2",
        )
        .bind(&user_id.0)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_user_session).collect()
    }

    /// Purge sessions older than `days`. Wired into the hourly
    /// retention task at the standard 30-day default.
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

    // ──────────────────────────────────────────────────────────────────
    // Phase 5b — per-user × destination tracking.
    // ──────────────────────────────────────────────────────────────────

    /// Bulk-record (user, destination_label) pairs observed in
    /// the current clash-poll tick. Each call atomically UPSERTs
    /// per-pair rows for TODAY's UTC date — hit_count += 1,
    /// last_seen = now. Pairs are de-duplicated by the caller
    /// before passing in (one tick contributes ONE hit per pair,
    /// regardless of how many connections share the (user, dest)).
    pub async fn record_user_destinations(&self, pairs: &[(UserId, String)]) -> Result<()> {
        if pairs.is_empty() {
            return Ok(());
        }
        let mut tx = self.pool.begin().await?;
        for (user_id, dest) in pairs {
            // Bound destination label to 200 chars (pathological
            // hostnames don't blow up the row). Truncate on a CHAR
            // boundary — `&dest[..200]` panics if byte 200 lands
            // mid-codepoint (Cyrillic / emoji / IDN-as-UTF-8 SNI/Host
            // labels), and that panic propagates uncaught all the way
            // up `clash_poller::poll_one_server`, permanently aborting
            // the whole poll task. `.chars().take(200)` is the repo
            // idiom (cf. `daemon/src/handlers/sub.rs` accept_language)
            // and is byte-identical to the old slice for ASCII.
            let dest_truncated: String = dest.chars().take(200).collect();
            // Pre-filter to existing users, SQL-side. The `user_id`
            // comes from the log-scrape attribution map (a raw
            // username), NOT validated against `users`. With
            // `foreign_keys=ON` and the NOT NULL REFERENCES users(id)
            // FK, an insert for a since-deleted user raises an FK error
            // (code 787) that, under `?`, rolls back the WHOLE tx —
            // losing EVERY user's destinations for this tick (one stale
            // user poisons all, every tick, until it ages out of the
            // logs). `INSERT OR IGNORE` does NOT help here: the IGNORE
            // conflict algorithm does not suppress FK violations
            // (verified empirically against sqlx). So we gate the
            // insert on `WHERE EXISTS (… users …)` — the row for an
            // unknown user is simply not inserted, the statement
            // succeeds (0 rows affected), and the batch continues. The
            // `INSERT … SELECT … WHERE EXISTS` form still drives the
            // upsert: the SELECT yields the row only when the user
            // exists, and the ON CONFLICT clause then handles the
            // (user, dest, date) UNIQUE collision exactly as before.
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

    /// Top destinations for one user across the last `days`
    /// days, sorted by total hits DESC. Used by the user-detail
    /// «куда ходит этот юзер» section.
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
             ORDER BY hit_count DESC, last_seen DESC
             LIMIT ?3",
        )
        .bind(&user_id.0)
        .bind(&cutoff)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_user_destination).collect()
    }

    /// Purge destination rows older than `days`. Wired into the
    /// hourly retention task at the standard 30-day default.
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

    /// Bulk-record (user, source_ip) pairs observed in the current
    /// clash-poll tick. The source-IP counterpart to
    /// [`record_user_destinations`](Self::record_user_destinations):
    /// each call atomically UPSERTs per-pair rows for TODAY's UTC date
    /// — `hit_count += 1`, `last_seen = now`. Pairs are de-duplicated
    /// by the caller (one tick = one hit per pair, regardless of how
    /// many connections share the (user, source_ip)). Empty IPs must
    /// be filtered by the caller — they're meaningless to classify.
    ///
    /// Uses the same `INSERT … SELECT … WHERE EXISTS (users)` guard as
    /// the destinations writer: a since-deleted user (the user_id comes
    /// from the unvalidated log-scrape attribution map) is silently
    /// skipped instead of raising an FK error that would roll back the
    /// whole tick's batch (#32-class bug).
    pub async fn record_user_source_ips(&self, pairs: &[(UserId, String)]) -> Result<()> {
        if pairs.is_empty() {
            return Ok(());
        }
        let mut tx = self.pool.begin().await?;
        for (user_id, ip) in pairs {
            // Defensive: skip empty IPs even if the caller didn't.
            if ip.is_empty() {
                continue;
            }
            // Bound to 45 chars — the max textual IPv6 length
            // (incl. an IPv4-mapped tail). `.chars().take()` avoids a
            // mid-codepoint slice panic (defensive; IPs are ASCII).
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

    /// Record, per user, the number of DISTINCT ISP-scale networks seen in
    /// ONE clash snapshot (the per-tick concurrent-network count). UPSERTs
    /// `peak_concurrent_ips = MAX(existing, n)` for TODAY's UTC date, so the
    /// stored value is the day's high-water mark of simultaneous networks.
    /// Same `WHERE EXISTS (users)` deleted-user guard as the source-IP
    /// writer. The caller passes one (user, distinct_network_count) pair per user
    /// present in this snapshot; `n == 0` rows are skipped.
    pub async fn record_user_ip_concurrency(&self, peaks: &[(UserId, u32)]) -> Result<()> {
        if peaks.is_empty() {
            return Ok(());
        }
        let mut tx = self.pool.begin().await?;
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

    /// Peak concurrent distinct source IPs for one user over the last
    /// `days` days (the day-level high-water marks, MAX'd across the
    /// window). `0` if the user never had a recorded snapshot. Kept for the
    /// per-user diagnostic API; the fleet scorer uses the robust P75 query.
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

    /// Purge IP-concurrency rows older than `days`. Wired into the hourly
    /// retention task alongside `purge_user_source_ips_older_than`.
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

    /// Top source IPs for one user across the last `days` days, sorted
    /// by total hits DESC. Used by the user-detail «Source IPs»
    /// section. Mirrors
    /// [`top_destinations_for_user`](Self::top_destinations_for_user).
    pub async fn top_source_ips_for_user(
        &self,
        user_id: &UserId,
        days: u32,
        limit: u32,
    ) -> Result<Vec<VpnUserSourceIpRow>> {
        let cutoff = format!("-{days} days");
        // Show only REAL client source IPs — drop OUR infra (VPN server
        // addresses when a user hops nodes, + the homelab LAN/control
        // egress) via the shared `real_client_ip_predicate`. Single source
        // of truth with the sub_access-origins views.
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
             ORDER BY hit_count DESC, last_seen DESC
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

    /// Purge source-IP rows older than `days`. Wired into the hourly
    /// retention task at the standard 30-day default.
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

    /// Best-effort GeoIP label lookup for a set of IPs, drawn from the
    /// most-recent `sub_access_log` row that carried geo for each IP.
    /// Geo is an attribute of the IP itself (operator-independent), so
    /// this deliberately does NOT filter by user — a source IP seen in
    /// VPN traffic is enriched from ANY user's /sub fetch that resolved
    /// it. Returns `ip -> (country_opt, asn_opt)`; an IP absent from
    /// the map (or mapping to (None, None)) simply has no GeoIP record
    /// and the caller falls back to the reserved-range classifier.
    ///
    /// Mirrors the dynamic-IN-clause shape of
    /// [`users_for_source_ips`](Self::users_for_source_ips) (sqlx has
    /// no array binding). Bounded by the caller's IP-list length.
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
        // For each IP, take the geo from its newest row that actually
        // carried a country or ASN (older rows may predate the GeoIP
        // enrichment migration and have NULLs). `MAX(ts)` over the
        // non-NULL-geo subset via a correlated pick: group by IP and
        // take the geo associated with the latest qualifying ts.
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
            // A later duplicate (same ip, same mts tie) just overwrites
            // with equivalent geo — harmless; the join already pinned
            // the newest qualifying ts.
            out.insert(ip, (country, asn));
        }
        Ok(out)
    }

    // ──────────────────────────────────────────────────────────────────
    // Phase 5a-2 — reverse-DNS (PTR) cache for destination IPs.
    //
    // Pattern: the DNS resolver task in daemon/src/dns_resolver.rs
    // calls `lookup_dns_ptr_bulk(ips)` to fetch what's cached, then
    // shells out to `getent hosts <ip>` for each missing IP (in
    // parallel via spawn_blocking), then writes back via
    // `upsert_dns_ptr`. The admin UI's render path only ever calls
    // `lookup_dns_ptr_bulk` — never the resolver itself.
    //
    // TTL: 7 days, pruned by the existing hourly retention scheduler.
    // ──────────────────────────────────────────────────────────────────

    /// Bulk-fetch cached PTR results for a list of IPs. Returns a
    /// map from IP to (hostname_opt, resolved_at). hostname None =
    /// we tried and got no answer; that's a CACHED negative answer
    /// — distinct from the IP not being in the map at all (= never
    /// looked up). The render path uses this distinction to know
    /// whether to fall back to `IP:port` (negative cached) or show
    /// the resolved hostname.
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

    /// Insert-or-update a PTR cache entry. NULL hostname is a
    /// VALID value — caches "we asked, got no PTR" so the
    /// resolver doesn't re-query for the TTL window.
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

    /// Purge cache entries older than `days`. Aligned with the
    /// hourly retention scheduler. Default TTL: 7 days.
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
