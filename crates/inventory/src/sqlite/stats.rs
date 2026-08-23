use super::*;
use chrono::{DateTime, Utc};
use sqlx::Row;
use vpnctl_core::{ServerId, UserId};

// Owned row argument is what `.into_iter().map(...)` over `Vec<SqliteRow>`
// gives us; taking by reference would force a `.collect()` round-trip.
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

#[allow(clippy::needless_pass_by_value)]
fn row_to_vpn_stats(r: sqlx::sqlite::SqliteRow) -> Result<VpnStatsRow> {
    let ts_s: String = r.try_get("ts")?;
    let ts = DateTime::parse_from_rfc3339(&ts_s)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|e| {
            SqliteInventoryError::Invalid(format!("vpn_connection_stats.ts malformed: {ts_s}: {e}"))
        })?;
    let server_id: String = r.try_get("server_id")?;
    let user_id_opt: Option<String> = r.try_get("user_id")?;
    let upload_i: i64 = r.try_get("upload_bytes")?;
    let download_i: i64 = r.try_get("download_bytes")?;
    let conns_i: i64 = r.try_get("active_connections")?;
    Ok(VpnStatsRow {
        ts,
        server_id: ServerId(server_id),
        user_id: user_id_opt.map(UserId),
        upload_bytes: u64::try_from(upload_i).unwrap_or(0),
        download_bytes: u64::try_from(download_i).unwrap_or(0),
        active_connections: u32::try_from(conns_i).unwrap_or(0),
    })
}

impl SqliteInventory {
    // ──────────────────────────────────────────────────────────────────
    // Track-3 chunk 2 — VPN connection stats (clash-api poller sink)
    //
    // The poller in `daemon::clash_poller` (separate iter / chunk) calls
    // `record_vpn_stats(server_id, deltas)` once per tick. The read
    // surfaces — `recent_vpn_stats_for_user` and
    // `recent_vpn_stats_for_server` — power chunk 3's UI on
    // `/admin/users/<id>` and `/admin/servers/<id>`.
    //
    // Server-wide rows are persisted under `user_id = NULL` so the
    // server-detail page can render bandwidth-vs-time without joining
    // across every per-user row.
    //
    // All deltas for one tick land in a single transaction so a poller
    // crash mid-write doesn't yield a half-attributed snapshot.
    //
    // **Audit-log exemption.** The "every inventory mutation gets one
    // audit_log row" invariant from CLAUDE.md is INTENTIONALLY waived
    // for `vpn_connection_stats`. Rationale: at homelab scale (5
    // servers × 60s tick × 24h × 30d = ~216K poller writes per month
    // before user multiplication), per-tick audit rows would dwarf
    // every other audit entry by 4 orders of magnitude and bury the
    // human-driven mutations the timeline is designed to surface. The
    // table itself IS the audit trail for poller activity (timestamps
    // + per-server + per-user breakdown); a chunk-3 retrospective on
    // /admin/audit can join in a derived "vpn-stats activity" entry
    // if operators ever need it. (Reviewed by independent review-agent
    // on cd61838^..492fdeb burst; documented exemption rather than
    // letting the invariant erode silently.)
    // ──────────────────────────────────────────────────────────────────

    /// Persist one tick's deltas. Empty `deltas` is a no-op (the
    /// poller may decide a quiet node doesn't deserve a row).
    /// Timestamp is `now` on the daemon, NOT pulled from the snapshot
    /// — clash-api doesn't carry a snapshot timestamp, and the
    /// daemon's clock is the only source we trust on the read side.
    pub async fn record_vpn_stats(
        &self,
        server_id: &ServerId,
        deltas: &[VpnStatsDelta],
    ) -> Result<()> {
        if deltas.is_empty() {
            return Ok(());
        }
        let mut tx = self.pool.begin().await?;
        for d in deltas {
            sqlx::query(
                "INSERT INTO vpn_connection_stats
                 (ts, server_id, user_id, upload_bytes, download_bytes, active_connections)
                 VALUES (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), ?1, ?2, ?3, ?4, ?5)",
            )
            .bind(&server_id.0)
            .bind(d.user_id.as_ref().map(|u| u.0.as_str()))
            .bind(i64::try_from(d.upload_bytes).unwrap_or(i64::MAX))
            .bind(i64::try_from(d.download_bytes).unwrap_or(i64::MAX))
            .bind(i64::from(d.active_connections))
            .execute(&mut *tx)
            .await?;
        }
        let rollup_up = deltas
            .iter()
            .fold(0u64, |sum, d| sum.saturating_add(d.upload_bytes));
        let rollup_down = deltas
            .iter()
            .fold(0u64, |sum, d| sum.saturating_add(d.download_bytes));
        let peak_connections = deltas
            .iter()
            .map(|d| d.active_connections)
            .max()
            .unwrap_or(0);
        sqlx::query(
            "INSERT INTO vpn_server_hourly
                (hour, server_id, upload_bytes, download_bytes,
                 active_connections_peak, last_sample_ts)
             VALUES (
                strftime('%Y-%m-%dT%H:00:00.000Z', 'now'),
                ?1, ?2, ?3, ?4,
                strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             )
             ON CONFLICT(server_id, hour) DO UPDATE SET
                upload_bytes = upload_bytes + excluded.upload_bytes,
                download_bytes = download_bytes + excluded.download_bytes,
                active_connections_peak = MAX(
                    active_connections_peak,
                    excluded.active_connections_peak
                ),
                last_sample_ts = excluded.last_sample_ts",
        )
        .bind(&server_id.0)
        .bind(i64::try_from(rollup_up).unwrap_or(i64::MAX))
        .bind(i64::try_from(rollup_down).unwrap_or(i64::MAX))
        .bind(i64::from(peak_connections))
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Recent per-user rows across ALL servers in the look-back
    /// window. Newest-first. The UI joins these by server_id to
    /// render a per-server breakdown if needed.
    pub async fn recent_vpn_stats_for_user(
        &self,
        user_id: &UserId,
        since_hours: u32,
    ) -> Result<Vec<VpnStatsRow>> {
        let rows = sqlx::query(
            "SELECT ts, server_id, user_id, upload_bytes, download_bytes, active_connections
             FROM vpn_connection_stats
             WHERE user_id = ?1
               AND ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)
             ORDER BY ts DESC",
        )
        .bind(&user_id.0)
        .bind(format!("-{since_hours} hours"))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_vpn_stats).collect()
    }

    pub async fn set_user_traffic_limit(
        &self,
        id: &UserId,
        limit_bytes: Option<u64>,
        threshold_pct: Option<u8>,
    ) -> Result<()> {
        // Cap threshold_pct at u8 max; SQLite stores as INTEGER so
        // both halves fit comfortably.
        let limit_i64 = limit_bytes.map(|b| i64::try_from(b).unwrap_or(i64::MAX));
        let threshold_i64 = threshold_pct.map(i64::from);
        let res = sqlx::query(
            "UPDATE users
                SET monthly_bandwidth_limit_bytes = ?1,
                    traffic_alert_threshold_pct  = ?2
              WHERE id = ?3",
        )
        .bind(limit_i64)
        .bind(threshold_i64)
        .bind(&id.0)
        .execute(&self.pool)
        .await?;
        if res.rows_affected() == 0 {
            return Err(SqliteInventoryError::Invalid(format!(
                "no such user: {}",
                id.0
            )));
        }
        Ok(())
    }

    /// Read both limit fields for a user. Returns
    /// `(monthly_bandwidth_limit_bytes, traffic_alert_threshold_pct)`
    /// — either or both may be `None` (no limit / use default
    /// threshold). Used by the user-detail page + the daemon-side
    /// alert evaluator.
    pub async fn get_user_traffic_limit(&self, id: &UserId) -> Result<(Option<u64>, Option<u8>)> {
        let row = sqlx::query(
            "SELECT monthly_bandwidth_limit_bytes, traffic_alert_threshold_pct
             FROM users WHERE id = ?1",
        )
        .bind(&id.0)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok((None, None));
        };
        let limit: Option<i64> = row.try_get("monthly_bandwidth_limit_bytes")?;
        let threshold: Option<i64> = row.try_get("traffic_alert_threshold_pct")?;
        let limit_u64 = limit.map(|v| if v < 0 { 0 } else { v as u64 });
        let threshold_u8 = threshold.map(|v| v.clamp(0, 100) as u8);
        Ok((limit_u64, threshold_u8))
    }

    /// Total (upload + download) bytes for a user since the start
    /// of the current calendar month (UTC). `0` when no traffic
    /// has been recorded this month — never errors on "no rows".
    /// SQLite's `strftime('%Y-%m-01T00:00:00Z', 'now')` gives the
    /// month-start anchor; resets automatically on the 1st.
    pub async fn user_traffic_this_month(&self, id: &UserId) -> Result<u64> {
        // Weight each tick's bytes by its server's `usage_coefficient`
        // (Marzban-style per-node traffic multiplier) so traffic on a
        // ×2 node counts double toward the monthly total. The REAL
        // multiply is cast back to INTEGER so the column stays an i64
        // for `try_get` (and the unit stays bytes). Default coeff 1.0
        // (or a NULL via COALESCE) is the identity — pre-existing
        // single-coefficient deployments see no change.
        let row = sqlx::query(
            "SELECT CAST(
                        COALESCE(
                            SUM((s.upload_bytes + s.download_bytes)
                                * COALESCE(sv.usage_coefficient, 1.0)),
                            0
                        ) AS INTEGER
                    ) AS total
             FROM vpn_connection_stats s
             JOIN servers sv ON sv.id = s.server_id
             WHERE s.user_id = ?1
               AND s.ts >= strftime('%Y-%m-01T00:00:00Z', 'now')",
        )
        .bind(&id.0)
        .fetch_one(&self.pool)
        .await?;
        let total: i64 = row.try_get("total")?;
        Ok(total.max(0) as u64)
    }

    /// Aggregate over every user: their month-to-date traffic +
    /// configured limit + configured threshold (or NULLs).
    /// Returns ONLY users who currently have a configured
    /// `monthly_bandwidth_limit_bytes` — operators without a cap
    /// don't need to appear in the dashboard alert section.
    /// Ordered by usage-as-pct-of-limit DESC so the most-at-risk
    /// account is first.
    pub async fn users_traffic_vs_limit(&self) -> Result<Vec<(UserId, u64, u64, u8)>> {
        // The percentage compare is done in Rust because SQLite
        // integer division would truncate to 0 for "5% of 100GB
        // = 5_000_000_000_000 / 100" before SQLite-3.45's bigint
        // arithmetic; safer + clearer in Rust where we already have
        // u64 + f64.
        let rows = sqlx::query(
            "SELECT u.id,
                    COALESCE(u.traffic_alert_threshold_pct, 80) AS threshold,
                    u.monthly_bandwidth_limit_bytes AS lim,
                    CAST(
                        COALESCE(
                            (SELECT SUM((s.upload_bytes + s.download_bytes)
                                        * COALESCE(sv.usage_coefficient, 1.0))
                             FROM vpn_connection_stats s
                             JOIN servers sv ON sv.id = s.server_id
                             WHERE s.user_id = u.id
                               AND s.ts >= strftime('%Y-%m-01T00:00:00Z', 'now')),
                            0
                        ) AS INTEGER
                    ) AS used
             FROM users u
             WHERE u.monthly_bandwidth_limit_bytes IS NOT NULL",
        )
        .fetch_all(&self.pool)
        .await?;
        let mut out: Vec<(UserId, u64, u64, u8)> = Vec::with_capacity(rows.len());
        for r in rows {
            let id: String = r.try_get("id")?;
            let threshold: i64 = r.try_get("threshold")?;
            let lim: i64 = r.try_get("lim")?;
            let used: i64 = r.try_get("used")?;
            let lim_u = lim.max(0) as u64;
            let used_u = used.max(0) as u64;
            let threshold_u = threshold.clamp(0, 100) as u8;
            out.push((UserId(id), used_u, lim_u, threshold_u));
        }
        // Sort by percent-of-limit DESC (most-at-risk first); ties
        // broken by absolute used DESC for stability.
        out.sort_by(|a, b| {
            let pa = if a.2 == 0 {
                0.0
            } else {
                a.1 as f64 / a.2 as f64
            };
            let pb = if b.2 == 0 {
                0.0
            } else {
                b.1 as f64 / b.2 as f64
            };
            pb.partial_cmp(&pa)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| b.1.cmp(&a.1))
        });
        Ok(out)
    }

    /// Top-N users by total (upload + download) bytes over the
    /// look-back window. Used by the dashboard's heavy-user heatmap
    /// to surface abuse-candidate accounts at a glance. Returns
    /// `(user_id, total_bytes)` sorted DESC; rows with NULL user_id
    /// (server-wide aggregates) are excluded.
    ///
    /// Empty Vec when no per-user traffic has been recorded yet (or
    /// when the poller hasn't run). Caller renders an empty-state.
    pub async fn top_users_by_traffic(
        &self,
        since_hours: u32,
        limit: u32,
    ) -> Result<Vec<HeavyUser>> {
        // Weight each row's bytes by the source server's
        // `usage_coefficient` before summing per-user, so a heavy user
        // on a ×2 node ranks above an equal-raw-bytes user on a ×1
        // node. The weighted SUMs are REAL; CAST back to INTEGER so the
        // result columns stay i64 (bytes). 1.0 (or NULL) is the
        // identity → existing rankings unchanged.
        //
        // upload + download are summed SEPARATELY (2026-06-16 — the
        // dashboard tile shows the three-column breakdown). `total` is
        // derived Rust-side as `up + down` so it's exactly consistent
        // with the two columns (independent CASTs could each truncate,
        // leaving `up + down != CAST(SUM(up+down))` by ±1). Ranking
        // still uses the un-CAST combined weighted SUM → identical order
        // to the pre-split query.
        let rows = sqlx::query(
            "SELECT s.user_id AS user_id,
                    CAST(SUM(s.upload_bytes   * COALESCE(sv.usage_coefficient, 1.0)) AS INTEGER) AS up_b,
                    CAST(SUM(s.download_bytes * COALESCE(sv.usage_coefficient, 1.0)) AS INTEGER) AS down_b
             FROM vpn_connection_stats s
             JOIN servers sv ON sv.id = s.server_id
             WHERE s.user_id IS NOT NULL
               AND s.ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1)
             GROUP BY s.user_id
             ORDER BY SUM((s.upload_bytes + s.download_bytes)
                          * COALESCE(sv.usage_coefficient, 1.0)) DESC
             LIMIT ?2",
        )
        .bind(format!("-{since_hours} hours"))
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
                total_bytes: up + down,
            });
        }
        Ok(out)
    }

    // ──────────────────────────────────────────────────────────────────
    // PR-Q — informativeness query layer.
    //
    // Index-backed read aggregates that back the admin-UI dashboard /
    // server-detail / user-detail informativeness cards. Each mirrors an
    // existing method's style; weighting by `usage_coefficient` matches
    // the #41 traffic-accounting convention. None of these mutate — no
    // audit rows. EXPLAIN QUERY PLAN evidence is in the PR description.
    // ──────────────────────────────────────────────────────────────────

    /// **Q-4a** — top traffic users restricted to ONE server. Same
    /// `usage_coefficient`-weighted ranking as `top_users_by_traffic`
    /// (#41 pattern) but with `AND s.server_id = ?`. Backs the
    /// server-detail "heaviest users on this node" card. `user_id IS
    /// NOT NULL` excludes the server-wide rollup rows.
    pub async fn top_users_by_traffic_for_server(
        &self,
        server: &ServerId,
        since_hours: u32,
        limit: u32,
    ) -> Result<Vec<(UserId, u64)>> {
        let rows = sqlx::query(
            "SELECT s.user_id AS user_id,
                    CAST(SUM((s.upload_bytes + s.download_bytes)
                             * COALESCE(sv.usage_coefficient, 1.0)) AS INTEGER) AS total
             FROM vpn_connection_stats s
             JOIN servers sv ON sv.id = s.server_id
             WHERE s.server_id = ?1
               AND s.user_id IS NOT NULL
               AND s.ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)
             GROUP BY s.user_id
             ORDER BY total DESC
             LIMIT ?3",
        )
        .bind(&server.0)
        .bind(format!("-{since_hours} hours"))
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let uid: String = r.try_get("user_id")?;
            let total: i64 = r.try_get("total")?;
            out.push((UserId(uid), total.max(0) as u64));
        }
        Ok(out)
    }

    /// **Q-4b** — one user's traffic broken down per server. Returns
    /// `(server_id, up_bytes, down_bytes)` summed over the window,
    /// `usage_coefficient`-weighted like the other traffic queries.
    /// Backs the user-detail "where this user's traffic lands" card.
    pub async fn user_traffic_by_server(
        &self,
        user: &UserId,
        since_hours: u32,
    ) -> Result<Vec<(ServerId, u64, u64)>> {
        let rows = sqlx::query(
            "SELECT s.server_id AS server_id,
                    CAST(SUM(s.upload_bytes
                             * COALESCE(sv.usage_coefficient, 1.0)) AS INTEGER) AS up_total,
                    CAST(SUM(s.download_bytes
                             * COALESCE(sv.usage_coefficient, 1.0)) AS INTEGER) AS down_total
             FROM vpn_connection_stats s
             JOIN servers sv ON sv.id = s.server_id
             WHERE s.user_id = ?1
               AND s.ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)
             GROUP BY s.server_id
             ORDER BY (up_total + down_total) DESC",
        )
        .bind(&user.0)
        .bind(format!("-{since_hours} hours"))
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let sid: String = r.try_get("server_id")?;
            let up: i64 = r.try_get("up_total")?;
            let down: i64 = r.try_get("down_total")?;
            out.push((ServerId(sid), up.max(0) as u64, down.max(0) as u64));
        }
        Ok(out)
    }

    /// Recent server-wide + per-user rows for one server in the
    /// look-back window. Newest-first. The server-detail UI uses
    /// the `user_id IS NULL` rows for the bandwidth sparkline and
    /// the rest for the per-user breakdown.
    pub async fn recent_vpn_stats_for_server(
        &self,
        server_id: &ServerId,
        since_hours: u32,
    ) -> Result<Vec<VpnStatsRow>> {
        let rows = sqlx::query(
            "SELECT ts, server_id, user_id, upload_bytes, download_bytes, active_connections
             FROM vpn_connection_stats
             WHERE server_id = ?1
               AND ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)
             ORDER BY ts DESC",
        )
        .bind(&server_id.0)
        .bind(format!("-{since_hours} hours"))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_vpn_stats).collect()
    }

    /// Detect per-user attribution STALL per server (2026-06-14 — backs the
    /// `server.attribution.stalled` health alert). A server is "stalled"
    /// when, over the recent window, it has live connections (server-wide
    /// rows show `active_connections >= min_active`) but ZERO distinct
    /// attributed users — the clash poll lands server-wide totals while the
    /// sing-box log scrape attributed nobody. This is the signature of an
    /// orphaned sing-box log fd (live log 0-byte) or a persistently failing
    /// scrape — exactly the silent break that hit prod twice (logrotate
    /// orphan, then the `install /dev/null` ensure_installed orphan).
    ///
    /// `window_minutes` spans multiple poll ticks so the transient one-tick
    /// blip right after a sing-box restart does NOT flag. Index-backed by
    /// `idx_vcs_ts` (ts range) + a small GROUP BY.
    pub async fn attribution_stall_servers(
        &self,
        window_minutes: u32,
        min_active: u32,
    ) -> Result<Vec<ServerId>> {
        use sqlx::Row;
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

    /// Fleet-wide stats for the dashboard's multi-window traffic chart.
    ///
    /// Reads the ingest-time hourly rollup, then lets SQLite collapse
    /// hours to the chart's selected bucket size.
    pub async fn recent_vpn_stats_fleet(
        &self,
        since_hours: u32,
        bucket_hours: u32,
    ) -> Result<Vec<VpnStatsRow>> {
        let bucket_seconds = i64::from(bucket_hours)
            .checked_mul(3600)
            .filter(|seconds| *seconds > 0)
            .ok_or_else(|| SqliteInventoryError::Invalid("bucket_hours must be > 0".into()))?;
        let rows = sqlx::query(
            "SELECT
                MAX(last_sample_ts) AS ts,
                server_id,
                NULL AS user_id,
                COALESCE(SUM(upload_bytes), 0) AS upload_bytes,
                COALESCE(SUM(download_bytes), 0) AS download_bytes,
                COALESCE(MAX(active_connections_peak), 0) AS active_connections
             FROM vpn_server_hourly
             WHERE hour >= strftime('%Y-%m-%dT%H:00:00.000Z', 'now', ?1)
             GROUP BY CAST(strftime('%s', hour) AS INTEGER) / ?2, server_id
             ORDER BY ts DESC, server_id",
        )
        .bind(format!("-{since_hours} hours"))
        .bind(bucket_seconds)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_vpn_stats).collect()
    }

    /// Weighted totals over the last `since_hours` aligned hourly buckets,
    /// one compact row per server.
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

    /// Phase 4b — single-query rollup of server-wide live activity
    /// for the server-detail tile + dashboard aggregate. Uses
    /// server-wide rows (user_id IS NULL) for the «active now»
    /// counter (clash-api per-tick `active_connections` value) and
    /// sums every row (per-user + server-wide) for the bytes-in-
    /// window counters. `distinct_users_attributed` reports how
    /// many per-user rows landed in the window — meaningful only
    /// AFTER the NM-11 sing-box upstream fix; today the operator
    /// sees `0` and the user-detail's «Live VPN stats» empty-
    /// state explains why.
    pub async fn server_live_activity(
        &self,
        server_id: &ServerId,
        since_hours: u32,
    ) -> Result<ServerLiveActivity> {
        let since = format!("-{since_hours} hours");
        // Single SELECT (Phase 4b post-review fix #2): the previous
        // two-query version had a race where a poller insert
        // between aggregates and «latest active» queries could
        // produce an `active_now` from a tick newer than
        // `last_sample_ts`. SQLite WITH clause holds the row set
        // for both correlated reads in one snapshot.
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
                 ORDER BY ts DESC LIMIT 1)                          AS active_now",
        )
        .bind(&server_id.0)
        .bind(&since)
        .fetch_one(&self.pool)
        .await?;

        let bytes_up: i64 = row.try_get("bytes_up")?;
        let bytes_dn: i64 = row.try_get("bytes_dn")?;
        let last_ts_s: Option<String> = row.try_get("last_ts")?;
        let attributed: i64 = row.try_get("attributed")?;
        let active_now_opt: Option<i64> = row.try_get("active_now")?;
        let active_now: u32 = match active_now_opt {
            Some(v) => u32::try_from(v.max(0)).unwrap_or(u32::MAX),
            None => 0,
        };

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

    /// Phase 4c — given a list of source IPs (from a clash-api
    /// snapshot's `metadata.sourceIP` fields), find for each IP the
    /// most-likely `user_id` by counting hits in `sub_access_log`
    /// over the look-back window. Returns a map `source_ip ->
    /// Vec<(user_id, hit_count)>` sorted DESC by hit count, so the
    /// top entry is the most plausible owner. Empty Vec means no
    /// user has hit subscription URL from that IP in the window.
    ///
    /// Why this works despite NM-11: sing-box's clash-api still
    /// emits `sourceIP` (real public IP of client behind VLESS/TUIC
    /// auth). vpnctld's `sub_access_log.ip` also stores the real
    /// client IP for every `/api/v1/app/config/<device>` and
    /// `/sub/<token>` request. The intersection identifies «whose
    /// devices are talking from that IP right now» without sing-box
    /// needing to emit the `user` field. False positives possible
    /// (NAT collision: two real users behind one CGNAT IP), so the
    /// UI labels this «likely» not «is».
    ///
    /// Bounded by `ips.len()` * `look_back_days` rows of
    /// sub_access_log — single GROUP BY query with `WHERE ip IN
    /// (?, ?, ?, …)`. Skips VPN-egress rows (is_vpn_egress = 0)
    /// because those are our own server IPs, not real clients.
    pub async fn users_for_source_ips(
        &self,
        ips: &[String],
        look_back_days: u32,
    ) -> Result<std::collections::HashMap<String, Vec<(UserId, u64)>>> {
        use std::collections::HashMap;
        if ips.is_empty() {
            return Ok(HashMap::new());
        }
        // Build the IN-clause placeholders dynamically (sqlx doesn't
        // support `IN (?)` with an array binding). Safe because
        // every `?` gets a single string bind; no string interp of
        // user-controlled data into the SQL itself.
        let placeholders = std::iter::repeat_n("?", ips.len())
            .collect::<Vec<_>>()
            .join(",");
        // `is_vpn_egress = 0` already drops VPN-server-IP fetches, but the
        // homelab LAN + control egress (192.168.0.x, 83.97.108.34, …) are
        // is_vpn_egress=0, so exclude them via `real_client_ip_predicate` —
        // otherwise every user we test/monitor from those IPs looks like
        // they "share" the IP.
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

    /// Phase 4b — dashboard rollup across every known server.
    /// Returns one `ServerLiveActivity` per `servers.id` (even for
    /// servers the poller never reached — they get the default-
    /// zeroed struct). Caller iterates + sums for the global
    /// dashboard KPI; the per-server map is also available for a
    /// «which server is busy» breakdown.
    pub async fn all_servers_live_activity(
        &self,
        since_hours: u32,
    ) -> Result<Vec<(ServerId, ServerLiveActivity)>> {
        // Returns a Vec keyed by ServerId — Vec rather than
        // HashMap/BTreeMap because the dashboard renderer iterates
        // in insertion order anyway, and the `SELECT … ORDER BY id`
        // below pre-sorts the keys alphabetically, so a Vec is the
        // simplest container that preserves that order at the
        // render site.
        let server_ids = sqlx::query("SELECT id FROM servers ORDER BY id")
            .fetch_all(&self.pool)
            .await?;
        let mut out = Vec::with_capacity(server_ids.len());
        for r in server_ids {
            let id: String = r.try_get("id")?;
            let sid = ServerId(id);
            let activity = self.server_live_activity(&sid, since_hours).await?;
            out.push((sid, activity));
        }
        Ok(out)
    }

    /// Drop rows older than `days`. Mirrors `purge_sub_access_older_than`
    /// — chunk 3 will wire this into the existing retention scheduler.
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

    // ──────────────────────────────────────────────────────────────────
    // Phase 5a-1 — daily per-user rollups for long-term retention.
    //
    // `vpn_connection_stats` is rolling 30-day raw 5-min ticks.
    // `vpn_user_daily` is the daily aggregate that lives indefinitely
    // (one row per (user, server, date), ~36k rows/year at 33 users
    // × 3 servers = trivial SQLite scale).
    //
    // Rollup pattern: each call to `rollup_vpn_user_daily` re-computes
    // the totals for ONE date from `vpn_connection_stats` rows in that
    // date's window and UPSERT-overwrites the matching `vpn_user_daily`
    // rows. Idempotent — running it twice on the same date yields the
    // same data. The hourly rollup scheduler (in `daemon/src/app.rs`)
    // re-rolls TODAY + YESTERDAY each tick so we capture late-arriving
    // ticks across midnight UTC.
    // ──────────────────────────────────────────────────────────────────

    /// Re-compute and UPSERT all `(user, server)` daily rollup rows
    /// for `date_utc` (format `YYYY-MM-DD`). Reads from
    /// `vpn_connection_stats` where `user_id IS NOT NULL` AND the
    /// ts falls within the date's 00:00–24:00 UTC window. Returns
    /// the number of UPSERTed rows.
    ///
    /// Safe to call concurrently for different dates; same-date
    /// concurrent calls race on the UPSERT but the last writer wins
    /// idempotently (deterministic sum).
    pub async fn rollup_vpn_user_daily(&self, date_utc: &str) -> Result<u64> {
        // Derive the 24h window from the date string. SQLite's
        // strftime returns `YYYY-MM-DDTHH:MM:SS.fffZ` form — match
        // that to `ts` shape used by `vpn_connection_stats` rows.
        let lower = format!("{date_utc}T00:00:00.000Z");
        let upper = format!("{date_utc}T23:59:59.999Z");

        // Aggregate raw ticks into per-(user, server) sums. Server-
        // wide rows (user_id IS NULL) are excluded — they belong
        // to a future server-wide rollup if/when we add one.
        let rows = sqlx::query(
            "SELECT
                user_id,
                server_id,
                COALESCE(SUM(upload_bytes), 0)        AS up_total,
                COALESCE(SUM(download_bytes), 0)      AS dn_total,
                COALESCE(MAX(active_connections), 0)  AS peak_conns
             FROM vpn_connection_stats
             WHERE user_id IS NOT NULL
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
            // distinct_source_ips currently not derivable from
            // vpn_connection_stats (which doesn't carry source IP)
            // — left at 0 for now. Phase 5b's destinations table
            // is where source-IP-diversity lives.
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

    /// Daily rollup rows for ONE user across the last N days.
    /// Newest-first. Used by the user-detail analytics section.
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

    /// Top-N users by daily-total traffic across `days`. Used by
    /// the dashboard «Heavy users» tile (now actually populated
    /// post-Phase-4e+5a-1, where the old `top_users_by_traffic`
    /// returned empty because of NM-11). Sums upload+download
    /// across all servers per user.
    pub async fn top_users_by_daily_traffic(
        &self,
        days: u32,
        limit: u32,
    ) -> Result<Vec<HeavyUser>> {
        let cutoff = format!("-{} days", days.saturating_sub(1));
        // Weight each daily row by its server's `usage_coefficient`
        // before the per-user sum, mirroring the raw-tick path so the
        // heavy-users ranking is consistent whichever table feeds it.
        // REAL product is CAST back to INTEGER (bytes, i64). 1.0/NULL
        // is the identity.
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

    /// Month-to-date total for one user across all servers. Used
    /// for traffic-limit alerts (`users.monthly_bandwidth_limit_bytes`).
    /// Post-Phase-5a-1 this replaces the old NULL-returning
    /// `user_traffic_this_month` for production use.
    pub async fn user_traffic_this_month_from_daily(&self, id: &UserId) -> Result<u64> {
        let row = sqlx::query(
            "SELECT COALESCE(SUM(upload_bytes + download_bytes), 0) AS total
             FROM vpn_user_daily
             WHERE user_id = ?1
               AND date >= strftime('%Y-%m-01', 'now')",
        )
        .bind(&id.0)
        .fetch_one(&self.pool)
        .await?;
        let total: i64 = row.try_get("total")?;
        Ok(total.max(0) as u64)
    }
}
