use sqlx::Row;
use vpnctl_core::{ServerId, UserId};

use crate::sqlite::base::SqliteInventory;
use crate::sqlite::models::{HeavyUser, Result, SqliteInventoryError};

impl SqliteInventory {
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
    /// has been recorded this month — never errors on \"no rows\".
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
        // integer division would truncate to 0 for \"5% of 100GB
        // = 5_000_000_000_000 / 100\" before SQLite-3.45's bigint
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
    /// server-detail \"heaviest users on this node\" card. `user_id IS
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
    /// Backs the user-detail \"where this user's traffic lands\" card.
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
}
