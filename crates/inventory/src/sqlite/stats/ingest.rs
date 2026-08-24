use chrono::{DateTime, Utc};
use sqlx::Row;
use vpnctl_core::{ServerId, UserId};

use crate::sqlite::base::SqliteInventory;
use crate::sqlite::models::{Result, SqliteInventoryError, VpnStatsDelta, VpnStatsRow};

// Owned row argument is what `.into_iter().map(...)` over `Vec<SqliteRow>`
// gives us; taking by reference would force a `.collect()` round-trip.
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
}
