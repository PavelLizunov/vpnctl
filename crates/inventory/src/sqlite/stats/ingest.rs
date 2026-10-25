use std::collections::HashSet;

use chrono::{DateTime, Utc};
use sqlx::{Row, Sqlite, Transaction};
use vpnctl_core::{ServerId, UserId};

use crate::sqlite::base::SqliteInventory;
use crate::sqlite::models::{
    Result, SqliteInventoryError, VpnCumulativeTick, VpnStatsDelta, VpnStatsRow,
};

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

fn sqlite_counter(value: u64, field: &str) -> Result<i64> {
    i64::try_from(value)
        .map_err(|_| SqliteInventoryError::Invalid(format!("{field} exceeds SQLite INTEGER range")))
}

fn cumulative_delta(prior: u64, current: u64) -> u64 {
    if current < prior {
        current
    } else {
        current - prior
    }
}

fn stored_counter(row: &sqlx::sqlite::SqliteRow, field: &str) -> Result<u64> {
    let value: i64 = row.try_get(field)?;
    u64::try_from(value)
        .map_err(|_| SqliteInventoryError::Invalid(format!("negative {field} baseline")))
}

fn reconciled_remainder(
    server: u64,
    users: u64,
    prior_pending: u64,
    prior_ahead: u64,
) -> (u64, u64, u64) {
    fn consume(primary: &mut u64, secondary: &mut u64, amount: u64) -> u64 {
        let from_primary = amount.min(*primary);
        *primary -= from_primary;
        let remaining = amount - from_primary;
        let from_secondary = remaining.min(*secondary);
        *secondary -= from_secondary;
        remaining - from_secondary
    }

    let mut new = server;
    let mut old = prior_pending;
    let unpaid_ahead = consume(&mut new, &mut old, prior_ahead);
    let users_ahead = consume(&mut old, &mut new, users);
    (old, new, unpaid_ahead.saturating_add(users_ahead))
}

async fn persist_stats_rows(
    tx: &mut Transaction<'_, Sqlite>,
    server_id: &ServerId,
    deltas: &[VpnStatsDelta],
) -> Result<()> {
    for delta in deltas {
        sqlx::query(
            "INSERT INTO vpn_connection_stats
             (ts, server_id, user_id, upload_bytes, download_bytes, active_connections)
             VALUES (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), ?1, ?2, ?3, ?4, ?5)",
        )
        .bind(&server_id.0)
        .bind(delta.user_id.as_ref().map(|user| user.0.as_str()))
        .bind(i64::try_from(delta.upload_bytes).unwrap_or(i64::MAX))
        .bind(i64::try_from(delta.download_bytes).unwrap_or(i64::MAX))
        .bind(i64::from(delta.active_connections))
        .execute(&mut **tx)
        .await?;
    }
    if deltas.is_empty() {
        return Ok(());
    }

    let rollup_up = deltas
        .iter()
        .fold(0u64, |sum, delta| sum.saturating_add(delta.upload_bytes));
    let rollup_down = deltas
        .iter()
        .fold(0u64, |sum, delta| sum.saturating_add(delta.download_bytes));
    let peak_connections = deltas
        .iter()
        .map(|delta| delta.active_connections)
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
    .execute(&mut **tx)
    .await?;
    Ok(())
}

impl SqliteInventory {
    pub async fn record_vpn_stats(
        &self,
        server_id: &ServerId,
        deltas: &[VpnStatsDelta],
    ) -> Result<()> {
        if deltas.is_empty() {
            return Ok(());
        }
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        persist_stats_rows(&mut tx, server_id, deltas).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn record_vpn_cumulative_stats(
        &self,
        server_id: &ServerId,
        tick: &VpnCumulativeTick,
    ) -> Result<u64> {
        let server_upload = sqlite_counter(tick.server_upload_total, "server_upload_total")?;
        let server_download = sqlite_counter(tick.server_download_total, "server_download_total")?;
        let uptime_seconds = sqlite_counter(tick.uptime_seconds, "uptime_seconds")?;
        let mut seen = HashSet::with_capacity(tick.users.len());
        let mut users = Vec::with_capacity(tick.users.len());
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        for counter in &tick.users {
            if !seen.insert(counter.user_id.0.as_str()) {
                return Err(SqliteInventoryError::Invalid(
                    "duplicate cumulative user counter".into(),
                ));
            }
            let known: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id = ?1)")
                    .bind(&counter.user_id.0)
                    .fetch_one(&mut *tx)
                    .await?;
            if !known {
                continue;
            }
            users.push((
                counter,
                sqlite_counter(counter.upload_total, "user upload_total")?,
                sqlite_counter(counter.download_total, "user download_total")?,
            ));
        }

        let observed_at: i64 = sqlx::query_scalar("SELECT unixepoch()")
            .fetch_one(&mut *tx)
            .await?;
        let prior_server = sqlx::query(
            "SELECT upload_total, download_total, uptime_seconds, observed_at, generation,
                    upload_ahead, download_ahead, upload_pending, download_pending
             FROM vpn_server_counter_baselines WHERE server_id = ?1",
        )
        .bind(&server_id.0)
        .fetch_optional(&mut *tx)
        .await?;

        let Some(prior_server) = prior_server else {
            sqlx::query(
                "INSERT INTO vpn_server_counter_baselines
                 (server_id, upload_total, download_total, uptime_seconds, observed_at, generation)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )
            .bind(&server_id.0)
            .bind(server_upload)
            .bind(server_download)
            .bind(uptime_seconds)
            .bind(observed_at)
            .bind(&tick.generation)
            .execute(&mut *tx)
            .await?;
            for (counter, upload, download) in &users {
                sqlx::query(
                    "INSERT INTO vpn_user_counter_baselines
                     (server_id, user_id, upload_total, download_total)
                     VALUES (?1, ?2, ?3, ?4)",
                )
                .bind(&server_id.0)
                .bind(&counter.user_id.0)
                .bind(upload)
                .bind(download)
                .execute(&mut *tx)
                .await?;
            }
            tx.commit().await?;
            return Ok(0);
        };

        let prior_server_upload = stored_counter(&prior_server, "upload_total")?;
        let prior_server_download = stored_counter(&prior_server, "download_total")?;
        let prior_uptime = stored_counter(&prior_server, "uptime_seconds")?;
        let prior_observed_at = stored_counter(&prior_server, "observed_at")?;
        let prior_upload_ahead = stored_counter(&prior_server, "upload_ahead")?;
        let prior_download_ahead = stored_counter(&prior_server, "download_ahead")?;
        let prior_upload_pending = stored_counter(&prior_server, "upload_pending")?;
        let prior_download_pending = stored_counter(&prior_server, "download_pending")?;
        let observed_at_u64 = u64::try_from(observed_at).map_err(|_| {
            SqliteInventoryError::Invalid("negative cumulative observation timestamp".into())
        })?;
        let elapsed = observed_at_u64.saturating_sub(prior_observed_at);
        let expected_uptime = prior_uptime.saturating_add(elapsed);
        let prior_generation: Option<String> = prior_server.try_get("generation")?;
        let restarted = match (prior_generation.as_deref(), tick.generation.as_deref()) {
            (Some(prior), Some(current)) => prior != current,
            _ => {
                tick.uptime_seconds < prior_uptime
                    || (tick.uptime_seconds.saturating_add(10) < expected_uptime
                        && (tick.server_upload_total < prior_server_upload
                            || tick.server_download_total < prior_server_download))
            }
        };
        let server_upload_delta = if restarted {
            tick.server_upload_total
        } else {
            cumulative_delta(prior_server_upload, tick.server_upload_total)
        };
        let server_download_delta = if restarted {
            tick.server_download_total
        } else {
            cumulative_delta(prior_server_download, tick.server_download_total)
        };

        let mut deltas = Vec::with_capacity(users.len().saturating_add(1));
        let mut attributed_upload = 0u64;
        let mut attributed_download = 0u64;
        for (counter, upload, download) in &users {
            let prior_user = sqlx::query(
                "SELECT upload_total, download_total
                 FROM vpn_user_counter_baselines
                 WHERE server_id = ?1 AND user_id = ?2",
            )
            .bind(&server_id.0)
            .bind(&counter.user_id.0)
            .fetch_optional(&mut *tx)
            .await?;
            if let Some(prior_user) = prior_user {
                let prior_upload = stored_counter(&prior_user, "upload_total")?;
                let prior_download = stored_counter(&prior_user, "download_total")?;
                let upload_delta = if restarted {
                    counter.upload_total
                } else {
                    cumulative_delta(prior_upload, counter.upload_total)
                };
                let download_delta = if restarted {
                    counter.download_total
                } else {
                    cumulative_delta(prior_download, counter.download_total)
                };
                attributed_upload = attributed_upload.saturating_add(upload_delta);
                attributed_download = attributed_download.saturating_add(download_delta);
                if upload_delta > 0 || download_delta > 0 {
                    deltas.push(VpnStatsDelta {
                        user_id: Some(counter.user_id.clone()),
                        upload_bytes: upload_delta,
                        download_bytes: download_delta,
                        active_connections: 0,
                    });
                }
            }
            sqlx::query(
                "INSERT INTO vpn_user_counter_baselines
                 (server_id, user_id, upload_total, download_total)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(server_id, user_id) DO UPDATE SET
                    upload_total = excluded.upload_total,
                    download_total = excluded.download_total",
            )
            .bind(&server_id.0)
            .bind(&counter.user_id.0)
            .bind(upload)
            .bind(download)
            .execute(&mut *tx)
            .await?;
        }

        let (mut remainder_upload, upload_pending, upload_ahead) = reconciled_remainder(
            server_upload_delta,
            attributed_upload,
            if restarted { 0 } else { prior_upload_pending },
            if restarted { 0 } else { prior_upload_ahead },
        );
        let (mut remainder_download, download_pending, download_ahead) = reconciled_remainder(
            server_download_delta,
            attributed_download,
            if restarted { 0 } else { prior_download_pending },
            if restarted { 0 } else { prior_download_ahead },
        );
        if restarted {
            remainder_upload = remainder_upload
                .checked_add(prior_upload_pending)
                .ok_or_else(|| SqliteInventoryError::Invalid("upload remainder overflow".into()))?;
            remainder_download = remainder_download
                .checked_add(prior_download_pending)
                .ok_or_else(|| {
                    SqliteInventoryError::Invalid("download remainder overflow".into())
                })?;
        }
        let upload_ahead = sqlite_counter(upload_ahead, "upload_ahead")?;
        let download_ahead = sqlite_counter(download_ahead, "download_ahead")?;
        let upload_pending = sqlite_counter(upload_pending, "upload_pending")?;
        let download_pending = sqlite_counter(download_pending, "download_pending")?;
        sqlite_counter(remainder_upload, "upload remainder")?;
        sqlite_counter(remainder_download, "download remainder")?;
        if remainder_upload > 0 || remainder_download > 0 {
            deltas.push(VpnStatsDelta {
                user_id: None,
                upload_bytes: remainder_upload,
                download_bytes: remainder_download,
                active_connections: tick.active_connections,
            });
        }
        persist_stats_rows(&mut tx, server_id, &deltas).await?;
        sqlx::query(
            "UPDATE vpn_server_counter_baselines
             SET upload_total = ?2, download_total = ?3, uptime_seconds = ?4,
                 observed_at = ?5, upload_ahead = ?6, download_ahead = ?7,
                 upload_pending = ?8, download_pending = ?9, generation = ?10
             WHERE server_id = ?1",
        )
        .bind(&server_id.0)
        .bind(server_upload)
        .bind(server_download)
        .bind(uptime_seconds)
        .bind(observed_at)
        .bind(upload_ahead)
        .bind(download_ahead)
        .bind(upload_pending)
        .bind(download_pending)
        .bind(&tick.generation)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(u64::try_from(deltas.len()).unwrap_or(u64::MAX))
    }

    // u32::MAX selects all retained history, including daily rows after raw purge.
    pub async fn recent_vpn_stats_for_user(
        &self,
        user_id: &UserId,
        since_hours: u32,
    ) -> Result<Vec<VpnStatsRow>> {
        let cutoff = (since_hours != u32::MAX).then(|| format!("-{since_hours} hours"));
        let rows = sqlx::query(
            "SELECT ts, server_id, user_id, upload_bytes, download_bytes, active_connections
             FROM vpn_connection_stats
             WHERE user_id = ?1
               AND ts > CASE WHEN ?2 IS NULL THEN ''
                             ELSE strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2) END
             UNION ALL
             SELECT d.date || 'T00:00:00.000Z' AS ts, d.server_id, d.user_id,
                    d.upload_bytes, d.download_bytes, d.active_connections_peak AS active_connections
             FROM vpn_user_daily d
             WHERE d.user_id = ?1 AND ?2 IS NULL
               AND NOT EXISTS (
                   SELECT 1 FROM vpn_connection_stats s
                   WHERE s.user_id = d.user_id AND s.server_id = d.server_id
                     AND s.ts >= d.date || 'T00:00:00.000Z'
                     AND s.ts < date(d.date, '+1 day') || 'T00:00:00.000Z'
               )
             ORDER BY ts DESC",
        )
        .bind(&user_id.0)
        .bind(cutoff)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_vpn_stats).collect()
    }

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

    pub async fn recent_vpn_stats_fleet(
        &self,
        since_hours: u32,
        bucket_hours: u32,
    ) -> Result<Vec<VpnStatsRow>> {
        let bucket_seconds = i64::from(bucket_hours)
            .checked_mul(3600)
            .filter(|seconds| *seconds > 0)
            .ok_or_else(|| SqliteInventoryError::Invalid("bucket_hours must be > 0".into()))?;
        let cutoff = (since_hours != u32::MAX).then(|| format!("-{since_hours} hours"));
        let rows = sqlx::query(
            "SELECT
                MAX(last_sample_ts) AS ts,
                server_id,
                NULL AS user_id,
                COALESCE(SUM(upload_bytes), 0) AS upload_bytes,
                COALESCE(SUM(download_bytes), 0) AS download_bytes,
                COALESCE(MAX(active_connections_peak), 0) AS active_connections
             FROM vpn_server_hourly
             WHERE hour >= CASE WHEN ?1 IS NULL THEN ''
                                ELSE strftime('%Y-%m-%dT%H:00:00.000Z', 'now', ?1) END
             GROUP BY CAST(strftime('%s', hour) AS INTEGER) / ?2, server_id
             ORDER BY ts DESC, server_id",
        )
        .bind(cutoff)
        .bind(bucket_seconds)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_vpn_stats).collect()
    }
}
