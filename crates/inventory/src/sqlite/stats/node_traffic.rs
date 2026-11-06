use std::collections::BTreeSet;

use chrono::{DateTime, Datelike, Months, NaiveDate, Utc};
use sqlx::Row;
use vpnctl_core::ServerId;

use crate::sqlite::{
    NodeNicDelta, NodeNicUsage, Result, ServerTrafficLimit, SqliteInventory, SqliteInventoryError,
};

const MAX_WINDOW_SECONDS: i64 = 40 * 86_400;
const MAX_SAMPLES: usize = 100_000;

fn invalid(message: &str) -> SqliteInventoryError {
    SqliteInventoryError::Invalid(message.to_string())
}

pub fn server_traffic_period(now: i64, reset_day: u8) -> Result<(i64, i64)> {
    if !(1..=31).contains(&reset_day) {
        return Err(invalid("traffic reset day must be 1..31"));
    }
    let now = DateTime::<Utc>::from_timestamp(now, 0)
        .ok_or_else(|| invalid("invalid traffic period timestamp"))?;
    let month = NaiveDate::from_ymd_opt(now.year(), now.month(), 1)
        .ok_or_else(|| invalid("invalid traffic period month"))?;
    let anchor = |month: NaiveDate| -> Result<i64> {
        let last = month
            .checked_add_months(Months::new(1))
            .and_then(|date| date.pred_opt())
            .ok_or_else(|| invalid("traffic period outside calendar range"))?;
        let date = month
            .with_day(u32::from(reset_day).min(last.day()))
            .and_then(|date| date.and_hms_opt(0, 0, 0))
            .ok_or_else(|| invalid("invalid traffic reset date"))?;
        Ok(date.and_utc().timestamp())
    };
    let start_month = if now.timestamp() >= anchor(month)? {
        month
    } else {
        month
            .checked_sub_months(Months::new(1))
            .ok_or_else(|| invalid("traffic period outside calendar range"))?
    };
    let end_month = start_month
        .checked_add_months(Months::new(1))
        .ok_or_else(|| invalid("traffic period outside calendar range"))?;
    Ok((anchor(start_month)?, anchor(end_month)?))
}

fn limit_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<ServerTrafficLimit> {
    Ok(ServerTrafficLimit {
        limit_bytes: row
            .try_get::<i64, _>("limit_bytes")?
            .try_into()
            .map_err(|_| invalid("negative traffic limit"))?,
        direction: row.try_get("direction")?,
        reset_day: row
            .try_get::<i64, _>("reset_day")?
            .try_into()
            .map_err(|_| invalid("invalid traffic reset day"))?,
        warning_pct: row
            .try_get::<i64, _>("warning_pct")?
            .try_into()
            .map_err(|_| invalid("invalid traffic warning percent"))?,
    })
}

impl SqliteInventory {
    pub async fn node_nic_usage(
        &self,
        sid: &ServerId,
        start: i64,
        now: i64,
        max_gap_seconds: u64,
    ) -> Result<Option<NodeNicUsage>> {
        if max_gap_seconds == 0
            || now
                .checked_sub(start)
                .is_none_or(|span| span <= 0 || span > MAX_WINDOW_SECONDS)
        {
            return Err(invalid("invalid NIC observation window"));
        }
        let lower = DateTime::<Utc>::from_timestamp(start, 0)
            .ok_or_else(|| invalid("invalid NIC window start"))?;
        DateTime::<Utc>::from_timestamp(now, 0).ok_or_else(|| invalid("invalid NIC window end"))?;
        // Use actual instants for RFC3339 offsets; malformed dates must reach
        // validation rather than disappearing from an optimistic total. The
        // server index and row bound keep retained history reads bounded.
        let rows = sqlx::query(
            "SELECT ts, nic_iface, nic_rx_bytes, nic_tx_bytes FROM node_health
             WHERE server_id = ?1 AND (julianday(ts) >= julianday(?2) OR julianday(ts) IS NULL)
             ORDER BY sample_seq LIMIT 100001",
        )
        .bind(&sid.0)
        .bind(lower.to_rfc3339())
        .fetch_all(&self.pool)
        .await?;
        if rows.len() > MAX_SAMPLES {
            return Ok(None);
        }
        let mut readings: Vec<(DateTime<Utc>, String, u64, u64)> = Vec::new();
        let mut hours = BTreeSet::new();
        for row in rows {
            let Ok(ts) = row.try_get::<String, _>("ts") else {
                return Ok(None);
            };
            let Ok(ts) = DateTime::parse_from_rfc3339(&ts) else {
                return Ok(None);
            };
            let ts = ts.with_timezone(&Utc);
            if ts.timestamp() < start {
                continue;
            }
            if ts.timestamp() > now {
                return Ok(None);
            }
            let (Ok(rx), Ok(tx)) = (
                row.try_get::<Option<i64>, _>("nic_rx_bytes"),
                row.try_get::<Option<i64>, _>("nic_tx_bytes"),
            ) else {
                return Ok(None);
            };
            if rx.is_none() && tx.is_none() {
                continue;
            }
            let (Some(rx), Some(tx)) = (rx, tx) else {
                return Ok(None);
            };
            let (Ok(rx), Ok(tx)) = (u64::try_from(rx), u64::try_from(tx)) else {
                return Ok(None);
            };
            let Ok(Some(iface)) = row.try_get::<Option<String>, _>("nic_iface") else {
                return Ok(None);
            };
            if iface.trim().is_empty() {
                return Ok(None);
            }
            if readings
                .last()
                .is_some_and(|(previous, _, _, _)| ts < *previous)
            {
                return Ok(None);
            }
            hours.insert(ts.timestamp().div_euclid(3600));
            readings.push((ts, iface, rx, tx));
        }
        if readings.len() < 2 {
            return Ok(None);
        }
        let mut rx_bytes = 0u64;
        let mut tx_bytes = 0u64;
        let mut interrupted = false;
        let mut deltas = Vec::with_capacity(readings.len() - 1);
        for pair in readings.windows(2) {
            let (previous, current) = (&pair[0], &pair[1]);
            if current.0.timestamp().saturating_sub(previous.0.timestamp()) as u64 > max_gap_seconds
            {
                interrupted = true;
            }
            if previous.1 != current.1 {
                interrupted = true;
                deltas.push(NodeNicDelta {
                    ts: current.0,
                    rx_bytes: 0,
                    tx_bytes: 0,
                });
                continue;
            }
            interrupted |= current.2 < previous.2 || current.3 < previous.3;
            let (rx, tx) = crate::sum_nic_deltas(&[
                (previous.1.clone(), previous.2, previous.3),
                (current.1.clone(), current.2, current.3),
            ]);
            deltas.push(NodeNicDelta {
                ts: current.0,
                rx_bytes: rx,
                tx_bytes: tx,
            });
            let (Some(rx), Some(tx)) = (rx_bytes.checked_add(rx), tx_bytes.checked_add(tx)) else {
                return Ok(None);
            };
            rx_bytes = rx;
            tx_bytes = tx;
        }
        let Some(total_bytes) = rx_bytes.checked_add(tx_bytes) else {
            return Ok(None);
        };
        let first_sample_ts = readings[0].0;
        let last_sample_ts = readings[readings.len() - 1].0;
        Ok(Some(NodeNicUsage {
            deltas,
            rx_bytes,
            tx_bytes,
            total_bytes,
            samples: readings.len(),
            observed_hours: hours.len(),
            first_sample_ts,
            last_sample_ts,
            interrupted,
            complete: !interrupted
                && first_sample_ts.timestamp().saturating_sub(start) as u64 <= max_gap_seconds
                && now.saturating_sub(last_sample_ts.timestamp()) as u64 <= max_gap_seconds,
        }))
    }

    pub async fn get_server_traffic_limit(
        &self,
        sid: &ServerId,
    ) -> Result<Option<ServerTrafficLimit>> {
        sqlx::query("SELECT limit_bytes, direction, reset_day, warning_pct FROM server_traffic_limits WHERE server_id=?1")
            .bind(&sid.0).fetch_optional(&self.pool).await?.as_ref().map(limit_from_row).transpose()
    }

    pub async fn set_server_traffic_limit(
        &self,
        sid: &ServerId,
        limit: Option<&ServerTrafficLimit>,
        actor: &str,
    ) -> Result<bool> {
        if let Some(value) = limit
            && (value.limit_bytes == 0
                || value.limit_bytes > i64::MAX as u64
                || !matches!(value.direction.as_str(), "rx" | "tx" | "both")
                || !(1..=31).contains(&value.reset_day)
                || !(1..=100).contains(&value.warning_pct))
        {
            return Err(invalid("invalid server traffic limit"));
        }
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM servers WHERE id=?1)")
            .bind(&sid.0)
            .fetch_one(&mut *tx)
            .await?;
        if !exists {
            return Err(invalid("no such server for traffic limit"));
        }
        let old = sqlx::query("SELECT limit_bytes, direction, reset_day, warning_pct FROM server_traffic_limits WHERE server_id=?1")
            .bind(&sid.0).fetch_optional(&mut *tx).await?.as_ref().map(limit_from_row).transpose()?;
        if old.as_ref() == limit {
            tx.commit().await?;
            return Ok(false);
        }
        if let Some(value) = limit {
            sqlx::query("INSERT INTO server_traffic_limits(server_id,limit_bytes,direction,reset_day,warning_pct)
                VALUES(?1,?2,?3,?4,?5) ON CONFLICT(server_id) DO UPDATE SET limit_bytes=excluded.limit_bytes,
                direction=excluded.direction,reset_day=excluded.reset_day,warning_pct=excluded.warning_pct")
                .bind(&sid.0).bind(value.limit_bytes as i64).bind(&value.direction)
                .bind(i64::from(value.reset_day)).bind(i64::from(value.warning_pct))
                .execute(&mut *tx).await?;
        } else {
            sqlx::query("DELETE FROM server_traffic_limits WHERE server_id=?1")
                .bind(&sid.0)
                .execute(&mut *tx)
                .await?;
        }
        let payload = serde_json::to_string(&serde_json::json!({"before":old,"after":limit}))?;
        sqlx::query("INSERT INTO audit_log(actor,action,target,payload) VALUES(?1,'server.traffic_limit.set',?2,?3)")
            .bind(actor).bind(&sid.0).bind(payload).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(true)
    }
}
