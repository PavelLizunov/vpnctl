use std::str::FromStr;

use chrono::{DateTime, Utc};
use sqlx::Row;
use vpnctl_core::ServerId;

use crate::assurance::{AssuranceStage, AssuranceState, ProtocolAssuranceSample};
use crate::sqlite::SqliteInventory;
use crate::sqlite::models::{Result, SqliteInventoryError};

impl SqliteInventory {
    pub async fn record_protocol_assurance_sample(
        &self,
        sample: &ProtocolAssuranceSample,
    ) -> Result<()> {
        let latency_ms = sample
            .latency_ms
            .map(|value| i64::try_from(value).unwrap_or(i64::MAX));
        sqlx::query(
            "INSERT INTO protocol_assurance_samples
             (ts, server_id, protocol_id, client_kind, stage, state, latency_ms, failure_code)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )
        .bind(
            sample
                .ts
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        )
        .bind(&sample.server_id.0)
        .bind(&sample.protocol_id.0)
        .bind(&sample.client_kind)
        .bind(sample.stage.as_str())
        .bind(sample.state.as_str())
        .bind(latency_ms)
        .bind(sample.failure_code.as_deref())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn latest_protocol_assurance_for_server(
        &self,
        server_id: &ServerId,
    ) -> Result<Vec<ProtocolAssuranceSample>> {
        let rows = sqlx::query(
            "WITH ranked AS (
                 SELECT ts, server_id, protocol_id, client_kind, stage, state,
                        latency_ms, failure_code,
                        ROW_NUMBER() OVER (PARTITION BY server_id, protocol_id ORDER BY id DESC) AS rn
                 FROM protocol_assurance_samples
                 WHERE server_id = ?1
             )
             SELECT ts, server_id, protocol_id, client_kind, stage, state,
                    latency_ms, failure_code
             FROM ranked WHERE rn = 1
             ORDER BY protocol_id",
        )
        .bind(&server_id.0)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(row_to_sample).collect()
    }

    pub async fn consecutive_protocol_assurance_failures(
        &self,
        server_id: &ServerId,
        protocol_id: &vpnctl_core::ProtocolId,
        limit: u32,
    ) -> Result<u32> {
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT state FROM protocol_assurance_samples
             WHERE server_id = ?1 AND protocol_id = ?2
             ORDER BY id DESC LIMIT ?3",
        )
        .bind(&server_id.0)
        .bind(&protocol_id.0)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .iter()
            .take_while(|state| matches!(state.as_str(), "blocked" | "degraded"))
            .count() as u32)
    }

    pub async fn purge_protocol_assurance_older_than(&self, days: u32) -> Result<u64> {
        let result = sqlx::query(
            "DELETE FROM protocol_assurance_samples
             WHERE ts < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1)",
        )
        .bind(format!("-{days} days"))
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }
}

fn row_to_sample(row: &sqlx::sqlite::SqliteRow) -> Result<ProtocolAssuranceSample> {
    let ts: String = row.try_get("ts")?;
    let stage: String = row.try_get("stage")?;
    let state: String = row.try_get("state")?;
    let latency: Option<i64> = row.try_get("latency_ms")?;
    Ok(ProtocolAssuranceSample {
        ts: DateTime::parse_from_rfc3339(&ts)
            .map_err(|error| {
                SqliteInventoryError::Invalid(format!("invalid assurance ts: {error}"))
            })?
            .with_timezone(&Utc),
        server_id: ServerId(row.try_get("server_id")?),
        protocol_id: vpnctl_core::ProtocolId(row.try_get("protocol_id")?),
        client_kind: row.try_get("client_kind")?,
        stage: AssuranceStage::from_str(&stage).map_err(SqliteInventoryError::Invalid)?,
        state: AssuranceState::from_str(&state).map_err(SqliteInventoryError::Invalid)?,
        latency_ms: latency.map(|value| value.max(0) as u64),
        failure_code: row.try_get("failure_code")?,
    })
}
