use super::*;
use crate::{ServicePathIncident, ServicePathState, ServicePathStatus, ServiceQualitySample};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Row, Sqlite, Transaction};
use vpnctl_core::ServerId;

#[derive(Serialize, Deserialize)]
struct StoredPath {
    current: ServicePathState,
    failures: u32,
    successes: u32,
    incident: Option<ServicePathIncident>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Round {
    Success,
    Partial,
    Failure,
    Unknown,
}

fn freshness_window(seconds: u64) -> chrono::Duration {
    chrono::Duration::seconds(
        i64::try_from(seconds)
            .unwrap_or(i64::MAX / 1000)
            .min(i64::MAX / 1000),
    )
}

fn classify(sample: &ServiceQualitySample) -> Result<Round> {
    if sample.available_targets > sample.target_count
        || sample.successes > sample.attempts
        || sample.control_successes > sample.control_attempts
        || matches!((sample.icmp_successes, sample.icmp_attempts), (Some(successes), Some(attempts)) if successes > attempts)
        || (sample.icmp_successes.is_some() != sample.icmp_attempts.is_some())
    {
        return Err(SqliteInventoryError::Invalid(
            "invalid path sample counts".into(),
        ));
    }
    if sample.target_count == 0 || sample.attempts == 0 {
        return Ok(Round::Unknown);
    }
    Ok(if sample.successes == 0 {
        Round::Failure
    } else if sample.successes == sample.attempts && sample.available_targets == sample.target_count
    {
        Round::Success
    } else {
        Round::Partial
    })
}

impl SqliteInventory {
    pub async fn record_service_path(
        &self,
        sample: &ServiceQualitySample,
        target_identity: &str,
        max_gap_secs: u64,
    ) -> Result<()> {
        if target_identity.trim().is_empty()
            || sample.vantage.trim().is_empty()
            || max_gap_secs == 0
            || sample.ts > Utc::now()
        {
            return Err(SqliteInventoryError::Invalid(
                "invalid path observation".into(),
            ));
        }
        let round = classify(sample)?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let previous: Option<String> = sqlx::query_scalar(
            "SELECT state_json FROM service_path_states WHERE server_id = ?1 AND target_identity = ?2",
        )
        .bind(&sample.server_id.0)
        .bind(target_identity)
        .fetch_optional(&mut *tx)
        .await?;
        let existed = previous.is_some();
        let mut stored = match previous {
            Some(json) => serde_json::from_str::<StoredPath>(&json)?,
            None => StoredPath {
                current: ServicePathState {
                    status: ServicePathStatus::Unknown,
                    vantage: sample.vantage.clone(),
                    checked_at: DateTime::<Utc>::MIN_UTC,
                    last_success_at: None,
                },
                failures: 0,
                successes: 0,
                incident: None,
            },
        };
        if existed && sample.ts <= stored.current.checked_at {
            return Ok(());
        }
        let old_status = stored.current.status;
        if sample.ts.signed_duration_since(stored.current.checked_at)
            > freshness_window(max_gap_secs)
        {
            stored.failures = 0;
            stored.successes = 0;
            if stored.incident.is_none() {
                stored.current.last_success_at = None;
            }
            if let Some(incident) = stored.incident.as_mut() {
                incident.first_recovery_at = None;
            }
        }
        stored.current.checked_at = sample.ts;
        stored.current.vantage.clone_from(&sample.vantage);
        let opens = matches!(round, Round::Failure | Round::Partial) && stored.incident.is_none();
        if opens {
            let diagnostics =
                capture_diagnostics(&mut tx, sample, stored.current.last_success_at).await?;
            let mut incident = ServicePathIncident {
                id: 0,
                vantage: sample.vantage.clone(),
                last_success_at: stored.current.last_success_at,
                first_failure_at: sample.ts,
                confirmed_at: None,
                first_recovery_at: None,
                recovered_at: None,
                diagnostics,
            };
            let result = sqlx::query(
                "INSERT INTO service_path_incidents (server_id, target_identity, incident_json) VALUES (?1, ?2, '{}')",
            )
            .bind(&sample.server_id.0)
            .bind(target_identity)
            .execute(&mut *tx)
            .await?;
            incident.id = result.last_insert_rowid();
            stored.incident = Some(incident);
        }
        let mut confirmed = false;
        let mut recovered = false;
        match round {
            Round::Success => {
                stored.failures = 0;
                stored.successes = stored.successes.saturating_add(1);
                stored.current.last_success_at = Some(sample.ts);
                stored.current.status = ServicePathStatus::Available;
                if let Some(incident) = stored.incident.as_mut() {
                    incident.first_recovery_at.get_or_insert(sample.ts);
                    if stored.successes >= 2 {
                        incident.recovered_at = Some(sample.ts);
                        recovered = true;
                    } else {
                        stored.current.status = ServicePathStatus::Recovering;
                    }
                }
            }
            Round::Failure | Round::Partial => {
                stored.successes = 0;
                stored.failures = if round == Round::Failure {
                    stored.failures.saturating_add(1)
                } else {
                    0
                };
                stored.current.status = ServicePathStatus::Degraded;
                if let Some(incident) = stored.incident.as_mut() {
                    incident.first_recovery_at = None;
                    if stored.failures >= 2 && incident.confirmed_at.is_none() {
                        incident.confirmed_at = Some(sample.ts);
                        confirmed = true;
                    }
                    if round == Round::Failure && incident.confirmed_at.is_some() {
                        stored.current.status = ServicePathStatus::Unreachable;
                    }
                }
            }
            Round::Unknown => {
                stored.failures = 0;
                stored.successes = 0;
                stored.current.status = ServicePathStatus::Unknown;
                stored.current.last_success_at = None;
                if let Some(incident) = stored.incident.as_mut() {
                    incident.first_recovery_at = None;
                }
            }
        }
        if let Some(incident) = stored.incident.as_ref() {
            sqlx::query(
                "UPDATE service_path_incidents SET incident_json = ?1, open = ?2 WHERE id = ?3",
            )
            .bind(serde_json::to_string(incident)?)
            .bind(!recovered)
            .bind(incident.id)
            .execute(&mut *tx)
            .await?;
            if confirmed || (recovered && incident.confirmed_at.is_some()) {
                incident_alert(&mut tx, sample, incident, recovered).await?;
            }
        }
        if opens || confirmed || recovered || old_status != stored.current.status {
            let action = if recovered {
                "server.path.recovered"
            } else if confirmed {
                "server.path.unavailable"
            } else {
                "server.path.changed"
            };
            sqlx::query("INSERT INTO audit_log (actor, action, target, payload) VALUES ('system', ?1, ?2, ?3)")
                .bind(action)
                .bind(&sample.server_id.0)
                .bind(serde_json::json!({"status": stored.current.status, "incident_id": stored.incident.as_ref().map(|i| i.id), "checked_at": sample.ts, "vantage": sample.vantage}).to_string())
                .execute(&mut *tx)
                .await?;
        }
        if recovered {
            stored.incident = None;
        }
        sqlx::query(
            "INSERT INTO service_path_states (server_id, target_identity, checked_at, state_json) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (server_id, target_identity) DO UPDATE SET checked_at = excluded.checked_at, state_json = excluded.state_json",
        )
        .bind(&sample.server_id.0)
        .bind(target_identity)
        .bind(sample.ts.to_rfc3339())
        .bind(serde_json::to_string(&stored)?)
        .execute(&mut *tx)
        .await?;
        reconcile_tcp_suppression(&mut tx, sample, target_identity, &stored, max_gap_secs).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn current_service_path(
        &self,
        server_id: &ServerId,
        now: DateTime<Utc>,
        max_age_secs: u64,
    ) -> Result<Option<ServicePathState>> {
        let json: Option<String> = sqlx::query_scalar(
            "SELECT state_json FROM service_path_states WHERE server_id = ?1 ORDER BY julianday(checked_at) DESC, rowid DESC LIMIT 1",
        )
        .bind(&server_id.0)
        .fetch_optional(&self.pool)
        .await?;
        let Some(json) = json else { return Ok(None) };
        let mut state = serde_json::from_str::<StoredPath>(&json)?.current;
        let age = now.signed_duration_since(state.checked_at);
        if age < chrono::Duration::zero() || age > freshness_window(max_age_secs) {
            state.status = ServicePathStatus::Unknown;
        }
        Ok(Some(state))
    }

    pub async fn service_path_incidents(
        &self,
        server_id: &ServerId,
        limit: i64,
    ) -> Result<Vec<ServicePathIncident>> {
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT incident_json FROM service_path_incidents WHERE server_id = ?1 ORDER BY id DESC LIMIT ?2",
        )
        .bind(&server_id.0)
        .bind(limit.clamp(1, 100))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|json| Ok(serde_json::from_str(&json)?))
            .collect()
    }
}

async fn reconcile_tcp_suppression(
    tx: &mut Transaction<'_, Sqlite>,
    sample: &ServiceQualitySample,
    target_identity: &str,
    stored: &StoredPath,
    max_age_secs: u64,
) -> Result<()> {
    let age = Utc::now().signed_duration_since(sample.ts);
    if age < chrono::Duration::zero() || age > freshness_window(max_age_secs) {
        return Ok(());
    }
    let latest: String = sqlx::query_scalar(
        "SELECT target_identity FROM service_path_states WHERE server_id = ?1
         ORDER BY julianday(checked_at) DESC, rowid DESC LIMIT 1",
    )
    .bind(&sample.server_id.0)
    .fetch_one(&mut **tx)
    .await?;
    if latest != target_identity {
        return Ok(());
    }
    let enabled: bool =
        sqlx::query_scalar("SELECT auto_suppress_when_unreachable FROM servers WHERE id = ?1")
            .bind(&sample.server_id.0)
            .fetch_one(&mut **tx)
            .await?;
    if enabled {
        let suppressed = match stored.current.status {
            ServicePathStatus::Unreachable => Some(true),
            ServicePathStatus::Available if stored.successes >= 2 => Some(false),
            _ => None,
        };
        if let Some(suppressed) = suppressed {
            SqliteInventory::set_server_suppressed_on(tx, &sample.server_id, suppressed).await?;
        }
    }
    Ok(())
}

async fn incident_alert(
    tx: &mut Transaction<'_, Sqlite>,
    sample: &ServiceQualitySample,
    incident: &ServicePathIncident,
    recovered: bool,
) -> Result<()> {
    let kind = format!("server.path.unavailable.{}", incident.id);
    if recovered {
        sqlx::query("UPDATE admin_alerts SET acked_at = ?1 WHERE kind = ?2 AND acked_at IS NULL")
            .bind(sample.ts.to_rfc3339())
            .bind(&kind)
            .execute(&mut **tx)
            .await?;
    }
    let summary = if recovered {
        "TCP path recovered after two successful rounds; VPN handshake/UDP not verified"
    } else {
        "TCP VPN ports unreachable from measurement network after two failed rounds; host/UDP state separate"
    };
    let event_kind = if recovered {
        format!("server.path.recovered.{}", incident.id)
    } else {
        kind
    };
    sqlx::query("INSERT INTO admin_alerts (kind, server_id, severity, summary, payload_json, acked_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)")
        .bind(event_kind)
        .bind(&sample.server_id.0)
        .bind(if recovered { "info" } else { "warning" })
        .bind(summary)
        .bind(serde_json::json!({"incident_id": incident.id, "vantage": sample.vantage, "first_failure_at": incident.first_failure_at, "checked_at": sample.ts}).to_string())
        .bind(recovered.then(|| sample.ts.to_rfc3339()))
        .execute(&mut **tx).await?;
    Ok(())
}

async fn capture_diagnostics(
    tx: &mut Transaction<'_, Sqlite>,
    sample: &ServiceQualitySample,
    last_success: Option<DateTime<Utc>>,
) -> Result<serde_json::Value> {
    let cutoff = last_success.unwrap_or(sample.ts);
    let subtract = |minutes| {
        cutoff
            .checked_sub_signed(chrono::Duration::minutes(minutes))
            .ok_or_else(|| {
                SqliteInventoryError::Invalid("path evidence window out of range".into())
            })
    };
    let since = subtract(60)?;
    let recent = subtract(15)?;
    let rows = sqlx::query(
        "SELECT user_id,
           MAX(CASE WHEN julianday(ts) <= julianday(?2) AND active_connections > 0 THEN 1 ELSE 0 END) AS live_60m,
           MAX(CASE WHEN julianday(ts) BETWEEN julianday(?3) AND julianday(?2) AND active_connections > 0 THEN 1 ELSE 0 END) AS live_15m,
           SUM(CASE WHEN julianday(ts) BETWEEN julianday(?3) AND julianday(?2) THEN upload_bytes ELSE 0 END) AS upload_15m,
           SUM(CASE WHEN julianday(ts) BETWEEN julianday(?3) AND julianday(?2) THEN download_bytes ELSE 0 END) AS download_15m,
           SUM(CASE WHEN julianday(ts) <= julianday(?2) THEN upload_bytes ELSE 0 END) AS upload_60m,
           SUM(CASE WHEN julianday(ts) <= julianday(?2) THEN download_bytes ELSE 0 END) AS download_60m,
           MAX(CASE WHEN julianday(ts) > julianday(?2) AND active_connections > 0 THEN 1 ELSE 0 END) AS transition_live,
           SUM(CASE WHEN julianday(ts) > julianday(?2) THEN upload_bytes + download_bytes ELSE 0 END) AS transition_bytes,
           MAX(CASE WHEN active_connections > 0 THEN ts END) AS last_live_at
         FROM vpn_connection_stats
         WHERE server_id = ?1 AND user_id IS NOT NULL AND ts >= ?4 AND julianday(ts) <= julianday(?5)
         GROUP BY user_id HAVING MAX(active_connections) > 0 OR SUM(upload_bytes) + SUM(download_bytes) > 0
         ORDER BY user_id",
    )
    .bind(&sample.server_id.0).bind(cutoff.to_rfc3339()).bind(recent.to_rfc3339())
    .bind(since.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)).bind(sample.ts.to_rfc3339())
    .fetch_all(&mut **tx).await?;
    let mut users = Vec::new();
    for row in rows {
        users.push(serde_json::json!({
            "user": row.try_get::<String,_>("user_id")?,
            "live_60m": row.try_get::<i64,_>("live_60m")? != 0,
            "live_15m": row.try_get::<i64,_>("live_15m")? != 0,
            "upload_15m": row.try_get::<i64,_>("upload_15m")?,
            "download_15m": row.try_get::<i64,_>("download_15m")?,
            "upload_60m": row.try_get::<i64,_>("upload_60m")?,
            "download_60m": row.try_get::<i64,_>("download_60m")?,
            "transition_live": row.try_get::<i64,_>("transition_live")? != 0,
            "transition_bytes": row.try_get::<i64,_>("transition_bytes")?,
            "last_live_at": row.try_get::<Option<String>,_>("last_live_at")?,
        }));
    }
    let health = sqlx::query("SELECT ts, sing_box_active, kernel_versions_json FROM node_health WHERE server_id = ?1 AND julianday(ts) <= julianday(?2) ORDER BY sample_seq DESC LIMIT 1")
        .bind(&sample.server_id.0).bind(sample.ts.to_rfc3339()).fetch_optional(&mut **tx).await?;
    let node = health.map(|row| -> Result<_> {
        // Versions/active flags only: no full node configuration or addresses.
        let kernels: Option<String> = row.try_get("kernel_versions_json")?;
        Ok(serde_json::json!({"ts": row.try_get::<String,_>("ts")?, "sing_box_active": row.try_get::<Option<bool>,_>("sing_box_active")?, "kernels": kernels.and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())}))
    }).transpose()?;
    let audits = sqlx::query("SELECT ts, action FROM audit_log WHERE (target = ?1 OR json_extract(CASE WHEN json_valid(payload) THEN payload ELSE '{}' END, '$.server') = ?1) AND ts >= ?2 AND julianday(ts) <= julianday(?3) ORDER BY id DESC LIMIT 20")
        .bind(&sample.server_id.0).bind(since.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)).bind(sample.ts.to_rfc3339()).fetch_all(&mut **tx).await?;
    let changes: Vec<_> = audits.into_iter().map(|row| -> Result<_> { Ok(serde_json::json!({"ts": row.try_get::<String,_>("ts")?, "action": row.try_get::<String,_>("action")?})) }).collect::<Result<_>>()?;
    Ok(
        serde_json::json!({"cutoff_at": cutoff, "window_start": since, "captured_at": sample.ts, "users": users, "node_health": node, "recent_changes": changes, "quality_round": {"attempts": sample.attempts, "successes": sample.successes, "target_count": sample.target_count, "available_targets": sample.available_targets, "control_attempts": sample.control_attempts, "control_successes": sample.control_successes}, "scope": "Observed user streams and byte deltas; absence is not failure and presence does not identify cause or a new TLS handshake."}),
    )
}
