use super::*;
use chrono::{DateTime, Utc};
use sqlx::Row;
use vpnctl_core::ServerId;

#[allow(clippy::needless_pass_by_value)]
pub(crate) fn row_to_admin_alert(r: sqlx::sqlite::SqliteRow) -> Result<AdminAlert> {
    let created_at_s: String = r.try_get("created_at")?;
    let created_at = DateTime::parse_from_rfc3339(&created_at_s)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|e| {
            SqliteInventoryError::Invalid(format!(
                "admin_alerts.created_at malformed: {created_at_s}: {e}"
            ))
        })?;
    let acked_at_s: Option<String> = r.try_get("acked_at")?;
    let acked_at = match acked_at_s {
        Some(s) => Some(
            DateTime::parse_from_rfc3339(&s)
                .map(|d| d.with_timezone(&Utc))
                .map_err(|e| {
                    SqliteInventoryError::Invalid(format!(
                        "admin_alerts.acked_at malformed: {s}: {e}"
                    ))
                })?,
        ),
        None => None,
    };
    let server_id_s: Option<String> = r.try_get("server_id")?;
    Ok(AdminAlert {
        id: r.try_get("id")?,
        created_at,
        kind: r.try_get("kind")?,
        server_id: server_id_s.map(ServerId),
        severity: r.try_get("severity")?,
        summary: r.try_get("summary")?,
        payload_json: r.try_get("payload_json")?,
        acked_at,
    })
}

impl SqliteInventory {
    pub async fn search_alerts(&self, q: &str, limit: i64) -> Result<Vec<AdminAlert>> {
        if q.is_empty() {
            return Ok(Vec::new());
        }
        let pat = format!("%{}%", escape_like(&q.to_lowercase()));
        let rows = sqlx::query(
            "SELECT id, created_at, kind, server_id, severity, summary, payload_json, acked_at
             FROM admin_alerts
             WHERE LOWER(kind) LIKE ?1 ESCAPE '\\' OR LOWER(summary) LIKE ?1 ESCAPE '\\'
             ORDER BY id DESC
             LIMIT ?2",
        )
        .bind(&pat)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_admin_alert).collect()
    }

    pub async fn alerts_by_kind_severity(&self) -> Result<Vec<(String, String, u64)>> {
        let rows = sqlx::query(
            "SELECT kind, severity, COUNT(*) AS n
             FROM admin_alerts
             WHERE acked_at IS NULL
             GROUP BY kind, severity
             ORDER BY n DESC, kind, severity",
        )
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let kind: String = r.try_get("kind")?;
            let severity: String = r.try_get("severity")?;
            let n: i64 = r.try_get("n")?;
            out.push((kind, severity, n.max(0) as u64));
        }
        Ok(out)
    }

    pub async fn today_digest(&self) -> Result<TodayDigest> {
        let rows = sqlx::query(
            "SELECT action, COUNT(*) AS n
             FROM audit_log
             WHERE ts >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', 'start of day')
             GROUP BY action",
        )
        .fetch_all(&self.pool)
        .await?;
        let mut digest = TodayDigest::default();
        for r in rows {
            let action: String = r.try_get("action")?;
            let n: i64 = r.try_get("n")?;
            let n = n.max(0) as u64;
            if action == "user.create" {
                digest.users_added += n;
            } else if action.ends_with(".grant") || action.ends_with(".revoke") {
                digest.grants_changed += n;
            } else if action == "server.deploy" {
                digest.deploys += n;
            }
        }
        Ok(digest)
    }

    pub async fn open_alert_subjects_with_kind_prefix(&self, prefix: &str) -> Result<Vec<String>> {
        use sqlx::Row;
        let plen = i64::try_from(prefix.chars().count()).unwrap_or(0);
        let rows = sqlx::query(
            "SELECT DISTINCT substr(kind, ?1 + 1) AS subject
             FROM admin_alerts
             WHERE acked_at IS NULL AND substr(kind, 1, ?1) = ?2",
        )
        .bind(plen)
        .bind(prefix)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| r.get::<String, _>("subject"))
            .collect())
    }

    pub async fn insert_alert(
        &self,
        kind: &str,
        server_id: Option<&ServerId>,
        severity: &str,
        summary: &str,
        payload_json: Option<&str>,
    ) -> Result<i64> {
        let res = sqlx::query(
            "INSERT INTO admin_alerts (kind, server_id, severity, summary, payload_json)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(kind)
        .bind(server_id.map(|s| s.0.as_str()))
        .bind(severity)
        .bind(summary)
        .bind(payload_json)
        .execute(&self.pool)
        .await?;
        Ok(res.last_insert_rowid())
    }

    pub async fn unacked_alert_count(&self) -> Result<u64> {
        let row: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM admin_alerts WHERE acked_at IS NULL")
                .fetch_one(&self.pool)
                .await?;
        Ok(u64::try_from(row.0).unwrap_or(0))
    }

    pub async fn recent_alerts(&self, limit: i64, include_acked: bool) -> Result<Vec<AdminAlert>> {
        let where_clause = if include_acked {
            ""
        } else {
            "WHERE acked_at IS NULL"
        };
        let sql = format!(
            "SELECT id, created_at, kind, server_id, severity, summary,
                    payload_json, acked_at
             FROM admin_alerts
             {where_clause}
             ORDER BY id DESC
             LIMIT ?1"
        );
        let rows = sqlx::query(&sql).bind(limit).fetch_all(&self.pool).await?;
        rows.into_iter().map(row_to_admin_alert).collect()
    }

    pub async fn ack_alert(&self, id: i64) -> Result<bool> {
        let res = sqlx::query(
            "UPDATE admin_alerts
             SET acked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE id = ?1 AND acked_at IS NULL",
        )
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn set_alert_telegram_message_id(
        &self,
        alert_id: i64,
        message_id: &str,
    ) -> Result<()> {
        sqlx::query("UPDATE admin_alerts SET telegram_message_id = ?2 WHERE id = ?1")
            .bind(alert_id)
            .bind(message_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn latest_alert_message_id(
        &self,
        kind: &str,
        server_id: Option<&ServerId>,
    ) -> Result<Option<String>> {
        let row: Option<(Option<String>,)> = sqlx::query_as(
            "SELECT telegram_message_id FROM admin_alerts
             WHERE kind = ?1
               AND ((?2 IS NULL AND server_id IS NULL) OR server_id = ?2)
               AND telegram_message_id IS NOT NULL
             ORDER BY id DESC
             LIMIT 1",
        )
        .bind(kind)
        .bind(server_id.map(|s| s.0.as_str()))
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.and_then(|(m,)| m))
    }

    pub async fn ack_all_unacked_alerts(&self) -> Result<u64> {
        let res = sqlx::query(
            "UPDATE admin_alerts
             SET acked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE acked_at IS NULL",
        )
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    pub async fn insert_alert_if_no_unacked(
        &self,
        kind: &str,
        server_id: Option<&ServerId>,
        severity: &str,
        summary: &str,
        payload_json: Option<&str>,
    ) -> Result<Option<i64>> {
        let server_id_str = server_id.map(|s| s.0.as_str());
        let source_event: Option<String> = payload_json.and_then(|raw| {
            let val: serde_json::Value = serde_json::from_str(raw).ok()?;
            val.get("_source_event")?.as_str().map(str::to_string)
        });
        let res = sqlx::query(
            "INSERT OR IGNORE INTO admin_alerts
                 (kind, server_id, severity, summary, payload_json)
             SELECT ?1, ?2, ?3, ?4, ?5
             WHERE (?6 IS NULL OR NOT EXISTS (
                 SELECT 1 FROM admin_alerts
                 WHERE kind = ?1
                   AND ((?2 IS NULL AND server_id IS NULL) OR server_id = ?2)
                   AND CASE WHEN json_valid(payload_json) THEN json_extract(payload_json, '$._source_event') ELSE NULL END = ?6
             ))",
        )
        .bind(kind)
        .bind(server_id_str)
        .bind(severity)
        .bind(summary)
        .bind(payload_json)
        .bind(source_event.as_deref())
        .execute(&self.pool)
        .await?;
        if res.rows_affected() == 1 {
            Ok(Some(res.last_insert_rowid()))
        } else {
            Ok(None)
        }
    }

    pub async fn insert_alert_acked(
        &self,
        kind: &str,
        server_id: Option<&ServerId>,
        severity: &str,
        summary: &str,
        payload_json: Option<&str>,
    ) -> Result<i64> {
        let server_id_str = server_id.map(|s| s.0.as_str());
        let res = sqlx::query(
            "INSERT INTO admin_alerts
                 (kind, server_id, severity, summary, payload_json, acked_at)
             VALUES (?1, ?2, ?3, ?4, ?5, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
        )
        .bind(kind)
        .bind(server_id_str)
        .bind(severity)
        .bind(summary)
        .bind(payload_json)
        .execute(&self.pool)
        .await?;
        Ok(res.last_insert_rowid())
    }

    pub async fn ack_unacked_by_kind_prefix(&self, prefix: &str) -> Result<u64> {
        let res = sqlx::query(
            "UPDATE admin_alerts
             SET acked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE kind LIKE ?1 ESCAPE '\\' AND acked_at IS NULL",
        )
        .bind(format!("{}%", escape_like(prefix)))
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    pub async fn ack_open_alerts(&self, kind: &str, server_id: Option<&ServerId>) -> Result<u64> {
        let server_id_str = server_id.map(|s| s.0.as_str());
        let res = sqlx::query(
            "UPDATE admin_alerts
             SET acked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE kind = ?1
               AND ((?2 IS NULL AND server_id IS NULL) OR server_id = ?2)
               AND acked_at IS NULL",
        )
        .bind(kind)
        .bind(server_id_str)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    pub async fn has_unacked_alert(
        &self,
        kind: &str,
        server_id: Option<&ServerId>,
    ) -> Result<bool> {
        let server_id_str = server_id.map(|s| s.0.as_str());
        let row: (i64,) = sqlx::query_as(
            "SELECT EXISTS(
                 SELECT 1 FROM admin_alerts
                 WHERE kind = ?1
                   AND ((?2 IS NULL AND server_id IS NULL) OR server_id = ?2)
                   AND acked_at IS NULL
             )",
        )
        .bind(kind)
        .bind(server_id_str)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.0 != 0)
    }

    pub async fn has_condition_since_recovery(
        &self,
        condition_kind: &str,
        recovery_kind: &str,
        server_id: Option<&ServerId>,
    ) -> Result<bool> {
        let server_id_str = server_id.map(|s| s.0.as_str());
        let row: (i64,) = sqlx::query_as(
            "SELECT EXISTS(
                 SELECT 1
                 FROM admin_alerts AS condition_alert
                 WHERE condition_alert.kind = ?1
                   AND ((?3 IS NULL AND condition_alert.server_id IS NULL)
                        OR condition_alert.server_id = ?3)
                   AND condition_alert.id > COALESCE((
                       SELECT MAX(recovery_alert.id)
                       FROM admin_alerts AS recovery_alert
                       WHERE recovery_alert.kind = ?2
                         AND ((?3 IS NULL AND recovery_alert.server_id IS NULL)
                              OR recovery_alert.server_id = ?3)
                   ), 0)
             )",
        )
        .bind(condition_kind)
        .bind(recovery_kind)
        .bind(server_id_str)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.0 != 0)
    }

    pub async fn purge_acked_alerts_older_than(&self, days: u32) -> Result<u64> {
        let res = sqlx::query(
            "DELETE FROM admin_alerts
             WHERE acked_at IS NOT NULL
               AND acked_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1)",
        )
        .bind(format!("-{days} days"))
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }
}
