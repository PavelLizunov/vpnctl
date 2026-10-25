use super::*;
use chrono::{DateTime, Utc};
use sqlx::Row;

#[allow(clippy::needless_pass_by_value)]
pub(crate) fn row_to_audit_entry(r: sqlx::sqlite::SqliteRow) -> Result<AuditEntry> {
    let ts_str: String = r.try_get("ts")?;
    let ts = DateTime::parse_from_rfc3339(&ts_str)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|e| {
            SqliteInventoryError::Invalid(format!("audit ts not RFC3339 ({ts_str}): {e}"))
        })?;
    let payload_opt: Option<String> = r.try_get("payload")?;
    let payload = match payload_opt {
        Some(s) => Some(serde_json::from_str(&s)?),
        None => None,
    };
    Ok(AuditEntry {
        id: r.try_get("id")?,
        ts,
        actor: r.try_get("actor")?,
        action: r.try_get("action")?,
        target: r.try_get("target")?,
        payload,
    })
}

impl SqliteInventory {
    pub async fn audit(
        &self,
        actor: &str,
        action: &str,
        target: Option<&str>,
        payload: Option<&serde_json::Value>,
    ) -> Result<()> {
        let payload_str = match payload {
            Some(v) => Some(serde_json::to_string(v)?),
            None => None,
        };
        sqlx::query(
            "INSERT INTO audit_log (actor, action, target, payload) VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(actor)
        .bind(action)
        .bind(target)
        .bind(payload_str)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn recent_audit_paginated(
        &self,
        limit: i64,
        offset: i64,
        actor_filter: Option<&str>,
        action_prefix: Option<&str>,
        target_contains: Option<&str>,
        action_exclude: Option<&str>,
    ) -> Result<Vec<AuditEntry>> {
        let mut where_parts: Vec<&str> = Vec::with_capacity(2);
        if actor_filter.is_some() {
            where_parts.push(if where_parts.is_empty() {
                "actor = ?"
            } else {
                "AND actor = ?"
            });
        }
        if action_prefix.is_some() {
            where_parts.push(if where_parts.is_empty() {
                "action LIKE ? ESCAPE '\\'"
            } else {
                "AND action LIKE ? ESCAPE '\\'"
            });
        }
        if target_contains.is_some() {
            where_parts.push(if where_parts.is_empty() {
                "target LIKE ? ESCAPE '\\'"
            } else {
                "AND target LIKE ? ESCAPE '\\'"
            });
        }
        if action_exclude.is_some() {
            where_parts.push(if where_parts.is_empty() {
                "action <> ?"
            } else {
                "AND action <> ?"
            });
        }
        let where_clause = if where_parts.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_parts.join(" "))
        };
        let sql = format!(
            "SELECT id, ts, actor, action, target, payload
             FROM audit_log
             {where_clause}
             ORDER BY id DESC
             LIMIT ? OFFSET ?"
        );
        let mut q = sqlx::query(&sql);
        if let Some(a) = actor_filter {
            q = q.bind(a);
        }
        if let Some(p) = action_prefix {
            q = q.bind(format!("{}%", escape_like(p)));
        }
        if let Some(t) = target_contains {
            q = q.bind(format!("%{}%", escape_like(t)));
        }
        if let Some(x) = action_exclude {
            q = q.bind(x);
        }
        q = q.bind(limit).bind(offset);
        let rows = q.fetch_all(&self.pool).await?;
        rows.into_iter().map(row_to_audit_entry).collect()
    }

    pub async fn audit_counts(
        &self,
        actor_filter: Option<&str>,
        action_prefix: Option<&str>,
        target_contains: Option<&str>,
        action_exclude: Option<&str>,
    ) -> Result<(u64, u64)> {
        let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_log")
            .fetch_one(&self.pool)
            .await?;
        let mut where_parts: Vec<&str> = Vec::with_capacity(4);
        if actor_filter.is_some() {
            where_parts.push("actor = ?");
        }
        if action_prefix.is_some() {
            where_parts.push("action LIKE ? ESCAPE '\\'");
        }
        if target_contains.is_some() {
            where_parts.push("target LIKE ? ESCAPE '\\'");
        }
        if action_exclude.is_some() {
            where_parts.push("action <> ?");
        }
        let matched = if where_parts.is_empty() {
            total.0
        } else {
            let sql = format!(
                "SELECT COUNT(*) FROM audit_log WHERE {}",
                where_parts.join(" AND ")
            );
            let mut q = sqlx::query_as::<_, (i64,)>(&sql);
            if let Some(a) = actor_filter {
                q = q.bind(a.to_string());
            }
            if let Some(pfx) = action_prefix {
                q = q.bind(format!("{}%", escape_like(pfx)));
            }
            if let Some(t) = target_contains {
                q = q.bind(format!("%{}%", escape_like(t)));
            }
            if let Some(x) = action_exclude {
                q = q.bind(x.to_string());
            }
            q.fetch_one(&self.pool).await?.0
        };
        Ok((
            u64::try_from(total.0).unwrap_or(0),
            u64::try_from(matched).unwrap_or(0),
        ))
    }

    pub async fn recent_audit(&self, limit: i64) -> Result<Vec<AuditEntry>> {
        let rows = sqlx::query(
            "SELECT id, ts, actor, action, target, payload
             FROM audit_log ORDER BY id DESC LIMIT ?1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_audit_entry).collect()
    }

    pub async fn audit_for_server(&self, server_id: &str, limit: i64) -> Result<Vec<AuditEntry>> {
        let rows = sqlx::query(
            "SELECT id, ts, actor, action, target, payload
             FROM audit_log
             WHERE target = ?1
                OR json_extract(payload, '$.server_id') = ?1
                OR json_extract(payload, '$.server') = ?1
             ORDER BY id DESC
             LIMIT ?2",
        )
        .bind(server_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_audit_entry).collect()
    }
}
