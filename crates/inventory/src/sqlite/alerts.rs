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
    /// Fleet search for alerts. Substring match against
    /// `admin_alerts.kind` and `summary`. Most recent first.
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

    /// **Q-4f** — unacked alerts grouped by `(kind, severity)`. Returns
    /// `(kind, severity, count)`. Backs the dashboard "open alerts by
    /// type" breakdown without pulling every alert row.
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

    /// **Q-4g** — "today so far" digest from `audit_log`. Counts rows
    /// since UTC local-midnight, bucketed Rust-side into users added /
    /// grants changed / deploys. Served by `idx_audit_ts`.
    pub async fn today_digest(&self) -> Result<TodayDigest> {
        // `'now','start of day'` is midnight UTC. We bucket Rust-side
        // (rather than three SQL COUNTs) so adding a category later is a
        // match-arm edit, not a new query.
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

    /// Distinct subject ids carried in the `kind` suffix of currently-OPEN
    /// (`acked_at IS NULL`) `admin_alerts` whose kind starts with `prefix`.
    /// Backs the per-user fire/resolve loops (kind shape
    /// `user.sub_no_traffic:<id>`): the caller fires for users in violation
    /// and acks the open alerts whose subject is no longer in that set.
    /// Returns the part AFTER `prefix` (the bare id).
    ///
    /// Matched with `substr(kind,1,len) = prefix` rather than `LIKE prefix||'%'`
    /// because the prefix contains `_`, a LIKE single-char wildcard — an exact
    /// substr compare avoids accidental over-matching.
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

    /// Insert one alert row. Returns the new row id so the caller can
    /// reference it in an `audit()` payload — every fired alert ALSO
    /// gets an audit_log row with `action='alert.fire'` so the full
    /// timeline view in `/admin/audit` stays coherent.
    ///
    /// `payload_json` is opaque to inventory — callers serialise
    /// whatever structured context they want (thresholds, prior
    /// values, observed timestamp) and pass the resulting JSON
    /// string. NULL = no extra context.
    ///
    /// **Do NOT serialise secrets** (`User.uuid`, `User.sub_token`,
    /// `tuic_password`, `wireguard_private`, etc.) into
    /// `payload_json`. The string is rendered verbatim in the
    /// operator-facing `/admin/alerts` feed AND copied into the
    /// `audit_log` row AND any future webhook payload (Phase G
    /// chunk 3). Stick to thresholds, percentages, prior/current
    /// values, and other operationally-relevant numbers.
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

    /// Count alerts that haven't been acked yet — backs the dashboard
    /// «N unacked alerts» tile. One indexed SELECT.
    pub async fn unacked_alert_count(&self) -> Result<u64> {
        let row: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM admin_alerts WHERE acked_at IS NULL")
                .fetch_one(&self.pool)
                .await?;
        Ok(u64::try_from(row.0).unwrap_or(0))
    }

    /// Recent alerts, newest first. `include_acked = false` matches the
    /// default feed view (only currently-actionable items); `true`
    /// shows the full history including ones the operator dismissed.
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

    /// Mark one alert as acked. Returns `true` if the row existed AND
    /// was unacked (the operator-visible state actually changed),
    /// `false` if the id is unknown OR was already acked (idempotent).
    /// Doesn't error on a duplicate ack — the dashboard tile uses POST
    /// without an Idempotency-Key, so a refresh-after-ack should not
    /// 500.
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

    /// Record the Telegram `message_id` of the push for `alert_id` so a
    /// later recovery can EDIT that message in place (🔴→🟢) instead of
    /// sending a second "recovered" message (migration 0037). Best-effort
    /// — a failed/absent push leaves it NULL and the recovery path falls
    /// back to a fresh message.
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

    /// The Telegram `message_id` of the most-recent alert of `kind` for
    /// `server_id` that carries one — edit-on-recover uses it to find the
    /// original 🔴 message to flip to 🟢. `None` when no matching alert
    /// recorded a message id (e.g. the transport was off when it fired),
    /// in which case the caller sends a fresh recovery message.
    pub async fn latest_alert_message_id(
        &self,
        kind: &str,
        server_id: Option<&ServerId>,
    ) -> Result<Option<String>> {
        let row: Option<(Option<String>,)> = sqlx::query_as(
            "SELECT telegram_message_id FROM admin_alerts
             WHERE kind = ?1
               AND (?2 IS NULL OR server_id = ?2)
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

    /// Ack EVERY currently-unacked alert in one UPDATE. Used by the
    /// «ack all (N)» button on /admin/alerts so the operator can
    /// clear a triaged backlog without 30 individual clicks.
    ///
    /// Returns the count of rows affected — caller uses it for the
    /// audit row + the success-banner («acked N alerts»).
    ///
    /// **Contract:** the UPDATE filters `WHERE acked_at IS NULL` so
    /// historical acks (already inside the 30-day retention window)
    /// are NOT touched — `acked_at` keeps its original timestamp, not
    /// the bulk-ack's «now». Pinned by
    /// `ack_all_unacked_alerts_preserves_existing_ack_timestamps`.
    ///
    /// **No `WHERE kind = …` overload yet** — Pavel's «33 stale
    /// suspicious_local_ip alerts» fire-drill (2026-05-22) is the
    /// only use case so far and it wants to clear everything; a
    /// per-kind variant can land when there's a second use case to
    /// motivate it. The endpoint stays a POST with no body to keep
    /// the contract «ack all» rather than «ack subset».
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

    /// Fire-once-per-condition variant of [`insert_alert`].
    ///
    /// Insert a new alert row ONLY if there is no currently-unacked row
    /// of the same `(kind, server_id)` pair. Returns `Some(new_id)` if
    /// inserted, `None` if a matching unacked row already existed
    /// (idempotent — the caller's tick-driven detection loop can call
    /// this every probe interval without flooding the feed).
    ///
    /// Semantics: a `(kind, server_id)` pair has at most ONE open row
    /// in the unacked view at a time. The operator acks it (or it gets
    /// auto-acked by a recovery transition via [`ack_open_alerts`]),
    /// AFTER which the next firing legitimately creates a fresh row.
    /// This matches the natural state-machine for «is this condition
    /// currently raised?».
    ///
    /// ## Atomicity
    ///
    /// The dedup is enforced at the SQL ENGINE level by the partial
    /// UNIQUE index `idx_admin_alerts_unique_unacked` (migration
    /// 0013), keyed on `(kind, COALESCE(server_id, '__GLOBAL__'))`
    /// filtered to `acked_at IS NULL`. A simple `INSERT OR IGNORE`
    /// is therefore atomic across concurrent writers — there is no
    /// READ-then-WRITE race window the way an `INSERT ... SELECT ...
    /// WHERE NOT EXISTS` formulation would have. Two daemons (or
    /// two sqlx pool connections) firing simultaneously cannot
    /// both succeed; the loser silently no-ops via the IGNORE clause.
    ///
    /// ## Secret-leakage warning (mirrored from [`insert_alert`])
    ///
    /// **Do NOT serialise secrets** (`User.uuid`, `User.sub_token`,
    /// `tuic_password`, `wireguard_private`, etc.) into `payload_json`.
    /// The string is rendered verbatim in the operator-facing
    /// `/admin/alerts` feed AND copied into the audit_log row AND any
    /// future webhook payload (Phase G chunk 3). Stick to thresholds,
    /// percentages, prior/current values, and other operationally-
    /// relevant numbers.
    pub async fn insert_alert_if_no_unacked(
        &self,
        kind: &str,
        server_id: Option<&ServerId>,
        severity: &str,
        summary: &str,
        payload_json: Option<&str>,
    ) -> Result<Option<i64>> {
        let server_id_str = server_id.map(|s| s.0.as_str());
        let res = sqlx::query(
            "INSERT OR IGNORE INTO admin_alerts
                 (kind, server_id, severity, summary, payload_json)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(kind)
        .bind(server_id_str)
        .bind(severity)
        .bind(summary)
        .bind(payload_json)
        .execute(&self.pool)
        .await?;
        if res.rows_affected() == 1 {
            Ok(Some(res.last_insert_rowid()))
        } else {
            Ok(None)
        }
    }

    /// Insert an alert row that is born ACKED (`acked_at = now`).
    /// Used for recovery events (`*.up` / `*.recovered`) since the
    /// alerts-cleanup (2026-06-10): a recovery is good news — it
    /// belongs in the history (`?show=all`) but must NOT sit in the
    /// open feed demanding a manual ack. Bypasses the partial UNIQUE
    /// dedup index by construction (the index only covers
    /// `acked_at IS NULL` rows), which is correct: each recovery is
    /// its own historical event.
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

    /// Bulk-ack every currently-unacked alert of the given `(kind,
    /// server_id)` pair. Returns `rows_affected` — `0` if no matching
    /// open row existed (idempotent: the caller's recovery-detection
    /// loop can call this every probe interval without erroring out
    /// when the condition was never raised).
    ///
    /// Companion to [`insert_alert_if_no_unacked`]. The «recovery
    /// silently clears the alert» semantics is intentional — an alert
    /// that auto-clears doesn't need operator attention; the audit_log
    /// row written by the caller preserves the timeline. If the
    /// operator's preference shifts to «recovery emits a new
    /// `*.recovered` info alert», that's a Phase G chunk 3 decision,
    /// not this helper's responsibility.
    ///
    /// ## NULL-equality predicate
    ///
    /// SQLite's regular `=` returns NULL on NULL operands; for the
    /// `server_id IS NULL` global-alert case we use
    /// `((?2 IS NULL AND server_id IS NULL) OR server_id = ?2)` so
    /// NULL matches NULL. The companion [`insert_alert_if_no_unacked`]
    /// achieves the same semantics via the partial UNIQUE index's
    /// `COALESCE(server_id, '__GLOBAL__')` expression — different
    /// mechanism, same observable rule.
    ///
    /// ## Race-vs-concurrent-fire
    ///
    /// If a new firing of the same (kind, server_id) lands between
    /// this UPDATE's row-scan and commit, that new row legitimately
    /// represents the NEXT occurrence — the condition recovered then
    /// re-fired. The new row remains unacked; the operator sees it.
    /// This is the correct semantics for a state-machine that
    /// distinguishes «raised → cleared → raised again».
    /// v2 5a — ack every unacked alert whose kind starts with `prefix`
    /// (e.g. `sub_access.` clears the whole suspicious-IP family in one
    /// click). Prefix is escaped for LIKE. Returns rows affected.
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

    /// Whether a condition alert was recorded after the latest recovery
    /// alert for the same scope, regardless of whether an operator already
    /// acknowledged that condition. Health-monitor recovery dispatch uses
    /// this after [`ack_open_alerts`]: a zero-row ack can mean either an
    /// orphan recovery boundary or a manually acknowledged condition.
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

    /// Drop ACKED alerts older than `days`. UNACKED alerts are NEVER
    /// auto-purged (an alert that fires once and is forgotten must
    /// still be visible — see migration 0011 doc-comment for the
    /// rationale). Wired into the existing retention scheduler.
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
