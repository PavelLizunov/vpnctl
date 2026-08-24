use crate::sqlite::{Result, SqliteInventory, SqliteInventoryError};
use sqlx::Row;
use std::collections::HashMap;
use vpnctl_core::{KernelId, ProtocolId, ServerId, UserId};

impl SqliteInventory {
    /// All kernels this server runs, sorted alphabetically for stable
    /// rendering. Empty Vec is legal in the DB but `validate_server`
    /// rejects it before deploy — see `Registry::validate_server`.
    pub async fn list_server_kernels(&self, id: &ServerId) -> Result<Vec<KernelId>> {
        let rows = sqlx::query(
            "SELECT kernel_id FROM server_kernels WHERE server_id = ?1 ORDER BY kernel_id",
        )
        .bind(&id.0)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| r.try_get::<String, _>("kernel_id").map(KernelId))
            .collect::<std::result::Result<_, _>>()?)
    }

    /// Add a single kernel to a server's runtime set. Idempotent (`ON
    /// CONFLICT DO NOTHING`). Mirrors `add_server_protocol`.
    /// FK constraint on `server_id` surfaces as `Invalid` for unknown
    /// server; kernel id is opaque to the DB (registry validation
    /// happens at deploy time).
    pub async fn add_server_kernel(&self, server: &ServerId, kernel: &KernelId) -> Result<u64> {
        let res = sqlx::query(
            "INSERT INTO server_kernels (server_id, kernel_id) VALUES (?1, ?2)
             ON CONFLICT(server_id, kernel_id) DO NOTHING",
        )
        .bind(&server.0)
        .bind(&kernel.0)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    /// Remove a kernel from a server. Idempotent. Mirrors
    /// `remove_server_protocol`.
    pub async fn remove_server_kernel(&self, server: &ServerId, kernel: &KernelId) -> Result<u64> {
        let res = sqlx::query("DELETE FROM server_kernels WHERE server_id = ?1 AND kernel_id = ?2")
            .bind(&server.0)
            .bind(&kernel.0)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected())
    }

    /// Add a single protocol to a server's `enabled_protocols`.
    /// Idempotent at the SQL layer (`OR IGNORE` on the PK pair) — calling
    /// twice with the same `(server, protocol)` is silent success.
    /// Returns the row-was-actually-inserted count so the caller can
    /// distinguish \"already there\" from \"just added\" if it wants to
    /// audit only effective changes (currently web handler audits both).
    /// FK constraint on `server_id` will surface as `Invalid` if the
    /// server doesn't exist; protocol id is opaque to the DB layer
    /// (registry validation happens at deploy time).
    pub async fn add_server_protocol(
        &self,
        server: &ServerId,
        protocol: &ProtocolId,
    ) -> Result<u64> {
        let res = sqlx::query(
            "INSERT INTO server_protocols (server_id, protocol_id) VALUES (?1, ?2)
             ON CONFLICT(server_id, protocol_id) DO NOTHING",
        )
        .bind(&server.0)
        .bind(&protocol.0)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    /// Remove a protocol from a server's `enabled_protocols`. Idempotent:
    /// removing a not-present (server, protocol) is silent success.
    /// Returns the row-was-actually-deleted count for the same audit
    /// reason as `add_server_protocol`.
    pub async fn remove_server_protocol(
        &self,
        server: &ServerId,
        protocol: &ProtocolId,
    ) -> Result<u64> {
        let res =
            sqlx::query("DELETE FROM server_protocols WHERE server_id = ?1 AND protocol_id = ?2")
                .bind(&server.0)
                .bind(&protocol.0)
                .execute(&self.pool)
                .await?;
        Ok(res.rows_affected())
    }

    pub(crate) async fn list_server_protocols(&self, id: &ServerId) -> Result<Vec<ProtocolId>> {
        let rows = sqlx::query(
            "SELECT protocol_id FROM server_protocols WHERE server_id = ?1 ORDER BY protocol_id",
        )
        .bind(&id.0)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|r| Ok(ProtocolId(r.try_get::<String, _>("protocol_id")?)))
            .collect()
    }

    // ── Per-(server, protocol) visibility (migration 0018) ───────────
    //
    // The `hidden` flag suppresses a protocol from EVERY rendered
    // subscription URL (sub.rs + vpn_router.rs filters) while keeping
    // the inbound running on the live node — clients with cached URIs
    // keep working until they re-pull. The render path checks via
    // `visible_protocols_for_subscription` (compound query that joins
    // server_protocols × grant_protocol_overrides); this method is the
    // raw read used by the admin UI's `/admin/servers/<id>` toggles.

    /// Is the (server, protocol) pair flagged `hidden=1`?
    /// `false` if the row exists with `hidden=0` OR if the row is
    /// absent (protocol not enabled on the server at all — nothing
    /// to hide). Use `list_server_protocols` first if you need to
    /// distinguish \"not enabled\" from \"enabled but visible\".
    pub async fn is_server_protocol_hidden(
        &self,
        sid: &ServerId,
        pid: &ProtocolId,
    ) -> Result<bool> {
        let row = sqlx::query(
            "SELECT hidden FROM server_protocols WHERE server_id = ?1 AND protocol_id = ?2",
        )
        .bind(&sid.0)
        .bind(&pid.0)
        .fetch_optional(&self.pool)
        .await?;
        // Propagate sqlx Decode errors via `?` — review-agent
        // 2026-05-20 flagged that `.unwrap_or(0)` would silently
        // return `false` (visible) on a broken column type, fail-
        // OPEN on a security-relevant flag.
        match row {
            Some(r) => {
                let h: i64 = r.try_get("hidden")?;
                Ok(h != 0)
            }
            None => Ok(false),
        }
    }

    /// Toggle the `hidden` flag on an existing (server, protocol) row.
    /// Refuses if the row doesn't exist (operator must `add_protocol`
    /// first — hide is a render-suppression, not a protocol enablement).
    /// Writes an audit row inside the same transaction (mirrors the
    /// `set_grant_client_uuid` write-+-audit invariant from CLAUDE.md).
    pub async fn set_server_protocol_hidden(
        &self,
        sid: &ServerId,
        pid: &ProtocolId,
        hidden: bool,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;

        // Read the old value first — needed for the audit payload AND
        // for the \"no such row\" check.
        let prior = sqlx::query(
            "SELECT hidden FROM server_protocols WHERE server_id = ?1 AND protocol_id = ?2",
        )
        .bind(&sid.0)
        .bind(&pid.0)
        .fetch_optional(&mut *tx)
        .await?;
        let prior_hidden: bool = match prior {
            Some(row) => row.try_get::<i64, _>("hidden")? != 0,
            None => {
                return Err(SqliteInventoryError::Invalid(format!(
                    "no such server_protocols row ({}, {}); enable the protocol first via add_protocol",
                    sid.0, pid.0
                )));
            }
        };

        // No-op short-circuit (review-agent 2026-05-20): if the flag
        // is already at the target value, don't UPDATE and don't
        // pollute audit_log. \"One audit row per mutation\" invariant
        // means non-mutations write zero rows. Idempotent re-clicks
        // from the UI become silent.
        if prior_hidden == hidden {
            tx.commit().await?;
            return Ok(());
        }

        let new_hidden = i64::from(hidden);
        sqlx::query(
            "UPDATE server_protocols SET hidden = ?1 WHERE server_id = ?2 AND protocol_id = ?3",
        )
        .bind(new_hidden)
        .bind(&sid.0)
        .bind(&pid.0)
        .execute(&mut *tx)
        .await?;

        let payload = serde_json::json!({
            "server_id": sid.0,
            "protocol_id": pid.0,
            "old_hidden": prior_hidden,
            "new_hidden": hidden,
        });
        let payload_str = serde_json::to_string(&payload)?;
        sqlx::query(
            "INSERT INTO audit_log (actor, action, target, payload)
             VALUES (?1, ?2, ?3, ?4)",
        )
        .bind("admin")
        .bind("server.protocol.set_hidden")
        .bind(&sid.0)
        .bind(payload_str)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Set or clear the per-(user, server, protocol) deny override.
    /// `disabled = true` inserts (or no-ops if already disabled).
    /// `disabled = false` deletes the override row (back to inherit-
    /// from-server). FK-fails (returns Invalid) if no grant exists for
    /// (user, server) — operator must grant first via `grant()`. Writes
    /// audit `grant.protocol.set_override`.
    pub async fn set_grant_protocol_override(
        &self,
        uid: &UserId,
        sid: &ServerId,
        pid: &ProtocolId,
        disabled: bool,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;

        // FK precheck — composite FK to grants(user_id, server_id).
        // Without this the INSERT fails with raw `Sqlx(Database(...))`
        // which is harder to handle on the caller side.
        let grant_exists =
            sqlx::query("SELECT 1 FROM grants WHERE user_id = ?1 AND server_id = ?2")
                .bind(&uid.0)
                .bind(&sid.0)
                .fetch_optional(&mut *tx)
                .await?
                .is_some();
        if !grant_exists {
            return Err(SqliteInventoryError::Invalid(format!(
                "no grant for ({}, {}); cannot set per-protocol override without an existing grant",
                uid.0, sid.0
            )));
        }

        // Capture rows_affected so we only write audit on actual
        // mutation (review-agent 2026-05-20 \"audit-per-mutation\"
        // invariant: re-clicking a disable button must NOT spam
        // the audit_log with no-op rows).
        let rows_affected = if disabled {
            sqlx::query(
                "INSERT INTO grant_protocol_overrides (user_id, server_id, protocol_id, state)
                 VALUES (?1, ?2, ?3, 'disabled')
                 ON CONFLICT(user_id, server_id, protocol_id) DO NOTHING",
            )
            .bind(&uid.0)
            .bind(&sid.0)
            .bind(&pid.0)
            .execute(&mut *tx)
            .await?
            .rows_affected()
        } else {
            sqlx::query(
                "DELETE FROM grant_protocol_overrides WHERE user_id = ?1 AND server_id = ?2 AND protocol_id = ?3",
            )
            .bind(&uid.0)
            .bind(&sid.0)
            .bind(&pid.0)
            .execute(&mut *tx)
            .await?
            .rows_affected()
        };

        if rows_affected == 0 {
            tx.commit().await?;
            return Ok(());
        }

        let payload = serde_json::json!({
            "user_id": uid.0,
            "server_id": sid.0,
            "protocol_id": pid.0,
            "disabled": disabled,
        });
        let payload_str = serde_json::to_string(&payload)?;
        sqlx::query(
            "INSERT INTO audit_log (actor, action, target, payload)
             VALUES (?1, ?2, ?3, ?4)",
        )
        .bind("admin")
        .bind("grant.protocol.set_override")
        .bind(&uid.0)
        .bind(payload_str)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Resolve the protocol set a user's subscription URL should
    /// expose for a given server. Combines both axes of the
    /// visibility model:
    ///
    ///   1. `server_protocols.hidden=1` → excluded
    ///   2. `grant_protocol_overrides.state='disabled'` → excluded
    ///   3. otherwise (row exists in `server_protocols` with
    ///      `hidden=0`, no override) → included
    ///
    /// Order: alphabetical by `protocol_id` for deterministic
    /// rendering (so a re-render with no schema change produces
    /// byte-identical output).
    pub async fn visible_protocols_for_subscription(
        &self,
        uid: &UserId,
        sid: &ServerId,
    ) -> Result<Vec<ProtocolId>> {
        let rows = sqlx::query(
            "SELECT sp.protocol_id
             FROM server_protocols sp
             WHERE sp.server_id = ?2
               AND sp.hidden = 0
               AND NOT EXISTS (
                   SELECT 1 FROM grant_protocol_overrides gpo
                   WHERE gpo.user_id = ?1
                     AND gpo.server_id = sp.server_id
                     AND gpo.protocol_id = sp.protocol_id
                     AND gpo.state = 'disabled'
               )
             ORDER BY sp.protocol_id",
        )
        .bind(&uid.0)
        .bind(&sid.0)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|r| Ok(ProtocolId(r.try_get::<String, _>("protocol_id")?)))
            .collect()
    }

    /// Bulk-fetch every enabled (server, protocol) row with its
    /// `hidden` flag for a given server. Useful for admin UI rendering
    /// without N+1 calls into `is_server_protocol_hidden`. Returns an
    /// empty map if the server has no enabled protocols.
    pub async fn list_server_protocols_with_hidden(
        &self,
        sid: &ServerId,
    ) -> Result<HashMap<ProtocolId, bool>> {
        let rows =
            sqlx::query("SELECT protocol_id, hidden FROM server_protocols WHERE server_id = ?1")
                .bind(&sid.0)
                .fetch_all(&self.pool)
                .await?;
        let mut out = HashMap::with_capacity(rows.len());
        for r in rows {
            let pid: String = r.try_get("protocol_id")?;
            let hidden: i64 = r.try_get("hidden")?;
            out.insert(ProtocolId(pid), hidden != 0);
        }
        Ok(out)
    }

    /// All-servers variant of `list_server_protocols_with_hidden` —
    /// one round-trip returns the full `(server, protocol) → hidden`
    /// matrix. Used by the `/admin/servers` list page so the server
    /// cards can render an accurate \"visible vs hidden\" breakdown
    /// without N queries (the per-server bulk helper would N+1 over
    /// the inventory). Empty map for servers that have no
    /// `server_protocols` rows yet — caller should fall back to a
    /// dash in that case.
    ///
    /// (Pavel 2026-05-20: «нужно сделаить на /admin/servers чтоб
    /// это отобразилось, сейчас показано что там все протоколы,
    /// хотя я сделал hide» — the list page was rendering from
    /// `Server.enabled_protocols` (in-memory cache, which doesn't
    /// know about hidden) instead of from this table, so post-hide
    /// state never reached the operator's eye.)
    pub async fn list_all_server_protocols_with_hidden(
        &self,
    ) -> Result<HashMap<(ServerId, ProtocolId), bool>> {
        let rows = sqlx::query("SELECT server_id, protocol_id, hidden FROM server_protocols")
            .fetch_all(&self.pool)
            .await?;
        let mut out = HashMap::with_capacity(rows.len());
        for r in rows {
            let sid: String = r.try_get("server_id")?;
            let pid: String = r.try_get("protocol_id")?;
            let hidden: i64 = r.try_get("hidden")?;
            out.insert((ServerId(sid), ProtocolId(pid)), hidden != 0);
        }
        Ok(out)
    }

    /// Map of (server_id, protocol_id) → `true` for every disabled
    /// override the user has set. Useful for rendering the admin UI
    /// checkboxes pre-populated. Empty map = no overrides = inherit
    /// every server's visibility verbatim.
    pub async fn list_protocol_overrides_for_user(
        &self,
        uid: &UserId,
    ) -> Result<std::collections::HashMap<(ServerId, ProtocolId), bool>> {
        let rows = sqlx::query(
            "SELECT server_id, protocol_id, state
             FROM grant_protocol_overrides
             WHERE user_id = ?1",
        )
        .bind(&uid.0)
        .fetch_all(&self.pool)
        .await?;
        let mut out = std::collections::HashMap::new();
        for r in rows {
            let sid: String = r.try_get("server_id")?;
            let pid: String = r.try_get("protocol_id")?;
            let state: String = r.try_get("state")?;
            // Only 'disabled' is valid today per the CHECK constraint;
            // future 'force-enabled' would flip the bool.
            out.insert((ServerId(sid), ProtocolId(pid)), state == "disabled");
        }
        Ok(out)
    }
}
