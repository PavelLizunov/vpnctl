use crate::sqlite::{Result, ServerRole, SqliteInventory, SqliteInventoryError};
use vpnctl_core::{Server, ServerId};

impl SqliteInventory {
    /// Get the role of a server (`vpn-exit` vs `workload-only`).
    pub async fn get_server_role(&self, sid: &ServerId) -> Result<ServerRole> {
        let row: Option<(String,)> = sqlx::query_as("SELECT role FROM servers WHERE id = ?1")
            .bind(&sid.0)
            .fetch_optional(&self.pool)
            .await?;

        match row {
            Some((role_str,)) => role_str.parse(),
            None => Err(SqliteInventoryError::Invalid(format!(
                "no such server '{}'",
                sid.0
            ))),
        }
    }

    /// Alias for [`get_server_role`].
    pub async fn get_role(&self, sid: &ServerId) -> Result<ServerRole> {
        self.get_server_role(sid).await
    }

    /// Set a server's role.
    ///
    /// Audit-on-actual-mutation: writes an audit row (`server.role.set`)
    /// only when the stored role value changes (idempotent re-saves are silent).
    ///
    /// Invariant: Role transition to `workload-only` rejects servers with
    /// existing user grants or active client detour relationships.
    pub async fn set_server_role(&self, sid: &ServerId, role: ServerRole) -> Result<()> {
        let mut tx = self.pool.begin().await?;

        let row: Option<(String,)> = sqlx::query_as("SELECT role FROM servers WHERE id = ?1")
            .bind(&sid.0)
            .fetch_optional(&mut *tx)
            .await?;

        let Some((curr_str,)) = row else {
            return Err(SqliteInventoryError::Invalid(format!(
                "no such server '{}'; cannot set role",
                sid.0
            )));
        };

        let curr_role: ServerRole = curr_str.parse()?;

        if curr_role == role {
            tx.commit().await?;
            return Ok(());
        }

        if role == ServerRole::WorkloadOnly {
            let (grant_count,): (i64,) =
                sqlx::query_as("SELECT COUNT(*) FROM grants WHERE server_id = ?1")
                    .bind(&sid.0)
                    .fetch_one(&mut *tx)
                    .await?;

            if grant_count > 0 {
                return Err(SqliteInventoryError::Invalid(format!(
                    "cannot transition server '{}' to workload-only role because it has {} existing grant(s)",
                    sid.0, grant_count
                )));
            }

            let (detour_count,): (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM servers WHERE (id = ?1 AND client_detour_via IS NOT NULL) OR client_detour_via = ?1",
            )
            .bind(&sid.0)
            .fetch_one(&mut *tx)
            .await?;

            if detour_count > 0 {
                return Err(SqliteInventoryError::Invalid(format!(
                    "cannot transition server '{}' to workload-only role because it participates in a client detour configuration",
                    sid.0
                )));
            }
        }

        sqlx::query("UPDATE servers SET role = ?1 WHERE id = ?2")
            .bind(role.as_str())
            .bind(&sid.0)
            .execute(&mut *tx)
            .await?;

        let payload = serde_json::json!({
            "old": curr_role.as_str(),
            "new": role.as_str(),
        });
        let payload_str = serde_json::to_string(&payload)?;

        sqlx::query(
            "INSERT INTO audit_log (actor, action, target, payload)
             VALUES (?1, ?2, ?3, ?4)",
        )
        .bind("admin")
        .bind("server.role.set")
        .bind(&sid.0)
        .bind(payload_str)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Alias for [`set_server_role`].
    pub async fn set_role(&self, sid: &ServerId, role: ServerRole) -> Result<()> {
        self.set_server_role(sid, role).await
    }

    /// Set or clear a server's one-hop management route.
    /// Validation is fail-closed and the audit row is written only on change.
    pub async fn set_server_jump_via(
        &self,
        sid: &ServerId,
        jump_via: Option<&ServerId>,
    ) -> Result<()> {
        let target = self
            .get_server(sid)
            .await?
            .ok_or_else(|| SqliteInventoryError::Invalid(format!("no such server '{}'", sid.0)))?;
        if target.jump_via.as_ref() == jump_via {
            return Ok(());
        }
        if let Some(jump_id) = jump_via {
            let jump = self.get_server(jump_id).await?.ok_or_else(|| {
                SqliteInventoryError::Invalid(format!("no such jump server '{}'", jump_id.0))
            })?;
            let mut candidate = target.clone();
            candidate.jump_via = Some(jump_id.clone());
            crate::jump_resolver::resolve_jump_host(&candidate, Some(&jump))
                .map_err(|error| SqliteInventoryError::Invalid(error.to_string()))?;
        }
        let old = target.jump_via.as_ref().map(|id| id.0.as_str());
        let new = jump_via.map(|id| id.0.as_str());
        let mut tx = self.pool.begin().await?;
        sqlx::query("UPDATE servers SET jump_via = ?1 WHERE id = ?2")
            .bind(new)
            .bind(&sid.0)
            .execute(&mut *tx)
            .await?;
        let payload = serde_json::json!({"old": old, "new": new});
        sqlx::query(
            "INSERT INTO audit_log (actor, action, target, payload) VALUES ('admin', 'server.jump_via.set', ?1, ?2)",
        )
        .bind(&sid.0)
        .bind(serde_json::to_string(&payload)?)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Atomically update role and one-hop route for the Web form.
    pub async fn set_server_routing_policy_as(
        &self,
        actor: &str,
        sid: &ServerId,
        role: ServerRole,
        jump_via: Option<&ServerId>,
    ) -> Result<()> {
        let target = self
            .get_server(sid)
            .await?
            .ok_or_else(|| SqliteInventoryError::Invalid(format!("no such server '{}'", sid.0)))?;
        let current_role = self.get_server_role(sid).await?;
        if current_role == role && target.jump_via.as_ref() == jump_via {
            return Ok(());
        }
        if role == ServerRole::WorkloadOnly {
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM grants WHERE server_id = ?1")
                .bind(&sid.0)
                .fetch_one(&self.pool)
                .await?;
            if count > 0 {
                return Err(SqliteInventoryError::Invalid(format!(
                    "cannot transition server '{}' to workload-only role because it has {count} existing grant(s)",
                    sid.0
                )));
            }

            let detour_count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM servers WHERE (id = ?1 AND client_detour_via IS NOT NULL) OR client_detour_via = ?1",
            )
            .bind(&sid.0)
            .fetch_one(&self.pool)
            .await?;
            if detour_count > 0 {
                return Err(SqliteInventoryError::Invalid(format!(
                    "cannot transition server '{}' to workload-only role because it participates in a client detour configuration",
                    sid.0
                )));
            }
        }
        if let Some(jump_id) = jump_via {
            let jump = self.get_server(jump_id).await?.ok_or_else(|| {
                SqliteInventoryError::Invalid(format!("no such jump server '{}'", jump_id.0))
            })?;
            let mut candidate = target.clone();
            candidate.jump_via = Some(jump_id.clone());
            crate::jump_resolver::resolve_jump_host(&candidate, Some(&jump))
                .map_err(|error| SqliteInventoryError::Invalid(error.to_string()))?;
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query("UPDATE servers SET role = ?1, jump_via = ?2 WHERE id = ?3")
            .bind(role.as_str())
            .bind(jump_via.map(|id| id.0.as_str()))
            .bind(&sid.0)
            .execute(&mut *tx)
            .await?;
        let payload = serde_json::json!({
            "old_role": current_role.as_str(),
            "new_role": role.as_str(),
            "old_jump_via": target.jump_via.as_ref().map(|id| &id.0),
            "new_jump_via": jump_via.map(|id| &id.0),
        });
        sqlx::query("INSERT INTO audit_log (actor, action, target, payload) VALUES (?1, 'server.routing_policy.set', ?2, ?3)")
            .bind(actor)
            .bind(&sid.0)
            .bind(serde_json::to_string(&payload)?)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// List all fleet servers (servers with role `vpn-exit`).
    pub async fn list_fleet_servers(&self) -> Result<Vec<Server>> {
        let rows = sqlx::query("SELECT id FROM servers WHERE role = 'vpn-exit' ORDER BY id")
            .fetch_all(&self.pool)
            .await?;

        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let id: String = sqlx::Row::try_get(&r, "id")?;
            if let Some(s) = self.get_server(&ServerId(id)).await? {
                out.push(s);
            }
        }
        Ok(out)
    }

    /// Get the client detour entry server for a target server, if set.
    pub async fn client_detour_via(&self, server: &ServerId) -> Result<Option<ServerId>> {
        let row: Option<(Option<String>,)> =
            sqlx::query_as("SELECT client_detour_via FROM servers WHERE id = ?1")
                .bind(&server.0)
                .fetch_optional(&self.pool)
                .await?;

        match row {
            Some((Some(upstream),)) => Ok(Some(ServerId(upstream))),
            _ => Ok(None),
        }
    }

    /// Set or clear a server's client detour entry server.
    ///
    /// Audit-on-actual-mutation: writes an audit row (`server.client_detour.set`)
    /// only when the stored detour value changes.
    pub async fn set_client_detour_via_as(
        &self,
        actor: &str,
        server: &ServerId,
        upstream: Option<&ServerId>,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;

        let target_row: Option<(String, Option<String>)> =
            sqlx::query_as("SELECT role, client_detour_via FROM servers WHERE id = ?1")
                .bind(&server.0)
                .fetch_optional(&mut *tx)
                .await?;

        let Some((target_role_str, current_detour)) = target_row else {
            return Err(SqliteInventoryError::Invalid(format!(
                "no such target server '{}'",
                server.0
            )));
        };

        let current_detour_id = current_detour.map(ServerId);
        if current_detour_id.as_ref() == upstream {
            tx.commit().await?;
            return Ok(());
        }

        if let Some(upstream_id) = upstream {
            let target_role: ServerRole = target_role_str.parse()?;
            if target_role != ServerRole::VpnExit {
                return Err(SqliteInventoryError::Invalid(format!(
                    "target server '{}' is not a vpn-exit server",
                    server.0
                )));
            }
            if server == upstream_id {
                return Err(SqliteInventoryError::Invalid(
                    "self-reference client detour is not allowed".into(),
                ));
            }

            let upstream_row: Option<(String, Option<String>)> =
                sqlx::query_as("SELECT role, client_detour_via FROM servers WHERE id = ?1")
                    .bind(&upstream_id.0)
                    .fetch_optional(&mut *tx)
                    .await?;

            let Some((upstream_role_str, upstream_detour)) = upstream_row else {
                return Err(SqliteInventoryError::Invalid(format!(
                    "no such upstream server '{}'",
                    upstream_id.0
                )));
            };

            let upstream_role: ServerRole = upstream_role_str.parse()?;
            if upstream_role != ServerRole::VpnExit {
                return Err(SqliteInventoryError::Invalid(format!(
                    "upstream server '{}' is not a vpn-exit server",
                    upstream_id.0
                )));
            }

            if upstream_detour.is_some() {
                return Err(SqliteInventoryError::Invalid(format!(
                    "upstream server '{}' already has a client detour configured",
                    upstream_id.0
                )));
            }

            let (detoured_by_count,): (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM servers WHERE client_detour_via = ?1 AND id != ?1",
            )
            .bind(&server.0)
            .fetch_one(&mut *tx)
            .await?;

            if detoured_by_count > 0 {
                return Err(SqliteInventoryError::Invalid(format!(
                    "target server '{}' is already used as a client detour by another server",
                    server.0
                )));
            }
        }

        sqlx::query("UPDATE servers SET client_detour_via = ?1 WHERE id = ?2")
            .bind(upstream.map(|id| &id.0))
            .bind(&server.0)
            .execute(&mut *tx)
            .await?;

        let payload = serde_json::json!({
            "old": current_detour_id.as_ref().map(|id| &id.0),
            "new": upstream.map(|id| &id.0),
        });

        sqlx::query(
            "INSERT INTO audit_log (actor, action, target, payload) VALUES (?1, 'server.client_detour.set', ?2, ?3)",
        )
        .bind(actor)
        .bind(&server.0)
        .bind(serde_json::to_string(&payload)?)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }
}
