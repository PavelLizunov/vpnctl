use crate::sqlite::{Result, SqliteInventory, SqliteInventoryError, escape_like, map_unique};
use sqlx::Row;
use vpnctl_core::{Server, ServerId};

impl SqliteInventory {
    pub async fn add_server(&self, s: &Server) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let res = sqlx::query(
            "INSERT INTO servers (id, address, ssh_port, ssh_user, hoster, jump_via, trusted_host_fingerprint, usage_coefficient)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )
        .bind(&s.id.0)
        .bind(&s.address)
        .bind(i64::from(s.ssh_port))
        .bind(&s.ssh_user)
        .bind(&s.hoster)
        .bind(s.jump_via.as_ref().map(|v| v.0.clone()))
        .bind(&s.trusted_host_fingerprint)
        .bind(s.usage_coefficient)
        .execute(&mut *tx)
        .await;
        map_unique(res, format!("server {}", s.id.0))?;

        for kid in &s.kernels {
            sqlx::query("INSERT INTO server_kernels (server_id, kernel_id) VALUES (?1, ?2)")
                .bind(&s.id.0)
                .bind(&kid.0)
                .execute(&mut *tx)
                .await?;
        }

        for proto in &s.enabled_protocols {
            sqlx::query("INSERT INTO server_protocols (server_id, protocol_id) VALUES (?1, ?2)")
                .bind(&s.id.0)
                .bind(&proto.0)
                .execute(&mut *tx)
                .await?;
        }

        if let Ok(ip) = s.address.parse::<std::net::IpAddr>() {
            sqlx::query(
                "INSERT INTO server_resolved_addresses (server_id, address) VALUES (?1, ?2)",
            )
            .bind(&s.id.0)
            .bind(ip.to_string())
            .execute(&mut *tx)
            .await?;
        }

        // Phase 4a (migration 0021) — when a server is added AFTER
        // the migration has run, any pre-existing sub_access_log
        // rows that happened to come from this server's IP (e.g.
        // logged before vpnctld knew this was an egress) need to
        // be flagged retroactively. Skipped if the server has no
        // address at all (defensive — Server.address is required
        // by the schema so this never happens in practice).
        if !s.address.is_empty() {
            sqlx::query(
                "UPDATE sub_access_log SET is_vpn_egress = 1
                 WHERE is_vpn_egress = 0
                   AND (ip = ?1 OR ip IN
                        (SELECT address FROM server_resolved_addresses WHERE server_id = ?2))",
            )
            .bind(&s.address)
            .bind(&s.id.0)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        if s.address.parse::<std::net::IpAddr>().is_err() {
            self.refresh_server_resolved_addresses().await?;
        }
        Ok(())
    }

    pub async fn resolve_jump_host(
        &self,
        target: &Server,
    ) -> Result<Option<vpnctl_core::PinnedJumpRoute>> {
        let jump_record = if let Some(ref jump_id) = target.jump_via {
            self.get_server(jump_id).await?
        } else {
            None
        };
        crate::jump_resolver::resolve_jump_host(target, jump_record.as_ref())
            .map_err(|e| SqliteInventoryError::Invalid(e.to_string()))
    }

    pub async fn get_server(&self, id: &ServerId) -> Result<Option<Server>> {
        let row_opt = sqlx::query(
            "SELECT id, address, ssh_port, ssh_user, hoster, jump_via, trusted_host_fingerprint, usage_coefficient
             FROM servers WHERE id = ?1",
        )
        .bind(&id.0)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row_opt else { return Ok(None) };

        let server_id: String = row.try_get("id")?;
        let protocols = self
            .list_server_protocols(&ServerId(server_id.clone()))
            .await?;
        let kernels = self
            .list_server_kernels(&ServerId(server_id.clone()))
            .await?;
        let s = Server {
            id: ServerId(server_id),
            address: row.try_get("address")?,
            ssh_port: u16::try_from(row.try_get::<i64, _>("ssh_port")?)
                .map_err(|_| SqliteInventoryError::Invalid("ssh_port out of u16 range".into()))?,
            ssh_user: row.try_get("ssh_user")?,
            kernels,
            enabled_protocols: protocols,
            trusted_host_fingerprint: row.try_get("trusted_host_fingerprint")?,
            hoster: row.try_get("hoster")?,
            jump_via: row.try_get::<Option<String>, _>("jump_via")?.map(ServerId),
            usage_coefficient: row.try_get("usage_coefficient")?,
        };
        Ok(Some(s))
    }

    pub async fn list_servers(&self) -> Result<Vec<Server>> {
        // NOTE(perf): N+1 query — one SELECT id, then per-server get_server
        // (which itself does 2 queries). For a homelab with <100 servers
        // this is fine; if it ever matters, switch to a single LEFT JOIN
        // and aggregate protocols in Rust.
        let rows = sqlx::query("SELECT id FROM servers ORDER BY id")
            .fetch_all(&self.pool)
            .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let id: String = r.try_get("id")?;
            if let Some(s) = self.get_server(&ServerId(id)).await? {
                out.push(s);
            }
        }
        Ok(out)
    }

    pub async fn remove_server(&self, id: &ServerId) -> Result<()> {
        sqlx::query("DELETE FROM servers WHERE id = ?1")
            .bind(&id.0)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Operator-set display name for a server — the `{Country}` part of
    /// the subscription URI fragment / sing-box outbound tag. `None`
    /// when unset (column NULL or blank), in which case the render falls
    /// back to `vpn_router::country_display_name(id)`. Blank/whitespace
    /// stored values are normalised to `None` here so a caller never has
    /// to second-guess them.
    pub async fn server_display_name(&self, sid: &ServerId) -> Result<Option<String>> {
        let row: Option<(Option<String>,)> =
            sqlx::query_as("SELECT display_name FROM servers WHERE id = ?1")
                .bind(&sid.0)
                .fetch_optional(&self.pool)
                .await?;
        // Outer None = no such server; inner None = NULL column. Both → None.
        Ok(row.and_then(|(v,)| v).filter(|s| !s.trim().is_empty()))
    }

    /// Set (or clear, when `name` trims to empty / is `None`) a server's
    /// display name. Audit-on-actual-mutation: writes exactly one
    /// `server.display_name.set` row, and only when the stored value
    /// actually changes (idempotent re-saves are silent). Errors
    /// `Invalid` if the server doesn't exist (matches `set_reserved_ports`
    /// — an unknown id is a caller logic bug, not an expected state).
    pub async fn set_server_display_name(&self, sid: &ServerId, name: Option<&str>) -> Result<()> {
        // Normalise: trim; blank → NULL (clear the override).
        let new_val: Option<String> = name
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        let mut tx = self.pool.begin().await?;

        let prior: Option<(Option<String>,)> =
            sqlx::query_as("SELECT display_name FROM servers WHERE id = ?1")
                .bind(&sid.0)
                .fetch_optional(&mut *tx)
                .await?;
        let prior_val = match prior {
            Some((v,)) => v.filter(|s| !s.trim().is_empty()),
            None => {
                return Err(SqliteInventoryError::Invalid(format!(
                    "no such server '{}'; cannot set display_name",
                    sid.0
                )));
            }
        };

        if prior_val == new_val {
            tx.commit().await?;
            return Ok(());
        }

        sqlx::query("UPDATE servers SET display_name = ?1 WHERE id = ?2")
            .bind(&new_val)
            .bind(&sid.0)
            .execute(&mut *tx)
            .await?;

        let payload = serde_json::json!({
            "server_id": sid.0,
            "old": prior_val,
            "new": new_val,
        });
        let payload_str = serde_json::to_string(&payload)?;
        sqlx::query(
            "INSERT INTO audit_log (actor, action, target, payload)
             VALUES (?1, ?2, ?3, ?4)",
        )
        .bind("admin")
        .bind("server.display_name.set")
        .bind(&sid.0)
        .bind(payload_str)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Cheap row count. `0` on an empty table.
    pub async fn count_servers(&self) -> Result<i64> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM servers")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.try_get("n")?)
    }

    /// Fleet search for servers. Substring match against `servers.id`
    /// and `servers.address`. See [`search_users`] for design notes.
    /// Delegates to `get_server` for each hit so the returned rows
    /// have populated `kernels`/`enabled_protocols` lists (the search
    /// page only renders id+address, but a future audit-row click
    /// would expect a fully-populated `Server`).
    pub async fn search_servers(&self, q: &str, limit: i64) -> Result<Vec<Server>> {
        if q.is_empty() {
            return Ok(Vec::new());
        }
        let pat = format!("%{}%", escape_like(&q.to_lowercase()));
        let rows = sqlx::query(
            "SELECT id FROM servers
             WHERE LOWER(id) LIKE ?1 ESCAPE '\\' OR LOWER(address) LIKE ?1 ESCAPE '\\'
             ORDER BY id
             LIMIT ?2",
        )
        .bind(&pat)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        let mut out: Vec<Server> = Vec::with_capacity(rows.len());
        for r in rows {
            let id: String = r.try_get("id")?;
            if let Some(s) = self.get_server(&ServerId(id)).await? {
                out.push(s);
            }
        }
        Ok(out)
    }
}
