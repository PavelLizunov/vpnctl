use crate::sqlite::{Result, SqliteInventory, SqliteInventoryError};
use sqlx::Row;
use std::collections::HashMap;
use vpnctl_core::{KernelId, ProtocolId, ServerId, UserId};

impl SqliteInventory {
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

    pub async fn remove_server_kernel(&self, server: &ServerId, kernel: &KernelId) -> Result<u64> {
        let res = sqlx::query("DELETE FROM server_kernels WHERE server_id = ?1 AND kernel_id = ?2")
            .bind(&server.0)
            .bind(&kernel.0)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected())
    }

    /// Kernels the operator disabled on this server (`server.kernel.disable`
    /// audit rows), whether or not they were enabled again later.
    pub async fn retired_server_kernels(&self, server: &ServerId) -> Result<Vec<KernelId>> {
        let rows = sqlx::query(
            "SELECT DISTINCT json_extract(payload, '$.kernel') AS kernel_id FROM audit_log
             WHERE action = 'server.kernel.disable' AND target = ?1
               AND json_valid(payload) AND json_extract(payload, '$.kernel') IS NOT NULL
             ORDER BY kernel_id",
        )
        .bind(&server.0)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| r.try_get::<String, _>("kernel_id").map(KernelId))
            .collect::<std::result::Result<_, _>>()?)
    }

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

    pub async fn list_server_protocols(&self, id: &ServerId) -> Result<Vec<ProtocolId>> {
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
        match row {
            Some(r) => {
                let h: i64 = r.try_get("hidden")?;
                Ok(h != 0)
            }
            None => Ok(false),
        }
    }

    pub async fn set_server_protocol_hidden(
        &self,
        sid: &ServerId,
        pid: &ProtocolId,
        hidden: bool,
    ) -> Result<()> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;

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

    pub async fn set_grant_protocol_override(
        &self,
        uid: &UserId,
        sid: &ServerId,
        pid: &ProtocolId,
        disabled: bool,
    ) -> Result<()> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;

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
            out.insert((ServerId(sid), ProtocolId(pid)), state == "disabled");
        }
        Ok(out)
    }
}
