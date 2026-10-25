use super::crud::row_to_user;
use super::grants::find_effective_uuid_conflict;
use crate::sqlite::base::{SqliteInventory, map_unique};
use crate::sqlite::models::{Result, SqliteInventoryError};
use sqlx::Row;
use vpnctl_core::{ServerId, User, UserId};

impl SqliteInventory {
    pub async fn set_user_wireguard_keypair(
        &self,
        id: &UserId,
        pubkey: &str,
        private: &str,
    ) -> Result<()> {
        let res = sqlx::query(
            "UPDATE users SET wireguard_pubkey = ?1, wireguard_private = ?2 WHERE id = ?3",
        )
        .bind(pubkey)
        .bind(private)
        .bind(&id.0)
        .execute(&self.pool)
        .await?;
        if res.rows_affected() == 0 {
            return Err(SqliteInventoryError::Invalid(format!(
                "no such user: {}",
                id.0
            )));
        }
        Ok(())
    }

    pub async fn client_uuid_for(
        &self,
        user: &UserId,
        server: &ServerId,
    ) -> Result<Option<String>> {
        let row = sqlx::query(
            "SELECT COALESCE(g.client_uuid, u.uuid) AS uuid
             FROM grants g
             INNER JOIN users u ON u.id = g.user_id
             WHERE g.user_id = ?1 AND g.server_id = ?2",
        )
        .bind(&user.0)
        .bind(&server.0)
        .fetch_optional(&self.pool)
        .await?;
        match row {
            None => Ok(None),
            Some(r) => Ok(Some(r.try_get("uuid")?)),
        }
    }

    pub async fn assert_no_uuid_collisions(&self, server: &ServerId) -> Result<()> {
        let rows = sqlx::query(
            "SELECT COALESCE(g.client_uuid, u.uuid) AS eff,
                    GROUP_CONCAT(
                        u.id || CASE WHEN g.client_uuid IS NOT NULL
                                     THEN ' (override)' ELSE ' (global)' END,
                        ', ') AS who
             FROM grants g
             INNER JOIN users u ON u.id = g.user_id
             WHERE g.server_id = ?1
               AND u.disabled = 0
             GROUP BY COALESCE(g.client_uuid, u.uuid)
             HAVING COUNT(*) > 1",
        )
        .bind(&server.0)
        .fetch_all(&self.pool)
        .await?;
        if rows.is_empty() {
            return Ok(());
        }
        let detail = rows
            .iter()
            .map(|r| {
                let eff: String = r.try_get("eff").unwrap_or_default();
                let who: String = r.try_get("who").unwrap_or_default();
                format!("{eff} → [{who}]")
            })
            .collect::<Vec<_>>()
            .join("; ");
        Err(SqliteInventoryError::Invalid(format!(
            "server {} has effective-uuid collisions; refusing to deploy the whole node until \
             fixed — clear or replace the offending grant's (override) client_uuid: {detail}",
            server.0
        )))
    }

    pub async fn set_grant_client_uuid(
        &self,
        user: &UserId,
        server: &ServerId,
        client_uuid: &str,
    ) -> Result<()> {
        if !vpnctl_crypto::is_valid_uuid(client_uuid) {
            return Err(SqliteInventoryError::Invalid(format!(
                "client_uuid {client_uuid:?} is not a valid UUID; refusing to write"
            )));
        }

        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;

        let grant_row =
            sqlx::query("SELECT client_uuid FROM grants WHERE user_id = ?1 AND server_id = ?2")
                .bind(&user.0)
                .bind(&server.0)
                .fetch_optional(&mut *tx)
                .await?;
        let grant_exists = grant_row.is_some();
        let old_uuid: Option<String> = grant_row.and_then(|row| {
            row.try_get::<Option<String>, _>("client_uuid")
                .ok()
                .flatten()
        });

        if grant_exists {
            if let Some((other, other_disabled)) =
                find_effective_uuid_conflict(&mut *tx, &server.0, client_uuid, &user.0).await?
            {
                let dis = if other_disabled {
                    " (disabled — hidden in the UI)"
                } else {
                    ""
                };
                return Err(SqliteInventoryError::AlreadyExists(format!(
                    "client_uuid {client_uuid} is already used by user {other}{dis} on server {}; \
                     refusing to set it for {} — they would collide on the node",
                    server.0, user.0
                )));
            }
        }

        let res = sqlx::query(
            "UPDATE grants SET client_uuid = ?3
             WHERE user_id = ?1 AND server_id = ?2 AND client_uuid IS NOT ?3",
        )
        .bind(&user.0)
        .bind(&server.0)
        .bind(client_uuid)
        .execute(&mut *tx)
        .await?;
        if res.rows_affected() == 0 {
            if !grant_exists {
                return Err(SqliteInventoryError::Invalid(format!(
                    "no grant for user={} server={}; cannot set client_uuid",
                    user.0, server.0
                )));
            }
            tx.commit().await?;
            return Ok(());
        }

        let audit_payload = serde_json::json!({
            "server_id": server.0,
            "old_client_uuid_set": old_uuid.is_some(),
            "new_client_uuid_set": true,
        });
        let payload_str = serde_json::to_string(&audit_payload)?;
        sqlx::query(
            "INSERT INTO audit_log (actor, action, target, payload)
             VALUES (?1, ?2, ?3, ?4)",
        )
        .bind("admin")
        .bind("grant.set_client_uuid")
        .bind(&user.0)
        .bind(&payload_str)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    pub async fn find_user_by_vpn_router_device_id(&self, device_id: &str) -> Result<Option<User>> {
        let row = sqlx::query(
            "SELECT id, uuid, tuic_password, wireguard_pubkey, wireguard_private, sub_token, vpn_router_device_id, disabled
             FROM users WHERE vpn_router_device_id = ?1",
        )
        .bind(device_id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(row_to_user).transpose()
    }

    pub async fn set_vpn_router_device_id(&self, user: &UserId, device_id: &str) -> Result<()> {
        if !vpnctl_crypto::is_valid_vpn_router_device_id(device_id) {
            return Err(SqliteInventoryError::Invalid(format!(
                "device_id {device_id:?} is not 32 lowercase hex chars; refusing to write"
            )));
        }

        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;

        let old_device_id: Option<String> =
            sqlx::query("SELECT vpn_router_device_id FROM users WHERE id = ?1")
                .bind(&user.0)
                .fetch_optional(&mut *tx)
                .await?
                .and_then(|row| {
                    row.try_get::<Option<String>, _>("vpn_router_device_id")
                        .ok()
                        .flatten()
                });

        if old_device_id.as_deref() == Some(device_id) {
            tx.commit().await?;
            return Ok(());
        }

        let res = map_unique(
            sqlx::query("UPDATE users SET vpn_router_device_id = ?2 WHERE id = ?1")
                .bind(&user.0)
                .bind(device_id)
                .execute(&mut *tx)
                .await,
            format!("vpn_router_device_id {device_id}"),
        )?;
        if res.rows_affected() == 0 {
            return Err(SqliteInventoryError::Invalid(format!(
                "no such user: {}; cannot set vpn_router_device_id",
                user.0
            )));
        }

        let audit_payload = serde_json::json!({
            "old_vpn_router_device_id_set": old_device_id.is_some(),
            "new_vpn_router_device_id_set": true,
        });
        let payload_str = serde_json::to_string(&audit_payload)?;
        sqlx::query(
            "INSERT INTO audit_log (actor, action, target, payload)
             VALUES (?1, ?2, ?3, ?4)",
        )
        .bind("admin")
        .bind("user.set_vpn_router_device_id")
        .bind(&user.0)
        .bind(&payload_str)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    pub async fn user_with_per_server_uuid(&self, user: &User, server: &ServerId) -> Result<User> {
        match self.client_uuid_for(&user.id, server).await? {
            Some(client_uuid) if client_uuid != user.uuid => {
                Ok(user.with_per_server_uuid(&client_uuid))
            }
            _ => Ok(user.clone()),
        }
    }
}
