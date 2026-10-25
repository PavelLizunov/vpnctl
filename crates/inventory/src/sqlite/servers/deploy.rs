use crate::sqlite::{Result, SqliteInventory, SqliteInventoryError};
use sqlx::Row;
use std::collections::HashMap;
use vpnctl_core::{ServerId, UserId};

pub(crate) const DEPLOY_INPUT_REVISION_SQL: &str = "SELECT json_object(
        'server', (SELECT json_array(address, ssh_port, ssh_user, reserved_ports)
                   FROM servers WHERE id = ?1),
        'kernels', (SELECT json_group_array(kernel_id) FROM
                   (SELECT kernel_id FROM server_kernels
                    WHERE server_id = ?1 ORDER BY kernel_id)),
        'protocols', (SELECT json_group_array(protocol_id) FROM
                     (SELECT protocol_id FROM server_protocols
                      WHERE server_id = ?1 ORDER BY protocol_id)),
        'secrets', (SELECT json_group_array(json_array(key, value)) FROM
                   (SELECT key, value FROM server_secrets
                    WHERE server_id = ?1 ORDER BY key)),
        'users', (SELECT json_group_array(json_array(id, uuid, tuic_password,
                                                    wireguard_pubkey, wireguard_private)) FROM
                 (SELECT u.id AS id, COALESCE(g.client_uuid, u.uuid) AS uuid,
                         u.tuic_password AS tuic_password,
                         u.wireguard_pubkey AS wireguard_pubkey,
                         u.wireguard_private AS wireguard_private
                  FROM grants g JOIN users u ON u.id = g.user_id
                  WHERE g.server_id = ?1 AND u.disabled = 0
                  ORDER BY u.id))
    )";

impl SqliteInventory {
    pub async fn deploy_input_revision(&self, id: &ServerId) -> Result<String> {
        Ok(sqlx::query_scalar(DEPLOY_INPUT_REVISION_SQL)
            .bind(&id.0)
            .fetch_one(&self.pool)
            .await?)
    }

    pub async fn audit_deploy_if_revision(
        &self,
        actor: &str,
        id: &ServerId,
        expected: &str,
        payload: &serde_json::Value,
    ) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("UPDATE servers SET id = id WHERE id = ?1")
            .bind(&id.0)
            .execute(&mut *tx)
            .await?;
        let current: String = sqlx::query_scalar(DEPLOY_INPUT_REVISION_SQL)
            .bind(&id.0)
            .fetch_one(&mut *tx)
            .await?;
        let matches = current == expected;
        let mut payload = payload.clone();
        payload["inputs_changed"] = serde_json::Value::Bool(!matches);
        sqlx::query(
            "INSERT INTO audit_log (actor, action, target, payload)
             VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(actor)
        .bind(if matches {
            "server.deploy"
        } else {
            "server.deploy.stale"
        })
        .bind(&id.0)
        .bind(payload.to_string())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(matches)
    }

    pub async fn get_reserved_ports(&self, sid: &ServerId) -> Result<Vec<u16>> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT reserved_ports FROM servers WHERE id = ?1")
                .bind(&sid.0)
                .fetch_optional(&self.pool)
                .await?;
        let json = match row {
            Some((s,)) => s,
            None => return Ok(Vec::new()),
        };
        let parsed: Vec<u16> = serde_json::from_str(&json).unwrap_or_default();
        Ok(parsed)
    }

    pub async fn set_reserved_ports(&self, sid: &ServerId, ports: &[u16]) -> Result<()> {
        let mut sorted: Vec<u16> = ports.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        let new_json = serde_json::to_string(&sorted)?;

        let mut tx = self.pool.begin().await?;

        let prior: Option<(String,)> =
            sqlx::query_as("SELECT reserved_ports FROM servers WHERE id = ?1")
                .bind(&sid.0)
                .fetch_optional(&mut *tx)
                .await?;
        let prior_json = match prior {
            Some((s,)) => s,
            None => {
                return Err(SqliteInventoryError::Invalid(format!(
                    "no such server '{}'; cannot set reserved_ports",
                    sid.0
                )));
            }
        };

        if prior_json == new_json {
            tx.commit().await?;
            return Ok(());
        }

        sqlx::query("UPDATE servers SET reserved_ports = ?1 WHERE id = ?2")
            .bind(&new_json)
            .bind(&sid.0)
            .execute(&mut *tx)
            .await?;

        let payload = serde_json::json!({
            "server_id": sid.0,
            "old": serde_json::from_str::<serde_json::Value>(&prior_json).unwrap_or(serde_json::json!([])),
            "new": sorted,
        });
        let payload_str = serde_json::to_string(&payload)?;
        sqlx::query(
            "INSERT INTO audit_log (actor, action, target, payload)
             VALUES (?1, ?2, ?3, ?4)",
        )
        .bind("admin")
        .bind("server.reserved_ports.set")
        .bind(&sid.0)
        .bind(payload_str)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    pub async fn set_server_secret(&self, id: &ServerId, key: &str, value: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO server_secrets (server_id, key, value) VALUES (?1, ?2, ?3)
             ON CONFLICT(server_id, key) DO UPDATE SET value = excluded.value",
        )
        .bind(&id.0)
        .bind(key)
        .bind(value)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(crate) async fn initialize_server_secret_set(
        &self,
        id: &ServerId,
        candidates: &[(&str, String)],
    ) -> Result<(HashMap<String, String>, bool)> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let mut stored = HashMap::with_capacity(candidates.len());
        for (key, _) in candidates {
            let value: Option<String> = sqlx::query_scalar(
                "SELECT value FROM server_secrets WHERE server_id = ?1 AND key = ?2",
            )
            .bind(&id.0)
            .bind(key)
            .fetch_optional(&mut *tx)
            .await?;
            if let Some(value) = value {
                stored.insert((*key).to_string(), value);
            }
        }
        if !stored.is_empty() && stored.len() != candidates.len() {
            let keys: Vec<_> = candidates.iter().map(|(key, _)| *key).collect();
            return Err(SqliteInventoryError::Invalid(format!(
                "incomplete server secret set ({}); refusing to replace existing keys",
                keys.join(", ")
            )));
        }
        let minted = stored.is_empty();
        if minted {
            for (key, value) in candidates {
                sqlx::query(
                    "INSERT INTO server_secrets (server_id, key, value) VALUES (?1, ?2, ?3)",
                )
                .bind(&id.0)
                .bind(key)
                .bind(value)
                .execute(&mut *tx)
                .await?;
                sqlx::query(
                    "INSERT INTO audit_log (actor, action, target, payload)
                     VALUES ('system', 'server.secret.set', ?1, ?2)",
                )
                .bind(&id.0)
                .bind(serde_json::json!({ "key": key }).to_string())
                .execute(&mut *tx)
                .await?;
                stored.insert((*key).to_string(), value.clone());
            }
        }
        tx.commit().await?;
        Ok((stored, minted))
    }

    pub async fn get_server_secret(&self, id: &ServerId, key: &str) -> Result<Option<String>> {
        let row = sqlx::query("SELECT value FROM server_secrets WHERE server_id = ?1 AND key = ?2")
            .bind(&id.0)
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|r| r.try_get::<String, _>("value"))
            .transpose()
            .map_err(Into::into)
    }

    pub async fn list_server_secrets(&self, id: &ServerId) -> Result<HashMap<String, String>> {
        let rows = sqlx::query("SELECT key, value FROM server_secrets WHERE server_id = ?1")
            .bind(&id.0)
            .fetch_all(&self.pool)
            .await?;
        let mut map = HashMap::with_capacity(rows.len());
        for r in rows {
            map.insert(r.try_get("key")?, r.try_get("value")?);
        }
        Ok(map)
    }

    pub async fn servers_pending_deploy_for_user(
        &self,
        user_id: &UserId,
        granted_server_ids: &[ServerId],
    ) -> Result<Vec<ServerId>> {
        if granted_server_ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut out: Vec<ServerId> = Vec::new();
        for sid in granted_server_ids {
            let user_row = sqlx::query(
                "SELECT MAX(id) AS id FROM audit_log
                 WHERE target = ?1
                   AND (
                     (action IN ('user.grant', 'user.revoke')
                        AND (json_extract(payload, '$.server') = ?2
                             OR json_extract(payload, '$.server') IS NULL))
                     OR action IN ('user.add',
                                   'user.set_vpn_router_device_id',
                                   'user.disable', 'user.enable',
                                   'user.wireguard.regen',
                                   'user.mint_tuic_password',
                                   'boosty.disable', 'boosty.enable')
                   )",
            )
            .bind(&user_id.0)
            .bind(&sid.0)
            .fetch_one(&self.pool)
            .await?;
            let user_latest_id: Option<i64> = user_row.try_get("id")?;
            let Some(user_latest_id) = user_latest_id else {
                continue;
            };
            let row = sqlx::query(
                "SELECT MAX(id) AS id FROM audit_log
                 WHERE target = ?1 AND action = 'server.deploy'",
            )
            .bind(&sid.0)
            .fetch_one(&self.pool)
            .await?;
            let deploy_id: Option<i64> = row.try_get("id")?;
            match deploy_id {
                None => out.push(sid.clone()),
                Some(id) if id < user_latest_id => out.push(sid.clone()),
                _ => {}
            }
        }
        Ok(out)
    }

    pub async fn server_pending_deploy(&self, server_id: &ServerId) -> Result<bool> {
        let row = sqlx::query(
            "SELECT MAX(id) AS id FROM audit_log
             WHERE (action IN ('user.grant', 'user.revoke')
                    AND json_extract(payload, '$.server') = ?1)
                OR (action IN ('server.protocol.enable', 'server.protocol.disable',
                               'server.kernel.enable', 'server.kernel.disable',
                               'server.reserved_ports.set', 'server.udp_pair.set',
                               'server.reality.set', 'server.naive.set',
                               'server.vlessws.set', 'server.secret.set')
                    AND target = ?1)
                OR (action IN ('user.add', 'user.set_vpn_router_device_id',
                               'user.disable', 'user.enable', 'user.wireguard.regen',
                               'user.mint_tuic_password', 'boosty.disable', 'boosty.enable')
                    AND target IN (SELECT user_id FROM grants WHERE server_id = ?1))",
        )
        .bind(&server_id.0)
        .fetch_one(&self.pool)
        .await?;
        let mutation_id: Option<i64> = row.try_get("id")?;
        let Some(mutation_id) = mutation_id else {
            return Ok(false);
        };
        let row = sqlx::query(
            "SELECT MAX(id) AS id FROM audit_log
             WHERE target = ?1 AND action = 'server.deploy'",
        )
        .bind(&server_id.0)
        .fetch_one(&self.pool)
        .await?;
        let deploy_id: Option<i64> = row.try_get("id")?;
        Ok(match deploy_id {
            None => true,
            Some(id) => id < mutation_id,
        })
    }

    pub async fn kernel_versions_fleet(&self) -> Result<Vec<(ServerId, Option<String>)>> {
        let rows = sqlx::query(
            "SELECT nh.server_id AS server_id,
                    nh.kernel_versions_json AS kernel_versions_json
             FROM node_health nh
             WHERE nh.ts = (SELECT MAX(nh2.ts)
                            FROM node_health nh2
                            WHERE nh2.server_id = nh.server_id)
             ORDER BY nh.server_id",
        )
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let sid: String = r.try_get("server_id")?;
            let json: Option<String> = r.try_get("kernel_versions_json")?;
            out.push((ServerId(sid), json));
        }
        Ok(out)
    }
}
