use crate::sqlite::{Result, SqliteInventory, SqliteInventoryError};
use std::collections::HashSet;
use std::net::{IpAddr, ToSocketAddrs};
use vpnctl_core::ServerId;

pub(super) async fn server_id_for_address_on(
    conn: &mut sqlx::SqliteConnection,
    addr: &str,
) -> Result<Option<String>> {
    let target_ip = addr.parse::<IpAddr>().ok();
    let rows = sqlx::query_as::<_, (String, String)>("SELECT id, address FROM servers ORDER BY id")
        .fetch_all(conn)
        .await?;
    Ok(rows.into_iter().find_map(|(id, address)| {
        let matches = match (target_ip, address.parse::<IpAddr>().ok()) {
            (Some(target), Some(existing)) => target == existing,
            (None, None) => addr.eq_ignore_ascii_case(&address),
            _ => false,
        };
        matches.then_some(id)
    }))
}

impl SqliteInventory {
    pub async fn is_known_server_address(&self, addr: &str) -> Result<bool> {
        let Ok(target) = addr.parse::<IpAddr>() else {
            return Ok(false);
        };
        Ok(self.known_server_ips().await?.contains(&target))
    }

    pub async fn known_server_ips(&self) -> Result<HashSet<IpAddr>> {
        let rows = sqlx::query_scalar::<_, String>(
            "SELECT address FROM servers
             UNION
             SELECT address FROM server_resolved_addresses",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .filter_map(|address| address.parse().ok())
            .collect())
    }

    pub async fn resolved_ips_for_server(&self, server_id: &ServerId) -> Result<Vec<IpAddr>> {
        let rows = sqlx::query_scalar::<_, String>(
            "SELECT address FROM server_resolved_addresses
             WHERE server_id = ?1 ORDER BY address",
        )
        .bind(&server_id.0)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .filter_map(|address| address.parse().ok())
            .collect())
    }

    pub async fn refresh_server_resolved_addresses(&self) -> Result<HashSet<IpAddr>> {
        let servers = sqlx::query_as::<_, (String, String)>("SELECT id, address FROM servers")
            .fetch_all(&self.pool)
            .await?;
        let resolved = tokio::task::spawn_blocking(move || {
            servers
                .into_iter()
                .map(|(id, address)| {
                    let ips = match address.parse::<IpAddr>() {
                        Ok(ip) => Some(vec![ip]),
                        Err(_) => (address.as_str(), 0)
                            .to_socket_addrs()
                            .ok()
                            .map(|iter| iter.map(|socket| socket.ip()).collect()),
                    };
                    (id, ips)
                })
                .collect::<Vec<_>>()
        })
        .await
        .map_err(|e| SqliteInventoryError::Invalid(format!("resolve server addresses: {e}")))?;

        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let mut all = HashSet::new();
        for (server_id, ips) in resolved {
            let Some(ips) = ips else { continue };
            sqlx::query("DELETE FROM server_resolved_addresses WHERE server_id = ?1")
                .bind(&server_id)
                .execute(&mut *tx)
                .await?;
            for ip in ips {
                all.insert(ip);
                sqlx::query(
                    "INSERT OR IGNORE INTO server_resolved_addresses (server_id, address)
                     VALUES (?1, ?2)",
                )
                .bind(&server_id)
                .bind(ip.to_string())
                .execute(&mut *tx)
                .await?;
            }
        }
        sqlx::query(
            "UPDATE sub_access_log SET is_vpn_egress = 1
             WHERE is_vpn_egress = 0
               AND ip IN (SELECT address FROM server_resolved_addresses)",
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        all.extend(self.known_server_ips().await?);
        Ok(all)
    }

    pub async fn server_id_for_address(&self, addr: &str) -> Result<Option<String>> {
        let mut conn = self.pool.acquire().await?;
        server_id_for_address_on(&mut conn, addr).await
    }

    pub async fn server_auto_suppress_state(
        &self,
        sid: &ServerId,
    ) -> Result<(bool, Option<String>)> {
        let row: Option<(i64, Option<String>)> = sqlx::query_as(
            "SELECT auto_suppress_when_unreachable, suppressed_at FROM servers WHERE id = ?1",
        )
        .bind(&sid.0)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(o, s)| (o != 0, s)).unwrap_or((false, None)))
    }

    pub async fn is_server_auto_suppressed(&self, sid: &ServerId) -> Result<bool> {
        let (opt_in, suppressed_at) = self.server_auto_suppress_state(sid).await?;
        Ok(opt_in && suppressed_at.is_some())
    }

    pub async fn set_server_auto_suppress(&self, sid: &ServerId, enabled: bool) -> Result<()> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let prior: Option<(i64, Option<String>)> = sqlx::query_as(
            "SELECT auto_suppress_when_unreachable, suppressed_at FROM servers WHERE id = ?1",
        )
        .bind(&sid.0)
        .fetch_optional(&mut *tx)
        .await?;
        let (prior_opt, prior_suppressed) = match prior {
            Some((o, s)) => (o != 0, s),
            None => {
                return Err(SqliteInventoryError::Invalid(format!(
                    "no such server '{}'; cannot set auto_suppress",
                    sid.0
                )));
            }
        };
        let new_suppressed: Option<String> = if enabled {
            prior_suppressed.clone()
        } else {
            None
        };
        if prior_opt == enabled && prior_suppressed == new_suppressed {
            tx.commit().await?;
            return Ok(());
        }
        sqlx::query(
            "UPDATE servers SET auto_suppress_when_unreachable = ?1, suppressed_at = ?2 WHERE id = ?3",
        )
        .bind(i64::from(enabled))
        .bind(&new_suppressed)
        .bind(&sid.0)
        .execute(&mut *tx)
        .await?;
        let payload = serde_json::json!({
            "server_id": sid.0,
            "enabled": enabled,
            "cleared_active_suppression": prior_suppressed.is_some() && new_suppressed.is_none(),
        });
        sqlx::query(
            "INSERT INTO audit_log (actor, action, target, payload) VALUES (?1, ?2, ?3, ?4)",
        )
        .bind("admin")
        .bind("server.auto_suppress.set")
        .bind(&sid.0)
        .bind(serde_json::to_string(&payload)?)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn is_server_udp_pair_enabled(&self, sid: &ServerId) -> Result<bool> {
        let row: Option<(i64,)> =
            sqlx::query_as("SELECT udp_pair_enabled FROM servers WHERE id = ?1")
                .bind(&sid.0)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|(v,)| v != 0).unwrap_or(false))
    }

    pub async fn set_server_udp_pair_enabled(&self, sid: &ServerId, enabled: bool) -> Result<()> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let prior: Option<(i64,)> =
            sqlx::query_as("SELECT udp_pair_enabled FROM servers WHERE id = ?1")
                .bind(&sid.0)
                .fetch_optional(&mut *tx)
                .await?;
        let prior_enabled = match prior {
            Some((o,)) => o != 0,
            None => {
                return Err(SqliteInventoryError::Invalid(format!(
                    "no such server '{}'; cannot set udp_pair_enabled",
                    sid.0
                )));
            }
        };
        if prior_enabled == enabled {
            tx.commit().await?;
            return Ok(());
        }
        sqlx::query("UPDATE servers SET udp_pair_enabled = ?1 WHERE id = ?2")
            .bind(i64::from(enabled))
            .bind(&sid.0)
            .execute(&mut *tx)
            .await?;
        let payload = serde_json::json!({ "server_id": sid.0, "enabled": enabled });
        sqlx::query(
            "INSERT INTO audit_log (actor, action, target, payload) VALUES (?1, ?2, ?3, ?4)",
        )
        .bind("admin")
        .bind("server.udp_pair.set")
        .bind(&sid.0)
        .bind(serde_json::to_string(&payload)?)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn set_server_suppressed(&self, sid: &ServerId, suppressed: bool) -> Result<bool> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let prior: Option<(Option<String>,)> =
            sqlx::query_as("SELECT suppressed_at FROM servers WHERE id = ?1")
                .bind(&sid.0)
                .fetch_optional(&mut *tx)
                .await?;
        let prior_suppressed = match prior {
            Some((s,)) => s.is_some(),
            None => {
                return Err(SqliteInventoryError::Invalid(format!(
                    "no such server '{}'; cannot set suppressed_at",
                    sid.0
                )));
            }
        };
        if prior_suppressed == suppressed {
            tx.commit().await?;
            return Ok(false);
        }
        sqlx::query(
            "UPDATE servers SET suppressed_at = CASE WHEN ?1 = 1 \
                 THEN strftime('%Y-%m-%dT%H:%M:%fZ','now') ELSE NULL END \
             WHERE id = ?2",
        )
        .bind(i64::from(suppressed))
        .bind(&sid.0)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO audit_log (actor, action, target, payload) VALUES (?1, ?2, ?3, ?4)",
        )
        .bind("vpnctld")
        .bind(if suppressed {
            "server.auto_suppressed"
        } else {
            "server.auto_restored"
        })
        .bind(&sid.0)
        .bind(serde_json::json!({ "server_id": sid.0 }).to_string())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    pub async fn update_server_address(
        &self,
        id: &ServerId,
        address: &str,
        ssh_port: u16,
        ssh_user: &str,
    ) -> Result<()> {
        if address.is_empty() {
            return Err(SqliteInventoryError::Invalid(
                "address must not be empty".into(),
            ));
        }
        sqlx::query(
            "UPDATE servers SET address = ?1, ssh_port = ?2, ssh_user = ?3,
                                 updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE id = ?4",
        )
        .bind(address)
        .bind(i64::from(ssh_port))
        .bind(ssh_user)
        .bind(&id.0)
        .execute(&self.pool)
        .await?;
        self.refresh_server_resolved_addresses().await?;
        Ok(())
    }

    pub async fn update_server_ssh_user_audited(
        &self,
        id: &ServerId,
        old_user: &str,
        new_user: &str,
        method: &str,
    ) -> Result<bool> {
        if new_user == old_user {
            return Ok(false);
        }
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let changed = sqlx::query(
            "UPDATE servers SET ssh_user = ?1,
                                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE id = ?2 AND ssh_user = ?3",
        )
        .bind(new_user)
        .bind(&id.0)
        .bind(old_user)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(SqliteInventoryError::Invalid(format!(
                "server '{}' SSH user changed concurrently",
                id.0
            )));
        }
        let payload = serde_json::json!({
            "old_ssh_user": old_user,
            "ssh_user": new_user,
            "method": method,
        });
        sqlx::query(
            "INSERT INTO audit_log (actor, action, target, payload) VALUES ('admin', 'server.ssh_user.update', ?1, ?2)",
        )
        .bind(&id.0)
        .bind(serde_json::to_string(&payload)?)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    pub async fn update_trusted_fingerprint(&self, id: &ServerId, fp: &str) -> Result<()> {
        if !vpnctl_host_fingerprint::validate_shape(fp) {
            return Err(SqliteInventoryError::Invalid(format!(
                "fingerprint must look like 'SHA256:<base64-43>', got {fp:?}"
            )));
        }
        sqlx::query(
            "UPDATE servers SET trusted_host_fingerprint = ?1,
                                 updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE id = ?2",
        )
        .bind(fp)
        .bind(&id.0)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Pin `fp` and write its audit row in one transaction; a no-op (same
    /// fingerprint already pinned) writes nothing and returns `false`.
    pub async fn update_trusted_fingerprint_audited(
        &self,
        id: &ServerId,
        fp: &str,
        actor: &str,
        source: &str,
    ) -> Result<bool> {
        if !vpnctl_host_fingerprint::validate_shape(fp) {
            return Err(SqliteInventoryError::Invalid(format!(
                "fingerprint must look like 'SHA256:<base64-43>', got {fp:?}"
            )));
        }
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let previous: Option<Option<String>> =
            sqlx::query_scalar("SELECT trusted_host_fingerprint FROM servers WHERE id = ?1")
                .bind(&id.0)
                .fetch_optional(&mut *tx)
                .await?;
        let Some(previous) = previous else {
            return Err(SqliteInventoryError::Invalid(format!(
                "no such server '{}'",
                id.0
            )));
        };
        if previous.as_deref() == Some(fp) {
            tx.commit().await?;
            return Ok(false);
        }
        sqlx::query(
            "UPDATE servers SET trusted_host_fingerprint = ?1,
                                 updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE id = ?2",
        )
        .bind(fp)
        .bind(&id.0)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO audit_log (actor, action, target, payload)
             VALUES (?1, 'server.fingerprint.set', ?2, ?3)",
        )
        .bind(actor)
        .bind(&id.0)
        .bind(
            serde_json::json!({
                "fingerprint": fp,
                "previous": previous,
                "source": source,
            })
            .to_string(),
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(true)
    }
}
