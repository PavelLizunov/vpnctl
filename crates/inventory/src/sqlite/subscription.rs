use std::collections::{HashMap, HashSet};

use sqlx::Row;
use vpnctl_core::{ProtocolId, Server, ServerId, User, UserId};

use super::users::crud::row_to_user;
use super::{Result, SqliteInventory, SqliteInventoryError};

/// Request-local inputs shared by all app-config protocol collectors.
pub struct SubscriptionServer {
    pub server: Server,
    pub suppressed: bool,
    pub detour_via: Option<ServerId>,
    pub display_name: Option<String>,
    pub udp_pair: bool,
    pub client_uuid: String,
    pub visible: Vec<ProtocolId>,
    pub secrets: HashMap<String, String>,
    pub peers: Vec<User>,
    pub wg_octets: HashMap<UserId, u16>,
}

// Manual impl: secrets and peer credentials must never reach debug output.
impl std::fmt::Debug for SubscriptionServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubscriptionServer")
            .field("server", &self.server.id)
            .field("suppressed", &self.suppressed)
            .field("detour_via", &self.detour_via)
            .field("udp_pair", &self.udp_pair)
            .field("visible", &self.visible)
            .field("peers", &self.peers.len())
            .finish_non_exhaustive()
    }
}

impl SqliteInventory {
    /// Load inputs in server order; only missing WG addresses need extra transactions.
    pub async fn subscription_render_inputs(
        &self,
        user: &UserId,
        include_awg_peers: bool,
    ) -> Result<Vec<SubscriptionServer>> {
        let servers = self.subscription_servers_for_user(user).await?;
        let mut inputs = HashMap::with_capacity(servers.len());
        let rows = sqlx::query(
            "SELECT s.id, s.auto_suppress_when_unreachable, s.suppressed_at,
                    s.client_detour_via, s.display_name, s.udp_pair_enabled,
                    COALESCE(g.client_uuid, u.uuid) AS uuid
             FROM servers s JOIN grants g ON g.server_id = s.id
             JOIN users u ON u.id = g.user_id
             WHERE g.user_id = ?1 AND s.role = 'vpn-exit'",
        )
        .bind(&user.0)
        .fetch_all(&self.pool)
        .await?;
        let mut server_map: HashMap<_, _> =
            servers.iter().map(|s| (s.id.clone(), s.clone())).collect();
        for row in rows {
            let id = ServerId(row.try_get("id")?);
            let Some(server) = server_map.remove(&id) else {
                continue;
            };
            inputs.insert(
                id,
                SubscriptionServer {
                    server,
                    suppressed: row.try_get::<i64, _>("auto_suppress_when_unreachable")? != 0
                        && row.try_get::<Option<String>, _>("suppressed_at")?.is_some(),
                    detour_via: row
                        .try_get::<Option<String>, _>("client_detour_via")?
                        .map(ServerId),
                    display_name: row
                        .try_get::<Option<String>, _>("display_name")?
                        .filter(|name| !name.trim().is_empty()),
                    udp_pair: row.try_get::<i64, _>("udp_pair_enabled")? != 0,
                    client_uuid: row.try_get("uuid")?,
                    visible: Vec::new(),
                    secrets: HashMap::new(),
                    peers: Vec::new(),
                    wg_octets: HashMap::new(),
                },
            );
        }
        let rows = sqlx::query(
            "SELECT ss.server_id, ss.key, ss.value FROM server_secrets ss
             JOIN grants g ON g.server_id = ss.server_id WHERE g.user_id = ?1",
        )
        .bind(&user.0)
        .fetch_all(&self.pool)
        .await?;
        for row in rows {
            if let Some(input) = inputs.get_mut(&ServerId(row.try_get("server_id")?)) {
                input
                    .secrets
                    .insert(row.try_get("key")?, row.try_get("value")?);
            }
        }
        let rows = sqlx::query(
            "SELECT sp.server_id, sp.protocol_id FROM server_protocols sp
             JOIN grants g ON g.server_id = sp.server_id
             WHERE g.user_id = ?1 AND sp.hidden = 0 AND NOT EXISTS (
                 SELECT 1 FROM grant_protocol_overrides gpo
                 WHERE gpo.user_id = ?1 AND gpo.server_id = sp.server_id
                   AND gpo.protocol_id = sp.protocol_id AND gpo.state = 'disabled'
             ) ORDER BY sp.server_id, sp.protocol_id",
        )
        .bind(&user.0)
        .fetch_all(&self.pool)
        .await?;
        for row in rows {
            if let Some(input) = inputs.get_mut(&ServerId(row.try_get("server_id")?)) {
                input.visible.push(ProtocolId(row.try_get("protocol_id")?));
            }
        }
        if include_awg_peers {
            let mut missing_octets = HashSet::new();
            let rows = sqlx::query(
                "SELECT g.server_id, u.id, COALESCE(g.client_uuid, u.uuid) AS uuid,
                        u.tuic_password, u.wireguard_pubkey, u.wireguard_private,
                        u.sub_token, u.vpn_router_device_id, u.disabled, g.wg_octet
                 FROM users u JOIN grants g ON g.user_id = u.id
                 WHERE u.disabled = 0 AND g.server_id IN (
                     SELECT own.server_id FROM grants own JOIN server_protocols sp
                       ON sp.server_id = own.server_id
                     WHERE own.user_id = ?1
                       AND sp.protocol_id IN ('wireguard', 'amneziawg2', 'amneziawg3')
                 ) ORDER BY g.server_id, u.id",
            )
            .bind(&user.0)
            .fetch_all(&self.pool)
            .await?;
            for row in rows {
                if let Some(input) = inputs.get_mut(&ServerId(row.try_get("server_id")?)) {
                    if input
                        .server
                        .enabled_protocols
                        .iter()
                        .any(|p| p.0 == "wireguard")
                    {
                        if let Some(octet) = row.try_get::<Option<i64>, _>("wg_octet")? {
                            let octet = u16::try_from(octet).map_err(|_| {
                                SqliteInventoryError::Invalid(format!(
                                    "invalid WireGuard octet {octet}"
                                ))
                            })?;
                            input.wg_octets.insert(UserId(row.try_get("id")?), octet);
                        } else {
                            missing_octets.insert(input.server.id.clone());
                        }
                    }
                    input.peers.push(row_to_user(row)?);
                }
            }
            for server in missing_octets {
                if let Some(input) = inputs.get_mut(&server) {
                    input.wg_octets = self.wg_octets_for_server(&server).await?;
                }
            }
        }
        Ok(servers
            .into_iter()
            .filter_map(|s| inputs.remove(&s.id))
            .collect())
    }
}
