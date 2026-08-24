use crate::sqlite::{Result, SqliteInventory, SqliteInventoryError};
use std::collections::HashSet;
use std::net::{IpAddr, ToSocketAddrs};
use vpnctl_core::ServerId;

impl SqliteInventory {
    /// `true` if `addr` is one of the canonical IPs currently belonging to a
    /// registered server. Literal IPv4/IPv6 addresses are canonicalised;
    /// hostnames are resolved off the async runtime and cached in SQLite.
    /// Used by the subscription rate-limiter to EXEMPT our own VPN-egress
    /// IPs: a client connected through a node has its config-refresh
    /// egress that node, so vpnctld sees the SERVER's IP. Without this
    /// exemption, N users on one server collapse into a single per-IP
    /// bucket and throttle each other (Pavel 2026-06-01: "может
    /// одновременно прийти 33 обновления если все будут на одном
    /// конфиге"). Cheap — the servers table is a handful of rows. Same
    /// membership the `sub_access_log.is_vpn_egress` trigger computes.
    pub async fn is_known_server_address(&self, addr: &str) -> Result<bool> {
        let Ok(target) = addr.parse::<IpAddr>() else {
            return Ok(false);
        };
        Ok(self.known_server_ips().await?.contains(&target))
    }

    /// Canonical server IPs from literal inventory addresses plus the latest
    /// hostname-resolution cache.
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

    /// Canonical resolved addresses for one server, used by direct
    /// service-path probes. Literal IP addresses are cached at creation;
    /// hostnames are refreshed by the existing resolver.
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

    /// Resolve every server address and atomically refresh the canonical-IP
    /// cache. DNS work stays off Tokio workers; failed lookups retain their
    /// last known-good cache rows.
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

        let mut tx = self.pool.begin().await?;
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

    /// Return the id of the first server already registered with `addr`,
    /// or `None`. Backs the add-server duplicate-address guard used by
    /// both quick-add and the wizard: two inventory records for one
    /// physical node fight over that node's `users[]`, and the second
    /// deploy trips the DG-1 user-removal guard — the `us`/`us1` incident
    /// (2026-07-08) where a duplicate record's empty-grants deploy would
    /// have wiped the working record's users. Cheap — the servers table
    /// is a handful of rows.
    pub async fn server_id_for_address(&self, addr: &str) -> Result<Option<String>> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT id FROM servers WHERE address = ?1 ORDER BY id LIMIT 1")
                .bind(addr)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|(id,)| id))
    }

    /// Auto-suppress state for a server (migration 0030): the per-server
    /// opt-in + the current runtime `suppressed_at` timestamp. Returns
    /// `(opt_in, suppressed_at)`; `(false, None)` for an unknown id.
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

    /// Subscription-render gate: `true` iff this server should be hidden
    /// from subscriptions RIGHT NOW — opt-in ON **and** currently flagged
    /// suppressed. Checked per-server in the `/sub` + `/api/v1/app/config`
    /// render loops, on TOP of the per-protocol visibility filter.
    pub async fn is_server_auto_suppressed(&self, sid: &ServerId) -> Result<bool> {
        let (opt_in, suppressed_at) = self.server_auto_suppress_state(sid).await?;
        Ok(opt_in && suppressed_at.is_some())
    }

    /// Set the per-server auto-suppress OPT-IN. Turning it OFF also
    /// clears any live `suppressed_at` (the server returns to the
    /// subscription immediately — the operator overrode the automation).
    /// Audit-on-actual-change (`server.auto_suppress.set`); `Invalid` on
    /// unknown id.
    pub async fn set_server_auto_suppress(&self, sid: &ServerId, enabled: bool) -> Result<()> {
        let mut tx = self.pool.begin().await?;
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
        // Turning the opt-in off also lifts an active suppression.
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

    /// Subscription-render flag (migration 0031, UX-3): `true` iff the
    /// operator enabled naive↔HY2 UDP pairing on this server. When ON **and**
    /// the server exposes BOTH naive and hysteria2, the `/api/v1/app/config`
    /// render stamps both share-links with a shared `pair=<server id>` so a
    /// client can route UDP — which naive can't carry — over the co-located
    /// HY2. Default false; no such server → false.
    pub async fn is_server_udp_pair_enabled(&self, sid: &ServerId) -> Result<bool> {
        let row: Option<(i64,)> =
            sqlx::query_as("SELECT udp_pair_enabled FROM servers WHERE id = ?1")
                .bind(&sid.0)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|(v,)| v != 0).unwrap_or(false))
    }

    /// Set the per-server naive↔HY2 UDP-pairing opt-in (migration 0031).
    /// Pure boolean — no side effects. Audit-on-actual-change
    /// (`server.udp_pair.set`); `Invalid` on unknown id.
    pub async fn set_server_udp_pair_enabled(&self, sid: &ServerId, enabled: bool) -> Result<()> {
        let mut tx = self.pool.begin().await?;
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

    /// Monitor-driven: set or clear the runtime `suppressed_at` flag.
    /// Idempotent — only writes (and audits) on an actual transition;
    /// returns `true` when it changed. Audits `server.auto_suppressed`
    /// (set) or `server.auto_restored` (clear). The CALLER gates on the
    /// opt-in before setting; clearing is always honoured (so a recovery
    /// lifts suppression even if the opt-in was toggled off meanwhile).
    /// `Invalid` on unknown id.
    pub async fn set_server_suppressed(&self, sid: &ServerId, suppressed: bool) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
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
        // Timestamp generated SQL-side to match the rest of the schema's
        // `strftime` ISO-8601-millis format.
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

    /// Replace a server's `address` + `ssh_port` + `ssh_user` in
    /// place. Used by the `--overwrite-existing` path of
    /// `vpnctl migrate from-bash` when an operator's earlier
    /// wizard-test created a server row with a stale IP that the
    /// migration needs to correct. Does NOT touch kernels,
    /// protocols, or secrets (those have their own setters); the
    /// scope is intentionally narrow so an accidental call can't
    /// nuke unrelated state.
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

    /// Update only the SSH login and record the mutation atomically.
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
        let mut tx = self.pool.begin().await?;
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
        // Defensive validation — a malicious or buggy caller could otherwise
        // store an empty / arbitrary value, after which every future connect
        // silently rejects the real host key with a useless error.
        //
        // Shape check lives in `vpnctl-host-fingerprint` so the CLI, web
        // handler, wizard SSE pipeline, and this final inventory gate all
        // agree on what \"valid\" means (until 2026-05-18 they did not —
        // the inventory variant rejected URL-safe base64 that the surface
        // validators accepted, producing a confusing late failure).
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
}
