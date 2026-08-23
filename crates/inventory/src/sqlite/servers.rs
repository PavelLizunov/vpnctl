use super::*;
use sqlx::Row;
use std::collections::HashMap;
use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, UserId};

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
    // ── Servers ─────────────────────────────────────────────────────────

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
        let Ok(target) = addr.parse::<std::net::IpAddr>() else {
            return Ok(false);
        };
        Ok(self.known_server_ips().await?.contains(&target))
    }

    /// Canonical server IPs from literal inventory addresses plus the latest
    /// hostname-resolution cache.
    pub async fn known_server_ips(&self) -> Result<std::collections::HashSet<std::net::IpAddr>> {
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
    pub async fn resolved_ips_for_server(
        &self,
        server_id: &ServerId,
    ) -> Result<Vec<std::net::IpAddr>> {
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
    pub async fn refresh_server_resolved_addresses(
        &self,
    ) -> Result<std::collections::HashSet<std::net::IpAddr>> {
        use std::net::ToSocketAddrs;

        let servers = sqlx::query_as::<_, (String, String)>("SELECT id, address FROM servers")
            .fetch_all(&self.pool)
            .await?;
        let resolved = tokio::task::spawn_blocking(move || {
            servers
                .into_iter()
                .map(|(id, address)| {
                    let ips = match address.parse::<std::net::IpAddr>() {
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
        let mut all = std::collections::HashSet::new();
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

    /// Stable snapshot of every inventory value that can change a node
    /// deploy. Compare before/after the SSH work so a concurrent Web edit
    /// cannot be masked by a later canonical `server.deploy` audit row.
    pub async fn deploy_input_revision(&self, id: &ServerId) -> Result<String> {
        Ok(sqlx::query_scalar(DEPLOY_INPUT_REVISION_SQL)
            .bind(&id.0)
            .fetch_one(&self.pool)
            .await?)
    }

    /// Atomically compare deploy inputs and write either the canonical
    /// baseline or a stale attempt. The no-op UPDATE acquires SQLite's write
    /// lock before the comparison, so no mutation can commit between them.
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

    pub async fn update_trusted_fingerprint(&self, id: &ServerId, fp: &str) -> Result<()> {
        // Defensive validation — a malicious or buggy caller could otherwise
        // store an empty / arbitrary value, after which every future connect
        // silently rejects the real host key with a useless error.
        //
        // Shape check lives in `vpnctl-host-fingerprint` so the CLI, web
        // handler, wizard SSE pipeline, and this final inventory gate all
        // agree on what "valid" means (until 2026-05-18 they did not —
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
    /// distinguish "already there" from "just added" if it wants to
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

    async fn list_server_protocols(&self, id: &ServerId) -> Result<Vec<ProtocolId>> {
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
    /// distinguish "not enabled" from "enabled but visible".
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
        // for the "no such row" check.
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
        // pollute audit_log. "One audit row per mutation" invariant
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

    /// Read the per-server reserved-ports list (migration 0028).
    /// Returns an empty Vec for servers that haven't had any ports
    /// reserved — most installs are byte-equivalent to pre-0028
    /// behaviour. Returns `Ok(vec![])` if the server doesn't exist
    /// (caller already passed an unknown id — no need to double-
    /// report; the deploy path will fail later with a useful
    /// «unknown server» error).
    ///
    /// Stored as a JSON array of u16. Parse failures (corrupted DB)
    /// degrade to empty — fail-OPEN on read because a wrong empty is
    /// safer than crash-looping the deploy path; the write side
    /// (`set_reserved_ports`) is the authoritative validator.
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
        // Lenient parse — operator could have hand-edited the row in
        // sqlite3, or a future schema migration could change shape.
        // Either way, the deploy guard fails open on parse error.
        let parsed: Vec<u16> = serde_json::from_str(&json).unwrap_or_default();
        Ok(parsed)
    }

    /// Replace the per-server reserved-ports list. `ports` is
    /// caller-validated to fit u16 (the parsing layer in admin /
    /// CLI rejects values outside 1..=65535 before calling). The
    /// stored format is a JSON array; duplicates are de-duped and
    /// the array is sorted ascending so `audit_log` payloads diff
    /// cleanly across calls.
    ///
    /// Writes one `server.reserved_ports.set` audit row whenever the
    /// stored value would change (NM-10 audit-on-actual-mutation
    /// contract). Idempotent re-saves of the same list are silent.
    /// Errors with `Invalid` if `sid` doesn't exist (matches the
    /// behaviour of `set_server_fingerprint` — caller passing an
    /// unknown id is a logic bug, not an expected condition).
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

        // Audit payload carries both old + new sorted lists so
        // operator can diff at a glance from the audit timeline.
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
        // mutation (review-agent 2026-05-20 "audit-per-mutation"
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
    /// cards can render an accurate "visible vs hidden" breakdown
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

    // ── Server secrets ──────────────────────────────────────────────────

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

    // ── Aggregations (read-only, used by daemon dashboard / list views) ──

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

    /// **Pending-deploy detection** (Option B from the 2026-05-23
    /// «user-create → silent server miss» quickfix discussion).
    ///
    /// Given a user_id + list of granted server_ids, return the
    /// subset of servers whose **latest `server.deploy` audit row
    /// is older than the user's latest mutation** (`user.add`,
    /// `user.grant`, `user.revoke`, `user.set_vpn_router_device_id`,
    /// `user.disable`, `user.enable`, and the Boosty-bridge flips
    /// `boosty.disable` / `boosty.enable`). Those servers' running sing-box
    /// config does NOT yet include the user's current state — clicking
    /// their detail page's «deploy» button pushes the fresh render and
    /// closes the gap.
    ///
    /// **Scoped since 2026-07-10** (was «coarse by design» before):
    /// `user.grant` / `user.revoke` rows count only against the server
    /// named in their `payload.server` — post-#92 the grant path
    /// auto-deploys that very server, so the old any-mutation-flags-
    /// every-server rule left a permanent phantom banner on all OTHER
    /// nodes after each grant (live repro: granting main-brat on `us`
    /// flagged cdn/de/is/nl «not deployed» though nothing about them
    /// changed). Genuinely server-agnostic mutations (`user.add`,
    /// device-id, disable/enable — they alter every node's desired
    /// config) still flag ALL granted servers, and legacy grant rows
    /// WITHOUT a `payload.server` field keep the old coarse reading
    /// (can't tell which server → assume relevant).
    ///
    /// **`None`-deploy case:** a server with no successful deploy audit
    /// baseline is pending if the user has any relevant mutation.
    ///
    /// **Only SUCCESSFUL deploys count as a baseline:** all deploy paths
    /// reserve the canonical `server.deploy` action for a config actually
    /// applied from an unchanged inventory revision. Failed, skipped, and
    /// stale attempts use distinct actions and cannot clear the banner.
    pub async fn servers_pending_deploy_for_user(
        &self,
        user_id: &UserId,
        granted_server_ids: &[ServerId],
    ) -> Result<Vec<ServerId>> {
        if granted_server_ids.is_empty() {
            return Ok(Vec::new());
        }
        // For each granted server: latest RELEVANT user-mutation id
        // (grant/revoke scoped to this server via payload.server;
        // server-agnostic mutations + legacy no-payload rows always
        // relevant) vs the server's latest good deploy. Loop is cheap
        // at homelab scale (≤100 servers ⇒ ≤200 indexed lookups).
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
                // No mutation relevant to this server (legacy import
                // with zero audit rows, or all grants target other
                // nodes) — nothing to flag here.
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
            // Pending if: no deploy ever recorded (None) OR last
            // deploy is older than the user's last relevant change.
            match deploy_id {
                None => out.push(sid.clone()),
                Some(id) if id < user_latest_id => out.push(sid.clone()),
                _ => {}
            }
        }
        Ok(out)
    }

    /// **Server-side pending-deploy detection** (audit 2026-06-10,
    /// review follow-up to the revoke unification). The per-user
    /// detector above can't cover one case at all: after a REVOKE the
    /// server leaves the user's granted list, so no user-detail banner
    /// will ever mention it — yet that node is exactly the one still
    /// running the revoked UUID. This is the server-detail counterpart:
    /// «has this server's grant MEMBERSHIP changed since its last
    /// deploy?»
    ///
    /// Keys on the canonical per-user rows (`user.grant` /
    /// `user.revoke`) via their `payload.server` field — both written
    /// since the 2026-06-04/2026-06-10 unifications, and only for
    /// ACTUAL mutations, so an idempotent re-grant can't raise a false
    /// pending here. Pre-unification legacy rows (`action='grant'`,
    /// target=server) are invisible to this query — acceptable: any
    /// server deployed since then has a fresher `server.deploy` row
    /// anyway.
    ///
    /// Scope is membership only (grant/revoke). Other user mutations
    /// (disable, device-id) surface through the per-user banner on
    /// every granted server — duplicating them here would make the
    /// server banner near-permanent on busy inventories.
    ///
    /// Only the canonical successful `server.deploy` action counts as a
    /// baseline, matching `servers_pending_deploy_for_user`.
    pub async fn server_pending_deploy(&self, server_id: &ServerId) -> Result<bool> {
        let row = sqlx::query(
            "SELECT MAX(id) AS id FROM audit_log
             WHERE (action IN ('user.grant', 'user.revoke')
                    AND json_extract(payload, '$.server') = ?1)
                OR (action IN ('server.protocol.enable', 'server.protocol.disable',
                               'server.kernel.enable', 'server.kernel.disable')
                    AND target = ?1)",
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

    /// **Q-4e** — newest `kernel_versions_json` per server across the
    /// fleet. Returns the raw JSON string (caller extracts the
    /// `"sing-box"` key); `None` for servers whose latest row predates
    /// version capture or had no versions. Backs the dashboard
    /// kernel-version fleet card. Served by `idx_node_health_server_ts`.
    pub async fn kernel_versions_fleet(&self) -> Result<Vec<(ServerId, Option<String>)>> {
        // Correlated subquery picks the newest ts per server; the outer
        // row then reads that row's JSON. One row per server.
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
