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
    /// `\"sing-box\"` key); `None` for servers whose latest row predates
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
