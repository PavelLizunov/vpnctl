use crate::sqlite::base::SqliteInventory;
use crate::sqlite::models::{Result, SqliteInventoryError};
use crate::sqlite::users::crud::row_to_user;
use chrono::{DateTime, Utc};
use sqlx::Row;
use std::collections::HashMap;
use vpnctl_core::{Server, ServerId, User, UserId};

/// Find an EXISTING grant on `server_id` whose **effective** VLESS uuid
/// (`COALESCE(grants.client_uuid, users.uuid)`) equals `candidate_uuid`,
/// ignoring grants that belong to `exclude_user`. Returns that other user's
/// id, or `None` when `candidate_uuid` is free to use on the server.
///
/// This is the core of the per-server uuid-uniqueness invariant. Two users
/// sharing one effective uuid on a node make sing-box dedup them, so one
/// silently fails to connect (HANDOFF §4.1 — the `main-brat@de` incident).
/// `users.uuid` is globally UNIQUE, but `grants.client_uuid` has no such
/// constraint and the effective value spans two tables, so the invariant is
/// enforced in code (write-time) + a pre-deploy assertion rather than via a
/// single-column UNIQUE index.\n///
/// Generic over the executor so callers can run it on the pool (`grant`) or
/// inside an already-open transaction (`set_grant_client_uuid`).
pub(super) async fn find_effective_uuid_conflict<'e, E>(
    executor: E,
    server_id: &str,
    candidate_uuid: &str,
    exclude_user: &str,
) -> Result<Option<(String, bool)>>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    let row = sqlx::query(
        "SELECT g.user_id AS who, u.disabled AS who_disabled
         FROM grants g
         INNER JOIN users u ON u.id = g.user_id
         WHERE g.server_id = ?1
           AND g.user_id <> ?2
           AND COALESCE(g.client_uuid, u.uuid) = ?3
         LIMIT 1",
    )
    .bind(server_id)
    .bind(exclude_user)
    .bind(candidate_uuid)
    .fetch_optional(executor)
    .await?;
    // Returns the conflicting user's id AND whether it is disabled — a disabled
    // user is invisible in the admin UI but still owns the uuid, so surfacing
    // that in the error stops the operator from chasing a \"ghost\".
    match row {
        None => Ok(None),
        Some(r) => {
            let who: String = r.try_get("who")?;
            let who_disabled: i64 = r.try_get("who_disabled")?;
            Ok(Some((who, who_disabled != 0)))
        }
    }
}

impl SqliteInventory {
    // ── Grants (user × server) ──────────────────────────────────────────

    /// Grant `user` access to `server`. Idempotent — re-granting an existing
    /// (user, server) pair is a no-op.
    ///
    /// **uuid-uniqueness invariant (HANDOFF §4.1).** A fresh grant's effective
    /// VLESS uuid is the user's GLOBAL `users.uuid` (the new row's
    /// `client_uuid` is NULL). If another user already resolves to that same
    /// effective uuid on this server, sing-box would dedup the two and one of
    /// them would silently fail to connect — so we reject the grant rather
    /// than mint a config that bricks a user. This can only happen when some
    /// *other* grant carries a `client_uuid` override equal to this user's
    /// global uuid (exactly the `main-brat@de` pathology). The check spans all
    /// users (incl. disabled) so a later re-enable can't surface a latent
    /// collision. Re-granting an existing pair skips the check so it never
    /// trips over pre-existing (legacy) data.
    pub async fn grant(&self, user: &UserId, server: &ServerId) -> Result<()> {
        let mut tx = self.pool.begin().await?;

        let server_role: Option<(String,)> =
            sqlx::query_as("SELECT role FROM servers WHERE id = ?1")
                .bind(&server.0)
                .fetch_optional(&mut *tx)
                .await?;

        let Some((role_str,)) = server_role else {
            return Err(SqliteInventoryError::Invalid(format!(
                "no such server {}; cannot grant",
                server.0
            )));
        };

        if role_str == "workload-only" {
            return Err(SqliteInventoryError::Invalid(format!(
                "cannot grant access to workload-only server '{}'",
                server.0
            )));
        }

        // Already granted? Idempotent no-op (preserves the prior
        // `ON CONFLICT DO NOTHING` semantics) — and skip the collision check.
        let already = sqlx::query("SELECT 1 FROM grants WHERE user_id = ?1 AND server_id = ?2")
            .bind(&user.0)
            .bind(&server.0)
            .fetch_optional(&mut *tx)
            .await?
            .is_some();
        if already {
            tx.commit().await?;
            return Ok(());
        }

        // Fresh grant ⇒ effective uuid will be the user's global uuid.
        let user_uuid: String = sqlx::query("SELECT uuid FROM users WHERE id = ?1")
            .bind(&user.0)
            .fetch_optional(&mut *tx)
            .await?
            .map(|r| r.try_get::<String, _>("uuid"))
            .transpose()?
            .ok_or_else(|| {
                SqliteInventoryError::Invalid(format!("no such user {}; cannot grant", user.0))
            })?;

        if let Some((other, other_disabled)) =
            find_effective_uuid_conflict(&mut *tx, &server.0, &user_uuid, &user.0).await?
        {
            let dis = if other_disabled {
                " (disabled — hidden in the UI)"
            } else {
                ""
            };
            return Err(SqliteInventoryError::AlreadyExists(format!(
                "effective uuid {user_uuid} on server {} is already used by user {other}{dis}; \
                 refusing to grant {} — they would collide and one would be bricked on the node",
                server.0, user.0
            )));
        }

        sqlx::query(
            "INSERT INTO grants (user_id, server_id, granted_at)
             VALUES (?1, ?2, datetime('now'))
             ON CONFLICT(user_id, server_id) DO NOTHING",
        )
        .bind(&user.0)
        .bind(&server.0)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Design v2 3d — grant timestamps for one server's grants table.
    /// `granted_at` is NULL for grants created before migration 0039;
    /// the UI renders those as \"—\".
    pub async fn grant_dates_for_server(
        &self,
        server: &ServerId,
    ) -> Result<Vec<(UserId, Option<DateTime<Utc>>)>> {
        let rows = sqlx::query(
            "SELECT user_id, granted_at FROM grants WHERE server_id = ?1 ORDER BY user_id",
        )
        .bind(&server.0)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|r| {
                let uid: String = r.try_get("user_id")?;
                let ts: Option<String> = r.try_get("granted_at")?;
                let parsed = ts.and_then(|s| {
                    chrono::NaiveDateTime::parse_from_str(&s, "%Y-%m-%d %H:%M:%S")
                        .ok()
                        .map(|n| n.and_utc())
                });
                Ok((UserId(uid), parsed))
            })
            .collect()
    }

    /// Design v2 4b — the user-side mirror of
    /// [`Self::grant_dates_for_server`]: when was each of this user's
    /// grants made. NULL (pre-0039 rows) reads as `None`.
    pub async fn grant_dates_for_user(
        &self,
        user: &UserId,
    ) -> Result<Vec<(ServerId, Option<DateTime<Utc>>)>> {
        let rows = sqlx::query(
            "SELECT server_id, granted_at FROM grants WHERE user_id = ?1 ORDER BY server_id",
        )
        .bind(&user.0)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|r| {
                let sid: String = r.try_get("server_id")?;
                let ts: Option<String> = r.try_get("granted_at")?;
                let parsed = ts.and_then(|s| {
                    chrono::NaiveDateTime::parse_from_str(&s, "%Y-%m-%d %H:%M:%S")
                        .ok()
                        .map(|n| n.and_utc())
                });
                Ok((ServerId(sid), parsed))
            })
            .collect()
    }

    pub async fn revoke(&self, user: &UserId, server: &ServerId) -> Result<()> {
        sqlx::query("DELETE FROM grants WHERE user_id = ?1 AND server_id = ?2")
            .bind(&user.0)
            .bind(&server.0)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Users granted on `server`, with `uuid` already overridden to the
    /// per-server `grants.client_uuid` if one is set (Phase 1 of the
    /// ninitux merge — see migration `0016_grants_per_server_uuid.sql`).
    ///
    /// Returned `User.uuid` is the value the SERVER expects to see in
    /// VLESS Reality handshakes from this user. It MAY differ between
    /// servers for the same `user.id` once Phase 2 has imported the
    /// per-(user, server) uuids harvested from subscription-server's
    /// `client_server_links` table.
    ///
    /// All OTHER `User` fields (`tuic_password`, `wireguard_pubkey`,
    /// `wireguard_private`, `sub_token`) keep their per-user values —
    /// only `uuid` is per-server. TUIC and WireGuard don't need
    /// per-server differentiation (TUIC carries password + per-user
    /// uuid; WG identifies peers by pubkey not name) so leaving them
    /// global is correct and avoids needless schema bloat.
    pub async fn users_for_server(&self, server: &ServerId) -> Result<Vec<User>> {
        // `u.disabled = 0` — a disabled user is EXCLUDED from the rendered
        // node config (this slice feeds every kernel's inbound users), so a
        // disable + redeploy REVOKES node access and an enable + redeploy
        // restores it. `disabled` is no longer a subscription-only soft mute.
        // `user_set_disabled_inner` kicks the redeploy on toggle.
        let rows = sqlx::query(
            "SELECT u.id, COALESCE(g.client_uuid, u.uuid) AS uuid, u.tuic_password, u.wireguard_pubkey, u.wireguard_private, u.sub_token, u.vpn_router_device_id, u.disabled
             FROM users u
             INNER JOIN grants g ON g.user_id = u.id
             WHERE g.server_id = ?1
               AND u.disabled = 0
             ORDER BY u.id",
        )
        .bind(&server.0)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_user).collect()
    }

    pub async fn servers_for_user(&self, user: &UserId) -> Result<Vec<Server>> {
        let rows = sqlx::query(
            "SELECT g.server_id FROM grants g WHERE g.user_id = ?1 ORDER BY g.server_id",
        )
        .bind(&user.0)
        .fetch_all(&self.pool)
        .await?;
        let sids: Vec<ServerId> = rows
            .into_iter()
            .map(|r| r.try_get::<String, _>("server_id").map(ServerId))
            .collect::<std::result::Result<_, _>>()?;
        self.get_servers_batch(&sids).await
    }

    pub async fn subscription_servers_for_user(&self, user: &UserId) -> Result<Vec<Server>> {
        let rows = sqlx::query(
            "SELECT g.server_id FROM grants g
             INNER JOIN servers s ON s.id = g.server_id
             WHERE g.user_id = ?1 AND s.role = 'vpn-exit'
             ORDER BY g.server_id",
        )
        .bind(&user.0)
        .fetch_all(&self.pool)
        .await?;
        let sids: Vec<ServerId> = rows
            .into_iter()
            .map(|r| r.try_get::<String, _>("server_id").map(ServerId))
            .collect::<std::result::Result<_, _>>()?;
        self.get_servers_batch(&sids).await
    }

    /// Cheap row count of (user, server) grant pairs. `0` on empty table.
    pub async fn count_grants(&self) -> Result<i64> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM grants")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.try_get("n")?)
    }

    /// Map of `server_id → number of users granted access to it`. Servers
    /// with no grants are absent (callers default to 0). One query, no N+1
    /// — call this once and look up by ID when rendering a server list.
    pub async fn users_count_per_server(&self) -> Result<HashMap<ServerId, i64>> {
        let rows = sqlx::query("SELECT server_id, COUNT(*) AS n FROM grants GROUP BY server_id")
            .fetch_all(&self.pool)
            .await?;
        let mut out = HashMap::with_capacity(rows.len());
        for r in rows {
            let sid: String = r.try_get("server_id")?;
            let n: i64 = r.try_get("n")?;
            out.insert(ServerId(sid), n);
        }
        Ok(out)
    }

    /// Map of `user_id → number of servers granted to it`. Users
    /// with no grants are absent (callers default to 0). Exactly 1 query,
    /// no N+1 — call this once and look up by user ID when rendering a user list.
    pub async fn servers_count_per_user(&self) -> Result<HashMap<UserId, i64>> {
        let rows = sqlx::query("SELECT user_id, COUNT(*) AS n FROM grants GROUP BY user_id")
            .fetch_all(&self.pool)
            .await?;
        let mut out = HashMap::with_capacity(rows.len());
        for r in rows {
            let uid: String = r.try_get("user_id")?;
            let n: i64 = r.try_get("n")?;
            out.insert(UserId(uid), n);
        }
        Ok(out)
    }
}
