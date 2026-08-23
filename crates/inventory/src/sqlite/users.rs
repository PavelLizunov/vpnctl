use super::*;
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
/// single-column UNIQUE index.
///
/// Generic over the executor so callers can run it on the pool (`grant`) or
/// inside an already-open transaction (`set_grant_client_uuid`).
async fn find_effective_uuid_conflict<'e, E>(
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
    // that in the error stops the operator from chasing a "ghost".
    match row {
        None => Ok(None),
        Some(r) => {
            let who: String = r.try_get("who")?;
            let who_disabled: i64 = r.try_get("who_disabled")?;
            Ok(Some((who, who_disabled != 0)))
        }
    }
}

// Owned `SqliteRow` is what `.map(...)` over `Vec<Row>` gives us — taking by
// reference here would require a `.collect()` round-trip. Accepting by value
// is correct.
//
// The SHA256 fingerprint shape check that used to live here moved to
// `vpnctl-host-fingerprint::validate_shape` so every surface (CLI / web /
// wizard / this inventory gate) shares one canonical definition.

#[allow(clippy::needless_pass_by_value)]
pub(crate) fn row_to_user(r: sqlx::sqlite::SqliteRow) -> Result<User> {
    Ok(User {
        id: UserId(r.try_get("id")?),
        uuid: r.try_get("uuid")?,
        tuic_password: r.try_get("tuic_password")?,
        wireguard_pubkey: r.try_get("wireguard_pubkey")?,
        wireguard_private: r.try_get("wireguard_private")?,
        sub_token: r.try_get("sub_token")?,
        // Reads the column added by migration 0017. Bare `?` (no
        // turbofish) — same pattern as the other Option<String>
        // columns above. Rust infers `T = Option<String>` from the
        // field type, which routes through sqlx's `Option<T>` Decode
        // impl and handles NULL → `None` correctly. Initial fix
        // used `.ok()` which inferred `T = String` and SQLite
        // decoded NULL as `""` (caught 2026-05-19: `DEVICE_ID =
        // Some("")` instead of `None` made every fresh-user
        // detail page render the ninitux URL with an empty
        // device_id).
        vpn_router_device_id: r.try_get("vpn_router_device_id")?,
        // Migration 0026 (audit B1.user, 2026-05-22). SQLite stores
        // BOOLEAN as INTEGER; we read i64 and map non-zero → true.
        disabled: {
            let v: i64 = r.try_get("disabled").unwrap_or(0);
            v != 0
        },
    })
}

impl SqliteInventory {
    // ── Users ───────────────────────────────────────────────────────────

    pub async fn add_user(&self, u: &User) -> Result<()> {
        // Ensure every user gets a sub_token. Caller may pre-set one (e.g.
        // when restoring from a snapshot); we generate only if absent.
        let token = match u.sub_token.as_deref() {
            Some(t) if !t.is_empty() => t.to_string(),
            _ => vpnctl_crypto::gen_sub_token().map_err(SqliteInventoryError::CryptoIo)?,
        };
        // Migration 0026 — honour the caller's `disabled` field on
        // INSERT. Default in the schema is 0, but callers may want
        // to import a pre-disabled user (snapshot restore, future
        // bulk-disable workflow). i64 mirror of the bool.
        let disabled_i: i64 = if u.disabled { 1 } else { 0 };
        // 2026-05-23 quickfix — also honour `vpn_router_device_id`
        // on INSERT (was getting silently dropped, leaving every
        // web-created user with NULL device_id → no production
        // ninitux URL on user-detail). NULL is still valid for
        // legacy imports that haven't been mapped to a device_id.
        let res = sqlx::query(
            "INSERT INTO users (id, uuid, tuic_password, wireguard_pubkey, wireguard_private, sub_token, vpn_router_device_id, disabled)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )
        .bind(&u.id.0)
        .bind(&u.uuid)
        .bind(&u.tuic_password)
        .bind(&u.wireguard_pubkey)
        .bind(&u.wireguard_private)
        .bind(&token)
        .bind(u.vpn_router_device_id.as_deref())
        .bind(disabled_i)
        .execute(&self.pool)
        .await;
        map_unique(res, format!("user {}", u.id.0))?;
        Ok(())
    }

    /// Look up a user by their subscription token. Constant-time'ish at the
    /// SQL layer (sqlite scans the unique index), but the caller is the
    /// public daemon — see also `vpnctld` rate-limit middleware.
    ///
    /// **Side-channel posture (review-agent #5, security-review #3,
    /// 2026-05-14):** SQLite's index walk + the Rust `String` comparison
    /// inside `bind` are not constant-time. With ~256 bits of entropy
    /// in `sub_token` (43 chars URL-safe base64 = 252 bits) brute force
    /// is infeasible regardless. Timing-based prefix discovery would
    /// matter ONLY if the daemon were exposed externally with no
    /// rate-limit. The deployment is LAN-only today, and Phase Track-2
    /// (per-token rate limit + auto-deny on burst) MUST land before any
    /// external exposure — see CLAUDE.md Roadmap. Do NOT remove this
    /// invariant by exposing the daemon publicly without Track-2.
    pub async fn find_user_by_sub_token(&self, token: &str) -> Result<Option<User>> {
        let row = sqlx::query(
            "SELECT id, uuid, tuic_password, wireguard_pubkey, wireguard_private, sub_token, vpn_router_device_id, disabled
             FROM users WHERE sub_token = ?1",
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await?;
        row.map(row_to_user).transpose()
    }

    /// Overwrite the user's WireGuard / AmneziaWG keypair atomically.
    /// Both halves set together — guarantees the
    /// `private = Some && public = None` inconsistent state can
    /// never appear via this code path.
    ///
    /// Caller produces the standard-base64 strings (typically via
    /// `vpnctl_crypto::gen_wireguard_keypair()`). No shape validation
    /// here — caller's responsibility (web `user_regen_wireguard`
    /// uses the crypto helper directly; no operator-typed input).
    ///
    /// Returns `Invalid` when no such user (mirrors
    /// `regenerate_sub_token` semantics).
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

    /// Regenerate the sub_token for an existing user (rotation). Returns the
    /// new token. Old URL stops working immediately.
    pub async fn regenerate_sub_token(&self, id: &UserId) -> Result<String> {
        let token = vpnctl_crypto::gen_sub_token().map_err(SqliteInventoryError::CryptoIo)?;
        let res = sqlx::query("UPDATE users SET sub_token = ?1 WHERE id = ?2")
            .bind(&token)
            .bind(&id.0)
            .execute(&self.pool)
            .await?;
        if res.rows_affected() == 0 {
            return Err(SqliteInventoryError::Invalid(format!(
                "no such user: {}",
                id.0
            )));
        }
        Ok(token)
    }

    /// Mint a `tuic_password` for `id` **only if it currently has none**.
    ///
    /// Returns `Ok(true)` if a password was minted, `Ok(false)` if the
    /// user already had one (no-op). We never rotate a live password
    /// here — that would break the user's TUIC / naive / Hysteria2 links
    /// until the node is redeployed. naive + hysteria2 reuse this field
    /// as their per-user secret, so a NULL `tuic_password` silently drops
    /// those protocols from the user's subscription (the `cdn`
    /// 2026-06-07 incident).
    pub async fn mint_tuic_password_if_absent(&self, id: &UserId) -> Result<bool> {
        // 24 bytes → 32-char url-safe base64, identical to the add-user
        // and CLI mint (`gen_password(TUIC_PW_BYTES)`).
        let pw = vpnctl_crypto::gen_password(24).map_err(SqliteInventoryError::CryptoIo)?;
        let res = sqlx::query(
            "UPDATE users SET tuic_password = ?1
             WHERE id = ?2 AND (tuic_password IS NULL OR tuic_password = '')",
        )
        .bind(&pw)
        .bind(&id.0)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn get_user(&self, id: &UserId) -> Result<Option<User>> {
        let row = sqlx::query(
            "SELECT id, uuid, tuic_password, wireguard_pubkey, wireguard_private, sub_token, vpn_router_device_id, disabled
             FROM users WHERE id = ?1",
        )
        .bind(&id.0)
        .fetch_optional(&self.pool)
        .await?;
        row.map(row_to_user).transpose()
    }

    pub async fn list_users(&self) -> Result<Vec<User>> {
        let rows = sqlx::query(
            "SELECT id, uuid, tuic_password, wireguard_pubkey, wireguard_private, sub_token, vpn_router_device_id, disabled
             FROM users ORDER BY id",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_user).collect()
    }

    pub async fn remove_user(&self, id: &UserId) -> Result<()> {
        sqlx::query("DELETE FROM users WHERE id = ?1")
            .bind(&id.0)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

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
    /// the UI renders those as "—".
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

    /// Design v2 3d — which granted users' key material is NOT yet in
    /// the node's deployed config: their `user.grant` audit row for
    /// this server has a greater monotonic audit id than the last
    /// successful `server.deploy`. Per-user so the banner can NAME
    /// who's affected without relying on timestamp precision.
    pub async fn users_pending_deploy_for_server(
        &self,
        server_id: &ServerId,
    ) -> Result<Vec<UserId>> {
        let rows = sqlx::query(
            "SELECT DISTINCT a.target AS uid FROM audit_log a
             WHERE a.action = 'user.grant'
               AND json_extract(a.payload, '$.server') = ?1
               AND a.target IN (SELECT user_id FROM grants WHERE server_id = ?1)
               AND a.id > COALESCE(
                     (SELECT MAX(d.id) FROM audit_log d
                      WHERE d.target = ?1 AND d.action = 'server.deploy'),
                     0)
             ORDER BY uid",
        )
        .bind(&server_id.0)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|r| Ok(UserId(r.try_get("uid")?)))
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
            "SELECT u.id, COALESCE(g.client_uuid, u.uuid) AS uuid, u.tuic_password, u.wireguard_pubkey, u.wireguard_private, u.sub_token, u.vpn_router_device_id
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

    /// Effective VLESS uuid for a (user, server) grant — the value the
    /// server's sing-box would expect in a Reality handshake from this
    /// user. Returns `None` if no grant exists for the pair.
    ///
    /// `COALESCE(grants.client_uuid, users.uuid)`. The override path:
    /// if Phase 2's import has set a per-server `client_uuid` on the
    /// grant (e.g. when ninitux carried a distinct uuid per server for
    /// the same user), that wins; otherwise the user's global uuid is
    /// returned — preserving pre-Phase-1 behaviour byte-for-byte.
    ///
    /// Use this instead of `get_user(id).uuid` when you're about to
    /// render a vless:// share-link OR push a sing-box `inbounds[*].users[*]`
    /// entry for a specific server. The global `users.uuid` is still the
    /// user IDENTITY (used in audit log targets, sub-token lookups, etc),
    /// but it's no longer guaranteed to be the AUTH secret on every
    /// server the user is granted to.
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

    /// Defence-in-depth pre-deploy assertion: error if any two **rendered**
    /// users on `server` (granted AND enabled — exactly the slice
    /// `users_for_server` feeds to the kernels) resolve to the same effective
    /// VLESS uuid. The write-time guards in `grant` / `set_grant_client_uuid`
    /// stop collisions at the source, but a manual `sqlite3` edit or a buggy
    /// import could still plant one; the deploy pipeline calls this so a
    /// colliding config is NEVER pushed (sing-box silently dedups the users,
    /// bricking one with no telemetry signal — HANDOFF §4.1). Read-only.
    ///
    /// Disabled users are excluded, matching `users_for_server` — a disabled
    /// user isn't rendered, so it can't collide on the wire, and including it
    /// would block deploys on a latent (non-shipping) duplicate.
    ///
    /// **Blast radius:** this fails the deploy of the WHOLE node fail-closed —
    /// the operator cannot push ANY change to the server until the collision
    /// is resolved. That is intentional (rendering a colliding config bricks a
    /// user with no signal, which is worse), but it means a collision can
    /// wedge an urgent unrelated deploy. The error therefore names each
    /// colliding user and marks which carries the `(override)` `client_uuid`,
    /// so remediation is one step: clear or replace that override.
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

    /// Set the per-server VLESS uuid override on an existing grant. The
    /// grant must already exist (call `grant` first if not). Idempotent —
    /// setting to the same value is a no-op SQL-wise; setting to a
    /// different value overwrites.
    ///
    /// `client_uuid` MUST be a syntactically valid RFC 4122 UUID
    /// (validated via `vpnctl_crypto::is_valid_uuid`). An empty /
    /// malformed value would silently brick the user on the server
    /// (Reality handshake rejects, no telemetry signals the cause) —
    /// the gate here means a Phase 2 import script that hits one bad
    /// row fails loudly per-row instead of silently degrading.
    ///
    /// Errors:
    ///   * `Invalid` when `client_uuid` doesn't pass the UUID-shape
    ///     check.
    ///   * `Invalid` when the (user, server) pair has no grant row —
    ///     callers should NOT silently create the grant here. The
    ///     Phase 2 import script grants first, then sets the per-server
    ///     uuid as a separate step (so audit log clearly reflects each
    ///     mutation).
    ///
    /// Audit: writes a `grant.set_client_uuid` row with both old + new
    /// uuid values in the payload, so the operator can trace «when did
    /// this user's vps-de-01 uuid change?» in the audit timeline.
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

        // Transaction wraps the SELECT-then-UPDATE so two concurrent
        // callers can't interleave (read old=A, read old=A, write B,
        // write C → audit log loses B as the «intermediate» state).
        // Phase 2's import script is single-threaded so the race
        // window is empty in the primary use-case; the transaction
        // exists for future callers + defence in depth. SQLite's
        // single-writer model already serialises the inner write,
        // so the cost here is just one extra BEGIN/COMMIT round-trip.
        //
        // Audit row is emitted INSIDE the same transaction so an
        // «I changed this» row never survives a write that didn't
        // commit (e.g. FK violation surfaced too late). On UPDATE
        // returning 0 rows we roll back via early-return + tx drop.
        let mut tx = self.pool.begin().await?;

        // Fetch the grant row's presence AND its old client_uuid in one
        // read. `grant_row` is `Some` iff the (user, server) grant exists
        // — kept separate from `old_uuid` so a grant with a NULL
        // client_uuid is distinguishable from a missing grant (both make
        // `old_uuid` None). Needed below to tell «no grant» (error) apart
        // from «same value, nothing to do» (silent no-op).
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

        // uuid-uniqueness invariant (HANDOFF §4.1): the new `client_uuid` must
        // not equal another user's effective uuid on this server, or sing-box
        // would dedup the two and brick one of them. Checked inside the same
        // transaction as the UPDATE so the read + write are atomic. Skipped
        // when the grant is absent — the "no grant" error below owns that
        // case. `exclude_user = user` means a same-value re-write (the
        // idempotent no-op path) never trips on itself.
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

        // `AND client_uuid IS NOT ?3` (NULL-safe) makes a same-value write
        // match 0 rows, mirroring the no-op-suppression idiom in
        // set_user_disabled / set_server_protocol_hidden: a write that
        // doesn't change anything emits no audit row. The presence check
        // below disambiguates the two 0-rows cases.
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
                // tx drops without commit → SELECT side-effect is rolled
                // back (snapshot read had no side effect anyway, but the
                // shape stays «atomic from caller's perspective»).
                return Err(SqliteInventoryError::Invalid(format!(
                    "no grant for user={} server={}; cannot set client_uuid",
                    user.0, server.0
                )));
            }
            // Grant exists but already holds this exact client_uuid →
            // idempotent no-op. Commit (read had no side effect) and skip
            // the audit row so "one audit row per mutation" holds.
            tx.commit().await?;
            return Ok(());
        }

        // Audit row inside the same transaction. Note: the payload
        // logs both old + new client_uuid in plaintext. The VLESS
        // client_uuid IS the Reality auth secret on the corresponding
        // server, so an admin-audit reader sees that secret. This is
        // acceptable for the LAN-only single-operator deployment
        // (admin gate + actor=admin everywhere), but if vpnctld ever
        // gets multi-tenant or externally-exposed audit, the payload
        // should switch to a short fingerprint (e.g. first 8 chars +
        // sha256 suffix) and the full UUID move to a separate
        // auth-gated detail endpoint.
        let audit_payload = serde_json::json!({
            "server_id": server.0,
            "old_client_uuid": old_uuid,
            "new_client_uuid": client_uuid,
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

    /// Look up a user by their 32-hex `vpn_router_device_id` — the
    /// canonical lookup key in the ninitux URL format. Returns `None`
    /// when no user carries that device_id (the column is partially
    /// unique so at most one row can match). Backs the
    /// `GET /api/v1/app/config/{device_id}` handler in
    /// `daemon::handlers::vpn_router`.
    ///
    /// Caller is expected to validate the input first via
    /// `vpnctl_crypto::is_valid_vpn_router_device_id` — this method
    /// just runs a parameterised SELECT and returns the row (or None).
    /// Refusing malformed input at the handler keeps the SQL fast-path
    /// uniform regardless of garbage input.
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

    /// Pin a 32-hex `vpn_router_device_id` on an existing user. The
    /// user must already exist (call `add_user` first). Setting the
    /// same value twice is a no-op SQL-wise; setting to a different
    /// value rotates the device_id (rare — happens if subscription-
    /// server's `clients.device_id` for that named client gets
    /// rotated for some reason, then re-imported).
    ///
    /// `device_id` MUST be syntactically valid (32 lowercase hex chars,
    /// validated via `vpnctl_crypto::is_valid_vpn_router_device_id`).
    /// Anything else returns `Invalid`. An empty string is rejected
    /// before the gate, so this method cannot accidentally clear an
    /// existing override — use the dedicated `clear` path if you want
    /// to disconnect a user from the vpn-router endpoint.
    ///
    /// Audit: writes `user.set_vpn_router_device_id` row with old +
    /// new values. Same transaction-wrapped pattern as
    /// `set_grant_client_uuid` — SELECT + UPDATE + INSERT all under
    /// one BEGIN…COMMIT so concurrent callers can't interleave.
    pub async fn set_vpn_router_device_id(&self, user: &UserId, device_id: &str) -> Result<()> {
        if !vpnctl_crypto::is_valid_vpn_router_device_id(device_id) {
            return Err(SqliteInventoryError::Invalid(format!(
                "device_id {device_id:?} is not 32 lowercase hex chars; refusing to write"
            )));
        }

        let mut tx = self.pool.begin().await?;

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

        // Map SQLite's UNIQUE constraint violation (a different user
        // already pinned this device_id, blocked by the partial
        // index added in migration 0017) to a clean `AlreadyExists`
        // — same shape as `add_user`'s duplicate-id error. Without
        // this mapping the caller would see a raw sqlx error code
        // 2067 wrapped in `Sqlx(...)`, which is hard to handle.
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

        // Audit row. device_id is NOT a secret (it's a public lookup
        // key — anyone hitting `https://ninitux.com/api/v1/app/config/<id>`
        // already knows it), so logging both old + new in plaintext is
        // safe for the admin-gated audit feed.
        let audit_payload = serde_json::json!({
            "old_vpn_router_device_id": old_device_id,
            "new_vpn_router_device_id": device_id,
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

    /// Return a `User` clone with `uuid` swapped to the per-server
    /// VLESS uuid override stored in `grants.client_uuid`. When no
    /// override is set (NULL → COALESCE returns `users.uuid`) the
    /// returned User has the same uuid as the input — the helper is
    /// safe to call unconditionally at render time.
    ///
    /// Use this at every share-link / `client_config` rendering
    /// callsite that has both the `User` (e.g. from `find_user_by_sub_token`)
    /// AND a target `ServerId`. Avoids the three-way clone-and-swap
    /// duplication between `cli/cmd/sub.rs` and `daemon/handlers/sub.rs`
    /// (admin uses the peers-list path, which already has the
    /// override applied by `users_for_server`'s COALESCE — that
    /// callsite keeps its own helper).
    ///
    /// Returns the original user clone (uuid unchanged) when no grant
    /// exists for the pair — same fallback as the inline pattern
    /// being replaced. This is the safe choice: a /sub renderer that
    /// hit an inconsistent state (servers_for_user returned a server
    /// the user got revoked from between calls) still produces a
    /// link rather than crashing the whole response.
    pub async fn user_with_per_server_uuid(&self, user: &User, server: &ServerId) -> Result<User> {
        match self.client_uuid_for(&user.id, server).await? {
            Some(client_uuid) if client_uuid != user.uuid => {
                Ok(user.with_per_server_uuid(&client_uuid))
            }
            _ => Ok(user.clone()),
        }
    }

    pub async fn servers_for_user(&self, user: &UserId) -> Result<Vec<Server>> {
        let rows = sqlx::query(
            "SELECT g.server_id FROM grants g WHERE g.user_id = ?1 ORDER BY g.server_id",
        )
        .bind(&user.0)
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let sid: String = r.try_get("server_id")?;
            if let Some(s) = self.get_server(&ServerId(sid)).await? {
                out.push(s);
            }
        }
        Ok(out)
    }

    /// Cheap row count. `0` on an empty table.
    pub async fn count_users(&self) -> Result<i64> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM users")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.try_get("n")?)
    }

    /// **Fleet search** (audit A5, shipped 2026-05-23). Substring
    /// match against `users.id`, `users.uuid`, `users.sub_token`,
    /// `users.vpn_router_device_id`. Case-insensitive via
    /// `LOWER(...)`; returns full `User` rows for the hits so the
    /// search results page can render `id` + secondary identifiers
    /// without a second roundtrip. Capped at `limit` so a pathological
    /// `q="a"` doesn't paginate the entire fleet.
    ///
    /// Empty `q` returns empty — search is opt-in, the index page
    /// shouldn't accidentally dump everything.
    pub async fn search_users(&self, q: &str, limit: i64) -> Result<Vec<User>> {
        if q.is_empty() {
            return Ok(Vec::new());
        }
        let pat = format!("%{}%", escape_like(&q.to_lowercase()));
        let rows = sqlx::query(
            "SELECT id, uuid, tuic_password, wireguard_pubkey, wireguard_private, sub_token, vpn_router_device_id, disabled
             FROM users
             WHERE LOWER(id) LIKE ?1 ESCAPE '\\'
                OR LOWER(uuid) LIKE ?1 ESCAPE '\\'
                OR LOWER(COALESCE(sub_token, '')) LIKE ?1 ESCAPE '\\'
                OR LOWER(COALESCE(vpn_router_device_id, '')) LIKE ?1 ESCAPE '\\'
             ORDER BY id
             LIMIT ?2",
        )
        .bind(&pat)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_user).collect()
    }

    /// Count of users with `disabled = 1` (B1.user, migration 0026).
    /// Cheap — backed by the partial `idx_users_disabled_partial`
    /// index which only contains the disabled rows, so this is O(N
    /// disabled), not O(N total). Used by the dashboard's «N paused»
    /// sub-line so disabled users don't fall off the operator's
    /// radar.
    pub async fn count_disabled_users(&self) -> Result<i64> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM users WHERE disabled = 1")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.try_get("n")?)
    }

    /// Cheap row count of (user, server) grant pairs. `0` on empty table.
    pub async fn count_grants(&self) -> Result<i64> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM grants")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.try_get("n")?)
    }

    /// **Idle users** — list `(user_id, last_seen)` for users whose
    /// most recent `sub_access_log` row is older than `days` days, OR
    /// who have never appeared in the access log at all (last_seen
    /// is `None`).
    ///
    /// Backs the dashboard «Idle users — revoke candidates» panel
    /// (audit A2). Cheap single LEFT-JOIN with one MAX aggregate;
    /// rows are sorted oldest-first (`last_seen ASC NULLS FIRST`)
    /// so the worst offenders appear at the top. Limit caps the
    /// result set so the panel doesn't grow unbounded.
    ///
    /// **`days = 30` is the canonical threshold for the dashboard**
    /// — a roughly-monthly cycle catches «forgotten phone in a
    /// drawer» without being so aggressive it surfaces normal-
    /// vacation users. Operator can pick a different number; the
    /// query is parameterised.
    ///
    /// Pinned by `idle_users_returns_users_with_old_or_no_last_seen`.
    pub async fn idle_users(
        &self,
        days: u32,
        limit: i64,
    ) -> Result<Vec<(UserId, Option<DateTime<Utc>>)>> {
        let cutoff = format!("-{days} days");
        // LEFT JOIN against an aggregate subquery: every user appears
        // exactly once; users with no sub_access_log row get
        // `last_seen = NULL`. WHERE filter keeps only `last_seen IS
        // NULL` (never seen) OR `last_seen < cutoff` (seen but old).
        // Sort `last_seen ASC NULLS FIRST` so never-seen users float
        // to the top alongside the longest-idle ones.
        let rows = sqlx::query(
            "SELECT u.id AS user_id, la.last_seen AS last_seen
             FROM users u
             LEFT JOIN (
                 SELECT user_id, MAX(ts) AS last_seen
                 FROM sub_access_log
                 WHERE is_vpn_egress = 0
                 GROUP BY user_id
             ) la ON la.user_id = u.id
             WHERE la.last_seen IS NULL
                -- `<=` not `<`: a row whose ts equals the cutoff is
                -- «no newer than the threshold» → idle. Also closes
                -- a CI flake: a tight loop on a fast box can write
                -- the access-log row + run idle_users(0) within one
                -- millisecond, leaving ts == cutoff exactly; strict
                -- `<` would have excluded the row and the test
                -- would intermittently fail.
                OR la.last_seen <= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1)
             ORDER BY (la.last_seen IS NOT NULL), la.last_seen ASC
             LIMIT ?2",
        )
        .bind(&cutoff)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        let mut out: Vec<(UserId, Option<DateTime<Utc>>)> = Vec::with_capacity(rows.len());
        for row in rows {
            let uid: String = row.try_get("user_id")?;
            let last_seen_str: Option<String> = row.try_get("last_seen")?;
            let last_seen = last_seen_str.and_then(|t| {
                DateTime::parse_from_rfc3339(&t)
                    .ok()
                    .map(|d| d.with_timezone(&Utc))
            });
            out.push((UserId(uid), last_seen));
        }
        Ok(out)
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

    /// Set or clear a user's monthly bandwidth limit + alert
    /// threshold. Pass `Some(limit)` to set, `None` to clear
    /// (operator decided the user no longer needs a cap). Threshold
    /// is a percent (0..=100); the daemon-side default lives in
    /// `vpnctld::admin::DEFAULT_TRAFFIC_THRESHOLD_PCT`.
    ///
    /// Returns `Invalid` if no such user — matches the existing
    /// `regenerate_sub_token` shape.
    /// Flip the `disabled` flag on a user (audit B1.user, migration
    /// 0026). Returns `Ok(true)` when the row was changed (operator
    /// actually flipped state), `Ok(false)` when the row already
    /// matched the requested state (idempotent no-op), or `Err` if
    /// the user doesn't exist.
    ///
    /// Caller is responsible for the audit row — this helper does
    /// only the SQL flip so the handler can decide whether the
    /// audit entry is `user.disable` or `user.enable` (mirrors the
    /// per-protocol `set_hidden` + `set_grant_protocol_override`
    /// convention from NM-10).
    pub async fn set_user_disabled(&self, id: &UserId, disabled: bool) -> Result<bool> {
        let new_val: i64 = if disabled { 1 } else { 0 };
        let res = sqlx::query("UPDATE users SET disabled = ?1 WHERE id = ?2 AND disabled != ?1")
            .bind(new_val)
            .bind(&id.0)
            .execute(&self.pool)
            .await?;
        if res.rows_affected() > 0 {
            return Ok(true);
        }
        // Either user doesn't exist OR already at target state.
        // Disambiguate with a presence check.
        let exists: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE id = ?1")
            .bind(&id.0)
            .fetch_one(&self.pool)
            .await?;
        if exists.0 == 0 {
            return Err(SqliteInventoryError::Invalid(format!(
                "no such user: {}",
                id.0
            )));
        }
        Ok(false)
    }

    /// **Q-4d** — user lifecycle facts. `users.created_at` exists
    /// (migration 0001) so this reads it directly + the most recent
    /// real `/sub` fetch, and derives `age_days`. Backs the
    /// user-detail header.
    pub async fn user_lifecycle(&self, user: &UserId) -> Result<UserLifecycle> {
        let row = sqlx::query(
            "SELECT u.created_at AS created_at,
                    (SELECT MAX(ts) FROM sub_access_log
                     WHERE user_id = u.id AND is_vpn_egress = 0) AS last_sub_fetch
             FROM users u
             WHERE u.id = ?1",
        )
        .bind(&user.0)
        .fetch_optional(&self.pool)
        .await?;
        let row =
            row.ok_or_else(|| SqliteInventoryError::Invalid(format!("no such user: {}", user.0)))?;
        let created_s: String = row.try_get("created_at")?;
        let created_at = DateTime::parse_from_rfc3339(&created_s)
            .map(|d| d.with_timezone(&Utc))
            .map_err(|e| {
                SqliteInventoryError::Invalid(format!(
                    "users.created_at malformed: {created_s}: {e}"
                ))
            })?;
        let last_s: Option<String> = row.try_get("last_sub_fetch")?;
        let last_sub_fetch = last_s.and_then(|s| {
            DateTime::parse_from_rfc3339(&s)
                .ok()
                .map(|d| d.with_timezone(&Utc))
        });
        // Floored whole days since creation; never negative (a clock
        // skew that put created_at slightly in the future yields 0).
        let age_days = (Utc::now() - created_at).num_days().max(0) as u64;
        Ok(UserLifecycle {
            created_at,
            last_sub_fetch,
            age_days,
        })
    }
}
