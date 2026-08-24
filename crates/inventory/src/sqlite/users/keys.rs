use super::crud::row_to_user;
use super::grants::find_effective_uuid_conflict;
use crate::sqlite::base::{SqliteInventory, map_unique};
use crate::sqlite::models::{Result, SqliteInventoryError};
use sqlx::Row;
use vpnctl_core::{ServerId, User, UserId};

impl SqliteInventory {
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
            // the audit row so \"one audit row per mutation\" holds.
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
}
