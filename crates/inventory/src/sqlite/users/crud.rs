use crate::sqlite::base::{SqliteInventory, map_unique};
use crate::sqlite::models::{Result, SqliteInventoryError};
use sqlx::Row;
use sqlx::sqlite::SqliteRow;
use vpnctl_core::{User, UserId};

// Owned `SqliteRow` is what `.map(...)` over `Vec<Row>` gives us — taking by
// reference here would require a `.collect()` round-trip. Accepting by value
// is correct.
//
// The SHA256 fingerprint shape check that used to live here moved to
// `vpnctl-host-fingerprint::validate_shape` so every surface (CLI / web /
// wizard / this inventory gate) shares one canonical definition.

#[allow(clippy::needless_pass_by_value)]
pub(crate) fn row_to_user(r: SqliteRow) -> Result<User> {
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
}
