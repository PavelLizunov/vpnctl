use std::collections::HashSet;

use crate::sqlite::base::{SqliteInventory, map_unique};
use crate::sqlite::models::{Result, SqliteInventoryError};
use sha2::{Digest, Sha256};
use sqlx::Row;
use sqlx::sqlite::SqliteRow;
use vpnctl_core::{ServerId, User, UserId};

#[allow(clippy::needless_pass_by_value)]
pub(crate) fn row_to_user(r: SqliteRow) -> Result<User> {
    Ok(User {
        id: UserId(r.try_get("id")?),
        uuid: r.try_get("uuid")?,
        tuic_password: r.try_get("tuic_password")?,
        wireguard_pubkey: r.try_get("wireguard_pubkey")?,
        wireguard_private: r.try_get("wireguard_private")?,
        sub_token: r.try_get("sub_token")?,
        vpn_router_device_id: r.try_get("vpn_router_device_id")?,
        disabled: {
            let v: i64 = r.try_get("disabled").unwrap_or(0);
            v != 0
        },
    })
}

fn normalize_admin_note(value: &str) -> Result<String> {
    let value = value.trim().replace("\r\n", "\n").replace('\r', "\n");
    if value.contains('\0') || value.chars().take(2_001).count() > 2_000 {
        return Err(SqliteInventoryError::Invalid("invalid user note".into()));
    }
    Ok(value)
}

const USER_ADMIN_NOTE_QUERY: &str = "SELECT coalesce(n.note, '')
    FROM users u LEFT JOIN user_admin_notes n ON n.user_id = u.id WHERE u.id = ?1";

impl SqliteInventory {
    pub async fn add_user(&self, u: &User) -> Result<()> {
        self.add_user_with_admin_note(u, "").await
    }

    pub async fn add_user_with_admin_note(&self, u: &User, note: &str) -> Result<()> {
        let note = normalize_admin_note(note)?;
        let token = match u.sub_token.as_deref() {
            Some(t) if !t.is_empty() => t.to_string(),
            _ => vpnctl_crypto::gen_sub_token().map_err(SqliteInventoryError::CryptoIo)?,
        };
        let disabled_i: i64 = if u.disabled { 1 } else { 0 };
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
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
        .execute(&mut *tx)
        .await;
        map_unique(res, format!("user {}", u.id.0))?;
        if !note.is_empty() {
            sqlx::query("INSERT INTO user_admin_notes (user_id, note) VALUES (?1, ?2)")
                .bind(&u.id.0)
                .bind(note)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn user_admin_note(&self, id: &UserId) -> Result<Option<String>> {
        Ok(sqlx::query_scalar(USER_ADMIN_NOTE_QUERY)
            .bind(&id.0)
            .fetch_optional(&self.pool)
            .await?)
    }

    pub async fn set_user_admin_note(&self, id: &UserId, note: &str, actor: &str) -> Result<bool> {
        let note = normalize_admin_note(note)?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let previous: Option<String> = sqlx::query_scalar(USER_ADMIN_NOTE_QUERY)
            .bind(&id.0)
            .fetch_optional(&mut *tx)
            .await?;
        let Some(previous) = previous else {
            return Ok(false);
        };
        if previous != note {
            let cleared = note.is_empty();
            if cleared {
                sqlx::query("DELETE FROM user_admin_notes WHERE user_id = ?1")
                    .bind(&id.0)
                    .execute(&mut *tx)
                    .await?;
            } else {
                sqlx::query(
                    "INSERT INTO user_admin_notes (user_id, note) VALUES (?1, ?2)
                     ON CONFLICT(user_id) DO UPDATE SET note = excluded.note",
                )
                .bind(&id.0)
                .bind(note)
                .execute(&mut *tx)
                .await?;
            }
            sqlx::query(
                "INSERT INTO audit_log (actor, action, target, payload) VALUES (?1, 'user.note.set', ?2, ?3)",
            )
            .bind(actor)
            .bind(&id.0)
            .bind(serde_json::json!({ "cleared": cleared }).to_string())
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(true)
    }

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

    pub async fn mint_tuic_password_if_absent(&self, id: &UserId) -> Result<bool> {
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

    pub async fn known_user_uuids(&self) -> Result<HashSet<String>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT uuid FROM users
             UNION SELECT client_uuid FROM grants WHERE client_uuid IS NOT NULL
             UNION SELECT uuid FROM retired_user_uuids",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(uuid,)| uuid).collect())
    }

    pub async fn rotate_user_uuid(
        &self,
        id: &UserId,
        expected_sha256: &str,
        replacement: &str,
        actor: &str,
    ) -> Result<Vec<ServerId>> {
        if replacement.len() != 36
            || replacement.bytes().any(|byte| byte.is_ascii_uppercase())
            || !vpnctl_crypto::is_valid_uuid(replacement)
        {
            return Err(SqliteInventoryError::Invalid(
                "replacement UUID must be canonical lowercase".into(),
            ));
        }
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let previous: Option<String> = sqlx::query_scalar("SELECT uuid FROM users WHERE id = ?1")
            .bind(&id.0)
            .fetch_optional(&mut *tx)
            .await?;
        let Some(previous) = previous else {
            return Err(SqliteInventoryError::Invalid("no such user".into()));
        };
        let servers = sqlx::query_scalar::<_, String>(
            "SELECT server_id FROM grants WHERE user_id = ?1 ORDER BY server_id",
        )
        .bind(&id.0)
        .fetch_all(&mut *tx)
        .await?
        .into_iter()
        .map(ServerId)
        .collect::<Vec<_>>();
        if previous == replacement {
            tx.commit().await?;
            return Ok(servers);
        }
        if format!("{:x}", Sha256::digest(previous.to_ascii_lowercase())) != expected_sha256 {
            return Err(SqliteInventoryError::Invalid(
                "current UUID has changed".into(),
            ));
        }
        let in_use: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                SELECT 1 FROM users WHERE uuid = ?1 COLLATE NOCASE
                UNION ALL SELECT 1 FROM grants WHERE client_uuid = ?1 COLLATE NOCASE
                UNION ALL SELECT 1 FROM retired_user_uuids WHERE uuid = ?1 COLLATE NOCASE
            )",
        )
        .bind(replacement)
        .fetch_one(&mut *tx)
        .await?;
        if in_use {
            return Err(SqliteInventoryError::Invalid(
                "replacement UUID is in use or retired".into(),
            ));
        }
        sqlx::query("UPDATE users SET uuid = ?1 WHERE id = ?2")
            .bind(replacement)
            .bind(&id.0)
            .execute(&mut *tx)
            .await?;
        let overrides = sqlx::query(
            "UPDATE grants SET client_uuid = ?1
             WHERE user_id = ?2 AND client_uuid = ?3 COLLATE NOCASE",
        )
        .bind(replacement)
        .bind(&id.0)
        .bind(&previous)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        sqlx::query(
            "INSERT INTO audit_log (actor, action, target, payload)
             VALUES (?1, 'user.uuid.rotate', ?2, ?3)",
        )
        .bind(actor)
        .bind(&id.0)
        .bind(
            serde_json::json!({"servers": servers.len(), "replaced_overrides": overrides})
                .to_string(),
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(servers)
    }

    pub async fn remove_user(&self, id: &UserId) -> Result<()> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        sqlx::query(
            "INSERT INTO audit_log (actor, action, target, payload)
             SELECT 'inventory', 'user.revoke', ?1,
                    json_object('server', server_id, 'reason', 'user.remove')
             FROM grants WHERE user_id = ?1",
        )
        .bind(&id.0)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM users WHERE id = ?1")
            .bind(&id.0)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn set_user_disabled_audited(
        &self,
        id: &UserId,
        disabled: bool,
        actor: &str,
    ) -> Result<bool> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let new_val: i64 = if disabled { 1 } else { 0 };
        let res = sqlx::query("UPDATE users SET disabled = ?1 WHERE id = ?2 AND disabled != ?1")
            .bind(new_val)
            .bind(&id.0)
            .execute(&mut *tx)
            .await?;
        let changed = res.rows_affected() > 0;
        if changed {
            sqlx::query(
                "INSERT INTO audit_log (actor, action, target, payload) VALUES (?1, ?2, ?3, ?4)",
            )
            .bind(actor)
            .bind(if disabled {
                "user.disable"
            } else {
                "user.enable"
            })
            .bind(&id.0)
            .bind(serde_json::json!({ "disabled": disabled }).to_string())
            .execute(&mut *tx)
            .await?;
        } else {
            let exists: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id = ?1)")
                    .bind(&id.0)
                    .fetch_one(&mut *tx)
                    .await?;
            if !exists {
                return Err(SqliteInventoryError::Invalid(format!(
                    "no such user: {}",
                    id.0
                )));
            }
        }
        tx.commit().await?;
        Ok(changed)
    }

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
