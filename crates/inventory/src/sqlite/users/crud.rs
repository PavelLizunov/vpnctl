use std::collections::HashSet;

use crate::sqlite::base::{SqliteInventory, map_unique};
use crate::sqlite::models::{Result, SqliteInventoryError};
use sqlx::Row;
use sqlx::sqlite::SqliteRow;
use vpnctl_core::{User, UserId};

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

impl SqliteInventory {
    pub async fn add_user(&self, u: &User) -> Result<()> {
        let token = match u.sub_token.as_deref() {
            Some(t) if !t.is_empty() => t.to_string(),
            _ => vpnctl_crypto::gen_sub_token().map_err(SqliteInventoryError::CryptoIo)?,
        };
        let disabled_i: i64 = if u.disabled { 1 } else { 0 };
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
