use crate::sqlite::base::SqliteInventory;
use crate::sqlite::models::{Result, SqliteInventoryError};
use crate::sqlite::users::crud::row_to_user;
use chrono::{DateTime, Utc};
use sqlx::Row;
use std::collections::HashMap;
use vpnctl_core::{Server, ServerId, User, UserId};

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

    pub async fn users_for_server(&self, server: &ServerId) -> Result<Vec<User>> {
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

    pub async fn count_grants(&self) -> Result<i64> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM grants")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.try_get("n")?)
    }

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
