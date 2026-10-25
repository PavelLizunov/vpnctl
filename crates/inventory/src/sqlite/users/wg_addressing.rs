use std::collections::HashMap;

use sqlx::{Row, SqliteConnection};
use vpnctl_core::{ServerId, UserId};

use crate::sqlite::base::SqliteInventory;
use crate::sqlite::models::{Result, SqliteInventoryError};

impl SqliteInventory {
    pub(crate) async fn next_wg_octet(
        conn: &mut SqliteConnection,
        server: &ServerId,
    ) -> Result<Option<u16>> {
        let octet: Option<i64> = sqlx::query_scalar(
            "WITH RECURSIVE slots(octet) AS (
             SELECT 2 UNION ALL SELECT octet + 1 FROM slots WHERE octet < 254
         ) SELECT MIN(octet) FROM slots WHERE NOT EXISTS (
             SELECT 1 FROM grants WHERE server_id = ?1 AND wg_octet = slots.octet
         )",
        )
        .bind(&server.0)
        .fetch_one(conn)
        .await?;
        // A full /24 leaves the grant without an address: only rendering a
        // WireGuard peer for it fails, other protocols on the server keep working.
        Ok(octet.and_then(|n| u16::try_from(n).ok()))
    }

    /// Load stable peer addresses, assigning missing enabled grants atomically.
    /// Disabled users retain their reservations but receive no new assignment.
    pub async fn wg_octets_for_server(&self, server: &ServerId) -> Result<HashMap<UserId, u16>> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let rows = sqlx::query(
            "SELECT g.user_id, g.wg_octet FROM grants g JOIN users u ON u.id = g.user_id
             WHERE g.server_id = ?1 AND u.disabled = 0 ORDER BY u.id",
        )
        .bind(&server.0)
        .fetch_all(&mut *tx)
        .await?;
        let mut octets = HashMap::with_capacity(rows.len());
        for row in rows {
            let user = UserId(row.try_get("user_id")?);
            let stored: Option<i64> = row.try_get("wg_octet")?;
            let octet = if let Some(stored) = stored {
                u16::try_from(stored).map_err(|_| {
                    SqliteInventoryError::Invalid(format!(
                        "invalid WireGuard octet {stored} for user '{}' on server '{}'",
                        user.0, server.0
                    ))
                })?
            } else {
                let Some(octet) = Self::next_wg_octet(&mut tx, server).await? else {
                    continue;
                };
                sqlx::query(
                    "UPDATE grants SET wg_octet = ?1 WHERE user_id = ?2 AND server_id = ?3",
                )
                .bind(i64::from(octet))
                .bind(&user.0)
                .bind(&server.0)
                .execute(&mut *tx)
                .await?;
                sqlx::query(
                    "INSERT INTO audit_log (actor, action, target, payload)
                     VALUES ('system', 'grant.wg_octet.assign', ?1,
                             json_object('server', ?2, 'wg_octet', ?3))",
                )
                .bind(&user.0)
                .bind(&server.0)
                .bind(i64::from(octet))
                .execute(&mut *tx)
                .await?;
                octet
            };
            octets.insert(user, octet);
        }
        tx.commit().await?;
        Ok(octets)
    }
}
