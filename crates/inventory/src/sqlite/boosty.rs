use super::*;
use vpnctl_core::{User, UserId};

impl SqliteInventory {
    pub async fn list_boosty_links(&self) -> Result<Vec<(UserId, i64)>> {
        let rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT id, boosty_subscriber_id FROM users
              WHERE boosty_subscriber_id IS NOT NULL
              ORDER BY id",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(id, sid)| (UserId(id), sid))
            .collect())
    }

    pub async fn list_boosty_links_with_lapse(&self) -> Result<Vec<(UserId, i64, Option<i64>)>> {
        let rows: Vec<(String, i64, Option<i64>)> = sqlx::query_as(
            "SELECT id, boosty_subscriber_id, boosty_lapsed_since FROM users
              WHERE boosty_subscriber_id IS NOT NULL
              ORDER BY id",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(id, sid, since)| (UserId(id), sid, since))
            .collect())
    }

    pub async fn link_boosty_subscriber(&self, user: &UserId, subscriber_id: i64) -> Result<bool> {
        let res = sqlx::query(
            "UPDATE users
                SET boosty_subscriber_id = ?1, boosty_lapsed_since = NULL
              WHERE id = ?2 AND boosty_subscriber_id IS NOT ?1",
        )
        .bind(subscriber_id)
        .bind(&user.0)
        .execute(&self.pool)
        .await?;
        if res.rows_affected() > 0 {
            return Ok(true);
        }
        let exists: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE id = ?1")
            .bind(&user.0)
            .fetch_one(&self.pool)
            .await?;
        if exists.0 == 0 {
            return Err(SqliteInventoryError::Invalid(format!(
                "no such user: {}",
                user.0
            )));
        }
        Ok(false)
    }

    pub async fn unlink_boosty_subscriber(&self, user: &UserId) -> Result<bool> {
        let res = sqlx::query(
            "UPDATE users
                SET boosty_subscriber_id = NULL, boosty_lapsed_since = NULL
              WHERE id = ?1 AND boosty_subscriber_id IS NOT NULL",
        )
        .bind(&user.0)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Apply a reconcile decision only while its link and opposite status still match.
    pub async fn set_boosty_user_disabled(
        &self,
        user: &UserId,
        subscriber_id: i64,
        disabled: bool,
    ) -> Result<bool> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let result = sqlx::query(
            "UPDATE users SET disabled = ?1
              WHERE id = ?2 AND boosty_subscriber_id = ?3 AND disabled = ?4",
        )
        .bind(i64::from(disabled))
        .bind(&user.0)
        .bind(subscriber_id)
        .bind(i64::from(!disabled))
        .execute(&mut *tx)
        .await?;
        let changed = result.rows_affected() == 1;
        if changed {
            let action = if disabled {
                "boosty.disable"
            } else {
                "boosty.enable"
            };
            sqlx::query(
                "INSERT INTO audit_log (actor, action, target, payload)
                 VALUES ('boosty-bridge', ?1, ?2, ?3)",
            )
            .bind(action)
            .bind(&user.0)
            .bind(serde_json::json!({ "reason": "subscription reconcile" }).to_string())
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(changed)
    }

    pub async fn observe_boosty_lapse(
        &self,
        user: &UserId,
        since: Option<i64>,
    ) -> Result<Option<i64>> {
        match since {
            Some(since) => {
                sqlx::query(
                    "UPDATE users
                        SET boosty_lapsed_since =
                            CASE
                                WHEN boosty_lapsed_since IS NULL
                                  OR boosty_lapsed_since > ?1 THEN ?1
                                ELSE boosty_lapsed_since
                            END
                      WHERE id = ?2 AND boosty_subscriber_id IS NOT NULL",
                )
                .bind(since)
                .bind(&user.0)
                .execute(&self.pool)
                .await?;
            }
            None => {
                sqlx::query(
                    "UPDATE users SET boosty_lapsed_since = NULL
                      WHERE id = ?1 AND boosty_subscriber_id IS NOT NULL",
                )
                .bind(&user.0)
                .execute(&self.pool)
                .await?;
            }
        }
        let row: Option<(Option<i64>,)> =
            sqlx::query_as("SELECT boosty_lapsed_since FROM users WHERE id = ?1")
                .bind(&user.0)
                .fetch_optional(&self.pool)
                .await?;
        row.map(|r| r.0).ok_or_else(|| {
            SqliteInventoryError::Invalid(format!("no such linked user: {}", user.0))
        })
    }

    pub async fn add_boosty_user(&self, user: &User, subscriber_id: i64) -> Result<u64> {
        let token = match user.sub_token.as_deref() {
            Some(token) if !token.is_empty() => token.to_string(),
            _ => vpnctl_crypto::gen_sub_token().map_err(SqliteInventoryError::CryptoIo)?,
        };
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let inserted = sqlx::query(
            "INSERT INTO users (
                id, uuid, tuic_password, wireguard_pubkey, wireguard_private,
                sub_token, vpn_router_device_id, disabled, boosty_subscriber_id
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        )
        .bind(&user.id.0)
        .bind(&user.uuid)
        .bind(&user.tuic_password)
        .bind(&user.wireguard_pubkey)
        .bind(&user.wireguard_private)
        .bind(token)
        .bind(&user.vpn_router_device_id)
        .bind(i64::from(user.disabled))
        .bind(subscriber_id)
        .execute(&mut *tx)
        .await;
        map_unique(inserted, format!("user {}", user.id.0))?;

        let servers: Vec<(String,)> =
            sqlx::query_as("SELECT id FROM servers WHERE role = 'vpn-exit' ORDER BY id")
                .fetch_all(&mut *tx)
                .await?;
        let mut grants = 0;
        for (server,) in servers {
            let server = vpnctl_core::ServerId(server);
            let octet = Self::next_wg_octet(&mut tx, &server).await?;
            grants += sqlx::query(
                "INSERT INTO grants (user_id, server_id, granted_at, wg_octet)
                 VALUES (?1, ?2, datetime('now'), ?3)",
            )
            .bind(&user.id.0)
            .bind(&server.0)
            .bind(octet.map(i64::from))
            .execute(&mut *tx)
            .await?
            .rows_affected();
            sqlx::query(
                "INSERT INTO audit_log (actor, action, target, payload)
                 VALUES ('boosty', 'user.grant', ?1,
                         json_object('server', ?2, 'source', 'boosty', 'wg_octet', ?3))",
            )
            .bind(&user.id.0)
            .bind(&server.0)
            .bind(octet.map(i64::from))
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(grants)
    }

    pub async fn get_boosty_settings(&self) -> Result<BoostySettings> {
        let row: Option<BoostySettingsRow> = sqlx::query_as(
            "SELECT enabled, blog_url, access_token, refresh_token, device_id,
                        poll_interval_secs, auto_disable_lapsed,
                        grace_days, auto_create_users
                   FROM boosty_settings WHERE id = 1",
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(match row {
            Some((
                enabled,
                blog_url,
                access_token,
                refresh_token,
                device_id,
                interval,
                auto_disable,
                grace_days,
                auto_create_users,
            )) => BoostySettings {
                enabled: enabled != 0,
                blog_url,
                access_token,
                refresh_token,
                device_id,
                poll_interval_secs: u64::try_from(interval).unwrap_or(3600),
                auto_disable_lapsed: auto_disable != 0,
                grace_days: u16::try_from(grace_days).unwrap_or(14),
                auto_create_users: auto_create_users != 0,
            },
            None => BoostySettings::default(),
        })
    }

    pub async fn set_boosty_settings(&self, s: &BoostySettings) -> Result<()> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let result = sqlx::query(
            "UPDATE boosty_settings
                SET enabled = ?1, blog_url = ?2, access_token = ?3,
                    refresh_token = COALESCE(?4, refresh_token), device_id = ?5, poll_interval_secs = ?6,
                    auto_disable_lapsed = ?7,
                    grace_days = ?8, auto_create_users = ?9,
                    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
              WHERE id = 1 AND (
                    enabled IS NOT ?1 OR blog_url IS NOT ?2 OR access_token IS NOT ?3
                    OR refresh_token IS NOT COALESCE(?4, refresh_token)
                    OR device_id IS NOT ?5 OR poll_interval_secs IS NOT ?6
                    OR auto_disable_lapsed IS NOT ?7 OR grace_days IS NOT ?8
                    OR auto_create_users IS NOT ?9)",
        )
        .bind(i64::from(s.enabled))
        .bind(&s.blog_url)
        .bind(&s.access_token)
        .bind(&s.refresh_token)
        .bind(&s.device_id)
        .bind(i64::try_from(s.poll_interval_secs).unwrap_or(3600))
        .bind(i64::from(s.auto_disable_lapsed))
        .bind(i64::from(s.grace_days))
        .bind(i64::from(s.auto_create_users))
        .execute(&mut *tx)
        .await?;

        if result.rows_affected() > 0 {
            sqlx::query(
                "INSERT INTO audit_log (actor, action, target, payload)
                 VALUES ('admin', 'boosty.configure', 'boosty_settings', ?1)",
            )
            .bind(
                serde_json::json!({
                    "enabled": s.enabled,
                    "blog_url": s.blog_url,
                    "poll_interval_secs": s.poll_interval_secs,
                    "auto_disable_lapsed": s.auto_disable_lapsed,
                    "grace_days": s.grace_days,
                    "auto_create_users": s.auto_create_users,
                })
                .to_string(),
            )
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn set_boosty_refresh_token(&self, refresh_token: &str) -> Result<()> {
        sqlx::query(
            "UPDATE boosty_settings
                SET refresh_token = ?1,
                    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
              WHERE id = 1",
        )
        .bind(refresh_token)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn rotate_boosty_refresh_token(&self, expected: &str, rotated: &str) -> Result<bool> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let result = sqlx::query(
            "UPDATE boosty_settings
                SET refresh_token = ?1,
                    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
              WHERE id = 1 AND refresh_token = ?2 AND refresh_token IS NOT ?1",
        )
        .bind(rotated)
        .bind(expected)
        .execute(&mut *tx)
        .await?;
        let changed = result.rows_affected() == 1;
        if changed {
            sqlx::query(
                "INSERT INTO audit_log (actor, action, target, payload)
                 VALUES ('boosty-bridge', 'boosty.refresh_token.rotated', 'boosty_settings', NULL)",
            )
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(changed)
    }

    pub async fn clear_boosty_access_token(&self, expected: &str) -> Result<bool> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let result = sqlx::query(
            "UPDATE boosty_settings
                SET access_token = NULL,
                    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
              WHERE id = 1 AND access_token = ?1",
        )
        .bind(expected)
        .execute(&mut *tx)
        .await?;

        if result.rows_affected() == 1 {
            sqlx::query(
                "INSERT INTO audit_log (actor, action, target, payload)
                 VALUES ('system', 'boosty.access_token.cleared', 'boosty_settings', ?1)",
            )
            .bind(
                serde_json::json!({
                    "reason": "refresh_recovery_success"
                })
                .to_string(),
            )
            .execute(&mut *tx)
            .await?;

            tx.commit().await?;
            Ok(true)
        } else {
            tx.rollback().await?;
            Ok(false)
        }
    }

    pub async fn acquire_boosty_sync_lease(&self, owner: &str, ttl_secs: i64) -> Result<bool> {
        self.update_boosty_sync_lease_at(owner, ttl_secs, chrono::Utc::now().timestamp(), false)
            .await
    }

    pub async fn renew_boosty_sync_lease(&self, owner: &str, ttl_secs: i64) -> Result<bool> {
        self.update_boosty_sync_lease_at(owner, ttl_secs, chrono::Utc::now().timestamp(), true)
            .await
    }

    async fn update_boosty_sync_lease_at(
        &self,
        owner: &str,
        ttl_secs: i64,
        now: i64,
        renew: bool,
    ) -> Result<bool> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let result = sqlx::query(
            "UPDATE boosty_settings
                SET sync_lease_owner = ?1,
                    sync_lease_until = ?2
              WHERE id = 1
                AND ((?4 = 0 AND sync_lease_until <= ?3)
                     OR (?4 = 1 AND sync_lease_owner = ?1 AND sync_lease_until > ?3))
                AND (sync_lease_owner IS NOT ?1 OR sync_lease_until IS NOT ?2)",
        )
        .bind(owner)
        .bind(now.saturating_add(ttl_secs))
        .bind(now)
        .bind(i64::from(renew))
        .execute(&mut *tx)
        .await?;
        let changed = result.rows_affected() == 1;
        if changed {
            sqlx::query(
                "INSERT INTO audit_log (actor, action, target, payload)
                 VALUES ('boosty-bridge', ?1, 'boosty_settings', NULL)",
            )
            .bind(if renew {
                "boosty.sync_lease.renewed"
            } else {
                "boosty.sync_lease.acquired"
            })
            .execute(&mut *tx)
            .await?;
        }
        // A renewal in the same second can retain the exact expiry without a write.
        let held = if !changed && renew {
            sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM boosty_settings
                  WHERE id = 1 AND sync_lease_owner = ?1 AND sync_lease_until > ?2)",
            )
            .bind(owner)
            .bind(now)
            .fetch_one(&mut *tx)
            .await?
        } else {
            changed
        };
        tx.commit().await?;
        Ok(held)
    }

    pub async fn release_boosty_sync_lease(&self, owner: &str) -> Result<()> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let result = sqlx::query(
            "UPDATE boosty_settings
                SET sync_lease_owner = NULL, sync_lease_until = 0
              WHERE id = 1 AND sync_lease_owner = ?1",
        )
        .bind(owner)
        .execute(&mut *tx)
        .await?;
        if result.rows_affected() == 1 {
            sqlx::query(
                "INSERT INTO audit_log (actor, action, target, payload)
                 VALUES ('boosty-bridge', 'boosty.sync_lease.released', 'boosty_settings', NULL)",
            )
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn set_boosty_last_report(&self, report_json: &str) -> Result<()> {
        self.set_boosty_report_and_events(report_json, &[]).await
    }

    pub async fn set_boosty_report_and_events(
        &self,
        report_json: &str,
        events: &[(String, Option<String>, serde_json::Value)],
    ) -> Result<()> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        for (action, target, payload) in events {
            sqlx::query(
                "INSERT INTO audit_log (actor, action, target, payload)
                 VALUES ('boosty-bridge', ?1, ?2, ?3)",
            )
            .bind(action)
            .bind(target)
            .bind(payload.to_string())
            .execute(&mut *tx)
            .await?;
        }
        sqlx::query(
            "UPDATE boosty_settings
                SET last_report_json = ?1,
                     last_sync_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
               WHERE id = 1",
        )
        .bind(report_json)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn boosty_last_report(&self) -> Result<Option<(String, String)>> {
        let row: Option<(Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT last_report_json, last_sync_at FROM boosty_settings WHERE id = 1",
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(match row {
            Some((Some(json), Some(ts))) => Some((json, ts)),
            _ => None,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sync_lease_renewal_excludes_other_connections_past_original_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("inv.db");
        let first = SqliteInventory::open(&path).await.unwrap();
        let second = SqliteInventory::open(&path).await.unwrap();
        assert!(
            first
                .update_boosty_sync_lease_at("a", 10, 100, false)
                .await
                .unwrap()
        );
        assert!(
            !second
                .update_boosty_sync_lease_at("b", 10, 109, false)
                .await
                .unwrap()
        );
        assert!(
            first
                .update_boosty_sync_lease_at("a", 10, 109, true)
                .await
                .unwrap()
        );
        let audits = first.recent_audit(20).await.unwrap();
        assert_eq!(audits.len(), 2);
        assert!(
            audits
                .iter()
                .any(|row| row.action == "boosty.sync_lease.renewed")
        );

        assert!(
            first
                .update_boosty_sync_lease_at("a", 10, 109, true)
                .await
                .unwrap()
        );
        assert!(
            !second
                .update_boosty_sync_lease_at("b", 10, 110, false)
                .await
                .unwrap()
        );
        assert_eq!(first.recent_audit(20).await.unwrap().len(), audits.len());
        assert!(
            second
                .update_boosty_sync_lease_at("b", 10, 119, false)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn expired_sync_lease_cannot_be_renewed_or_release_successor() {
        let dir = tempfile::tempdir().unwrap();
        let inv = SqliteInventory::open(&dir.path().join("inv.db"))
            .await
            .unwrap();
        assert!(
            inv.update_boosty_sync_lease_at("a", 10, 100, false)
                .await
                .unwrap()
        );
        assert!(
            !inv.update_boosty_sync_lease_at("a", 10, 110, true)
                .await
                .unwrap()
        );
        assert!(
            inv.update_boosty_sync_lease_at("b", 10, 110, false)
                .await
                .unwrap()
        );
        let audits_before = inv.recent_audit(20).await.unwrap().len();

        assert!(
            !inv.update_boosty_sync_lease_at("a", 10, 111, true)
                .await
                .unwrap()
        );
        inv.release_boosty_sync_lease("a").await.unwrap();
        assert!(
            !inv.update_boosty_sync_lease_at("c", 10, 119, false)
                .await
                .unwrap()
        );
        assert_eq!(inv.recent_audit(20).await.unwrap().len(), audits_before);
        inv.release_boosty_sync_lease("b").await.unwrap();
        assert_eq!(inv.recent_audit(20).await.unwrap().len(), audits_before + 1);
        assert!(
            inv.update_boosty_sync_lease_at("c", 10, 119, false)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn sync_lease_audit_failure_rolls_back_renewal() {
        let dir = tempfile::tempdir().unwrap();
        let inv = SqliteInventory::open(&dir.path().join("inv.db"))
            .await
            .unwrap();
        assert!(
            inv.update_boosty_sync_lease_at("a", 10, 100, false)
                .await
                .unwrap()
        );
        sqlx::query(
            "CREATE TRIGGER reject_lease_renewal_audit BEFORE INSERT ON audit_log
             WHEN NEW.action = 'boosty.sync_lease.renewed'
             BEGIN SELECT RAISE(ABORT, 'reject renewal audit'); END",
        )
        .execute(&inv.pool)
        .await
        .unwrap();
        assert!(
            inv.update_boosty_sync_lease_at("a", 10, 109, true)
                .await
                .is_err()
        );
        assert!(
            inv.update_boosty_sync_lease_at("b", 10, 110, false)
                .await
                .unwrap()
        );
        assert_eq!(inv.recent_audit(20).await.unwrap().len(), 2);
    }
}
