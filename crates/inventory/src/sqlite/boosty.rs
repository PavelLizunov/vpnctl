use super::*;
use vpnctl_core::{User, UserId};

impl SqliteInventory {
    // ── Boosty bridge (migration 0040) ──────────────────────────────────

    /// All user → Boosty-subscriber links (users with a non-NULL
    /// `boosty_subscriber_id`). The reconciler joins these with each
    /// user's `disabled` state.
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

    /// Boosty links with the persisted start of the current lapse spell.
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

    /// Link a vpnctl user to a Boosty subscriber id. Errors only if the user
    /// doesn't exist. Returns whether anything changed (`false` = this user
    /// already carried this exact subscriber id) so callers audit only actual
    /// mutations.
    ///
    /// **Many-to-one is allowed** (migration 0041): one Boosty subscriber can
    /// gate SEVERAL users — one paying person's multiple devices
    /// (`demonnot-1..5`). The reconciler evaluates each link independently, so
    /// they all follow that subscriber's active state.
    pub async fn link_boosty_subscriber(&self, user: &UserId, subscriber_id: i64) -> Result<bool> {
        // `IS NOT ?1` (NULL-safe) makes a same-value re-link match 0 rows →
        // reported as an idempotent no-op below (audit-on-actual-mutation).
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
        // 0 rows: either the user doesn't exist, or it already holds this
        // exact subscriber id. Disambiguate with a presence check.
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

    /// Remove a user's Boosty link. Idempotent; returns whether a link was
    /// actually removed so callers audit only actual mutations.
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

    /// Record the start of a lapse spell, keeping the earliest observation.
    /// Passing `None` clears the marker after a paid subscription recovers.
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

    /// Atomically create a Boosty-owned user and grant every current server.
    pub async fn add_boosty_user(&self, user: &User, subscriber_id: i64) -> Result<u64> {
        let token = match user.sub_token.as_deref() {
            Some(token) if !token.is_empty() => token.to_string(),
            _ => vpnctl_crypto::gen_sub_token().map_err(SqliteInventoryError::CryptoIo)?,
        };
        let mut tx = self.pool.begin().await?;
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

        let grants = sqlx::query(
            "INSERT INTO grants (user_id, server_id, granted_at)
             SELECT ?1, id, datetime('now') FROM servers",
        )
        .bind(&user.id.0)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        tx.commit().await?;
        Ok(grants)
    }

    /// Read the singleton bridge settings row.
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

    /// Overwrite the singleton bridge settings row.
    pub async fn set_boosty_settings(&self, s: &BoostySettings) -> Result<()> {
        sqlx::query(
            "UPDATE boosty_settings
                SET enabled = ?1, blog_url = ?2, access_token = ?3,
                    refresh_token = ?4, device_id = ?5, poll_interval_secs = ?6,
                    auto_disable_lapsed = ?7,
                    grace_days = ?8, auto_create_users = ?9,
                    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
              WHERE id = 1",
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
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Persist a rotated refresh token (Boosty rotates it on every refresh).
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

    /// Persist a rotated token only if the credential used to obtain it is
    /// still current. A token pasted in the Web UI during an in-flight poll
    /// must win instead of being overwritten by that older poll.
    pub async fn rotate_boosty_refresh_token(&self, expected: &str, rotated: &str) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE boosty_settings
                SET refresh_token = ?1,
                    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
              WHERE id = 1 AND refresh_token = ?2",
        )
        .bind(rotated)
        .bind(expected)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Cross-process lease for the rotating Boosty credential and the
    /// snapshot→event transaction. Expired leases recover automatically.
    pub async fn acquire_boosty_sync_lease(&self, owner: &str, ttl_secs: i64) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE boosty_settings
                SET sync_lease_owner = ?1,
                    sync_lease_until = CAST(strftime('%s', 'now') AS INTEGER) + ?2
              WHERE id = 1
                AND sync_lease_until <= CAST(strftime('%s', 'now') AS INTEGER)",
        )
        .bind(owner)
        .bind(ttl_secs)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn release_boosty_sync_lease(&self, owner: &str) -> Result<()> {
        sqlx::query(
            "UPDATE boosty_settings
                SET sync_lease_owner = NULL, sync_lease_until = 0
              WHERE id = 1 AND sync_lease_owner = ?1",
        )
        .bind(owner)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Persist the last APPLIED sync report (serialized `SyncReport`).
    /// `/admin/boosty` renders its actionable sections from this instead of
    /// doing a live (state-mutating) sync on GET.
    pub async fn set_boosty_last_report(&self, report_json: &str) -> Result<()> {
        self.set_boosty_report_and_events(report_json, &[]).await
    }

    /// Atomically replace the applied Boosty snapshot and append its derived
    /// subscriber events. The transaction prevents a crash from writing an
    /// event twice (or losing it) on the next poll.
    pub async fn set_boosty_report_and_events(
        &self,
        report_json: &str,
        events: &[(String, Option<String>, serde_json::Value)],
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
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

    /// The last applied sync report as `(report_json, synced_at)`, when one
    /// has ever been stored.
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
