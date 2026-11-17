mod types;
mod validation;

pub use types::*;

use sqlx::{Connection, Row, Sqlite, SqliteConnection, Transaction};
use vpnctl_core::{ServerId, UserId};

use super::SqliteInventory;

async fn durable_connection(inv: &CorpInventory) -> CorpResult<sqlx::pool::PoolConnection<Sqlite>> {
    if !validation::identifier(&inv.company_id) {
        return Err(CorpStoreError::InvalidInput("invalid company identity"));
    }
    let mut connection = inv.pool.acquire().await?;
    // This setting is connection-local and must precede the transaction. Keep
    // FULL on return to the pool, including cancellation/error paths.
    sqlx::query("PRAGMA synchronous = FULL")
        .execute(&mut *connection)
        .await?;
    Ok(connection)
}

fn unsigned(value: i64) -> CorpResult<u64> {
    u64::try_from(value).map_err(|_| CorpStoreError::InvalidInput("negative stored counter"))
}

fn record_from_row(row: &sqlx::sqlite::SqliteRow) -> CorpResult<CorpRecord> {
    let json: String = row.try_get("credentials_json")?;
    let credentials = validation::decode_credentials(&json)?;
    let status = CorpStatus {
        user_id: UserId(row.try_get("user_id")?),
        policy_id: row.try_get("policy_id")?,
        enabled: row.try_get("enabled")?,
        auth_generation: unsigned(row.try_get("auth_generation")?)?,
        config_version: unsigned(row.try_get("config_version")?)?,
        revision: unsigned(row.try_get("revision")?)?,
        active_key_id: row.try_get("active_key_id")?,
    };
    if status.active_key_id != credentials.active_key_id {
        return Err(CorpStoreError::InvalidInput(
            "inconsistent stored active key",
        ));
    }
    Ok(CorpRecord {
        status,
        credentials,
    })
}

async fn record_on(conn: &mut SqliteConnection, company: &str) -> CorpResult<Option<CorpRecord>> {
    sqlx::query(
        "SELECT user_id, policy_id, enabled, auth_generation, config_version,
                revision, active_key_id, credentials_json FROM corp_policy_settings WHERE company_id = ?1",
    )
    .bind(company)
    .fetch_optional(conn)
    .await?
    .as_ref()
    .map(record_from_row)
    .transpose()
}

async fn required_record(conn: &mut SqliteConnection, company: &str) -> CorpResult<CorpRecord> {
    record_on(conn, company)
        .await?
        .ok_or(CorpStoreError::Unavailable)
}

async fn user_enabled(conn: &mut SqliteConnection, user: &UserId) -> CorpResult<bool> {
    Ok(
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id = ?1 AND disabled = 0)")
            .bind(&user.0)
            .fetch_one(conn)
            .await?,
    )
}

async fn require_active(conn: &mut SqliteConnection, status: &CorpStatus) -> CorpResult<()> {
    if !status.enabled || !user_enabled(conn, &status.user_id).await? {
        return Err(CorpStoreError::Unavailable);
    }
    Ok(())
}

fn require_version(status: &CorpStatus, expected: u64) -> CorpResult<()> {
    if status.config_version != expected {
        return Err(CorpStoreError::Conflict);
    }
    Ok(())
}

async fn audit(
    conn: &mut SqliteConnection,
    actor: &str,
    action: &str,
    status: &CorpStatus,
    payload: &serde_json::Value,
) -> CorpResult<()> {
    sqlx::query("INSERT INTO audit_log (actor, action, target, payload) VALUES (?1, ?2, ?3, ?4)")
        .bind(actor)
        .bind(action)
        .bind(&status.policy_id)
        .bind(payload.to_string())
        .execute(conn)
        .await?;
    Ok(())
}

async fn advance_authority(
    tx: &mut Transaction<'_, Sqlite>,
    status: &mut CorpStatus,
    company: &str,
) -> CorpResult<()> {
    status.auth_generation = validation::next_counter(status.auth_generation)?;
    status.config_version = validation::next_counter(status.config_version)?;
    sqlx::query(
        "UPDATE corp_policy_settings SET auth_generation = ?1, config_version = ?2 WHERE company_id = ?3",
    )
    .bind(status.auth_generation as i64)
    .bind(status.config_version as i64)
    .bind(company)
    .execute(&mut **tx)
    .await?;
    sqlx::query("DELETE FROM corp_policy_sessions WHERE company_id = ?1")
        .bind(company)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

fn revision_from_row(row: &sqlx::sqlite::SqliteRow) -> CorpResult<CorpRevision> {
    Ok(CorpRevision {
        revision: unsigned(row.try_get("revision")?)?,
        key_id: row.try_get("key_id")?,
        published_at: row.try_get("published_at")?,
        payload_sha256: row.try_get("payload_sha256")?,
        payload: row.try_get("payload")?,
        envelope: row.try_get("envelope")?,
    })
}

async fn revision_on(
    conn: &mut SqliteConnection,
    revision: u64,
    phone: bool,
    company: &str,
) -> CorpResult<Option<CorpRevision>> {
    sqlx::query(if phone {
        "SELECT revision, key_id, published_at, payload_sha256, payload, envelope
         FROM corp_policy_phone_revisions WHERE revision = ?1 AND company_id = ?2"
    } else {
        "SELECT revision, key_id, published_at, payload_sha256, payload, envelope
         FROM corp_policy_revisions WHERE revision = ?1 AND company_id = ?2"
    })
    .bind(revision as i64)
    .bind(company)
    .fetch_optional(conn)
    .await?
    .as_ref()
    .map(revision_from_row)
    .transpose()
}

async fn phone_floor(conn: &mut SqliteConnection, company: &str) -> CorpResult<u64> {
    unsigned(
        sqlx::query_scalar("SELECT revision FROM corp_policy_phone_settings WHERE company_id = ?1")
            .bind(company)
            .fetch_one(conn)
            .await?,
    )
}

async fn egress_on(
    conn: &mut SqliteConnection,
    company: &str,
) -> CorpResult<Vec<CorpVerifiedEgress>> {
    let rows = sqlx::query(
        "SELECT server_id, ip, configuration_fingerprint, verified_at FROM corp_policy_egress WHERE company_id = ?1",
    )
    .bind(company)
    .fetch_all(conn)
    .await?;
    let mut entries = Vec::with_capacity(rows.len());
    for row in rows {
        let ip: String = row.try_get("ip")?;
        entries.push(CorpVerifiedEgress {
            server_id: ServerId(row.try_get("server_id")?),
            ip: ip
                .parse()
                .map_err(|_| CorpStoreError::InvalidInput("invalid stored exit IP"))?,
            configuration_fingerprint: row.try_get("configuration_fingerprint")?,
            verified_at: row.try_get("verified_at")?,
        });
    }
    validation::egress(&entries)
}

#[derive(Clone, Debug)]
pub struct CorpInventory {
    pool: sqlx::SqlitePool,
    company_id: String,
}

impl CorpInventory {
    pub async fn corp_record(&self) -> CorpResult<Option<CorpRecord>> {
        let mut conn = self.pool.acquire().await?;
        record_on(&mut conn, &self.company_id).await
    }

    pub async fn create_corp(&self, setup: &CorpSetup, actor: &str) -> CorpResult<CorpStatus> {
        validation::actor(actor)?;
        if !validation::identifier(&self.company_id)
            || !validation::identifier(&setup.user_id.0)
            || !validation::identifier(&setup.policy_id)
        {
            return Err(CorpStoreError::InvalidInput("invalid binding identity"));
        }
        let credentials = validation::credentials(&setup.credentials)?;
        let mut conn = durable_connection(self).await?;
        let mut tx = conn.begin_with("BEGIN IMMEDIATE").await?;
        if record_on(&mut tx, &self.company_id).await?.is_some() {
            return Err(CorpStoreError::Conflict);
        }
        let bound: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM corp_policy_settings WHERE user_id = ?1 OR policy_id = ?2)")
            .bind(&setup.user_id.0).bind(&setup.policy_id).fetch_one(&mut *tx).await?;
        if bound {
            return Err(CorpStoreError::Conflict);
        }
        if !user_enabled(&mut tx, &setup.user_id).await? {
            return Err(CorpStoreError::Unavailable);
        }
        sqlx::query(
            "INSERT INTO corp_policy_settings
             (company_id, user_id, policy_id, enabled, auth_generation, config_version, revision, active_key_id, credentials_json)
             VALUES (?5, ?1, ?2, 0, 1, 1, 0, ?3, ?4)",
        )
        .bind(&setup.user_id.0)
        .bind(&setup.policy_id)
        .bind(&credentials.active_key_id)
        .bind(validation::encode_credentials(&credentials))
        .bind(&self.company_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query("INSERT INTO corp_policy_phone_settings (company_id, revision) VALUES (?1, 0) ON CONFLICT(company_id) DO NOTHING")
            .bind(&self.company_id).execute(&mut *tx).await?;
        let status = required_record(&mut tx, &self.company_id).await?.status;
        audit(
            &mut tx,
            actor,
            "corp.create",
            &status,
            &serde_json::json!({"user_id": setup.user_id.0}),
        )
        .await?;
        tx.commit().await?;
        Ok(status)
    }

    pub async fn update_corp_security(
        &self,
        expected_config_version: u64,
        enabled: bool,
        credentials: &CorpCredentials,
        actor: &str,
    ) -> CorpResult<CorpStatus> {
        validation::actor(actor)?;
        let credentials = validation::credentials(credentials)?;
        let mut conn = durable_connection(self).await?;
        let mut tx = conn.begin_with("BEGIN IMMEDIATE").await?;
        let current = required_record(&mut tx, &self.company_id).await?;
        let mut status = current.status;
        require_version(&status, expected_config_version)?;
        if enabled && !user_enabled(&mut tx, &status.user_id).await? {
            return Err(CorpStoreError::Unavailable);
        }
        if status.enabled == enabled && current.credentials == credentials {
            tx.commit().await?;
            return Ok(status);
        }
        for old_key in &current.credentials.signing_keys {
            if !credentials
                .signing_keys
                .iter()
                .any(|key| key.id == old_key.id && key.spki == old_key.spki)
            {
                let retained: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM corp_policy_phone_revisions WHERE key_id = ?1 AND company_id = ?2)",
                )
                .bind(&old_key.id)
                .bind(&self.company_id)
                .fetch_one(&mut *tx)
                .await?;
                if retained {
                    return Err(CorpStoreError::Conflict);
                }
            }
        }
        advance_authority(&mut tx, &mut status, &self.company_id).await?;
        status.enabled = enabled;
        status.active_key_id.clone_from(&credentials.active_key_id);
        sqlx::query(
            "UPDATE corp_policy_settings SET enabled = ?1, active_key_id = ?2, credentials_json = ?3 WHERE company_id = ?4",
        )
        .bind(enabled)
        .bind(&credentials.active_key_id)
        .bind(validation::encode_credentials(&credentials))
        .bind(&self.company_id)
        .execute(&mut *tx)
        .await?;
        audit(
            &mut tx,
            actor,
            "corp.security.update",
            &status,
            &serde_json::json!({"enabled": enabled, "config_version": status.config_version}),
        )
        .await?;
        tx.commit().await?;
        Ok(status)
    }

    pub async fn replace_corp_egress(
        &self,
        expected_config_version: u64,
        entries: &[CorpVerifiedEgress],
        actor: &str,
    ) -> CorpResult<CorpStatus> {
        validation::actor(actor)?;
        let entries = validation::egress(entries)?;
        let mut conn = durable_connection(self).await?;
        let mut tx = conn.begin_with("BEGIN IMMEDIATE").await?;
        let mut status = required_record(&mut tx, &self.company_id).await?.status;
        require_version(&status, expected_config_version)?;
        if egress_on(&mut tx, &self.company_id).await? == entries {
            tx.commit().await?;
            return Ok(status);
        }
        for entry in &entries {
            let exists: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM servers WHERE id = ?1)")
                    .bind(&entry.server_id.0)
                    .fetch_one(&mut *tx)
                    .await?;
            if !exists {
                return Err(CorpStoreError::InvalidInput(
                    "verified exit server does not exist",
                ));
            }
        }
        advance_authority(&mut tx, &mut status, &self.company_id).await?;
        sqlx::query("DELETE FROM corp_policy_egress WHERE company_id = ?1")
            .bind(&self.company_id)
            .execute(&mut *tx)
            .await?;
        for entry in &entries {
            sqlx::query(
                "INSERT INTO corp_policy_egress (server_id, ip, configuration_fingerprint, verified_at, company_id)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
            )
            .bind(&entry.server_id.0)
            .bind(entry.ip.to_string())
            .bind(&entry.configuration_fingerprint)
            .bind(entry.verified_at)
            .bind(&self.company_id)
            .execute(&mut *tx).await?;
        }
        audit(
            &mut tx,
            actor,
            "corp.egress.replace",
            &status,
            &serde_json::json!({"count": entries.len(), "config_version": status.config_version}),
        )
        .await?;
        tx.commit().await?;
        Ok(status)
    }

    pub async fn refresh_corp_egress(
        &self,
        expected_config_version: u64,
        previous: &[CorpVerifiedEgress],
        refreshed: &[CorpVerifiedEgress],
        actor: &str,
    ) -> CorpResult<CorpStatus> {
        validation::actor(actor)?;
        let previous = validation::egress(previous)?;
        let refreshed = validation::egress(refreshed)?;
        if previous.len() != refreshed.len()
            || previous.iter().zip(&refreshed).any(|(old, new)| {
                old.server_id != new.server_id
                    || old.ip != new.ip
                    || old.configuration_fingerprint != new.configuration_fingerprint
                    || new.verified_at < old.verified_at
            })
        {
            return Err(CorpStoreError::InvalidInput(
                "renewal must preserve exit identities and not backdate proof",
            ));
        }
        let mut conn = durable_connection(self).await?;
        let mut tx = conn.begin_with("BEGIN IMMEDIATE").await?;
        let status = required_record(&mut tx, &self.company_id).await?.status;
        require_version(&status, expected_config_version)?;
        if egress_on(&mut tx, &self.company_id).await? != previous {
            return Err(CorpStoreError::Conflict);
        }
        if !user_enabled(&mut tx, &status.user_id).await? {
            return Err(CorpStoreError::Unavailable);
        }
        for entry in &refreshed {
            let exists: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM servers WHERE id = ?1)")
                    .bind(&entry.server_id.0)
                    .fetch_one(&mut *tx)
                    .await?;
            if !exists {
                return Err(CorpStoreError::InvalidInput(
                    "verified exit server does not exist",
                ));
            }
        }
        if previous == refreshed {
            tx.commit().await?;
            return Ok(status);
        }
        for (old, entry) in previous.iter().zip(&refreshed) {
            if old.verified_at == entry.verified_at {
                continue;
            }
            sqlx::query(
                "UPDATE corp_policy_egress SET verified_at = ?1 WHERE server_id = ?2 AND ip = ?3 AND company_id = ?4",
            )
            .bind(entry.verified_at)
            .bind(&entry.server_id.0)
            .bind(entry.ip.to_string())
            .bind(&self.company_id)
            .execute(&mut *tx)
            .await?;
        }
        audit(
            &mut tx,
            actor,
            "corp.egress.refresh",
            &status,
            &serde_json::json!({"count": refreshed.len()}),
        )
        .await?;
        tx.commit().await?;
        Ok(status)
    }

    pub async fn corp_verified_egress(&self) -> CorpResult<Vec<CorpVerifiedEgress>> {
        let mut conn = self.pool.acquire().await?;
        egress_on(&mut conn, &self.company_id).await
    }

    pub async fn issue_corp_session(
        &self,
        expected_auth_generation: u64,
        session: &CorpSessionInput,
        now: i64,
        actor: &str,
    ) -> CorpResult<()> {
        validation::actor(actor)?;
        validation::session(session, now)?;
        let mut conn = durable_connection(self).await?;
        let mut tx = conn.begin_with("BEGIN IMMEDIATE").await?;
        let status = required_record(&mut tx, &self.company_id).await?.status;
        require_active(&mut tx, &status).await?;
        if status.auth_generation != expected_auth_generation {
            return Err(CorpStoreError::Conflict);
        }
        let pruned = sqlx::query(
            "DELETE FROM corp_policy_sessions WHERE expires_at <= ?1 AND company_id = ?2",
        )
        .bind(now)
        .bind(&self.company_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM corp_policy_sessions WHERE company_id = ?1")
                .bind(&self.company_id)
                .fetch_one(&mut *tx)
                .await?;
        if count >= 128 {
            return Err(CorpStoreError::Conflict);
        }
        let duplicate: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM corp_policy_sessions WHERE token_hash = ?1)",
        )
        .bind(&session.token_hash)
        .fetch_one(&mut *tx)
        .await?;
        if duplicate {
            return Err(CorpStoreError::Conflict);
        }
        sqlx::query(
            "INSERT INTO corp_policy_sessions (token_hash, csrf_token, expires_at, auth_generation, company_id)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(&session.token_hash)
        .bind(&session.csrf_token)
        .bind(session.expires_at)
        .bind(status.auth_generation as i64)
        .bind(&self.company_id)
        .execute(&mut *tx)
        .await?;
        audit(&mut tx, actor, "corp.session.create", &status,
            &serde_json::json!({"auth_generation": status.auth_generation, "expired_removed": pruned})).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn corp_session(
        &self,
        token_hash: &str,
        now: i64,
    ) -> CorpResult<Option<CorpSession>> {
        if !validation::hex_digest(token_hash) || !validation::unix_time(now) {
            return Err(CorpStoreError::InvalidInput("invalid session lookup"));
        }
        let row = sqlx::query(
            "SELECT s.auth_generation, c.config_version, s.csrf_token, s.expires_at
             FROM corp_policy_sessions s
             JOIN corp_policy_settings c ON c.company_id = s.company_id AND c.auth_generation = s.auth_generation
             JOIN users u ON u.id = c.user_id AND u.disabled = 0
             WHERE s.token_hash = ?1 AND s.expires_at > ?2 AND c.enabled = 1 AND s.company_id = ?3",
        )
        .bind(token_hash)
        .bind(now)
        .bind(&self.company_id)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref()
            .map(|row| {
                Ok(CorpSession {
                    auth_generation: unsigned(row.try_get("auth_generation")?)?,
                    config_version: unsigned(row.try_get("config_version")?)?,
                    csrf_token: row.try_get("csrf_token")?,
                    expires_at: row.try_get("expires_at")?,
                })
            })
            .transpose()
    }

    pub async fn revoke_corp_session(&self, token_hash: &str, actor: &str) -> CorpResult<bool> {
        validation::actor(actor)?;
        if !validation::hex_digest(token_hash) {
            return Err(CorpStoreError::InvalidInput("invalid session digest"));
        }
        let mut conn = durable_connection(self).await?;
        let mut tx = conn.begin_with("BEGIN IMMEDIATE").await?;
        let deleted = sqlx::query(
            "DELETE FROM corp_policy_sessions WHERE token_hash = ?1 AND company_id = ?2",
        )
        .bind(token_hash)
        .bind(&self.company_id)
        .execute(&mut *tx)
        .await?
        .rows_affected()
            != 0;
        if deleted {
            let status = required_record(&mut tx, &self.company_id).await?.status;
            audit(
                &mut tx,
                actor,
                "corp.session.revoke",
                &status,
                &serde_json::json!({}),
            )
            .await?;
        }
        tx.commit().await?;
        Ok(deleted)
    }

    pub async fn revoke_corp_sessions(
        &self,
        expected_config_version: u64,
        actor: &str,
    ) -> CorpResult<CorpStatus> {
        validation::actor(actor)?;
        let mut conn = durable_connection(self).await?;
        let mut tx = conn.begin_with("BEGIN IMMEDIATE").await?;
        let mut status = required_record(&mut tx, &self.company_id).await?.status;
        require_version(&status, expected_config_version)?;
        advance_authority(&mut tx, &mut status, &self.company_id).await?;
        audit(
            &mut tx,
            actor,
            "corp.sessions.revoke",
            &status,
            &serde_json::json!({"auth_generation": status.auth_generation}),
        )
        .await?;
        tx.commit().await?;
        Ok(status)
    }

    pub async fn publish_corp_policy(
        &self,
        publication: &CorpPublication,
        actor: &str,
    ) -> CorpResult<CorpRevision> {
        self.publish_corp_feed(publication, actor, false).await
    }

    pub async fn publish_corp_phone_policy(
        &self,
        publication: &CorpPublication,
        actor: &str,
    ) -> CorpResult<CorpRevision> {
        self.publish_corp_feed(publication, actor, true).await
    }

    async fn publish_corp_feed(
        &self,
        publication: &CorpPublication,
        actor: &str,
        phone: bool,
    ) -> CorpResult<CorpRevision> {
        validation::actor(actor)?;
        let mut conn = durable_connection(self).await?;
        let mut tx = conn.begin_with("BEGIN IMMEDIATE").await?;
        let mut status = required_record(&mut tx, &self.company_id).await?.status;
        require_active(&mut tx, &status).await?;
        require_version(&status, publication.expected_config_version)?;
        if phone {
            status.revision = phone_floor(&mut tx, &self.company_id).await?;
        }
        if status.revision != publication.expected_revision
            || status.active_key_id != publication.key_id
        {
            return Err(CorpStoreError::Conflict);
        }
        let rule_count = validation::publication(publication, &status, phone)?;
        status.revision = validation::next_counter(status.revision)?;
        sqlx::query(
            if phone { "INSERT INTO corp_policy_phone_revisions (revision, key_id, published_at, payload_sha256, payload, envelope, company_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)" } else { "INSERT INTO corp_policy_revisions (revision, key_id, published_at, payload_sha256, payload, envelope, company_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)" },
        )
        .bind(status.revision as i64).bind(&publication.key_id).bind(publication.published_at)
        .bind(&publication.payload_sha256).bind(&publication.payload).bind(&publication.envelope).bind(&self.company_id)
        .execute(&mut *tx).await?;
        sqlx::query(if phone {
            "UPDATE corp_policy_phone_settings SET revision = ?1 WHERE company_id = ?2"
        } else {
            "UPDATE corp_policy_settings SET revision = ?1 WHERE company_id = ?2"
        })
        .bind(status.revision as i64)
        .bind(&self.company_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(if phone {
            "DELETE FROM corp_policy_phone_revisions WHERE revision <= ?1 AND company_id = ?2"
        } else {
            "DELETE FROM corp_policy_revisions WHERE revision <= ?1 AND company_id = ?2"
        })
        .bind(status.revision.saturating_sub(100) as i64)
        .bind(&self.company_id)
        .execute(&mut *tx)
        .await?;
        audit(
            &mut tx,
            actor,
            if phone {
                "corp.telephony.publish"
            } else {
                "corp.policy.publish"
            },
            &status,
            &serde_json::json!({
                "revision": status.revision, "key_id": publication.key_id,
                "payload_sha256": publication.payload_sha256, "rule_count": rule_count,
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(CorpRevision {
            revision: status.revision,
            key_id: publication.key_id.clone(),
            published_at: publication.published_at,
            payload_sha256: publication.payload_sha256.clone(),
            payload: publication.payload.clone(),
            envelope: publication.envelope.clone(),
        })
    }

    pub async fn corp_current_policy(
        &self,
        expected_config_version: u64,
    ) -> CorpResult<Option<CorpRevision>> {
        self.corp_current_feed(expected_config_version, false).await
    }

    pub async fn corp_current_phone_policy(
        &self,
        expected_config_version: u64,
    ) -> CorpResult<Option<CorpRevision>> {
        self.corp_current_feed(expected_config_version, true).await
    }

    async fn corp_current_feed(
        &self,
        expected_config_version: u64,
        phone: bool,
    ) -> CorpResult<Option<CorpRevision>> {
        // One read snapshot binds credential version and current publication.
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let status = required_record(&mut tx, &self.company_id).await?.status;
        require_active(&mut tx, &status).await?;
        require_version(&status, expected_config_version)?;
        let revision = if phone {
            phone_floor(&mut tx, &self.company_id).await?
        } else {
            status.revision
        };
        let result = revision_on(&mut tx, revision, phone, &self.company_id).await?;
        tx.commit().await?;
        Ok(result)
    }

    pub async fn corp_revision(&self, revision: u64) -> CorpResult<Option<CorpRevision>> {
        self.corp_feed_revision(revision, false).await
    }

    pub async fn corp_phone_revision(&self, revision: u64) -> CorpResult<Option<CorpRevision>> {
        self.corp_feed_revision(revision, true).await
    }

    async fn corp_feed_revision(
        &self,
        revision: u64,
        phone: bool,
    ) -> CorpResult<Option<CorpRevision>> {
        if !(1..=CORP_MAX_REVISION).contains(&revision) {
            return Err(CorpStoreError::InvalidInput("revision is out of range"));
        }
        let mut conn = self.pool.acquire().await?;
        revision_on(&mut conn, revision, phone, &self.company_id).await
    }

    pub async fn corp_history(&self, limit: usize) -> CorpResult<Vec<CorpRevision>> {
        self.corp_feed_history(limit, false).await
    }

    pub async fn corp_phone_history(&self, limit: usize) -> CorpResult<Vec<CorpRevision>> {
        self.corp_feed_history(limit, true).await
    }

    async fn corp_feed_history(&self, limit: usize, phone: bool) -> CorpResult<Vec<CorpRevision>> {
        if !(1..=100).contains(&limit) {
            return Err(CorpStoreError::InvalidInput("history limit must be 1-100"));
        }
        let rows = sqlx::query(if phone {
            "SELECT revision, key_id, published_at, payload_sha256, payload, envelope
             FROM corp_policy_phone_revisions WHERE company_id = ?2 ORDER BY revision DESC LIMIT ?1"
        } else {
            "SELECT revision, key_id, published_at, payload_sha256, payload, envelope
             FROM corp_policy_revisions WHERE company_id = ?2 ORDER BY revision DESC LIMIT ?1"
        })
        .bind(limit as i64)
        .bind(&self.company_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(revision_from_row).collect()
    }
}

impl SqliteInventory {
    pub fn corp_for(&self, company_id: &str) -> CorpInventory {
        CorpInventory {
            pool: self.pool.clone(),
            company_id: company_id.to_owned(),
        }
    }

    pub async fn corp_companies(&self) -> CorpResult<Vec<CorpCompany>> {
        let rows = sqlx::query("SELECT company_id, user_id, policy_id, enabled, auth_generation, config_version, revision, active_key_id, credentials_json FROM corp_policy_settings ORDER BY company_id")
            .fetch_all(&self.pool).await?;
        rows.iter()
            .map(|row| {
                Ok(CorpCompany {
                    company_id: row.try_get("company_id")?,
                    status: record_from_row(row)?.status,
                })
            })
            .collect()
    }

    pub async fn corp_company_for_username(
        &self,
        username: &str,
    ) -> CorpResult<Option<CorpCompany>> {
        let row = sqlx::query("SELECT c.company_id, c.user_id, c.policy_id, c.enabled, c.auth_generation, c.config_version, c.revision, c.active_key_id, c.credentials_json FROM corp_policy_settings c JOIN users u ON u.id = c.user_id WHERE u.id = ?1")
            .bind(username).fetch_optional(&self.pool).await?;
        row.as_ref()
            .map(|row| {
                Ok(CorpCompany {
                    company_id: row.try_get("company_id")?,
                    status: record_from_row(row)?.status,
                })
            })
            .transpose()
    }

    pub async fn corp_company_session(
        &self,
        token_hash: &str,
        now: i64,
    ) -> CorpResult<Option<CorpCompanySession>> {
        if !validation::hex_digest(token_hash) || !validation::unix_time(now) {
            return Err(CorpStoreError::InvalidInput("invalid session lookup"));
        }
        let row = sqlx::query("SELECT s.company_id, s.auth_generation, c.config_version, s.csrf_token, s.expires_at FROM corp_policy_sessions s JOIN corp_policy_settings c ON c.company_id = s.company_id AND c.auth_generation = s.auth_generation JOIN users u ON u.id = c.user_id AND u.disabled = 0 WHERE s.token_hash = ?1 AND s.expires_at > ?2 AND c.enabled = 1")
            .bind(token_hash).bind(now).fetch_optional(&self.pool).await?;
        row.as_ref()
            .map(|row| {
                Ok(CorpCompanySession {
                    company_id: row.try_get("company_id")?,
                    session: CorpSession {
                        auth_generation: unsigned(row.try_get("auth_generation")?)?,
                        config_version: unsigned(row.try_get("config_version")?)?,
                        csrf_token: row.try_get("csrf_token")?,
                        expires_at: row.try_get("expires_at")?,
                    },
                })
            })
            .transpose()
    }

    pub async fn corp_record(&self) -> CorpResult<Option<CorpRecord>> {
        self.corp_for("legacy").corp_record().await
    }

    pub async fn create_corp(&self, setup: &CorpSetup, actor: &str) -> CorpResult<CorpStatus> {
        self.corp_for("legacy").create_corp(setup, actor).await
    }

    pub async fn update_corp_security(
        &self,
        expected_config_version: u64,
        enabled: bool,
        credentials: &CorpCredentials,
        actor: &str,
    ) -> CorpResult<CorpStatus> {
        self.corp_for("legacy")
            .update_corp_security(expected_config_version, enabled, credentials, actor)
            .await
    }

    pub async fn replace_corp_egress(
        &self,
        expected_config_version: u64,
        entries: &[CorpVerifiedEgress],
        actor: &str,
    ) -> CorpResult<CorpStatus> {
        self.corp_for("legacy")
            .replace_corp_egress(expected_config_version, entries, actor)
            .await
    }

    pub async fn refresh_corp_egress(
        &self,
        expected_config_version: u64,
        previous: &[CorpVerifiedEgress],
        refreshed: &[CorpVerifiedEgress],
        actor: &str,
    ) -> CorpResult<CorpStatus> {
        self.corp_for("legacy")
            .refresh_corp_egress(expected_config_version, previous, refreshed, actor)
            .await
    }

    pub async fn corp_verified_egress(&self) -> CorpResult<Vec<CorpVerifiedEgress>> {
        self.corp_for("legacy").corp_verified_egress().await
    }

    pub async fn issue_corp_session(
        &self,
        expected_auth_generation: u64,
        session: &CorpSessionInput,
        now: i64,
        actor: &str,
    ) -> CorpResult<()> {
        self.corp_for("legacy")
            .issue_corp_session(expected_auth_generation, session, now, actor)
            .await
    }

    pub async fn corp_session(
        &self,
        token_hash: &str,
        now: i64,
    ) -> CorpResult<Option<CorpSession>> {
        self.corp_for("legacy").corp_session(token_hash, now).await
    }

    pub async fn revoke_corp_session(&self, token_hash: &str, actor: &str) -> CorpResult<bool> {
        self.corp_for("legacy")
            .revoke_corp_session(token_hash, actor)
            .await
    }

    pub async fn revoke_corp_sessions(
        &self,
        expected_config_version: u64,
        actor: &str,
    ) -> CorpResult<CorpStatus> {
        self.corp_for("legacy")
            .revoke_corp_sessions(expected_config_version, actor)
            .await
    }

    pub async fn publish_corp_policy(
        &self,
        publication: &CorpPublication,
        actor: &str,
    ) -> CorpResult<CorpRevision> {
        self.corp_for("legacy")
            .publish_corp_policy(publication, actor)
            .await
    }

    pub async fn publish_corp_phone_policy(
        &self,
        publication: &CorpPublication,
        actor: &str,
    ) -> CorpResult<CorpRevision> {
        self.corp_for("legacy")
            .publish_corp_phone_policy(publication, actor)
            .await
    }

    pub async fn corp_current_policy(
        &self,
        expected_config_version: u64,
    ) -> CorpResult<Option<CorpRevision>> {
        self.corp_for("legacy")
            .corp_current_policy(expected_config_version)
            .await
    }

    pub async fn corp_current_phone_policy(
        &self,
        expected_config_version: u64,
    ) -> CorpResult<Option<CorpRevision>> {
        self.corp_for("legacy")
            .corp_current_phone_policy(expected_config_version)
            .await
    }

    pub async fn corp_revision(&self, revision: u64) -> CorpResult<Option<CorpRevision>> {
        self.corp_for("legacy").corp_revision(revision).await
    }

    pub async fn corp_phone_revision(&self, revision: u64) -> CorpResult<Option<CorpRevision>> {
        self.corp_for("legacy").corp_phone_revision(revision).await
    }

    pub async fn corp_history(&self, limit: usize) -> CorpResult<Vec<CorpRevision>> {
        self.corp_for("legacy").corp_history(limit).await
    }

    pub async fn corp_phone_history(&self, limit: usize) -> CorpResult<Vec<CorpRevision>> {
        self.corp_for("legacy").corp_phone_history(limit).await
    }
}
