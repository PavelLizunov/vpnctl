use super::*;

impl SqliteInventory {
    /// Load persistent signing material, creating and auditing it only once.
    pub async fn get_or_create_admin_session_secret(&self) -> Result<String> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let existing: Option<String> =
            sqlx::query_scalar("SELECT session_secret FROM admin_auth_settings WHERE id = 1")
                .fetch_optional(&mut *tx)
                .await?;
        if let Some(secret) = existing {
            tx.commit().await?;
            return Ok(secret);
        }
        let secret = vpnctl_crypto::gen_password(32).map_err(SqliteInventoryError::CryptoIo)?;
        sqlx::query("INSERT INTO admin_auth_settings (id, session_secret) VALUES (1, ?1)")
            .bind(&secret)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO audit_log (actor, action, target, payload)
             VALUES ('system', 'admin.session_secret.create', 'admin', '{}')",
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(secret)
    }

    pub async fn get_display_timezone(&self) -> Result<String> {
        let row =
            sqlx::query_as::<_, (String,)>("SELECT timezone FROM display_settings WHERE id = 1")
                .fetch_optional(&self.pool)
                .await?;
        Ok(row
            .map(|(tz,)| tz)
            .unwrap_or_else(|| "Europe/Moscow".into()))
    }

    pub async fn set_display_timezone(&self, tz: &str) -> Result<()> {
        sqlx::query("UPDATE display_settings SET timezone = ?1 WHERE id = 1")
            .bind(tz)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn get_public_base_url(&self) -> Result<Option<String>> {
        let row = sqlx::query_as::<_, (Option<String>,)>(
            "SELECT public_base_url FROM display_settings WHERE id = 1",
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.and_then(|(url,)| url).filter(|url| !url.is_empty()))
    }

    pub async fn set_public_base_url(&self, url: Option<&str>) -> Result<()> {
        sqlx::query("UPDATE display_settings SET public_base_url = ?1 WHERE id = 1")
            .bind(url)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn update_public_base_url_audited(
        &self,
        actor: &str,
        url: Option<&str>,
    ) -> Result<bool> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let current = sqlx::query_as::<_, (Option<String>,)>(
            "SELECT public_base_url FROM display_settings WHERE id = 1",
        )
        .fetch_optional(&mut *tx)
        .await?
        .and_then(|(url,)| url)
        .filter(|url| !url.is_empty());
        if current.as_deref() == url {
            return Ok(false);
        }
        let res = sqlx::query("UPDATE display_settings SET public_base_url = ?1 WHERE id = 1")
            .bind(url)
            .execute(&mut *tx)
            .await?;
        if res.rows_affected() != 1 {
            return Err(SqliteInventoryError::Invalid(
                "display_settings row id=1 is missing".into(),
            ));
        }
        let payload = serde_json::json!({ "from": current, "to": url });
        sqlx::query(
            "INSERT INTO audit_log (actor, action, target, payload) VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(actor)
        .bind("settings.public_url.set")
        .bind("display")
        .bind(serde_json::to_string(&payload)?)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    pub async fn get_telegram_config(&self) -> Result<Option<TelegramConfig>> {
        let row = sqlx::query_as::<
            _,
            (
                Option<String>,
                Option<String>,
                Option<String>,
                Option<String>,
            ),
        >(
            "SELECT telegram_bot_token, telegram_chat_id, proxy_via_server_id, language
                 FROM notification_settings WHERE id = 1",
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(
            |(token, chat_id, proxy_via_server_id, language)| TelegramConfig {
                token,
                chat_id,
                proxy_via_server_id,
                language,
            },
        ))
    }

    pub async fn set_telegram_config(
        &self,
        token: Option<&str>,
        chat_id: Option<&str>,
        proxy_via_server_id: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE notification_settings
             SET telegram_bot_token  = ?1,
                 telegram_chat_id    = ?2,
                 proxy_via_server_id = ?3,
                 updated_at          = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE id = 1",
        )
        .bind(token)
        .bind(chat_id)
        .bind(proxy_via_server_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn set_notification_language(&self, lang: Option<&str>) -> Result<()> {
        sqlx::query(
            "UPDATE notification_settings
             SET language    = ?1,
                 updated_at  = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE id = 1",
        )
        .bind(lang)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn admin_session_secret_is_persistent_unique_and_audited_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("inv.db");
        let inv = SqliteInventory::open(&path).await.unwrap();
        let other_handle = SqliteInventory::open(&path).await.unwrap();
        let (first, second) = tokio::join!(
            inv.get_or_create_admin_session_secret(),
            other_handle.get_or_create_admin_session_secret(),
        );
        let secret = first.unwrap();
        assert_eq!(secret.len(), 43);
        assert!(
            secret
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        );
        assert_eq!(secret, second.unwrap());
        inv.close().await;
        other_handle.close().await;
        let reopened = SqliteInventory::open(&path).await.unwrap();
        assert_eq!(
            secret,
            reopened.get_or_create_admin_session_secret().await.unwrap()
        );
        let audit = reopened.recent_audit(10).await.unwrap();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].action, "admin.session_secret.create");
        assert_eq!(audit[0].payload, Some(serde_json::json!({})));
        assert!(!format!("{reopened:?}").contains(&secret));
        let other = SqliteInventory::open(&dir.path().join("other.db"))
            .await
            .unwrap();
        assert_ne!(
            secret,
            other.get_or_create_admin_session_secret().await.unwrap()
        );
    }

    #[tokio::test]
    async fn admin_session_secret_creation_rolls_back_if_audit_fails() {
        let dir = tempfile::tempdir().unwrap();
        let inv = SqliteInventory::open(&dir.path().join("inv.db"))
            .await
            .unwrap();
        sqlx::query(
            "CREATE TRIGGER reject_session_secret_audit BEFORE INSERT ON audit_log
             WHEN NEW.action = 'admin.session_secret.create'
             BEGIN SELECT RAISE(ABORT, 'test audit failure'); END",
        )
        .execute(&inv.pool)
        .await
        .unwrap();
        assert!(inv.get_or_create_admin_session_secret().await.is_err());
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM admin_auth_settings")
            .fetch_one(&inv.pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
        assert!(inv.recent_audit(10).await.unwrap().is_empty());
        sqlx::query("DROP TRIGGER reject_session_secret_audit")
            .execute(&inv.pool)
            .await
            .unwrap();
        assert_eq!(
            inv.get_or_create_admin_session_secret()
                .await
                .unwrap()
                .len(),
            43
        );
        assert_eq!(inv.recent_audit(10).await.unwrap().len(), 1);
    }
}
