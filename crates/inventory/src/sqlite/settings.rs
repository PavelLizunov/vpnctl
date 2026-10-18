use super::*;

impl SqliteInventory {
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
