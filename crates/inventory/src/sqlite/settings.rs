use super::*;

impl SqliteInventory {
    // ── Display settings (migration 0027) ──────────────────────────

    /// Read the operator-configured display timezone (IANA name like
    /// «Europe/Moscow», «America/New_York», «UTC»). Defaults to
    /// «Europe/Moscow» — migration 0027 seeds the row.
    ///
    /// Returns `Err` only on storage-layer failures; missing-row
    /// returns the default («Europe/Moscow») since a corrupted DB
    /// shouldn't crash-loop the daemon's render path.
    pub async fn get_display_timezone(&self) -> Result<String> {
        let row =
            sqlx::query_as::<_, (String,)>("SELECT timezone FROM display_settings WHERE id = 1")
                .fetch_optional(&self.pool)
                .await?;
        Ok(row
            .map(|(tz,)| tz)
            .unwrap_or_else(|| "Europe/Moscow".into()))
    }

    /// Update the display timezone. Caller is responsible for
    /// validating the value is a valid IANA name BEFORE calling
    /// (the daemon's handler parses via `chrono_tz::Tz::from_str`
    /// and rejects invalid input with 400; this layer just writes
    /// whatever string the caller hands it). Also responsible for
    /// updating any in-memory cache.
    pub async fn set_display_timezone(&self, tz: &str) -> Result<()> {
        sqlx::query("UPDATE display_settings SET timezone = ?1 WHERE id = 1")
            .bind(tz)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ── Phase G chunk 3 notification_settings ──────────────────────

    /// Read the singleton notification-transport config. All three
    /// fields are `Option<String>` because each can independently be
    /// NULL in the schema; callers downstream (the dispatch loop, the
    /// Settings UI) decide what to do with partial config.
    ///
    /// Returns `Ok(None)` if the singleton row is somehow missing
    /// (shouldn't happen — migration 0014 seeds it — but defended
    /// against so a corrupted DB doesn't crash-loop the daemon).
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

    /// Atomically set ALL THREE halves of the Telegram config. `None`
    /// for a field clears it. Caller-side validators (the Settings
    /// POST handler) reject the «partial config» state of
    /// (Some(token), None, _) or vice versa before reaching here —
    /// but the DB doesn't enforce it because «clear» is a legitimate
    /// `Set(None, None, None)` call.
    ///
    /// `proxy_via_server_id` is a plain TEXT (no FK to `servers.id`)
    /// — see migration 0015's doc-comment for the rationale (operator
    /// gets a loud SSH-spawn error rather than a silent FK-cascade
    /// NULL when the referenced server is deleted).
    ///
    /// Writes `updated_at` automatically via `strftime`. Does NOT
    /// write to `audit_log` — caller is responsible for the audit
    /// row (with `payload_json` that NEVER includes the token).
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

    /// Set the operator's notification language (`'en'` / `'ru'`;
    /// `None` clears → renders as English). Independent of
    /// `set_telegram_config` (which leaves this column untouched), so
    /// flipping the language never disturbs the token / chat_id. Caller
    /// writes the audit row.
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
