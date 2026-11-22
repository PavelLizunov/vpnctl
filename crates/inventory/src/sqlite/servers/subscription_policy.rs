use crate::sqlite::{Result, SqliteInventory, SqliteInventoryError};
use vpnctl_core::ServerId;

impl SqliteInventory {
    pub async fn desktop_subscription_core(&self, server: &ServerId) -> Result<Option<String>> {
        sqlx::query_scalar("SELECT desktop_subscription_core FROM servers WHERE id = ?1")
            .bind(&server.0)
            .fetch_one(&self.pool)
            .await
            .map_err(Into::into)
    }

    pub async fn set_desktop_subscription_core(
        &self,
        server: &ServerId,
        core_version: Option<&str>,
    ) -> Result<()> {
        if core_version.is_some_and(|version| !valid_core_version(version)) {
            return Err(SqliteInventoryError::Invalid(
                "enter a managed sing-box version such as 1.14.4-vpnctl.3".to_owned(),
            ));
        }
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let previous: Option<String> =
            sqlx::query_scalar("SELECT desktop_subscription_core FROM servers WHERE id = ?1")
                .bind(&server.0)
                .fetch_one(&mut *transaction)
                .await?;
        if previous.as_deref() == core_version {
            transaction.commit().await?;
            return Ok(());
        }
        sqlx::query("UPDATE servers SET desktop_subscription_core = ?1 WHERE id = ?2")
            .bind(core_version)
            .bind(&server.0)
            .execute(&mut *transaction)
            .await?;
        sqlx::query(
            "INSERT INTO audit_log (actor, action, target, payload)
             VALUES ('admin', 'server.desktop_subscription.set', ?1, ?2)",
        )
        .bind(&server.0)
        .bind(serde_json::json!({"old": previous, "new": core_version}).to_string())
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }
}

fn valid_core_version(version: &str) -> bool {
    let Some((base, revision)) = version.split_once("-vpnctl.") else {
        return false;
    };
    let canonical_number = |value: &str| {
        value.as_bytes().iter().all(u8::is_ascii_digit)
            && (!value.starts_with('0') || value.len() == 1)
            && value.parse::<u32>().is_ok()
    };
    let mut components = base.split('.');
    (0..3).all(|_| {
        components
            .next()
            .is_some_and(|value| canonical_number(value) && value.parse::<i32>().is_ok())
    }) && components.next().is_none()
        && canonical_number(revision)
        && revision != "0"
}
