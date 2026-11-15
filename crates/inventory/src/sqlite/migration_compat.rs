use super::{Result, SqliteInventoryError};
use sqlx::{Sqlite, Transaction};

pub(super) async fn adopt_legacy_traffic_migration(tx: &mut Transaction<'_, Sqlite>) -> Result<()> {
    let applied: Option<(String, Vec<u8>, bool)> = sqlx::query_as(
        "SELECT description, checksum, success FROM _sqlx_migrations WHERE version = 70",
    )
    .fetch_optional(&mut **tx)
    .await?;
    let Some((description, checksum, true)) = applied else {
        return Ok(());
    };
    if description != "server traffic limits" {
        return Ok(());
    }
    let canonical = super::base::migrator()
        .iter()
        .find(|m| m.version == 71)
        .ok_or_else(|| {
            SqliteInventoryError::Invalid("canonical traffic migration missing".into())
        })?;
    if checksum.as_slice() != canonical.checksum.as_ref() {
        return Err(SqliteInventoryError::Invalid(
            "unrecognized legacy traffic migration checksum".into(),
        ));
    }
    let collision: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM _sqlx_migrations WHERE version = 71)")
            .fetch_one(&mut **tx)
            .await?;
    if collision {
        return Err(SqliteInventoryError::Invalid(
            "legacy traffic migration version collision".into(),
        ));
    }
    sqlx::query("UPDATE _sqlx_migrations SET version = 71 WHERE version = 70")
        .execute(&mut **tx)
        .await?;
    sqlx::query("INSERT INTO audit_log (actor, action, payload) VALUES ('system', 'migration.server_traffic.reindex', '{\"from\":70,\"to\":71}')")
        .execute(&mut **tx).await?;
    Ok(())
}
