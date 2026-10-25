use std::path::{Path, PathBuf};

use crate::sqlite::SqliteInventoryError;

pub async fn restore_from(
    snapshot_path: &Path,
    db_path: &Path,
) -> Result<(), SqliteInventoryError> {
    let validate_opts = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(snapshot_path)
        .read_only(true);
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(validate_opts)
        .await
        .map_err(|e| {
            SqliteInventoryError::Invalid(format!(
                "snapshot {} not a valid SQLite file: {e}",
                snapshot_path.display()
            ))
        })?;
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'
         AND name IN ('_sqlx_migrations', 'users', 'servers')",
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        SqliteInventoryError::Invalid(format!(
            "snapshot {} sqlite_master query failed: {e}",
            snapshot_path.display()
        ))
    })?;
    if row.0 != 3 {
        pool.close().await;
        return Err(SqliteInventoryError::Invalid(format!(
            "snapshot {} is missing vpnctl inventory tables — not a vpnctl backup",
            snapshot_path.display()
        )));
    }
    pool.close().await;

    let tmp_path = restore_tmp_path(db_path);
    tokio::task::spawn_blocking({
        let snapshot_path = snapshot_path.to_path_buf();
        let tmp_path = tmp_path.clone();
        move || {
            if tmp_path.exists() {
                let _ = std::fs::remove_file(&tmp_path);
            }
            std::fs::copy(&snapshot_path, &tmp_path)
        }
    })
    .await
    .map_err(|e| SqliteInventoryError::Invalid(format!("spawn_blocking failed: {e}")))?
    .map_err(|e| {
        SqliteInventoryError::Invalid(format!(
            "copy {} -> {}: {e}",
            snapshot_path.display(),
            tmp_path.display()
        ))
    })?;
    let migrate_opts = sqlx::sqlite::SqliteConnectOptions::new().filename(&tmp_path);
    let migrate_pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(migrate_opts)
        .await
        .map_err(|e| {
            let _ = std::fs::remove_file(&tmp_path);
            SqliteInventoryError::Invalid(format!("open tmp restore {}: {e}", tmp_path.display()))
        })?;
    if let Err(e) = crate::sqlite::migrator().run(&migrate_pool).await {
        migrate_pool.close().await;
        let _ = std::fs::remove_file(&tmp_path);
        return Err(SqliteInventoryError::Invalid(format!(
            "snapshot {} schema incompatible with current binary: {e}",
            snapshot_path.display()
        )));
    }
    migrate_pool.close().await;
    tokio::task::spawn_blocking({
        let tmp_path = tmp_path.clone();
        let db_path = db_path.to_path_buf();
        move || {
            if let Ok(f) = std::fs::OpenOptions::new().read(true).open(&tmp_path) {
                let _ = f.sync_all();
            }
            std::fs::rename(&tmp_path, &db_path)
        }
    })
    .await
    .map_err(|e| SqliteInventoryError::Invalid(format!("spawn_blocking failed: {e}")))?
    .map_err(|e| {
        let _ = std::fs::remove_file(&tmp_path);
        SqliteInventoryError::Invalid(format!(
            "rename {} -> {}: {e}",
            tmp_path.display(),
            db_path.display()
        ))
    })?;
    for ext in ["-wal", "-shm"] {
        let sidecar = sidecar_path(db_path, ext);
        if sidecar.exists() {
            let _ = std::fs::remove_file(&sidecar);
        }
    }
    Ok(())
}

fn restore_tmp_path(db: &Path) -> PathBuf {
    let mut s = db.as_os_str().to_os_string();
    s.push(".restore.tmp");
    PathBuf::from(s)
}

fn sidecar_path(db: &Path, suffix: &str) -> PathBuf {
    let mut s = db.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}
