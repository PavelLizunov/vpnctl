use std::path::{Path, PathBuf};

use crate::sqlite::SqliteInventoryError;

/// Atomically replace `db_path` with `snapshot_path`. **Daemon MUST
/// be stopped** before calling this — open WAL handles + a hot
/// rename are a recipe for silent corruption.
///
/// Pre-validates the snapshot in two passes:
/// 1. Read-only open + `SELECT name FROM sqlite_master LIMIT 1` —
///    catches truncated / non-SQLite files.
/// 2. `sqlx::Migrator::run` against a temp-file copy of the
///    snapshot — catches schema-version drift (snapshot from older
///    binary missing tables the current binary depends on). If the
///    migrator fails on the temp copy, the live `db_path` is
///    untouched.
///
/// The swap itself is atomic: copy snapshot → `<db_path>.restore.tmp`,
/// run migrations against the tmp, `fsync` it, then
/// `rename(tmp, db_path)`. If the copy fails mid-write, the live DB
/// stays intact and the partial tmp is removed. Only AFTER the
/// rename succeeds do we strip the stale `-wal` / `-shm` sidecars
/// (SQLite re-derives them on next open; a stale sidecar paired with
/// the new DB is silent corruption).
pub async fn restore_from(
    snapshot_path: &Path,
    db_path: &Path,
) -> Result<(), SqliteInventoryError> {
    // Pass 1: read-only open via SqliteConnectOptions::filename so
    // operator-typed paths with `?`, `#`, `&`, or non-ASCII bytes
    // don't get parsed as URL components.
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
    let row: Option<(String,)> = sqlx::query_as("SELECT name FROM sqlite_master LIMIT 1")
        .fetch_optional(&pool)
        .await
        .map_err(|e| {
            SqliteInventoryError::Invalid(format!(
                "snapshot {} sqlite_master query failed: {e}",
                snapshot_path.display()
            ))
        })?;
    if row.is_none() {
        pool.close().await;
        return Err(SqliteInventoryError::Invalid(format!(
            "snapshot {} has empty sqlite_master — not a vpnctl backup",
            snapshot_path.display()
        )));
    }
    pool.close().await;

    // Pass 2: schema-version compatibility. Copy snapshot to a
    // sibling tmp (same FS as db_path, so the later rename is
    // atomic), open it RW, run the embedded migrator. Migrations
    // are forward-only: an OLDER-than-binary snapshot is upgraded
    // forward to the current schema. A NEWER-than-binary snapshot
    // (taken by a later binary with migrations this build doesn't
    // know about) is REJECTED — sqlx 0.8 has no `set_ignore_missing`,
    // so the migrator returns `VersionMissing` for the unknown
    // applied versions and we treat it as schema-incompatible. If
    // migration fails (VersionMissing, dirty/incompatible schema,
    // sqlx version mismatch, etc) we reject the restore BEFORE
    // touching the live db_path.
    let tmp_path = restore_tmp_path(db_path);
    tokio::task::spawn_blocking({
        let snapshot_path = snapshot_path.to_path_buf();
        let tmp_path = tmp_path.clone();
        move || {
            if tmp_path.exists() {
                // Leftover from a previous aborted restore — clean up.
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
    // fsync the tmp so its bytes hit disk before we rename over
    // db_path. Without fsync a power loss between copy and rename
    // can leave the operator with a half-written tmp + a fresh
    // missing-rows db.
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
            // Best-effort: SQLite would treat a stale -wal as
            // pending uncommitted writes against the OLD page set,
            // which doesn't exist anymore in the restored DB.
            let _ = std::fs::remove_file(&sidecar);
        }
    }
    Ok(())
}

/// Tempfile path used by `restore_from` for the atomic-rename
/// two-step. Lives next to `db_path` so the final `rename` stays
/// on one filesystem (POSIX guarantees `rename` is atomic only
/// within a filesystem).
fn restore_tmp_path(db: &Path) -> PathBuf {
    let mut s = db.as_os_str().to_os_string();
    s.push(".restore.tmp");
    PathBuf::from(s)
}

/// Build a sidecar path like `inv.db-wal` for a given `-wal` /
/// `-shm` suffix. SQLite sidecars share the DB path with the
/// suffix appended (not prefixed with a dot).
fn sidecar_path(db: &Path, suffix: &str) -> PathBuf {
    let mut s = db.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}
