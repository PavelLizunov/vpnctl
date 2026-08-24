use std::path::{Path, PathBuf};

use crate::sqlite::{SqliteInventory, SqliteInventoryError};

use super::listing::snapshot_filename_at;

/// Create a snapshot of the inventory database at `snapshot_path`.
///
/// Uses SQLite's `VACUUM INTO` which:
///   * is online (no readers blocked, writers serialised on the
///     write lock — usually held for <100ms at homelab DB sizes);
///   * produces a fully-checkpointed single file (no WAL/`-shm`
///     sidecars needed);
///   * REFUSES to overwrite an existing file — caller should pick a
///     unique path (see `snapshot_filename_at`).
///
/// The path is escaped per SQLite's string-literal rules. Caller is
/// responsible for the parent directory existing and being writable.
///
/// On Unix the new file's permissions are tightened to `0o600` right
/// after creation — these snapshots contain every per-user secret
/// (sub-tokens, WG private keys, TUIC passwords); inheriting the
/// process umask (usually 0644 = world-readable) would be a leak.
pub async fn snapshot_to(
    inv: &SqliteInventory,
    snapshot_path: &Path,
) -> Result<(), SqliteInventoryError> {
    // SQLite's `VACUUM INTO` takes a string literal, NOT a bind
    // parameter. We escape `'` by doubling it (SQL standard).
    // Other path bytes (NUL etc) would already have been rejected
    // when the operator typed the path; nevertheless reject `'` in
    // the path defensively before substituting.
    let path_str = snapshot_path.to_string_lossy();
    if path_str.contains('\0') {
        return Err(SqliteInventoryError::Invalid(format!(
            "snapshot path contains NUL byte: {path_str:?}"
        )));
    }
    // Standard SQL escape for single quotes.
    let escaped = path_str.replace('\'', "''");
    let sql = format!("VACUUM INTO '{escaped}'");
    sqlx::query(&sql).execute(inv.pool()).await?;
    // Tighten permissions to 0o600 (owner read+write only). Snapshot
    // bytes include every sub_token + WG private key + TUIC password
    // — inheriting umask 0644 would let any local user read them.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(snapshot_path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o600);
            // Best-effort — if chmod fails (very unusual on the
            // daemon's owned dir) we'd rather succeed with the file
            // created than refuse the snapshot. Surface via tracing
            // in callers if needed.
            let _ = std::fs::set_permissions(snapshot_path, perms);
        }
    }
    Ok(())
}

/// Convenience: snapshot using the standard `inv.db.<ts>.bak`
/// filename inside `dir`. Returns the full path of the new snapshot.
pub async fn snapshot_now(
    inv: &SqliteInventory,
    dir: &Path,
) -> Result<PathBuf, SqliteInventoryError> {
    ensure_backup_dir(dir)?;
    let name = snapshot_filename_at(chrono::Utc::now());
    let path = dir.join(name);
    snapshot_to(inv, &path).await?;
    Ok(path)
}

/// Ensure `dir` exists with restrictive permissions (0o700). Run on
/// every snapshot — cheap. On Unix sets the mode; on other platforms
/// the directory is created with the OS default and the caller is
/// trusted to lock it down.
pub(crate) fn ensure_backup_dir(dir: &Path) -> Result<(), SqliteInventoryError> {
    std::fs::create_dir_all(dir)
        .map_err(|e| SqliteInventoryError::Invalid(format!("mkdir {}: {e}", dir.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(dir)
            .map_err(|e| SqliteInventoryError::Invalid(format!("stat {}: {e}", dir.display())))?
            .permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(dir, perms)
            .map_err(|e| SqliteInventoryError::Invalid(format!("chmod {}: {e}", dir.display())))?;
    }
    Ok(())
}
