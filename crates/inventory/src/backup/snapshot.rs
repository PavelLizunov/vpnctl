use std::path::{Path, PathBuf};

use crate::sqlite::{SqliteInventory, SqliteInventoryError};

use super::listing::snapshot_filename_at;

pub async fn snapshot_to(
    inv: &SqliteInventory,
    snapshot_path: &Path,
) -> Result<(), SqliteInventoryError> {
    let path_str = snapshot_path.to_string_lossy();
    if path_str.contains('\0') {
        return Err(SqliteInventoryError::Invalid(format!(
            "snapshot path contains NUL byte: {path_str:?}"
        )));
    }
    let escaped = path_str.replace('\'', "''");
    let sql = format!("VACUUM INTO '{escaped}'");
    sqlx::query(&sql).execute(inv.pool()).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(snapshot_path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o600);
            let _ = std::fs::set_permissions(snapshot_path, perms);
        }
    }
    Ok(())
}

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
