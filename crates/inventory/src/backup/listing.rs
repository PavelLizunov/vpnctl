use std::path::{Path, PathBuf};

use crate::sqlite::SqliteInventoryError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotInfo {
    pub path: PathBuf,
    pub file_name: String,
    pub created: Option<String>,
    pub size_bytes: u64,
}

pub const DEFAULT_BACKUP_DIR: &str = "/var/lib/vpnctl/backups";

/// Resolve the shared CLI and daemon snapshot directory.
pub fn backup_dir_from_env() -> PathBuf {
    std::env::var("VPNCTLD_BACKUP_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_BACKUP_DIR))
}

pub const SNAPSHOT_FILENAME_PREFIX: &str = "inv.db.";
pub const SNAPSHOT_FILENAME_SUFFIX: &str = ".bak";

pub fn snapshot_filename_at(at: chrono::DateTime<chrono::Utc>) -> String {
    let ts = at.format("%Y-%m-%dT%H-%M-%S%.3fZ").to_string();
    format!("{SNAPSHOT_FILENAME_PREFIX}{ts}{SNAPSHOT_FILENAME_SUFFIX}")
}

pub fn parse_snapshot_filename(name: &str) -> Option<String> {
    let rest = name.strip_prefix(SNAPSHOT_FILENAME_PREFIX)?;
    let stem = rest.strip_suffix(SNAPSHOT_FILENAME_SUFFIX)?;
    if stem.len() < 19 || !stem.is_char_boundary(11) || !stem.is_char_boundary(19) {
        return None;
    }
    let (date, rest_after_date) = stem.split_at(11);
    if !date.ends_with('T') {
        return None;
    }
    let (hms_raw, tail) = rest_after_date.split_at(8);
    let hms = hms_raw.replacen('-', ":", 2);
    Some(format!("{date}{hms}{tail}"))
}

pub fn list_snapshots(dir: &Path) -> Result<Vec<SnapshotInfo>, SqliteInventoryError> {
    let mut out = Vec::new();
    let read_dir = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => {
            return Err(SqliteInventoryError::Invalid(format!(
                "read backup dir {}: {e}",
                dir.display()
            )));
        }
    };
    for entry in read_dir.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let file_name = entry.file_name().to_string_lossy().into_owned();
        if !file_name.ends_with(SNAPSHOT_FILENAME_SUFFIX) {
            continue;
        }
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(e) => {
                return Err(SqliteInventoryError::Invalid(format!(
                    "stat snapshot {}: {e}",
                    path.display()
                )));
            }
        };
        out.push(SnapshotInfo {
            created: parse_snapshot_filename(&file_name),
            file_name,
            path,
            size_bytes: meta.len(),
        });
    }
    out.sort_by(|a, b| b.file_name.cmp(&a.file_name));
    Ok(out)
}
