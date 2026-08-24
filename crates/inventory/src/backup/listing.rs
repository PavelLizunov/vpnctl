use std::path::{Path, PathBuf};

use crate::sqlite::SqliteInventoryError;

/// One entry in the snapshot directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotInfo {
    /// Absolute path to the snapshot file.
    pub path: PathBuf,
    /// Just the file stem — used by the Settings UI for the download
    /// `<a download="…">` attribute. Same as `path.file_name()` minus
    /// the directory prefix.
    pub file_name: String,
    /// Wall-clock timestamp embedded in the filename, RFC3339-UTC.
    /// `None` if the filename doesn't match the expected pattern
    /// (the directory might also contain operator-dropped files we
    /// don't want to choke on).
    pub created: Option<String>,
    /// Size in bytes. Used by the Settings UI for at-a-glance
    /// "is this snapshot suspiciously small / large" feedback.
    pub size_bytes: u64,
}

/// Where snapshots live by default. Matches the `vpnctld.service`
/// systemd unit's `ReadWritePaths=/var/lib/vpnctl/backups`. The
/// daemon-owner (typically `user:user 0750` on the homelab) MUST
/// have write access; the production install creates the directory
/// during the first daemon start (see `ensure_backup_dir`).
pub const DEFAULT_BACKUP_DIR: &str = "/var/lib/vpnctl/backups";

/// Format used for snapshot filenames. UTC, RFC3339-ish but with the
/// colons replaced with hyphens so the file is safe on Windows /
/// most filesystems / OS export panels.
///
/// Example: `inv.db.2026-05-17T18-45-12Z.bak`
pub const SNAPSHOT_FILENAME_PREFIX: &str = "inv.db.";
pub const SNAPSHOT_FILENAME_SUFFIX: &str = ".bak";

/// Compute the filename for a snapshot timestamped `at`.
pub fn snapshot_filename_at(at: chrono::DateTime<chrono::Utc>) -> String {
    // RFC3339 with colons swapped — keeps lexicographic = chronological
    // ordering AND survives `cmd.exe` / Windows export. Sub-second
    // precision (milliseconds) so back-to-back manual snapshots from
    // the Settings page can't collide.
    let ts = at.format("%Y-%m-%dT%H-%M-%S%.3fZ").to_string();
    format!("{SNAPSHOT_FILENAME_PREFIX}{ts}{SNAPSHOT_FILENAME_SUFFIX}")
}

/// Parse an RFC3339-like timestamp out of a snapshot file name.
/// Inverse of `snapshot_filename_at`. Returns `None` if the name
/// doesn't match the expected shape — used by `list_snapshots` to
/// surface non-vpnctl files without panicking.
pub fn parse_snapshot_filename(name: &str) -> Option<String> {
    let rest = name.strip_prefix(SNAPSHOT_FILENAME_PREFIX)?;
    let stem = rest.strip_suffix(SNAPSHOT_FILENAME_SUFFIX)?;
    // Reverse the colon-swap so the operator sees a real RFC3339.
    // Restrict to the `HH-MM-SS` portion (chars 11..19); anything
    // else stays untouched.
    if stem.len() < 19 || !stem.is_char_boundary(11) || !stem.is_char_boundary(19) {
        return None;
    }
    let (date, rest_after_date) = stem.split_at(11); // "YYYY-MM-DDT"
    if !date.ends_with('T') {
        return None;
    }
    let (hms_raw, tail) = rest_after_date.split_at(8); // "HH-MM-SS"
    let hms = hms_raw.replacen('-', ":", 2);
    Some(format!("{date}{hms}{tail}"))
}

/// List every `inv.db.*.bak` file in `dir`, newest first. Files that
/// don't match the naming convention are still listed (with
/// `created = None`) so the operator can spot stray downloads /
/// editor backup files via the Settings page.
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
        // Only surface files that look like our snapshots OR have the
        // `.bak` suffix at all — keeps random `.txt` notes out.
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
    // Newest first — `inv.db.<ts>.bak` is lex-ordered = chrono-ordered.
    out.sort_by(|a, b| b.file_name.cmp(&a.file_name));
    Ok(out)
}
