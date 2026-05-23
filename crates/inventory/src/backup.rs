//! Hot snapshots of the inventory DB (`inv.db`) for disaster recovery.
//!
//! # The threat model
//!
//! `192.168.0.236` (the homelab host running vpnctld) is today a
//! single point of failure. If the disk dies, the rootfs is corrupted,
//! or someone `rm -rf`'s `/var/lib/vpnctl/`, every per-user secret
//! (sub-tokens, WG private keys, TUIC passwords) is gone — and every
//! VPN client has to be re-onboarded by hand. CLAUDE.md "Strategic
//! context" calls this out as critical.
//!
//! This module solves the *snapshot* half — making a coherent copy
//! of `inv.db` while the daemon is still writing to it — and the
//! *retention* half (don't fill the disk with hourly snapshots
//! forever). The *off-site* half is operator-driven: the Settings
//! page surfaces each snapshot as a downloadable file; the operator
//! copies it to whatever off-machine target they trust (USB,
//! Forgejo, cloud bucket). That keeps credentials for off-site
//! destinations OUT of the daemon — zero blast radius if the host
//! is compromised.
//!
//! # How the snapshot stays coherent
//!
//! SQLite's `VACUUM INTO 'path'` writes a fresh, fully-checkpointed
//! database file at `path` while honouring the WAL — no readers are
//! blocked, in-flight writes are serialised against the VACUUM via
//! the usual SQLite write lock. The output is a self-contained
//! single-file copy you can drop into another vpnctld instance and
//! it opens immediately.
//!
//! `VACUUM INTO` requires the target file NOT to exist (it refuses
//! to overwrite), which is what we want — never silently clobber.
//! The `snapshot_now` helper uses a timestamped filename so
//! collisions are statistically impossible at the homelab cadence
//! (1 ms resolution).
//!
//! # Why no encryption at this layer
//!
//! Encrypting at the daemon would mean either:
//! 1. The decryption key lives next to the encrypted file on the
//!    same disk (zero benefit — burn the disk, lose both), or
//! 2. The operator memorises / offline-stores the key (high
//!    operational burden, easy to lock yourself out).
//!
//! Neither is right for a single-operator homelab. Instead, we keep
//! the local snapshot in plaintext (same trust boundary as the
//! daemon-owned inv.db itself: `user:user 0640`) and let the
//! operator apply encryption at the off-site step (`age`, `gpg`,
//! filesystem encryption, etc) on whichever target they pick.
//!
//! # Restore
//!
//! Restore is a `vpnctl restore <snapshot>` CLI command (see
//! `cli/src/cmd/restore.rs`). It MUST run while the daemon is
//! stopped — otherwise the daemon's open WAL file would race with
//! the new DB. The CLI command pre-validates the snapshot
//! (opens it, runs a sanity SELECT) before performing the atomic
//! rename, so a corrupt snapshot fails fast.
//!
//! The Settings page surfaces the restore command pre-filled with
//! the snapshot path; the operator copies the command into a
//! terminal (one of the few approved CLI exceptions to the
//! "web-only" rule, because the daemon literally cannot replace
//! its own DB while it's holding it open).

use std::path::{Path, PathBuf};

use crate::sqlite::{SqliteInventory, SqliteInventoryError};

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
pub async fn snapshot_to(inv: &SqliteInventory, snapshot_path: &Path) -> Result<()> {
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
pub async fn snapshot_now(inv: &SqliteInventory, dir: &Path) -> Result<PathBuf> {
    ensure_backup_dir(dir)?;
    let name = snapshot_filename_at(chrono::Utc::now());
    let path = dir.join(name);
    snapshot_to(inv, &path).await?;
    Ok(path)
}

/// List every `inv.db.*.bak` file in `dir`, newest first. Files that
/// don't match the naming convention are still listed (with
/// `created = None`) so the operator can spot stray downloads /
/// editor backup files via the Settings page.
pub fn list_snapshots(dir: &Path) -> Result<Vec<SnapshotInfo>> {
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

/// Retention policy applied by `prune_snapshots`. Each field caps
/// how many snapshots survive in that age bucket:
///
///   * `keep_hourly` — keep the N newest snapshots regardless of
///     date,
///   * `keep_daily` — additionally, keep one-per-day for the N
///     newest distinct days,
///   * `keep_monthly` — additionally, keep one-per-month for the N
///     newest distinct months.
///
/// Default (`Retention::default`) is `24h / 30d / 12mo` — enough to
/// roll back a same-day mistake AND a month-old "what was the
/// inventory like before the bash migration" question without
/// running out of disk on a 4 GB partition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Retention {
    pub keep_hourly: usize,
    pub keep_daily: usize,
    pub keep_monthly: usize,
}

impl Default for Retention {
    fn default() -> Self {
        Self {
            keep_hourly: 24,
            keep_daily: 30,
            keep_monthly: 12,
        }
    }
}

/// Drop snapshots that don't fit the retention policy. Returns the
/// number of files removed.
///
/// Algorithm: walk snapshots newest→oldest, classify each into the
/// hourly / daily / monthly bucket. Keep it if its bucket isn't full
/// yet; otherwise delete. Files without a parseable timestamp are
/// LEFT ALONE — operator-dropped files / manually-renamed snapshots
/// shouldn't get nuked by the scheduler.
pub fn prune_snapshots(dir: &Path, policy: Retention) -> Result<u64> {
    let snapshots = list_snapshots(dir)?;
    let mut kept_hourly = 0usize;
    let mut kept_daily_days: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut kept_monthly_months: std::collections::HashSet<String> =
        std::collections::HashSet::new();
    let mut removed = 0u64;

    for snap in snapshots {
        let Some(ts) = snap.created.as_deref() else {
            // Stray / non-vpnctl file: leave alone.
            continue;
        };
        let mut keep = false;
        // Hourly bucket: the N most recent snapshots, regardless of date.
        if kept_hourly < policy.keep_hourly {
            kept_hourly = kept_hourly.saturating_add(1);
            keep = true;
        }
        // Daily bucket: first snapshot we see for each YYYY-MM-DD.
        if let Some((day, _)) = ts.split_once('T')
            && kept_daily_days.len() < policy.keep_daily
            && kept_daily_days.insert(day.to_string())
        {
            keep = true;
        }
        // Monthly bucket: first snapshot per YYYY-MM.
        if ts.len() >= 7
            && let Some(month) = ts.get(..7)
            && kept_monthly_months.len() < policy.keep_monthly
            && kept_monthly_months.insert(month.to_string())
        {
            keep = true;
        }
        if !keep {
            std::fs::remove_file(&snap.path).map_err(|e| {
                SqliteInventoryError::Invalid(format!(
                    "remove old snapshot {}: {e}",
                    snap.path.display()
                ))
            })?;
            removed = removed.saturating_add(1);
        }
    }
    Ok(removed)
}

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
pub async fn restore_from(snapshot_path: &Path, db_path: &Path) -> Result<()> {
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
    // are forward-only + idempotent — running them against a
    // newer-or-current snapshot is a no-op; running against an
    // older snapshot brings it up to current. If migration fails
    // (incompatible schema, sqlx version mismatch, etc) we reject
    // the restore BEFORE touching the live db_path.
    let tmp_path = restore_tmp_path(db_path);
    if tmp_path.exists() {
        // Leftover from a previous aborted restore — clean up.
        let _ = std::fs::remove_file(&tmp_path);
    }
    std::fs::copy(snapshot_path, &tmp_path).map_err(|e| {
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
    if let Ok(f) = std::fs::OpenOptions::new().read(true).open(&tmp_path) {
        let _ = f.sync_all();
    }

    // Atomic on same FS — at no point is db_path missing if the
    // rename succeeds. Stale sidecars get stripped AFTER the
    // rename so they're never paired with a stale db file.
    std::fs::rename(&tmp_path, db_path).map_err(|e| {
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

/// Ensure `dir` exists with restrictive permissions (0o700). Run on
/// every snapshot — cheap. On Unix sets the mode; on other platforms
/// the directory is created with the OS default and the caller is
/// trusted to lock it down.
fn ensure_backup_dir(dir: &Path) -> Result<()> {
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

/// Outcome of a single restore self-test check.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub enum CheckStatus {
    Ok,
    Warn,
    Fail,
}

impl CheckStatus {
    /// Lowercase label suitable for HTML class names + log payloads.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }
}

/// One named check in a [`SelfTestReport`]. The check `name` is
/// stable (used as a key for future history / alerting); `detail`
/// is the human-readable text shown to the operator.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct CheckResult {
    pub name: &'static str,
    pub status: CheckStatus,
    pub detail: String,
}

/// Result of running [`verify_snapshot`] against a snapshot file.
///
/// The `overall` status is the worst of every individual check.
/// A `Fail` means the snapshot would NOT restore cleanly into a
/// live daemon (schema mismatch, empty DB, etc); `Warn` means it
/// would restore but the operator should investigate (e.g. snapshot
/// is suspiciously old, some users have no sub_token).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct SelfTestReport {
    pub snapshot_path: String,
    pub snapshot_size_bytes: u64,
    /// Seconds elapsed between snapshot filename timestamp and `now`.
    /// `None` if the filename doesn't carry a parseable timestamp.
    pub snapshot_age_seconds: Option<i64>,
    pub schema_migrations_applied: i64,
    pub user_count: i64,
    pub server_count: i64,
    pub grant_count: i64,
    pub users_with_sub_token: i64,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub duration_ms: i64,
    pub overall: CheckStatus,
    pub checks: Vec<CheckResult>,
}

/// Number of embedded SQL migration files in this binary. Computed at
/// compile time via `sqlx::migrate!()` — kept in lock-step with the
/// migrator. Used by the snapshot self-test to assert the bundled
/// snapshot's `_sqlx_migrations` row count matches.
fn embedded_migration_count() -> i64 {
    // `Migrator::iter()` yields one entry per `*.sql` file under the
    // `migrations/` dir at compile time. Cheap O(N) — N≈25 today.
    crate::sqlite::migrator().iter().count() as i64
}

/// **Phase 5c — restore self-test**: verify that `snapshot_path`
/// would restore cleanly into a fresh daemon, WITHOUT touching the
/// live `inv.db`.
///
/// What it does (in order, short-circuiting on hard failure):
/// 1. Stat the snapshot file (size + filename age).
/// 2. Read-only open + `SELECT name FROM sqlite_master` — same
///    sanity check as `restore_from` pass 1.
/// 3. Copy to a per-call tmpfile in the system tempdir (NOT next
///    to the live `inv.db` — self-test must be safe to run on a
///    daemon-up host).
/// 4. Open the tmpfile RW and run the embedded migrator — proves
///    schema-compatibility with the CURRENT binary.
/// 5. Query a handful of metrics that catch the «backup was made
///    while DB was empty / truncated» bug class: user count,
///    server count, grant count, sub_token NULL count.
/// 6. Compose a [`SelfTestReport`] with a per-check breakdown and
///    an overall status (worst of all checks).
/// 7. Best-effort cleanup of the tmpfile (errors logged via tracing
///    rather than propagated — the report is still valid).
///
/// Errors from this function are reserved for «the self-test could
/// not even RUN» (snapshot file missing, permission denied, OOM).
/// Schema mismatches, empty DBs, etc are reported as `Fail` checks
/// inside an `Ok(report)`.
pub async fn verify_snapshot(snapshot_path: &Path) -> Result<SelfTestReport> {
    let started_at = chrono::Utc::now();
    let stat = std::fs::metadata(snapshot_path).map_err(|e| {
        SqliteInventoryError::Invalid(format!("stat snapshot {}: {e}", snapshot_path.display()))
    })?;
    let snapshot_size_bytes = stat.len();
    let snapshot_age_seconds = snapshot_path
        .file_name()
        .and_then(|s| s.to_str())
        .and_then(parse_snapshot_filename)
        .and_then(|ts| chrono::DateTime::parse_from_rfc3339(&ts).ok())
        .map(|when| {
            let when_utc = when.with_timezone(&chrono::Utc);
            (started_at - when_utc).num_seconds()
        });

    let mut checks: Vec<CheckResult> = Vec::new();

    // Check 1: read-only sqlite_master sanity. Mirrors restore_from
    // pass 1. If this fails, every subsequent step is moot.
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
    let master_row: Option<(String,)> = sqlx::query_as("SELECT name FROM sqlite_master LIMIT 1")
        .fetch_optional(&pool)
        .await
        .map_err(|e| {
            SqliteInventoryError::Invalid(format!(
                "snapshot {} sqlite_master query failed: {e}",
                snapshot_path.display()
            ))
        })?;
    pool.close().await;
    if master_row.is_none() {
        // Empty DB — record as a fatal check + return early without
        // attempting the expensive copy + migrate steps. The report
        // is still well-formed so the UI can render it.
        checks.push(CheckResult {
            name: "sqlite_master_non_empty",
            status: CheckStatus::Fail,
            detail: "snapshot has empty sqlite_master — not a vpnctl backup".to_string(),
        });
        return Ok(SelfTestReport {
            snapshot_path: snapshot_path.display().to_string(),
            snapshot_size_bytes,
            snapshot_age_seconds,
            schema_migrations_applied: 0,
            user_count: 0,
            server_count: 0,
            grant_count: 0,
            users_with_sub_token: 0,
            started_at,
            duration_ms: (chrono::Utc::now() - started_at).num_milliseconds(),
            overall: CheckStatus::Fail,
            checks,
        });
    }

    // Check 2: copy to system tempfile + run migrator. Unlike
    // restore_from we use the SYSTEM tempdir (not sibling-to-db_path)
    // because self-test must be safe to run concurrently with the
    // live daemon — sibling-to-inv.db is the daemon's WAL territory.
    let tmpfile = tempfile::NamedTempFile::new()
        .map_err(|e| SqliteInventoryError::Invalid(format!("create self-test tmpfile: {e}")))?;
    let tmp_path = tmpfile.path().to_path_buf();
    std::fs::copy(snapshot_path, &tmp_path).map_err(|e| {
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
            SqliteInventoryError::Invalid(format!("open self-test tmp {}: {e}", tmp_path.display()))
        })?;
    let migration_ok = crate::sqlite::migrator().run(&migrate_pool).await;
    let expected_migrations = embedded_migration_count();
    let mut schema_migrations_applied: i64 = 0;
    match migration_ok {
        Ok(()) => {
            // Count rows in _sqlx_migrations. After a successful run
            // this should equal the embedded count. A failure of the
            // COUNT query itself (locked, OOM, etc) MUST surface as a
            // distinct Fail check — `unwrap_or(0)` would silently
            // produce the «snapshot has 0 migrations» Warn shape that
            // looks identical to a real schema-drift case.
            match sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM _sqlx_migrations")
                .fetch_one(&migrate_pool)
                .await
            {
                Ok(n) => {
                    schema_migrations_applied = n;
                    if schema_migrations_applied == expected_migrations {
                        checks.push(CheckResult {
                            name: "schema_migrations_match_binary",
                            status: CheckStatus::Ok,
                            detail: format!(
                                "{schema_migrations_applied} migrations applied (matches binary)"
                            ),
                        });
                    } else {
                        checks.push(CheckResult {
                            name: "schema_migrations_match_binary",
                            status: CheckStatus::Warn,
                            detail: format!(
                                "snapshot has {schema_migrations_applied} migrations, \
                                 binary expects {expected_migrations} \
                                 (snapshot from older/newer vpnctld?)"
                            ),
                        });
                    }
                }
                Err(e) => {
                    checks.push(CheckResult {
                        name: "schema_migrations_match_binary",
                        status: CheckStatus::Fail,
                        detail: format!("migration count query failed: {e}"),
                    });
                }
            }
        }
        Err(e) => {
            checks.push(CheckResult {
                name: "schema_migrations_match_binary",
                status: CheckStatus::Fail,
                detail: format!("migration replay failed: {e}"),
            });
            migrate_pool.close().await;
            return Ok(SelfTestReport {
                snapshot_path: snapshot_path.display().to_string(),
                snapshot_size_bytes,
                snapshot_age_seconds,
                schema_migrations_applied,
                user_count: 0,
                server_count: 0,
                grant_count: 0,
                users_with_sub_token: 0,
                started_at,
                duration_ms: (chrono::Utc::now() - started_at).num_milliseconds(),
                overall: CheckStatus::Fail,
                checks,
            });
        }
    }

    // Check 3-5: data presence metrics. The bug class these catch
    // is «backup was made of an EMPTY db» — VACUUM INTO succeeds on
    // an empty source, producing a syntactically valid but
    // operationally useless backup. COUNT-query failures push a
    // distinct Fail check so the operator can tell «no users» from
    // «we couldn't even ask».
    let user_count = self_test_count(&migrate_pool, "SELECT COUNT(*) FROM users").await;
    let server_count = self_test_count(&migrate_pool, "SELECT COUNT(*) FROM servers").await;
    let grant_count = self_test_count(&migrate_pool, "SELECT COUNT(*) FROM grants").await;
    let users_with_sub_token = self_test_count(
        &migrate_pool,
        "SELECT COUNT(*) FROM users WHERE sub_token IS NOT NULL",
    )
    .await;
    migrate_pool.close().await;

    // Expose count or `-1`-sentinel via the report struct, since the
    // caller still wants raw numbers for UI/audit. Errors are
    // surfaced via the per-check Fail entries below.
    let user_count_i64 = user_count.as_ref().copied().unwrap_or(-1);
    let server_count_i64 = server_count.as_ref().copied().unwrap_or(-1);
    let grant_count_i64 = grant_count.as_ref().copied().unwrap_or(-1);
    let users_with_sub_token_i64 = users_with_sub_token.as_ref().copied().unwrap_or(-1);

    push_count_check(&mut checks, "users_present", &user_count, |n| {
        if n > 0 {
            CheckStatus::Ok
        } else {
            CheckStatus::Fail
        }
    });
    push_count_check(&mut checks, "servers_present", &server_count, |n| {
        if n > 0 {
            CheckStatus::Ok
        } else {
            CheckStatus::Fail
        }
    });
    push_count_check(&mut checks, "grants_present", &grant_count, |n| {
        // Grants empty = nobody has access yet — not fatal (fresh
        // install), but the operator should know.
        if n > 0 {
            CheckStatus::Ok
        } else {
            CheckStatus::Warn
        }
    });

    // users_have_sub_tokens needs BOTH counts to interpret; if either
    // counts query failed, the check itself is unavailable.
    match (&user_count, &users_with_sub_token) {
        (Ok(n_users), Ok(n_with_tok)) => {
            checks.push(CheckResult {
                name: "users_have_sub_tokens",
                // sub_token NULL is acceptable for freshly-created
                // users before mint, but if MANY users lack one it
                // suggests a backup-during-migration race. Warn if
                // any are missing.
                status: if *n_users > 0 && n_with_tok < n_users {
                    CheckStatus::Warn
                } else {
                    CheckStatus::Ok
                },
                detail: format!("{n_with_tok}/{n_users} users have sub_token"),
            });
        }
        _ => {
            checks.push(CheckResult {
                name: "users_have_sub_tokens",
                status: CheckStatus::Fail,
                detail: "could not run check (one of the count queries failed above)".to_string(),
            });
        }
    }

    // Snapshot freshness — derived from filename timestamp. The
    // hourly snapshot cadence + 25h staleness window means even one
    // missed-tick day triggers Warn. Skip the check entirely if
    // filename has no timestamp (downloaded-and-renamed by operator).
    if let Some(age) = snapshot_age_seconds {
        // Negative age = snapshot timestamp in the future (clock
        // skew / wrong TZ on writer). Treat as Warn — the snapshot
        // itself is fine for restore, but the writer's clock needs
        // investigation.
        if age < 0 {
            checks.push(CheckResult {
                name: "snapshot_freshness",
                status: CheckStatus::Warn,
                detail: format!(
                    "snapshot timestamp is {} seconds in the future (clock skew?)",
                    -age
                ),
            });
        } else {
            let status = if age <= 25 * 3600 {
                CheckStatus::Ok
            } else if age <= 72 * 3600 {
                CheckStatus::Warn
            } else {
                CheckStatus::Fail
            };
            let hours = age / 3600;
            checks.push(CheckResult {
                name: "snapshot_freshness",
                status,
                detail: format!("snapshot is {hours} hours old"),
            });
        }
    }

    let overall = checks
        .iter()
        .map(|c| &c.status)
        .max_by_key(|s| match s {
            CheckStatus::Ok => 0,
            CheckStatus::Warn => 1,
            CheckStatus::Fail => 2,
        })
        .cloned()
        .unwrap_or(CheckStatus::Ok);

    let duration_ms = (chrono::Utc::now() - started_at).num_milliseconds();

    Ok(SelfTestReport {
        snapshot_path: snapshot_path.display().to_string(),
        snapshot_size_bytes,
        snapshot_age_seconds,
        schema_migrations_applied,
        user_count: user_count_i64,
        server_count: server_count_i64,
        grant_count: grant_count_i64,
        users_with_sub_token: users_with_sub_token_i64,
        started_at,
        duration_ms,
        overall,
        checks,
    })
}

/// Run a `SELECT COUNT(*) ...` query for the self-test. Returns
/// `Ok(n)` on success or `Err(message)` on any DB error — caller
/// decides how to surface the failure (typically a `Fail` check).
async fn self_test_count(pool: &sqlx::SqlitePool, sql: &str) -> std::result::Result<i64, String> {
    sqlx::query_scalar::<_, i64>(sql)
        .fetch_one(pool)
        .await
        .map_err(|e| format!("query `{sql}` failed: {e}"))
}

/// Helper to push a `users_present` / `servers_present` / etc check
/// based on a [`self_test_count`] result. Centralised so the Ok→OK,
/// Err→Fail wiring is identical at every call site.
fn push_count_check(
    checks: &mut Vec<CheckResult>,
    name: &'static str,
    result: &std::result::Result<i64, String>,
    classify: impl FnOnce(i64) -> CheckStatus,
) {
    match result {
        Ok(n) => checks.push(CheckResult {
            name,
            status: classify(*n),
            detail: format!("{n} {}", name.trim_end_matches("_present")),
        }),
        Err(msg) => checks.push(CheckResult {
            name,
            status: CheckStatus::Fail,
            detail: msg.clone(),
        }),
    }
}

type Result<T> = std::result::Result<T, SqliteInventoryError>;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_filename_round_trips_through_parser() {
        let at = chrono::DateTime::parse_from_rfc3339("2026-05-17T18:45:12.345Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let name = snapshot_filename_at(at);
        assert!(name.starts_with("inv.db.2026-05-17T18-45-12"));
        assert!(name.ends_with(".bak"));
        let parsed = parse_snapshot_filename(&name).unwrap();
        assert!(parsed.starts_with("2026-05-17T18:45:12"));
    }

    #[test]
    fn parse_snapshot_filename_returns_none_for_non_vpnctl_files() {
        assert!(parse_snapshot_filename("inv.db").is_none());
        assert!(parse_snapshot_filename("random.bak").is_none());
        assert!(parse_snapshot_filename("inv.db.bak").is_none());
        assert!(parse_snapshot_filename("inv.db.notes.txt").is_none());
    }

    #[tokio::test]
    async fn snapshot_now_creates_file_and_lists() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("inv.db");
        let inv = SqliteInventory::open(&db).await.unwrap();
        let backup_dir = dir.path().join("backups");
        let snap = snapshot_now(&inv, &backup_dir).await.unwrap();
        assert!(snap.exists(), "snapshot file should exist at {snap:?}");
        assert!(snap.metadata().unwrap().len() > 0);

        let list = list_snapshots(&backup_dir).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].path, snap);
        assert!(list[0].created.is_some());
        assert!(list[0].size_bytes > 0);
    }

    #[tokio::test]
    async fn snapshot_refuses_to_overwrite_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("inv.db");
        let inv = SqliteInventory::open(&db).await.unwrap();
        let backup_dir = dir.path().join("backups");
        std::fs::create_dir_all(&backup_dir).unwrap();
        let target = backup_dir.join("inv.db.2026-01-01T00-00-00.000Z.bak");
        std::fs::write(&target, b"pre-existing").unwrap();
        // VACUUM INTO refuses to overwrite. Caller would have used
        // a fresh timestamp to avoid this; the test pins the safety
        // net. The exact wording is SQLite's choice — we accept
        // anything sqlx surfaces as an error (rather than silently
        // overwriting which is the actual safety risk).
        let err = snapshot_to(&inv, &target).await;
        assert!(
            err.is_err(),
            "snapshot_to MUST refuse to clobber an existing file"
        );
        // Verify the original file is intact (sqlite didn't half-write).
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"pre-existing",
            "existing snapshot file must be untouched on collision"
        );
    }

    #[tokio::test]
    async fn prune_keeps_recent_hourly_and_per_day_per_month() {
        let dir = tempfile::tempdir().unwrap();
        let backup_dir = dir.path().to_path_buf();
        // Seed 50 snapshots: every 15 minutes for ~12 hours, then a
        // few daily-spaced and a few monthly-spaced ones farther
        // back. Cheap empty files — we don't care about content.
        let mut at = chrono::DateTime::parse_from_rfc3339("2026-05-17T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        for _ in 0..48 {
            let name = snapshot_filename_at(at);
            std::fs::write(backup_dir.join(name), b"x").unwrap();
            at -= chrono::Duration::minutes(15);
        }
        for d in 1..=10 {
            let day = chrono::DateTime::parse_from_rfc3339(&format!("2026-05-{:02}T03:00:00Z", d))
                .unwrap()
                .with_timezone(&chrono::Utc);
            std::fs::write(backup_dir.join(snapshot_filename_at(day)), b"x").unwrap();
        }
        for m in 1..=6 {
            let mo = chrono::DateTime::parse_from_rfc3339(&format!("2026-{:02}-01T00:00:00Z", m))
                .unwrap()
                .with_timezone(&chrono::Utc);
            std::fs::write(backup_dir.join(snapshot_filename_at(mo)), b"x").unwrap();
        }

        let policy = Retention {
            keep_hourly: 4,
            keep_daily: 3,
            keep_monthly: 2,
        };
        let removed = prune_snapshots(&backup_dir, policy).unwrap();
        let remaining = list_snapshots(&backup_dir).unwrap();
        assert!(
            remaining.len() <= policy.keep_hourly + policy.keep_daily + policy.keep_monthly,
            "kept {} > cap {}",
            remaining.len(),
            policy.keep_hourly + policy.keep_daily + policy.keep_monthly
        );
        assert!(removed > 0, "should have removed some old snapshots");
    }

    #[tokio::test]
    async fn restore_swaps_db_when_snapshot_valid() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("inv.db");
        let inv = SqliteInventory::open(&db).await.unwrap();
        // Mark the live DB with a known server so we can prove restore happened.
        use vpnctl_core::{KernelId, ProtocolId, Server, ServerId};
        inv.add_server(&Server {
            id: ServerId("live-only".into()),
            address: "203.0.113.99".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![ProtocolId("vless+reality".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
        // Take the snapshot. At this point the snapshot has 'live-only'.
        let snap = snapshot_now(&inv, dir.path()).await.unwrap();
        // Add another server — this MUST NOT be in the restored DB.
        inv.add_server(&Server {
            id: ServerId("after-snapshot".into()),
            address: "203.0.113.100".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![ProtocolId("vless+reality".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
        // Close the live pool BEFORE restoring (mimics "daemon stopped").
        drop(inv);
        // Restore.
        restore_from(&snap, &db).await.unwrap();
        // Re-open and confirm the post-snapshot server is GONE.
        let restored = SqliteInventory::open(&db).await.unwrap();
        let servers = restored.list_servers().await.unwrap();
        let ids: std::collections::HashSet<String> = servers.into_iter().map(|s| s.id.0).collect();
        assert!(
            ids.contains("live-only"),
            "restored DB must contain pre-snapshot row"
        );
        assert!(
            !ids.contains("after-snapshot"),
            "restored DB must NOT contain post-snapshot row"
        );
    }

    #[tokio::test]
    async fn restore_rejects_non_sqlite_file() {
        let dir = tempfile::tempdir().unwrap();
        let bogus = dir.path().join("not-a-db.bak");
        std::fs::write(&bogus, b"hello not a database").unwrap();
        let target = dir.path().join("inv.db");
        let err = restore_from(&bogus, &target).await.unwrap_err();
        assert!(
            format!("{err}").contains("not a valid SQLite file")
                || format!("{err}").to_lowercase().contains("malformed")
                || format!("{err}").to_lowercase().contains("sqlite"),
            "expected validation error, got: {err}"
        );
        // db_path must NOT have been created if validation failed.
        assert!(
            !target.exists(),
            "restore must not create target on validation failure"
        );
    }

    // ── Phase 5c — verify_snapshot tests ─────────────────────────────────

    #[tokio::test]
    async fn verify_snapshot_reports_ok_on_freshly_minted_snapshot() {
        use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("inv.db");
        let inv = SqliteInventory::open(&db).await.unwrap();
        // Seed: 1 user + 1 server + 1 grant + sub_token. This is the
        // minimum «would actually restore into something usable» shape.
        inv.add_user(&User {
            id: UserId("alice".into()),
            uuid: "11111111-1111-1111-1111-111111111111".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
        inv.regenerate_sub_token(&UserId("alice".into()))
            .await
            .unwrap();
        inv.add_server(&Server {
            id: ServerId("de".into()),
            address: "1.2.3.4".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![ProtocolId("vless+reality".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
        inv.grant(&UserId("alice".into()), &ServerId("de".into()))
            .await
            .unwrap();

        let snap = snapshot_now(&inv, dir.path()).await.unwrap();
        let report = verify_snapshot(&snap).await.unwrap();

        assert_eq!(report.overall, CheckStatus::Ok, "{report:?}");
        assert_eq!(report.user_count, 1);
        assert_eq!(report.server_count, 1);
        assert_eq!(report.grant_count, 1);
        assert_eq!(report.users_with_sub_token, 1);
        assert!(report.schema_migrations_applied > 0);
        assert!(report.snapshot_size_bytes > 0);
        // Snapshot just minted → age must be tiny (single-digit seconds).
        assert!(
            report.snapshot_age_seconds.unwrap_or(i64::MAX) < 60,
            "freshly minted snapshot should be < 1min old, got {:?}",
            report.snapshot_age_seconds
        );
        // Every per-check entry must be Ok.
        for c in &report.checks {
            assert_eq!(
                c.status,
                CheckStatus::Ok,
                "check {:?} should be Ok on fresh snapshot",
                c.name
            );
        }
    }

    #[tokio::test]
    async fn verify_snapshot_warns_when_grants_empty() {
        use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("inv.db");
        let inv = SqliteInventory::open(&db).await.unwrap();
        // User + server but NO grants — restore would succeed but
        // the user would have access to nothing. Both presence checks
        // are Ok; only `grants_present` should Warn → overall=Warn.
        inv.add_user(&User {
            id: UserId("alice".into()),
            uuid: "11111111-1111-1111-1111-111111111111".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
        inv.add_server(&Server {
            id: ServerId("de".into()),
            address: "1.2.3.4".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![ProtocolId("vless+reality".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
        let snap = snapshot_now(&inv, dir.path()).await.unwrap();
        let report = verify_snapshot(&snap).await.unwrap();
        assert_eq!(report.overall, CheckStatus::Warn, "{report:?}");
        let grants_check = report
            .checks
            .iter()
            .find(|c| c.name == "grants_present")
            .expect("grants_present check must be present");
        assert_eq!(grants_check.status, CheckStatus::Warn);
    }

    #[tokio::test]
    async fn verify_snapshot_fails_on_empty_db() {
        // Empty SQLite file = `sqlite_master` empty = the «backup
        // pulled before migrations ran» bug class.
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("empty.db.bak");
        // Touch a syntactically-valid empty SQLite file by opening
        // a fresh sqlx connection and immediately dropping it.
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(
                sqlx::sqlite::SqliteConnectOptions::new()
                    .filename(&empty)
                    .create_if_missing(true),
            )
            .await
            .unwrap();
        pool.close().await;
        let report = verify_snapshot(&empty).await.unwrap();
        assert_eq!(report.overall, CheckStatus::Fail, "{report:?}");
        let master_check = report
            .checks
            .iter()
            .find(|c| c.name == "sqlite_master_non_empty")
            .expect("sqlite_master_non_empty check must be present");
        assert_eq!(master_check.status, CheckStatus::Fail);
        // Early-out: no metric checks should have run.
        assert!(
            report
                .checks
                .iter()
                .all(|c| c.name == "sqlite_master_non_empty"),
            "empty-master report must short-circuit; got {:?}",
            report.checks
        );
    }

    #[tokio::test]
    async fn verify_snapshot_errors_on_missing_file() {
        // The function reserves Err for «could not even RUN» —
        // file-not-found qualifies.
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.bak");
        let err = verify_snapshot(&missing).await.unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("stat snapshot"),
            "missing-file error should mention stat, got: {msg}"
        );
    }

    #[tokio::test]
    async fn verify_snapshot_errors_on_non_sqlite_file() {
        // Mirrors restore's input validation — `verify_snapshot`
        // must reject the same garbage with the same precision.
        let dir = tempfile::tempdir().unwrap();
        let bogus = dir.path().join("not-a-db.bak");
        std::fs::write(&bogus, b"hello not a database").unwrap();
        let err = verify_snapshot(&bogus).await.unwrap_err();
        let msg = format!("{err}").to_lowercase();
        assert!(
            msg.contains("sqlite") || msg.contains("malformed"),
            "expected sqlite-validation error, got: {msg}"
        );
    }

    #[tokio::test]
    async fn verify_snapshot_fails_when_snapshot_is_from_newer_binary() {
        // Schema-drift detection for the «we tried to restore a
        // backup made by a NEWER vpnctld binary than the one we're
        // running» case. sqlx's migrator refuses to run when the
        // snapshot's `_sqlx_migrations` includes a version number
        // the binary's embedded migrator doesn't know about — this
        // is the exact bug class operators would hit during a
        // post-incident downgrade. Verify the failure surfaces as a
        // `schema_migrations_match_binary` Fail (NOT silently
        // swallowed into Ok).
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("inv.db");
        let inv = SqliteInventory::open(&db).await.unwrap();
        let snap = snapshot_now(&inv, dir.path()).await.unwrap();
        // Inject a fake future migration row. The binary's migrator
        // will reject it with «migration <N+1> was previously applied
        // but is missing in the resolved migrations».
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(sqlx::sqlite::SqliteConnectOptions::new().filename(&snap))
            .await
            .unwrap();
        let max_version: i64 =
            sqlx::query_scalar("SELECT COALESCE(MAX(version), 0) FROM _sqlx_migrations")
                .fetch_one(&pool)
                .await
                .unwrap();
        sqlx::query(
            "INSERT INTO _sqlx_migrations
             (version, description, installed_on, success, checksum, execution_time)
             VALUES (?, 'fake_future_migration', '2030-01-01T00:00:00Z', 1, X'00', 0)",
        )
        .bind(max_version + 1)
        .execute(&pool)
        .await
        .unwrap();
        pool.close().await;

        let report = verify_snapshot(&snap).await.unwrap();
        let mig_check = report
            .checks
            .iter()
            .find(|c| c.name == "schema_migrations_match_binary")
            .expect("schema_migrations_match_binary check must be present");
        assert_eq!(
            mig_check.status,
            CheckStatus::Fail,
            "snapshot from newer binary should Fail at migration replay, got: {mig_check:?}"
        );
        assert!(
            mig_check.detail.contains("migration replay failed"),
            "Fail detail should explain it was a migration replay failure, got: {}",
            mig_check.detail
        );
        // Overall must be Fail (this is the «cannot restore» branch).
        assert_eq!(report.overall, CheckStatus::Fail);
        // Early-return: data-presence checks should NOT have run.
        assert!(
            !report
                .checks
                .iter()
                .any(|c| c.name == "users_present" || c.name == "servers_present"),
            "data checks must short-circuit on migration failure; got {:?}",
            report.checks
        );
    }

    #[test]
    fn check_status_label_is_lowercase_for_html_class_compatibility() {
        // Pinned because the admin UI uses the label as a CSS class
        // (`.self-test-check--ok / --warn / --fail`).
        assert_eq!(CheckStatus::Ok.label(), "ok");
        assert_eq!(CheckStatus::Warn.label(), "warn");
        assert_eq!(CheckStatus::Fail.label(), "fail");
    }
}
