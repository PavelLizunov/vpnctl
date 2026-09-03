use std::path::Path;

use crate::sqlite::SqliteInventoryError;

use super::listing::parse_snapshot_filename;

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
pub async fn verify_snapshot(snapshot_path: &Path) -> Result<SelfTestReport, SqliteInventoryError> {
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
    tokio::task::spawn_blocking({
        let snapshot_path = snapshot_path.to_path_buf();
        let tmp_path = tmp_path.clone();
        move || std::fs::copy(&snapshot_path, &tmp_path)
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
async fn self_test_count(pool: &sqlx::SqlitePool, sql: &str) -> Result<i64, String> {
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
    result: &Result<i64, String>,
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
