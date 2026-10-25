use super::*;
use sqlx::Row;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{ConnectOptions, SqlitePool, migrate::Migrator};
use std::fs::{DirBuilder, OpenOptions};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

pub(crate) fn migrator() -> &'static Migrator {
    &MIGRATOR
}

pub(crate) async fn run_migrations(pool: &SqlitePool) -> Result<()> {
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    let tables: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'
         AND name IN ('_sqlx_migrations', 'admin_alerts')",
    )
    .fetch_one(&mut *tx)
    .await?;
    if tables == 2 {
        let applied: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM _sqlx_migrations WHERE version = 13 AND success = 1",
        )
        .fetch_one(&mut *tx)
        .await?;
        if applied == 0 {
            let changed = sqlx::query(
                "UPDATE admin_alerts SET acked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE id IN (
                     SELECT id FROM (
                         SELECT id, ROW_NUMBER() OVER (
                             PARTITION BY kind, COALESCE(server_id, '__GLOBAL__')
                             ORDER BY created_at DESC, id DESC
                         ) AS position
                         FROM admin_alerts WHERE acked_at IS NULL
                     ) WHERE position > 1
                 )",
            )
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if changed > 0 {
                sqlx::query(
                    "INSERT INTO audit_log (actor, action, payload)
                     VALUES ('system', 'migration.admin_alerts.deduplicate', ?1)",
                )
                .bind(serde_json::json!({ "acked": changed }).to_string())
                .execute(&mut *tx)
                .await?;
            }
        }
    }
    tx.commit().await?;
    MIGRATOR.run(pool).await?;
    Ok(())
}

pub(crate) fn map_unique<T>(
    res: std::result::Result<T, sqlx::Error>,
    what: impl std::fmt::Display,
) -> Result<T> {
    match res {
        Ok(v) => Ok(v),
        Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
            Err(SqliteInventoryError::AlreadyExists(what.to_string()))
        }
        Err(e) => Err(e.into()),
    }
}

pub const OUR_EGRESS_CONTROL_IPS: &[&str] = &["83.97.108.34"];

pub(crate) fn real_client_ip_predicate(col: &str) -> String {
    let control_clause = if OUR_EGRESS_CONTROL_IPS.is_empty() {
        String::new()
    } else {
        let list = OUR_EGRESS_CONTROL_IPS
            .iter()
            .map(|ip| format!("'{ip}'"))
            .collect::<Vec<_>>()
            .join(",");
        format!(" AND {col} NOT IN ({list})")
    };
    format!(
        "{col} NOT LIKE '10.%' AND {col} NOT LIKE '127.%' \
         AND {col} NOT LIKE '192.168.%' AND {col} NOT LIKE '169.254.%' \
         AND {col} NOT GLOB '172.1[6-9].*' AND {col} NOT GLOB '172.2[0-9].*' \
         AND {col} NOT GLOB '172.3[0-1].*' \
         AND {col} <> '0.0.0.0' AND {col} <> '::' AND {col} <> '::1' \
         AND {col} NOT LIKE 'fc%' AND {col} NOT LIKE 'fd%' \
         AND {col} NOT LIKE 'fe8%' AND {col} NOT LIKE 'fe9%' \
         AND {col} NOT LIKE 'fea%' AND {col} NOT LIKE 'feb%' \
         AND {col} NOT IN (SELECT address FROM servers) \
         AND {col} NOT IN (SELECT address FROM server_resolved_addresses){control_clause}"
    )
}

pub(crate) fn canonical_ip_text(ip: &str) -> String {
    ip.parse::<std::net::IpAddr>()
        .map_or_else(|_| ip.chars().take(45).collect(), |ip| ip.to_string())
}

pub fn network_key(ip: &str) -> String {
    use std::net::IpAddr;
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            let [a, b, _, _] = v4.octets();
            format!("{a}.{b}")
        }
        Ok(IpAddr::V6(v6)) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
        Err(_) => ip.to_string(),
    }
}

#[derive(Debug, Clone)]
pub struct SqliteInventory {
    pub(crate) pool: SqlitePool,
    coordination_identity: std::sync::Arc<String>,
}

fn prepare_database_file(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(file) => file.set_permissions(std::fs::Permissions::from_mode(0o600))?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    for suffix in ["", "-wal", "-shm"] {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        match std::fs::metadata(Path::new(&name)) {
            Ok(metadata) if metadata.permissions().mode() & 0o077 != 0 => {
                // Installs created before the 0600 default: close them on open,
                // keeping the owner.
                if let Err(error) = std::fs::set_permissions(
                    Path::new(&name),
                    std::fs::Permissions::from_mode(0o600),
                ) {
                    eprintln!(
                        "warning: inventory file {name:?} is accessible to other users and could not be restricted: {error}"
                    );
                }
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

impl SqliteInventory {
    pub(crate) fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub async fn open(path: &Path) -> Result<Self> {
        let opts =
            SqliteConnectOptions::from_str(path.to_str().ok_or_else(|| {
                SqliteInventoryError::Invalid(format!("non-utf8 path: {path:?}"))
            })?)?
            .journal_mode(SqliteJournalMode::Wal)
            .pragma("synchronous", "NORMAL")
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(5));

        // SQLx has no memory-mode getter; serialize a safe placeholder filename.
        let in_memory = opts
            .clone()
            .filename("/inventory")
            .to_url_lossy()
            .query_pairs()
            .any(|(key, value)| key == "mode" && value == "memory");
        if !in_memory {
            prepare_database_file(opts.get_filename()).map_err(|error| {
                SqliteInventoryError::Invalid(format!("cannot prepare inventory file: {error}"))
            })?;
        }

        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(opts)
            .await?;

        run_migrations(&pool).await?;

        backfill_sub_tokens(&pool).await?;

        let filename: String =
            sqlx::query_scalar("SELECT file FROM pragma_database_list WHERE name = 'main'")
                .fetch_one(&pool)
                .await?;
        let identity = if filename.is_empty() {
            static NEXT_MEMORY_ID: std::sync::atomic::AtomicU64 =
                std::sync::atomic::AtomicU64::new(1);
            format!(
                "memory:{}",
                NEXT_MEMORY_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            )
        } else {
            let canonical = std::fs::canonicalize(&filename).map_err(|error| {
                SqliteInventoryError::Invalid(format!("cannot resolve inventory identity: {error}"))
            })?;
            format!(
                "file:{}",
                canonical.to_str().ok_or_else(|| {
                    SqliteInventoryError::Invalid("non-utf8 canonical inventory path".into())
                })?
            )
        };
        Ok(Self {
            pool,
            coordination_identity: std::sync::Arc::new(identity),
        })
    }

    pub fn coordination_identity(&self) -> &str {
        &self.coordination_identity
    }

    pub async fn close(self) {
        self.pool.close().await;
    }
}

pub(crate) fn ip_slash16(ip: &str) -> Option<String> {
    if ip.contains(':') {
        return None;
    }
    let mut parts = ip.split('.');
    let a = parts.next()?;
    let b = parts.next()?;
    let _ = parts.next()?;
    if a.is_empty() || b.is_empty() {
        return None;
    }
    if !a.bytes().all(|x| x.is_ascii_digit()) || !b.bytes().all(|x| x.is_ascii_digit()) {
        return None;
    }
    Some(format!("{a}.{b}"))
}

pub(crate) fn escape_like(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' | '%' | '_' => {
                out.push('\\');
                out.push(ch);
            }
            other => out.push(other),
        }
    }
    out
}

async fn backfill_sub_tokens(pool: &SqlitePool) -> Result<()> {
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    let rows = sqlx::query("SELECT id FROM users WHERE sub_token IS NULL")
        .fetch_all(&mut *tx)
        .await?;
    for r in rows {
        let id: String = r.try_get("id")?;
        let token = vpnctl_crypto::gen_sub_token().map_err(SqliteInventoryError::CryptoIo)?;
        sqlx::query("UPDATE users SET sub_token = ?1 WHERE id = ?2")
            .bind(&token)
            .bind(&id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}
