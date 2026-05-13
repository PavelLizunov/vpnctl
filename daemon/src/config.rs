use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context;

#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub db_path: PathBuf,
    pub addr: SocketAddr,
}

impl DaemonConfig {
    /// Resolve final config from CLI/env. Same default as the CLI uses for
    /// `--db` so a single inventory backs both.
    pub async fn resolve(db_flag: Option<PathBuf>, addr: SocketAddr) -> anyhow::Result<Self> {
        let db_path = match db_flag {
            Some(p) => p,
            None => {
                let dir = dirs_data_dir()
                    .ok_or_else(|| {
                        anyhow::anyhow!("cannot resolve XDG data dir; pass --db / VPNCTL_DB")
                    })?
                    .join("vpnctl");
                // Surface dir-creation errors immediately rather than letting
                // the next sqlx::open() fail with an opaque "unable to open
                // database file" hours later.
                tokio::fs::create_dir_all(&dir)
                    .await
                    .with_context(|| format!("create {}", dir.display()))?;
                dir.join("inv.db")
            }
        };
        Ok(Self { db_path, addr })
    }
}

/// Avoid pulling the whole `dirs` crate just for this one lookup.
fn dirs_data_dir() -> Option<PathBuf> {
    if let Some(x) = std::env::var_os("XDG_DATA_HOME") {
        return Some(PathBuf::from(x));
    }
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".local/share"))
}
