//! `vpnctl backup …` and `vpnctl restore <snapshot>` — the CLI side
//! of Phase C-4.
//!
//! # When the CLI matters vs the web
//!
//! `Web is the ONLY operator surface` (CLAUDE.md) — and indeed the
//! Settings page covers the everyday cases (list snapshots, take a
//! snapshot now, download for off-site copy). The CLI exists for the
//! one case that fundamentally can't go through the web:
//!
//!   * **Restore.** The daemon owns the open `inv.db` handle + WAL.
//!     Replacing the file while the daemon is running causes
//!     undefined behaviour (silent corruption is the failure mode).
//!     So restore demands: stop daemon → CLI swaps the file → start
//!     daemon. That's an SSH session by definition.
//!
//! Backup `snapshot` / `list` / `prune` are mirrored here as
//! quality-of-life helpers (the same operator may want to script a
//! cron job that copies the newest snapshot to a remote host, or
//! verify retention from a non-browser context).
//!
//! All commands read the canonical backup dir from the
//! `VPNCTLD_BACKUP_DIR` env var, falling back to
//! `vpnctl_inventory::DEFAULT_BACKUP_DIR`. The daemon's systemd unit
//! sets the env var when there's a non-default install layout; the
//! CLI honours it so the operator's `vpnctl restore` lands in the
//! same place the daemon was writing.

use std::path::PathBuf;

use clap::Subcommand;

use crate::OutputFormat;
use crate::ui;
use vpnctl_core::humanize::format_size_bytes;
use vpnctl_inventory::{SqliteInventory, list_snapshots, prune_snapshots, snapshot_now};

#[derive(Subcommand, Debug)]
pub(crate) enum BackupCmd {
    /// Take a snapshot now. Mirrors the web `snapshot now` button.
    Snapshot,
    /// List snapshots in the configured backup directory, newest first.
    List,
    /// Apply the default retention policy: keep 24 hourly plus 30
    /// daily plus 12 monthly snapshots; remove everything else.
    /// Mirrors what the daemon scheduler does at the end of every
    /// tick.
    Prune,
}

pub(crate) async fn run(
    cmd: BackupCmd,
    db: Option<PathBuf>,
    output: OutputFormat,
) -> anyhow::Result<()> {
    let dir = backup_dir_from_env();
    match cmd {
        BackupCmd::Snapshot => {
            let db_path = ui::resolve_db_path(db)?;
            let inv = SqliteInventory::open(&db_path).await?;
            let snap = snapshot_now(&inv, &dir).await?;
            match output {
                OutputFormat::Text => println!("snapshot written: {}", snap.display()),
                OutputFormat::Json => println!(
                    "{}",
                    serde_json::json!({"snapshot": snap.display().to_string()})
                ),
            }
            Ok(())
        }
        BackupCmd::List => {
            let list = list_snapshots(&dir)?;
            match output {
                OutputFormat::Text => {
                    if list.is_empty() {
                        println!("(no snapshots in {})", dir.display());
                    } else {
                        println!("{:<32}  {:>10}  file", "created (UTC)", "size");
                        for snap in &list {
                            println!(
                                "{:<32}  {:>10}  {}",
                                snap.created.as_deref().unwrap_or("?"),
                                format_size_bytes(snap.size_bytes),
                                snap.path.display()
                            );
                        }
                    }
                }
                OutputFormat::Json => {
                    let arr: Vec<_> = list
                        .iter()
                        .map(|s| {
                            serde_json::json!({
                                "created": s.created,
                                "file_name": s.file_name,
                                "path": s.path.display().to_string(),
                                "size_bytes": s.size_bytes,
                            })
                        })
                        .collect();
                    println!("{}", serde_json::Value::Array(arr));
                }
            }
            Ok(())
        }
        BackupCmd::Prune => {
            let removed = prune_snapshots(&dir, vpnctl_inventory::Retention::default())?;
            match output {
                OutputFormat::Text => {
                    println!("pruned {removed} snapshot(s) in {}", dir.display());
                }
                OutputFormat::Json => {
                    println!(
                        "{}",
                        serde_json::json!({"removed": removed, "dir": dir.display().to_string()})
                    );
                }
            }
            Ok(())
        }
    }
}

/// `vpnctl restore <snapshot>` — atomic swap of the snapshot file
/// over the live `inv.db`. Daemon MUST be stopped first; we don't
/// try to detect that (no good cross-platform way) — the operator
/// follows the documented sequence:
///
///   1. `sudo systemctl stop vpnctld`
///   2. `vpnctl restore /var/lib/vpnctl/backups/inv.db.<ts>.bak`
///   3. `sudo systemctl start vpnctld`
pub(crate) async fn run_restore(
    snapshot: PathBuf,
    db: Option<PathBuf>,
    output: OutputFormat,
) -> anyhow::Result<()> {
    let db_path = ui::resolve_db_path(db)?;
    if !snapshot.exists() {
        anyhow::bail!("snapshot not found: {}", snapshot.display());
    }
    vpnctl_inventory::restore_from(&snapshot, &db_path).await?;
    match output {
        OutputFormat::Text => {
            println!(
                "ok — restored {} -> {}",
                snapshot.display(),
                db_path.display()
            );
            println!("now run `sudo systemctl start vpnctld` to bring the daemon back up");
        }
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::json!({
                    "restored_from": snapshot.display().to_string(),
                    "db_path": db_path.display().to_string(),
                })
            );
        }
    }
    Ok(())
}

/// Resolve the backup directory: env var override, otherwise the
/// shipped default. Mirrors the daemon's resolution order so the CLI
/// + daemon agree on the same dir even in non-standard installs.
fn backup_dir_from_env() -> PathBuf {
    std::env::var("VPNCTLD_BACKUP_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(vpnctl_inventory::DEFAULT_BACKUP_DIR))
}

// `format_size_bytes` moved to `vpnctl_core::humanize::format_size_bytes`
// (2026-05-18). The «duplicated here because the daemon module isn't
// a CLI dep» note is no longer true — both surfaces now share
// `vpnctl-core`, which has zero tokio/sqlx baggage.

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn run_snapshot_and_restore_uses_resolved_db_path() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("inv.db");
        let backup_dir = dir.path().join("backups");
        std::fs::create_dir_all(&backup_dir).unwrap();

        // Seed an inventory
        let inv = SqliteInventory::open(&db_path).await.unwrap();
        inv.add_user(&vpnctl_core::User {
            id: vpnctl_core::UserId("alice".into()),
            uuid: "00000000-0000-0000-0000-000000000001".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
        drop(inv);

        // Run snapshot with custom db flag
        let snap = vpnctl_inventory::snapshot_now(
            &SqliteInventory::open(&db_path).await.unwrap(),
            &backup_dir,
        )
        .await
        .unwrap();
        assert!(snap.exists());

        // Test restore
        let restored_db = dir.path().join("restored.db");
        run_restore(snap, Some(restored_db.clone()), OutputFormat::Json)
            .await
            .unwrap();
        assert!(restored_db.exists());

        let restored_inv = SqliteInventory::open(&restored_db).await.unwrap();
        let user = restored_inv
            .get_user(&vpnctl_core::UserId("alice".into()))
            .await
            .unwrap();
        assert!(user.is_some());
    }
}
