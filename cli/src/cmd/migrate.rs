//! `vpnctl migrate from-bash` — Phase C-5 import path.
//!
//! Orchestrates the SSH I/O around the pure planner in
//! `vpnctl_inventory::migrate`. Two execution modes:
//!
//!   * **dry-run (default)** — read everything, print the plan, exit
//!     without touching inv.db. Operator inspects + decides.
//!   * **`--apply`** — read everything, write to inv.db, audit, print
//!     the outcome summary. Idempotent at SQL: existing servers /
//!     users / grants are skipped, not overwritten.
//!
//! # Why dry-run is default
//!
//! CLAUDE.md «важно сейчас не уранить vpn не одному из пользователей»
//! (Pavel 2026-05-17). A typo or stale `inventory/<IP>.env` can
//! mint duplicate users with wrong UUIDs; the dry-run gate forces
//! the operator to confirm BEFORE inv.db is mutated. The audit row
//! captures the resolved plan as well, so post-hoc forensics are
//! possible regardless.

use std::path::PathBuf;

use clap::Args;

use crate::OutputFormat;
use vpnctl_core::SshTransport;
use vpnctl_inventory::{
    BashSingboxData, MigrationPlan, SqliteInventory, apply_migration_plan, build_migration_plan,
    parse_bash_inventory_env, parse_bash_singbox,
};
use vpnctl_ssh::RusshTransportBuilder;

#[derive(Args, Debug)]
pub(crate) struct MigrateFromBashArgs {
    /// Directory containing `<IP>.env` files (`SERVER_IP=`, `SHORT_ID=`,
    /// `REALITY_PUBLIC=`, `USERS=`). Same layout as the bash project's
    /// `inventory/`.
    pub inventory_dir: PathBuf,

    /// SSH private key path. Default: `~/.ssh/id_ed25519`.
    #[arg(long)]
    pub key: Option<PathBuf>,

    /// Limit to a single bash server (IP). Without this every
    /// `<IP>.env` in `inventory_dir` is processed.
    #[arg(long, value_name = "IP")]
    pub server: Option<String>,

    /// Override the vpnctl `Server.id`. Without it the id is derived
    /// from the IP (IPv6 colons → hyphens; IPv4 unchanged). Mutually
    /// exclusive with `--server` requiring a single bash server.
    #[arg(long, value_name = "ID")]
    pub server_id: Option<String>,

    /// Apply the plan to inv.db. Without this flag the tool prints
    /// the plan and exits (dry-run = SAFE default).
    #[arg(long)]
    pub apply: bool,

    /// Overwrite users that already exist in inv.db with bash data
    /// (UUID + TUIC password + sub_token replaced). Drops vpnctl-only
    /// state including WireGuard keypair, hand-edited sub_token,
    /// traffic limits. Use when the existing vpnctl users have stale
    /// test UUIDs that don't match the bash production data — without
    /// this flag vpnctl's `/sub/<token>` would keep returning links
    /// with the wrong UUID (existing phone scans still work because
    /// they hold the original bash-scanned vless://, but vpnctl-minted
    /// re-shares would be broken).
    #[arg(long)]
    pub overwrite_existing: bool,
}

pub(crate) async fn run_from_bash(
    args: MigrateFromBashArgs,
    db: Option<PathBuf>,
    output: OutputFormat,
) -> anyhow::Result<()> {
    let key_path = args
        .key
        .clone()
        .unwrap_or_else(|| dirs_home().join(".ssh/id_ed25519"));
    if !args.inventory_dir.is_dir() {
        anyhow::bail!(
            "inventory dir not found or not a directory: {}",
            args.inventory_dir.display()
        );
    }
    if args.server_id.is_some() && args.server.is_none() {
        anyhow::bail!("--server-id requires --server <IP> (only valid for single-server import)");
    }

    // Enumerate .env files. Skip `EXAMPLE.env.tpl` and any non-.env files.
    let mut env_files: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(&args.inventory_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.ends_with(".env") || name.ends_with(".env.tpl") {
            continue;
        }
        // Apply --server filter via EXACT basename match
        // (`<IP>.env`). Pre-2026-05-17 used `starts_with(only)`
        // which made `--server 1` match `1.2.3.40.env` AND
        // `10.0.0.1.env` — false matches on shared prefix.
        if let Some(only) = &args.server
            && name != format!("{only}.env")
        {
            continue;
        }
        env_files.push(path);
    }
    env_files.sort();
    if env_files.is_empty() {
        println!("(no <IP>.env files in {})", args.inventory_dir.display());
        return Ok(());
    }

    let mut plans: Vec<MigrationPlan> = Vec::with_capacity(env_files.len());
    for env_path in &env_files {
        let env_text = std::fs::read_to_string(env_path)?;
        let inv = parse_bash_inventory_env(&env_text)
            .map_err(|e| anyhow::anyhow!("{}: {e}", env_path.display()))?;
        println!(
            "→ SSH root@{}:{} (read-only: /etc/sing-box/{{config.json,keys.env}})",
            inv.server_ip, inv.ssh_port
        );
        let singbox = fetch_bash_singbox(&inv.server_ip, inv.ssh_port, &key_path).await?;
        // sub_token generator. RNG failure → bail the WHOLE
        // migration, never invent a deterministic token: if RNG is
        // broken for one user it's likely broken for ALL of them,
        // and a collision means find_user_by_sub_token returns the
        // first match and every other user is silently unreachable
        // via /sub. (review-agent 2026-05-17 critical.)
        let token_err: std::sync::Arc<std::sync::Mutex<Option<String>>> =
            std::sync::Arc::new(std::sync::Mutex::new(None));
        let token_err_clone = std::sync::Arc::clone(&token_err);
        let plan = build_migration_plan(args.server_id.clone(), &inv, &singbox, |name| {
            match vpnctl_crypto::gen_password(24) {
                Ok(s) => s,
                Err(e) => {
                    if let Ok(mut g) = token_err_clone.lock() {
                        *g = Some(format!("sub-token RNG failure for '{name}': {e}"));
                    }
                    // Return an empty string — the bail check below
                    // surfaces the real error to the operator. We
                    // can't bail from inside the closure (signature
                    // is `FnMut(&str) -> String`).
                    String::new()
                }
            }
        })
        .map_err(|e| anyhow::anyhow!("{}: {e}", env_path.display()))?;
        if let Ok(g) = token_err.lock()
            && let Some(msg) = g.as_ref()
        {
            anyhow::bail!(
                "aborting migration — {msg}. Investigate /dev/urandom on the migration host before retrying."
            );
        }
        print_plan(&plan);
        plans.push(plan);
    }

    if !args.apply {
        println!();
        println!("=== DRY-RUN — no writes ===");
        println!(
            "Re-run with --apply to commit {} server(s) to inv.db.",
            plans.len()
        );
        return Ok(());
    }

    // ─── APPLY ─────────────────────────────────────────────────────
    let db_path = db.unwrap_or_else(|| PathBuf::from("/var/lib/vpnctl/inv.db"));
    let inv = SqliteInventory::open(&db_path).await?;
    println!();
    // Surface UUID-replacement conflicts up front. Without
    // --overwrite-existing this is informational; WITH it, this is
    // the operator's last chance to abort if a conflict is unexpected.
    let mut total_conflicts = 0usize;
    for plan in &plans {
        total_conflicts += report_overwrite_conflicts(&inv, plan).await?;
    }
    if total_conflicts > 0 && !args.overwrite_existing {
        anyhow::bail!(
            "{total_conflicts} existing user(s) have different uuids than the bash data. \
             Re-run with --overwrite-existing to REPLACE them (drops vpnctl-only state \
             including WireGuard keypairs + hand-rotated sub_tokens), or rename the \
             conflicting bash users on the source server first."
        );
    }
    println!("=== APPLYING to {} ===", db_path.display());
    let mut total_users_created = 0usize;
    let mut total_users_overwritten = 0usize;
    let mut total_grants_made = 0usize;
    for plan in &plans {
        let outcome = apply_migration_plan(&inv, plan, args.overwrite_existing).await?;
        let server_status = if outcome.server_created {
            "CREATED"
        } else {
            "already existed"
        };
        let overwrite_note = if args.overwrite_existing {
            format!(", {} overwritten", outcome.users_overwritten.len())
        } else {
            format!(
                ", {} skipped (existing)",
                outcome.users_skipped_existing.len()
            )
        };
        println!(
            "  · {} ({}): {} new users{overwrite_note}, {} grants, {} secrets set",
            plan.server.id.0,
            server_status,
            outcome.users_created,
            outcome.grants_made,
            outcome.secrets_set,
        );
        total_users_created += outcome.users_created;
        total_users_overwritten += outcome.users_overwritten.len();
        total_grants_made += outcome.grants_made;
    }
    println!();
    match output {
        OutputFormat::Text => {
            println!(
                "ok — {} server(s), {} new users, {} overwritten, {} grants applied.",
                plans.len(),
                total_users_created,
                total_users_overwritten,
                total_grants_made
            );
        }
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::json!({
                    "servers": plans.len(),
                    "users_created": total_users_created,
                    "users_overwritten": total_users_overwritten,
                    "grants_made": total_grants_made,
                })
            );
        }
    }
    Ok(())
}

/// SSH to the bash server, cat `/etc/sing-box/config.json` and
/// `/etc/sing-box/keys.env`, parse. **Read-only on the bash side** —
/// we explicitly avoid running anything that could modify state on
/// the production node.
///
/// Two separate `exec` calls (one per file) — previous version used
/// a single `cat A; echo SEP; cat B` round-trip with a literal
/// sentinel, which silently truncated keys.env if config.json ever
/// contained the sentinel string (review-agent critical 2026-05-17).
/// The two-call cost is one extra SSH round-trip; for a one-off
/// migration the operator absorbs it without noticing.
async fn fetch_bash_singbox(
    addr: &str,
    port: u16,
    key_path: &std::path::Path,
) -> anyhow::Result<BashSingboxData> {
    let ssh =
        RusshTransportBuilder::new(addr.to_string(), "root".to_string(), key_path.to_path_buf())
            .port(port)
            .connect()
            .await?;
    // Each file goes through `cat` standalone so the contents can
    // contain ANY byte sequence (including what would have been our
    // old sentinel). `set -eu` makes a missing file abort with
    // exit≠0 → SSH transport surfaces that as an Err.
    let cfg = ssh
        .exec("set -eu; cat /etc/sing-box/config.json")
        .await
        .map_err(|e| anyhow::anyhow!("read config.json on {addr}:{port}: {e}"))?;
    let keys = ssh
        .exec("set -eu; cat /etc/sing-box/keys.env")
        .await
        .map_err(|e| anyhow::anyhow!("read keys.env on {addr}:{port}: {e}"))?;
    parse_bash_singbox(cfg.trim(), keys.trim())
        .map_err(|e| anyhow::anyhow!("parsing {addr}:{port} sing-box files: {e}"))
}

/// Print a plan. Deliberately does NOT echo any uuid / tuic_password
/// / sub_token bytes — these are the secret material a `vless://`
/// link is composed of, and the operator's terminal scrollback may
/// be screen-shared / pasted into chats. Per-user presence markers
/// (`uuid:set`, `tuic:set`) give the operator enough info to verify
/// the planner did the right thing.
fn print_plan(plan: &MigrationPlan) {
    println!();
    println!(
        "  PLAN for server '{}' ({}:{}):",
        plan.server.id.0, plan.server.address, plan.server.ssh_port
    );
    println!(
        "    protocols: {}",
        plan.server
            .enabled_protocols
            .iter()
            .map(|p| p.0.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!("    secrets: {} keys", plan.server_secrets.len());
    println!("    users to import: {}", plan.users_to_import.len());
    for u in plan.users_to_import.iter().take(5) {
        let tuic = if u.tuic_password.is_some() {
            "yes"
        } else {
            "no"
        };
        // Print ONLY the name + presence markers — never any byte
        // of uuid/password/token. Operator wants to verify the
        // PLAN, not exfiltrate secrets through scrollback.
        println!("      · {}  uuid:set  tuic:{tuic}", u.id.0);
    }
    if plan.users_to_import.len() > 5 {
        println!("      …and {} more", plan.users_to_import.len() - 5);
    }
    if !plan.skipped.is_empty() {
        println!("    skipped: {}", plan.skipped.len());
        for s in &plan.skipped {
            println!("      · {}  — {}", s.name, s.reason);
        }
    }
    if !plan.warnings.is_empty() {
        println!("    warnings:");
        for w in &plan.warnings {
            println!("      ! {w}");
        }
    }
}

/// Report which existing vpnctl users will be OVERWRITTEN before the
/// `--apply --overwrite-existing` path runs. Lets the operator
/// abort if a user-name conflict is unexpected (e.g. a typo on the
/// bash side that would clobber a different real user in vpnctl).
async fn report_overwrite_conflicts(
    inv: &SqliteInventory,
    plan: &MigrationPlan,
) -> anyhow::Result<usize> {
    let mut conflicts: Vec<(String, String, String)> = Vec::new();
    for u in &plan.users_to_import {
        if let Some(existing) = inv.get_user(&u.id).await?
            && existing.uuid != u.uuid
        {
            // Show only the first 6 chars of each uuid so the
            // operator can SEE a divergence without giving away
            // either full uuid. Six chars is enough to compare.
            let prefix = |s: &str| -> String {
                let n = s.len().min(6);
                s.get(..n).unwrap_or("").to_string()
            };
            conflicts.push((u.id.0.clone(), prefix(&existing.uuid), prefix(&u.uuid)));
        }
    }
    if !conflicts.is_empty() {
        println!();
        println!(
            "  ! {} existing user(s) will have their UUID REPLACED (--overwrite-existing):",
            conflicts.len()
        );
        for (name, old, new) in &conflicts {
            println!("      · {name}  uuid {old}… → {new}…");
        }
        println!("    Their grants on other vpnctl servers are preserved.");
        println!("    Their vpnctl-only state (WG keypair, traffic limit) is RESET.");
    }
    Ok(conflicts.len())
}

/// `$HOME` resolution that doesn't pull the `dirs` crate (we avoid
/// adding deps for tiny needs). Falls back to `/root` on the homelab
/// where `vpnctl` runs as root via systemd.
fn dirs_home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/root"))
}
