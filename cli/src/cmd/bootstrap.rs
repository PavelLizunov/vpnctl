//! `vpnctl bootstrap` — provision a brand-new node so the rest of vpnctl
//! can talk to it via SSH-key only.
//!
//! Steps:
//!
//! 1. Connect via SSH using the **root password** as fallback (pubkey is
//!    tried first; on a fresh box it fails; we then submit the password).
//! 2. Append our public key (default `~/.ssh/id_ed25519.pub`) to the
//!    target user's `~/.ssh/authorized_keys` if it isn't already there.
//! 3. Capture the host's SHA256 fingerprint observed during connect.
//! 4. Persist the server to inventory with the fingerprint baked in
//!    (so subsequent `vpnctl deploy` enforces strict host-key check).
//! 5. Write an audit_log entry.
//!
//! After bootstrap, `vpnctl deploy <id>` works without any password —
//! pure key auth + fingerprint-pinned host verification.
//!
//! Hardening (disable password sshd auth, install fail2ban / UFW / BBR)
//! is deliberately a separate command — see `vpnctl harden` (v0.4 plan).
//! Splitting the steps lets you bootstrap, observe, and only then close
//! the door behind you.

use crate::ui;
use serde_json::json;
use std::path::PathBuf;
use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, SshTransport};
use vpnctl_inventory::SqliteInventory;
use vpnctl_ssh::RusshTransportBuilder;

#[derive(clap::Args, Debug)]
pub(crate) struct BootstrapArgs {
    /// Stable inventory id, e.g. "stg-debian12".
    pub id: String,
    /// IP or hostname of the new node.
    #[arg(long)]
    pub address: String,
    /// Root password — used **once** to install our SSH key. Subsequent
    /// connects use the key. Pass via env to keep it out of shell history:
    /// `--root-password "$VPNCTL_ROOT_PW"`.
    #[arg(long, env = "VPNCTL_ROOT_PW")]
    pub root_password: String,
    #[arg(long, default_value_t = 22)]
    pub ssh_port: u16,
    #[arg(long, default_value = "root")]
    pub ssh_user: String,
    /// Public key to push (default: ~/.ssh/id_ed25519.pub).
    #[arg(long)]
    pub pubkey: Option<PathBuf>,
    /// Private key path the deploy will subsequently use.
    /// Default: ~/.ssh/id_ed25519.
    #[arg(long)]
    pub key: Option<PathBuf>,
    #[arg(long, default_value = "sing-box")]
    pub kernel: String,
    #[arg(long, default_value = "generic")]
    pub hoster: String,
    #[arg(long, value_delimiter = ',', default_values_t = ["vless+reality".to_string(), "tuic-v5".to_string()])]
    pub protocols: Vec<String>,
    #[arg(long, default_value_t = 1.0)]
    pub usage_coefficient: f64,
}

pub(crate) async fn run(args: BootstrapArgs, db_flag: Option<PathBuf>) -> anyhow::Result<()> {
    let db_path = ui::resolve_db_path(db_flag)?;
    let inv = SqliteInventory::open(&db_path).await?;

    // Per review finding: short-circuit re-runs BEFORE we touch the remote.
    // Otherwise the pubkey gets re-appended (idempotent thanks to grep -qxF
    // — but only because of the previous fix), no audit row is written, and
    // the user just sees a confusing "AlreadyExists" error after the SSH
    // round-trip.
    let sid = ServerId(args.id.clone());
    if inv.get_server(&sid).await?.is_some() {
        return Err(anyhow::anyhow!(
            "server '{}' already in inventory — bootstrap is one-shot. \
             Use `vpnctl server remove {} --yes` first if you really want to redo it.",
            args.id,
            args.id
        ));
    }

    // Load our pubkey first — fail fast if it's missing/unreadable.
    let pub_path = match args.pubkey {
        Some(p) => p,
        None => {
            let key_path = crate::cmd::deploy::resolve_key_path(args.key.clone())?;
            key_path.with_extension("pub")
        }
    };
    let pubkey_text = std::fs::read_to_string(&pub_path)
        .map_err(|e| anyhow::anyhow!("read pubkey {}: {e}", pub_path.display()))?;
    // Per review-agent finding: `trim()` doesn't collapse interior newlines —
    // a pubkey file with a trailing comment or extra blank line would land
    // a multi-line argument inside `grep -qxF`, which then never matches on
    // rerun and the key gets double-appended. Take the first non-empty line
    // only and reject files that contain more than one key line.
    let key_lines: Vec<&str> = pubkey_text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    let pubkey_one_line = match key_lines.as_slice() {
        [] => {
            return Err(anyhow::anyhow!(
                "pubkey file {} contains no key",
                pub_path.display()
            ));
        }
        [single] => (*single).to_string(),
        many => {
            return Err(anyhow::anyhow!(
                "pubkey file {} has {} keys; bootstrap only handles one (split it)",
                pub_path.display(),
                many.len()
            ));
        }
    };

    let priv_key_path = crate::cmd::deploy::resolve_key_path(args.key)?;

    // Build registry early — same validation as `server add`.
    let registry = crate::registry::build()?;

    // ─── 1. SSH connect with password fallback ───────────────────────────
    println!(
        "→ connecting (password fallback) {}@{}:{}",
        args.ssh_user, args.address, args.ssh_port
    );
    let ssh =
        RusshTransportBuilder::new(args.address.clone(), args.ssh_user.clone(), priv_key_path)
            .port(args.ssh_port)
            .password(args.root_password.clone())
            .connect()
            .await?;

    // ─── 2. Push pubkey idempotently ─────────────────────────────────────
    // Use `grep -qxF` so the *exact* line is matched (no false-positive
    // because of substring overlap), and append only if absent.
    println!(
        "→ installing pubkey into ~{}/.ssh/authorized_keys",
        args.ssh_user
    );
    let install_cmd = format!(
        "set -eu; \
         mkdir -p ~/.ssh && chmod 700 ~/.ssh; \
         touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys; \
         grep -qxF {key_quoted} ~/.ssh/authorized_keys || echo {key_quoted} >> ~/.ssh/authorized_keys; \
         echo OK",
        key_quoted = shell_single_quote(&pubkey_one_line),
    );
    let out = ssh.exec(&install_cmd).await?;
    // Per review finding: `out.contains("OK")` would happily match MOTD
    // text like "TOKEN" or "COOKIE". Compare the LAST line exactly.
    let last_line = out.lines().last().map(str::trim).unwrap_or("");
    if last_line != "OK" {
        return Err(anyhow::anyhow!(
            "key install did not finish with OK; remote ended with: {last_line:?}"
        ));
    }

    // ─── 3. Capture TOFU fingerprint ─────────────────────────────────────
    let observed_fp = ssh
        .observed_host_fingerprint()
        .await
        .ok_or_else(|| anyhow::anyhow!("no host fingerprint observed (russh internal)"))?;
    println!("  host fingerprint: {observed_fp}");

    // ─── 4. Persist server in inventory ──────────────────────────────────
    let server = Server {
        id: ServerId(args.id.clone()),
        address: args.address.clone(),
        ssh_port: args.ssh_port,
        ssh_user: args.ssh_user.clone(),
        // Bootstrap creates the server with the single kernel the
        // operator chose; multi-kernel can be added later from the
        // admin UI or `vpnctl server kernel-add`. Pre-multi-kernel
        // this was `kernel: KernelId(...)`.
        kernels: vec![KernelId(args.kernel.clone())],
        enabled_protocols: args.protocols.iter().cloned().map(ProtocolId).collect(),
        trusted_host_fingerprint: Some(observed_fp.clone()),
        hoster: args.hoster.clone(),
        jump_via: None,
        usage_coefficient: args.usage_coefficient,
    };
    registry.validate_server(&server)?;
    inv.add_server(&server).await?;

    inv.audit(
        "cli",
        "server.bootstrap",
        Some(&args.id),
        Some(&json!({
            "address": args.address,
            "ssh_user": args.ssh_user,
            "ssh_port": args.ssh_port,
            "kernel": args.kernel,
            "hoster": args.hoster,
            "protocols": args.protocols,
            "host_fingerprint": observed_fp,
        })),
    )
    .await?;

    println!(
        "✔ bootstrap complete — '{id}' is in inventory; run `vpnctl deploy {id}` next.",
        id = args.id
    );
    Ok(())
}

// `shell_single_quote` moved to `vpnctl_core::shell::single_quote`
// (2026-05-18) — was triplicated; consolidated for parity.
use vpnctl_core::shell::single_quote as shell_single_quote;
