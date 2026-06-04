//! `vpnctl` — тонкий CLI поверх крейтов. Бизнес-логика живёт в крейтах,
//! здесь только парсинг аргументов, dispatch и форматирование вывода.

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

mod cmd;
mod registry;
mod ui;

#[derive(Parser, Debug)]
#[command(name = "vpnctl", version, about = "VPN infrastructure control")]
struct Cli {
    /// Path to the SQLite inventory file. Created on first use.
    #[arg(long, env = "VPNCTL_DB", global = true)]
    db: Option<PathBuf>,

    /// Output format for list/show commands.
    #[arg(long, short, global = true, default_value = "text", value_enum)]
    output: OutputFormat,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub(crate) enum OutputFormat {
    Text,
    Json,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Generate a fresh UUID v4 (smoke).
    Uuid,
    /// Show registered kernels and protocols.
    Registry,
    /// Manage servers in the inventory.
    Server {
        #[command(subcommand)]
        cmd: cmd::server::ServerCmd,
    },
    /// Manage users in the inventory.
    User {
        #[command(subcommand)]
        cmd: cmd::user::UserCmd,
    },
    /// Grant a user access to a server.
    Grant { user: String, server: String },
    /// Revoke a user's access to a server.
    Revoke { user: String, server: String },
    /// Push current inventory state to a server (install kernel, generate
    /// missing REALITY keys / TUIC cert, render & apply config, restart).
    Deploy {
        server: String,
        /// SSH private key path (default: ~/.ssh/id_ed25519).
        #[arg(long)]
        key: Option<PathBuf>,
    },
    /// Query a server for kernel runtime status.
    Status {
        server: String,
        #[arg(long)]
        key: Option<PathBuf>,
    },
    /// Print share links (vless://, tuic://, ...) for every server×protocol
    /// the user has been granted access to. Applies the same subscription
    /// policy as the live `/sub` endpoint (disabled user → empty;
    /// auto-suppressed servers + hidden / per-user-denied protocols
    /// filtered).
    Sub {
        user: String,
        /// Render an ASCII QR code under each link (for phone scanning).
        #[arg(long)]
        qr: bool,
        /// Bypass subscription policy and print every raw link, including
        /// those the live `/sub` endpoint would suppress (disabled user,
        /// hidden / per-user-denied protocols, auto-suppressed servers).
        /// For debugging only.
        #[arg(long)]
        ignore_policy: bool,
    },
    /// Provision a brand-new node: install our SSH key (using root password
    /// once), record the host fingerprint, and add the server to inventory.
    /// After this, `vpnctl deploy <id>` works key-only.
    Bootstrap(cmd::bootstrap::BootstrapArgs),
    /// Render the kernel-native config for a server to STDOUT without
    /// touching SSH. Useful for offline review + live-staging tests
    /// (closes the methodology TODO in docs/PROTOCOL_TESTING.md).
    Render { server: String },
    /// Manage `inv.db` snapshots (Phase C-4 backups). Subcommands:
    /// `snapshot` (take one now), `list` (newest-first), `prune`
    /// (apply default retention).
    Backup {
        #[command(subcommand)]
        cmd: cmd::backup::BackupCmd,
    },
    /// Restore the inventory from a snapshot file. **Daemon MUST be
    /// stopped first** — replacing the open DB while vpnctld holds it
    /// silently corrupts state. Sequence:
    ///   1. sudo systemctl stop vpnctld
    ///   2. vpnctl restore /var/lib/vpnctl/backups/inv.db.<ts>.bak
    ///   3. sudo systemctl start vpnctld
    Restore {
        /// Path to the snapshot file produced by `vpnctl backup snapshot`
        /// or downloaded from the Settings page.
        snapshot: PathBuf,
    },
    /// Migrate state from the legacy bash `vpn-control` project (Phase
    /// C-5). Subcommand `from-bash <dir>` reads each `<IP>.env`, SSHs
    /// to each server read-only to pull `/etc/sing-box/{config.json,keys.env}`,
    /// builds a plan, and (with `--apply`) inserts servers/users/grants
    /// into vpnctl's inv.db preserving UUIDs + TUIC passwords. Default
    /// is dry-run.
    Migrate {
        #[command(subcommand)]
        cmd: MigrateCmd,
    },
    /// Download + atomic-install the current month's DB-IP Lite City +
    /// ASN MaxMind-compatible MMDB files into `VPNCTLD_GEOIP_DIR`
    /// (default `/var/lib/vpnctl/geoip`). DB-IP Lite is CC-BY 4.0 +
    /// no signup — pure-Rust reqwest download, no curl shell-out.
    /// Restart vpnctld after to load the new DBs.
    GeoipUpdate {
        /// Override target dir (default reads `VPNCTLD_GEOIP_DIR` env
        /// var, falls back to `/var/lib/vpnctl/geoip`).
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// `vpnctld` admin-side utilities. Today: hash an admin password
    /// into the Argon2id PHC format expected by
    /// `VPNCTLD_ADMIN_PASSWORD`. Was referenced in `daemon/handlers/
    /// auth.rs` doc-comment for 9 months without an actual implementation
    /// (audit B2, 2026-05-22) — anyone following the docs got
    /// «unrecognized subcommand». Now real.
    Admin {
        #[command(subcommand)]
        cmd: AdminCmd,
    },
}

#[derive(Subcommand, Debug)]
enum AdminCmd {
    /// Hash a plaintext admin password to Argon2id PHC format. Read
    /// the plaintext from stdin (recommended — never appears on the
    /// process command line) or `--password <plain>` for ad-hoc use.
    /// Writes the `$argon2id$v=19$…` line to stdout; paste into
    /// `/etc/vpnctl/vpnctld.env` as `VPNCTLD_ADMIN_PASSWORD=…`.
    HashPassword {
        /// Plaintext password. If omitted, read one line from stdin.
        /// Prefer stdin — passing on the command line leaves the
        /// password in shell history + `/proc/<pid>/cmdline`.
        #[arg(long)]
        password: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum MigrateCmd {
    /// Pull state out of a bash `vpn-control` inventory + servers.
    FromBash(cmd::migrate::MigrateFromBashArgs),
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let cli = Cli::parse();

    let res: anyhow::Result<()> = match cli.cmd {
        Cmd::Uuid => {
            println!("{}", vpnctl_crypto::gen_uuid());
            Ok(())
        }
        Cmd::Registry => cmd::registry_cmd::run(cli.output),
        Cmd::Server { cmd } => cmd::server::run(cmd, cli.db, cli.output).await,
        Cmd::User { cmd } => cmd::user::run(cmd, cli.db, cli.output).await,
        Cmd::Grant { user, server } => cmd::grant::run_grant(&user, &server, cli.db).await,
        Cmd::Revoke { user, server } => cmd::grant::run_revoke(&user, &server, cli.db).await,
        Cmd::Deploy { server, key } => cmd::deploy::run(&server, key, cli.db).await,
        Cmd::Status { server, key } => cmd::status::run(&server, key, cli.db, cli.output).await,
        Cmd::Sub {
            user,
            qr,
            ignore_policy,
        } => cmd::sub::run(&user, qr, ignore_policy, cli.db, cli.output).await,
        Cmd::Bootstrap(args) => cmd::bootstrap::run(args, cli.db).await,
        Cmd::Render { server } => cmd::render::run(&server, cli.db).await,
        Cmd::Backup { cmd } => cmd::backup::run(cmd, cli.db, cli.output).await,
        Cmd::Restore { snapshot } => cmd::backup::run_restore(snapshot, cli.db, cli.output).await,
        Cmd::Migrate { cmd } => match cmd {
            MigrateCmd::FromBash(args) => {
                cmd::migrate::run_from_bash(args, cli.db, cli.output).await
            }
        },
        Cmd::GeoipUpdate { dir } => cmd::geoip::run(dir).await,
        Cmd::Admin { cmd } => match cmd {
            AdminCmd::HashPassword { password } => cmd::admin::hash_password(password),
        },
    };

    match res {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}
