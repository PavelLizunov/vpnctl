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
    };

    match res {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}
