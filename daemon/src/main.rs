//! `vpnctld` binary entry point. All Router / handler logic lives in
//! the library crate (`vpnctld::*`) so integration tests can exercise
//! the real Router shape.
//!
//! Endpoints (v0.4.1 — pre-UI):
//!
//! - `GET /api/v1/health` — liveness probe.
//! - `GET /sub/<token>` — return a sing-box JSON config for the user
//!   whose `sub_token` matches. Public (no auth): the token is the secret.
//!
//! Admin endpoints + UI land in v0.4.2 once the design lands.

use std::net::SocketAddr;

use anyhow::Context;
use clap::Parser;
use tracing::info;

use vpnctld::{DaemonConfig, assert_auth_safe_for_addr};

mod server;

#[derive(Parser, Debug)]
#[command(name = "vpnctld", version, about = "vpnctl HTTP daemon")]
struct Cli {
    #[arg(long, hide = true, conflicts_with = "ha_artifact")]
    ha_execute: bool,

    #[arg(long, hide = true)]
    ha_artifact: bool,

    /// Path to the SQLite inventory file (same one CLI uses).
    #[arg(long, env = "VPNCTL_DB")]
    db: Option<std::path::PathBuf>,

    /// Listen address (e.g. 127.0.0.1:18402, 0.0.0.0:18402).
    #[arg(long, env = "VPNCTLD_ADDR", default_value = "127.0.0.1:18402")]
    addr: SocketAddr,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    if cli.ha_artifact {
        use std::io::Write;

        let mut stdout = std::io::stdout().lock();
        serde_json::to_writer(&mut stdout, &ha_artifact()?)?;
        stdout.write_all(b"\n")?;
        stdout.flush()?;
        return Ok(());
    }
    if cli.ha_execute {
        use std::io::{Read, Write};

        const MAX_FRAME: usize = 64 * 1024 * 1024;
        let mut request = Vec::new();
        std::io::stdin()
            .take((MAX_FRAME + 1) as u64)
            .read_to_end(&mut request)
            .context("reading HA executor request")?;
        let response = vpnctl_ssh::subprocess::handle_ha_execute_request(&request).await?;
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(&response)?;
        stdout.write_all(b"\n")?;
        stdout.flush()?;
        return Ok(());
    }
    init_tracing();

    let config = DaemonConfig::resolve(cli.db, cli.addr).await?;
    assert_auth_safe_for_addr(config.addr)?;
    info!(
        target = "vpnctld",
        db = %config.db_path.display(),
        addr = %config.addr,
        "starting"
    );

    let (app, writer_handle) = vpnctld::build(config.clone()).await?;
    let listener = tokio::net::TcpListener::bind(config.addr)
        .await
        .with_context(|| format!("bind {}", config.addr))?;
    info!(target = "vpnctld", "listening on http://{}", config.addr);

    server::serve(listener, app, shutdown_signal()).await;
    vpnctld::access_log::drain_writer(writer_handle).await;
    Ok(())
}

fn ha_artifact() -> anyhow::Result<serde_json::Value> {
    use std::io::Read;

    use sha2::{Digest, Sha256};

    let mut executable = std::fs::File::open("/proc/self/exe")
        .context("opening running executable for HA artifact verification")?;
    let mut executable_hash = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = executable.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        executable_hash.update(&buffer[..count]);
    }
    let migrations = vpnctl_inventory::embedded_migration_checksums();
    let mut migration_hash = Sha256::new();
    let mut records = Vec::new();
    for (version, checksum) in &migrations {
        use std::fmt::Write;

        let mut checksum_hex = String::with_capacity(checksum.len() * 2);
        for byte in checksum {
            write!(&mut checksum_hex, "{byte:02x}")?;
        }
        migration_hash.update(format!("{version}:{checksum_hex}\n").as_bytes());
        records.push(serde_json::json!({ "version": version, "checksum_hex": checksum_hex }));
    }
    Ok(serde_json::json!({
        "build_sha": option_env!("VPNCTL_BUILD_SHA").unwrap_or("unknown"),
        "executable_sha256": format!("{:x}", executable_hash.finalize()),
        "schema": migrations.last().map_or(0, |(version, _)| *version),
        "migrations": records,
        "migrations_sha256": format!("{:x}", migration_hash.finalize()),
    }))
}

fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt};
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,vpnctld=info,tower_http=warn"));
    fmt().with_env_filter(filter).with_target(true).init();
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => info!(target = "vpnctld", "ctrl-c, shutting down"),
        () = terminate => info!(target = "vpnctld", "SIGTERM, shutting down"),
    }
}
