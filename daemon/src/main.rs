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

use vpnctld::DaemonConfig;

#[derive(Parser, Debug)]
#[command(name = "vpnctld", version, about = "vpnctl HTTP daemon")]
struct Cli {
    /// Path to the SQLite inventory file (same one CLI uses).
    #[arg(long, env = "VPNCTL_DB")]
    db: Option<std::path::PathBuf>,

    /// Listen address (e.g. 127.0.0.1:18402, 0.0.0.0:18402).
    #[arg(long, env = "VPNCTLD_ADDR", default_value = "127.0.0.1:18402")]
    addr: SocketAddr,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let cli = Cli::parse();
    let config = DaemonConfig::resolve(cli.db, cli.addr).await?;
    info!(
        target = "vpnctld",
        db = %config.db_path.display(),
        addr = %config.addr,
        "starting"
    );

    let app = vpnctld::build(config.clone()).await?;
    let listener = tokio::net::TcpListener::bind(config.addr)
        .await
        .with_context(|| format!("bind {}", config.addr))?;
    info!(target = "vpnctld", "listening on http://{}", config.addr);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("axum::serve")?;
    Ok(())
}

fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt};
    // Production default: info-only, tower_http at warn (request span at info
    // is too noisy and was leaking the token-bearing URI for /sub/<token>
    // before we switched the trace span to use MatchedPath). Set RUST_LOG
    // for verbose traces.
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
