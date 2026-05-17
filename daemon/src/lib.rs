//! Library face of `vpnctld`. Lets integration tests build the SAME
//! `Router` that the binary uses, so spec tests assert the real handler
//! contract instead of a shim. Without this, the daemon binary alone
//! has no externally-visible surface and tests must reimplement the
//! Router structure (which defeats the purpose of spec tests).
//!
//! The binary itself just calls `vpnctld::serve(config)` — kept thin.

pub mod access_log;
pub mod app;
pub mod clash_api;
pub mod clash_poller;
pub mod config;
pub mod handlers;
pub mod node_probe;
pub mod rate_limit;
// Subprocess-based SSH transport — wraps system `ssh` binary instead
// of linking russh. Lets vpnctld talk to nodes without pulling
// glibc 2.38; see ssh_subprocess.rs for the rationale.
pub mod ssh_subprocess;
pub mod wizard;
// Phase E sub-iter 4b — wizard SSE bootstrap engine. Pulled out of
// the admin handler so the bootstrap pipeline can be unit-tested
// without spinning up an axum router. See module-level doc for the
// 9-phase pipeline.
pub mod wizard_bootstrap;

pub use app::{
    AppState, build, make_app_state_for_tests, make_app_state_with_rate_limiter, router,
};
pub use config::DaemonConfig;

/// Test-only re-export of the retention purger spawner so integration
/// tests can verify the wiring. Production code uses
/// `vpnctld::build()` which calls this internally.
pub fn spawn_retention_purger_for_test(
    inv: vpnctl_inventory::SqliteInventory,
) -> tokio::task::JoinHandle<()> {
    app::spawn_retention_purger(inv)
}

/// Test-only re-export of the backup scheduler with custom delays
/// — lets the integration test prove the scheduler actually
/// snapshots + audits without waiting the production 60-second
/// startup delay.
pub fn spawn_backup_scheduler_with_for_test(
    inv: vpnctl_inventory::SqliteInventory,
    backup_dir: std::path::PathBuf,
    startup_delay: std::time::Duration,
    tick: std::time::Duration,
) -> tokio::task::JoinHandle<()> {
    app::spawn_backup_scheduler_with(inv, backup_dir, startup_delay, tick)
}
