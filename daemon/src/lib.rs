//! Library face of `vpnctld`. Lets integration tests build the SAME
//! `Router` that the binary uses, so spec tests assert the real handler
//! contract instead of a shim. Without this, the daemon binary alone
//! has no externally-visible surface and tests must reimplement the
//! Router structure (which defeats the purpose of spec tests).
//!
//! The binary itself just calls `vpnctld::serve(config)` — kept thin.

pub mod access_log;
pub mod app;
pub mod config;
pub mod handlers;
pub mod rate_limit;

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
