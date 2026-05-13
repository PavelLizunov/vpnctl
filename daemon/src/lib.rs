//! Library face of `vpnctld`. Lets integration tests build the SAME
//! `Router` that the binary uses, so spec tests assert the real handler
//! contract instead of a shim. Without this, the daemon binary alone
//! has no externally-visible surface and tests must reimplement the
//! Router structure (which defeats the purpose of spec tests).
//!
//! The binary itself just calls `vpnctld::serve(config)` — kept thin.

pub mod app;
pub mod config;
pub mod handlers;

pub use app::{AppState, build, router};
pub use config::DaemonConfig;
