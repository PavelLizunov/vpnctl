//! Wire the axum Router. Kept separate from `main.rs` so tests can build
//! the same Router without the network/signal plumbing.

pub mod registry;
pub mod routes;
pub mod schedulers;
pub mod state;

pub(crate) use registry::build_registry;
pub use routes::router;
pub(crate) use schedulers::{spawn_backup_scheduler_with, spawn_retention_purger};
pub use state::{
    AppState, DEFAULT_BACKUP_DIR, DEFAULT_DEPLOY_KEY_PATH, build, deploy_key_path,
    make_app_state_for_tests, make_app_state_with_rate_limiter, resolve_deploy_key_path,
};
