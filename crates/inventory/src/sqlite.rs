//! SQLite-backed inventory.
//!
//! Notes:
//!
//! - Uses `sqlx::query` (runtime-checked) for now to keep bootstrap simple
//!   (no `cargo sqlx prepare` / `.sqlx/` pipeline). When the schema is
//!   stable in v0.3, migrate to `sqlx::query!` for compile-time checking.
//! - Connection options force WAL, FK enforcement, and a 5-second
//!   busy-timeout (PRAGMAs applied via `SqliteConnectOptions`).
//! - Schema lives in `migrations/0001_init.sql` and is embedded into the
//!   binary by `sqlx::migrate!`.

mod access;
mod alerts;
mod audit;
mod base;
mod boosty;
mod health;
mod models;
mod servers;
mod sessions;
mod settings;
mod stats;
mod users;

#[cfg(test)]
mod tests;

pub use base::*;
pub use health::sum_nic_deltas;
pub use models::*;
