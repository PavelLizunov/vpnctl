//! Inventory — хранение состояния (servers/users/grants/audit).
//!
//! Два варианта реализации:
//!
//! - `InMemoryInventory` (`mem.rs`) — для unit-тестов в других крейтах.
//! - `SqliteInventory` (`sqlite.rs`) — production: persistence через `sqlx`,
//!   embedded migrations, WAL, FK enforcement, audit log.

pub mod mem;
pub mod sqlite;

pub use mem::InMemoryInventory;
pub use sqlite::{
    AccessBucket, AuditEntry, Ban, NodeHealthRow, SqliteInventory, SqliteInventoryError,
    SubAccessEntry, UaCluster, VpnStatsDelta, VpnStatsRow,
};
