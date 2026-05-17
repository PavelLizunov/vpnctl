//! Inventory — хранение состояния (servers/users/grants/audit).
//!
//! Два варианта реализации:
//!
//! - `InMemoryInventory` (`mem.rs`) — для unit-тестов в других крейтах.
//! - `SqliteInventory` (`sqlite.rs`) — production: persistence через `sqlx`,
//!   embedded migrations, WAL, FK enforcement, audit log.

pub mod backup;
pub mod mem;
pub mod sqlite;

pub use backup::{
    DEFAULT_BACKUP_DIR, Retention, SnapshotInfo, list_snapshots, parse_snapshot_filename,
    prune_snapshots, restore_from, snapshot_filename_at, snapshot_now, snapshot_to,
};
pub use mem::InMemoryInventory;
pub use sqlite::{
    AccessBucket, AuditEntry, Ban, NodeHealthRow, SqliteInventory, SqliteInventoryError,
    SubAccessEntry, UaCluster, VpnStatsDelta, VpnStatsRow,
};
