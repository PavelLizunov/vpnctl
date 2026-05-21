//! Inventory — хранение состояния (servers/users/grants/audit).
//!
//! Два варианта реализации:
//!
//! - `InMemoryInventory` (`mem.rs`) — для unit-тестов в других крейтах.
//! - `SqliteInventory` (`sqlite.rs`) — production: persistence через `sqlx`,
//!   embedded migrations, WAL, FK enforcement, audit log.

pub mod backup;
pub mod mem;
pub mod migrate;
pub mod sqlite;

pub use backup::{
    DEFAULT_BACKUP_DIR, Retention, SnapshotInfo, list_snapshots, parse_snapshot_filename,
    prune_snapshots, restore_from, snapshot_filename_at, snapshot_now, snapshot_to,
};
pub use mem::InMemoryInventory;
pub use migrate::{
    BashInventoryEnv, BashSingboxData, BashTuicUser, BashVlessUser, MigrationOutcome,
    MigrationPlan, SkippedUser, apply_migration_plan, build_migration_plan,
    derive_server_id_from_ip, parse_bash_inventory_env, parse_bash_singbox,
};
pub use sqlite::{
    AccessBucket, AdminAlert, AuditEntry, Ban, NodeHealthRow, ServerLiveActivity, SqliteInventory,
    SqliteInventoryError, SubAccessAggregates, SubAccessEntry, TelegramConfig, UaCluster,
    VpnStatsDelta, VpnStatsRow, VpnUserDailyRow, VpnUserDestinationRow, VpnUserSessionRow,
};
