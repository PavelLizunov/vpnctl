//! Inventory — хранение состояния (servers/users/grants/audit).
//!
//! Backing store: `SqliteInventory` (`sqlite.rs`) — production
//! persistence через `sqlx`, embedded migrations, WAL, FK
//! enforcement, audit log. Tests use a per-test TempDir + the same
//! `SqliteInventory::open` so the test-target ↔ production-target gap
//! is zero (no separate `InMemoryInventory` to drift). The previous
//! `mem.rs` stub was deleted 2026-05-22 as orphan code — no caller
//! used it in 9 months (audit I3 catch).

pub mod backup;
// Declarative per-server secret bootstrap, shared by the daemon's
// wizard/web deploy AND the CLI `vpnctl deploy` so the two paths can't
// drift (the CLI used to hand-roll vless/wireguard minting and miss
// shadowsocks-2022's `ss2022.psk` + hysteria2's obfs password).
pub mod bootstrap;
pub mod migrate;
pub mod sqlite;

pub use backup::{
    CheckResult, CheckStatus, DEFAULT_BACKUP_DIR, Retention, SelfTestReport, SnapshotInfo,
    list_snapshots, parse_snapshot_filename, prune_snapshots, restore_from, snapshot_filename_at,
    snapshot_now, snapshot_to, verify_snapshot,
};
pub use bootstrap::bootstrap_server_secrets;
pub use migrate::{
    BashInventoryEnv, BashSingboxData, BashTuicUser, BashVlessUser, MigrationOutcome,
    MigrationPlan, SkippedUser, apply_migration_plan, build_migration_plan,
    derive_server_id_from_ip, parse_bash_inventory_env, parse_bash_singbox,
};
pub use sqlite::{
    AccessBucket, AdminAlert, AuditEntry, Ban, NodeHealthRow, ServerLiveActivity, SqliteInventory,
    SqliteInventoryError, SubAccessAggregates, SubAccessEntry, SubDeviceFp, SubOriginAsn,
    SubOriginCountry, SubOriginIp, TelegramConfig, TodayDigest, UaCluster, UptimeStat,
    UserLifecycle, VpnStatsDelta, VpnStatsRow, VpnUserDailyRow, VpnUserDestinationRow,
    VpnUserSessionRow,
};
