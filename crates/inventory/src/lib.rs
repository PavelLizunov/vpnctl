pub mod assurance;
pub mod backup;
pub mod bootstrap;
pub mod jump_resolver;
pub mod migrate;
pub mod operation_lock;
pub mod quality;
pub mod reachability;
pub use reachability::{ServicePathIncident, ServicePathState, ServicePathStatus};
pub mod sqlite;

/// Return the embedded migration versions and complete SQLx checksum bytes in
/// ascending version order, without opening or migrating an inventory.
pub fn embedded_migration_checksums() -> Vec<(i64, Vec<u8>)> {
    let mut migrations: Vec<_> = sqlite::migrator()
        .iter()
        .map(|migration| (migration.version, migration.checksum.to_vec()))
        .collect();
    migrations.sort_by_key(|(version, _)| *version);
    migrations
}

mod ssh_access;
pub use ssh_access::{
    SshAccessCheck, SshAccessFailure, SshAccessRoute, SshAccessState, SshAccessStatus,
};

pub use jump_resolver::{JumpResolverError, resolve_jump_host};

pub use assurance::{AssuranceStage, AssuranceState, ProtocolAssuranceSample};
pub use backup::{
    CheckResult, CheckStatus, DEFAULT_BACKUP_DIR, Retention, SelfTestReport, SnapshotInfo,
    backup_dir_from_env, list_snapshots, parse_snapshot_filename, prune_snapshots, restore_from,
    snapshot_filename_at, snapshot_now, snapshot_to, verify_snapshot,
};
pub use bootstrap::bootstrap_server_secrets;
pub use migrate::{
    BashInventoryEnv, BashSingboxData, BashTuicUser, BashVlessUser, MigrationOutcome,
    MigrationPlan, SkippedUser, apply_migration_plan, build_migration_plan,
    derive_server_id_from_ip, parse_bash_inventory_env, parse_bash_singbox,
};
pub use operation_lock::NodeOperationLock;
pub use quality::{QUALITY_MIN_SAMPLES, ServiceQualitySample, ServiceQualityScore, score_samples};
pub use sqlite::{
    AccessBucket, AdminAlert, AuditEntry, Ban, BillingCycle, BoostySettings, ConversionResult,
    CurrencyRate, CurrencySettings, CurrencySettingsInput, FleetBillingSummary, HeavyUser,
    NodeHealthRow, NodeNicDelta, NodeNicUsage, ProxyMaskedStats, ServerBilling, ServerBillingInput,
    ServerBillingItem, ServerBillingSummaryItem, ServerLiveActivity, ServerPayment,
    ServerPaymentInput, ServerRole, ServerTrafficLimit, SharingSignals, SqliteInventory,
    SqliteInventoryError, SubAccessAggregates, SubAccessEntry, SubAccessEntryInput, SubDeviceFp,
    SubOriginAsn, SubOriginCountry, SubOriginIp, TelegramConfig, TodayDigest, TrafficBreakdown,
    UaCluster, UptimeStat, UserLifecycle, VPN_STATS_RETENTION_DAYS, VpnCumulativeCounter,
    VpnCumulativeTick, VpnStatsDelta, VpnStatsRow, VpnUserDailyRow, VpnUserDestinationRow,
    VpnUserSessionRow, VpnUserSourceIpRow, advance_date_by_cycle, convert_minor,
    monthly_equivalent, server_traffic_period, sum_nic_deltas, validate_due_date,
};

pub use sqlite::{
    CORP_MAX_REVISION, CorpCompany, CorpCompanySession, CorpCredentials, CorpInventory,
    CorpPublication, CorpReaderToken, CorpRecord, CorpResult, CorpRevision, CorpSession,
    CorpSessionInput, CorpSetup, CorpSigningKey, CorpStatus, CorpStoreError, CorpVerifiedEgress,
};
