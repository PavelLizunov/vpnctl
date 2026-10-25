use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use vpnctl_core::{ServerId, UserId};

#[derive(Debug, thiserror::Error)]
pub enum SqliteInventoryError {
    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("migration: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid data in db: {0}")]
    Invalid(String),
    #[error("already exists: {0}")]
    AlreadyExists(String),
    #[error("io (rng): {0}")]
    CryptoIo(std::io::Error),
}

pub type Result<T> = std::result::Result<T, SqliteInventoryError>;

pub(crate) type BoostySettingsRow = (
    i64,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    i64,
    i64,
    i64,
    i64,
);

#[derive(Debug, Clone)]
pub struct BoostySettings {
    pub enabled: bool,
    pub blog_url: Option<String>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub device_id: Option<String>,
    pub poll_interval_secs: u64,
    pub auto_disable_lapsed: bool,
    pub grace_days: u16,
    pub auto_create_users: bool,
}

impl Default for BoostySettings {
    fn default() -> Self {
        Self {
            enabled: false,
            blog_url: None,
            access_token: None,
            refresh_token: None,
            device_id: None,
            poll_interval_secs: 3600,
            auto_disable_lapsed: false,
            grace_days: 14,
            auto_create_users: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: i64,
    pub ts: DateTime<Utc>,
    pub actor: String,
    pub action: String,
    pub target: Option<String>,
    pub payload: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UaCluster {
    pub ua: Option<String>,
    pub distinct_ips: u64,
    pub distinct_slash16: u64,
    pub hits: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccessBucket {
    pub bucket_start: DateTime<Utc>,
    pub hits: u64,
    pub distinct_ips: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubFetchStallUser {
    pub user_id: UserId,
    pub last_fetch: String,
    pub last_traffic: Option<String>,
    pub fetch_age_minutes: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeavyUser {
    pub user_id: UserId,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharingSignals {
    pub user_id: UserId,
    pub distinct_ips: u64,
    pub distinct_asns: u64,
    pub distinct_countries: u64,
    pub distinct_device_classes: u64,
    pub typical_concurrent_nets: u32,
    pub max_daily_nets: u32,
    pub impossible_travel_hops: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubAccessEntry {
    pub id: i64,
    pub ts: DateTime<Utc>,
    pub user_id: String,
    pub ip: String,
    pub ua: Option<String>,
    pub status: u16,
    pub bytes: u64,
    pub accept_language: Option<String>,
    pub http_version: Option<String>,
    pub device_class: Option<String>,
    pub geo_country: Option<String>,
    pub geo_asn: Option<String>,
    pub tls_ja3: Option<String>,
    pub tls_ja4: Option<String>,
    pub is_vpn_egress: bool,
}

#[derive(Debug, Clone)]
pub struct SubAccessEntryInput {
    pub user_id: vpnctl_core::UserId,
    pub ip: String,
    pub ua: Option<String>,
    pub status: u16,
    pub bytes: u64,
    pub accept_language: Option<String>,
    pub http_version: Option<String>,
    pub device_class: Option<String>,
    pub geo_country: Option<String>,
    pub geo_asn: Option<String>,
    pub tls_ja3: Option<String>,
    pub tls_ja4: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubAccessAggregates {
    pub total_rows: u64,
    pub egress_rows: u64,
    pub distinct_ips: u64,
    pub distinct_countries: u64,
    pub distinct_asns: u64,
    pub total_bytes: u64,
    pub last_seen: Option<DateTime<Utc>>,
    pub first_seen: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProxyMaskedStats {
    pub window_rows: u64,
    pub masked_rows: u64,
    pub masked_min_ts: Option<String>,
    pub masked_max_ts: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubOriginCountry {
    pub country: Option<String>,
    pub fetches: u64,
    pub ips: u64,
    pub asns: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubOriginAsn {
    pub asn: Option<String>,
    pub country: Option<String>,
    pub fetches: u64,
    pub ips: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubOriginIp {
    pub ip: String,
    pub country: Option<String>,
    pub asn: Option<String>,
    pub fetches: u64,
    pub first_seen: String,
    pub last_seen: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubDeviceFp {
    pub distinct_device_classes: u64,
    pub distinct_ja4: u64,
    pub distinct_uas: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TodayDigest {
    pub users_added: u64,
    pub grants_changed: u64,
    pub deploys: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserLifecycle {
    pub created_at: DateTime<Utc>,
    pub last_sub_fetch: Option<DateTime<Utc>>,
    pub age_days: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ban {
    pub id: i64,
    pub created_at: DateTime<Utc>,
    pub until_ts: DateTime<Utc>,
    pub kind: String,
    pub key: String,
    pub reason: String,
}

// Raw readers include calendar-month usage (up to 31 days) and 30-day charts.
pub const VPN_STATS_RETENTION_DAYS: u32 = 32;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerLiveActivity {
    pub active_now: Option<u32>,
    pub bytes_up_window: u64,
    pub bytes_dn_window: u64,
    pub last_sample_ts: Option<DateTime<Utc>>,
    pub distinct_users_attributed: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VpnUserSessionRow {
    pub id: i64,
    pub user_id: UserId,
    pub server_id: ServerId,
    pub started_at: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub conn_count_peak: u32,
    pub total_bytes: u64,
}

impl VpnUserSessionRow {
    pub fn duration(&self) -> chrono::Duration {
        self.last_seen - self.started_at
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VpnUserDestinationRow {
    pub user_id: UserId,
    pub destination_label: String,
    pub date: String,
    pub hit_count: u64,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VpnUserSourceIpRow {
    pub user_id: UserId,
    pub source_ip: String,
    pub date: String,
    pub hit_count: u64,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VpnUserDailyRow {
    pub date: String,
    pub user_id: UserId,
    pub server_id: ServerId,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub active_connections_peak: u32,
    pub distinct_source_ips: u32,
}

impl VpnUserDailyRow {
    pub fn total_bytes(&self) -> u64 {
        self.upload_bytes.saturating_add(self.download_bytes)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VpnStatsRow {
    pub ts: DateTime<Utc>,
    pub server_id: ServerId,
    pub user_id: Option<UserId>,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub active_connections: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnStatsDelta {
    pub user_id: Option<UserId>,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub active_connections: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnCumulativeCounter {
    pub user_id: UserId,
    pub upload_total: u64,
    pub download_total: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnCumulativeTick {
    pub server_upload_total: u64,
    pub server_download_total: u64,
    pub uptime_seconds: u64,
    pub active_connections: u32,
    pub users: Vec<VpnCumulativeCounter>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeHealthRow {
    #[serde(default)]
    pub sample_seq: Option<i64>,
    #[serde(default)]
    pub sample_id: Option<String>,
    pub ts: DateTime<Utc>,
    pub server_id: ServerId,
    pub sing_box_active: Option<bool>,
    pub fail2ban_active: Option<bool>,
    pub disk_used_mib: Option<u64>,
    pub disk_total_mib: Option<u64>,
    pub mem_available_mib: Option<u64>,
    pub mem_total_mib: Option<u64>,
    pub load_1min_x100: Option<u32>,
    pub listening_ports_json: Option<String>,
    pub sing_box_log_bytes: Option<u64>,
    pub kernel_versions_json: Option<String>,
    pub nic_iface: Option<String>,
    pub nic_rx_bytes: Option<u64>,
    pub nic_tx_bytes: Option<u64>,
    pub sing_box_nrestarts: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrafficBreakdown {
    pub nic_total_bytes: u64,
    pub nic_rx_bytes: u64,
    pub nic_tx_bytes: u64,
    pub attributed_bytes: u64,
    pub gap_bytes: u64,
    pub nic_samples: usize,
    pub nic_iface: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UptimeStat {
    pub window_hours: u32,
    pub total_rows: u64,
    pub up_rows: u64,
    pub down_rows: u64,
    pub unknown_rows: u64,
    pub uptime_pct: Option<u8>,
    pub last_outage_at: Option<DateTime<Utc>>,
    pub last_probe_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdminAlert {
    pub id: i64,
    pub created_at: DateTime<Utc>,
    pub kind: String,
    pub server_id: Option<ServerId>,
    pub severity: String,
    pub summary: String,
    pub payload_json: Option<String>,
    pub acked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelegramConfig {
    pub token: Option<String>,
    pub chat_id: Option<String>,
    pub proxy_via_server_id: Option<String>,
    pub language: Option<String>,
}

impl TelegramConfig {
    pub fn is_enabled(&self) -> bool {
        self.token.is_some() && self.chat_id.is_some()
    }

    pub fn token_last4(&self) -> String {
        match &self.token {
            Some(t) => {
                let count = t.chars().count();
                if count > 4 {
                    t.chars().skip(count - 4).collect()
                } else {
                    t.clone()
                }
            }
            None => String::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServerRole {
    #[default]
    VpnExit,
    WorkloadOnly,
}

impl ServerRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            ServerRole::VpnExit => "vpn-exit",
            ServerRole::WorkloadOnly => "workload-only",
        }
    }
}

impl std::fmt::Display for ServerRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for ServerRole {
    type Err = SqliteInventoryError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "vpn-exit" => Ok(ServerRole::VpnExit),
            "workload-only" => Ok(ServerRole::WorkloadOnly),
            other => Err(SqliteInventoryError::Invalid(format!(
                "invalid server role '{other}'"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BillingCycle {
    #[default]
    Monthly,
    Quarterly,
    SemiAnnual,
    Annual,
}

impl BillingCycle {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Monthly => "monthly",
            Self::Quarterly => "quarterly",
            Self::SemiAnnual => "semi-annual",
            Self::Annual => "annual",
        }
    }

    pub fn months(&self) -> u32 {
        match self {
            Self::Monthly => 1,
            Self::Quarterly => 3,
            Self::SemiAnnual => 6,
            Self::Annual => 12,
        }
    }
}

impl std::fmt::Display for BillingCycle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for BillingCycle {
    type Err = SqliteInventoryError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "monthly" => Ok(Self::Monthly),
            "quarterly" => Ok(Self::Quarterly),
            "semi-annual" => Ok(Self::SemiAnnual),
            "annual" => Ok(Self::Annual),
            other => Err(SqliteInventoryError::Invalid(format!(
                "invalid billing cycle '{other}'"
            ))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerBilling {
    pub server_id: ServerId,
    pub due_date: String,
    pub billing_cycle: BillingCycle,
    pub amount_cents: i64,
    pub currency: String,
    pub auto_renew: bool,
    pub billing_url: Option<String>,
    pub notes: Option<String>,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerBillingInput {
    pub due_date: String,
    pub billing_cycle: BillingCycle,
    pub amount_cents: i64,
    pub currency: String,
    pub auto_renew: bool,
    pub billing_url: Option<String>,
    pub notes: Option<String>,
    #[serde(default)]
    pub initial_payments_count: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerBillingItem {
    pub server_id: ServerId,
    pub display_name: Option<String>,
    pub hoster: String,
    pub address: String,
    pub billing: Option<ServerBilling>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CurrencyRate {
    pub base_currency: String,
    pub target_currency: String,
    pub rate_micros: i64,
    pub source: String,
    pub fetched_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrencySettings {
    pub display_currency: String,
    pub default_markup_bps: i64,
    pub markup_overrides: std::collections::HashMap<String, i64>,
    pub rate_overrides: std::collections::HashMap<String, i64>,
    pub auto_refresh: bool,
}

impl Default for CurrencySettings {
    fn default() -> Self {
        Self {
            display_currency: "EUR".into(),
            default_markup_bps: 10_700,
            markup_overrides: std::collections::HashMap::new(),
            rate_overrides: std::collections::HashMap::new(),
            auto_refresh: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrencySettingsInput {
    pub display_currency: Option<String>,
    pub default_markup_bps: Option<i64>,
    pub markup_overrides: Option<std::collections::HashMap<String, i64>>,
    pub rate_overrides: Option<std::collections::HashMap<String, i64>>,
    pub auto_refresh: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerPayment {
    pub id: i64,
    pub server_id: ServerId,
    pub paid_at: String,
    pub amount_minor: i64,
    pub currency: String,
    pub cycle: BillingCycle,
    pub converted_minor: Option<i64>,
    pub display_currency: Option<String>,
    pub rate_micros_used: Option<i64>,
    pub markup_bps_used: Option<i64>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPaymentInput {
    pub amount_minor: i64,
    pub currency: String,
    pub cycle: BillingCycle,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversionResult {
    pub amount_minor: i64,
    pub target_currency: String,
    pub rate_micros: i64,
    pub markup_bps: i64,
    pub identity: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetBillingSummary {
    pub display_currency: String,
    pub markup_bps: i64,
    pub total_spend_minor: i64,
    pub monthly_burn_minor: i64,
    pub annual_burn_minor: i64,
    pub servers: Vec<ServerBillingSummaryItem>,
    pub unconvertible: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerBillingSummaryItem {
    pub server_id: ServerId,
    pub display_name: Option<String>,
    pub source_amount_minor: i64,
    pub source_currency: String,
    pub billing_cycle: BillingCycle,
    pub converted_monthly_minor: Option<i64>,
    pub total_spend_minor: i64,
    pub payment_count: i64,
}
