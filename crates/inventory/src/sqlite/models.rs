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
    /// Тypизированная ошибка для PRIMARY KEY / UNIQUE — CLI может выдать
    /// дружелюбный текст «already exists» вместо raw SQL message.
    #[error("already exists: {0}")]
    AlreadyExists(String),
    /// Wrapping `std::io::Error` from the crypto layer (RNG failure).
    #[error("io (rng): {0}")]
    CryptoIo(std::io::Error),
}

pub type Result<T> = std::result::Result<T, SqliteInventoryError>;

/// Raw column tuple for the `boosty_settings` singleton row.
/// (enabled, blog_url, access_token, refresh_token, device_id,
/// poll_interval_secs, auto_disable_lapsed, grace_days, auto_create_users)
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

/// Bridge configuration (migration `0040_boosty_bridge.sql`, singleton row).
///
/// The three credential fields are SECRETS — never audit-log them, never
/// render them verbatim in admin HTML (mask to `••••<last4>`).
#[derive(Debug, Clone)]
pub struct BoostySettings {
    /// Whether the sync poller is active.
    pub enabled: bool,
    /// Blog url/slug whose subscribers are managed (e.g. `"ninitux"`).
    pub blog_url: Option<String>,
    /// Static bearer token (short-lived; expires ~hourly).
    pub access_token: Option<String>,
    /// Refresh token (long-lived, rotating — daemon persists rotations).
    pub refresh_token: Option<String>,
    /// Device id for the refresh flow.
    pub device_id: Option<String>,
    /// Reconciliation cadence in seconds.
    pub poll_interval_secs: u64,
    /// When true, lapsed subscribers are auto-disabled; when false, they
    /// are only surfaced for the operator to confirm.
    pub auto_disable_lapsed: bool,
    /// Days after the first observed lapse (or Boosty's `off_time`) before
    /// an automatic disable may be applied.
    pub grace_days: u16,
    /// Create a complete vpnctl user and grant every server for a new paid
    /// subscriber.
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

/// One UA-cluster row for the Phase Track-4 fingerprint heuristic.
/// Groups `sub_access_log` rows by User-Agent within the recent
/// window. The classifier ("roaming" vs "shared URL") lives in the
/// admin handler, not here — inventory just exposes raw aggregates.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UaCluster {
    /// User-Agent string. `None` means rows whose UA was missing
    /// (curl scripts, misconfigured clients).
    pub ua: Option<String>,
    /// Distinct IPs that hit /sub with this UA in the window.
    pub distinct_ips: u64,
    /// Distinct /16 networks (first two octets of v4) — the heuristic
    /// signal: one device usually roams within a single ISP /16,
    /// while a shared URL spreads across ASNs and therefore /16s.
    pub distinct_slash16: u64,
    /// Total hits with this UA in the window.
    pub hits: u64,
}

/// One time-bucket of `sub_access_log` aggregated for the Phase F
/// monitoring sparklines. `ts` is the bucket start (ISO-8601, UTC),
/// `hits` is the count of requests in the bucket, `distinct_ips` is
/// `COUNT(DISTINCT ip)` in the bucket. Buckets with zero hits are
/// NOT returned by the query — the renderer fills gaps with zero so
/// the sparkline x-axis stays evenly spaced.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccessBucket {
    pub bucket_start: DateTime<Utc>,
    pub hits: u64,
    pub distinct_ips: u64,
}

/// One user flagged by [`SqliteInventory::sub_fetch_without_traffic_users`]
/// (2026-06-16). The user pulled their `/sub` subscription `fetch_age_minutes`
/// ago (between the grace floor and the lookback ceiling), was actively
/// passing traffic *before* that fetch, yet has had ZERO attributed traffic
/// *since* — the silent signature of a subscription whose freshly-issued
/// config no longer connects (e.g. the 2026-06-16 `fp=chrome` DPI breakage:
/// clients re-imported the sub and then silently failed to dial, with no
/// server-side error to catch).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubFetchStallUser {
    pub user_id: UserId,
    /// ISO-8601 UTC of the most recent real (non-egress, status 200) fetch.
    pub last_fetch: String,
    /// ISO-8601 UTC of the user's last attributed traffic, if any. Always
    /// BEFORE `last_fetch` by construction — that gap IS the violation.
    pub last_traffic: Option<String>,
    /// Whole minutes between `last_fetch` and now (for the alert summary).
    pub fetch_age_minutes: i64,
}

/// One row of the dashboard "Heavy users · <window>" table (2026-06-16 —
/// split out from the old `(UserId, total)` tuple so the tile can show
/// upload / download / total as three columns). All three figures are
/// `usage_coefficient`-weighted (a ×2 node's bytes count double), matching
/// the #41 traffic-accounting convention; `total_bytes` is exactly
/// `upload_bytes + download_bytes`, and the ranking is by that total.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeavyUser {
    pub user_id: UserId,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub total_bytes: u64,
}

/// Raw account-sharing signals for one user over the scoring window
/// (2026-06-17). The daemon's `sharing_score` turns these into a weighted
/// 0-100 risk score + a human-readable breakdown. All fields are bounded to
/// REAL external clients (the `real_client_ip_predicate` is applied to the
/// sub_access-derived counts; the concurrency/source-IP tables only ever
/// hold public client IPs). Each field is an independent signal:
///
/// - `typical_concurrent_nets` — STRONGEST: P75 of daily peak simultaneous
///   ISP-scale networks (true concurrency without one-off outliers).
/// - `impossible_travel_hops` — country changes between consecutive `/sub`
///   fetches < the impossible-travel window.
/// - `max_daily_nets` — most distinct ISP-scale networks in any one day.
/// - `distinct_device_classes`/`distinct_asns`/`distinct_countries`/`distinct_ips`
///   — cumulative diversity of `/sub` fetches (weaker).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharingSignals {
    pub user_id: UserId,
    // Fetch-side diversity — kept for DISPLAY context only; the redesigned
    // scorer no longer feeds these into the risk number (they're inflated by
    // power users with many client apps + proxy/CDN fetches, not sharing).
    pub distinct_ips: u64,
    pub distinct_asns: u64,
    pub distinct_countries: u64,
    pub distinct_device_classes: u64,
    /// 75th percentile of the user's daily peak simultaneous access-network
    /// counts. A one-off stale connection or carrier hand-over cannot own the
    /// score for 30 days; sustained concurrency still does.
    pub typical_concurrent_nets: u32,
    /// Most distinct ISP-scale networks the user connected from in any single
    /// day (secondary signal).
    pub max_daily_nets: u32,
    /// `/sub` country changes faster than `impossible_travel_hours` (weak —
    /// proxy/CDN fetches + geoip flap trip it; only many hops score).
    pub impossible_travel_hops: u64,
}

/// One row of `sub_access_log` (Phase Track-1) — emitted by the daemon
/// every time `/sub/<token>` is hit, after the token has been resolved.
/// The token itself is never stored, only the resolved `user_id`, so a
/// row alone can't replay the request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubAccessEntry {
    pub id: i64,
    pub ts: DateTime<Utc>,
    pub user_id: String,
    pub ip: String,
    pub ua: Option<String>,
    pub status: u16,
    pub bytes: u64,
    // Track-1.2 (migration 0019) — richer per-request metadata.
    // All Optional; old rows stay None (pre-migration NULL).
    pub accept_language: Option<String>,
    pub http_version: Option<String>,
    pub device_class: Option<String>,
    pub geo_country: Option<String>,
    pub geo_asn: Option<String>,
    // Track-1.4 (migration 0020) — TLS client fingerprint forwarded
    // by nginx (X-SSL-JA3 / X-SSL-JA4) when an nginx-side JA3/JA4
    // module is installed AND the peer is in
    // VPNCTLD_TRUSTED_PROXIES. None until that path is wired —
    // schema is ready, capture is gated on host config.
    pub tls_ja3: Option<String>,
    pub tls_ja4: Option<String>,
    // Phase 4a (migration 0021) — true when this row's src IP is
    // one of our own VPN-server addresses. Means: the user was in
    // full-tunnel mode and their request reached us through the
    // VPN exit, so `ip` is OUR server IP, NOT the user's device IP.
    // Set automatically by a SQLite trigger on INSERT (no Rust-
    // side state to invalidate when servers come and go).
    pub is_vpn_egress: bool,
}

/// Aggregates over a user's `sub_access_log` rows for the
/// per-user-detail summary cards. Phase 4a — Pavel needs «I've
/// reset the iPhone, what was its last seen IP?» / «how many
/// countries did this user hit us from?» at a glance instead of
/// scanning the timeline. All counters EXCLUDE VPN-egress rows
/// (they're our own servers, no operator-actionable signal).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubAccessAggregates {
    /// Total rows in the window (real client IPs only — egress
    /// rows excluded).
    pub total_rows: u64,
    /// How many rows were filtered out as VPN-egress in this
    /// window — surface as a small badge so the operator knows
    /// the «N hidden» count without scrolling.
    pub egress_rows: u64,
    /// Distinct real client IPs. A high number with low
    /// distinct_countries (e.g. 50 IPs, 1 country) usually means
    /// a single roaming device on a busy ISP; high+high means
    /// shared subscription.
    pub distinct_ips: u64,
    /// Distinct ISO country codes from GeoIP enrichment. NULL
    /// geo_country (pre-2026-05-21 rows / private IPs) is not
    /// counted.
    pub distinct_countries: u64,
    /// Distinct ASN labels (full string `AS1234 Operator Ltd`).
    pub distinct_asns: u64,
    /// Sum of `bytes` across the window — total subscription
    /// payload bytes served to this user.
    pub total_bytes: u64,
    /// Timestamp of the most recent row (real or egress). None if
    /// the user has zero history. Useful for the «last seen
    /// recently / inactive» chip on the user-detail page.
    pub last_seen: Option<DateTime<Utc>>,
    /// Earliest row in the window. None if zero history.
    pub first_seen: Option<DateTime<Utc>>,
}

/// TT-2 — proxy-masked accounting for the Activity-tab honesty banner.
/// See [`SqliteInventory::sub_access_proxy_masked_stats`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProxyMaskedStats {
    /// Real-client-attempt rows (`is_vpn_egress = 0`) in the window.
    pub window_rows: u64,
    /// Of those, how many logged a private/reserved/proxy IP instead of
    /// a real client IP (the front-proxy masking).
    pub masked_rows: u64,
    /// RFC3339 ts of the oldest masked row (banner date span), if any.
    pub masked_min_ts: Option<String>,
    /// RFC3339 ts of the newest masked row, if any.
    pub masked_max_ts: Option<String>,
}

/// One row of the per-user "Subscription origins · by country" breakdown
/// (abuse-origins PR). Built from `sub_access_by_country`, which groups a
/// user's real (`is_vpn_egress = 0`, non-NULL `user_id`) `sub_access_log`
/// rows by `geo_country`. The operator reads this to answer «from how
/// many countries — and how many distinct IPs/ISPs in each — was this
/// one subscription fetched».
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubOriginCountry {
    /// ISO country code from GeoIP. `None` for rows GeoIP couldn't
    /// resolve (the UI renders "(unknown)").
    pub country: Option<String>,
    /// Total non-egress fetches from this country in the window.
    pub fetches: u64,
    /// Distinct client IPs from this country.
    pub ips: u64,
    /// Distinct ASN labels seen from this country.
    pub asns: u64,
}

/// One row of the per-user "Subscription origins · by ISP" breakdown
/// (abuse-origins PR). Built from `sub_access_by_asn`, grouping by the
/// descriptive `geo_asn` string (e.g. "AS8359 MTS PJSC"). Top-N by
/// fetch count — the operator sees which networks the link is being
/// pulled from.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubOriginAsn {
    /// Full ASN / ISP label from GeoIP-ASN. `None` for unresolved rows.
    pub asn: Option<String>,
    /// A representative country code for this ASN (MAX over the group —
    /// most ASNs sit in one country, so this is informative without a
    /// second grouping dimension). `None` when unresolved.
    pub country: Option<String>,
    /// Total non-egress fetches from this ASN in the window.
    pub fetches: u64,
    /// Distinct client IPs from this ASN.
    pub ips: u64,
}

/// One row of the per-user "Subscription origins · by IP" breakdown
/// (abuse-origins PR). Built from `sub_access_by_ip`, grouping by the
/// raw client `ip`. Top-N by most-recent activity — the operator sees
/// the actual devices/locations sharing the link, newest first.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubOriginIp {
    /// The client source IP (never NULL — it's `NOT NULL` in schema).
    pub ip: String,
    /// Country code GeoIP last associated with this IP. `None` when
    /// unresolved.
    pub country: Option<String>,
    /// ASN / ISP label GeoIP last associated with this IP. `None` when
    /// unresolved.
    pub asn: Option<String>,
    /// Total non-egress fetches from this IP in the window.
    pub fetches: u64,
    /// ISO-8601 (UTC) timestamp of the earliest fetch from this IP in
    /// the window. Same string format `log_sub_access` writes; the
    /// renderer parses + reformats via `format_msk_iso`.
    pub first_seen: String,
    /// ISO-8601 (UTC) timestamp of the most recent fetch from this IP.
    pub last_seen: String,
}

/// Rough distinct-device proxy for one user over the origins window
/// (abuse-origins PR). Built from `sub_access_device_fingerprint`,
/// counting `DISTINCT` device_class / tls_ja4 / ua over the real
/// (non-egress, non-NULL-user) rows. Higher distinct counts than a
/// household's device count is a sharing signal — surfaced as a single
/// "≈N devices" line on the user-detail page.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubDeviceFp {
    /// Distinct non-NULL `device_class` values (parsed client family).
    pub distinct_device_classes: u64,
    /// Distinct non-NULL `tls_ja4` fingerprints — the sharpest device
    /// signal when nginx forwards JA4 (often 0 until that's wired).
    pub distinct_ja4: u64,
    /// Distinct non-NULL `ua` strings — a coarser device proxy that's
    /// always populated.
    pub distinct_uas: u64,
}

/// PR-Q — "today so far" operational digest for the dashboard banner.
/// Buckets the day's `audit_log` rows (since local-midnight UTC) into
/// the three operator-relevant categories. Pure counts — the UI
/// renders the copy ("3 users added, 2 grants changed, 1 deploy").
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TodayDigest {
    /// `action = 'user.create'` rows today.
    pub users_added: u64,
    /// Grant mutations today (`*.grant` / `*.revoke`).
    pub grants_changed: u64,
    /// `action = 'server.deploy'` rows today.
    pub deploys: u64,
}

/// PR-Q — user lifecycle facts for the user-detail header. `created_at`
/// is the row from `users` (migration 0001); `last_sub_fetch` is the
/// most recent real (non-egress) `sub_access_log` hit; `age_days` is
/// derived from `created_at` to "now" so the UI doesn't re-implement
/// the date math.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserLifecycle {
    /// When the user row was created (from `users.created_at`).
    pub created_at: DateTime<Utc>,
    /// Most recent real `/sub` fetch, if any. `None` for a user who
    /// has never fetched their subscription.
    pub last_sub_fetch: Option<DateTime<Utc>>,
    /// Whole days between `created_at` and now (floored, never
    /// negative).
    pub age_days: u64,
}

/// One row of `sub_rate_bans` (Phase Track-2 chunk 2). Persistent
/// auto-bans for `/sub` abuse: after K consecutive 429s for the same
/// (kind, key) the daemon writes a row valid for 24h.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ban {
    pub id: i64,
    pub created_at: DateTime<Utc>,
    pub until_ts: DateTime<Utc>,
    pub kind: String,
    pub key: String,
    pub reason: String,
}

/// Phase 4b — server-wide live activity rollup for the dashboard +
/// server-detail page. Aggregated over a configurable look-back
/// window via `server_live_activity`. NM-11 hard-limits per-user
/// attribution from clash-api to NULL, but server-wide totals work
/// without upstream sing-box changes.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerLiveActivity {
    /// Currently-active connections — the value of
    /// `active_connections` from the freshest server-wide row
    /// (user_id IS NULL). `0` when no sample exists.
    pub active_now: u32,
    /// Sum of `upload_bytes` deltas across server-wide rows in
    /// the window. Counts ALL traffic the kernel saw, regardless
    /// of whether per-user attribution worked.
    pub bytes_up_window: u64,
    /// Sum of `download_bytes` deltas across server-wide rows in
    /// the window. Same caveat as `bytes_up_window`.
    pub bytes_dn_window: u64,
    /// Timestamp of the most recent sample for this server, real
    /// or aggregate. None when the poller has NEVER seen this
    /// server (fresh-deploy state).
    pub last_sample_ts: Option<DateTime<Utc>>,
    /// Distinct number of per-user attributed rows in the window.
    /// When NM-11 lands a fix (sing-box PR or fork), this will
    /// climb past zero. Today: always 0 on production. Surface as
    /// «N attributed users · last 24h» pinch to make the upstream
    /// limit explicit instead of silently absent.
    pub distinct_users_attributed: u32,
}

/// One row in `vpn_user_sessions` (Phase 5c) — per-(user, server)
/// activity window, closed by inactivity gap. Built by the
/// session-tracker logic: tick observations advance an OPEN
/// session's last_seen; a gap > SESSION_GAP_MINUTES makes the
/// next observation OPEN a new row.
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

/// One row in `vpn_user_destinations` (Phase 5b) — per-(user,
/// destination_label, date) hit counter. Used to render «куда
/// ходит этот юзер» on /admin/users/<id>. NOT a byte counter —
/// the writer increments `hit_count` per clash-poll tick where
/// the pair was observed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VpnUserDestinationRow {
    pub user_id: UserId,
    pub destination_label: String,
    pub date: String,
    pub hit_count: u64,
    pub last_seen: DateTime<Utc>,
}

/// One row in `vpn_user_source_ips` (2026-06-14) — per-(user,
/// source_ip, date) hit counter. The source-IP counterpart to
/// [`VpnUserDestinationRow`]: answers «from which client IP did this
/// user connect, and how often» on /admin/users/<id>. NOT a byte
/// counter — `hit_count` is incremented per clash-poll tick where the
/// (user, source_ip) pair had at least one live connection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VpnUserSourceIpRow {
    pub user_id: UserId,
    pub source_ip: String,
    pub date: String,
    pub hit_count: u64,
    pub last_seen: DateTime<Utc>,
}

/// One row in `vpn_user_daily` (Phase 5a-1) — per-(user, server,
/// date) aggregated traffic + peak conns. Long-term retention
/// counterpart to the rolling 30-day `vpn_connection_stats`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VpnUserDailyRow {
    /// UTC date as `YYYY-MM-DD`.
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

/// One row in `vpn_connection_stats` (Track-3 chunk 2). The poller
/// writes deltas (not totals) per (server, user) on every tick where
/// the delta is non-zero.
///
/// `user_id = None` is the server-wide row for that snapshot — sum
/// of all per-user deltas plus any unattributed traffic from
/// connections that didn't carry a `metadata.user`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VpnStatsRow {
    pub ts: DateTime<Utc>,
    pub server_id: ServerId,
    pub user_id: Option<UserId>,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub active_connections: u32,
}

/// One delta the poller wants to write — produced by the in-memory
/// diff engine in `daemon::clash_poller`. Bundled into a single
/// transaction by `record_vpn_stats` so a tick lands atomically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnStatsDelta {
    /// `None` = server-wide row.
    pub user_id: Option<UserId>,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub active_connections: u32,
}

/// One row in `node_health` (Phase H chunk 2). Daemon-side poller
/// writes one per tick per server. Fields are `Option` to mirror
/// `daemon::node_probe::Probe` — partial-success snapshots
/// (one parser failed, others succeeded) preserve the working
/// metrics instead of throwing the whole row away.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeHealthRow {
    pub ts: DateTime<Utc>,
    pub server_id: ServerId,
    pub sing_box_active: Option<bool>,
    pub fail2ban_active: Option<bool>,
    pub disk_used_mib: Option<u64>,
    pub disk_total_mib: Option<u64>,
    pub mem_available_mib: Option<u64>,
    pub mem_total_mib: Option<u64>,
    pub load_1min_x100: Option<u32>,
    /// JSON array of sorted `"proto/port"` strings (e.g.
    /// `["tcp/443","udp/8443"]`). Parsed on the UI side via
    /// `serde_json::from_str`. Stored as a String so SQL
    /// `LIKE '%/443%'` queries can grep without parsing.
    pub listening_ports_json: Option<String>,
    pub sing_box_log_bytes: Option<u64>,
    /// PR-Q — on-node kernel versions as a JSON object, e.g.
    /// `{"sing-box":"1.13.12","caddy":"2.8.4"}`. `None` for rows
    /// written before the version capture landed, or partial-probe
    /// ticks where no version command succeeded. Caller extracts the
    /// key it cares about (`"sing-box"`) for the drift-detail card.
    pub kernel_versions_json: Option<String>,
    /// Traffic ground-truth (migration 0038) — default-route interface
    /// name + its RAW cumulative `rx_bytes`/`tx_bytes`. NOT deltas; the
    /// gap computation (`server_traffic_breakdown`) diffs consecutive
    /// rows with a reboot/reset guard. `None` for rows predating this or
    /// ticks where the counters were unreadable.
    pub nic_iface: Option<String>,
    pub nic_rx_bytes: Option<u64>,
    pub nic_tx_bytes: Option<u64>,
    /// sing-box monotonic systemd `NRestarts` counter (migration 0042).
    /// RAW cumulative value; the health monitor (`diff_rows`) diffs
    /// consecutive rows and fires a dedicated infra alert on an increase
    /// (sing-box crashed + auto-restarted between probes), guarding the
    /// drop that follows a host reboot / `systemctl reset-failed`. `None`
    /// for rows predating this or ticks where `systemctl show` failed.
    pub sing_box_nrestarts: Option<u64>,
}

/// Traffic-accounting breakdown for one server over a window, produced
/// by [`SqliteInventory::server_traffic_breakdown`]. The GAP is the
/// headline: real NIC traffic minus what clash-api could attribute to
/// sing-box — i.e. non-sing-box protocols (naive/Caddy)
/// plus protocol/OS overhead that vpnctl currently can't break
/// down per-user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrafficBreakdown {
    /// NIC ground-truth total (rx+tx deltas) — ALL traffic on the node.
    pub nic_total_bytes: u64,
    pub nic_rx_bytes: u64,
    pub nic_tx_bytes: u64,
    /// Bytes attributed to sing-box via clash-api (up+dn) — the part
    /// vpnctl can break down per-user.
    pub attributed_bytes: u64,
    /// `nic_total − attributed`, saturating at 0. The unattributed slice.
    pub gap_bytes: u64,
    /// NIC samples in the window (≥2 needed for any delta). 0/1 ⇒ no NIC
    /// figure yet (fresh node / probe predates this feature).
    pub nic_samples: usize,
    /// Interface the counters came from (newest sample), for display.
    pub nic_iface: Option<String>,
}

/// Phase H+ — rolling-window aggregate computed by
/// [`SqliteInventory::uptime_for_server`]. Pure data carrier — all
/// derivation (chip colour, time-since-outage formatting) belongs
/// in the UI layer.
///
/// `uptime_pct` is `Option<u8>` rather than e.g. `f32` because:
///   * UI renders integer % (`99%`, never `98.7%`) — the 10-min
///     probe cadence doesn't justify fractional precision and the
///     extra digits would falsely imply otherwise. `u8` is cheaper
///     to format + compare than a float.
///   * `None` is a distinct state from `Some(0)` — the former means
///     «no decidable data in window», the latter «server was DOWN
///     for the entire window». Conflating them via a sentinel float
///     (NaN, -1) loses signal.
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

/// Phase G — one operator-facing alert row.
///
/// Written by `daemon::health_monitor` when a node_health snapshot
/// crosses a threshold or flips a service state. Stays in the table
/// until the operator explicitly acks via the dashboard / feed page;
/// acked rows enter the 30-day retention window in the existing
/// retention scheduler.
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

/// Phase G chunk 3 — Telegram bot transport config. Singleton row.
/// The two main halves (`token`, `chat_id`) are `Option<String>`
/// because the schema allows either to be NULL; the dispatch loop
/// treats either-None as «transport disabled». An «Enable» flow in
/// the Settings UI requires BOTH set.
///
/// **`token` is a SECRET** — same care as `users.wireguard_private`.
/// Never serialise into `audit_log.payload_json` or any
/// operator-visible feed.
///
/// The Settings page renders `••••<last4>` + a «replace» button;
/// the only place the full value goes is the outgoing HTTPS POST
/// to `api.telegram.org`.
///
/// `proxy_via_server_id` (migration 0015) routes the outbound HTTPS
/// through an inventory server via SSH — used when the daemon host
/// can't reach api.telegram.org directly (РФ network blocks, etc).
/// `None` = local curl from the daemon host. Plain TEXT in the
/// schema, NOT an FK, so the operator gets a loud SSH-spawn error
/// if the referenced server is deleted rather than a silent
/// transport-broken state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelegramConfig {
    pub token: Option<String>,
    pub chat_id: Option<String>,
    pub proxy_via_server_id: Option<String>,
    /// Operator's notification language (migration 0036). `Some("ru")`
    /// → Russian alert pushes; `None`/anything else → English. Read by
    /// `alert_text::render_alert` at push time.
    pub language: Option<String>,
}

impl TelegramConfig {
    /// True iff both halves are present — the dispatch loop should
    /// only attempt a send when this is true. The `proxy_via_server_id`
    /// doesn't gate enablement — direct mode is the default and a
    /// missing server reference is independent of «can we Telegram
    /// at all».
    pub fn is_enabled(&self) -> bool {
        self.token.is_some() && self.chat_id.is_some()
    }

    /// Last 4 characters of the token, suitable for «••••<last4>»
    /// rendering on the Settings page. Returns empty string when the
    /// token is absent (caller should branch on `token.is_some()`
    /// first; this is for rendering convenience).
    pub fn token_last4(&self) -> String {
        match &self.token {
            Some(t) if t.len() >= 4 => t[t.len() - 4..].to_string(),
            Some(t) => t.clone(),
            None => String::new(),
        }
    }
}
