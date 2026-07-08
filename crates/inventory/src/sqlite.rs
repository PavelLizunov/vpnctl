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

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{SqlitePool, migrate::Migrator};
use std::collections::HashMap;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;
use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// Expose the embedded `Migrator` to sibling modules — currently
/// `backup::restore_from` uses it to validate that an incoming
/// snapshot's schema is at-or-above the current binary's expected
/// version before atomically swapping it over the live DB.
pub(crate) fn migrator() -> &'static Migrator {
    &MIGRATOR
}

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

/// Convert sqlx UNIQUE constraint violations to `AlreadyExists`. Other
/// sqlx errors propagate untouched.
fn map_unique<T>(
    res: std::result::Result<T, sqlx::Error>,
    what: impl std::fmt::Display,
) -> Result<T> {
    match res {
        Ok(v) => Ok(v),
        Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
            Err(SqliteInventoryError::AlreadyExists(what.to_string()))
        }
        Err(e) => Err(e.into()),
    }
}

pub type Result<T> = std::result::Result<T, SqliteInventoryError>;

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
/// - `peak_concurrent_ips` — STRONGEST: most distinct client IPs in ONE
///   clash snapshot (true simultaneity).
/// - `impossible_travel_hops` — country changes between consecutive `/sub`
///   fetches < the impossible-travel window.
/// - `max_daily_source_ips` — most distinct connect-from IPs in any one day.
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
    /// Peak distinct `/24` networks for this user in ONE clash snapshot
    /// (rotation-immune simultaneity). The dominant scoring signal.
    pub peak_concurrent_nets: u32,
    /// Most distinct `/24` networks the user connected from in any single
    /// day (secondary signal).
    pub max_daily_nets: u32,
    /// `/sub` country changes faster than `impossible_travel_hours` (weak —
    /// proxy/CDN fetches + geoip flap trip it; only many hops score).
    pub impossible_travel_hops: u64,
}

/// Collapse an IP to its network key for sharing-detection counting
/// (2026-06-17): IPv4 → its `/24` (`"91.79.36.72"` → `"91.79.36"`), IPv6 →
/// the address verbatim. Mobile carriers rotate a single device across many
/// IPs WITHIN one `/24`-ish pool, so counting distinct `/24`s instead of raw
/// IPs stops one rotating phone from looking like a dozen shared clients
/// (the multiviruss false positive: 16 raw IPs were ~5 `/24`s, mostly one
/// carrier). A real shared sub spans DIFFERENT access networks → different
/// `/24`s. Not perfect (a carrier can span two `/24`s) but kills the bulk of
/// the rotation inflation with zero geoip dependency.
pub fn ipv4_net24(ip: &str) -> String {
    if ip.contains(':') {
        return ip.to_string(); // IPv6 — no cheap /24 analogue; keep whole.
    }
    match ip.rsplit_once('.') {
        Some((prefix, _last_octet)) => prefix.to_string(),
        None => ip.to_string(),
    }
}

/// All-zero [`SharingSignals`] for `user_id` — the per-user accumulator seed
/// in `sharing_signals_all_users` (each of the four signal queries fills in
/// its own fields).
fn blank_sharing_signals(user_id: &str) -> SharingSignals {
    SharingSignals {
        user_id: UserId(user_id.to_string()),
        distinct_ips: 0,
        distinct_asns: 0,
        distinct_countries: 0,
        distinct_device_classes: 0,
        peak_concurrent_nets: 0,
        max_daily_nets: 0,
        impossible_travel_hops: 0,
    }
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

/// Our OWN infrastructure egress IPs that must never count as a real
/// client source-IP (2026-06-16, Pavel). The homelab NAT egress
/// `83.97.108.34` is where every LAN box exits — the control-plane curl
/// tests, the phase6-monitor canary, the claude-chat proxy, and any
/// browser-opened `/sub` check all appear as this IP, so without the
/// exclusion it dominates the per-user source-IP counter (it was 656 of
/// ninitux's 723 hits — 90% pure test noise). VPN SERVER addresses are
/// excluded separately via `(SELECT address FROM servers)` because a user
/// who hops node A→B briefly shows node A's egress as their source while
/// the old session drains. Extend this list if more control-plane egresses
/// appear; keep it NON-EMPTY (an empty `NOT IN ()` is a SQL error — the
/// query layer guards by omitting the clause when empty).
pub const OUR_EGRESS_CONTROL_IPS: &[&str] = &["83.97.108.34"];

/// SQL `WHERE`-fragment (NOT prefixed with `AND`) that keeps only REAL
/// external client IPs in column `col`, dropping every flavour of OUR OWN
/// infrastructure (2026-06-16, Pavel — «всё ещё вижу 192.168.0.200 LAN curl
/// … Likely-shared показывает те же цифры»):
///   - RFC 1918 / loopback / link-local — the homelab LAN (every box is
///     `192.168.0.x`; a real client never appears as a private IP because
///     nginx resolves the true client via `X-Forwarded-For`, so a private
///     `ip` row is always our own tooling hitting the daemon directly),
///   - VPN server addresses (`SELECT address FROM servers` — a node hop or
///     full-tunnel egress),
///   - the control egress(es) in [`OUR_EGRESS_CONTROL_IPS`].
///
/// Single source of truth so the abuse-origins list, the breakdowns, the
/// likely-shared summary, and the source-IP counter all agree on «what is a
/// real client». Mirrors the daemon's `ip_kind::classify_ip` logic in SQL.
/// Inlined literals are safe — every value is our own constant (servers via
/// sub-SELECT), never user input. `172.16-31/12` is matched with GLOB
/// char-ranges so a real `172.0-15` / `172.32+` client is NOT dropped.
fn real_client_ip_predicate(col: &str) -> String {
    let control_clause = if OUR_EGRESS_CONTROL_IPS.is_empty() {
        String::new()
    } else {
        let list = OUR_EGRESS_CONTROL_IPS
            .iter()
            .map(|ip| format!("'{ip}'"))
            .collect::<Vec<_>>()
            .join(",");
        format!(" AND {col} NOT IN ({list})")
    };
    format!(
        "{col} NOT LIKE '10.%' AND {col} NOT LIKE '127.%' \
         AND {col} NOT LIKE '192.168.%' AND {col} NOT LIKE '169.254.%' \
         AND {col} NOT GLOB '172.1[6-9].*' AND {col} NOT GLOB '172.2[0-9].*' \
         AND {col} NOT GLOB '172.3[0-1].*' \
         AND {col} NOT IN (SELECT address FROM servers){control_clause}"
    )
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
}

/// Traffic-accounting breakdown for one server over a window, produced
/// by [`SqliteInventory::server_traffic_breakdown`]. The GAP is the
/// headline: real NIC traffic minus what clash-api could attribute to
/// sing-box — i.e. non-sing-box protocols (naive/Caddy, dns-tunnel,
/// wgturn) plus protocol/OS overhead that vpnctl currently can't break
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

#[derive(Debug, Clone)]
pub struct SqliteInventory {
    pool: SqlitePool,
}

impl SqliteInventory {
    /// Internal-ish accessor for the underlying `SqlitePool`. Currently
    /// used by the `backup` module to run `VACUUM INTO` (which can't go
    /// through a typed query because the target path isn't bindable).
    /// `pub(crate)` keeps the door closed for external callers — pool
    /// is owned state, not API.
    pub(crate) fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Open (or create) DB at `path`, apply pragmas, run migrations.
    pub async fn open(path: &Path) -> Result<Self> {
        let opts = SqliteConnectOptions::from_str(path.to_str().ok_or_else(|| {
                SqliteInventoryError::Invalid(format!("non-utf8 path: {path:?}"))
            })?)?
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            // synchronous=NORMAL (vs the SQLite default of FULL): in WAL
            // mode NORMAL never fsyncs on every commit, only at checkpoint.
            // FULL was stalling unrelated writers (dns_ptr_cache, node_health,
            // admin_alerts, vpn_user_sessions) 1-5s under checkpoint pressure.
            // SQLite docs: NORMAL in WAL is durability-safe — it can never
            // corrupt the DB; the only window is losing the last few committed
            // transactions on a power loss / OS crash, which is acceptable for
            // this stats/inventory daemon. See sqlite.org WAL docs + forum
            // thread 9d6f13e.
            .pragma("synchronous", "NORMAL")
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(5));

        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(opts)
            .await?;

        MIGRATOR.run(&pool).await?;

        // Backfill: every user must have a non-null sub_token after open().
        // Migration 0002 adds the column nullable; we fill it here so the
        // rest of the code can rely on `User.sub_token` being Some.
        backfill_sub_tokens(&pool).await?;

        Ok(Self { pool })
    }

    /// Force-close all pooled connections. Useful in tests.
    pub async fn close(self) {
        self.pool.close().await;
    }

    // ── Servers ─────────────────────────────────────────────────────────

    pub async fn add_server(&self, s: &Server) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let res = sqlx::query(
            "INSERT INTO servers (id, address, ssh_port, ssh_user, hoster, jump_via, trusted_host_fingerprint, usage_coefficient)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )
        .bind(&s.id.0)
        .bind(&s.address)
        .bind(i64::from(s.ssh_port))
        .bind(&s.ssh_user)
        .bind(&s.hoster)
        .bind(s.jump_via.as_ref().map(|v| v.0.clone()))
        .bind(&s.trusted_host_fingerprint)
        .bind(s.usage_coefficient)
        .execute(&mut *tx)
        .await;
        map_unique(res, format!("server {}", s.id.0))?;

        for kid in &s.kernels {
            sqlx::query("INSERT INTO server_kernels (server_id, kernel_id) VALUES (?1, ?2)")
                .bind(&s.id.0)
                .bind(&kid.0)
                .execute(&mut *tx)
                .await?;
        }

        for proto in &s.enabled_protocols {
            sqlx::query("INSERT INTO server_protocols (server_id, protocol_id) VALUES (?1, ?2)")
                .bind(&s.id.0)
                .bind(&proto.0)
                .execute(&mut *tx)
                .await?;
        }

        // Phase 4a (migration 0021) — when a server is added AFTER
        // the migration has run, any pre-existing sub_access_log
        // rows that happened to come from this server's IP (e.g.
        // logged before vpnctld knew this was an egress) need to
        // be flagged retroactively. Skipped if the server has no
        // address at all (defensive — Server.address is required
        // by the schema so this never happens in practice).
        if !s.address.is_empty() {
            sqlx::query(
                "UPDATE sub_access_log SET is_vpn_egress = 1
                 WHERE ip = ?1 AND is_vpn_egress = 0",
            )
            .bind(&s.address)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    pub async fn get_server(&self, id: &ServerId) -> Result<Option<Server>> {
        let row_opt = sqlx::query(
            "SELECT id, address, ssh_port, ssh_user, hoster, jump_via, trusted_host_fingerprint, usage_coefficient
             FROM servers WHERE id = ?1",
        )
        .bind(&id.0)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row_opt else { return Ok(None) };

        let server_id: String = row.try_get("id")?;
        let protocols = self
            .list_server_protocols(&ServerId(server_id.clone()))
            .await?;
        let kernels = self
            .list_server_kernels(&ServerId(server_id.clone()))
            .await?;
        let s = Server {
            id: ServerId(server_id),
            address: row.try_get("address")?,
            ssh_port: u16::try_from(row.try_get::<i64, _>("ssh_port")?)
                .map_err(|_| SqliteInventoryError::Invalid("ssh_port out of u16 range".into()))?,
            ssh_user: row.try_get("ssh_user")?,
            kernels,
            enabled_protocols: protocols,
            trusted_host_fingerprint: row.try_get("trusted_host_fingerprint")?,
            hoster: row.try_get("hoster")?,
            jump_via: row.try_get::<Option<String>, _>("jump_via")?.map(ServerId),
            usage_coefficient: row.try_get("usage_coefficient")?,
        };
        Ok(Some(s))
    }

    pub async fn list_servers(&self) -> Result<Vec<Server>> {
        // NOTE(perf): N+1 query — one SELECT id, then per-server get_server
        // (which itself does 2 queries). For a homelab with <100 servers
        // this is fine; if it ever matters, switch to a single LEFT JOIN
        // and aggregate protocols in Rust.
        let rows = sqlx::query("SELECT id FROM servers ORDER BY id")
            .fetch_all(&self.pool)
            .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let id: String = r.try_get("id")?;
            if let Some(s) = self.get_server(&ServerId(id)).await? {
                out.push(s);
            }
        }
        Ok(out)
    }

    pub async fn remove_server(&self, id: &ServerId) -> Result<()> {
        sqlx::query("DELETE FROM servers WHERE id = ?1")
            .bind(&id.0)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// `true` if `addr` exactly matches a registered server's `address`.
    /// Used by the subscription rate-limiter to EXEMPT our own VPN-egress
    /// IPs: a client connected through a node has its config-refresh
    /// egress that node, so vpnctld sees the SERVER's IP. Without this
    /// exemption, N users on one server collapse into a single per-IP
    /// bucket and throttle each other (Pavel 2026-06-01: "может
    /// одновременно прийти 33 обновления если все будут на одном
    /// конфиге"). Cheap — the servers table is a handful of rows. Same
    /// membership the `sub_access_log.is_vpn_egress` trigger computes.
    pub async fn is_known_server_address(&self, addr: &str) -> Result<bool> {
        let row: (i64,) = sqlx::query_as("SELECT EXISTS(SELECT 1 FROM servers WHERE address = ?1)")
            .bind(addr)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.0 != 0)
    }

    /// Auto-suppress state for a server (migration 0030): the per-server
    /// opt-in + the current runtime `suppressed_at` timestamp. Returns
    /// `(opt_in, suppressed_at)`; `(false, None)` for an unknown id.
    pub async fn server_auto_suppress_state(
        &self,
        sid: &ServerId,
    ) -> Result<(bool, Option<String>)> {
        let row: Option<(i64, Option<String>)> = sqlx::query_as(
            "SELECT auto_suppress_when_unreachable, suppressed_at FROM servers WHERE id = ?1",
        )
        .bind(&sid.0)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(o, s)| (o != 0, s)).unwrap_or((false, None)))
    }

    /// Subscription-render gate: `true` iff this server should be hidden
    /// from subscriptions RIGHT NOW — opt-in ON **and** currently flagged
    /// suppressed. Checked per-server in the `/sub` + `/api/v1/app/config`
    /// render loops, on TOP of the per-protocol visibility filter.
    pub async fn is_server_auto_suppressed(&self, sid: &ServerId) -> Result<bool> {
        let (opt_in, suppressed_at) = self.server_auto_suppress_state(sid).await?;
        Ok(opt_in && suppressed_at.is_some())
    }

    /// Set the per-server auto-suppress OPT-IN. Turning it OFF also
    /// clears any live `suppressed_at` (the server returns to the
    /// subscription immediately — the operator overrode the automation).
    /// Audit-on-actual-change (`server.auto_suppress.set`); `Invalid` on
    /// unknown id.
    pub async fn set_server_auto_suppress(&self, sid: &ServerId, enabled: bool) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let prior: Option<(i64, Option<String>)> = sqlx::query_as(
            "SELECT auto_suppress_when_unreachable, suppressed_at FROM servers WHERE id = ?1",
        )
        .bind(&sid.0)
        .fetch_optional(&mut *tx)
        .await?;
        let (prior_opt, prior_suppressed) = match prior {
            Some((o, s)) => (o != 0, s),
            None => {
                return Err(SqliteInventoryError::Invalid(format!(
                    "no such server '{}'; cannot set auto_suppress",
                    sid.0
                )));
            }
        };
        // Turning the opt-in off also lifts an active suppression.
        let new_suppressed: Option<String> = if enabled {
            prior_suppressed.clone()
        } else {
            None
        };
        if prior_opt == enabled && prior_suppressed == new_suppressed {
            tx.commit().await?;
            return Ok(());
        }
        sqlx::query(
            "UPDATE servers SET auto_suppress_when_unreachable = ?1, suppressed_at = ?2 WHERE id = ?3",
        )
        .bind(i64::from(enabled))
        .bind(&new_suppressed)
        .bind(&sid.0)
        .execute(&mut *tx)
        .await?;
        let payload = serde_json::json!({
            "server_id": sid.0,
            "enabled": enabled,
            "cleared_active_suppression": prior_suppressed.is_some() && new_suppressed.is_none(),
        });
        sqlx::query(
            "INSERT INTO audit_log (actor, action, target, payload) VALUES (?1, ?2, ?3, ?4)",
        )
        .bind("admin")
        .bind("server.auto_suppress.set")
        .bind(&sid.0)
        .bind(serde_json::to_string(&payload)?)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Subscription-render flag (migration 0031, UX-3): `true` iff the
    /// operator enabled naive↔HY2 UDP pairing on this server. When ON **and**
    /// the server exposes BOTH naive and hysteria2, the `/api/v1/app/config`
    /// render stamps both share-links with a shared `pair=<server id>` so a
    /// client can route UDP — which naive can't carry — over the co-located
    /// HY2. Default false; no such server → false.
    pub async fn is_server_udp_pair_enabled(&self, sid: &ServerId) -> Result<bool> {
        let row: Option<(i64,)> =
            sqlx::query_as("SELECT udp_pair_enabled FROM servers WHERE id = ?1")
                .bind(&sid.0)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|(v,)| v != 0).unwrap_or(false))
    }

    /// Set the per-server naive↔HY2 UDP-pairing opt-in (migration 0031).
    /// Pure boolean — no side effects. Audit-on-actual-change
    /// (`server.udp_pair.set`); `Invalid` on unknown id.
    pub async fn set_server_udp_pair_enabled(&self, sid: &ServerId, enabled: bool) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let prior: Option<(i64,)> =
            sqlx::query_as("SELECT udp_pair_enabled FROM servers WHERE id = ?1")
                .bind(&sid.0)
                .fetch_optional(&mut *tx)
                .await?;
        let prior_enabled = match prior {
            Some((o,)) => o != 0,
            None => {
                return Err(SqliteInventoryError::Invalid(format!(
                    "no such server '{}'; cannot set udp_pair_enabled",
                    sid.0
                )));
            }
        };
        if prior_enabled == enabled {
            tx.commit().await?;
            return Ok(());
        }
        sqlx::query("UPDATE servers SET udp_pair_enabled = ?1 WHERE id = ?2")
            .bind(i64::from(enabled))
            .bind(&sid.0)
            .execute(&mut *tx)
            .await?;
        let payload = serde_json::json!({ "server_id": sid.0, "enabled": enabled });
        sqlx::query(
            "INSERT INTO audit_log (actor, action, target, payload) VALUES (?1, ?2, ?3, ?4)",
        )
        .bind("admin")
        .bind("server.udp_pair.set")
        .bind(&sid.0)
        .bind(serde_json::to_string(&payload)?)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Monitor-driven: set or clear the runtime `suppressed_at` flag.
    /// Idempotent — only writes (and audits) on an actual transition;
    /// returns `true` when it changed. Audits `server.auto_suppressed`
    /// (set) or `server.auto_restored` (clear). The CALLER gates on the
    /// opt-in before setting; clearing is always honoured (so a recovery
    /// lifts suppression even if the opt-in was toggled off meanwhile).
    /// `Invalid` on unknown id.
    pub async fn set_server_suppressed(&self, sid: &ServerId, suppressed: bool) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        let prior: Option<(Option<String>,)> =
            sqlx::query_as("SELECT suppressed_at FROM servers WHERE id = ?1")
                .bind(&sid.0)
                .fetch_optional(&mut *tx)
                .await?;
        let prior_suppressed = match prior {
            Some((s,)) => s.is_some(),
            None => {
                return Err(SqliteInventoryError::Invalid(format!(
                    "no such server '{}'; cannot set suppressed_at",
                    sid.0
                )));
            }
        };
        if prior_suppressed == suppressed {
            tx.commit().await?;
            return Ok(false);
        }
        // Timestamp generated SQL-side to match the rest of the schema's
        // `strftime` ISO-8601-millis format.
        sqlx::query(
            "UPDATE servers SET suppressed_at = CASE WHEN ?1 = 1 \
                 THEN strftime('%Y-%m-%dT%H:%M:%fZ','now') ELSE NULL END \
             WHERE id = ?2",
        )
        .bind(i64::from(suppressed))
        .bind(&sid.0)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO audit_log (actor, action, target, payload) VALUES (?1, ?2, ?3, ?4)",
        )
        .bind("vpnctld")
        .bind(if suppressed {
            "server.auto_suppressed"
        } else {
            "server.auto_restored"
        })
        .bind(&sid.0)
        .bind(serde_json::json!({ "server_id": sid.0 }).to_string())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Replace a server's `address` + `ssh_port` + `ssh_user` in
    /// place. Used by the `--overwrite-existing` path of
    /// `vpnctl migrate from-bash` when an operator's earlier
    /// wizard-test created a server row with a stale IP that the
    /// migration needs to correct. Does NOT touch kernels,
    /// protocols, or secrets (those have their own setters); the
    /// scope is intentionally narrow so an accidental call can't
    /// nuke unrelated state.
    pub async fn update_server_address(
        &self,
        id: &ServerId,
        address: &str,
        ssh_port: u16,
        ssh_user: &str,
    ) -> Result<()> {
        if address.is_empty() {
            return Err(SqliteInventoryError::Invalid(
                "address must not be empty".into(),
            ));
        }
        sqlx::query(
            "UPDATE servers SET address = ?1, ssh_port = ?2, ssh_user = ?3,
                                 updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE id = ?4",
        )
        .bind(address)
        .bind(i64::from(ssh_port))
        .bind(ssh_user)
        .bind(&id.0)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn update_trusted_fingerprint(&self, id: &ServerId, fp: &str) -> Result<()> {
        // Defensive validation — a malicious or buggy caller could otherwise
        // store an empty / arbitrary value, after which every future connect
        // silently rejects the real host key with a useless error.
        //
        // Shape check lives in `vpnctl-host-fingerprint` so the CLI, web
        // handler, wizard SSE pipeline, and this final inventory gate all
        // agree on what "valid" means (until 2026-05-18 they did not —
        // the inventory variant rejected URL-safe base64 that the surface
        // validators accepted, producing a confusing late failure).
        if !vpnctl_host_fingerprint::validate_shape(fp) {
            return Err(SqliteInventoryError::Invalid(format!(
                "fingerprint must look like 'SHA256:<base64-43>', got {fp:?}"
            )));
        }
        sqlx::query(
            "UPDATE servers SET trusted_host_fingerprint = ?1,
                                 updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE id = ?2",
        )
        .bind(fp)
        .bind(&id.0)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// All kernels this server runs, sorted alphabetically for stable
    /// rendering. Empty Vec is legal in the DB but `validate_server`
    /// rejects it before deploy — see `Registry::validate_server`.
    pub async fn list_server_kernels(&self, id: &ServerId) -> Result<Vec<KernelId>> {
        let rows = sqlx::query(
            "SELECT kernel_id FROM server_kernels WHERE server_id = ?1 ORDER BY kernel_id",
        )
        .bind(&id.0)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| r.try_get::<String, _>("kernel_id").map(KernelId))
            .collect::<std::result::Result<_, _>>()?)
    }

    /// Add a single kernel to a server's runtime set. Idempotent (`ON
    /// CONFLICT DO NOTHING`). Mirrors `add_server_protocol`.
    /// FK constraint on `server_id` surfaces as `Invalid` for unknown
    /// server; kernel id is opaque to the DB (registry validation
    /// happens at deploy time).
    pub async fn add_server_kernel(&self, server: &ServerId, kernel: &KernelId) -> Result<u64> {
        let res = sqlx::query(
            "INSERT INTO server_kernels (server_id, kernel_id) VALUES (?1, ?2)
             ON CONFLICT(server_id, kernel_id) DO NOTHING",
        )
        .bind(&server.0)
        .bind(&kernel.0)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    /// Remove a kernel from a server. Idempotent. Mirrors
    /// `remove_server_protocol`.
    pub async fn remove_server_kernel(&self, server: &ServerId, kernel: &KernelId) -> Result<u64> {
        let res = sqlx::query("DELETE FROM server_kernels WHERE server_id = ?1 AND kernel_id = ?2")
            .bind(&server.0)
            .bind(&kernel.0)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected())
    }

    /// Add a single protocol to a server's `enabled_protocols`.
    /// Idempotent at the SQL layer (`OR IGNORE` on the PK pair) — calling
    /// twice with the same `(server, protocol)` is silent success.
    /// Returns the row-was-actually-inserted count so the caller can
    /// distinguish "already there" from "just added" if it wants to
    /// audit only effective changes (currently web handler audits both).
    /// FK constraint on `server_id` will surface as `Invalid` if the
    /// server doesn't exist; protocol id is opaque to the DB layer
    /// (registry validation happens at deploy time).
    pub async fn add_server_protocol(
        &self,
        server: &ServerId,
        protocol: &ProtocolId,
    ) -> Result<u64> {
        let res = sqlx::query(
            "INSERT INTO server_protocols (server_id, protocol_id) VALUES (?1, ?2)
             ON CONFLICT(server_id, protocol_id) DO NOTHING",
        )
        .bind(&server.0)
        .bind(&protocol.0)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    /// Remove a protocol from a server's `enabled_protocols`. Idempotent:
    /// removing a not-present (server, protocol) is silent success.
    /// Returns the row-was-actually-deleted count for the same audit
    /// reason as `add_server_protocol`.
    pub async fn remove_server_protocol(
        &self,
        server: &ServerId,
        protocol: &ProtocolId,
    ) -> Result<u64> {
        let res =
            sqlx::query("DELETE FROM server_protocols WHERE server_id = ?1 AND protocol_id = ?2")
                .bind(&server.0)
                .bind(&protocol.0)
                .execute(&self.pool)
                .await?;
        Ok(res.rows_affected())
    }

    async fn list_server_protocols(&self, id: &ServerId) -> Result<Vec<ProtocolId>> {
        let rows = sqlx::query(
            "SELECT protocol_id FROM server_protocols WHERE server_id = ?1 ORDER BY protocol_id",
        )
        .bind(&id.0)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|r| Ok(ProtocolId(r.try_get::<String, _>("protocol_id")?)))
            .collect()
    }

    // ── Per-(server, protocol) visibility (migration 0018) ───────────
    //
    // The `hidden` flag suppresses a protocol from EVERY rendered
    // subscription URL (sub.rs + vpn_router.rs filters) while keeping
    // the inbound running on the live node — clients with cached URIs
    // keep working until they re-pull. The render path checks via
    // `visible_protocols_for_subscription` (compound query that joins
    // server_protocols × grant_protocol_overrides); this method is the
    // raw read used by the admin UI's `/admin/servers/<id>` toggles.

    /// Is the (server, protocol) pair flagged `hidden=1`?
    /// `false` if the row exists with `hidden=0` OR if the row is
    /// absent (protocol not enabled on the server at all — nothing
    /// to hide). Use `list_server_protocols` first if you need to
    /// distinguish "not enabled" from "enabled but visible".
    pub async fn is_server_protocol_hidden(
        &self,
        sid: &ServerId,
        pid: &ProtocolId,
    ) -> Result<bool> {
        let row = sqlx::query(
            "SELECT hidden FROM server_protocols WHERE server_id = ?1 AND protocol_id = ?2",
        )
        .bind(&sid.0)
        .bind(&pid.0)
        .fetch_optional(&self.pool)
        .await?;
        // Propagate sqlx Decode errors via `?` — review-agent
        // 2026-05-20 flagged that `.unwrap_or(0)` would silently
        // return `false` (visible) on a broken column type, fail-
        // OPEN on a security-relevant flag.
        match row {
            Some(r) => {
                let h: i64 = r.try_get("hidden")?;
                Ok(h != 0)
            }
            None => Ok(false),
        }
    }

    /// Toggle the `hidden` flag on an existing (server, protocol) row.
    /// Refuses if the row doesn't exist (operator must `add_protocol`
    /// first — hide is a render-suppression, not a protocol enablement).
    /// Writes an audit row inside the same transaction (mirrors the
    /// `set_grant_client_uuid` write-+-audit invariant from CLAUDE.md).
    pub async fn set_server_protocol_hidden(
        &self,
        sid: &ServerId,
        pid: &ProtocolId,
        hidden: bool,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;

        // Read the old value first — needed for the audit payload AND
        // for the "no such row" check.
        let prior = sqlx::query(
            "SELECT hidden FROM server_protocols WHERE server_id = ?1 AND protocol_id = ?2",
        )
        .bind(&sid.0)
        .bind(&pid.0)
        .fetch_optional(&mut *tx)
        .await?;
        let prior_hidden: bool = match prior {
            Some(row) => row.try_get::<i64, _>("hidden")? != 0,
            None => {
                return Err(SqliteInventoryError::Invalid(format!(
                    "no such server_protocols row ({}, {}); enable the protocol first via add_protocol",
                    sid.0, pid.0
                )));
            }
        };

        // No-op short-circuit (review-agent 2026-05-20): if the flag
        // is already at the target value, don't UPDATE and don't
        // pollute audit_log. "One audit row per mutation" invariant
        // means non-mutations write zero rows. Idempotent re-clicks
        // from the UI become silent.
        if prior_hidden == hidden {
            tx.commit().await?;
            return Ok(());
        }

        let new_hidden = i64::from(hidden);
        sqlx::query(
            "UPDATE server_protocols SET hidden = ?1 WHERE server_id = ?2 AND protocol_id = ?3",
        )
        .bind(new_hidden)
        .bind(&sid.0)
        .bind(&pid.0)
        .execute(&mut *tx)
        .await?;

        let payload = serde_json::json!({
            "server_id": sid.0,
            "protocol_id": pid.0,
            "old_hidden": prior_hidden,
            "new_hidden": hidden,
        });
        let payload_str = serde_json::to_string(&payload)?;
        sqlx::query(
            "INSERT INTO audit_log (actor, action, target, payload)
             VALUES (?1, ?2, ?3, ?4)",
        )
        .bind("admin")
        .bind("server.protocol.set_hidden")
        .bind(&sid.0)
        .bind(payload_str)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Read the per-server reserved-ports list (migration 0028).
    /// Returns an empty Vec for servers that haven't had any ports
    /// reserved — most installs are byte-equivalent to pre-0028
    /// behaviour. Returns `Ok(vec![])` if the server doesn't exist
    /// (caller already passed an unknown id — no need to double-
    /// report; the deploy path will fail later with a useful
    /// «unknown server» error).
    ///
    /// Stored as a JSON array of u16. Parse failures (corrupted DB)
    /// degrade to empty — fail-OPEN on read because a wrong empty is
    /// safer than crash-looping the deploy path; the write side
    /// (`set_reserved_ports`) is the authoritative validator.
    pub async fn get_reserved_ports(&self, sid: &ServerId) -> Result<Vec<u16>> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT reserved_ports FROM servers WHERE id = ?1")
                .bind(&sid.0)
                .fetch_optional(&self.pool)
                .await?;
        let json = match row {
            Some((s,)) => s,
            None => return Ok(Vec::new()),
        };
        // Lenient parse — operator could have hand-edited the row in
        // sqlite3, or a future schema migration could change shape.
        // Either way, the deploy guard fails open on parse error.
        let parsed: Vec<u16> = serde_json::from_str(&json).unwrap_or_default();
        Ok(parsed)
    }

    /// Replace the per-server reserved-ports list. `ports` is
    /// caller-validated to fit u16 (the parsing layer in admin /
    /// CLI rejects values outside 1..=65535 before calling). The
    /// stored format is a JSON array; duplicates are de-duped and
    /// the array is sorted ascending so `audit_log` payloads diff
    /// cleanly across calls.
    ///
    /// Writes one `server.reserved_ports.set` audit row whenever the
    /// stored value would change (NM-10 audit-on-actual-mutation
    /// contract). Idempotent re-saves of the same list are silent.
    /// Errors with `Invalid` if `sid` doesn't exist (matches the
    /// behaviour of `set_server_fingerprint` — caller passing an
    /// unknown id is a logic bug, not an expected condition).
    pub async fn set_reserved_ports(&self, sid: &ServerId, ports: &[u16]) -> Result<()> {
        let mut sorted: Vec<u16> = ports.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        let new_json = serde_json::to_string(&sorted)?;

        let mut tx = self.pool.begin().await?;

        let prior: Option<(String,)> =
            sqlx::query_as("SELECT reserved_ports FROM servers WHERE id = ?1")
                .bind(&sid.0)
                .fetch_optional(&mut *tx)
                .await?;
        let prior_json = match prior {
            Some((s,)) => s,
            None => {
                return Err(SqliteInventoryError::Invalid(format!(
                    "no such server '{}'; cannot set reserved_ports",
                    sid.0
                )));
            }
        };

        if prior_json == new_json {
            tx.commit().await?;
            return Ok(());
        }

        sqlx::query("UPDATE servers SET reserved_ports = ?1 WHERE id = ?2")
            .bind(&new_json)
            .bind(&sid.0)
            .execute(&mut *tx)
            .await?;

        // Audit payload carries both old + new sorted lists so
        // operator can diff at a glance from the audit timeline.
        let payload = serde_json::json!({
            "server_id": sid.0,
            "old": serde_json::from_str::<serde_json::Value>(&prior_json).unwrap_or(serde_json::json!([])),
            "new": sorted,
        });
        let payload_str = serde_json::to_string(&payload)?;
        sqlx::query(
            "INSERT INTO audit_log (actor, action, target, payload)
             VALUES (?1, ?2, ?3, ?4)",
        )
        .bind("admin")
        .bind("server.reserved_ports.set")
        .bind(&sid.0)
        .bind(payload_str)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Operator-set display name for a server — the `{Country}` part of
    /// the subscription URI fragment / sing-box outbound tag. `None`
    /// when unset (column NULL or blank), in which case the render falls
    /// back to `vpn_router::country_display_name(id)`. Blank/whitespace
    /// stored values are normalised to `None` here so a caller never has
    /// to second-guess them.
    pub async fn server_display_name(&self, sid: &ServerId) -> Result<Option<String>> {
        let row: Option<(Option<String>,)> =
            sqlx::query_as("SELECT display_name FROM servers WHERE id = ?1")
                .bind(&sid.0)
                .fetch_optional(&self.pool)
                .await?;
        // Outer None = no such server; inner None = NULL column. Both → None.
        Ok(row.and_then(|(v,)| v).filter(|s| !s.trim().is_empty()))
    }

    /// Set (or clear, when `name` trims to empty / is `None`) a server's
    /// display name. Audit-on-actual-mutation: writes exactly one
    /// `server.display_name.set` row, and only when the stored value
    /// actually changes (idempotent re-saves are silent). Errors
    /// `Invalid` if the server doesn't exist (matches `set_reserved_ports`
    /// — an unknown id is a caller logic bug, not an expected state).
    pub async fn set_server_display_name(&self, sid: &ServerId, name: Option<&str>) -> Result<()> {
        // Normalise: trim; blank → NULL (clear the override).
        let new_val: Option<String> = name
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        let mut tx = self.pool.begin().await?;

        let prior: Option<(Option<String>,)> =
            sqlx::query_as("SELECT display_name FROM servers WHERE id = ?1")
                .bind(&sid.0)
                .fetch_optional(&mut *tx)
                .await?;
        let prior_val = match prior {
            Some((v,)) => v.filter(|s| !s.trim().is_empty()),
            None => {
                return Err(SqliteInventoryError::Invalid(format!(
                    "no such server '{}'; cannot set display_name",
                    sid.0
                )));
            }
        };

        if prior_val == new_val {
            tx.commit().await?;
            return Ok(());
        }

        sqlx::query("UPDATE servers SET display_name = ?1 WHERE id = ?2")
            .bind(&new_val)
            .bind(&sid.0)
            .execute(&mut *tx)
            .await?;

        let payload = serde_json::json!({
            "server_id": sid.0,
            "old": prior_val,
            "new": new_val,
        });
        let payload_str = serde_json::to_string(&payload)?;
        sqlx::query(
            "INSERT INTO audit_log (actor, action, target, payload)
             VALUES (?1, ?2, ?3, ?4)",
        )
        .bind("admin")
        .bind("server.display_name.set")
        .bind(&sid.0)
        .bind(payload_str)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Set or clear the per-(user, server, protocol) deny override.
    /// `disabled = true` inserts (or no-ops if already disabled).
    /// `disabled = false` deletes the override row (back to inherit-
    /// from-server). FK-fails (returns Invalid) if no grant exists for
    /// (user, server) — operator must grant first via `grant()`. Writes
    /// audit `grant.protocol.set_override`.
    pub async fn set_grant_protocol_override(
        &self,
        uid: &UserId,
        sid: &ServerId,
        pid: &ProtocolId,
        disabled: bool,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;

        // FK precheck — composite FK to grants(user_id, server_id).
        // Without this the INSERT fails with raw `Sqlx(Database(...))`
        // which is harder to handle on the caller side.
        let grant_exists =
            sqlx::query("SELECT 1 FROM grants WHERE user_id = ?1 AND server_id = ?2")
                .bind(&uid.0)
                .bind(&sid.0)
                .fetch_optional(&mut *tx)
                .await?
                .is_some();
        if !grant_exists {
            return Err(SqliteInventoryError::Invalid(format!(
                "no grant for ({}, {}); cannot set per-protocol override without an existing grant",
                uid.0, sid.0
            )));
        }

        // Capture rows_affected so we only write audit on actual
        // mutation (review-agent 2026-05-20 "audit-per-mutation"
        // invariant: re-clicking a disable button must NOT spam
        // the audit_log with no-op rows).
        let rows_affected = if disabled {
            sqlx::query(
                "INSERT INTO grant_protocol_overrides (user_id, server_id, protocol_id, state)
                 VALUES (?1, ?2, ?3, 'disabled')
                 ON CONFLICT(user_id, server_id, protocol_id) DO NOTHING",
            )
            .bind(&uid.0)
            .bind(&sid.0)
            .bind(&pid.0)
            .execute(&mut *tx)
            .await?
            .rows_affected()
        } else {
            sqlx::query(
                "DELETE FROM grant_protocol_overrides WHERE user_id = ?1 AND server_id = ?2 AND protocol_id = ?3",
            )
            .bind(&uid.0)
            .bind(&sid.0)
            .bind(&pid.0)
            .execute(&mut *tx)
            .await?
            .rows_affected()
        };

        if rows_affected == 0 {
            tx.commit().await?;
            return Ok(());
        }

        let payload = serde_json::json!({
            "user_id": uid.0,
            "server_id": sid.0,
            "protocol_id": pid.0,
            "disabled": disabled,
        });
        let payload_str = serde_json::to_string(&payload)?;
        sqlx::query(
            "INSERT INTO audit_log (actor, action, target, payload)
             VALUES (?1, ?2, ?3, ?4)",
        )
        .bind("admin")
        .bind("grant.protocol.set_override")
        .bind(&uid.0)
        .bind(payload_str)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Resolve the protocol set a user's subscription URL should
    /// expose for a given server. Combines both axes of the
    /// visibility model:
    ///
    ///   1. `server_protocols.hidden=1` → excluded
    ///   2. `grant_protocol_overrides.state='disabled'` → excluded
    ///   3. otherwise (row exists in `server_protocols` with
    ///      `hidden=0`, no override) → included
    ///
    /// Order: alphabetical by `protocol_id` for deterministic
    /// rendering (so a re-render with no schema change produces
    /// byte-identical output).
    pub async fn visible_protocols_for_subscription(
        &self,
        uid: &UserId,
        sid: &ServerId,
    ) -> Result<Vec<ProtocolId>> {
        let rows = sqlx::query(
            "SELECT sp.protocol_id
             FROM server_protocols sp
             WHERE sp.server_id = ?2
               AND sp.hidden = 0
               AND NOT EXISTS (
                   SELECT 1 FROM grant_protocol_overrides gpo
                   WHERE gpo.user_id = ?1
                     AND gpo.server_id = sp.server_id
                     AND gpo.protocol_id = sp.protocol_id
                     AND gpo.state = 'disabled'
               )
             ORDER BY sp.protocol_id",
        )
        .bind(&uid.0)
        .bind(&sid.0)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|r| Ok(ProtocolId(r.try_get::<String, _>("protocol_id")?)))
            .collect()
    }

    /// Bulk-fetch every enabled (server, protocol) row with its
    /// `hidden` flag for a given server. Useful for admin UI rendering
    /// without N+1 calls into `is_server_protocol_hidden`. Returns an
    /// empty map if the server has no enabled protocols.
    pub async fn list_server_protocols_with_hidden(
        &self,
        sid: &ServerId,
    ) -> Result<HashMap<ProtocolId, bool>> {
        let rows =
            sqlx::query("SELECT protocol_id, hidden FROM server_protocols WHERE server_id = ?1")
                .bind(&sid.0)
                .fetch_all(&self.pool)
                .await?;
        let mut out = HashMap::with_capacity(rows.len());
        for r in rows {
            let pid: String = r.try_get("protocol_id")?;
            let hidden: i64 = r.try_get("hidden")?;
            out.insert(ProtocolId(pid), hidden != 0);
        }
        Ok(out)
    }

    /// All-servers variant of `list_server_protocols_with_hidden` —
    /// one round-trip returns the full `(server, protocol) → hidden`
    /// matrix. Used by the `/admin/servers` list page so the server
    /// cards can render an accurate "visible vs hidden" breakdown
    /// without N queries (the per-server bulk helper would N+1 over
    /// the inventory). Empty map for servers that have no
    /// `server_protocols` rows yet — caller should fall back to a
    /// dash in that case.
    ///
    /// (Pavel 2026-05-20: «нужно сделаить на /admin/servers чтоб
    /// это отобразилось, сейчас показано что там все протоколы,
    /// хотя я сделал hide» — the list page was rendering from
    /// `Server.enabled_protocols` (in-memory cache, which doesn't
    /// know about hidden) instead of from this table, so post-hide
    /// state never reached the operator's eye.)
    pub async fn list_all_server_protocols_with_hidden(
        &self,
    ) -> Result<HashMap<(ServerId, ProtocolId), bool>> {
        let rows = sqlx::query("SELECT server_id, protocol_id, hidden FROM server_protocols")
            .fetch_all(&self.pool)
            .await?;
        let mut out = HashMap::with_capacity(rows.len());
        for r in rows {
            let sid: String = r.try_get("server_id")?;
            let pid: String = r.try_get("protocol_id")?;
            let hidden: i64 = r.try_get("hidden")?;
            out.insert((ServerId(sid), ProtocolId(pid)), hidden != 0);
        }
        Ok(out)
    }

    /// Map of (server_id, protocol_id) → `true` for every disabled
    /// override the user has set. Useful for rendering the admin UI
    /// checkboxes pre-populated. Empty map = no overrides = inherit
    /// every server's visibility verbatim.
    pub async fn list_protocol_overrides_for_user(
        &self,
        uid: &UserId,
    ) -> Result<std::collections::HashMap<(ServerId, ProtocolId), bool>> {
        let rows = sqlx::query(
            "SELECT server_id, protocol_id, state
             FROM grant_protocol_overrides
             WHERE user_id = ?1",
        )
        .bind(&uid.0)
        .fetch_all(&self.pool)
        .await?;
        let mut out = std::collections::HashMap::new();
        for r in rows {
            let sid: String = r.try_get("server_id")?;
            let pid: String = r.try_get("protocol_id")?;
            let state: String = r.try_get("state")?;
            // Only 'disabled' is valid today per the CHECK constraint;
            // future 'force-enabled' would flip the bool.
            out.insert((ServerId(sid), ProtocolId(pid)), state == "disabled");
        }
        Ok(out)
    }

    // ── Server secrets ──────────────────────────────────────────────────

    pub async fn set_server_secret(&self, id: &ServerId, key: &str, value: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO server_secrets (server_id, key, value) VALUES (?1, ?2, ?3)
             ON CONFLICT(server_id, key) DO UPDATE SET value = excluded.value",
        )
        .bind(&id.0)
        .bind(key)
        .bind(value)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_server_secret(&self, id: &ServerId, key: &str) -> Result<Option<String>> {
        let row = sqlx::query("SELECT value FROM server_secrets WHERE server_id = ?1 AND key = ?2")
            .bind(&id.0)
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|r| r.try_get::<String, _>("value"))
            .transpose()
            .map_err(Into::into)
    }

    pub async fn list_server_secrets(&self, id: &ServerId) -> Result<HashMap<String, String>> {
        let rows = sqlx::query("SELECT key, value FROM server_secrets WHERE server_id = ?1")
            .bind(&id.0)
            .fetch_all(&self.pool)
            .await?;
        let mut map = HashMap::with_capacity(rows.len());
        for r in rows {
            map.insert(r.try_get("key")?, r.try_get("value")?);
        }
        Ok(map)
    }

    // ── Users ───────────────────────────────────────────────────────────

    pub async fn add_user(&self, u: &User) -> Result<()> {
        // Ensure every user gets a sub_token. Caller may pre-set one (e.g.
        // when restoring from a snapshot); we generate only if absent.
        let token = match u.sub_token.as_deref() {
            Some(t) if !t.is_empty() => t.to_string(),
            _ => vpnctl_crypto::gen_sub_token().map_err(SqliteInventoryError::CryptoIo)?,
        };
        // Migration 0026 — honour the caller's `disabled` field on
        // INSERT. Default in the schema is 0, but callers may want
        // to import a pre-disabled user (snapshot restore, future
        // bulk-disable workflow). i64 mirror of the bool.
        let disabled_i: i64 = if u.disabled { 1 } else { 0 };
        // 2026-05-23 quickfix — also honour `vpn_router_device_id`
        // on INSERT (was getting silently dropped, leaving every
        // web-created user with NULL device_id → no production
        // ninitux URL on user-detail). NULL is still valid for
        // legacy imports that haven't been mapped to a device_id.
        let res = sqlx::query(
            "INSERT INTO users (id, uuid, tuic_password, wireguard_pubkey, wireguard_private, sub_token, vpn_router_device_id, disabled)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )
        .bind(&u.id.0)
        .bind(&u.uuid)
        .bind(&u.tuic_password)
        .bind(&u.wireguard_pubkey)
        .bind(&u.wireguard_private)
        .bind(&token)
        .bind(u.vpn_router_device_id.as_deref())
        .bind(disabled_i)
        .execute(&self.pool)
        .await;
        map_unique(res, format!("user {}", u.id.0))?;
        Ok(())
    }

    /// Look up a user by their subscription token. Constant-time'ish at the
    /// SQL layer (sqlite scans the unique index), but the caller is the
    /// public daemon — see also `vpnctld` rate-limit middleware.
    ///
    /// **Side-channel posture (review-agent #5, security-review #3,
    /// 2026-05-14):** SQLite's index walk + the Rust `String` comparison
    /// inside `bind` are not constant-time. With ~256 bits of entropy
    /// in `sub_token` (43 chars URL-safe base64 = 252 bits) brute force
    /// is infeasible regardless. Timing-based prefix discovery would
    /// matter ONLY if the daemon were exposed externally with no
    /// rate-limit. The deployment is LAN-only today, and Phase Track-2
    /// (per-token rate limit + auto-deny on burst) MUST land before any
    /// external exposure — see CLAUDE.md Roadmap. Do NOT remove this
    /// invariant by exposing the daemon publicly without Track-2.
    pub async fn find_user_by_sub_token(&self, token: &str) -> Result<Option<User>> {
        let row = sqlx::query(
            "SELECT id, uuid, tuic_password, wireguard_pubkey, wireguard_private, sub_token, vpn_router_device_id, disabled
             FROM users WHERE sub_token = ?1",
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await?;
        row.map(row_to_user).transpose()
    }

    /// Overwrite the user's WireGuard / AmneziaWG keypair atomically.
    /// Both halves set together — guarantees the
    /// `private = Some && public = None` inconsistent state can
    /// never appear via this code path.
    ///
    /// Caller produces the standard-base64 strings (typically via
    /// `vpnctl_crypto::gen_wireguard_keypair()`). No shape validation
    /// here — caller's responsibility (web `user_regen_wireguard`
    /// uses the crypto helper directly; no operator-typed input).
    ///
    /// Returns `Invalid` when no such user (mirrors
    /// `regenerate_sub_token` semantics).
    pub async fn set_user_wireguard_keypair(
        &self,
        id: &UserId,
        pubkey: &str,
        private: &str,
    ) -> Result<()> {
        let res = sqlx::query(
            "UPDATE users SET wireguard_pubkey = ?1, wireguard_private = ?2 WHERE id = ?3",
        )
        .bind(pubkey)
        .bind(private)
        .bind(&id.0)
        .execute(&self.pool)
        .await?;
        if res.rows_affected() == 0 {
            return Err(SqliteInventoryError::Invalid(format!(
                "no such user: {}",
                id.0
            )));
        }
        Ok(())
    }

    /// Regenerate the sub_token for an existing user (rotation). Returns the
    /// new token. Old URL stops working immediately.
    pub async fn regenerate_sub_token(&self, id: &UserId) -> Result<String> {
        let token = vpnctl_crypto::gen_sub_token().map_err(SqliteInventoryError::CryptoIo)?;
        let res = sqlx::query("UPDATE users SET sub_token = ?1 WHERE id = ?2")
            .bind(&token)
            .bind(&id.0)
            .execute(&self.pool)
            .await?;
        if res.rows_affected() == 0 {
            return Err(SqliteInventoryError::Invalid(format!(
                "no such user: {}",
                id.0
            )));
        }
        Ok(token)
    }

    /// Mint a `tuic_password` for `id` **only if it currently has none**.
    ///
    /// Returns `Ok(true)` if a password was minted, `Ok(false)` if the
    /// user already had one (no-op). We never rotate a live password
    /// here — that would break the user's TUIC / naive / Hysteria2 links
    /// until the node is redeployed. naive + hysteria2 reuse this field
    /// as their per-user secret, so a NULL `tuic_password` silently drops
    /// those protocols from the user's subscription (the `cdn`
    /// 2026-06-07 incident).
    pub async fn mint_tuic_password_if_absent(&self, id: &UserId) -> Result<bool> {
        // 24 bytes → 32-char url-safe base64, identical to the add-user
        // and CLI mint (`gen_password(TUIC_PW_BYTES)`).
        let pw = vpnctl_crypto::gen_password(24).map_err(SqliteInventoryError::CryptoIo)?;
        let res = sqlx::query(
            "UPDATE users SET tuic_password = ?1
             WHERE id = ?2 AND (tuic_password IS NULL OR tuic_password = '')",
        )
        .bind(&pw)
        .bind(&id.0)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn get_user(&self, id: &UserId) -> Result<Option<User>> {
        let row = sqlx::query(
            "SELECT id, uuid, tuic_password, wireguard_pubkey, wireguard_private, sub_token, vpn_router_device_id, disabled
             FROM users WHERE id = ?1",
        )
        .bind(&id.0)
        .fetch_optional(&self.pool)
        .await?;
        row.map(row_to_user).transpose()
    }

    pub async fn list_users(&self) -> Result<Vec<User>> {
        let rows = sqlx::query(
            "SELECT id, uuid, tuic_password, wireguard_pubkey, wireguard_private, sub_token, vpn_router_device_id, disabled
             FROM users ORDER BY id",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_user).collect()
    }

    pub async fn remove_user(&self, id: &UserId) -> Result<()> {
        sqlx::query("DELETE FROM users WHERE id = ?1")
            .bind(&id.0)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ── Grants (user × server) ──────────────────────────────────────────

    pub async fn grant(&self, user: &UserId, server: &ServerId) -> Result<()> {
        sqlx::query(
            "INSERT INTO grants (user_id, server_id) VALUES (?1, ?2)
             ON CONFLICT(user_id, server_id) DO NOTHING",
        )
        .bind(&user.0)
        .bind(&server.0)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn revoke(&self, user: &UserId, server: &ServerId) -> Result<()> {
        sqlx::query("DELETE FROM grants WHERE user_id = ?1 AND server_id = ?2")
            .bind(&user.0)
            .bind(&server.0)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Users granted on `server`, with `uuid` already overridden to the
    /// per-server `grants.client_uuid` if one is set (Phase 1 of the
    /// ninitux merge — see migration `0016_grants_per_server_uuid.sql`).
    ///
    /// Returned `User.uuid` is the value the SERVER expects to see in
    /// VLESS Reality handshakes from this user. It MAY differ between
    /// servers for the same `user.id` once Phase 2 has imported the
    /// per-(user, server) uuids harvested from subscription-server's
    /// `client_server_links` table.
    ///
    /// All OTHER `User` fields (`tuic_password`, `wireguard_pubkey`,
    /// `wireguard_private`, `sub_token`) keep their per-user values —
    /// only `uuid` is per-server. TUIC and WireGuard don't need
    /// per-server differentiation (TUIC carries password + per-user
    /// uuid; WG identifies peers by pubkey not name) so leaving them
    /// global is correct and avoids needless schema bloat.
    pub async fn users_for_server(&self, server: &ServerId) -> Result<Vec<User>> {
        // `u.disabled = 0` — a disabled user is EXCLUDED from the rendered
        // node config (this slice feeds every kernel's inbound users), so a
        // disable + redeploy REVOKES node access and an enable + redeploy
        // restores it. `disabled` is no longer a subscription-only soft mute.
        // `user_set_disabled_inner` kicks the redeploy on toggle.
        let rows = sqlx::query(
            "SELECT u.id, COALESCE(g.client_uuid, u.uuid) AS uuid, u.tuic_password, u.wireguard_pubkey, u.wireguard_private, u.sub_token, u.vpn_router_device_id
             FROM users u
             INNER JOIN grants g ON g.user_id = u.id
             WHERE g.server_id = ?1
               AND u.disabled = 0
             ORDER BY u.id",
        )
        .bind(&server.0)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_user).collect()
    }

    /// Effective VLESS uuid for a (user, server) grant — the value the
    /// server's sing-box would expect in a Reality handshake from this
    /// user. Returns `None` if no grant exists for the pair.
    ///
    /// `COALESCE(grants.client_uuid, users.uuid)`. The override path:
    /// if Phase 2's import has set a per-server `client_uuid` on the
    /// grant (e.g. when ninitux carried a distinct uuid per server for
    /// the same user), that wins; otherwise the user's global uuid is
    /// returned — preserving pre-Phase-1 behaviour byte-for-byte.
    ///
    /// Use this instead of `get_user(id).uuid` when you're about to
    /// render a vless:// share-link OR push a sing-box `inbounds[*].users[*]`
    /// entry for a specific server. The global `users.uuid` is still the
    /// user IDENTITY (used in audit log targets, sub-token lookups, etc),
    /// but it's no longer guaranteed to be the AUTH secret on every
    /// server the user is granted to.
    pub async fn client_uuid_for(
        &self,
        user: &UserId,
        server: &ServerId,
    ) -> Result<Option<String>> {
        let row = sqlx::query(
            "SELECT COALESCE(g.client_uuid, u.uuid) AS uuid
             FROM grants g
             INNER JOIN users u ON u.id = g.user_id
             WHERE g.user_id = ?1 AND g.server_id = ?2",
        )
        .bind(&user.0)
        .bind(&server.0)
        .fetch_optional(&self.pool)
        .await?;
        match row {
            None => Ok(None),
            Some(r) => Ok(Some(r.try_get("uuid")?)),
        }
    }

    /// Set the per-server VLESS uuid override on an existing grant. The
    /// grant must already exist (call `grant` first if not). Idempotent —
    /// setting to the same value is a no-op SQL-wise; setting to a
    /// different value overwrites.
    ///
    /// `client_uuid` MUST be a syntactically valid RFC 4122 UUID
    /// (validated via `vpnctl_crypto::is_valid_uuid`). An empty /
    /// malformed value would silently brick the user on the server
    /// (Reality handshake rejects, no telemetry signals the cause) —
    /// the gate here means a Phase 2 import script that hits one bad
    /// row fails loudly per-row instead of silently degrading.
    ///
    /// Errors:
    ///   * `Invalid` when `client_uuid` doesn't pass the UUID-shape
    ///     check.
    ///   * `Invalid` when the (user, server) pair has no grant row —
    ///     callers should NOT silently create the grant here. The
    ///     Phase 2 import script grants first, then sets the per-server
    ///     uuid as a separate step (so audit log clearly reflects each
    ///     mutation).
    ///
    /// Audit: writes a `grant.set_client_uuid` row with both old + new
    /// uuid values in the payload, so the operator can trace «when did
    /// this user's vps-de-01 uuid change?» in the audit timeline.
    pub async fn set_grant_client_uuid(
        &self,
        user: &UserId,
        server: &ServerId,
        client_uuid: &str,
    ) -> Result<()> {
        if !vpnctl_crypto::is_valid_uuid(client_uuid) {
            return Err(SqliteInventoryError::Invalid(format!(
                "client_uuid {client_uuid:?} is not a valid UUID; refusing to write"
            )));
        }

        // Transaction wraps the SELECT-then-UPDATE so two concurrent
        // callers can't interleave (read old=A, read old=A, write B,
        // write C → audit log loses B as the «intermediate» state).
        // Phase 2's import script is single-threaded so the race
        // window is empty in the primary use-case; the transaction
        // exists for future callers + defence in depth. SQLite's
        // single-writer model already serialises the inner write,
        // so the cost here is just one extra BEGIN/COMMIT round-trip.
        //
        // Audit row is emitted INSIDE the same transaction so an
        // «I changed this» row never survives a write that didn't
        // commit (e.g. FK violation surfaced too late). On UPDATE
        // returning 0 rows we roll back via early-return + tx drop.
        let mut tx = self.pool.begin().await?;

        // Fetch the grant row's presence AND its old client_uuid in one
        // read. `grant_row` is `Some` iff the (user, server) grant exists
        // — kept separate from `old_uuid` so a grant with a NULL
        // client_uuid is distinguishable from a missing grant (both make
        // `old_uuid` None). Needed below to tell «no grant» (error) apart
        // from «same value, nothing to do» (silent no-op).
        let grant_row =
            sqlx::query("SELECT client_uuid FROM grants WHERE user_id = ?1 AND server_id = ?2")
                .bind(&user.0)
                .bind(&server.0)
                .fetch_optional(&mut *tx)
                .await?;
        let grant_exists = grant_row.is_some();
        let old_uuid: Option<String> = grant_row.and_then(|row| {
            row.try_get::<Option<String>, _>("client_uuid")
                .ok()
                .flatten()
        });

        // `AND client_uuid IS NOT ?3` (NULL-safe) makes a same-value write
        // match 0 rows, mirroring the no-op-suppression idiom in
        // set_user_disabled / set_server_protocol_hidden: a write that
        // doesn't change anything emits no audit row. The presence check
        // below disambiguates the two 0-rows cases.
        let res = sqlx::query(
            "UPDATE grants SET client_uuid = ?3
             WHERE user_id = ?1 AND server_id = ?2 AND client_uuid IS NOT ?3",
        )
        .bind(&user.0)
        .bind(&server.0)
        .bind(client_uuid)
        .execute(&mut *tx)
        .await?;
        if res.rows_affected() == 0 {
            if !grant_exists {
                // tx drops without commit → SELECT side-effect is rolled
                // back (snapshot read had no side effect anyway, but the
                // shape stays «atomic from caller's perspective»).
                return Err(SqliteInventoryError::Invalid(format!(
                    "no grant for user={} server={}; cannot set client_uuid",
                    user.0, server.0
                )));
            }
            // Grant exists but already holds this exact client_uuid →
            // idempotent no-op. Commit (read had no side effect) and skip
            // the audit row so "one audit row per mutation" holds.
            tx.commit().await?;
            return Ok(());
        }

        // Audit row inside the same transaction. Note: the payload
        // logs both old + new client_uuid in plaintext. The VLESS
        // client_uuid IS the Reality auth secret on the corresponding
        // server, so an admin-audit reader sees that secret. This is
        // acceptable for the LAN-only single-operator deployment
        // (admin gate + actor=admin everywhere), but if vpnctld ever
        // gets multi-tenant or externally-exposed audit, the payload
        // should switch to a short fingerprint (e.g. first 8 chars +
        // sha256 suffix) and the full UUID move to a separate
        // auth-gated detail endpoint.
        let audit_payload = serde_json::json!({
            "server_id": server.0,
            "old_client_uuid": old_uuid,
            "new_client_uuid": client_uuid,
        });
        let payload_str = serde_json::to_string(&audit_payload)?;
        sqlx::query(
            "INSERT INTO audit_log (actor, action, target, payload)
             VALUES (?1, ?2, ?3, ?4)",
        )
        .bind("admin")
        .bind("grant.set_client_uuid")
        .bind(&user.0)
        .bind(&payload_str)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Look up a user by their 32-hex `vpn_router_device_id` — the
    /// canonical lookup key in the ninitux URL format. Returns `None`
    /// when no user carries that device_id (the column is partially
    /// unique so at most one row can match). Backs the
    /// `GET /api/v1/app/config/{device_id}` handler in
    /// `daemon::handlers::vpn_router`.
    ///
    /// Caller is expected to validate the input first via
    /// `vpnctl_crypto::is_valid_vpn_router_device_id` — this method
    /// just runs a parameterised SELECT and returns the row (or None).
    /// Refusing malformed input at the handler keeps the SQL fast-path
    /// uniform regardless of garbage input.
    pub async fn find_user_by_vpn_router_device_id(&self, device_id: &str) -> Result<Option<User>> {
        let row = sqlx::query(
            "SELECT id, uuid, tuic_password, wireguard_pubkey, wireguard_private, sub_token, vpn_router_device_id, disabled
             FROM users WHERE vpn_router_device_id = ?1",
        )
        .bind(device_id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(row_to_user).transpose()
    }

    /// Pin a 32-hex `vpn_router_device_id` on an existing user. The
    /// user must already exist (call `add_user` first). Setting the
    /// same value twice is a no-op SQL-wise; setting to a different
    /// value rotates the device_id (rare — happens if subscription-
    /// server's `clients.device_id` for that named client gets
    /// rotated for some reason, then re-imported).
    ///
    /// `device_id` MUST be syntactically valid (32 lowercase hex chars,
    /// validated via `vpnctl_crypto::is_valid_vpn_router_device_id`).
    /// Anything else returns `Invalid`. An empty string is rejected
    /// before the gate, so this method cannot accidentally clear an
    /// existing override — use the dedicated `clear` path if you want
    /// to disconnect a user from the vpn-router endpoint.
    ///
    /// Audit: writes `user.set_vpn_router_device_id` row with old +
    /// new values. Same transaction-wrapped pattern as
    /// `set_grant_client_uuid` — SELECT + UPDATE + INSERT all under
    /// one BEGIN…COMMIT so concurrent callers can't interleave.
    pub async fn set_vpn_router_device_id(&self, user: &UserId, device_id: &str) -> Result<()> {
        if !vpnctl_crypto::is_valid_vpn_router_device_id(device_id) {
            return Err(SqliteInventoryError::Invalid(format!(
                "device_id {device_id:?} is not 32 lowercase hex chars; refusing to write"
            )));
        }

        let mut tx = self.pool.begin().await?;

        let old_device_id: Option<String> =
            sqlx::query("SELECT vpn_router_device_id FROM users WHERE id = ?1")
                .bind(&user.0)
                .fetch_optional(&mut *tx)
                .await?
                .and_then(|row| {
                    row.try_get::<Option<String>, _>("vpn_router_device_id")
                        .ok()
                        .flatten()
                });

        // Map SQLite's UNIQUE constraint violation (a different user
        // already pinned this device_id, blocked by the partial
        // index added in migration 0017) to a clean `AlreadyExists`
        // — same shape as `add_user`'s duplicate-id error. Without
        // this mapping the caller would see a raw sqlx error code
        // 2067 wrapped in `Sqlx(...)`, which is hard to handle.
        let res = map_unique(
            sqlx::query("UPDATE users SET vpn_router_device_id = ?2 WHERE id = ?1")
                .bind(&user.0)
                .bind(device_id)
                .execute(&mut *tx)
                .await,
            format!("vpn_router_device_id {device_id}"),
        )?;
        if res.rows_affected() == 0 {
            return Err(SqliteInventoryError::Invalid(format!(
                "no such user: {}; cannot set vpn_router_device_id",
                user.0
            )));
        }

        // Audit row. device_id is NOT a secret (it's a public lookup
        // key — anyone hitting `https://ninitux.com/api/v1/app/config/<id>`
        // already knows it), so logging both old + new in plaintext is
        // safe for the admin-gated audit feed.
        let audit_payload = serde_json::json!({
            "old_vpn_router_device_id": old_device_id,
            "new_vpn_router_device_id": device_id,
        });
        let payload_str = serde_json::to_string(&audit_payload)?;
        sqlx::query(
            "INSERT INTO audit_log (actor, action, target, payload)
             VALUES (?1, ?2, ?3, ?4)",
        )
        .bind("admin")
        .bind("user.set_vpn_router_device_id")
        .bind(&user.0)
        .bind(&payload_str)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Return a `User` clone with `uuid` swapped to the per-server
    /// VLESS uuid override stored in `grants.client_uuid`. When no
    /// override is set (NULL → COALESCE returns `users.uuid`) the
    /// returned User has the same uuid as the input — the helper is
    /// safe to call unconditionally at render time.
    ///
    /// Use this at every share-link / `client_config` rendering
    /// callsite that has both the `User` (e.g. from `find_user_by_sub_token`)
    /// AND a target `ServerId`. Avoids the three-way clone-and-swap
    /// duplication between `cli/cmd/sub.rs` and `daemon/handlers/sub.rs`
    /// (admin uses the peers-list path, which already has the
    /// override applied by `users_for_server`'s COALESCE — that
    /// callsite keeps its own helper).
    ///
    /// Returns the original user clone (uuid unchanged) when no grant
    /// exists for the pair — same fallback as the inline pattern
    /// being replaced. This is the safe choice: a /sub renderer that
    /// hit an inconsistent state (servers_for_user returned a server
    /// the user got revoked from between calls) still produces a
    /// link rather than crashing the whole response.
    pub async fn user_with_per_server_uuid(&self, user: &User, server: &ServerId) -> Result<User> {
        match self.client_uuid_for(&user.id, server).await? {
            Some(client_uuid) if client_uuid != user.uuid => {
                Ok(user.with_per_server_uuid(&client_uuid))
            }
            _ => Ok(user.clone()),
        }
    }

    pub async fn servers_for_user(&self, user: &UserId) -> Result<Vec<Server>> {
        let rows = sqlx::query(
            "SELECT g.server_id FROM grants g WHERE g.user_id = ?1 ORDER BY g.server_id",
        )
        .bind(&user.0)
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let sid: String = r.try_get("server_id")?;
            if let Some(s) = self.get_server(&ServerId(sid)).await? {
                out.push(s);
            }
        }
        Ok(out)
    }

    // ── Aggregations (read-only, used by daemon dashboard / list views) ──

    /// Cheap row count. `0` on an empty table.
    pub async fn count_servers(&self) -> Result<i64> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM servers")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.try_get("n")?)
    }

    /// Cheap row count. `0` on an empty table.
    pub async fn count_users(&self) -> Result<i64> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM users")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.try_get("n")?)
    }

    /// **Fleet search** (audit A5, shipped 2026-05-23). Substring
    /// match against `users.id`, `users.uuid`, `users.sub_token`,
    /// `users.vpn_router_device_id`. Case-insensitive via
    /// `LOWER(...)`; returns full `User` rows for the hits so the
    /// search results page can render `id` + secondary identifiers
    /// without a second roundtrip. Capped at `limit` so a pathological
    /// `q="a"` doesn't paginate the entire fleet.
    ///
    /// Empty `q` returns empty — search is opt-in, the index page
    /// shouldn't accidentally dump everything.
    pub async fn search_users(&self, q: &str, limit: i64) -> Result<Vec<User>> {
        if q.is_empty() {
            return Ok(Vec::new());
        }
        let pat = format!("%{}%", escape_like(&q.to_lowercase()));
        let rows = sqlx::query(
            "SELECT id, uuid, tuic_password, wireguard_pubkey, wireguard_private, sub_token, vpn_router_device_id, disabled
             FROM users
             WHERE LOWER(id) LIKE ?1 ESCAPE '\\'
                OR LOWER(uuid) LIKE ?1 ESCAPE '\\'
                OR LOWER(COALESCE(sub_token, '')) LIKE ?1 ESCAPE '\\'
                OR LOWER(COALESCE(vpn_router_device_id, '')) LIKE ?1 ESCAPE '\\'
             ORDER BY id
             LIMIT ?2",
        )
        .bind(&pat)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_user).collect()
    }

    /// Fleet search for servers. Substring match against `servers.id`
    /// and `servers.address`. See [`search_users`] for design notes.
    /// Delegates to `get_server` for each hit so the returned rows
    /// have populated `kernels`/`enabled_protocols` lists (the search
    /// page only renders id+address, but a future audit-row click
    /// would expect a fully-populated `Server`).
    pub async fn search_servers(&self, q: &str, limit: i64) -> Result<Vec<Server>> {
        if q.is_empty() {
            return Ok(Vec::new());
        }
        let pat = format!("%{}%", escape_like(&q.to_lowercase()));
        let rows = sqlx::query(
            "SELECT id FROM servers
             WHERE LOWER(id) LIKE ?1 ESCAPE '\\' OR LOWER(address) LIKE ?1 ESCAPE '\\'
             ORDER BY id
             LIMIT ?2",
        )
        .bind(&pat)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        let mut out: Vec<Server> = Vec::with_capacity(rows.len());
        for r in rows {
            let id: String = r.try_get("id")?;
            if let Some(s) = self.get_server(&ServerId(id)).await? {
                out.push(s);
            }
        }
        Ok(out)
    }

    /// Fleet search for alerts. Substring match against
    /// `admin_alerts.kind` and `summary`. Most recent first.
    pub async fn search_alerts(&self, q: &str, limit: i64) -> Result<Vec<AdminAlert>> {
        if q.is_empty() {
            return Ok(Vec::new());
        }
        let pat = format!("%{}%", escape_like(&q.to_lowercase()));
        let rows = sqlx::query(
            "SELECT id, created_at, kind, server_id, severity, summary, payload_json, acked_at
             FROM admin_alerts
             WHERE LOWER(kind) LIKE ?1 ESCAPE '\\' OR LOWER(summary) LIKE ?1 ESCAPE '\\'
             ORDER BY id DESC
             LIMIT ?2",
        )
        .bind(&pat)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_admin_alert).collect()
    }

    /// **Pending-deploy detection** (Option B from the 2026-05-23
    /// «user-create → silent server miss» quickfix discussion).
    ///
    /// Given a user_id + list of granted server_ids, return the
    /// subset of servers whose **latest `server.deploy` audit row
    /// is older than the user's latest mutation** (`user.add`,
    /// `user.grant`, `user.revoke`, `user.set_vpn_router_device_id`,
    /// `user.disable`, `user.enable`). Those servers' running sing-box
    /// config does NOT yet include the user's current state — clicking
    /// their detail page's «deploy» button pushes the fresh render and
    /// closes the gap.
    ///
    /// **Coarse by design:** ANY user mutation marks ALL the user's
    /// granted servers pending (a grant/revoke of server A also flags
    /// B and C). Over-notifying costs one idempotent redeploy;
    /// under-notifying leaves a stale UUID live on a node — the
    /// silent-miss class this detector exists to catch. `user.revoke`
    /// (added 2026-06-10) inherits the same semantics: the revoked
    /// server itself leaves the user's granted list (so this per-user
    /// surface can't show it), but the row still timestamps the
    /// mutation for the remaining servers.
    ///
    /// **Heuristic, not exact:** an alternative deploy via CLI (not
    /// through the web button) doesn't write the same audit row.
    /// Future-proof by extending the SQL `IN (...)` action list when
    /// new audit actions appear.
    ///
    /// **`None`-deploy case:** a server never deployed via web (only
    /// via CLI / wizard) has no `server.deploy` audit row. We treat
    /// this as «pending» if the user has ANY mutation — operator
    /// resolves by clicking deploy at least once, which then sets
    /// a baseline timestamp.
    ///
    /// **Only SUCCESSFUL deploys count as a baseline** (review
    /// 2026-07-08, auto-deploy-on-grant follow-up): every deploy path
    /// writes a `server.deploy` row even when it failed or was skipped
    /// (`ssh_errors` non-empty / `ssh_skip_reason` set) — before this
    /// filter, a failed deploy cleared the pending banner while the
    /// node's `users[]` stayed stale, hiding the exact «connects but
    /// no internet» class the banner exists to expose. Rows without
    /// those payload fields (wizard-bootstrap success rows, legacy /
    /// test-seeded baselines) keep counting as successes.
    pub async fn servers_pending_deploy_for_user(
        &self,
        user_id: &UserId,
        granted_server_ids: &[ServerId],
    ) -> Result<Vec<ServerId>> {
        if granted_server_ids.is_empty() {
            return Ok(Vec::new());
        }
        // Latest user-mutation timestamp from audit_log.
        let user_row = sqlx::query(
            "SELECT MAX(ts) AS ts FROM audit_log
             WHERE target = ?1
               AND action IN ('user.add', 'user.grant', 'user.revoke',
                              'user.set_vpn_router_device_id',
                              'user.disable', 'user.enable')",
        )
        .bind(&user_id.0)
        .fetch_one(&self.pool)
        .await?;
        let user_latest_ts: Option<String> = user_row.try_get("ts")?;
        let Some(user_ts) = user_latest_ts else {
            // User has zero audit mutations (legacy import?) — nothing
            // to flag.
            return Ok(Vec::new());
        };
        // For each granted server, fetch its latest deploy ts and
        // compare. Loop is cheap at homelab scale (≤100 servers
        // ⇒ ≤100 indexed lookups).
        let mut out: Vec<ServerId> = Vec::new();
        for sid in granted_server_ids {
            let row = sqlx::query(
                "SELECT MAX(ts) AS ts FROM audit_log
                 WHERE target = ?1 AND action = 'server.deploy'
                   AND json_extract(payload, '$.ssh_skip_reason') IS NULL
                   AND (json_extract(payload, '$.ssh_errors') IS NULL
                        OR json_array_length(payload, '$.ssh_errors') = 0)",
            )
            .bind(&sid.0)
            .fetch_one(&self.pool)
            .await?;
            let deploy_ts: Option<String> = row.try_get("ts")?;
            // Pending if: no deploy ever recorded (None) OR last
            // deploy is older than the user's last change.
            match deploy_ts {
                None => out.push(sid.clone()),
                Some(dts) if dts < user_ts => out.push(sid.clone()),
                _ => {}
            }
        }
        Ok(out)
    }

    /// **Server-side pending-deploy detection** (audit 2026-06-10,
    /// review follow-up to the revoke unification). The per-user
    /// detector above can't cover one case at all: after a REVOKE the
    /// server leaves the user's granted list, so no user-detail banner
    /// will ever mention it — yet that node is exactly the one still
    /// running the revoked UUID. This is the server-detail counterpart:
    /// «has this server's grant MEMBERSHIP changed since its last
    /// deploy?»
    ///
    /// Keys on the canonical per-user rows (`user.grant` /
    /// `user.revoke`) via their `payload.server` field — both written
    /// since the 2026-06-04/2026-06-10 unifications, and only for
    /// ACTUAL mutations, so an idempotent re-grant can't raise a false
    /// pending here. Pre-unification legacy rows (`action='grant'`,
    /// target=server) are invisible to this query — acceptable: any
    /// server deployed since then has a fresher `server.deploy` row
    /// anyway.
    ///
    /// Scope is membership only (grant/revoke). Other user mutations
    /// (disable, device-id) surface through the per-user banner on
    /// every granted server — duplicating them here would make the
    /// server banner near-permanent on busy inventories.
    ///
    /// Only SUCCESSFUL deploys count as a baseline — same filter and
    /// rationale as `servers_pending_deploy_for_user`.
    pub async fn server_pending_deploy(&self, server_id: &ServerId) -> Result<bool> {
        let row = sqlx::query(
            "SELECT MAX(ts) AS ts FROM audit_log
             WHERE action IN ('user.grant', 'user.revoke')
               AND json_extract(payload, '$.server') = ?1",
        )
        .bind(&server_id.0)
        .fetch_one(&self.pool)
        .await?;
        let mutation_ts: Option<String> = row.try_get("ts")?;
        let Some(mts) = mutation_ts else {
            return Ok(false);
        };
        let row = sqlx::query(
            "SELECT MAX(ts) AS ts FROM audit_log
             WHERE target = ?1 AND action = 'server.deploy'
               AND json_extract(payload, '$.ssh_skip_reason') IS NULL
               AND (json_extract(payload, '$.ssh_errors') IS NULL
                    OR json_array_length(payload, '$.ssh_errors') = 0)",
        )
        .bind(&server_id.0)
        .fetch_one(&self.pool)
        .await?;
        let deploy_ts: Option<String> = row.try_get("ts")?;
        Ok(match deploy_ts {
            None => true,
            Some(dts) => dts < mts,
        })
    }

    /// Count of users with `disabled = 1` (B1.user, migration 0026).
    /// Cheap — backed by the partial `idx_users_disabled_partial`
    /// index which only contains the disabled rows, so this is O(N
    /// disabled), not O(N total). Used by the dashboard's «N paused»
    /// sub-line so disabled users don't fall off the operator's
    /// radar.
    pub async fn count_disabled_users(&self) -> Result<i64> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM users WHERE disabled = 1")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.try_get("n")?)
    }

    /// Cheap row count of (user, server) grant pairs. `0` on empty table.
    pub async fn count_grants(&self) -> Result<i64> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM grants")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.try_get("n")?)
    }

    /// **Idle users** — list `(user_id, last_seen)` for users whose
    /// most recent `sub_access_log` row is older than `days` days, OR
    /// who have never appeared in the access log at all (last_seen
    /// is `None`).
    ///
    /// Backs the dashboard «Idle users — revoke candidates» panel
    /// (audit A2). Cheap single LEFT-JOIN with one MAX aggregate;
    /// rows are sorted oldest-first (`last_seen ASC NULLS FIRST`)
    /// so the worst offenders appear at the top. Limit caps the
    /// result set so the panel doesn't grow unbounded.
    ///
    /// **`days = 30` is the canonical threshold for the dashboard**
    /// — a roughly-monthly cycle catches «forgotten phone in a
    /// drawer» without being so aggressive it surfaces normal-
    /// vacation users. Operator can pick a different number; the
    /// query is parameterised.
    ///
    /// Pinned by `idle_users_returns_users_with_old_or_no_last_seen`.
    pub async fn idle_users(
        &self,
        days: u32,
        limit: i64,
    ) -> Result<Vec<(UserId, Option<DateTime<Utc>>)>> {
        let cutoff = format!("-{days} days");
        // LEFT JOIN against an aggregate subquery: every user appears
        // exactly once; users with no sub_access_log row get
        // `last_seen = NULL`. WHERE filter keeps only `last_seen IS
        // NULL` (never seen) OR `last_seen < cutoff` (seen but old).
        // Sort `last_seen ASC NULLS FIRST` so never-seen users float
        // to the top alongside the longest-idle ones.
        let rows = sqlx::query(
            "SELECT u.id AS user_id, la.last_seen AS last_seen
             FROM users u
             LEFT JOIN (
                 SELECT user_id, MAX(ts) AS last_seen
                 FROM sub_access_log
                 WHERE is_vpn_egress = 0
                 GROUP BY user_id
             ) la ON la.user_id = u.id
             WHERE la.last_seen IS NULL
                -- `<=` not `<`: a row whose ts equals the cutoff is
                -- «no newer than the threshold» → idle. Also closes
                -- a CI flake: a tight loop on a fast box can write
                -- the access-log row + run idle_users(0) within one
                -- millisecond, leaving ts == cutoff exactly; strict
                -- `<` would have excluded the row and the test
                -- would intermittently fail.
                OR la.last_seen <= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1)
             ORDER BY (la.last_seen IS NOT NULL), la.last_seen ASC
             LIMIT ?2",
        )
        .bind(&cutoff)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        let mut out: Vec<(UserId, Option<DateTime<Utc>>)> = Vec::with_capacity(rows.len());
        for row in rows {
            let uid: String = row.try_get("user_id")?;
            let last_seen_str: Option<String> = row.try_get("last_seen")?;
            let last_seen = last_seen_str.and_then(|t| {
                DateTime::parse_from_rfc3339(&t)
                    .ok()
                    .map(|d| d.with_timezone(&Utc))
            });
            out.push((UserId(uid), last_seen));
        }
        Ok(out)
    }

    /// Map of `server_id → number of users granted access to it`. Servers
    /// with no grants are absent (callers default to 0). One query, no N+1
    /// — call this once and look up by ID when rendering a server list.
    pub async fn users_count_per_server(&self) -> Result<HashMap<ServerId, i64>> {
        let rows = sqlx::query("SELECT server_id, COUNT(*) AS n FROM grants GROUP BY server_id")
            .fetch_all(&self.pool)
            .await?;
        let mut out = HashMap::with_capacity(rows.len());
        for r in rows {
            let sid: String = r.try_get("server_id")?;
            let n: i64 = r.try_get("n")?;
            out.insert(ServerId(sid), n);
        }
        Ok(out)
    }

    // ── Audit ───────────────────────────────────────────────────────────

    pub async fn audit(
        &self,
        actor: &str,
        action: &str,
        target: Option<&str>,
        payload: Option<&serde_json::Value>,
    ) -> Result<()> {
        let payload_str = match payload {
            Some(v) => Some(serde_json::to_string(v)?),
            None => None,
        };
        sqlx::query(
            "INSERT INTO audit_log (actor, action, target, payload) VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(actor)
        .bind(action)
        .bind(target)
        .bind(payload_str)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Paginated + filterable audit query — backs Phase D timeline UI.
    ///
    /// Both filter args are optional substrings: `actor_filter = Some("admin")`
    /// matches rows where `actor = 'admin'` (exact match); `action_filter
    /// = Some("user.")` matches rows where `action LIKE 'user.%'`. Pass
    /// `None` to skip a filter axis.
    ///
    /// `limit` and `offset` drive the pagination — caller computes them
    /// from a page number (typically `offset = page * limit`). Newest-
    /// first order matches `recent_audit`.
    ///
    /// Returns at most `limit` rows. The caller decides "is there a next
    /// page?" by asking for one extra row (`limit+1`) and checking the
    /// returned length, OR by issuing a separate `count_audit_filtered`
    /// query (we don't expose one yet — the +1 trick is enough).
    pub async fn recent_audit_paginated(
        &self,
        limit: i64,
        offset: i64,
        actor_filter: Option<&str>,
        action_prefix: Option<&str>,
    ) -> Result<Vec<AuditEntry>> {
        // Build the WHERE clause incrementally. SQLite uses positional
        // `?` placeholders so we don't number them — the bind() calls
        // below run in the same order as the WHERE conditions.
        let mut where_parts: Vec<&str> = Vec::with_capacity(2);
        if actor_filter.is_some() {
            where_parts.push(if where_parts.is_empty() {
                "actor = ?"
            } else {
                "AND actor = ?"
            });
        }
        if action_prefix.is_some() {
            where_parts.push(if where_parts.is_empty() {
                "action LIKE ? ESCAPE '\\'"
            } else {
                "AND action LIKE ? ESCAPE '\\'"
            });
        }
        let where_clause = if where_parts.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_parts.join(" "))
        };
        let sql = format!(
            "SELECT id, ts, actor, action, target, payload
             FROM audit_log
             {where_clause}
             ORDER BY id DESC
             LIMIT ? OFFSET ?"
        );
        let mut q = sqlx::query(&sql);
        if let Some(a) = actor_filter {
            q = q.bind(a);
        }
        if let Some(p) = action_prefix {
            // Append `%` for prefix match — caller passes `"user."` and
            // we turn it into `"user.%"`. LIKE metacharacters in `p`
            // (`%` `_` `\`) are escaped first so an operator typing
            // `?action=user_` matches LITERAL `user_`, not `user.`,
            // and `?action=%` matches literal `%`, not "everything".
            // Pairs with the `ESCAPE '\\'` clause above.
            q = q.bind(format!("{}%", escape_like(p)));
        }
        q = q.bind(limit).bind(offset);
        let rows = q.fetch_all(&self.pool).await?;
        rows.into_iter().map(row_to_audit_entry).collect()
    }

    pub async fn recent_audit(&self, limit: i64) -> Result<Vec<AuditEntry>> {
        let rows = sqlx::query(
            "SELECT id, ts, actor, action, target, payload
             FROM audit_log ORDER BY id DESC LIMIT ?1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_audit_entry).collect()
    }

    // ── Subscription access log (Phase Track-1) ─────────────────────────

    /// Append one row to `sub_access_log`. Called by the `/sub/<token>`
    /// handler AFTER the token has been resolved to a user (so a 404 path
    /// — "unknown token" — does NOT land here; that's intentional, we
    /// don't want to keep a per-attempt log of probing tokens because it
    /// would let an attacker fill the table by spamming garbage).
    ///
    /// Best-effort write. The handler calls this in a fire-and-forget
    /// `tokio::spawn`; if it errors the response has already been sent.
    pub async fn log_sub_access(
        &self,
        user_id: &UserId,
        ip: &str,
        ua: Option<&str>,
        status: u16,
        bytes: u64,
    ) -> Result<()> {
        // Convenience wrapper for tests + old call sites — passes None
        // for the Track-1.2 metadata columns (migration 0019) AND the
        // Track-1.4 TLS fingerprint columns (migration 0020). The
        // production writer task on the access-log channel calls
        // `log_sub_access_rich` directly so it can pass the captured
        // UA / Accept-Language / HTTP version / GeoIP / TLS-JA3/JA4
        // results.
        self.log_sub_access_rich(
            user_id, ip, ua, status, bytes, None, None, None, None, None, None, None,
        )
        .await
    }

    /// Full sub-access logging — accepts all Track-1.2 + Track-1.4
    /// metadata columns (migrations 0019, 0020). Called from the
    /// access-log writer task; handlers populate the captured-from-
    /// request fields and the writer enriches with GeoIP before
    /// passing through here.
    #[allow(clippy::too_many_arguments)]
    pub async fn log_sub_access_rich(
        &self,
        user_id: &UserId,
        ip: &str,
        ua: Option<&str>,
        status: u16,
        bytes: u64,
        accept_language: Option<&str>,
        http_version: Option<&str>,
        device_class: Option<&str>,
        geo_country: Option<&str>,
        geo_asn: Option<&str>,
        tls_ja3: Option<&str>,
        tls_ja4: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO sub_access_log
             (user_id, ip, ua, status, bytes,
              accept_language, http_version, device_class,
              geo_country, geo_asn, tls_ja3, tls_ja4)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        )
        .bind(&user_id.0)
        .bind(ip)
        .bind(ua)
        // SQLite has no u16 affinity; cast through i64.
        .bind(i64::from(status))
        .bind(i64::try_from(bytes).unwrap_or(i64::MAX))
        .bind(accept_language)
        .bind(http_version)
        .bind(device_class)
        .bind(geo_country)
        .bind(geo_asn)
        .bind(tls_ja3)
        .bind(tls_ja4)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Number of distinct source IPs that fetched this user's
    /// subscription URL in the last `since_hours` hours. Drives the
    /// "abuse signal" headline on the user-detail page.
    ///
    /// **Timestamp-format invariant (caught by retroactive review-agent
    /// 2026-05-14, was a critical bug):** the cutoff must be produced
    /// in the **same** format as `ts` is written by `log_sub_access` —
    /// ISO `YYYY-MM-DDTHH:MM:SS.fffZ` (note the `T` separator and the
    /// trailing `Z`). `datetime('now', ?)` returns the SQL form
    /// `YYYY-MM-DD HH:MM:SS` (space separator, no millis, no `Z`) and
    /// then SQLite compares both sides as TEXT — the `T` (0x54) is
    /// greater than space (0x20), so every same-day row would compare
    /// as "newer than the cutoff" regardless of its actual time-of-day.
    /// Always wrap with `strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)` so
    /// both sides share the format the row was written in.
    pub async fn distinct_ips_for_user(&self, user_id: &UserId, since_hours: u32) -> Result<u64> {
        let row = sqlx::query(
            "SELECT COUNT(DISTINCT ip) AS n FROM sub_access_log
             WHERE user_id = ?1
               AND ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)",
        )
        .bind(&user_id.0)
        .bind(format!("-{since_hours} hours"))
        .fetch_one(&self.pool)
        .await?;
        let n: i64 = row.try_get("n")?;
        Ok(u64::try_from(n).unwrap_or(0))
    }

    /// Most recent N access rows for one user, newest first. Drives the
    /// recent-activity table on the user-detail page; the limit caps
    /// memory + render cost since chatty clients can rack up thousands
    /// of rows in the retention window.
    pub async fn recent_sub_access(
        &self,
        user_id: &UserId,
        limit: i64,
    ) -> Result<Vec<SubAccessEntry>> {
        // Default behaviour preserved (returns ALL rows including
        // VPN-egress) so existing callers + spec tests keep their
        // contract. Callers that want the «real IPs only» variant
        // call `recent_sub_access_filtered` (Phase 4a) instead.
        let rows = sqlx::query(
            "SELECT id, ts, user_id, ip, ua, status, bytes,
                    accept_language, http_version, device_class,
                    geo_country, geo_asn, tls_ja3, tls_ja4,
                    is_vpn_egress
             FROM sub_access_log
             WHERE user_id = ?1
             ORDER BY id DESC
             LIMIT ?2",
        )
        .bind(&user_id.0)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_sub_access).collect()
    }

    /// Phase 4a — `recent_sub_access` with VPN-egress filter. When
    /// `include_egress = false` (the user-detail page's default),
    /// returns ONLY rows where the src IP is a real client device,
    /// not one of our own VPN server addresses. The `is_vpn_egress`
    /// flag is set by the SQLite trigger added in migration 0021,
    /// so this filter is just a `WHERE is_vpn_egress = 0` predicate
    /// using the partial index `idx_sub_access_log_user_ts_real`.
    pub async fn recent_sub_access_filtered(
        &self,
        user_id: &UserId,
        limit: i64,
        include_egress: bool,
    ) -> Result<Vec<SubAccessEntry>> {
        // `include_egress` widened (2026-06-16) to "show our own infra
        // rows": the default (false) view now hides not just VPN-server
        // egress (`is_vpn_egress = 0`) but ALSO LAN / loopback / control-
        // egress fetches (our curl tests, the claude-chat host at
        // 192.168.0.200, the monitor canary) via `real_client_ip_predicate`.
        let sql = if include_egress {
            "SELECT id, ts, user_id, ip, ua, status, bytes,
                    accept_language, http_version, device_class,
                    geo_country, geo_asn, tls_ja3, tls_ja4,
                    is_vpn_egress
             FROM sub_access_log
             WHERE user_id = ?1
             ORDER BY id DESC
             LIMIT ?2"
                .to_string()
        } else {
            format!(
                "SELECT id, ts, user_id, ip, ua, status, bytes,
                        accept_language, http_version, device_class,
                        geo_country, geo_asn, tls_ja3, tls_ja4,
                        is_vpn_egress
                 FROM sub_access_log
                 WHERE user_id = ?1 AND is_vpn_egress = 0 AND {pred}
                 ORDER BY id DESC
                 LIMIT ?2",
                pred = real_client_ip_predicate("ip")
            )
        };
        let rows = sqlx::query(&sql)
            .bind(&user_id.0)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter().map(row_to_sub_access).collect()
    }

    /// Phase 4a — aggregates over a user's recent `sub_access_log`
    /// rows for the user-detail summary cards (distinct IPs /
    /// countries / ASNs, total bytes, first/last seen, hidden-
    /// egress badge count). `days` bounds the window — Pavel's
    /// chosen UX is 30d for the cards, matching the retention
    /// purger's max window.
    ///
    /// One SQL round-trip; SQLite computes the aggregates over the
    /// already-filtered window so we don't ship raw rows through
    /// Rust just to count distinct values. The `egress_rows`
    /// counter is the only field that includes egress (so the
    /// «N hidden» badge has the right denominator).
    pub async fn sub_access_aggregates_for_user(
        &self,
        user_id: &UserId,
        days: u32,
    ) -> Result<SubAccessAggregates> {
        let cutoff = format!("-{days} days");
        // One query returns 8 scalars. Wraps NULL aggregates in
        // sensible defaults (zero / None) via the conversion below.
        let row = sqlx::query(
            "SELECT
                COUNT(*) FILTER (WHERE is_vpn_egress = 0)                    AS total_rows,
                COUNT(*) FILTER (WHERE is_vpn_egress = 1)                    AS egress_rows,
                COUNT(DISTINCT CASE WHEN is_vpn_egress = 0 THEN ip END)      AS distinct_ips,
                COUNT(DISTINCT CASE WHEN is_vpn_egress = 0 AND geo_country IS NOT NULL THEN geo_country END) AS distinct_countries,
                COUNT(DISTINCT CASE WHEN is_vpn_egress = 0 AND geo_asn IS NOT NULL THEN geo_asn END)         AS distinct_asns,
                COALESCE(SUM(CASE WHEN is_vpn_egress = 0 THEN bytes END), 0) AS total_bytes,
                MAX(ts)                                                      AS last_seen,
                MIN(ts)                                                      AS first_seen
             FROM sub_access_log
             WHERE user_id = ?1
               AND ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)",
        )
        .bind(&user_id.0)
        .bind(&cutoff)
        .fetch_one(&self.pool)
        .await?;

        let total_rows: i64 = row.try_get("total_rows")?;
        let egress_rows: i64 = row.try_get("egress_rows")?;
        let distinct_ips: i64 = row.try_get("distinct_ips")?;
        let distinct_countries: i64 = row.try_get("distinct_countries")?;
        let distinct_asns: i64 = row.try_get("distinct_asns")?;
        let total_bytes: i64 = row.try_get("total_bytes")?;
        let last_seen_str: Option<String> = row.try_get("last_seen")?;
        let first_seen_str: Option<String> = row.try_get("first_seen")?;

        let parse_ts = |s: Option<String>| -> Option<DateTime<Utc>> {
            s.and_then(|t| {
                DateTime::parse_from_rfc3339(&t)
                    .ok()
                    .map(|d| d.with_timezone(&Utc))
            })
        };

        // `i64 → u64` via `.max(0) as u64` is a saturating cast —
        // honest about discarding negatives (impossible for
        // COALESCE(SUM, 0) and COUNT(*), but defensive against any
        // future schema bug that lets a sentinel `-1` slip through;
        // the previous `.unwrap_or(0)` form silently swallowed
        // those without telemetry). Review-agent Phase 4a #4.
        Ok(SubAccessAggregates {
            total_rows: total_rows.max(0) as u64,
            egress_rows: egress_rows.max(0) as u64,
            distinct_ips: distinct_ips.max(0) as u64,
            distinct_countries: distinct_countries.max(0) as u64,
            distinct_asns: distinct_asns.max(0) as u64,
            total_bytes: total_bytes.max(0) as u64,
            last_seen: parse_ts(last_seen_str),
            first_seen: parse_ts(first_seen_str),
        })
    }

    /// UA-cluster aggregate for the Phase Track-4 fingerprint
    /// heuristic. Groups this user's recent `sub_access_log` rows
    /// by User-Agent and reports per-UA distinct IPs, distinct /16
    /// networks (first two v4 octets), and total hits.
    ///
    /// The /16 count is the key signal: a single roaming device
    /// usually moves within one ISP /16 (Wi-Fi switching subnets,
    /// LTE base stations under the same provider) — so distinct_ips
    /// can be high but distinct_slash16 stays at 1-2. A shared sub
    /// URL hits from many ISPs / countries → distinct_slash16 climbs.
    ///
    /// IPv6 addresses contribute `0` to the /16 count (we don't try
    /// to derive a meaningful network prefix without ASN data); the
    /// `distinct_ips` count still reflects them.
    pub async fn ua_clusters_for_user(
        &self,
        user_id: &UserId,
        since_hours: u32,
    ) -> Result<Vec<UaCluster>> {
        // Pull raw (ua, ip) tuples then aggregate in Rust — SQLite
        // can't extract /16 prefixes natively, and the row count is
        // bounded by the recent window so memory is fine.
        let rows = sqlx::query(
            "SELECT ua, ip FROM sub_access_log
             WHERE user_id = ?1
               AND ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)",
        )
        .bind(&user_id.0)
        .bind(format!("-{since_hours} hours"))
        .fetch_all(&self.pool)
        .await?;

        use std::collections::{HashMap, HashSet};
        // (ua_or_none) → (set of distinct IPs, set of distinct /16, hit count)
        let mut by_ua: HashMap<Option<String>, (HashSet<String>, HashSet<String>, u64)> =
            HashMap::new();
        for r in rows {
            let ua: Option<String> = r.try_get("ua")?;
            let ip: String = r.try_get("ip")?;
            let s16 = ip_slash16(&ip);
            let entry = by_ua.entry(ua).or_default();
            entry.0.insert(ip);
            if let Some(net) = s16 {
                entry.1.insert(net);
            }
            entry.2 += 1;
        }
        let mut out: Vec<UaCluster> = by_ua
            .into_iter()
            .map(|(ua, (ips, s16s, hits))| UaCluster {
                ua,
                distinct_ips: ips.len() as u64,
                distinct_slash16: s16s.len() as u64,
                hits,
            })
            .collect();
        // Sort by hit count DESC so the noisy UAs surface first in
        // the UI.
        out.sort_by_key(|c| std::cmp::Reverse(c.hits));
        Ok(out)
    }

    /// Drop all rows older than `days`. Returns the number of rows
    /// removed so the caller (a periodic task in the daemon) can log
    /// the retention activity.
    ///
    /// See `distinct_ips_for_user` for the timestamp-format invariant;
    /// the same `strftime` wrap applies here so the purge cutoff is
    /// comparable to the ISO timestamps `log_sub_access` writes.
    pub async fn purge_sub_access_older_than(&self, days: u32) -> Result<u64> {
        let res = sqlx::query(
            "DELETE FROM sub_access_log WHERE ts < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1)",
        )
        .bind(format!("-{days} days"))
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    /// Aggregate `sub_access_log` into time buckets for the Phase F
    /// monitoring sparklines. `bucket = "hour"` groups by hourly
    /// truncation, `bucket = "day"` by date. `since_hours` is the
    /// look-back window from now.
    ///
    /// Returns ONE row per bucket that had at least one hit; the
    /// caller fills gaps with zero so the sparkline x-axis stays
    /// evenly spaced. Newest-first sort is NOT used — buckets come
    /// back oldest-first (ASC) so the renderer can walk them
    /// chronologically without re-sorting.
    pub async fn sub_access_buckets(
        &self,
        bucket: &str,
        since_hours: u32,
    ) -> Result<Vec<AccessBucket>> {
        // Bucket grouping format. We REJECT unknown bucket strings
        // rather than silently default — an operator typo should
        // surface as an error, not as a meaningless aggregate.
        let group_fmt = match bucket {
            "hour" => "%Y-%m-%dT%H:00:00.000Z",
            "day" => "%Y-%m-%dT00:00:00.000Z",
            other => {
                return Err(SqliteInventoryError::Invalid(format!(
                    "sub_access_buckets: unknown bucket kind '{other}' (allowed: hour, day)"
                )));
            }
        };
        let rows = sqlx::query(
            "SELECT
                strftime(?1, ts) AS bucket_start,
                COUNT(*) AS hits,
                COUNT(DISTINCT ip) AS distinct_ips
             FROM sub_access_log
             WHERE ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)
             GROUP BY bucket_start
             ORDER BY bucket_start ASC",
        )
        .bind(group_fmt)
        .bind(format!("-{since_hours} hours"))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|r| {
                let ts_str: String = r.try_get("bucket_start")?;
                let ts = DateTime::parse_from_rfc3339(&ts_str)
                    .map(|d| d.with_timezone(&Utc))
                    .map_err(|e| {
                        SqliteInventoryError::Invalid(format!(
                            "bucket_start not RFC3339 ({ts_str}): {e}"
                        ))
                    })?;
                let hits_i: i64 = r.try_get("hits")?;
                let ips_i: i64 = r.try_get("distinct_ips")?;
                Ok(AccessBucket {
                    bucket_start: ts,
                    hits: u64::try_from(hits_i).unwrap_or(0),
                    distinct_ips: u64::try_from(ips_i).unwrap_or(0),
                })
            })
            .collect()
    }

    // ── Persistent rate-limit bans (Phase Track-2 chunk 2) ──────────────

    /// Insert a new ban valid for `ttl_secs` seconds. `kind` MUST be
    /// `"ip"` or `"token"` (the SQL `CHECK` constraint will reject
    /// other values; we don't pre-validate so a typo surfaces as a
    /// loud `Err` instead of a silent skip). Multiple overlapping
    /// bans for the same key are allowed — `is_banned` returns true
    /// if ANY non-expired ban matches, so re-banning is harmless.
    pub async fn add_ban(&self, kind: &str, key: &str, ttl_secs: u64, reason: &str) -> Result<()> {
        // Cap ttl at i64::MAX seconds (~292B years) defensively. The
        // SQL `+N seconds` modifier takes signed values; an unsigned
        // u64 of MAX would silently wrap. Practical max here is the
        // 24h default the daemon writes.
        let ttl_signed: i64 = i64::try_from(ttl_secs).unwrap_or(i64::MAX);
        sqlx::query(
            "INSERT INTO sub_rate_bans (until_ts, kind, key, reason)
             VALUES (
                strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1),
                ?2, ?3, ?4
             )",
        )
        .bind(format!("+{ttl_signed} seconds"))
        .bind(kind)
        .bind(key)
        .bind(reason)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Returns `Some(seconds_until_oldest_ban_expires)` if `(kind,
    /// key)` has any non-expired ban; `None` otherwise. Hot-path
    /// query: the index `idx_sub_rate_bans_kind_key_until` covers
    /// the entire predicate so this is sub-millisecond.
    ///
    /// Returns the SOONEST expiry among all matching bans (so
    /// `Retry-After` reflects the conservative "you'll be unbanned
    /// in this many seconds at the earliest"). If multiple
    /// overlapping bans exist, the oldest one expires first.
    pub async fn is_banned(&self, kind: &str, key: &str) -> Result<Option<u64>> {
        let row_opt = sqlx::query(
            "SELECT MIN(until_ts) AS until FROM sub_rate_bans
             WHERE kind = ?1 AND key = ?2
               AND until_ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
        )
        .bind(kind)
        .bind(key)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row_opt else {
            return Ok(None);
        };
        let until_str: Option<String> = row.try_get("until")?;
        let Some(until_str) = until_str else {
            // No matching rows — MIN() over an empty set returns NULL.
            return Ok(None);
        };
        let until = DateTime::parse_from_rfc3339(&until_str)
            .map(|d| d.with_timezone(&Utc))
            .map_err(|e| {
                SqliteInventoryError::Invalid(format!("ban until_ts malformed: {until_str}: {e}"))
            })?;
        let now = Utc::now();
        let secs = (until - now).num_seconds();
        // Defensive: race between SELECT and the `now` value here
        // could surface as 0 or -1 if the ban just expired.
        Ok(Some(u64::try_from(secs.max(1)).unwrap_or(1)))
    }

    /// List all currently-active bans (any kind). Powers the
    /// admin UI's "Active bans" surface. Sorted newest-first by
    /// `created_at` so the most recent abuse pops to the top.
    pub async fn active_bans(&self) -> Result<Vec<Ban>> {
        // ORDER BY created_at DESC, id DESC — `id DESC` is the stable
        // tiebreaker for inserts that land in the same millisecond
        // (caught by `spec_sub_rate_bans::active_bans_lists_all_kinds_newest_first`
        // flaking on CI). `id` is monotonic on insert (SQLite ROWID),
        // so id DESC == insert-order DESC for ties.
        let rows = sqlx::query(
            "SELECT id, created_at, until_ts, kind, key, reason
             FROM sub_rate_bans
             WHERE until_ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             ORDER BY created_at DESC, id DESC",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_ban).collect()
    }

    /// Drop expired ban rows. Called periodically by the daemon's
    /// rate-limit cleanup task. Returns the number of rows removed
    /// for telemetry.
    pub async fn purge_expired_bans(&self) -> Result<u64> {
        let res = sqlx::query(
            "DELETE FROM sub_rate_bans
             WHERE until_ts <= strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
        )
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    // ──────────────────────────────────────────────────────────────────
    // Track-3 chunk 2 — VPN connection stats (clash-api poller sink)
    //
    // The poller in `daemon::clash_poller` (separate iter / chunk) calls
    // `record_vpn_stats(server_id, deltas)` once per tick. The read
    // surfaces — `recent_vpn_stats_for_user` and
    // `recent_vpn_stats_for_server` — power chunk 3's UI on
    // `/admin/users/<id>` and `/admin/servers/<id>`.
    //
    // Server-wide rows are persisted under `user_id = NULL` so the
    // server-detail page can render bandwidth-vs-time without joining
    // across every per-user row.
    //
    // All deltas for one tick land in a single transaction so a poller
    // crash mid-write doesn't yield a half-attributed snapshot.
    //
    // **Audit-log exemption.** The "every inventory mutation gets one
    // audit_log row" invariant from CLAUDE.md is INTENTIONALLY waived
    // for `vpn_connection_stats`. Rationale: at homelab scale (5
    // servers × 60s tick × 24h × 30d = ~216K poller writes per month
    // before user multiplication), per-tick audit rows would dwarf
    // every other audit entry by 4 orders of magnitude and bury the
    // human-driven mutations the timeline is designed to surface. The
    // table itself IS the audit trail for poller activity (timestamps
    // + per-server + per-user breakdown); a chunk-3 retrospective on
    // /admin/audit can join in a derived "vpn-stats activity" entry
    // if operators ever need it. (Reviewed by independent review-agent
    // on cd61838^..492fdeb burst; documented exemption rather than
    // letting the invariant erode silently.)
    // ──────────────────────────────────────────────────────────────────

    /// Persist one tick's deltas. Empty `deltas` is a no-op (the
    /// poller may decide a quiet node doesn't deserve a row).
    /// Timestamp is `now` on the daemon, NOT pulled from the snapshot
    /// — clash-api doesn't carry a snapshot timestamp, and the
    /// daemon's clock is the only source we trust on the read side.
    pub async fn record_vpn_stats(
        &self,
        server_id: &ServerId,
        deltas: &[VpnStatsDelta],
    ) -> Result<()> {
        if deltas.is_empty() {
            return Ok(());
        }
        let mut tx = self.pool.begin().await?;
        for d in deltas {
            sqlx::query(
                "INSERT INTO vpn_connection_stats
                 (ts, server_id, user_id, upload_bytes, download_bytes, active_connections)
                 VALUES (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), ?1, ?2, ?3, ?4, ?5)",
            )
            .bind(&server_id.0)
            .bind(d.user_id.as_ref().map(|u| u.0.as_str()))
            .bind(i64::try_from(d.upload_bytes).unwrap_or(i64::MAX))
            .bind(i64::try_from(d.download_bytes).unwrap_or(i64::MAX))
            .bind(i64::from(d.active_connections))
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Recent per-user rows across ALL servers in the look-back
    /// window. Newest-first. The UI joins these by server_id to
    /// render a per-server breakdown if needed.
    pub async fn recent_vpn_stats_for_user(
        &self,
        user_id: &UserId,
        since_hours: u32,
    ) -> Result<Vec<VpnStatsRow>> {
        let rows = sqlx::query(
            "SELECT ts, server_id, user_id, upload_bytes, download_bytes, active_connections
             FROM vpn_connection_stats
             WHERE user_id = ?1
               AND ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)
             ORDER BY ts DESC",
        )
        .bind(&user_id.0)
        .bind(format!("-{since_hours} hours"))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_vpn_stats).collect()
    }

    /// Set or clear a user's monthly bandwidth limit + alert
    /// threshold. Pass `Some(limit)` to set, `None` to clear
    /// (operator decided the user no longer needs a cap). Threshold
    /// is a percent (0..=100); the daemon-side default lives in
    /// `vpnctld::admin::DEFAULT_TRAFFIC_THRESHOLD_PCT`.
    ///
    /// Returns `Invalid` if no such user — matches the existing
    /// `regenerate_sub_token` shape.
    /// Flip the `disabled` flag on a user (audit B1.user, migration
    /// 0026). Returns `Ok(true)` when the row was changed (operator
    /// actually flipped state), `Ok(false)` when the row already
    /// matched the requested state (idempotent no-op), or `Err` if
    /// the user doesn't exist.
    ///
    /// Caller is responsible for the audit row — this helper does
    /// only the SQL flip so the handler can decide whether the
    /// audit entry is `user.disable` or `user.enable` (mirrors the
    /// per-protocol `set_hidden` + `set_grant_protocol_override`
    /// convention from NM-10).
    pub async fn set_user_disabled(&self, id: &UserId, disabled: bool) -> Result<bool> {
        let new_val: i64 = if disabled { 1 } else { 0 };
        let res = sqlx::query("UPDATE users SET disabled = ?1 WHERE id = ?2 AND disabled != ?1")
            .bind(new_val)
            .bind(&id.0)
            .execute(&self.pool)
            .await?;
        if res.rows_affected() > 0 {
            return Ok(true);
        }
        // Either user doesn't exist OR already at target state.
        // Disambiguate with a presence check.
        let exists: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE id = ?1")
            .bind(&id.0)
            .fetch_one(&self.pool)
            .await?;
        if exists.0 == 0 {
            return Err(SqliteInventoryError::Invalid(format!(
                "no such user: {}",
                id.0
            )));
        }
        Ok(false)
    }

    pub async fn set_user_traffic_limit(
        &self,
        id: &UserId,
        limit_bytes: Option<u64>,
        threshold_pct: Option<u8>,
    ) -> Result<()> {
        // Cap threshold_pct at u8 max; SQLite stores as INTEGER so
        // both halves fit comfortably.
        let limit_i64 = limit_bytes.map(|b| i64::try_from(b).unwrap_or(i64::MAX));
        let threshold_i64 = threshold_pct.map(i64::from);
        let res = sqlx::query(
            "UPDATE users
                SET monthly_bandwidth_limit_bytes = ?1,
                    traffic_alert_threshold_pct  = ?2
              WHERE id = ?3",
        )
        .bind(limit_i64)
        .bind(threshold_i64)
        .bind(&id.0)
        .execute(&self.pool)
        .await?;
        if res.rows_affected() == 0 {
            return Err(SqliteInventoryError::Invalid(format!(
                "no such user: {}",
                id.0
            )));
        }
        Ok(())
    }

    /// Read both limit fields for a user. Returns
    /// `(monthly_bandwidth_limit_bytes, traffic_alert_threshold_pct)`
    /// — either or both may be `None` (no limit / use default
    /// threshold). Used by the user-detail page + the daemon-side
    /// alert evaluator.
    pub async fn get_user_traffic_limit(&self, id: &UserId) -> Result<(Option<u64>, Option<u8>)> {
        let row = sqlx::query(
            "SELECT monthly_bandwidth_limit_bytes, traffic_alert_threshold_pct
             FROM users WHERE id = ?1",
        )
        .bind(&id.0)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok((None, None));
        };
        let limit: Option<i64> = row.try_get("monthly_bandwidth_limit_bytes")?;
        let threshold: Option<i64> = row.try_get("traffic_alert_threshold_pct")?;
        let limit_u64 = limit.map(|v| if v < 0 { 0 } else { v as u64 });
        let threshold_u8 = threshold.map(|v| v.clamp(0, 100) as u8);
        Ok((limit_u64, threshold_u8))
    }

    /// Total (upload + download) bytes for a user since the start
    /// of the current calendar month (UTC). `0` when no traffic
    /// has been recorded this month — never errors on "no rows".
    /// SQLite's `strftime('%Y-%m-01T00:00:00Z', 'now')` gives the
    /// month-start anchor; resets automatically on the 1st.
    pub async fn user_traffic_this_month(&self, id: &UserId) -> Result<u64> {
        // Weight each tick's bytes by its server's `usage_coefficient`
        // (Marzban-style per-node traffic multiplier) so traffic on a
        // ×2 node counts double toward the monthly total. The REAL
        // multiply is cast back to INTEGER so the column stays an i64
        // for `try_get` (and the unit stays bytes). Default coeff 1.0
        // (or a NULL via COALESCE) is the identity — pre-existing
        // single-coefficient deployments see no change.
        let row = sqlx::query(
            "SELECT CAST(
                        COALESCE(
                            SUM((s.upload_bytes + s.download_bytes)
                                * COALESCE(sv.usage_coefficient, 1.0)),
                            0
                        ) AS INTEGER
                    ) AS total
             FROM vpn_connection_stats s
             JOIN servers sv ON sv.id = s.server_id
             WHERE s.user_id = ?1
               AND s.ts >= strftime('%Y-%m-01T00:00:00Z', 'now')",
        )
        .bind(&id.0)
        .fetch_one(&self.pool)
        .await?;
        let total: i64 = row.try_get("total")?;
        Ok(total.max(0) as u64)
    }

    /// Aggregate over every user: their month-to-date traffic +
    /// configured limit + configured threshold (or NULLs).
    /// Returns ONLY users who currently have a configured
    /// `monthly_bandwidth_limit_bytes` — operators without a cap
    /// don't need to appear in the dashboard alert section.
    /// Ordered by usage-as-pct-of-limit DESC so the most-at-risk
    /// account is first.
    pub async fn users_traffic_vs_limit(&self) -> Result<Vec<(UserId, u64, u64, u8)>> {
        // The percentage compare is done in Rust because SQLite
        // integer division would truncate to 0 for "5% of 100GB
        // = 5_000_000_000_000 / 100" before SQLite-3.45's bigint
        // arithmetic; safer + clearer in Rust where we already have
        // u64 + f64.
        let rows = sqlx::query(
            "SELECT u.id,
                    COALESCE(u.traffic_alert_threshold_pct, 80) AS threshold,
                    u.monthly_bandwidth_limit_bytes AS lim,
                    CAST(
                        COALESCE(
                            (SELECT SUM((s.upload_bytes + s.download_bytes)
                                        * COALESCE(sv.usage_coefficient, 1.0))
                             FROM vpn_connection_stats s
                             JOIN servers sv ON sv.id = s.server_id
                             WHERE s.user_id = u.id
                               AND s.ts >= strftime('%Y-%m-01T00:00:00Z', 'now')),
                            0
                        ) AS INTEGER
                    ) AS used
             FROM users u
             WHERE u.monthly_bandwidth_limit_bytes IS NOT NULL",
        )
        .fetch_all(&self.pool)
        .await?;
        let mut out: Vec<(UserId, u64, u64, u8)> = Vec::with_capacity(rows.len());
        for r in rows {
            let id: String = r.try_get("id")?;
            let threshold: i64 = r.try_get("threshold")?;
            let lim: i64 = r.try_get("lim")?;
            let used: i64 = r.try_get("used")?;
            let lim_u = lim.max(0) as u64;
            let used_u = used.max(0) as u64;
            let threshold_u = threshold.clamp(0, 100) as u8;
            out.push((UserId(id), used_u, lim_u, threshold_u));
        }
        // Sort by percent-of-limit DESC (most-at-risk first); ties
        // broken by absolute used DESC for stability.
        out.sort_by(|a, b| {
            let pa = if a.2 == 0 {
                0.0
            } else {
                a.1 as f64 / a.2 as f64
            };
            let pb = if b.2 == 0 {
                0.0
            } else {
                b.1 as f64 / b.2 as f64
            };
            pb.partial_cmp(&pa)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| b.1.cmp(&a.1))
        });
        Ok(out)
    }

    /// Top-N users by total (upload + download) bytes over the
    /// look-back window. Used by the dashboard's heavy-user heatmap
    /// to surface abuse-candidate accounts at a glance. Returns
    /// `(user_id, total_bytes)` sorted DESC; rows with NULL user_id
    /// (server-wide aggregates) are excluded.
    ///
    /// Empty Vec when no per-user traffic has been recorded yet (or
    /// when the poller hasn't run). Caller renders an empty-state.
    pub async fn top_users_by_traffic(
        &self,
        since_hours: u32,
        limit: u32,
    ) -> Result<Vec<HeavyUser>> {
        // Weight each row's bytes by the source server's
        // `usage_coefficient` before summing per-user, so a heavy user
        // on a ×2 node ranks above an equal-raw-bytes user on a ×1
        // node. The weighted SUMs are REAL; CAST back to INTEGER so the
        // result columns stay i64 (bytes). 1.0 (or NULL) is the
        // identity → existing rankings unchanged.
        //
        // upload + download are summed SEPARATELY (2026-06-16 — the
        // dashboard tile shows the three-column breakdown). `total` is
        // derived Rust-side as `up + down` so it's exactly consistent
        // with the two columns (independent CASTs could each truncate,
        // leaving `up + down != CAST(SUM(up+down))` by ±1). Ranking
        // still uses the un-CAST combined weighted SUM → identical order
        // to the pre-split query.
        let rows = sqlx::query(
            "SELECT s.user_id AS user_id,
                    CAST(SUM(s.upload_bytes   * COALESCE(sv.usage_coefficient, 1.0)) AS INTEGER) AS up_b,
                    CAST(SUM(s.download_bytes * COALESCE(sv.usage_coefficient, 1.0)) AS INTEGER) AS down_b
             FROM vpn_connection_stats s
             JOIN servers sv ON sv.id = s.server_id
             WHERE s.user_id IS NOT NULL
               AND s.ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1)
             GROUP BY s.user_id
             ORDER BY SUM((s.upload_bytes + s.download_bytes)
                          * COALESCE(sv.usage_coefficient, 1.0)) DESC
             LIMIT ?2",
        )
        .bind(format!("-{since_hours} hours"))
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let uid: String = r.try_get("user_id")?;
            let up = r.try_get::<i64, _>("up_b")?.max(0) as u64;
            let down = r.try_get::<i64, _>("down_b")?.max(0) as u64;
            out.push(HeavyUser {
                user_id: UserId(uid),
                upload_bytes: up,
                download_bytes: down,
                total_bytes: up + down,
            });
        }
        Ok(out)
    }

    // ──────────────────────────────────────────────────────────────────
    // PR-Q — informativeness query layer.
    //
    // Index-backed read aggregates that back the admin-UI dashboard /
    // server-detail / user-detail informativeness cards. Each mirrors an
    // existing method's style; weighting by `usage_coefficient` matches
    // the #41 traffic-accounting convention. None of these mutate — no
    // audit rows. EXPLAIN QUERY PLAN evidence is in the PR description.
    // ──────────────────────────────────────────────────────────────────

    /// **Q-4a** — top traffic users restricted to ONE server. Same
    /// `usage_coefficient`-weighted ranking as `top_users_by_traffic`
    /// (#41 pattern) but with `AND s.server_id = ?`. Backs the
    /// server-detail "heaviest users on this node" card. `user_id IS
    /// NOT NULL` excludes the server-wide rollup rows.
    pub async fn top_users_by_traffic_for_server(
        &self,
        server: &ServerId,
        since_hours: u32,
        limit: u32,
    ) -> Result<Vec<(UserId, u64)>> {
        let rows = sqlx::query(
            "SELECT s.user_id AS user_id,
                    CAST(SUM((s.upload_bytes + s.download_bytes)
                             * COALESCE(sv.usage_coefficient, 1.0)) AS INTEGER) AS total
             FROM vpn_connection_stats s
             JOIN servers sv ON sv.id = s.server_id
             WHERE s.server_id = ?1
               AND s.user_id IS NOT NULL
               AND s.ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)
             GROUP BY s.user_id
             ORDER BY total DESC
             LIMIT ?3",
        )
        .bind(&server.0)
        .bind(format!("-{since_hours} hours"))
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let uid: String = r.try_get("user_id")?;
            let total: i64 = r.try_get("total")?;
            out.push((UserId(uid), total.max(0) as u64));
        }
        Ok(out)
    }

    /// **Q-4b** — one user's traffic broken down per server. Returns
    /// `(server_id, up_bytes, down_bytes)` summed over the window,
    /// `usage_coefficient`-weighted like the other traffic queries.
    /// Backs the user-detail "where this user's traffic lands" card.
    pub async fn user_traffic_by_server(
        &self,
        user: &UserId,
        since_hours: u32,
    ) -> Result<Vec<(ServerId, u64, u64)>> {
        let rows = sqlx::query(
            "SELECT s.server_id AS server_id,
                    CAST(SUM(s.upload_bytes
                             * COALESCE(sv.usage_coefficient, 1.0)) AS INTEGER) AS up_total,
                    CAST(SUM(s.download_bytes
                             * COALESCE(sv.usage_coefficient, 1.0)) AS INTEGER) AS down_total
             FROM vpn_connection_stats s
             JOIN servers sv ON sv.id = s.server_id
             WHERE s.user_id = ?1
               AND s.ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)
             GROUP BY s.server_id
             ORDER BY (up_total + down_total) DESC",
        )
        .bind(&user.0)
        .bind(format!("-{since_hours} hours"))
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let sid: String = r.try_get("server_id")?;
            let up: i64 = r.try_get("up_total")?;
            let down: i64 = r.try_get("down_total")?;
            out.push((ServerId(sid), up.max(0) as u64, down.max(0) as u64));
        }
        Ok(out)
    }

    /// **Q-4c** — audit timeline scoped to one server. Matches rows
    /// where the server is the audit `target` OR where the JSON
    /// `payload` carries a `server_id` field equal to `server_id`
    /// (deploy/grant rows reference the server in the payload, not the
    /// target). Newest-first. Reuses `row_to_audit_entry`.
    pub async fn audit_for_server(&self, server_id: &str, limit: i64) -> Result<Vec<AuditEntry>> {
        let rows = sqlx::query(
            "SELECT id, ts, actor, action, target, payload
             FROM audit_log
             WHERE target = ?1
                OR json_extract(payload, '$.server_id') = ?1
             ORDER BY id DESC
             LIMIT ?2",
        )
        .bind(server_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_audit_entry).collect()
    }

    /// **Q-4d** — user lifecycle facts. `users.created_at` exists
    /// (migration 0001) so this reads it directly + the most recent
    /// real `/sub` fetch, and derives `age_days`. Backs the
    /// user-detail header.
    pub async fn user_lifecycle(&self, user: &UserId) -> Result<UserLifecycle> {
        let row = sqlx::query(
            "SELECT u.created_at AS created_at,
                    (SELECT MAX(ts) FROM sub_access_log
                     WHERE user_id = u.id AND is_vpn_egress = 0) AS last_sub_fetch
             FROM users u
             WHERE u.id = ?1",
        )
        .bind(&user.0)
        .fetch_optional(&self.pool)
        .await?;
        let row =
            row.ok_or_else(|| SqliteInventoryError::Invalid(format!("no such user: {}", user.0)))?;
        let created_s: String = row.try_get("created_at")?;
        let created_at = DateTime::parse_from_rfc3339(&created_s)
            .map(|d| d.with_timezone(&Utc))
            .map_err(|e| {
                SqliteInventoryError::Invalid(format!(
                    "users.created_at malformed: {created_s}: {e}"
                ))
            })?;
        let last_s: Option<String> = row.try_get("last_sub_fetch")?;
        let last_sub_fetch = last_s.and_then(|s| {
            DateTime::parse_from_rfc3339(&s)
                .ok()
                .map(|d| d.with_timezone(&Utc))
        });
        // Floored whole days since creation; never negative (a clock
        // skew that put created_at slightly in the future yields 0).
        let age_days = (Utc::now() - created_at).num_days().max(0) as u64;
        Ok(UserLifecycle {
            created_at,
            last_sub_fetch,
            age_days,
        })
    }

    /// **Q-4e** — newest `kernel_versions_json` per server across the
    /// fleet. Returns the raw JSON string (caller extracts the
    /// `"sing-box"` key); `None` for servers whose latest row predates
    /// version capture or had no versions. Backs the dashboard
    /// kernel-version fleet card. Served by `idx_node_health_server_ts`.
    pub async fn kernel_versions_fleet(&self) -> Result<Vec<(ServerId, Option<String>)>> {
        // Correlated subquery picks the newest ts per server; the outer
        // row then reads that row's JSON. One row per server.
        let rows = sqlx::query(
            "SELECT nh.server_id AS server_id,
                    nh.kernel_versions_json AS kernel_versions_json
             FROM node_health nh
             WHERE nh.ts = (SELECT MAX(nh2.ts)
                            FROM node_health nh2
                            WHERE nh2.server_id = nh.server_id)
             ORDER BY nh.server_id",
        )
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let sid: String = r.try_get("server_id")?;
            let json: Option<String> = r.try_get("kernel_versions_json")?;
            out.push((ServerId(sid), json));
        }
        Ok(out)
    }

    /// **Q-4f** — unacked alerts grouped by `(kind, severity)`. Returns
    /// `(kind, severity, count)`. Backs the dashboard "open alerts by
    /// type" breakdown without pulling every alert row.
    pub async fn alerts_by_kind_severity(&self) -> Result<Vec<(String, String, u64)>> {
        let rows = sqlx::query(
            "SELECT kind, severity, COUNT(*) AS n
             FROM admin_alerts
             WHERE acked_at IS NULL
             GROUP BY kind, severity
             ORDER BY n DESC, kind, severity",
        )
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let kind: String = r.try_get("kind")?;
            let severity: String = r.try_get("severity")?;
            let n: i64 = r.try_get("n")?;
            out.push((kind, severity, n.max(0) as u64));
        }
        Ok(out)
    }

    /// **Q-4g** — "today so far" digest from `audit_log`. Counts rows
    /// since UTC local-midnight, bucketed Rust-side into users added /
    /// grants changed / deploys. Served by `idx_audit_ts`.
    pub async fn today_digest(&self) -> Result<TodayDigest> {
        // `'now','start of day'` is midnight UTC. We bucket Rust-side
        // (rather than three SQL COUNTs) so adding a category later is a
        // match-arm edit, not a new query.
        let rows = sqlx::query(
            "SELECT action, COUNT(*) AS n
             FROM audit_log
             WHERE ts >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', 'start of day')
             GROUP BY action",
        )
        .fetch_all(&self.pool)
        .await?;
        let mut digest = TodayDigest::default();
        for r in rows {
            let action: String = r.try_get("action")?;
            let n: i64 = r.try_get("n")?;
            let n = n.max(0) as u64;
            if action == "user.create" {
                digest.users_added += n;
            } else if action.ends_with(".grant") || action.ends_with(".revoke") {
                digest.grants_changed += n;
            } else if action == "server.deploy" {
                digest.deploys += n;
            }
        }
        Ok(digest)
    }

    /// **Q-4h** — fleet-wide likely-shared-subscription summary. Groups
    /// real (`is_vpn_egress = 0`) `sub_access_log` rows by user and
    /// returns `(user_id, distinct_ips, distinct_asns, distinct_countries)`
    /// for users whose distinct-ASN count is at least `min_asns` — the
    /// "one URL fetched from many networks" signal. Reuses the distinct-
    /// count column logic from `sub_access_aggregates_for_user`. Backs
    /// the dashboard abuse-overview card.
    ///
    /// **abuse-origins fix:** `sub_access_log.user_id` is nullable
    /// (`ON DELETE SET NULL`, migration 0004) — rows from since-deleted
    /// users carry a NULL `user_id` and were silently folded into a
    /// single blank-name group, which the dashboard then rendered as a
    /// nameless row aggregating every deleted user. The
    /// `AND user_id IS NOT NULL AND user_id != ''` predicate drops that
    /// forensic group from this per-user view (the `!= ''` arm is
    /// defensive — no path writes an empty id, but it costs nothing and
    /// guarantees the card never links to `/admin/users/`).
    pub async fn likely_shared_summary(
        &self,
        min_asns: u32,
    ) -> Result<Vec<(UserId, u64, u64, u64)>> {
        // Exclude our own infra IPs (LAN / loopback / server / control)
        // via `real_client_ip_predicate` — otherwise the homelab boxes that
        // fetch many users' subs (192.168.0.200 curl, the monitor) inflate
        // every user's distinct-IP/ASN counts and falsely flag them as
        // "shared". (2026-06-16 — Pavel: «показывает те же цифры».)
        let sql = format!(
            "SELECT user_id,
                    COUNT(DISTINCT ip) AS distinct_ips,
                    COUNT(DISTINCT CASE WHEN geo_asn IS NOT NULL THEN geo_asn END)
                        AS distinct_asns,
                    COUNT(DISTINCT CASE WHEN geo_country IS NOT NULL THEN geo_country END)
                        AS distinct_countries
             FROM sub_access_log
             WHERE is_vpn_egress = 0
               AND {pred}
               AND user_id IS NOT NULL
               AND user_id != ''
             GROUP BY user_id
             HAVING distinct_asns >= ?1
             ORDER BY distinct_asns DESC, distinct_ips DESC",
            pred = real_client_ip_predicate("ip")
        );
        let rows = sqlx::query(&sql)
            .bind(i64::from(min_asns))
            .fetch_all(&self.pool)
            .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let uid: String = r.try_get("user_id")?;
            let ips: i64 = r.try_get("distinct_ips")?;
            let asns: i64 = r.try_get("distinct_asns")?;
            let countries: i64 = r.try_get("distinct_countries")?;
            out.push((
                UserId(uid),
                ips.max(0) as u64,
                asns.max(0) as u64,
                countries.max(0) as u64,
            ));
        }
        Ok(out)
    }

    /// Gather the raw account-sharing signals for EVERY user over the last
    /// `days` days (2026-06-17 — backs the redesigned sharing-risk scorer
    /// that replaces the bare `distinct_asns >= 3` heuristic). Four
    /// index-backed reads, merged in Rust by user_id (fleet scale is tiny):
    /// (1) sub_access diversity — distinct real-client IPs / ASNs / countries
    /// / device-classes; (2) impossible travel — consecutive `/sub` fetches
    /// whose country changed in under `impossible_travel_hours` (two locations
    /// at once); (3) peak concurrent source IPs — the true-simultaneity signal
    /// from `vpn_user_ip_concurrency`; (4) max distinct connect-from IPs in any
    /// single day.
    /// All sub_access/source-IP reads apply `real_client_ip_predicate` so
    /// our own infra never inflates a user's signals.
    pub async fn sharing_signals_all_users(
        &self,
        days: u32,
        impossible_travel_hours: f64,
    ) -> Result<Vec<SharingSignals>> {
        use sqlx::Row;
        use std::collections::HashMap;
        let ts_cut = format!("-{days} days");
        let pred_ip = real_client_ip_predicate("ip");
        let pred_src = real_client_ip_predicate("source_ip");

        let mut acc: HashMap<String, SharingSignals> = HashMap::new();

        // 1 — sub_access diversity.
        let q1 = format!(
            "SELECT user_id,
                    COUNT(DISTINCT ip)            AS d_ips,
                    COUNT(DISTINCT geo_asn)       AS d_asns,
                    COUNT(DISTINCT geo_country)   AS d_countries,
                    COUNT(DISTINCT device_class)  AS d_devcls
             FROM sub_access_log
             WHERE is_vpn_egress = 0 AND {pred_ip}
               AND user_id IS NOT NULL AND user_id != ''
               AND ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1)
             GROUP BY user_id"
        );
        for r in sqlx::query(&q1).bind(&ts_cut).fetch_all(&self.pool).await? {
            let uid: String = r.try_get("user_id")?;
            let s = acc
                .entry(uid.clone())
                .or_insert_with(|| blank_sharing_signals(&uid));
            s.distinct_ips = r.try_get::<i64, _>("d_ips")?.max(0) as u64;
            s.distinct_asns = r.try_get::<i64, _>("d_asns")?.max(0) as u64;
            s.distinct_countries = r.try_get::<i64, _>("d_countries")?.max(0) as u64;
            s.distinct_device_classes = r.try_get::<i64, _>("d_devcls")?.max(0) as u64;
        }

        // 2 — impossible travel (country change between consecutive fetches
        // faster than `impossible_travel_hours`). LAG yields the previous
        // country + ts per user; the delta is computed in the outer query
        // (Debian-12 SQLite 3.40 julianday can't parse the trailing 'Z').
        let q2 = format!(
            "WITH ordered AS (
                SELECT user_id, geo_country AS c, ts,
                       LAG(geo_country) OVER (PARTITION BY user_id ORDER BY ts) AS pc,
                       LAG(ts)          OVER (PARTITION BY user_id ORDER BY ts) AS pts
                FROM sub_access_log
                WHERE is_vpn_egress = 0 AND {pred_ip}
                  AND geo_country IS NOT NULL AND geo_country != ''
                  AND user_id IS NOT NULL AND user_id != ''
                  AND ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1)
             )
             SELECT user_id, COUNT(*) AS hops
             FROM ordered
             WHERE pc IS NOT NULL AND c <> pc
               AND (julianday(replace(ts, 'Z', '')) -
                    julianday(replace(pts, 'Z', ''))) * 24.0 < ?2
             GROUP BY user_id"
        );
        for r in sqlx::query(&q2)
            .bind(&ts_cut)
            .bind(impossible_travel_hours)
            .fetch_all(&self.pool)
            .await?
        {
            let uid: String = r.try_get("user_id")?;
            acc.entry(uid.clone())
                .or_insert_with(|| blank_sharing_signals(&uid))
                .impossible_travel_hops = r.try_get::<i64, _>("hops")?.max(0) as u64;
        }

        // 3 — peak concurrent /24 networks (the poller stores the per-
        // snapshot distinct-/24 count in `peak_concurrent_ips`).
        for r in sqlx::query(
            "SELECT user_id, MAX(peak_concurrent_ips) AS peak
             FROM vpn_user_ip_concurrency
             WHERE date >= strftime('%Y-%m-%d', 'now', ?1)
             GROUP BY user_id",
        )
        .bind(&ts_cut)
        .fetch_all(&self.pool)
        .await?
        {
            let uid: String = r.try_get("user_id")?;
            acc.entry(uid.clone())
                .or_insert_with(|| blank_sharing_signals(&uid))
                .peak_concurrent_nets = r.try_get::<i64, _>("peak")?.max(0) as u32;
        }

        // 4 — max distinct /24 NETWORKS connected from in any single day.
        // Raw (user, date, ip) rows are folded to distinct /24 per day in
        // Rust (a carrier's rotating IPs collapse to a handful of /24s), then
        // MAX'd over the window.
        let q4 = format!(
            "SELECT user_id, date, source_ip
             FROM vpn_user_source_ips
             WHERE date >= strftime('%Y-%m-%d', 'now', ?1) AND {pred_src}"
        );
        let mut per_day_nets: HashMap<(String, String), std::collections::HashSet<String>> =
            HashMap::new();
        for r in sqlx::query(&q4).bind(&ts_cut).fetch_all(&self.pool).await? {
            let uid: String = r.try_get("user_id")?;
            let date: String = r.try_get("date")?;
            let ip: String = r.try_get("source_ip")?;
            per_day_nets
                .entry((uid, date))
                .or_default()
                .insert(ipv4_net24(&ip));
        }
        let mut max_nets: HashMap<String, u32> = HashMap::new();
        for ((uid, _date), nets) in per_day_nets {
            let n = nets.len() as u32;
            let e = max_nets.entry(uid).or_insert(0);
            *e = (*e).max(n);
        }
        for (uid, n) in max_nets {
            acc.entry(uid.clone())
                .or_insert_with(|| blank_sharing_signals(&uid))
                .max_daily_nets = n;
        }

        Ok(acc.into_values().collect())
    }

    // ── abuse-origins: per-user "Subscription origins" breakdown ───────
    //
    // Four grouped, index-backed reads behind the user-detail
    // "Subscription origins" section. Every one scopes to ONE user's
    // real client fetches:
    //   * `user_id = ?1`     — this user only,
    //   * `is_vpn_egress = 0` — exclude rows where the src IP is one of
    //                           our own VPN servers (full-tunnel egress),
    //   * `ts > <days-ago>`   — bound the window.
    // The partial index `idx_sub_access_log_user_id_real (user_id, id DESC)
    // WHERE is_vpn_egress = 0` covers the `user_id = ?1 AND
    // is_vpn_egress = 0` prefix, so SQLite seeks instead of scanning.
    // NULL `user_id` (since-deleted users) is excluded for free by the
    // `user_id = ?1` equality (SQL `=` never matches NULL).

    /// abuse-origins — group this user's real `/sub` fetches by GeoIP
    /// country over the last `days`. One row per distinct `geo_country`
    /// (NULL countries collapse into one `None` group), ordered by fetch
    /// count DESC. Backs the "by country" table of the origins section.
    pub async fn sub_access_by_country(
        &self,
        user: &UserId,
        days: u32,
    ) -> Result<Vec<SubOriginCountry>> {
        let sql = format!(
            "SELECT geo_country AS country,
                    COUNT(*)                                                AS fetches,
                    COUNT(DISTINCT ip)                                      AS ips,
                    COUNT(DISTINCT CASE WHEN geo_asn IS NOT NULL THEN geo_asn END) AS asns
             FROM sub_access_log
             WHERE user_id = ?1
               AND is_vpn_egress = 0
               AND {pred}
               AND ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)
             GROUP BY geo_country
             ORDER BY fetches DESC",
            pred = real_client_ip_predicate("ip")
        );
        let rows = sqlx::query(&sql)
            .bind(&user.0)
            .bind(format!("-{days} days"))
            .fetch_all(&self.pool)
            .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let country: Option<String> = r.try_get("country")?;
            let fetches: i64 = r.try_get("fetches")?;
            let ips: i64 = r.try_get("ips")?;
            let asns: i64 = r.try_get("asns")?;
            out.push(SubOriginCountry {
                country,
                fetches: fetches.max(0) as u64,
                ips: ips.max(0) as u64,
                asns: asns.max(0) as u64,
            });
        }
        Ok(out)
    }

    /// abuse-origins — group this user's real `/sub` fetches by GeoIP
    /// ASN / ISP over the last `days`, returning the top `limit` by fetch
    /// count. `country` is a representative `MAX(geo_country)` for the
    /// group (most ASNs sit in one country). Backs the "by ISP" table.
    pub async fn sub_access_by_asn(
        &self,
        user: &UserId,
        days: u32,
        limit: u32,
    ) -> Result<Vec<SubOriginAsn>> {
        let sql = format!(
            "SELECT geo_asn AS asn,
                    MAX(geo_country)   AS country,
                    COUNT(*)           AS fetches,
                    COUNT(DISTINCT ip) AS ips
             FROM sub_access_log
             WHERE user_id = ?1
               AND is_vpn_egress = 0
               AND {pred}
               AND ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)
             GROUP BY geo_asn
             ORDER BY fetches DESC
             LIMIT ?3",
            pred = real_client_ip_predicate("ip")
        );
        let rows = sqlx::query(&sql)
            .bind(&user.0)
            .bind(format!("-{days} days"))
            .bind(i64::from(limit))
            .fetch_all(&self.pool)
            .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let asn: Option<String> = r.try_get("asn")?;
            let country: Option<String> = r.try_get("country")?;
            let fetches: i64 = r.try_get("fetches")?;
            let ips: i64 = r.try_get("ips")?;
            out.push(SubOriginAsn {
                asn,
                country,
                fetches: fetches.max(0) as u64,
                ips: ips.max(0) as u64,
            });
        }
        Ok(out)
    }

    /// abuse-origins — group this user's real `/sub` fetches by source
    /// IP over the last `days`, returning the top `limit` by most-recent
    /// activity (`MAX(ts)` DESC). `country` / `asn` are the
    /// representative `MAX(…)` for the IP (one IP usually maps to one
    /// network). `first_seen` / `last_seen` are ISO-8601 strings the
    /// renderer reformats via `format_msk_iso`. Backs the "by IP" table.
    pub async fn sub_access_by_ip(
        &self,
        user: &UserId,
        days: u32,
        limit: u32,
    ) -> Result<Vec<SubOriginIp>> {
        let sql = format!(
            "SELECT ip,
                    MAX(geo_country) AS country,
                    MAX(geo_asn)     AS asn,
                    COUNT(*)         AS fetches,
                    MIN(ts)          AS first_seen,
                    MAX(ts)          AS last_seen
             FROM sub_access_log
             WHERE user_id = ?1
               AND is_vpn_egress = 0
               AND {pred}
               AND ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)
             GROUP BY ip
             ORDER BY last_seen DESC
             LIMIT ?3",
            pred = real_client_ip_predicate("ip")
        );
        let rows = sqlx::query(&sql)
            .bind(&user.0)
            .bind(format!("-{days} days"))
            .bind(i64::from(limit))
            .fetch_all(&self.pool)
            .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let ip: String = r.try_get("ip")?;
            let country: Option<String> = r.try_get("country")?;
            let asn: Option<String> = r.try_get("asn")?;
            let fetches: i64 = r.try_get("fetches")?;
            let first_seen: String = r.try_get("first_seen")?;
            let last_seen: String = r.try_get("last_seen")?;
            out.push(SubOriginIp {
                ip,
                country,
                asn,
                fetches: fetches.max(0) as u64,
                first_seen,
                last_seen,
            });
        }
        Ok(out)
    }

    /// abuse-origins — rough distinct-device proxy for this user over the
    /// last `days`. Counts `DISTINCT` non-NULL `device_class`, `tls_ja4`,
    /// and `ua` across the user's real (`is_vpn_egress = 0`) rows. A
    /// distinct-device count well above a household's device count is a
    /// sharing signal. One round-trip, all three counts in one row.
    pub async fn sub_access_device_fingerprint(
        &self,
        user: &UserId,
        days: u32,
    ) -> Result<SubDeviceFp> {
        let row = sqlx::query(
            "SELECT
                COUNT(DISTINCT device_class) AS distinct_device_classes,
                COUNT(DISTINCT tls_ja4)      AS distinct_ja4,
                COUNT(DISTINCT ua)           AS distinct_uas
             FROM sub_access_log
             WHERE user_id = ?1
               AND is_vpn_egress = 0
               AND ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)",
        )
        .bind(&user.0)
        .bind(format!("-{days} days"))
        .fetch_one(&self.pool)
        .await?;
        // `COUNT(DISTINCT col)` already ignores NULLs in SQLite, so a
        // user whose rows have NULL device_class / ja4 contributes 0
        // there — exactly the "unknown, don't claim a device" semantics
        // we want.
        let distinct_device_classes: i64 = row.try_get("distinct_device_classes")?;
        let distinct_ja4: i64 = row.try_get("distinct_ja4")?;
        let distinct_uas: i64 = row.try_get("distinct_uas")?;
        Ok(SubDeviceFp {
            distinct_device_classes: distinct_device_classes.max(0) as u64,
            distinct_ja4: distinct_ja4.max(0) as u64,
            distinct_uas: distinct_uas.max(0) as u64,
        })
    }

    /// Recent server-wide + per-user rows for one server in the
    /// look-back window. Newest-first. The server-detail UI uses
    /// the `user_id IS NULL` rows for the bandwidth sparkline and
    /// the rest for the per-user breakdown.
    pub async fn recent_vpn_stats_for_server(
        &self,
        server_id: &ServerId,
        since_hours: u32,
    ) -> Result<Vec<VpnStatsRow>> {
        let rows = sqlx::query(
            "SELECT ts, server_id, user_id, upload_bytes, download_bytes, active_connections
             FROM vpn_connection_stats
             WHERE server_id = ?1
               AND ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)
             ORDER BY ts DESC",
        )
        .bind(&server_id.0)
        .bind(format!("-{since_hours} hours"))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_vpn_stats).collect()
    }

    /// Detect per-user attribution STALL per server (2026-06-14 — backs the
    /// `server.attribution.stalled` health alert). A server is "stalled"
    /// when, over the recent window, it has live connections (server-wide
    /// rows show `active_connections >= min_active`) but ZERO distinct
    /// attributed users — the clash poll lands server-wide totals while the
    /// sing-box log scrape attributed nobody. This is the signature of an
    /// orphaned sing-box log fd (live log 0-byte) or a persistently failing
    /// scrape — exactly the silent break that hit prod twice (logrotate
    /// orphan, then the `install /dev/null` ensure_installed orphan).
    ///
    /// `window_minutes` spans multiple poll ticks so the transient one-tick
    /// blip right after a sing-box restart does NOT flag. Index-backed by
    /// `idx_vcs_ts` (ts range) + a small GROUP BY.
    pub async fn attribution_stall_servers(
        &self,
        window_minutes: u32,
        min_active: u32,
    ) -> Result<Vec<ServerId>> {
        use sqlx::Row;
        let rows = sqlx::query(
            "SELECT server_id
             FROM vpn_connection_stats
             WHERE ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1)
             GROUP BY server_id
             HAVING MAX(active_connections) >= ?2
                AND COUNT(DISTINCT CASE WHEN user_id IS NOT NULL THEN user_id END) = 0",
        )
        .bind(format!("-{window_minutes} minutes"))
        .bind(i64::from(min_active))
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| ServerId(r.get::<String, _>("server_id")))
            .collect())
    }

    /// Users whose freshly-fetched subscription produced no traffic
    /// (2026-06-16 — backs `health_monitor::check_sub_fetch_without_traffic`).
    ///
    /// Returns previously-active users (had attributed traffic within
    /// `active_days` BEFORE the fetch) whose MOST-RECENT real `/sub` fetch is
    /// between `grace_minutes` and `lookback_minutes` ago AND who have had
    /// ZERO attributed traffic SINCE that fetch. This is the silent signature
    /// of a subscription whose issued config no longer dials (the `fp=chrome`
    /// DPI breakage, a protocol-visibility regression, a broken share-link):
    /// the client re-imports and then never connects, with no server error.
    ///
    /// - `grace_minutes`: a just-fetched user is still importing/setting up;
    ///   don't flag until the fetch is at least this old (no traffic by now is
    ///   the real signal, not impatience).
    /// - `lookback_minutes`: only RECENT re-imports are actionable; also
    ///   bounds how long a never-recovering user keeps re-firing.
    /// - `active_days`: the "was working before" gate — restricts to a
    ///   regression (a known-good user broke), not a brand-new user who never
    ///   connected (their failure is a setup problem, not our regression).
    ///
    /// `julianday(replace(t,'Z',''))` strips the trailing `Z` because the
    /// Debian-12 SQLite (3.40) predates 3.42's native `Z` parsing — without
    /// it `julianday` returns NULL and `fetch_age_minutes` is bogus. The
    /// window-boundary comparisons stay as lexicographic string `<=`/`>=`
    /// against `strftime(...Z)` output, matching every other query here.
    pub async fn sub_fetch_without_traffic_users(
        &self,
        grace_minutes: u32,
        lookback_minutes: u32,
        active_days: u32,
    ) -> Result<Vec<SubFetchStallUser>> {
        use sqlx::Row;
        let rows = sqlx::query(
            "WITH last_fetch AS (
                 SELECT user_id, MAX(ts) AS t
                 FROM sub_access_log
                 WHERE user_id IS NOT NULL AND is_vpn_egress = 0 AND status = 200
                 GROUP BY user_id
             )
             SELECT lf.user_id AS user_id,
                    lf.t        AS last_fetch,
                    (SELECT MAX(c.ts) FROM vpn_connection_stats c
                       WHERE c.user_id = lf.user_id
                         AND (c.upload_bytes > 0 OR c.download_bytes > 0)) AS last_traffic,
                    CAST((julianday('now') - julianday(replace(lf.t, 'Z', ''))) * 24 * 60
                         AS INTEGER) AS age_min
             FROM last_fetch lf
             WHERE lf.t <= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1)
               AND lf.t >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)
               AND NOT EXISTS (
                   SELECT 1 FROM vpn_connection_stats c
                   WHERE c.user_id = lf.user_id AND c.ts >= lf.t
                     AND (c.upload_bytes > 0 OR c.download_bytes > 0))
               AND EXISTS (
                   SELECT 1 FROM vpn_connection_stats c2
                   WHERE c2.user_id = lf.user_id
                     AND c2.ts >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?3)
                     AND c2.ts < lf.t
                     AND (c2.upload_bytes > 0 OR c2.download_bytes > 0))
             ORDER BY lf.t ASC",
        )
        .bind(format!("-{grace_minutes} minutes"))
        .bind(format!("-{lookback_minutes} minutes"))
        .bind(format!("-{active_days} days"))
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| SubFetchStallUser {
                user_id: UserId(r.get::<String, _>("user_id")),
                last_fetch: r.get::<String, _>("last_fetch"),
                last_traffic: r.get::<Option<String>, _>("last_traffic"),
                fetch_age_minutes: r.get::<i64, _>("age_min"),
            })
            .collect())
    }

    /// Distinct subject ids carried in the `kind` suffix of currently-OPEN
    /// (`acked_at IS NULL`) `admin_alerts` whose kind starts with `prefix`.
    /// Backs the per-user fire/resolve loops (kind shape
    /// `user.sub_no_traffic:<id>`): the caller fires for users in violation
    /// and acks the open alerts whose subject is no longer in that set.
    /// Returns the part AFTER `prefix` (the bare id).
    ///
    /// Matched with `substr(kind,1,len) = prefix` rather than `LIKE prefix||'%'`
    /// because the prefix contains `_`, a LIKE single-char wildcard — an exact
    /// substr compare avoids accidental over-matching.
    pub async fn open_alert_subjects_with_kind_prefix(&self, prefix: &str) -> Result<Vec<String>> {
        use sqlx::Row;
        let plen = i64::try_from(prefix.chars().count()).unwrap_or(0);
        let rows = sqlx::query(
            "SELECT DISTINCT substr(kind, ?1 + 1) AS subject
             FROM admin_alerts
             WHERE acked_at IS NULL AND substr(kind, 1, ?1) = ?2",
        )
        .bind(plen)
        .bind(prefix)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| r.get::<String, _>("subject"))
            .collect())
    }

    /// **Fleet-wide raw stats** (2026-05-23 — backs the dashboard's
    /// multi-window traffic chart). Same row shape as the per-
    /// server/per-user variants but with no `WHERE` filter on the
    /// subject — every server's every user's row in the window
    /// returned, then the caller buckets / aggregates as it sees
    /// fit.
    ///
    /// **Cardinality note:** at 5-min tick × N users × M servers,
    /// the 30d window can pull ~864k rows for a 10-server, 100-user
    /// fleet. Homelab scale (3 servers, 35 users) is comfortable
    /// (~100k rows max at 30d, ~17 MB serialised) but a future
    /// productisation should add a server-side bucket aggregate
    /// helper. For now the chart aggregation runs Rust-side in
    /// the daemon and the caller never paginates.
    pub async fn recent_vpn_stats_fleet(&self, since_hours: u32) -> Result<Vec<VpnStatsRow>> {
        let rows = sqlx::query(
            "SELECT ts, server_id, user_id, upload_bytes, download_bytes, active_connections
             FROM vpn_connection_stats
             WHERE ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1)
             ORDER BY ts DESC",
        )
        .bind(format!("-{since_hours} hours"))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_vpn_stats).collect()
    }

    /// Phase 4b — single-query rollup of server-wide live activity
    /// for the server-detail tile + dashboard aggregate. Uses
    /// server-wide rows (user_id IS NULL) for the «active now»
    /// counter (clash-api per-tick `active_connections` value) and
    /// sums every row (per-user + server-wide) for the bytes-in-
    /// window counters. `distinct_users_attributed` reports how
    /// many per-user rows landed in the window — meaningful only
    /// AFTER the NM-11 sing-box upstream fix; today the operator
    /// sees `0` and the user-detail's «Live VPN stats» empty-
    /// state explains why.
    pub async fn server_live_activity(
        &self,
        server_id: &ServerId,
        since_hours: u32,
    ) -> Result<ServerLiveActivity> {
        let since = format!("-{since_hours} hours");
        // Single SELECT (Phase 4b post-review fix #2): the previous
        // two-query version had a race where a poller insert
        // between aggregates and «latest active» queries could
        // produce an `active_now` from a tick newer than
        // `last_sample_ts`. SQLite WITH clause holds the row set
        // for both correlated reads in one snapshot.
        let row = sqlx::query(
            "WITH win AS (
                SELECT upload_bytes, download_bytes, ts, user_id, active_connections
                FROM vpn_connection_stats
                WHERE server_id = ?1
                  AND ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)
            )
            SELECT
                COALESCE((SELECT SUM(upload_bytes)   FROM win), 0) AS bytes_up,
                COALESCE((SELECT SUM(download_bytes) FROM win), 0) AS bytes_dn,
                (SELECT MAX(ts) FROM win)                           AS last_ts,
                (SELECT COUNT(DISTINCT user_id) FROM win WHERE user_id IS NOT NULL) AS attributed,
                (SELECT active_connections FROM vpn_connection_stats
                 WHERE server_id = ?1 AND user_id IS NULL
                 ORDER BY ts DESC LIMIT 1)                          AS active_now",
        )
        .bind(&server_id.0)
        .bind(&since)
        .fetch_one(&self.pool)
        .await?;

        let bytes_up: i64 = row.try_get("bytes_up")?;
        let bytes_dn: i64 = row.try_get("bytes_dn")?;
        let last_ts_s: Option<String> = row.try_get("last_ts")?;
        let attributed: i64 = row.try_get("attributed")?;
        let active_now_opt: Option<i64> = row.try_get("active_now")?;
        let active_now: u32 = match active_now_opt {
            Some(v) => u32::try_from(v.max(0)).unwrap_or(u32::MAX),
            None => 0,
        };

        Ok(ServerLiveActivity {
            active_now,
            bytes_up_window: bytes_up.max(0) as u64,
            bytes_dn_window: bytes_dn.max(0) as u64,
            last_sample_ts: last_ts_s.and_then(|t| {
                DateTime::parse_from_rfc3339(&t)
                    .ok()
                    .map(|d| d.with_timezone(&Utc))
            }),
            distinct_users_attributed: u32::try_from(attributed.max(0)).unwrap_or(u32::MAX),
        })
    }

    /// Phase 4c — given a list of source IPs (from a clash-api
    /// snapshot's `metadata.sourceIP` fields), find for each IP the
    /// most-likely `user_id` by counting hits in `sub_access_log`
    /// over the look-back window. Returns a map `source_ip ->
    /// Vec<(user_id, hit_count)>` sorted DESC by hit count, so the
    /// top entry is the most plausible owner. Empty Vec means no
    /// user has hit subscription URL from that IP in the window.
    ///
    /// Why this works despite NM-11: sing-box's clash-api still
    /// emits `sourceIP` (real public IP of client behind VLESS/TUIC
    /// auth). vpnctld's `sub_access_log.ip` also stores the real
    /// client IP for every `/api/v1/app/config/<device>` and
    /// `/sub/<token>` request. The intersection identifies «whose
    /// devices are talking from that IP right now» without sing-box
    /// needing to emit the `user` field. False positives possible
    /// (NAT collision: two real users behind one CGNAT IP), so the
    /// UI labels this «likely» not «is».
    ///
    /// Bounded by `ips.len()` * `look_back_days` rows of
    /// sub_access_log — single GROUP BY query with `WHERE ip IN
    /// (?, ?, ?, …)`. Skips VPN-egress rows (is_vpn_egress = 0)
    /// because those are our own server IPs, not real clients.
    pub async fn users_for_source_ips(
        &self,
        ips: &[String],
        look_back_days: u32,
    ) -> Result<std::collections::HashMap<String, Vec<(UserId, u64)>>> {
        use std::collections::HashMap;
        if ips.is_empty() {
            return Ok(HashMap::new());
        }
        // Build the IN-clause placeholders dynamically (sqlx doesn't
        // support `IN (?)` with an array binding). Safe because
        // every `?` gets a single string bind; no string interp of
        // user-controlled data into the SQL itself.
        let placeholders = std::iter::repeat_n("?", ips.len())
            .collect::<Vec<_>>()
            .join(",");
        // `is_vpn_egress = 0` already drops VPN-server-IP fetches, but the
        // homelab LAN + control egress (192.168.0.x, 83.97.108.34, …) are
        // is_vpn_egress=0, so exclude them via `real_client_ip_predicate` —
        // otherwise every user we test/monitor from those IPs looks like
        // they "share" the IP.
        let sql = format!(
            "SELECT ip, user_id, COUNT(*) AS hits
             FROM sub_access_log
             WHERE ip IN ({placeholders})
               AND is_vpn_egress = 0
               AND {pred}
               AND user_id IS NOT NULL
               AND ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)
             GROUP BY ip, user_id
             ORDER BY ip, hits DESC",
            pred = real_client_ip_predicate("ip")
        );
        let cutoff = format!("-{look_back_days} days");
        let mut q = sqlx::query(&sql);
        for ip in ips {
            q = q.bind(ip);
        }
        q = q.bind(&cutoff);
        let rows = q.fetch_all(&self.pool).await?;
        let mut out: HashMap<String, Vec<(UserId, u64)>> = HashMap::new();
        for r in rows {
            let ip: String = r.try_get("ip")?;
            let uid: String = r.try_get("user_id")?;
            let hits: i64 = r.try_get("hits")?;
            out.entry(ip)
                .or_default()
                .push((UserId(uid), hits.max(0) as u64));
        }
        Ok(out)
    }

    /// Phase 4b — dashboard rollup across every known server.
    /// Returns one `ServerLiveActivity` per `servers.id` (even for
    /// servers the poller never reached — they get the default-
    /// zeroed struct). Caller iterates + sums for the global
    /// dashboard KPI; the per-server map is also available for a
    /// «which server is busy» breakdown.
    pub async fn all_servers_live_activity(
        &self,
        since_hours: u32,
    ) -> Result<Vec<(ServerId, ServerLiveActivity)>> {
        // Returns a Vec keyed by ServerId — Vec rather than
        // HashMap/BTreeMap because the dashboard renderer iterates
        // in insertion order anyway, and the `SELECT … ORDER BY id`
        // below pre-sorts the keys alphabetically, so a Vec is the
        // simplest container that preserves that order at the
        // render site.
        let server_ids = sqlx::query("SELECT id FROM servers ORDER BY id")
            .fetch_all(&self.pool)
            .await?;
        let mut out = Vec::with_capacity(server_ids.len());
        for r in server_ids {
            let id: String = r.try_get("id")?;
            let sid = ServerId(id);
            let activity = self.server_live_activity(&sid, since_hours).await?;
            out.push((sid, activity));
        }
        Ok(out)
    }

    /// Drop rows older than `days`. Mirrors `purge_sub_access_older_than`
    /// — chunk 3 will wire this into the existing retention scheduler.
    pub async fn purge_vpn_stats_older_than(&self, days: u32) -> Result<u64> {
        let res = sqlx::query(
            "DELETE FROM vpn_connection_stats
             WHERE ts < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1)",
        )
        .bind(format!("-{days} days"))
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    // ──────────────────────────────────────────────────────────────────
    // Phase 5a-1 — daily per-user rollups for long-term retention.
    //
    // `vpn_connection_stats` is rolling 30-day raw 5-min ticks.
    // `vpn_user_daily` is the daily aggregate that lives indefinitely
    // (one row per (user, server, date), ~36k rows/year at 33 users
    // × 3 servers = trivial SQLite scale).
    //
    // Rollup pattern: each call to `rollup_vpn_user_daily` re-computes
    // the totals for ONE date from `vpn_connection_stats` rows in that
    // date's window and UPSERT-overwrites the matching `vpn_user_daily`
    // rows. Idempotent — running it twice on the same date yields the
    // same data. The hourly rollup scheduler (in `daemon/src/app.rs`)
    // re-rolls TODAY + YESTERDAY each tick so we capture late-arriving
    // ticks across midnight UTC.
    // ──────────────────────────────────────────────────────────────────

    /// Re-compute and UPSERT all `(user, server)` daily rollup rows
    /// for `date_utc` (format `YYYY-MM-DD`). Reads from
    /// `vpn_connection_stats` where `user_id IS NOT NULL` AND the
    /// ts falls within the date's 00:00–24:00 UTC window. Returns
    /// the number of UPSERTed rows.
    ///
    /// Safe to call concurrently for different dates; same-date
    /// concurrent calls race on the UPSERT but the last writer wins
    /// idempotently (deterministic sum).
    pub async fn rollup_vpn_user_daily(&self, date_utc: &str) -> Result<u64> {
        // Derive the 24h window from the date string. SQLite's
        // strftime returns `YYYY-MM-DDTHH:MM:SS.fffZ` form — match
        // that to `ts` shape used by `vpn_connection_stats` rows.
        let lower = format!("{date_utc}T00:00:00.000Z");
        let upper = format!("{date_utc}T23:59:59.999Z");

        // Aggregate raw ticks into per-(user, server) sums. Server-
        // wide rows (user_id IS NULL) are excluded — they belong
        // to a future server-wide rollup if/when we add one.
        let rows = sqlx::query(
            "SELECT
                user_id,
                server_id,
                COALESCE(SUM(upload_bytes), 0)        AS up_total,
                COALESCE(SUM(download_bytes), 0)      AS dn_total,
                COALESCE(MAX(active_connections), 0)  AS peak_conns
             FROM vpn_connection_stats
             WHERE user_id IS NOT NULL
               AND ts >= ?1
               AND ts <= ?2
             GROUP BY user_id, server_id",
        )
        .bind(&lower)
        .bind(&upper)
        .fetch_all(&self.pool)
        .await?;

        let mut tx = self.pool.begin().await?;
        let mut upserted: u64 = 0;
        for r in rows {
            let user_id: String = r.try_get("user_id")?;
            let server_id: String = r.try_get("server_id")?;
            let up_total: i64 = r.try_get("up_total")?;
            let dn_total: i64 = r.try_get("dn_total")?;
            let peak_conns: i64 = r.try_get("peak_conns")?;
            // distinct_source_ips currently not derivable from
            // vpn_connection_stats (which doesn't carry source IP)
            // — left at 0 for now. Phase 5b's destinations table
            // is where source-IP-diversity lives.
            let res = sqlx::query(
                "INSERT INTO vpn_user_daily
                    (date, user_id, server_id, upload_bytes,
                     download_bytes, active_connections_peak,
                     distinct_source_ips, last_rolled_up_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0,
                     strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
                 ON CONFLICT(user_id, server_id, date) DO UPDATE SET
                     upload_bytes              = excluded.upload_bytes,
                     download_bytes            = excluded.download_bytes,
                     active_connections_peak   = excluded.active_connections_peak,
                     last_rolled_up_at         = excluded.last_rolled_up_at",
            )
            .bind(date_utc)
            .bind(&user_id)
            .bind(&server_id)
            .bind(up_total.max(0))
            .bind(dn_total.max(0))
            .bind(peak_conns.max(0))
            .execute(&mut *tx)
            .await?;
            upserted = upserted.saturating_add(res.rows_affected());
        }
        tx.commit().await?;
        Ok(upserted)
    }

    /// Daily rollup rows for ONE user across the last N days.
    /// Newest-first. Used by the user-detail analytics section.
    pub async fn vpn_user_daily_for_user(
        &self,
        user_id: &UserId,
        days: u32,
    ) -> Result<Vec<VpnUserDailyRow>> {
        let cutoff = format!("-{days} days");
        let rows = sqlx::query(
            "SELECT date, user_id, server_id, upload_bytes,
                    download_bytes, active_connections_peak,
                    distinct_source_ips
             FROM vpn_user_daily
             WHERE user_id = ?1
               AND date >= strftime('%Y-%m-%d', 'now', ?2)
             ORDER BY date DESC, server_id",
        )
        .bind(&user_id.0)
        .bind(&cutoff)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_vpn_user_daily).collect()
    }

    /// Top-N users by daily-total traffic across `days`. Used by
    /// the dashboard «Heavy users» tile (now actually populated
    /// post-Phase-4e+5a-1, where the old `top_users_by_traffic`
    /// returned empty because of NM-11). Sums upload+download
    /// across all servers per user.
    pub async fn top_users_by_daily_traffic(
        &self,
        days: u32,
        limit: u32,
    ) -> Result<Vec<(UserId, u64)>> {
        let cutoff = format!("-{days} days");
        // Weight each daily row by its server's `usage_coefficient`
        // before the per-user sum, mirroring the raw-tick path so the
        // heavy-users ranking is consistent whichever table feeds it.
        // REAL product is CAST back to INTEGER (bytes, i64). 1.0/NULL
        // is the identity.
        let rows = sqlx::query(
            "SELECT d.user_id AS user_id,
                    CAST(
                        COALESCE(SUM((d.upload_bytes + d.download_bytes)
                                     * COALESCE(sv.usage_coefficient, 1.0)), 0)
                        AS INTEGER
                    ) AS total
             FROM vpn_user_daily d
             JOIN servers sv ON sv.id = d.server_id
             WHERE d.date >= strftime('%Y-%m-%d', 'now', ?1)
             GROUP BY d.user_id
             ORDER BY total DESC
             LIMIT ?2",
        )
        .bind(&cutoff)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let uid: String = r.try_get("user_id")?;
            let total: i64 = r.try_get("total")?;
            out.push((UserId(uid), total.max(0) as u64));
        }
        Ok(out)
    }

    /// Month-to-date total for one user across all servers. Used
    /// for traffic-limit alerts (`users.monthly_bandwidth_limit_bytes`).
    /// Post-Phase-5a-1 this replaces the old NULL-returning
    /// `user_traffic_this_month` for production use.
    pub async fn user_traffic_this_month_from_daily(&self, id: &UserId) -> Result<u64> {
        let row = sqlx::query(
            "SELECT COALESCE(SUM(upload_bytes + download_bytes), 0) AS total
             FROM vpn_user_daily
             WHERE user_id = ?1
               AND date >= strftime('%Y-%m-01', 'now')",
        )
        .bind(&id.0)
        .fetch_one(&self.pool)
        .await?;
        let total: i64 = row.try_get("total")?;
        Ok(total.max(0) as u64)
    }

    // ──────────────────────────────────────────────────────────────────
    // Phase 5c — per-user session windows.
    //
    // Session model: a tick observation of (user, server) either
    // EXTENDS the most-recent OPEN session for that pair (if the
    // gap since its `last_seen` is ≤ SESSION_GAP_MINUTES = 15),
    // or OPENS a new session row. Sessions are never explicitly
    // closed — they just stop being extended; old ones get
    // displayed with `last_seen < now - 15min`.
    // ──────────────────────────────────────────────────────────────────

    /// Either extend the currently-open session for (user, server)
    /// or open a new one, based on the time-since-last_seen vs
    /// the `gap_minutes` budget. Returns the session id touched
    /// for testability.
    ///
    /// `now` is passed in so tests can stub time; production code
    /// passes `Utc::now()`. `bytes_delta` and `conn_count` are
    /// added/maxed into the session's running totals.
    pub async fn session_observe(
        &self,
        user_id: &UserId,
        server_id: &ServerId,
        now: DateTime<Utc>,
        gap_minutes: i64,
        bytes_delta: u64,
        conn_count: u32,
    ) -> Result<i64> {
        // Look up the most-recent session for this (user, server).
        let cutoff = now - chrono::Duration::minutes(gap_minutes);
        let cutoff_s = cutoff.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        let now_s = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        let maybe_existing: Option<(i64, i64, i64)> = sqlx::query(
            "SELECT id, total_bytes, conn_count_peak
             FROM vpn_user_sessions
             WHERE user_id = ?1 AND server_id = ?2 AND last_seen >= ?3
             ORDER BY last_seen DESC
             LIMIT 1",
        )
        .bind(&user_id.0)
        .bind(&server_id.0)
        .bind(&cutoff_s)
        .fetch_optional(&self.pool)
        .await?
        .map(|r| {
            (
                r.try_get::<i64, _>("id").unwrap_or(0),
                r.try_get::<i64, _>("total_bytes").unwrap_or(0),
                r.try_get::<i64, _>("conn_count_peak").unwrap_or(0),
            )
        });

        if let Some((existing_id, prev_bytes, prev_peak)) = maybe_existing {
            let new_bytes = (prev_bytes.max(0) as u64).saturating_add(bytes_delta);
            let new_peak = (prev_peak.max(0) as u32).max(conn_count);
            sqlx::query(
                "UPDATE vpn_user_sessions
                 SET last_seen = ?1, total_bytes = ?2, conn_count_peak = ?3
                 WHERE id = ?4",
            )
            .bind(&now_s)
            .bind(i64::try_from(new_bytes).unwrap_or(i64::MAX))
            .bind(i64::from(new_peak))
            .bind(existing_id)
            .execute(&self.pool)
            .await?;
            Ok(existing_id)
        } else {
            // Gate the INSERT on user existence, SQL-side (mirrors the
            // #32 fix in `record_user_destinations`). `user_id` comes from
            // the log-scrape attribution map (a raw username), NOT
            // validated against `users`. `vpn_user_sessions.user_id` is
            // NOT NULL REFERENCES users(id); with `foreign_keys=ON` an
            // INSERT for a since-deleted user raises FK error 787. The
            // caller loops per-user and logs+continues, so it's currently
            // non-fatal, but it spams the warn-log every tick until the
            // stale user ages out of the scrape. `INSERT … SELECT …
            // WHERE EXISTS (… users …)` skips the unknown user cleanly:
            // 0 rows inserted, no FK error, no log noise.
            let res = sqlx::query(
                "INSERT INTO vpn_user_sessions
                    (user_id, server_id, started_at, last_seen, conn_count_peak, total_bytes)
                 SELECT ?1, ?2, ?3, ?3, ?4, ?5
                 WHERE EXISTS (SELECT 1 FROM users WHERE id = ?1)",
            )
            .bind(&user_id.0)
            .bind(&server_id.0)
            .bind(&now_s)
            .bind(i64::from(conn_count))
            .bind(i64::try_from(bytes_delta).unwrap_or(i64::MAX))
            .execute(&self.pool)
            .await?;
            // 0 rows ⇒ unknown user, nothing inserted. Return 0 rather
            // than `last_insert_rowid()`, which would otherwise echo a
            // stale rowid from an earlier insert on this connection.
            if res.rows_affected() == 0 {
                Ok(0)
            } else {
                Ok(res.last_insert_rowid())
            }
        }
    }

    /// Recent sessions for one user, newest-first. Used by the
    /// user-detail «sessions timeline» on /admin/users/<id>.
    pub async fn recent_sessions_for_user(
        &self,
        user_id: &UserId,
        limit: i64,
    ) -> Result<Vec<VpnUserSessionRow>> {
        let rows = sqlx::query(
            "SELECT id, user_id, server_id, started_at, last_seen,
                    conn_count_peak, total_bytes
             FROM vpn_user_sessions
             WHERE user_id = ?1
             ORDER BY started_at DESC
             LIMIT ?2",
        )
        .bind(&user_id.0)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_user_session).collect()
    }

    /// Purge sessions older than `days`. Wired into the hourly
    /// retention task at the standard 30-day default.
    pub async fn purge_user_sessions_older_than(&self, days: u32) -> Result<u64> {
        let res = sqlx::query(
            "DELETE FROM vpn_user_sessions
             WHERE started_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1)",
        )
        .bind(format!("-{days} days"))
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    // ──────────────────────────────────────────────────────────────────
    // Phase 5b — per-user × destination tracking.
    // ──────────────────────────────────────────────────────────────────

    /// Bulk-record (user, destination_label) pairs observed in
    /// the current clash-poll tick. Each call atomically UPSERTs
    /// per-pair rows for TODAY's UTC date — hit_count += 1,
    /// last_seen = now. Pairs are de-duplicated by the caller
    /// before passing in (one tick contributes ONE hit per pair,
    /// regardless of how many connections share the (user, dest)).
    pub async fn record_user_destinations(&self, pairs: &[(UserId, String)]) -> Result<()> {
        if pairs.is_empty() {
            return Ok(());
        }
        let mut tx = self.pool.begin().await?;
        for (user_id, dest) in pairs {
            // Bound destination label to 200 chars (pathological
            // hostnames don't blow up the row). Truncate on a CHAR
            // boundary — `&dest[..200]` panics if byte 200 lands
            // mid-codepoint (Cyrillic / emoji / IDN-as-UTF-8 SNI/Host
            // labels), and that panic propagates uncaught all the way
            // up `clash_poller::poll_one_server`, permanently aborting
            // the whole poll task. `.chars().take(200)` is the repo
            // idiom (cf. `daemon/src/handlers/sub.rs` accept_language)
            // and is byte-identical to the old slice for ASCII.
            let dest_truncated: String = dest.chars().take(200).collect();
            // Pre-filter to existing users, SQL-side. The `user_id`
            // comes from the log-scrape attribution map (a raw
            // username), NOT validated against `users`. With
            // `foreign_keys=ON` and the NOT NULL REFERENCES users(id)
            // FK, an insert for a since-deleted user raises an FK error
            // (code 787) that, under `?`, rolls back the WHOLE tx —
            // losing EVERY user's destinations for this tick (one stale
            // user poisons all, every tick, until it ages out of the
            // logs). `INSERT OR IGNORE` does NOT help here: the IGNORE
            // conflict algorithm does not suppress FK violations
            // (verified empirically against sqlx). So we gate the
            // insert on `WHERE EXISTS (… users …)` — the row for an
            // unknown user is simply not inserted, the statement
            // succeeds (0 rows affected), and the batch continues. The
            // `INSERT … SELECT … WHERE EXISTS` form still drives the
            // upsert: the SELECT yields the row only when the user
            // exists, and the ON CONFLICT clause then handles the
            // (user, dest, date) UNIQUE collision exactly as before.
            sqlx::query(
                "INSERT INTO vpn_user_destinations
                    (user_id, destination_label, date, hit_count, last_seen)
                 SELECT ?1, ?2, strftime('%Y-%m-%d', 'now'), 1,
                        strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE EXISTS (SELECT 1 FROM users WHERE id = ?1)
                 ON CONFLICT(user_id, destination_label, date) DO UPDATE SET
                     hit_count = hit_count + 1,
                     last_seen = excluded.last_seen",
            )
            .bind(&user_id.0)
            .bind(&dest_truncated)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Top destinations for one user across the last `days`
    /// days, sorted by total hits DESC. Used by the user-detail
    /// «куда ходит этот юзер» section.
    pub async fn top_destinations_for_user(
        &self,
        user_id: &UserId,
        days: u32,
        limit: u32,
    ) -> Result<Vec<VpnUserDestinationRow>> {
        let cutoff = format!("-{days} days");
        let rows = sqlx::query(
            "SELECT user_id, destination_label, date, hit_count, last_seen
             FROM (
                SELECT user_id, destination_label,
                       MAX(date)        AS date,
                       SUM(hit_count)   AS hit_count,
                       MAX(last_seen)   AS last_seen
                FROM vpn_user_destinations
                WHERE user_id = ?1
                  AND date >= strftime('%Y-%m-%d', 'now', ?2)
                GROUP BY user_id, destination_label
             )
             ORDER BY hit_count DESC, last_seen DESC
             LIMIT ?3",
        )
        .bind(&user_id.0)
        .bind(&cutoff)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_user_destination).collect()
    }

    /// Purge destination rows older than `days`. Wired into the
    /// hourly retention task at the standard 30-day default.
    pub async fn purge_user_destinations_older_than(&self, days: u32) -> Result<u64> {
        let res = sqlx::query(
            "DELETE FROM vpn_user_destinations
             WHERE date < strftime('%Y-%m-%d', 'now', ?1)",
        )
        .bind(format!("-{days} days"))
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    /// Bulk-record (user, source_ip) pairs observed in the current
    /// clash-poll tick. The source-IP counterpart to
    /// [`record_user_destinations`](Self::record_user_destinations):
    /// each call atomically UPSERTs per-pair rows for TODAY's UTC date
    /// — `hit_count += 1`, `last_seen = now`. Pairs are de-duplicated
    /// by the caller (one tick = one hit per pair, regardless of how
    /// many connections share the (user, source_ip)). Empty IPs must
    /// be filtered by the caller — they're meaningless to classify.
    ///
    /// Uses the same `INSERT … SELECT … WHERE EXISTS (users)` guard as
    /// the destinations writer: a since-deleted user (the user_id comes
    /// from the unvalidated log-scrape attribution map) is silently
    /// skipped instead of raising an FK error that would roll back the
    /// whole tick's batch (#32-class bug).
    pub async fn record_user_source_ips(&self, pairs: &[(UserId, String)]) -> Result<()> {
        if pairs.is_empty() {
            return Ok(());
        }
        let mut tx = self.pool.begin().await?;
        for (user_id, ip) in pairs {
            // Defensive: skip empty IPs even if the caller didn't.
            if ip.is_empty() {
                continue;
            }
            // Bound to 45 chars — the max textual IPv6 length
            // (incl. an IPv4-mapped tail). `.chars().take()` avoids a
            // mid-codepoint slice panic (defensive; IPs are ASCII).
            let ip_truncated: String = ip.chars().take(45).collect();
            sqlx::query(
                "INSERT INTO vpn_user_source_ips
                    (user_id, source_ip, date, hit_count, last_seen)
                 SELECT ?1, ?2, strftime('%Y-%m-%d', 'now'), 1,
                        strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE EXISTS (SELECT 1 FROM users WHERE id = ?1)
                 ON CONFLICT(user_id, source_ip, date) DO UPDATE SET
                     hit_count = hit_count + 1,
                     last_seen = excluded.last_seen",
            )
            .bind(&user_id.0)
            .bind(&ip_truncated)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Record, per user, the number of DISTINCT source IPs seen in ONE
    /// clash snapshot (the per-tick "concurrent clients" count). UPSERTs
    /// `peak_concurrent_ips = MAX(existing, n)` for TODAY's UTC date, so the
    /// stored value is the day's high-water mark of simultaneous client IPs.
    /// Same `WHERE EXISTS (users)` deleted-user guard as the source-IP
    /// writer. The caller passes one (user, distinct_ip_count) pair per user
    /// present in this snapshot; `n == 0` rows are skipped.
    pub async fn record_user_ip_concurrency(&self, peaks: &[(UserId, u32)]) -> Result<()> {
        if peaks.is_empty() {
            return Ok(());
        }
        let mut tx = self.pool.begin().await?;
        for (user_id, n) in peaks {
            if *n == 0 {
                continue;
            }
            sqlx::query(
                "INSERT INTO vpn_user_ip_concurrency
                    (user_id, date, peak_concurrent_ips, updated_at)
                 SELECT ?1, strftime('%Y-%m-%d', 'now'), ?2,
                        strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE EXISTS (SELECT 1 FROM users WHERE id = ?1)
                 ON CONFLICT(user_id, date) DO UPDATE SET
                     peak_concurrent_ips =
                         max(peak_concurrent_ips, excluded.peak_concurrent_ips),
                     updated_at = excluded.updated_at",
            )
            .bind(&user_id.0)
            .bind(i64::from(*n))
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Peak concurrent distinct source IPs for one user over the last
    /// `days` days (the day-level high-water marks, MAX'd across the
    /// window). `0` if the user never had a recorded snapshot. Feeds the
    /// composite sharing-risk score.
    pub async fn ip_concurrency_peak_for_user(&self, user_id: &UserId, days: u32) -> Result<u32> {
        let row: Option<(i64,)> = sqlx::query_as(
            "SELECT COALESCE(MAX(peak_concurrent_ips), 0)
             FROM vpn_user_ip_concurrency
             WHERE user_id = ?1
               AND date >= strftime('%Y-%m-%d', 'now', ?2)",
        )
        .bind(&user_id.0)
        .bind(format!("-{days} days"))
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(m,)| m.max(0) as u32).unwrap_or(0))
    }

    /// Purge IP-concurrency rows older than `days`. Wired into the hourly
    /// retention task alongside `purge_user_source_ips_older_than`.
    pub async fn purge_user_ip_concurrency_older_than(&self, days: u32) -> Result<u64> {
        let res = sqlx::query(
            "DELETE FROM vpn_user_ip_concurrency
             WHERE date < strftime('%Y-%m-%d', 'now', ?1)",
        )
        .bind(format!("-{days} days"))
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    /// Top source IPs for one user across the last `days` days, sorted
    /// by total hits DESC. Used by the user-detail «Source IPs»
    /// section. Mirrors
    /// [`top_destinations_for_user`](Self::top_destinations_for_user).
    pub async fn top_source_ips_for_user(
        &self,
        user_id: &UserId,
        days: u32,
        limit: u32,
    ) -> Result<Vec<VpnUserSourceIpRow>> {
        let cutoff = format!("-{days} days");
        // Show only REAL client source IPs — drop OUR infra (VPN server
        // addresses when a user hops nodes, + the homelab LAN/control
        // egress) via the shared `real_client_ip_predicate`. Single source
        // of truth with the sub_access-origins views.
        let sql = format!(
            "SELECT user_id, source_ip, date, hit_count, last_seen
             FROM (
                SELECT user_id, source_ip,
                       MAX(date)        AS date,
                       SUM(hit_count)   AS hit_count,
                       MAX(last_seen)   AS last_seen
                FROM vpn_user_source_ips
                WHERE user_id = ?1
                  AND date >= strftime('%Y-%m-%d', 'now', ?2)
                  AND {pred}
                GROUP BY user_id, source_ip
             )
             ORDER BY hit_count DESC, last_seen DESC
             LIMIT ?3",
            pred = real_client_ip_predicate("source_ip")
        );
        let rows = sqlx::query(&sql)
            .bind(&user_id.0)
            .bind(&cutoff)
            .bind(i64::from(limit))
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter().map(row_to_user_source_ip).collect()
    }

    /// Purge source-IP rows older than `days`. Wired into the hourly
    /// retention task at the standard 30-day default.
    pub async fn purge_user_source_ips_older_than(&self, days: u32) -> Result<u64> {
        let res = sqlx::query(
            "DELETE FROM vpn_user_source_ips
             WHERE date < strftime('%Y-%m-%d', 'now', ?1)",
        )
        .bind(format!("-{days} days"))
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    /// Best-effort GeoIP label lookup for a set of IPs, drawn from the
    /// most-recent `sub_access_log` row that carried geo for each IP.
    /// Geo is an attribute of the IP itself (operator-independent), so
    /// this deliberately does NOT filter by user — a source IP seen in
    /// VPN traffic is enriched from ANY user's /sub fetch that resolved
    /// it. Returns `ip -> (country_opt, asn_opt)`; an IP absent from
    /// the map (or mapping to (None, None)) simply has no GeoIP record
    /// and the caller falls back to the reserved-range classifier.
    ///
    /// Mirrors the dynamic-IN-clause shape of
    /// [`users_for_source_ips`](Self::users_for_source_ips) (sqlx has
    /// no array binding). Bounded by the caller's IP-list length.
    pub async fn geo_labels_for_ips(
        &self,
        ips: &[String],
    ) -> Result<std::collections::HashMap<String, (Option<String>, Option<String>)>> {
        use std::collections::HashMap;
        if ips.is_empty() {
            return Ok(HashMap::new());
        }
        let placeholders = std::iter::repeat_n("?", ips.len())
            .collect::<Vec<_>>()
            .join(",");
        // For each IP, take the geo from its newest row that actually
        // carried a country or ASN (older rows may predate the GeoIP
        // enrichment migration and have NULLs). `MAX(ts)` over the
        // non-NULL-geo subset via a correlated pick: group by IP and
        // take the geo associated with the latest qualifying ts.
        let sql = format!(
            "SELECT s.ip AS ip, s.geo_country AS country, s.geo_asn AS asn
             FROM sub_access_log s
             JOIN (
                SELECT ip, MAX(ts) AS mts
                FROM sub_access_log
                WHERE ip IN ({placeholders})
                  AND (geo_country IS NOT NULL OR geo_asn IS NOT NULL)
                GROUP BY ip
             ) j ON j.ip = s.ip AND j.mts = s.ts
             -- Re-assert non-NULL geo on the OUTER row too: when an
             -- enriched and an un-enriched row for the same IP share
             -- the max ts (sub-ms inserts), the join would otherwise
             -- also match the NULL row and a HashMap overwrite could
             -- non-deterministically blank the geo.
             WHERE s.geo_country IS NOT NULL OR s.geo_asn IS NOT NULL"
        );
        let mut q = sqlx::query(&sql);
        for ip in ips {
            q = q.bind(ip);
        }
        let rows = q.fetch_all(&self.pool).await?;
        let mut out: HashMap<String, (Option<String>, Option<String>)> = HashMap::new();
        for r in rows {
            let ip: String = r.try_get("ip")?;
            let country: Option<String> = r.try_get("country")?;
            let asn: Option<String> = r.try_get("asn")?;
            // A later duplicate (same ip, same mts tie) just overwrites
            // with equivalent geo — harmless; the join already pinned
            // the newest qualifying ts.
            out.insert(ip, (country, asn));
        }
        Ok(out)
    }

    // ──────────────────────────────────────────────────────────────────
    // Phase 5a-2 — reverse-DNS (PTR) cache for destination IPs.
    //
    // Pattern: the DNS resolver task in daemon/src/dns_resolver.rs
    // calls `lookup_dns_ptr_bulk(ips)` to fetch what's cached, then
    // shells out to `getent hosts <ip>` for each missing IP (in
    // parallel via spawn_blocking), then writes back via
    // `upsert_dns_ptr`. The admin UI's render path only ever calls
    // `lookup_dns_ptr_bulk` — never the resolver itself.
    //
    // TTL: 7 days, pruned by the existing hourly retention scheduler.
    // ──────────────────────────────────────────────────────────────────

    /// Bulk-fetch cached PTR results for a list of IPs. Returns a
    /// map from IP to (hostname_opt, resolved_at). hostname None =
    /// we tried and got no answer; that's a CACHED negative answer
    /// — distinct from the IP not being in the map at all (= never
    /// looked up). The render path uses this distinction to know
    /// whether to fall back to `IP:port` (negative cached) or show
    /// the resolved hostname.
    pub async fn lookup_dns_ptr_bulk(
        &self,
        ips: &[String],
    ) -> Result<std::collections::HashMap<String, Option<String>>> {
        use std::collections::HashMap;
        if ips.is_empty() {
            return Ok(HashMap::new());
        }
        let placeholders = std::iter::repeat_n("?", ips.len())
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!("SELECT ip, hostname FROM dns_ptr_cache WHERE ip IN ({placeholders})");
        let mut q = sqlx::query(&sql);
        for ip in ips {
            q = q.bind(ip);
        }
        let rows = q.fetch_all(&self.pool).await?;
        let mut out: HashMap<String, Option<String>> = HashMap::new();
        for r in rows {
            let ip: String = r.try_get("ip")?;
            let hostname: Option<String> = r.try_get("hostname")?;
            out.insert(ip, hostname);
        }
        Ok(out)
    }

    /// Insert-or-update a PTR cache entry. NULL hostname is a
    /// VALID value — caches "we asked, got no PTR" so the
    /// resolver doesn't re-query for the TTL window.
    pub async fn upsert_dns_ptr(&self, ip: &str, hostname: Option<&str>) -> Result<()> {
        sqlx::query(
            "INSERT INTO dns_ptr_cache (ip, hostname, resolved_at)
             VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
             ON CONFLICT(ip) DO UPDATE SET
                 hostname    = excluded.hostname,
                 resolved_at = excluded.resolved_at",
        )
        .bind(ip)
        .bind(hostname)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Purge cache entries older than `days`. Aligned with the
    /// hourly retention scheduler. Default TTL: 7 days.
    pub async fn purge_dns_ptr_older_than(&self, days: u32) -> Result<u64> {
        let res = sqlx::query(
            "DELETE FROM dns_ptr_cache
             WHERE resolved_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1)",
        )
        .bind(format!("-{days} days"))
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    // ──────────────────────────────────────────────────────────────────
    // Phase H chunk 2 — node telemetry storage (node_probe sink)
    //
    // Same shape + lifecycle as `vpn_connection_stats`:
    //   * Daemon poller calls `record_node_health(server_id, &Probe)`
    //     once per tick per server (chunk 3).
    //   * UI reads via `recent_node_health_for_server(id, since_hours)`.
    //   * Retention purge mirrors the others.
    //
    // **Audit exemption** (same rationale as `record_vpn_stats`):
    // probe writes happen at poller cadence × server count; audit
    // log volume would drown human-driven mutations. The table IS the
    // audit trail for telemetry. Documented exemption — not a silent
    // drift from the "every mutation audited" invariant.
    // ──────────────────────────────────────────────────────────────────

    /// Persist one node probe. `listening_ports_json` is the JSON
    /// serialization of the sorted `(proto, port)` set — caller
    /// builds it from `daemon::node_probe::Probe::listening`. Always
    /// stamps `ts` with daemon-side now; clash-api / probes don't
    /// carry their own timestamp.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_node_health(
        &self,
        server_id: &ServerId,
        sing_box_active: Option<bool>,
        fail2ban_active: Option<bool>,
        disk_used_mib: Option<u64>,
        disk_total_mib: Option<u64>,
        mem_available_mib: Option<u64>,
        mem_total_mib: Option<u64>,
        load_1min_x100: Option<u32>,
        listening_ports_json: Option<&str>,
        sing_box_log_bytes: Option<u64>,
        kernel_versions_json: Option<&str>,
        nic_iface: Option<&str>,
        nic_rx_bytes: Option<u64>,
        nic_tx_bytes: Option<u64>,
    ) -> Result<()> {
        // SQLite has no BOOLEAN — map Option<bool> → Option<i64>.
        let sb = sing_box_active.map(i64::from);
        let f2b = fail2ban_active.map(i64::from);
        sqlx::query(
            "INSERT INTO node_health
             (ts, server_id, sing_box_active, fail2ban_active,
              disk_used_mib, disk_total_mib,
              mem_available_mib, mem_total_mib,
              load_1min_x100, listening_ports_json, sing_box_log_bytes,
              kernel_versions_json, nic_iface, nic_rx_bytes, nic_tx_bytes)
             VALUES (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                     ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        )
        .bind(&server_id.0)
        .bind(sb)
        .bind(f2b)
        .bind(disk_used_mib.and_then(|n| i64::try_from(n).ok()))
        .bind(disk_total_mib.and_then(|n| i64::try_from(n).ok()))
        .bind(mem_available_mib.and_then(|n| i64::try_from(n).ok()))
        .bind(mem_total_mib.and_then(|n| i64::try_from(n).ok()))
        .bind(load_1min_x100.map(i64::from))
        .bind(listening_ports_json)
        .bind(sing_box_log_bytes.and_then(|n| i64::try_from(n).ok()))
        .bind(kernel_versions_json)
        .bind(nic_iface)
        .bind(nic_rx_bytes.and_then(|n| i64::try_from(n).ok()))
        .bind(nic_tx_bytes.and_then(|n| i64::try_from(n).ok()))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Recent rows for one server in the look-back window, newest
    /// first. UI reads this for the server-detail page (chunk 3).
    pub async fn recent_node_health_for_server(
        &self,
        server_id: &ServerId,
        since_hours: u32,
    ) -> Result<Vec<NodeHealthRow>> {
        let rows = sqlx::query(
            "SELECT ts, server_id, sing_box_active, fail2ban_active,
                    disk_used_mib, disk_total_mib,
                    mem_available_mib, mem_total_mib,
                    load_1min_x100, listening_ports_json, sing_box_log_bytes,
                    kernel_versions_json, nic_iface, nic_rx_bytes, nic_tx_bytes
             FROM node_health
             WHERE server_id = ?1
               AND ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)
             ORDER BY ts DESC",
        )
        .bind(&server_id.0)
        .bind(format!("-{since_hours} hours"))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_node_health).collect()
    }

    /// Most recent single row for a server. Convenience for the
    /// "current state" hero block on the server-detail page —
    /// callers that only need the latest snapshot don't have to
    /// pull a whole 24h Vec just to read the first element.
    pub async fn latest_node_health(&self, server_id: &ServerId) -> Result<Option<NodeHealthRow>> {
        let row_opt = sqlx::query(
            "SELECT ts, server_id, sing_box_active, fail2ban_active,
                    disk_used_mib, disk_total_mib,
                    mem_available_mib, mem_total_mib,
                    load_1min_x100, listening_ports_json, sing_box_log_bytes,
                    kernel_versions_json, nic_iface, nic_rx_bytes, nic_tx_bytes
             FROM node_health
             WHERE server_id = ?1
             ORDER BY ts DESC, rowid DESC
             LIMIT 1",
        )
        .bind(&server_id.0)
        .fetch_optional(&self.pool)
        .await?;
        row_opt.map(row_to_node_health).transpose()
    }

    /// Traffic accounting breakdown for one server over the window:
    /// NIC ground-truth total (ALL protocols), the part attributed to
    /// sing-box via clash-api, and the GAP between them (non-sing-box
    /// protocols — naive/Caddy, dns-tunnel, wgturn — plus protocol/OS
    /// overhead). Backs the «Traffic accounting» section on the
    /// server-detail page; the gap is THE signal the operator wants
    /// (how much real traffic vpnctl currently can't see per-user).
    ///
    /// NIC total = sum of per-interval deltas of the cumulative
    /// `node_health.nic_*` counters (reboot/reset-guarded via
    /// [`sum_nic_deltas`]). Attributed = `SUM(upload+download)` over ALL
    /// `vpn_connection_stats` rows (per-user + the server-wide remainder)
    /// — clash-api's total view of sing-box traffic.
    pub async fn server_traffic_breakdown(
        &self,
        server_id: &ServerId,
        since_hours: u32,
    ) -> Result<TrafficBreakdown> {
        // Cumulative NIC readings in the window, oldest→newest (need ≥2
        // for a delta). Only rows that actually captured the counters.
        let nic_rows = sqlx::query_as::<_, (Option<i64>, Option<i64>, Option<String>)>(
            "SELECT nic_rx_bytes, nic_tx_bytes, nic_iface
             FROM node_health
             WHERE server_id = ?1
               AND ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)
               AND nic_rx_bytes IS NOT NULL AND nic_tx_bytes IS NOT NULL
             ORDER BY ts ASC, rowid ASC",
        )
        .bind(&server_id.0)
        .bind(format!("-{since_hours} hours"))
        .fetch_all(&self.pool)
        .await?;
        let nic_iface = nic_rows.last().and_then(|(_, _, i)| i.clone());
        // Carry the iface into each reading so sum_nic_deltas can break
        // continuity on an iface change (rename / failover) — diffing two
        // different counters would otherwise inflate the total.
        let readings: Vec<(String, u64, u64)> = nic_rows
            .iter()
            .filter_map(|(rx, tx, ifc)| {
                Some((
                    ifc.clone().unwrap_or_default(),
                    u64::try_from((*rx)?).ok()?,
                    u64::try_from((*tx)?).ok()?,
                ))
            })
            .collect();
        let (nic_rx_bytes, nic_tx_bytes) = sum_nic_deltas(&readings);
        let nic_total_bytes = nic_rx_bytes.saturating_add(nic_tx_bytes);

        // Attributed (clash-api / sing-box) — sum of up+dn over ALL rows
        // (per-user + the NULL server-wide remainder) in the window. These
        // are DISJOINT by the clash poller's design (it emits per-user
        // deltas plus a remainder = total − attributed), so summing both
        // yields clash's true total view — not a double-count.
        let (attributed,): (i64,) = sqlx::query_as(
            "SELECT COALESCE(SUM(upload_bytes + download_bytes), 0)
             FROM vpn_connection_stats
             WHERE server_id = ?1
               AND ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)",
        )
        .bind(&server_id.0)
        .bind(format!("-{since_hours} hours"))
        .fetch_one(&self.pool)
        .await?;
        let attributed_bytes = u64::try_from(attributed).unwrap_or(0);

        Ok(TrafficBreakdown {
            nic_total_bytes,
            nic_rx_bytes,
            nic_tx_bytes,
            attributed_bytes,
            // Saturating: clash can briefly exceed NIC at window edges
            // (sample boundaries don't align) — never show a negative gap.
            gap_bytes: nic_total_bytes.saturating_sub(attributed_bytes),
            nic_samples: readings.len(),
            nic_iface,
        })
    }

    /// Phase H+ — uptime aggregation for the per-server detail page.
    ///
    /// Single SQL round-trip returns the rolling-window counts +
    /// last-outage + last-probe timestamps over `window_hours`. The
    /// UI builds three of these (24h, 7d, 30d) for one server with
    /// effectively the cost of three indexed range scans against
    /// `(server_id, ts)` — cheap even on the 632-row/day production
    /// rate that the live `is` node generates today.
    ///
    /// Definitions:
    ///   * "up" = `sing_box_active=1` — what users care about (the
    ///     daemon serving VPN traffic).
    ///   * "down" = `sing_box_active=0` — sing-box.service in any
    ///     non-active state at probe time.
    ///   * "unknown" = `sing_box_active IS NULL` — probe ran but
    ///     couldn't decide (early-bootstrap row before sing-box was
    ///     installed, or SSH probe partial-failure).
    ///
    /// `uptime_pct` excludes "unknown" from the denominator. A
    /// freshly-added server whose only rows are unknown reports
    /// `uptime_pct = None` rather than `0%`, which would be a wrong
    /// alarm in the chip ("0% over 30d" looks dire — "no data"
    /// is the honest answer).
    pub async fn uptime_for_server(
        &self,
        server_id: &ServerId,
        window_hours: u32,
    ) -> Result<UptimeStat> {
        let row = sqlx::query(
            "SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN sing_box_active = 1 THEN 1 ELSE 0 END) AS up_count,
                SUM(CASE WHEN sing_box_active = 0 THEN 1 ELSE 0 END) AS down_count,
                SUM(CASE WHEN sing_box_active IS NULL THEN 1 ELSE 0 END) AS unknown_count,
                MAX(CASE WHEN sing_box_active = 0 THEN ts ELSE NULL END) AS last_outage,
                MAX(ts) AS last_probe
             FROM node_health
             WHERE server_id = ?1
               AND ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)",
        )
        .bind(&server_id.0)
        .bind(format!("-{window_hours} hours"))
        .fetch_one(&self.pool)
        .await?;

        // `COUNT(*)` is always non-null; `SUM(...)` returns NULL
        // when there are zero rows. `try_get` with default-on-NULL
        // semantics avoids panicking on the empty-window case
        // (server brand-new, no probes in this window).
        let total: i64 = row.try_get("total").unwrap_or(0);
        let up: i64 = row.try_get("up_count").unwrap_or(0);
        let down: i64 = row.try_get("down_count").unwrap_or(0);
        let unknown: i64 = row.try_get("unknown_count").unwrap_or(0);
        let last_outage_s: Option<String> = row.try_get("last_outage").ok();
        let last_probe_s: Option<String> = row.try_get("last_probe").ok();

        // uptime% over decidable rows. None when no up+down rows.
        let uptime_pct: Option<u8> = if up + down > 0 {
            // u8 fits 0..=100 even with i64 inputs since we clamp.
            Some(((up * 100) / (up + down)).clamp(0, 100) as u8)
        } else {
            None
        };

        // Strings from SQLite come back ISO-8601 UTC (the column is
        // written that way by the writer). Parse → DateTime<Utc>.
        let parse = |s: Option<String>| -> Option<DateTime<Utc>> {
            s.as_deref()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|d| d.with_timezone(&Utc))
        };

        Ok(UptimeStat {
            window_hours,
            total_rows: total.max(0) as u64,
            up_rows: up.max(0) as u64,
            down_rows: down.max(0) as u64,
            unknown_rows: unknown.max(0) as u64,
            uptime_pct,
            last_outage_at: parse(last_outage_s),
            last_probe_at: parse(last_probe_s),
        })
    }

    /// Drop rows older than `days`. Wired by chunk 3 into the
    /// existing retention scheduler.
    pub async fn purge_node_health_older_than(&self, days: u32) -> Result<u64> {
        let res = sqlx::query(
            "DELETE FROM node_health
             WHERE ts < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1)",
        )
        .bind(format!("-{days} days"))
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    // ── Phase G admin_alerts ────────────────────────────────────────────

    /// Insert one alert row. Returns the new row id so the caller can
    /// reference it in an `audit()` payload — every fired alert ALSO
    /// gets an audit_log row with `action='alert.fire'` so the full
    /// timeline view in `/admin/audit` stays coherent.
    ///
    /// `payload_json` is opaque to inventory — callers serialise
    /// whatever structured context they want (thresholds, prior
    /// values, observed timestamp) and pass the resulting JSON
    /// string. NULL = no extra context.
    ///
    /// **Do NOT serialise secrets** (`User.uuid`, `User.sub_token`,
    /// `tuic_password`, `wireguard_private`, etc.) into
    /// `payload_json`. The string is rendered verbatim in the
    /// operator-facing `/admin/alerts` feed AND copied into the
    /// `audit_log` row AND any future webhook payload (Phase G
    /// chunk 3). Stick to thresholds, percentages, prior/current
    /// values, and other operationally-relevant numbers.
    pub async fn insert_alert(
        &self,
        kind: &str,
        server_id: Option<&ServerId>,
        severity: &str,
        summary: &str,
        payload_json: Option<&str>,
    ) -> Result<i64> {
        let res = sqlx::query(
            "INSERT INTO admin_alerts (kind, server_id, severity, summary, payload_json)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(kind)
        .bind(server_id.map(|s| s.0.as_str()))
        .bind(severity)
        .bind(summary)
        .bind(payload_json)
        .execute(&self.pool)
        .await?;
        Ok(res.last_insert_rowid())
    }

    /// Count alerts that haven't been acked yet — backs the dashboard
    /// «N unacked alerts» tile. One indexed SELECT.
    pub async fn unacked_alert_count(&self) -> Result<u64> {
        let row: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM admin_alerts WHERE acked_at IS NULL")
                .fetch_one(&self.pool)
                .await?;
        Ok(u64::try_from(row.0).unwrap_or(0))
    }

    /// Recent alerts, newest first. `include_acked = false` matches the
    /// default feed view (only currently-actionable items); `true`
    /// shows the full history including ones the operator dismissed.
    pub async fn recent_alerts(&self, limit: i64, include_acked: bool) -> Result<Vec<AdminAlert>> {
        let where_clause = if include_acked {
            ""
        } else {
            "WHERE acked_at IS NULL"
        };
        let sql = format!(
            "SELECT id, created_at, kind, server_id, severity, summary,
                    payload_json, acked_at
             FROM admin_alerts
             {where_clause}
             ORDER BY id DESC
             LIMIT ?1"
        );
        let rows = sqlx::query(&sql).bind(limit).fetch_all(&self.pool).await?;
        rows.into_iter().map(row_to_admin_alert).collect()
    }

    /// Mark one alert as acked. Returns `true` if the row existed AND
    /// was unacked (the operator-visible state actually changed),
    /// `false` if the id is unknown OR was already acked (idempotent).
    /// Doesn't error on a duplicate ack — the dashboard tile uses POST
    /// without an Idempotency-Key, so a refresh-after-ack should not
    /// 500.
    pub async fn ack_alert(&self, id: i64) -> Result<bool> {
        let res = sqlx::query(
            "UPDATE admin_alerts
             SET acked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE id = ?1 AND acked_at IS NULL",
        )
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Record the Telegram `message_id` of the push for `alert_id` so a
    /// later recovery can EDIT that message in place (🔴→🟢) instead of
    /// sending a second "recovered" message (migration 0037). Best-effort
    /// — a failed/absent push leaves it NULL and the recovery path falls
    /// back to a fresh message.
    pub async fn set_alert_telegram_message_id(
        &self,
        alert_id: i64,
        message_id: &str,
    ) -> Result<()> {
        sqlx::query("UPDATE admin_alerts SET telegram_message_id = ?2 WHERE id = ?1")
            .bind(alert_id)
            .bind(message_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// The Telegram `message_id` of the most-recent alert of `kind` for
    /// `server_id` that carries one — edit-on-recover uses it to find the
    /// original 🔴 message to flip to 🟢. `None` when no matching alert
    /// recorded a message id (e.g. the transport was off when it fired),
    /// in which case the caller sends a fresh recovery message.
    pub async fn latest_alert_message_id(
        &self,
        kind: &str,
        server_id: Option<&ServerId>,
    ) -> Result<Option<String>> {
        let row: Option<(Option<String>,)> = sqlx::query_as(
            "SELECT telegram_message_id FROM admin_alerts
             WHERE kind = ?1
               AND (?2 IS NULL OR server_id = ?2)
               AND telegram_message_id IS NOT NULL
             ORDER BY id DESC
             LIMIT 1",
        )
        .bind(kind)
        .bind(server_id.map(|s| s.0.as_str()))
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.and_then(|(m,)| m))
    }

    /// Ack EVERY currently-unacked alert in one UPDATE. Used by the
    /// «ack all (N)» button on /admin/alerts so the operator can
    /// clear a triaged backlog without 30 individual clicks.
    ///
    /// Returns the count of rows affected — caller uses it for the
    /// audit row + the success-banner («acked N alerts»).
    ///
    /// **Contract:** the UPDATE filters `WHERE acked_at IS NULL` so
    /// historical acks (already inside the 30-day retention window)
    /// are NOT touched — `acked_at` keeps its original timestamp, not
    /// the bulk-ack's «now». Pinned by
    /// `ack_all_unacked_alerts_preserves_existing_ack_timestamps`.
    ///
    /// **No `WHERE kind = …` overload yet** — Pavel's «33 stale
    /// suspicious_local_ip alerts» fire-drill (2026-05-22) is the
    /// only use case so far and it wants to clear everything; a
    /// per-kind variant can land when there's a second use case to
    /// motivate it. The endpoint stays a POST with no body to keep
    /// the contract «ack all» rather than «ack subset».
    pub async fn ack_all_unacked_alerts(&self) -> Result<u64> {
        let res = sqlx::query(
            "UPDATE admin_alerts
             SET acked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE acked_at IS NULL",
        )
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    /// Fire-once-per-condition variant of [`insert_alert`].
    ///
    /// Insert a new alert row ONLY if there is no currently-unacked row
    /// of the same `(kind, server_id)` pair. Returns `Some(new_id)` if
    /// inserted, `None` if a matching unacked row already existed
    /// (idempotent — the caller's tick-driven detection loop can call
    /// this every probe interval without flooding the feed).
    ///
    /// Semantics: a `(kind, server_id)` pair has at most ONE open row
    /// in the unacked view at a time. The operator acks it (or it gets
    /// auto-acked by a recovery transition via [`ack_open_alerts`]),
    /// AFTER which the next firing legitimately creates a fresh row.
    /// This matches the natural state-machine for «is this condition
    /// currently raised?».
    ///
    /// ## Atomicity
    ///
    /// The dedup is enforced at the SQL ENGINE level by the partial
    /// UNIQUE index `idx_admin_alerts_unique_unacked` (migration
    /// 0013), keyed on `(kind, COALESCE(server_id, '__GLOBAL__'))`
    /// filtered to `acked_at IS NULL`. A simple `INSERT OR IGNORE`
    /// is therefore atomic across concurrent writers — there is no
    /// READ-then-WRITE race window the way an `INSERT ... SELECT ...
    /// WHERE NOT EXISTS` formulation would have. Two daemons (or
    /// two sqlx pool connections) firing simultaneously cannot
    /// both succeed; the loser silently no-ops via the IGNORE clause.
    ///
    /// ## Secret-leakage warning (mirrored from [`insert_alert`])
    ///
    /// **Do NOT serialise secrets** (`User.uuid`, `User.sub_token`,
    /// `tuic_password`, `wireguard_private`, etc.) into `payload_json`.
    /// The string is rendered verbatim in the operator-facing
    /// `/admin/alerts` feed AND copied into the audit_log row AND any
    /// future webhook payload (Phase G chunk 3). Stick to thresholds,
    /// percentages, prior/current values, and other operationally-
    /// relevant numbers.
    pub async fn insert_alert_if_no_unacked(
        &self,
        kind: &str,
        server_id: Option<&ServerId>,
        severity: &str,
        summary: &str,
        payload_json: Option<&str>,
    ) -> Result<Option<i64>> {
        let server_id_str = server_id.map(|s| s.0.as_str());
        let res = sqlx::query(
            "INSERT OR IGNORE INTO admin_alerts
                 (kind, server_id, severity, summary, payload_json)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(kind)
        .bind(server_id_str)
        .bind(severity)
        .bind(summary)
        .bind(payload_json)
        .execute(&self.pool)
        .await?;
        if res.rows_affected() == 1 {
            Ok(Some(res.last_insert_rowid()))
        } else {
            Ok(None)
        }
    }

    /// Insert an alert row that is born ACKED (`acked_at = now`).
    /// Used for recovery events (`*.up` / `*.recovered`) since the
    /// alerts-cleanup (2026-06-10): a recovery is good news — it
    /// belongs in the history (`?show=all`) but must NOT sit in the
    /// open feed demanding a manual ack. Bypasses the partial UNIQUE
    /// dedup index by construction (the index only covers
    /// `acked_at IS NULL` rows), which is correct: each recovery is
    /// its own historical event.
    pub async fn insert_alert_acked(
        &self,
        kind: &str,
        server_id: Option<&ServerId>,
        severity: &str,
        summary: &str,
        payload_json: Option<&str>,
    ) -> Result<i64> {
        let server_id_str = server_id.map(|s| s.0.as_str());
        let res = sqlx::query(
            "INSERT INTO admin_alerts
                 (kind, server_id, severity, summary, payload_json, acked_at)
             VALUES (?1, ?2, ?3, ?4, ?5, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
        )
        .bind(kind)
        .bind(server_id_str)
        .bind(severity)
        .bind(summary)
        .bind(payload_json)
        .execute(&self.pool)
        .await?;
        Ok(res.last_insert_rowid())
    }

    /// Bulk-ack every currently-unacked alert of the given `(kind,
    /// server_id)` pair. Returns `rows_affected` — `0` if no matching
    /// open row existed (idempotent: the caller's recovery-detection
    /// loop can call this every probe interval without erroring out
    /// when the condition was never raised).
    ///
    /// Companion to [`insert_alert_if_no_unacked`]. The «recovery
    /// silently clears the alert» semantics is intentional — an alert
    /// that auto-clears doesn't need operator attention; the audit_log
    /// row written by the caller preserves the timeline. If the
    /// operator's preference shifts to «recovery emits a new
    /// `*.recovered` info alert», that's a Phase G chunk 3 decision,
    /// not this helper's responsibility.
    ///
    /// ## NULL-equality predicate
    ///
    /// SQLite's regular `=` returns NULL on NULL operands; for the
    /// `server_id IS NULL` global-alert case we use
    /// `((?2 IS NULL AND server_id IS NULL) OR server_id = ?2)` so
    /// NULL matches NULL. The companion [`insert_alert_if_no_unacked`]
    /// achieves the same semantics via the partial UNIQUE index's
    /// `COALESCE(server_id, '__GLOBAL__')` expression — different
    /// mechanism, same observable rule.
    ///
    /// ## Race-vs-concurrent-fire
    ///
    /// If a new firing of the same (kind, server_id) lands between
    /// this UPDATE's row-scan and commit, that new row legitimately
    /// represents the NEXT occurrence — the condition recovered then
    /// re-fired. The new row remains unacked; the operator sees it.
    /// This is the correct semantics for a state-machine that
    /// distinguishes «raised → cleared → raised again».
    pub async fn ack_open_alerts(&self, kind: &str, server_id: Option<&ServerId>) -> Result<u64> {
        let server_id_str = server_id.map(|s| s.0.as_str());
        let res = sqlx::query(
            "UPDATE admin_alerts
             SET acked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE kind = ?1
               AND ((?2 IS NULL AND server_id IS NULL) OR server_id = ?2)
               AND acked_at IS NULL",
        )
        .bind(kind)
        .bind(server_id_str)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    // ── Display settings (migration 0027) ──────────────────────────

    /// Read the operator-configured display timezone (IANA name like
    /// «Europe/Moscow», «America/New_York», «UTC»). Defaults to
    /// «Europe/Moscow» — migration 0027 seeds the row.
    ///
    /// Returns `Err` only on storage-layer failures; missing-row
    /// returns the default («Europe/Moscow») since a corrupted DB
    /// shouldn't crash-loop the daemon's render path.
    pub async fn get_display_timezone(&self) -> Result<String> {
        let row =
            sqlx::query_as::<_, (String,)>("SELECT timezone FROM display_settings WHERE id = 1")
                .fetch_optional(&self.pool)
                .await?;
        Ok(row
            .map(|(tz,)| tz)
            .unwrap_or_else(|| "Europe/Moscow".into()))
    }

    /// Update the display timezone. Caller is responsible for
    /// validating the value is a valid IANA name BEFORE calling
    /// (the daemon's handler parses via `chrono_tz::Tz::from_str`
    /// and rejects invalid input with 400; this layer just writes
    /// whatever string the caller hands it). Also responsible for
    /// updating any in-memory cache.
    pub async fn set_display_timezone(&self, tz: &str) -> Result<()> {
        sqlx::query("UPDATE display_settings SET timezone = ?1 WHERE id = 1")
            .bind(tz)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ── Phase G chunk 3 notification_settings ──────────────────────

    /// Read the singleton notification-transport config. All three
    /// fields are `Option<String>` because each can independently be
    /// NULL in the schema; callers downstream (the dispatch loop, the
    /// Settings UI) decide what to do with partial config.
    ///
    /// Returns `Ok(None)` if the singleton row is somehow missing
    /// (shouldn't happen — migration 0014 seeds it — but defended
    /// against so a corrupted DB doesn't crash-loop the daemon).
    pub async fn get_telegram_config(&self) -> Result<Option<TelegramConfig>> {
        let row = sqlx::query_as::<
            _,
            (
                Option<String>,
                Option<String>,
                Option<String>,
                Option<String>,
            ),
        >(
            "SELECT telegram_bot_token, telegram_chat_id, proxy_via_server_id, language
                 FROM notification_settings WHERE id = 1",
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(
            |(token, chat_id, proxy_via_server_id, language)| TelegramConfig {
                token,
                chat_id,
                proxy_via_server_id,
                language,
            },
        ))
    }

    /// Atomically set ALL THREE halves of the Telegram config. `None`
    /// for a field clears it. Caller-side validators (the Settings
    /// POST handler) reject the «partial config» state of
    /// (Some(token), None, _) or vice versa before reaching here —
    /// but the DB doesn't enforce it because «clear» is a legitimate
    /// `Set(None, None, None)` call.
    ///
    /// `proxy_via_server_id` is a plain TEXT (no FK to `servers.id`)
    /// — see migration 0015's doc-comment for the rationale (operator
    /// gets a loud SSH-spawn error rather than a silent FK-cascade
    /// NULL when the referenced server is deleted).
    ///
    /// Writes `updated_at` automatically via `strftime`. Does NOT
    /// write to `audit_log` — caller is responsible for the audit
    /// row (with `payload_json` that NEVER includes the token).
    pub async fn set_telegram_config(
        &self,
        token: Option<&str>,
        chat_id: Option<&str>,
        proxy_via_server_id: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE notification_settings
             SET telegram_bot_token  = ?1,
                 telegram_chat_id    = ?2,
                 proxy_via_server_id = ?3,
                 updated_at          = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE id = 1",
        )
        .bind(token)
        .bind(chat_id)
        .bind(proxy_via_server_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Set the operator's notification language (`'en'` / `'ru'`;
    /// `None` clears → renders as English). Independent of
    /// `set_telegram_config` (which leaves this column untouched), so
    /// flipping the language never disturbs the token / chat_id. Caller
    /// writes the audit row.
    pub async fn set_notification_language(&self, lang: Option<&str>) -> Result<()> {
        sqlx::query(
            "UPDATE notification_settings
             SET language    = ?1,
                 updated_at  = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE id = 1",
        )
        .bind(lang)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Drop ACKED alerts older than `days`. UNACKED alerts are NEVER
    /// auto-purged (an alert that fires once and is forgotten must
    /// still be visible — see migration 0011 doc-comment for the
    /// rationale). Wired into the existing retention scheduler.
    pub async fn purge_acked_alerts_older_than(&self, days: u32) -> Result<u64> {
        let res = sqlx::query(
            "DELETE FROM admin_alerts
             WHERE acked_at IS NOT NULL
               AND acked_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1)",
        )
        .bind(format!("-{days} days"))
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }
}

/// Extract the `/16` network prefix from a v4 IP literal as a
/// string (`"192.168.0.1"` → `Some("192.168")`). Returns `None`
/// for v6 addresses (no meaningful prefix without ASN data) or
/// malformed strings. Used by the Track-4 UA fingerprint heuristic
/// to count distinct ISP-ish networks per UA.
pub(crate) fn ip_slash16(ip: &str) -> Option<String> {
    // Reject v6 cheaply — colons don't appear in v4 dotted-quad.
    if ip.contains(':') {
        return None;
    }
    let mut parts = ip.split('.');
    let a = parts.next()?;
    let b = parts.next()?;
    let _ = parts.next()?; // third octet must exist (else not v4)
    if a.is_empty() || b.is_empty() {
        return None;
    }
    if !a.bytes().all(|x| x.is_ascii_digit()) || !b.bytes().all(|x| x.is_ascii_digit()) {
        return None;
    }
    Some(format!("{a}.{b}"))
}

/// Escape SQLite LIKE metacharacters (`\`, `%`, `_`) so user-supplied
/// substrings match LITERALLY rather than as patterns. Caller MUST
/// pair this with `ESCAPE '\\'` in the LIKE clause. Without escaping,
/// a filter input of `user_` would match `user.` (the `.` slot is
/// any char per `_`) and `%` would match everything.
pub(crate) fn escape_like(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' | '%' | '_' => {
                out.push('\\');
                out.push(ch);
            }
            other => out.push(other),
        }
    }
    out
}

/// Shared row decoder for audit rows. Used by both `recent_audit` and
/// `recent_audit_paginated` so the field-by-field parsing logic lives
/// in exactly one place.
#[allow(clippy::needless_pass_by_value)]
fn row_to_audit_entry(r: sqlx::sqlite::SqliteRow) -> Result<AuditEntry> {
    let ts_str: String = r.try_get("ts")?;
    let ts = DateTime::parse_from_rfc3339(&ts_str)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|e| {
            SqliteInventoryError::Invalid(format!("audit ts not RFC3339 ({ts_str}): {e}"))
        })?;
    let payload_opt: Option<String> = r.try_get("payload")?;
    let payload = match payload_opt {
        Some(s) => Some(serde_json::from_str(&s)?),
        None => None,
    };
    Ok(AuditEntry {
        id: r.try_get("id")?,
        ts,
        actor: r.try_get("actor")?,
        action: r.try_get("action")?,
        target: r.try_get("target")?,
        payload,
    })
}

#[allow(clippy::needless_pass_by_value)]
fn row_to_ban(r: sqlx::sqlite::SqliteRow) -> Result<Ban> {
    let parse_ts = |col: &str, raw: &str| {
        DateTime::parse_from_rfc3339(raw)
            .map(|d| d.with_timezone(&Utc))
            .map_err(|e| {
                SqliteInventoryError::Invalid(format!("ban {col} not RFC3339 ({raw}): {e}"))
            })
    };
    let created_str: String = r.try_get("created_at")?;
    let until_str: String = r.try_get("until_ts")?;
    Ok(Ban {
        id: r.try_get("id")?,
        created_at: parse_ts("created_at", &created_str)?,
        until_ts: parse_ts("until_ts", &until_str)?,
        kind: r.try_get("kind")?,
        key: r.try_get("key")?,
        reason: r.try_get("reason")?,
    })
}

#[allow(clippy::needless_pass_by_value)]
fn row_to_sub_access(r: sqlx::sqlite::SqliteRow) -> Result<SubAccessEntry> {
    let ts_str: String = r.try_get("ts")?;
    let ts = DateTime::parse_from_rfc3339(&ts_str)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|e| {
            SqliteInventoryError::Invalid(format!("sub_access_log ts not RFC3339 ({ts_str}): {e}"))
        })?;
    let status_i: i64 = r.try_get("status")?;
    let bytes_i: i64 = r.try_get("bytes")?;
    Ok(SubAccessEntry {
        id: r.try_get("id")?,
        ts,
        user_id: r.try_get("user_id")?,
        ip: r.try_get("ip")?,
        ua: r.try_get("ua")?,
        // SQLite stores INTEGER, narrow defensively rather than panic.
        status: u16::try_from(status_i).unwrap_or(0),
        bytes: u64::try_from(bytes_i).unwrap_or(0),
        // Track-1.2 (migration 0019) — old rows have NULL, try_get
        // maps that to Option::None for Option<String> targets. No
        // defensive code needed.
        accept_language: r.try_get("accept_language")?,
        http_version: r.try_get("http_version")?,
        device_class: r.try_get("device_class")?,
        geo_country: r.try_get("geo_country")?,
        geo_asn: r.try_get("geo_asn")?,
        // Track-1.4 (migration 0020) — same NULL-tolerant pattern.
        tls_ja3: r.try_get("tls_ja3")?,
        tls_ja4: r.try_get("tls_ja4")?,
        // Phase 4a (migration 0021) — INTEGER NOT NULL DEFAULT 0
        // in SQL → bool in Rust. SQLite stores 0/1; `try_get::<i64>`
        // and compare. Always present (NOT NULL with DEFAULT).
        is_vpn_egress: r.try_get::<i64, _>("is_vpn_egress").unwrap_or(0) != 0,
    })
}

// Owned `SqliteRow` is what `.map(...)` over `Vec<Row>` gives us — taking by
// reference here would require a `.collect()` round-trip. Accepting by value
// is correct.
//
// The SHA256 fingerprint shape check that used to live here moved to
// `vpnctl-host-fingerprint::validate_shape` so every surface (CLI / web /
// wizard / this inventory gate) shares one canonical definition.

#[allow(clippy::needless_pass_by_value)]
fn row_to_user(r: sqlx::sqlite::SqliteRow) -> Result<User> {
    Ok(User {
        id: UserId(r.try_get("id")?),
        uuid: r.try_get("uuid")?,
        tuic_password: r.try_get("tuic_password")?,
        wireguard_pubkey: r.try_get("wireguard_pubkey")?,
        wireguard_private: r.try_get("wireguard_private")?,
        sub_token: r.try_get("sub_token")?,
        // Reads the column added by migration 0017. Bare `?` (no
        // turbofish) — same pattern as the other Option<String>
        // columns above. Rust infers `T = Option<String>` from the
        // field type, which routes through sqlx's `Option<T>` Decode
        // impl and handles NULL → `None` correctly. Initial fix
        // used `.ok()` which inferred `T = String` and SQLite
        // decoded NULL as `""` (caught 2026-05-19: `DEVICE_ID =
        // Some("")` instead of `None` made every fresh-user
        // detail page render the ninitux URL with an empty
        // device_id).
        vpn_router_device_id: r.try_get("vpn_router_device_id")?,
        // Migration 0026 (audit B1.user, 2026-05-22). SQLite stores
        // BOOLEAN as INTEGER; we read i64 and map non-zero → true.
        disabled: {
            let v: i64 = r.try_get("disabled").unwrap_or(0);
            v != 0
        },
    })
}

/// Sum per-interval deltas of cumulative NIC counters, `readings`
/// oldest→newest as `(iface, rx, tx)` triples. Two discontinuity guards
/// each count the new value itself as that interval's delta (a lower
/// bound; the pre-discontinuity tail is unknowable): a reboot/reset (a
/// reading LOWER than the previous — counter wrapped / NIC reset), and an
/// interface change (`iface` differs from the previous reading — rename
/// `eth0`→`ens18`, uplink failover; the two readings are DIFFERENT
/// counters, so a plain subtraction would be garbage, and a higher new
/// counter would otherwise inflate the total). Fewer than 2 readings ⇒
/// `(0, 0)`. Pure + saturating, so it's spec-testable in isolation and
/// can't overflow on a corrupt counter. Returns `(rx_total, tx_total)`.
pub fn sum_nic_deltas(readings: &[(String, u64, u64)]) -> (u64, u64) {
    let mut rx = 0u64;
    let mut tx = 0u64;
    for w in readings.windows(2) {
        let (piface, prx, ptx) = (&w[0].0, w[0].1, w[0].2);
        let (ciface, crx, ctx) = (&w[1].0, w[1].1, w[1].2);
        let continuous = piface == ciface;
        rx = rx.saturating_add(if continuous && crx >= prx {
            crx - prx
        } else {
            crx
        });
        tx = tx.saturating_add(if continuous && ctx >= ptx {
            ctx - ptx
        } else {
            ctx
        });
    }
    (rx, tx)
}

#[allow(clippy::needless_pass_by_value)]
fn row_to_node_health(r: sqlx::sqlite::SqliteRow) -> Result<NodeHealthRow> {
    let ts_s: String = r.try_get("ts")?;
    let ts = DateTime::parse_from_rfc3339(&ts_s)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|e| {
            SqliteInventoryError::Invalid(format!("node_health.ts malformed: {ts_s}: {e}"))
        })?;
    let server_id: String = r.try_get("server_id")?;
    let sb_i: Option<i64> = r.try_get("sing_box_active")?;
    let f2b_i: Option<i64> = r.try_get("fail2ban_active")?;
    let disk_u: Option<i64> = r.try_get("disk_used_mib")?;
    let disk_t: Option<i64> = r.try_get("disk_total_mib")?;
    let mem_a: Option<i64> = r.try_get("mem_available_mib")?;
    let mem_t: Option<i64> = r.try_get("mem_total_mib")?;
    let load_i: Option<i64> = r.try_get("load_1min_x100")?;
    let ports: Option<String> = r.try_get("listening_ports_json")?;
    let log_b: Option<i64> = r.try_get("sing_box_log_bytes")?;
    let kernel_versions: Option<String> = r.try_get("kernel_versions_json")?;
    let nic_iface: Option<String> = r.try_get("nic_iface")?;
    let nic_rx: Option<i64> = r.try_get("nic_rx_bytes")?;
    let nic_tx: Option<i64> = r.try_get("nic_tx_bytes")?;
    Ok(NodeHealthRow {
        ts,
        server_id: ServerId(server_id),
        sing_box_active: sb_i.map(|n| n != 0),
        fail2ban_active: f2b_i.map(|n| n != 0),
        disk_used_mib: disk_u.and_then(|n| u64::try_from(n).ok()),
        disk_total_mib: disk_t.and_then(|n| u64::try_from(n).ok()),
        mem_available_mib: mem_a.and_then(|n| u64::try_from(n).ok()),
        mem_total_mib: mem_t.and_then(|n| u64::try_from(n).ok()),
        load_1min_x100: load_i.and_then(|n| u32::try_from(n).ok()),
        listening_ports_json: ports,
        sing_box_log_bytes: log_b.and_then(|n| u64::try_from(n).ok()),
        kernel_versions_json: kernel_versions,
        nic_iface,
        nic_rx_bytes: nic_rx.and_then(|n| u64::try_from(n).ok()),
        nic_tx_bytes: nic_tx.and_then(|n| u64::try_from(n).ok()),
    })
}

#[allow(clippy::needless_pass_by_value)]
fn row_to_admin_alert(r: sqlx::sqlite::SqliteRow) -> Result<AdminAlert> {
    let created_at_s: String = r.try_get("created_at")?;
    let created_at = DateTime::parse_from_rfc3339(&created_at_s)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|e| {
            SqliteInventoryError::Invalid(format!(
                "admin_alerts.created_at malformed: {created_at_s}: {e}"
            ))
        })?;
    let acked_at_s: Option<String> = r.try_get("acked_at")?;
    let acked_at = match acked_at_s {
        Some(s) => Some(
            DateTime::parse_from_rfc3339(&s)
                .map(|d| d.with_timezone(&Utc))
                .map_err(|e| {
                    SqliteInventoryError::Invalid(format!(
                        "admin_alerts.acked_at malformed: {s}: {e}"
                    ))
                })?,
        ),
        None => None,
    };
    let server_id_s: Option<String> = r.try_get("server_id")?;
    Ok(AdminAlert {
        id: r.try_get("id")?,
        created_at,
        kind: r.try_get("kind")?,
        server_id: server_id_s.map(ServerId),
        severity: r.try_get("severity")?,
        summary: r.try_get("summary")?,
        payload_json: r.try_get("payload_json")?,
        acked_at,
    })
}

#[allow(clippy::needless_pass_by_value)]
fn row_to_user_session(r: sqlx::sqlite::SqliteRow) -> Result<VpnUserSessionRow> {
    let id: i64 = r.try_get("id")?;
    let user_id: String = r.try_get("user_id")?;
    let server_id: String = r.try_get("server_id")?;
    let started_at_s: String = r.try_get("started_at")?;
    let last_seen_s: String = r.try_get("last_seen")?;
    let conn_count_peak: i64 = r.try_get("conn_count_peak")?;
    let total_bytes: i64 = r.try_get("total_bytes")?;
    let parse_ts = |s: &str, label: &str| -> Result<DateTime<Utc>> {
        DateTime::parse_from_rfc3339(s)
            .map(|d| d.with_timezone(&Utc))
            .map_err(|e| {
                SqliteInventoryError::Invalid(format!(
                    "vpn_user_sessions.{label} malformed: {s}: {e}"
                ))
            })
    };
    Ok(VpnUserSessionRow {
        id,
        user_id: UserId(user_id),
        server_id: ServerId(server_id),
        started_at: parse_ts(&started_at_s, "started_at")?,
        last_seen: parse_ts(&last_seen_s, "last_seen")?,
        conn_count_peak: u32::try_from(conn_count_peak.max(0)).unwrap_or(u32::MAX),
        total_bytes: total_bytes.max(0) as u64,
    })
}

#[allow(clippy::needless_pass_by_value)]
fn row_to_user_destination(r: sqlx::sqlite::SqliteRow) -> Result<VpnUserDestinationRow> {
    let user_id: String = r.try_get("user_id")?;
    let destination_label: String = r.try_get("destination_label")?;
    let date: String = r.try_get("date")?;
    let hits: i64 = r.try_get("hit_count")?;
    let last_seen_s: String = r.try_get("last_seen")?;
    let last_seen = DateTime::parse_from_rfc3339(&last_seen_s)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|e| {
            SqliteInventoryError::Invalid(format!(
                "vpn_user_destinations.last_seen malformed: {last_seen_s}: {e}"
            ))
        })?;
    Ok(VpnUserDestinationRow {
        user_id: UserId(user_id),
        destination_label,
        date,
        hit_count: hits.max(0) as u64,
        last_seen,
    })
}

#[allow(clippy::needless_pass_by_value)]
fn row_to_user_source_ip(r: sqlx::sqlite::SqliteRow) -> Result<VpnUserSourceIpRow> {
    let user_id: String = r.try_get("user_id")?;
    let source_ip: String = r.try_get("source_ip")?;
    let date: String = r.try_get("date")?;
    let hits: i64 = r.try_get("hit_count")?;
    let last_seen_s: String = r.try_get("last_seen")?;
    let last_seen = DateTime::parse_from_rfc3339(&last_seen_s)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|e| {
            SqliteInventoryError::Invalid(format!(
                "vpn_user_source_ips.last_seen malformed: {last_seen_s}: {e}"
            ))
        })?;
    Ok(VpnUserSourceIpRow {
        user_id: UserId(user_id),
        source_ip,
        date,
        hit_count: hits.max(0) as u64,
        last_seen,
    })
}

// Owned row argument is what `.into_iter().map(...)` over `Vec<SqliteRow>`
// gives us; taking by reference would force a `.collect()` round-trip.
#[allow(clippy::needless_pass_by_value)]
fn row_to_vpn_user_daily(r: sqlx::sqlite::SqliteRow) -> Result<VpnUserDailyRow> {
    let date: String = r.try_get("date")?;
    let user_id: String = r.try_get("user_id")?;
    let server_id: String = r.try_get("server_id")?;
    let upload_i: i64 = r.try_get("upload_bytes")?;
    let download_i: i64 = r.try_get("download_bytes")?;
    let peak_i: i64 = r.try_get("active_connections_peak")?;
    let distinct_i: i64 = r.try_get("distinct_source_ips")?;
    Ok(VpnUserDailyRow {
        date,
        user_id: UserId(user_id),
        server_id: ServerId(server_id),
        upload_bytes: upload_i.max(0) as u64,
        download_bytes: download_i.max(0) as u64,
        active_connections_peak: u32::try_from(peak_i.max(0)).unwrap_or(u32::MAX),
        distinct_source_ips: u32::try_from(distinct_i.max(0)).unwrap_or(u32::MAX),
    })
}

#[allow(clippy::needless_pass_by_value)]
fn row_to_vpn_stats(r: sqlx::sqlite::SqliteRow) -> Result<VpnStatsRow> {
    let ts_s: String = r.try_get("ts")?;
    let ts = DateTime::parse_from_rfc3339(&ts_s)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|e| {
            SqliteInventoryError::Invalid(format!("vpn_connection_stats.ts malformed: {ts_s}: {e}"))
        })?;
    let server_id: String = r.try_get("server_id")?;
    let user_id_opt: Option<String> = r.try_get("user_id")?;
    let upload_i: i64 = r.try_get("upload_bytes")?;
    let download_i: i64 = r.try_get("download_bytes")?;
    let conns_i: i64 = r.try_get("active_connections")?;
    Ok(VpnStatsRow {
        ts,
        server_id: ServerId(server_id),
        user_id: user_id_opt.map(UserId),
        upload_bytes: u64::try_from(upload_i).unwrap_or(0),
        download_bytes: u64::try_from(download_i).unwrap_or(0),
        active_connections: u32::try_from(conns_i).unwrap_or(0),
    })
}

/// Walk users whose sub_token is NULL after migrate, generate one each.
/// Idempotent — a second call sees no rows.
async fn backfill_sub_tokens(pool: &SqlitePool) -> Result<()> {
    // Wrap in a transaction so two concurrent `open()` calls can't race on
    // the same NULL row. sqlx::Transaction holds an `IMMEDIATE` write lock
    // on first write; the loser blocks until the winner commits, then sees
    // no NULLs and does nothing. On crash mid-loop the txn rolls back —
    // next open retries cleanly, no half-state.
    let mut tx = pool.begin().await?;
    let rows = sqlx::query("SELECT id FROM users WHERE sub_token IS NULL")
        .fetch_all(&mut *tx)
        .await?;
    for r in rows {
        let id: String = r.try_get("id")?;
        let token = vpnctl_crypto::gen_sub_token().map_err(SqliteInventoryError::CryptoIo)?;
        sqlx::query("UPDATE users SET sub_token = ?1 WHERE id = ?2")
            .bind(&token)
            .bind(&id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::tempdir;
    use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};

    async fn fresh() -> SqliteInventory {
        let dir = Box::leak(Box::new(tempdir().expect("tempdir")));
        let path = dir.path().join("inv.db");
        SqliteInventory::open(&path).await.expect("open inventory")
    }

    fn sample_server(id: &str) -> Server {
        Server {
            id: ServerId(id.into()),
            address: "1.2.3.4".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![
                ProtocolId("vless+reality".into()),
                ProtocolId("tuic-v5".into()),
            ],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        }
    }

    fn sample_user(id: &str) -> User {
        User {
            id: UserId(id.into()),
            uuid: format!("uuid-{id}"),
            tuic_password: Some(format!("pw-{id}")),
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None, // inventory will generate one
            vpn_router_device_id: None,
            disabled: false,
        }
    }

    #[tokio::test]
    async fn migrations_apply_and_tables_exist() -> Result<()> {
        let inv = fresh().await;
        // If we can list servers without error, migration ran.
        assert!(inv.list_servers().await?.is_empty());
        Ok(())
    }

    // sub_fetch_without_traffic_users — the «subscription updated but no
    // traffic followed» detector query (2026-06-16). Raw inserts with
    // explicit `ts` offsets because the public record helpers stamp `now`.
    #[tokio::test]
    async fn sub_fetch_without_traffic_flags_regression_then_clears() -> Result<()> {
        let inv = fresh().await;
        inv.add_server(&sample_server("s1")).await?;
        for u in ["oleg", "newbie", "healthy", "justfetched"] {
            inv.add_user(&sample_user(u)).await?;
        }

        // A real (non-egress) `/sub` fetch `mins_ago` in the past. IP differs
        // from the server address (1.2.3.4) so the is_vpn_egress trigger
        // leaves the row at 0.
        async fn fetch(inv: &SqliteInventory, uid: &str, mins_ago: i64) {
            sqlx::query(
                "INSERT INTO sub_access_log
                    (ts, user_id, ip, ua, status, bytes, is_vpn_egress)
                 VALUES (strftime('%Y-%m-%dT%H:%M:%fZ','now',?1), ?2,
                         '198.51.100.7', 'Happ/1', 200, 900, 0)",
            )
            .bind(format!("-{mins_ago} minutes"))
            .bind(uid)
            .execute(&inv.pool)
            .await
            .unwrap();
        }
        // Attributed traffic at an explicit strftime offset ("-2 days",
        // "-5 minutes", "+0 minutes").
        async fn traffic(inv: &SqliteInventory, uid: &str, offset: &str) {
            sqlx::query(
                "INSERT INTO vpn_connection_stats
                    (ts, server_id, user_id, upload_bytes, download_bytes, active_connections)
                 VALUES (strftime('%Y-%m-%dT%H:%M:%fZ','now',?1), 's1', ?2, 1000, 2000, 1)",
            )
            .bind(offset)
            .bind(uid)
            .execute(&inv.pool)
            .await
            .unwrap();
        }

        // oleg — FIRES: active 2d ago, fetched 60m ago, silent since.
        fetch(&inv, "oleg", 60).await;
        traffic(&inv, "oleg", "-2 days").await;
        // newbie — NO fire: fetched but never had any traffic (setup problem,
        // not a regression).
        fetch(&inv, "newbie", 60).await;
        // healthy — NO fire: active before AND traffic 5m ago (after fetch).
        fetch(&inv, "healthy", 60).await;
        traffic(&inv, "healthy", "-2 days").await;
        traffic(&inv, "healthy", "-5 minutes").await;
        // justfetched — NO fire: fetched only 10m ago, still inside the grace.
        fetch(&inv, "justfetched", 10).await;
        traffic(&inv, "justfetched", "-2 days").await;

        let flagged = inv.sub_fetch_without_traffic_users(45, 360, 7).await?;
        let ids: Vec<&str> = flagged.iter().map(|u| u.user_id.0.as_str()).collect();
        assert_eq!(
            ids,
            ["oleg"],
            "only the previously-active, past-grace, silent-since-fetch user fires"
        );
        assert!(flagged[0].last_traffic.is_some(), "last_traffic populated");
        assert!(
            flagged[0].fetch_age_minutes >= 45,
            "age past grace: {}",
            flagged[0].fetch_age_minutes
        );

        // Resolve: oleg now passes traffic AFTER the fetch → drops out.
        traffic(&inv, "oleg", "+0 minutes").await;
        let after = inv.sub_fetch_without_traffic_users(45, 360, 7).await?;
        assert!(
            after.is_empty(),
            "oleg clears once traffic resumes: {after:?}"
        );
        Ok(())
    }

    // open_alert_subjects_with_kind_prefix — backs the per-user auto-resolve
    // sweep. Must return only UNACKED subjects of the EXACT prefix.
    #[tokio::test]
    async fn open_alert_subjects_filters_by_prefix_and_unacked() -> Result<()> {
        let inv = fresh().await;
        inv.insert_alert_if_no_unacked("user.sub_no_traffic:oleg", None, "warning", "s", None)
            .await?;
        inv.insert_alert_if_no_unacked("user.sub_no_traffic:masha", None, "warning", "s", None)
            .await?;
        // different prefix — must be ignored even though it's open.
        inv.insert_alert_if_no_unacked("user.traffic_limit:bob", None, "warning", "s", None)
            .await?;
        // ack masha → must drop from the open set.
        inv.ack_open_alerts("user.sub_no_traffic:masha", None)
            .await?;

        let mut subs = inv
            .open_alert_subjects_with_kind_prefix("user.sub_no_traffic:")
            .await?;
        subs.sort();
        assert_eq!(
            subs,
            vec!["oleg".to_string()],
            "only the open, exact-prefix subject (suffix stripped) is returned"
        );
        Ok(())
    }

    // top_source_ips_for_user must hide every flavour of OUR infra
    // (2026-06-16): VPN server addresses (node-hop transient source), the
    // control egress, AND RFC1918 / loopback / link-local (homelab LAN).
    // A real 172.32+ client (just outside the private /12) must survive —
    // guards the GLOB char-range boundaries.
    #[tokio::test]
    async fn top_source_ips_excludes_all_infra_ip_classes() -> Result<()> {
        let inv = fresh().await;
        inv.add_server(&sample_server("s1")).await?; // address 1.2.3.4
        inv.add_user(&sample_user("u")).await?;
        inv.record_user_source_ips(&[
            (UserId("u".into()), "203.0.113.9".into()), // real client — KEEP
            (UserId("u".into()), "172.32.5.5".into()),  // public (>172.31) — KEEP
            (UserId("u".into()), "1.2.3.4".into()),     // == server s1 address
            (UserId("u".into()), "83.97.108.34".into()), // control egress const
            (UserId("u".into()), "192.168.0.200".into()), // LAN (claude-chat host)
            (UserId("u".into()), "10.5.5.5".into()),    // RFC1918 10/8
            (UserId("u".into()), "172.20.5.5".into()),  // RFC1918 172.16-31
            (UserId("u".into()), "127.0.0.1".into()),   // loopback
            (UserId("u".into()), "169.254.9.9".into()), // link-local
        ])
        .await?;
        let mut ips: Vec<String> = inv
            .top_source_ips_for_user(&UserId("u".into()), 30, 50)
            .await?
            .into_iter()
            .map(|r| r.source_ip)
            .collect();
        ips.sort();
        assert_eq!(
            ips,
            vec!["172.32.5.5".to_string(), "203.0.113.9".to_string()],
            "only the two real public clients survive; server/control/LAN/loopback/link-local all dropped"
        );
        Ok(())
    }

    // IP-concurrency: per-day peak is the MAX across snapshots; unknown
    // users are FK-guard-skipped silently.
    #[tokio::test]
    async fn ip_concurrency_records_daily_peak_max() -> Result<()> {
        let inv = fresh().await;
        inv.add_user(&sample_user("u")).await?;
        // snapshots this day: 1, then 3, then 2 distinct IPs → peak 3.
        inv.record_user_ip_concurrency(&[(UserId("u".into()), 1)])
            .await?;
        inv.record_user_ip_concurrency(&[(UserId("u".into()), 3)])
            .await?;
        inv.record_user_ip_concurrency(&[(UserId("u".into()), 2)])
            .await?;
        assert_eq!(
            inv.ip_concurrency_peak_for_user(&UserId("u".into()), 30)
                .await?,
            3
        );
        // since-deleted / unknown user → silently skipped, peak stays 0.
        inv.record_user_ip_concurrency(&[(UserId("ghost".into()), 9)])
            .await?;
        assert_eq!(
            inv.ip_concurrency_peak_for_user(&UserId("ghost".into()), 30)
                .await?,
            0
        );
        Ok(())
    }

    // sharing_signals_all_users gathers the two NEW signals — peak
    // concurrency (simultaneity) + country-level impossible travel — plus
    // the sub_access diversity, all keyed by user.
    #[tokio::test]
    async fn sharing_signals_gathers_concurrency_and_impossible_travel() -> Result<()> {
        let inv = fresh().await;
        inv.add_user(&sample_user("sharer")).await?;
        inv.add_user(&sample_user("solo")).await?;

        // Two `/sub` fetches for `sharer` from DIFFERENT countries 15 min
        // apart (public IPs, non-egress) → exactly one impossible-travel hop.
        async fn fetch(inv: &SqliteInventory, uid: &str, ip: &str, cc: &str, asn: &str, mins: i64) {
            sqlx::query(
                "INSERT INTO sub_access_log
                    (ts, user_id, ip, ua, status, bytes, device_class,
                     geo_country, geo_asn, is_vpn_egress)
                 VALUES (strftime('%Y-%m-%dT%H:%M:%fZ','now',?1), ?2, ?3, 'cli', 200, 100,
                         'Shadowrocket', ?4, ?5, 0)",
            )
            .bind(format!("-{mins} minutes"))
            .bind(uid)
            .bind(ip)
            .bind(cc)
            .bind(asn)
            .execute(&inv.pool)
            .await
            .unwrap();
        }
        fetch(&inv, "sharer", "203.0.113.10", "US", "AS1", 200).await;
        fetch(&inv, "sharer", "198.51.100.20", "DE", "AS2", 185).await;
        // solo — single country, single fetch (no impossible travel).
        fetch(&inv, "solo", "203.0.113.30", "RU", "AS3", 100).await;

        // Concurrency: sharer hit 3 simultaneous IPs once; solo only ever 1.
        inv.record_user_ip_concurrency(&[(UserId("sharer".into()), 3)])
            .await?;
        inv.record_user_ip_concurrency(&[(UserId("solo".into()), 1)])
            .await?;

        let sigs = inv.sharing_signals_all_users(30, 2.0).await?;
        let find = |u: &str| sigs.iter().find(|s| s.user_id.0 == u).cloned();
        let sharer = find("sharer").expect("sharer present");
        let solo = find("solo").expect("solo present");

        assert_eq!(sharer.peak_concurrent_nets, 3, "sharer concurrency peak");
        assert_eq!(
            sharer.impossible_travel_hops, 1,
            "US→DE in 15 min = one impossible-travel hop"
        );
        assert_eq!(sharer.distinct_countries, 2);
        assert_eq!(sharer.distinct_asns, 2);

        assert_eq!(
            solo.peak_concurrent_nets, 1,
            "solo never had two nets at once"
        );
        assert_eq!(solo.impossible_travel_hops, 0, "solo single country");
        Ok(())
    }

    // 0032: the fleet-dashboard ts index must exist after migrations so
    // `recent_vpn_stats_fleet` can range-scan the window instead of
    // full-scanning + temp-sorting the whole table.
    #[tokio::test]
    async fn migration_creates_vcs_ts_index() -> Result<()> {
        let inv = fresh().await;
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT name FROM sqlite_master \
             WHERE type = 'index' AND name = 'idx_vcs_ts'",
        )
        .fetch_optional(inv.pool())
        .await?;
        assert_eq!(
            row.map(|r| r.0).as_deref(),
            Some("idx_vcs_ts"),
            "migration 0032 must create idx_vcs_ts on vpn_connection_stats(ts)"
        );
        Ok(())
    }

    // 0033 (PR-Q): the additive nullable kernel-version column must
    // exist on node_health AND the per-server audit expression index
    // must exist, so `audit_for_server` gets a MULTI-INDEX OR plan
    // instead of a full SCAN of the unbounded audit_log.
    #[tokio::test]
    async fn migration_0033_adds_column_and_audit_index() -> Result<()> {
        let inv = fresh().await;
        // New nullable column present (PRAGMA table_info lists it).
        let cols: Vec<(String,)> = sqlx::query_as(
            "SELECT name FROM pragma_table_info('node_health') \
             WHERE name = 'kernel_versions_json'",
        )
        .fetch_all(inv.pool())
        .await?;
        assert_eq!(
            cols.len(),
            1,
            "0033 must add node_health.kernel_versions_json"
        );
        // New expression index present.
        let idx: Option<(String,)> = sqlx::query_as(
            "SELECT name FROM sqlite_master \
             WHERE type = 'index' AND name = 'idx_audit_payload_server'",
        )
        .fetch_optional(inv.pool())
        .await?;
        assert_eq!(
            idx.map(|r| r.0).as_deref(),
            Some("idx_audit_payload_server"),
            "0033 must create idx_audit_payload_server on audit_log(json_extract(payload,'$.server_id'))"
        );
        Ok(())
    }

    // open() must set synchronous=NORMAL (1). FULL (2) is the SQLite
    // default and was stalling unrelated writers under WAL checkpoint
    // pressure; NORMAL is WAL-safe. A connection drawn from the pool must
    // observe the pragma applied at connect time.
    #[tokio::test]
    async fn open_sets_synchronous_normal() -> Result<()> {
        let inv = fresh().await;
        let (sync_mode,): (i64,) = sqlx::query_as("PRAGMA synchronous")
            .fetch_one(inv.pool())
            .await?;
        assert_eq!(
            sync_mode, 1,
            "expected PRAGMA synchronous = 1 (NORMAL), got {sync_mode}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn server_roundtrip() -> Result<()> {
        let inv = fresh().await;
        inv.add_server(&sample_server("s1")).await?;
        let got = inv.get_server(&ServerId("s1".into())).await?.unwrap();
        assert_eq!(got.address, "1.2.3.4");
        assert_eq!(got.enabled_protocols.len(), 2);
        assert!(got.enabled_protocols.iter().any(|p| p.0 == "vless+reality"));
        Ok(())
    }

    #[tokio::test]
    async fn duplicate_server_returns_already_exists() -> Result<()> {
        let inv = fresh().await;
        inv.add_server(&sample_server("dup")).await?;
        let err = inv.add_server(&sample_server("dup")).await.unwrap_err();
        assert!(
            matches!(err, SqliteInventoryError::AlreadyExists(ref s) if s == "server dup"),
            "expected AlreadyExists(\"server dup\"), got {err:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn duplicate_user_returns_already_exists() -> Result<()> {
        let inv = fresh().await;
        inv.add_user(&sample_user("alice")).await?;
        let err = inv.add_user(&sample_user("alice")).await.unwrap_err();
        assert!(
            matches!(err, SqliteInventoryError::AlreadyExists(ref s) if s == "user alice"),
            "expected AlreadyExists(\"user alice\"), got {err:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn fingerprint_update_persists() -> Result<()> {
        let inv = fresh().await;
        inv.add_server(&sample_server("s")).await?;
        // 43-char unpadded SHA-256 base64 (russh's natural format).
        let valid = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        inv.update_trusted_fingerprint(&ServerId("s".into()), valid)
            .await?;
        let got = inv.get_server(&ServerId("s".into())).await?.unwrap();
        assert_eq!(got.trusted_host_fingerprint.as_deref(), Some(valid));
        Ok(())
    }

    #[tokio::test]
    async fn fingerprint_update_rejects_garbage() -> Result<()> {
        let inv = fresh().await;
        inv.add_server(&sample_server("s")).await?;
        for bad in ["", "abc", "MD5:xxx", "SHA256:short", "SHA256:!!!!"] {
            let err = inv
                .update_trusted_fingerprint(&ServerId("s".into()), bad)
                .await
                .unwrap_err();
            assert!(
                matches!(err, SqliteInventoryError::Invalid(_)),
                "input {bad:?} should be rejected with Invalid, got {err:?}"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn server_secrets_upsert() -> Result<()> {
        let inv = fresh().await;
        inv.add_server(&sample_server("s")).await?;
        let sid = ServerId("s".into());
        inv.set_server_secret(&sid, "reality_private", "PRIV1")
            .await?;
        inv.set_server_secret(&sid, "reality_private", "PRIV2")
            .await?; // upsert
        let got = inv.get_server_secret(&sid, "reality_private").await?;
        assert_eq!(got.as_deref(), Some("PRIV2"));
        Ok(())
    }

    #[tokio::test]
    async fn grants_and_users_for_server() -> Result<()> {
        let inv = fresh().await;
        inv.add_server(&sample_server("srv")).await?;
        inv.add_user(&sample_user("alice")).await?;
        inv.add_user(&sample_user("bob")).await?;
        inv.grant(&UserId("alice".into()), &ServerId("srv".into()))
            .await?;
        inv.grant(&UserId("bob".into()), &ServerId("srv".into()))
            .await?;
        let users = inv.users_for_server(&ServerId("srv".into())).await?;
        assert_eq!(users.len(), 2);

        inv.revoke(&UserId("alice".into()), &ServerId("srv".into()))
            .await?;
        let users = inv.users_for_server(&ServerId("srv".into())).await?;
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].id.0, "bob");
        Ok(())
    }

    #[tokio::test]
    async fn users_for_server_excludes_disabled_users() -> Result<()> {
        // (B) disable = real revoke: a disabled user must drop out of the
        // node-config slice (grant kept) so a redeploy removes them from
        // sing-box; re-enable puts them back.
        let inv = fresh().await;
        inv.add_server(&sample_server("srv")).await?;
        inv.add_user(&sample_user("alice")).await?;
        inv.add_user(&sample_user("bob")).await?;
        inv.grant(&UserId("alice".into()), &ServerId("srv".into()))
            .await?;
        inv.grant(&UserId("bob".into()), &ServerId("srv".into()))
            .await?;
        assert_eq!(
            inv.users_for_server(&ServerId("srv".into())).await?.len(),
            2
        );

        assert!(inv.set_user_disabled(&UserId("alice".into()), true).await?);
        let users = inv.users_for_server(&ServerId("srv".into())).await?;
        assert_eq!(
            users.len(),
            1,
            "disabled user must be excluded from the node config slice"
        );
        assert_eq!(users[0].id.0, "bob");

        assert!(
            inv.set_user_disabled(&UserId("alice".into()), false)
                .await?
        );
        assert_eq!(
            inv.users_for_server(&ServerId("srv".into())).await?.len(),
            2,
            "re-enabled user must return to the node config slice"
        );
        Ok(())
    }

    #[tokio::test]
    async fn cascade_delete_user_removes_grants() -> Result<()> {
        let inv = fresh().await;
        inv.add_server(&sample_server("srv")).await?;
        inv.add_user(&sample_user("alice")).await?;
        inv.grant(&UserId("alice".into()), &ServerId("srv".into()))
            .await?;
        inv.remove_user(&UserId("alice".into())).await?;
        let users = inv.users_for_server(&ServerId("srv".into())).await?;
        assert!(users.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn list_all_server_protocols_with_hidden_returns_full_matrix() -> Result<()> {
        // Pavel 2026-05-20 follow-up: the /admin/servers list page
        // needs the (server, protocol) → hidden matrix in ONE round
        // trip. Per-server bulk helper would N+1 over the inventory.
        // This test exercises the multi-server happy path: 2 servers,
        // 3 protocols each, 2 of them hidden across the matrix.
        let inv = fresh().await;

        // Server A: vless+reality + tuic-v5 (sample_server defaults)
        // → hide tuic-v5.
        inv.add_server(&sample_server("alpha")).await?;
        inv.set_server_protocol_hidden(
            &ServerId("alpha".into()),
            &ProtocolId("tuic-v5".into()),
            true,
        )
        .await?;

        // Server B: vless+reality + tuic-v5, both visible. Plus we
        // add anytls then hide it — exercises the
        // add_server_protocol + set_server_protocol_hidden path.
        inv.add_server(&sample_server("beta")).await?;
        inv.add_server_protocol(&ServerId("beta".into()), &ProtocolId("anytls".into()))
            .await?;
        inv.set_server_protocol_hidden(
            &ServerId("beta".into()),
            &ProtocolId("anytls".into()),
            true,
        )
        .await?;

        let matrix = inv.list_all_server_protocols_with_hidden().await?;

        // Total entries: alpha (2) + beta (3) = 5.
        assert_eq!(
            matrix.len(),
            5,
            "matrix should hold 5 entries (2 alpha + 3 beta), got {}",
            matrix.len()
        );
        // Spot-check the 4 distinctive cells.
        assert_eq!(
            matrix
                .get(&(ServerId("alpha".into()), ProtocolId("vless+reality".into())))
                .copied(),
            Some(false),
            "alpha.vless+reality must be visible"
        );
        assert_eq!(
            matrix
                .get(&(ServerId("alpha".into()), ProtocolId("tuic-v5".into())))
                .copied(),
            Some(true),
            "alpha.tuic-v5 must be hidden"
        );
        assert_eq!(
            matrix
                .get(&(ServerId("beta".into()), ProtocolId("tuic-v5".into())))
                .copied(),
            Some(false),
            "beta.tuic-v5 must be visible (NOT hidden — only anytls is)"
        );
        assert_eq!(
            matrix
                .get(&(ServerId("beta".into()), ProtocolId("anytls".into())))
                .copied(),
            Some(true),
            "beta.anytls must be hidden"
        );
        Ok(())
    }

    #[tokio::test]
    async fn list_all_server_protocols_with_hidden_empty_on_fresh_inventory() -> Result<()> {
        // Defensive: no servers, no protocols → empty map. The
        // /admin/servers caller relies on this for the "no servers
        // yet" empty-state to render without panicking.
        let inv = fresh().await;
        let matrix = inv.list_all_server_protocols_with_hidden().await?;
        assert!(
            matrix.is_empty(),
            "empty inventory must produce empty matrix, got {} entries",
            matrix.len()
        );
        Ok(())
    }

    #[tokio::test]
    async fn audit_log_records_and_lists() -> Result<()> {
        let inv = fresh().await;
        inv.audit(
            "cli",
            "server.create",
            Some("srv"),
            Some(&json!({"address": "1.2.3.4"})),
        )
        .await?;
        inv.audit("cli", "user.add", Some("alice"), None).await?;

        let log = inv.recent_audit(10).await?;
        assert_eq!(log.len(), 2);
        // recent_audit orders by id DESC, so user.add comes first.
        assert_eq!(log[0].action, "user.add");
        assert_eq!(log[1].action, "server.create");
        assert_eq!(
            log[1]
                .payload
                .as_ref()
                .and_then(|v| v.get("address"))
                .and_then(|v| v.as_str()),
            Some("1.2.3.4")
        );
        Ok(())
    }

    // ── Phase 5b destination-writer robustness ──────────────────────────

    #[tokio::test]
    async fn record_user_destinations_truncates_multibyte_label_without_panic() -> Result<()> {
        // A destination label whose byte-200 lands mid-codepoint must
        // NOT panic the writer (the old `&dest[..200]` slice did — and
        // that panic propagates uncaught through `clash_poller`,
        // permanently aborting the whole poll task). Build a label
        // where byte 200 is inside a 4-byte emoji: leading ASCII 'a'
        // (1 byte) + repeated 😀 (4 bytes each) → boundaries at 1+4k,
        // and 200 ≡ 3 (mod 4) from offset 1 → NOT a char boundary.
        let inv = fresh().await;
        inv.add_user(&sample_user("alice")).await?;

        let mut dest = String::from("a");
        dest.push_str(&"😀".repeat(60)); // 1 + 240 = 241 bytes, 61 chars
        assert!(dest.len() > 200, "label must exceed 200 bytes");
        assert!(
            !dest.is_char_boundary(200),
            "byte 200 must land mid-codepoint to exercise the panic path",
        );

        // Must not panic.
        inv.record_user_destinations(&[(UserId("alice".into()), dest.clone())])
            .await?;

        let rows = inv
            .top_destinations_for_user(&UserId("alice".into()), 1, 10)
            .await?;
        assert_eq!(rows.len(), 1, "the valid pair must have landed");
        let stored = &rows[0].destination_label;
        // Stored truncated on a CHAR boundary (so it round-trips as
        // valid UTF-8) and capped at ≤ 200 chars.
        assert!(
            stored.chars().count() <= 200,
            "label capped at 200 chars, got {} chars",
            stored.chars().count(),
        );
        assert!(
            dest.starts_with(stored.as_str()),
            "stored label must be a char-boundary prefix of the input",
        );
        Ok(())
    }

    #[tokio::test]
    async fn record_user_destinations_skips_unknown_user_without_aborting_batch() -> Result<()> {
        // The user_id comes from the log-scrape attribution map (a raw
        // username), NOT validated against `users`. A pair for a
        // since-deleted user would raise an FK error and (under `?`)
        // roll back the WHOLE tx, losing every user's destinations for
        // the tick. The writer's `WHERE EXISTS (… users …)` pre-filter
        // must skip ONLY the offending row; the valid pairs in the same
        // batch must still land.
        let inv = fresh().await;
        inv.add_user(&sample_user("alice")).await?;
        inv.add_user(&sample_user("bob")).await?;

        let pairs = vec![
            (UserId("alice".into()), "youtube.com:443".to_string()),
            // "ghost" was never added → FK violation on insert.
            (UserId("ghost".into()), "discord.com:443".to_string()),
            (UserId("bob".into()), "telegram.org:443".to_string()),
        ];

        // No error must bubble — the batch is not rolled back.
        inv.record_user_destinations(&pairs).await?;

        let alice = inv
            .top_destinations_for_user(&UserId("alice".into()), 1, 10)
            .await?;
        let bob = inv
            .top_destinations_for_user(&UserId("bob".into()), 1, 10)
            .await?;
        let ghost = inv
            .top_destinations_for_user(&UserId("ghost".into()), 1, 10)
            .await?;

        assert_eq!(alice.len(), 1, "alice's valid row must have landed");
        assert_eq!(alice[0].destination_label, "youtube.com:443");
        assert_eq!(bob.len(), 1, "bob's valid row must have landed");
        assert_eq!(bob[0].destination_label, "telegram.org:443");
        assert!(
            ghost.is_empty(),
            "the FK-violating ghost row must be skipped"
        );
        Ok(())
    }

    // ── set_grant_client_uuid no-op audit suppression ───────────────────

    #[tokio::test]
    async fn set_grant_client_uuid_same_value_writes_no_audit_row() -> Result<()> {
        // SQLite's rows_affected() counts matched-not-changed rows, so a
        // plain `UPDATE … WHERE user=? AND server=?` re-writing the SAME
        // uuid still passes the `>0` guard and emits a no-op
        // `grant.set_client_uuid` audit row (old == new). The
        // `AND client_uuid IS NOT ?` no-op gate must make a same-value
        // write affect 0 rows and skip the audit, mirroring
        // set_user_disabled / set_server_protocol_hidden.
        let inv = fresh().await;
        inv.add_server(&sample_server("srv")).await?;
        inv.add_user(&sample_user("alice")).await?;
        inv.grant(&UserId("alice".into()), &ServerId("srv".into()))
            .await?;

        let uuid = "11111111-1111-4111-8111-111111111111";
        inv.set_grant_client_uuid(&UserId("alice".into()), &ServerId("srv".into()), uuid)
            .await?;

        let audit_after_first: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM audit_log WHERE action = 'grant.set_client_uuid'")
                .fetch_one(inv.pool())
                .await?;
        assert_eq!(
            audit_after_first.0, 1,
            "first set must write exactly one audit row"
        );

        // Re-write the SAME value → no-op, no new audit row.
        inv.set_grant_client_uuid(&UserId("alice".into()), &ServerId("srv".into()), uuid)
            .await?;

        let audit_after_second: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM audit_log WHERE action = 'grant.set_client_uuid'")
                .fetch_one(inv.pool())
                .await?;
        assert_eq!(
            audit_after_second.0, 1,
            "re-writing the same client_uuid must NOT add a second audit row"
        );

        // A genuine change still audits (regression guard).
        let uuid2 = "22222222-2222-4222-8222-222222222222";
        inv.set_grant_client_uuid(&UserId("alice".into()), &ServerId("srv".into()), uuid2)
            .await?;
        let audit_after_change: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM audit_log WHERE action = 'grant.set_client_uuid'")
                .fetch_one(inv.pool())
                .await?;
        assert_eq!(
            audit_after_change.0, 2,
            "a real value change must still emit an audit row"
        );

        // Setting client_uuid on a (user, server) with no grant must
        // still error (the no-op gate must not mask the missing grant).
        inv.add_user(&sample_user("bob")).await?;
        let err = inv
            .set_grant_client_uuid(&UserId("bob".into()), &ServerId("srv".into()), uuid)
            .await;
        assert!(
            err.is_err(),
            "setting client_uuid without a grant must still error"
        );
        Ok(())
    }

    // ── session_observe FK gate ─────────────────────────────────────────

    #[tokio::test]
    async fn session_observe_skips_unknown_user() -> Result<()> {
        // user_id comes from the log-scrape attribution map (a raw
        // username), NOT validated against `users`. With foreign_keys=ON
        // and vpn_user_sessions.user_id NOT NULL REFERENCES users(id), an
        // INSERT for a since-deleted user raises FK error 787. The
        // `WHERE EXISTS (… users …)` gate must skip it cleanly: no error
        // bubbles, no row inserted, and a valid user's session still
        // records.
        let inv = fresh().await;
        inv.add_server(&sample_server("srv")).await?;
        inv.add_user(&sample_user("alice")).await?;
        let now = chrono::Utc::now();

        // Unknown user → no FK error, nothing inserted (rowid 0 sentinel).
        let ghost_id = inv
            .session_observe(
                &UserId("ghost".into()),
                &ServerId("srv".into()),
                now,
                15,
                0,
                1,
            )
            .await?;
        assert_eq!(ghost_id, 0, "unknown user must insert no session row");

        let ghost_sessions = inv
            .recent_sessions_for_user(&UserId("ghost".into()), 10)
            .await?;
        assert!(
            ghost_sessions.is_empty(),
            "no session row may exist for an unknown user"
        );

        // Valid user still records.
        let alice_id = inv
            .session_observe(
                &UserId("alice".into()),
                &ServerId("srv".into()),
                now,
                15,
                0,
                1,
            )
            .await?;
        assert!(alice_id > 0, "a known user's session must record");
        let alice_sessions = inv
            .recent_sessions_for_user(&UserId("alice".into()), 10)
            .await?;
        assert_eq!(
            alice_sessions.len(),
            1,
            "the known user's session must land"
        );
        Ok(())
    }
}
