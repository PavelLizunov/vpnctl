//! Library face of `vpnctld`. Lets integration tests build the SAME
//! `Router` that the binary uses, so spec tests assert the real handler
//! contract instead of a shim. Without this, the daemon binary alone
//! has no externally-visible surface and tests must reimplement the
//! Router structure (which defeats the purpose of spec tests).
//!
//! The binary itself just calls `vpnctld::serve(config)` — kept thin.

pub mod access_log;
pub mod app;
// Locale detection (cookie + Accept-Language) + the bilingual EN/RU
// translation table for admin UI chrome. Pavel 2026-05-21.
pub mod i18n;
// GeoIP / ASN lookup for the access-log writer (Track-1.2). Stub
// when the daemon is built without the `geoip` feature or when
// VPNCTLD_GEOIP_DIR isn't set — handlers see no behaviour change,
// the new columns just stay NULL in the DB.
pub mod geoip;
// Shared User-Agent parser for the access-log writer + admin UI
// rendering. Lives outside `handlers::admin` so both surfaces share
// one truth (Track-1.2 / migration 0019).
pub mod ua;
// IPv4 classifier (loopback / RFC1918 / link-local / public) shared
// between admin render (chip colour) and access-log writer
// (suspicious-LAN-IP alert predicate). Pavel 2026-05-21.
pub mod ip_kind;
// Real-client-IP resolution from X-Forwarded-For when the immediate
// peer is a trusted reverse proxy (post-Phase-5 nginx cutover).
// Without this every external client collapses to the nginx peer IP
// → rate-limit single-bucket + per-user distinct-IP counter = 1.
pub mod boosty_sync_poller;
pub mod clash_api;
pub mod clash_poller;
pub mod config;
pub mod handlers;
pub mod health_monitor;
pub mod real_ip;
// AmneziaWG per-user source-IP poller — the "amneziawg metrics from wg show"
// path clash_poller's skip comment names; feeds the sharing verdict for WG.
pub mod wg_stats_poller;
// Composite account-sharing risk scorer (weighted, explainable) — replaces
// the single `distinct_asns >= 3` heuristic. Pavel 2026-06-17.
pub mod sharing_score;
// Generic HTTP helpers shared across handler surfaces and (in the
// future) CLI consumers of form-encoded payloads. Started life as
// `decode_form_value` inlined in `handlers/admin.rs`; extracted so
// the next surface that needs form decoding doesn't reinvent it.
pub mod http_util;
// Phase G chunk 3 — pluggable push-notification sink. NullSink as
// default; TelegramSink for the operator's configured chat. Future
// ntfy.sh / journald-bridge land as sibling impls in the same module.
pub mod alert_sink;
/// Localized (ru/en) + pretty rendering of alert messages. Consumed by
/// `alert_sink` (Telegram HTML push) and the admin UI alert surfaces.
pub mod alert_text;
pub mod node_probe;
pub mod node_probe_poller;
pub mod protocol_assurance_poller;
pub mod quality_poller;
pub mod rate_limit;
// Subprocess-based SSH transport — wraps system `ssh` binary instead
// of linking russh. Lets vpnctld talk to nodes without pulling
// glibc 2.38; see ssh_subprocess.rs for the rationale.
pub mod ssh_subprocess;
// Phase 4c — in-memory cache of the last clash-api snapshot per VPN
// server, plus per-destination / per-source aggregation helpers
// for the Live-connections drill-down on /admin/servers/<id>.
// Cache is shared between the poller (writer) and admin handlers
// (readers) through a SnapshotCache handle that lives in AppState.
pub mod snapshot_cache;
// Phase 5a-2 — periodic reverse-DNS (PTR) resolver. Walks the
// SnapshotCache, picks unique destination IPs lacking a host
// field, shells out to `getent hosts <ip>` via spawn_blocking,
// caches results in `dns_ptr_cache` (7-day TTL).
pub mod dns_resolver;
// Phase 3c — SSE backend for the Settings GeoIP «update now» button.
// Wraps `/usr/local/bin/vpnctl geoip-update` via `std::process::Command`
// + `tokio::task::spawn_blocking`. NOT `tokio::process` (glibc 2.39+
// pidfd_spawnp = prod crash on bookworm). Same workaround pattern as
// `ssh_subprocess`.
pub mod geoip_update_runner;
pub mod wizard;
// Phase E sub-iter 4b — wizard SSE bootstrap engine. Pulled out of
// the admin handler so the bootstrap pipeline can be unit-tested
// without spinning up an axum router. See module-level doc for the
// 9-phase pipeline.
pub mod wizard_bootstrap;

pub use app::{
    AppState, build, make_app_state_for_tests, make_app_state_with_rate_limiter, router,
};
pub use config::{DaemonConfig, assert_auth_safe_for_addr, assert_auth_safe_for_addr_with};

/// Test-only re-export of the retention purger spawner so integration
/// tests can verify the wiring. Production code uses
/// `vpnctld::build()` which calls this internally.
pub fn spawn_retention_purger_for_test(
    inv: vpnctl_inventory::SqliteInventory,
) -> tokio::task::JoinHandle<()> {
    app::spawn_retention_purger(inv)
}

/// Test-only re-export of the node-probe poller (Phase H chunk 4)
/// spawner so integration tests can verify the wiring without
/// constructing a full `AppState`. Production code uses
/// `vpnctld::build()` which calls this internally.
pub fn spawn_node_probe_poller_for_test(
    inv: vpnctl_inventory::SqliteInventory,
) -> tokio::task::JoinHandle<()> {
    node_probe_poller::spawn_node_probe_poller(inv)
}

/// Test-only re-export of the Phase G health-monitor spawner so the
/// integration suite can verify the wiring. Production code uses
/// `vpnctld::build()` which calls this internally.
pub fn spawn_health_monitor_for_test(
    inv: vpnctl_inventory::SqliteInventory,
) -> tokio::task::JoinHandle<()> {
    health_monitor::spawn_health_monitor(inv)
}

/// Test-only re-export of the backup scheduler with custom delays
/// — lets the integration test prove the scheduler actually
/// snapshots + audits without waiting the production 60-second
/// startup delay.
pub fn spawn_backup_scheduler_with_for_test(
    inv: vpnctl_inventory::SqliteInventory,
    backup_dir: std::path::PathBuf,
    startup_delay: std::time::Duration,
    tick: std::time::Duration,
) -> tokio::task::JoinHandle<()> {
    app::spawn_backup_scheduler_with(inv, backup_dir, startup_delay, tick)
}
