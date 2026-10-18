pub mod access_log;
pub mod alert_sink;
pub mod alert_text;
pub mod app;
pub mod boosty_sync_poller;
pub mod clash_api;
pub mod clash_poller;
pub mod config;
pub mod dns_resolver;
pub mod exchange_rate_poller;
pub mod geoip;
pub mod geoip_update_runner;
pub mod handlers;
pub mod health_monitor;
pub mod http_util;
pub mod i18n;
pub mod ip_kind;
pub mod node_probe;
pub mod node_probe_poller;
pub mod protocol_assurance_poller;
pub mod quality_poller;
pub mod rate_limit;
pub mod real_ip;
pub mod sharing_score;
mod singbox_stats;
pub mod snapshot_cache;
pub mod ssh_subprocess;
pub mod ua;
pub mod wg_stats_poller;
pub mod wizard;
pub mod wizard_bootstrap;

pub use app::{
    AppState, build, make_app_state_for_tests, make_app_state_with_rate_limiter, router,
};
pub use config::{DaemonConfig, assert_auth_safe_for_addr, assert_auth_safe_for_addr_with};

pub fn spawn_retention_purger_for_test(
    inv: vpnctl_inventory::SqliteInventory,
) -> tokio::task::JoinHandle<()> {
    app::spawn_retention_purger(inv)
}

pub fn spawn_node_probe_poller_for_test(
    inv: vpnctl_inventory::SqliteInventory,
) -> tokio::task::JoinHandle<()> {
    node_probe_poller::spawn_node_probe_poller(inv)
}

pub fn spawn_health_monitor_for_test(
    inv: vpnctl_inventory::SqliteInventory,
) -> tokio::task::JoinHandle<()> {
    health_monitor::spawn_health_monitor(inv)
}

pub fn spawn_backup_scheduler_with_for_test(
    inv: vpnctl_inventory::SqliteInventory,
    backup_dir: std::path::PathBuf,
    startup_delay: std::time::Duration,
    tick: std::time::Duration,
) -> tokio::task::JoinHandle<()> {
    app::spawn_backup_scheduler_with(inv, backup_dir, startup_delay, tick)
}
