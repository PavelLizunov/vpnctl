use std::sync::Arc;

use axum::Router;
use tokio::sync::mpsc;

use vpnctl_core::Registry;
use vpnctl_inventory::SqliteInventory;

use crate::access_log::{self, AccessLogRecord};
use crate::config::DaemonConfig;
use crate::rate_limit::RateLimiter;
use crate::wizard::WizardStore;

use super::registry::build_registry;
use super::routes::router;
use super::schedulers::{
    spawn_backup_scheduler, spawn_digest_scheduler, spawn_rate_limit_cleanup,
    spawn_retention_purger,
};

#[derive(Clone)]
pub struct AppState {
    pub inv: SqliteInventory,
    pub registry: Arc<Registry>,
    pub access_log_tx: mpsc::Sender<AccessLogRecord>,
    pub rate_limiter: Arc<RateLimiter>,
    pub wizard: Arc<WizardStore>,
    pub snapshot_cache: crate::snapshot_cache::SnapshotCache,
    pub geo: crate::geoip::GeoLookup,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState").finish_non_exhaustive()
    }
}

pub const DEFAULT_DEPLOY_KEY_PATH: &str = "/var/lib/vpnctl/.ssh/id_ed25519";

pub fn resolve_deploy_key_path(raw: Option<&str>) -> std::path::PathBuf {
    match raw {
        Some(val) if !val.trim().is_empty() => std::path::PathBuf::from(val.trim()),
        _ => std::path::PathBuf::from(DEFAULT_DEPLOY_KEY_PATH),
    }
}

pub fn deploy_key_path() -> std::path::PathBuf {
    resolve_deploy_key_path(std::env::var("VPNCTLD_DEPLOY_KEY").ok().as_deref())
}

pub const DEFAULT_BACKUP_DIR: &str = vpnctl_inventory::DEFAULT_BACKUP_DIR;

pub async fn build(config: DaemonConfig) -> anyhow::Result<(Router, tokio::task::JoinHandle<()>)> {
    let inv = SqliteInventory::open(&config.db_path).await?;
    let registry = Arc::new(build_registry()?);

    let deploy_key_path = deploy_key_path();
    if let Err(e) = crate::ssh_subprocess::ensure_deploy_key(&deploy_key_path).await {
        tracing::warn!(
            target = "vpnctld::startup",
            path = %deploy_key_path.display(),
            error = %e,
            "deploy key auto-generation failed — web deploy + poller will fall back to logging warnings until resolved. Most common cause: vpnctld user lacks write access to /var/lib/vpnctl/.ssh/"
        );
    } else {
        tracing::info!(
            target = "vpnctld::startup",
            path = %deploy_key_path.display(),
            "deploy key ready (auto-generated if absent)"
        );
    }

    drop(spawn_retention_purger(inv.clone()));

    let snapshot_cache = crate::snapshot_cache::SnapshotCache::new();
    drop(crate::clash_poller::spawn_clash_poller(
        inv.clone(),
        snapshot_cache.clone(),
    ));

    drop(crate::wg_stats_poller::spawn_wg_stats_poller(inv.clone()));

    drop(crate::dns_resolver::spawn_dns_resolver(
        inv.clone(),
        snapshot_cache.clone(),
    ));

    drop(crate::node_probe_poller::spawn_node_probe_poller(
        inv.clone(),
    ));
    drop(crate::quality_poller::spawn_quality_poller(
        inv.clone(),
        Arc::clone(&registry),
    ));
    drop(
        crate::protocol_assurance_poller::spawn_protocol_assurance_poller(
            inv.clone(),
            Arc::clone(&registry),
        ),
    );

    drop(crate::health_monitor::spawn_health_monitor(inv.clone()));

    drop(spawn_digest_scheduler(inv.clone()));

    drop(crate::boosty_sync_poller::spawn_boosty_sync_poller(
        inv.clone(),
        Arc::clone(&registry),
        deploy_key_path.clone(),
    ));

    drop(crate::exchange_rate_poller::spawn_exchange_rate_poller(
        inv.clone(),
    ));

    let (access_log_tx, writer_handle) = access_log::spawn_writer(inv.clone());

    let rate_limiter = Arc::new(RateLimiter::default());

    let wizard = Arc::new(WizardStore::new());

    drop(spawn_rate_limit_cleanup(
        Arc::clone(&rate_limiter),
        inv.clone(),
        Arc::clone(&wizard),
    ));

    drop(spawn_backup_scheduler(
        inv.clone(),
        vpnctl_inventory::backup_dir_from_env(),
    ));

    match inv.get_display_timezone().await {
        Ok(name) => {
            let tz: chrono_tz::Tz = name.parse().unwrap_or_else(|_| {
                tracing::warn!(
                    target = "vpnctld::startup",
                    saved_name = %name,
                    "display_settings.timezone is not a valid IANA name; falling back to Europe/Moscow"
                );
                chrono_tz::Europe::Moscow
            });
            crate::handlers::admin::init_display_tz(tz);
        }
        Err(e) => {
            tracing::warn!(target = "vpnctld::startup", error = %e, "get_display_timezone failed; using Europe/Moscow default");
            crate::handlers::admin::init_display_tz(chrono_tz::Europe::Moscow);
        }
    }

    let geo = crate::geoip::GeoLookup::from_env();
    let state = AppState {
        inv,
        registry,
        access_log_tx,
        rate_limiter,
        wizard,
        snapshot_cache,
        geo,
    };
    Ok((router(state), writer_handle))
}

pub fn make_app_state_for_tests(
    inv: SqliteInventory,
    registry: Arc<Registry>,
) -> (AppState, tokio::task::JoinHandle<()>) {
    make_app_state_with_rate_limiter(inv, registry, Arc::new(RateLimiter::default()))
}

pub fn make_app_state_with_rate_limiter(
    inv: SqliteInventory,
    registry: Arc<Registry>,
    rate_limiter: Arc<RateLimiter>,
) -> (AppState, tokio::task::JoinHandle<()>) {
    let (access_log_tx, handle) = access_log::spawn_writer(inv.clone());
    (
        AppState {
            inv,
            registry,
            access_log_tx,
            rate_limiter,
            wizard: Arc::new(WizardStore::new()),
            snapshot_cache: crate::snapshot_cache::SnapshotCache::new(),
            geo: crate::geoip::GeoLookup::disabled(),
        },
        handle,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn resolve_deploy_key_path_defaults_when_unset() {
        assert_eq!(
            resolve_deploy_key_path(None),
            PathBuf::from(DEFAULT_DEPLOY_KEY_PATH)
        );
    }

    #[test]
    fn resolve_deploy_key_path_defaults_when_empty() {
        assert_eq!(
            resolve_deploy_key_path(Some("")),
            PathBuf::from(DEFAULT_DEPLOY_KEY_PATH)
        );
    }

    #[test]
    fn resolve_deploy_key_path_defaults_when_whitespace_only() {
        assert_eq!(
            resolve_deploy_key_path(Some("   \t \n ")),
            PathBuf::from(DEFAULT_DEPLOY_KEY_PATH)
        );
    }

    #[test]
    fn resolve_deploy_key_path_honors_custom_override() {
        assert_eq!(
            resolve_deploy_key_path(Some("/etc/vpnctl/custom_id_ed25519")),
            PathBuf::from("/etc/vpnctl/custom_id_ed25519")
        );
    }

    #[test]
    fn resolve_deploy_key_path_trims_whitespace() {
        assert_eq!(
            resolve_deploy_key_path(Some("  /custom/key/path  ")),
            PathBuf::from("/custom/key/path")
        );
    }

    #[test]
    fn deploy_key_path_matches_pure_resolver() {
        let expected = resolve_deploy_key_path(std::env::var("VPNCTLD_DEPLOY_KEY").ok().as_deref());
        assert_eq!(deploy_key_path(), expected);
    }
}
