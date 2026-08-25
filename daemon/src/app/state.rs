//! Application state, configuration constants, and startup build pipeline.

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

/// Per-process state cloned into every handler.
///
/// * `access_log_tx` — Phase Track-1 producer side of the bounded
///   mpsc that drains into `sub_access_log` (see `crate::access_log`
///   for the full rationale).
/// * `rate_limiter` — Phase Track-2 token-bucket limiter for `/sub`,
///   throttles abuse before the daemon spends meaningful work (see
///   `crate::rate_limit` for the design).
///
/// Cloning `AppState` clones the `Sender` and bumps the `Arc`s — the
/// channel stays open and the limiter stays shared across all
/// per-request clones.
#[derive(Clone)]
pub struct AppState {
    pub inv: SqliteInventory,
    pub registry: Arc<Registry>,
    pub access_log_tx: mpsc::Sender<AccessLogRecord>,
    pub rate_limiter: Arc<RateLimiter>,
    /// Phase E — add-server wizard's in-flight session store. Holds
    /// the operator's step-1 input (IP + root password) between the
    /// step-1 POST and the step-2 SSE handler. See `crate::wizard`
    /// for TTL + key schema.
    pub wizard: Arc<WizardStore>,
    /// Phase 4c — in-memory cache of the last clash-api snapshot
    /// per VPN server. Filled by `spawn_clash_poller` on every
    /// successful 5-minute tick; read by the server-detail handler
    /// to render the «Live connections» drill-down. Cheap to
    /// `.clone()` (internal `Arc`).
    pub snapshot_cache: crate::snapshot_cache::SnapshotCache,
    /// TT-1 — the MaxMind GeoIP reader (mmap-backed, Arc-inside, cheap
    /// to clone), built once at startup via `GeoLookup::from_env()`.
    /// The access-log WRITER already enriches sub_access_log rows at
    /// insert time; this lets RENDER paths resolve an arbitrary IP
    /// directly — notably the clash-api «Source IPs» table, whose geo
    /// used to be parasitically borrowed from sub_access_log (broken
    /// once the front proxy masked client IPs).
    pub geo: crate::geoip::GeoLookup,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState").finish_non_exhaustive()
    }
}

/// Default deploy-key path for vpnctld. Matches the path the
/// `/admin/settings` page surfaces + the path poller/deploy tasks
/// read via `VPNCTLD_DEPLOY_KEY` env (which wins if set).
pub const DEFAULT_DEPLOY_KEY_PATH: &str = "/var/lib/vpnctl/.ssh/id_ed25519";

/// Pure core of [`deploy_key_path`]: resolve deploy-key path given the
/// optional raw environment variable value (`None` = unset).
///
/// Pure so it is unit-testable without touching the process environment.
pub fn resolve_deploy_key_path(raw: Option<&str>) -> std::path::PathBuf {
    match raw {
        Some(val) if !val.trim().is_empty() => std::path::PathBuf::from(val.trim()),
        _ => std::path::PathBuf::from(DEFAULT_DEPLOY_KEY_PATH),
    }
}

/// Central resolver for vpnctld's deploy SSH key path.
///
/// Honors the `VPNCTLD_DEPLOY_KEY` environment variable when non-empty,
/// otherwise falls back to [`DEFAULT_DEPLOY_KEY_PATH`].
pub fn deploy_key_path() -> std::path::PathBuf {
    resolve_deploy_key_path(std::env::var("VPNCTLD_DEPLOY_KEY").ok().as_deref())
}

/// Default backup directory for vpnctld. Surfaced in the Settings page's
/// Backups section. Same value as `vpnctl_inventory::DEFAULT_BACKUP_DIR`
/// — re-exported here so the daemon's other surfaces (download
/// handler, scheduler) can reference one canonical constant.
pub const DEFAULT_BACKUP_DIR: &str = vpnctl_inventory::DEFAULT_BACKUP_DIR;

pub async fn build(config: DaemonConfig) -> anyhow::Result<Router> {
    let inv = SqliteInventory::open(&config.db_path).await?;
    let registry = Arc::new(build_registry()?);

    // Auto-bootstrap vpnctld's deploy SSH key on first start.
    // Generates an ed25519 keypair at the resolved deploy key path
    // via the system `ssh-keygen` binary (no Rust crypto deps).
    // Idempotent — re-call when the key already exists is a no-op.
    // The public half is surfaced in the admin Settings page so the
    // operator can paste it into each VPN node's authorized_keys.
    // After that, every web-deploy / poller call is fully self-service.
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

    // Phase Track-1.1 retention scheduler: hourly purge of access-log
    // rows older than 30 days. The user-detail page promises this
    // ("auto-purged after 30 days") — without the scheduler the rows
    // accumulate forever and the UI lies.
    //
    // Spawned ONLY here, not in `router()` — tests construct AppState
    // directly via `router(state)` and don't need a background tokio
    // task running per test (those leak handles across the test
    // process). Production goes through `build()` and gets one purger
    // per daemon process. The returned JoinHandle is intentionally
    // dropped — the task lives until the process exits, and the
    // tokio runtime aborts it on graceful shutdown.
    drop(spawn_retention_purger(inv.clone()));

    // Phase Track-3 chunk 4 — periodic clash-api poller.
    // Uses SubprocessSshTransport (Path C), so no Cargo-feature
    // gate + no glibc 2.38 dep. Spawned unconditionally; the poller
    // itself logs-and-skips when the SSH key isn't on the homelab
    // host yet OR when a node hasn't authorised it.
    //
    // Phase 4c — the poller also fills `snapshot_cache` with the
    // full per-tick snapshot (per-connection detail) so the admin
    // UI's «Live connections» drill-down has data to render.
    let snapshot_cache = crate::snapshot_cache::SnapshotCache::new();
    drop(crate::clash_poller::spawn_clash_poller(
        inv.clone(),
        snapshot_cache.clone(),
    ));

    // AmneziaWG per-user source-IP poller — clash-api covers only sing-box,
    // so `wireguard`-protocol users (served by the amneziawg kernel, iface
    // awg0) were invisible to the sharing verdict. This SSHes each amneziawg
    // node's `awg show awg0 dump`, maps peer pubkeys → users, and records
    // their endpoint IPs into the same `vpn_user_source_ips` the verdict reads.
    drop(crate::wg_stats_poller::spawn_wg_stats_poller(inv.clone()));

    // Phase 5a-2 — periodic reverse-DNS resolver. Walks
    // `snapshot_cache` for unique destination IPs lacking a host
    // field, calls `getent hosts <ip>`, caches result in
    // `dns_ptr_cache`. Admin UI's «top destinations» table
    // enriches IP-only labels with the cached hostname.
    drop(crate::dns_resolver::spawn_dns_resolver(
        inv.clone(),
        snapshot_cache.clone(),
    ));

    // Phase H chunk 4 — periodic node_health probe (systemctl /
    // disk / mem / load / listening ports / sing-box log size).
    // Same SubprocessSshTransport, same skip-when-no-key behaviour,
    // independent cadence (10 min by default vs clash's 5 min — see
    // node_probe_poller doc-comment for the cadence rationale).
    // Until this is wired, `/admin/servers/{id}` shows empty-state
    // forever because the underlying `node_health` table never
    // gets a row.
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

    // Phase G — operator-facing alerts on top of node_health rows.
    // Same cadence as the probe (10 min) — no point scanning faster
    // than the probe writes. Each scan diffs the two newest rows per
    // server and INSERTs an admin_alerts row + mirrored audit row
    // on every state-change.
    drop(crate::health_monitor::spawn_health_monitor(inv.clone()));

    // Daily fleet digest to Telegram (all-clear 🟢 or the open-problems
    // list), localized. Cadence env-overridable via
    // VPNCTLD_DIGEST_INTERVAL_SECS (default 86400 = 24h); the first
    // digest fires one interval after start, not at boot. No-op until
    // the operator configures the Telegram transport.
    drop(spawn_digest_scheduler(inv.clone()));

    // Boosty → VPN subscription bridge. When enabled in boosty_settings,
    // reconciles VPN access with the blog's subscriber roster on its own
    // cadence (auto-enable active subscribers; surface or auto-disable
    // lapsed ones), then re-deploys the affected users' servers so the
    // flips reach the nodes. No-op tick while disabled — safe to always
    // spawn.
    drop(crate::boosty_sync_poller::spawn_boosty_sync_poller(
        inv.clone(),
        Arc::clone(&registry),
        deploy_key_path.clone(),
    ));

    // Phase Track-1 back-pressure (audit-fix B + retroactive review #3
    // / security #2): a dedicated writer task drains a bounded mpsc
    // channel into `sub_access_log`. Without this, an attacker
    // holding ONE valid sub-token could OOM the daemon by spawning a
    // tokio task per request.
    let (access_log_tx, _writer_handle) = access_log::spawn_writer(inv.clone());

    // Phase Track-2 rate limiter: token bucket per (IP, token).
    // Defaults give 5-burst then 1 token / 30 sec. See `rate_limit`
    // module docs for the design rationale.
    let rate_limiter = Arc::new(RateLimiter::default());

    // Phase E — wizard session store. Created here (not inline in the
    // AppState literal) so the rate-limit cleanup task can share it
    // and sweep expired sessions on its tick (Round-3 L1).
    let wizard = Arc::new(WizardStore::new());

    // Periodic cleanup of idle bucket entries (otherwise the per-IP
    // map grows unbounded over time). 10-minute cadence is plenty —
    // the idle TTL is 1 hour by default. Also sweeps abandoned wizard
    // sessions (their TTL is 10 min, matching this cadence).
    drop(spawn_rate_limit_cleanup(
        Arc::clone(&rate_limiter),
        inv.clone(),
        Arc::clone(&wizard),
    ));

    // Phase C-4 — hourly inventory snapshot to /var/lib/vpnctl/backups
    // plus retention pruning (24h / 30d / 12mo). Settings UI surfaces
    // the snapshot list + a manual "snapshot now" button + per-file
    // download anchor for operator off-site (USB, cloud, etc).
    // Restore is CLI-only — the daemon literally can't replace its
    // own open DB file while it's holding it (see `vpnctl restore`).
    drop(spawn_backup_scheduler(
        inv.clone(),
        std::path::PathBuf::from(vpnctl_inventory::DEFAULT_BACKUP_DIR),
    ));

    // 2026-05-23 — initialise the global display-TZ cache from
    // `display_settings.timezone` (migration 0027). Parse failure
    // → log + fall back to Europe/Moscow (the seed default).
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

    // TT-1 — same env-driven loader the access-log writer uses, so
    // render-side geo resolution and write-side enrichment read the
    // exact same DB files.
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
    Ok(router(state))
}

/// Test-only: build an `AppState` with the access-log writer wired up,
/// the same way `build()` does. Returns the `AppState` plus the
/// writer's `JoinHandle` so the test can `abort()` it deterministically
/// at teardown (the task otherwise lives until all senders drop, which
/// happens when the state goes out of scope — usually fine, but tests
/// that want to inspect the writer's behavior need the explicit handle).
///
/// The rate limiter is built with `RateLimiter::default()` (production
/// capacity). Tests that want to exercise throttling can build their
/// own state with a tighter limiter; see
/// `make_app_state_with_rate_limiter` for that path.
pub fn make_app_state_for_tests(
    inv: SqliteInventory,
    registry: Arc<Registry>,
) -> (AppState, tokio::task::JoinHandle<()>) {
    make_app_state_with_rate_limiter(inv, registry, Arc::new(RateLimiter::default()))
}

/// Test-only: like `make_app_state_for_tests` but takes a custom
/// `RateLimiter` so tests can exercise throttling against a
/// deterministically-tuned limiter (e.g. capacity=2, refill=0/sec)
/// without waiting for production-rate refills.
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
            // Tests run without mmdb files — the disabled stub falls
            // back to the sub_access_log join + reserved-range labels,
            // exactly the pre-TT-1 behaviour the existing specs pin.
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
