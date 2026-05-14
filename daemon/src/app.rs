//! Wire the axum Router. Kept separate from `main.rs` so tests can build
//! the same Router without the network/signal plumbing.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::MatchedPath;
use axum::http::Request;
use axum::routing::{get, post};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::services::ServeDir;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tracing::info_span;

use crate::handlers::auth::BasicAuth;

use crate::config::DaemonConfig;
use crate::handlers;
use vpnctl_core::Registry;
use vpnctl_inventory::SqliteInventory;

#[derive(Clone)]
pub struct AppState {
    pub inv: SqliteInventory,
    pub registry: Arc<Registry>,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState").finish_non_exhaustive()
    }
}

pub async fn build(config: DaemonConfig) -> anyhow::Result<Router> {
    let inv = SqliteInventory::open(&config.db_path).await?;
    let registry = Arc::new(build_registry()?);

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

    let state = AppState { inv, registry };
    Ok(router(state))
}

/// Spawn the access-log retention purger. Returns the `JoinHandle` so
/// callers (production: discard; tests: abort to prove the spawn worked
/// without letting the loop actually tick). The loop body is
/// `inv.purge_sub_access_older_than(30)` which has full spec coverage in
/// `crates/inventory/tests/spec_sub_access.rs` — the scheduler itself
/// is dumb wiring around it.
pub(crate) fn spawn_retention_purger(inv: SqliteInventory) -> tokio::task::JoinHandle<()> {
    use std::time::Duration;
    use tokio::time::{MissedTickBehavior, interval};

    /// 30-day retention matches the user-detail page copy. Configurable
    /// later via the Settings section.
    const RETENTION_DAYS: u32 = 30;
    /// Hourly cadence is plenty — the purge cost grows linearly with
    /// row count, and at homelab scale (<10k rows/day) one tick per
    /// hour bounds the table to ~30 days × 24 h × 10k = ~7M rows worst
    /// case, safely indexed.
    const TICK_INTERVAL: Duration = Duration::from_secs(3600);

    tokio::spawn(async move {
        let mut tick = interval(TICK_INTERVAL);
        // Skip the immediate first tick — daemon startup is hot enough
        // (migrations, registry init); a purge on the same scheduler
        // pass adds noise to the journal without doing useful work.
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        tick.tick().await;
        loop {
            tick.tick().await;
            match inv.purge_sub_access_older_than(RETENTION_DAYS).await {
                Ok(0) => tracing::debug!(
                    target = "vpnctld::retention",
                    days = RETENTION_DAYS,
                    "purge tick: nothing to remove"
                ),
                Ok(n) => tracing::info!(
                    target = "vpnctld::retention",
                    days = RETENTION_DAYS,
                    removed = n,
                    "purged old sub_access_log rows"
                ),
                Err(e) => tracing::warn!(
                    target = "vpnctld::retention",
                    error = %e,
                    "retention purge failed; will retry next tick"
                ),
            }
        }
    })
}

/// Pulled out so tests can inject a state pointed at a tempdir DB.
pub fn router(state: AppState) -> Router {
    // Trace-layer span uses MatchedPath ("/sub/{token}") instead of the raw
    // URI ("/sub/<actual-secret-token>"). Otherwise every subscriber's token
    // would land in INFO-level logs and any aggregator downstream — that's a
    // critical leak (review-agent caught it before it shipped).
    let trace_layer = TraceLayer::new_for_http().make_span_with(|req: &Request<_>| {
        let matched = req
            .extensions()
            .get::<MatchedPath>()
            .map_or("<unknown>", MatchedPath::as_str);
        info_span!("http", method = %req.method(), path = matched)
    });

    let admin_router = admin_router(state.clone());

    Router::new()
        .route("/api/v1/health", get(handlers::health::get))
        .route("/sub/{token}", get(handlers::sub::get))
        .with_state(state)
        .merge(admin_router)
        .layer(TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(15),
        ))
        .layer(RequestBodyLimitLayer::new(8 * 1024)) // GET only — paranoia
        .layer(trace_layer)
}

/// `/admin/*` subtree. Phase A: shell + tweaks + static assets, all
/// behind basic-auth IF env vars present (otherwise open — useful for
/// local smoke).
fn admin_router(state: AppState) -> Router {
    use crate::handlers::admin;

    // Resolve assets dir relative to CARGO_MANIFEST_DIR for `cargo run`,
    // falling back to ./daemon/assets for `vpnctld` invoked from the
    // workspace root, falling back to ./assets for a binary distributed
    // alongside its assets dir. We pick whichever exists.
    let assets_dir: PathBuf = [
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets"),
        PathBuf::from("daemon/assets"),
        PathBuf::from("assets"),
    ]
    .into_iter()
    .find(|p| p.exists())
    .unwrap_or_else(|| PathBuf::from("daemon/assets"));

    // Explicit routes instead of `nest("/admin", ...)` — axum 0.8's nest
    // does NOT auto-match the trailing-slash variant of the inner "/" route
    // (so `/admin` works but `/admin/` 404s). Explicitly register both.
    // `nest_service` is fine for static — its prefix-match handles the
    // trailing slash naturally.
    //
    // Phase A section routes render the same shell with `active_nav` set
    // and a placeholder body; real content lands in subsequent phases.
    // Without these, clicking a nav anchor 404'd.
    //
    // Each section is registered with AND without the trailing slash —
    // axum 0.8 routes match exactly, so `/admin/users` and `/admin/users/`
    // would otherwise diverge (200 vs 404). Same reason `/admin` and
    // `/admin/` are both wired for dashboard.
    let with_admin = Router::new()
        .route("/admin", get(admin::dashboard))
        .route("/admin/", get(admin::dashboard))
        .route("/admin/monitoring", get(admin::monitoring))
        .route("/admin/monitoring/", get(admin::monitoring))
        .route("/admin/servers", get(admin::servers))
        .route("/admin/servers/", get(admin::servers))
        .route("/admin/users", get(admin::users))
        .route("/admin/users/", get(admin::users))
        // User detail: `/admin/users/<id>` (with and without trailing
        // slash). Path param doesn't capture an empty segment, so
        // `/admin/users/` continues to hit the list above.
        .route("/admin/users/{id}", get(admin::user_detail))
        .route("/admin/users/{id}/", get(admin::user_detail))
        // Phase C-3 writes (Users). Each write goes via POST so a casual
        // GET (link preview, prefetch, search-bot) cannot mutate state.
        .route(
            "/admin/users/{id}/sub-token/regenerate",
            post(admin::user_regen_sub_token),
        )
        .route("/admin/audit", get(admin::audit))
        .route("/admin/audit/", get(admin::audit))
        .route("/admin/settings", get(admin::settings))
        .route("/admin/settings/", get(admin::settings))
        .route("/admin/tweak/{kind}", post(admin::set_tweak))
        .nest_service("/admin/assets", ServeDir::new(&assets_dir))
        .with_state(state);

    // CSRF guard runs FIRST (outermost layer), so basic-auth never even
    // gets a chance to validate credentials on a cross-origin POST. This
    // also means the 403 lands without consuming the auth check, so an
    // attacker can't probe whether a given user/password combo is valid
    // via a CSRF flow.
    let with_csrf = with_admin.layer(axum::middleware::from_fn(
        crate::handlers::csrf::require_same_origin,
    ));

    if let Some(auth) = BasicAuth::from_env() {
        with_csrf.layer(axum::middleware::from_fn_with_state(
            auth,
            crate::handlers::auth::require_basic_auth,
        ))
    } else {
        with_csrf
    }
}

/// Same canonical Registry as the CLI uses. Kept in a tiny helper so a
/// future shared `crate vpnctl-registry` can replace this without changing
/// callers.
fn build_registry() -> anyhow::Result<Registry> {
    use vpnctl_kernels::SingBox;
    use vpnctl_protocols::{Hysteria2, TuicV5, VlessReality};

    let mut reg = Registry::new();
    reg.register_kernel(Box::new(SingBox::new()))?;
    reg.register_protocol(Box::new(VlessReality::new()))?;
    reg.register_protocol(Box::new(TuicV5::new()))?;
    reg.register_protocol(Box::new(Hysteria2::new()))?;
    Ok(reg)
}
