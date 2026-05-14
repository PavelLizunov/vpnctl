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
    let state = AppState { inv, registry };
    Ok(router(state))
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
        .route("/admin/audit", get(admin::audit))
        .route("/admin/audit/", get(admin::audit))
        .route("/admin/settings", get(admin::settings))
        .route("/admin/settings/", get(admin::settings))
        .route("/admin/tweak/{kind}", post(admin::set_tweak))
        .nest_service("/admin/assets", ServeDir::new(&assets_dir))
        .with_state(state);

    if let Some(auth) = BasicAuth::from_env() {
        with_admin.layer(axum::middleware::from_fn_with_state(
            auth,
            crate::handlers::auth::require_basic_auth,
        ))
    } else {
        with_admin
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
