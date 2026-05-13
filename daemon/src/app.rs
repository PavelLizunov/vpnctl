//! Wire the axum Router. Kept separate from `main.rs` so tests can build
//! the same Router without the network/signal plumbing.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::MatchedPath;
use axum::http::Request;
use axum::routing::get;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tracing::info_span;

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

    Router::new()
        .route("/api/v1/health", get(handlers::health::get))
        .route("/sub/{token}", get(handlers::sub::get))
        .with_state(state)
        .layer(TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(15),
        ))
        .layer(RequestBodyLimitLayer::new(8 * 1024)) // GET only — paranoia
        .layer(trace_layer)
}

/// Same canonical Registry as the CLI uses. Kept in a tiny helper so a
/// future shared `crate vpnctl-registry` can replace this without changing
/// callers.
fn build_registry() -> anyhow::Result<Registry> {
    use vpnctl_kernels::SingBox;
    use vpnctl_protocols::{TuicV5, VlessReality};

    let mut reg = Registry::new();
    reg.register_kernel(Box::new(SingBox::new()))?;
    reg.register_protocol(Box::new(VlessReality::new()))?;
    reg.register_protocol(Box::new(TuicV5::new()))?;
    Ok(reg)
}
