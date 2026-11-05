//! Private transport observations, separate from protocol assurance and alerts.
mod probe;
mod view;

use std::collections::BTreeMap;
use std::net::IpAddr;

use axum::extract::State;
use axum::response::{IntoResponse, Redirect, Response};
use chrono::{DateTime, Utc};
use maud::Markup;
use tokio::sync::Mutex;

use crate::AppState;
use crate::handlers::admin::helpers::{internal_error, render_page, theme_accent_lang};

const PATH: &str = "/admin/monitoring/private-checks";
const MAX_TARGETS: usize = 32;
const MAX_SOURCES: usize = 4;
const CONCURRENCY: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Target {
    server: String,
    address: String,
    ip: Option<IpAddr>,
    protocol: String,
    transport: String,
    port: Option<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Source {
    Controller,
    Server(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Outcome {
    Reachable(u128),
    Failed,
    Refused,
    Timeout,
    SelfCheck,
    NoAddress,
    SourceUnavailable,
    Unsupported,
    UdpNotChecked,
}

#[derive(Clone, Debug)]
struct ResultRow {
    source: Source,
    target: Target,
    outcome: Outcome,
    time: DateTime<Utc>,
}

// Also includes jump nodes: a changed route invalidates old observations.
#[derive(Clone, Debug, PartialEq, Eq)]
struct SourceConfig {
    id: String,
    address: String,
    user: String,
    port: u16,
    fingerprint: Option<String>,
    jump: Option<vpnctl_core::ServerId>,
    resolved: Vec<IpAddr>,
}

async fn source_configs(
    state: &AppState,
    servers: &[vpnctl_core::Server],
) -> anyhow::Result<Vec<SourceConfig>> {
    let mut configs = Vec::new();
    for server in servers {
        let mut resolved = state.inv.resolved_ips_for_server(&server.id).await?;
        resolved.sort();
        configs.push(SourceConfig {
            id: server.id.0.clone(),
            address: server.address.clone(),
            user: server.ssh_user.clone(),
            port: server.ssh_port,
            fingerprint: server.trusted_host_fingerprint.clone(),
            jump: server.jump_via.clone(),
            resolved,
        });
    }
    configs.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(configs)
}

#[derive(Clone, Default)]
struct Snapshot {
    inventory_changed: bool,
    inventory: Vec<Target>,
    source_configs: Vec<SourceConfig>,
    running: bool,
    failed: bool,
    rows: Vec<ResultRow>,
    sources: Vec<Source>,
    started_at: Option<DateTime<Utc>>,
    finished_at: Option<DateTime<Utc>>,
    selected_targets: usize,
    total_targets: usize,
    total_sources: usize,
}

#[derive(Default)]
struct CheckState {
    snapshot: Snapshot,
    cursor: BatchCursor,
}

#[derive(Default)]
pub(crate) struct PrivateChecks {
    state: Mutex<CheckState>,
}

// One owner selects batches while the run is active; no atomics are needed.
#[derive(Default)]
struct BatchCursor {
    target: usize,
    source: usize,
}

impl BatchCursor {
    fn select<T: Clone, S: Clone>(&mut self, targets: &[T], sources: &[S]) -> (Vec<T>, Vec<S>) {
        let (targets, next_target) = batch(targets, self.target, MAX_TARGETS);
        let (sources, next_source) = batch(sources, self.source, MAX_SOURCES);
        self.target = next_target;
        if next_target == 0 {
            self.source = next_source;
        }
        (targets, sources)
    }
}

fn batch<T: Clone>(items: &[T], offset: usize, limit: usize) -> (Vec<T>, usize) {
    if items.is_empty() {
        return (Vec::new(), 0);
    }
    let start = offset % items.len();
    let end = start.saturating_add(limit).min(items.len());
    (
        items[start..end].to_vec(),
        if end == items.len() { 0 } else { end },
    )
}

pub(crate) async fn private_checks_run(State(state): State<AppState>) -> Response {
    let start = {
        let mut checks = state.private_checks.state.lock().await;
        if checks.snapshot.running {
            false
        } else {
            checks.snapshot = Snapshot {
                running: true,
                started_at: Some(Utc::now()),
                ..Snapshot::default()
            };
            true
        }
    };
    if start {
        tokio::spawn(async move {
            let result = sweep(&state).await;
            let mut checks = state.private_checks.state.lock().await;
            match result {
                Ok(rows) => checks.snapshot.rows = rows,
                Err(()) => checks.snapshot.failed = true,
            }
            checks.snapshot.finished_at = Some(Utc::now());
            checks.snapshot.running = false;
        });
    }
    Redirect::to(PATH).into_response()
}

async fn sweep(state: &AppState) -> Result<Vec<ResultRow>, ()> {
    let mut servers = state.inv.list_servers().await.map_err(|_| ())?;
    servers.sort_by(|a, b| a.id.0.cmp(&b.id.0));
    let mut all_targets = probe::targets(state, &servers).await.map_err(|_| ())?;
    all_targets.sort();
    let configs = source_configs(state, &servers).await.map_err(|_| ())?;
    let (targets, sources) = {
        let mut checks = state.private_checks.state.lock().await;
        let selected = checks.cursor.select(&all_targets, &servers);
        checks.snapshot.inventory = all_targets.clone();
        checks.snapshot.source_configs = configs;
        checks.snapshot.selected_targets = selected.0.len();
        checks.snapshot.total_targets = all_targets.len();
        checks.snapshot.total_sources = servers.len() + 1;
        checks.snapshot.sources = std::iter::once(Source::Controller)
            .chain(selected.1.iter().map(|s| Source::Server(s.id.0.clone())))
            .collect();
        selected
    };
    let mut rows = Vec::new();
    for group in targets.chunks(CONCURRENCY) {
        let mut tasks = tokio::task::JoinSet::new();
        for target in group.iter().cloned() {
            tasks.spawn(async move {
                let outcome = probe::local(&target).await;
                ResultRow {
                    source: Source::Controller,
                    target,
                    outcome,
                    time: Utc::now(),
                }
            });
        }
        while let Some(result) = tasks.join_next().await {
            rows.push(result.map_err(|_| ())?);
        }
    }
    let mut tasks = tokio::task::JoinSet::new();
    for source in sources {
        let state = state.clone();
        let targets = targets.clone();
        tasks.spawn(async move { probe::remote(&state, &targets, &source).await });
    }
    // Drain even after a JoinError: dropping a future cannot cancel blocking SSH.
    let mut failed = false;
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(remote) => rows.extend(remote),
            Err(_) => failed = true,
        }
    }
    if failed { Err(()) } else { Ok(rows) }
}

pub(crate) async fn private_checks_page(
    headers: axum::http::HeaderMap,
    State(state): State<AppState>,
) -> Result<Markup, Response> {
    let (theme, accent, lang) = theme_accent_lang(&headers);
    let servers = state
        .inv
        .list_servers()
        .await
        .map_err(|e| internal_error(e.into()))?;
    let mut targets = probe::targets(&state, &servers)
        .await
        .map_err(internal_error)?;
    targets.sort();
    let configs = source_configs(&state, &servers)
        .await
        .map_err(internal_error)?;
    let mut names = BTreeMap::new();
    for server in servers {
        let name = state
            .inv
            .server_display_name(&server.id)
            .await
            .map_err(|e| internal_error(e.into()))?
            .filter(|name| !name.trim().is_empty())
            .unwrap_or_else(|| server.id.0.clone());
        names.insert(server.id.0, name);
    }
    let mut snapshot = state.private_checks.state.lock().await.snapshot.clone();
    if snapshot.finished_at.is_some()
        && (snapshot.inventory != targets || snapshot.source_configs != configs)
    {
        snapshot.inventory_changed = true;
        snapshot.rows.clear();
        snapshot.sources.clear();
    }
    if snapshot.sources.is_empty() && !snapshot.running {
        snapshot.sources = std::iter::once(Source::Controller)
            .chain(names.keys().take(MAX_SOURCES).cloned().map(Source::Server))
            .collect();
    }
    let body = view::render(&targets, &names, &snapshot, lang, Utc::now());
    Ok(render_page(&state, "monitoring", &theme, &accent, lang, body).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotating_batches_cover_every_pair_without_atomic_state() {
        let mut cursor = BatchCursor::default();
        let targets: Vec<_> = (0..65).collect();
        let sources: Vec<_> = (0..9).collect();
        let mut pairs = std::collections::BTreeSet::new();
        for _ in 0..9 {
            let (targets, sources) = cursor.select(&targets, &sources);
            for target in targets {
                for source in &sources {
                    pairs.insert((target, *source));
                }
            }
        }
        assert_eq!(pairs.len(), 65 * 9);
        assert_eq!(cursor.select::<u8, u8>(&[], &[]), (vec![], vec![]));
    }
}
