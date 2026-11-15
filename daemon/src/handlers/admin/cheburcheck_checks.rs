//! Explicit external observations; independent of node health and routing policy.
mod view;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use chrono::{DateTime, Utc};
use maud::Markup;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use vpnctl_core::{Server, ServerId};

use crate::AppState;
use crate::cheburcheck::{Client, DynamicPhase, DynamicResult, Failure, FailureCode, Report};
use crate::handlers::admin::helpers::{internal_error, not_found, render_page, theme_accent_lang};
use crate::http_util::path_segment_encode;
use view::PageModel;

const STARTED: &str = "server.cheburcheck.started";
const RESULT: &str = "server.cheburcheck.result";
const COOLDOWN: Duration = Duration::from_secs(15);

#[derive(Default)]
struct Gate {
    active: Option<(String, String, Instant)>,
    next_start: Option<Instant>,
}

impl Gate {
    fn expire(&mut self) {
        if self
            .active
            .as_ref()
            .is_some_and(|(_, _, until)| *until <= Instant::now())
        {
            self.active = None;
        }
    }

    fn cooldown_secs(&self) -> u64 {
        let duration = self.next_start.map_or(Duration::ZERO, |until| {
            until.saturating_duration_since(Instant::now())
        });
        duration.as_secs() + u64::from(duration.subsec_nanos() > 0)
    }
}

pub(crate) struct ExternalChecks {
    client: Option<Client>,
    gate: Mutex<Gate>,
}

impl Default for ExternalChecks {
    fn default() -> Self {
        Self {
            client: Client::new().ok(),
            gate: Mutex::default(),
        }
    }
}

impl ExternalChecks {
    pub(crate) fn with_client(client: Client) -> Self {
        Self {
            client: Some(client),
            gate: Mutex::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredRun {
    run_id: String,
    address: String,
    inventory_address: String,
    started_at: String,
    finished_at: Option<String>,
    report: Option<Report>,
}

fn eligible(ip: IpAddr) -> bool {
    if crate::ip_kind::classify_ip(&ip.to_string()).is_lan_or_loopback() || ip.is_multicast() {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            !v4.is_broadcast()
                && octets[0] != 0
                && octets[0] < 240
                && !(octets[0] == 100 && (64..=127).contains(&octets[1]))
        }
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .is_none_or(|v4| eligible(IpAddr::V4(v4))),
    }
}

async fn target(state: &AppState, server: &Server) -> Result<Option<IpAddr>, Response> {
    if let Ok(ip) = server.address.parse() {
        return Ok(eligible(ip).then_some(ip));
    }
    let mut ips = state
        .inv
        .resolved_ips_for_server(&server.id)
        .await
        .map_err(|error| internal_error(error.into()))?;
    ips.sort();
    ips.dedup();
    Ok(if ips.len() == 1 {
        ips.first().copied().filter(|ip| eligible(*ip))
    } else {
        None
    })
}

fn check_path(id: &str) -> String {
    format!("/admin/servers/{}/cheburcheck", path_segment_encode(id))
}

fn safe_failure(code: FailureCode) -> Report {
    Report {
        list: None,
        dynamic: DynamicResult {
            phase: DynamicPhase::Unavailable,
            online_probes: None,
            reports: Vec::new(),
        },
        failure: Some(Failure {
            code,
            retry_after_secs: None,
        }),
    }
}

pub(crate) async fn cheburcheck_run(
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> Response {
    let sid = ServerId(id.clone());
    let server = match state.inv.get_server(&sid).await {
        Ok(Some(server)) => server,
        Ok(None) => return not_found("No such server"),
        Err(error) => return internal_error(error.into()),
    };
    let address = match target(&state, &server).await {
        Ok(Some(ip)) => ip,
        Ok(None) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                "A configured public IP is required",
            )
                .into_response();
        }
        Err(response) => return response,
    };
    let mut gate = state.cheburcheck.gate.lock().await;
    gate.expire();
    if gate.active.is_some() {
        return (StatusCode::CONFLICT, "A Cheburcheck run is already active").into_response();
    }
    let wait = gate.cooldown_secs();
    if wait > 0 {
        let mut response =
            (StatusCode::TOO_MANY_REQUESTS, "Cheburcheck start cooldown").into_response();
        if let Ok(value) = wait.to_string().parse() {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
        return response;
    }
    let run = StoredRun {
        run_id: vpnctl_crypto::gen_uuid(),
        address: address.to_string(),
        inventory_address: server.address,
        started_at: Utc::now().to_rfc3339(),
        finished_at: None,
        report: None,
    };
    let payload = match serde_json::to_value(&run) {
        Ok(payload) => payload,
        Err(error) => return internal_error(error.into()),
    };
    if let Err(error) = state
        .inv
        .audit("admin", STARTED, Some(&id), Some(&payload))
        .await
    {
        return internal_error(error.into());
    }
    gate.active = Some((
        id.clone(),
        run.run_id.clone(),
        Instant::now() + Duration::from_secs(90),
    ));
    gate.next_start = Some(Instant::now() + COOLDOWN);
    drop(gate);

    let background = state.clone();
    tokio::spawn(async move {
        finish_run(background, id, address, run).await;
    });
    Redirect::to(&check_path(&sid.0)).into_response()
}

async fn finish_run(state: AppState, id: String, address: IpAddr, mut run: StoredRun) {
    let report = match state.cheburcheck.client.as_ref() {
        Some(client) => tokio::time::timeout(Duration::from_secs(80), client.check(address))
            .await
            .unwrap_or_else(|_| safe_failure(FailureCode::Timeout)),
        None => safe_failure(FailureCode::Unavailable),
    };
    let retry = report
        .failure
        .as_ref()
        .and_then(|failure| failure.retry_after_secs);
    run.report = Some(report);
    run.finished_at = Some(Utc::now().to_rfc3339());
    let saved = match serde_json::to_value(&run) {
        Ok(payload) => state
            .inv
            .audit("system", RESULT, Some(&id), Some(&payload))
            .await
            .is_ok(),
        Err(_) => false,
    };
    if !saved {
        tracing::warn!(server = %id, "Cheburcheck result could not be persisted");
    }
    let mut gate = state.cheburcheck.gate.lock().await;
    if gate
        .active
        .as_ref()
        .is_some_and(|(_, run_id, _)| run_id == &run.run_id)
    {
        gate.active = None;
    }
    if let Some(seconds) = retry {
        let deadline = Instant::now() + Duration::from_secs(u64::from(seconds.clamp(1, 3600)));
        if gate.next_start.is_none_or(|current| deadline > current) {
            gate.next_start = Some(deadline);
        }
    }
}

async fn model(state: &AppState, server: &Server) -> Result<PageModel, Response> {
    let chosen = target(state, server).await?.map(|ip| ip.to_string());
    // Starts publish under this lock; completion publishes before clearing it.
    // Hold it while reading the journal so a finished run cannot look interrupted.
    let mut gate = state.cheburcheck.gate.lock().await;
    gate.expire();
    let started = state
        .inv
        .latest_audit_for_target_action(&server.id.0, STARTED)
        .await
        .map_err(|error| internal_error(error.into()))?;
    let result = state
        .inv
        .latest_audit_for_target_action(&server.id.0, RESULT)
        .await
        .map_err(|error| internal_error(error.into()))?;
    let started_id = started.as_ref().map(|row| row.id);
    let result_id = result.as_ref().map(|row| row.id);
    let begin: Option<StoredRun> = started
        .and_then(|row| row.payload)
        .and_then(|value| serde_json::from_value(value).ok());
    let end: Option<StoredRun> = result
        .and_then(|row| row.payload)
        .and_then(|value| serde_json::from_value(value).ok());
    let running = gate
        .active
        .as_ref()
        .is_some_and(|(id, _, _)| id == &server.id.0);
    let busy = gate.active.is_some();
    let cooldown_secs = gate.cooldown_secs();
    drop(gate);
    let unmatched = started_id.is_some_and(|id| result_id.is_none_or(|result| id > result))
        || begin
            .as_ref()
            .is_some_and(|start| end.as_ref().is_some_and(|end| start.run_id != end.run_id));
    let state_code = if running {
        "running"
    } else if unmatched {
        "interrupted"
    } else if end.as_ref().is_some_and(|run| run.report.is_some()) {
        "finished"
    } else if started_id.is_some() || result_id.is_some() {
        "interrupted"
    } else {
        "not_checked"
    };
    let stored = if running || unmatched { begin } else { end };
    let address_changed = stored.as_ref().is_some_and(|run| {
        run.inventory_address != server.address || chosen.as_deref() != Some(run.address.as_str())
    });
    let finished_at = stored.as_ref().and_then(|run| run.finished_at.clone());
    let stale = finished_at.as_ref().is_some_and(|value| {
        DateTime::parse_from_rfc3339(value).map_or(true, |time| {
            Utc::now().signed_duration_since(time) > chrono::Duration::hours(1)
        })
    });
    let display_name = state
        .inv
        .server_display_name(&server.id)
        .await
        .map_err(|error| internal_error(error.into()))?
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| server.id.0.clone());
    Ok(PageModel {
        server_id: server.id.0.clone(),
        server_name: display_name,
        inventory_address: if server.address.parse::<IpAddr>().is_ok()
            || (!server.address.is_empty()
                && server.address.len() <= 253
                && server
                    .address
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')))
        {
            server.address.clone()
        } else {
            "—".into()
        },
        target_address: chosen,
        checked_address: stored.as_ref().map(|run| run.address.clone()),
        state: state_code,
        started_at: stored.as_ref().map(|run| run.started_at.clone()),
        finished_at,
        report: if state_code == "finished" {
            stored.and_then(|run| run.report)
        } else {
            None
        },
        busy,
        cooldown_secs,
        stale,
        address_changed,
    })
}

pub(crate) async fn cheburcheck_page(
    Path(id): Path<String>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Markup, Response> {
    let server = state
        .inv
        .get_server(&ServerId(id))
        .await
        .map_err(|error| internal_error(error.into()))?
        .ok_or_else(|| not_found("No such server"))?;
    let model = model(&state, &server).await?;
    let (theme, accent, lang) = theme_accent_lang(&headers);
    Ok(render_page(
        &state,
        "monitoring",
        &theme,
        &accent,
        lang,
        view::render(&model, lang),
    )
    .await)
}

pub(crate) async fn cheburcheck_overview(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Markup, Response> {
    let mut servers = state
        .inv
        .list_servers()
        .await
        .map_err(|error| internal_error(error.into()))?;
    servers.sort_by(|a, b| a.id.0.cmp(&b.id.0));
    let mut models = Vec::new();
    for server in servers {
        models.push(model(&state, &server).await?);
    }
    let (theme, accent, lang) = theme_accent_lang(&headers);
    Ok(render_page(
        &state,
        "monitoring",
        &theme,
        &accent,
        lang,
        view::overview(&models, lang),
    )
    .await)
}

pub(crate) fn with_client(client: Client) -> Arc<ExternalChecks> {
    Arc::new(ExternalChecks::with_client(client))
}
