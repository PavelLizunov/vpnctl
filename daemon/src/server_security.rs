use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;
use vpnctl_core::{PinnedJumpRoute, Server, SshTransport, shell::single_quote};
use vpnctl_inventory::{SqliteInventory, sqlite::ServerSecurityReport};

use crate::ssh_subprocess::SubprocessSshTransport;
use crate::wizard_bootstrap::DeployGuard;

const CHECK_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);
const CHECK_TIMEOUT: Duration = Duration::from_secs(165);
const APPLY_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const REMOTE_SCRIPT: &str = include_str!("server_security/apt.py");
pub(crate) const APPLY_AUDIT: &str = "server.security_apply";

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CheckState {
    Checked,
    Unsupported,
    MissingApt,
    NoSecurityIndex,
    DpkgUnsettled,
    RefreshFailed,
    HostIdentity,
    Busy,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ApplyOutcome {
    Started,
    Verified,
    Changed,
    RequiresOtherChanges,
    Blocked,
    InstallUnverified,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BlockReason {
    Held,
    Policy,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct Package {
    pub(crate) name: String,
    pub(crate) installed: String,
    pub(crate) candidate: String,
    pub(crate) blocked: Option<BlockReason>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Nginx {
    pub(crate) installed: Option<String>,
    pub(crate) running: Option<String>,
    pub(crate) http2: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Report {
    pub(crate) state: CheckState,
    #[serde(default)]
    pub(crate) packages: Vec<Package>,
    pub(crate) nginx: Option<Nginx>,
    #[serde(default)]
    pub(crate) reboot_required: bool,
    pub(crate) outcome: Option<ApplyOutcome>,
}

impl Report {
    fn failed(state: CheckState) -> Self {
        Self {
            state,
            packages: Vec::new(),
            nginx: None,
            reboot_required: false,
            outcome: None,
        }
    }
}

#[derive(Debug)]
pub(crate) struct Observation {
    pub(crate) revision: i64,
    pub(crate) checked_at: DateTime<Utc>,
    pub(crate) report: Report,
}

impl Observation {
    pub(crate) fn stale(&self) -> bool {
        let elapsed = Utc::now().signed_duration_since(self.checked_at);
        elapsed
            .to_std()
            .map_or(true, |age| age > CHECK_INTERVAL * 2)
    }
}

struct Route {
    jump: Option<PinnedJumpRoute>,
    fingerprint: String,
}

async fn resolve(inv: &SqliteInventory, server: &Server) -> Route {
    let resolved = inv.resolve_jump_host(server).await;
    let key = serde_json::json!([
        server.address,
        server.ssh_user,
        server.ssh_port,
        server.trusted_host_fingerprint,
        server.jump_via,
        server.kernels,
        resolved.is_ok(),
        resolved.as_ref().ok().and_then(Option::as_ref),
    ]);
    Route {
        jump: resolved.ok().flatten(),
        fingerprint: format!("{:x}", Sha256::digest(key.to_string())),
    }
}

pub(crate) async fn observation(
    inv: &SqliteInventory,
    server: &Server,
    stored: Option<ServerSecurityReport>,
) -> Option<Observation> {
    let stored = stored?;
    if resolve(inv, server).await.fingerprint != stored.route_fingerprint {
        return None;
    }
    Some(Observation {
        revision: stored.revision,
        checked_at: DateTime::from_timestamp_micros(stored.revision)?,
        report: serde_json::from_str(&stored.report_json).ok()?,
    })
}

async fn remote(server: &Server, route: Route, selected: Option<&[Package]>) -> Report {
    if (server.jump_via.is_some() && route.jump.is_none())
        || server
            .trusted_host_fingerprint
            .as_deref()
            .and_then(vpnctl_host_fingerprint::canonicalize_sha256)
            .is_none()
    {
        return Report::failed(CheckState::HostIdentity);
    }
    let key = crate::app::deploy_key_path();
    if !key.is_file() {
        return Report::failed(CheckState::Unavailable);
    }

    let (mode, timeout) = if selected.is_some() {
        ("apply", APPLY_TIMEOUT)
    } else {
        ("check", CHECK_TIMEOUT)
    };
    let request = serde_json::json!({ "kernels": server.kernels, "packages": selected });
    let args = single_quote(&request.to_string());
    let command = format!(
        "if [ ! -x /usr/bin/python3 ]; then printf '%s\\n' '{{\"state\":\"missing_apt\"}}'; exit 0; fi\n\
         LC_ALL=C /usr/bin/python3 -I - {mode} {args} <<'VPNCTL_SECURITY_PY'\n{REMOTE_SCRIPT}VPNCTL_SECURITY_PY"
    );
    let ssh = SubprocessSshTransport::new(&server.address, &server.ssh_user, key)
        .port(server.ssh_port)
        .trusted_fingerprint(server.trusted_host_fingerprint.clone())
        .with_jump(route.jump)
        .timeout(timeout);
    match ssh.exec(&command).await {
        Ok(output) => serde_json::from_str(&output)
            .unwrap_or_else(|_| Report::failed(CheckState::Unavailable)),
        Err(_) => Report::failed(CheckState::Unavailable),
    }
}

async fn save(inv: &SqliteInventory, server: &Server, route_fingerprint: String, report: &Report) {
    let Ok(report_json) = serde_json::to_string(report) else {
        return;
    };
    let stored = ServerSecurityReport {
        route_fingerprint,
        revision: Utc::now().timestamp_micros(),
        report_json,
    };
    if inv
        .record_server_security_report(&server.id, &stored)
        .await
        .is_err()
    {
        tracing::warn!(target: "vpnctld::server_security", "could not save security observation");
    }
}

async fn check(inv: &SqliteInventory, server: &Server) {
    let route = resolve(inv, server).await;
    let fingerprint = route.fingerprint.clone();
    let report = remote(server, route, None).await;
    save(inv, server, fingerprint, &report).await;
}

pub(crate) fn start_check(inv: SqliteInventory, server: Server) -> bool {
    let Some(guard) = DeployGuard::try_acquire(&server.id.0) else {
        return false;
    };
    tokio::spawn(async move {
        let _guard = guard;
        check(&inv, &server).await;
    });
    true
}

pub(crate) fn spawn_poller(inv: SqliteInventory) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let slots = Arc::new(Semaphore::new(2));
        let mut ticker = tokio::time::interval(CHECK_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let Ok(servers) = inv.list_servers().await else {
                tracing::warn!(target: "vpnctld::server_security", "could not list servers");
                continue;
            };
            for server in servers {
                let Ok(slot) = Arc::clone(&slots).acquire_owned().await else {
                    return;
                };
                let Some(guard) = DeployGuard::try_acquire(&server.id.0) else {
                    continue;
                };
                let inv = inv.clone();
                tokio::spawn(async move {
                    let (_slot, _guard) = (slot, guard);
                    check(&inv, &server).await;
                });
            }
        }
    })
}

#[derive(Debug)]
pub(crate) enum ApplyError {
    Busy,
    Changed,
    Inventory(vpnctl_inventory::SqliteInventoryError),
}

pub(crate) async fn start_apply(
    inv: SqliteInventory,
    server: Server,
    revision: i64,
    names: &[String],
) -> Result<(), ApplyError> {
    let guard = DeployGuard::try_acquire(&server.id.0).ok_or(ApplyError::Busy)?;
    let stored = inv
        .server_security_report(&server.id)
        .await
        .map_err(ApplyError::Inventory)?;
    let Some(stored) = stored.filter(|report| report.revision == revision) else {
        return Err(ApplyError::Changed);
    };
    let route_fingerprint = stored.route_fingerprint.clone();
    let current = observation(&inv, &server, Some(stored))
        .await
        .filter(|obs| !obs.stale() && obs.report.state == CheckState::Checked)
        .ok_or(ApplyError::Changed)?;
    let selected = names
        .iter()
        .map(|name| {
            current
                .report
                .packages
                .iter()
                .find(|item| &item.name == name && item.blocked.is_none())
                .cloned()
        })
        .collect::<Option<Vec<_>>>()
        .ok_or(ApplyError::Changed)?;

    audit(
        &inv,
        &server,
        &route_fingerprint,
        &selected,
        ApplyOutcome::Started,
    )
    .await
    .map_err(ApplyError::Inventory)?;
    tokio::spawn(async move {
        let _guard = guard;
        let outcome = apply_to_route(&inv, &server.id, &route_fingerprint, &selected).await;
        if audit(&inv, &server, &route_fingerprint, &selected, outcome)
            .await
            .is_err()
        {
            tracing::warn!(target: "vpnctld::server_security", "could not save package installation outcome");
        }
    });
    Ok(())
}

async fn apply_to_route(
    inv: &SqliteInventory,
    id: &vpnctl_core::ServerId,
    approved_route: &str,
    selected: &[Package],
) -> ApplyOutcome {
    let Ok(Some(server)) = inv.get_server(id).await else {
        return ApplyOutcome::Changed;
    };
    let route = resolve(inv, &server).await;
    if route.fingerprint != approved_route {
        return ApplyOutcome::Changed;
    }

    let refreshed = remote(&server, route, None).await;
    if refreshed.state != CheckState::Checked {
        save(inv, &server, approved_route.to_owned(), &refreshed).await;
        return ApplyOutcome::Blocked;
    }

    // Check the route again after the potentially slow index refresh. Dispatch
    // only to this approved pinned identity, even if the inventory later moves.
    let Ok(Some(current)) = inv.get_server(id).await else {
        return ApplyOutcome::Changed;
    };
    let route = resolve(inv, &current).await;
    if route.fingerprint != approved_route {
        return ApplyOutcome::Changed;
    }
    let report = remote(&current, route, Some(selected)).await;
    let outcome = report.outcome.unwrap_or(ApplyOutcome::InstallUnverified);
    save(inv, &current, approved_route.to_owned(), &report).await;
    outcome
}

async fn audit(
    inv: &SqliteInventory,
    server: &Server,
    route_fingerprint: &str,
    packages: &[Package],
    outcome: ApplyOutcome,
) -> Result<(), vpnctl_inventory::SqliteInventoryError> {
    inv.audit(
        "admin", APPLY_AUDIT, Some(&server.id.0),
        Some(&serde_json::json!({ "packages": packages, "outcome": outcome, "route_fingerprint": route_fingerprint })),
    ).await
}
