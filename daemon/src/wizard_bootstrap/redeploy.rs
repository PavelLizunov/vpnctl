use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_core::Stream;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use super::audit::write_deploy_audit;
use super::guard::{DEPLOY_ALREADY_RUNNING_PREFIX, DEPLOY_KEY_ABSENT_MSG, DeployGuard};
use super::types::BootstrapEvent;
use crate::http_util::path_segment_encode;
use crate::ssh_subprocess::SubprocessSshTransport;
use vpnctl_core::{Registry, RenderCtx, Server};
use vpnctl_inventory::{SqliteInventory, bootstrap_server_secrets};

#[path = "autodeploy.rs"]
mod autodeploy;
pub use autodeploy::queue_servers_redeploy;
pub use autodeploy::{AutodeployPhase, AutodeployStatus, autodeploy_status};

pub fn run_redeploy(
    server: Server,
    inv: SqliteInventory,
    registry: Arc<Registry>,
    deploy_key_path: PathBuf,
) -> impl Stream<Item = BootstrapEvent> + Send + 'static {
    let (tx, rx) = mpsc::channel::<BootstrapEvent>(64);
    match DeployGuard::try_acquire(&server.id.0) {
        Some(guard) => {
            tokio::spawn(async move {
                redeploy_pipeline(server, inv, registry, deploy_key_path, tx).await;
                drop(guard);
            });
        }
        None => {
            let _ = tx.try_send(BootstrapEvent::Error {
                phase: "deploy",
                message: format!(
                    "{DEPLOY_ALREADY_RUNNING_PREFIX} for server '{}' — wait for it to finish, then retry",
                    server.id.0
                ),
            });
        }
    }
    ReceiverStream::new(rx)
}

const DEPLOY_SLOT_WAIT: Duration = Duration::from_secs(300);
const DEPLOY_SLOT_POLL: Duration = Duration::from_millis(500);

pub fn run_redeploy_when_idle(
    server: Server,
    inv: SqliteInventory,
    registry: Arc<Registry>,
    deploy_key_path: PathBuf,
) -> impl Stream<Item = BootstrapEvent> + Send + 'static {
    run_redeploy_after_wait(server, inv, registry, deploy_key_path, DEPLOY_SLOT_WAIT)
}

pub(super) fn run_redeploy_after_wait(
    server: Server,
    inv: SqliteInventory,
    registry: Arc<Registry>,
    deploy_key_path: PathBuf,
    wait_limit: Duration,
) -> impl Stream<Item = BootstrapEvent> + Send + 'static {
    let (tx, rx) = mpsc::channel::<BootstrapEvent>(64);
    tokio::spawn(async move {
        let sid = server.id.0.clone();
        let deadline = Instant::now() + wait_limit;
        let mut announced = false;
        let guard = loop {
            if let Some(guard) = DeployGuard::try_acquire(&sid) {
                break guard;
            }
            if Instant::now() >= deadline {
                let _ = tx
                    .send(BootstrapEvent::Error {
                        phase: "deploy",
                        message: format!(
                            "{DEPLOY_ALREADY_RUNNING_PREFIX} for server '{sid}' — wait for it to finish, then retry"
                        ),
                    })
                    .await;
                return;
            }
            if !announced {
                announced = true;
                let _ = tx
                    .send(BootstrapEvent::Step {
                        phase: "wait",
                        message: format!(
                            "another deploy is running on {sid}; waiting for it to finish…"
                        ),
                    })
                    .await;
            }
            if tx.is_closed() {
                return;
            }
            tokio::time::sleep(DEPLOY_SLOT_POLL).await;
        };
        redeploy_pipeline(server, inv, registry, deploy_key_path, tx).await;
        drop(guard);
    });
    ReceiverStream::new(rx)
}

pub fn run_deploy_all(
    servers: Vec<Server>,
    inv: SqliteInventory,
    registry: Arc<Registry>,
    deploy_key_path: PathBuf,
) -> impl Stream<Item = BootstrapEvent> + Send + 'static {
    let (tx, rx) = mpsc::channel::<BootstrapEvent>(128);
    tokio::spawn(async move {
        deploy_all_pipeline(servers, inv, registry, deploy_key_path, tx).await;
    });
    ReceiverStream::new(rx)
}

async fn deploy_all_pipeline(
    servers: Vec<Server>,
    inv: SqliteInventory,
    registry: Arc<Registry>,
    deploy_key_path: PathBuf,
    tx: mpsc::Sender<BootstrapEvent>,
) {
    use tokio_stream::StreamExt;
    let total = servers.len();
    let concurrency_limit = std::env::var("VPNCTL_FLEET_CONCURRENCY")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(4)
        .max(1);
    let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency_limit));
    let mut tasks = tokio::task::JoinSet::new();

    for server in servers {
        let sid = server.id.0.clone();
        let inv = inv.clone();
        let registry = Arc::clone(&registry);
        let deploy_key_path = deploy_key_path.clone();
        let tx = tx.clone();
        let sem = Arc::clone(&semaphore);

        tasks.spawn(async move {
            let _permit = sem.acquire().await.ok();
            let _ = tx
                .send(BootstrapEvent::Step {
                    phase: "server",
                    message: format!("── deploying {sid} ──"),
                })
                .await;
            let mut stream = Box::pin(run_redeploy_when_idle(
                server,
                inv,
                registry,
                deploy_key_path,
            ));
            let mut had_error = false;
            while let Some(ev) = stream.next().await {
                match ev {
                    BootstrapEvent::Step { phase, message } => {
                        let _ = tx
                            .send(BootstrapEvent::Step {
                                phase,
                                message: format!("{sid}: {message}"),
                            })
                            .await;
                    }
                    BootstrapEvent::Ok { .. } => {
                        let _ = tx
                            .send(BootstrapEvent::Step {
                                phase: "apply",
                                message: format!("✓ {sid} deployed"),
                            })
                            .await;
                    }
                    BootstrapEvent::Error { message, .. } => {
                        had_error = true;
                        let _ = tx
                            .send(BootstrapEvent::Step {
                                phase: "apply",
                                message: format!("✗ {sid}: {message}"),
                            })
                            .await;
                    }
                }
            }
            (sid, had_error)
        });
    }

    let mut ok_count = 0usize;
    let mut failed = Vec::new();
    while let Some(res) = tasks.join_next().await {
        match res {
            Ok((sid, had_error)) => {
                if had_error {
                    failed.push(sid);
                } else {
                    ok_count += 1;
                }
            }
            Err(e) => {
                failed.push(format!("panicked_task: {e}"));
            }
        }
    }
    failed.sort();

    let summary = if failed.is_empty() {
        format!("done — deployed all {total} server(s).")
    } else {
        format!(
            "done — {ok_count}/{total} deployed; failed: {}",
            failed.join(", ")
        )
    };
    let _ = tx
        .send(BootstrapEvent::Step {
            phase: "done",
            message: summary.clone(),
        })
        .await;
    let _ = tx.send(deploy_all_terminal(&failed, summary)).await;
}

pub(super) fn deploy_all_terminal(failed: &[String], summary: String) -> BootstrapEvent {
    if failed.is_empty() {
        BootstrapEvent::Ok {
            server_id: "all".into(),
            redirect: "/admin/servers".into(),
        }
    } else {
        BootstrapEvent::Error {
            phase: "done",
            message: summary,
        }
    }
}

pub(crate) async fn redeploy_servers_collect_errors(
    servers: Vec<Server>,
    inv: SqliteInventory,
    registry: Arc<Registry>,
    deploy_key_path: PathBuf,
) -> Vec<String> {
    queue_servers_redeploy(servers, &inv, &registry, &deploy_key_path).await
}

async fn redeploy_pipeline(
    server: Server,
    inv: SqliteInventory,
    registry: Arc<Registry>,
    deploy_key_path: PathBuf,
    tx: mpsc::Sender<BootstrapEvent>,
) {
    macro_rules! send_step {
        ($phase:expr, $($arg:tt)*) => {{
            let msg = format!($($arg)*);
            let _ = tx.send(BootstrapEvent::Step { phase: $phase, message: msg }).await;
        }};
    }
    macro_rules! fail {
        ($phase:expr, $($arg:tt)*) => {{
            let msg = format!($($arg)*);
            let _ = tx.send(BootstrapEvent::Error { phase: $phase, message: msg }).await;
            return;
        }};
    }

    let server = match inv.get_server(&server.id).await {
        Ok(Some(server)) => server,
        Ok(None) => fail!("deploy", "server was removed before deploy"),
        Err(e) => fail!("deploy", "cannot refresh server before bootstrap: {e}"),
    };
    let redirect = format!("/admin/servers/{}", path_segment_encode(&server.id.0));
    let mut ssh_errors: Vec<String> = Vec::new();
    let mut ssh_kernels_pushed: Vec<String> = Vec::new();
    let mut total_config_bytes: usize = 0;
    let mut configs_applied: usize = 0;

    let pre_secrets = match inv.list_server_secrets(&server.id).await {
        Ok(s) => s,
        Err(e) => fail!("validate", "cannot load server secrets: {e}"),
    };
    if let Err(e) = registry.validate_server(&server, &pre_secrets) {
        fail!("validate", "config invalid before deploy: {e}");
    }

    send_step!("secrets", "minting any missing per-protocol secrets…");
    let (_, bootstrapped) = match bootstrap_server_secrets(&inv, &server, &registry).await {
        Ok((secrets, minted)) => {
            if minted.is_empty() {
                send_step!("secrets", "ok — all secrets already present.");
            } else {
                for label in &minted {
                    send_step!("secrets", "ok — minted {label}.");
                }
            }
            (secrets, minted)
        }
        Err(e) => fail!("secrets", "secret bootstrap failed: {e}"),
    };

    if let Err(e) = inv.wg_octets_for_server(&server.id).await {
        fail!("deploy", "WireGuard address assignment failed: {e}");
    }
    let deploy_revision = match inv.deploy_input_revision(&server.id).await {
        Ok(revision) => revision,
        Err(e) => fail!("deploy", "cannot snapshot deploy inputs: {e}"),
    };
    let current_server = match inv.get_server(&server.id).await {
        Ok(Some(server)) => server,
        Ok(None) => fail!("deploy", "server was removed before deploy"),
        Err(e) => fail!("deploy", "cannot refresh server before deploy: {e}"),
    };
    if current_server.enabled_protocols != server.enabled_protocols
        || current_server.kernels != server.kernels
    {
        write_deploy_audit(
            &inv,
            &current_server,
            &bootstrapped,
            &[],
            &[],
            0,
            0,
            None,
            true,
            &deploy_revision,
        )
        .await;
        fail!("deploy", "inventory changed while preparing deploy; retry");
    }
    let server = current_server;
    let secrets = match inv.list_server_secrets(&server.id).await {
        Ok(secrets) => secrets,
        Err(e) => fail!("deploy", "cannot refresh server secrets: {e}"),
    };
    if let Err(e) = registry.validate_server(&server, &secrets) {
        fail!("validate", "config changed before deploy: {e}");
    }

    let skip_reason: Option<&'static str> = if !deploy_key_path.exists() {
        Some(DEPLOY_KEY_ABSENT_MSG)
    } else if server.kernels.is_empty() {
        Some("server has no kernels declared")
    } else {
        None
    };
    if let Some(reason) = skip_reason {
        write_deploy_audit(
            &inv,
            &server,
            &bootstrapped,
            &[],
            &[],
            0,
            0,
            Some(reason),
            false,
            &deploy_revision,
        )
        .await;
        fail!("deploy", "deploy skipped — {reason}.");
    }

    let jump = match inv.resolve_jump_host(&server).await {
        Ok(j) => j,
        Err(e) => fail!("deploy", "jump host resolution failed: {e}"),
    };

    let ssh = SubprocessSshTransport::new(
        server.address.clone(),
        server.ssh_user.clone(),
        deploy_key_path,
    )
    .port(server.ssh_port)
    .trusted_fingerprint(server.trusted_host_fingerprint.clone())
    .with_jump(jump);

    let users = match inv.users_for_server(&server.id).await {
        Ok(u) => u,
        Err(e) => fail!("deploy", "users_for_server failed: {e}"),
    };
    let wg_octets = match inv.wg_octets_for_server(&server.id).await {
        Ok(octets) => octets,
        Err(e) => fail!("deploy", "WireGuard address assignment failed: {e}"),
    };
    if inv
        .deploy_input_revision(&server.id)
        .await
        .map_or(true, |current| current != deploy_revision)
    {
        write_deploy_audit(
            &inv,
            &server,
            &bootstrapped,
            &[],
            &[],
            0,
            0,
            None,
            true,
            &deploy_revision,
        )
        .await;
        fail!("deploy", "inventory changed while preparing deploy; retry");
    }
    if let Err(e) = inv.assert_no_uuid_collisions(&server.id).await {
        fail!("deploy", "{e}");
    }
    let known_user_uuids = match inv.known_user_uuids().await {
        Ok(k) => k,
        Err(e) => fail!("deploy", "known user UUID lookup failed: {e}"),
    };
    let ctx = RenderCtx::with_peers(&server, &secrets, &users).with_wg_octets(wg_octets);

    match inv.retired_server_kernels(&server.id).await {
        Ok(retired) => {
            if let Err(e) =
                vpnctl_kernels::reconcile_disabled_kernels(&registry, &server, &retired, &ssh).await
            {
                ssh_errors.push(format!("kernel shutdown failed: {e}"));
            }
        }
        Err(e) => ssh_errors.push(format!("retired kernel lookup failed: {e}")),
    }

    for kid in &server.kernels {
        let Some(kernel) = registry.kernel(kid) else {
            ssh_errors.push(format!("{}: kernel not registered", kid.0));
            send_step!("apply", "✗ {} — kernel not registered.", kid.0);
            continue;
        };
        let supported = kernel.supported_protocols();
        let protocols: Vec<&dyn vpnctl_core::Protocol> = server
            .enabled_protocols
            .iter()
            .filter(|p| supported.contains(p))
            .filter_map(|p| registry.protocol(p))
            .collect();
        if protocols.is_empty() {
            send_step!("apply", "{}: no enabled protocols; skipping config.", kid.0);
            continue;
        }
        send_step!("install", "{}: ensure_installed (apt + systemd)…", kid.0);
        if let Err(e) = kernel.ensure_installed(&ssh).await {
            ssh_errors.push(format!("{}: ensure_installed failed: {e}", kid.0));
            send_step!("install", "✗ {} install failed: {e}", kid.0);
            continue;
        }
        send_step!(
            "render",
            "{}: rendering config for {} protocol(s)…",
            kid.0,
            protocols.len()
        );
        let config = match kernel.render_config(&ctx, &users, &protocols) {
            Ok(c) => c,
            Err(e) => {
                ssh_errors.push(format!("{}: render failed: {e}", kid.0));
                send_step!("render", "✗ {} render failed: {e}", kid.0);
                continue;
            }
        };
        if kid.0 == "sing-box" {
            match inv.get_reserved_ports(&server.id).await {
                Ok(reserved) => {
                    if let Err(e) =
                        vpnctl_kernels::validate_config_excludes_ports(&config, &reserved)
                    {
                        ssh_errors.push(format!("{}: reserved-ports guard refused: {e}", kid.0));
                        send_step!("render", "✗ {} reserved-ports guard refused: {e}", kid.0);
                        continue;
                    }
                }
                Err(e) => {
                    ssh_errors.push(format!("{}: reserved-ports lookup failed: {e}", kid.0));
                    send_step!("render", "✗ {} reserved-ports lookup failed: {e}", kid.0);
                    continue;
                }
            }
        }
        total_config_bytes += config.len();
        send_step!("apply", "{}: applying config + restart…", kid.0);
        if let Err(e) = kernel
            .apply_config_with_known_users(&ssh, &config, &known_user_uuids)
            .await
        {
            ssh_errors.push(format!("{}: apply_config failed: {e}", kid.0));
            send_step!("apply", "✗ {} apply failed: {e}", kid.0);
            continue;
        }
        ssh_kernels_pushed.push(kid.0.clone());
        configs_applied += 1;
        send_step!("apply", "✓ {} — config applied, service active.", kid.0);
        if let Err(e) = kernel.open_firewall(&ssh, &ctx, &protocols).await {
            ssh_errors.push(format!("{}: open_firewall failed: {e}", kid.0));
            send_step!("apply", "✗ {} firewall failed: {e}", kid.0);
            continue;
        }
        if let Err(e) = vpnctl_inventory::bootstrap::refresh_deployed_server_secrets(
            &inv, kernel, &ssh, &ctx, "admin",
        )
        .await
        {
            ssh_errors.push(format!("{}: {e}", kid.0));
            send_step!("apply", "✗ {}: {e}", kid.0);
        }
    }

    let audit_action = write_deploy_audit(
        &inv,
        &server,
        &bootstrapped,
        &ssh_kernels_pushed,
        &ssh_errors,
        total_config_bytes,
        configs_applied,
        None,
        false,
        &deploy_revision,
    )
    .await;

    if audit_action == "server.deploy" {
        let _ = tx
            .send(BootstrapEvent::Ok {
                server_id: server.id.0.clone(),
                redirect,
            })
            .await;
    } else {
        let message = if audit_action == "server.deploy.stale" && ssh_errors.is_empty() {
            "inventory changed during deploy; the server remains pending — deploy again".to_string()
        } else if ssh_errors.is_empty() {
            "deploy skipped — no kernel config was applied".to_string()
        } else {
            format!(
                "deploy finished with {} error(s): {}",
                ssh_errors.len(),
                ssh_errors.join("; ")
            )
        };
        let _ = tx
            .send(BootstrapEvent::Error {
                phase: "apply",
                message,
            })
            .await;
    }
}
