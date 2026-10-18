use std::path::PathBuf;
use std::sync::Arc;

use futures_core::Stream;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use super::audit::write_update_kernels_audit;
use super::guard::{DEPLOY_KEY_ABSENT_MSG, DeployGuard};
use super::types::BootstrapEvent;
use crate::http_util::path_segment_encode;
use crate::ssh_subprocess::SubprocessSshTransport;
use vpnctl_core::{Registry, Server};
use vpnctl_inventory::SqliteInventory;

pub fn run_update_kernels(
    server: Server,
    inv: SqliteInventory,
    registry: Arc<Registry>,
    deploy_key_path: PathBuf,
) -> impl Stream<Item = BootstrapEvent> + Send + 'static {
    let (tx, rx) = mpsc::channel::<BootstrapEvent>(64);
    match DeployGuard::try_acquire(&server.id.0) {
        Some(guard) => {
            tokio::spawn(async move {
                update_kernels_pipeline(server, inv, registry, deploy_key_path, tx).await;
                drop(guard);
            });
        }
        None => {
            let _ = tx.try_send(BootstrapEvent::Error {
                phase: "update",
                message: format!(
                    "deploy/update already running for server '{}' — wait for it to finish, then retry",
                    server.id.0
                ),
            });
        }
    }
    ReceiverStream::new(rx)
}

pub fn run_update_kernels_all(
    servers: Vec<Server>,
    inv: SqliteInventory,
    registry: Arc<Registry>,
    deploy_key_path: PathBuf,
) -> impl Stream<Item = BootstrapEvent> + Send + 'static {
    let (tx, rx) = mpsc::channel::<BootstrapEvent>(128);
    tokio::spawn(async move {
        update_kernels_all_pipeline(servers, inv, registry, deploy_key_path, tx).await;
    });
    ReceiverStream::new(rx)
}

async fn update_kernels_all_pipeline(
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
                    message: format!("── updating kernels on {sid} ──"),
                })
                .await;
            let mut stream = Box::pin(run_update_kernels(server, inv, registry, deploy_key_path));
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
                                phase: "done",
                                message: format!("✓ {sid} kernels updated"),
                            })
                            .await;
                    }
                    BootstrapEvent::Error { message, .. } => {
                        had_error = true;
                        let _ = tx
                            .send(BootstrapEvent::Step {
                                phase: "done",
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
        format!("done — updated kernels on {total}/{total} servers.")
    } else {
        format!(
            "done — updated kernels on {ok_count}/{total} servers; failed: {}",
            failed.join(", ")
        )
    };
    let _ = tx
        .send(BootstrapEvent::Step {
            phase: "done",
            message: summary,
        })
        .await;
    let _ = tx
        .send(BootstrapEvent::Ok {
            server_id: "all".into(),
            redirect: "/admin/servers".into(),
        })
        .await;
}

async fn update_kernels_pipeline(
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

    let redirect = format!("/admin/servers/{}", path_segment_encode(&server.id.0));
    let mut ssh_errors: Vec<String> = Vec::new();
    let mut kernels_touched: Vec<String> = Vec::new();
    let mut versions_before: Vec<serde_json::Value> = Vec::new();
    let mut versions_after: Vec<serde_json::Value> = Vec::new();

    let skip_reason: Option<&'static str> = if !deploy_key_path.exists() {
        Some(DEPLOY_KEY_ABSENT_MSG)
    } else if server.kernels.is_empty() {
        Some("server has no kernels declared")
    } else {
        None
    };
    if let Some(reason) = skip_reason {
        write_update_kernels_audit(&inv, &server, &[], &[], &[], &[], Some(reason)).await;
        fail!("update", "update skipped — {reason}.");
    }

    let jump = match inv.resolve_jump_host(&server).await {
        Ok(j) => j,
        Err(e) => fail!("update", "jump host resolution failed: {e}"),
    };

    let ssh = SubprocessSshTransport::new(
        server.address.clone(),
        server.ssh_user.clone(),
        deploy_key_path,
    )
    .port(server.ssh_port)
    .trusted_fingerprint(server.trusted_host_fingerprint.clone())
    .with_jump(jump);

    for kid in &server.kernels {
        let Some(kernel) = registry.kernel(kid) else {
            ssh_errors.push(format!("{}: kernel not registered", kid.0));
            send_step!("update", "✗ {} — kernel not registered.", kid.0);
            continue;
        };
        send_step!("status", "{}: probing…", kid.0);
        let before = match kernel.status(&ssh).await {
            Ok(st) => st.version,
            Err(e) => {
                ssh_errors.push(format!("{}: status (before) failed: {e}", kid.0));
                send_step!("status", "✗ {} status probe failed: {e}", kid.0);
                continue;
            }
        };
        send_step!("install", "{}: ensure_installed…", kid.0);
        if let Err(e) = kernel.ensure_installed(&ssh).await {
            ssh_errors.push(format!("{}: ensure_installed failed: {e}", kid.0));
            send_step!("install", "✗ {} ensure_installed failed: {e}", kid.0);
            continue;
        }
        let after = match kernel.status(&ssh).await {
            Ok(st) => st.version,
            Err(e) => {
                ssh_errors.push(format!("{}: status (after) failed: {e}", kid.0));
                send_step!("status", "✗ {} status probe failed: {e}", kid.0);
                continue;
            }
        };
        send_step!("done", "{}: {before:?} → {after:?}", kid.0);
        kernels_touched.push(kid.0.clone());
        versions_before.push(serde_json::json!(before));
        versions_after.push(serde_json::json!(after));
    }

    write_update_kernels_audit(
        &inv,
        &server,
        &kernels_touched,
        &versions_before,
        &versions_after,
        &ssh_errors,
        None,
    )
    .await;

    if ssh_errors.is_empty() {
        let _ = tx
            .send(BootstrapEvent::Ok {
                server_id: server.id.0.clone(),
                redirect,
            })
            .await;
    } else {
        let _ = tx
            .send(BootstrapEvent::Error {
                phase: "update",
                message: format!(
                    "update finished with {} error(s): {}",
                    ssh_errors.len(),
                    ssh_errors.join("; ")
                ),
            })
            .await;
    }
}
