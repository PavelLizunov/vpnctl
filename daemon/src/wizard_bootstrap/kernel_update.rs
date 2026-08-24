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

/// Update the kernel BINARIES on an EXISTING server, streaming per-step
/// progress over SSE — the "Update kernels" button (update-kernels PR2).
///
/// Unlike [`run_redeploy`], this NEVER renders or applies a config: it
/// runs only each declared kernel's `ensure_installed` (apt upgrade +
/// service install/restart of the package), bracketed by a `status()`
/// version probe so the operator sees `before → after`. Because it does
/// NOT call `render_config`/`apply_config`, it never enters the DG-1
/// UUID-removal guard path — which is the whole point: a node whose
/// inventory has drifted (users removed in inv.db but still live on the
/// node) can have its kernel binary upgraded WITHOUT the deploy guard
/// refusing to push a user-shrinking config. This is intentional and the
/// node's running config is left exactly as-is.
///
/// Shares the SAME per-server [`DeployGuard`] as the deploy paths so an
/// update can't race a deploy (or another update) restarting the same
/// node. Writes a DISTINCT `kernel.update` audit row (kept separate from
/// `server.deploy` so the timeline distinguishes the two actions).
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
                // Hold the per-server permit for the whole pipeline; drop
                // here (also on panic/cancel via RAII) releases it.
                drop(guard);
            });
        }
        None => {
            // A deploy OR update of this server is already in flight —
            // refuse rather than restart the same node concurrently.
            let _ = tx.try_send(BootstrapEvent::Error {
                phase: "update",
                message: format!(
                    "deploy/update already running for server '{}' — wait for it to finish, then retry",
                    server.id.0
                ),
            });
            // tx drops → ReceiverStream completes after this one event.
        }
    }
    ReceiverStream::new(rx)
}

/// Update kernel binaries on EVERY server in one streamed pass — the
/// "Update all kernels" button. Copies [`run_deploy_all`]'s structure
/// verbatim but drives [`run_update_kernels`] per server. Best-effort:
/// a down node is reported as a `✗` line and the rest still update.
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
    let mut ok_count = 0usize;
    let mut failed: Vec<String> = Vec::new();

    for server in servers {
        let sid = server.id.0.clone();
        let _ = tx
            .send(BootstrapEvent::Step {
                phase: "server",
                message: format!("── updating kernels on {sid} ──"),
            })
            .await;
        // Drive this server's kernel update to completion, forwarding its
        // events as Step lines (prefixed with the server id). A per-server
        // Ok/Error becomes a ✓/✗ summary line — NOT a stream terminal.
        let mut stream = Box::pin(run_update_kernels(
            server,
            inv.clone(),
            Arc::clone(&registry),
            deploy_key_path.clone(),
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
        if had_error {
            failed.push(sid);
        } else {
            ok_count += 1;
        }
    }

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
    // Terminal Ok — best-effort across the fleet; per-server failures are
    // surfaced as ✗ lines above. The frontend reloads /admin/servers.
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
    // Parallel per-kernel records for the `kernel.update` audit payload.
    let mut kernels_touched: Vec<String> = Vec::new();
    let mut versions_before: Vec<serde_json::Value> = Vec::new();
    let mut versions_after: Vec<serde_json::Value> = Vec::new();

    // ── SSH preconditions — same skip-reasons as redeploy, MINUS the
    // secret-minting (no config is rendered here, so no secrets needed).
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

    let ssh = SubprocessSshTransport::new(
        server.address.clone(),
        server.ssh_user.clone(),
        deploy_key_path,
    )
    .port(server.ssh_port);

    // ── Per-kernel: probe version → ensure_installed → probe again. ──
    // NO render_config, NO apply_config, NO reserved-ports guard, NO
    // DG-1 path — only the binary is touched, the running config is left
    // exactly as-is (the whole point: safe on inventory-drift nodes).
    // Per-kernel isolation identical to redeploy_pipeline: a failure is
    // collected and we `continue`, so one kernel's failure doesn't abort
    // the others.
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

    // ── Audit — DISTINCT `kernel.update` action (kept separate from
    // `server.deploy` so the timeline distinguishes them). ────────────
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

    // ── Terminal event — Ok ONLY when every kernel succeeded. ─────────
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
