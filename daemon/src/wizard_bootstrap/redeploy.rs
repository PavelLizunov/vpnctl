use std::path::PathBuf;
use std::sync::Arc;

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

/// Re-deploy an EXISTING server, streaming per-step progress over SSE
/// (item-1, 2026-05-31). Unlike `run_bootstrap` (a NEW server: probe →
/// fingerprint → push-key → register), the server already exists and
/// already trusts the deploy key, so this runs only the tail:
/// mint-missing-secrets → per-kernel `ensure_installed` → render
/// (+ reserved-ports guard) → `apply_config`. It writes the SAME
/// `server.deploy` audit row the synchronous handler did, AND — the
/// reason this exists — it ends in `BootstrapEvent::Error` (not `Ok`)
/// whenever ANY kernel's install/render/apply failed. The old
/// synchronous handler pushed those failures into the audit payload but
/// still returned a 303 redirect the operator read as success, so a
/// sing-box that crash-looped (e.g. a missing cert) looked "deployed".
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
                // Hold the per-server permit for the whole pipeline; drop
                // here (also on panic/cancel via RAII) releases it.
                drop(guard);
            });
        }
        None => {
            // A deploy of this server is already in flight — refuse rather
            // than render + restart the same node concurrently. The
            // deploy-all pass surfaces this as a per-server ✗ line and
            // moves on; a single-server SSE deploy shows it as the
            // terminal error.
            let _ = tx.try_send(BootstrapEvent::Error {
                phase: "deploy",
                message: format!(
                    "{DEPLOY_ALREADY_RUNNING_PREFIX} for server '{}' — wait for it to finish, then retry",
                    server.id.0
                ),
            });
            // tx drops → ReceiverStream completes after this one event.
        }
    }
    ReceiverStream::new(rx)
}

/// Re-deploy EVERY server in one streamed pass — the "Deploy all" button
/// (2026-06-03). Run after adding a user / granting servers so the new
/// UUID lands on every node (a grant only updates inv.db; the node's
/// sing-box isn't touched until a deploy). Sequentially runs
/// [`run_redeploy`] per server, flattening each server's events into
/// this single stream as `Step`s (so one server's terminal Ok/Error
/// isn't mistaken for the whole-run terminal), then emits ONE terminal
/// `Ok` with a summary. Best-effort: a down node is reported as a `✗`
/// line and the rest still deploy.
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
    let mut ok_count = 0usize;
    let mut failed: Vec<String> = Vec::new();

    for server in servers {
        let sid = server.id.0.clone();
        let _ = tx
            .send(BootstrapEvent::Step {
                phase: "server",
                message: format!("── deploying {sid} ──"),
            })
            .await;
        // Drive this server's re-deploy to completion, forwarding its
        // events as Step lines (prefixed with the server id). A per-server
        // Ok/Error becomes a ✓/✗ summary line — NOT a stream terminal.
        let mut stream = Box::pin(run_redeploy(
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
        if had_error {
            failed.push(sid);
        } else {
            ok_count += 1;
        }
    }

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
    // Terminal event — Ok when every node deployed, Error when any
    // failed. The frontend uses the terminal kind to decide the
    // banner colour; per-server failures are ALSO surfaced as ✗
    // lines above so the operator sees exactly which nodes need
    // attention.
    let _ = tx.send(deploy_all_terminal(&failed, summary)).await;
}

/// Choose the terminal SSE event for a fleet deploy pass. Pure —
/// tested in isolation below.
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

/// Drive [`run_redeploy`] over `servers` sequentially and return per-server
/// error strings (`"<sid>: <phase>: <msg>"`; empty = all deployed). Shared
/// by every after-mutation auto-deploy dispatcher (user disable/enable,
/// grant/revoke, the Boosty bridge) so they all get the same semantics:
///
/// * **Deploy-lock retry** — a deploy already in flight rendered its config
///   BEFORE the caller's mutation committed, so a lock refusal would leave
///   the mutation off the node until a manual deploy. Bounded retry
///   (3 × 5 s) covers back-to-back operator clicks; a node stuck for
///   minutes still ends in an error + the pending banner staying up.
/// * **Missing-key guard** — with no deploy key, running the pipeline would
///   only stamp `ssh_skip_reason` `server.deploy` rows; return one error
///   instead and leave the pending banner up.
/// * Per-server terminal Ok/Error stays observable (run_deploy_all's
///   stream wraps failures as Step lines and always ends Ok — wrong here).
pub(crate) async fn redeploy_servers_collect_errors(
    servers: Vec<Server>,
    inv: SqliteInventory,
    registry: Arc<Registry>,
    deploy_key_path: PathBuf,
) -> Vec<String> {
    use tokio_stream::StreamExt;
    let mut errors: Vec<String> = Vec::new();
    if !deploy_key_path.exists() {
        errors.push(DEPLOY_KEY_ABSENT_MSG.into());
        return errors;
    }
    for server in servers {
        let sid = server.id.0.clone();
        let mut failure: Option<String> = None;
        for attempt in 0u32..4 {
            if attempt > 0 {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
            failure = None;
            let mut stream = Box::pin(run_redeploy(
                server.clone(),
                inv.clone(),
                Arc::clone(&registry),
                deploy_key_path.clone(),
            ));
            while let Some(ev) = stream.next().await {
                if let BootstrapEvent::Error { phase, message } = ev {
                    failure = Some(format!("{phase}: {message}"));
                }
            }
            match &failure {
                Some(msg) if msg.contains(DEPLOY_ALREADY_RUNNING_PREFIX) => continue,
                _ => break,
            }
        }
        if let Some(msg) = failure {
            errors.push(format!("{sid}: {msg}"));
        }
    }
    errors
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

    let redirect = format!("/admin/servers/{}", path_segment_encode(&server.id.0));
    let mut ssh_errors: Vec<String> = Vec::new();
    let mut ssh_kernels_pushed: Vec<String> = Vec::new();
    let mut total_config_bytes: usize = 0;
    let mut configs_applied: usize = 0;

    // ── 0. Pre-flight: kernel/protocol compatibility ─────────────
    // Same check the synchronous handler runs before anything else
    // (admin.rs server_deploy). Without it, a protocol enabled on the
    // server but supported by NO declared kernel is silently filtered
    // out of every per-kernel render and the deploy still reports Ok —
    // the operator would never learn it isn't being delivered.
    // Secrets loaded BEFORE validation so the port-conflict guard sees
    // per-server overrides (vless.listen_port) already set by the operator.
    let pre_secrets = match inv.list_server_secrets(&server.id).await {
        Ok(s) => s,
        Err(e) => fail!("validate", "cannot load server secrets: {e}"),
    };
    if let Err(e) = registry.validate_server(&server, &pre_secrets) {
        fail!("validate", "config invalid before deploy: {e}");
    }

    // ── 1. Mint any missing per-protocol secrets (idempotent) ─────
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

    let deploy_revision = match inv.deploy_input_revision(&server.id).await {
        Ok(revision) => revision,
        Err(e) => fail!("deploy", "cannot snapshot deploy inputs: {e}"),
    };
    let server = match inv.get_server(&server.id).await {
        Ok(Some(server)) => server,
        Ok(None) => fail!("deploy", "server was removed before deploy"),
        Err(e) => fail!("deploy", "cannot refresh server before deploy: {e}"),
    };
    let secrets = match inv.list_server_secrets(&server.id).await {
        Ok(secrets) => secrets,
        Err(e) => fail!("deploy", "cannot refresh server secrets: {e}"),
    };
    if let Err(e) = registry.validate_server(&server, &secrets) {
        fail!("validate", "config changed before deploy: {e}");
    }

    // ── 2. SSH skip-reason ────────────────────────────────────────
    // Mirror the synchronous handler: these conditions write a distinct
    // skipped-attempt audit row carrying `ssh_skip_reason`, then end in a
    // terminal Error.
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

    let ssh = SubprocessSshTransport::new(
        server.address.clone(),
        server.ssh_user.clone(),
        deploy_key_path,
    )
    .port(server.ssh_port);

    let users = match inv.users_for_server(&server.id).await {
        Ok(u) => u,
        Err(e) => fail!("deploy", "users_for_server failed: {e}"),
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
    // uuid-uniqueness gate (HANDOFF §4.1) — fail CLOSED before any render or
    // `systemctl restart`: never push a config where two rendered users share
    // an effective VLESS uuid (sing-box would dedup them and brick one).
    if let Err(e) = inv.assert_no_uuid_collisions(&server.id).await {
        fail!("deploy", "{e}");
    }
    let ctx = RenderCtx::new(&server, &secrets);

    // ── 3. Per-kernel install → render → apply ────────────────────
    // Per-kernel isolation: a failed amneziawg install does NOT abort
    // the sing-box restart (matches the synchronous handler). Each
    // failure is collected; the terminal event reflects the aggregate.
    for kid in &server.kernels {
        let Some(kernel) = registry.kernel(kid) else {
            ssh_errors.push(format!("{}: kernel not registered", kid.0));
            send_step!("apply", "✗ {} — kernel not registered.", kid.0);
            continue;
        };
        send_step!("install", "{}: ensure_installed (apt + systemd)…", kid.0);
        if let Err(e) = kernel.ensure_installed(&ssh).await {
            ssh_errors.push(format!("{}: ensure_installed failed: {e}", kid.0));
            send_step!("install", "✗ {} install failed: {e}", kid.0);
            continue;
        }
        let supported = kernel.supported_protocols();
        let protocols: Vec<&dyn vpnctl_core::Protocol> = server
            .enabled_protocols
            .iter()
            .filter(|p| supported.contains(p))
            .filter_map(|p| registry.protocol(p))
            .collect();
        if protocols.is_empty() {
            ssh_kernels_pushed.push(format!("{} (installed, no protocols)", kid.0));
            send_step!(
                "apply",
                "{}: installed (no protocols enabled for it).",
                kid.0
            );
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
        // Reserved-ports pre-apply guard (migration 0028) — refuse a
        // config that would bind a co-tenant's port. sing-box only.
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
        if let Err(e) = kernel.apply_config(&ssh, &config).await {
            ssh_errors.push(format!("{}: apply_config failed: {e}", kid.0));
            send_step!("apply", "✗ {} apply failed: {e}", kid.0);
            continue;
        }
        ssh_kernels_pushed.push(kid.0.clone());
        configs_applied += 1;
        send_step!("apply", "✓ {} — config applied, service active.", kid.0);
        // Open the host firewall for the ports these protocols bind, so a
        // fresh deploy is reachable without a manual `ufw allow`. Best-effort:
        // a firewall failure (no ufw / cloud-firewall host) is surfaced but
        // does NOT fail the deploy — the config is already live.
        if let Err(e) = kernel.open_firewall(&ssh, &ctx, &protocols).await {
            send_step!("apply", "⚠ {} — firewall step skipped: {e}", kid.0);
        }
    }

    // ── 4. Audit (same shape + action as the synchronous handler) ──
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

    // ── 5. Terminal event — Ok ONLY when every kernel succeeded ───
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
