use std::sync::Arc;

use futures_core::Stream;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use super::guard::DeployGuard;
use super::types::{BootstrapEvent, BootstrapPlan};
use super::util::ssh_password_run;
use crate::http_util::path_segment_encode;
use crate::ssh_subprocess::SubprocessSshTransport;
use vpnctl_core::shell::single_quote as shell_single_quote;
use vpnctl_core::{KernelId, ProtocolId, Registry, RenderCtx, Server, ServerId, SshTransport};
use vpnctl_inventory::{SqliteInventory, bootstrap_server_secrets};

/// Operator-facing remediation for the verify-key phase, rendered into
/// the browser via the SSE `Error` event. Operator-action-policy
/// (CLAUDE.md HARD rule): NO `cat … on the node` / shell instruction —
/// point at the product surfaces (restart the wizard, redeploy from the
/// server page) instead. Extracted to a const so
/// `verify_key_fail_copy_has_no_cat_on_node` can pin it without SSH.
pub(super) const VERIFY_KEY_FAIL_HINT: &str = "The deploy key push didn't take — \
     restart the wizard or re-run deploy from the server page.";

/// Run the full bootstrap as an async stream of events. The caller
/// (the SSE handler) wraps this into `axum::response::sse::Sse::new`.
///
/// Internally: spawn the pipeline as a tokio task that pushes events
/// into a bounded mpsc channel (capacity 64 — enough for the burst
/// at startup plus the trickle during the slow apt-get step). The
/// returned `ReceiverStream` is the consumer end; when the spawned
/// task ends, the Sender drops and the stream completes naturally
/// (browser sees a clean EOF).
pub fn run_bootstrap(
    plan: BootstrapPlan,
    inv: SqliteInventory,
    registry: Arc<Registry>,
) -> impl Stream<Item = BootstrapEvent> + Send + 'static {
    let (tx, rx) = mpsc::channel::<BootstrapEvent>(64);
    tokio::spawn(async move {
        bootstrap_pipeline(plan, inv, registry, tx).await;
    });
    ReceiverStream::new(rx)
}

/// The 9-phase pipeline itself. Each phase sends one or more `Step`
/// events; on failure it sends an `Error` and returns early. Helpers
/// `send_step!` and `fail!` keep the call sites readable; both
/// macros gracefully ignore channel-send failures (the receiver
/// closing mid-bootstrap = browser disconnected, nothing to do).
async fn bootstrap_pipeline(
    plan: BootstrapPlan,
    inv: SqliteInventory,
    registry: Arc<Registry>,
    tx: mpsc::Sender<BootstrapEvent>,
) {
    // Helper macros — these are NOT `yield`-based (would conflict
    // with async_stream::stream!), they call `tx.send(...).await`
    // directly. macro_rules expands at the use site so the resulting
    // code compiles cleanly.
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

    // ── 0. Pubkey sanity check ────────────────────────────────────
    send_step!(
        "setup",
        "loading vpnctld deploy pubkey from {}",
        plan.deploy_key_path.display()
    );
    let deploy_pubkey = match crate::ssh_subprocess::read_public_key(&plan.deploy_key_path) {
        Ok(s) => s,
        Err(e) => fail!(
            "setup",
            "can't read {}: {e}. Re-check daemon's deploy key (see /admin/settings).",
            plan.deploy_key_path.with_extension("pub").display()
        ),
    };

    // ── 1. SSH probe (password auth) ──────────────────────────────
    send_step!(
        "probe",
        "ssh {}@{}:{} with supplied password…",
        plan.ssh_user,
        plan.address,
        plan.ssh_port
    );
    match ssh_password_run(
        &plan.address,
        plan.ssh_port,
        &plan.ssh_user,
        &plan.root_password,
        &plan.known_hosts_path,
        "true",
    )
    .await
    {
        Ok(_) => send_step!("probe", "ok — {} login confirmed.", plan.ssh_user),
        Err(e) => fail!("probe", "{e}. Re-check IP, port, SSH user and password."),
    }
    if plan.ssh_user != "root" {
        send_step!("probe", "checking passwordless sudo for {}…", plan.ssh_user);
        match ssh_password_run(
            &plan.address,
            plan.ssh_port,
            &plan.ssh_user,
            &plan.root_password,
            &plan.known_hosts_path,
            "sudo -n sh -c true",
        )
        .await
        {
            Ok(_) => send_step!("probe", "ok — passwordless sudo confirmed."),
            Err(e) => fail!(
                "probe",
                "{e}. User '{}' needs passwordless sudo to manage the server.",
                plan.ssh_user
            ),
        }
    }

    // ── 2. ssh-keyscan + fingerprint ──────────────────────────────
    send_step!(
        "fingerprint",
        "fetching host key fingerprint via ssh-keyscan…"
    );
    // Wrap the blocking subprocess in spawn_blocking so a slow
    // ssh-keyscan (~5–10s default `-T 10`) doesn't pin the tokio
    // worker thread serving this SSE stream. Per the
    // `vpnctl-host-fingerprint` doc-comment.
    let addr = plan.address.clone();
    let port = plan.ssh_port;
    let fingerprint = match tokio::task::spawn_blocking(move || {
        vpnctl_host_fingerprint::fetch_via_keyscan(&addr, port)
    })
    .await
    {
        Ok(Ok(fp)) => fp,
        Ok(Err(e)) => fail!("fingerprint", "{e}"),
        Err(join_err) => {
            // `JoinError` fires on BOTH panic and runtime cancellation
            // — distinguish them so the SSE operator sees the right
            // failure cause (a cancelled wizard step is very different
            // from a panicked subprocess).
            let cause = if join_err.is_panic() {
                "panicked"
            } else {
                "cancelled"
            };
            fail!("fingerprint", "ssh-keyscan task {cause}: {join_err}");
        }
    };
    send_step!("fingerprint", "pinned {}", fingerprint);

    // ── 3. Push deploy pubkey to authorized_keys ──────────────────
    send_step!(
        "push-key",
        "appending deploy pubkey to ~/.ssh/authorized_keys (idempotent)…"
    );
    let push_cmd = format!(
        "set -eu; \
         mkdir -p ~/.ssh && chmod 0700 ~/.ssh; \
         touch ~/.ssh/authorized_keys && chmod 0600 ~/.ssh/authorized_keys; \
         grep -qxF {pk_q} ~/.ssh/authorized_keys || echo {pk_q} >> ~/.ssh/authorized_keys; \
         echo done",
        pk_q = shell_single_quote(&deploy_pubkey),
    );
    match ssh_password_run(
        &plan.address,
        plan.ssh_port,
        &plan.ssh_user,
        &plan.root_password,
        &plan.known_hosts_path,
        &push_cmd,
    )
    .await
    {
        Ok(_) => send_step!("push-key", "ok — pubkey present in authorized_keys."),
        Err(e) => fail!("push-key", "{e}"),
    }

    // ── 4. Verify pubkey auth works ───────────────────────────────
    send_step!(
        "verify-key",
        "re-connecting with pubkey auth (BatchMode=yes)…"
    );
    let ssh = SubprocessSshTransport::new(
        plan.address.clone(),
        plan.ssh_user.clone(),
        plan.deploy_key_path.clone(),
    )
    .port(plan.ssh_port)
    .known_hosts(plan.known_hosts_path.clone());
    if let Err(e) = ssh.exec("true").await {
        fail!(
            "verify-key",
            "pubkey auth failed: {e}. {VERIFY_KEY_FAIL_HINT}"
        );
    }
    send_step!("verify-key", "ok — pubkey auth confirmed.");

    // ── 5. Register server in inventory ───────────────────────────
    // Duplicate-address guard (HANDOFF §6 #2, review-agent important):
    // this is the wizard's REAL add_server point. `wizard_new_submit`
    // checks at step 1, but `find_available_server_id` suffixes the id
    // (`id-2`) around a collision — so an address registered between step 1
    // and here would still persist a second record for one box (the
    // `us`/`us1` shape the fix targets). Guard the ADDRESS at the single
    // write point every wizard bootstrap funnels through. SSH-gated path —
    // not unit-testable without a node; `server_id_for_address` is
    // unit-tested and the placement is review-verified.
    match inv.server_id_for_address(&plan.address).await {
        Ok(Some(existing)) => fail!(
            "register",
            "address {} is already registered to server '{existing}' — one node = one server record; redeploy '{existing}' from its server page instead of bootstrapping a duplicate",
            plan.address
        ),
        Ok(None) => {}
        Err(e) => fail!("register", "server_id_for_address: {e}"),
    }
    send_step!(
        "register",
        "minting Server row in inv.db (id='{}')…",
        plan.server_id
    );
    let kernel_id = KernelId("sing-box".into());
    let default_protocols: Vec<ProtocolId> = registry
        .kernel(&kernel_id)
        .map(|k| k.supported_protocols())
        .unwrap_or_default();
    let server = Server {
        id: ServerId(plan.server_id.clone()),
        address: plan.address.clone(),
        ssh_port: plan.ssh_port,
        ssh_user: plan.ssh_user.clone(),
        kernels: vec![kernel_id.clone()],
        enabled_protocols: default_protocols.clone(),
        trusted_host_fingerprint: Some(fingerprint.clone()),
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    };
    if let Err(e) = inv.add_server(&server).await {
        fail!("register", "inv.add_server: {e}");
    }
    if let Err(e) = inv
        .update_trusted_fingerprint(&server.id, &fingerprint)
        .await
    {
        fail!("register", "update_trusted_fingerprint: {e}");
    }
    if let Err(e) = inv
        .audit(
            "admin",
            "server.wizard",
            Some(&plan.server_id),
            Some(&serde_json::json!({
                "address": plan.address,
                "ssh_user": plan.ssh_user,
                "ssh_port": plan.ssh_port,
                "kernels": ["sing-box"],
                "protocols": default_protocols.iter().map(|p| &p.0).collect::<Vec<_>>(),
                "fingerprint": fingerprint,
            })),
        )
        .await
    {
        // Audit failure is non-fatal — server is already registered.
        tracing::warn!(
            target = "vpnctld::wizard",
            server = %plan.server_id,
            error = %e,
            "wizard audit write failed (non-fatal)"
        );
    }
    send_step!("register", "ok — server registered.");
    let _deploy_guard = match DeployGuard::try_acquire(&server.id.0) {
        Some(guard) => guard,
        None => fail!("register", "another deploy started for this server; retry"),
    };

    // ── 6. Bootstrap per-server secrets ───────────────────────────
    send_step!(
        "secrets",
        "minting per-protocol secrets (VLESS REALITY, WireGuard, hy2)…"
    );
    // Per-protocol secret bootstrapping is centralised in
    // `bootstrap_server_secrets` (below) so the wizard, the
    // `server_deploy` handler, and any future re-deploy entry point
    // mint the same secret-key shapes. When a 4th protocol with a
    // server-side secret arrives, that helper is the only place to
    // touch — see the function's own doc-comment for the long-term
    // plan (`Protocol::mint_server_secrets` trait method).
    match bootstrap_server_secrets(&inv, &server, &registry).await {
        Ok((_, minted)) => {
            for label in minted {
                send_step!("secrets", "ok — {label} minted.");
            }
        }
        Err(e) => fail!("secrets", "{e}"),
    };

    // ── 7-8. Per-kernel install + apply ───────────────────────────
    let deploy_revision = match inv.deploy_input_revision(&server.id).await {
        Ok(revision) => revision,
        Err(e) => fail!("install", "cannot snapshot deploy inputs: {e}"),
    };
    let server = match inv.get_server(&server.id).await {
        Ok(Some(server)) => server,
        Ok(None) => fail!("install", "server was removed during bootstrap"),
        Err(e) => fail!("install", "cannot refresh server: {e}"),
    };
    let secrets = match inv.list_server_secrets(&server.id).await {
        Ok(secrets) => secrets,
        Err(e) => fail!("install", "cannot refresh server secrets: {e}"),
    };
    let users = match inv.users_for_server(&server.id).await {
        Ok(u) => u,
        Err(e) => fail!("install", "users_for_server: {e}"),
    };
    if inv
        .deploy_input_revision(&server.id)
        .await
        .map_or(true, |current| current != deploy_revision)
    {
        fail!("install", "inventory changed while preparing deploy; retry");
    }
    // uuid-uniqueness gate (HANDOFF §4.1) — fail CLOSED before render/apply.
    if let Err(e) = inv.assert_no_uuid_collisions(&server.id).await {
        fail!("install", "{e}");
    }
    let ctx = RenderCtx::new(&server, &secrets);
    for kid in &server.kernels {
        let Some(kernel) = registry.kernel(kid) else {
            send_step!(
                "install",
                "skip {} — kernel not registered in this build.",
                kid.0
            );
            continue;
        };
        send_step!(
            "install",
            "{}: apt-get install + start (this is the slow step — up to 60s)…",
            kid.0
        );
        if let Err(e) = kernel.ensure_installed(&ssh).await {
            fail!("install", "{}: ensure_installed: {e}", kid.0);
        }
        send_step!("install", "{}: ok — installed.", kid.0);

        let supported = kernel.supported_protocols();
        let protocols: Vec<&dyn vpnctl_core::Protocol> = server
            .enabled_protocols
            .iter()
            .filter(|p| supported.contains(p))
            .filter_map(|p| registry.protocol(p))
            .collect();
        if protocols.is_empty() {
            send_step!(
                "apply",
                "{}: no protocols for this kernel — skipping config render.",
                kid.0
            );
            continue;
        }
        send_step!(
            "apply",
            "{}: rendering config for {} protocol(s)…",
            kid.0,
            protocols.len()
        );
        let config = match kernel.render_config(&ctx, &users, &protocols) {
            Ok(c) => c,
            Err(e) => fail!("apply", "{}: render_config: {e}", kid.0),
        };
        // Reserved-ports pre-apply guard (post-2026-05-26). A fresh
        // wizard bootstrap is unlikely to have a reserved list set
        // yet (the operator typically reserves AFTER importing the
        // co-tenant ports), but defending here keeps the contract
        // honest for any future flow that pre-seeds reservations
        // before the first bootstrap.
        if kid.0 == "sing-box" {
            match inv.get_reserved_ports(&server.id).await {
                Ok(reserved) => {
                    if let Err(e) =
                        vpnctl_kernels::validate_config_excludes_ports(&config, &reserved)
                    {
                        fail!("apply", "{}: reserved-ports guard refused: {e}", kid.0);
                    }
                }
                Err(e) => {
                    fail!("apply", "{}: reserved-ports lookup failed: {e}", kid.0);
                }
            }
        }
        send_step!(
            "apply",
            "{}: pushing {} bytes + systemctl restart…",
            kid.0,
            config.len()
        );
        if let Err(e) = kernel.apply_config(&ssh, &config).await {
            fail!("apply", "{}: apply_config: {e}", kid.0);
        }
        send_step!("apply", "{}: ok — service running with new config.", kid.0);
        // Best-effort firewall open (Kernel::open_firewall) — fresh deploy
        // reachable without a manual `ufw allow`; non-fatal (config is live).
        if let Err(e) = kernel.open_firewall(&ssh, &ctx, &protocols).await {
            send_step!("apply", "⚠ {}: firewall step skipped: {e}", kid.0);
        }
    }

    // ── 8.5 Deploy-baseline audit (review 2026-06-04) ─────────────
    // The wizard genuinely rendered + applied config above, but used
    // to audit only `server.wizard` — so the server's deploy HISTORY
    // stayed empty until the first manual deploy and the audit
    // timeline read «server is live» with zero deploys. Write the
    // canonical `server.deploy` row (via:\"wizard-bootstrap\"). This
    // also gives the pending-deploy detector a real baseline: a grant
    // made after the wizard (a per-user `user.grant` row) compares
    // newer than this ts → the «config not yet deployed» banner fires
    // exactly when it should. Reaching this point = every kernel
    // applied successfully (any failure above returned via fail!).
    //
    // The revision covers every render input, not only grant membership,
    // and the compare + audit insert are one SQLite write transaction.
    let payload = serde_json::json!({
        "kernels": server.kernels.iter().map(|k| &k.0).collect::<Vec<_>>(),
        "protocols": server.enabled_protocols.iter().map(|p| &p.0).collect::<Vec<_>>(),
        "via": "wizard-bootstrap",
    });
    match inv
        .audit_deploy_if_revision("admin", &server.id, &deploy_revision, &payload)
        .await
    {
        Ok(true) => {}
        Err(e) => {
            tracing::warn!(
                target = "vpnctld::wizard",
                server = %plan.server_id,
                error = %e,
                "audit write failed for server.deploy (wizard-bootstrap) — node already live"
            );
        }
        Ok(false) => {
            send_step!(
                "apply",
                "note: inventory changed while bootstrapping — the applied config predates it; \
                 deploy this server again."
            );
        }
    }

    // ── 9. Done ───────────────────────────────────────────────────
    let redirect = format!("/admin/servers/{}", path_segment_encode(&plan.server_id));
    let _ = tx
        .send(BootstrapEvent::Ok {
            server_id: plan.server_id,
            redirect,
        })
        .await;
}
