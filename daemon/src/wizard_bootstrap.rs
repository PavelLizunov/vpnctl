//! Phase E sub-iter 4b — add-server wizard's SSE bootstrap engine.
//!
//! # What this does (operator's view)
//!
//! Operator pasted an IP + root password into step 1. This module
//! turns that into a fully-deployed VPN server, streaming progress
//! line-by-line over Server-Sent Events:
//!
//! 1. **probe** — `ssh root@<addr>` with the supplied password, run
//!    `true` to confirm credentials work.
//! 2. **fingerprint** — `ssh-keyscan` the host's ed25519/rsa key and
//!    pin it as `trusted_host_fingerprint` (SHA256 form). TOFU — if
//!    we ever see a different fingerprint later, the daemon will
//!    refuse to connect until the operator approves the change.
//! 3. **push-key** — append the daemon's deploy pubkey to the
//!    server's `~/.ssh/authorized_keys` (idempotent — won't double-
//!    add if the operator re-runs the wizard for the same host).
//! 4. **verify-key** — `ssh -i <deploy-key>` (NO password) and run
//!    `true`. Proves pubkey auth works before we commit to inventory.
//! 5. **register** — `inv.add_server()` with default kernel
//!    `sing-box` + every protocol sing-box supports. Pavel's UX brief:
//!    "сразу все" — operator can disable on the detail page after.
//! 6. **secrets** — mint VLESS-REALITY keypair, WireGuard server
//!    keypair, Hysteria2 obfs password. Same logic as
//!    `server_deploy` handler.
//! 7. **install-\<kernel\>** — for each declared kernel:
//!    `kernel.ensure_installed(&ssh)` (apt-get install sing-box etc).
//! 8. **apply-\<kernel\>** — render the config + push via
//!    `kernel.apply_config(&ssh, &config)` (systemctl restart).
//! 9. **done** — final event carrying the new server's URL so the
//!    browser can redirect.
//!
//! Steps 1-2-3 use **password auth** via `sshpass -e ssh`; steps 4
//! onward use **key auth** via `SubprocessSshTransport`. The split
//! exists because we can't use key auth until step 3 finishes
//! pushing the key.
//!
//! # Why a separate module (not inline in the handler)
//!
//! The handler's job is request/response routing — wrapping a stream
//! into an `axum::response::sse::Sse` value. The bootstrap LOGIC
//! (sequencing, retries, error mapping) lives here so it can be unit-
//! tested without spinning up an axum router.
//!
//! # Error model
//!
//! Each phase either yields a `Step` (advisory progress text) or an
//! `Error` (terminal — pipeline returns early, no more events). After
//! `Ok` or `Error`, the spawned task ends and the mpsc Sender drops,
//! closing the ReceiverStream so the browser sees a clean EOF.
//!
//! # Cancellation semantics (deliberate — do not "fix")
//!
//! The bootstrap task is **detached** — it runs to completion even
//! if the SSE client disconnects mid-flight. Rationale: the operator
//! clicked "create server" with the expectation that the server
//! WILL exist when they next look. Aborting on tab-close would leave
//! a half-bootstrapped node (key pushed, server registered, sing-box
//! not installed yet) and require a second deploy click. Worse, the
//! operator might assume their click had no effect and not come back.
//!
//! The cost is small: a stranded subprocess running sshpass/ssh-keyscan
//! against a real node finishes in <60 s and the spawned task is
//! capped by the kernel install timeout. If the operator wants to
//! ABORT (rare), the recovery path is "go to /admin/servers, find
//! the half-baked entry, delete it" — one explicit operator action,
//! which matches the one-action ceiling.
//!
//! Review-agent 2026-05-17 (critical-2) flagged the lack of
//! cancellation; the decision to keep "run-to-completion" is
//! documented here so the next review pass doesn't re-raise it.
//!
//! # Why mpsc + ReceiverStream (not `async_stream::stream!`)
//!
//! Tried `stream!` first — it lets you write straight-line async
//! code with `yield X;` to emit events. But `stream!` is a syntactic
//! macro: it walks the body looking for `yield` tokens BEFORE other
//! macros expand, so `macro_rules! step { … yield X; … }` invocations
//! at the call site never get scanned and the resulting code doesn't
//! compile. We have ~30 yield points and don't want to expand them
//! all by hand, so we switched to a separate `bootstrap_pipeline()`
//! function that calls `tx.send(...).await` (which behaves like a
//! normal expression and can be macro-wrapped) and spawn it on a
//! tokio task feeding a bounded mpsc channel. The `ReceiverStream`
//! adapter turns the channel into a `Stream` for axum's `Sse::new`.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;

use futures_core::Stream;
use serde::Serialize;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use crate::http_util::path_segment_encode;
use crate::ssh_subprocess::{SubprocessSshTransport, ssh_safety_opts};
use vpnctl_core::shell::single_quote as shell_single_quote;
use vpnctl_core::{KernelId, ProtocolId, Registry, RenderCtx, Server, ServerId, SshTransport};
use vpnctl_inventory::SqliteInventory;

/// All the inputs the bootstrap needs. Built by the SSE handler from
/// the wizard session + the daemon's deploy key path.
#[derive(Clone, Debug)]
pub struct BootstrapPlan {
    /// Server id we're going to register the host as. Derived from
    /// `address` by `derive_server_id` so the operator doesn't have
    /// to invent a name (one-action ceiling).
    pub server_id: String,
    /// IPv4, IPv6 or hostname. Already validated by
    /// `crate::wizard::validate_address`.
    pub address: String,
    /// `root@<addr>` port. Defaults to 22 — overridden when the
    /// step-1 form's optional port field is non-empty.
    pub ssh_port: u16,
    /// Root password — used ONCE to push the deploy pubkey, then
    /// every subsequent step uses key auth.
    pub root_password: String,
    /// Path to the daemon's deploy private key
    /// (`/var/lib/vpnctl/.ssh/id_ed25519` in production). The bootstrap
    /// reads `.pub` from this to push to `authorized_keys`.
    pub deploy_key_path: PathBuf,
    /// known_hosts file the daemon uses for subsequent connects.
    /// Defaults to `/var/lib/vpnctl/.ssh/known_hosts`. Tests override
    /// with a tempdir.
    pub known_hosts_path: PathBuf,
}

/// One event in the bootstrap progress stream. Serialised as JSON
/// into the SSE event payload.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BootstrapEvent {
    /// Advisory progress. `phase` is a short machine-readable id
    /// (the browser groups consecutive events with the same phase);
    /// `message` is the human-readable text shown in the log pane.
    Step {
        phase: &'static str,
        message: String,
    },
    /// Terminal success. `server_id` is the registered id; `redirect`
    /// is the URL the browser should navigate to next (the server
    /// detail page).
    Ok { server_id: String, redirect: String },
    /// Terminal failure. `phase` is where it failed; `message` is
    /// the operator-readable reason. Stream ends after this — no more
    /// events.
    Error {
        phase: &'static str,
        message: String,
    },
}

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
        "ssh root@{}:{} with supplied password…",
        plan.address,
        plan.ssh_port
    );
    match ssh_password_run(
        &plan.address,
        plan.ssh_port,
        "root",
        &plan.root_password,
        &plan.known_hosts_path,
        "true",
    )
    .await
    {
        Ok(_) => send_step!("probe", "ok — root login confirmed."),
        Err(e) => fail!("probe", "{e}. Re-check IP, port and root password."),
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
        "root",
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
        "root".to_string(),
        plan.deploy_key_path.clone(),
    )
    .port(plan.ssh_port)
    .known_hosts(plan.known_hosts_path.clone());
    if let Err(e) = ssh.exec("true").await {
        fail!(
            "verify-key",
            "pubkey auth failed: {e}. \
             Check the pubkey landed (cat ~/.ssh/authorized_keys on the node) \
             and that sshd allows ed25519."
        );
    }
    send_step!("verify-key", "ok — pubkey auth confirmed.");

    // ── 5. Register server in inventory ───────────────────────────
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
        ssh_user: "root".into(),
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
    let secrets = match bootstrap_server_secrets(&inv, &server).await {
        Ok((secrets, minted)) => {
            for label in minted {
                send_step!("secrets", "ok — {label} minted.");
            }
            secrets
        }
        Err(e) => fail!("secrets", "{e}"),
    };

    // ── 7-8. Per-kernel install + apply ───────────────────────────
    let users = match inv.users_for_server(&server.id).await {
        Ok(u) => u,
        Err(e) => fail!("install", "users_for_server: {e}"),
    };
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

/// Mint the per-protocol server-side secrets a Server needs to
/// render configs (VLESS-REALITY keypair + short_id, WireGuard
/// server keypair, Hysteria2 obfs password). Idempotent: only mints
/// what's missing from `inv.list_server_secrets`, so re-running
/// against a partially-bootstrapped server picks up where the last
/// run left off.
///
/// Returns the full (existing + freshly minted) secret map plus a
/// list of human-readable "what we minted" labels the caller can
/// surface in progress logs / audit payload.
///
/// # Why a free function (not a `Protocol` trait method)
///
/// The orthogonal design would be `Protocol::mint_server_secrets(&inv,
/// &server) -> Vec<&'static str>` so adding a protocol with new
/// server-side secret keys requires zero changes here. That refactor
/// is queued (see PR-TODO: kernel-protocol orthogonality phase 2) —
/// it cascades through every protocol implementation in
/// `crates/protocols/`, and we'd rather ship the wizard now and do
/// the wider refactor in one focused PR. Until then, THIS is the
/// single place protocol→secret mapping lives, called from both
/// `wizard_bootstrap::bootstrap_pipeline` AND `server_deploy`
/// handler — adding a new protocol without server-side secrets
/// (e.g. Trojan, AnyTLS) needs zero changes here.
pub async fn bootstrap_server_secrets(
    inv: &SqliteInventory,
    server: &Server,
) -> std::result::Result<(std::collections::HashMap<String, String>, Vec<&'static str>), String> {
    let mut secrets = inv
        .list_server_secrets(&server.id)
        .await
        .map_err(|e| format!("list_server_secrets: {e}"))?;
    let mut minted: Vec<&'static str> = Vec::new();

    // VLESS-REALITY: x25519 keypair + 8-byte short_id. Bash
    // vpn-control bytes that exactly — same crypto primitives.
    let needs_reality = server
        .enabled_protocols
        .iter()
        .any(|p| p.0 == "vless+reality");
    if needs_reality
        && (!secrets.contains_key("vless.private_key")
            || !secrets.contains_key("vless.public_key")
            || !secrets.contains_key("vless.short_id"))
    {
        let (priv_key, pub_key) = vpnctl_crypto::gen_x25519_keypair();
        let short_id = vpnctl_crypto::gen_short_id().map_err(|e| format!("gen_short_id: {e}"))?;
        for (k, v) in [
            ("vless.private_key", &priv_key),
            ("vless.public_key", &pub_key),
            ("vless.short_id", &short_id),
        ] {
            inv.set_server_secret(&server.id, k, v)
                .await
                .map_err(|e| format!("set_server_secret {k}: {e}"))?;
            secrets.insert(k.to_string(), v.clone());
        }
        minted.push("vless+reality keypair + short_id");
    }

    // WireGuard: server-side Curve25519 keypair. The per-user pair
    // lives in the `users` table (`wireguard_pubkey`/`wireguard_private`)
    // — different bootstrap path, handled in user_create.
    let needs_wg = server.enabled_protocols.iter().any(|p| p.0 == "wireguard");
    if needs_wg
        && (!secrets.contains_key("wireguard.server_public_key")
            || !secrets.contains_key("wireguard.server_private_key"))
    {
        let (priv_key, pub_key) = vpnctl_crypto::gen_wireguard_keypair();
        for (k, v) in [
            ("wireguard.server_private_key", &priv_key),
            ("wireguard.server_public_key", &pub_key),
        ] {
            inv.set_server_secret(&server.id, k, v)
                .await
                .map_err(|e| format!("set_server_secret {k}: {e}"))?;
            secrets.insert(k.to_string(), v.clone());
        }
        minted.push("wireguard server keypair");
    }

    // Hysteria2: 24-byte salamander obfs password (matches bash
    // shape — 32 chars URL-safe base64).
    let needs_hy2 = server.enabled_protocols.iter().any(|p| p.0 == "hysteria2");
    if needs_hy2 && !secrets.contains_key("hysteria2.obfs.password") {
        let pw = vpnctl_crypto::gen_password(24).map_err(|e| format!("gen_password: {e}"))?;
        inv.set_server_secret(&server.id, "hysteria2.obfs.password", &pw)
            .await
            .map_err(|e| format!("set_server_secret hysteria2.obfs.password: {e}"))?;
        secrets.insert("hysteria2.obfs.password".into(), pw);
        minted.push("hysteria2 salamander obfs password");
    }

    Ok((secrets, minted))
}

/// Pick a free server id given the set of existing ids and a base
/// name derived from the operator's address input. Returns the base
/// unchanged if it's free; otherwise appends `-2`, `-3`, … until a
/// free slot is found. Bounded to avoid an infinite loop on a
/// pathological inventory.
///
/// Pure function with no I/O — testable in isolation; the SSE handler
/// fetches `inv.list_servers()` once and passes the id set in.
pub fn find_available_server_id(
    existing: &std::collections::HashSet<String>,
    base: &str,
) -> std::result::Result<String, String> {
    if !existing.contains(base) {
        return Ok(base.to_string());
    }
    for n in 2u32..=1000u32 {
        let candidate = format!("{base}-{n}");
        if !existing.contains(&candidate) {
            return Ok(candidate);
        }
    }
    Err(format!(
        "all id slots 2..1000 taken for base '{base}' — operator should delete stale servers first"
    ))
}

/// Replace any occurrence of `password` in the sshpass/ssh stderr
/// stream with a redaction placeholder, then trim. Defensive — the
/// stock OpenSSH client does NOT echo the password and sshpass
/// intercepts the prompt without echoing either, so this should
/// never fire in practice. If it ever does (LogLevel=DEBUG on a
/// nonstandard sshd config, future sshpass version change), the
/// password won't end up in the SSE stream visible to the browser DOM
/// or in the daemon's tracing log.
fn redact_password(stderr: &str, password: &str) -> String {
    let trimmed = stderr.trim();
    if password.is_empty() || !trimmed.contains(password) {
        return trimmed.to_string();
    }
    trimmed.replace(password, "<redacted>")
}

/// Derive a server id from an address. The wizard step-1 form
/// intentionally has no separate "id" field — operators shouldn't
/// have to name things (one-action ceiling). The id has to satisfy
/// the inventory's allowed alphabet (alphanumeric + `.` + `_` + `-`)
/// and the server-detail URL's path-encoding.
///
/// Strategy: replace `:` (IPv6 separator) with `-` so the result is
/// `[A-Za-z0-9.-]`. If the address is already alphanumeric+dots, it
/// passes through unchanged (so `198.51.100.42` stays
/// `198.51.100.42`). Caller is responsible for collision detection.
pub fn derive_server_id(address: &str) -> String {
    address
        .chars()
        .map(|c| if c == ':' { '-' } else { c })
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        .collect()
}

/// Run a remote command via `sshpass -e ssh` (password auth). Returns
/// the remote's stdout on success or a `String` error message on
/// any non-zero exit / spawn failure.
///
/// `BatchMode=no` is implicit (sshpass injects the password by
/// answering the prompt that BatchMode would otherwise suppress).
/// `accept-new` for first connect, after which the host key is pinned
/// in the daemon's known_hosts.
///
/// Password lives in the `SSHPASS` env var (sshpass's `-e` flag) so
/// it never appears in argv — `ps auxe` wouldn't expose it (only
/// `/proc/PID/environ`, which is root-only on Linux).
async fn ssh_password_run(
    host: &str,
    port: u16,
    user: &str,
    password: &str,
    known_hosts: &std::path::Path,
    remote_cmd: &str,
) -> std::result::Result<String, String> {
    let pw = password.to_string();
    let host = host.to_string();
    let user = user.to_string();
    let cmd_owned = remote_cmd.to_string();
    let port_s = port.to_string();
    let userhost = format!("{user}@{host}");

    // Build argv BEFORE moving into spawn_blocking — `ssh_safety_opts`
    // borrows `known_hosts: &Path` which is not `'static`, so the
    // safety-opts block must be materialised here (owned Strings) and
    // captured by move.
    let mut args: Vec<String> = vec![
        "-e".into(),
        "ssh".into(),
        "-o".into(),
        "PreferredAuthentications=password".into(),
        "-o".into(),
        "PubkeyAuthentication=no".into(),
    ];
    args.extend(ssh_safety_opts(known_hosts));
    args.push("-p".into());
    args.push(port_s);
    args.push(userhost);
    args.push(cmd_owned);

    let pw_for_redact = pw.clone();
    tokio::task::spawn_blocking(move || {
        let mut cmd = Command::new("sshpass");
        cmd.env("SSHPASS", &pw)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let output = cmd.output().map_err(|e| {
            format!("spawning sshpass: {e} (is sshpass installed on the daemon host?)")
        })?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // redact_password defends against the (theoretical) case
            // where ssh/sshpass echoes the password literal into
            // stderr — the SSE event payload is visible in the
            // operator's browser DOM, so anything that ends up here
            // ends up in JS land.
            return Err(format!(
                "sshpass exit={:?} stderr={}",
                output.status.code(),
                redact_password(&stderr, &pw_for_redact)
            ));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    })
    .await
    .map_err(|e| format!("spawn_blocking JoinError: {e}"))?
}

// ssh-keyscan/-keygen fingerprint fetching + ed25519 line picking +
// SHA256-token extraction live in `vpnctl-host-fingerprint`. The
// inline implementation that used to sit here was missing the `--`
// flag-injection defense that landed in the CLI + admin handler
// copies during review on commit `9819538` — the review-agent only
// sees the diff, so this third copy slipped through untouched.
// Crate is the single source of truth.

// `shell_single_quote` moved to `vpnctl_core::shell::single_quote`
// (2026-05-18). Was triplicated across this file (verbose char-by-
// char loop), `crates/ssh/src/russh_transport.rs::shell_quote`
// (terse `format!`-based copy) and `cli/src/cmd/bootstrap.rs::
// shell_single_quote` (also terse). All three produced identical
// observable output; consolidated for parity. Imported via
// `use vpnctl_core::shell::single_quote as shell_single_quote;`
// at the top of this file so existing call sites stay byte-identical.

// `path_segment_encode` moved to `crate::http_util::path_segment_encode`
// (2026-05-18). The previous «duplicated rather than `pub`-exposed
// because admin.rs's copy is `pub(crate)`» justification is no
// longer true — the shared copy in `http_util` is `pub` and the
// module is `pub mod http_util;` in `lib.rs`.

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // shell_single_quote tests moved with the implementation to
    // `crates/core/src/shell.rs::tests` — that module pins 8 cases
    // including `$HOME` literalness and multi-quote escape chains.

    // ssh-keyscan + parse_keygen_fingerprint + pick_keyscan_line tests
    // moved with the implementations to
    // `crates/host-fingerprint/tests/spec_host_fingerprint.rs` — that's
    // now the single source of truth for both behaviours.

    #[test]
    fn derive_server_id_keeps_ipv4_unchanged() {
        assert_eq!(derive_server_id("198.51.100.42"), "198.51.100.42");
    }

    #[test]
    fn derive_server_id_replaces_ipv6_colons() {
        assert_eq!(derive_server_id("2001:db8::1"), "2001-db8--1");
    }

    #[test]
    fn derive_server_id_filters_non_alphabet_chars() {
        // Whitespace and semicolons (shouldn't reach here — the
        // wizard validates upfront — but defensive) get stripped.
        assert_eq!(derive_server_id("foo bar; rm -rf"), "foobarrm-rf");
    }

    // path_segment_encode tests moved with the implementation to
    // `daemon/src/http_util.rs::path_segment_encode_tests` — that's
    // now the single source of truth.

    /// `BootstrapPlan` is the contract between handler and engine —
    /// the test confirms we can build one without any axum types in
    /// scope (which would couple the engine to the HTTP surface).
    #[test]
    fn bootstrap_plan_constructible_outside_handler() {
        let plan = BootstrapPlan {
            server_id: "vps-test".into(),
            address: "203.0.113.7".into(),
            ssh_port: 22,
            root_password: "redacted".into(),
            deploy_key_path: PathBuf::from("/tmp/k"),
            known_hosts_path: PathBuf::from("/tmp/kh"),
        };
        assert_eq!(plan.server_id, "vps-test");
        assert_eq!(plan.ssh_port, 22);
    }

    #[test]
    fn redact_password_replaces_substring_with_placeholder() {
        let stderr = "permission denied: password 'hunter2' rejected";
        assert_eq!(
            redact_password(stderr, "hunter2"),
            "permission denied: password '<redacted>' rejected"
        );
    }

    #[test]
    fn redact_password_passthrough_when_password_absent() {
        let stderr = "ssh: connect to host 198.51.100.1: connection refused";
        assert_eq!(
            redact_password(stderr, "secret"),
            "ssh: connect to host 198.51.100.1: connection refused"
        );
    }

    #[test]
    fn redact_password_handles_empty_password_safely() {
        // Empty password would otherwise match every char position
        // (`str::replace("", "<redacted>")` would explode). Guard
        // returns trimmed stderr unchanged.
        let stderr = "  hello world  ";
        assert_eq!(redact_password(stderr, ""), "hello world");
    }

    #[test]
    fn find_available_server_id_returns_base_when_free() {
        let existing = std::collections::HashSet::new();
        assert_eq!(
            find_available_server_id(&existing, "198.51.100.1").unwrap(),
            "198.51.100.1"
        );
    }

    #[test]
    fn find_available_server_id_suffixes_2_on_first_collision() {
        let mut existing = std::collections::HashSet::new();
        existing.insert("198.51.100.1".into());
        assert_eq!(
            find_available_server_id(&existing, "198.51.100.1").unwrap(),
            "198.51.100.1-2"
        );
    }

    #[test]
    fn find_available_server_id_walks_through_taken_suffixes() {
        let mut existing = std::collections::HashSet::new();
        existing.insert("a".into());
        existing.insert("a-2".into());
        existing.insert("a-3".into());
        existing.insert("a-4".into());
        assert_eq!(find_available_server_id(&existing, "a").unwrap(), "a-5");
    }

    /// `bootstrap_server_secrets` is now the single source of truth
    /// for server-side per-protocol secret minting (shared between
    /// the wizard and `server_deploy`). Spec it against an in-memory
    /// inventory: mint once → 3 vless keys + 1 hy2 password; mint
    /// again → no churn (idempotent).
    #[tokio::test]
    async fn bootstrap_secrets_mints_then_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("inv.db");
        let inv = vpnctl_inventory::SqliteInventory::open(&db).await.unwrap();
        let server = Server {
            id: ServerId("test-server".into()),
            address: "203.0.113.7".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![
                ProtocolId("vless+reality".into()),
                ProtocolId("hysteria2".into()),
            ],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        };
        inv.add_server(&server).await.unwrap();

        let (secrets1, minted1) = bootstrap_server_secrets(&inv, &server).await.unwrap();
        assert!(secrets1.contains_key("vless.private_key"));
        assert!(secrets1.contains_key("vless.public_key"));
        assert!(secrets1.contains_key("vless.short_id"));
        assert!(secrets1.contains_key("hysteria2.obfs.password"));
        assert!(!secrets1.contains_key("wireguard.server_public_key"));
        assert_eq!(minted1.len(), 2, "expected 2 mint labels, got {minted1:?}");

        // Second call — nothing new to mint.
        let (secrets2, minted2) = bootstrap_server_secrets(&inv, &server).await.unwrap();
        assert_eq!(secrets1, secrets2);
        assert!(
            minted2.is_empty(),
            "second call must mint nothing; got {minted2:?}"
        );
    }

    #[test]
    fn find_available_server_id_errors_when_1000_taken() {
        // Pathological — operator has registered 'a', 'a-2', …,
        // 'a-1000'. Refusing avoids an infinite loop on a corrupt
        // inventory. The error message points the operator at the
        // recovery path.
        let mut existing = std::collections::HashSet::new();
        existing.insert("a".into());
        for n in 2u32..=1000u32 {
            existing.insert(format!("a-{n}"));
        }
        assert!(find_available_server_id(&existing, "a").is_err());
    }

    /// JSON shape pinned — the SSE handler serialises events to JSON
    /// in each Event's `data:` payload, and the browser parses them
    /// with a `tag: "kind"` discriminator. If we ever rename `kind`
    /// the front-end breaks silently — this test surfaces the rename.
    #[test]
    fn bootstrap_event_serialises_with_kind_tag() {
        let step = BootstrapEvent::Step {
            phase: "probe",
            message: "ssh root@…".into(),
        };
        let json = serde_json::to_string(&step).unwrap();
        assert!(json.contains("\"kind\":\"step\""), "got: {json}");
        assert!(json.contains("\"phase\":\"probe\""), "got: {json}");

        let ok = BootstrapEvent::Ok {
            server_id: "vps-1".into(),
            redirect: "/admin/servers/vps-1".into(),
        };
        let json_ok = serde_json::to_string(&ok).unwrap();
        assert!(json_ok.contains("\"kind\":\"ok\""), "got: {json_ok}");
        assert!(json_ok.contains("\"redirect\""), "got: {json_ok}");

        let err = BootstrapEvent::Error {
            phase: "probe",
            message: "permission denied".into(),
        };
        let json_err = serde_json::to_string(&err).unwrap();
        assert!(json_err.contains("\"kind\":\"error\""), "got: {json_err}");
    }
}
