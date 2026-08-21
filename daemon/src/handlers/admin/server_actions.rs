//! Server action admin handlers: the write side of the servers surface —
//! traffic limits, protocol/kernel enable-disable, grants (single + bulk),
//! deploy, quick-add, delete, deploy-key push, the per-server config
//! setters and protocol hide/unhide. The read-only server list lives in
//! `servers.rs`. Extracted from `legacy.rs` as part of the admin
//! submodules refactor.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use maud::{Markup, html};

use super::helpers::{
    bad_request, error_resp, internal_error, not_found, render_page, theme_accent_lang,
    user_not_found, valid_server_id,
};
use super::legacy::spawn_user_servers_redeploy;
use crate::AppState;
use crate::http_util::{form_field, path_segment_encode};

/// `POST /admin/servers/{id}/protocols/{proto}/enable` — add a
/// protocol to a server's `enabled_protocols`. Idempotent at SQL.
/// Returns 404 if server doesn't exist, 400 if protocol id isn't
/// registered with the daemon (no point persisting a string that
/// nothing knows how to render). Audit row written. Always
/// redirects back to the server-detail page.
pub(crate) async fn server_enable_protocol(
    State(state): State<AppState>,
    Path((server_id_str, protocol_id_str)): Path<(String, String)>,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id_str.clone());
    let pid = vpnctl_core::ProtocolId(protocol_id_str.clone());

    // Existence check (404 if no server).
    let server = match state.inv.get_server(&sid).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return not_found(&format!("no such server '{server_id_str}'"));
        }
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    // Reject unregistered protocol id — persisting a typo would
    // silently no-op every render+deploy from now on.
    if state.registry.protocol(&pid).is_none() {
        let known: Vec<String> = state
            .registry
            .protocol_ids()
            .into_iter()
            .map(|p| p.0)
            .collect();
        return bad_request(&format!(
            "unknown protocol '{protocol_id_str}' — registered: {}",
            known.join(", ")
        ));
    }

    let inserted = match state.inv.add_server_protocol(&sid, &pid).await {
        Ok(n) => n,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };

    // NM-10 contract (audit 2026-06-10): a no-op re-POST (inserted == 0)
    // writes NO audit row — unconditional writes polluted the timeline
    // and the `newly_added` flag inside is honest-but-buried.
    if inserted == 1 {
        if let Err(e) = state
            .inv
            .audit(
                "admin",
                "server.protocol.enable",
                Some(&server_id_str),
                Some(&serde_json::json!({
                    "protocol": protocol_id_str,
                    "newly_added": inserted == 1,
                })),
            )
            .await
        {
            tracing::warn!(
                target = "vpnctld::admin",
                server = %server_id_str,
                error = %e,
                "audit write failed for server.protocol.enable"
            );
        }
        // Auto-deploy — the protocol change must land on the node;
        // without this the rendered config diverges from inventory.
        spawn_user_servers_redeploy(
            &state,
            vec![server],
            server_id_str.clone(),
            "server.protocol.enable",
        );
    }

    Redirect::to(&format!(
        "/admin/servers/{}/protocols#enabled-protocols",
        path_segment_encode(&server_id_str)
    ))
    .into_response()
}

/// `POST /admin/servers/{id}/protocols/{proto}/disable` — remove a
/// protocol from a server's `enabled_protocols`. Idempotent. Same
/// 404/audit/redirect posture as `server_enable_protocol`.
pub(crate) async fn server_disable_protocol(
    State(state): State<AppState>,
    Path((server_id_str, protocol_id_str)): Path<(String, String)>,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id_str.clone());
    let pid = vpnctl_core::ProtocolId(protocol_id_str.clone());

    let server = match state.inv.get_server(&sid).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return not_found(&format!("no such server '{server_id_str}'"));
        }
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };

    let removed = match state.inv.remove_server_protocol(&sid, &pid).await {
        Ok(n) => n,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };

    // NM-10 contract (audit 2026-06-10): a no-op re-POST (removed == 0)
    // writes NO audit row — unconditional writes polluted the timeline
    // and the `was_present` flag inside is honest-but-buried.
    if removed == 1 {
        if let Err(e) = state
            .inv
            .audit(
                "admin",
                "server.protocol.disable",
                Some(&server_id_str),
                Some(&serde_json::json!({
                    "protocol": protocol_id_str,
                    "was_present": removed == 1,
                })),
            )
            .await
        {
            tracing::warn!(
                target = "vpnctld::admin",
                server = %server_id_str,
                error = %e,
                "audit write failed for server.protocol.disable"
            );
        }
        spawn_user_servers_redeploy(
            &state,
            vec![server],
            server_id_str.clone(),
            "server.protocol.disable",
        );
    }

    Redirect::to(&format!(
        "/admin/servers/{}/protocols#enabled-protocols",
        path_segment_encode(&server_id_str)
    ))
    .into_response()
}

/// `POST /admin/servers/{sid}/grants/{uid}` — grant the user access
/// from the SERVER side. Identical mutation to `user_grant_server`
/// (same `inv.grant` call), but the redirect target is the SERVER
/// detail page so the operator stays where they started. Mirror
/// pair: `server_revoke_user`.
pub(crate) async fn server_grant_user(
    State(state): State<AppState>,
    Path((server_id_str, user_id_str)): Path<(String, String)>,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id_str.clone());
    let uid = vpnctl_core::UserId(user_id_str.clone());
    // Existence checks — explicit 404 for both, otherwise the FK
    // violation surfaces as a generic 500.
    let server = match state.inv.get_server(&sid).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return not_found(&format!("no such server '{server_id_str}'"));
        }
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    match state.inv.get_user(&uid).await {
        Ok(Some(_)) => {}
        Ok(None) => return user_not_found(&user_id_str),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }

    // Membership BEFORE the grant — the audit row is written only for
    // a NEW grant. An idempotent re-grant must NOT add a fresh
    // `user.grant` row: it would falsely re-mark the server
    // pending-deploy until a no-op redeploy (review-agent important;
    // matches the bulk path's skip-already-granted semantics).
    let was_granted = match state.inv.servers_for_user(&uid).await {
        Ok(v) => v.iter().any(|s| s.id == sid),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    if let Err(e) = state.inv.grant(&uid, &sid).await {
        return internal_error(anyhow::Error::new(e));
    }
    // Canonical grant-audit shape (2026-06-04 unification): per-user
    // `user.grant` row with target = USER id. The pending-deploy
    // detector keys on exactly this; the previous `action="grant",
    // target=<server>` row was invisible to it, so a grant made from
    // the server-detail page never raised the «config not yet
    // deployed» banner once the server had its first deploy baseline.
    if !was_granted {
        if let Err(e) = state
            .inv
            .audit(
                "admin",
                "user.grant",
                Some(&user_id_str),
                Some(&serde_json::json!({
                    "server": server_id_str,
                    "source": "server-detail",
                })),
            )
            .await
        {
            tracing::warn!(target = "vpnctld::admin", error = %e, "audit write failed for user.grant");
        }
        // Auto-deploy — same contract as `user_grant_server` (HANDOFF
        // §4.1); the mutation is identical, only the redirect differs.
        spawn_user_servers_redeploy(&state, vec![server], user_id_str.clone(), "user.grant");
    }
    Redirect::to(&format!(
        "/admin/servers/{}/grants",
        path_segment_encode(&server_id_str)
    ))
    .into_response()
}

/// `POST /admin/servers/{sid}/grants` — the v2 3d grant bar: user id
/// arrives as a form field instead of a path segment. Validates the
/// field then delegates to [`server_grant_user`] (extractors are just
/// values) so the mutation, audit shape and auto-deploy stay single-
/// sourced.
pub(crate) async fn server_grant_user_form(
    State(state): State<AppState>,
    Path(server_id_str): Path<String>,
    body: String,
) -> Response {
    let Some(user_id) = crate::http_util::form_field(&body, "user_id") else {
        return bad_request("missing form field 'user_id'");
    };
    let user_id = user_id.trim().to_string();
    if user_id.is_empty() {
        return bad_request("empty 'user_id'");
    }
    server_grant_user(State(state), Path((server_id_str, user_id))).await
}

/// `POST /admin/servers/{sid}/grants/{uid}/revoke` — revoke from the
/// SERVER side. Mirror of `server_grant_user`.
pub(crate) async fn server_revoke_user(
    State(state): State<AppState>,
    Path((server_id_str, user_id_str)): Path<(String, String)>,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id_str.clone());
    let uid = vpnctl_core::UserId(user_id_str.clone());
    let server = match state.inv.get_server(&sid).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return not_found(&format!("no such server '{server_id_str}'"));
        }
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    // User-existence check — the grant twin always had it; without it
    // an unknown user 200-redirected as if revoked (audit 2026-06-10).
    match state.inv.get_user(&uid).await {
        Ok(Some(_)) => {}
        Ok(None) => return user_not_found(&user_id_str),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }
    // Membership BEFORE the revoke — the audit row is written only for
    // an ACTUAL revoke (mirror of the grant paths' 2026-06-04 shape).
    let was_granted = match state.inv.servers_for_user(&uid).await {
        Ok(v) => v.iter().any(|s| s.id == sid),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    if let Err(e) = state.inv.revoke(&uid, &sid).await {
        return internal_error(anyhow::Error::new(e));
    }
    // Canonical per-user `user.revoke` (target = USER id) — the
    // pending-deploy detector keys on per-user mutation rows; the old
    // `action="revoke", target=<server>` row was invisible to it, so a
    // revoked UUID stayed live on the node with no warning anywhere.
    if was_granted {
        if let Err(e) = state
            .inv
            .audit(
                "admin",
                "user.revoke",
                Some(&user_id_str),
                Some(&serde_json::json!({
                    "server": server_id_str,
                    "source": "server-detail",
                })),
            )
            .await
        {
            tracing::warn!(target = "vpnctld::admin", error = %e, "audit write failed for user.revoke");
        }
        // Auto-deploy — mirror of `user_revoke_server`.
        spawn_user_servers_redeploy(&state, vec![server], user_id_str.clone(), "user.revoke");
    }
    Redirect::to(&format!(
        "/admin/servers/{}/grants",
        path_segment_encode(&server_id_str)
    ))
    .into_response()
}

/// `POST /admin/servers/{id}/deploy` — the operator-facing deploy
/// button. Per CLAUDE.md "Web is the ONLY operator surface; CLI is
/// implementation detail" — Pavel must never have to open a terminal
/// to deploy a server.
///
/// **What this does TODAY (no SSH dep in production binary):**
///   * Bootstrap every missing server-secret the inventory needs to
///     render configs: REALITY keypair + short_id (for vless+reality),
///     WireGuard server keypair (for wireguard), Hysteria2 obfs
///     password (for hysteria2 + salamander). All mints happen
///     server-side via vpnctl_crypto — no SSH.
///   * Persist each new secret with audit_log row.
///   * Render kernel configs for the operator's pre-flight review
///     (writes nothing to the node — just confirms the render
///     succeeds with the now-complete secret set).
///
/// **What still needs an SSH push to the node** (post-musl-build
/// roadmap — tracked as TODO `web-deploy-apply`):
///   * `ensure_installed` (apt install sing-box / amneziawg-tools)
///   * `apply_config` (scp render output + systemctl restart)
///
/// Until the daemon ships with a working SSH path (musl static
/// binary OR glibc upgrade on the host), the install/apply steps
/// remain a one-time per-node CLI action — but the button still
/// solves the per-click pain (no operator-typed keypair generation).
///
/// Returns 303 to /admin/servers/{id} after success so the operator
/// sees the now-populated `secret_keys` block + any newly-enabled
/// share-links in the user-detail Flow B section.
pub(crate) async fn server_deploy(
    State(state): State<AppState>,
    Path(server_id_str): Path<String>,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id_str.clone());

    let server = match state.inv.get_server(&sid).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return not_found(&format!("no such server '{server_id_str}'"));
        }
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };

    // Pre-flight: validate kernel/protocol compatibility via the
    // registry. If a protocol declared on this server can't be
    // rendered by any of its kernels, every bootstrap step below
    // would still succeed but the render would later fail with a
    // confusing "unsupported protocol" — surface that upfront.
    // Secrets are loaded first so the port-conflict guard honours
    // per-server overrides (vless.listen_port).
    let pre_secrets = match state.inv.list_server_secrets(&sid).await {
        Ok(s) => s,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    if let Err(e) = state.registry.validate_server(&server, &pre_secrets) {
        return bad_request(&format!("config invalid before deploy: {e}"));
    }

    // Concurrency gate: refuse a second node-touching deploy of THIS
    // server while one is already in flight (another tab, a curl, the
    // SSE deploy / deploy-all path). Without it two pipelines render +
    // restart the same sing-box at once. The permit is released when
    // this handler returns (RAII) — including every early-return error
    // path below.
    let _deploy_guard = match crate::wizard_bootstrap::DeployGuard::try_acquire(&server.id.0) {
        Some(g) => g,
        None => {
            return error_resp(
                StatusCode::CONFLICT,
                &format!(
                    "deploy already running for server '{}' — wait for it to finish, then retry",
                    server.id.0
                ),
            );
        }
    };

    // Bootstrap missing secrets. Shared with the Phase-E wizard
    // via `wizard_bootstrap::bootstrap_server_secrets` so any new
    // server-side secret added for a future protocol is minted
    // identically by deploy + wizard. Idempotent — re-clicking
    // deploy when everything is already minted is a safe no-op.
    let (_, bootstrapped) = match crate::wizard_bootstrap::bootstrap_server_secrets(
        &state.inv,
        &server,
        &state.registry,
    )
    .await
    {
        Ok(v) => v,
        Err(e) => return internal_error(anyhow::anyhow!(e)),
    };
    let deploy_revision = match state.inv.deploy_input_revision(&sid).await {
        Ok(revision) => revision,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    let server = match state.inv.get_server(&sid).await {
        Ok(Some(server)) => server,
        Ok(None) => return not_found(&format!("no such server '{server_id_str}'")),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    let secrets = match state.inv.list_server_secrets(&sid).await {
        Ok(secrets) => secrets,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    if let Err(e) = state.registry.validate_server(&server, &secrets) {
        return bad_request(&format!("config changed before deploy: {e}"));
    }

    // SSH push to the node — Path C via SubprocessSshTransport.
    // For each declared kernel: ensure_installed → render config
    // (only protocols this kernel can run) → apply_config.
    //
    // Per-kernel + per-step errors are isolated to the offending
    // kernel: a failed amneziawg install does NOT prevent the
    // sing-box restart. Aggregate result is captured in the audit
    // payload (`ssh_kernels_pushed`, `ssh_errors`).
    use crate::ssh_subprocess::SubprocessSshTransport;
    let key_path = std::path::PathBuf::from(crate::app::DEFAULT_DEPLOY_KEY_PATH);
    let mut ssh_kernels_pushed: Vec<String> = Vec::new();
    let mut ssh_errors: Vec<String> = Vec::new();
    let mut total_config_bytes: usize = 0;
    let mut configs_applied: usize = 0;
    let ssh_skip_reason: Option<&'static str> = if !key_path.exists() {
        Some(crate::wizard_bootstrap::DEPLOY_KEY_ABSENT_MSG)
    } else if server.kernels.is_empty() {
        Some("server has no kernels declared")
    } else {
        None
    };
    if ssh_skip_reason.is_none() {
        let ssh =
            SubprocessSshTransport::new(server.address.clone(), server.ssh_user.clone(), key_path)
                .port(server.ssh_port);

        // Pre-load users + render context once; reused for every
        // kernel's render call.
        let users = match state.inv.users_for_server(&sid).await {
            Ok(u) => u,
            Err(e) => return internal_error(anyhow::Error::new(e)),
        };
        if let Err(e) = state.inv.assert_no_uuid_collisions(&sid).await {
            return internal_error(anyhow::Error::new(e));
        }
        if state
            .inv
            .deploy_input_revision(&sid)
            .await
            .map_or(true, |current| current != deploy_revision)
        {
            return error_resp(
                StatusCode::CONFLICT,
                "inventory changed while preparing deploy — retry",
            );
        }
        let ctx = vpnctl_core::RenderCtx::new(&server, &secrets);

        for kid in &server.kernels {
            let Some(kernel) = state.registry.kernel(kid) else {
                ssh_errors.push(format!("{}: kernel not registered", kid.0));
                continue;
            };
            if let Err(e) = kernel.ensure_installed(&ssh).await {
                ssh_errors.push(format!("{}: ensure_installed failed: {e}", kid.0));
                continue;
            }
            let supported = kernel.supported_protocols();
            let protocols: Vec<&dyn vpnctl_core::Protocol> = server
                .enabled_protocols
                .iter()
                .filter(|p| supported.contains(p))
                .filter_map(|p| state.registry.protocol(p))
                .collect();
            if protocols.is_empty() {
                // Kernel installed but no protocols for it — still
                // a valid step (e.g. preparing a node for future
                // protocols). Skip render+apply, report neutral.
                ssh_kernels_pushed.push(format!("{} (installed, no protocols)", kid.0));
                continue;
            }
            let config = match kernel.render_config(&ctx, &users, &protocols) {
                Ok(c) => c,
                Err(e) => {
                    ssh_errors.push(format!("{}: render failed: {e}", kid.0));
                    continue;
                }
            };
            // Reserved-ports pre-apply guard (post-2026-05-26).
            // Refuses configs that would bind a co-tenant's port.
            if kid.0 == "sing-box" {
                match state.inv.get_reserved_ports(&server.id).await {
                    Ok(reserved) => {
                        if let Err(e) =
                            vpnctl_kernels::validate_config_excludes_ports(&config, &reserved)
                        {
                            ssh_errors
                                .push(format!("{}: reserved-ports guard refused: {e}", kid.0));
                            continue;
                        }
                    }
                    Err(e) => {
                        ssh_errors.push(format!("{}: reserved-ports lookup failed: {e}", kid.0));
                        continue;
                    }
                }
            }
            total_config_bytes += config.len();
            if let Err(e) = kernel.apply_config(&ssh, &config).await {
                ssh_errors.push(format!("{}: apply_config failed: {e}", kid.0));
                continue;
            }
            ssh_kernels_pushed.push(kid.0.clone());
            configs_applied += 1;
            // Best-effort firewall open (Kernel::open_firewall) — a fresh
            // deploy must be reachable without a manual `ufw allow`; non-fatal
            // (the config is already applied).
            if let Err(e) = kernel.open_firewall(&ssh, &ctx, &protocols).await {
                tracing::warn!(target = "vpnctld::deploy", kernel = %kid.0, error = %e, "open_firewall skipped (best-effort)");
            }
        }
    }

    let mut audit_action = crate::wizard_bootstrap::deploy_audit_action(
        &ssh_errors,
        configs_applied,
        ssh_skip_reason,
        false,
    );
    let payload = serde_json::json!({
        "bootstrapped": bootstrapped,
        "kernels": server.kernels.iter().map(|k| &k.0).collect::<Vec<_>>(),
        "protocols": server.enabled_protocols.iter().map(|p| &p.0).collect::<Vec<_>>(),
        "ssh_skip_reason": ssh_skip_reason,
        "ssh_kernels_pushed": ssh_kernels_pushed,
        "ssh_errors": ssh_errors,
        "ssh_config_bytes_total": total_config_bytes,
        "configs_applied": configs_applied,
        "inputs_changed": false,
    });
    let audit_result = if audit_action == "server.deploy" {
        state
            .inv
            .audit_deploy_if_revision("admin", &sid, &deploy_revision, &payload)
            .await
            .map(|matches| {
                if !matches {
                    audit_action = "server.deploy.stale";
                }
            })
    } else {
        state
            .inv
            .audit("admin", audit_action, Some(&server_id_str), Some(&payload))
            .await
    };
    if let Err(e) = audit_result {
        audit_action = "server.deploy.failed";
        tracing::warn!(
            target = "vpnctld::admin",
            server = %server_id_str,
            action = audit_action,
            error = %e,
            "audit write failed for deploy attempt"
        );
    }

    if audit_action != "server.deploy" {
        let message = if let Some(reason) = ssh_skip_reason {
            format!("deploy skipped — {reason}")
        } else if !ssh_errors.is_empty() {
            format!("deploy failed: {}", ssh_errors.join("; "))
        } else if audit_action == "server.deploy.stale" {
            "inventory changed during deploy; the server remains pending — deploy again".to_string()
        } else {
            "deploy skipped — no kernel config was applied".to_string()
        };
        return error_resp(StatusCode::BAD_GATEWAY, &message);
    }

    Redirect::to(&format!(
        "/admin/servers/{}",
        path_segment_encode(&server_id_str)
    ))
    .into_response()
}

/// `POST /admin/servers/quick-add` — register a SERVER YOU ALREADY HAVE
/// in inventory with minimal input: id + address (+ optional ssh_port).
/// Default kernel = sing-box; default protocols = every protocol
/// sing-box supports. Operator tweaks on the detail page right after.
///
/// This is the inline path on `/admin/servers`. The fancy Phase-E
/// SSE-streamed bootstrap wizard at `/admin/servers/new` is a
/// DIFFERENT flow (it ssh-pushes our key and installs the kernel from
/// scratch — only useful for fresh nodes).
pub(crate) async fn server_quick_add(State(state): State<AppState>, body: String) -> Response {
    // Tiny form parser via the shared `form_field` helper. Note:
    // `form_field` decodes BEFORE trim (whereas the legacy inline
    // pattern trimmed BEFORE decode); strictly stricter — `%20`-
    // encoded whitespace at the edges is now normalised the same as
    // literal whitespace, so a paste like `"  vps-de1  "` and
    // `"%20vps-de1%20"` both produce `"vps-de1"`.
    let id: String = form_field(&body, "id")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    if !valid_server_id(&id) {
        // Dedicated server-id validator (review 2026-06-04): the user-id
        // validator (2..=32 lowercase) used to gate this while the error
        // text promised 1-64 mixed-case — now the message matches the
        // enforced policy exactly.
        return bad_request(&format!(
            "invalid server id '{id}' (allowed: 1-64 chars of A-Z a-z 0-9 . _ -)"
        ));
    }

    let address_raw: String = form_field(&body, "address")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    // Route through the wizard's strict validator (charset
    // `[A-Za-z0-9.:_-]`, length ≤ 255). The old quick-add gate
    // only rejected ASCII space + length > 253, letting `\n`, `\r`,
    // `\t`, and most control bytes through into `Server.address`
    // (where they could later land in log lines / audit payloads as
    // broken multi-line records). Security audit 2026-05-18 finding.
    let address = match crate::wizard::validate_address(&address_raw) {
        Ok(s) => s.to_string(),
        Err(why) => {
            return bad_request(&format!("invalid address: {why}"));
        }
    };

    // Duplicate-address guard (HANDOFF §6 #2): refuse a second inventory
    // record for a box that's already registered. Two records for one node
    // fight over its `users[]`; the second deploy trips the DG-1
    // user-removal guard (the `us` / `us1` incident, 2026-07-08). Report the
    // clashing id so the operator edits that server instead of duplicating.
    match state.inv.server_id_for_address(&address).await {
        Ok(Some(existing)) => {
            return bad_request(&format!(
                "address '{address}' is already registered to server '{existing}' — one node = one server record; edit '{existing}' instead of adding a duplicate"
            ));
        }
        Ok(None) => {}
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }

    let ssh_port: u16 = form_field(&body, "ssh_port")
        .and_then(|s| s.parse().ok())
        .unwrap_or(22);

    // Default kernel = sing-box; protocols = ALL it supports. This
    // mirrors the "users are low-tech" one-action ceiling for the
    // operator: register the server, then enable/disable on the
    // detail page (a single click each).
    use vpnctl_core::{KernelId, ProtocolId, Server, ServerId};
    let kernel_id = KernelId("sing-box".into());
    let default_protocols: Vec<ProtocolId> = state
        .registry
        .kernel(&kernel_id)
        .map(|k| k.supported_protocols())
        .unwrap_or_default();

    let server = Server {
        id: ServerId(id.clone()),
        address: address.clone(),
        ssh_port,
        ssh_user: "root".into(),
        kernels: vec![kernel_id],
        enabled_protocols: default_protocols.clone(),
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    };

    if let Err(e) = state.inv.add_server(&server).await {
        return match e {
            vpnctl_inventory::SqliteInventoryError::AlreadyExists(what) => {
                bad_request(&format!("{what} already exists — pick a different id"))
            }
            other => internal_error(anyhow::Error::new(other)),
        };
    }

    if let Err(e) = state
        .inv
        .audit(
            "admin",
            // dot+underscore per naming convention (was the hyphenated
            // `server.quick-add`). Convention-only: the action_kind
            // chip maps the last dot-segment and `quick_add` still
            // lands on «other» — the win is consistent `server.`-prefix
            // filtering and one fewer odd-man-out name.
            "server.quick_add",
            Some(&id),
            Some(&serde_json::json!({
                "address": address,
                "ssh_port": ssh_port,
                "kernels": ["sing-box"],
                "protocols": default_protocols.iter().map(|p| &p.0).collect::<Vec<_>>(),
            })),
        )
        .await
    {
        tracing::warn!(
            target = "vpnctld::admin",
            server = %id,
            error = %e,
            "audit write failed for server.quick_add"
        );
    }

    Redirect::to(&format!("/admin/servers/{}", path_segment_encode(&id))).into_response()
}

/// `POST /admin/servers/{id}/kernels/{kernel}/enable` — add a kernel
/// to a server's runtime set. Mirrors `server_enable_protocol`.
pub(crate) async fn server_enable_kernel(
    State(state): State<AppState>,
    Path((server_id_str, kernel_id_str)): Path<(String, String)>,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id_str.clone());
    let kid = vpnctl_core::KernelId(kernel_id_str.clone());

    let server = match state.inv.get_server(&sid).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return not_found(&format!("no such server '{server_id_str}'"));
        }
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    // Reject unregistered kernel id — same posture as
    // server_enable_protocol: persisting a typo would silently no-op
    // every deploy.
    if state.registry.kernel(&kid).is_none() {
        let known: Vec<String> = state
            .registry
            .kernel_ids()
            .into_iter()
            .map(|k| k.0)
            .collect();
        return bad_request(&format!(
            "unknown kernel '{kernel_id_str}' — registered: {}",
            known.join(", ")
        ));
    }

    let inserted = match state.inv.add_server_kernel(&sid, &kid).await {
        Ok(n) => n,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };

    // NM-10 contract (audit 2026-06-10): a no-op re-POST (inserted == 0)
    // writes NO audit row — unconditional writes polluted the timeline
    // and the `newly_added` flag inside is honest-but-buried.
    if inserted == 1 {
        if let Err(e) = state
            .inv
            .audit(
                "admin",
                "server.kernel.enable",
                Some(&server_id_str),
                Some(&serde_json::json!({
                    "kernel": kernel_id_str,
                    "newly_added": inserted == 1,
                })),
            )
            .await
        {
            tracing::warn!(
                target = "vpnctld::admin",
                server = %server_id_str,
                error = %e,
                "audit write failed for server.kernel.enable"
            );
        }
        spawn_user_servers_redeploy(
            &state,
            vec![server],
            server_id_str.clone(),
            "server.kernel.enable",
        );
    }

    Redirect::to(&format!(
        "/admin/servers/{}/protocols",
        path_segment_encode(&server_id_str)
    ))
    .into_response()
}

/// `POST /admin/servers/{id}/kernels/{kernel}/disable` — remove a
/// kernel. Mirrors `server_disable_protocol`.
pub(crate) async fn server_disable_kernel(
    State(state): State<AppState>,
    Path((server_id_str, kernel_id_str)): Path<(String, String)>,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id_str.clone());
    let kid = vpnctl_core::KernelId(kernel_id_str.clone());

    let server = match state.inv.get_server(&sid).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return not_found(&format!("no such server '{server_id_str}'"));
        }
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };

    let removed = match state.inv.remove_server_kernel(&sid, &kid).await {
        Ok(n) => n,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };

    // NM-10 contract (audit 2026-06-10): a no-op re-POST (removed == 0)
    // writes NO audit row — unconditional writes polluted the timeline
    // and the `was_present` flag inside is honest-but-buried.
    if removed == 1 {
        if let Err(e) = state
            .inv
            .audit(
                "admin",
                "server.kernel.disable",
                Some(&server_id_str),
                Some(&serde_json::json!({
                    "kernel": kernel_id_str,
                    "was_present": removed == 1,
                })),
            )
            .await
        {
            tracing::warn!(
                target = "vpnctld::admin",
                server = %server_id_str,
                error = %e,
                "audit write failed for server.kernel.disable"
            );
        }
        spawn_user_servers_redeploy(
            &state,
            vec![server],
            server_id_str.clone(),
            "server.kernel.disable",
        );
    }

    Redirect::to(&format!(
        "/admin/servers/{}/protocols",
        path_segment_encode(&server_id_str)
    ))
    .into_response()
}

/// `POST /admin/servers/{id}/grants/_grant-all` (B2, audit 2026-05-22,
/// shipped 2026-05-23) — grant access to **every existing user** on
/// this server. Common after deploying a new server: instead of
/// clicking «grant» for each user, click one button. Per-user grant
/// is idempotent at the SQL layer (`ON CONFLICT DO NOTHING`), so
/// re-running this on a fully-granted server is a no-op.
///
/// Audit shape (2026-06-04 unification): ONE summary row
/// (`server.grants.bulk_grant` with `{granted, already_granted,
/// failed, total_users}`) **plus a per-user `user.grant` row
/// (target = user id) for each NEWLY-granted user**. The per-user
/// rows are what the pending-deploy detector
/// (`servers_pending_deploy_for_user`) keys on — without them a
/// bulk grant after the server's first deploy never raised the
/// «config not yet deployed» banner. Timeline flood stays bounded:
/// re-running on a fully-granted server grants 0 → writes 0
/// per-user rows (idempotent), so only the first click of the «50
/// users» case pays the N rows — and those N are exactly the N
/// real mutations. Per-user grant failures (rare — inventory-layer
/// DB error) are counted in `failed` and logged at warn but DO NOT
/// abort the batch — partial success is operator-recoverable via
/// the per-row UI.
///
/// No confirm gate (safe + reversible — operator can revoke
/// per-user OR use the bulk revoke flow).
pub(crate) async fn server_grant_all_users(
    State(state): State<AppState>,
    Path(server_id_str): Path<String>,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id_str.clone());
    // 3-arm match (audit 2026-06-10): the old `if let Ok(None)` SWALLOWED
    // the DB-error arm and fell through as if the server existed.
    let server = match state.inv.get_server(&sid).await {
        Ok(Some(s)) => s,
        Ok(None) => return not_found(&format!("no such server '{server_id_str}'")),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    let users = match state.inv.list_users().await {
        Ok(u) => u,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    let already_granted: std::collections::HashSet<vpnctl_core::UserId> =
        match state.inv.users_for_server(&sid).await {
            Ok(v) => v.into_iter().map(|u| u.id).collect(),
            Err(e) => return internal_error(anyhow::Error::new(e)),
        };
    let mut granted: u32 = 0;
    let mut already: u32 = 0;
    let mut failed: u32 = 0;
    let mut skipped_disabled: u32 = 0;
    for u in &users {
        // Don't bulk-grant to soft-paused users (B1.user, audit
        // finding 2026-05-23). The grant would be functionally
        // harmless — disabled users' /sub renders an empty
        // config regardless — but silently un-paused-by-side-
        // effect violates the operator's «paused means out of
        // sight» mental model. Disabled users get caught here +
        // counted; operator can grant them individually after
        // enabling. Symmetric handling on revoke-all isn't
        // needed (revoking a disabled user is consistent with
        // them already being out-of-rotation).
        if u.disabled {
            skipped_disabled += 1;
            continue;
        }
        if already_granted.contains(&u.id) {
            already += 1;
            continue;
        }
        match state.inv.grant(&u.id, &sid).await {
            Ok(()) => {
                granted += 1;
                // Per-user `user.grant` row for each ACTUAL new grant —
                // the canonical shape the pending-deploy detector keys
                // on (see the handler doc-comment). Audit failure is
                // non-fatal: the grant is already committed.
                if let Err(e) = state
                    .inv
                    .audit(
                        "admin",
                        "user.grant",
                        Some(&u.id.0),
                        Some(&serde_json::json!({
                            "server": server_id_str,
                            "source": "server-detail.bulk",
                        })),
                    )
                    .await
                {
                    tracing::warn!(
                        target = "vpnctld::admin",
                        server = %server_id_str,
                        user = %u.id,
                        error = %e,
                        "audit write failed for user.grant (bulk) — mutation already committed"
                    );
                }
            }
            Err(e) => {
                failed += 1;
                tracing::warn!(
                    target = "vpnctld::admin",
                    server = %server_id_str,
                    user = %u.id,
                    error = %e,
                    "bulk-grant: per-user grant failed; continuing"
                );
            }
        }
    }
    if let Err(e) = state
        .inv
        .audit(
            "admin",
            "server.grants.bulk_grant",
            Some(&server_id_str),
            Some(&serde_json::json!({
                "granted": granted,
                "already_granted": already,
                "failed": failed,
                "skipped_disabled": skipped_disabled,
                "total_users": users.len(),
            })),
        )
        .await
    {
        tracing::warn!(
            target = "vpnctld::admin",
            server = %server_id_str,
            error = %e,
            "audit write failed for server.grants.bulk_grant — mutations already committed"
        );
    }
    tracing::info!(
        target = "vpnctld::admin",
        server = %server_id_str,
        granted = granted,
        already = already,
        failed = failed,
        total = users.len(),
        "bulk-grant complete"
    );
    // Auto-deploy the affected server ONCE for the whole batch (not
    // once per user) so every new UUID lands in the node's users[].
    // Skipped on a fully-granted re-run (granted == 0 → no-op batch).
    if granted > 0 {
        spawn_user_servers_redeploy(
            &state,
            vec![server],
            server_id_str.clone(),
            "server.grants.bulk_grant",
        );
    }
    Redirect::to(&format!(
        "/admin/servers/{}/grants",
        path_segment_encode(&server_id_str)
    ))
    .into_response()
}

/// `POST /admin/servers/{id}/grants/_revoke-all` (B2, audit 2026-05-22,
/// shipped 2026-05-23) — revoke access for **every currently-granted
/// user** on this server. Destructive — operator must confirm by
/// re-typing the server id in the `confirm=<id>` form field (same
/// double-submit shape as user delete in C-3.4). Mismatch → 400.
///
/// Writes ONE summary audit row (`server.grants.bulk_revoke` with
/// `{revoked, failed, total_was}`) rather than N per-user rows.
/// Per-user revoke is idempotent at the SQL layer; failures are
/// counted + logged but don't abort the batch.
pub(crate) async fn server_revoke_all_users(
    State(state): State<AppState>,
    Path(server_id_str): Path<String>,
    body: String,
) -> Response {
    let confirm = form_field(&body, "confirm").unwrap_or_default();
    if confirm != server_id_str {
        return bad_request(&format!(
            "bulk-revoke confirm mismatch: form sent '{confirm}', URL targets '{server_id_str}' — type the server id exactly to confirm"
        ));
    }
    let sid = vpnctl_core::ServerId(server_id_str.clone());
    // 3-arm match (audit 2026-06-10): the old `if let Ok(None)` SWALLOWED
    // the DB-error arm and fell through as if the server existed.
    let server = match state.inv.get_server(&sid).await {
        Ok(Some(s)) => s,
        Ok(None) => return not_found(&format!("no such server '{server_id_str}'")),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    let granted = match state.inv.users_for_server(&sid).await {
        Ok(v) => v,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    let total_was = granted.len();
    let mut revoked: u32 = 0;
    let mut failed: u32 = 0;
    for u in &granted {
        match state.inv.revoke(&u.id, &sid).await {
            Ok(()) => {
                revoked += 1;
                // Per-user `user.revoke` row for each ACTUAL revoke
                // (the `granted` list is exactly the granted set, so
                // every Ok here is a real mutation). Mirrors the bulk
                // grant path; keeps the pending-deploy detector fed.
                // Audit failure non-fatal: revoke already committed.
                if let Err(e) = state
                    .inv
                    .audit(
                        "admin",
                        "user.revoke",
                        Some(&u.id.0),
                        Some(&serde_json::json!({
                            "server": server_id_str,
                            "source": "server-detail.bulk",
                        })),
                    )
                    .await
                {
                    tracing::warn!(
                        target = "vpnctld::admin",
                        server = %server_id_str,
                        user = %u.id,
                        error = %e,
                        "audit write failed for user.revoke (bulk) — mutation already committed"
                    );
                }
            }
            Err(e) => {
                failed += 1;
                tracing::warn!(
                    target = "vpnctld::admin",
                    server = %server_id_str,
                    user = %u.id,
                    error = %e,
                    "bulk-revoke: per-user revoke failed; continuing"
                );
            }
        }
    }
    if let Err(e) = state
        .inv
        .audit(
            "admin",
            "server.grants.bulk_revoke",
            Some(&server_id_str),
            Some(&serde_json::json!({
                "revoked": revoked,
                "failed": failed,
                "total_was": total_was,
            })),
        )
        .await
    {
        tracing::warn!(
            target = "vpnctld::admin",
            server = %server_id_str,
            error = %e,
            "audit write failed for server.grants.bulk_revoke — mutations already committed"
        );
    }
    tracing::info!(
        target = "vpnctld::admin",
        server = %server_id_str,
        revoked = revoked,
        failed = failed,
        total_was = total_was,
        "bulk-revoke complete"
    );
    // Auto-deploy ONCE for the batch — mirror of the bulk-grant path.
    if revoked > 0 {
        spawn_user_servers_redeploy(
            &state,
            vec![server],
            server_id_str.clone(),
            "server.grants.bulk_revoke",
        );
    }
    Redirect::to(&format!(
        "/admin/servers/{}/grants",
        path_segment_encode(&server_id_str)
    ))
    .into_response()
}

/// `GET /admin/servers/{id}/delete-confirm` — retype-to-confirm page
/// for removing a server from the inventory (mirrors user delete). Shows
/// the cascade scope (grants / secrets / protocols) before the operator
/// commits.
pub(crate) async fn server_delete_confirm(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(server_id_str): Path<String>,
) -> Result<Markup, Response> {
    let (theme, accent, lang) = theme_accent_lang(&headers);
    let sid = vpnctl_core::ServerId(server_id_str.clone());
    let server = match state.inv.get_server(&sid).await {
        Ok(Some(s)) => s,
        Ok(None) => return Err(not_found(&format!("no such server '{server_id_str}'"))),
        Err(e) => return Err(internal_error(anyhow::Error::new(e))),
    };
    // `Option` so a DB error renders as «unknown», not a reassuring
    // fake «0 grant(s)» (audit 2026-06-10).
    let grant_count = match state.inv.users_for_server(&sid).await {
        Ok(v) => Some(v.len()),
        Err(e) => {
            tracing::warn!(
                target = "vpnctld::admin",
                server = %server_id_str,
                error = %e,
                "users_for_server failed on delete-confirm; rendering count as unknown"
            );
            None
        }
    };
    // Telegram alert relay: deleting the proxy server is allowed (the
    // FK is a deliberate non-cascade dangle, migration 0015) but every
    // subsequent alert send will fail at SSH-spawn time — warn the
    // operator BEFORE the delete, not in the logs after.
    let is_telegram_proxy = match state.inv.get_telegram_config().await {
        Ok(cfg) => cfg
            .and_then(|c| c.proxy_via_server_id)
            .is_some_and(|p| p == server_id_str),
        Err(e) => {
            // Don't silently drop the relay warning on a DB error —
            // log it; the page still renders (warning-less, like the
            // pre-fix behavior, but now visibly in the daemon log).
            tracing::warn!(
                target = "vpnctld::admin",
                server = %server_id_str,
                error = %e,
                "get_telegram_config failed on delete-confirm; relay warning suppressed"
            );
            false
        }
    };
    let back = format!("/admin/servers/{}", path_segment_encode(&server_id_str));
    let body = html! {
        div.ed-art-eyebrow {
            a href=(back) style="color: var(--mute); text-decoration: none;" { "← back to server" }
            "  ·  delete"
        }
        h1.ed-art-h1 { "delete " em { (server_id_str) } " — really?" }
        p.ed-art-deck {
            "Drops the server (" span.ed-mono { (server.address) } ") from the inventory. "
            b {
                @match grant_count {
                    Some(n) => { (n) " grant(s)" },
                    None => { "an unknown number of grants (inventory read failed — reload to retry)" },
                }
            }
            " cascade-delete — those users lose this server from their subscription on the next pull. "
            b { "Secrets" }
            " (REALITY keypair, short_id, obfs passwords) are deleted — re-adding the server later generates BRAND-NEW ones. "
            "Protocols, kernels, probe history + alerts also cascade. If another server uses this one as a ProxyJump host, that link is cleared. "
            b { "The sing-box on the node itself is NOT touched" }
            " — stop/wipe it on the host separately if the VPS lives on."
        }
        @if is_telegram_proxy {
            p style="font-family: var(--mono); font-size: 11px; color: var(--acc); border: 1px solid var(--acc); padding: 8px 12px; margin: 10px 0;" {
                b { "This server is the Telegram alert relay" }
                " (settings → notifications → proxy-via). Deleting it silently breaks every alert send until you pick another relay or clear the setting."
            }
        }
        p style="font-family: var(--serif); font-style: italic; color: var(--mute); padding: 8px 0;" {
            "Type the server-id "
            span.ed-mono { (server_id_str) }
            " in the box below to confirm. Exact match — copy/paste counts."
        }
        form method="post"
             action=(format!("/admin/servers/{}/delete", path_segment_encode(&server_id_str)))
             style="display: flex; gap: 10px; align-items: baseline; padding: 14px 16px; border: 1px solid var(--rule); margin: 16px 0;" {
            label style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase;" {
                "confirm id"
            }
            input type="text" name="confirm" required="required"
                  autocomplete="off"
                  style="flex: 1; max-width: 280px; padding: 4px 8px; border: 1px solid var(--rule-s); background: var(--paper); font-family: var(--mono); font-size: 12px; color: var(--ink);";
            button type="submit"
                   title=(format!("Delete server {server_id_str} from the inventory permanently"))
                   class="ed-abtn ed-abtn--danger-solid" {
                "delete forever"
            }
            a href=(back)
              class="ed-abtn ed-abtn--secondary ed-abtn--sm" {
                "cancel"
            }
        }
    };
    Ok(render_page(&state, "servers", &theme, &accent, lang, body).await)
}

/// `POST /admin/servers/{id}/delete` — actually delete. Body must be
/// `confirm=<exact-server-id>`; mismatch → 400. Captures the cascade
/// scope (grant count) for the audit payload BEFORE the FK cascade wipes
/// it, then removes the server and audits `server.remove`.
pub(crate) async fn server_delete(
    State(state): State<AppState>,
    Path(server_id_str): Path<String>,
    body: String,
) -> Response {
    let confirm = form_field(&body, "confirm").unwrap_or_default();
    if confirm != server_id_str {
        return bad_request(&format!(
            "delete confirm mismatch: form sent '{confirm}', URL targets '{server_id_str}' — type the server id exactly to confirm"
        ));
    }
    let sid = vpnctl_core::ServerId(server_id_str.clone());
    let server = match state.inv.get_server(&sid).await {
        Ok(Some(s)) => s,
        Ok(None) => return not_found(&format!("no such server '{server_id_str}'")),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    // Deploy-concurrency gate (audit 2026-06-10): deleting a server
    // while its deploy pipeline is in flight let the pipeline keep
    // SSH-pushing to the node, fail FK-wise on secret upserts mid-
    // stream, and then write a server.deploy audit row for a server
    // that no longer exists. Hold the same per-server permit a deploy
    // takes; 409 if one is running. The guard drops at handler return
    // (RAII), covering every early-return below.
    let _deploy_guard = match crate::wizard_bootstrap::DeployGuard::try_acquire(&server_id_str) {
        Some(g) => g,
        None => {
            return error_resp(
                StatusCode::CONFLICT,
                &format!(
                    "deploy in flight for server '{server_id_str}' — wait for it to finish, then delete"
                ),
            );
        }
    };
    // Capture cascade scope BEFORE the delete (FK CASCADE wipes grants).
    let grants_removed = state
        .inv
        .users_for_server(&sid)
        .await
        .map(|v| v.len())
        .unwrap_or(0);
    if let Err(e) = state.inv.remove_server(&sid).await {
        return internal_error(anyhow::Error::new(e));
    }
    if let Err(e) = state
        .inv
        .audit(
            "admin",
            "server.remove",
            Some(&server_id_str),
            Some(&serde_json::json!({
                "address": server.address,
                "grants_removed": grants_removed,
            })),
        )
        .await
    {
        tracing::warn!(
            target = "vpnctld::admin",
            server = %server_id_str,
            error = %e,
            "audit row for server.remove failed; mutation already committed"
        );
    }
    Redirect::to("/admin/servers").into_response()
}

/// `POST /admin/servers/{id}/push-deploy-key` — append the daemon's
/// deploy pubkey to the server's `~/.ssh/authorized_keys`. Recovery
/// action for servers added via quick-add / migrate-from-bash
/// (Phase E wizard does this automatically as step 3 of bootstrap).
///
/// ## Two egress paths, tried in order
///
/// 1. **Reference SSH key** (preferred) — if `VPNCTLD_REFERENCE_SSH_KEY`
///    env var points at a readable private key on the daemon host AND
///    `root_password` is left empty, the handler uses that key
///    (assumed pre-authorised on every inventory server, e.g. the
///    operator's existing `~/.ssh/id_ed25519`) for a silent push. This
///    matches Pavel's «if I added the server, the daemon should have
///    all the access» expectation: configure the env var ONCE, all
///    subsequent push-deploy-key clicks are no-input.
/// 2. **Root password via sshpass** — fallback when reference key
///    isn't set / isn't readable / didn't work. Operator-typed
///    password → SSHPASS env var of the sshpass child process →
///    never in argv (`ps auxe` from non-root can't see it). After
///    the SSH call returns, the password lives only on this handler's
///    stack; not stored, not logged, not in the audit payload.
///
/// Server-side command is byte-identical to the wizard's step 3
/// (push-key) and idempotent (`grep -qxF || echo >>`) — a successful
/// click followed by an accidental second click is a no-op.
///
/// **Audit row** written on both success + failure (operator action
/// either way). Payload: `{success: bool, method: "reference-key" | "sshpass", error?: str}`
/// — never the password.
pub(crate) async fn server_push_deploy_key(
    Path(server_id_str): Path<String>,
    State(state): State<AppState>,
    body: String,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id_str.clone());

    // Look up server. 404 if not in inventory.
    let server = match state.inv.get_server(&sid).await {
        Ok(Some(s)) => s,
        Ok(None) => return not_found(&format!("no such server '{server_id_str}'")),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };

    let password = form_field(&body, "root_password").unwrap_or_default();

    // ─── Credentials gate (BEFORE expensive pubkey read) ─────────
    // 400 ASAP if operator gave neither a password nor a usable
    // reference key on the daemon host — otherwise a missing
    // deploy-pubkey file (read step below) would surface as a
    // misleading 500 hiding the real «no creds» bug.
    let reference_key_path = std::env::var("VPNCTLD_REFERENCE_SSH_KEY").ok();
    let try_reference = password.is_empty()
        && reference_key_path
            .as_ref()
            .is_some_and(|p| !p.is_empty() && std::path::Path::new(p).exists());
    if password.is_empty() && !try_reference {
        return bad_request(
            "root_password is required (or set VPNCTLD_REFERENCE_SSH_KEY \
             on the daemon host to use a pre-authorised key instead)",
        );
    }

    // Read the daemon's deploy pubkey from disk. Same path the
    // Settings page surfaces + the wizard's BootstrapPlan uses.
    let key_path = std::path::Path::new(crate::app::DEFAULT_DEPLOY_KEY_PATH);
    let pubkey = match crate::ssh_subprocess::read_public_key(key_path) {
        Ok(p) => p,
        Err(e) => {
            return error_resp(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!(
                    "deploy pubkey unreadable at {}: {e}. \
                     Check /admin/settings (Deploy SSH key section) for the root cause.",
                    key_path.with_extension("pub").display()
                ),
            );
        }
    };

    // Idempotent remote append + chmod. Byte-identical to the
    // wizard's step 3 (push-key).
    let push_cmd = format!(
        "set -eu; \
         mkdir -p ~/.ssh && chmod 0700 ~/.ssh; \
         touch ~/.ssh/authorized_keys && chmod 0600 ~/.ssh/authorized_keys; \
         grep -qxF {pk_q} ~/.ssh/authorized_keys || echo {pk_q} >> ~/.ssh/authorized_keys; \
         echo done",
        pk_q = vpnctl_core::shell::single_quote(&pubkey),
    );

    if let Some(ref_key) = reference_key_path.clone().filter(|_| try_reference) {
        let ssh = crate::ssh_subprocess::SubprocessSshTransport::new(
            server.address.clone(),
            server.ssh_user.clone(),
            std::path::PathBuf::from(&ref_key),
        )
        .port(server.ssh_port);
        use vpnctl_core::SshTransport;
        match ssh.exec(&push_cmd).await {
            Ok(_) => {
                if let Err(audit_err) = state
                    .inv
                    .audit(
                        "admin",
                        "server.push_deploy_key",
                        Some(&server_id_str),
                        Some(&serde_json::json!({
                            "success": true,
                            "server_id": &server_id_str,
                            "method": "reference-key",
                            "reference_key_path": &ref_key,
                        })),
                    )
                    .await
                {
                    // Bug-hunt 2026-05-18 — was `let _ =`, silently
                    // losing the operator action trail. Mirror the
                    // sshpass-path warn block.
                    tracing::warn!(
                        target = "vpnctld::admin::server_push_deploy_key",
                        server = %server_id_str,
                        error = %audit_err,
                        "audit row for server.push_deploy_key (reference-key success) failed; push succeeded"
                    );
                }
                return Redirect::to(&format!(
                    "/admin/servers/{}/setup#push-deploy-key",
                    path_segment_encode(&server_id_str)
                ))
                .into_response();
            }
            Err(e) => {
                // Reference key didn't work (likely not authorised on
                // THIS server). If a password was ALSO provided, fall
                // through to sshpass path; otherwise surface the
                // reference-key failure with a hint.
                if password.is_empty() {
                    if let Err(audit_err) = state
                        .inv
                        .audit(
                            "admin",
                            "server.push_deploy_key",
                            Some(&server_id_str),
                            Some(&serde_json::json!({
                                "success": false,
                                "server_id": &server_id_str,
                                "method": "reference-key",
                                "error": e.to_string(),
                            })),
                        )
                        .await
                    {
                        tracing::warn!(
                            target = "vpnctld::admin::server_push_deploy_key",
                            server = %server_id_str,
                            error = %audit_err,
                            "audit row for server.push_deploy_key (reference-key failure) failed"
                        );
                    }
                    return error_resp(
                        StatusCode::BAD_GATEWAY,
                        &format!(
                            "push-deploy-key via reference key ({ref_key}) failed for \
                             {server_id_str}: {e} — the reference key isn't authorised \
                             on this server. Supply the root password below to fall back \
                             to sshpass. If password auth is also disabled, the daemon \
                             can't self-recover this server — use the hoster's console \
                             to add the pubkey shown on /admin/settings."
                        ),
                    );
                }
                // password is non-empty → continue to sshpass path.
                tracing::info!(
                    target = "vpnctld::admin::server_push_deploy_key",
                    server = %server_id_str,
                    error = %e,
                    "reference key failed; falling back to sshpass"
                );
            }
        }
    }

    // ─── Path 2: sshpass + operator-typed password ────────────────
    // (Credentials gate above already ensured password is non-empty
    // when we get here — either initial state, or fall-through from
    // reference-key failure with password supplied.)

    // known_hosts path mirrors the wizard's default (and the
    // daemon's `SubprocessSshTransport` default for subsequent
    // pubkey-auth connects). Living in `/var/lib/vpnctl/.ssh/`
    // keeps it daemon-owned.
    let known_hosts = std::path::PathBuf::from("/var/lib/vpnctl/.ssh/known_hosts");

    let result = crate::wizard_bootstrap::ssh_password_run(
        &server.address,
        server.ssh_port,
        &server.ssh_user,
        &password,
        &known_hosts,
        &push_cmd,
    )
    .await;

    // Audit either way. Payload: server id, success, optional error.
    // Never the password (caller-owned secret); never the full sshpass
    // stderr (might quote the password verbatim if sshpass leaks it).
    let audit_payload = match &result {
        Ok(_) => serde_json::json!({
            "success": true,
            "server_id": &server_id_str,
            "method": "sshpass",
        }),
        Err(e) => serde_json::json!({
            "success": false,
            "server_id": &server_id_str,
            "method": "sshpass",
            "error": e,
        }),
    };
    if let Err(audit_err) = state
        .inv
        .audit(
            "admin",
            "server.push_deploy_key",
            Some(&server_id_str),
            Some(&audit_payload),
        )
        .await
    {
        tracing::warn!(
            target = "vpnctld::admin::server_push_deploy_key",
            server = %server_id_str,
            error = %audit_err,
            "audit row failed; push result was {:?}",
            result.is_ok()
        );
    }

    match result {
        Ok(_) => {
            // Anchor scroll back to the section + a query flag a
            // future toast could read. For now the operator just
            // sees the page refresh; pubkey-auth verification
            // happens organically the next time the node probe
            // poller runs.
            Redirect::to(&format!(
                "/admin/servers/{}/setup#push-deploy-key",
                path_segment_encode(&server_id_str)
            ))
            .into_response()
        }
        Err(e) => error_resp(
            StatusCode::BAD_GATEWAY,
            &format!(
                "push-deploy-key failed for {server_id_str}: {e} — \
                 common causes: wrong password; server's sshd rejected \
                 password auth (PasswordAuthentication off — daemon can't \
                 self-recover, use the hoster's console to authorise the \
                 pubkey shown on /admin/settings); server unreachable on \
                 configured port (check /admin/servers/{server_id_str})."
            ),
        ),
    }
}

/// `POST /admin/servers/{id}/set-fingerprint` — operator pins the
/// trusted SHA-256. Two modes (selected by hidden form field `mode`):
///   * `keyscan` — daemon shells out to `ssh-keyscan -t ed25519 -p
///     <port> <addr> | ssh-keygen -lf -`, takes the 2nd whitespace
///     token. Convenience for the typical operator flow.
///   * `manual` — operator pasted a fingerprint string into the form.
///     Same shape validation as the CLI side.
///
/// Both audit-log `server.fingerprint.set` with the pinned value +
/// source, then redirect to `/admin/servers/{id}` so the section
/// re-renders with the new value visible.
pub(crate) async fn server_set_fingerprint(
    axum::extract::Path(server_id): axum::extract::Path<String>,
    State(state): State<AppState>,
    body: String,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id.clone());
    let server = match state.inv.get_server(&sid).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return not_found(&format!("no such server '{server_id}'"));
        }
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };

    // Same `&`-split + decode_form_value pattern as user_create /
    // server_quick_add — doesn't pull a form-extractor feature.
    let mode = form_field(&body, "mode").unwrap_or_default();
    let fingerprint_in = form_field(&body, "fingerprint").unwrap_or_default();

    let (fp, source) = match mode.as_str() {
        "keyscan" => {
            // Defense-in-depth: re-validate the stored address before
            // shelling out — `validate_address` runs on every wizard
            // submit + server-quick-add, but a migrated row could
            // predate the validator. Cheap; rejects with 400 before
            // we spawn anything.
            if let Err(reason) = crate::wizard::validate_address(&server.address) {
                return bad_request(&format!(
                    "server '{server_id}' has an address that fails the validator ({reason}); \
                         fix it in the inventory before running auto-detect"
                ));
            }
            // Wrap blocking subprocess in spawn_blocking — otherwise an
            // unreachable host pins the tokio worker thread for the
            // ssh-keyscan default timeout (~5–10s), starving other
            // requests on the small homelab runtime.
            let addr = server.address.clone();
            let port = server.ssh_port;
            let scan_res = tokio::task::spawn_blocking(move || {
                vpnctl_host_fingerprint::fetch_via_keyscan(&addr, port)
            })
            .await;
            match scan_res {
                Ok(Ok(fp)) => (fp, "ssh-keyscan"),
                Ok(Err(e)) => {
                    return error_resp(
                        StatusCode::BAD_GATEWAY,
                        &format!("ssh-keyscan failed: {e}"),
                    );
                }
                Err(join_err) => {
                    return internal_error(anyhow::anyhow!(
                        "ssh-keyscan task panicked: {join_err}"
                    ));
                }
            }
        }
        "manual" => {
            if fingerprint_in.trim().is_empty() {
                return bad_request("manual mode requires a non-empty 'fingerprint' field");
            }
            (fingerprint_in.trim().to_string(), "operator-provided")
        }
        _ => {
            return bad_request("missing or invalid 'mode' (expected 'keyscan' or 'manual')");
        }
    };

    if !vpnctl_host_fingerprint::validate_shape(&fp) {
        return bad_request(&format!(
            "fingerprint '{fp}' is not in SHA256:<base64> shape"
        ));
    }

    // Capture previous fingerprint BEFORE overwriting — same forensic
    // reasoning as the CLI side. A TOFU-pin rotation has very different
    // implications depending on whether the operator rebuilt the node
    // (legit) vs someone is MITM-rotating the key (attack).
    let previous = server.trusted_host_fingerprint.clone();
    if let Err(e) = state.inv.update_trusted_fingerprint(&sid, &fp).await {
        return internal_error(anyhow::Error::new(e));
    }
    // Audit only a REAL pin change (NM-10) under the dot-convention
    // name `server.fingerprint.set` (was `server.set_fingerprint` —
    // the only server.* action with the verb glued to the domain,
    // breaking `server.fingerprint.`-prefix filtering; renamed
    // 2026-06-10, old rows keep the legacy name). A same-value re-pin
    // is a no-op — writing a row made every re-submit look like a
    // TOFU rotation in the timeline.
    if previous.as_deref() != Some(fp.as_str())
        && let Err(e) = state
            .inv
            .audit(
                "admin",
                "server.fingerprint.set",
                Some(&server_id),
                Some(&serde_json::json!({
                    "fingerprint": fp,
                    "previous": previous,
                    "source": source,
                })),
            )
            .await
    {
        tracing::warn!(
            target = "vpnctld::admin::server_set_fingerprint",
            server = %server_id,
            error = %e,
            "set_fingerprint succeeded but audit row failed; timeline will be missing this entry"
        );
    }

    Redirect::to(&format!(
        "/admin/servers/{}/setup",
        path_segment_encode(&server_id)
    ))
    .into_response()
}

/// `POST /admin/servers/{id}/naive-config` — set the naive (Caddy)
/// per-server params `naive.domain` + `naive.acme_email` (server_secrets)
/// the caddy kernel renders into the Caddyfile and Caddy's built-in ACME
/// consumes. Domain is required (the deploy render rejects an empty one).
/// Both fields are fail-closed against whitespace/brace injection — they
/// land verbatim in a Caddyfile, so the same illegal-char set the kernel
/// guards with is enforced here too, returning a clean 400 instead of a
/// node-side `caddy validate` failure. Redirects to the detail page.
pub(crate) async fn server_set_naive_config(
    axum::extract::Path(server_id): axum::extract::Path<String>,
    State(state): State<AppState>,
    body: String,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id.clone());
    match state.inv.get_server(&sid).await {
        Ok(Some(_)) => {}
        Ok(None) => return not_found(&format!("no such server '{server_id}'")),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }

    let domain_raw = form_field(&body, "domain").unwrap_or_default();
    let domain = domain_raw.trim();
    let email_raw = form_field(&body, "acme_email").unwrap_or_default();
    let email = email_raw.trim();

    // These strings land verbatim in a Caddyfile; reject anything that
    // could break out of its line/block (same guard the caddy kernel
    // applies at render). Fail with a 400 here rather than at node-side
    // `caddy validate`.
    const ILLEGAL: [char; 5] = ['\n', '\r', ' ', '{', '}'];
    if domain.is_empty() {
        return bad_request("vpnctl admin: naive domain is required");
    }
    if domain.chars().count() > 253 || domain.contains(ILLEGAL) {
        return bad_request("vpnctl admin: invalid naive domain");
    }
    if email.chars().count() > 254 || email.contains(ILLEGAL) {
        return bad_request("vpnctl admin: invalid naive ACME email");
    }

    // Two separate upserts (the generic KV setter is per-key). Not one
    // transaction, so a mid-failure could leave domain set but email
    // stale — acceptable here: single operator, the form is idempotent,
    // and re-submitting reconciles both keys.
    if let Err(e) = state
        .inv
        .set_server_secret(&sid, "naive.domain", domain)
        .await
    {
        return internal_error(anyhow::Error::new(e));
    }
    if let Err(e) = state
        .inv
        .set_server_secret(&sid, "naive.acme_email", email)
        .await
    {
        return internal_error(anyhow::Error::new(e));
    }
    // set_server_secret is the generic KV setter (no built-in audit), so
    // emit the audit row here. Best-effort: a failed audit write must not
    // 500 the operator's save (the secrets already persisted).
    let _ = state
        .inv
        .audit(
            "admin",
            "server.naive.set",
            Some(&server_id),
            Some(&serde_json::json!({
                "domain": domain,
                "acme_email_set": !email.is_empty(),
            })),
        )
        .await;

    Redirect::to(&format!(
        "/admin/servers/{}/protocols",
        path_segment_encode(&server_id)
    ))
    .into_response()
}

/// `POST /admin/servers/{id}/vlessws-config` — set the vless-ws (Caddy)
/// per-server params `vlessws.domain` + `vlessws.acme_email` +
/// `vlessws.listen_port` (server_secrets) the caddy kernel renders into the
/// vless-ws bundle + Caddy's built-in ACME consumes. The secret ws path
/// (`vlessws.path`) is NOT set here — it's auto-minted at deploy. Domain is
/// required; all three land in config/URI artefacts, so the same
/// illegal-char guard the kernel applies is enforced here, and `listen_port`
/// (when non-blank) must be a valid non-zero u16. Redirects to the detail.
pub(crate) async fn server_set_vlessws_config(
    axum::extract::Path(server_id): axum::extract::Path<String>,
    State(state): State<AppState>,
    body: String,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id.clone());
    let server = match state.inv.get_server(&sid).await {
        Ok(Some(s)) => s,
        Ok(None) => return not_found(&format!("no such server '{server_id}'")),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };

    let domain_raw = form_field(&body, "domain").unwrap_or_default();
    let domain = domain_raw.trim();
    let email_raw = form_field(&body, "acme_email").unwrap_or_default();
    let email = email_raw.trim();
    let port_raw = form_field(&body, "listen_port").unwrap_or_default();
    let port = port_raw.trim();

    // These land verbatim in a Caddyfile / vless:// URI; reject anything
    // that could break out of its line/block (same guard the caddy kernel +
    // the vless_ws protocol apply at render). Fail 400 here rather than at
    // node-side `caddy validate`.
    const ILLEGAL: [char; 5] = ['\n', '\r', ' ', '{', '}'];
    if domain.is_empty() {
        return bad_request("vpnctl admin: vless-ws domain is required");
    }
    if domain.chars().count() > 253 || domain.contains(ILLEGAL) {
        return bad_request("vpnctl admin: invalid vless-ws domain");
    }
    if email.chars().count() > 254 || email.contains(ILLEGAL) {
        return bad_request("vpnctl admin: invalid vless-ws ACME email");
    }
    // Front port: optional (blank → kernel default 8443). When set it must
    // be a valid non-zero u16, else the kernel silently falls back and the
    // operator's typo is hidden.
    if !port.is_empty() && !matches!(port.parse::<u16>(), Ok(p) if p != 0) {
        return bad_request("vpnctl admin: invalid vless-ws front port (1..=65535)");
    }

    // Save-time port-conflict gate, symmetric with reality-config: the
    // front port is load-bearing (`effective_listen_ports`), so validate
    // the CANDIDATE secret map before persisting — e.g. front 8443 next
    // to a reality moved to 8443 via `vless.listen_port` is rejected
    // here instead of at deploy time. Deploy stays the authoritative gate.
    let mut candidate = match state.inv.list_server_secrets(&sid).await {
        Ok(s) => s,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    if port.is_empty() {
        candidate.remove("vlessws.listen_port");
    } else {
        candidate.insert("vlessws.listen_port".to_string(), port.to_string());
    }
    if let Err(e) = state.registry.validate_server(&server, &candidate) {
        return bad_request(&format!("{e}"));
    }

    // Three per-key upserts (the generic KV setter is per-key). Same
    // non-transactional, idempotent-form caveat as the naive handler.
    for (key, val) in [
        ("vlessws.domain", domain),
        ("vlessws.acme_email", email),
        ("vlessws.listen_port", port),
    ] {
        if let Err(e) = state.inv.set_server_secret(&sid, key, val).await {
            return internal_error(anyhow::Error::new(e));
        }
    }
    // set_server_secret has no built-in audit, so emit the row here.
    // Best-effort: a failed audit must not 500 the save.
    let _ = state
        .inv
        .audit(
            "admin",
            "server.vlessws.set",
            Some(&server_id),
            Some(&serde_json::json!({
                "domain": domain,
                "acme_email_set": !email.is_empty(),
                "listen_port": port,
            })),
        )
        .await;

    Redirect::to(&format!(
        "/admin/servers/{}/protocols",
        path_segment_encode(&server_id)
    ))
    .into_response()
}

/// `POST /admin/servers/{id}/reality-config` — set the VLESS+REALITY
/// per-server listen port (`vless.listen_port`; blank = default 443).
/// The value is load-bearing: sing-box binds it, client links carry it,
/// the firewall step opens it, and the port-conflict guard + drift table
/// read it (`effective_listen_ports`). Validated like
/// `vlessws.listen_port` — blank or non-zero u16 — and the full
/// port-conflict gate runs against the CANDIDATE secret map, so a
/// collision (naive on 443, vless-ws on 8443, …) is rejected at save
/// time instead of at deploy time. Redirects to the detail page.
pub(crate) async fn server_set_reality_config(
    axum::extract::Path(server_id): axum::extract::Path<String>,
    State(state): State<AppState>,
    body: String,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id.clone());
    let server = match state.inv.get_server(&sid).await {
        Ok(Some(s)) => s,
        Ok(None) => return not_found(&format!("no such server '{server_id}'")),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };

    let port_raw = form_field(&body, "listen_port").unwrap_or_default();
    let port = port_raw.trim();
    if !port.is_empty() && !matches!(port.parse::<u16>(), Ok(p) if p != 0) {
        return bad_request("invalid REALITY listen port (1..=65535)");
    }

    // Reject port collisions at SAVE time: validate with the candidate
    // secret map (current secrets + candidate override). Blank clears the
    // override → default 443, which is validated too — that is exactly
    // the naive-on-443 case the guard exists for.
    let mut candidate = match state.inv.list_server_secrets(&sid).await {
        Ok(s) => s,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    if port.is_empty() {
        candidate.remove("vless.listen_port");
    } else {
        candidate.insert("vless.listen_port".to_string(), port.to_string());
    }
    if let Err(e) = state.registry.validate_server(&server, &candidate) {
        return bad_request(&format!("{e}"));
    }

    // Blank stores "" — the parser treats empty as "default 443", same
    // convention as vlessws.listen_port.
    if let Err(e) = state
        .inv
        .set_server_secret(&sid, "vless.listen_port", port)
        .await
    {
        return internal_error(anyhow::Error::new(e));
    }
    // set_server_secret has no built-in audit, so emit the row here.
    // Best-effort: a failed audit must not 500 the save.
    let _ = state
        .inv
        .audit(
            "admin",
            "server.reality.set",
            Some(&server_id),
            Some(&serde_json::json!({ "listen_port": port })),
        )
        .await;

    Redirect::to(&format!(
        "/admin/servers/{}/protocols",
        path_segment_encode(&server_id)
    ))
    .into_response()
}

/// `POST /admin/servers/{id}/display-name` — set (or clear) the
/// operator-friendly subscription label (migration 0029). Form field
/// `display_name`; blank/whitespace clears the override (render falls
/// back to the ISO-code→country map, then the uppercased id). The audit
/// row (`server.display_name.set`, on actual change only) is written
/// inside the inventory transaction, so this handler doesn't double-
/// audit. Redirects to the detail page so the new label is visible.
pub(crate) async fn server_set_display_name(
    axum::extract::Path(server_id): axum::extract::Path<String>,
    State(state): State<AppState>,
    body: String,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id.clone());
    // Clean 404 if the server doesn't exist (set_server_display_name
    // would reject with Invalid → 500; prefer an explicit not_found).
    match state.inv.get_server(&sid).await {
        Ok(Some(_)) => {}
        Ok(None) => return not_found(&format!("no such server '{server_id}'")),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }

    let name = form_field(&body, "display_name").unwrap_or_default();
    // Sanity bound for a mobile client's server-list row. The inventory
    // layer trims + treats blank as a clear, so no further parsing here.
    if name.chars().count() > 64 {
        return bad_request("vpnctl admin: display name too long (max 64 characters)");
    }

    if let Err(e) = state.inv.set_server_display_name(&sid, Some(&name)).await {
        return internal_error(anyhow::Error::new(e));
    }

    Redirect::to(&format!(
        "/admin/servers/{}/setup",
        path_segment_encode(&server_id)
    ))
    .into_response()
}

/// `POST /admin/servers/{id}/auto-suppress` — toggle the per-server
/// opt-in (migration 0030) to auto-hide the server from subscriptions
/// while it's unreachable. Form field `enabled` = "true"/"false".
/// Turning it OFF also lifts any active suppression (handled in the
/// inventory layer). Audited (`server.auto_suppress.set`); redirects to
/// the detail page.
pub(crate) async fn server_set_auto_suppress(
    axum::extract::Path(server_id): axum::extract::Path<String>,
    State(state): State<AppState>,
    body: String,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id.clone());
    match state.inv.get_server(&sid).await {
        Ok(Some(_)) => {}
        Ok(None) => return not_found(&format!("no such server '{server_id}'")),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }
    let enabled = form_field(&body, "enabled").as_deref() == Some("true");
    if let Err(e) = state.inv.set_server_auto_suppress(&sid, enabled).await {
        return internal_error(anyhow::Error::new(e));
    }
    Redirect::to(&format!(
        "/admin/servers/{}/setup",
        path_segment_encode(&server_id)
    ))
    .into_response()
}

/// `POST /admin/servers/{id}/udp-pair` — toggle the per-server naive↔HY2
/// UDP-pairing opt-in (migration 0031, UX-3). Form field `enabled` =
/// "true"/"false". Audited (`server.udp_pair.set`); redirects to the detail
/// page.
pub(crate) async fn server_set_udp_pair(
    axum::extract::Path(server_id): axum::extract::Path<String>,
    State(state): State<AppState>,
    body: String,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id.clone());
    match state.inv.get_server(&sid).await {
        Ok(Some(_)) => {}
        Ok(None) => return not_found(&format!("no such server '{server_id}'")),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }
    let enabled = form_field(&body, "enabled").as_deref() == Some("true");
    if let Err(e) = state.inv.set_server_udp_pair_enabled(&sid, enabled).await {
        return internal_error(anyhow::Error::new(e));
    }
    Redirect::to(&format!(
        "/admin/servers/{}/protocols",
        path_segment_encode(&server_id)
    ))
    .into_response()
}

/// `POST /admin/servers/{id}/reserved-ports` — set the per-server
/// reserved-ports list (migration 0028). Form field `ports` is a
/// comma-separated u16 list; empty string clears. Mirrors the CLI
/// `vpnctl server set-reserved-ports` semantics one-for-one.
///
/// Per the operator-action policy in CLAUDE.md, every CLI command
/// needs a web equivalent — this handler is that equivalent for
/// the reservation contract added in commit 0028.
pub(crate) async fn server_set_reserved_ports(
    axum::extract::Path(server_id): axum::extract::Path<String>,
    State(state): State<AppState>,
    body: String,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id.clone());
    // 3-arm match (audit 2026-06-10): the old `if let Ok(None)` SWALLOWED
    // the DB-error arm and fell through as if the server existed.
    match state.inv.get_server(&sid).await {
        Ok(Some(_)) => {}
        Ok(None) => return not_found(&format!("no such server '{server_id}'")),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }

    let raw = form_field(&body, "ports").unwrap_or_default();
    let trimmed = raw.trim();
    let parsed: Vec<u16> = if trimmed.is_empty() {
        Vec::new()
    } else {
        let mut acc: Vec<u16> = Vec::new();
        for tok in trimmed.split(',') {
            let t = tok.trim();
            if t.is_empty() {
                continue;
            }
            match t.parse::<u16>() {
                Ok(0) => {
                    return bad_request("port 0 is not valid; allowed range 1..=65535");
                }
                Ok(p) => acc.push(p),
                Err(_) => {
                    return bad_request(&format!(
                        "invalid port '{t}'; expected comma-separated u16 (e.g. \
                         443,2053,2096) or empty to clear"
                    ));
                }
            }
        }
        acc.sort_unstable();
        acc.dedup();
        acc
    };

    if let Err(e) = state.inv.set_reserved_ports(&sid, &parsed).await {
        return internal_error(anyhow::Error::new(e));
    }

    Redirect::to(&format!(
        "/admin/servers/{}/protocols",
        path_segment_encode(&server_id)
    ))
    .into_response()
}

/// `POST /admin/servers/{sid}/protocols/{pid}/hide` — flip
/// `server_protocols.hidden = 1` for (sid, pid). Render path
/// (sub.rs + vpn_router.rs) immediately stops emitting this
/// protocol for any user's next subscription pull. Existing
/// cached client URIs keep working (the live sing-box inbound is
/// untouched).
pub(crate) async fn server_protocol_hide(
    State(state): State<AppState>,
    Path((server_id_str, protocol_id_str)): Path<(String, String)>,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id_str.clone());
    let pid = vpnctl_core::ProtocolId(protocol_id_str.clone());
    match state.inv.set_server_protocol_hidden(&sid, &pid, true).await {
        Ok(()) => Redirect::to(&format!(
            "/admin/servers/{}/protocols#enabled-protocols",
            path_segment_encode(&server_id_str)
        ))
        .into_response(),
        Err(vpnctl_inventory::SqliteInventoryError::Invalid(msg)) => bad_request(&msg),
        Err(e) => internal_error(anyhow::Error::new(e)),
    }
}

/// `POST /admin/servers/{sid}/protocols/{pid}/unhide` — flip
/// `server_protocols.hidden = 0` for (sid, pid). Render path
/// resumes emitting this protocol on next subscription pull.
pub(crate) async fn server_protocol_unhide(
    State(state): State<AppState>,
    Path((server_id_str, protocol_id_str)): Path<(String, String)>,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id_str.clone());
    let pid = vpnctl_core::ProtocolId(protocol_id_str.clone());
    match state
        .inv
        .set_server_protocol_hidden(&sid, &pid, false)
        .await
    {
        Ok(()) => Redirect::to(&format!(
            "/admin/servers/{}/protocols#enabled-protocols",
            path_segment_encode(&server_id_str)
        ))
        .into_response(),
        Err(vpnctl_inventory::SqliteInventoryError::Invalid(msg)) => bad_request(&msg),
        Err(e) => internal_error(anyhow::Error::new(e)),
    }
}
