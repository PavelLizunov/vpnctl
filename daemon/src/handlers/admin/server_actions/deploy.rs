use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};

use super::super::helpers::{bad_request, error_resp, internal_error, not_found};
use crate::AppState;
use crate::http_util::{form_field, path_segment_encode};

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

    let pre_secrets = match state.inv.list_server_secrets(&sid).await {
        Ok(s) => s,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    if let Err(e) = state.registry.validate_server(&server, &pre_secrets) {
        return bad_request(&format!("config invalid before deploy: {e}"));
    }

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

    match tokio::spawn(async move {
        let _deploy_guard = _deploy_guard;
        server_deploy_locked(state, server_id_str, sid, server).await
    })
    .await
    {
        Ok(response) => response,
        Err(e) => internal_error(anyhow::Error::new(e)),
    }
}

async fn server_deploy_locked(
    state: AppState,
    server_id_str: String,
    sid: vpnctl_core::ServerId,
    server: vpnctl_core::Server,
) -> Response {
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

    use crate::ssh_subprocess::SubprocessSshTransport;
    let key_path = crate::app::deploy_key_path();
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
        let jump = match state.inv.resolve_jump_host(&server).await {
            Ok(j) => j,
            Err(e) => return internal_error(anyhow::Error::new(e)),
        };
        let ssh =
            SubprocessSshTransport::new(server.address.clone(), server.ssh_user.clone(), key_path)
                .port(server.ssh_port)
                .trusted_fingerprint(server.trusted_host_fingerprint.clone())
                .with_jump(jump);

        let users = match state.inv.users_for_server(&sid).await {
            Ok(u) => u,
            Err(e) => return internal_error(anyhow::Error::new(e)),
        };
        if let Err(e) = state.inv.assert_no_uuid_collisions(&sid).await {
            return internal_error(anyhow::Error::new(e));
        }
        let known_user_uuids = match state.inv.known_user_uuids().await {
            Ok(k) => k,
            Err(e) => return internal_error(anyhow::Error::new(e)),
        };
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

        match state.inv.retired_server_kernels(&sid).await {
            Ok(retired) => {
                if let Err(e) = vpnctl_kernels::reconcile_disabled_kernels(
                    &state.registry,
                    &server,
                    &retired,
                    &ssh,
                )
                .await
                {
                    ssh_errors.push(format!("kernel shutdown failed: {e}"));
                }
            }
            Err(e) => ssh_errors.push(format!("retired kernel lookup failed: {e}")),
        }

        for kid in &server.kernels {
            let Some(kernel) = state.registry.kernel(kid) else {
                ssh_errors.push(format!("{}: kernel not registered", kid.0));
                continue;
            };
            if let Err(e) = kernel.ensure_installed(&ssh).await {
                ssh_errors.push(format!("{}: ensure_installed failed: {e}", kid.0));
                continue;
            };
            let supported = kernel.supported_protocols();
            let protocols: Vec<&dyn vpnctl_core::Protocol> = server
                .enabled_protocols
                .iter()
                .filter(|p| supported.contains(p))
                .filter_map(|p| state.registry.protocol(p))
                .collect();
            if protocols.is_empty() {
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
            if let Err(e) = kernel
                .apply_config_with_known_users(&ssh, &config, &known_user_uuids)
                .await
            {
                ssh_errors.push(format!("{}: apply_config failed: {e}", kid.0));
                continue;
            }
            ssh_kernels_pushed.push(kid.0.clone());
            configs_applied += 1;
            if let Err(e) = kernel.open_firewall(&ssh, &ctx, &protocols).await {
                ssh_errors.push(format!("{}: open_firewall failed: {e}", kid.0));
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

pub(crate) async fn server_push_deploy_key(
    Path(server_id_str): Path<String>,
    State(state): State<AppState>,
    body: String,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id_str.clone());

    let server = match state.inv.get_server(&sid).await {
        Ok(Some(s)) => s,
        Ok(None) => return not_found(&format!("no such server '{server_id_str}'")),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };

    let password = form_field(&body, "root_password").unwrap_or_default();
    let ssh_user_raw = form_field(&body, "ssh_user").unwrap_or_else(|| server.ssh_user.clone());
    let ssh_user = match crate::wizard::validate_ssh_user(&ssh_user_raw) {
        Ok(user) => user.to_string(),
        Err(why) => return bad_request(&format!("invalid ssh_user — {why}")),
    };

    let verify_only = match form_field(&body, "auth_method").as_deref() {
        None => false,
        Some("deploy-key") => true,
        _ => return bad_request("invalid auth_method"),
    };
    let key_path = crate::app::deploy_key_path();
    let jump = match state.inv.resolve_jump_host(&server).await {
        Ok(value) => value,
        Err(error) => return bad_request(&format!("jump host validation failed: {error}")),
    };
    if verify_only && server.trusted_host_fingerprint.is_none() {
        return bad_request(
            "Pin the server's trusted SSH host key on its setup page before checking the deploy key.",
        );
    }
    let (method, push_result) = if verify_only {
        ("deploy-key", Ok(()))
    } else {
        let reference_key_path = std::env::var("VPNCTLD_REFERENCE_SSH_KEY").ok();
        let try_reference = reference_key_path
            .as_ref()
            .is_some_and(|p| !p.is_empty() && std::path::Path::new(p).exists());
        if password.is_empty() && !try_reference {
            return bad_request(
                "ssh password is required (or set VPNCTLD_REFERENCE_SSH_KEY \
             on the daemon host to use a pre-authorised key instead)",
            );
        }

        let pubkey = match crate::ssh_subprocess::read_public_key(&key_path) {
            Ok(p) => p,
            Err(e) => {
                return error_resp(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!(
                        "deploy pubkey unreadable at {}: {e}. \
                     Check /admin/settings (Deploy SSH key section) for the root cause.",
                        crate::ssh_subprocess::public_key_path(&key_path).display()
                    ),
                );
            }
        };

        let push_cmd = crate::wizard_bootstrap::authorized_key_push_cmd(&pubkey);

        let mut method = "sshpass";
        if jump.is_some() && !try_reference {
            return bad_request(
                "password deploy-key push through a jump host is not supported; use the existing reference/deploy key path",
            );
        }
        let mut push_result: std::result::Result<(), String>;
        if let Some(ref_key) = reference_key_path.clone().filter(|_| try_reference) {
            method = "reference-key";
            let ssh = crate::ssh_subprocess::SubprocessSshTransport::new(
                server.address.clone(),
                ssh_user.clone(),
                std::path::PathBuf::from(&ref_key),
            )
            .port(server.ssh_port)
            .trusted_fingerprint(server.trusted_host_fingerprint.clone())
            .with_jump(jump.clone());
            push_result = ssh
                .exec_unprivileged(&push_cmd)
                .await
                .map(|_| ())
                .map_err(|e| e.to_string());
            if push_result.is_err() && !password.is_empty() && jump.is_none() {
                method = "sshpass";
                let known_hosts = std::path::PathBuf::from("/var/lib/vpnctl/.ssh/known_hosts");
                push_result = crate::wizard_bootstrap::ssh_password_run(
                    &server.address,
                    server.ssh_port,
                    &ssh_user,
                    &password,
                    &known_hosts,
                    server.trusted_host_fingerprint.as_deref(),
                    &push_cmd,
                )
                .await
                .map(|_| ());
            }
        } else {
            let known_hosts = std::path::PathBuf::from("/var/lib/vpnctl/.ssh/known_hosts");
            push_result = crate::wizard_bootstrap::ssh_password_run(
                &server.address,
                server.ssh_port,
                &ssh_user,
                &password,
                &known_hosts,
                server.trusted_host_fingerprint.as_deref(),
                &push_cmd,
            )
            .await
            .map(|_| ());
        }

        (method, push_result)
    };

    let result =
        match push_result {
            Ok(()) => {
                use vpnctl_core::SshTransport;
                let verify = crate::ssh_subprocess::SubprocessSshTransport::new(
                    server.address.clone(),
                    ssh_user.clone(),
                    key_path.to_path_buf(),
                )
                .port(server.ssh_port)
                .trusted_fingerprint(server.trusted_host_fingerprint.clone())
                .with_jump(jump);
                verify.exec("true").await.map(|_| ()).map_err(|e| {
                    format!("deploy-key or passwordless-sudo verification failed: {e}")
                })
            }
            Err(e) => Err(e),
        };

    if result.is_ok() && ssh_user != server.ssh_user {
        if let Err(e) = state
            .inv
            .update_server_ssh_user_audited(&sid, &server.ssh_user, &ssh_user, method)
            .await
        {
            return internal_error(anyhow::Error::new(e));
        }
    }

    if verify_only {
        return match result {
            Ok(()) => Redirect::to(&format!(
                "/admin/servers/{}/setup#push-deploy-key",
                path_segment_encode(&server_id_str)
            ))
            .into_response(),
            Err(error) => {
                let reason = if error.contains("sudo:") {
                    "Passwordless sudo verification failed."
                } else if error.contains("Permission denied") {
                    "SSH key authentication was rejected for this username."
                } else if error.contains("fingerprint")
                    || error.contains("pinned host key")
                    || error.contains("Host key verification failed")
                {
                    "Trusted SSH host-key verification failed."
                } else if error.contains("timed out") {
                    "SSH verification timed out."
                } else {
                    "Deploy-key verification failed; check the SSH username, installed key and server reachability."
                };
                error_resp(
                    StatusCode::BAD_GATEWAY,
                    &format!(
                        "{reason} The SSH username was not changed. Non-root accounts need passwordless sudo; if access needs repair, use the hoster's console."
                    ),
                )
            }
        };
    }

    let audit_payload = match &result {
        Ok(_) => serde_json::json!({
            "success": true,
            "server_id": &server_id_str,
            "method": method,
            "ssh_user": &ssh_user,
        }),
        Err(e) => serde_json::json!({
            "success": false,
            "server_id": &server_id_str,
            "method": method,
            "ssh_user": &ssh_user,
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
        Ok(_) => Redirect::to(&format!(
            "/admin/servers/{}/setup#push-deploy-key",
            path_segment_encode(&server_id_str)
        ))
        .into_response(),
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

#[cfg(test)]
mod existing_key_spec_tests;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use std::sync::Arc;
    use vpnctl_core::{KernelId, ProtocolId, Server, ServerId};

    #[tokio::test]
    async fn server_push_deploy_key_reports_exact_dotted_pubkey_path_on_missing_pubkey() {
        let dir = tempfile::tempdir().unwrap();
        let inv = vpnctl_inventory::SqliteInventory::open(&dir.path().join("inv.db"))
            .await
            .unwrap();
        let registry = Arc::new(crate::app::build_registry().unwrap());
        let (state, _handle) = crate::app::make_app_state_for_tests(inv.clone(), registry);

        let server = Server {
            id: ServerId("node-1".into()),
            address: "203.0.113.10".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![ProtocolId("vless+reality".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        };
        inv.add_server(&server).await.unwrap();

        let key_path = crate::app::deploy_key_path();
        let expected_pub = crate::ssh_subprocess::public_key_path(&key_path);

        let resp = server_push_deploy_key(
            Path("node-1".into()),
            State(state),
            "root_password=hunter2".into(),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body_bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let body_str = String::from_utf8_lossy(&body_bytes);

        let expected_prefix = format!(
            "vpnctl admin: deploy pubkey unreadable at {}:",
            expected_pub.display()
        );
        assert!(
            body_str.contains(&expected_prefix),
            "expected body containing '{expected_prefix}', got: '{body_str}'"
        );
        assert!(
            body_str.contains("Check /admin/settings (Deploy SSH key section) for the root cause."),
            "expected settings hint in '{body_str}'"
        );
    }
}
