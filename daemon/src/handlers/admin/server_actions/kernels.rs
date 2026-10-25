use axum::extract::{Path, State};
use axum::response::{IntoResponse, Redirect, Response};

use super::super::helpers::{bad_request, internal_error, not_found};
use super::super::legacy::spawn_user_servers_redeploy;
use crate::AppState;
use crate::http_util::path_segment_encode;

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

    let mut after = server.clone();
    after.kernels.retain(|k| k != &kid);
    if after.kernels.len() != server.kernels.len()
        && let Some(msg) = unsupported_change(&state.registry, &server, &after)
    {
        return bad_request(&format!("cannot disable kernel '{kernel_id_str}': {msg}"));
    }

    let removed = match state.inv.remove_server_kernel(&sid, &kid).await {
        Ok(n) => n,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };

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

fn orphaned_protocols(
    registry: &vpnctl_core::Registry,
    server: &vpnctl_core::Server,
) -> Vec<vpnctl_core::ProtocolId> {
    server
        .enabled_protocols
        .iter()
        .filter(|pid| {
            !server.kernels.iter().any(|kid| {
                registry
                    .kernel(kid)
                    .is_some_and(|k| k.supported_protocols().contains(pid))
            })
        })
        .cloned()
        .collect()
}

pub(crate) fn unsupported_change(
    registry: &vpnctl_core::Registry,
    before: &vpnctl_core::Server,
    after: &vpnctl_core::Server,
) -> Option<String> {
    let already = orphaned_protocols(registry, before);
    let orphaned: Vec<vpnctl_core::ProtocolId> = orphaned_protocols(registry, after)
        .into_iter()
        .filter(|pid| !already.contains(pid))
        .collect();
    if orphaned.is_empty() {
        return (after.kernels.is_empty() && !before.kernels.is_empty())
            .then(|| "a server needs at least one kernel".to_string());
    }
    let names: Vec<&str> = orphaned.iter().map(|p| p.0.as_str()).collect();
    let supporters: Vec<String> = registry
        .kernel_ids()
        .into_iter()
        .filter(|kid| {
            registry
                .kernel(kid)
                .is_some_and(|k| orphaned.iter().any(|p| k.supported_protocols().contains(p)))
        })
        .map(|k| k.0)
        .collect();
    Some(format!(
        "no kernel on this server would serve {} — {}",
        names.join(", "),
        if supporters.is_empty() {
            "no registered kernel supports it".to_string()
        } else {
            format!("keep or enable one of: {}", supporters.join(", "))
        }
    ))
}
