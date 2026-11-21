use axum::extract::{Path, State};
use axum::response::{IntoResponse, Redirect, Response};

use super::super::helpers::{bad_request, internal_error, not_found};
use super::super::legacy::spawn_user_servers_redeploy;
use crate::AppState;
use crate::http_util::path_segment_encode;

pub(crate) async fn server_enable_protocol(
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

    if !server.enabled_protocols.contains(&pid) {
        if state
            .registry
            .protocol(&pid)
            .is_some_and(|protocol| protocol.is_retired())
        {
            return bad_request(&format!("protocol '{protocol_id_str}' is retired"));
        }
        if pid.0 == "dnstt" {
            let secrets = match state.inv.list_server_secrets(&sid).await {
                Ok(secrets) => secrets,
                Err(error) => return internal_error(anyhow::Error::new(error)),
            };
            let ports = match state.inv.get_reserved_ports(&sid).await {
                Ok(ports) => ports,
                Err(error) => return internal_error(anyhow::Error::new(error)),
            };
            if ports.contains(&53) {
                return bad_request("UDP/53 is reserved on this server");
            }
            if let Some(protocol) = state.registry.protocol(&pid)
                && let Err(error) =
                    protocol.validate_server(&vpnctl_core::RenderCtx::new(&server, &secrets))
            {
                return bad_request(&error.to_string());
            }
        }
        let mut after = server.clone();
        after.enabled_protocols.push(pid.clone());
        if let Some(msg) = super::kernels::unsupported_change(&state.registry, &server, &after) {
            return bad_request(&format!(
                "cannot enable protocol '{protocol_id_str}': {msg}"
            ));
        }
        for kid in &after.kernels {
            if let Some(kernel) = state.registry.kernel(kid)
                && let Err(e) = kernel.validate_server_support(&after)
            {
                return bad_request(&format!("cannot enable protocol '{protocol_id_str}': {e}"));
            }
        }
        if pid.0 == "vmess" {
            let secrets = match state.inv.list_server_secrets(&sid).await {
                Ok(secrets) => secrets,
                Err(error) => return internal_error(anyhow::Error::new(error)),
            };
            if let Err(error) = state.registry.validate_server(&after, &secrets) {
                return bad_request(&error.to_string());
            }
            let reserved = match state.inv.get_reserved_ports(&sid).await {
                Ok(ports) => ports,
                Err(error) => return internal_error(anyhow::Error::new(error)),
            };
            if state.registry.protocol(&pid).is_some_and(|protocol| {
                protocol
                    .effective_listen_ports(&secrets)
                    .iter()
                    .any(|(_, port)| reserved.contains(port))
            }) {
                return bad_request("The VMess TCP port is reserved on this server");
            }
        }
    }

    let inserted = match state.inv.add_server_protocol(&sid, &pid).await {
        Ok(n) => n,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };

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
