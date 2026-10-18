use crate::handlers::admin::icons::icon;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use maud::{Markup, html};

use super::super::helpers::{
    bad_request, error_resp, internal_error, not_found, render_page, theme_accent_lang,
    valid_server_id,
};
use crate::AppState;
use crate::http_util::{form_field, path_segment_encode};

pub(crate) async fn server_set_routing_policy(
    State(state): State<AppState>,
    Path(id): Path<String>,
    body: String,
) -> Response {
    let sid = vpnctl_core::ServerId(id.clone());
    if match state.inv.get_server(&sid).await {
        Ok(Some(_)) => false,
        Ok(None) => true,
        Err(error) => return internal_error(anyhow::Error::new(error)),
    } {
        return not_found(&format!("no such server '{id}'"));
    }
    let Some(role) = form_field(&body, "role") else {
        return bad_request("role field is required");
    };
    let role: vpnctl_inventory::ServerRole = match role.parse() {
        Ok(value) => value,
        Err(error) => return bad_request(&error.to_string()),
    };
    let Some(jump_field) = form_field(&body, "jump_via") else {
        return bad_request("jump_via field is required (blank means direct)");
    };
    let jump = Some(jump_field)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(vpnctl_core::ServerId);
    if let Err(error) = state
        .inv
        .set_server_routing_policy_as("admin", &sid, role, jump.as_ref())
        .await
    {
        return bad_request(&error.to_string());
    }
    Redirect::to(&format!(
        "/admin/servers/{}/setup#routing-policy",
        path_segment_encode(&id)
    ))
    .into_response()
}

pub(crate) async fn server_set_client_detour_via(
    State(state): State<AppState>,
    Path(id): Path<String>,
    body: String,
) -> Response {
    let sid = vpnctl_core::ServerId(id.clone());
    if match state.inv.get_server(&sid).await {
        Ok(Some(_)) => false,
        Ok(None) => true,
        Err(error) => return internal_error(anyhow::Error::new(error)),
    } {
        return not_found(&format!("no such server '{id}'"));
    }
    let Some(detour_field) = form_field(&body, "client_detour_via") else {
        return bad_request("client_detour_via field is required (blank means direct)");
    };
    let detour = Some(detour_field)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(vpnctl_core::ServerId);
    if let Err(error) = state
        .inv
        .set_client_detour_via_as("admin", &sid, detour.as_ref())
        .await
    {
        return bad_request(&error.to_string());
    }
    Redirect::to(&format!(
        "/admin/servers/{}/setup#client-detour",
        path_segment_encode(&id)
    ))
    .into_response()
}

pub(crate) async fn server_quick_add(State(state): State<AppState>, body: String) -> Response {
    let id: String = form_field(&body, "id")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    if !valid_server_id(&id) {
        return bad_request(&format!(
            "invalid server id '{id}' (allowed: 1-64 chars of A-Z a-z 0-9 . _ -; must start and end with alphanumeric; no consecutive dots)"
        ));
    }

    let address_raw: String = form_field(&body, "address")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let address = match crate::wizard::validate_address(&address_raw) {
        Ok(s) => s.to_string(),
        Err(why) => {
            return bad_request(&format!("invalid address: {why}"));
        }
    };

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
    let is_telegram_proxy = match state.inv.get_telegram_config().await {
        Ok(cfg) => cfg
            .and_then(|c| c.proxy_via_server_id)
            .is_some_and(|p| p == server_id_str),
        Err(e) => {
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
            a href=(back) style="color: var(--mute); text-decoration: none;" { (icon("arrow-left")) "back to server" }
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
                (icon("trash-2")) "delete forever"
            }
            a href=(back)
              class="ed-abtn ed-abtn--secondary ed-abtn--sm" {
                (icon("x")) "cancel"
            }
        }
    };
    Ok(render_page(&state, "servers", &theme, &accent, lang, body).await)
}

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
