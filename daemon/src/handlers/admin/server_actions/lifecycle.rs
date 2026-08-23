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
    // literal whitespace, so a paste like `\"  vps-de1  \"` and
    // `\"%20vps-de1%20\"` both produce `\"vps-de1\"`.
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
