use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};

use super::super::helpers::{bad_request, error_resp, internal_error, not_found};
use crate::AppState;
use crate::http_util::{form_field, path_segment_encode};

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
    Path(server_id): Path<String>,
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
    Path(server_id): Path<String>,
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
    Path(server_id): Path<String>,
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
    Path(server_id): Path<String>,
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
    Path(server_id): Path<String>,
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
    Path(server_id): Path<String>,
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
    Path(server_id): Path<String>,
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
    Path(server_id): Path<String>,
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
