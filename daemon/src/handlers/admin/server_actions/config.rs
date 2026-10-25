use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};

use super::super::helpers::{bad_request, error_resp, internal_error, not_found};
use crate::AppState;
use crate::http_util::{form_field, path_segment_encode};

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

    let mode = form_field(&body, "mode").unwrap_or_default();
    let fingerprint_in = form_field(&body, "fingerprint").unwrap_or_default();

    let (fp, source) = match mode.as_str() {
        "keyscan" => {
            if let Err(reason) = crate::wizard::validate_address(&server.address) {
                return bad_request(&format!(
                    "server '{server_id}' has an address that fails the validator ({reason}); \
                         fix it in the inventory before running auto-detect"
                ));
            }
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

    let previous = server.trusted_host_fingerprint.clone();
    if let Err(e) = state.inv.update_trusted_fingerprint(&sid, &fp).await {
        return internal_error(anyhow::Error::new(e));
    }
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

    const ILLEGAL: [char; 5] = ['\n', '\r', ' ', '{', '}'];
    if domain.is_empty() {
        return bad_request("naive domain is required");
    }
    if domain.chars().count() > 253 || domain.contains(ILLEGAL) {
        return bad_request("invalid naive domain");
    }
    if email.chars().count() > 254 || email.contains(ILLEGAL) {
        return bad_request("invalid naive ACME email");
    }

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

    const ILLEGAL: [char; 5] = ['\n', '\r', ' ', '{', '}'];
    if domain.is_empty() {
        return bad_request("vless-ws domain is required");
    }
    if domain.chars().count() > 253 || domain.contains(ILLEGAL) {
        return bad_request("invalid vless-ws domain");
    }
    if email.chars().count() > 254 || email.contains(ILLEGAL) {
        return bad_request("invalid vless-ws ACME email");
    }
    if !port.is_empty() && !matches!(port.parse::<u16>(), Ok(p) if p != 0) {
        return bad_request("invalid vless-ws front port (1..=65535)");
    }

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

    for (key, val) in [
        ("vlessws.domain", domain),
        ("vlessws.acme_email", email),
        ("vlessws.listen_port", port),
    ] {
        if let Err(e) = state.inv.set_server_secret(&sid, key, val).await {
            return internal_error(anyhow::Error::new(e));
        }
    }
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

    let sni_raw = form_field(&body, "sni");
    let sni = sni_raw.as_deref().map(str::trim);
    if let Some(sni) = sni
        && (sni.is_empty()
            || sni.len() > 253
            || sni.parse::<std::net::IpAddr>().is_ok()
            || !sni.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label.starts_with(|c: char| c.is_ascii_alphanumeric())
                    && label.ends_with(|c: char| c.is_ascii_alphanumeric())
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            }))
    {
        return bad_request("invalid REALITY handshake domain (expected a hostname)");
    }

    let mut candidate = match state.inv.list_server_secrets(&sid).await {
        Ok(s) => s,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    let mut values = Vec::new();
    if !port.is_empty() || candidate.contains_key("vless.listen_port") {
        values.push(("vless.listen_port", port));
    }
    if port.is_empty() {
        candidate.remove("vless.listen_port");
    } else {
        candidate.insert("vless.listen_port".to_string(), port.to_string());
    }
    if let Some(sni) = sni {
        candidate.insert("vless.sni".to_string(), sni.to_string());
        values.push(("vless.sni", sni));
    }
    if let Err(e) = state.registry.validate_server(&server, &candidate) {
        return bad_request(&format!("{e}"));
    }

    if let Err(e) = state
        .inv
        .set_server_secrets_audited(&sid, "admin", "server.reality.set", &values)
        .await
    {
        return internal_error(anyhow::Error::new(e));
    }

    Redirect::to(&format!(
        "/admin/servers/{}/protocols",
        path_segment_encode(&server_id)
    ))
    .into_response()
}

pub(crate) async fn server_rotate_hysteria2_obfs(
    Path(server_id): Path<String>,
    State(state): State<AppState>,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id.clone());
    let server = match state.inv.get_server(&sid).await {
        Ok(Some(s)) => s,
        Ok(None) => return not_found(&format!("no such server '{server_id}'")),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    if !server.enabled_protocols.iter().any(|p| p.0 == "hysteria2") {
        return bad_request("Hysteria2 is not enabled on this server");
    }
    let password = match vpnctl_crypto::gen_password(24) {
        Ok(password) => password,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    if let Err(e) = state
        .inv
        .set_server_secrets_audited(
            &sid,
            "admin",
            "server.secret.set",
            &[("hysteria2.obfs.password", password.as_str())],
        )
        .await
    {
        return internal_error(anyhow::Error::new(e));
    }
    Redirect::to(&format!(
        "/admin/servers/{}/protocols",
        path_segment_encode(&server_id)
    ))
    .into_response()
}

pub(crate) async fn server_set_display_name(
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

    let name = form_field(&body, "display_name").unwrap_or_default();
    if name.chars().count() > 64 {
        return bad_request("display name too long (max 64 characters)");
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

pub(crate) async fn server_set_reserved_ports(
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
