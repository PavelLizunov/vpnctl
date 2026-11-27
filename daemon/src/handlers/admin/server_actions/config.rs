use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};

use super::super::helpers::{bad_request, error_resp, internal_error, not_found};
use super::super::turnrelay::{self, ENTRY, RELAY_ID};
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
        .set_server_secrets_audited(
            &sid,
            "admin",
            "server.naive.set",
            &[("naive.domain", domain), ("naive.acme_email", email)],
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

    if let Err(e) = state
        .inv
        .set_server_secrets_audited(
            &sid,
            "admin",
            "server.vlessws.set",
            &[
                ("vlessws.domain", domain),
                ("vlessws.acme_email", email),
                ("vlessws.listen_port", port),
            ],
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
        && !vpnctl_protocols::is_valid_reality_sni(sni)
    {
        return bad_request("invalid REALITY handshake domain (expected a hostname)");
    }

    let fp_raw = form_field(&body, "fp");
    let fp = fp_raw.as_deref().map(str::trim);
    if let Some(fp) = fp
        && !fp.is_empty()
        && !vpnctl_protocols::is_valid_reality_fp(fp)
    {
        return bad_request("invalid REALITY uTLS fingerprint");
    }

    let handshake_server_raw = form_field(&body, "handshake_server");
    let handshake_server = handshake_server_raw.as_deref().map(str::trim);
    if let Some(hs) = handshake_server
        && !hs.is_empty()
        && !vpnctl_protocols::is_valid_reality_handshake_server(hs)
    {
        return bad_request("invalid REALITY handshake server (expected a hostname or IP)");
    }

    let handshake_port_raw = form_field(&body, "handshake_port");
    let handshake_port = handshake_port_raw.as_deref().map(str::trim);
    if let Some(hp) = handshake_port
        && !hp.is_empty()
        && !matches!(hp.parse::<u16>(), Ok(p) if p != 0)
    {
        return bad_request("invalid REALITY handshake port (1..=65535)");
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
    if let Some(fp) = fp {
        if !fp.is_empty() || candidate.contains_key("vless.fp") {
            values.push(("vless.fp", fp));
        }
        if fp.is_empty() {
            candidate.remove("vless.fp");
        } else {
            candidate.insert("vless.fp".to_string(), fp.to_string());
        }
    }
    if let Some(hs) = handshake_server {
        if !hs.is_empty() || candidate.contains_key("vless.handshake_server") {
            values.push(("vless.handshake_server", hs));
        }
        if hs.is_empty() {
            candidate.remove("vless.handshake_server");
        } else {
            candidate.insert("vless.handshake_server".to_string(), hs.to_string());
        }
    }
    if let Some(hp) = handshake_port {
        if !hp.is_empty() || candidate.contains_key("vless.handshake_port") {
            values.push(("vless.handshake_port", hp));
        }
        if hp.is_empty() {
            candidate.remove("vless.handshake_port");
        } else {
            candidate.insert("vless.handshake_port".to_string(), hp.to_string());
        }
    }
    if let Err(e) = state.registry.validate_server(&server, &candidate) {
        return bad_request(&format!("{e}"));
    }

    if !values.is_empty()
        && let Err(e) = state
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

pub(crate) async fn server_set_quic_tls_config(
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
    if !server
        .enabled_protocols
        .iter()
        .any(|p| matches!(p.0.as_str(), "tuic-v5" | "hysteria2"))
    {
        return bad_request("TUIC or Hysteria2 is not enabled on this server");
    }

    let sni_raw = form_field(&body, "server_name").unwrap_or_default();
    let sni = sni_raw.trim();
    if !sni.is_empty() && !vpnctl_protocols::is_valid_reality_sni(sni) {
        return bad_request("invalid QUIC TLS server_name (expected a hostname)");
    }

    let candidate = match state.inv.list_server_secrets(&sid).await {
        Ok(s) => s,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    let mut values = Vec::new();
    if !sni.is_empty() || candidate.contains_key("tls.server_name") {
        values.push(("tls.server_name", sni));
    }
    if !values.is_empty()
        && let Err(e) = state
            .inv
            .set_server_secrets_audited(&sid, "admin", "server.quic_tls.set", &values)
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

pub(crate) async fn server_set_new_server_bandwidth_default(
    Path(server_id): Path<String>,
    State(state): State<AppState>,
) -> Response {
    use crate::boosty_bandwidth::{POLICY_KEY, TierPolicy};
    use vpnctl_kernels::{USER_BANDWIDTH_KEY, USER_BANDWIDTH_MAX_MBPS};

    let sid = vpnctl_core::ServerId(server_id.clone());
    match state.inv.get_server(&sid).await {
        Ok(Some(server)) if server.kernels.iter().any(|kernel| kernel.0 == "sing-box") => {}
        Ok(Some(_)) => return bad_request("per-user speed requires the sing-box kernel"),
        Ok(None) => return not_found(&format!("no such server '{server_id}'")),
        Err(error) => return internal_error(anyhow::Error::new(error)),
    }
    let secrets = match state.inv.list_server_secrets(&sid).await {
        Ok(secrets) => secrets,
        Err(error) => return internal_error(anyhow::Error::new(error)),
    };
    let mbps = secrets
        .get(USER_BANDWIDTH_KEY)
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| (1..=USER_BANDWIDTH_MAX_MBPS).contains(value));
    let Some((mbps, policy)) = mbps.zip(
        secrets
            .get(POLICY_KEY)
            .filter(|json| TierPolicy::from_saved(json).is_some()),
    ) else {
        return bad_request("Apply Boosty rates on this node before making them the default");
    };
    if let Err(error) = state
        .inv
        .set_new_server_bandwidth_default_as("admin", mbps, policy)
        .await
    {
        return internal_error(anyhow::Error::new(error));
    }
    Redirect::to(&format!(
        "/admin/servers/{}/protocols#user-bandwidth",
        path_segment_encode(&server_id)
    ))
    .into_response()
}

pub(crate) async fn server_set_user_bandwidth(
    Path(server_id): Path<String>,
    State(state): State<AppState>,
    body: String,
) -> Response {
    use crate::boosty_bandwidth::{PENDING_KEY, POLICY_KEY, Roster, TierPolicy};
    use vpnctl_kernels::{
        USER_BANDWIDTH_KEY, USER_BANDWIDTH_MAX_MBPS, USER_BANDWIDTH_OVERRIDES_KEY,
    };

    let Some(rate) = form_field(&body, "mbps")
        .and_then(|value| value.trim().parse::<u32>().ok())
        .filter(|rate| *rate <= USER_BANDWIDTH_MAX_MBPS)
    else {
        return bad_request(&format!(
            "speed must be an integer in 0..={USER_BANDWIDTH_MAX_MBPS} Mbit/s"
        ));
    };
    let sid = vpnctl_core::ServerId(server_id.clone());
    let server = match state.inv.get_server(&sid).await {
        Ok(Some(server)) => server,
        Ok(None) => return not_found(&format!("no such server '{server_id}'")),
        Err(error) => return internal_error(anyhow::Error::new(error)),
    };
    if !server.kernels.iter().any(|kernel| kernel.0 == "sing-box") {
        return bad_request("per-user speed requires the sing-box kernel on this server");
    }
    let mut policy = TierPolicy::default();
    let mut overrides = std::collections::BTreeMap::new();
    if let Some(expected_blog) = form_field(&body, "boosty_blog") {
        if rate == 0 {
            return bad_request("Boosty tiers require a positive default speed");
        }
        for field in body
            .split('&')
            .filter_map(|field| field.strip_prefix("tier_"))
        {
            let Some((id, value)) = field.split_once('=') else {
                return bad_request("invalid Boosty tier setting");
            };
            let value = crate::http_util::decode_form_value(value);
            if value.trim().is_empty() {
                continue;
            }
            let (Ok(id), Ok(mbps)) = (id.parse::<i64>(), value.trim().parse::<u32>()) else {
                return bad_request("invalid Boosty tier speed");
            };
            if id <= 0
                || !(1..=USER_BANDWIDTH_MAX_MBPS).contains(&mbps)
                || policy.levels.insert(id, mbps).is_some()
            {
                return bad_request("invalid Boosty tier speed");
            }
        }
        let roster = match Roster::fetch(&state.boosty_roster_url).await {
            Ok(roster) => roster,
            Err(issue) => {
                tracing::warn!(target: "vpnctld::boosty_bandwidth", ?issue, "could not apply Boosty rates");
                return error_resp(StatusCode::SERVICE_UNAVAILABLE, &issue.to_string());
            }
        };
        if roster.blog != expected_blog {
            return bad_request(
                "The active Boosty account changed. Reload the Protocols tab and verify the levels.",
            );
        }
        policy.blog.clone_from(&roster.blog);
        overrides = match roster.inventory_overrides(&state.inv, &policy, rate).await {
            Ok(overrides) => overrides,
            Err(error) => return internal_error(anyhow::Error::new(error)),
        };
    }
    let value = rate.to_string();
    let policy = match serde_json::to_string(&policy) {
        Ok(policy) => policy,
        Err(error) => return internal_error(anyhow::Error::new(error)),
    };
    let overrides = match serde_json::to_string(&overrides) {
        Ok(overrides) => overrides,
        Err(error) => return internal_error(anyhow::Error::new(error)),
    };
    let mut values = vec![
        (USER_BANDWIDTH_KEY, value.as_str()),
        (POLICY_KEY, policy.as_str()),
        (USER_BANDWIDTH_OVERRIDES_KEY, overrides.as_str()),
    ];
    match state.inv.get_server_secret(&sid, PENDING_KEY).await {
        Ok(Some(value)) if value == "1" => values.push((PENDING_KEY, "")),
        Ok(_) => {}
        Err(error) => return internal_error(anyhow::Error::new(error)),
    }
    let changed = match state
        .inv
        .set_server_secrets_audited(&sid, "admin", "server.user_bandwidth.set", &values)
        .await
    {
        Ok(changed) => changed,
        Err(error) => return internal_error(anyhow::Error::new(error)),
    };
    if changed {
        super::super::legacy::spawn_user_servers_redeploy(
            &state,
            vec![server],
            server_id.clone(),
            "server.user_bandwidth.set",
        );
    }
    Redirect::to(&format!(
        "/admin/servers/{}/protocols#user-bandwidth",
        path_segment_encode(&server_id)
    ))
    .into_response()
}

pub(crate) async fn server_set_ss2022_mode(
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
    let pid = vpnctl_core::ProtocolId("shadowsocks-2022".into());
    if !server.enabled_protocols.contains(&pid) {
        return bad_request("Shadowsocks-2022 is not enabled on this server");
    }
    let mode = form_field(&body, "mode").unwrap_or_default();
    if !matches!(mode.as_str(), "shared" | "multi-user") {
        return bad_request("ss2022.mode must be shared or multi-user");
    }
    let mut secrets = match state.inv.list_server_secrets(&sid).await {
        Ok(s) => s,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    let changed = secrets.get("ss2022.mode").map_or("shared", String::as_str) != mode.as_str();
    secrets.insert("ss2022.mode".into(), mode.clone());
    let Some(protocol) = state.registry.protocol(&pid) else {
        return bad_request("Shadowsocks-2022 is not registered");
    };
    if let Err(e) = protocol.validate_server(&vpnctl_core::RenderCtx::new(&server, &secrets)) {
        return bad_request(&e.to_string());
    }
    if changed
        && let Err(e) = state
            .inv
            .set_server_secrets_audited(
                &sid,
                "admin",
                "server.secret.set",
                &[("ss2022.mode", mode.as_str())],
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

pub(crate) async fn server_set_dnstt_config(
    Path(server_id): Path<String>,
    State(state): State<AppState>,
    body: String,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id.clone());
    let server = match state.inv.get_server(&sid).await {
        Ok(Some(server)) => server,
        Ok(None) => return not_found("DNSTT server not found"),
        Err(error) => return internal_error(anyhow::Error::new(error)),
    };
    let Some(protocol) = state
        .registry
        .protocol(&vpnctl_core::ProtocolId("dnstt".into()))
    else {
        return bad_request("DNSTT is not registered");
    };
    let domain = form_field(&body, "domain")
        .unwrap_or_default()
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let resolver = form_field(&body, "resolver")
        .unwrap_or_default()
        .trim()
        .to_owned();
    let values = [
        ("dnstt.domain", domain.as_str()),
        ("dnstt.resolver", resolver.as_str()),
    ];
    let mut secrets = match state.inv.list_server_secrets(&sid).await {
        Ok(secrets) => secrets,
        Err(error) => return internal_error(anyhow::Error::new(error)),
    };
    let changed = values
        .iter()
        .any(|(key, value)| secrets.get(*key).map(String::as_str) != Some(*value));
    secrets.extend(values.map(|(key, value)| (key.to_owned(), value.to_owned())));
    if let Err(error) = protocol.validate_server(&vpnctl_core::RenderCtx::new(&server, &secrets)) {
        return bad_request(&error.to_string());
    }
    if changed
        && let Err(error) = state
            .inv
            .set_server_secrets_audited(&sid, "admin", "server.dnstt.set", &values)
            .await
    {
        return internal_error(anyhow::Error::new(error));
    }
    Redirect::to(&format!(
        "/admin/servers/{}/protocols#dnstt",
        path_segment_encode(&server_id)
    ))
    .into_response()
}

pub(crate) async fn server_set_vmess_config(
    Path(server_id): Path<String>,
    State(state): State<AppState>,
    body: String,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id.clone());
    let server = match state.inv.get_server(&sid).await {
        Ok(Some(server)) => server,
        Ok(None) => return not_found("VMess server not found"),
        Err(error) => return internal_error(anyhow::Error::new(error)),
    };
    let vmess = vpnctl_core::ProtocolId("vmess".into());
    let Some(protocol) = state.registry.protocol(&vmess) else {
        return bad_request("VMess is not registered");
    };
    let domain = form_field(&body, "domain")
        .unwrap_or_default()
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let port = form_field(&body, "listen_port").unwrap_or_default();
    let port = if port.trim().is_empty() {
        "443"
    } else {
        port.trim()
    };
    let detour = form_field(&body, "detour_via").unwrap_or_default();
    let detour = detour.trim();
    if !detour.is_empty() {
        if detour == server_id {
            return bad_request("VMess entry must be a different server");
        }
        match state
            .inv
            .get_server(&vpnctl_core::ServerId(detour.into()))
            .await
        {
            Ok(Some(entry))
                if entry
                    .enabled_protocols
                    .contains(&vpnctl_core::ProtocolId("vless+reality".into())) => {}
            Ok(_) => return bad_request("VMess entry must have VLESS Reality enabled"),
            Err(error) => return internal_error(anyhow::Error::new(error)),
        }
    }

    let certificate = form_field(&body, "certificate").unwrap_or_default();
    let key = form_field(&body, "key").unwrap_or_default();
    if certificate.trim().is_empty() != key.trim().is_empty() {
        return bad_request("Provide both the VMess certificate chain and private key");
    }
    let mut values = vec![
        ("vmess.domain", domain.as_str()),
        ("vmess.listen_port", port),
        ("vmess.preferred_entry", detour),
    ];
    if !certificate.trim().is_empty() {
        values.extend([
            ("vmess.certificate", certificate.trim()),
            ("vmess.key", key.trim()),
        ]);
    }
    let mut candidate = match state.inv.list_server_secrets(&sid).await {
        Ok(secrets) => secrets,
        Err(error) => return internal_error(anyhow::Error::new(error)),
    };
    let changed = values
        .iter()
        .any(|(key, value)| candidate.get(*key).map(String::as_str) != Some(*value));
    candidate.extend(
        values
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string())),
    );
    if let Err(error) = protocol.validate_server(&vpnctl_core::RenderCtx::new(&server, &candidate))
    {
        return bad_request(&error.to_string());
    }
    if let Err(error) = state.registry.validate_server(&server, &candidate) {
        return bad_request(&error.to_string());
    }
    if !certificate.trim().is_empty() && !vmess_tls_pair_matches(certificate.trim(), key.trim()) {
        return bad_request("The VMess PEM certificate and private key must form a valid pair");
    }
    if server.enabled_protocols.contains(&vmess) {
        let reserved = match state.inv.get_reserved_ports(&sid).await {
            Ok(ports) => ports,
            Err(error) => return internal_error(anyhow::Error::new(error)),
        };
        if let Some((_, port)) = protocol
            .effective_listen_ports(&candidate)
            .into_iter()
            .find(|(_, port)| reserved.contains(port))
        {
            return bad_request(&format!("VMess TCP/{port} is reserved on this server"));
        }
    }
    if changed
        && let Err(error) = state
            .inv
            .set_server_secrets_audited(&sid, "admin", "server.vmess.set", &values)
            .await
    {
        return internal_error(anyhow::Error::new(error));
    }
    Redirect::to(&format!(
        "/admin/servers/{}/protocols#vmess",
        path_segment_encode(&server_id)
    ))
    .into_response()
}

pub(crate) async fn server_set_trusttunnel_config(
    Path(server_id): Path<String>,
    State(state): State<AppState>,
    body: String,
) -> Response {
    let setting = |key, default: &str| {
        form_field(&body, key).map_or_else(|| default.to_string(), |value| value.trim().to_string())
    };
    let port = setting("listen_port", "8444");
    let quic = setting("quic", "true");
    let client_quic = setting("client_quic", "false");
    let udp = setting("udp", "true");
    let domain = setting("domain", "")
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let sni = setting("sni", "");
    let certificate = setting("certificate", "");
    let key = setting("key", "");
    if certificate.is_empty() != key.is_empty() || (domain.is_empty() && !key.is_empty()) {
        return bad_request(
            "Provide the TrustTunnel TLS hostname, certificate chain, and private key together",
        );
    }
    let mut values = vec![
        ("trusttunnel.listen_port", port.as_str()),
        ("trusttunnel.quic", &quic),
        ("trusttunnel.client_quic", &client_quic),
        ("trusttunnel.udp", &udp),
    ];
    let mut remove = Vec::new();
    if sni.is_empty() {
        remove.push("trusttunnel.sni");
    } else {
        values.push(("trusttunnel.sni", &sni));
    }
    if domain.is_empty() {
        remove.extend([
            "trusttunnel.domain",
            "trusttunnel.certificate",
            "trusttunnel.key",
        ]);
    } else {
        values.push(("trusttunnel.domain", &domain));
        if !key.is_empty() {
            values.extend([
                ("trusttunnel.certificate", certificate.as_str()),
                ("trusttunnel.key", key.as_str()),
            ]);
        }
    }
    save_sing_box_protocol_config(&state, server_id, "trusttunnel", &values, &remove).await
}

pub(crate) async fn server_set_mieru_config(
    Path(server_id): Path<String>,
    State(state): State<AppState>,
    body: String,
) -> Response {
    let fields = [
        ("listen_port", "mieru.listen_port", "8445"),
        ("transport", "mieru.transport", "tcp"),
        ("multiplexing", "mieru.multiplexing", "middle"),
        ("handshake_mode", "mieru.handshake_mode", "standard"),
    ];
    let values = fields.map(|(field, key, default)| {
        (
            key,
            form_field(&body, field).unwrap_or_else(|| default.to_string()),
        )
    });
    let values = values.each_ref().map(|(key, value)| (*key, value.trim()));
    save_sing_box_protocol_config(&state, server_id, "mieru", &values, &[]).await
}

async fn save_sing_box_protocol_config(
    state: &AppState,
    server_id: String,
    protocol_id: &str,
    values: &[(&str, &str)],
    remove: &[&str],
) -> Response {
    let sid = vpnctl_core::ServerId(server_id);
    let pid = vpnctl_core::ProtocolId(protocol_id.into());
    let server = match state.inv.get_server(&sid).await {
        Ok(Some(server)) => server,
        Ok(None) => return not_found("server not found"),
        Err(error) => return internal_error(error.into()),
    };
    let Some(protocol) = state.registry.protocol(&pid) else {
        return bad_request("protocol is not registered");
    };
    let mut candidate = match state.inv.list_server_secrets(&sid).await {
        Ok(secrets) => secrets,
        Err(error) => return internal_error(error.into()),
    };
    candidate.extend(
        values
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string())),
    );
    for key in remove {
        candidate.remove(*key);
    }
    if let Err(error) = protocol.validate_server(&vpnctl_core::RenderCtx::new(&server, &candidate))
    {
        return bad_request(&error.to_string());
    }
    if server.enabled_protocols.contains(&pid)
        && let Err(error) = state.registry.validate_server(&server, &candidate)
    {
        return bad_request(&error.to_string());
    }
    if let Err(response) =
        super::protocols::check_protocol_reserved_ports(state, &sid, &pid, &candidate).await
    {
        return response;
    }
    if let Err(error) = state
        .inv
        .update_server_secrets_audited(
            &sid,
            "admin",
            &format!("server.{protocol_id}.set"),
            values,
            remove,
        )
        .await
    {
        return internal_error(error.into());
    }
    Redirect::to(&format!(
        "/admin/servers/{}/protocols#{protocol_id}",
        path_segment_encode(&sid.0)
    ))
    .into_response()
}

pub(crate) async fn server_set_turnrelay_config(
    Path(server_id): Path<String>,
    State(state): State<AppState>,
    body: String,
) -> Response {
    let _topology = turnrelay::MUTATIONS.lock().await;
    let sid = vpnctl_core::ServerId(server_id.clone());
    let server = match state.inv.get_server(&sid).await {
        Ok(Some(server)) => server,
        Ok(None) => return not_found("TurnRelay server not found"),
        Err(error) => return internal_error(anyhow::Error::new(error)),
    };
    let pid = vpnctl_core::ProtocolId("turnrelay".into());
    let Some(protocol) = state.registry.protocol(&pid) else {
        return bad_request("TurnRelay is not registered");
    };
    let mut secrets = match state.inv.list_server_secrets(&sid).await {
        Ok(secrets) => secrets,
        Err(error) => return internal_error(anyhow::Error::new(error)),
    };

    let previous_entry = secrets.get(RELAY_ID).is_some_and(|id| !id.is_empty());
    let selected_entry = form_field(&body, "relay_server_id");
    let selected_entry = selected_entry.as_deref().map(str::trim);
    let port = form_field(&body, "listen_port")
        .unwrap_or_default()
        .trim()
        .to_owned();
    if !port.is_empty() && !matches!(port.parse::<u16>(), Ok(port) if port != 0) {
        return bad_request("invalid TurnRelay UDP port (1..=65535)");
    }
    let mode = form_field(&body, "mode").unwrap_or_default();
    let mode = match mode.trim() {
        "" => vpnctl_protocols::TURNRELAY_DEFAULT_MODE,
        value @ ("dtls" | "srtp") => value,
        _ => return bad_request("invalid TurnRelay mode (expected dtls or srtp)"),
    };
    let turn_server = form_field(&body, "turn_server")
        .unwrap_or_default()
        .trim()
        .to_owned();
    let turn_username = form_field(&body, "turn_username")
        .unwrap_or_default()
        .trim()
        .to_owned();
    let turn_password_input = form_field(&body, "turn_password").unwrap_or_default();
    let turn_password = if turn_password_input.trim().is_empty() {
        secrets
            .get("turnrelay.turn_password")
            .cloned()
            .unwrap_or_default()
    } else {
        turn_password_input.trim().to_owned()
    };
    let connections = form_field(&body, "connections").unwrap_or_default();
    let connections = match connections.trim() {
        "" => vpnctl_protocols::TURNRELAY_DEFAULT_CONNECTIONS.to_string(),
        value => match value.parse::<u8>() {
            Ok(connections) if (1..=60).contains(&connections) => connections.to_string(),
            _ => return bad_request("invalid TurnRelay connections (expected 1..=60)"),
        },
    };
    let udp = if form_field(&body, "udp")
        .is_some_and(|value| matches!(value.trim(), "true" | "on" | "1" | "yes"))
    {
        "true"
    } else {
        "false"
    };
    let publish = form_field(&body, "publish")
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if !valid_turnrelay_publish(&publish) {
        return bad_request("invalid TurnRelay publish list (use vless+reality or all)");
    }
    let publish_targets = form_field(&body, "publish_targets")
        .unwrap_or_default()
        .trim()
        .to_owned();
    if !valid_turnrelay_publish_targets(&publish_targets) {
        return bad_request("invalid TurnRelay publish targets");
    }

    let mut values = vec![
        ("turnrelay.listen_port", port.as_str()),
        ("turnrelay.mode", mode),
        ("turnrelay.turn_server", turn_server.as_str()),
        ("turnrelay.turn_username", turn_username.as_str()),
        ("turnrelay.turn_password", turn_password.as_str()),
        ("turnrelay.connections", connections.as_str()),
        ("turnrelay.udp", udp),
        ("turnrelay.publish", publish.as_str()),
        ("turnrelay.publish_targets", publish_targets.as_str()),
    ];
    if previous_entry {
        values.push((RELAY_ID, ""));
    }
    secrets.extend(
        values
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned())),
    );
    if let Some(entry) = selected_entry.filter(|entry| !entry.is_empty()) {
        if let Err(response) =
            turnrelay::wire_exit(&state, &server, &mut secrets, Some(entry)).await
        {
            return response;
        }
        values.retain(|(key, _)| !turnrelay::WIRING_KEYS.contains(key));
        values.extend(turnrelay::wiring_values(&secrets));
    }
    if let Err(error) = protocol.validate_server(&vpnctl_core::RenderCtx::new(&server, &secrets)) {
        return bad_request(&error.to_string());
    }
    if let Err(error) = state.registry.validate_server(&server, &secrets) {
        return bad_request(&error.to_string());
    }
    if server.enabled_protocols.contains(&pid) {
        let reserved = match state.inv.get_reserved_ports(&sid).await {
            Ok(ports) => ports,
            Err(error) => return internal_error(anyhow::Error::new(error)),
        };
        if let Some((_, port)) = protocol
            .effective_listen_ports(&secrets)
            .into_iter()
            .find(|(_, port)| reserved.contains(port))
        {
            return bad_request(&format!("TurnRelay UDP/{port} is reserved on this server"));
        }
    }
    let changed = match state
        .inv
        .set_server_secrets_audited(&sid, "admin", "server.turnrelay.set", &values)
        .await
    {
        Ok(changed) => changed,
        Err(error) => return internal_error(error.into()),
    };
    let redeploy = if changed
        && server.enabled_protocols.contains(&pid)
        && (previous_entry || selected_entry.is_some_and(|entry| !entry.is_empty()))
    {
        vec![server]
    } else {
        Vec::new()
    };
    if let Err(response) = turnrelay::sync_turnrelay_relay_allowlists(
        &state,
        &sid,
        false,
        redeploy,
        "server.turnrelay.set",
    )
    .await
    {
        return response;
    }
    Redirect::to(&format!(
        "/admin/servers/{}/protocols#turnrelay",
        path_segment_encode(&server_id)
    ))
    .into_response()
}

pub(crate) async fn server_set_turnrelay_relay_config(
    Path(server_id): Path<String>,
    State(state): State<AppState>,
    body: String,
) -> Response {
    let _topology = turnrelay::MUTATIONS.lock().await;
    let sid = vpnctl_core::ServerId(server_id.clone());
    let server = match state.inv.get_server(&sid).await {
        Ok(Some(server)) => server,
        Ok(None) => return not_found("TurnRelay entry server not found"),
        Err(error) => return internal_error(error.into()),
    };
    let pid = vpnctl_core::ProtocolId(ENTRY.into());
    let Some(protocol) = state.registry.protocol(&pid) else {
        return bad_request("TurnRelay entry is not registered");
    };
    if !server.kernels.iter().any(|id| id.0 == ENTRY) && !server.enabled_protocols.contains(&pid) {
        return bad_request("Enable the TurnRelay entry kernel before configuring it");
    }
    let mut secrets = match state.inv.list_server_secrets(&sid).await {
        Ok(secrets) => secrets,
        Err(error) => return internal_error(error.into()),
    };
    let input = form_field(&body, "listen_port").unwrap_or_default();
    let port = if input.trim().is_empty() {
        vpnctl_protocols::TURNRELAY_RELAY_PORT
    } else if let Ok(port @ 1..=65535) = input.trim().parse::<u16>() {
        port
    } else {
        return bad_request("Invalid TurnRelay entry port (expected 1..=65535)");
    };
    let reserved = match state.inv.get_reserved_ports(&sid).await {
        Ok(ports) => ports,
        Err(error) => return internal_error(error.into()),
    };
    if reserved.contains(&port) {
        return bad_request("TurnRelay entry port is reserved on this server");
    }
    let port_setting = port.to_string();
    secrets.insert(turnrelay::PORT.into(), port_setting.clone());
    if let Err(error) = protocol
        .validate_server(&vpnctl_core::RenderCtx::new(&server, &secrets))
        .and_then(|_| state.registry.validate_server(&server, &secrets))
    {
        return bad_request(&error.to_string());
    }
    let changed = match state
        .inv
        .set_server_secrets_audited(
            &sid,
            "admin",
            "server.turnrelay_relay.set",
            &[(turnrelay::PORT, &port_setting)],
        )
        .await
    {
        Ok(changed) => changed,
        Err(error) => return internal_error(error.into()),
    };
    let redeploy = if changed && server.enabled_protocols.contains(&pid) {
        vec![server]
    } else {
        Vec::new()
    };
    if let Err(response) = turnrelay::sync_turnrelay_relay_allowlists(
        &state,
        &sid,
        true,
        redeploy,
        "server.turnrelay_relay.set",
    )
    .await
    {
        return response;
    }
    Redirect::to(&format!(
        "/admin/servers/{}/protocols#turnrelay-relay",
        path_segment_encode(&server_id)
    ))
    .into_response()
}

fn valid_turnrelay_publish(value: &str) -> bool {
    value.is_empty()
        || value.split(',').all(|token| {
            matches!(
                token.trim(),
                "" | "vless+reality" | "all" | "true" | "1" | "yes"
            )
        })
}

fn valid_turnrelay_publish_targets(value: &str) -> bool {
    value.is_empty()
        || value.split(',').all(|token| {
            let token = token.trim();
            token == "*"
                || (!token.is_empty()
                    && token.len() <= 64
                    && !token
                        .chars()
                        .any(|character| character.is_control() || character.is_whitespace()))
        })
}

fn vmess_tls_pair_matches(certificate: &str, key: &str) -> bool {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let Ok(chain) =
        CertificateDer::pem_slice_iter(certificate.as_bytes()).collect::<Result<Vec<_>, _>>()
    else {
        return false;
    };
    let Ok(key) = PrivateKeyDer::from_pem_slice(key.as_bytes()) else {
        return false;
    };
    let provider = rustls::crypto::ring::default_provider();
    rustls::sign::CertifiedKey::from_der(chain, key, &provider)
        .is_ok_and(|pair| pair.keys_match().is_ok())
}
