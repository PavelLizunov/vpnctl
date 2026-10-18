use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use vpnctl_core::url_host::host_for_url;
use vpnctl_core::{RenderCtx, User, UserId};
use vpnctl_protocols::VLESS_PACKET_ENCODING;

use super::compat::server_display_label;
use crate::app::AppState;

pub(crate) const NINITUX_QUOTE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

#[allow(clippy::too_many_arguments)]
pub(crate) fn render_vless_uri(
    server_ip: &str,
    port: u16,
    sni: &str,
    pbk: &str,
    sid: &str,
    client_uuid: &str,
    server_tag: &str,
    client_name: &str,
) -> String {
    let pbk_e = utf8_percent_encode(pbk, NINITUX_QUOTE);
    let sni_e = utf8_percent_encode(sni, NINITUX_QUOTE);
    let sid_e = utf8_percent_encode(sid, NINITUX_QUOTE);
    let params = format!(
        "encryption=none&type=tcp&security=reality&pbk={pbk_e}&fp=randomized&sni={sni_e}&sid={sid_e}&spx=%2F&flow=xtls-rprx-vision&packetEncoding={VLESS_PACKET_ENCODING}"
    );

    let label = format!("{server_tag} VLESS ~{client_name}");
    let fragment = utf8_percent_encode(&label, NINITUX_QUOTE);

    let host = host_for_url(server_ip);

    format!("vless://{client_uuid}@{host}:{port}?{params}#{fragment}")
}

pub(crate) async fn collect_vless_uris_for_user(
    state: &AppState,
    user_id: &UserId,
    client_name: &str,
    detour_capable: bool,
) -> Result<Vec<String>, String> {
    let servers = state
        .inv
        .subscription_servers_for_user(user_id)
        .await
        .map_err(|e| format!("subscription_servers_for_user: {e}"))?;

    struct RenderedServer {
        server_id: vpnctl_core::ServerId,
        detour_via: Option<vpnctl_core::ServerId>,
        base_uri: String,
    }

    let mut rendered: Vec<RenderedServer> = Vec::with_capacity(servers.len());
    let vless_id = vpnctl_core::ProtocolId("vless+reality".to_string());
    for server in &servers {
        if state
            .inv
            .is_server_auto_suppressed(&server.id)
            .await
            .unwrap_or(false)
        {
            continue;
        }

        let detour_via = state
            .inv
            .client_detour_via(&server.id)
            .await
            .map_err(|e| format!("client_detour_via: {e}"))?;

        let visible = state
            .inv
            .visible_protocols_for_subscription(user_id, &server.id)
            .await
            .map_err(|e| format!("visible_protocols_for_subscription: {e}"))?;
        if !visible.contains(&vless_id) {
            continue;
        }

        let secrets = state
            .inv
            .list_server_secrets(&server.id)
            .await
            .map_err(|e| format!("list_server_secrets: {e}"))?;
        let pbk = match secrets.get("vless.public_key") {
            Some(v) => v.as_str(),
            None => continue,
        };
        let sid = match secrets.get("vless.short_id") {
            Some(v) => v.as_str(),
            None => continue,
        };
        let sni = secrets
            .get("vless.sni")
            .map(String::as_str)
            .unwrap_or(vpnctl_protocols::DEFAULT_REALITY_SNI);

        let client_uuid = match state
            .inv
            .client_uuid_for(user_id, &server.id)
            .await
            .map_err(|e| format!("client_uuid_for: {e}"))?
        {
            Some(u) => u,
            None => continue,
        };

        let port: u16 = vpnctl_protocols::reality_listen_port(&secrets);

        let custom_name = state
            .inv
            .server_display_name(&server.id)
            .await
            .map_err(|e| format!("server_display_name: {e}"))?;
        let server_display = server_display_label(&server.id.0, custom_name.as_deref());
        let base_uri = render_vless_uri(
            &server.address,
            port,
            sni,
            pbk,
            sid,
            &client_uuid,
            &server_display,
            client_name,
        );

        rendered.push(RenderedServer {
            server_id: server.id.clone(),
            detour_via,
            base_uri,
        });
    }

    if !detour_capable {
        let uris = rendered
            .into_iter()
            .filter(|r| r.detour_via.is_none())
            .map(|r| r.base_uri)
            .collect();
        return Ok(uris);
    }

    let direct_entry_ids: std::collections::HashSet<vpnctl_core::ServerId> = rendered
        .iter()
        .filter(|r| r.detour_via.is_none())
        .map(|r| r.server_id.clone())
        .collect();

    let valid_targets: std::collections::HashSet<vpnctl_core::ServerId> = rendered
        .iter()
        .filter_map(|r| {
            r.detour_via
                .as_ref()
                .filter(|entry_id| {
                    *entry_id != &r.server_id && direct_entry_ids.contains(*entry_id)
                })
                .map(|_| r.server_id.clone())
        })
        .collect();

    let valid_entries: std::collections::HashSet<vpnctl_core::ServerId> = rendered
        .iter()
        .filter_map(|r| {
            r.detour_via
                .as_ref()
                .filter(|entry_id| {
                    *entry_id != &r.server_id && direct_entry_ids.contains(*entry_id)
                })
                .cloned()
        })
        .collect();

    let mut uris = Vec::with_capacity(rendered.len());
    for item in rendered {
        if let Some(entry_id) = &item.detour_via {
            if !valid_targets.contains(&item.server_id) {
                continue;
            }
            let outbound_enc = utf8_percent_encode(&item.server_id.0, NINITUX_QUOTE).to_string();
            let detour_enc = utf8_percent_encode(&entry_id.0, NINITUX_QUOTE).to_string();
            let uri_with_outbound = add_query_param(&item.base_uri, "outbound", &outbound_enc);
            let final_uri = add_query_param(&uri_with_outbound, "detour", &detour_enc);
            uris.push(final_uri);
        } else if valid_entries.contains(&item.server_id) {
            let outbound_enc = utf8_percent_encode(&item.server_id.0, NINITUX_QUOTE).to_string();
            let final_uri = add_query_param(&item.base_uri, "outbound", &outbound_enc);
            uris.push(final_uri);
        } else {
            uris.push(item.base_uri);
        }
    }

    Ok(uris)
}

pub(crate) async fn collect_extra_protocol_uris(
    state: &AppState,
    user: &User,
    pid: &vpnctl_core::ProtocolId,
    label_tag: &str,
    require_secret: Option<&str>,
) -> Result<Vec<String>, String> {
    let Some(proto) = state.registry.protocol(pid) else {
        return Ok(Vec::new());
    };

    let servers = state
        .inv
        .subscription_servers_for_user(&user.id)
        .await
        .map_err(|e| format!("subscription_servers_for_user: {e}"))?;

    let naive_pid = vpnctl_core::ProtocolId("naive".to_string());
    let hy2_pid = vpnctl_core::ProtocolId("hysteria2".to_string());
    let mut uris: Vec<String> = Vec::new();
    for server in &servers {
        if state
            .inv
            .is_server_auto_suppressed(&server.id)
            .await
            .unwrap_or(false)
        {
            continue;
        }
        if state
            .inv
            .client_detour_via(&server.id)
            .await
            .map_err(|e| format!("client_detour_via: {e}"))?
            .is_some()
        {
            continue;
        }
        let visible = state
            .inv
            .visible_protocols_for_subscription(&user.id, &server.id)
            .await
            .map_err(|e| format!("visible_protocols_for_subscription: {e}"))?;
        if !visible.contains(pid) {
            continue;
        }
        let secrets = state
            .inv
            .list_server_secrets(&server.id)
            .await
            .map_err(|e| format!("list_server_secrets: {e}"))?;
        if let Some(req) = require_secret {
            if !secrets.contains_key(req) {
                continue;
            }
        }
        let ctx = RenderCtx::new(server, &secrets);
        match proto.share_link(&ctx, user) {
            Ok(link) => {
                let custom = state
                    .inv
                    .server_display_name(&server.id)
                    .await
                    .ok()
                    .flatten();
                let label = server_display_label(&server.id.0, custom.as_deref());
                let fragment = format!("{label} {label_tag} ~{}", user.id.0);
                let encoded = utf8_percent_encode(&fragment, NINITUX_QUOTE).to_string();
                let mut out = relabel_uri_fragment(&link, &encoded);
                if (pid == &naive_pid || pid == &hy2_pid)
                    && visible.contains(&naive_pid)
                    && visible.contains(&hy2_pid)
                    && state
                        .inv
                        .is_server_udp_pair_enabled(&server.id)
                        .await
                        .unwrap_or(false)
                {
                    let pair = utf8_percent_encode(&server.id.0, NINITUX_QUOTE).to_string();
                    out = add_query_param(&out, "pair", &pair);
                }
                uris.push(out);
            }
            Err(e) => {
                tracing::warn!(
                    target = "vpnctld::vpn_router",
                    user = %user.id,
                    server = %server.id,
                    protocol = %pid.0,
                    error = %e,
                    "extra-protocol share_link failed; skipping this server"
                );
            }
        }
    }
    Ok(uris)
}

pub(crate) async fn collect_awg_subscription_uris(state: &AppState, user: &User) -> Vec<String> {
    let servers = match state.inv.subscription_servers_for_user(&user.id).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(target = "vpnctld::vpn_router", user = %user.id, error = %e, "awg: subscription_servers_for_user failed");
            return Vec::new();
        }
    };
    let wg_pid = vpnctl_core::ProtocolId("wireguard".to_string());
    let awg2_pid = vpnctl_core::ProtocolId("amneziawg2".to_string());
    let awg3_pid = vpnctl_core::ProtocolId("amneziawg3".to_string());
    let mut uris: Vec<String> = Vec::new();
    for server in &servers {
        let has_awg2 = server.enabled_protocols.contains(&awg2_pid);
        let has_awg3 = server.enabled_protocols.contains(&awg3_pid);
        let has_legacy_awg = server.kernels.iter().any(|k| k.0 == "amneziawg")
            && server.enabled_protocols.contains(&wg_pid);
        if !has_awg2 && !has_awg3 && !has_legacy_awg {
            continue;
        }
        if state
            .inv
            .is_server_auto_suppressed(&server.id)
            .await
            .unwrap_or(false)
        {
            continue;
        }
        match state.inv.client_detour_via(&server.id).await {
            Ok(Some(_)) => continue,
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(target = "vpnctld::vpn_router", user = %user.id, server = %server.id, error = %e, "awg: client_detour_via lookup failed; skipping");
                continue;
            }
        }
        let visible = match state
            .inv
            .visible_protocols_for_subscription(&user.id, &server.id)
            .await
        {
            Ok(vis) => vis,
            Err(e) => {
                tracing::warn!(target = "vpnctld::vpn_router", user = %user.id, server = %server.id, error = %e, "awg: visibility lookup failed; skipping");
                continue;
            }
        };

        let mut target_pids: Vec<(&vpnctl_core::ProtocolId, &'static str)> = Vec::new();
        if has_awg2 && visible.contains(&awg2_pid) {
            target_pids.push((&awg2_pid, "AWG"));
        } else if has_legacy_awg && visible.contains(&wg_pid) {
            target_pids.push((&wg_pid, "AWG"));
        }
        if has_awg3 && visible.contains(&awg3_pid) {
            target_pids.push((&awg3_pid, "AWG3"));
        }

        if target_pids.is_empty() {
            continue;
        }

        let secrets = match state.inv.list_server_secrets(&server.id).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(target = "vpnctld::vpn_router", user = %user.id, server = %server.id, error = %e, "awg: list_server_secrets failed; skipping");
                continue;
            }
        };
        let peers = match state.inv.users_for_server(&server.id).await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(target = "vpnctld::vpn_router", user = %user.id, server = %server.id, error = %e, "awg: users_for_server failed; skipping");
                continue;
            }
        };
        let ctx = RenderCtx::with_peers(server, &secrets, &peers);
        for (chosen_pid, tag) in target_pids {
            let link_res = if chosen_pid == &awg3_pid {
                vpnctl_protocols::awg3_share_link(&ctx, user)
            } else if chosen_pid == &awg2_pid {
                vpnctl_protocols::awg2_share_link(&ctx, user)
            } else {
                vpnctl_protocols::awg_share_link(&ctx, user)
            };
            match link_res {
                Ok(link) => {
                    let custom = state
                        .inv
                        .server_display_name(&server.id)
                        .await
                        .ok()
                        .flatten();
                    let label = server_display_label(&server.id.0, custom.as_deref());
                    let fragment = format!("{label} {tag} ~{}", user.id.0);
                    let encoded = utf8_percent_encode(&fragment, NINITUX_QUOTE).to_string();
                    uris.push(relabel_uri_fragment(&link, &encoded));
                }
                Err(e) => {
                    tracing::warn!(target = "vpnctld::vpn_router", user = %user.id, server = %server.id, protocol = %chosen_pid.0, error = %e, "awg share_link failed; skipping this server protocol");
                }
            }
        }
    }
    uris
}

pub(crate) fn relabel_uri_fragment(uri: &str, encoded_fragment: &str) -> String {
    match uri.find('#') {
        Some(i) => format!("{}#{encoded_fragment}", &uri[..i]),
        None => format!("{uri}#{encoded_fragment}"),
    }
}

pub(crate) fn add_query_param(uri: &str, key: &str, encoded_value: &str) -> String {
    let (head, frag) = match uri.find('#') {
        Some(i) => (&uri[..i], &uri[i..]),
        None => (uri, ""),
    };
    let sep = if head.contains('?') { '&' } else { '?' };
    format!("{head}{sep}{key}={encoded_value}{frag}")
}

pub(crate) fn make_config_blob(uris: &[String]) -> Option<String> {
    if uris.is_empty() {
        return None;
    }
    let joined = uris.join("\n");
    Some(BASE64_STANDARD.encode(joined.as_bytes()))
}
