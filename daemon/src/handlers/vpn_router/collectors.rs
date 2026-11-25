use std::collections::HashSet;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use vpnctl_core::url_host::host_for_url;
use vpnctl_core::{ProtocolId, RenderCtx, ServerId, User};
use vpnctl_inventory::sqlite::SubscriptionServer;
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
    fp: &str,
    pbk: &str,
    sid: &str,
    client_uuid: &str,
    server_tag: &str,
    client_name: &str,
) -> String {
    let pbk_e = utf8_percent_encode(pbk, NINITUX_QUOTE);
    let fp_e = utf8_percent_encode(fp, NINITUX_QUOTE);
    let sni_e = utf8_percent_encode(sni, NINITUX_QUOTE);
    let sid_e = utf8_percent_encode(sid, NINITUX_QUOTE);
    let params = format!(
        "encryption=none&type=tcp&security=reality&pbk={pbk_e}&fp={fp_e}&sni={sni_e}&sid={sid_e}&spx=%2F&flow=xtls-rprx-vision&packetEncoding={VLESS_PACKET_ENCODING}"
    );

    let label = format!("{server_tag} VLESS ~{client_name}");
    let fragment = utf8_percent_encode(&label, NINITUX_QUOTE);

    let host = host_for_url(server_ip);

    format!("vless://{client_uuid}@{host}:{port}?{params}#{fragment}")
}

fn vless_reality_keys(input: &SubscriptionServer) -> Option<(&str, &str)> {
    if (input.suppressed && input.detour_via.is_none())
        || !input.visible.iter().any(|id| id.0 == "vless+reality")
    {
        return None;
    }
    Some((
        input.secrets.get("vless.public_key")?.as_str(),
        input.secrets.get("vless.short_id")?.as_str(),
    ))
}

fn vless_base_uri(input: &SubscriptionServer, client_name: &str) -> Option<String> {
    let (pbk, sid) = vless_reality_keys(input)?;
    let server = &input.server;
    let secrets = &input.secrets;
    let sni = secrets
        .get("vless.sni")
        .map(String::as_str)
        .unwrap_or(vpnctl_protocols::DEFAULT_REALITY_SNI);
    let fp = vpnctl_protocols::reality_fp(secrets);
    let port: u16 = vpnctl_protocols::reality_listen_port(secrets);
    let server_display = server_display_label(&server.id.0, input.display_name.as_deref());
    Some(render_vless_uri(
        &server.address,
        port,
        sni,
        fp,
        pbk,
        sid,
        &input.client_uuid,
        &server_display,
        client_name,
    ))
}

pub(crate) fn collect_vless_uris_for_user(
    inputs: &[SubscriptionServer],
    client_name: &str,
    detour_capable: bool,
) -> Vec<String> {
    collect_vless_uris_with_entries(inputs, client_name, detour_capable, &HashSet::new())
}

pub(super) fn collect_vless_uris_with_entries(
    inputs: &[SubscriptionServer],
    client_name: &str,
    detour_capable: bool,
    extra_entries: &HashSet<ServerId>,
) -> Vec<String> {
    struct RenderedServer {
        server_id: vpnctl_core::ServerId,
        detour_via: Option<vpnctl_core::ServerId>,
        base_uri: String,
    }

    let mut rendered: Vec<RenderedServer> = Vec::with_capacity(inputs.len());
    for input in inputs {
        let Some(base_uri) = vless_base_uri(input, client_name) else {
            continue;
        };
        rendered.push(RenderedServer {
            server_id: input.server.id.clone(),
            detour_via: input.detour_via.clone(),
            base_uri,
        });
    }

    if !detour_capable {
        return rendered
            .into_iter()
            .filter(|r| r.detour_via.is_none())
            .map(|r| r.base_uri)
            .collect();
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

    let mut valid_entries: HashSet<ServerId> = rendered
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
    valid_entries.extend(extra_entries.intersection(&direct_entry_ids).cloned());

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

    uris
}

pub(super) fn collect_vmess_uris(
    state: &AppState,
    inputs: &[SubscriptionServer],
    user: &User,
    detour_capable: bool,
) -> (Vec<String>, HashSet<ServerId>) {
    let mut entries = HashSet::new();
    let mut uris = Vec::new();
    let vmess = ProtocolId("vmess".into());
    let Some(protocol) = state.registry.protocol(&vmess) else {
        return (uris, entries);
    };
    let direct_hops: HashSet<ServerId> = inputs
        .iter()
        .filter(|input| input.detour_via.is_none() && vless_reality_keys(input).is_some())
        .map(|input| input.server.id.clone())
        .collect();

    for input in inputs {
        if !input.visible.contains(&vmess) || (input.suppressed && input.detour_via.is_none()) {
            continue;
        }
        let ctx = RenderCtx::new(&input.server, &input.secrets);
        let per_server_user = user.with_per_server_uuid(&input.client_uuid);
        let Ok(uri) = protocol.share_link(&ctx, &per_server_user) else {
            continue;
        };
        let Some(encoded) = uri.strip_prefix("vmess://") else {
            continue;
        };
        let Ok(decoded) = BASE64_STANDARD.decode(encoded) else {
            continue;
        };
        let Ok(mut profile) =
            serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(&decoded)
        else {
            continue;
        };
        let label = server_display_label(&input.server.id.0, input.display_name.as_deref());

        let preferred = input
            .secrets
            .get("vmess.preferred_entry")
            .filter(|value| !value.is_empty())
            .map(|value| ServerId(value.clone()));
        let entry = input.detour_via.as_ref().or(preferred.as_ref());
        if detour_capable
            && input.server.address.parse::<std::net::IpAddr>().is_ok()
            && let Some(entry) = entry
            && entry != &input.server.id
            && direct_hops.contains(entry)
        {
            let mut chained = profile.clone();
            chained.insert("add".into(), input.server.address.clone().into());
            chained.insert("detour".into(), entry.0.clone().into());
            chained.insert(
                "outbound".into(),
                format!("vmess-{}", input.server.id.0).into(),
            );
            chained.insert(
                "ps".into(),
                format!("{label} VMess via {} ~{}", entry.0, user.id.0).into(),
            );
            uris.push(encode_vmess_profile(chained));
            entries.insert(entry.clone());
        }
        if input.detour_via.is_none() {
            profile.insert("ps".into(), format!("{label} VMess ~{}", user.id.0).into());
            uris.push(encode_vmess_profile(profile));
        }
    }
    (uris, entries)
}

fn encode_vmess_profile(profile: serde_json::Map<String, serde_json::Value>) -> String {
    let encoded = BASE64_STANDARD.encode(serde_json::Value::Object(profile).to_string());
    format!("vmess://{encoded}")
}

pub(crate) fn collect_extra_protocol_uris(
    state: &AppState,
    inputs: &[SubscriptionServer],
    user: &User,
    pid: &vpnctl_core::ProtocolId,
    label_tag: &str,
    require_secret: Option<&str>,
) -> Vec<String> {
    let Some(proto) = state.registry.protocol(pid) else {
        return Vec::new();
    };

    let mut uris: Vec<String> = Vec::new();
    for input in inputs {
        let server = &input.server;
        let visible = &input.visible;
        if input.suppressed || input.detour_via.is_some() || !visible.contains(pid) {
            continue;
        }
        let secrets = &input.secrets;
        if let Some(req) = require_secret
            && !secrets.contains_key(req)
        {
            continue;
        }
        let per_server_user = user.with_per_server_uuid(&input.client_uuid);
        let ctx = RenderCtx::new(server, secrets);
        match proto.share_link(&ctx, &per_server_user) {
            Ok(link) => {
                let label = server_display_label(&server.id.0, input.display_name.as_deref());
                let fragment = format!("{label} {label_tag} ~{}", user.id.0);
                let encoded = utf8_percent_encode(&fragment, NINITUX_QUOTE).to_string();
                uris.push(relabel_uri_fragment(&link, &encoded));
            }
            Err(vpnctl_core::CoreError::ShareLinkUnavailable(_)) => continue,
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
    uris
}

fn turnrelay_publishes_vless(secrets: &std::collections::HashMap<String, String>) -> bool {
    secrets.get("turnrelay.publish").is_some_and(|value| {
        value.split(',').map(str::trim).any(|token| {
            matches!(
                token.to_ascii_lowercase().as_str(),
                "vless+reality" | "all" | "true" | "1" | "yes"
            )
        })
    })
}

fn turnrelay_targets<'a>(
    exit: &SubscriptionServer,
    inputs: &'a [SubscriptionServer],
    vless: &ProtocolId,
) -> Vec<&'a SubscriptionServer> {
    let Some(raw) = exit.secrets.get("turnrelay.publish_targets") else {
        return Vec::new();
    };
    let targets: Vec<&str> = raw
        .split(',')
        .map(str::trim)
        .filter(|target| !target.is_empty())
        .collect();
    if targets.is_empty() {
        return Vec::new();
    }
    let all = targets.contains(&"*");
    inputs
        .iter()
        .filter(|target| {
            target.server.id != exit.server.id
                && !target.suppressed
                && target.detour_via.is_none()
                && target.visible.contains(vless)
                && (all || targets.iter().any(|id| *id == target.server.id.0))
        })
        .collect()
}

/// Append capability-gated TurnRelay profiles: one relayed VLESS duplicate per
/// eligible VLESS endpoint, then one deduplicated `turnrelay://` hop per exit.
/// Direct URIs are owned by the existing collectors and never modified here.
pub(crate) fn collect_turnrelay_uris(
    state: &AppState,
    inputs: &[SubscriptionServer],
    user: &User,
) -> Vec<String> {
    let turnrelay = ProtocolId("turnrelay".into());
    let vless = ProtocolId("vless+reality".into());
    let Some(protocol) = state.registry.protocol(&turnrelay) else {
        return Vec::new();
    };
    let mut uris = Vec::new();
    let mut profiled = HashSet::new();
    for exit in inputs {
        if exit.suppressed
            || exit.detour_via.is_some()
            || !exit.visible.contains(&turnrelay)
            || exit.server.address.parse::<std::net::IpAddr>().is_err()
            || !turnrelay_publishes_vless(&exit.secrets)
        {
            continue;
        }
        let ctx = RenderCtx::new(&exit.server, &exit.secrets);
        if protocol.client_config(&ctx, user).is_err() {
            continue;
        }
        let exit_label = server_display_label(&exit.server.id.0, exit.display_name.as_deref());
        let mut emitted = false;

        if let Some(base) = vless_base_uri(exit, &user.id.0) {
            let outbound = utf8_percent_encode(
                &format!("vless-turnrelay-{}", exit.server.id.0),
                NINITUX_QUOTE,
            )
            .to_string();
            let detour =
                utf8_percent_encode(&format!("turnrelay-{}", exit.server.id.0), NINITUX_QUOTE)
                    .to_string();
            let uri = add_query_param(
                &add_query_param(&base, "outbound", &outbound),
                "detour",
                &detour,
            );
            let fragment = utf8_percent_encode(
                &format!("{exit_label} VLESS · TurnRelay ~{}", user.id.0),
                NINITUX_QUOTE,
            )
            .to_string();
            uris.push(relabel_uri_fragment(&uri, &fragment));
            emitted = true;
        }

        for target in turnrelay_targets(exit, inputs, &vless) {
            let Some(base) = vless_base_uri(target, &user.id.0) else {
                continue;
            };
            let outbound = utf8_percent_encode(
                &format!(
                    "vless-turnrelay-{}-via-{}",
                    target.server.id.0, exit.server.id.0
                ),
                NINITUX_QUOTE,
            )
            .to_string();
            let detour =
                utf8_percent_encode(&format!("turnrelay-{}", exit.server.id.0), NINITUX_QUOTE)
                    .to_string();
            let uri = add_query_param(
                &add_query_param(&base, "outbound", &outbound),
                "detour",
                &detour,
            );
            let target_label =
                server_display_label(&target.server.id.0, target.display_name.as_deref());
            let fragment = utf8_percent_encode(
                &format!(
                    "{target_label} VLESS · TurnRelay ({exit_label}) ~{}",
                    user.id.0
                ),
                NINITUX_QUOTE,
            )
            .to_string();
            uris.push(relabel_uri_fragment(&uri, &fragment));
            emitted = true;
        }

        if emitted
            && profiled.insert(exit.server.id.clone())
            && let Ok(link) = protocol.share_link(&ctx, user)
        {
            let fragment = utf8_percent_encode(
                &format!("{exit_label} TurnRelay ~{}", user.id.0),
                NINITUX_QUOTE,
            )
            .to_string();
            uris.push(relabel_uri_fragment(&link, &fragment));
        }
    }
    uris
}

pub(crate) fn collect_awg_subscription_uris(
    inputs: &[SubscriptionServer],
    user: &User,
) -> Vec<String> {
    let wg_pid = vpnctl_core::ProtocolId("wireguard".to_string());
    let awg2_pid = vpnctl_core::ProtocolId("amneziawg2".to_string());
    let awg3_pid = vpnctl_core::ProtocolId("amneziawg3".to_string());
    let mut uris: Vec<String> = Vec::new();
    for input in inputs {
        let server = &input.server;
        let has_awg2 = server.enabled_protocols.contains(&awg2_pid);
        let has_awg3 = server.enabled_protocols.contains(&awg3_pid);
        let has_legacy_awg = server.kernels.iter().any(|k| k.0 == "amneziawg")
            && server.enabled_protocols.contains(&wg_pid);
        if !has_awg2 && !has_awg3 && !has_legacy_awg {
            continue;
        }
        if input.suppressed || input.detour_via.is_some() {
            continue;
        }
        let visible = &input.visible;

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

        let ctx = RenderCtx::with_peers(server, &input.secrets, &input.peers)
            .with_wg_octets(input.wg_octets.clone());
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
                    let label = server_display_label(&server.id.0, input.display_name.as_deref());
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
