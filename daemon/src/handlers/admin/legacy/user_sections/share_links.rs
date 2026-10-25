use std::collections::HashMap;

use axum::http::{HeaderMap, header};
use maud::{Markup, html};

use crate::AppState;
use crate::handlers::admin::users::mask_secret;

fn request_base(headers: &HeaderMap) -> String {
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("127.0.0.1:18402");
    format!("http://{host}")
}

pub(crate) fn sub_url(headers: &HeaderMap, sub_token: &str) -> String {
    format!("{}/sub/{sub_token}", request_base(headers))
}

pub(crate) fn public_base(headers: &HeaderMap, configured: Option<&str>) -> String {
    match configured.map(|url| url.trim_end_matches('/')) {
        Some(url) if !url.is_empty() => url.to_string(),
        _ => request_base(headers),
    }
}

pub(crate) fn app_config_url(base: &str, device_id: &str) -> Option<String> {
    if !vpnctl_crypto::is_valid_vpn_router_device_id(device_id) {
        return None;
    }
    Some(format!("{base}/api/v1/app/config/{device_id}"))
}

pub(crate) fn mihomo_sub_url(base: &str, sub_token: &str) -> String {
    let encoded_token = crate::http_util::path_segment_encode(sub_token);
    format!("{base}/api/v1/sub/{encoded_token}")
}

const QR_DISPLAY_PX: u32 = 220;

pub(crate) fn qr_svg(url: &str) -> Markup {
    use qrcode::QrCode;
    use qrcode::render::svg;

    match QrCode::new(url.as_bytes()) {
        Ok(code) => {
            let svg_str = code
                .render::<svg::Color<'_>>()
                .min_dimensions(QR_DISPLAY_PX, QR_DISPLAY_PX)
                .quiet_zone(true)
                .dark_color(svg::Color("#1a1611"))
                .light_color(svg::Color("#f5efe6"))
                .build();
            let card_px = QR_DISPLAY_PX + 24;
            let inner_style = format!(
                "width: {QR_DISPLAY_PX}px; height: {QR_DISPLAY_PX}px; \
                 display: flex; align-items: stretch;"
            );
            let wrapper_style = format!(
                "display: inline-block; padding: 12px; background: var(--paper); \
                 border: 1px solid var(--rule); width: {card_px}px; height: {card_px}px; \
                 box-sizing: border-box;"
            );
            html! {
                div style=(wrapper_style) {
                    style {
                        ".vpnctl-qr-frame svg { \
                          width: 100% !important; \
                          height: 100% !important; \
                          display: block; \
                        }"
                    }
                    div class="vpnctl-qr-frame" style=(inner_style) {
                        (maud::PreEscaped(svg_str))
                    }
                }
            }
        }
        Err(e) => html! {
            div style="font-family: var(--mono); color: var(--red); font-size: 12px;" {
                "QR generation failed: " (e.to_string())
            }
        },
    }
}

pub(crate) fn share_link_card(link: &str, footnote: &Markup) -> Markup {
    html! {
        div style="display: flex; gap: 14px; align-items: stretch; margin-bottom: 14px; min-height: 244px;" {
            (qr_svg(link))
            div style="flex: 1; display: flex; flex-direction: column; gap: 6px; min-width: 0;" {
                div style="font-family: var(--mono); font-size: 11px; color: var(--soft); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;"
                     title=(mask_secret(link)) {
                    (mask_secret(link))
                }
                textarea readonly="readonly" rows="3"
                         data-select-on-click
                         title="Click to select the full link (or triple-click if JS is disabled), then Ctrl+C / Cmd+C to copy"
                         style="width: 100%; padding: 8px 10px; font-family: var(--mono); font-size: 10px; line-height: 1.45; color: var(--ink); background: var(--paper); border: 1px solid var(--rule); resize: vertical; word-break: break-all; box-sizing: border-box;" {
                    (link)
                }
                div style="font-family: var(--serif); font-style: italic; color: var(--mute); font-size: 12px; line-height: 1.5;" {
                    (footnote)
                }
            }
        }
    }
}

fn user_for_server_render(
    user: &vpnctl_core::User,
    peers: &[vpnctl_core::User],
    server_id: &vpnctl_core::ServerId,
) -> vpnctl_core::User {
    let per_server_uuid = peers
        .iter()
        .find(|p| p.id == user.id)
        .map(|p| p.uuid.as_str());
    match per_server_uuid {
        Some(uuid) => user.with_per_server_uuid(uuid),
        None => {
            if !peers.is_empty() {
                tracing::warn!(
                    target = "vpnctld::admin",
                    server = %server_id,
                    user = %user.id,
                    "peer list for server does not contain target user; \
                     falling back to global user.uuid (caller bug — peers \
                     built for wrong server, or grant revoked mid-render)"
                );
            }
            user.clone()
        }
    }
}

pub(crate) async fn collect_amnezia_links(
    state: &AppState,
    user: &vpnctl_core::User,
    servers: &[vpnctl_core::Server],
    secrets_per_server: &HashMap<vpnctl_core::ServerId, HashMap<String, String>>,
    peers_per_server: &HashMap<vpnctl_core::ServerId, Vec<vpnctl_core::User>>,
) -> Vec<(vpnctl_core::ServerId, String)> {
    if user.disabled {
        return Vec::new();
    }
    let mut out = Vec::new();
    for server in servers {
        if !server.enabled_protocols.iter().any(|p| p.0 == "wireguard") {
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
        let visible_protocols = state
            .inv
            .visible_protocols_for_subscription(&user.id, &server.id)
            .await
            .unwrap_or_default();
        let wg_pid = vpnctl_core::ProtocolId("wireguard".into());
        if !visible_protocols.contains(&wg_pid) {
            continue;
        }
        let Some(secrets) = secrets_per_server.get(&server.id) else {
            tracing::warn!(target = "vpnctld::admin", server = %server.id, "secrets missing for granted WG server (amnezia link)");
            continue;
        };
        let peers: &[vpnctl_core::User] = peers_per_server
            .get(&server.id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let wg_octets = match state.inv.wg_octets_for_server(&server.id).await {
            Ok(octets) => octets,
            Err(e) => {
                tracing::warn!(target = "vpnctld::admin", server = %server.id, error = %e, "WireGuard address assignment failed");
                continue;
            }
        };
        let ctx =
            vpnctl_core::RenderCtx::with_peers(server, secrets, peers).with_wg_octets(wg_octets);
        let per_server_user = user_for_server_render(user, peers, &server.id);
        match vpnctl_protocols::amnezia_share_link(&ctx, &per_server_user) {
            Ok(link) => out.push((server.id.clone(), link)),
            Err(e) => {
                tracing::warn!(
                    target = "vpnctld::admin",
                    server = %server.id,
                    user = %user.id,
                    error = %e,
                    "amnezia_share_link failed, skipping Flow C entry"
                );
            }
        }
    }
    out
}

pub(crate) async fn collect_awg_links(
    state: &AppState,
    user: &vpnctl_core::User,
    servers: &[vpnctl_core::Server],
    secrets_per_server: &HashMap<vpnctl_core::ServerId, HashMap<String, String>>,
    peers_per_server: &HashMap<vpnctl_core::ServerId, Vec<vpnctl_core::User>>,
) -> Vec<(vpnctl_core::ServerId, String)> {
    if user.disabled {
        return Vec::new();
    }
    let mut out = Vec::new();
    for server in servers {
        let is_amnezia = server.kernels.iter().any(|k| k.0 == "amneziawg");
        let serves_wg = server.enabled_protocols.iter().any(|p| p.0 == "wireguard");
        if !is_amnezia || !serves_wg {
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
        let visible_protocols = state
            .inv
            .visible_protocols_for_subscription(&user.id, &server.id)
            .await
            .unwrap_or_default();
        let wg_pid = vpnctl_core::ProtocolId("wireguard".into());
        if !visible_protocols.contains(&wg_pid) {
            continue;
        }
        let Some(secrets) = secrets_per_server.get(&server.id) else {
            continue;
        };
        let peers: &[vpnctl_core::User] = peers_per_server
            .get(&server.id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let wg_octets = match state.inv.wg_octets_for_server(&server.id).await {
            Ok(octets) => octets,
            Err(e) => {
                tracing::warn!(target = "vpnctld::admin", server = %server.id, error = %e, "WireGuard address assignment failed");
                continue;
            }
        };
        let ctx =
            vpnctl_core::RenderCtx::with_peers(server, secrets, peers).with_wg_octets(wg_octets);
        let per_server_user = user_for_server_render(user, peers, &server.id);
        match vpnctl_protocols::awg_share_link(&ctx, &per_server_user) {
            Ok(link) => out.push((server.id.clone(), link)),
            Err(e) => {
                tracing::debug!(
                    target = "vpnctld::admin",
                    server = %server.id,
                    user = %user.id,
                    error = %e,
                    "awg_share_link skipped (no obfs / no server-gen privkey)"
                );
            }
        }
    }
    out
}

pub(crate) async fn collect_share_links(
    state: &AppState,
    user: &vpnctl_core::User,
    servers: &[vpnctl_core::Server],
    secrets_per_server: &HashMap<vpnctl_core::ServerId, HashMap<String, String>>,
    peers_per_server: &HashMap<vpnctl_core::ServerId, Vec<vpnctl_core::User>>,
) -> Vec<(vpnctl_core::ServerId, vpnctl_core::ProtocolId, String)> {
    if user.disabled {
        return Vec::new();
    }
    let mut out = Vec::new();
    for server in servers {
        if state
            .inv
            .is_server_auto_suppressed(&server.id)
            .await
            .unwrap_or(false)
        {
            continue;
        }
        let visible_protocols = state
            .inv
            .visible_protocols_for_subscription(&user.id, &server.id)
            .await
            .unwrap_or_default();
        let visible_set: std::collections::HashSet<vpnctl_core::ProtocolId> =
            visible_protocols.into_iter().collect();

        let Some(secrets) = secrets_per_server.get(&server.id) else {
            tracing::warn!(target = "vpnctld::admin", server = %server.id, "secrets missing for granted server");
            continue;
        };
        let peers: &[vpnctl_core::User] = peers_per_server
            .get(&server.id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let wg_octets = match state.inv.wg_octets_for_server(&server.id).await {
            Ok(octets) => octets,
            Err(e) => {
                tracing::warn!(target = "vpnctld::admin", server = %server.id, error = %e, "WireGuard address assignment failed");
                continue;
            }
        };
        let ctx =
            vpnctl_core::RenderCtx::with_peers(server, secrets, peers).with_wg_octets(wg_octets);
        let per_server_user = user_for_server_render(user, peers, &server.id);
        for pid in &server.enabled_protocols {
            if !visible_set.contains(pid) {
                continue;
            }
            let Some(proto) = state.registry.protocol(pid) else {
                tracing::warn!(target = "vpnctld::admin", protocol = %pid, "protocol not registered");
                continue;
            };
            match proto.share_link(&ctx, &per_server_user) {
                Ok(link) => out.push((server.id.clone(), pid.clone(), link)),
                Err(e) => {
                    tracing::warn!(
                        target = "vpnctld::admin",
                        server = %server.id,
                        protocol = %pid,
                        error = %e,
                        "share_link failed, skipping"
                    );
                }
            }
        }
    }
    out
}
