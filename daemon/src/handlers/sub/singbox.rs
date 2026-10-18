use serde_json::{Value, json};
use vpnctl_core::{RenderCtx, ServerId, User, UserId};

use super::handler::SubError;
use crate::app::AppState;

#[derive(Clone, Copy, Debug)]
enum Compatibility {
    Legacy,
    Stock,
    Mihomo,
}

pub(super) async fn render_singbox(
    state: &AppState,
    user: &User,
    stock_only: bool,
) -> Result<(UserId, Value), SubError> {
    let compatibility = if stock_only {
        Compatibility::Stock
    } else {
        Compatibility::Legacy
    };
    render_singbox_with(state, user, compatibility).await
}

pub(super) async fn render_singbox_for_mihomo(
    state: &AppState,
    user: &User,
) -> Result<(UserId, Value), SubError> {
    render_singbox_with(state, user, Compatibility::Mihomo).await
}

async fn render_singbox_with(
    state: &AppState,
    user: &User,
    compatibility: Compatibility,
) -> Result<(UserId, Value), SubError> {
    let user_id = user.id.clone();

    if user.disabled {
        tracing::info!(
            target = "vpnctld::sub",
            user = %user_id.0,
            "user is disabled — returning empty config"
        );
        return Ok((user_id, empty_singbox_config()));
    }

    let servers = state
        .inv
        .subscription_servers_for_user(&user.id)
        .await
        .map_err(|e| SubError::Internal(format!("inventory: {e}")))?;

    let mut rendered: Vec<(ServerId, Value, String)> = Vec::new();
    let mut detours: std::collections::HashMap<ServerId, Option<ServerId>> =
        std::collections::HashMap::new();

    for server in &servers {
        if state
            .inv
            .is_server_auto_suppressed(&server.id)
            .await
            .unwrap_or(false)
        {
            continue;
        }
        let detour = state
            .inv
            .client_detour_via(&server.id)
            .await
            .map_err(|e| SubError::Internal(format!("inventory: {e}")))?;
        detours.insert(server.id.clone(), detour);

        let secrets = state
            .inv
            .list_server_secrets(&server.id)
            .await
            .map_err(|e| SubError::Internal(format!("inventory: {e}")))?;
        let ctx = RenderCtx::new(server, &secrets);

        let per_server_user = state
            .inv
            .user_with_per_server_uuid(user, &server.id)
            .await
            .map_err(|e| SubError::Internal(format!("inventory: {e}")))?;

        let visible_protocols = state
            .inv
            .visible_protocols_for_subscription(&user.id, &server.id)
            .await
            .map_err(|e| SubError::Internal(format!("inventory: {e}")))?;
        let visible_set: std::collections::HashSet<&vpnctl_core::ProtocolId> =
            visible_protocols.iter().collect();

        let custom_name = state
            .inv
            .server_display_name(&server.id)
            .await
            .map_err(|e| SubError::Internal(format!("server_display_name: {e}")))?;
        let server_display =
            crate::handlers::vpn_router::server_display_label(&server.id.0, custom_name.as_deref());

        for pid in &server.enabled_protocols {
            if !visible_set.contains(pid) {
                continue;
            }
            let Some(proto) = state.registry.protocol(pid) else {
                tracing::warn!(
                    target = "vpnctld::sub",
                    protocol = %pid,
                    "protocol not registered, skipping"
                );
                continue;
            };
            let compatible = match compatibility {
                Compatibility::Legacy => proto.appears_in_sing_box_sub(),
                Compatibility::Stock => proto.appears_in_stock_sing_box_sub(),
                Compatibility::Mihomo => matches!(pid.0.as_str(), "vless+reality" | "hysteria2"),
            };
            if !compatible {
                tracing::debug!(
                    target = "vpnctld::sub",
                    server = %server.id,
                    protocol = %pid,
                    ?compatibility,
                    "protocol incompatible with requested subscription format; skipping"
                );
                continue;
            }
            match proto.client_config(&ctx, &per_server_user) {
                Ok(mut value) => {
                    let proto_display = protocol_display_name(&pid.0);
                    let tag = format!(
                        "{server_display} {proto_display} ~{user_id}",
                        user_id = user.id.0
                    );
                    if let Some(obj) = value.as_object_mut() {
                        obj.insert("tag".into(), json!(tag));
                    }
                    rendered.push((server.id.clone(), value, tag));
                }
                Err(e) => {
                    tracing::warn!(
                        target = "vpnctld::sub",
                        server = %server.id,
                        protocol = %pid,
                        error = %e,
                        "client_config failed, skipping"
                    );
                }
            }
        }
    }

    let mut first_tag_by_server: std::collections::HashMap<ServerId, String> =
        std::collections::HashMap::new();
    for (server_id, _, tag) in &rendered {
        first_tag_by_server
            .entry(server_id.clone())
            .or_insert_with(|| tag.clone());
    }

    let mut outbounds: Vec<Value> = Vec::with_capacity(rendered.len());
    let mut tags: Vec<String> = Vec::with_capacity(rendered.len());
    for (server_id, mut value, tag) in rendered {
        if let Some(Some(entry_id)) = detours.get(&server_id) {
            let Some(entry_tag) = first_tag_by_server.get(entry_id) else {
                tracing::warn!(
                    target = "vpnctld::sub",
                    user = %user.id,
                    server = %server_id,
                    entry_server = %entry_id,
                    "client detour entry has no usable outbound; omitting target"
                );
                continue;
            };
            let Some(obj) = value.as_object_mut() else {
                tracing::warn!(
                    target = "vpnctld::sub",
                    user = %user.id,
                    server = %server_id,
                    "client detour target rendered a non-object outbound; omitting target"
                );
                continue;
            };
            obj.insert("detour".into(), json!(entry_tag));
        }
        outbounds.push(value);
        tags.push(tag);
    }

    let cfg = build_client_envelope(user, outbounds, &tags);
    Ok((user_id, cfg))
}

fn protocol_display_name(protocol_id: &str) -> String {
    match protocol_id {
        "vless+reality" => "VLESS".into(),
        "tuic-v5" => "TUIC".into(),
        "hysteria2" => "HY2".into(),
        "shadowsocks-2022" => "SS-22".into(),
        "trojan" => "Trojan".into(),
        "anytls" => "AnyTLS".into(),
        "wireguard" => "WireGuard".into(),
        other => other.to_ascii_uppercase(),
    }
}

fn build_client_envelope(_user: &User, mut outbounds: Vec<Value>, tags: &[String]) -> Value {
    if !tags.is_empty() {
        let selector_outbounds: Vec<Value> = tags.iter().map(|t| json!(t)).collect();
        outbounds.insert(
            0,
            json!({
                "type": "selector",
                "tag": "proxy",
                "outbounds": selector_outbounds,
                "default": tags.first(),
            }),
        );
    }
    outbounds.push(json!({ "type": "direct", "tag": "direct" }));
    outbounds.push(json!({ "type": "block",  "tag": "block"  }));

    json!({
        "log": { "level": "info", "timestamp": true },
        "outbounds": outbounds,
        "route": {
            "rules": [
                { "protocol": "dns", "outbound": "direct" }
            ],
            "final": "proxy",
            "auto_detect_interface": true
        }
    })
}

fn empty_singbox_config() -> Value {
    json!({
        "log": { "level": "info", "timestamp": true },
        "outbounds": [
            { "type": "direct", "tag": "direct" },
            { "type": "block",  "tag": "block"  },
        ],
        "route": {
            "rules": [
                { "protocol": "dns", "outbound": "direct" }
            ],
            "final": "direct",
            "auto_detect_interface": true
        }
    })
}
