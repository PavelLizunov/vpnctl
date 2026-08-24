use serde_json::{Value, json};
use vpnctl_core::{RenderCtx, User, UserId};

use super::handler::SubError;
use crate::app::AppState;

/// Render the sing-box JSON envelope for an ALREADY-RESOLVED user.
/// Takes `&User` (not a token) because the handler resolves the user
/// once up front and runs the per-token ban + rate-limit gates before
/// dispatching here — see [`get`](super::handler::get).
pub(super) async fn render_singbox(
    state: &AppState,
    user: &User,
) -> Result<(UserId, Value), SubError> {
    let user_id = user.id.clone();

    // B1.user — disabled-user soft mute (audit 2026-05-22, migration
    // 0026). Render an EMPTY config (no outbounds, no servers) so
    // the operator's «pause this user» action is visible to the
    // client on next refresh WITHOUT rotating secrets or revoking
    // grants. The /sub URL stays reachable (no 404 — that would
    // break the client's polling assumption and surface as a
    // confusing error); the response is just an empty sing-box
    // config with the standard route structure. Re-enabling flips
    // bytes back to identical-to-before.
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
        .servers_for_user(&user.id)
        .await
        .map_err(|e| SubError::Internal(format!("inventory: {e}")))?;

    let mut outbounds: Vec<Value> = Vec::new();
    let mut tags: Vec<String> = Vec::new();

    for server in &servers {
        // Auto-suppress (migration 0030): skip a server the health
        // monitor flagged unreachable (per-server opt-in); auto-restores
        // on recovery. DB error → don't suppress (keep it in the sub).
        if state
            .inv
            .is_server_auto_suppressed(&server.id)
            .await
            .unwrap_or(false)
        {
            continue;
        }
        let secrets = state
            .inv
            .list_server_secrets(&server.id)
            .await
            .map_err(|e| SubError::Internal(format!("inventory: {e}")))?;
        let ctx = RenderCtx::new(server, &secrets);

        // Per-server UUID override (Phase 1 of the ninitux merge —
        // migration `0016_grants_per_server_uuid.sql`). The user's
        // global `uuid` is their IDENTITY; the server-specific
        // `grants.client_uuid` is the AUTH secret the server's
        // sing-box expects in Reality handshakes from this user.
        // `user_with_per_server_uuid` returns the user unchanged when
        // no override is set, so this branch is byte-identical to
        // the pre-Phase-1 rendering until a Phase 2 import sets
        // distinct per-server uuids.
        let per_server_user = state
            .inv
            .user_with_per_server_uuid(user, &server.id)
            .await
            .map_err(|e| SubError::Internal(format!("inventory: {e}")))?;

        // Visibility filter (migration 0018): only emit protocols
        // visible for THIS user on THIS server. Compound query joins
        // server_protocols × grant_protocol_overrides:
        //   * `server_protocols.hidden=1` → suppressed for everyone
        //   * `grant_protocol_overrides.state='disabled'` →
        //     suppressed for this specific user
        //   * absent override + hidden=0 → visible (default)
        // Inbound on the node still runs — only the rendered URL is
        // filtered, so cached client URIs keep working.
        let visible_protocols = state
            .inv
            .visible_protocols_for_subscription(&user.id, &server.id)
            .await
            .map_err(|e| SubError::Internal(format!("inventory: {e}")))?;
        let visible_set: std::collections::HashSet<&vpnctl_core::ProtocolId> =
            visible_protocols.iter().collect();

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
            // Skip protocols that are not sing-box-native. Such
            // protocols are still surfaced in admin UI's per-protocol
            // share-links section via their own client.
            if !proto.appears_in_sing_box_sub() {
                tracing::debug!(
                    target = "vpnctld::sub",
                    server = %server.id,
                    protocol = %pid,
                    "protocol declared non-sing-box; skipping in sub config"
                );
                continue;
            }
            match proto.client_config(&ctx, &per_server_user) {
                Ok(mut value) => {
                    // Outbound tag user sees in their sing-box client's
                    // outbound list. Format: `{Country} {Protocol}`
                    // (e.g. `Germany VLESS`, `Iceland TUIC`). Post-rename
                    // 2026-05-20 server IDs are ISO country codes — see
                    // `vpn_router::country_display_name` for the
                    // canonical mapping. Protocol IDs come from each
                    // `impl Protocol` registration (`vless+reality`,
                    // `tuic-v5`, `hysteria2`, …) — we transform to the
                    // user-facing label here so the Protocol trait
                    // doesn't need to know about display strings.
                    let custom_name = state
                        .inv
                        .server_display_name(&server.id)
                        .await
                        .map_err(|e| SubError::Internal(format!("server_display_name: {e}")))?;
                    let server_display = crate::handlers::vpn_router::server_display_label(
                        &server.id.0,
                        custom_name.as_deref(),
                    );
                    let proto_display = protocol_display_name(&pid.0);
                    let tag = format!(
                        "{server_display} {proto_display} ~{user_id}",
                        user_id = user.id.0
                    );
                    if let Some(obj) = value.as_object_mut() {
                        obj.insert("tag".into(), json!(tag));
                    }
                    outbounds.push(value);
                    tags.push(tag);
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

    let cfg = build_client_envelope(user, outbounds, &tags);
    Ok((user_id, cfg))
}

/// Map a protocol ID (`vless+reality`, `tuic-v5`, …) to the user-facing
/// label rendered in sing-box outbound tags. Stable across versions:
/// what the operator's user sees in their app's outbound list MUST NOT
/// drift on a vpnctl deploy unless the protocol itself changed.
///
/// Conservative naming — full word for well-known protocols, short
/// abbreviation only for verbose names (Hysteria2, Shadowsocks-2022).
/// Unknown protocols fall back to uppercased ID — operator can read it.
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

/// Wrap the per-server outbounds in a minimal sing-box client envelope:
/// a `selector` lets the user pick a route in the UI, plus the standard
/// `direct` / `block` outbounds.
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

/// Build the byte-stable «no-proxy» sing-box config returned to
/// disabled users (B1.user, audit 2026-05-22). Same envelope shape
/// as a normal config but with NO proxy outbounds — only `direct`
/// and `block`, with `final: direct`. The client parses successfully
/// (no error toast), every route falls through to `direct` (which
/// for a VPN client means «no VPN»), and re-enabling the user
/// restores the full config on next refresh.
///
/// **Deliberately matches the normal-config envelope keys** so a
/// future log-scraper / linter can't tell the difference between
/// «empty config because disabled» and «empty config because zero
/// grants» — both represent «this user has no servers to use right
/// now», and operator distinguishes via the user-detail page.
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
