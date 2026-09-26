use crate::AppState;
use crate::handlers::admin::audit::sanitize_header_filename;
use crate::handlers::admin::helpers::{bad_request, internal_error, not_found, user_not_found};
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

/// `GET /admin/users/{user_id}/wireguard/conf/{server_id}` — serve a
/// drag-drop-ready `.conf` file (INI body — `[Interface]` + `[Peer]`,
/// optionally + AmneziaWG obfs lines when secrets are set) for this
/// (user, server) pair. Imports into the official WireGuard app, into
/// Hiddify, AND into AmneziaVPN's "File with settings" picker — i.e.
/// every WG client, no matter the URI scheme they prefer.
///
/// Headers:
///   * `Content-Type: text/plain; charset=utf-8` — most clients sniff
///     the body regardless, but `text/plain` is the closest match.
///   * `Content-Disposition: attachment; filename="<user>-<server>.conf"`
///     — triggers the browser's download UI instead of inline display.
///
/// Errors:
///   * 404 if the user or server doesn't exist (canonical body).
///   * 400 if the server doesn't enable the `wireguard` protocol.
///   * 500 on rendering errors (missing server pubkey etc.) — these
///     usually indicate the server hasn't been deployed.
pub(crate) async fn user_wireguard_conf_download(
    State(state): State<AppState>,
    Path((user_id_str, server_id_str)): Path<(String, String)>,
) -> Response {
    let uid = vpnctl_core::UserId(user_id_str.clone());
    let sid = vpnctl_core::ServerId(server_id_str.clone());

    let user = match state.inv.get_user(&uid).await {
        Ok(Some(u)) => u,
        Ok(None) => return user_not_found(&user_id_str),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    let server = match state.inv.get_server(&sid).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return not_found(&format!("no such server '{server_id_str}'"));
        }
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    if !server.enabled_protocols.iter().any(|p| p.0 == "wireguard") {
        return bad_request(&format!(
            "server '{server_id_str}' does not enable the 'wireguard' protocol — enable it on the server detail page before downloading a .conf"
        ));
    }
    // Grant check — refuse the download if the (user, server) pair
    // isn't granted. Without this, the URL stays "live" after a
    // revoke and a stale browser tab can still pull the .conf.
    // Doubles as the source of `ctx.peers` so the .conf address
    // matches the server's [Peer] block 1:1.
    let peers = match state.inv.users_for_server(&sid).await {
        Ok(p) => p,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    if !peers.iter().any(|p| p.id == uid) {
        return not_found(&format!(
            "user '{user_id_str}' is not granted on server '{server_id_str}'"
        ));
    }
    let secrets = match state.inv.list_server_secrets(&sid).await {
        Ok(m) => m,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    let ctx = vpnctl_core::RenderCtx::with_peers(&server, &secrets, &peers);
    let conf = match vpnctl_protocols::render_client_conf_public(&ctx, &user) {
        Ok(c) => c,
        Err(e) => return internal_error(anyhow::anyhow!(e)),
    };

    // Strip every RFC-6266 unsafe set + control bytes + non-ASCII characters
    // from the filename before quoting using sanitize_header_filename.
    let safe_user = sanitize_header_filename(&user.id.0);
    let safe_server = sanitize_header_filename(&server.id.0);
    let filename = format!("{safe_user}-{safe_server}.conf");

    let mut resp = (StatusCode::OK, conf).into_response();
    let headers = resp.headers_mut();
    if let Ok(v) = HeaderValue::from_str("text/plain; charset=utf-8") {
        headers.insert(header::CONTENT_TYPE, v);
    }
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{filename}\"")) {
        headers.insert(header::CONTENT_DISPOSITION, v);
    }
    resp
}

/// Shared delivery-button and direct-download policy. Database failures must
/// propagate: an unavailable visibility/suppression check is never permission.
pub(crate) async fn amnezia_conf_available(
    state: &AppState,
    user: &vpnctl_core::User,
    server: &vpnctl_core::Server,
    peers: &[vpnctl_core::User],
    version: u8,
) -> Result<bool, vpnctl_inventory::SqliteInventoryError> {
    let protocol = match version {
        2 => vpnctl_core::ProtocolId("amneziawg2".into()),
        3 => vpnctl_core::ProtocolId("amneziawg3".into()),
        _ => return Ok(false),
    };
    if user.disabled
        || !peers
            .iter()
            .any(|peer| peer.id == user.id && !peer.disabled)
        || !server.enabled_protocols.contains(&protocol)
        || state.registry.protocol(&protocol).is_none()
        || !server.kernels.iter().any(|id| {
            id.0 == "sing-box"
                && state
                    .registry
                    .kernel(id)
                    .is_some_and(|kernel| kernel.supported_protocols().contains(&protocol))
        })
    {
        return Ok(false);
    }
    if state.inv.get_server_role(&server.id).await? != vpnctl_inventory::ServerRole::VpnExit
        || state.inv.is_server_auto_suppressed(&server.id).await?
        || state.inv.client_detour_via(&server.id).await?.is_some()
    {
        return Ok(false);
    }
    Ok(state
        .inv
        .visible_protocols_for_subscription(&user.id, &server.id)
        .await?
        .contains(&protocol))
}

pub(crate) fn amnezia_user_keypair_valid(user: &vpnctl_core::User) -> bool {
    match (&user.wireguard_private, &user.wireguard_pubkey) {
        (Some(private), Some(public)) => vpnctl_crypto::wireguard_keypair_matches(private, public),
        _ => false,
    }
}

pub(crate) fn amnezia_server_keypair_valid(
    version: u8,
    secrets: &std::collections::HashMap<String, String>,
) -> bool {
    if !matches!(version, 2 | 3) {
        return false;
    }
    match (
        secrets.get(&format!("amneziawg{version}.server_private_key")),
        secrets.get(&format!("amneziawg{version}.server_public_key")),
    ) {
        (Some(private), Some(public)) => vpnctl_crypto::wireguard_keypair_matches(private, public),
        _ => false,
    }
}

fn amnezia_download_error(status: StatusCode, message: &'static str) -> Response {
    (status, [(header::CACHE_CONTROL, "no-store")], message).into_response()
}

/// Read-only native AWG2/3 export. Never mint keys or expose renderer/DB errors.
pub(crate) async fn user_amneziawg_conf_download(
    State(state): State<AppState>,
    Path((user_id, version, server_id)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    let version = match version.as_str() {
        "2" => 2,
        "3" => 3,
        _ => {
            return Err(amnezia_download_error(
                StatusCode::BAD_REQUEST,
                "Choose AmneziaWG 2.0 or 3.1 from the user's Delivery page.",
            ));
        }
    };
    let unavailable = || {
        amnezia_download_error(
            StatusCode::NOT_FOUND,
            "This AmneziaWG download is unavailable. Review user access and the server's protocol settings in the admin UI.",
        )
    };
    let database_error = |_| {
        amnezia_download_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to verify AmneziaWG download settings. Please try again.",
        )
    };
    let uid = vpnctl_core::UserId(user_id);
    let sid = vpnctl_core::ServerId(server_id);
    let user = state
        .inv
        .get_user(&uid)
        .await
        .map_err(database_error)?
        .ok_or_else(unavailable)?;
    let server = state
        .inv
        .get_server(&sid)
        .await
        .map_err(database_error)?
        .ok_or_else(unavailable)?;
    let peers = state
        .inv
        .users_for_server(&sid)
        .await
        .map_err(database_error)?;
    if !amnezia_conf_available(&state, &user, &server, &peers, version)
        .await
        .map_err(database_error)?
    {
        return Err(unavailable());
    }
    if !amnezia_user_keypair_valid(&user) {
        return Err(amnezia_download_error(
            StatusCode::CONFLICT,
            "A ready AmneziaWG file needs a matching user keypair. Open Delivery and explicitly Generate or Rotate the WireGuard keypair, then deploy the updated configuration.",
        ));
    }
    let secrets = state
        .inv
        .list_server_secrets(&sid)
        .await
        .map_err(database_error)?;
    let ctx = vpnctl_core::RenderCtx::with_peers(&server, &secrets, &peers);
    if !amnezia_server_keypair_valid(version, &secrets) {
        return Err(amnezia_download_error(
            StatusCode::CONFLICT,
            "A ready AmneziaWG file needs a matching server keypair. Review the server's Settings before deploying; downloading does not repair keys.",
        ));
    }
    let conf = vpnctl_protocols::render_amnezia_conf(version, &ctx, &user).map_err(|_| {
        amnezia_download_error(
            StatusCode::CONFLICT,
            "The AmneziaWG file is not ready. Review keys in user Delivery and server Settings, then deploy the server. Downloading does not generate or repair keys.",
        )
    })?;
    let filename = format!(
        "{}-{}-amneziawg{version}.conf",
        sanitize_header_filename(&uid.0),
        sanitize_header_filename(&sid.0),
    );
    let disposition = HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
        .map_err(|_| {
            amnezia_download_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to prepare the download. Please try again.",
            )
        })?;
    let mut response = (
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        conf,
    )
        .into_response();
    response
        .headers_mut()
        .insert(axum::http::header::CONTENT_DISPOSITION, disposition);
    Ok(response)
}
