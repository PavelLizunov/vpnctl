mod limits;
mod projection;

#[cfg(test)]
mod spec_support;
#[cfg(test)]
mod spec_tests;
#[cfg(test)]
mod tests;

use std::net::SocketAddr;

use axum::Json;
use axum::extract::{ConnectInfo, Path, State, rejection::PathRejection};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use vpnctl_core::{Server, User};
use vpnctl_inventory::SqliteInventoryError;

use crate::app::AppState;
use projection::{NodeMetadata, NodesResponse};

pub(crate) async fn get_device_nodes(
    State(state): State<AppState>,
    path: Result<Path<String>, PathRejection>,
    request: axum::extract::Request,
) -> Response {
    get_nodes(&state, path, request, Identity::Device).await
}

pub(crate) async fn get_subscription_nodes(
    State(state): State<AppState>,
    path: Result<Path<String>, PathRejection>,
    request: axum::extract::Request,
) -> Response {
    get_nodes(&state, path, request, Identity::Subscription).await
}

pub(crate) async fn unauthorized_nodes() -> Response {
    error_response(StatusCode::UNAUTHORIZED, "unauthorized")
}

#[derive(Clone, Copy)]
enum Identity {
    Device,
    Subscription,
}

impl Identity {
    fn namespace(&self) -> &'static [u8] {
        match self {
            Self::Device => b"nodes:device",
            Self::Subscription => b"nodes:subscription",
        }
    }

    fn valid(&self, credential: &str) -> bool {
        match self {
            Self::Device => vpnctl_crypto::is_valid_vpn_router_device_id(credential),
            // Imports may retain legacy tokens. Accept the existing URL-safe
            // identity alphabet without assuming the current generator's length.
            Self::Subscription => {
                !credential.is_empty()
                    && credential.len() <= 256
                    && credential
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            }
        }
    }
}

async fn get_nodes(
    state: &AppState,
    path: Result<Path<String>, PathRejection>,
    request: axum::extract::Request,
    identity: Identity,
) -> Response {
    let Ok(Path(credential)) = path else {
        return unauthorized_nodes().await;
    };
    if !identity.valid(&credential) {
        return unauthorized_nodes().await;
    }
    if let Some(ConnectInfo(peer)) = request.extensions().get::<ConnectInfo<SocketAddr>>() {
        let ip = crate::real_ip::resolve_peer_real_ip(request.headers(), peer.ip());
        if let Err(retry) = limits::acquire(&state.rate_limiter, b"nodes:ip", &ip.to_string(), 600)
        {
            return throttled(retry);
        }
    }
    drop(request);
    let user = match identity {
        Identity::Device => {
            state
                .inv
                .find_user_by_vpn_router_device_id(&credential)
                .await
        }
        Identity::Subscription => state.inv.find_user_by_sub_token(&credential).await,
    };
    let user = match user {
        Ok(Some(user)) if !user.disabled => user,
        Ok(_) => return unauthorized_nodes().await,
        Err(_) => return error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
    };
    if let Err(retry) = limits::acquire(&state.rate_limiter, identity.namespace(), &credential, 60)
    {
        return throttled(retry);
    }
    match project_nodes(state, &user).await {
        Ok(body) => secure(Json(body).into_response()),
        Err(_) => error_response(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
    }
}

async fn project_nodes(
    state: &AppState,
    user: &User,
) -> Result<NodesResponse, SqliteInventoryError> {
    let now = chrono::Utc::now().timestamp();
    let ttl = metadata_ttl();
    let servers = state.inv.subscription_servers_for_user(&user.id).await?;
    let mut eligible = Vec::with_capacity(servers.len());
    for server in servers {
        if state.inv.is_server_auto_suppressed(&server.id).await? {
            continue;
        }
        let visible = state
            .inv
            .visible_protocols_for_subscription(&user.id, &server.id)
            .await?;
        let protocols: Vec<_> = visible
            .into_iter()
            .filter(|pid| server.enabled_protocols.contains(pid))
            .collect();
        if protocols.is_empty() {
            continue;
        }
        let detour = state.inv.client_detour_via(&server.id).await?;
        eligible.push((server, protocols, detour));
    }
    let mut nodes = Vec::new();
    for (server, protocols, detour) in &eligible {
        // App-config only issues detoured Reality endpoints when the user's
        // grants contain a visible, direct Reality entry as well.
        if let Some(entry_id) = detour {
            let reality = vpnctl_core::ProtocolId("vless+reality".into());
            if !protocols.contains(&reality)
                || !eligible.iter().any(|(entry, visible, via)| {
                    entry.id == *entry_id
                        && entry.id != server.id
                        && via.is_none()
                        && visible.contains(&reality)
                })
            {
                continue;
            }
        }
        let endpoints = endpoint_hosts(state, server, protocols, detour.is_some()).await?;
        let sample = state.inv.latest_node_health(&server.id).await?;
        let cached_ips = if server.address.parse::<std::net::IpAddr>().is_ok() {
            Vec::new()
        } else {
            state.inv.resolved_ips_for_server(&server.id).await?
        };
        let country = projection::country_for_node(&server.address, &cached_ips, |ip| {
            state.geo.lookup(ip).and_then(|info| info.country_iso)
        });
        for endpoint_host in endpoints {
            nodes.push(NodeMetadata::new(
                endpoint_host,
                country.clone(),
                sample.as_ref(),
                now,
                ttl,
            ));
        }
    }
    Ok(NodesResponse {
        schema: 1,
        generated_at: now,
        max_age_seconds: ttl,
        nodes,
    })
}

async fn endpoint_hosts(
    state: &AppState,
    server: &Server,
    protocols: &[vpnctl_core::ProtocolId],
    detoured: bool,
) -> Result<Vec<String>, SqliteInventoryError> {
    let mut hosts = std::collections::BTreeSet::new();
    for pid in protocols {
        if detoured && pid.0 != "vless+reality" {
            continue;
        }
        let host = match pid.0.as_str() {
            "naive" => {
                state
                    .inv
                    .get_server_secret(&server.id, "naive.domain")
                    .await?
            }
            "vless-ws" => {
                state
                    .inv
                    .get_server_secret(&server.id, "vlessws.domain")
                    .await?
            }
            _ => Some(server.address.clone()),
        };
        if let Some(host) = host.filter(|host| valid_endpoint_host(host)) {
            hosts.insert(host);
        }
    }
    Ok(hosts.into_iter().collect())
}

fn valid_endpoint_host(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
        || (!host.is_empty()
            && host.len() <= 253
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-'))
}

fn metadata_ttl() -> u64 {
    projection::ttl_for_interval(crate::config::parse_positive_secs(
        "VPNCTLD_NODE_PROBE_INTERVAL_SECS",
        600,
    ))
}

fn secure(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        axum::http::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        axum::http::HeaderValue::from_static("no-referrer"),
    );
    response
}

fn error_response(status: StatusCode, error: &'static str) -> Response {
    secure((status, Json(serde_json::json!({ "error": error }))).into_response())
}

fn throttled(retry: u64) -> Response {
    let mut response = error_response(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    if let Ok(value) = axum::http::HeaderValue::from_str(&retry.to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}
