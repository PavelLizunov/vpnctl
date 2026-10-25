use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::extract::{ConnectInfo, Path, Query, Request, State};
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use serde::Deserialize;
use vpnctl_core::User;

use super::mihomo::render_mihomo;
use super::singbox::render_singbox;
use super::v2ray::render_v2ray_subscription;
use crate::app::AppState;

static WARNED_MISSING_CONNECT_INFO: AtomicBool = AtomicBool::new(false);

#[derive(Deserialize)]
struct SubQuery {
    format: Option<String>,
}

enum FormatSelector {
    SingBox,
    Mihomo,
}

enum SubFormat {
    V2Ray,
    SingBox { stock_only: bool },
    Mihomo,
}

#[derive(Clone, Copy)]
struct DefaultMihomo;

pub(crate) async fn get_mihomo(
    state: State<AppState>,
    path: Path<String>,
    mut request: Request,
) -> impl IntoResponse {
    request.extensions_mut().insert(DefaultMihomo);
    get(state, path, request).await
}

pub(crate) async fn get(
    State(state): State<AppState>,
    Path(token): Path<String>,
    request: Request,
) -> impl IntoResponse {
    let ua = request
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let accept_language = request
        .headers()
        .get(header::ACCEPT_LANGUAGE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.chars().take(120).collect::<String>());
    let http_version = Some(crate::ua::http_version_label(request.version()).to_owned());
    let device_class = crate::ua::parse_ua_short(ua.as_deref()).map(str::to_owned);
    let peer_ip: Option<std::net::IpAddr> = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip());
    let SubIps {
        log_ip: real_peer_ip,
        sec_ip: sec_peer_ip,
    } = resolve_sub_ips(request.headers(), peer_ip);
    let ip = match real_peer_ip {
        Some(addr) => addr.to_string(),
        None => {
            if !WARNED_MISSING_CONNECT_INFO.swap(true, Ordering::Relaxed) {
                tracing::warn!(
                    target = "vpnctld::sub",
                    "ConnectInfo extension absent — sub_access_log will record 0.0.0.0 for every hit \
                     until make-service is fixed; this kills the abuse-signal accuracy"
                );
            }
            "0.0.0.0".to_string()
        }
    };

    let is_egress = match sec_peer_ip {
        Some(addr) if !addr.is_unspecified() => state
            .inv
            .is_known_server_address(&addr.to_string())
            .await
            .unwrap_or(false),
        _ => false,
    };
    let per_ip_ip = crate::handlers::vpn_router::ip_to_throttle(sec_peer_ip, is_egress);

    if let Some(addr) = per_ip_ip {
        let ip_str = addr.to_string();
        match state.inv.is_banned("ip", &ip_str).await {
            Ok(Some(secs)) => return rate_limited(secs, "ip-ban"),
            Ok(None) => {}
            Err(e) => tracing::warn!(
                target = "vpnctld::sub",
                ip = %ip_str,
                error = %e,
                "is_banned(ip) failed; falling through to bucket"
            ),
        }
    }

    if let Some(addr) = per_ip_ip {
        if let Err((retry, denial_count)) = state.rate_limiter.try_acquire_ip(addr) {
            if denial_count == crate::rate_limit::K_DENIALS_TO_BAN {
                let ip_str = addr.to_string();
                let reason = format!("{denial_count} consecutive 429s on /sub");
                match state
                    .inv
                    .add_ban(
                        "ip",
                        &ip_str,
                        crate::rate_limit::DEFAULT_BAN_TTL_SECS,
                        &reason,
                    )
                    .await
                {
                    Ok(()) => {
                        tracing::warn!(
                            target = "vpnctld::sub",
                            ip = %ip_str,
                            denials = denial_count,
                            ttl_secs = crate::rate_limit::DEFAULT_BAN_TTL_SECS,
                            "escalated to 24h persistent ban after consecutive 429s"
                        );
                        if let Err(e) = state
                            .inv
                            .audit(
                                "daemon",
                                "rate.ban.add",
                                Some(&ip_str),
                                Some(&serde_json::json!({
                                    "kind": "ip",
                                    "ttl_secs": crate::rate_limit::DEFAULT_BAN_TTL_SECS,
                                    "reason": reason,
                                })),
                            )
                            .await
                        {
                            tracing::warn!(
                                target = "vpnctld::sub",
                                ip = %ip_str,
                                error = %e,
                                "audit row for rate.ban.add(ip) failed; ban already persisted"
                            );
                        }
                        state.rate_limiter.reset_denials_ip(addr);
                    }
                    Err(e) => {
                        tracing::error!(
                            target = "vpnctld::sub",
                            ip = %ip_str,
                            error = %e,
                            "add_ban(ip) failed; clamping denial counter to K-1 to retry on next denial"
                        );
                        state.rate_limiter.clamp_denials_ip(addr);
                    }
                }
            }
            return rate_limited(retry, "ip");
        }
    }

    let ua_wants_v2ray_subscription = ua
        .as_deref()
        .map(crate::handlers::vpn_router::is_vpn_client_ua_v2ray_family)
        .unwrap_or(false);

    let user = match resolve_user(&state, &token).await {
        Ok(user) => user,
        Err(SubError::NotFound) => {
            return (StatusCode::NOT_FOUND, "unknown token\n").into_response();
        }
        Err(SubError::Internal(msg)) => {
            tracing::error!(target = "vpnctld::sub", error = %msg, "sub user resolve failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error\n").into_response();
        }
    };

    match state.inv.is_banned("token", &token).await {
        Ok(Some(secs)) => return rate_limited(secs, "token-ban"),
        Ok(None) => {}
        Err(e) => tracing::warn!(
            target = "vpnctld::sub",
            error = %e,
            "is_banned(token) failed; falling through to bucket"
        ),
    }

    if let Err((retry, denial_count)) = state.rate_limiter.try_acquire_token(&token) {
        if denial_count == crate::rate_limit::K_DENIALS_TO_BAN {
            let reason = format!("{denial_count} consecutive 429s on /sub");
            match state
                .inv
                .add_ban(
                    "token",
                    &token,
                    crate::rate_limit::DEFAULT_BAN_TTL_SECS,
                    &reason,
                )
                .await
            {
                Ok(()) => {
                    tracing::warn!(
                        target = "vpnctld::sub",
                        denials = denial_count,
                        ttl_secs = crate::rate_limit::DEFAULT_BAN_TTL_SECS,
                        "escalated to 24h persistent ban after consecutive 429s"
                    );
                    let audit_target = if token.chars().count() <= 8 {
                        "<redacted>".to_string()
                    } else {
                        crate::handlers::admin::users::mask_secret(&token)
                    };
                    if let Err(e) = state
                        .inv
                        .audit(
                            "daemon",
                            "rate.ban.add",
                            Some(&audit_target),
                            Some(&serde_json::json!({
                                "kind": "token",
                                "ttl_secs": crate::rate_limit::DEFAULT_BAN_TTL_SECS,
                                "reason": reason,
                            })),
                        )
                        .await
                    {
                        tracing::warn!(
                            target = "vpnctld::sub",
                            error = %e,
                            "audit row for rate.ban.add(token) failed; ban already persisted"
                        );
                    }
                    state.rate_limiter.reset_denials_token(&token);
                }
                Err(e) => {
                    tracing::error!(
                        target = "vpnctld::sub",
                        error = %e,
                        "add_ban(token) failed; clamping denial counter to K-1 to retry on next denial"
                    );
                    state.rate_limiter.clamp_denials_token(&token);
                }
            }
        }
        return rate_limited(retry, "token");
    }

    let default_mihomo = request.extensions().get::<DefaultMihomo>().is_some();

    let format_selector = match Query::<SubQuery>::try_from_uri(request.uri()) {
        Ok(Query(query)) => match query.format.as_deref() {
            None => None,
            Some("sing-box") => Some(FormatSelector::SingBox),
            Some("mihomo") => Some(FormatSelector::Mihomo),
            Some(_) => {
                return (StatusCode::BAD_REQUEST, "invalid format selector\n").into_response();
            }
        },
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid format selector\n").into_response(),
    };

    let sub_format = match format_selector {
        Some(FormatSelector::Mihomo) => SubFormat::Mihomo,
        Some(FormatSelector::SingBox) => SubFormat::SingBox { stock_only: true },
        None if default_mihomo => SubFormat::Mihomo,
        None if ua_wants_v2ray_subscription => SubFormat::V2Ray,
        None => SubFormat::SingBox { stock_only: false },
    };

    let (tls_ja3, tls_ja4) = peer_ip
        .map(|p| crate::real_ip::collect_tls_fingerprints(request.headers(), p))
        .unwrap_or((None, None));

    let render_res = match sub_format {
        SubFormat::V2Ray => render_v2ray_subscription(&state, &user, ua.as_deref())
            .await
            .map(|(uid, body)| (uid, body, "text/plain; charset=utf-8")),
        SubFormat::SingBox { stock_only } => render_singbox(&state, &user, stock_only)
            .await
            .map(|(uid, cfg)| (uid, cfg.to_string(), "application/json")),
        SubFormat::Mihomo => render_mihomo(&state, &user)
            .await
            .map(|(uid, yaml)| (uid, yaml, "text/yaml")),
    };

    match render_res {
        Ok((user_id, body, content_type)) => {
            let bytes = u64::try_from(body.len()).unwrap_or(u64::MAX);
            let _ = crate::access_log::try_enqueue(
                &state.access_log_tx,
                crate::access_log::AccessLogRecord {
                    user_id,
                    ip,
                    ua,
                    status: 200,
                    bytes,
                    accept_language,
                    http_version,
                    device_class,
                    geo_country: None,
                    geo_asn: None,
                    tls_ja3,
                    tls_ja4,
                },
            );

            (StatusCode::OK, [("content-type", content_type)], body).into_response()
        }
        Err(SubError::NotFound) => (StatusCode::NOT_FOUND, "unknown token\n").into_response(),
        Err(SubError::Internal(msg)) => {
            tracing::error!(target = "vpnctld::sub", error = %msg, "sub render failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error\n").into_response()
        }
    }
}

pub(super) struct SubIps {
    pub(super) log_ip: Option<std::net::IpAddr>,
    pub(super) sec_ip: Option<std::net::IpAddr>,
}

fn resolve_sub_ips(headers: &header::HeaderMap, peer_ip: Option<std::net::IpAddr>) -> SubIps {
    SubIps {
        log_ip: peer_ip.map(|p| crate::real_ip::resolve_real_ip(headers, p)),
        sec_ip: peer_ip.map(|p| crate::real_ip::resolve_peer_real_ip(headers, p)),
    }
}

#[cfg(test)]
pub(super) fn resolve_sub_ips_with(
    headers: &header::HeaderMap,
    peer_ip: Option<std::net::IpAddr>,
    trusted: &[std::net::IpAddr],
) -> SubIps {
    SubIps {
        log_ip: peer_ip.map(|p| crate::real_ip::resolve_real_ip_with(headers, p, trusted)),
        sec_ip: peer_ip.map(|p| crate::real_ip::resolve_peer_real_ip_with(headers, p, trusted)),
    }
}

pub(crate) fn rate_limited(retry_after_secs: u64, gate: &'static str) -> axum::response::Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [
            ("retry-after", retry_after_secs.to_string()),
            ("content-type", "text/plain; charset=utf-8".to_string()),
        ],
        format!("rate limited ({gate}); retry in {retry_after_secs}s\n"),
    )
        .into_response()
}

#[derive(Debug)]
pub(super) enum SubError {
    NotFound,
    Internal(String),
}

async fn resolve_user(state: &AppState, token: &str) -> Result<User, SubError> {
    state
        .inv
        .find_user_by_sub_token(token)
        .await
        .map_err(|e| SubError::Internal(format!("inventory: {e}")))?
        .ok_or(SubError::NotFound)
}
