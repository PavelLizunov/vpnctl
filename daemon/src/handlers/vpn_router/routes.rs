use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use super::collectors::{
    collect_awg_subscription_uris, collect_extra_protocol_uris, collect_vless_uris_with_entries,
    collect_vmess_uris, make_config_blob,
};
use super::compat::{is_vpn_client_ua, is_vpnrouter_client_ua};
use crate::app::AppState;

#[derive(Serialize)]
pub(crate) struct AppConfigResponse {
    pub(crate) status: &'static str,
    pub(crate) app: &'static str,
    pub(crate) version: &'static str,
    pub(crate) update_available: bool,
    pub(crate) config: Option<String>,
    pub(crate) check_interval: u32,
    pub(crate) timestamp: u64,
}

pub(crate) const APP_NAME: &str = "vpn-router";
pub(crate) const APP_VERSION: &str = "2.4.1";
pub(crate) const CHECK_INTERVAL_SECS: u32 = 3600;

pub(crate) fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub(crate) fn empty_response(want_raw: bool, now: u64) -> Response {
    if want_raw {
        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            String::new(),
        )
            .into_response();
    }
    let body = AppConfigResponse {
        status: "device_not_registered",
        app: APP_NAME,
        version: APP_VERSION,
        update_available: false,
        config: None,
        check_interval: CHECK_INTERVAL_SECS,
        timestamp: now,
    };
    json_response(&body)
}

pub(crate) fn json_response<T: Serialize>(value: &T) -> Response {
    match serde_json::to_vec(value) {
        Ok(bytes) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            bytes,
        )
            .into_response(),
        Err(e) => {
            tracing::error!(target = "vpnctld::vpn_router", error = %e, "json serialisation failed; falling back to empty 200");
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                br#"{"status":"device_not_registered","app":"vpn-router","version":"2.4.1","update_available":false,"config":null,"check_interval":3600,"timestamp":0}"#.as_slice(),
            )
                .into_response()
        }
    }
}

pub(crate) fn unregistered_response(headers: &HeaderMap) -> Response {
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let want_raw = is_vpn_client_ua(ua);
    let now = now_unix_secs();
    empty_response(want_raw, now)
}

pub(crate) fn ip_to_throttle(
    real_ip: Option<std::net::IpAddr>,
    is_known_server: bool,
) -> Option<std::net::IpAddr> {
    match real_ip {
        Some(ip) if !ip.is_unspecified() && !is_known_server => Some(ip),
        _ => None,
    }
}

pub(crate) async fn get_config_root_catchall(headers: HeaderMap) -> Response {
    unregistered_response(&headers)
}

fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    values.next().is_none().then_some(value)
}

pub(crate) async fn get_config(
    State(state): State<AppState>,
    Path(tail): Path<String>,
    request: axum::extract::Request,
) -> Response {
    let headers = request.headers().clone();
    if tail.contains('/') || tail.is_empty() {
        return unregistered_response(&headers);
    }

    let device_id = tail;

    if !vpnctl_crypto::is_valid_vpn_router_device_id(&device_id) {
        return unregistered_response(&headers);
    }

    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let want_raw = is_vpn_client_ua(ua);
    let vpnrouter = is_vpnrouter_client_ua(ua);
    let desktop_vpnrouter = single_header(&headers, "user-agent")
        .and_then(|ua| ua.split_ascii_whitespace().next())
        .and_then(|product| product.split('/').next())
        .is_some_and(|product| product.eq_ignore_ascii_case("VPNRouter"));
    let desktop_core = if desktop_vpnrouter
        && matches!(
            single_header(&headers, "x-vpnrouter-platform"),
            Some("windows" | "macos" | "linux")
        ) {
        single_header(&headers, "x-vpnrouter-core-version")
    } else {
        None
    };
    let supports = |capability: &str| {
        vpnrouter
            && headers
                .get_all("X-VPNRouter-Capabilities")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .flat_map(|s| s.split(',').flat_map(str::split_whitespace))
                .any(|token| token == capability)
    };
    let has_detour_cap = supports("detour-v1");
    let has_dnstt_cap = supports("dnstt-v1");
    let has_vmess_cap = supports("vmess-v1");
    let now = now_unix_secs();

    let peer_ip: Option<std::net::IpAddr> = request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|axum::extract::ConnectInfo(addr)| addr.ip());
    let rl_ip: Option<std::net::IpAddr> =
        peer_ip.map(|p| crate::real_ip::resolve_peer_real_ip(&headers, p));
    let real_ip: Option<std::net::IpAddr> =
        peer_ip.map(|p| crate::real_ip::resolve_real_ip(&headers, p));
    let is_egress = match rl_ip {
        Some(ip) if !ip.is_unspecified() => state
            .inv
            .is_known_server_address(&ip.to_string())
            .await
            .unwrap_or(false),
        _ => false,
    };
    if let Some(ip) = ip_to_throttle(rl_ip, is_egress)
        && let Err((retry, _)) = state.rate_limiter.try_acquire_ip(ip)
    {
        return crate::handlers::sub::rate_limited(retry, "ip");
    }

    let user = match state
        .inv
        .find_user_by_vpn_router_device_id(&device_id)
        .await
    {
        Ok(Some(u)) => u,
        Ok(None) => return empty_response(want_raw, now),
        Err(e) => {
            tracing::error!(target = "vpnctld::vpn_router", error = %e, "inventory lookup failed");
            return empty_response(want_raw, now);
        }
    };

    if let Err((retry, _)) = state.rate_limiter.try_acquire_token(&device_id) {
        return crate::handlers::sub::rate_limited(retry, "device");
    }

    if user.disabled {
        tracing::info!(
            target = "vpnctld::vpn_router",
            user = %user.id,
            "user is disabled — returning empty config"
        );
        return empty_response(want_raw, now);
    }

    let inputs = match state
        .inv
        .subscription_render_inputs_for_client(&user.id, vpnrouter, desktop_core)
        .await
    {
        Ok(inputs) => inputs,
        Err(e) => {
            tracing::warn!(target = "vpnctld::vpn_router", user = %user.id, error = %e, "subscription render inputs failed");
            return empty_response(want_raw, now);
        }
    };
    let (vmess, vmess_entries) = if has_vmess_cap {
        collect_vmess_uris(&state, &inputs, &user, has_detour_cap)
    } else {
        Default::default()
    };
    let mut uris =
        collect_vless_uris_with_entries(&inputs, &user.id.0, has_detour_cap, &vmess_entries);

    const EXTRA_PROTOCOLS: &[(&str, &str, Option<&str>)] = &[
        ("naive", "NAIVE", Some("naive.domain")),
        ("vless-ws", "WS", Some("vlessws.domain")),
    ];
    for (pid_str, label_tag, require_secret) in EXTRA_PROTOCOLS {
        let pid = vpnctl_core::ProtocolId((*pid_str).to_string());
        uris.extend(collect_extra_protocol_uris(
            &state,
            &inputs,
            &user,
            &pid,
            label_tag,
            *require_secret,
        ));
    }

    if is_vpnrouter_client_ua(ua) {
        uris.extend(collect_awg_subscription_uris(&inputs, &user));
        let xhttp_pid = vpnctl_core::ProtocolId("vless+xhttp".to_string());
        uris.extend(collect_extra_protocol_uris(
            &state,
            &inputs,
            &user,
            &xhttp_pid,
            "XHTTP",
            Some("vlessxhttp.path"),
        ));
    }

    if has_dnstt_cap {
        let dnstt = vpnctl_core::ProtocolId("dnstt".to_string());
        uris.extend(collect_extra_protocol_uris(
            &state,
            &inputs,
            &user,
            &dnstt,
            "DNSTT",
            Some("observed.dnstt.applied"),
        ));
    }

    uris.extend(vmess);

    let Some(config) = make_config_blob(&uris) else {
        return empty_response(want_raw, now);
    };

    let ip_for_log = real_ip
        .map(|a| a.to_string())
        .unwrap_or_else(|| "0.0.0.0".to_string());
    let ua_for_log: Option<String> = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let bytes_for_log = u64::try_from(config.len()).unwrap_or(u64::MAX);
    let accept_language: Option<String> = headers
        .get(header::ACCEPT_LANGUAGE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.chars().take(120).collect::<String>());
    let http_version = Some(crate::ua::http_version_label(request.version()).to_owned());
    let device_class = crate::ua::parse_ua_short(ua_for_log.as_deref()).map(str::to_owned);
    let (tls_ja3, tls_ja4) = peer_ip
        .map(|p| crate::real_ip::collect_tls_fingerprints(&headers, p))
        .unwrap_or((None, None));
    let _ = crate::access_log::try_enqueue(
        &state.access_log_tx,
        crate::access_log::AccessLogRecord {
            user_id: user.id.clone(),
            ip: ip_for_log,
            ua: ua_for_log,
            status: 200,
            bytes: bytes_for_log,
            accept_language,
            http_version,
            device_class,
            geo_country: None,
            geo_asn: None,
            tls_ja3,
            tls_ja4,
        },
    );

    if want_raw {
        return config_response(
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                config,
            )
                .into_response(),
        );
    }

    let body = AppConfigResponse {
        status: "ok",
        app: APP_NAME,
        version: APP_VERSION,
        update_available: false,
        config: Some(config),
        check_interval: CHECK_INTERVAL_SECS,
        timestamp: now,
    };
    config_response(json_response(&body))
}

fn config_response(mut response: Response) -> Response {
    use axum::http::HeaderValue;
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    response.headers_mut().append(
        header::VARY,
        HeaderValue::from_static(
            "User-Agent, X-VPNRouter-Capabilities, X-VPNRouter-Platform, X-VPNRouter-Core-Version",
        ),
    );
    response
}
