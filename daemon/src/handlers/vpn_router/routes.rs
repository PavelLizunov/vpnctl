//! Route handlers, rate limiting, and anti-fingerprinting responses for
//! the ninitux subscription compatibility endpoint.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use super::collectors::{
    collect_awg_subscription_uris, collect_extra_protocol_uris, collect_vless_uris_for_user,
    make_config_blob,
};
use super::compat::{is_vpn_client_ua, is_vpnrouter_client_ua};
use crate::app::AppState;

/// JSON wrapper shape — matches `app.schemas.AppConfigResponse` in
/// subscription-server. Field declaration order is the SERIALIZATION
/// order (serde-json preserves struct order); both fastapi and pydantic
/// emit keys in declaration order, so this serialises byte-for-byte
/// against the Python service.
///
/// `config: Option<String>` deliberately does NOT have
/// `#[serde(skip_serializing_if = "Option::is_none")]` — when no
/// config is available the field MUST appear as `"config":null`, not
/// be omitted.
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

/// Build a `device_not_registered` JSON wrapper or empty raw response,
/// per the UA. Used for invalid device_id, missing user, or user with
/// no grants. Same response either way — anti-fingerprinting against
/// probes.
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

/// Manually-rendered JSON response so the byte layout is fully
/// predictable. We use `serde_json::to_vec` (no pretty-print, default
/// compact form) — that matches FastAPI's `JSONResponse` which uses
/// `json.dumps(content, separators=(",", ":"))`. Both produce keys in
/// declaration order with no whitespace.
///
/// On the (effectively-unreachable) serde failure path we MUST still
/// return HTTP 200 — anti-fingerprinting otherwise leaks state via
/// the status code. The fallback body is the canonical
/// `device_not_registered` JSON literal (timestamp=0; preserves the
/// shape without re-entering `json_response`, which would loop).
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

/// Read the UA header + compute `now` + return `empty_response` —
/// the byte-canonical `device_not_registered` shape (or empty raw
/// for VPN client UAs). One helper used by every error / catchall
/// branch in this module: when adding a new error path, call this
/// instead of inlining the 4-line preamble (review-agent flagged
/// drift risk between `get_config_root_catchall` and `get_config`).
pub(crate) fn unregistered_response(headers: &HeaderMap) -> Response {
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let want_raw = is_vpn_client_ua(ua);
    let now = now_unix_secs();
    empty_response(want_raw, now)
}

/// Which source IP (if any) to apply the per-IP anti-flood bucket to.
/// Returns `None` (SKIP per-IP throttle) when the IP is unknown /
/// unspecified (no `ConnectInfo`, e.g. a test rig — can't identify a
/// source), OR when it's one of our own VPN-egress nodes
/// (`is_known_server`): connected clients egress the node, so many users
/// on one server share that IP and per-IP would throttle them as a group
/// — they're protected by the per-`device_id` bucket instead. Otherwise
/// `Some(ip)` → apply the per-IP bucket. Pure (no I/O) so the
/// egress-exemption rule is unit-testable without an HTTP rig.
///
/// Shared by the prod `/api/v1/app/config` endpoint AND the legacy
/// `/sub/<token>` handler (both must exempt our VPN-egress IPs from the
/// shared per-IP axis) — `pub(crate)` so the exemption rule lives in ONE
/// place instead of drifting between the two callers.
pub(crate) fn ip_to_throttle(
    real_ip: Option<std::net::IpAddr>,
    is_known_server: bool,
) -> Option<std::net::IpAddr> {
    match real_ip {
        Some(ip) if !ip.is_unspecified() && !is_known_server => Some(ip),
        _ => None,
    }
}

/// Axum handler — catch-all for `/api/v1/app/config` and
/// `/api/v1/app/config/` (no device_id at all). See the doc-comment
/// on `get_config` below for the defence-in-depth rationale.
pub(crate) async fn get_config_root_catchall(headers: HeaderMap) -> Response {
    unregistered_response(&headers)
}

/// Axum handler — entry point for `GET /api/v1/app/config/{*tail}`.
/// `tail` captures one OR MORE path segments (axum/matchit `*name`
/// semantics). Behaviour:
///
///   * `tail = "<32-lowercase-hex>"` (single segment, valid shape) →
///     existing happy path: device lookup + URI rendering. Byte-
///     equivalent to subscription-server for registered users.
///   * `tail = "<anything-with-a-slash>"` (multi-segment) → catch-
///     all. Never touches inventory; returns the canonical
///     `device_not_registered` shape (or empty-raw for VPN client
///     UAs) directly.
///   * `tail = "<single-segment-bad-shape>"` (e.g. uppercase, too
///     short, has non-hex) → also caught by the existing path-shape
///     gate `vpnctl_crypto::is_valid_vpn_router_device_id(...)` →
///     same `empty_response`.
///
/// Defense-in-depth rationale: without the multi-segment branch
/// here, paths like `/api/v1/app/config/<id>/extra` would surface
/// as a 404 from axum's router (the previous route was the
/// strict-single-segment `/api/v1/app/config/{device_id}`). nginx
/// in front of vpnctld already rewrites the upstream URI to short-
/// circuit this case (Phase 5 post-cutover hardening, 2026-05-19),
/// but the daemon must also be safe if any future upstream forgets
/// the rewrite or if a probe lands directly on port 18402 on the
/// LAN. NEVER a 401 / NEVER a `WWW-Authenticate: Basic realm="vpnctl
/// admin"` header for these paths — that header would identify the
/// backend as vpnctld.
///
/// Why one route instead of `{device_id}` + `{*tail}` split: axum
/// 0.8's matchit 0.8.4 panics at router build time with `Insertion
/// failed due to conflict with previously registered route` when a
/// single-segment `{name}` and a wildcard `{*name}` share the same
/// prefix. The unified handler is the workaround.
pub(crate) async fn get_config(
    State(state): State<AppState>,
    Path(tail): Path<String>,
    // Request must come last (owns body). We pull ConnectInfo from
    // extensions manually — same pattern as sub.rs handler. In
    // production axum injects ConnectInfo via
    // `into_make_service_with_connect_info::<SocketAddr>()`; in test
    // rigs (oneshot) the extension is absent and we fall back to
    // 0.0.0.0 (sub_access_log row still lands so downstream tests
    // can assert the write happened).
    request: axum::extract::Request,
) -> Response {
    let headers = request.headers().clone();
    // Multi-segment defence-in-depth: any `/` in `tail` means the
    // request was /api/v1/app/config/<seg1>/<seg2>[/...]. NEVER a
    // valid device_id; return the same bytes as the unregistered
    // single-segment case. NB: axum's `Path<String>` percent-decodes
    // the captured tail, so `foo%2Fbar` arrives here as `foo/bar`
    // and ALSO trips this gate (verified by spec test).
    if tail.contains('/') || tail.is_empty() {
        return unregistered_response(&headers);
    }

    let device_id = tail;

    // Path-shape gate. Invalid device_id → same response as a
    // valid-but-unregistered device. Mirrors subscription-server's
    // dummy `0`*32 lookup path.
    if !vpnctl_crypto::is_valid_vpn_router_device_id(&device_id) {
        return unregistered_response(&headers);
    }

    // From here on we KNOW `tail` is a valid 32-hex device_id; the
    // remaining branches inherit `want_raw` + `now` for the happy
    // path. Keep the explicit variables (rather than re-deriving via
    // `unregistered_response`) so the happy-path JSON wrapper still
    // carries the SAME `timestamp` as any subsequent error
    // `empty_response` call for this request.
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let want_raw = is_vpn_client_ua(ua);
    let now = now_unix_secs();

    // ── Rate limit (item-3, 2026-06-01) ───────────────────────────
    // Two axes like /sub, but tuned for the fact that a VPN-connected
    // client's config refresh EGRESSES its node — vpnctld sees the
    // SERVER's IP, so N users on one server share it. So the per-IP
    // bucket is applied ONLY to NON-egress source IPs (anti-flood vs
    // random-device_id scraping from an attacker's own IP); the
    // per-device_id bucket (post-resolve, below) is the real per-user
    // limit, so e.g. 33 users on one node never throttle each other.
    // Throttle-only — NO persistent ban here: banning an egress IP or a
    // legit user's device_id over a misbehaving-app retry-storm would
    // sever real VPN access.
    let peer_ip: Option<std::net::IpAddr> = request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|axum::extract::ConnectInfo(addr)| addr.ip());
    // SECURITY decision IP — spoof-proof `X-Real-IP` (nginx overwrites
    // it with the true peer). NOT the leftmost XFF: nginx APPENDS via
    // `$proxy_add_x_forwarded_for`, so a client could prepend a fake
    // VPN-node IP to leftmost-XFF and either dodge the per-IP throttle
    // OR wrongly claim the egress-exemption. Using X-Real-IP closes
    // that. (Logging below keeps leftmost-XFF — observability, separate
    // concern.)
    let rl_ip: Option<std::net::IpAddr> =
        peer_ip.map(|p| crate::real_ip::resolve_peer_real_ip(&headers, p));
    // Logging IP (abuse-detection observability) — established
    // leftmost-XFF semantics, unchanged. Reused by the access-log below.
    let real_ip: Option<std::net::IpAddr> =
        peer_ip.map(|p| crate::real_ip::resolve_real_ip(&headers, p));
    let is_egress = match rl_ip {
        Some(ip) if !ip.is_unspecified() => state
            .inv
            .is_known_server_address(&ip.to_string())
            .await
            .unwrap_or(false), // DB hiccup → treat as non-egress (fail toward throttling)
        _ => false,
    };
    if let Some(ip) = ip_to_throttle(rl_ip, is_egress) {
        if let Err((retry, _)) = state.rate_limiter.try_acquire_ip(ip) {
            return crate::handlers::sub::rate_limited(retry, "ip");
        }
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

    // Per-device_id throttle — post-resolve so random/unregistered ids
    // never fill the bucket map. THE per-user limit, independent of the
    // egress path: each device_id is its own bucket, so many users
    // behind one VPN node never share a quota.
    if let Err((retry, _)) = state.rate_limiter.try_acquire_token(&device_id) {
        return crate::handlers::sub::rate_limited(retry, "device");
    }

    // B1.user (audit 2026-05-22, migration 0026). Disabled users
    // get the same empty-response envelope as «no such device_id»
    // — the ninitux endpoint's existing empty path renders the
    // standard «no servers» config so the client parses
    // successfully + falls back to direct routing. Re-enabling
    // restores access without rotating device_id/sub_token.
    if user.disabled {
        tracing::info!(
            target = "vpnctld::vpn_router",
            user = %user.id,
            "user is disabled — returning empty config"
        );
        return empty_response(want_raw, now);
    }

    let mut uris = match collect_vless_uris_for_user(&state, &user.id, &user.id.0).await {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!(target = "vpnctld::vpn_router", user = %user.id, error = %e, "uri collection failed");
            return empty_response(want_raw, now);
        }
    };

    // Extra protocols beyond the byte-stable vless render, appended STRICTLY
    // AFTER all vless (two-pass) so a tolerant line-by-line client parser
    // keeps every vless even if it can't parse a trailing extra line. Each is
    // opt-in by grant + NM-10 visibility (hide = instant request-time
    // kill-switch) and failure-isolated: a collection error logs + serves
    // what we already have, never dropping a user's vless. Order is stable
    // (declaration order), so the blob stays deterministic.
    //
    //   naive     — Caddy kernel; requires the `naive.domain` ACME secret.
    //   hysteria2 — sing-box (UDP/8444); Salamander obfs is auto-applied when
    //               its server secret is minted (the share-link mirrors it).
    //   dns-tunnel — slipstream-over-НСДИ break-glass transport. Delivered
    //               here, NOT in the sing-box envelope or the v2ray /sub
    //               (`appears_in_sing_box_sub() == false`): a `dns-tunnel://`
    //               line is unparseable to a generic sing-box/v2ray client
    //               and would drop the whole config, so ONLY our custom
    //               VPNRouter client — which reads this tolerant blob — ever
    //               sees it. Gated on the operator-set `dns-tunnel:domain`
    //               secret; the share-link also needs `dns-tunnel:fingerprint`
    //               (a render-error there is logged + skipped per-server, same
    //               failure-isolation as the others). No `pair=` — the tunnel
    //               carries everything over its loopback VLESS, so there's no
    //               co-located UDP sibling to pair with. The `dns-tunnel://`
    //               line lands strictly after every vless, so a client build
    //               without dns-tunnel support simply ignores the trailing
    //               line and keeps every vless (forward-compatible rollout).
    const EXTRA_PROTOCOLS: &[(&str, &str, Option<&str>)] = &[
        ("naive", "NAIVE", Some("naive.domain")),
        ("hysteria2", "HY2", None),
        // vless-ws — VLESS/WebSocket+TLS direct (caddy front, no CDN). The
        // RU-DPI fallback the v2ray-core family (v2RayTun) CAN parse, unlike
        // HY2/TUIC. Skipped on a server without the `vlessws.domain` ACME
        // secret (same gate shape as naive). `share_link` additionally needs
        // the minted `vlessws.path` → a server missing it logs+skips
        // (failure-isolated), never dropping the user's vless.
        ("vless-ws", "WS", Some("vlessws.domain")),
        ("dns-tunnel", "WL-BYPASS", Some("dns-tunnel:domain")),
    ];
    for (pid_str, label_tag, require_secret) in EXTRA_PROTOCOLS {
        let pid = vpnctl_core::ProtocolId((*pid_str).to_string());
        match collect_extra_protocol_uris(&state, &user, &pid, label_tag, *require_secret).await {
            Ok(extra) => uris.extend(extra),
            Err(e) => {
                tracing::warn!(target = "vpnctld::vpn_router", user = %user.id, protocol = %pid_str, error = %e, "extra-protocol uri collection failed; skipping");
            }
        }
    }

    // Custom schemes — UA-gated to the operator's VPNRouter client, the only
    // consumer that parses them; generic v2ray/clash clients never see them,
    // so advertising a custom transport fleet-wide can't break their parser.
    if is_vpnrouter_client_ua(ua) {
        // AmneziaWG (awg://) — special renderer (`awg_share_link`, per-peer
        // context), gated on `wireguard` visibility + the minted obfs.
        uris.extend(collect_awg_subscription_uris(&state, &user).await);
        // vless+xhttp — renders via the generic `share_link` (a `vless://…
        // type=xhttp` URI), gated on `vlessxhttp.path` + NM-10 visibility.
        // Same failure-isolation as the other extras; lands after every vless.
        let xhttp_pid = vpnctl_core::ProtocolId("vless+xhttp".to_string());
        match collect_extra_protocol_uris(
            &state,
            &user,
            &xhttp_pid,
            "XHTTP",
            Some("vlessxhttp.path"),
        )
        .await
        {
            Ok(extra) => uris.extend(extra),
            Err(e) => {
                tracing::warn!(target = "vpnctld::vpn_router", user = %user.id, error = %e, "vless+xhttp uri collection failed; skipping");
            }
        }
    }

    let Some(config) = make_config_blob(&uris) else {
        return empty_response(want_raw, now);
    };

    // Phase Track-1 abuse signal — production endpoint visibility.
    // Without this enqueue, EVERY ninitux pull from a mobile client
    // is invisible to the operator (sub_access_log fills only from
    // the legacy `/sub/<token>` path which the new clients don't use
    // post-Phase-5 cutover). Same back-pressure pattern as `sub.rs`:
    // bounded mpsc channel drained by a dedicated writer task;
    // `try_send` is non-blocking so the HTTP response never waits
    // on the SQLite write, and a saturated channel drops the row
    // with a warn rather than OOM'ing the process. Logged metadata:
    // user_id (from device_id lookup we already did), source IP
    // (cardinality bound for abuse-detection bucketing), UA (for
    // Layer-3 client-fingerprint clustering), status 200, response
    // bytes for traffic-distribution histograms. Caught 2026-05-20
    // by Pavel's post-Phase-7 audit: "сколько у него ip, сколько
    // интернета, с каких девайсов".
    // peer_ip + real_ip were already resolved above for the rate-limiter
    // (item-3) via the same `resolve_real_ip` (XFF parsed only from a
    // trusted proxy; spoof-safe). Reuse them — both are `Copy` — instead
    // of a second extensions() read.
    let ip_for_log = real_ip
        .map(|a| a.to_string())
        .unwrap_or_else(|| "0.0.0.0".to_string());
    let ua_for_log: Option<String> = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let bytes_for_log = u64::try_from(config.len()).unwrap_or(u64::MAX);
    // Track-1.2: richer per-request metadata (migration 0019). Same
    // shape as sub.rs handler.
    let accept_language: Option<String> = headers
        .get(header::ACCEPT_LANGUAGE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.chars().take(120).collect::<String>());
    let http_version = Some(crate::ua::http_version_label(request.version()).to_owned());
    let device_class = crate::ua::parse_ua_short(ua_for_log.as_deref()).map(str::to_owned);
    // Track-1.4 — TLS fingerprint from nginx-forwarded headers,
    // gated by VPNCTLD_TRUSTED_PROXIES. peer_ip is the raw TCP peer
    // (NOT the XFF-resolved one) since the trust gate keys on the
    // immediate connection's source.
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
            // GeoIP fields populated by writer task.
            geo_country: None,
            geo_asn: None,
            tls_ja3,
            tls_ja4,
        },
    );

    if want_raw {
        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            config,
        )
            .into_response();
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
    json_response(&body)
}
