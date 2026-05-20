//! `GET /api/v1/app/config/{device_id}` — ninitux subscription-server
//! compatibility endpoint (Phase 3 of the migration plan in
//! `docs/COMPREHENSIVE_AUDIT_2026-05-19.md`).
//!
//! Goal: every client that today fetches its config via
//! `https://ninitux.com/api/v1/app/config/<device_id>` continues to
//! work after nginx (Phase 5) cuts that path over to vpnctld. The
//! response shape mirrors subscription-server's `app/routers/subscription.py`
//! byte-for-byte:
//!
//!   * HTTP 200 always — anti-fingerprinting against probes that
//!     would otherwise tell a missing device_id from a valid one
//!     via the status code. NB: subscription-server (and therefore
//!     this handler, to preserve byte-equivalence) does NOT
//!     constant-length the response body — a registered device's
//!     base64 blob is much larger than the empty string returned for
//!     the unregistered raw path, so Content-Length still leaks
//!     state. Inherited limitation, not a regression. A future
//!     hardening pass could pad the empty response to a typical
//!     blob length, but that breaks byte-equivalence with the
//!     Python service and would need to be applied to both sides
//!     simultaneously.
//!   * Inventory read errors (DB outage, schema drift) collapse to
//!     the `device_not_registered` shape rather than 5xx — preserves
//!     anti-fingerprinting and lets the daemon keep serving other
//!     paths. Operator-visible signal lives in `tracing::error!`
//!     under target=`vpnctld::vpn_router` (read via `journalctl -u
//!     vpnctld`). Wiring this into `admin_alerts` is Phase G work,
//!     deferred.
//!   * Path is NOT rate-limited at the handler level (unlike
//!     `/sub/{token}`). Pre-Phase-5 the endpoint is reachable only
//!     on the LAN-only daemon port 18402; pre-cutover hardening
//!     (Phase 4.5) adds an axum rate-limit middleware on
//!     `/api/v1/app/config/*` before nginx switches external
//!     traffic onto it.
//!   * UA-based content negotiation. Standard VPN clients
//!     (Streisand, v2rayNG, Shadowrocket, Hiddify, sing-box, …) get
//!     `text/plain; charset=utf-8` with the raw base64 subscription.
//!     Browsers / curl / the custom «VPN Router» app get the JSON
//!     wrapper (`status, app, version, update_available, config,
//!     check_interval, timestamp` in that exact key order).
//!   * Base64-of-newline-joined-`vless://` URIs as the payload.
//!   * Per-server `client_uuid` taken from `grants.client_uuid` set
//!     by the Phase 2 import; the VLESS render uses ninitux's
//!     specific query-param order (`type, security, pbk, fp, sni,
//!     sid, spx, flow`) — NOT vpnctld's existing `share_link()`
//!     format (which is bash-script-derived + pinned by
//!     `vless_happy_path_byte_equal` — leaving it untouched).
//!   * Fragment label `"{server_stripped} {port} {client_name}"`
//!     where `server_stripped = "vps-de-01"` → `"de-01"`. Full URL
//!     encoding (spaces → `%20`, hyphens kept).
//!
//! KNOWN GAP — multi-SNI inbounds:
//!   Subscription-server emits ONE vless URI per VLESS inbound per
//!   granted server (vps-de-01 has 2, vps-is-01 has 3). vpnctld
//!   today only tracks a single VLESS inbound per server in
//!   `server_secrets` (no `vless.extra_sni_1` etc.). This handler
//!   emits ONE URI per granted server, byte-equivalent on the
//!   primary inbound (port 443 + microsoft.com SNI), but missing the
//!   secondary/tertiary failover URIs. Acceptable for migration —
//!   clients still connect via the primary URI; failover redundancy
//!   on secondary ports is lost until vpnctld grows multi-inbound
//!   per-protocol support. Document this in the Phase 4 A/B report.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde::Serialize;
use vpnctl_core::UserId;

use crate::app::AppState;

/// Matches `urllib.parse.quote(s, safe="")` — encodes everything
/// except ASCII alphanumerics + `-._~`. Used for the URL fragment in
/// each vless:// link, mirroring `_make_uri_for_inbound` in
/// `subscription-server/app/ssh_manager.py`.
const NINITUX_QUOTE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

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
struct AppConfigResponse {
    status: &'static str,
    app: &'static str,
    version: &'static str,
    update_available: bool,
    config: Option<String>,
    check_interval: u32,
    timestamp: u64,
}

const APP_NAME: &str = "vpn-router";
const APP_VERSION: &str = "2.4.1";
const CHECK_INTERVAL_SECS: u32 = 3600;

/// Lowercase substrings that identify a standard VPN client UA — when
/// any of these appear in the header, the response switches to raw
/// base64 instead of the JSON wrapper. Verbatim from
/// `_VPN_CLIENT_KEYWORDS` in
/// `subscription-server/app/routers/subscription.py`.
const VPN_CLIENT_KEYWORDS: &[&str] = &[
    "streisand",
    "v2rayn",
    "v2rayng",
    "shadowrocket",
    "quantumult",
    "surge",
    "clash",
    "sing-box",
    "hiddify",
    "nekoray",
    "nekobox",
    "v2box",
    "foxray",
    "matsuri",
    "sagernet",
    "karing",
];

fn is_vpn_client_ua(ua: &str) -> bool {
    let lower = ua.to_ascii_lowercase();
    VPN_CLIENT_KEYWORDS.iter().any(|kw| lower.contains(kw))
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Build a single ninitux-format vless URI. Caller provides the
/// pre-stripped server tag (`"de-01"` not `"vps-de-01"`).
///
/// Eight scalar args is a lot, but they're all independent strings
/// passed straight through to `format!()`; bundling them into a
/// `RenderCtx`-style struct would mean a copy at every callsite (the
/// caller already holds the values as `&str` from separate sources:
/// `Server.address`, `server_secrets["vless.public_key"]`, etc.). The
/// `clippy::too_many_arguments` lint targets readability problems
/// from cohesive parameters that ought to be grouped — these are
/// not. Pinned by `render_vless_uri_matches_ninitux_byte_format`.
#[allow(clippy::too_many_arguments)]
fn render_vless_uri(
    server_ip: &str,
    port: u16,
    sni: &str,
    pbk: &str,
    sid: &str,
    client_uuid: &str,
    server_tag: &str,
    client_name: &str,
) -> String {
    // Param order: type, security, pbk, fp, sni, sid, spx, flow.
    // No `encryption=none` (subscription-server omits it; vpnctld's
    // /sub share_link does include it for bash-script byte-equality,
    // but the ninitux endpoint must NOT include it).
    let pbk_e = utf8_percent_encode(pbk, NINITUX_QUOTE);
    let sni_e = utf8_percent_encode(sni, NINITUX_QUOTE);
    let sid_e = utf8_percent_encode(sid, NINITUX_QUOTE);
    let params = format!(
        "type=tcp&security=reality&pbk={pbk_e}&fp=chrome&sni={sni_e}&sid={sid_e}&spx=%2F&flow=xtls-rprx-vision"
    );

    let label = format!("{server_tag} VLESS");
    let fragment = utf8_percent_encode(&label, NINITUX_QUOTE);

    let _ = client_name; // kept in signature for caller compat; intentionally not in label
    format!("vless://{client_uuid}@{server_ip}:{port}?{params}#{fragment}")
}

/// Map an ISO-3166-1 alpha-2 server id to a user-facing country name.
///
/// Server IDs in vpnctld inventory follow the convention (post-2026-05-20
/// rename): two-letter lowercase ISO codes for production country nodes
/// (`de`, `is`, `fi`, `nl`, `us`, …). The label rendered into the
/// subscription URI fragment (`#Germany VLESS`) is what end-users see
/// in their mobile app's outbound list — Pavel's UX requirement: «по
/// названию легко понять для чего конфиг и что за сервер».
///
/// Unknown IDs (legacy multi-segment slugs, test servers, ad-hoc
/// names) fall back to uppercased ID — operator-debugging-friendly,
/// still distinct from production country names. When adding a new
/// production country, extend the match arm here AND rename the
/// inventory row (`UPDATE servers SET id='nl' WHERE id='vps-nl-01'`).
///
/// Hard-coded mapping (not a `servers.display_name` column) because:
///   1. ISO country codes are an external standard, not operator data
///   2. Adding a column + UI form for editing is scope creep — the
///      country mapping is stable (Germany was Germany 50 years ago)
///   3. Compiled mapping means typos surface at build time
pub(crate) fn country_display_name(server_id: &str) -> String {
    match server_id {
        "de" => "Germany".into(),
        "is" => "Iceland".into(),
        "fi" => "Finland".into(),
        "se" => "Sweden".into(),
        "nl" => "Netherlands".into(),
        "us" => "United States".into(),
        "gb" => "United Kingdom".into(),
        "fr" => "France".into(),
        other => other.to_ascii_uppercase(),
    }
}

/// Look up all server-grant rows for `user_id` and turn each into a
/// ninitux-format vless URI string. Skips servers that don't carry
/// the `vless.public_key` / `vless.short_id` secrets (i.e. the
/// vless+reality inbound isn't provisioned there).
async fn collect_vless_uris_for_user(
    state: &AppState,
    user_id: &UserId,
    client_name: &str,
) -> Result<Vec<String>, String> {
    let servers = state
        .inv
        .servers_for_user(user_id)
        .await
        .map_err(|e| format!("servers_for_user: {e}"))?;

    let mut uris: Vec<String> = Vec::with_capacity(servers.len());
    for server in &servers {
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
            .unwrap_or("www.microsoft.com");

        // Per-server uuid override (Phase 1 + 2 merge). When no
        // override is pinned, falls back to user.uuid via COALESCE
        // inside the inventory layer — byte-stable with pre-Phase-2
        // behaviour for any user whose name doesn't match a
        // subscription-server client.
        let client_uuid = match state
            .inv
            .client_uuid_for(user_id, &server.id)
            .await
            .map_err(|e| format!("client_uuid_for: {e}"))?
        {
            Some(u) => u,
            None => continue,
        };

        let server_display = country_display_name(&server.id.0);
        uris.push(render_vless_uri(
            &server.address,
            443,
            sni,
            pbk,
            sid,
            &client_uuid,
            &server_display,
            client_name,
        ));
    }
    Ok(uris)
}

/// Encode the joined URIs as base64. Empty input → empty output.
fn make_config_blob(uris: &[String]) -> Option<String> {
    if uris.is_empty() {
        return None;
    }
    let joined = uris.join("\n");
    Some(BASE64_STANDARD.encode(joined.as_bytes()))
}

/// Build a `device_not_registered` JSON wrapper or empty raw response,
/// per the UA. Used for invalid device_id, missing user, or user with
/// no grants. Same response either way — anti-fingerprinting against
/// probes.
fn empty_response(want_raw: bool, now: u64) -> Response {
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
fn json_response<T: Serialize>(value: &T) -> Response {
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
fn unregistered_response(headers: &HeaderMap) -> Response {
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let want_raw = is_vpn_client_ua(ua);
    let now = now_unix_secs();
    empty_response(want_raw, now)
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
    headers: HeaderMap,
) -> Response {
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

    let uris = match collect_vless_uris_for_user(&state, &user.id, &user.id.0).await {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!(target = "vpnctld::vpn_router", user = %user.id, error = %e, "uri collection failed");
            return empty_response(want_raw, now);
        }
    };

    let Some(config) = make_config_blob(&uris) else {
        return empty_response(want_raw, now);
    };

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

// ── Unit tests for the pure helpers ─────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn vpn_client_ua_matches_known_keywords() {
        for ua in [
            "v2rayN/6.62",
            "v2rayNG/1.9.0",
            "Streisand/1.6 CFNetwork/1390 Darwin/22.0.0",
            "Shadowrocket/2.2.62 CFNetwork/1568 Darwin/24.1.0",
            "sing-box/1.10.0",
            "Hiddify/1.5.3",
            "ClashforWindows/0.20.39",
            "Quantumult/1.0.27",
            "NekoBox/1.3.7",
            "Karing/1.0.0",
        ] {
            assert!(is_vpn_client_ua(ua), "expected VPN client: {ua}");
        }
    }

    #[test]
    fn browser_ua_takes_json_wrapper_path() {
        for ua in [
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "curl/8.4.0",
            "VPNRouter/2.4.1 (custom mobile app)",
            "",
        ] {
            assert!(!is_vpn_client_ua(ua), "expected non-VPN-client: {ua}");
        }
    }

    #[test]
    fn country_display_name_maps_iso_codes() {
        assert_eq!(country_display_name("de"), "Germany");
        assert_eq!(country_display_name("is"), "Iceland");
        assert_eq!(country_display_name("fi"), "Finland");
        // Unknown id → uppercased fallback (legacy or test server).
        assert_eq!(country_display_name("stg"), "STG");
        assert_eq!(country_display_name("vps-de-01"), "VPS-DE-01");
        assert_eq!(country_display_name(""), "");
    }

    #[test]
    fn render_vless_uri_post_rename_fragment_format() {
        // Post-2026-05-20 rename: fragment is `{Country} VLESS` without
        // port (visible from host) or client_name (user already knows
        // their own name). Pre-rename format was
        // `{server_tag} {port} {client_name}` byte-equivalent with
        // subscription-server — that contract intentionally retired
        // when subscription-server was decommissioned + the operator
        // requirement shifted to user-friendly labels («чтоб
        // пользователь по названию легко мог понять для чего конфиг
        // и что за сервер»).
        let got = render_vless_uri(
            "104.194.156.93",
            443,
            "www.microsoft.com",
            "gDawCMB0X6iGXZkG8nZIFW5TaaW29x0DMzWijN-gc2A",
            "d86e92a0c6dd2271",
            "60063863-d2be-4d57-bc0b-aef4da88528b",
            "Germany",
            "tester-1", // ignored in label — kept for signature compat
        );

        let expected = "vless://60063863-d2be-4d57-bc0b-aef4da88528b@104.194.156.93:443?type=tcp&security=reality&pbk=gDawCMB0X6iGXZkG8nZIFW5TaaW29x0DMzWijN-gc2A&fp=chrome&sni=www.microsoft.com&sid=d86e92a0c6dd2271&spx=%2F&flow=xtls-rprx-vision#Germany%20VLESS";
        assert_eq!(got, expected, "vless URI fragment drifted");
    }

    #[test]
    fn make_config_blob_empty_input_returns_none() {
        assert_eq!(make_config_blob(&[]), None);
    }

    #[test]
    fn make_config_blob_joins_with_newline_then_base64() {
        let uris = vec!["vless://aaa".to_string(), "vless://bbb".to_string()];
        let blob = make_config_blob(&uris).unwrap();
        // Standard base64 of "vless://aaa\nvless://bbb".
        let decoded = BASE64_STANDARD.decode(blob.as_bytes()).unwrap();
        let s = std::str::from_utf8(&decoded).unwrap();
        assert_eq!(s, "vless://aaa\nvless://bbb");
    }

    #[test]
    fn app_config_response_serialises_in_declared_field_order() {
        let body = AppConfigResponse {
            status: "ok",
            app: "vpn-router",
            version: "2.4.1",
            update_available: false,
            config: Some("base64body".to_string()),
            check_interval: 3600,
            timestamp: 1747588800,
        };
        let json = serde_json::to_string(&body).unwrap();
        assert_eq!(
            json,
            r#"{"status":"ok","app":"vpn-router","version":"2.4.1","update_available":false,"config":"base64body","check_interval":3600,"timestamp":1747588800}"#
        );
    }

    #[test]
    fn app_config_response_emits_config_null_when_missing() {
        let body = AppConfigResponse {
            status: "device_not_registered",
            app: "vpn-router",
            version: "2.4.1",
            update_available: false,
            config: None,
            check_interval: 3600,
            timestamp: 0,
        };
        let json = serde_json::to_string(&body).unwrap();
        // Notably: `"config":null` literal, NOT omitted.
        assert!(json.contains(r#""config":null"#), "got: {json}");
        // And status must be the exact string.
        assert!(json.contains(r#""status":"device_not_registered""#));
    }
}
