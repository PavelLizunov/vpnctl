//! `GET /sub/<token>` — opaque-token-keyed sing-box client config.
//!
//! Hiddify-style clients are pointed at this URL once and re-pull on
//! their own schedule. We resolve the token to a user, walk all servers
//! granted to that user, and emit a sing-box client JSON containing one
//! outbound per (server × protocol) plus a selector for switching.
//!
//! Phase Track-1 hook: every successful resolve (200) writes one row
//! into `sub_access_log` so the admin can see "how many distinct IPs
//! are pulling THIS user's URL". Failed resolves (404 unknown token)
//! are deliberately NOT logged — we don't want a probing attacker to
//! be able to fill the table by spamming garbage tokens.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::extract::{ConnectInfo, Path, Request, State};
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use base64::Engine;
use serde_json::{Value, json};
use vpnctl_core::{RenderCtx, User, UserId};

use crate::app::AppState;

/// One-shot flag: true once we've already warned about a missing
/// `ConnectInfo` extension. Without this flag a misconfigured daemon
/// would spam the journal with one warn per request — once is enough
/// for the operator to notice. Resets on daemon restart, which is what
/// we want (a fresh warn after a deploy that re-broke the wiring).
static WARNED_MISSING_CONNECT_INFO: AtomicBool = AtomicBool::new(false);

pub(crate) async fn get(
    State(state): State<AppState>,
    Path(token): Path<String>,
    // The Request extractor must come last (it owns the body). We pull
    // headers + ConnectInfo from it manually so the handler works both
    // in production (where `into_make_service_with_connect_info` injects
    // ConnectInfo as a request extension) and in `tower::ServiceExt::
    // oneshot` test rigs (where no make-service ran and the extension is
    // absent — falls back to `0.0.0.0` so the access log row still lands
    // and downstream tests can assert the write happened).
    request: Request,
) -> impl IntoResponse {
    let ua = request
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    // Track-1.2 — capture richer request metadata at handler time.
    // accept_language is truncated to 120 chars (the column is
    // declared TEXT with no length limit but we don't want
    // misbehaved clients to fill the DB with megabyte UA strings).
    let accept_language = request
        .headers()
        .get(header::ACCEPT_LANGUAGE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.chars().take(120).collect::<String>());
    let http_version = Some(crate::ua::http_version_label(request.version()).to_owned());
    let device_class = crate::ua::parse_ua_short(ua.as_deref()).map(str::to_owned);
    // IP only, port stripped — the port rotates per connection and would
    // explode the cardinality of "distinct IPs". Both v4 and v6 land as
    // `IpAddr::to_string()` (192.0.2.1 / fe80::1) — same shape SQLite
    // can index without a separate column.
    let peer_ip: Option<std::net::IpAddr> = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip());
    // Post-Phase-5 (2026-05-19): traffic now goes through nginx on
    // 192.168.0.207 → vpnctld:18402. Without X-Forwarded-For
    // resolution every client's IP collapses to nginx's peer
    // address → rate-limit single-bucket + per-user distinct-IP
    // counter = 1. `real_ip::resolve_real_ip` parses XFF ONLY when
    // peer is in the trusted-proxy allowlist (overridable via
    // `VPNCTLD_TRUSTED_PROXIES`).
    //
    // TWO resolvers, two purposes — mirrors `vpn_router::get_config`
    // (the prod `/api/v1/app/config` endpoint, hardened in RL-1):
    //
    //   * `real_peer_ip` — LOGGING / observability IP. Leftmost-XFF
    //     (`resolve_real_ip`). Intentionally the richer client value
    //     for abuse-detection (geo, /16-clustering) per the CLAUDE.md
    //     "Known gaps" note. Feeds `sub_access_log.ip` ONLY.
    //   * `sec_peer_ip` — SECURITY-decision IP. Spoof-proof `X-Real-IP`
    //     (`resolve_peer_real_ip`; nginx OVERWRITES it, a client can't
    //     forge it). Used for the rate-limit bucket key AND the 24h
    //     persistent-ban key. CWE-345 fix: nginx APPENDS to XFF
    //     (`$proxy_add_x_forwarded_for`), so the leftmost-XFF value is
    //     client-controlled — from a trusted-proxy position an attacker
    //     could prepend an ARBITRARY victim IP to leftmost-XFF and get
    //     that third party banned for 24h. Keying the ban on `X-Real-IP`
    //     (the true immediate peer of nginx) closes that.
    //
    // Both fall back to the raw `peer` when the immediate peer is not a
    // trusted proxy OR the header is absent/malformed, so the no-XFF /
    // untrusted-peer cases are byte-identical to before this change.
    let SubIps {
        log_ip: real_peer_ip,
        sec_ip: sec_peer_ip,
    } = resolve_sub_ips(request.headers(), peer_ip);
    let ip = match real_peer_ip {
        Some(addr) => addr.to_string(),
        None => {
            // Production rigs MUST install ConnectInfo via
            // `into_make_service_with_connect_info::<SocketAddr>()`. If
            // the extension is missing, every access-log row will land
            // with `0.0.0.0` and the abuse-signal counters silently
            // collapse all clients to one bucket. Warn once per process
            // so the operator notices in journalctl. Test rigs (oneshot
            // Service::call) deliberately don't install ConnectInfo;
            // there the warn is a benign single line.
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

    // Phase Track-2 chunk 2: persistent ban check runs BEFORE the
    // bucket math — a banned IP is rejected without spending any
    // bucket tokens. The ban table is indexed on (kind, key,
    // until_ts) so the lookup is sub-millisecond. Keyed on the
    // spoof-proof `sec_peer_ip` (X-Real-IP) so a third party can't be
    // banned by prepending their IP to leftmost-XFF (CWE-345).
    if let Some(addr) = sec_peer_ip {
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

    // Phase Track-2 rate limit: per-IP gate runs FIRST, BEFORE the
    // token is resolved. This way unknown-token probing also gets
    // throttled (a probing attacker can't keep hitting random tokens
    // for free). Per-token gate runs AFTER the token resolves to
    // bound the by_token map size by the user count, not by attacker
    // creativity. Both gates issue HTTP 429 with `Retry-After`.
    //
    // Keyed on `sec_peer_ip` (spoof-proof X-Real-IP), NOT the
    // leftmost-XFF `real_peer_ip` — both the bucket key and the
    // escalated `add_ban` below must resist the leftmost-XFF
    // victim-ban attack (CWE-345). Parity with `vpn_router::get_config`.
    if let Some(addr) = sec_peer_ip {
        if let Err((retry, denial_count)) = state.rate_limiter.try_acquire_ip(addr) {
            // Phase Track-2 chunk 2: escalate to a persistent ban EXACTLY
            // when the denial counter crosses K. Using `==` (not `>=`)
            // closes the parallel-request race the review-agent caught:
            // under load, multiple in-flight requests could otherwise
            // each see `count >= K` and each write a duplicate ban row.
            // The Mutex serializes counter increments, so exactly one
            // request observes the K-crossing transition.
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
                        // Audit row — every inventory write must be
                        // auditable per CLAUDE.md invariant. Mirrors
                        // CLI patterns ("cli", "user.add", …).
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
                        // Reset the counter only on a SUCCESSFUL ban
                        // write so it doesn't keep re-triggering the
                        // escalation on every subsequent 429.
                        state.rate_limiter.reset_denials_ip(addr);
                    }
                    Err(e) => {
                        // C3 fix (mirror of the token path below):
                        // `try_acquire_ip` already bumped the counter
                        // to K. If the ban write fails and we leave it
                        // at K, the NEXT denial overshoots to K+1,
                        // `K+1 == K` is false, and the escalation never
                        // retries until the counter resets on a success.
                        // Clamp back to K-1 so the next denial re-hits
                        // `== K` and re-attempts the ban — preserving
                        // the deliberate `== K` race-fix on the happy
                        // path.
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

    // 2026-05-23 — V2Ray-family UA detection (quickfix per Pavel
    // «через V2raytun наш QR не работает»). The dispatch mirrors
    // `vpn_router::is_vpn_client_ua` exactly so a UA that already
    // worked on the ninitux endpoint now also works on the legacy
    // `/sub/<token>` LAN fallback. Default (no UA / browser / sing-
    // box / Hiddify) renders the JSON envelope.
    let want_v2ray_subscription = ua
        .as_deref()
        .map(crate::handlers::vpn_router::is_vpn_client_ua_v2ray_family)
        .unwrap_or(false);

    // ────────────────────────────────────────────────────────────────
    // Per-TOKEN abuse gates — run BEFORE we dispatch into either the
    // v2ray or the sing-box render branch.
    //
    // Why here and not inside each branch: the per-token ban check and
    // the per-token rate-limit gate are SECURITY decisions that must
    // apply to EVERY successful token resolve, regardless of which
    // client UA pulled the URL. V2rayTun / v2rayNG / Shadowrocket are
    // the dominant production clients; when these gates lived only in
    // the sing-box arm, a token ban (including the auto-24h escalation)
    // and the per-token URL-sharing throttle were no-ops for most
    // traffic. Resolving the user ONCE up front and gating here closes
    // that — the UA now only selects the RENDER format, never whether
    // the abuse defenses run.
    //
    // Ordering mirrors the per-IP path above: 404 on unknown token
    // (so probing is bounded by the per-IP gate, which already ran),
    // then ban check, then bucket gate. The per-IP gate ordering is
    // unchanged.
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

    // Per-token ban check (mirror of the per-IP path above).
    match state.inv.is_banned("token", &token).await {
        Ok(Some(secs)) => return rate_limited(secs, "token-ban"),
        Ok(None) => {}
        Err(e) => tracing::warn!(
            target = "vpnctld::sub",
            error = %e,
            "is_banned(token) failed; falling through to bucket"
        ),
    }

    // Per-token gate runs only on successful resolve so the by_token
    // map is bounded by user count, not by attacker creativity.
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
                    if let Err(e) = state
                        .inv
                        .audit(
                            "daemon",
                            "rate.ban.add",
                            Some(&token),
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
                    // C3 fix: `try_acquire_token` already incremented
                    // the denial counter to K, and on success above we
                    // would reset it — but the ban write FAILED. If we
                    // just left the counter at K, the NEXT denial would
                    // bump it to K+1, `K+1 == K` is false, and the
                    // escalation would never retry until the counter
                    // happened to reset on a successful acquire. Clamp
                    // it back to K-1 so the next denial re-hits `== K`
                    // and re-attempts the ban. This preserves the
                    // deliberate `== K` race-fix on the happy path and
                    // only changes error-recovery.
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

    // ────────────────────────────────────────────────────────────────
    // Render branch — UA selects format ONLY. Both arms share the
    // already-resolved `user` and the already-passed token gates above.
    let (tls_ja3, tls_ja4) = peer_ip
        .map(|p| crate::real_ip::collect_tls_fingerprints(request.headers(), p))
        .unwrap_or((None, None));

    if want_v2ray_subscription {
        match render_v2ray_subscription(&state, &user, ua.as_deref()).await {
            Ok((user_id, body)) => {
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
                (
                    StatusCode::OK,
                    [("content-type", "text/plain; charset=utf-8")],
                    body,
                )
                    .into_response()
            }
            Err(SubError::NotFound) => (StatusCode::NOT_FOUND, "unknown token\n").into_response(),
            Err(SubError::Internal(msg)) => {
                tracing::error!(target = "vpnctld::sub", error = %msg, "v2ray sub render failed");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error\n").into_response()
            }
        }
    } else {
        match render_singbox(&state, &user).await {
            Ok((user_id, cfg)) => {
                let body = cfg.to_string();
                // 32-bit defensive — `body.len()` is `usize`; on a
                // 32-bit build `as u64` would silently truncate if it
                // ever exceeded 4 GiB (impossible for a sub-config, but
                // the same defensive cast pattern is used in
                // `log_sub_access` for the bytes bind, so keep symmetry).
                let bytes = u64::try_from(body.len()).unwrap_or(u64::MAX);

                // Bounded back-pressure (audit-fix Plan B / retroactive
                // review #3 / security #2): hand the record to the
                // dedicated writer task via a non-blocking `try_send`.
                // Channel-full → record dropped + warn-log; channel-
                // closed → error-log (writer crashed). Either way the
                // HTTP response stays 200 — we never block on the log
                // write and we never spawn an unbounded number of tasks.
                // See `crate::access_log` module docs for the rationale.
                // Track-1.4 — TLS fingerprint from nginx-forwarded
                // headers, GATED by VPNCTLD_TRUSTED_PROXIES. peer_ip is
                // the raw TCP peer (NOT the XFF-resolved one) since the
                // trust gate keys on the immediate connection's source.
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
                        // GeoIP fields populated by writer task —
                        // handler always sends None.
                        geo_country: None,
                        geo_asn: None,
                        tls_ja3,
                        tls_ja4,
                    },
                );

                (StatusCode::OK, [("content-type", "application/json")], body).into_response()
            }
            Err(SubError::NotFound) => (StatusCode::NOT_FOUND, "unknown token\n").into_response(),
            Err(SubError::Internal(msg)) => {
                tracing::error!(target = "vpnctld::sub", error = %msg, "sub render failed");
                // Don't leak internals to the user — generic 500.
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error\n").into_response()
            }
        }
    }
}

/// The two client IPs the `/sub` handler resolves from one request:
/// a richer LOGGING value and a spoof-proof SECURITY value. Split
/// intentionally — see `resolve_sub_ips` and the inline rationale at
/// the top of [`get`].
struct SubIps {
    /// Leftmost-XFF (`resolve_real_ip`). Observability ONLY —
    /// `sub_access_log.ip`. Client-controllable behind the appending
    /// nginx; never feeds a security decision.
    log_ip: Option<std::net::IpAddr>,
    /// Spoof-proof `X-Real-IP` (`resolve_peer_real_ip`). The rate-limit
    /// bucket key AND the 24h persistent-ban key. nginx overwrites
    /// `X-Real-IP`, so a client can't forge it (CWE-345 defense).
    sec_ip: Option<std::net::IpAddr>,
}

/// Resolve both `/sub` IPs from the request, using the process-wide
/// `VPNCTLD_TRUSTED_PROXIES` allowlist. Thin wrapper over
/// [`resolve_sub_ips_with`] so the handler stays a one-liner; the
/// `_with` form (trusted list lifted to a parameter) carries the
/// testable logic — same split `real_ip.rs` uses to stay env-free
/// under the workspace `unsafe_code = "forbid"` lint.
fn resolve_sub_ips(headers: &header::HeaderMap, peer_ip: Option<std::net::IpAddr>) -> SubIps {
    resolve_sub_ips_with(headers, peer_ip, crate::real_ip::trusted_proxies())
}

/// Pure inner helper for [`resolve_sub_ips`] — trusted list lifted to a
/// parameter so tests exercise the spoof scenario without mutating the
/// process env. Mirrors the security-vs-logging IP split in
/// `vpn_router::get_config` exactly.
fn resolve_sub_ips_with(
    headers: &header::HeaderMap,
    peer_ip: Option<std::net::IpAddr>,
    trusted: &[std::net::IpAddr],
) -> SubIps {
    SubIps {
        log_ip: peer_ip.map(|p| crate::real_ip::resolve_real_ip_with(headers, p, trusted)),
        sec_ip: peer_ip.map(|p| crate::real_ip::resolve_peer_real_ip_with(headers, p, trusted)),
    }
}

/// Build the 429 response with `Retry-After` (seconds). The `gate`
/// argument identifies which axis (ip / token / device) tripped — it
/// ends up in the response body so an operator running curl during
/// incident response can tell whether they're hitting their own per-IP
/// limit (legit traffic) or a per-token limit (URL-shared scenario).
/// `pub(crate)` so the ninitux endpoint (`vpn_router`) reuses the exact
/// same 429 shape.
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
enum SubError {
    NotFound,
    Internal(String),
}

/// 2026-05-23 quickfix (Pavel: «через V2raytun наш QR не работает»).
/// V2Ray-family clients (v2rayN, v2rayNG, v2rayTun, Shadowrocket,
/// Streisand, Quantumult, …) expect the classic «base64-encoded
/// line-separated raw URIs» subscription format. They CAN'T parse
/// sing-box JSON. The ninitux endpoint already does this via
/// `vpn_router::is_vpn_client_ua` content-negotiation; mirroring
/// the same dispatch here means the legacy `/sub/<token>` URL
/// works for both V2Ray-family clients AND sing-box/Hiddify.
///
/// **Returns:** the base64 subscription body for the resolved user.
/// Takes an ALREADY-RESOLVED `&User` (not a token) — the handler runs
/// the per-token ban + rate-limit gates on the resolved user BEFORE
/// dispatching here, so this path can no longer skip those defenses
/// (the original bug). Disabled users get an empty body.
async fn render_v2ray_subscription(
    state: &AppState,
    user: &User,
    ua: Option<&str>,
) -> Result<(UserId, String), SubError> {
    let user_id = user.id.clone();
    // Disabled-user check — same semantics as the JSON path: empty
    // body. V2Ray clients tolerate an empty subscription as
    // «nothing to import», which is the right surface.
    if user.disabled {
        tracing::info!(
            target = "vpnctld::sub",
            user = %user_id.0,
            "user is disabled — returning empty v2ray sub"
        );
        return Ok((user_id, String::new()));
    }
    let servers = state
        .inv
        .servers_for_user(&user.id)
        .await
        .map_err(|e| SubError::Internal(format!("inventory: {e}")))?;
    // Whether THIS client can parse the sing-box-only transports
    // (Hysteria2 / TUIC / AnyTLS). V2Ray/Xray-core clients (V2rayTun,
    // v2rayN/NG) can't, and a leading `hysteria2://` entry breaks their
    // whole import — so they get VLESS-family only. Unknown/sing-box UAs
    // stay permissive. 2026-06-16 fix.
    let client_singbox = ua
        .map(crate::handlers::vpn_router::client_supports_singbox_transports)
        .unwrap_or(true);
    // Split by capability so VLESS-family (universally parsed) is always
    // emitted FIRST — a client that chokes on a trailing sing-box entry
    // has, by then, already imported the configs everyone supports.
    let mut core_links: Vec<String> = Vec::new();
    let mut singbox_links: Vec<String> = Vec::new();
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
        for pid in &server.enabled_protocols {
            if !visible_set.contains(pid) {
                continue;
            }
            let Some(proto) = state.registry.protocol(pid) else {
                continue;
            };
            match proto.share_link(&ctx, &per_server_user) {
                Ok(link) => {
                    // V2Ray-family clients only understand a subset of
                    // share-link schemes. WireGuard's `wireguard://?conf=…`
                    // and wgturn's `wgturn://…` would be silently dropped
                    // at best, crash the parser at worst — so neither
                    // bucket takes them. The sing-box-only transports go
                    // to `singbox_links` and are emitted only to clients
                    // that can parse them (see `client_singbox`).
                    if link.starts_with("vless://")
                        || link.starts_with("vmess://")
                        || link.starts_with("trojan://")
                        || link.starts_with("ss://")
                        || link.starts_with("ssr://")
                    {
                        core_links.push(link);
                    } else if link.starts_with("hysteria2://")
                        || link.starts_with("hy2://")
                        || link.starts_with("tuic://")
                        || link.starts_with("anytls://")
                    {
                        singbox_links.push(link);
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        target = "vpnctld::sub",
                        server = %server.id,
                        protocol = %pid,
                        error = %e,
                        "share_link failed for v2ray sub; skipping"
                    );
                }
            }
        }
    }
    // VLESS-family first; append the sing-box transports only for
    // clients that can parse them.
    if client_singbox {
        core_links.extend(singbox_links);
    }
    let joined = core_links.join("\n");
    let body = base64::engine::general_purpose::STANDARD.encode(joined.as_bytes());
    Ok((user_id, body))
}

/// Resolve a `/sub` token to its `User`, mapping the "no such token"
/// case to [`SubError::NotFound`] (404) and DB failures to
/// [`SubError::Internal`] (500). Pulled out of the per-branch render
/// functions so the handler can resolve the user ONCE, run the
/// per-token ban + rate-limit gates on the result, and only THEN
/// dispatch into either render branch. Both branches previously did
/// this lookup independently, which is exactly why the token ban /
/// throttle could be skipped on the v2ray path.
async fn resolve_user(state: &AppState, token: &str) -> Result<User, SubError> {
    state
        .inv
        .find_user_by_sub_token(token)
        .await
        .map_err(|e| SubError::Internal(format!("inventory: {e}")))?
        .ok_or(SubError::NotFound)
}

/// Render the sing-box JSON envelope for an ALREADY-RESOLVED user.
/// Takes `&User` (not a token) because the handler resolves the user
/// once up front and runs the per-token ban + rate-limit gates before
/// dispatching here — see [`get`].
async fn render_singbox(state: &AppState, user: &User) -> Result<(UserId, Value), SubError> {
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
            // Skip protocols that are not sing-box-native (today:
            // wgturn — its `type: "wgturn"` outbound is unknown to
            // sing-box / Hiddify and would make the WHOLE sub config
            // unparseable, dropping every legit route too). Such
            // protocols are still surfaced in admin UI's per-protocol
            // share-links section via their own client (e.g. wgturn-cli
            // connect-url '<wgturn://...>').
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
        "wgturn" => "WGTurn".into(),
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};
    use std::net::{IpAddr, Ipv4Addr};

    /// A trusted reverse proxy (stand-in for nginx). The `_with`
    /// resolvers honour XFF / X-Real-IP only when the immediate peer is
    /// in this list — same trust gate as `real_ip.rs`.
    const TRUSTED_PROXY: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 207));
    /// The third-party VICTIM whose IP a malicious client prepends to
    /// leftmost-XFF hoping to get it banned for 24h.
    const VICTIM_IP: &str = "198.51.100.77";
    /// The attacker's TRUE immediate peer — what nginx writes into
    /// `X-Real-IP` (overwriting any client-supplied value).
    const ATTACKER_IP: &str = "203.0.113.9";

    /// The CWE-345 fix, pinned at the exact seam `sub.rs` keys its
    /// security decisions on. A request from a trusted proxy carries a
    /// spoofed leftmost-XFF (the victim) but an honest `X-Real-IP` (the
    /// attacker). The SECURITY IP — which feeds BOTH the rate-limit
    /// bucket and `add_ban` — must be the attacker's true IP, so a third
    /// party can NEVER be banned by header injection. The LOGGING IP
    /// keeps the richer leftmost-XFF (observability semantics unchanged).
    #[test]
    fn security_ip_resists_leftmost_xff_spoof_logging_ip_keeps_it() {
        let mut h = HeaderMap::new();
        // nginx appends $remote_addr → leftmost is the client-supplied
        // (spoofed) victim; the trailing entry is the real peer.
        h.insert(
            "x-forwarded-for",
            HeaderValue::from_str(&format!("{VICTIM_IP}, {ATTACKER_IP}")).unwrap(),
        );
        // nginx OVERWRITES X-Real-IP with the true peer ($remote_addr).
        h.insert("x-real-ip", HeaderValue::from_static(ATTACKER_IP));

        let ips = resolve_sub_ips_with(&h, Some(TRUSTED_PROXY), &[TRUSTED_PROXY]);

        // Ban / rate-limit key = attacker's TRUE IP, never the victim.
        assert_eq!(
            ips.sec_ip.map(|i| i.to_string()).as_deref(),
            Some(ATTACKER_IP),
            "security IP (rate-limit bucket + 24h ban key) must be the spoof-proof \
             X-Real-IP, NOT the client-controlled leftmost-XFF — else a third party \
             gets banned via header injection (CWE-345)"
        );
        // The victim's IP must NOT be the thing that gets banned.
        assert_ne!(
            ips.sec_ip.map(|i| i.to_string()).as_deref(),
            Some(VICTIM_IP),
            "the spoofed victim IP must never become the ban/rate-limit key"
        );
        // Logging IP semantics preserved — still the leftmost-XFF.
        assert_eq!(
            ips.log_ip.map(|i| i.to_string()).as_deref(),
            Some(VICTIM_IP),
            "logging IP (sub_access_log) keeps the established richer leftmost-XFF \
             value per CLAUDE.md 'Known gaps' — only the security decision moved"
        );
    }

    /// No-XFF / no-X-Real-IP from a trusted proxy: both IPs fall back to
    /// the raw peer. Guards that the split introduced no behaviour change
    /// for ordinary direct requests.
    #[test]
    fn both_ips_fall_back_to_peer_when_no_headers() {
        let h = HeaderMap::new();
        let ips = resolve_sub_ips_with(&h, Some(TRUSTED_PROXY), &[TRUSTED_PROXY]);
        assert_eq!(ips.sec_ip, Some(TRUSTED_PROXY));
        assert_eq!(ips.log_ip, Some(TRUSTED_PROXY));
    }

    /// Untrusted immediate peer: every forwarding header is dropped on
    /// the floor for BOTH IPs (an arbitrary external client can't spoof
    /// either axis). This is the pre-existing spoof defense — the change
    /// must not weaken it.
    #[test]
    fn untrusted_peer_ignores_all_forwarding_headers() {
        let untrusted = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1));
        let mut h = HeaderMap::new();
        h.insert(
            "x-forwarded-for",
            HeaderValue::from_str(&format!("{VICTIM_IP}, {ATTACKER_IP}")).unwrap(),
        );
        h.insert("x-real-ip", HeaderValue::from_static(ATTACKER_IP));
        // Trusted list does NOT contain `untrusted`.
        let ips = resolve_sub_ips_with(&h, Some(untrusted), &[TRUSTED_PROXY]);
        assert_eq!(
            ips.sec_ip,
            Some(untrusted),
            "untrusted peer's X-Real-IP must be ignored — raw peer is the key"
        );
        assert_eq!(
            ips.log_ip,
            Some(untrusted),
            "untrusted peer's XFF must be ignored for logging too"
        );
    }

    /// Missing ConnectInfo (oneshot test rigs, misconfigured make-service)
    /// → both IPs are `None`, so the handler skips the per-IP ban + bucket
    /// entirely (the `if let Some(addr)` guards). No panic, no key.
    #[test]
    fn no_peer_ip_yields_none_for_both() {
        let mut h = HeaderMap::new();
        h.insert("x-real-ip", HeaderValue::from_static(ATTACKER_IP));
        let ips = resolve_sub_ips_with(&h, None, &[TRUSTED_PROXY]);
        assert_eq!(ips.sec_ip, None);
        assert_eq!(ips.log_ip, None);
    }
}
