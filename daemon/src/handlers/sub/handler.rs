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

/// One-shot flag: true once we've already warned about a missing
/// `ConnectInfo` extension. Without this flag a misconfigured daemon
/// would spam the journal with one warn per request — once is enough
/// for the operator to notice. Resets on daemon restart, which is what
/// we want (a fresh warn after a deploy that re-broke the wiring).
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

    // Egress exemption (parity with the prod `/api/v1/app/config`
    // endpoint, RL-1): a VPN-connected client's `/sub` refresh EGRESSES
    // its node, so vpnctld sees the SERVER's IP. N users on one server
    // collapse into ONE shared per-IP bucket — and worse, one user's
    // retry-storm could escalate that shared egress IP into a 24h
    // persistent ban, severing EVERY user on the node. Known server
    // addresses are therefore exempt from the shared per-IP axis (both
    // the ban check and the bucket / ban-escalation below); they remain
    // protected by the per-TOKEN axis, which runs after resolve and is
    // keyed per user. The decision uses the spoof-proof `sec_peer_ip`
    // (X-Real-IP), so an attacker can't forge an egress IP to dodge the
    // per-IP ban (CWE-345) — same resolver the prod endpoint trusts.
    let is_egress = match sec_peer_ip {
        Some(addr) if !addr.is_unspecified() => state
            .inv
            .is_known_server_address(&addr.to_string())
            .await
            .unwrap_or(false), // DB hiccup → treat as non-egress (fail toward throttling)
        _ => false,
    };
    // Single source of truth for "which IP (if any) drives the per-IP
    // axis" — shared with the prod endpoint (`ip_to_throttle`). `None`
    // for egress nodes and for unknown/unspecified sources; both per-IP
    // blocks below key off this so egress traffic neither consumes nor
    // triggers the shared per-IP ban.
    let per_ip_ip = crate::handlers::vpn_router::ip_to_throttle(sec_peer_ip, is_egress);

    // Phase Track-2 chunk 2: persistent ban check runs BEFORE the
    // bucket math — a banned IP is rejected without spending any
    // bucket tokens. The ban table is indexed on (kind, key,
    // until_ts) so the lookup is sub-millisecond. Keyed on the
    // spoof-proof `sec_peer_ip` (X-Real-IP) so a third party can't be
    // banned by prepending their IP to leftmost-XFF (CWE-345).
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
    // `per_ip_ip` is `None` for egress nodes (exempted above), so a
    // shared VPN-egress IP never consumes this bucket nor trips the
    // `add_ban` escalation — those users ride the per-token axis only.
    if let Some(addr) = per_ip_ip {
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

    // Existing clients keep their UA-selected legacy format unless the
    // operator hands them an explicit format URL. The query is validated
    // only after both abuse gates below have run.
    let ua_wants_v2ray_subscription = ua
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

    // ────────────────────────────────────────────────────────────────
    // Render branch — UA / format query selects renderer.
    // All arms share the already-resolved user and token gates above.
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

/// The two client IPs the `/sub` handler resolves from one request:
/// a richer LOGGING value and a spoof-proof SECURITY value. Split
/// intentionally — see `resolve_sub_ips` and the inline rationale at
/// the top of [`get`].
pub(super) struct SubIps {
    /// Leftmost-XFF (`resolve_real_ip`). Observability ONLY —
    /// `sub_access_log.ip`. Client-controllable behind the appending
    /// nginx; never feeds a security decision.
    pub(super) log_ip: Option<std::net::IpAddr>,
    /// Spoof-proof `X-Real-IP` (`resolve_peer_real_ip`). The rate-limit
    /// bucket key AND the 24h persistent-ban key. nginx overwrites
    /// `X-Real-IP`, so a client can't forge it (CWE-345 defense).
    pub(super) sec_ip: Option<std::net::IpAddr>,
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
pub(super) enum SubError {
    NotFound,
    Internal(String),
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
