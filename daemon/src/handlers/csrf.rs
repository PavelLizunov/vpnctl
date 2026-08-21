//! Same-origin CSRF guard for state-mutating `/admin/*` requests.
//!
//! Why this exists
//! ---------------
//! `vpnctld` admin endpoints sit behind HTTP basic-auth. Browsers
//! attach basic-auth credentials AUTOMATICALLY on every cross-origin
//! request to the realm — that's exactly the CSRF threat model: a
//! page on `evil.example.com` can submit a form POST to
//! `http://192.168.0.236:18402/admin/users/X/sub-token/regenerate`,
//! the operator's authenticated browser will replay the basic-auth
//! header, and the mutation will succeed even though the operator
//! never clicked anything on the admin UI.
//!
//! This middleware closes that hole by demanding that any
//! state-mutating request (POST / PUT / DELETE / PATCH) under
//! `/admin/*` carry an `Origin` header (or, as fallback, a `Referer`
//! header) whose authority matches the request's `Host` header. A
//! cross-origin form-POST from `evil.example.com` will either omit
//! `Origin` entirely (some clients) or set it to `http://evil.example.com`
//! — both cases get a 403 here.
//!
//! Caveats
//! -------
//! * Behind a reverse proxy that rewrites `Host`, the comparison is
//!   still correct AS LONG AS the proxy also passes through the
//!   client's `Origin` unchanged. Document the trusted-proxy contract
//!   when external exposure lands.
//! * GET / HEAD / OPTIONS pass through unchanged — they are
//!   nominally safe per RFC 9110, and the admin tree's GET handlers
//!   do not mutate state.
//! * Tests that POST to `/admin/*` MUST set both `host` and `origin`
//!   headers. The `same_origin_post` helper in `tests/admin_smoke.rs`
//!   wraps that boilerplate.
//! * Returns the `vpnctl admin: csrf …` body that matches the unified
//!   copy contract from `handlers::admin::error_text`.

use axum::extract::Request;
use axum::http::{Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// Wrap the admin router with this middleware via
/// `axum::middleware::from_fn(require_same_origin)`.
pub(crate) async fn require_same_origin(req: Request, next: Next) -> Response {
    if !is_state_mutating(req.method()) {
        return next.run(req).await;
    }

    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok());

    // Origin first (RFC 6454 — the canonical CSRF defense header), then
    // Referer (older fallback some browsers still rely on).
    let claimed = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .and_then(authority_of)
        .or_else(|| {
            req.headers()
                .get(header::REFERER)
                .and_then(|v| v.to_str().ok())
                .and_then(authority_of)
        });

    match (host, claimed) {
        (Some(h), Some(c)) if h.eq_ignore_ascii_case(c) => next.run(req).await,
        _ => {
            // Pull the raw header values for the error body so the
            // operator can diagnose without `journalctl` (per CLAUDE.md
            // Operator-action policy — error messages must NOT instruct
            // shell access).
            let origin_raw = req
                .headers()
                .get(header::ORIGIN)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("(absent)");
            let referer_raw = req
                .headers()
                .get(header::REFERER)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("(absent)");
            let host_raw = host.unwrap_or("(absent)");
            tracing::warn!(
                target = "vpnctld::csrf",
                method = %req.method(),
                path = %req.uri().path(),
                host = ?host_raw,
                origin = ?origin_raw,
                referer = ?referer_raw,
                "rejecting cross-origin or origin-less mutating request"
            );
            // Body carries the values + a plausible cause for the
            // three most-seen failure modes:
            //   * Origin: null  → opaque-origin context (sandboxed
            //     iframe, certain privacy extensions, file:// open)
            //   * Origin: absent + Referer: absent → operator
            //     curl/wget hitting POST without --header
            //   * Origin/Referer points at a different host → genuine
            //     cross-origin attempt (or proxy rewriting Host)
            let likely_cause = if origin_raw == "null" {
                "  likely cause: Origin: null — browser treats this document as an opaque origin\n  \
                 (sandboxed iframe / privacy extension / file:// open). Open the admin URL\n  \
                 directly in a normal tab — same hostname + port as bookmarked.\n"
            } else if origin_raw == "(absent)" && referer_raw == "(absent)" {
                "  likely cause: no Origin and no Referer — this looks like curl/wget without\n  \
                 a browser. Add `-H 'Origin: http://<host>:<port>'` matching your daemon URL.\n"
            } else {
                "  likely cause: Origin / Referer points at a different host than Host.\n  \
                 If you're behind a reverse proxy, ensure it passes Origin through unchanged.\n"
            };
            let body = format!(
                "vpnctl admin: csrf — Origin (or Referer) must match Host\n\
                 \n\
                 received:\n  \
                 Host:    {host_raw}\n  \
                 Origin:  {origin_raw}\n  \
                 Referer: {referer_raw}\n\
                 \n\
                 {likely_cause}"
            );
            (StatusCode::FORBIDDEN, body).into_response()
        }
    }
}

/// Mutating methods per RFC 9110 §9.2.1 — these are the only ones the
/// CSRF guard refuses to pass through unchecked. GET / HEAD / OPTIONS
/// are safe; TRACE / CONNECT aren't reachable on this router.
fn is_state_mutating(m: &Method) -> bool {
    matches!(
        *m,
        Method::POST | Method::PUT | Method::DELETE | Method::PATCH
    )
}

/// Extract `host[:port]` from an `Origin`-style URL string. Returns
/// `None` for malformed input — the middleware then refuses the
/// request, which is the conservative outcome.
///
/// Strips userinfo (`userinfo@`) per RFC 3986 §3.2 if present in the
/// authority component, so that requests with embedded credentials
/// in `Referer` (or `Origin`) match the HTTP `Host` header.
///
/// Examples:
///   `http://192.168.0.236:18402`           → `Some("192.168.0.236:18402")`
///   `http://user:pass@192.168.0.236:18402` → `Some("192.168.0.236:18402")`
///   `https://admin.example.com/some/path`  → `Some("admin.example.com")`
///   `null`                                 → `None` (sandboxed iframe)
///   ``                                     → `None`
fn authority_of(s: &str) -> Option<&str> {
    let after_scheme = s
        .strip_prefix("http://")
        .or_else(|| s.strip_prefix("https://"))?;
    // Stop at the first `/` (path), `?` (query), `#` (fragment), or
    // end-of-string — anything before that is the authority.
    let end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..end];
    // Strip RFC 3986 §3.2 userinfo if present: `[ userinfo "@" ] host [ ":" port ]`
    let host_port = match authority.rfind('@') {
        Some(idx) => &authority[idx + 1..],
        None => authority,
    };
    if host_port.is_empty() {
        None
    } else {
        Some(host_port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_of_strips_scheme_and_path() {
        assert_eq!(
            authority_of("http://192.168.0.236:18402"),
            Some("192.168.0.236:18402")
        );
        assert_eq!(
            authority_of("http://192.168.0.236:18402/admin/users"),
            Some("192.168.0.236:18402")
        );
        assert_eq!(
            authority_of("https://admin.example.com/x?y=1#z"),
            Some("admin.example.com")
        );
    }

    #[test]
    fn authority_of_strips_userinfo() {
        assert_eq!(
            authority_of("http://user:pass@192.168.0.236:18402"),
            Some("192.168.0.236:18402")
        );
        assert_eq!(
            authority_of("http://admin@192.168.0.236:18402/admin/users"),
            Some("192.168.0.236:18402")
        );
        assert_eq!(
            authority_of("https://user:pass@admin.example.com/x?y=1#z"),
            Some("admin.example.com")
        );
    }

    #[test]
    fn authority_of_rejects_malformed_inputs() {
        assert_eq!(authority_of("null"), None, "sandboxed-iframe Origin");
        assert_eq!(authority_of(""), None, "empty Origin");
        assert_eq!(authority_of("javascript:alert(1)"), None, "non-http scheme");
        assert_eq!(authority_of("ftp://example.com"), None, "non-http scheme");
        assert_eq!(authority_of("http://"), None, "scheme but no authority");
        assert_eq!(authority_of("http://user@"), None, "userinfo but no host");
    }

    #[test]
    fn is_state_mutating_covers_post_put_delete_patch() {
        assert!(is_state_mutating(&Method::POST));
        assert!(is_state_mutating(&Method::PUT));
        assert!(is_state_mutating(&Method::DELETE));
        assert!(is_state_mutating(&Method::PATCH));
        assert!(!is_state_mutating(&Method::GET));
        assert!(!is_state_mutating(&Method::HEAD));
        assert!(!is_state_mutating(&Method::OPTIONS));
    }
}
