use axum::extract::Request;
use axum::http::{Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

pub(crate) async fn require_same_origin(req: Request, next: Next) -> Response {
    if !is_state_mutating(req.method()) {
        return next.run(req).await;
    }

    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok());

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

fn is_state_mutating(m: &Method) -> bool {
    matches!(
        *m,
        Method::POST | Method::PUT | Method::DELETE | Method::PATCH
    )
}

fn authority_of(s: &str) -> Option<&str> {
    let after_scheme = s
        .strip_prefix("http://")
        .or_else(|| s.strip_prefix("https://"))?;
    let end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..end];
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
