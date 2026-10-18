use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::password_hash::{PasswordHash, PasswordVerifier};
use axum::extract::Request;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const SESSION_COOKIE: &str = "vpnctl_admin_session";

const DEFAULT_SESSION_TTL_DAYS: u64 = 30;

fn session_ttl_secs() -> u64 {
    let days = std::env::var("VPNCTLD_SESSION_TTL_DAYS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|d| *d > 0 && *d <= 365)
        .unwrap_or(DEFAULT_SESSION_TTL_DAYS);
    days.saturating_mul(86_400)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Clone)]
enum PasswordSecret {
    Argon2Phc(Arc<String>),
    PlainBytes(Arc<Vec<u8>>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthConfigError {
    MalformedArgon2Hash,
}

impl std::fmt::Display for AuthConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedArgon2Hash => f.write_str(
                "VPNCTLD_ADMIN_PASSWORD starts with $argon2 but is not a valid PHC hash",
            ),
        }
    }
}

impl std::error::Error for AuthConfigError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdminAuthConfig {
    Configured,
    Absent,
    Malformed,
}

fn parse_password_secret(pw: String) -> Result<PasswordSecret, AuthConfigError> {
    if pw.starts_with("$argon2") {
        if PasswordHash::new(&pw).is_err() {
            return Err(AuthConfigError::MalformedArgon2Hash);
        }
        Ok(PasswordSecret::Argon2Phc(Arc::new(pw)))
    } else {
        Ok(PasswordSecret::PlainBytes(Arc::new(pw.into_bytes())))
    }
}

pub(crate) fn classify_admin_auth(user: Option<String>, pw: Option<String>) -> AdminAuthConfig {
    let (Some(user), Some(pw)) = (user, pw) else {
        return AdminAuthConfig::Absent;
    };
    if user.is_empty() || pw.is_empty() {
        return AdminAuthConfig::Absent;
    }
    match parse_password_secret(pw) {
        Ok(_) => AdminAuthConfig::Configured,
        Err(AuthConfigError::MalformedArgon2Hash) => AdminAuthConfig::Malformed,
    }
}

pub(crate) fn classify_admin_auth_env() -> AdminAuthConfig {
    classify_admin_auth(
        std::env::var("VPNCTLD_ADMIN_USER").ok(),
        std::env::var("VPNCTLD_ADMIN_PASSWORD").ok(),
    )
}

#[derive(Clone)]
pub(crate) struct BasicAuth {
    pub user: Arc<String>,
    secret: PasswordSecret,
    session_key: Arc<[u8; 32]>,
}

fn derive_session_key(secret: &PasswordSecret) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"vpnctl-session-v1\0");
    match secret {
        PasswordSecret::Argon2Phc(phc) => h.update(phc.as_bytes()),
        PasswordSecret::PlainBytes(bytes) => h.update(bytes.as_slice()),
    }
    h.finalize().into()
}

impl BasicAuth {
    pub(crate) fn from_env() -> Result<Option<Self>, AuthConfigError> {
        Self::from_parts(
            std::env::var("VPNCTLD_ADMIN_USER").ok(),
            std::env::var("VPNCTLD_ADMIN_PASSWORD").ok(),
        )
    }

    pub(crate) fn from_parts(
        user: Option<String>,
        pw: Option<String>,
    ) -> Result<Option<Self>, AuthConfigError> {
        let (Some(user), Some(pw)) = (user, pw) else {
            return Ok(None);
        };
        if user.is_empty() || pw.is_empty() {
            return Ok(None);
        }
        let is_plaintext = !pw.starts_with("$argon2");
        let secret = parse_password_secret(pw)?;
        if is_plaintext {
            tracing::warn!(
                target = "vpnctld::auth",
                "VPNCTLD_ADMIN_PASSWORD is plaintext — backward-compat path. \
                 Consider hashing via `vpnctl admin hash-password <plain>` + \
                 paste the `$argon2id$...` line into /etc/vpnctl/vpnctld.env. \
                 Plaintext is verified at request time via constant-time \
                 compare but offers zero defense if the env file leaks."
            );
        }
        let session_key = Arc::new(derive_session_key(&secret));
        Ok(Some(Self {
            user: Arc::new(user),
            secret,
            session_key,
        }))
    }

    fn sign_session(&self, now: u64) -> String {
        let exp = now.saturating_add(session_ttl_secs());
        let payload = format!("v1|{exp}|{user}", user = self.user.as_str());
        let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(self.session_key.as_ref()) else {
            return format!("{exp}.");
        };
        mac.update(payload.as_bytes());
        let sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        format!("{exp}.{sig}")
    }

    fn verify_session(&self, value: &str, now: u64) -> bool {
        let Some((exp_str, sig_b64)) = value.split_once('.') else {
            return false;
        };
        let Ok(exp) = exp_str.parse::<u64>() else {
            return false;
        };
        if exp <= now {
            return false;
        }
        let Ok(provided_sig) = URL_SAFE_NO_PAD.decode(sig_b64) else {
            return false;
        };
        let payload = format!("v1|{exp}|{user}", user = self.user.as_str());
        let mut mac = match Hmac::<Sha256>::new_from_slice(self.session_key.as_ref()) {
            Ok(m) => m,
            Err(_) => return false,
        };
        mac.update(payload.as_bytes());
        let expected = mac.finalize().into_bytes();
        if provided_sig.len() != expected.len() {
            return false;
        }
        bool::from(provided_sig.ct_eq(&expected))
    }
}

fn extract_cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    for hdr in headers.get_all(header::COOKIE) {
        let Ok(raw) = hdr.to_str() else { continue };
        for kv in raw.split(';') {
            let trimmed = kv.trim();
            if let Some(v) = trimmed.strip_prefix(&format!("{name}=")) {
                return Some(v);
            }
        }
    }
    None
}

fn build_session_cookie(value: &str) -> String {
    let max_age = session_ttl_secs();
    format!("{SESSION_COOKIE}={value}; Path=/; Max-Age={max_age}; HttpOnly; SameSite=Lax")
}

pub(crate) fn build_logout_cookie() -> String {
    format!("{SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax")
}

pub(crate) async fn require_basic_auth(
    axum::extract::State(auth): axum::extract::State<BasicAuth>,
    req: Request,
    next: Next,
) -> Response {
    let now = now_unix();

    if let Some(value) = extract_cookie(req.headers(), SESSION_COOKIE) {
        if auth.verify_session(value, now) {
            return next.run(req).await;
        }
    }

    if check_basic(&req, &auth) {
        let mut resp = next.run(req).await;
        let cookie = build_session_cookie(&auth.sign_session(now));
        if let Ok(hv) = HeaderValue::from_str(&cookie) {
            resp.headers_mut().append(header::SET_COOKIE, hv);
        }
        return resp;
    }

    let mut resp = (StatusCode::UNAUTHORIZED, "vpnctl admin: auth required\n").into_response();
    if let Ok(hv) = HeaderValue::from_str(r#"Basic realm="vpnctl admin", charset="UTF-8""#) {
        resp.headers_mut().insert(header::WWW_AUTHENTICATE, hv);
    }
    resp
}

pub(crate) async fn deny_all_misconfigured(_req: Request, _next: Next) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "vpnctl admin: auth misconfigured\n",
    )
        .into_response()
}

fn check_basic(req: &Request, auth: &BasicAuth) -> bool {
    let Some(hv) = req.headers().get(header::AUTHORIZATION) else {
        return false;
    };
    let Ok(s) = hv.to_str() else { return false };
    let Some(b64) = s.strip_prefix("Basic ") else {
        return false;
    };
    let Ok(decoded) = STANDARD.decode(b64.trim()) else {
        return false;
    };
    let Ok(creds) = std::str::from_utf8(&decoded) else {
        return false;
    };
    let Some((u, p)) = creds.split_once(':') else {
        return false;
    };
    let user_ok: bool = u.as_bytes().ct_eq(auth.user.as_bytes()).into();
    let pw_ok: bool = match &auth.secret {
        PasswordSecret::Argon2Phc(phc) => match PasswordHash::new(phc) {
            Ok(parsed) => argon2::Argon2::default()
                .verify_password(p.as_bytes(), &parsed)
                .is_ok(),
            Err(_) => false,
        },
        PasswordSecret::PlainBytes(bytes) => p.as_bytes().ct_eq(bytes).into(),
    };
    user_ok && pw_ok
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn req_with_basic(user: &str, pw: &str) -> Request {
        let creds = format!("{user}:{pw}");
        let b64 = STANDARD.encode(creds.as_bytes());
        let mut req = Request::builder()
            .uri("/")
            .body(axum::body::Body::empty())
            .unwrap();
        req.headers_mut().insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {b64}")).unwrap(),
        );
        req
    }

    fn auth_plain(user: &str, pw: &str) -> BasicAuth {
        let secret = PasswordSecret::PlainBytes(Arc::new(pw.as_bytes().to_vec()));
        let session_key = Arc::new(derive_session_key(&secret));
        BasicAuth {
            user: Arc::new(user.to_string()),
            secret,
            session_key,
        }
    }

    fn auth_argon2(user: &str, phc: &str) -> BasicAuth {
        let secret = PasswordSecret::Argon2Phc(Arc::new(phc.to_string()));
        let session_key = Arc::new(derive_session_key(&secret));
        BasicAuth {
            user: Arc::new(user.to_string()),
            secret,
            session_key,
        }
    }

    fn make_phc(plain: &str) -> String {
        use argon2::password_hash::{PasswordHasher, SaltString};
        let salt = SaltString::from_b64("ZmFrZXNhbHRmYWtlc2FsdA").unwrap();
        argon2::Argon2::default()
            .hash_password(plain.as_bytes(), &salt)
            .unwrap()
            .to_string()
    }

    #[test]
    fn plain_path_accepts_correct_password() {
        let auth = auth_plain("slovn", "hunter2");
        let req = req_with_basic("slovn", "hunter2");
        assert!(check_basic(&req, &auth), "correct plain creds must pass");
    }

    #[test]
    fn plain_path_rejects_wrong_password() {
        let auth = auth_plain("slovn", "hunter2");
        let req = req_with_basic("slovn", "wrong");
        assert!(!check_basic(&req, &auth));
    }

    #[test]
    fn plain_path_rejects_wrong_user_does_not_short_circuit() {
        let auth = auth_plain("slovn", "hunter2");
        let req = req_with_basic("wrong", "hunter2");
        assert!(!check_basic(&req, &auth));
    }

    #[test]
    fn argon2_path_accepts_correct_password() {
        let phc = make_phc("hunter2");
        let auth = auth_argon2("slovn", &phc);
        let req = req_with_basic("slovn", "hunter2");
        assert!(
            check_basic(&req, &auth),
            "argon2 verify must accept correct pw"
        );
    }

    #[test]
    fn argon2_path_rejects_wrong_password() {
        let phc = make_phc("hunter2");
        let auth = auth_argon2("slovn", &phc);
        let req = req_with_basic("slovn", "WRONG");
        assert!(!check_basic(&req, &auth));
    }

    #[test]
    fn argon2_path_rejects_malformed_phc_safely() {
        let auth = auth_argon2("slovn", "$argon2id$bogus");
        let req = req_with_basic("slovn", "anything");
        assert!(!check_basic(&req, &auth));
    }

    const MALFORMED_ARGON2: &str = "$argon2id$!!!";

    #[test]
    fn from_parts_absent_when_a_var_is_missing() {
        assert!(matches!(BasicAuth::from_parts(None, None), Ok(None)));
        assert!(matches!(
            BasicAuth::from_parts(Some("slovn".into()), None),
            Ok(None)
        ));
        assert!(matches!(
            BasicAuth::from_parts(None, Some("hunter2".into())),
            Ok(None)
        ));
    }

    #[test]
    fn from_parts_absent_when_a_var_is_empty() {
        assert!(matches!(
            BasicAuth::from_parts(Some(String::new()), Some("hunter2".into())),
            Ok(None)
        ));
        assert!(matches!(
            BasicAuth::from_parts(Some("slovn".into()), Some(String::new())),
            Ok(None)
        ));
    }

    #[test]
    fn from_parts_configured_for_plaintext_password() {
        let got = BasicAuth::from_parts(Some("slovn".into()), Some("hunter2".into()));
        assert!(
            matches!(got, Ok(Some(_))),
            "plaintext creds must yield a usable BasicAuth"
        );
    }

    #[test]
    fn from_parts_configured_for_valid_argon2() {
        let phc = make_phc("hunter2");
        let got = BasicAuth::from_parts(Some("slovn".into()), Some(phc));
        assert!(
            matches!(got, Ok(Some(_))),
            "valid argon2 PHC must yield a usable BasicAuth"
        );
    }

    #[test]
    fn from_parts_malformed_argon2_is_error_not_none() {
        let got = BasicAuth::from_parts(Some("slovn".into()), Some(MALFORMED_ARGON2.into()));
        assert!(
            matches!(got, Err(AuthConfigError::MalformedArgon2Hash)),
            "malformed argon2 must be a hard error, not Ok(None)"
        );
    }

    #[test]
    fn classify_admin_auth_mirrors_from_parts_tristate() {
        assert_eq!(classify_admin_auth(None, None), AdminAuthConfig::Absent);
        assert_eq!(
            classify_admin_auth(Some("slovn".into()), Some(String::new())),
            AdminAuthConfig::Absent
        );
        assert_eq!(
            classify_admin_auth(Some("slovn".into()), Some("plain".into())),
            AdminAuthConfig::Configured
        );
        assert_eq!(
            classify_admin_auth(Some("slovn".into()), Some(make_phc("x"))),
            AdminAuthConfig::Configured
        );
        assert_eq!(
            classify_admin_auth(Some("slovn".into()), Some(MALFORMED_ARGON2.into())),
            AdminAuthConfig::Malformed
        );
    }

    #[test]
    fn rejects_request_without_authorization_header() {
        let auth = auth_plain("slovn", "hunter2");
        let req = Request::builder()
            .uri("/")
            .body(axum::body::Body::empty())
            .unwrap();
        assert!(!check_basic(&req, &auth));
    }

    #[test]
    fn rejects_request_with_non_basic_authorization() {
        let auth = auth_plain("slovn", "hunter2");
        let mut req = Request::builder()
            .uri("/")
            .body(axum::body::Body::empty())
            .unwrap();
        req.headers_mut().insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer some-jwt"),
        );
        assert!(!check_basic(&req, &auth));
    }

    #[test]
    fn session_cookie_signed_now_verifies_now() {
        let auth = auth_plain("slovn", "hunter2");
        let now = 1_700_000_000_u64;
        let cookie = auth.sign_session(now);
        assert!(
            auth.verify_session(&cookie, now),
            "freshly minted cookie must verify at the same instant"
        );
    }

    #[test]
    fn session_cookie_rejected_after_expiry() {
        let auth = auth_plain("slovn", "hunter2");
        let cookie = auth.sign_session(1_700_000_000);
        let way_later = 1_700_000_000 + 100 * 365 * 86_400;
        assert!(
            !auth.verify_session(&cookie, way_later),
            "expired cookie must be rejected"
        );
    }

    #[test]
    fn session_cookie_with_tampered_signature_rejected() {
        let auth = auth_plain("slovn", "hunter2");
        let now = 1_700_000_000;
        let cookie = auth.sign_session(now);
        let (exp, sig) = cookie.split_once('.').unwrap();
        let mut bad_sig: String = sig.to_string();
        bad_sig.push('A');
        let tampered = format!("{exp}.{bad_sig}");
        assert!(
            !auth.verify_session(&tampered, now),
            "tampered signature must be rejected"
        );
    }

    #[test]
    fn session_cookie_with_tampered_expiry_rejected() {
        let auth = auth_plain("slovn", "hunter2");
        let cookie = auth.sign_session(1_700_000_000);
        let (_orig_exp, sig) = cookie.split_once('.').unwrap();
        let forged = format!("9999999999.{sig}");
        assert!(
            !auth.verify_session(&forged, 1_700_000_000),
            "forged-exp cookie must be rejected"
        );
    }

    #[test]
    fn session_cookie_rejected_after_password_rotation() {
        let auth1 = auth_plain("slovn", "old-password");
        let auth2 = auth_plain("slovn", "new-password");
        let cookie = auth1.sign_session(1_700_000_000);
        assert!(
            !auth2.verify_session(&cookie, 1_700_000_000),
            "cookie from old password must not verify under new password"
        );
    }

    #[test]
    fn session_cookie_rejected_when_user_changes() {
        let auth_old = auth_plain("slovn", "hunter2");
        let auth_new = auth_plain("admin", "hunter2");
        let cookie = auth_old.sign_session(1_700_000_000);
        assert!(
            !auth_new.verify_session(&cookie, 1_700_000_000),
            "cookie signed for a different user must be rejected"
        );
    }

    #[test]
    fn session_cookie_malformed_safely_rejected() {
        let auth = auth_plain("slovn", "hunter2");
        assert!(!auth.verify_session("nodothere", 1_700_000_000));
        assert!(!auth.verify_session("notanumber.SIGNATURE", 1_700_000_000));
        assert!(!auth.verify_session("1700000100.!!!notb64!!!", 1_700_000_000));
        assert!(!auth.verify_session("", 1_700_000_000));
    }

    #[test]
    fn extract_cookie_picks_correct_value() {
        let mut hm = HeaderMap::new();
        hm.insert(
            header::COOKIE,
            HeaderValue::from_static("foo=1; vpnctl_admin_session=abc.def; bar=2"),
        );
        assert_eq!(
            extract_cookie(&hm, SESSION_COOKIE),
            Some("abc.def"),
            "must extract the session cookie value among siblings"
        );
        assert_eq!(extract_cookie(&hm, "missing"), None);
    }

    #[test]
    fn extract_cookie_handles_multiple_headers_and_first_match() {
        let mut hm = HeaderMap::new();
        hm.append(
            header::COOKIE,
            HeaderValue::from_static("foo=1; vpnctl_admin_session=abc.def; bar=2"),
        );
        hm.append(
            header::COOKIE,
            HeaderValue::from_static("vpnctl_admin_session=shadowed; baz=3"),
        );
        assert_eq!(
            extract_cookie(&hm, SESSION_COOKIE),
            Some("abc.def"),
            "must extract the first session cookie value across multiple headers"
        );
        assert_eq!(extract_cookie(&hm, "baz"), Some("3"));
        assert_eq!(extract_cookie(&hm, "missing"), None);
    }

    #[test]
    fn build_session_cookie_carries_required_attrs() {
        let c = build_session_cookie("payload.sig");
        assert!(c.starts_with("vpnctl_admin_session=payload.sig"));
        assert!(c.contains("Path=/"));
        assert!(c.contains("HttpOnly"));
        assert!(c.contains("SameSite=Lax"));
        assert!(
            c.contains("Max-Age="),
            "must carry a Max-Age so the browser persists past tab-close"
        );
        assert!(
            !c.contains("Secure"),
            "Secure flag must not be set while the admin UI is HTTP-only"
        );
    }

    #[test]
    fn build_logout_cookie_expires_immediately() {
        let c = build_logout_cookie();
        assert!(c.starts_with("vpnctl_admin_session="));
        assert!(c.contains("Max-Age=0"), "logout cookie must expire now");
        assert!(c.contains("Path=/"), "Path must match the set form");
    }
}
