use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use argon2::password_hash::{PasswordHash, PasswordVerifier};
use axum::extract::{ConnectInfo, Request};
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
                "VPNCTLD_ADMIN_PASSWORD starts with $argon2 but is not a complete, supported Argon2 PHC hash",
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
        let valid = PasswordHash::new(&pw).is_ok_and(|parsed| {
            parsed.hash.is_some()
                && argon2::Algorithm::try_from(parsed.algorithm).is_ok()
                && parsed
                    .version
                    .is_none_or(|v| argon2::Version::try_from(v).is_ok())
                && argon2::Params::try_from(&parsed).is_ok()
                && parsed.salt.is_some_and(|salt| {
                    let mut decoded = [0u8; 64];
                    salt.decode_b64(&mut decoded)
                        .is_ok_and(|bytes| bytes.len() >= argon2::MIN_SALT_LEN)
                })
        });
        if !valid {
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

const LOGIN_WINDOW: Duration = Duration::from_secs(60);
const LOGIN_ATTEMPTS: u8 = 5;
const MAX_LOGIN_CLIENTS: usize = 1024;

#[derive(Default)]
struct LoginThrottle {
    attempts: Mutex<HashMap<Option<IpAddr>, (Instant, u8)>>,
}

impl LoginThrottle {
    fn try_acquire(&self, ip: Option<IpAddr>, now: Instant) -> bool {
        let Ok(mut attempts) = self.attempts.lock() else {
            return false;
        };
        attempts.retain(|_, (start, _)| now.duration_since(*start) < LOGIN_WINDOW);
        if !attempts.contains_key(&ip) && attempts.len() >= MAX_LOGIN_CLIENTS {
            // Evict the oldest window instead of refusing: refusing new clients
            // would let anyone with many addresses lock the operator out.
            if let Some(oldest) = attempts
                .iter()
                .min_by_key(|(_, (start, _))| *start)
                .map(|(key, _)| *key)
            {
                attempts.remove(&oldest);
            }
        }
        let (_, count) = attempts.entry(ip).or_insert((now, 0));
        if *count >= LOGIN_ATTEMPTS {
            return false;
        }
        // Reserve before verification so concurrent requests share the same budget.
        *count += 1;
        true
    }

    fn clear(&self, ip: Option<IpAddr>) {
        if let Ok(mut attempts) = self.attempts.lock() {
            attempts.remove(&ip);
        }
    }
}

#[derive(Clone)]
pub(crate) struct BasicAuth {
    pub user: Arc<String>,
    secret: PasswordSecret,
    session_key: Arc<[u8; 32]>,
    login_throttle: Arc<LoginThrottle>,
}

fn derive_session_key(secret: &PasswordSecret, install_secret: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"vpnctl-session-v2\0");
    h.update(install_secret.as_bytes());
    h.update(b"\0");
    match secret {
        PasswordSecret::Argon2Phc(phc) => h.update(phc.as_bytes()),
        PasswordSecret::PlainBytes(bytes) => h.update(bytes.as_slice()),
    }
    h.finalize().into()
}

impl BasicAuth {
    pub(crate) fn from_env(install_secret: &str) -> Result<Option<Self>, AuthConfigError> {
        Self::from_parts(
            std::env::var("VPNCTLD_ADMIN_USER").ok(),
            std::env::var("VPNCTLD_ADMIN_PASSWORD").ok(),
            install_secret,
        )
    }

    pub(crate) fn from_parts(
        user: Option<String>,
        pw: Option<String>,
        install_secret: &str,
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
        let session_key = Arc::new(derive_session_key(&secret, install_secret));
        Ok(Some(Self {
            user: Arc::new(user),
            secret,
            session_key,
            login_throttle: Arc::default(),
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

fn build_session_cookie(value: &str, forwarded_proto: Option<&str>) -> String {
    let max_age = session_ttl_secs();
    let secure = if forwarded_proto == Some("https") {
        "; Secure"
    } else {
        ""
    };
    format!("{SESSION_COOKIE}={value}; Path=/; Max-Age={max_age}; HttpOnly; SameSite=Lax{secure}")
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

    if let Some(header) = req.headers().get(header::AUTHORIZATION).cloned() {
        let ip = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|peer| crate::real_ip::resolve_peer_real_ip(req.headers(), peer.0.ip()));
        if !auth.login_throttle.try_acquire(ip, Instant::now()) {
            let mut resp =
                (StatusCode::TOO_MANY_REQUESTS, "vpnctl admin: retry later\n").into_response();
            resp.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
            return resp;
        }
        if verify_basic(header, auth.clone(), &VERIFY_PERMITS).await {
            auth.login_throttle.clear(ip);
            let logout =
                req.method() == axum::http::Method::POST && req.uri().path() == "/admin/logout";
            let forwarded_proto =
                req.extensions()
                    .get::<ConnectInfo<SocketAddr>>()
                    .and_then(|peer| {
                        crate::real_ip::resolve_trusted_header(
                            req.headers(),
                            peer.0.ip(),
                            "x-forwarded-proto",
                        )
                    });
            let mut resp = next.run(req).await;
            if !logout {
                let cookie =
                    build_session_cookie(&auth.sign_session(now), forwarded_proto.as_deref());
                if let Ok(hv) = HeaderValue::from_str(&cookie) {
                    resp.headers_mut().append(header::SET_COOKIE, hv);
                }
            }
            return resp;
        }
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

/// At most this many Argon2 verifications run at once, so a flood of password
/// attempts from many addresses cannot exhaust the blocking pool and CPU.
const MAX_CONCURRENT_VERIFICATIONS: usize = 4;

static VERIFY_PERMITS: tokio::sync::Semaphore =
    tokio::sync::Semaphore::const_new(MAX_CONCURRENT_VERIFICATIONS);

async fn verify_basic(
    header: HeaderValue,
    auth: BasicAuth,
    permits: &'static tokio::sync::Semaphore,
) -> bool {
    let Ok(permit) = permits.acquire().await else {
        return false;
    };
    tokio::task::spawn_blocking(move || {
        // The blocking job outlives a cancelled HTTP request.
        let _permit = permit;
        check_basic(Some(&header), &auth)
    })
    .await
    .unwrap_or(false)
}

fn check_basic(header: Option<&HeaderValue>, auth: &BasicAuth) -> bool {
    let Some(hv) = header else {
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
    use axum::routing::{get, post};
    use tower::ServiceExt;

    const TEST_INSTALL_SECRET: &str = "test-install-secret";

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
        let session_key = Arc::new(derive_session_key(&secret, TEST_INSTALL_SECRET));
        BasicAuth {
            user: Arc::new(user.to_string()),
            secret,
            session_key,
            login_throttle: Arc::default(),
        }
    }

    fn auth_argon2(user: &str, phc: &str) -> BasicAuth {
        let secret = PasswordSecret::Argon2Phc(Arc::new(phc.to_string()));
        let session_key = Arc::new(derive_session_key(&secret, TEST_INSTALL_SECRET));
        BasicAuth {
            user: Arc::new(user.to_string()),
            secret,
            session_key,
            login_throttle: Arc::default(),
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
        assert!(
            check_basic(req.headers().get(header::AUTHORIZATION), &auth),
            "correct plain creds must pass"
        );
    }

    #[test]
    fn plain_path_rejects_wrong_password() {
        let auth = auth_plain("slovn", "hunter2");
        let req = req_with_basic("slovn", "wrong");
        assert!(!check_basic(
            req.headers().get(header::AUTHORIZATION),
            &auth
        ));
    }

    #[test]
    fn plain_path_rejects_wrong_user_does_not_short_circuit() {
        let auth = auth_plain("slovn", "hunter2");
        let req = req_with_basic("wrong", "hunter2");
        assert!(!check_basic(
            req.headers().get(header::AUTHORIZATION),
            &auth
        ));
    }

    #[test]
    fn argon2_path_accepts_correct_password() {
        let phc = make_phc("hunter2");
        let auth = auth_argon2("slovn", &phc);
        let req = req_with_basic("slovn", "hunter2");
        assert!(
            check_basic(req.headers().get(header::AUTHORIZATION), &auth),
            "argon2 verify must accept correct pw"
        );
    }

    #[test]
    fn argon2_path_rejects_wrong_password() {
        let phc = make_phc("hunter2");
        let auth = auth_argon2("slovn", &phc);
        let req = req_with_basic("slovn", "WRONG");
        assert!(!check_basic(
            req.headers().get(header::AUTHORIZATION),
            &auth
        ));
    }

    #[test]
    fn argon2_path_rejects_malformed_phc_safely() {
        let auth = auth_argon2("slovn", "$argon2id$bogus");
        let req = req_with_basic("slovn", "anything");
        assert!(!check_basic(
            req.headers().get(header::AUTHORIZATION),
            &auth
        ));
    }

    fn protected_router(auth: BasicAuth) -> axum::Router {
        axum::Router::new()
            .route("/", get(|| async { "ok" }))
            .route(
                "/admin/logout",
                post(crate::handlers::admin::helpers::logout),
            )
            .layer(axum::middleware::from_fn_with_state(
                auth,
                require_basic_auth,
            ))
    }

    #[tokio::test(flavor = "current_thread")]
    async fn argon2_verification_keeps_async_runtime_responsive() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let auth = auth_argon2("admin", &make_phc("password"));
        let header = req_with_basic("admin", "password").headers()[header::AUTHORIZATION].clone();
        let progressed = AtomicBool::new(false);
        let verify = async {
            let valid = verify_basic(header, auth, &VERIFY_PERMITS).await;
            assert!(progressed.load(Ordering::SeqCst));
            valid
        };
        let heartbeat = async {
            tokio::task::yield_now().await;
            progressed.store(true, Ordering::SeqCst);
        };
        let (valid, ()) = tokio::join!(verify, heartbeat);
        assert!(valid);
    }

    #[test]
    fn cancelled_verifications_hold_permits_until_blocking_jobs_finish() {
        static PERMITS: tokio::sync::Semaphore =
            tokio::sync::Semaphore::const_new(MAX_CONCURRENT_VERIFICATIONS);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .max_blocking_threads(1)
            .enable_time()
            .build()
            .unwrap();
        let auth = auth_argon2("admin", &make_phc("password"));
        let header = req_with_basic("admin", "password").headers()[header::AUTHORIZATION].clone();
        runtime.block_on(async {
            let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
            let (started_tx, started_rx) = tokio::sync::oneshot::channel();
            let blocker = tokio::task::spawn_blocking(move || {
                started_tx.send(()).unwrap();
                let _ = release_rx.recv();
            });
            started_rx.await.unwrap();
            let mut requests = Vec::new();
            for _ in 0..MAX_CONCURRENT_VERIFICATIONS {
                requests.push(tokio::spawn(verify_basic(
                    header.clone(),
                    auth.clone(),
                    &PERMITS,
                )));
            }
            tokio::time::timeout(Duration::from_secs(10), async {
                while PERMITS.available_permits() != 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            let following = tokio::spawn(verify_basic(header, auth, &PERMITS));
            for request in &requests {
                request.abort();
            }
            for request in requests {
                assert!(request.await.unwrap_err().is_cancelled());
            }
            // Queued blocking jobs still own the entire verification budget.
            assert_eq!(PERMITS.available_permits(), 0);
            release_tx.send(()).unwrap();
            blocker.await.unwrap();
            let permit = tokio::time::timeout(
                Duration::from_secs(10),
                PERMITS.acquire_many(u32::try_from(MAX_CONCURRENT_VERIFICATIONS).unwrap()),
            )
            .await
            .unwrap()
            .unwrap();
            drop(permit);
            assert!(following.await.unwrap());
            assert_eq!(PERMITS.available_permits(), MAX_CONCURRENT_VERIFICATIONS);
        });
    }

    #[tokio::test]
    async fn failed_logins_throttle_only_the_same_client_ip() {
        let app = protected_router(auth_plain("admin", "password"));
        let peer: SocketAddr = "192.0.2.1:12345".parse().unwrap();
        for _ in 0..LOGIN_ATTEMPTS {
            let mut req = req_with_basic("admin", "wrong");
            req.extensions_mut().insert(ConnectInfo(peer));
            assert_eq!(
                app.clone().oneshot(req).await.unwrap().status(),
                StatusCode::UNAUTHORIZED
            );
        }
        let mut req = req_with_basic("admin", "password");
        req.extensions_mut().insert(ConnectInfo(peer));
        req.headers_mut()
            .insert("x-real-ip", HeaderValue::from_static("192.0.2.2"));
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(resp.headers()[header::RETRY_AFTER], "60");

        let mut req = req_with_basic("admin", "password");
        req.extensions_mut().insert(ConnectInfo(
            "192.0.2.2:12345".parse::<SocketAddr>().unwrap(),
        ));
        // Untrusted forwarding headers cannot move a request into another IP's bucket.
        req.headers_mut()
            .insert("x-real-ip", HeaderValue::from_static("192.0.2.1"));
        assert_eq!(app.oneshot(req).await.unwrap().status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn successful_login_resets_failures_and_sessions_bypass_throttle() {
        let auth = auth_plain("admin", "password");
        let app = protected_router(auth.clone());
        for _ in 0..LOGIN_ATTEMPTS - 1 {
            let resp = app
                .clone()
                .oneshot(req_with_basic("admin", "wrong"))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        }
        let resp = app
            .clone()
            .oneshot(req_with_basic("admin", "password"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        for _ in 0..LOGIN_ATTEMPTS {
            let resp = app
                .clone()
                .oneshot(req_with_basic("admin", "wrong"))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        }
        let mut req = req_with_basic("admin", "wrong");
        req.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_str(&format!(
                "{SESSION_COOKIE}={}",
                auth.sign_session(now_unix())
            ))
            .unwrap(),
        );
        assert_eq!(app.oneshot(req).await.unwrap().status(), StatusCode::OK);
    }

    #[test]
    fn login_throttle_is_bounded_and_expires_at_window_boundary() {
        let throttle = LoginThrottle::default();
        let now = Instant::now();
        let ip = |n: usize| Some(IpAddr::from(std::net::Ipv4Addr::from(n as u32)));
        let at = |n: usize| now + Duration::from_nanos(n as u64);
        for n in 0..MAX_LOGIN_CLIENTS {
            assert!(throttle.try_acquire(ip(n), at(n)));
        }
        // A full table evicts the oldest window; a new client is never refused.
        assert!(throttle.try_acquire(None, at(MAX_LOGIN_CLIENTS)));
        {
            let attempts = throttle.attempts.lock().unwrap();
            assert_eq!(attempts.len(), MAX_LOGIN_CLIENTS);
            assert!(!attempts.contains_key(&ip(0)));
        }
        let t = at(MAX_LOGIN_CLIENTS);
        for _ in 1..LOGIN_ATTEMPTS {
            assert!(throttle.try_acquire(ip(1), t));
        }
        assert!(!throttle.try_acquire(ip(1), at(1) + LOGIN_WINDOW - Duration::from_nanos(1)));
        assert!(throttle.try_acquire(ip(1), at(1) + LOGIN_WINDOW));
        assert!(throttle.try_acquire(None, at(1) + LOGIN_WINDOW * 2));
        assert_eq!(throttle.attempts.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn logout_with_basic_credentials_does_not_reissue_session() {
        let auth = auth_plain("admin", "password");
        let app = protected_router(auth.clone());
        for (with_basic, with_session) in [(true, false), (false, true), (true, true)] {
            let mut req = req_with_basic("admin", "password");
            if !with_basic {
                req.headers_mut().remove(header::AUTHORIZATION);
            }
            *req.method_mut() = axum::http::Method::POST;
            *req.uri_mut() = "/admin/logout".parse().unwrap();
            if with_session {
                req.headers_mut().insert(
                    header::COOKIE,
                    HeaderValue::from_str(&format!(
                        "{SESSION_COOKIE}={}",
                        auth.sign_session(now_unix())
                    ))
                    .unwrap(),
                );
            }
            let resp = app.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
            assert!(resp.headers().contains_key(header::WWW_AUTHENTICATE));
            assert_eq!(resp.headers()[header::CACHE_CONTROL], "no-store");
            assert!(!resp.headers().contains_key(header::LOCATION));
            let cookies: Vec<_> = resp.headers().get_all(header::SET_COOKIE).iter().collect();
            assert_eq!(cookies.len(), 1);
            assert!(cookies[0].to_str().unwrap().contains("Max-Age=0"));
        }
    }

    #[test]
    fn incomplete_or_unsupported_argon2_phc_is_rejected() {
        let valid = make_phc("password");
        let salt_only = valid.rsplit_once('$').unwrap().0.to_string();
        for phc in [
            "$argon2id".to_string(),
            salt_only,
            valid.replace("argon2id", "argon2bogus"),
            valid.replace("v=19", "v=42"),
            valid.replace("m=19456", "m=0"),
            valid.replace("ZmFrZXNhbHRmYWtlc2FsdA", "YWJj"),
        ] {
            assert!(
                matches!(
                    BasicAuth::from_parts(
                        Some("admin".into()),
                        Some(phc.clone()),
                        TEST_INSTALL_SECRET
                    ),
                    Err(AuthConfigError::MalformedArgon2Hash)
                ),
                "must reject {phc}"
            );
            assert_eq!(
                classify_admin_auth(Some("admin".into()), Some(phc)),
                AdminAuthConfig::Malformed
            );
        }
    }

    const MALFORMED_ARGON2: &str = "$argon2id$!!!";

    #[test]
    fn from_parts_absent_when_a_var_is_missing() {
        assert!(matches!(
            BasicAuth::from_parts(None, None, TEST_INSTALL_SECRET),
            Ok(None)
        ));
        assert!(matches!(
            BasicAuth::from_parts(Some("slovn".into()), None, TEST_INSTALL_SECRET),
            Ok(None)
        ));
        assert!(matches!(
            BasicAuth::from_parts(None, Some("hunter2".into()), TEST_INSTALL_SECRET),
            Ok(None)
        ));
    }

    #[test]
    fn from_parts_absent_when_a_var_is_empty() {
        assert!(matches!(
            BasicAuth::from_parts(
                Some(String::new()),
                Some("hunter2".into()),
                TEST_INSTALL_SECRET
            ),
            Ok(None)
        ));
        assert!(matches!(
            BasicAuth::from_parts(
                Some("slovn".into()),
                Some(String::new()),
                TEST_INSTALL_SECRET
            ),
            Ok(None)
        ));
    }

    #[test]
    fn from_parts_configured_for_plaintext_password() {
        let got = BasicAuth::from_parts(
            Some("slovn".into()),
            Some("hunter2".into()),
            TEST_INSTALL_SECRET,
        );
        assert!(
            matches!(got, Ok(Some(_))),
            "plaintext creds must yield a usable BasicAuth"
        );
    }

    #[test]
    fn from_parts_configured_for_valid_argon2() {
        let phc = make_phc("hunter2");
        let got = BasicAuth::from_parts(Some("slovn".into()), Some(phc), TEST_INSTALL_SECRET);
        assert!(
            matches!(got, Ok(Some(_))),
            "valid argon2 PHC must yield a usable BasicAuth"
        );
    }

    #[test]
    fn from_parts_malformed_argon2_is_error_not_none() {
        let got = BasicAuth::from_parts(
            Some("slovn".into()),
            Some(MALFORMED_ARGON2.into()),
            TEST_INSTALL_SECRET,
        );
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
        assert!(!check_basic(
            req.headers().get(header::AUTHORIZATION),
            &auth
        ));
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
        assert!(!check_basic(
            req.headers().get(header::AUTHORIZATION),
            &auth
        ));
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

    #[tokio::test]
    async fn session_cookie_forged_from_phc_alone_is_rejected() {
        let phc = make_phc("password");
        let auth = auth_argon2("admin", &phc);
        let exp = now_unix() + 86_400;
        let mut hash = Sha256::new();
        hash.update(b"vpnctl-session-v1\0");
        hash.update(phc.as_bytes());
        let mut mac = Hmac::<Sha256>::new_from_slice(&hash.finalize()).unwrap();
        mac.update(format!("v1|{exp}|admin").as_bytes());
        let forged = format!(
            "{exp}.{}",
            URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
        );
        assert!(!auth.verify_session(&forged, now_unix()));
        let mut req = Request::builder().body(axum::body::Body::empty()).unwrap();
        req.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("{SESSION_COOKIE}={forged}")).unwrap(),
        );
        assert_eq!(
            protected_router(auth).oneshot(req).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn session_cookie_survives_inventory_reopen_but_not_credential_changes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("inv.db");
        let inv = vpnctl_inventory::SqliteInventory::open(&path)
            .await
            .unwrap();
        let install_secret = inv.get_or_create_admin_session_secret().await.unwrap();
        let phc = make_phc("password");
        let auth = BasicAuth::from_parts(Some("admin".into()), Some(phc.clone()), &install_secret)
            .unwrap()
            .unwrap();
        let now = 1_700_000_000;
        let cookie = auth.sign_session(now);
        inv.close().await;
        let reopened = vpnctl_inventory::SqliteInventory::open(&path)
            .await
            .unwrap();
        let persisted = reopened.get_or_create_admin_session_secret().await.unwrap();
        let restarted = BasicAuth::from_parts(Some("admin".into()), Some(phc.clone()), &persisted)
            .unwrap()
            .unwrap();
        assert!(restarted.verify_session(&cookie, now));
        let changed_password = BasicAuth::from_parts(
            Some("admin".into()),
            Some(make_phc("new-password")),
            &persisted,
        )
        .unwrap()
        .unwrap();
        assert!(!changed_password.verify_session(&cookie, now));
        let changed_user =
            BasicAuth::from_parts(Some("other".into()), Some(phc.clone()), &persisted)
                .unwrap()
                .unwrap();
        assert!(!changed_user.verify_session(&cookie, now));
        let other_install =
            BasicAuth::from_parts(Some("admin".into()), Some(phc), "other-install-secret")
                .unwrap()
                .unwrap();
        assert!(!other_install.verify_session(&cookie, now));
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
        let c = build_session_cookie("payload.sig", None);
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
            "Plain HTTP must remain usable without a Secure flag"
        );
    }

    #[test]
    fn session_cookie_secure_requires_https_from_a_trusted_proxy() {
        let peer: IpAddr = "192.0.2.1".parse().unwrap();
        for (trusted, proto, secure) in [
            (true, "https", true),
            (true, "http", false),
            (true, "https,http", false),
            (false, "https", false),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert("x-forwarded-proto", HeaderValue::from_str(proto).unwrap());
            let trusted_peers = if trusted { vec![peer] } else { Vec::new() };
            let forwarded = crate::real_ip::resolve_trusted_header_with(
                &headers,
                peer,
                "x-forwarded-proto",
                &trusted_peers,
            );
            let cookie = build_session_cookie("payload.sig", forwarded.as_deref());
            assert_eq!(cookie.ends_with("; Secure"), secure, "{trusted}: {proto}");
        }
        assert!(!build_session_cookie("payload.sig", None).contains("Secure"));
    }

    #[tokio::test]
    async fn login_ignores_https_forwarding_from_untrusted_or_missing_peer() {
        for peer in [None, Some("192.0.2.1:12345".parse::<SocketAddr>().unwrap())] {
            let mut req = req_with_basic("admin", "password");
            if let Some(peer) = peer {
                req.extensions_mut().insert(ConnectInfo(peer));
            }
            req.headers_mut()
                .insert("x-forwarded-proto", HeaderValue::from_static("https"));
            let resp = protected_router(auth_plain("admin", "password"))
                .oneshot(req)
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            assert!(
                !resp.headers()[header::SET_COOKIE]
                    .to_str()
                    .unwrap()
                    .contains("Secure")
            );
        }
    }

    #[test]
    fn build_logout_cookie_expires_immediately() {
        let c = build_logout_cookie();
        assert!(c.starts_with("vpnctl_admin_session="));
        assert!(c.contains("Max-Age=0"), "logout cookie must expire now");
        assert!(c.contains("Path=/"), "Path must match the set form");
    }
}
