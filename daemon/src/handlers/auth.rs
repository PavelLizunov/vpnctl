//! Auth middleware for the admin UI — Basic Auth + signed session cookie.
//!
//! Reads expected credentials from env at startup (`VPNCTLD_ADMIN_USER`,
//! `VPNCTLD_ADMIN_PASSWORD`). When both are set, every request that
//! traverses this layer must carry EITHER a valid signed
//! `vpnctl_admin_session` cookie OR `Authorization: Basic ...` matching
//! the configured credentials; otherwise 401. When neither env var is
//! set the layer is a no-op (useful for local smoke).
//!
//! ## Why the session cookie (2026-05-26)
//!
//! Pavel: «мне постоянно приходится пароль писать, почему он не
//! сохраняется». Plain HTTP Basic Auth caches the `Authorization`
//! header only in the **browser process memory**, scoped to the
//! `(origin, realm)` tuple. The cache lifetime is browser-specific:
//! Chrome flushes when all tabs of an origin close (so re-opening
//! `/admin/` an hour later re-prompts); some privacy modes flush on
//! suspend; cross-tab consistency is also flaky. The operator hits
//! the prompt many times per day even though they never logged out.
//!
//! Fix: on a successful basic-auth, issue a signed cookie that the
//! browser persists for 30 days (default; env-overridable). Subsequent
//! requests authenticate via the cookie — no 401 fires, the browser
//! never re-prompts, and the basic-auth header path stays for CLI /
//! curl users who don't have a cookie jar.
//!
//! ## Cookie format
//!
//! ```text
//! vpnctl_admin_session=<expires_unix>.<base64url(hmac_sha256(payload, key))>
//! ```
//!
//! * `expires_unix` — decimal seconds since epoch when the cookie
//!   becomes invalid. Verified against current wall-clock at request
//!   time, so a leaked cookie auto-expires even if revocation isn't
//!   plumbed.
//! * `hmac_sha256(payload, key)` — signed body covers the literal
//!   `"v1|" + expires_unix + "|" + admin_user`. Domain-separation
//!   prefix `v1|` reserves the namespace for future format bumps
//!   without invalidation surprises.
//! * `key` — derived from the configured admin password via
//!   `SHA256(b"vpnctl-session-v1\0" || password_secret_bytes)`. NO
//!   new env var to manage. Side-benefit: rotating the password
//!   atomically invalidates every live session — every device on
//!   the old password gets re-prompted on next request.
//!
//! Cookie attributes:
//! ```text
//! Path=/; HttpOnly; SameSite=Lax; Max-Age=<ttl_secs>
//! ```
//!
//! `HttpOnly` blocks JS read access (defense-in-depth against future
//! XSS). `SameSite=Lax` blocks cross-site POSTs that would otherwise
//! ride the cookie. `Secure` is intentionally NOT set — the admin UI
//! ships LAN-only over plain HTTP today; flipping `Secure` would
//! silently break the cookie on the LAN host. When external TLS
//! exposure lands (post-OAuth/2FA, see CLAUDE.md roadmap) revisit.
//!
//! ## Logout
//!
//! `POST /admin/logout` clears the cookie (`Max-Age=0`) and 303-
//! redirects to `/admin/`. The browser then has no session cookie
//! AND has not been told to forget basic-auth; the next admin request
//! falls back to basic-auth and prompts the operator again. Use this
//! when switching identity or after rotating the password from
//! another device.
//!
//! ## Password storage formats (security-audit 2026-05-18)
//!
//! `VPNCTLD_ADMIN_PASSWORD` may hold either:
//!
//!   * **Argon2id hash** (preferred) — starts with `$argon2id$v=19$…`.
//!     Verified via [`argon2::Argon2::verify_password`]. If the env
//!     file leaks (backup, grep, accidental commit), the secret stays
//!     protected by the slow-hash + per-secret salt.
//!   * **Plain string** (backward-compat) — anything not starting with
//!     `$argon2`. Verified via `subtle::ConstantTimeEq`. Logs a startup
//!     warn («consider hashing») once.
//!
//! Generate a hash via the `vpnctl admin hash-password` CLI
//! (reads plaintext from stdin, writes the `$argon2id$…` line to
//! stdout — paste into the EnvironmentFile):
//!
//! ```bash
//! echo -n 'mySecret' | vpnctl admin hash-password
//! # → $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>
//! ```
//!
//! Use `--password <plain>` for ad-hoc use; the CLI warns because
//! the plaintext lands in shell history and `/proc/<pid>/cmdline`.
//! The implementation is in `cli/src/cmd/admin.rs`; before
//! 2026-05-22 this doc-comment referenced a non-existent subcommand.
//!
//! ## Constant-time
//!
//! Comparison on BOTH user and password is constant-time — no
//! early-exit timing oracle on either field. The user field is always
//! plaintext (low value to hash) but still uses `ct_eq`.

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

/// Name of the persistent admin session cookie. Versioned via the
/// `v1|` prefix inside the signed payload, not the cookie name —
/// renaming would force every operator's browser to re-prompt on
/// upgrade, which defeats the point of the cookie.
const SESSION_COOKIE: &str = "vpnctl_admin_session";

/// Default session lifetime: 30 days. Long enough that the operator
/// never sees the prompt during normal use, short enough that a stolen
/// laptop's cached session expires within a billing cycle.
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

/// Stored credential for the admin password. Distinguishes hashed
/// from plaintext at construction time so the per-request hot path
/// doesn't re-parse the prefix every call.
#[derive(Clone)]
enum PasswordSecret {
    /// PHC-string of the form `$argon2id$v=19$m=…,t=…,p=…$<salt>$<hash>`.
    /// Verified via `argon2::verify_password`. Constant-time at the
    /// argon2 library level.
    Argon2Phc(Arc<String>),
    /// Raw bytes. Constant-time `ct_eq` against the candidate.
    /// Backward-compat for operators with pre-hash env files.
    PlainBytes(Arc<Vec<u8>>),
}

#[derive(Clone)]
pub(crate) struct BasicAuth {
    pub user: Arc<String>,
    secret: PasswordSecret,
    /// 32-byte HMAC-SHA256 key for signing session cookies. Derived
    /// at construction from the configured password secret — see
    /// `derive_session_key`. Wrapped in `Arc` so the clone-per-
    /// middleware-layer is cheap.
    session_key: Arc<[u8; 32]>,
}

/// Derive the cookie-signing key from the stored password material.
/// Domain-separated by a literal prefix so the key can never collide
/// with another HMAC use of the same secret.
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
    /// Construct from env. Returns `None` if either var is missing —
    /// caller decides whether to enforce or skip the layer.
    ///
    /// Detects `$argon2` prefix → Argon2Phc; otherwise → PlainBytes
    /// with a one-shot warn-log on the startup logger.
    pub(crate) fn from_env() -> Option<Self> {
        let user = std::env::var("VPNCTLD_ADMIN_USER").ok()?;
        let pw = std::env::var("VPNCTLD_ADMIN_PASSWORD").ok()?;
        if user.is_empty() || pw.is_empty() {
            return None;
        }
        let secret = if pw.starts_with("$argon2") {
            // Validate the hash parses at construction time, so a
            // malformed env doesn't slow-fail on first request.
            if PasswordHash::new(&pw).is_err() {
                tracing::error!(
                    target = "vpnctld::auth",
                    "VPNCTLD_ADMIN_PASSWORD starts with $argon2 but doesn't parse \
                     as a PHC string — basic-auth DISABLED. Re-generate via \
                     `vpnctl admin hash-password <plain>`."
                );
                return None;
            }
            PasswordSecret::Argon2Phc(Arc::new(pw))
        } else {
            tracing::warn!(
                target = "vpnctld::auth",
                "VPNCTLD_ADMIN_PASSWORD is plaintext — backward-compat path. \
                 Consider hashing via `vpnctl admin hash-password <plain>` + \
                 paste the `$argon2id$...` line into /etc/vpnctl/vpnctld.env. \
                 Plaintext is verified at request time via constant-time \
                 compare but offers zero defense if the env file leaks."
            );
            PasswordSecret::PlainBytes(Arc::new(pw.into_bytes()))
        };
        let session_key = Arc::new(derive_session_key(&secret));
        Some(Self {
            user: Arc::new(user),
            secret,
            session_key,
        })
    }

    /// Build the cookie value `<exp>.<sig>` for the configured user
    /// with the configured TTL counted from `now_unix()`.
    fn sign_session(&self, now: u64) -> String {
        let exp = now.saturating_add(session_ttl_secs());
        let payload = format!("v1|{exp}|{user}", user = self.user.as_str());
        // `Hmac::new_from_slice` only errors when the key length is
        // invalid; HMAC-SHA256 accepts any byte length, so this branch
        // is unreachable. Returning an unsigned placeholder on the
        // impossible branch keeps the signature `-> String` while
        // staying inside the no-panic policy.
        let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(self.session_key.as_ref()) else {
            return format!("{exp}.");
        };
        mac.update(payload.as_bytes());
        let sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        format!("{exp}.{sig}")
    }

    /// Return Some when `value` is a well-formed, non-expired session
    /// cookie signed with the current admin password's derived key.
    /// Constant-time signature compare — no leak about which half
    /// (timestamp vs sig) was wrong.
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
        // ct_eq returns Choice; cast via `.into()` to bool. Lengths
        // are fixed-32 from SHA256 — mismatch would mean the b64
        // decode produced a wrong-length sig, reject early.
        if provided_sig.len() != expected.len() {
            return false;
        }
        bool::from(provided_sig.ct_eq(&expected))
    }
}

/// Extract the value of a single cookie from the `Cookie:` header,
/// if present. Returns the FIRST match — cookie shadowing (multiple
/// values for one name) is not our concern; pick the first.
fn extract_cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for kv in raw.split(';') {
        let trimmed = kv.trim();
        if let Some(v) = trimmed.strip_prefix(&format!("{name}=")) {
            return Some(v);
        }
    }
    None
}

/// Build the `Set-Cookie` value for a fresh session. `Path=/` so the
/// cookie is sent to both `/admin/*` and `/api/*` (the latter for
/// any future admin-gated JSON endpoints). HttpOnly + SameSite=Lax
/// match the rest of the cookie family.
fn build_session_cookie(value: &str) -> String {
    let max_age = session_ttl_secs();
    format!("{SESSION_COOKIE}={value}; Path=/; Max-Age={max_age}; HttpOnly; SameSite=Lax")
}

/// Build the cookie-clear directive used by `/admin/logout`. Same
/// attributes as the set so the browser actually matches the cookie
/// to delete (mismatched Path leaves a zombie cookie).
pub(crate) fn build_logout_cookie() -> String {
    format!("{SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax")
}

pub(crate) async fn require_basic_auth(
    axum::extract::State(auth): axum::extract::State<BasicAuth>,
    req: Request,
    next: Next,
) -> Response {
    let now = now_unix();

    // 1) Session cookie path — fast, no Set-Cookie roundtrip.
    if let Some(value) = extract_cookie(req.headers(), SESSION_COOKIE) {
        if auth.verify_session(value, now) {
            return next.run(req).await;
        }
        // Cookie present but invalid (expired, tampered, or password
        // rotated). Fall through to basic-auth — if that succeeds we
        // re-issue a fresh cookie and the browser silently replaces
        // the stale one.
    }

    // 2) Basic-auth path — accepted; mint a session cookie so the
    // operator's NEXT request rides on the cookie and the browser
    // never has to surface the prompt again.
    if check_basic(&req, &auth) {
        let mut resp = next.run(req).await;
        let cookie = build_session_cookie(&auth.sign_session(now));
        if let Ok(hv) = HeaderValue::from_str(&cookie) {
            resp.headers_mut().append(header::SET_COOKIE, hv);
        }
        return resp;
    }

    // 3) Reject. Match the `vpnctl admin: …` copy contract used by
    // every other backend response (see `handlers::admin::error_text`).
    // Operators grep `journalctl -u vpnctld` for the prefix.
    let mut resp = (StatusCode::UNAUTHORIZED, "vpnctl admin: auth required\n").into_response();
    if let Ok(hv) = HeaderValue::from_str(r#"Basic realm="vpnctl admin", charset="UTF-8""#) {
        resp.headers_mut().insert(header::WWW_AUTHENTICATE, hv);
    }
    resp
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
    // Constant-time compare on user (never short-circuit on user
    // mismatch — that would let an attacker enumerate the user).
    let user_ok: bool = u.as_bytes().ct_eq(auth.user.as_bytes()).into();
    // Password verification depends on the stored format. Both
    // paths are constant-time (argon2 verify is by construction;
    // ct_eq for the plain path).
    let pw_ok: bool = match &auth.secret {
        PasswordSecret::Argon2Phc(phc) => {
            // PHC was validated at construction; re-parse is cheap
            // (no allocation in the happy path beyond the salt).
            match PasswordHash::new(phc) {
                Ok(parsed) => argon2::Argon2::default()
                    .verify_password(p.as_bytes(), &parsed)
                    .is_ok(),
                Err(_) => false,
            }
        }
        PasswordSecret::PlainBytes(bytes) => p.as_bytes().ct_eq(bytes).into(),
    };
    user_ok && pw_ok
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // Helpers — small fake Request with an Authorization header.
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

    /// Generate a real argon2id PHC for the given plain password.
    /// Uses the default argon2 params (m=19456, t=2, p=1 — RFC 9106).
    /// Salt is a deterministic 16-byte literal for test reproducibility;
    /// production paths use `SaltString::generate(OsRng)`.
    fn make_phc(plain: &str) -> String {
        use argon2::password_hash::{PasswordHasher, SaltString};
        // Base64-no-pad 16-byte literal. Deterministic test salt.
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
        // Defense: an attacker who knows the password but is fishing
        // for the username must not be able to enumerate via timing.
        // We don't measure timing here (flaky); we just confirm the
        // logic computes BOTH ct_eq calls and AND's them.
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
        // If the operator pasted a malformed `$argon2…` string, the
        // request layer must reject (NOT panic, NOT accept). The
        // construction-time validator in `from_env` catches most of
        // this, but the per-request reparse path is also defended.
        let auth = auth_argon2("slovn", "$argon2id$bogus");
        let req = req_with_basic("slovn", "anything");
        assert!(!check_basic(&req, &auth));
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

    // ─── session cookie ─────────────────────────────────────────────

    #[test]
    fn session_cookie_signed_now_verifies_now() {
        // The cookie minted at `now` (with whatever TTL is configured)
        // must verify at the same instant. Smoke test that
        // sign_session ↔ verify_session round-trip.
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
        // Same cookie, asked to verify long after the TTL — must fail.
        // We probe at now + 100 years to be safely past any TTL the
        // env var could pump up to (capped at 365 days).
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
        // Flip one base64url char in the signature half. The HMAC
        // verify must fail constant-time.
        let (exp, sig) = cookie.split_once('.').unwrap();
        let mut bad_sig: String = sig.to_string();
        // Pick a char that's safe to flip — replace 1st char with
        // a different valid b64url char, or just append a junk byte.
        bad_sig.push('A');
        let tampered = format!("{exp}.{bad_sig}");
        assert!(
            !auth.verify_session(&tampered, now),
            "tampered signature must be rejected"
        );
    }

    #[test]
    fn session_cookie_with_tampered_expiry_rejected() {
        // Operator can't extend their own session by editing the exp
        // field — the signature covers exp.
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
        // Mint a cookie under password P1; spin up a new auth with
        // password P2 (simulating operator rotation); the old cookie
        // MUST NOT verify under the new key. This is the property that
        // makes password rotation auto-revoke every live session.
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
        // Cookie payload binds (exp, user); changing the configured
        // admin user invalidates pre-existing cookies.
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
        // No dot separator
        assert!(!auth.verify_session("nodothere", 1_700_000_000));
        // Non-numeric expiry
        assert!(!auth.verify_session("notanumber.SIGNATURE", 1_700_000_000));
        // Non-b64 signature
        assert!(!auth.verify_session("1700000100.!!!notb64!!!", 1_700_000_000));
        // Empty
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
        // Defensive: ensure we did NOT accidentally include `Secure`
        // (LAN-only deployment ships over plain HTTP — `Secure` would
        // silently drop the cookie). When TLS exposure lands the
        // contract changes and this assertion should be inverted.
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
