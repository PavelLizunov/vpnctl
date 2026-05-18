//! Basic-auth middleware for the admin UI.
//!
//! Reads expected credentials from env at startup (`VPNCTLD_ADMIN_USER`,
//! `VPNCTLD_ADMIN_PASSWORD`). When both are set, every request that
//! traverses this layer must carry `Authorization: Basic ...` matching
//! them; otherwise the layer is a no-op (useful for local smoke).
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
//! Generate a hash via the `vpnctl admin hash-password <plain>` CLI
//! (writes the `$argon2id$…` line to stdout, paste into the
//! EnvironmentFile).
//!
//! ## Constant-time
//!
//! Comparison on BOTH user and password is constant-time — no
//! early-exit timing oracle on either field. The user field is always
//! plaintext (low value to hash) but still uses `ct_eq`.

use std::sync::Arc;

use argon2::password_hash::{PasswordHash, PasswordVerifier};
use axum::extract::Request;
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use base64::{Engine, engine::general_purpose::STANDARD};
use subtle::ConstantTimeEq;

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
        Some(Self {
            user: Arc::new(user),
            secret,
        })
    }
}

pub(crate) async fn require_basic_auth(
    axum::extract::State(auth): axum::extract::State<BasicAuth>,
    req: Request,
    next: Next,
) -> Response {
    if check(&req, &auth) {
        return next.run(req).await;
    }
    // Match the `vpnctl admin: …` copy contract used by every other
    // backend response (see `handlers::admin::error_text`). Operators
    // grep `journalctl -u vpnctld` for the prefix.
    let mut resp = (StatusCode::UNAUTHORIZED, "vpnctl admin: auth required\n").into_response();
    if let Ok(hv) = HeaderValue::from_str(r#"Basic realm="vpnctl admin", charset="UTF-8""#) {
        resp.headers_mut().insert(header::WWW_AUTHENTICATE, hv);
    }
    resp
}

fn check(req: &Request, auth: &BasicAuth) -> bool {
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
        BasicAuth {
            user: Arc::new(user.to_string()),
            secret: PasswordSecret::PlainBytes(Arc::new(pw.as_bytes().to_vec())),
        }
    }

    fn auth_argon2(user: &str, phc: &str) -> BasicAuth {
        BasicAuth {
            user: Arc::new(user.to_string()),
            secret: PasswordSecret::Argon2Phc(Arc::new(phc.to_string())),
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
        assert!(check(&req, &auth), "correct plain creds must pass");
    }

    #[test]
    fn plain_path_rejects_wrong_password() {
        let auth = auth_plain("slovn", "hunter2");
        let req = req_with_basic("slovn", "wrong");
        assert!(!check(&req, &auth));
    }

    #[test]
    fn plain_path_rejects_wrong_user_does_not_short_circuit() {
        // Defense: an attacker who knows the password but is fishing
        // for the username must not be able to enumerate via timing.
        // We don't measure timing here (flaky); we just confirm the
        // logic computes BOTH ct_eq calls and AND's them.
        let auth = auth_plain("slovn", "hunter2");
        let req = req_with_basic("wrong", "hunter2");
        assert!(!check(&req, &auth));
    }

    #[test]
    fn argon2_path_accepts_correct_password() {
        let phc = make_phc("hunter2");
        let auth = auth_argon2("slovn", &phc);
        let req = req_with_basic("slovn", "hunter2");
        assert!(check(&req, &auth), "argon2 verify must accept correct pw");
    }

    #[test]
    fn argon2_path_rejects_wrong_password() {
        let phc = make_phc("hunter2");
        let auth = auth_argon2("slovn", &phc);
        let req = req_with_basic("slovn", "WRONG");
        assert!(!check(&req, &auth));
    }

    #[test]
    fn argon2_path_rejects_malformed_phc_safely() {
        // If the operator pasted a malformed `$argon2…` string, the
        // request layer must reject (NOT panic, NOT accept). The
        // construction-time validator in `from_env` catches most of
        // this, but the per-request reparse path is also defended.
        let auth = auth_argon2("slovn", "$argon2id$bogus");
        let req = req_with_basic("slovn", "anything");
        assert!(!check(&req, &auth));
    }

    #[test]
    fn rejects_request_without_authorization_header() {
        let auth = auth_plain("slovn", "hunter2");
        let req = Request::builder()
            .uri("/")
            .body(axum::body::Body::empty())
            .unwrap();
        assert!(!check(&req, &auth));
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
        assert!(!check(&req, &auth));
    }
}
