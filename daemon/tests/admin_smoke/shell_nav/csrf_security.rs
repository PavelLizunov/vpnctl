use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::UserId;
use vpnctld::router;

use crate::common::*;

/// Anti-fingerprint regression (caught by pre-monitoring vuln scan
/// 2026-05-20): the auth / CSRF / security-headers middleware was
/// applied via `.layer()` instead of `.route_layer()`, which in
/// axum's contract wraps the router's default 404 fallback too. Any
/// unrelated path on the daemon (e.g. `/etc/passwd`, `/`, `/.env`,
/// `/wp-login.php`) returned `401 WWW-Authenticate: Basic realm=
/// "vpnctl admin"` for GETs and `403 vpnctl admin: csrf …` for
/// POSTs, plus the admin-only CSP / X-Frame-Options / Permissions-
/// Policy headers on EVERY 404 — all distinctive backend
/// fingerprints. Fix swapped `.layer` → `.route_layer` so the
/// middleware applies only to matched admin routes.
///
/// This test pins the no-leak invariant. Note: the test runs
/// without `VPNCTLD_ADMIN_PASSWORD` set, so the auth layer is
/// skipped entirely — what we're really pinning here is that
/// CSRF + security-headers ALSO use `route_layer` (the only ones
/// that fire without the env var). The auth-layer no-leak is
/// covered by the live-verify in the same commit.
#[tokio::test]
async fn admin_unmatched_paths_do_not_leak_admin_fingerprint() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    for path in [
        "/etc/passwd",
        "/",
        "/foo",
        "/.env",
        "/wp-login.php",
        "/api/v2/something",
    ] {
        // GET: must not carry the admin-tree CSP / X-Frame-Options /
        // Permissions-Policy headers — those are distinctive.
        let req = Request::builder().uri(path).body(Body::empty()).unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let headers = resp.headers().clone();
        assert!(
            headers.get("content-security-policy").is_none(),
            "GET {path} leaks CSP header (admin fingerprint)"
        );
        assert!(
            headers.get("x-frame-options").is_none(),
            "GET {path} leaks X-Frame-Options (admin fingerprint)"
        );
        assert!(
            headers.get("permissions-policy").is_none(),
            "GET {path} leaks Permissions-Policy (admin fingerprint)"
        );
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let s = String::from_utf8_lossy(&body);
        assert!(
            !s.contains("vpnctl admin"),
            "GET {path} leaks 'vpnctl admin' in body: {s}"
        );

        // POST: same — CSRF middleware should NOT fire on unmatched
        // paths. Pre-fix, POST returned 403 with body
        // "vpnctl admin: csrf — Origin (or Referer) must match Host"
        // + dump of Host/Origin/Referer headers.
        let req = Request::builder()
            .uri(path)
            .method("POST")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from("x=1"))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let s = String::from_utf8_lossy(&body);
        assert!(
            !s.contains("vpnctl admin"),
            "POST {path} leaks 'vpnctl admin' in body: {s}"
        );
        assert!(
            !s.contains("csrf"),
            "POST {path} leaks CSRF copy in body: {s}"
        );
    }

    // Positive control: an actual admin path STILL produces admin-shaped
    // responses (the fix must not break the legitimate path). Without
    // auth env var, /admin renders the page directly (200 + CSP header).
    let req = Request::builder()
        .uri("/admin")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers().get("content-security-policy").is_some(),
        "admin pages MUST still carry CSP — security-headers layer broken"
    );
}

/// Security audit 2026-05-18 — admin responses must carry CSP +
/// X-Content-Type-Options + X-Frame-Options + Referrer-Policy +
/// Permissions-Policy headers. Defense-in-depth against XSS,
/// MIME-sniff, clickjacking, referrer leakage. CSP must NOT have
/// `unsafe-inline` for script-src (style-src does, intentional).
#[tokio::test]
async fn admin_responses_carry_security_headers() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let headers = resp.headers();
    // CSP
    let csp = headers
        .get("content-security-policy")
        .expect("CSP must be set on /admin/* responses")
        .to_str()
        .unwrap();
    assert!(
        csp.contains("default-src 'self'"),
        "CSP must default to self"
    );
    assert!(
        csp.contains("script-src 'self'") && !csp.contains("script-src 'self' 'unsafe-inline'"),
        "script-src MUST NOT include 'unsafe-inline' — XSS defense: {csp}"
    );
    assert!(
        csp.contains("frame-ancestors 'none'"),
        "frame-ancestors must be 'none' — clickjacking defense: {csp}"
    );
    // Companion headers
    assert_eq!(
        headers
            .get("x-content-type-options")
            .map(|v| v.to_str().unwrap()),
        Some("nosniff")
    );
    assert_eq!(
        headers.get("x-frame-options").map(|v| v.to_str().unwrap()),
        Some("DENY")
    );
    assert_eq!(
        headers.get("referrer-policy").map(|v| v.to_str().unwrap()),
        // `same-origin` (NOT `no-referrer`): the strict version
        // bricked the CSRF middleware in prod 2026-05-19 by
        // stripping Referer from same-origin POSTs that browsers
        // send with `Origin: null`. `same-origin` keeps the no-
        // external-leakage guarantee while preserving the
        // Origin-→-Referer fallback inside our own admin tree.
        Some("same-origin")
    );
    let perm = headers
        .get("permissions-policy")
        .expect("Permissions-Policy must be set")
        .to_str()
        .unwrap();
    assert!(
        perm.contains("camera=()")
            && perm.contains("microphone=()")
            && perm.contains("geolocation=()"),
        "Permissions-Policy must block sensor / device APIs: {perm}"
    );
}

/// Post-2026-05-18 rule (Pavel: «не должен просить меня сделать
/// что-то вручную на серверах»). No 4xx/5xx response body, no
/// admin HTML deck-copy, and no UI hint may instruct the operator
/// to manually `ssh root@…` + edit `authorized_keys`. Daemon
/// either auto-handles, surfaces a button, or — in the genuinely
/// impossible case (banned, can't reach) — explicitly says «use
/// hoster console».
///
/// This test exercises the THREE known operator-facing output
/// paths that historically held those instructions:
///   1. `classify_ssh_failure` (called by test-send 502)
///   2. `/admin/settings` Deploy SSH key section (rendered HTML)
///   3. `server.fail2ban.banned_self` alert payload
/// and asserts none contain the forbidden phrasing. Future regressions
/// (a new error message or alert payload that asks for manual SSH)
/// would have to add that pattern to one of these surfaces; this
/// test would catch it.
#[tokio::test]
async fn no_operator_facing_output_asks_for_manual_ssh_edit() {
    use vpnctld::alert_sink::classify_ssh_failure;

    // (1) classify_ssh_failure permission-denied branch — the most
    // common SSH failure mode operator hits. MUST surface the «push
    // deploy key» button, MUST NOT include the literal
    // `echo … >> ~/.ssh/authorized_keys` command.
    let msg = classify_ssh_failure(
        "ssh transport error: ssh root@1.2.3.4:22 exit=Some(255) \
         stderr=root@1.2.3.4: Permission denied (publickey,password).",
    );
    assert!(
        !msg.contains("echo '<paste>'") && !msg.contains(">> ~/.ssh/authorized_keys"),
        "classify_ssh_failure MUST NOT instruct manual authorized_keys edit: {msg}"
    );
    assert!(
        msg.contains("push deploy key"),
        "classify_ssh_failure SHOULD point at the «push deploy key» button: {msg}"
    );

    // (2) /admin/settings rendered HTML. In test env the daemon's
    // deploy pubkey file at /var/lib/vpnctl/.ssh/id_ed25519.pub
    // doesn't exist, so the @match hits the Err arm («Public key
    // file unreadable») — the «push deploy key» button copy lives
    // in the Ok arm. We can't easily inject a fake pubkey because
    // the path is a `const &str`. So we assert the NEGATIVE (no
    // forbidden pattern), which holds in BOTH arms.
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/settings/system")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body_bytes).unwrap();
    assert!(
        !html.contains("echo '<paste>' >> ~/.ssh/authorized_keys"),
        "Deploy SSH key section MUST NOT contain the manual echo …>> instruction"
    );
    // (3) /admin/alerts deck — neither the empty-state nor the
    // alerts-table sections should embed an «ssh into the node»
    // hint. The fail2ban banned-self ALERT PAYLOAD (in node_probe_
    // poller.rs) was rewritten to point at hoster console — not
    // ask for SSH; we don't render it from `/admin/alerts` deck
    // directly, but we DO assert the alerts page's static copy
    // doesn't carry the old manual-ssh phrasing.
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/alerts")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body_bytes).unwrap();
    assert!(
        !html.contains("ssh into the node out-of-band"),
        "alerts page must NOT ask operator to ssh into the node"
    );
}

// ────────────────────────────────────────────────────────────────────────
//  Phase Hardening — CSRF middleware (handlers/csrf.rs)
//
//  Caught by retroactive review-agent (review #2) AND security-review
//  (security #1) on 2026-05-14: the regenerate handler had no
//  Origin/Referer check, so any cross-origin form-POST visited by an
//  authenticated operator's browser would silently rotate a victim
//  user's sub_token.
//
//  The middleware now sits OUTSIDE basic-auth on /admin/* and rejects
//  state-mutating requests whose Origin (or Referer fallback) does not
//  match the Host header.
// ────────────────────────────────────────────────────────────────────────

/// State-mutating POST WITHOUT an Origin (and WITHOUT a Referer) is
/// the classic "form auto-submitted from evil.example.com" scenario —
/// some browsers omit Origin on form-POST. Must 403 with the unified
/// `vpnctl admin:` error prefix.
#[tokio::test]
async fn admin_csrf_post_without_origin_is_403() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    let resp = app
        .oneshot(
            // Deliberately NO Host, NO Origin, NO Referer.
            Request::builder()
                .method("POST")
                .uri("/admin/tweak/theme")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("value=foxed"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "POST without Origin must be rejected by CSRF middleware"
    );
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let s = std::str::from_utf8(&body).unwrap();
    assert!(
        s.starts_with("vpnctl admin: csrf"),
        "CSRF reject body must use unified prefix, got: {s:?}"
    );
}

/// State-mutating POST WITH an Origin pointing at a different host
/// than the request's Host header — the cross-origin attack surface.
/// Must 403, must NOT mutate state.
#[tokio::test]
async fn admin_csrf_post_with_mismatched_origin_is_403() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await;
    // Snapshot the token; if CSRF protection works the regenerate
    // request below MUST NOT change it.
    let before = s
        .inv
        .get_user(&UserId("u0".into()))
        .await
        .unwrap()
        .unwrap()
        .sub_token
        .unwrap();

    let app = router(s.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/users/u0/sub-token/regenerate")
                .header("host", "test.example")
                .header("origin", "http://evil.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "cross-origin POST must be rejected by CSRF middleware"
    );
    let after = s
        .inv
        .get_user(&UserId("u0".into()))
        .await
        .unwrap()
        .unwrap()
        .sub_token
        .unwrap();
    assert_eq!(
        before, after,
        "sub_token must be unchanged after CSRF-rejected POST"
    );
}

/// GET requests pass through the CSRF middleware unchanged — they are
/// not state-mutating per RFC 9110 and the admin tree's GET handlers
/// are read-only. A test rig that hits /admin/ without ANY headers
/// should still see the page.
#[tokio::test]
async fn admin_csrf_get_passes_through_without_origin() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "GET on /admin/ must pass through CSRF middleware regardless of Origin"
    );
}

/// Falling back from Origin to Referer: when the browser omits Origin
/// (older clients on simple form-POSTs) but sends a Referer pointing
/// at the same host, the middleware must accept the request.
#[tokio::test]
async fn admin_csrf_referer_fallback_when_origin_absent() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/tweak/theme")
                .header("host", "test.example")
                // NO Origin — Referer fallback should kick in.
                .header("referer", "http://test.example/admin/")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("value=foxed"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        resp.status() == StatusCode::SEE_OTHER || resp.status() == StatusCode::TEMPORARY_REDIRECT,
        "same-origin Referer (no Origin) must pass CSRF, got {:?}",
        resp.status()
    );
}

/// Regression for the 2026-05-19 broken-admin bug: when the browser
/// sends `Origin: null` (opaque-origin context — sandboxed iframe,
/// privacy extension, file:// open), the Referer fallback MUST work
/// because that's the only remaining signal. Pre-fix:
/// Referrer-Policy was `no-referrer` which stripped Referer from
/// every same-origin POST → CSRF middleware bricked admin UI.
#[tokio::test]
async fn admin_csrf_referer_fallback_when_origin_is_literal_null() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/tweak/theme")
                .header("host", "test.example")
                // `Origin: null` is what privacy-mode browsers actually
                // send for opaque-origin documents (per the Fetch spec).
                .header("origin", "null")
                .header("referer", "http://test.example/admin/users")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("value=foxed"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        resp.status() == StatusCode::SEE_OTHER || resp.status() == StatusCode::TEMPORARY_REDIRECT,
        "`Origin: null` + same-origin Referer must pass CSRF \
         (this exact scenario bricked prod 2026-05-19), got {:?}",
        resp.status()
    );
}

/// Regression for the 2026-05-19 Pavel-debugged-via-journalctl pain:
/// when CSRF rejects, the response body MUST include the actual
/// Host + Origin + Referer values + a likely-cause hint, so the
/// operator can self-diagnose without shell access (per CLAUDE.md
/// Operator-action policy).
#[tokio::test]
async fn admin_csrf_403_body_shows_host_origin_referer_and_cause() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/tweak/theme")
                .header("host", "real.example")
                // `Origin: null` (opaque origin), no Referer — exact
                // shape Pavel saw in the prod logs 2026-05-19.
                .header("origin", "null")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("value=foxed"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = std::str::from_utf8(&body).unwrap();

    // Body lists the three header values verbatim — operator can
    // see exactly what mismatched.
    assert!(
        text.contains("Host:    real.example"),
        "Host missing from body: {text}"
    );
    assert!(
        text.contains("Origin:  null"),
        "Origin (literal `null`) missing: {text}"
    );
    assert!(
        text.contains("Referer: (absent)"),
        "Referer state missing: {text}"
    );
    // Likely-cause hint for the `Origin: null` shape — points operator
    // at the opaque-origin diagnosis instead of leaving them guessing.
    assert!(
        text.contains("opaque origin"),
        "must explain the `Origin: null` case in plain English: {text}"
    );
}

/// Regression: the 2026-05-18 security audit shipped
/// `Referrer-Policy: no-referrer` which stripped Referer from every
/// outbound request — including our own same-origin form POSTs. Pinned
/// at `same-origin` so the CSRF middleware's Referer fallback survives.
/// A regression to `no-referrer` would re-brick admin UI for any
/// browser sending `Origin: null`.
#[tokio::test]
async fn admin_referrer_policy_header_is_same_origin_not_no_referrer() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let policy = resp
        .headers()
        .get("referrer-policy")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(
        policy, "same-origin",
        "Referrer-Policy must be `same-origin` (NOT `no-referrer` — that bricks the CSRF middleware)"
    );
}

#[tokio::test]
async fn admin_audit_timeline_summary_never_leaks_secret_fields() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    // Simulate a payload that contains BOTH whitelisted keys AND
    // hypothetical secret fields the summary must NOT render.
    s.inv
        .audit(
            "admin",
            "user.add",
            Some("alice"),
            Some(&serde_json::json!({
                "uuid": "aaa-bbb",
                "wg_keypair_provenance": "server-generated",
                // Hypothetical leak vectors — MUST NOT appear in summary
                "tuic_password": "PW_SECRET_LEAK_CHECK",
                "wireguard_private": "PRIV_SECRET_LEAK_CHECK",
                "sub_token": "TOKEN_SECRET_LEAK_CHECK",
            })),
        )
        .await
        .unwrap();
    let app = router(s);
    let html = fetch_html(app, "/admin/audit").await;
    // Whitelisted key visible
    assert!(html.contains("wg_keypair_provenance=server-generated"));
    // Secrets MUST NOT leak via the summary rendering path
    for leak in [
        "PW_SECRET_LEAK_CHECK",
        "PRIV_SECRET_LEAK_CHECK",
        "TOKEN_SECRET_LEAK_CHECK",
    ] {
        assert!(
            !html.contains(leak),
            "audit summary leaked {leak} into HTML"
        );
    }
}

// ── B2 — operator-facing copy must not instruct terminal use ─────────
//
// Operator-action policy: the admin UI is web-only, so no rendered page
// may tell the operator to run a shell command. Every needle below is a
// command shape that used to appear in error bodies, tooltips, SSE
// payloads; each was replaced with a web action or neutral guidance.
// Disaster recovery is deliberately excluded: after the daemon host is
// lost there is no Web UI, so its runbook must retain exact commands.
#[tokio::test]
async fn admin_pages_contain_no_shell_command_instructions() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    // Seed a server + granted user so the detail pages render their
    // guidance copy (not just the empty state).
    seed(&st.inv, 1, 1, &[(0, 0)]).await;

    // The everyday operator surfaces.
    let pages = [
        "/admin/",
        "/admin/servers",
        "/admin/servers/s0",
        "/admin/servers/s0/protocols",
        "/admin/users",
        "/admin/users/u0",
        "/admin/monitoring",
        "/admin/activity",
        "/admin/settings/appearance",
        "/admin/settings/notifications",
        "/admin/settings/system",
        "/admin/alerts",
    ];
    let needles = [
        "journalctl",
        "systemctl",
        "ssh root@",
        "ls -la",
        "age -d",
        "vpnctl bootstrap",
        "vpnctl deploy",
        "vpnctl geoip-update",
        "vpnctl grant",
        "vpnctl restore",
        "vpnctl server add",
        "vpnctl user",
        "--gen-wireguard",
        "see vpnctld logs",
    ];
    let app = router(st);
    for path in pages {
        let html = fetch_html(app.clone(), path).await;
        for needle in needles {
            assert!(
                !html.contains(needle),
                "rendered page {path} must not contain shell-command instruction «{needle}» — operator copy is web-only"
            );
        }
    }

    // Disaster recovery is the only terminal exception because the Web UI
    // may be gone. Keep the rest of the Backups page under the same guard.
    let backups = fetch_html(app, "/admin/settings/backups").await;
    for command in [
        "age -d -i /path/to/vpnctl-backup-key.age",
        "vpnctl restore /path/to/inv.db",
        "systemctl restart vpnctld",
    ] {
        assert_eq!(
            backups.matches(command).count(),
            1,
            "the disaster-recovery runbook must contain exactly one {command:?}"
        );
    }
    let backups_without_recovery_commands = backups
        .replace("age -d -i /path/to/vpnctl-backup-key.age", "")
        .replace("vpnctl restore /path/to/inv.db", "")
        .replace("systemctl restart vpnctld", "");
    for needle in needles {
        assert!(
            !backups_without_recovery_commands.contains(needle),
            "settings/backups contains an unexpected shell instruction {needle:?}"
        );
    }
}
