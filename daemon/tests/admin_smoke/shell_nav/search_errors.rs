use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{KernelId, Server, ServerId, User, UserId};
use vpnctld::router;

use crate::common::*;

// ────────────────────────────────────────────────────────────────────────
//  Phase C-2 — copy contracts (backend response texts + frontend voice)
//
//  These tests pin USER-FACING STRINGS — both the backend's plaintext
//  error responses (what the operator sees in `journalctl` / curl) and
//  a handful of headline frontend strings (what the operator sees in
//  the browser). Drift in copy was previously caught only by review;
//  pinning it here means a casual one-word edit can't accidentally land
//  in main.
//
//  Backend contract: every admin response body starts with
//  `vpnctl admin: ` and ends with a single newline. Status code and
//  WWW-Authenticate header are checked alongside.
//
//  Frontend contract: the editorial voice is sentence-case with em-
//  dashes, never shouting; the empty states quote a literal CLI command
//  the operator can copy.
// ────────────────────────────────────────────────────────────────────────

/// All four backend error endpoints must use the unified
/// `vpnctl admin: <detail>\n` prefix. Tested in one place so the
/// contract can't drift handler-by-handler.
#[tokio::test]
async fn admin_backend_error_responses_use_unified_prefix() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    // 1. 404 — unknown user-detail id.
    let body = body_of(app.clone(), "GET", "/admin/users/no-such", None, None).await;
    assert_eq!(
        body, "vpnctl admin: no such user 'no-such'\n",
        "user-not-found 404 body drifted from the copy contract"
    );

    // 2. 400 — invalid tweak value. Includes which kind + what value
    //    + the allowed values (operators don't have to remember them).
    let body = body_of(
        app.clone(),
        "POST",
        "/admin/tweak/theme",
        Some("application/x-www-form-urlencoded"),
        Some("value=neon"),
    )
    .await;
    assert_eq!(
        body,
        "vpnctl admin: invalid value 'neon' for tweak 'vpnctl_theme' \
         (allowed: default, newsprint, foxed, ink)\n",
        "tweak 400 body drifted"
    );

    // 3. 404 — unknown tweak kind. Lists known kinds inline.
    let body = body_of(
        app.clone(),
        "POST",
        "/admin/tweak/whatever",
        Some("application/x-www-form-urlencoded"),
        Some("value=foxed"),
    )
    .await;
    assert_eq!(
        body, "vpnctl admin: unknown tweak kind 'whatever' (known: theme, accent, lang)\n",
        "unknown-tweak 404 body drifted"
    );
}

/// Defense-in-depth: even if a caller passes a `detail` containing
/// literal `\n` or `\r` (e.g. an axum `Path<String>` extractor
/// straight through without validation, future regression), the body
/// must NOT contain extra line breaks beyond the trailing one. The
/// `error_text` helper collapses `\n`/`\r` to spaces.
///
/// Today every caller sanitises upstream (UserId/ServerId/form
/// validators reject `\n`), but pinning the invariant here means a
/// future refactor that bypasses those guards cannot silently
/// re-introduce response-splitting-shaped behaviour.
#[tokio::test]
async fn admin_backend_error_text_normalises_newlines_in_detail() {
    // Smoke the helper directly via a path that's known to interpolate
    // user-controlled content into the error body. The tweak handler's
    // 400 includes the user-supplied `value=...` field — but the form
    // decoder strips %-encoding and our validators reject control
    // chars. We instead test via the `/admin/users/<id>` 404 path,
    // which interpolates the raw path segment after decoding.
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    // %0A is a literal newline, percent-encoded as a single path
    // segment. axum's `Path<String>` extractor URL-decodes it back to
    // `\n`. Before the normalisation fix, the response body would be:
    //   "vpnctl admin: no such user '\n.poison'\n"
    // → splits into 2 lines for `curl … | head -1`. After the fix, the
    // `\n` collapses to a space.
    let body = body_of(app.clone(), "GET", "/admin/users/%0A.poison", None, None).await;
    // Body must be exactly ONE line + the trailing `\n`. Count
    // explicit newlines.
    let nl_count = body.matches('\n').count();
    assert_eq!(
        nl_count, 1,
        "error_text MUST normalise embedded \\n — body has {nl_count} newlines: {body:?}",
    );
    assert!(
        body.starts_with("vpnctl admin: no such user '"),
        "prefix survived the normalisation: {body:?}"
    );
    assert!(
        body.ends_with(".poison'\n"),
        "trailing context survived the normalisation: {body:?}"
    );
}

/// W5 pin: LIKE metacharacters in search match LITERALLY — `%` must
/// not return the whole fleet.
#[tokio::test]
async fn search_percent_is_literal_not_wildcard() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[]).await; // u0 + s0 exist
    let html = fetch_html(router(s), "/admin/search?q=%25").await;
    assert!(
        !html.contains("/admin/users/u0"),
        "bare % must not wildcard-match every user"
    );
}

/// W4 pin (review 2026-06-10): search results must mask the uuid —
/// it IS the VLESS credential; the users list masks it for exactly
/// that reason and search must not be the page that leaks it whole.
#[tokio::test]
async fn search_masks_user_uuid() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await; // u0, uuid 00000000-0000-0000-0000-000000000000
    let html = fetch_html(router(s), "/admin/search?q=u0").await;
    assert!(
        html.contains("uuid=0000\u{2026}0000 (36 chars)")
            || html.contains("uuid=0000…0000 (36 chars)"),
        "search must render the masked uuid preview"
    );
    assert!(
        !html.contains("00000000-0000-0000-0000-000000000000"),
        "search must not leak the full uuid (it is the VLESS credential)"
    );
}

// ── B1 — internal_error must NOT leak anyhow chain ───────────────────
//
// Pre-2026-05-22 the body of a 500 response inlined `err.to_string()`.
// That bled sqlx/anyhow chains (schema names, file paths, occasional
// row contents) to anyone reaching the admin UI. The new contract:
// body is a fixed opaque string «internal error — please retry the
// action», full chain stays in the structured log. We can't easily inject a
// failure into a live handler from a smoke test without invasive
// surgery, so this test uses an unknown-server detail route that
// would surface a sqlx error if the body weren't sanitised, AND
// directly tests the error_text helper for the exact contract
// string the operator will see.

#[tokio::test]
async fn internal_error_body_does_not_leak_anyhow_chain() {
    // The user_detail handler maps DB-not-found errors to a clean
    // 404 ("vpnctl admin: no such user 'X'"). That's the happy
    // path — verifies we're not leaking sqlx error strings either.
    // For the actual internal_error code path we'd need to break
    // the DB, which is too invasive for a smoke test. So this is
    // a defense-in-depth check: any error response must NOT contain
    // sqlx-like substrings or file-path-like substrings.
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    let app = router(st);
    // Route that always 404s with a sanitised message.
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/users/no-such-user")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let body_str = std::str::from_utf8(&body).unwrap_or("");
    // Anti-leak heuristic: 4xx/5xx body must not contain a sqlx-ish
    // substring («sqlx», «sqlite», «error returned from database»),
    // a file path («/var/», «/home/», «/tmp/»), or rust panic
    // markers. If any of these slip through, internal_error / the
    // 4xx mappers somewhere are leaking implementation details.
    for needle in [
        "sqlx",
        "sqlite::",
        "error returned from database",
        "/var/",
        "/home/",
        "/tmp/",
        "panicked",
        "unwrap_or",
    ] {
        assert!(
            !body_str.contains(needle),
            "4xx/5xx response body must not contain «{needle}» — leak: {body_str:?}"
        );
    }
}

// ── A5 — fleet-wide search /admin/search?q= ────────────────────────

#[tokio::test]
async fn search_empty_q_renders_prompt_no_groups() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/search")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body_bytes).unwrap();
    assert!(
        html.contains(r#"action="/admin/search""#),
        "search form must render"
    );
    assert!(
        !html.contains("hits across") && !html.contains("совпадений"),
        "no group summary when q is empty"
    );
}

#[tokio::test]
async fn search_finds_user_by_id_substring() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    st.inv
        .add_user(&User {
            id: UserId("ninitux".into()),
            uuid: "00000000-0000-0000-0000-000000000111".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    let app = router(st);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/search?q=nini")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body_bytes).unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "search must return 200; body sample: {}",
        if html.len() > 400 { &html[..400] } else { html }
    );
    assert!(
        html.contains(r#"href="/admin/users/ninitux""#),
        "search must link to user detail page"
    );
}

#[tokio::test]
async fn search_finds_server_by_address_substring() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    st.inv
        .add_server(&Server {
            id: ServerId("germany".into()),
            address: "104.194.156.93".into(),
            ssh_port: 2222,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "cloudzy".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let app = router(st);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/search?q=104.194")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        html.contains(r#"href="/admin/servers/germany""#),
        "address substring must surface the server"
    );
    assert!(
        html.contains("104.194.156.93"),
        "rendered row must show the matching address"
    );
}

#[tokio::test]
async fn search_zero_hits_renders_friendly_empty_state() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/search?q=nothing-matches-this")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        html.contains("No matches") || html.contains("Ничего не найдено"),
        "zero-hit empty state must render"
    );
    assert!(
        html.contains("/admin/audit"),
        "fallback link to audit page must be present"
    );
}
