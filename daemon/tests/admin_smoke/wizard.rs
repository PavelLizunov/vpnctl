use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctld::router;

use super::common::*;

#[tokio::test]
async fn admin_wizard_new_renders_form_with_required_fields() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let html = fetch_html(app, "/admin/servers/new").await;
    // Form posts back to the same URL.
    assert!(
        html.contains(r#"action="/admin/servers/new""#),
        "form action missing"
    );
    // Both fields present, both required.
    assert!(html.contains(r#"name="address""#), "address field missing");
    assert!(
        html.contains(r#"name="root_password""#),
        "root_password field missing"
    );
    // Password input must be type=password (no echo to the page).
    assert!(
        html.contains(r#"id="root_password" name="root_password" type="password""#),
        "root_password must be type=password"
    );
    // Headline + step indicator (copy contract). «of 2» — the wizard
    // is a 2-step flow; the old «of 3» promised a step that never
    // existed (review 2026-06-04).
    assert!(
        html.contains("Add server · step 1 of 2"),
        "step indicator missing"
    );
}

#[tokio::test]
async fn admin_wizard_submit_rejects_empty_address_400() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/new")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("address=&root_password=hunter2"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(
        text.starts_with("vpnctl admin: invalid address"),
        "expected canonical 'vpnctl admin: invalid address …' body, got {text:?}"
    );
}

#[tokio::test]
async fn admin_wizard_submit_rejects_shell_injection_in_address() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/new")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            // %3B is `;`, %20 is space — these are exactly what a
            // browser form would send for `; rm -rf /`.
            .body(Body::from(
                "address=10.0.0.1%3B%20rm%20-rf%20%2F&root_password=hunter2",
            ))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "shell metacharacters in address must be rejected"
    );
}

#[tokio::test]
async fn admin_wizard_submit_rejects_empty_password_400() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/new")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("address=192.0.2.1&root_password="))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(
        text.starts_with("vpnctl admin: invalid root password"),
        "expected canonical 'vpnctl admin: invalid root password …' body, got {text:?}"
    );
}

/// Happy path: valid input → 303 to step-2 + HttpOnly session cookie.
/// The cookie's Path scope MUST be limited to the wizard so the
/// session id never rides along on /admin/users/* etc.
#[tokio::test]
async fn admin_wizard_submit_happy_path_sets_scoped_cookie_and_redirects() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    assert_eq!(s.wizard.len(), 0, "store starts empty");
    let app = router(s.clone());

    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/new")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("address=198.51.100.42&root_password=hunter2"))
            .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        resp.headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(""),
        "/admin/servers/new/step-2",
        "redirect must go to step-2"
    );
    let cookie = resp
        .headers()
        .get("set-cookie")
        .expect("set-cookie missing")
        .to_str()
        .unwrap();
    assert!(
        cookie.starts_with("vpnctl_wizard="),
        "wrong cookie name: {cookie}"
    );
    // Security flags: path-scope, HttpOnly, SameSite=Strict.
    assert!(
        cookie.contains("Path=/admin/servers/new"),
        "cookie path must be wizard-scoped, got: {cookie}"
    );
    assert!(
        cookie.contains("HttpOnly"),
        "cookie must be HttpOnly, got: {cookie}"
    );
    assert!(
        cookie.contains("SameSite=Strict"),
        "cookie must be SameSite=Strict, got: {cookie}"
    );
    // Server-side state has the row.
    assert_eq!(s.wizard.len(), 1, "session must be stashed server-side");
}

#[tokio::test]
async fn admin_wizard_step2_renders_address_with_valid_session() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let session_id = s.wizard.insert(
        "vpn-de1.example.org".into(),
        "r00tpwXYZ-distinct".into(),
        22,
    );
    let app = router(s);

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/servers/new/step-2")
                .header("cookie", format!("vpnctl_wizard={session_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    // Address echoed back; password MUST NOT be in the page.
    assert!(
        html.contains("vpn-de1.example.org"),
        "address must echo on step-2"
    );
    assert!(
        !html.contains("r00tpwXYZ-distinct"),
        "root password must NEVER appear in step-2 HTML"
    );
    // Step indicator («of 2» — see step-1's copy-contract note).
    assert!(
        html.contains("Add server · step 2 of 2"),
        "step indicator missing on step-2"
    );
}

#[tokio::test]
async fn admin_wizard_step2_rejects_missing_session_400() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/servers/new/step-2")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "step-2 must 400 without a session"
    );
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(
        text.starts_with("vpnctl admin: wizard session expired"),
        "canonical missing-session body required, got {text:?}"
    );
}

#[tokio::test]
async fn admin_wizard_step2_rejects_bogus_cookie_400() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/servers/new/step-2")
                .header("cookie", "vpnctl_wizard=not-a-real-session-id")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "unknown session ids must 400 (no session enumeration leak)"
    );
}

// ───────────────────────────────────────────────────────────────────
// Phase E sub-iter 4b — wizard SSE bootstrap.
//
// The step-2 page must:
//   * render an inline EventSource pointed at the SSE source,
//   * have a log pane + status line populated by the client JS,
//   * NEVER echo the operator's root password into the HTML,
//   * link a fallback "start over" anchor.
//
// The SSE endpoint must:
//   * reject missing/bogus session with 400 + canonical body,
//   * single-shot consume the session (re-attach 400s),
//   * advertise `Content-Type: text/event-stream` (browsers refuse
//     to treat the response as an EventSource otherwise),
//   * never appear in the CSRF/auth blast radius without protection
//     (it's a GET — CSRF passes through, basic-auth wraps it).
// ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn admin_wizard_step2_page_attaches_autostart_sse_to_endpoint() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let session_id = s.wizard.insert("198.51.100.42".into(), "pw".into(), 22);
    let app = router(s);

    let html = fetch_html_with_cookie(
        app,
        "/admin/servers/new/step-2",
        &format!("vpnctl_wizard={session_id}"),
    )
    .await;

    // v2 6b — CSP-safe: admin.js opens the EventSource from the
    // data-sse-autostart attribute (the old inline <script> was blocked
    // by script-src 'self').
    assert!(
        html.contains(r#"data-sse-autostart="/admin/servers/new/step-2/sse""#),
        "step-2 log pane must carry the autostart SSE URL"
    );
    // The old inline EventSource block is gone (CSP-blocked); the
    // only <script> is the external admin.js the shell always ships.
    assert!(
        !html.contains("new EventSource("),
        "step-2 must not ship an inline EventSource script (CSP-blocked)"
    );
    assert!(
        html.contains("id=\"wizard-log\""),
        "step-2 must have a log pane the SSE handlers append into"
    );
    // v2 6b — the live steps checklist replaced the status <div>;
    // admin.js maps each `step` event's phase to a row here.
    assert!(
        html.contains("id=\"wizard-steps\"") && html.contains("data-step-phase="),
        "step-2 must have the live steps checklist"
    );
    assert!(
        !html.contains(">pw<") && !html.contains("\"pw\""),
        "root password must NEVER appear in the step-2 page HTML"
    );
}

#[tokio::test]
async fn admin_wizard_sse_rejects_missing_session_400() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/servers/new/step-2/sse")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "SSE endpoint must 400 without a session cookie"
    );
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(
        text.starts_with("vpnctl admin: wizard session missing"),
        "canonical missing-session body required, got {text:?}"
    );
}

#[tokio::test]
async fn admin_wizard_sse_rejects_bogus_cookie_400() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/servers/new/step-2/sse")
                .header("cookie", "vpnctl_wizard=bogus")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "SSE endpoint must 400 on unknown session id"
    );
}

#[tokio::test]
async fn admin_wizard_sse_consumes_session_on_first_attach() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    // Address that's deliberately unroutable — the SSE handler will
    // start streaming events, the bootstrap's probe phase will fail
    // (RFC 5737 TEST-NET-1 doesn't route), but we only care here
    // that the session is GONE after the first attach.
    let session_id = s.wizard.insert("198.51.100.1".into(), "pw".into(), 22);
    assert_eq!(s.wizard.len(), 1, "precondition: session present");
    let app = router(s.clone());

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/servers/new/step-2/sse")
                .header("cookie", format!("vpnctl_wizard={session_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "first SSE attach with valid session must succeed"
    );
    // The response body is an open SSE stream; we don't have to drain
    // it — dropping the response closes the receiver. Session must be
    // gone immediately on attach (single-shot semantics).
    assert_eq!(
        s.wizard.len(),
        0,
        "SSE attach must consume the wizard session"
    );
    drop(resp);
}

#[tokio::test]
async fn admin_wizard_sse_advertises_event_stream_content_type() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let session_id = s.wizard.insert("198.51.100.1".into(), "pw".into(), 22);
    let app = router(s);

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/servers/new/step-2/sse")
                .header("cookie", format!("vpnctl_wizard={session_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.starts_with("text/event-stream"),
        "EventSource requires Content-Type: text/event-stream, got {ct:?}"
    );
}

#[tokio::test]
async fn admin_wizard_submit_carries_ssh_port_2222_into_session() {
    // Review-agent (2026-05-17, important-4): Cloudzy hosts on
    // 2222, the wizard's ssh_port input field must round-trip.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let app = router(s.clone());
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/new")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from(
                "address=104.194.156.93&root_password=pw&ssh_port=2222",
            ))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    // Session must have port 2222 stashed.
    let cookie = resp
        .headers()
        .get("set-cookie")
        .expect("set-cookie missing")
        .to_str()
        .unwrap();
    let session_id = cookie
        .split(';')
        .next()
        .unwrap()
        .trim_start_matches("vpnctl_wizard=");
    let session = s
        .wizard
        .get(session_id)
        .expect("session must be retrievable by id");
    assert_eq!(session.ssh_port, 2222, "ssh_port must round-trip from form");
}

#[tokio::test]
async fn admin_wizard_submit_blank_ssh_port_defaults_to_22() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let app = router(s.clone());
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/new")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("address=10.0.0.1&root_password=pw&ssh_port="))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let cookie = resp
        .headers()
        .get("set-cookie")
        .expect("set-cookie missing")
        .to_str()
        .unwrap();
    let session_id = cookie
        .split(';')
        .next()
        .unwrap()
        .trim_start_matches("vpnctl_wizard=");
    let session = s.wizard.get(session_id).unwrap();
    assert_eq!(session.ssh_port, 22, "blank ssh_port must default to 22");
}

#[tokio::test]
async fn admin_wizard_submit_rejects_bogus_ssh_port_400() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/new")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from(
                "address=10.0.0.1&root_password=pw&ssh_port=99999",
            ))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(
        text.starts_with("vpnctl admin: invalid ssh_port"),
        "canonical body required, got {text:?}"
    );
}

#[tokio::test]
async fn admin_wizard_step1_form_has_ssh_port_field() {
    // Front-end: ensure the operator sees the (optional) ssh_port
    // field on step 1 — otherwise they'd never know they can change
    // it for Cloudzy / non-22 hosts.
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let html = fetch_html(app, "/admin/servers/new").await;
    assert!(
        html.contains("name=\"ssh_port\""),
        "wizard step-1 must expose an ssh_port input field"
    );
    assert!(
        html.contains("optional, default 22"),
        "ssh_port label must clarify it's optional with default 22"
    );
}

#[tokio::test]
async fn admin_wizard_sse_collision_appends_numeric_suffix() {
    // Operator runs the wizard for the same IP twice. The second
    // attach must derive a non-colliding server id rather than
    // 400-ing — that's the difference between an operator hitting
    // back-button + retry (good UX) vs. having to invent a new
    // address (bad UX).
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    // Pre-seed a server with the id that would be derived from the
    // wizard's address.
    let server = vpnctl_core::Server {
        id: vpnctl_core::ServerId("198.51.100.1".into()),
        address: "198.51.100.1".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![vpnctl_core::KernelId("sing-box".into())],
        enabled_protocols: vec![],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    };
    s.inv.add_server(&server).await.unwrap();

    let session_id = s.wizard.insert("198.51.100.1".into(), "pw".into(), 22);
    let app = router(s);
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/servers/new/step-2/sse")
                .header("cookie", format!("vpnctl_wizard={session_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // The SSE attach itself succeeds (200) — the collision is handled
    // by id suffixing inside the handler. The bootstrap pipeline will
    // then fail at the probe phase (no real server) but that's fine
    // for this test; we only care that the attach didn't 409.
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "repeat wizard for same address must suffix id, not 409"
    );
    drop(resp);
}

/// HANDOFF §6 #2 — the Phase-E wizard (step 1) must reject a duplicate
/// address up-front, before the operator commits to a full bootstrap.
#[tokio::test]
async fn admin_wizard_step1_rejects_duplicate_address() {
    use vpnctl_core::{KernelId, Server, ServerId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("us".into()),
            address: "130.94.19.7".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let app = router(s);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/new")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from(
                "address=130.94.19.7&root_password=hunter2&ssh_port=22",
            ))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert!(
        std::str::from_utf8(&body)
            .unwrap()
            .contains("already registered to server 'us'"),
        "wizard step-1 must reject a duplicate address naming the clash"
    );
}
