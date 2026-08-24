use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{KernelId, Server, ServerId, UserId};
use vpnctld::router;

use super::common::*;

/// Servers screen must show the empty-state when the DB is empty,
/// pointing the operator at the web wizard (operator-action policy:
/// no terminal instructions in admin copy).
#[tokio::test]
async fn admin_servers_empty_state_points_at_wizard() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let html = fetch_html(app, "/admin/servers").await;

    assert!(html.contains("No servers yet"), "empty-state copy missing");
    assert!(
        html.contains("wizard"),
        "empty-state must point at the web wizard"
    );
    assert!(
        !html.contains("vpnctl bootstrap"),
        "empty-state must not instruct a CLI command"
    );
    // No <article class="ed-server"> when the list is empty.
    assert!(
        !html.contains(r#"class="ed-server""#),
        "server cards must not render on empty inventory"
    );
}

/// Populated servers screen must render exactly one ed-server card per
/// server, expose each server id and address, and mark the right user
/// counts (0 for ungranted, N for granted).
#[tokio::test]
async fn admin_servers_renders_one_card_per_server_with_user_counts() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    // s0 -> 2 users, s1 -> 1 user, s2 -> 0 users
    seed(&s.inv, 3, 2, &[(0, 0), (1, 0), (0, 1)]).await;

    let app = router(s);
    let html = fetch_html(app, "/admin/servers").await;

    // One row per server in the dense inventory table (densify 2a).
    assert!(
        html.contains(r#"<table class="ed-grid">"#),
        "servers list must render the dense inventory table"
    );
    assert_eq!(
        html.matches(r#"class="ed-grid__id""#).count(),
        3,
        "expected three server rows (one ed-grid__id link each)"
    );
    // Header shows total.
    assert!(
        html.contains("3 <em>servers</em>"),
        "page header should announce 3 servers"
    );
    // Each id renders.
    for id in ["s0", "s1", "s2"] {
        assert!(html.contains(id), "server id {id} missing from html");
    }
    // Each address renders (port suffix appended by render).
    for addr in ["10.0.0.0:22", "10.0.0.1:22", "10.0.0.2:22"] {
        assert!(html.contains(addr), "address {addr} missing");
    }
    // User counts: 2 users, 1 user, 0 users — singular vs plural.
    assert!(
        html.contains("<b>2</b> users"),
        "s0 should show 2 users granted access"
    );
    assert!(
        html.contains("<b>1</b> user"),
        "s1 should show 1 user (singular form)"
    );
    assert!(
        html.contains("<b>0</b> users"),
        "s2 should show 0 users granted access"
    );
}

/// "Deploy all" button (2026-06-03): the servers page shows the
/// SSE-driven deploy-all trigger + the live log pane when ≥1 server.
#[tokio::test]
async fn admin_servers_renders_deploy_all_button() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 2, 0, &[]).await;
    let html = fetch_html(router(s), "/admin/servers").await;
    assert!(
        html.contains(r#"data-sse-url="/admin/servers/deploy-all/sse""#),
        "deploy-all button must carry the SSE trigger URL"
    );
    assert!(
        html.contains("deploy all servers"),
        "deploy-all button label drifted"
    );
    assert!(
        html.contains(r#"id="deploy-log""#),
        "deploy-all needs a live log pane"
    );
}

/// `run_deploy_all` flattens each server's re-deploy into one stream and
/// ends in a terminal Error when ANY server failed (here: no deploy key
/// on disk → every server errors). Per-server ✗ lines still surface
/// individual failures; the terminal kind tells the frontend the run
/// was not fully green.
#[tokio::test]
async fn run_deploy_all_streams_terminal_error_with_per_server_failures() {
    use tokio_stream::StreamExt;
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 2, 0, &[]).await;
    let servers = s.inv.list_servers().await.unwrap();
    // A deploy-key path that does NOT exist → run_redeploy fails each
    // server at the pre-flight; deploy_all forwards the failures and
    // reaches a terminal Error.
    let key = dir.path().join("nope-id_ed25519");
    let stream = vpnctld::wizard_bootstrap::run_deploy_all(
        servers,
        s.inv.clone(),
        std::sync::Arc::clone(&s.registry),
        key,
    );
    tokio::pin!(stream);
    let mut events = Vec::new();
    while let Some(ev) = stream.next().await {
        events.push(ev);
    }
    // Terminal Error — the failed list is non-empty.
    match events.last() {
        Some(vpnctld::wizard_bootstrap::BootstrapEvent::Error { phase, message }) => {
            assert_eq!(*phase, "done");
            assert!(
                message.contains("failed:"),
                "summary must name failures: {message}"
            );
        }
        other => panic!("expected terminal Error, got {other:?}"),
    }
    // Per-server failures surfaced as ✗ step lines, and a summary that
    // names them (both seeded servers failed → "failed: …").
    let joined: String = events
        .iter()
        .filter_map(|e| match e {
            vpnctld::wizard_bootstrap::BootstrapEvent::Step { message, .. } => {
                Some(message.clone())
            }
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        joined.contains("✗ s0"),
        "s0 failure must be reported: {joined}"
    );
    assert!(
        joined.contains("failed:"),
        "summary must report failures: {joined}"
    );
}

/// A single-server inventory must render the page header in the singular
/// form. Catches the easy-to-miss pluralisation bug.
#[tokio::test]
async fn admin_servers_header_singular_for_one_server() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;

    let app = router(s);
    let html = fetch_html(app, "/admin/servers").await;

    assert!(
        html.contains("1 <em>server</em>"),
        "expected singular 'server' in page header"
    );
    assert!(
        !html.contains("1 <em>servers</em>"),
        "must not pluralise when count is 1"
    );
}

/// REGRESSION (audit 2026-06-10): deleting a server while its deploy
/// pipeline holds the per-server permit must 409, not proceed — the
/// pipeline would keep SSH-pushing to the node, FK-fail its secret
/// upserts mid-stream, then audit a deploy for a deleted server.
///
/// Server id is test-UNIQUE («del-409-srv», not the shared «s0»):
/// DeployGuard's in-flight set is process-global and admin_smoke tests
/// run in parallel threads — holding «s0» here would intermittently
/// collide with every other test that deploys s0.
#[tokio::test]
async fn admin_server_delete_refuses_while_deploy_in_flight() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    inv.add_server(&vpnctl_core::Server {
        id: ServerId("del-409-srv".into()),
        address: "203.0.113.77".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![vpnctl_core::KernelId("sing-box".into())],
        enabled_protocols: Vec::new(),
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();
    let app = router(s);

    // Hold the deploy permit, as a live pipeline would.
    let _held =
        vpnctld::wizard_bootstrap::DeployGuard::try_acquire("del-409-srv").expect("hold permit");
    let resp = app
        .clone()
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/del-409-srv/delete")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("confirm=del-409-srv"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CONFLICT,
        "delete during an in-flight deploy must 409"
    );
    assert!(
        inv.get_server(&ServerId("del-409-srv".into()))
            .await
            .unwrap()
            .is_some(),
        "server must survive the refused delete"
    );

    // Permit released → the same delete goes through.
    drop(_held);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/del-409-srv/delete")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("confirm=del-409-srv"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(
        inv.get_server(&ServerId("del-409-srv".into()))
            .await
            .unwrap()
            .is_none(),
        "delete must proceed once the deploy permit is free"
    );
}

/// Security audit 2026-05-18 — quick-add must reject addresses
/// containing control bytes (`\n`, `\r`, `\t`, etc) that would
/// produce broken multi-line audit / log records downstream. Old
/// validator only rejected ASCII space + length>253.
#[tokio::test]
async fn server_quick_add_rejects_control_chars_in_address() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    // Control chars MID-STRING (not trailing — `.trim()` would strip
    // those). These produce broken multi-line audit / log records
    // if persisted as-is.
    for (encoded_addr, label) in [
        ("198%0A.51.100.1", "embedded newline in middle"),
        ("198%0D.51.100.1", "embedded CR"),
        ("198%09.51.100.1", "embedded tab"),
        ("host%20with%20space", "embedded space"),
        (
            "evil%3B%20rm%20-rf%20%2F",
            "shell-metachar injection attempt",
        ),
    ] {
        let body = format!("id=test&address={encoded_addr}&ssh_port=22");
        let mut req = Request::builder()
            .method("POST")
            .uri("/admin/servers/quick-add")
            .header("content-type", "application/x-www-form-urlencoded");
        req = add_same_origin(req);
        let resp = app
            .clone()
            .oneshot(req.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "quick-add MUST 400 on {label} in address"
        );
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let text = std::str::from_utf8(&body_bytes).unwrap();
        assert!(
            text.contains("invalid address"),
            "error must call out 'invalid address': {text}"
        );
    }
}

// ────────────────────────────────────────────────────────────────────────
// Phase E sub-iter 4a — add-server wizard step 1 + step-2 stub.
//
// The wizard is the marquee differentiator over the bash project
// (per CLAUDE.md "Strategic context"). Sub-iter 4a's contract:
//   * GET /admin/servers/new renders a form with `address` +
//     `root_password` fields and the editorial chrome.
//   * POST validates input, stashes it server-side keyed by an
//     HttpOnly+SameSite=Strict cookie, and 303s to step 2.
//   * GET step-2 either reads the session cookie and shows the
//     stashed address, or 400s if the session is missing/expired.
//   * /admin/servers list links to /admin/servers/new (the CLI
//     nudge alone leaves operators stranded).

#[tokio::test]
async fn admin_servers_index_links_to_wizard() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let html = fetch_html(app, "/admin/servers").await;
    assert!(
        html.contains("/admin/servers/new"),
        "servers list must link to the wizard; got {}",
        &html[..html.len().min(800)]
    );
    // The "add server →" CTA is the editorial-voice prompt.
    assert!(
        html.contains("add server"),
        "wizard CTA copy missing on /admin/servers"
    );
}

#[tokio::test]
async fn admin_servers_list_link_to_detail_page() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    let html = fetch_html(router(s), "/admin/servers").await;
    assert!(
        html.contains(r#"href="/admin/servers/s0""#),
        "server card headline must link to detail page"
    );
}

// ────────────────────────────────────────────────────────────────────────
// Pavel iter A2 — quick-add server inline form on /admin/servers.
// Single-action UX matching the one-input user-create form: id +
// address + ssh_port → server registered with default kernel=sing-box
// and EVERY sing-box-supported protocol enabled. Per-knob tuning
// lives on the detail page.

#[tokio::test]
async fn admin_server_quick_add_registers_with_default_protocols() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    let app = router(s);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/quick-add")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("id=fra-01&address=203.0.113.7&ssh_port=2222"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let srv = inv
        .get_server(&vpnctl_core::ServerId("fra-01".into()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(srv.address, "203.0.113.7");
    assert_eq!(srv.ssh_port, 2222);
    assert_eq!(srv.kernels.len(), 1);
    assert_eq!(srv.kernels[0].0, "sing-box");
    // Default protocols = every protocol the kernel supports. Spot-check
    // a few that sing-box implements in the workspace registry.
    let pids: Vec<&str> = srv.enabled_protocols.iter().map(|p| p.0.as_str()).collect();
    assert!(
        pids.contains(&"vless+reality"),
        "default protocols: {pids:?}"
    );
    assert!(pids.contains(&"tuic-v5"));
    assert!(pids.contains(&"hysteria2"));
    // wireguard must NOT be in defaults — different kernel.
    assert!(!pids.contains(&"wireguard"));
}

/// REGRESSION (review 2026-06-04): quick-add validated server ids with
/// the USER-id validator (2..=32, lowercase-only) while the error text
/// promised «1-64 chars of A-Z a-z 0-9 . _ -» — so a 1-char or
/// mixed-case id was rejected with a message claiming it's allowed.
/// The dedicated `valid_server_id` now enforces exactly what the
/// message says.
#[tokio::test]
async fn admin_server_quick_add_id_policy_matches_error_text() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    let app = router(s);

    let post = |id_addr: &'static str| {
        add_same_origin(
            Request::builder()
                .method("POST")
                .uri("/admin/servers/quick-add")
                .header("content-type", "application/x-www-form-urlencoded"),
        )
        .body(Body::from(id_addr))
        .unwrap()
    };

    // Mixed case — promised by the message, used to 400.
    let resp = app
        .clone()
        .oneshot(post("id=Fra-01&address=203.0.113.8"))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "mixed-case server id must be accepted (the error text always promised A-Z)"
    );
    assert!(
        inv.get_server(&vpnctl_core::ServerId("Fra-01".into()))
            .await
            .unwrap()
            .is_some()
    );

    // 1-char — promised by the message («1-64»), used to 400 (user cap 2..=32).
    let resp = app
        .clone()
        .oneshot(post("id=x&address=203.0.113.9"))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "1-char server id must be accepted"
    );

    // Genuinely invalid stays rejected: embedded space…
    let resp = app
        .clone()
        .oneshot(post("id=bad%20id&address=203.0.113.10"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    // …and over-long (65 chars).
    let long = format!("id={}&address=203.0.113.11", "a".repeat(65));
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/quick-add")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from(long))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "65-char id must 400"
    );
}

#[tokio::test]
async fn admin_server_quick_add_rejects_duplicate_id() {
    use vpnctl_core::{KernelId, Server, ServerId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("dup".into()),
            address: "203.0.113.7".into(),
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
                    .uri("/admin/servers/quick-add")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("id=dup&address=198.51.100.5&ssh_port=22"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert!(
        std::str::from_utf8(&body)
            .unwrap()
            .contains("already exists"),
        "duplicate id must surface 'already exists' wording"
    );
}

/// HANDOFF §6 #2 — duplicate-ADDRESS guard. Two inventory records for one
/// physical node fight over its `users[]`; the second deploy trips the
/// DG-1 user-removal guard (the `us` / `us1` incident, 2026-07-08).
/// quick-add must 400 when the address already belongs to another server,
/// naming the clashing id, and must NOT create the duplicate.
#[tokio::test]
async fn admin_server_quick_add_rejects_duplicate_address() {
    use vpnctl_core::{KernelId, Server, ServerId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    inv.add_server(&Server {
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
    // Different id, SAME address → rejected.
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/quick-add")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("id=us1&address=130.94.19.7&ssh_port=22"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let txt = std::str::from_utf8(&body).unwrap();
    assert!(
        txt.contains("already registered to server 'us'"),
        "dup-address 400 must name the clashing server id, got: {txt}"
    );
    // The duplicate must NOT have been created.
    assert!(
        inv.get_server(&ServerId("us1".into()))
            .await
            .unwrap()
            .is_none(),
        "duplicate-address server must not be registered"
    );
}

/// "Update all kernels" button (update-kernels PR2): the servers-list
/// page shows the fleet-wide SSE trigger + its own log pane when ≥1
/// server. Copy-contract.
#[tokio::test]
async fn admin_servers_renders_update_all_kernels_button() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 2, 0, &[]).await;
    let html = fetch_html(router(s), "/admin/servers").await;
    assert!(
        html.contains(r#"data-sse-url="/admin/servers/update-kernels-all/sse""#),
        "update-all-kernels button must carry the fleet-wide SSE trigger URL"
    );
    assert!(
        html.contains(r#"id="update-kernels-log""#),
        "update-all-kernels needs its own live log pane"
    );
    assert!(
        html.contains("update all kernels") || html.contains("обновить все ядра"),
        "update-all-kernels button label drifted"
    );
}

/// Handler smoke: the fleet-wide update-kernels-all SSE route refuses a
/// cross-site `Sec-Fetch-Site` with 403, mirroring the deploy-all guard.
#[tokio::test]
async fn servers_update_kernels_all_sse_cross_site_is_403() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/servers/update-kernels-all/sse")
                .header("sec-fetch-site", "cross-site")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "cross-site update-kernels-all SSE trigger must be refused"
    );
}

/// The delete-confirm page must render the retype form (POSTing to the
/// delete route, with a `confirm` field) and disclose the cascade scope —
/// the exact grant count that will be dropped.
#[tokio::test]
async fn admin_server_delete_confirm_page_shows_form_and_grant_count() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    // s0 carries two grants (u0, u1); s1 carries none.
    seed(&s.inv, 2, 2, &[(0, 0), (1, 0)]).await;
    let html = fetch_html(router(s), "/admin/servers/s0/delete-confirm").await;
    assert!(
        html.contains(r#"action="/admin/servers/s0/delete""#),
        "confirm form must POST to the delete route"
    );
    assert!(
        html.contains(r#"name="confirm""#),
        "retype-to-confirm input must be present"
    );
    assert!(
        html.contains("2 grant(s)"),
        "must disclose the exact cascade grant count (2)"
    );
}

/// A mismatched confirm token must be rejected with 400 and leave the
/// server (and its grants) fully intact — the guard against fat-finger
/// deletes.
#[tokio::test]
async fn admin_server_delete_rejects_confirm_mismatch() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 2, 2, &[(0, 0), (1, 0)]).await;
    let resp = router(s.clone())
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/s0/delete")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("confirm=wrong"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(
        s.inv
            .get_server(&ServerId("s0".into()))
            .await
            .unwrap()
            .is_some(),
        "server must survive a mismatched confirm"
    );
    assert_eq!(
        s.inv
            .users_for_server(&ServerId("s0".into()))
            .await
            .unwrap()
            .len(),
        2,
        "grants must survive a mismatched confirm"
    );
}

/// The happy path: an exact-match confirm deletes the server, cascades its
/// grants, audits `server.remove` (with the captured grant count), redirects
/// to the server list — and leaves OTHER servers and the affected users
/// themselves untouched.
#[tokio::test]
async fn admin_server_delete_cascades_grants_and_audits() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 2, 2, &[(0, 0), (1, 0)]).await;
    let resp = router(s.clone())
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/s0/delete")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("confirm=s0"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    // Server is gone.
    assert!(
        s.inv
            .get_server(&ServerId("s0".into()))
            .await
            .unwrap()
            .is_none(),
        "deleted server must be absent from inventory"
    );
    // Its grants cascaded.
    assert_eq!(
        s.inv
            .users_for_server(&ServerId("s0".into()))
            .await
            .unwrap()
            .len(),
        0,
        "grants for the deleted server must cascade away"
    );
    // The other server is untouched.
    assert!(
        s.inv
            .get_server(&ServerId("s1".into()))
            .await
            .unwrap()
            .is_some(),
        "cascade must be scoped — sibling server must survive"
    );
    // The users themselves survive (only the grant rows cascade).
    assert!(
        s.inv
            .get_user(&UserId("u0".into()))
            .await
            .unwrap()
            .is_some(),
        "user must survive — only its grant to s0 is removed"
    );
    // Audit row landed, target s0, with the captured grant count.
    let audit = s.inv.recent_audit(20).await.unwrap();
    let row = audit
        .iter()
        .find(|e| e.action == "server.remove" && e.target.as_deref() == Some("s0"))
        .expect("server.remove audit row must land");
    let payload = row
        .payload
        .as_ref()
        .expect("server.remove must carry a payload");
    assert_eq!(
        payload.get("grants_removed").and_then(|v| v.as_u64()),
        Some(2),
        "audit payload must record the 2 grants removed"
    );
}

#[tokio::test]
async fn kernel_quality_release_renders_all_kernel_versions() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let server = Server {
        id: ServerId("all-kernels".into()),
        address: "203.0.113.50".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: ["sing-box", "amneziawg", "caddy", "xray"]
            .into_iter()
            .map(|id| KernelId(id.into()))
            .collect(),
        enabled_protocols: vec![],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    };
    s.inv.add_server(&server).await.unwrap();
    s.inv
        .record_node_health(
            &server.id,
            Some(true),
            Some(true),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(
                r#"{"sing-box":{"version":"1.13.18","active":true},"amneziawg":{"version":"1.0.20210913-1","active":true},"caddy":{"version":"v2.11.4","active":true},"xray":{"version":"26.3.27","active":true}}"#,
            ),
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

    let app = router(s);
    let detail = fetch_html(app.clone(), "/admin/servers/all-kernels").await;
    assert!(detail.contains("Kernel versions"));
    assert!(detail.contains(r#"data-kernel-version="xray""#));
    assert!(detail.contains("26.3.27"));
    assert!(detail.contains("v26.3.27"));

    let list = fetch_html(app.clone(), "/admin/servers").await;
    assert!(list.contains(r#"id="fleet-kernel-versions""#));
    assert!(list.contains("xray"));
    let fleet_versions = list
        .split_once("fleet-kernel-versions")
        .expect("fleet kernel-version section")
        .1;
    let order = ["sing-box", "xray", "amneziawg", "caddy"].map(|kernel| {
        fleet_versions
            .find(kernel)
            .expect("kernel in fleet version section")
    });
    assert!(
        order.windows(2).all(|pair| pair[0] < pair[1]),
        "fleet kernels must use priority order: {order:?}"
    );
    assert!(
        list.contains(r#"class="ed-kvers""#),
        "fleet versions must use the single-line compact layout"
    );
    assert!(
        list.contains(r#"class="ed-kvers__value" title="1.0.20210913-1">1.0.2021…13-1</span>"#),
        "amneziawg must use a compact middle ellipsis with the full package version in title"
    );

    let css = fetch_html(app.clone(), "/admin/assets/admin.css").await;
    let compact_rule = css
        .split_once(".ed-kvers {")
        .and_then(|(_, tail)| tail.split_once('}'))
        .map(|(rule, _)| rule)
        .expect("compact kernel-version CSS rule");
    assert!(compact_rule.contains("white-space: nowrap"));
    assert!(compact_rule.contains("overflow: hidden"));
    assert!(compact_rule.contains("text-overflow: ellipsis"));

    let list_ru = fetch_html_with_cookie(app, "/admin/servers", "vpnctl_lang=ru").await;
    assert!(list_ru.contains("Версии ядер"));
    assert!(list_ru.contains(r#"class="ed-kvers""#));
}
