use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{KernelId, Server, ServerId, UserId};
use vpnctld::router;

use super::common::*;

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
    assert!(
        !html.contains(r#"class="ed-server""#),
        "server cards must not render on empty inventory"
    );
}

#[tokio::test]
async fn admin_servers_renders_one_card_per_server_with_user_counts() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 3, 2, &[(0, 0), (1, 0), (0, 1)]).await;

    let app = router(s);
    let html = fetch_html(app, "/admin/servers").await;

    assert!(
        html.contains(r#"<table class="ed-grid">"#),
        "servers list must render the dense inventory table"
    );
    assert_eq!(
        html.matches(r#"class="ed-grid__id""#).count(),
        3,
        "expected three server rows (one ed-grid__id link each)"
    );
    assert!(
        html.contains("3 <em>servers</em>"),
        "page header should announce 3 servers"
    );
    for id in ["s0", "s1", "s2"] {
        assert!(html.contains(id), "server id {id} missing from html");
    }
    for addr in ["10.0.0.0:22", "10.0.0.1:22", "10.0.0.2:22"] {
        assert!(html.contains(addr), "address {addr} missing");
    }
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

#[tokio::test]
async fn run_deploy_all_streams_terminal_error_with_per_server_failures() {
    use tokio_stream::StreamExt;
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 2, 0, &[]).await;
    let servers = s.inv.list_servers().await.unwrap();
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

#[tokio::test]
async fn server_quick_add_rejects_control_chars_in_address() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

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
    let pids: Vec<&str> = srv.enabled_protocols.iter().map(|p| p.0.as_str()).collect();
    assert!(
        pids.contains(&"vless+reality"),
        "default protocols: {pids:?}"
    );
    assert!(pids.contains(&"tuic-v5"));
    assert!(pids.contains(&"hysteria2"));
    assert!(!pids.contains(&"wireguard"));
}

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

    let resp = app
        .clone()
        .oneshot(post("id=bad%20id&address=203.0.113.10"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    for bad_id in [
        "..",
        "srv..01",
        ".leadingdot",
        "trailingdot.",
        "-leadingdash",
        "trailingdash-",
        "_leadingunderscore",
        "trailingunderscore_",
        "slash/in/id",
    ] {
        let body = format!("id={bad_id}&address=203.0.113.10");
        let resp = app
            .clone()
            .oneshot(
                add_same_origin(
                    Request::builder()
                        .method("POST")
                        .uri("/admin/servers/quick-add")
                        .header("content-type", "application/x-www-form-urlencoded"),
                )
                .body(Body::from(body))
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "server id {bad_id:?} must be rejected"
        );
    }
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
    assert!(
        inv.get_server(&ServerId("us1".into()))
            .await
            .unwrap()
            .is_none(),
        "duplicate-address server must not be registered"
    );
}

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

#[tokio::test]
async fn servers_update_kernels_all_sse_cross_site_is_403() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/servers/update-kernels-all/sse")
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

#[tokio::test]
async fn admin_server_delete_confirm_page_shows_form_and_grant_count() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
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

#[tokio::test]
async fn admin_server_delete_client_entry_returns_conflict_with_targets() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 3, 1, &[(0, 0), (0, 1)]).await;
    let entry = ServerId("s0".into());
    for id in ["s1", "s2"] {
        s.inv
            .set_client_detour_via_as("admin", &ServerId(id.into()), Some(&entry))
            .await
            .unwrap();
    }
    let before = s.inv.recent_audit(100).await.unwrap().len();
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
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let body = std::str::from_utf8(&body).unwrap();
    assert!(body.contains("s1, s2"));
    assert!(s.inv.get_server(&entry).await.unwrap().is_some());
    assert_eq!(s.inv.users_for_server(&entry).await.unwrap().len(), 1);
    assert_eq!(s.inv.recent_audit(100).await.unwrap().len(), before);
}

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

    assert!(
        s.inv
            .get_server(&ServerId("s0".into()))
            .await
            .unwrap()
            .is_none(),
        "deleted server must be absent from inventory"
    );
    assert_eq!(
        s.inv
            .users_for_server(&ServerId("s0".into()))
            .await
            .unwrap()
            .len(),
        0,
        "grants for the deleted server must cascade away"
    );
    assert!(
        s.inv
            .get_server(&ServerId("s1".into()))
            .await
            .unwrap()
            .is_some(),
        "cascade must be scoped — sibling server must survive"
    );
    assert!(
        s.inv
            .get_user(&UserId("u0".into()))
            .await
            .unwrap()
            .is_some(),
        "user must survive — only its grant to s0 is removed"
    );
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

#[tokio::test]
async fn admin_servers_billing_page_and_actions() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();

    inv.add_server(&Server {
        id: ServerId("srv-bill-1".into()),
        address: "203.0.113.101".into(),
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

    let html = fetch_html(app.clone(), "/admin/servers/billing").await;
    assert!(html.contains("Server rental &amp; payment schedule"));
    assert!(html.contains("srv-bill-1"));
    assert!(html.contains("unconfigured"));

    let resp = app
        .clone()
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/srv-bill-1/billing")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("due_date=2026-10-15&billing_cycle=monthly&amount=5.50&currency=EUR&auto_renew=1&billing_url=https%3A%2F%2Fexample.com%2Fbilling&notes=Order123"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    let html_after = fetch_html(app.clone(), "/admin/servers/billing").await;
    assert!(html_after.contains("5.50 €"), "amount missing in html");
    assert!(html_after.contains("Order123"), "notes missing in html");
    assert!(
        html_after.contains("15.10.2026"),
        "due date missing in html"
    );
    assert!(html_after.contains("Order123"));
    assert!(html_after.contains("15.10.2026"));

    let resp_adv = app
        .clone()
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/srv-bill-1/billing/advance")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_adv.status(), StatusCode::SEE_OTHER);

    let html_adv = fetch_html(app.clone(), "/admin/servers/billing").await;
    assert!(
        html_adv.contains("15.11.2026"),
        "due date should advance to November: {html_adv}"
    );

    let resp_settings = app
        .clone()
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/billing/settings")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("display_currency=RUB&markup_coeff=1.07"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_settings.status(), StatusCode::SEE_OTHER);

    inv.upsert_currency_rate(&vpnctl_inventory::CurrencyRate {
        base_currency: "EUR".into(),
        target_currency: "RUB".into(),
        rate_micros: 98_000_000,
        source: "test".into(),
        fetched_at: "2026-09-12T00:00:00Z".into(),
    })
    .await
    .unwrap();

    let html_rub = fetch_html(app.clone(), "/admin/servers/billing").await;
    assert!(
        html_rub.contains("576.73 ₽"),
        "converted RUB amount missing: {html_rub}"
    );
}

#[tokio::test]
async fn admin_server_billing_boosty_income_and_pl_overview() {
    use vpnctl_core::{KernelId, Server, ServerId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();

    let app = router(s);
    let html_no_boosty = fetch_html(app.clone(), "/admin/servers/billing").await;
    assert!(html_no_boosty.contains("Connect Boosty on"));
    assert!(html_no_boosty.contains("/admin/boosty"));

    inv.set_boosty_report_and_events(
        &serde_json::json!({
            "observed_at": 1_754_000_000_i64,
            "total_subscribers": 1,
            "active_subscribers": 1,
            "subscribers": [{
                "subscriber_id": 101,
                "name": "Alice",
                "present": true,
                "status": "active",
                "subscribed": true,
                "price": "1000",
                "payments": "3000",
                "level_id": 1,
                "level_name": "Premium",
                "level_price": "1000"
            }]
        })
        .to_string(),
        &[],
    )
    .await
    .unwrap();

    inv.add_server(&Server {
        id: ServerId("node-1".into()),
        address: "192.0.2.10".into(),
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

    inv.set_server_billing(
        &ServerId("node-1".into()),
        &vpnctl_inventory::ServerBillingInput {
            due_date: "2026-10-01".into(),
            billing_cycle: vpnctl_inventory::BillingCycle::Monthly,
            amount_cents: 500,
            currency: "EUR".into(),
            auto_renew: true,
            billing_url: None,
            notes: None,
            initial_payments_count: None,
        },
    )
    .await
    .unwrap();

    inv.upsert_currency_rate(&vpnctl_inventory::CurrencyRate {
        base_currency: "EUR".into(),
        target_currency: "RUB".into(),
        rate_micros: 100_000_000,
        source: "test".into(),
        fetched_at: "2026-09-12T00:00:00Z".into(),
    })
    .await
    .unwrap();

    let html_pl = fetch_html(app.clone(), "/admin/servers/billing").await;
    assert!(html_pl.contains("Financial Balance &amp; P&amp;L"));
    assert!(html_pl.contains("Boosty Income (MRR)"));
    assert!(html_pl.contains("10.00 €"), "MRR in EUR: {html_pl}");
    assert!(html_pl.contains("5.00 €"), "Spend in EUR: {html_pl}");
    assert!(html_pl.contains("+5.00 €"), "Net margin in EUR: {html_pl}");
    assert!(
        html_pl.contains("cost coverage: 200% (2.0×)")
            || html_pl.contains("cost coverage: 200% (2.0x)")
            || html_pl.contains("покрытие расходов: 200% (2.0×)")
            || html_pl.contains("покрытие расходов: 200% (2.0x)"),
        "coverage ratio missing in html: {html_pl}"
    );
    assert!(
        html_pl.contains("all-time:") || html_pl.contains("история блога:"),
        "all-time label missing in html: {html_pl}"
    );
}

#[tokio::test]
async fn billing_missing_rates_mark_totals_incomplete_and_hide_profit_and_coverage() {
    for currencies in [["EUR", "USD", "CHF"], ["USD", "CHF", "CHF"]] {
        let dir = TempDir::new().unwrap();
        let s = state(&dir).await;
        seed(&s.inv, 3, 0, &[]).await;
        let inv = s.inv.clone();
        for (index, currency) in currencies.iter().enumerate() {
            inv.set_server_billing(
                &ServerId(format!("s{index}")),
                &vpnctl_inventory::ServerBillingInput {
                    due_date: "2026-10-01".into(),
                    billing_cycle: vpnctl_inventory::BillingCycle::Monthly,
                    amount_cents: 500,
                    currency: (*currency).into(),
                    auto_renew: false,
                    billing_url: None,
                    notes: None,
                    initial_payments_count: None,
                },
            )
            .await
            .unwrap();
        }
        inv.set_boosty_last_report(
            &serde_json::json!({
                "subscribers": [{"present": true, "status": "active", "price": "1000"}]
            })
            .to_string(),
        )
        .await
        .unwrap();
        inv.upsert_currency_rate(&vpnctl_inventory::CurrencyRate {
            base_currency: "EUR".into(),
            target_currency: "RUB".into(),
            rate_micros: 100_000_000,
            source: "test".into(),
            fetched_at: "2026-10-01T00:00:00Z".into(),
        })
        .await
        .unwrap();

        let app = router(s);
        let html = fetch_html(app.clone(), "/admin/servers/billing").await;
        assert!(html.contains("ed-alert ed-alert--warn"));
        assert!(html.contains("Incomplete totals. Missing exchange rates for: CHF, USD"));
        assert!(html.contains("10.00 €"), "income remains available");
        assert!(html.contains("Incomplete expenses"));
        assert!(html.contains("cost coverage unavailable"));
        assert!(!html.contains("cost coverage:"));
        assert!(!html.contains("zero server expenses"));
        assert!(!html.contains("+5.00 €"));
        assert!(!html.contains("+10.00 €"));

        for currency in ["USD", "CHF"] {
            inv.upsert_currency_rate(&vpnctl_inventory::CurrencyRate {
                base_currency: "EUR".into(),
                target_currency: currency.into(),
                rate_micros: 1_000_000,
                source: "test".into(),
                fetched_at: "2026-10-01T00:00:00Z".into(),
            })
            .await
            .unwrap();
        }
        let complete = fetch_html(app, "/admin/servers/billing").await;
        assert!(!complete.contains("Incomplete"));
        assert!(complete.contains("cost coverage:"));
    }
}
