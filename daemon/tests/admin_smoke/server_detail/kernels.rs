use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{KernelId, Server, ServerId};
use vpnctld::router;

use crate::common::*;

#[tokio::test]
async fn admin_server_detail_kernels_section_shows_every_registered_kernel() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("sb-only".into()),
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
    let html = fetch_html(app, "/admin/servers/sb-only/protocols").await;
    assert!(html.contains("Kernels"), "Kernels heading missing");
    // sing-box is registered AND enabled → disable form
    assert!(
        html.contains("/admin/servers/sb-only/kernels/sing-box/disable"),
        "enabled kernel must have disable form"
    );
    // amneziawg is registered but NOT enabled → enable form
    assert!(
        html.contains("/admin/servers/sb-only/kernels/amneziawg/enable"),
        "disabled kernel must have enable form"
    );
}

#[tokio::test]
async fn admin_server_enable_kernel_persists_and_audits() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    s.inv
        .add_server(&Server {
            id: ServerId("hybrid".into()),
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
                    .uri("/admin/servers/hybrid/kernels/amneziawg/enable"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let server = inv
        .get_server(&ServerId("hybrid".into()))
        .await
        .unwrap()
        .unwrap();
    let kids: Vec<&str> = server.kernels.iter().map(|k| k.0.as_str()).collect();
    assert!(
        kids.contains(&"sing-box") && kids.contains(&"amneziawg"),
        "hybrid server must run both kernels post-enable, got: {kids:?}"
    );
    let audit = inv.recent_audit(5).await.unwrap();
    assert!(
        audit.iter().any(|a| a.action == "server.kernel.enable"),
        "audit row for kernel enable missing"
    );
}

#[tokio::test]
async fn admin_server_enable_kernel_rejects_unregistered_id() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("sb".into()),
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
                    .uri("/admin/servers/sb/kernels/totally-fake/enable"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(text.contains("unknown kernel"));
}

#[tokio::test]
async fn admin_multi_kernel_server_enables_wireguard_protocol() {
    // The end-to-end scenario Pavel raised: add amneziawg kernel
    // to a sing-box node → wireguard protocol becomes enable-able
    // (not "incompatible") on the same server.
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    s.inv
        .add_server(&Server {
            id: ServerId("dual".into()),
            address: "203.0.113.7".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into()), KernelId("amneziawg".into())],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let app = router(s);
    let html = fetch_html(app.clone(), "/admin/servers/dual/protocols").await;
    // wireguard MUST now show an enable form (previously was
    // "incompatible" under the sing-box-only kernel).
    assert!(
        html.contains("/admin/servers/dual/protocols/wireguard/enable"),
        "wireguard must be enable-able once amneziawg kernel is on the server"
    );
    // Validate end-to-end: actually enable wireguard, then assert
    // it lands in the row.
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/dual/protocols/wireguard/enable"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let server = inv
        .get_server(&ServerId("dual".into()))
        .await
        .unwrap()
        .unwrap();
    assert!(
        server.enabled_protocols.iter().any(|p| p.0 == "wireguard"),
        "wireguard should be in enabled_protocols after enable"
    );
}

/// "Update kernels" button (update-kernels PR2): the server-detail page
/// shows the SSE-driven kernel-binary upgrade trigger with its OWN log
/// pane (`update-kernels-log`, distinct from `deploy-log`). Copy-contract.
#[tokio::test]
async fn admin_server_detail_shows_update_kernels_button() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("ukb".into()),
            address: "203.0.113.8".into(),
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
    let html = fetch_html(app, "/admin/servers/ukb").await;
    assert!(
        html.contains(r#"data-sse-url="/admin/servers/ukb/update-kernels/sse""#),
        "update-kernels button must carry the per-server SSE trigger URL"
    );
    // Its OWN log pane — distinct from the deploy button's `deploy-log`.
    assert!(
        html.contains(r#"id="update-kernels-log""#),
        "update-kernels needs its own live log pane (not deploy-log)"
    );
    assert!(
        html.contains(r#"data-log="update-kernels-log""#),
        "update-kernels button must point admin.js at its own log pane"
    );
    assert!(
        html.contains("update kernels") || html.contains("обновить ядра"),
        "update-kernels button label drifted"
    );
}

/// Operator-action-policy contract (CLAUDE.md HARD rule): the
/// update-kernels button's title / caption must NOT carry a bare
/// `ssh root@…` operator instruction. It describes what the DAEMON does
/// (apt upgrade + service restart), matching Deploy's allowed descriptive
/// register — it must not read as a shell-on-node instruction-to-operator.
#[tokio::test]
async fn admin_server_detail_update_kernels_copy_has_no_ssh_operator_instruction() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("ukpolicy".into()),
            address: "203.0.113.11".into(),
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
    let html = fetch_html(app, "/admin/servers/ukpolicy").await;
    // No bare operator-facing `ssh root@…` instruction anywhere on the
    // page (the page carries no ssh-instruction copy today; the new
    // update-kernels block must not introduce one).
    assert!(
        !html.contains("ssh root@"),
        "update-kernels copy must not instruct the operator to `ssh root@…` the node"
    );
}

/// Handler smoke: a cross-site `Sec-Fetch-Site` on the per-server
/// update-kernels SSE route is refused with 403 (CSRF guard), mirroring
/// the deploy SSE guard. A full stream needs a live node — the guard +
/// not-found below are the daemon-side analog.
#[tokio::test]
async fn server_update_kernels_sse_cross_site_is_403() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_server(&Server {
            id: ServerId("uksse".into()),
            address: "203.0.113.12".into(),
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
            Request::builder()
                .uri("/admin/servers/uksse/update-kernels/sse")
                .header("sec-fetch-site", "cross-site")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "cross-site update-kernels SSE trigger must be refused"
    );
}

/// Handler smoke: the per-server update-kernels SSE route 404s for an
/// unknown server id (server lookup runs after the same-origin guard).
#[tokio::test]
async fn server_update_kernels_sse_unknown_server_is_404() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/servers/no-such/update-kernels/sse")
                .header("sec-fetch-site", "same-origin")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(
        text.contains("no such server"),
        "404 body should name the missing server, got: {text}"
    );
}

/// server#2 — per-server kernel rollup renders the sing-box floor +
/// on-target verdict from this node's kernel_versions_json.
#[tokio::test]
async fn server_detail_kernel_rollup_renders_version_for_this_node() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    s.inv
        .record_node_health(
            &ServerId("s0".into()),
            Some(true),
            Some(true),
            Some(1000),
            Some(10000),
            Some(500),
            Some(1000),
            Some(100),
            Some(r#"["tcp/443","udp/8443"]"#),
            Some(1000),
            Some(r#"{"sing-box":"1.13.12"}"#),
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
    let html = fetch_html(router(s), "/admin/servers/s0/protocols").await;
    assert!(
        html.contains("Kernel rollup · sing-box"),
        "per-server kernel-rollup eyebrow missing"
    );
    assert!(
        html.contains("1.13.12"),
        "kernel-rollup must show this node's sing-box version"
    );
    assert!(
        html.contains("on target"),
        "single node at its own floor reads on-target"
    );
}
