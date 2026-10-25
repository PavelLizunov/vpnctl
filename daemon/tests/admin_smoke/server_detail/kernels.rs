use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{KernelId, ProtocolId, Server, ServerId};
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
    assert!(
        html.contains("/admin/servers/sb-only/kernels/sing-box/disable"),
        "enabled kernel must have disable form"
    );
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
    assert!(
        html.contains("/admin/servers/dual/protocols/wireguard/enable"),
        "wireguard must be enable-able once amneziawg kernel is on the server"
    );
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
    assert!(
        !html.contains("ssh root@"),
        "update-kernels copy must not instruct the operator to `ssh root@…` the node"
    );
}

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

#[tokio::test]
async fn server_update_kernels_sse_unknown_server_is_404() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let sse_uri = ticketed_sse_uri(&app, "/admin/servers/no-such/update-kernels/sse").await;
    let resp = app
        .oneshot(Request::builder().uri(sse_uri).body(Body::empty()).unwrap())
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

#[tokio::test]
async fn admin_kernel_disable_refuses_to_orphan_enabled_protocols() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    let inv = s.inv.clone();
    let resp = router(s)
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/s0/kernels/sing-box/disable"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.starts_with("vpnctl admin: cannot disable kernel 'sing-box'"),
        "{text}"
    );
    assert!(text.contains("vless+reality"), "{text}");
    let server = inv
        .get_server(&ServerId("s0".into()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(server.kernels, vec![KernelId("sing-box".into())]);
}

#[tokio::test]
async fn admin_protocol_enable_refuses_protocol_no_assigned_kernel_serves() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    let inv = s.inv.clone();
    let resp = router(s)
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/s0/protocols/vless%2Bxhttp/enable"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.contains("cannot enable protocol 'vless+xhttp'"),
        "{text}"
    );
    assert!(
        text.contains("xray"),
        "must name the kernel that would serve it: {text}"
    );
    let server = inv
        .get_server(&ServerId("s0".into()))
        .await
        .unwrap()
        .unwrap();
    assert!(
        !server
            .enabled_protocols
            .contains(&ProtocolId("vless+xhttp".into()))
    );
}

#[tokio::test]
async fn admin_form_errors_render_inside_the_admin_shell_for_browsers() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    let app = router(s);
    let req = |accept: &str| {
        add_same_origin(
            Request::builder()
                .method("POST")
                .uri("/admin/servers/s0/kernels/sing-box/disable")
                .header("accept", accept)
                .header(
                    "referer",
                    "http://127.0.0.1:18402/admin/servers/s0/protocols",
                ),
        )
        .body(Body::empty())
        .unwrap()
    };
    let resp = app
        .clone()
        .oneshot(req("text/html,application/xhtml+xml"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let html =
        String::from_utf8_lossy(&resp.into_body().collect().await.unwrap().to_bytes()).to_string();
    assert!(
        html.contains("<nav") || html.contains("ed-tb"),
        "must keep the admin shell"
    );
    assert!(html.contains("cannot disable kernel"));
    assert!(
        html.contains("href=\"/admin/servers/s0/protocols\""),
        "back link to the form page"
    );

    let resp = app.oneshot(req("*/*")).await.unwrap();
    let text =
        String::from_utf8_lossy(&resp.into_body().collect().await.unwrap().to_bytes()).to_string();
    assert!(
        text.starts_with("vpnctl admin: "),
        "non-browser clients keep the plain contract"
    );
}

#[tokio::test]
async fn admin_form_error_back_link_rejects_traversal_referer() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    let app = router(s);
    let req = add_same_origin(
        Request::builder()
            .method("POST")
            .uri("/admin/servers/s0/kernels/sing-box/disable")
            .header("accept", "text/html")
            .header("referer", "http://127.0.0.1:18402/admin/../evil"),
    )
    .body(Body::empty())
    .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let html =
        String::from_utf8_lossy(&resp.into_body().collect().await.unwrap().to_bytes()).to_string();
    assert!(html.contains("href=\"/admin/\""), "{html}");
    assert!(!html.contains("evil"), "{html}");
}

#[tokio::test]
async fn admin_kernel_disable_allowed_when_another_kernel_still_serves_protocols() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    let sid = ServerId("s0".into());
    s.inv
        .add_server_kernel(&sid, &KernelId("xray".into()))
        .await
        .unwrap();
    let inv = s.inv.clone();
    let resp = router(s)
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/s0/kernels/xray/disable")
                    .header("accept", "text/html"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert!(resp.status().is_redirection(), "got {}", resp.status());
    assert!(
        resp.headers().get("location").is_some(),
        "success redirects must pass through the error-page layer unchanged"
    );
    let server = inv.get_server(&sid).await.unwrap().unwrap();
    assert_eq!(server.kernels, vec![KernelId("sing-box".into())]);
    assert_eq!(
        inv.retired_server_kernels(&sid).await.unwrap(),
        vec![KernelId("xray".into())],
        "deploy must stop exactly the kernels disabled through the admin action"
    );
}
