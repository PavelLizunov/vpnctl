//! Server-side grant management tests.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{KernelId, Server, ServerId, User, UserId};
use vpnctld::router;

use crate::common::{add_same_origin, fetch_html, seed, state};

#[tokio::test]
async fn admin_server_grant_user_persists_and_redirects_to_server() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
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
    s.inv
        .add_user(&User {
            id: UserId("alice".into()),
            uuid: "uuid-a".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    let app = router(s);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/servers/sb/grants/alice"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    // Redirect target should be the SERVER page, not the user page.
    let loc = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert_eq!(loc, "/admin/servers/sb/grants");
    // Mutation landed.
    let users_on_server = inv.users_for_server(&ServerId("sb".into())).await.unwrap();
    assert!(users_on_server.iter().any(|u| u.id.0 == "alice"));
}

/// v2 3d gap-close — the Grants tab renders clickable sort links and the
/// `?grant_sort=` param drives the row order.
#[tokio::test]
async fn v2_server_grants_sort_links_render() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 2, &[(0, 0), (1, 0)]).await; // s0 granted to u0,u1
    let html = fetch_html(router(s), "/admin/servers/s0/grants?grant_sort=traffic").await;
    assert!(
        html.contains("sort:") || html.contains("сортировка:"),
        "sort label missing"
    );
    assert!(
        html.contains("grant_sort=presence") && html.contains("grant_sort=id"),
        "sort links for the other keys must render"
    );
    // The active key renders as unlinked bold text (no href for traffic).
    assert!(
        !html.contains("grant_sort=traffic\""),
        "the active sort key must not link to itself"
    );
}
