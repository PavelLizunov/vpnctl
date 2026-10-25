use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{ServerId, UserId};
use vpnctld::{AppState, router};

use crate::common::*;

async fn state_with_chain(dir: &TempDir, grant_entry: bool) -> (AppState, String) {
    let state = state(dir).await;
    let grants = if grant_entry {
        vec![(0, 0), (0, 1)]
    } else {
        vec![(0, 1)]
    };
    seed(&state.inv, 2, 1, &grants).await;
    state
        .inv
        .set_server_display_name(&ServerId("s0".into()), Some("Iceland"))
        .await
        .unwrap();
    state
        .inv
        .set_server_display_name(&ServerId("s1".into()), Some("S5"))
        .await
        .unwrap();
    state
        .inv
        .set_client_detour_via_as("test", &ServerId("s1".into()), Some(&ServerId("s0".into())))
        .await
        .unwrap();
    let token = state
        .inv
        .get_user(&UserId("u0".into()))
        .await
        .unwrap()
        .unwrap()
        .sub_token
        .unwrap();
    (state, token)
}

#[tokio::test]
async fn delivery_shows_chain_url_and_qr_when_both_members_are_granted() {
    let dir = TempDir::new().unwrap();
    let (state, token) = state_with_chain(&dir, true).await;
    let html = fetch_html(router(state), "/admin/users/u0/delivery").await;

    assert!(html.contains(&format!("/sub/{token}?format=sing-box")));
    assert!(html.contains("Sing-box chain subscription"));
    assert!(html.contains("S5 via Iceland"));
    assert!(html.contains("vpnctl-qr-frame"));
}

#[tokio::test]
async fn delivery_omits_chain_artefact_when_entry_grant_is_missing() {
    let dir = TempDir::new().unwrap();
    let (state, _token) = state_with_chain(&dir, false).await;
    let html = fetch_html(router(state), "/admin/users/u0/delivery").await;

    assert!(!html.contains("format=sing-box"));
    assert!(!html.contains("Sing-box chain subscription"));
}

#[tokio::test]
async fn delivery_omits_chain_artefact_without_chained_servers() {
    let dir = TempDir::new().unwrap();
    let state = state(&dir).await;
    seed(&state.inv, 1, 1, &[(0, 0)]).await;
    let html = fetch_html(router(state), "/admin/users/u0/delivery").await;

    assert!(!html.contains("format=sing-box"));
    assert!(!html.contains("Sing-box chain subscription"));
}

#[tokio::test]
async fn delivery_chain_url_uses_configured_public_base() {
    let dir = TempDir::new().unwrap();
    let (state, token) = state_with_chain(&dir, true).await;
    state
        .inv
        .set_public_base_url(Some("https://vpn.example.com"))
        .await
        .unwrap();
    let html = fetch_html(router(state), "/admin/users/u0/delivery").await;

    assert!(
        html.contains(&format!(
            "https://vpn.example.com/api/v1/sub/{token}?format=sing-box"
        )),
        "chain QR must point at the public base, not the request Host: {html}"
    );
}

#[tokio::test]
async fn delivery_flow_a_uses_public_base() {
    for configured in [Some("https://vpn.example.com/"), None] {
        let dir = TempDir::new().unwrap();
        let (state, token) = state_with_chain(&dir, true).await;
        state.inv.set_public_base_url(configured).await.unwrap();
        let (private, public) = vpnctl_crypto::gen_wireguard_keypair();
        state
            .inv
            .set_user_wireguard_keypair(&UserId("u0".into()), &public, &private)
            .await
            .unwrap();
        let resp = router(state)
            .oneshot(
                Request::builder()
                    .uri("/admin/users/u0/delivery")
                    .header("host", "vpnctld:18402")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let html = std::str::from_utf8(&body).unwrap();
        let flow_a = html
            .split_once("Flow A — Hiddify / Sing-box")
            .unwrap()
            .1
            .split_once("Flow B — official WireGuard app / Hiddify")
            .unwrap()
            .0;
        let base = configured.map_or("http://vpnctld:18402", |url| url.trim_end_matches('/'));
        let expected = format!("{base}/sub/{token}");
        let textarea = flow_a
            .split_once("<textarea ")
            .unwrap()
            .1
            .split_once('>')
            .unwrap()
            .1
            .split_once("</textarea>")
            .unwrap()
            .0;
        assert_eq!(textarea.as_bytes(), expected.as_bytes());
        assert!(flow_a.contains("vpnctl-qr-frame"));
        assert!(flow_a.contains("Recommended default — one URL covers everything."));
        if configured.is_some() {
            assert!(!flow_a.contains("http://vpnctld"));
            assert!(!flow_a.contains("http://vpn.example.com"));
        }
    }
}
