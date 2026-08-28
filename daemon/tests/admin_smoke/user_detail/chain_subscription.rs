use tempfile::TempDir;

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
