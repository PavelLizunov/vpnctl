use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;
use vpnctl_core::{KernelId, ProtocolId, ServerId, UserId};
use vpnctld::{AppState, router};

use crate::common::{mk_user, seed, state};

const AUTH_USER: &str = "awg-smoke";
const AUTH_PASSWORD: &str = "test-only-not-a-deployed-password";

async fn fixture(dir: &TempDir, keys: bool) -> AppState {
    let state = state(dir).await;
    seed(&state.inv, 2, 0, &[]).await;
    let sid = ServerId("s0".into());
    let mut user = mk_user("awg-user", false);
    if keys {
        let (private, public) = vpnctl_crypto::gen_wireguard_keypair();
        user.wireguard_private = Some(private);
        user.wireguard_pubkey = Some(public);
    }
    state.inv.add_user(&user).await.unwrap();
    state.inv.grant(&user.id, &sid).await.unwrap();
    for version in [2, 3] {
        state
            .inv
            .add_server_protocol(&sid, &ProtocolId(format!("amneziawg{version}")))
            .await
            .unwrap();
        let (private, public) = vpnctl_crypto::gen_wireguard_keypair();
        for (name, value) in [
            ("server_private_key", private),
            ("server_public_key", public),
            ("profile_seed", STANDARD.encode([version; 32])),
        ] {
            state
                .inv
                .set_server_secret(&sid, &format!("amneziawg{version}.{name}"), &value)
                .await
                .unwrap();
        }
    }
    state
        .inv
        .set_server_secret(
            &sid,
            "amneziawg3.header_protection_key",
            &STANDARD.encode([3; 32]),
        )
        .await
        .unwrap();
    state
}

// Fault injection only in this test's disposable inventory. Python's stdlib
// avoids adding a daemon dependency or exposing the inventory's private pool.
fn mutate_test_database(dir: &TempDir, sql: &str) {
    let status = std::process::Command::new("python3")
        .args(["-c", "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.executescript(sys.argv[2]); c.commit(); c.close()"])
        .arg(dir.path().join("inv.db"))
        .arg(sql)
        .status()
        .unwrap();
    assert!(
        status.success(),
        "temporary database fault injection failed"
    );
}

async fn request(app: axum::Router, path: &str, authenticated: bool) -> Response {
    let mut request = Request::builder().uri(path);
    if authenticated {
        request = request.header(
            "authorization",
            format!(
                "Basic {}",
                STANDARD.encode(format!("{AUTH_USER}:{AUTH_PASSWORD}"))
            ),
        );
    }
    app.oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

async fn text(response: Response) -> String {
    String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

fn download(version: u8) -> String {
    format!("/admin/users/awg-user/amneziawg/{version}/conf/s0")
}

#[tokio::test]
async fn authenticated_native_download_is_no_store_and_read_only() {
    // Set auth only in a child process: no unsafe process-global env mutation,
    // and no contamination of the admin smoke suite's auth-free fixtures.
    const CHILD: &str = "VPNCTL_AWG_AUTH_SMOKE_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "user_detail::amneziawg::authenticated_native_download_is_no_store_and_read_only",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("VPNCTLD_ADMIN_USER", AUTH_USER)
            .env("VPNCTLD_ADMIN_PASSWORD", AUTH_PASSWORD)
            .status()
            .unwrap();
        assert!(status.success(), "isolated authenticated smoke failed");
        return;
    }
    let dir = TempDir::new().unwrap();
    let state = fixture(&dir, true).await;
    let sid = ServerId("s0".into());
    let uid = UserId("awg-user".into());
    let before_user = state.inv.get_user(&uid).await.unwrap().unwrap();
    let before_secrets = state.inv.list_server_secrets(&sid).await.unwrap();
    let app = router(state.clone());
    assert_eq!(
        request(app.clone(), &download(2), false).await.status(),
        StatusCode::UNAUTHORIZED
    );
    for version in [2, 3] {
        let response = request(app.clone(), &download(version), true).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(
            response.headers()["content-type"],
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            response.headers()["content-disposition"],
            format!("attachment; filename=\"awg-user-s0-amneziawg{version}.conf\"")
        );
        let body = text(response).await;
        assert!(body.contains("[Interface]") && body.contains("[Peer]"));
        assert!(body.contains(&format!(
            "PrivateKey = {}",
            before_user.wireguard_private.as_deref().unwrap()
        )));
        assert!(body.contains(&format!(
            "Endpoint = 10.0.0.0:{}",
            51819 + u16::from(version)
        )));
        assert_eq!(body.contains("HeaderProtectionKey ="), version == 3);
        assert_eq!(
            text(request(app.clone(), &download(version), true).await).await,
            body
        );
    }
    let page = text(request(app, "/admin/users/awg-user/delivery", true).await).await;
    assert!(page.contains(&download(2)) && page.contains(&download(3)));
    assert!(page.contains("AmneziaWG 2.0") && page.contains("AmneziaWG 3.1"));
    assert!(!page.contains(before_user.wireguard_private.as_deref().unwrap()));
    let after_user = state.inv.get_user(&uid).await.unwrap().unwrap();
    assert_eq!(before_user.wireguard_private, after_user.wireguard_private);
    assert_eq!(before_user.wireguard_pubkey, after_user.wireguard_pubkey);
    assert_eq!(
        before_secrets,
        state.inv.list_server_secrets(&sid).await.unwrap()
    );
}

#[tokio::test]
async fn stale_urls_and_delivery_obey_every_visibility_gate() {
    for gate in [
        "missing-grant",
        "revoked",
        "disabled-user",
        "disabled-protocol",
        "hidden",
        "override",
        "suppressed",
        "detour",
        "detour-no-entry-grant",
        "wrong-kernel",
        "role",
    ] {
        let dir = TempDir::new().unwrap();
        let state = fixture(&dir, true).await;
        let sid = ServerId("s0".into());
        let uid = UserId("awg-user".into());
        let pid = ProtocolId("amneziawg2".into());
        let app = router(state.clone());
        assert_eq!(
            request(app.clone(), &download(2), true).await.status(),
            StatusCode::OK,
            "fixture: {gate}"
        );
        match gate {
            "missing-grant" | "revoked" => {
                state.inv.revoke(&uid, &sid).await.unwrap();
            }
            "disabled-user" => {
                state.inv.set_user_disabled(&uid, true).await.unwrap();
            }
            "disabled-protocol" => {
                state.inv.remove_server_protocol(&sid, &pid).await.unwrap();
            }
            "hidden" => {
                state
                    .inv
                    .set_server_protocol_hidden(&sid, &pid, true)
                    .await
                    .unwrap();
            }
            "override" => {
                state
                    .inv
                    .set_grant_protocol_override(&uid, &sid, &pid, true)
                    .await
                    .unwrap();
            }
            "suppressed" => {
                state
                    .inv
                    .set_server_auto_suppress(&sid, true)
                    .await
                    .unwrap();
                state.inv.set_server_suppressed(&sid, true).await.unwrap();
            }
            "detour" | "detour-no-entry-grant" => {
                let entry = ServerId("s1".into());
                if gate == "detour" {
                    state.inv.grant(&uid, &entry).await.unwrap();
                }
                state
                    .inv
                    .set_client_detour_via_as("test", &sid, Some(&entry))
                    .await
                    .unwrap();
            }
            "wrong-kernel" => {
                state
                    .inv
                    .remove_server_kernel(&sid, &KernelId("sing-box".into()))
                    .await
                    .unwrap();
            }
            "role" => {
                // Corrupt a legacy row deliberately: normal role mutation refuses
                // existing grants. The read path must still fail closed.
                mutate_test_database(
                    &dir,
                    "DROP TRIGGER trg_workload_role_rejects_grants; UPDATE servers SET role = 'workload-only' WHERE id = 's0';",
                );
            }
            _ => unreachable!(),
        }
        let response = request(app.clone(), &download(2), true).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "gate: {gate}");
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert!(!text(response).await.contains("PrivateKey"));
        let page = text(request(app, "/admin/users/awg-user/delivery", true).await).await;
        assert!(!page.contains(&download(2)), "stale UI bypass: {gate}");
    }
}

#[tokio::test]
async fn missing_entities_and_non_exact_versions_are_rejected() {
    let dir = TempDir::new().unwrap();
    let app = router(fixture(&dir, true).await);
    for path in [
        "/admin/users/missing/amneziawg/2/conf/s0",
        "/admin/users/awg-user/amneziawg/2/conf/missing",
    ] {
        assert_eq!(
            request(app.clone(), path, true).await.status(),
            StatusCode::NOT_FOUND
        );
    }
    for version in ["0", "1", "4", "02", "2.0", "3.1", "256", "latest"] {
        let response = request(
            app.clone(),
            &format!("/admin/users/awg-user/amneziawg/{version}/conf/s0"),
            true,
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "version: {version}"
        );
        assert_eq!(response.headers()["cache-control"], "no-store");
    }
}

#[tokio::test]
async fn missing_keys_never_produce_placeholders_or_generate_on_get() {
    for missing in [
        "both",
        "private",
        "public",
        "mismatched",
        "server-mismatched",
        "server-malformed",
        "server_public_key",
        "server_private_key",
        "profile_seed",
        "header_protection_key",
    ] {
        let dir = TempDir::new().unwrap();
        let state = fixture(&dir, missing != "both").await;
        match missing {
            "both" => {}
            "private" => {
                mutate_test_database(
                    &dir,
                    "UPDATE users SET wireguard_private = NULL WHERE id = 'awg-user';",
                );
            }
            "public" => {
                mutate_test_database(
                    &dir,
                    "UPDATE users SET wireguard_pubkey = NULL WHERE id = 'awg-user';",
                );
            }
            "mismatched" => {
                let uid = UserId("awg-user".into());
                let user = state.inv.get_user(&uid).await.unwrap().unwrap();
                let (unrelated_private, _) = vpnctl_crypto::gen_wireguard_keypair();
                state
                    .inv
                    .set_user_wireguard_keypair(
                        &uid,
                        user.wireguard_pubkey.as_deref().unwrap(),
                        &unrelated_private,
                    )
                    .await
                    .unwrap();
            }
            "server-mismatched" => {
                let (unrelated_private, _) = vpnctl_crypto::gen_wireguard_keypair();
                state
                    .inv
                    .set_server_secret(
                        &ServerId("s0".into()),
                        "amneziawg3.server_private_key",
                        &unrelated_private,
                    )
                    .await
                    .unwrap();
            }
            "server-malformed" => {
                state
                    .inv
                    .set_server_secret(
                        &ServerId("s0".into()),
                        "amneziawg3.server_public_key",
                        "not-a-canonical-key",
                    )
                    .await
                    .unwrap();
            }
            name => {
                state
                    .inv
                    .set_server_secret(&ServerId("s0".into()), &format!("amneziawg3.{name}"), "")
                    .await
                    .unwrap();
            }
        }
        let uid = UserId("awg-user".into());
        let before = state.inv.get_user(&uid).await.unwrap().unwrap();
        let secrets = state
            .inv
            .list_server_secrets(&ServerId("s0".into()))
            .await
            .unwrap();
        let app = router(state.clone());
        let response = request(app.clone(), &download(3), true).await;
        assert_eq!(
            response.status(),
            StatusCode::CONFLICT,
            "missing: {missing}"
        );
        assert_eq!(response.headers()["cache-control"], "no-store");
        let body = text(response).await;
        assert!(!body.contains("[Interface]") && !body.contains("ssh"));
        let page = text(request(app, "/admin/users/awg-user/delivery", true).await).await;
        assert!(
            !page.contains(&download(3)),
            "not-ready download: {missing}"
        );
        assert!(page.contains("File not ready"));
        if matches!(missing, "both" | "private" | "public" | "mismatched") {
            assert!(page.contains("/admin/users/awg-user/wireguard/regenerate"));
        }
        let after = state.inv.get_user(&uid).await.unwrap().unwrap();
        assert_eq!(before.wireguard_private, after.wireguard_private);
        assert_eq!(before.wireguard_pubkey, after.wireguard_pubkey);
        assert_eq!(
            secrets,
            state
                .inv
                .list_server_secrets(&ServerId("s0".into()))
                .await
                .unwrap()
        );
    }
}

#[tokio::test]
async fn visibility_database_errors_fail_closed_without_secret_errors() {
    let dir = TempDir::new().unwrap();
    let state = fixture(&dir, true).await;
    let app = router(state);
    mutate_test_database(&dir, "DROP TABLE grant_protocol_overrides;");
    let response = request(app, &download(2), true).await;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let body = text(response).await;
    assert!(body.contains("Please try again"));
    assert!(!body.contains("grant_protocol_overrides") && !body.contains("PrivateKey"));
}
