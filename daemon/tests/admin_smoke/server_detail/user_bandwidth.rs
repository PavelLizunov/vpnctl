use axum::body::Body;
use axum::http::{Request, StatusCode};
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{KernelId, ProtocolId, Server, ServerId};
use vpnctld::{AppState, router};

use crate::common::*;

const KEY: &str = "sing-box.user_bandwidth_mbps";
const AUDIT: &str = "server.user_bandwidth.set";

async fn fixture(dir: &TempDir) -> AppState {
    let s = state(dir).await;
    seed(&s.inv, 2, 0, &[]).await;
    s.inv
        .audit("test", "server.deploy", Some("s0"), None)
        .await
        .unwrap();
    s
}

async fn add_caddy_only_server(s: &AppState) {
    s.inv
        .add_server(&Server {
            id: ServerId("caddy-only".into()),
            address: "203.0.113.11".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("caddy".into())],
            enabled_protocols: vec![ProtocolId("naive".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    s.inv
        .audit("test", "server.deploy", Some("caddy-only"), None)
        .await
        .unwrap();
}

async fn post(s: &AppState, id: &str, body: &str) -> axum::response::Response {
    router(s.clone())
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri(format!("/admin/servers/{id}/user-bandwidth"))
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from(body.to_owned()))
            .unwrap(),
        )
        .await
        .unwrap()
}

async fn stored(s: &AppState, id: &str) -> Option<String> {
    s.inv
        .get_server_secret(&ServerId(id.into()), KEY)
        .await
        .unwrap()
}

async fn audit_count(s: &AppState) -> usize {
    s.inv
        .recent_audit(200)
        .await
        .unwrap()
        .iter()
        .filter(|row| row.action == AUDIT)
        .count()
}

async fn pending(s: &AppState, id: &str) -> bool {
    s.inv
        .server_pending_deploy(&ServerId(id.into()))
        .await
        .unwrap()
}

#[tokio::test]
async fn user_bandwidth_save_stores_value_audits_once_and_queues_redeploy() {
    let dir = TempDir::new().unwrap();
    let s = fixture(&dir).await;
    assert_eq!(stored(&s, "s0").await, None);
    assert!(!pending(&s, "s0").await);

    let resp = post(&s, "s0", "mbps=40").await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(stored(&s, "s0").await.as_deref(), Some("40"));
    assert_eq!(audit_count(&s).await, 1);
    let row = s
        .inv
        .recent_audit(200)
        .await
        .unwrap()
        .into_iter()
        .find(|row| row.action == AUDIT)
        .expect("user-bandwidth audit row");
    assert_eq!(row.target.as_deref(), Some("s0"));
    assert!(pending(&s, "s0").await);

    // An identical repost after the queue drains must be a pure no-op.
    s.inv
        .audit("test", "server.deploy", Some("s0"), None)
        .await
        .unwrap();
    assert!(!pending(&s, "s0").await);
    assert_eq!(
        post(&s, "s0", "mbps=40").await.status(),
        StatusCode::SEE_OTHER
    );
    assert_eq!(stored(&s, "s0").await.as_deref(), Some("40"));
    assert_eq!(audit_count(&s).await, 1);
    assert!(!pending(&s, "s0").await);

    // A real change audits and queues again.
    assert_eq!(
        post(&s, "s0", "mbps=250").await.status(),
        StatusCode::SEE_OTHER
    );
    assert_eq!(stored(&s, "s0").await.as_deref(), Some("250"));
    assert_eq!(audit_count(&s).await, 2);
    assert!(pending(&s, "s0").await);
}

#[tokio::test]
async fn user_bandwidth_accepts_bounds_and_rejects_invalid_values_without_mutation() {
    let dir = TempDir::new().unwrap();
    let s = fixture(&dir).await;
    assert!(!pending(&s, "s0").await);

    for body in [
        "mbps=",
        "mbps=-1",
        "mbps=4001",
        "mbps=12.5",
        "mbps=1e3",
        "mbps=0x10",
        "mbps=abc",
        "mbps=99999999999999999999",
    ] {
        assert_eq!(
            post(&s, "s0", body).await.status(),
            StatusCode::BAD_REQUEST,
            "body: {body}"
        );
    }
    assert_eq!(stored(&s, "s0").await, None);
    assert_eq!(audit_count(&s).await, 0);
    assert!(!pending(&s, "s0").await);

    assert_eq!(
        post(&s, "s0", "mbps=4000").await.status(),
        StatusCode::SEE_OTHER
    );
    assert_eq!(stored(&s, "s0").await.as_deref(), Some("4000"));
    assert_eq!(audit_count(&s).await, 1);
    assert!(pending(&s, "s0").await);

    s.inv
        .audit("test", "server.deploy", Some("s0"), None)
        .await
        .unwrap();
    assert!(!pending(&s, "s0").await);
    assert_eq!(
        post(&s, "s0", "mbps=0").await.status(),
        StatusCode::SEE_OTHER
    );
    assert_eq!(stored(&s, "s0").await.as_deref(), Some("0"));
    assert_eq!(audit_count(&s).await, 2);
    assert!(pending(&s, "s0").await);
}

#[tokio::test]
async fn user_bandwidth_requires_sing_box_kernel_without_mutation() {
    let dir = TempDir::new().unwrap();
    let s = fixture(&dir).await;
    add_caddy_only_server(&s).await;
    let before = audit_count(&s).await;

    assert_eq!(
        post(&s, "caddy-only", "mbps=40").await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(stored(&s, "caddy-only").await, None);
    assert_eq!(audit_count(&s).await, before);
    assert!(!pending(&s, "caddy-only").await);
}

#[tokio::test]
async fn user_bandwidth_post_rejects_cross_origin_without_mutation() {
    let dir = TempDir::new().unwrap();
    let s = fixture(&dir).await;

    for origin in [None, Some("https://evil.example")] {
        let mut req = Request::builder()
            .method("POST")
            .uri("/admin/servers/s0/user-bandwidth")
            .header("host", SAME_ORIGIN_HOST)
            .header("content-type", "application/x-www-form-urlencoded");
        if let Some(origin) = origin {
            req = req.header("origin", origin);
        }
        let resp = router(s.clone())
            .oneshot(req.body(Body::from("mbps=40")).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
    assert_eq!(stored(&s, "s0").await, None);
    assert_eq!(audit_count(&s).await, 0);
    assert!(!pending(&s, "s0").await);
}

#[tokio::test]
async fn user_bandwidth_control_renders_on_sing_box_protocols_tab_only() {
    let dir = TempDir::new().unwrap();
    let s = fixture(&dir).await;
    add_caddy_only_server(&s).await;

    let html = fetch_html(router(s.clone()), "/admin/servers/s0/protocols").await;
    let form = html
        .split_once(r#"action="/admin/servers/s0/user-bandwidth""#)
        .expect("protocols tab must offer the user-bandwidth form on a sing-box node")
        .1
        .split_once("</form>")
        .unwrap()
        .0;
    assert!(form.contains(r#"name="mbps""#));
    assert!(form.contains(r#"type="number""#));
    assert!(form.contains(r#"min="0""#));
    assert!(form.contains(r#"max="4000""#));
    assert!(form.contains("Mbit/s"));

    assert_eq!(
        post(&s, "s0", "mbps=250").await.status(),
        StatusCode::SEE_OTHER
    );
    let html = fetch_html(router(s.clone()), "/admin/servers/s0/protocols").await;
    let form = html
        .split_once(r#"action="/admin/servers/s0/user-bandwidth""#)
        .unwrap()
        .1
        .split_once("</form>")
        .unwrap()
        .0;
    assert!(form.contains(r#"value="250""#));

    let other = fetch_html(router(s), "/admin/servers/caddy-only/protocols").await;
    assert!(!other.contains("/admin/servers/caddy-only/user-bandwidth"));
}
