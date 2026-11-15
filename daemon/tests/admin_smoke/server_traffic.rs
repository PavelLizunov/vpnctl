use super::common::*;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use tempfile::TempDir;
use tower::ServiceExt;
use vpnctl_core::ServerId;
use vpnctld::router;

async fn post(app: &axum::Router, server: &str, body: &str) -> StatusCode {
    app.clone()
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri(format!("/admin/servers/{server}/traffic-limit")),
            )
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body.to_string()))
            .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn hoster_quota_form_is_optional_and_save_round_trips_exact_bytes_without_noop_audits() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    let inv = s.inv.clone();
    let sid = ServerId("s0".into());
    let app = router(s);
    let html = fetch_html(app.clone(), "/admin/servers/s0/activity").await;
    assert!(html.contains("Hoster limit not configured"));
    assert!(html.contains("name=\"limit\""));
    assert!(html.contains("value=\"\""));
    assert!(!html.contains("remaining:"));
    let body = "limit=4.000000001&unit=TB&direction=tx&reset_day=31&warning_pct=80";
    assert_eq!(post(&app, "s0", body).await, StatusCode::SEE_OTHER);
    let configured = inv.get_server_traffic_limit(&sid).await.unwrap().unwrap();
    assert_eq!(configured.limit_bytes, 4_000_000_001_000);
    assert_eq!(configured.direction, "tx");
    assert_eq!(configured.reset_day, 31);
    let before = inv.recent_audit(100).await.unwrap().len();
    assert_eq!(post(&app, "s0", body).await, StatusCode::SEE_OTHER);
    assert_eq!(before, inv.recent_audit(100).await.unwrap().len());
    let html = fetch_html(app.clone(), "/admin/servers/s0/activity").await;
    assert!(html.contains("value=\"4000.000001000\""));
    assert!(html.contains("remaining quota is unknown"));
    assert!(html.contains("TX (outgoing)"));
    let fleet = fetch_html(app.clone(), "/admin/monitoring").await;
    assert!(fleet.contains("/admin/servers/s0/activity#traffic-limit"));
    assert!(fleet.contains("4000000001000 B"));
    assert_eq!(post(&app, "s0", "limit=").await, StatusCode::SEE_OTHER);
    assert!(inv.get_server_traffic_limit(&sid).await.unwrap().is_none());
}

#[tokio::test]
async fn hoster_quota_rejects_bad_input_unknown_servers_and_cross_origin_mutations() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 0, &[]).await;
    let inv = s.inv.clone();
    let app = router(s);
    for body in [
        "",
        "limit=-4&unit=TB",
        "limit=NaN&unit=TB",
        "limit=4e3&unit=GB",
        "limit=0&unit=TB",
        "limit=99999999999&unit=TB",
        "limit=4&unit=TB&direction=up&reset_day=1&warning_pct=80",
        "limit=4&unit=TB&direction=both&reset_day=0&warning_pct=80",
        "limit=4&unit=TB&direction=both&reset_day=1&warning_pct=101",
    ] {
        assert_eq!(
            post(&app, "s0", body).await,
            StatusCode::BAD_REQUEST,
            "{body}"
        );
    }
    assert!(
        inv.get_server_traffic_limit(&ServerId("s0".into()))
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(post(&app, "missing", "limit=").await, StatusCode::NOT_FOUND);
    let rejected = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/servers/s0/traffic-limit")
                .header("host", SAME_ORIGIN_HOST)
                .header("origin", "https://attacker.example")
                .body(Body::from("limit="))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::FORBIDDEN);
}
