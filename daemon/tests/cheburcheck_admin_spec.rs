//! Admin behavior derived from docs/specs/cheburcheck.md.
//! Every upstream request is handled by a fresh loopback fixture.

#[cfg(test)]
#[path = "common/cheburcheck_http.rs"]
mod cheburcheck_http;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod spec {
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;

    use super::cheburcheck_http::{HttpFixture, HttpResponse};

    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use serde_json::{Value, json};
    use tempfile::TempDir;
    use tower::ServiceExt;
    use vpnctl_core::{Registry, Server, ServerId};
    use vpnctl_inventory::SqliteInventory;
    use vpnctld::cheburcheck::Client;

    const NODE: &str = "fixture-node";
    const ADDRESS: &str = "198.51.100.9";
    const REMOTE_REGION: &str = "<img src=x onerror=alert(1)>";
    const REMOTE_PROVIDER: &str = "<script>alert('remote')</script>";

    fn upstream(blocked: bool) -> HttpFixture {
        HttpFixture::from_handler(blocked, |request, _| {
            let (status, content_type, body) = if request.starts_with("GET /api/v1/check?") {
                (
                    "200 OK",
                    "application/json",
                    json!({
                        "id": "fixture-signed-context",
                        "target": ADDRESS,
                        "blocked": false,
                        "blocked_subnets": [],
                        "cdn_providers": {},
                        "subscription_url": "https://credential.invalid/private-subscription-token"
                    })
                    .to_string(),
                )
            } else if request.starts_with("GET /api/v1/probe/fixture-signed-context ") {
                let result = json!({
                    "probe_id": "private-observer-id",
                    "cached": true,
                    "region": REMOTE_REGION,
                    "provider": REMOTE_PROVIDER,
                    "asn": "AS64500",
                    "verdicts": ["tspu_block"],
                    "target_hop": null,
                    "dpi_hop": 2
                });
                (
                    "200 OK",
                    "text/event-stream",
                    format!(
                        "event: started\ndata: {{\"online_probes\":1}}\n\nevent: result\ndata: {result}\n\nevent: done\ndata: {{\"response_count\":1,\"online_probes\":1}}\n\n"
                    ),
                )
            } else {
                (
                    "400 Bad Request",
                    "text/plain",
                    "fixture rejected request".to_owned(),
                )
            };
            HttpResponse::new(
                status,
                &format!("Content-Type: {content_type}\r\n"),
                body.into_bytes(),
            )
        })
    }

    struct Harness {
        _temp: TempDir,
        path: PathBuf,
        upstream: HttpFixture,
    }

    struct App {
        router: axum::Router,
        worker: tokio::task::JoinHandle<()>,
    }

    impl Drop for App {
        fn drop(&mut self) {
            self.worker.abort();
        }
    }

    impl Harness {
        async fn new(blocked: bool) -> Self {
            let temp = tempfile::tempdir().expect("fresh inventory directory");
            let path = temp.path().join("inventory.sqlite");
            SqliteInventory::open(&path)
                .await
                .expect("initialize fresh inventory");
            Self {
                _temp: temp,
                path,
                upstream: upstream(blocked),
            }
        }

        async fn inventory(&self) -> SqliteInventory {
            SqliteInventory::open(&self.path)
                .await
                .expect("open fixture inventory")
        }

        async fn add_server(&self, id: &str, address: &str) {
            self.inventory()
                .await
                .add_server(&Server {
                    id: ServerId(id.to_owned()),
                    address: address.to_owned(),
                    ssh_port: 22,
                    ssh_user: "fixture-user".to_owned(),
                    kernels: Vec::new(),
                    enabled_protocols: Vec::new(),
                    trusted_host_fingerprint: None,
                    hoster: "fixture".to_owned(),
                    jump_via: None,
                    usage_coefficient: 1.0,
                })
                .await
                .expect("configured inventory server");
        }

        async fn app(&self) -> App {
            let client =
                Client::for_base_url(&self.upstream.base_url).expect("injected loopback client");
            let (state, worker) = vpnctld::make_app_state_with_cheburcheck_for_tests(
                self.inventory().await,
                Arc::new(Registry::new()),
                client,
            );
            App {
                router: vpnctld::router(state),
                worker,
            }
        }

        async fn wait_for_result(&self, app: &App, id: &str) -> vpnctl_inventory::AuditEntry {
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let response = get(app, &format!("/admin/servers/{id}/cheburcheck")).await;
                    assert_eq!(response.status(), StatusCode::OK);
                    let _ = html(response).await;
                    if let Some(result) = self
                        .inventory()
                        .await
                        .latest_audit_for_target_action(id, "server.cheburcheck.result")
                        .await
                        .expect("read completed result")
                    {
                        return result;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("loopback runner completes within bounded GET polling")
        }
    }

    async fn get(app: &App, path: &str) -> axum::response::Response {
        app.router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header("host", "localhost")
                    .body(Body::empty())
                    .expect("GET request"),
            )
            .await
            .expect("GET response")
    }

    async fn post(app: &App, path: &str, origin: &str, body: &str) -> axum::response::Response {
        app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("host", "localhost")
                    .header("origin", origin)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(body.to_owned()))
                    .expect("POST request"),
            )
            .await
            .expect("POST response")
    }

    async fn html(response: axum::response::Response) -> String {
        String::from_utf8(
            to_bytes(response.into_body(), 2 * 1024 * 1024)
                .await
                .expect("bounded HTML body")
                .to_vec(),
        )
        .expect("UTF-8 HTML")
    }

    fn saved_payload(run_id: &str, address: &str, completed: bool) -> Value {
        json!({
            "run_id": run_id,
            "address": address,
            "inventory_address": address,
            "started_at": "2026-01-01T00:00:00Z",
            "finished_at": if completed { json!("2026-01-01T00:00:10Z") } else { Value::Null },
            "report": if completed { json!({
                "list": {"blocked": false, "blocked_subnets": [], "providers": []},
                "dynamic": {"phase": "done", "online_probes": 1, "reports": [{
                    "region": "Saved region",
                    "provider": "Saved provider",
                    "asn": "AS64500",
                    "cached": false,
                    "verdicts": ["tspu_block"],
                    "target_hop": null,
                    "dpi_hop": 2
                }]},
                "failure": null
            }) } else { Value::Null }
        })
    }

    async fn seed(harness: &Harness, action: &str, payload: &Value) {
        harness
            .inventory()
            .await
            .audit("spec-test", action, Some(NODE), Some(payload))
            .await
            .expect("seed journal row");
    }

    #[tokio::test]
    async fn get_pages_are_inventory_only_and_never_start_external_work() {
        let harness = Harness::new(false).await;
        harness.add_server(NODE, ADDRESS).await;
        let app = harness.app().await;
        for path in [
            "/admin/monitoring/cheburcheck",
            "/admin/servers/fixture-node/cheburcheck",
        ] {
            let response = get(&app, path).await;
            assert_eq!(response.status(), StatusCode::OK);
            let body = html(response).await;
            assert!(body.contains(ADDRESS));
            assert!(body.to_lowercase().contains("cheburcheck"));
            if path == "/admin/monitoring/cheburcheck" {
                assert!(body.contains("/admin/servers/fixture-node/cheburcheck"));
            }
        }
        assert!(harness.upstream.requests().is_empty());
        let inv = harness.inventory().await;
        assert!(
            inv.latest_audit_for_target_action(NODE, "server.cheburcheck.started")
                .await
                .expect("no start row")
                .is_none()
        );
        assert!(
            inv.latest_audit_for_target_action(NODE, "server.cheburcheck.result")
                .await
                .expect("no result row")
                .is_none()
        );
    }

    #[tokio::test]
    async fn missing_servers_return_404_without_external_work_or_audit() {
        let harness = Harness::new(false).await;
        let app = harness.app().await;
        assert_eq!(
            get(&app, "/admin/servers/missing/cheburcheck")
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            post(
                &app,
                "/admin/servers/missing/cheburcheck",
                "http://localhost",
                ""
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );
        assert!(harness.upstream.requests().is_empty());
        assert!(
            harness
                .inventory()
                .await
                .latest_audit_for_target_action("missing", "server.cheburcheck.started")
                .await
                .expect("no rejected-start audit")
                .is_none()
        );
    }

    #[tokio::test]
    async fn private_unsupported_and_unresolved_targets_return_422_without_network() {
        let harness = Harness::new(false).await;
        let addresses = [
            "10.0.0.1",
            "127.0.0.1",
            "::1",
            "vpn.example.invalid",
            "https://user:secret@198.51.100.9/private-subscription-token",
            "198.51.100.9:443",
            "198.51.100.9,203.0.113.9",
        ];
        for (index, address) in addresses.iter().enumerate() {
            harness
                .add_server(&format!("invalid-{index}"), address)
                .await;
        }
        let app = harness.app().await;
        for (index, address) in addresses.iter().enumerate() {
            let id = format!("invalid-{index}");
            let response = post(
                &app,
                &format!("/admin/servers/{id}/cheburcheck"),
                "http://localhost",
                "target=198.51.100.9",
            )
            .await;
            assert_eq!(
                response.status(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "{}",
                address
            );
            let error_body = html(response).await;
            for private in ["private-subscription-token", "user:secret"] {
                assert!(!error_body.contains(private));
            }
            for path in [
                format!("/admin/servers/{id}/cheburcheck"),
                "/admin/monitoring/cheburcheck".to_owned(),
            ] {
                let body = html(get(&app, &path).await).await;
                for private in ["private-subscription-token", "user:secret"] {
                    assert!(!body.contains(private), "private address text on {path}");
                }
            }
            assert!(
                harness
                    .inventory()
                    .await
                    .latest_audit_for_target_action(&id, "server.cheburcheck.started")
                    .await
                    .expect("no invalid-target audit")
                    .is_none()
            );
        }
        assert!(harness.upstream.requests().is_empty());
    }

    #[tokio::test]
    async fn cross_origin_post_is_forbidden_before_network_or_audit() {
        let harness = Harness::new(false).await;
        harness.add_server(NODE, ADDRESS).await;
        let app = harness.app().await;
        let response = post(
            &app,
            "/admin/servers/fixture-node/cheburcheck",
            "https://evil.invalid",
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(harness.upstream.requests().is_empty());
        assert!(
            harness
                .inventory()
                .await
                .latest_audit_for_target_action(NODE, "server.cheburcheck.started")
                .await
                .expect("no cross-origin audit")
                .is_none()
        );
    }

    #[tokio::test]
    async fn accepted_post_uses_inventory_ip_and_persists_safe_results_across_app_state() {
        let harness = Harness::new(false).await;
        harness.add_server(NODE, ADDRESS).await;
        let app = harness.app().await;
        let response = post(&app, "/admin/servers/fixture-node/cheburcheck?target=203.0.113.7&base_url=https://evil.invalid", "http://localhost", "target=203.0.113.7&subscription=https://credential.invalid/private-subscription-token").await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response
                .headers()
                .get("location")
                .expect("redirect location"),
            "/admin/servers/fixture-node/cheburcheck"
        );
        let result = harness.wait_for_result(&app, NODE).await;
        let start = harness
            .inventory()
            .await
            .latest_audit_for_target_action(NODE, "server.cheburcheck.started")
            .await
            .expect("start lookup")
            .expect("persisted start");
        let start_payload = start.payload.as_ref().expect("start payload");
        let result_payload = result.payload.as_ref().expect("result payload");
        assert_eq!(start_payload["run_id"], result_payload["run_id"]);
        assert!(start_payload["started_at"].is_string());
        assert_eq!(start_payload["inventory_address"], ADDRESS);
        assert_eq!(result_payload["inventory_address"], ADDRESS);
        assert_eq!(result_payload["address"], ADDRESS);
        assert!(result_payload["finished_at"].is_string());
        assert_eq!(result_payload["report"]["list"]["blocked"], false);
        assert_eq!(result_payload["report"]["dynamic"]["phase"], "done");
        let payload = result_payload.to_string();
        for private in [
            "fixture-signed-context",
            "private-observer-id",
            "private-subscription-token",
        ] {
            assert!(!payload.contains(private));
        }
        let requests = harness.upstream.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].starts_with("GET /api/v1/check?target=198.51.100.9 HTTP/1.1\r\n"));
        assert!(
            requests
                .iter()
                .all(|request| !request.contains("203.0.113.7")
                    && !request.contains("private-subscription-token"))
        );
        drop(app);
        let restored = harness.app().await;
        let response = get(&restored, "/admin/servers/fixture-node/cheburcheck").await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = html(response).await;
        assert!(body.contains(ADDRESS));
        assert!(body.to_lowercase().contains("tspu"));
        assert!(body.to_lowercase().contains("cached") || body.to_lowercase().contains("кэш"));
        assert!(!body.contains(REMOTE_REGION));
        assert!(!body.contains(REMOTE_PROVIDER));
        assert!(body.contains("&lt;img"));
        assert!(body.contains("&lt;script&gt;"));
        for private in [
            "fixture-signed-context",
            "private-observer-id",
            "private-subscription-token",
        ] {
            assert!(!body.contains(private));
        }
        assert_eq!(
            harness.upstream.requests().len(),
            2,
            "restored GET uses persisted result"
        );
    }

    #[tokio::test]
    async fn concurrent_gets_during_completion_never_report_false_interruption() {
        async fn read_state(router: axum::Router) -> bool {
            let response = router
                .oneshot(
                    Request::builder()
                        .uri("/admin/servers/fixture-node/cheburcheck")
                        .header("host", "localhost")
                        .body(Body::empty())
                        .expect("concurrent GET request"),
                )
                .await
                .expect("concurrent GET response");
            assert_eq!(response.status(), StatusCode::OK);
            let body = html(response).await;
            let id = body
                .find("id=\"cheburcheck-checks\"")
                .expect("public check-state container");
            let start = body[..id].rfind('<').expect("container opening tag");
            let end = id + body[id..].find('>').expect("container tag end");
            let container = &body[start..=end];
            assert!(
                !container.contains("data-state=\"interrupted\""),
                "normal completion must not appear interrupted: {container}"
            );
            let running = container.contains("data-state=\"running\"");
            let finished = container.contains("data-state=\"finished\"");
            assert!(
                running ^ finished,
                "an accepted live run must be running or finished: {container}"
            );
            finished
        }

        let harness = Harness::new(true).await;
        harness.add_server(NODE, ADDRESS).await;
        let app = harness.app().await;
        assert_eq!(
            post(
                &app,
                "/admin/servers/fixture-node/cheburcheck",
                "http://localhost",
                ""
            )
            .await
            .status(),
            StatusCode::SEE_OTHER
        );
        assert!(!read_state(app.router.clone()).await);

        tokio::time::timeout(Duration::from_secs(10), async {
            const READERS: usize = 8;
            let ready = Arc::new(tokio::sync::Barrier::new(READERS + 1));
            let mut readers = tokio::task::JoinSet::new();
            for _ in 0..READERS {
                let router = app.router.clone();
                let ready = Arc::clone(&ready);
                readers.spawn(async move {
                    assert!(!read_state(router.clone()).await);
                    ready.wait().await;
                    let mut running_reads = 1;
                    let mut finished_reads = 0;
                    for round in 0..64 {
                        if read_state(router.clone()).await {
                            finished_reads += 1;
                        } else {
                            running_reads += 1;
                        }
                        if round >= 7 && finished_reads > 0 {
                            return (running_reads, finished_reads);
                        }
                        tokio::task::yield_now().await;
                    }
                    panic!("concurrent GETs did not observe normal completion");
                });
            }

            ready.wait().await;
            tokio::task::yield_now().await;
            harness.upstream.release();
            let mut running_reads = 0;
            let mut finished_reads = 0;
            while let Some(reader) = readers.join_next().await {
                let (running, finished) = reader.expect("concurrent state reader");
                running_reads += running;
                finished_reads += finished;
            }
            assert!(running_reads >= READERS);
            assert!(finished_reads >= READERS);
        })
        .await
        .expect("concurrent completion observation is bounded");

        assert!(read_state(app.router.clone()).await);
        assert!(
            harness
                .inventory()
                .await
                .latest_audit_for_target_action(NODE, "server.cheburcheck.result")
                .await
                .expect("completed result lookup")
                .is_some()
        );
        assert_eq!(harness.upstream.requests().len(), 2);
    }

    #[tokio::test]
    async fn a_busy_start_is_global_and_rejection_does_not_write_another_start() {
        let harness = Harness::new(true).await;
        harness.add_server(NODE, ADDRESS).await;
        harness.add_server("second-node", "203.0.113.10").await;
        let app = harness.app().await;
        assert_eq!(
            post(
                &app,
                "/admin/servers/fixture-node/cheburcheck",
                "http://localhost",
                ""
            )
            .await
            .status(),
            StatusCode::SEE_OTHER
        );
        let first = harness
            .inventory()
            .await
            .latest_audit_for_target_action(NODE, "server.cheburcheck.started")
            .await
            .expect("first start")
            .expect("accepted start row");
        assert_eq!(
            post(
                &app,
                "/admin/servers/second-node/cheburcheck",
                "http://localhost",
                ""
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            post(
                &app,
                "/admin/servers/fixture-node/cheburcheck",
                "http://localhost",
                ""
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        let unchanged = harness
            .inventory()
            .await
            .latest_audit_for_target_action(NODE, "server.cheburcheck.started")
            .await
            .expect("start after rejection")
            .expect("retained first start");
        assert_eq!(unchanged.id, first.id);
        assert!(
            harness
                .inventory()
                .await
                .latest_audit_for_target_action("second-node", "server.cheburcheck.started")
                .await
                .expect("no second start")
                .is_none()
        );
        harness.upstream.release();
        harness.wait_for_result(&app, NODE).await;
        assert_eq!(harness.upstream.requests().len(), 2);
    }

    #[tokio::test]
    async fn cooldown_returns_bounded_retry_after_and_retains_the_result() {
        let harness = Harness::new(false).await;
        harness.add_server(NODE, ADDRESS).await;
        let app = harness.app().await;
        assert_eq!(
            post(
                &app,
                "/admin/servers/fixture-node/cheburcheck",
                "http://localhost",
                ""
            )
            .await
            .status(),
            StatusCode::SEE_OTHER
        );
        let result = harness.wait_for_result(&app, NODE).await;
        let start = harness
            .inventory()
            .await
            .latest_audit_for_target_action(NODE, "server.cheburcheck.started")
            .await
            .expect("start lookup")
            .expect("start row");
        let response = post(
            &app,
            "/admin/servers/fixture-node/cheburcheck",
            "http://localhost",
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        let retry: u32 = response
            .headers()
            .get("retry-after")
            .expect("cooldown retry header")
            .to_str()
            .expect("numeric header text")
            .parse()
            .expect("retry seconds");
        assert!((1..=15).contains(&retry));
        let inv = harness.inventory().await;
        assert_eq!(
            inv.latest_audit_for_target_action(NODE, "server.cheburcheck.started")
                .await
                .expect("retained start")
                .expect("start")
                .id,
            start.id
        );
        assert_eq!(
            inv.latest_audit_for_target_action(NODE, "server.cheburcheck.result")
                .await
                .expect("retained result")
                .expect("result")
                .id,
            result.id
        );
        assert_eq!(harness.upstream.requests().len(), 2);
    }

    #[tokio::test]
    async fn old_results_are_stale_without_starting_network_work() {
        let harness = Harness::new(false).await;
        harness.add_server(NODE, ADDRESS).await;
        seed(
            &harness,
            "server.cheburcheck.result",
            &saved_payload("old-run", ADDRESS, true),
        )
        .await;
        let app = harness.app().await;
        let response = get(&app, "/admin/servers/fixture-node/cheburcheck").await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = html(response).await.to_lowercase();
        assert!(body.contains("stale") || body.contains("устар"));
        assert!(body.contains("saved region"));
        assert!(harness.upstream.requests().is_empty());
    }

    #[tokio::test]
    async fn changed_inventory_address_is_distinguished_from_a_fresh_result() {
        let harness = Harness::new(false).await;
        harness.add_server(NODE, ADDRESS).await;
        seed(
            &harness,
            "server.cheburcheck.result",
            &saved_payload("old-address-run", "198.51.100.8", true),
        )
        .await;
        let app = harness.app().await;
        let response = get(&app, "/admin/servers/fixture-node/cheburcheck").await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = html(response).await.to_lowercase();
        assert!(
            (body.contains("address") && body.contains("changed"))
                || (body.contains("адрес") && body.contains("измен"))
        );
        assert!(body.contains("198.51.100.8"));
        assert!(body.contains(ADDRESS));
        assert!(harness.upstream.requests().is_empty());
    }

    #[tokio::test]
    async fn latest_unmatched_start_is_interrupted_after_reconstruction() {
        let harness = Harness::new(false).await;
        harness.add_server(NODE, ADDRESS).await;
        seed(
            &harness,
            "server.cheburcheck.result",
            &saved_payload("previous-finished-run", ADDRESS, true),
        )
        .await;
        seed(
            &harness,
            "server.cheburcheck.started",
            &saved_payload("new-unfinished-run", ADDRESS, false),
        )
        .await;
        let app = harness.app().await;
        let response = get(&app, "/admin/servers/fixture-node/cheburcheck").await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = html(response).await.to_lowercase();
        assert!(body.contains("interrupted") || body.contains("прерван"));
        assert!(harness.upstream.requests().is_empty());
    }

    #[tokio::test]
    async fn latest_audit_lookup_matches_exact_target_and_action_and_newest_id() {
        let harness = Harness::new(false).await;
        let inv = harness.inventory().await;
        assert!(
            inv.latest_audit_for_target_action(NODE, "server.cheburcheck.started")
                .await
                .expect("empty exact lookup")
                .is_none()
        );
        inv.audit(
            "spec-test",
            "server.cheburcheck.started",
            Some(NODE),
            Some(&json!({"version": 1})),
        )
        .await
        .expect("first exact row");
        let first = inv
            .latest_audit_for_target_action(NODE, "server.cheburcheck.started")
            .await
            .expect("first lookup")
            .expect("first exact row");
        inv.audit(
            "spec-test",
            "server.cheburcheck.started",
            Some("fixture-node-extra"),
            Some(&json!({"version": 99})),
        )
        .await
        .expect("near target");
        inv.audit(
            "spec-test",
            "server.cheburcheck.started.extra",
            Some(NODE),
            Some(&json!({"version": 99})),
        )
        .await
        .expect("near action");
        inv.audit(
            "spec-test",
            "server.cheburcheck.started",
            Some("prefix-fixture-node"),
            Some(&json!({"version": 99})),
        )
        .await
        .expect("substring target");
        let still_first = inv
            .latest_audit_for_target_action(NODE, "server.cheburcheck.started")
            .await
            .expect("exact lookup")
            .expect("exact row");
        assert_eq!(still_first.id, first.id);
        inv.audit(
            "spec-test",
            "server.cheburcheck.started",
            Some(NODE),
            Some(&json!({"version": 2})),
        )
        .await
        .expect("newest exact row");
        let newest = inv
            .latest_audit_for_target_action(NODE, "server.cheburcheck.started")
            .await
            .expect("newest lookup")
            .expect("newest exact row");
        assert!(newest.id > first.id);
        assert_eq!(newest.target.as_deref(), Some(NODE));
        assert_eq!(newest.action, "server.cheburcheck.started");
        assert_eq!(newest.payload.expect("newest payload")["version"], 2);
        assert!(
            inv.latest_audit_for_target_action("missing", "server.cheburcheck.started")
                .await
                .expect("missing lookup")
                .is_none()
        );
    }
}
