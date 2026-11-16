#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod spec {
    use std::net::{IpAddr, SocketAddr};
    use std::sync::{Arc, Mutex};

    use axum::Router;
    use axum::body::{Body, to_bytes};
    use axum::extract::{ConnectInfo, State};
    use axum::http::{Request, StatusCode};
    use axum::response::Response;
    use axum::routing::any;
    use base64::Engine;
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use tower::ServiceExt;
    use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
    use vpnctl_inventory::{
        CorpCredentials, CorpReaderToken, CorpSessionInput, CorpSetup, CorpSigningKey,
        CorpVerifiedEgress, SqliteInventory,
    };
    use vpnctld::app;
    use vpnctld::corp_policy::PolicySigningKey;
    use vpnctld::corp_portal::{diagnostics::Client, eligibility};

    const HOST: &str = "admin.corp.ninitux.com";
    const ORIGIN: &str = "https://admin.corp.ninitux.com";
    const TOKEN: &str = "synthetic-service-token-01234567890123456789";
    const SESSION: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
    const CSRF: &str = "ccccccccccccccccccccccccccccccccccccccccccc";
    const REPORT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const EXIT: &str = "198.51.100.27";
    const PRIVATE_MARKER: &str = "PRIVATE_UPSTREAM_FIELD_MUST_NOT_ESCAPE";

    type Capture = Arc<Mutex<Vec<(String, axum::http::HeaderMap, Vec<u8>)>>>;

    struct Mock {
        url: String,
        requests: Capture,
        job: tokio::task::JoinHandle<()>,
    }
    impl Drop for Mock {
        fn drop(&mut self) {
            self.job.abort();
        }
    }
    async fn mock(status: StatusCode, body: String) -> Mock {
        async fn reply(
            State((capture, status, body)): State<(Capture, StatusCode, String)>,
            req: Request<Body>,
        ) -> Response {
            let (parts, stream) = req.into_parts();
            let bytes = to_bytes(stream, 65536).await.unwrap();
            capture
                .lock()
                .unwrap()
                .push((parts.uri.to_string(), parts.headers, bytes.to_vec()));
            Response::builder()
                .status(status)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap()
        }
        let requests = Arc::new(Mutex::new(Vec::new()));
        let router =
            Router::new()
                .fallback(any(reply))
                .with_state((Arc::clone(&requests), status, body));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let job = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        Mock { url, requests, job }
    }

    struct Fixture {
        router: Router,
        inv: SqliteInventory,
        job: tokio::task::JoinHandle<()>,
        _dir: tempfile::TempDir,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            self.job.abort();
        }
    }
    async fn fixture(upstream: Option<&Mock>) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let inv = SqliteInventory::open(&dir.path().join("inventory.db"))
            .await
            .unwrap();
        let user = User {
            id: UserId("diagnostics-spec-user".into()),
            uuid: "15450643-1c7b-4a5f-aa91-9454c13f84ae".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        };
        let server = Server {
            id: ServerId("diagnostics-spec-server".into()),
            address: "192.0.2.71".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![ProtocolId("vless+reality".into())],
            trusted_host_fingerprint: None,
            hoster: "synthetic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        };
        inv.add_user(&user).await.unwrap();
        inv.add_server(&server).await.unwrap();
        inv.grant(&user.id, &server.id).await.unwrap();
        let public = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]);
        for (key, value) in [
            ("vless.public_key", public.as_str()),
            ("vless.short_id", "12345678"),
            ("vless.sni", "www.example.com"),
        ] {
            inv.set_server_secret(&server.id, key, value).await.unwrap();
        }
        let signer = PolicySigningKey::generate().unwrap();
        let creds = CorpCredentials {
            password_phc: "$argon2id$v=19$m=8192,t=1,p=1$c3ludGhldGljc2FsdDEyMw$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            reader_tokens: vec![CorpReaderToken { id: "reader".into(), token: "synthetic-reader-token-01234567890123456789".into() }],
            signing_keys: vec![CorpSigningKey { id: "signer".into(), pkcs8: base64::engine::general_purpose::STANDARD.encode(signer.export_pkcs8_der().unwrap().as_bytes()), spki: signer.spki_base64().unwrap() }],
            active_key_id: "signer".into(),
        };
        let created = inv
            .create_corp(
                &CorpSetup {
                    user_id: user.id.clone(),
                    policy_id: "diagnostics-spec".into(),
                    credentials: creds.clone(),
                },
                "spec",
            )
            .await
            .unwrap();
        inv.update_corp_security(created.config_version, true, &creds, "spec")
            .await
            .unwrap();
        let (mut state, job) = app::make_app_state_for_tests(
            inv.clone(),
            Arc::new(vpnctl_kernels::build_registry().unwrap()),
        );
        let candidates = eligibility::eligible_servers(&state, &user.id)
            .await
            .unwrap();
        assert_eq!(candidates.len(), 1);
        let status = inv.corp_record().await.unwrap().unwrap().status;
        let status = inv
            .replace_corp_egress(
                status.config_version,
                &[CorpVerifiedEgress {
                    server_id: server.id,
                    ip: EXIT.parse().unwrap(),
                    configuration_fingerprint: candidates[0].configuration_fingerprint.clone(),
                    verified_at: chrono::Utc::now().timestamp(),
                }],
                "spec",
            )
            .await
            .unwrap();
        inv.issue_corp_session(
            status.auth_generation,
            &CorpSessionInput {
                token_hash: format!("{:x}", Sha256::digest(SESSION.as_bytes())),
                csrf_token: CSRF.into(),
                expires_at: chrono::Utc::now().timestamp() + 3600,
            },
            chrono::Utc::now().timestamp(),
            "spec",
        )
        .await
        .unwrap();
        state.corp_diagnostics =
            upstream.map(|mock| Arc::new(Client::new(&mock.url, TOKEN).unwrap()));
        Fixture {
            router: app::router(state),
            inv,
            job,
            _dir: dir,
        }
    }
    fn request(
        method: &str,
        path: &str,
        session: bool,
        peer: Option<&str>,
        csrf: Option<&str>,
        origin: Option<&str>,
    ) -> Request<Body> {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("host", HOST);
        if session {
            builder = builder.header("cookie", format!("__Host-vpnctl_corp={SESSION}"));
        }
        if let Some(csrf) = csrf {
            builder = builder.header("x-corp-csrf", csrf);
        }
        if let Some(origin) = origin {
            builder = builder.header("origin", origin);
        }
        let mut req = builder
            .header("content-type", "application/json")
            .body(Body::from(if method == "POST" { "{}" } else { "" }))
            .unwrap();
        if let Some(ip) = peer {
            req.extensions_mut().insert(ConnectInfo(SocketAddr::new(
                ip.parse::<IpAddr>().unwrap(),
                40123,
            )));
        }
        req
    }
    async fn body(response: Response) -> Value {
        serde_json::from_slice(&to_bytes(response.into_body(), 300_000).await.unwrap()).unwrap()
    }
    fn summary() -> Value {
        json!({"report_id":REPORT,"received_utc":"2026-11-16T12:00:00Z","bytes":1234,"device_label":"Клиент сообщил имя","analysis_state":"ready","verdict":"insufficient_data","summary_ru":"Недостаточно данных","model":"synthetic-model","updated_utc":"2026-11-16T12:01:00Z"})
    }

    #[test]
    fn client_configuration_allows_only_safe_deployment_urls_and_bearers() {
        for url in [
            "http://127.0.0.1:3210",
            "http://[::1]:3210",
            "http://10.23.4.5",
            "http://192.168.2.3",
            "http://172.16.4.5",
            "https://receiver.example.com",
        ] {
            assert!(
                Client::new(url, TOKEN).is_ok(),
                "valid synthetic deployment URL {url}"
            );
        }
        for url in [
            "http://receiver.example.com",
            "http://8.8.8.8",
            "http://172.32.0.1",
            "http://localhost",
            "https://user:password@receiver.example.com",
            "https://receiver.example.com?token=private",
            "https://receiver.example.com#private",
            "ftp://receiver.example.com",
            "not a URL",
        ] {
            assert!(Client::new(url, TOKEN).is_err(), "must reject {url}");
        }
        for token in [
            "".to_owned(),
            "x".repeat(31),
            "x".repeat(513),
            "x y".repeat(16),
            format!("{}\r\nInjected: true", "x".repeat(32)),
            "я".repeat(32),
        ] {
            assert!(Client::new("http://127.0.0.1", &token).is_err());
        }
        for length in [32, 512] {
            assert!(Client::new("http://127.0.0.1", &"x".repeat(length)).is_ok());
        }
        let debug = format!("{:?}", Client::new("http://127.0.0.1", TOKEN).unwrap());
        assert!(!debug.contains(TOKEN));
    }

    #[tokio::test]
    async fn missing_session_peer_or_eligible_exit_never_contacts_upstream() {
        let upstream = mock(
            StatusCode::OK,
            json!({"schema":1,"reports":[],"next_cursor":null}).to_string(),
        )
        .await;
        let f = fixture(Some(&upstream)).await;
        for path in [
            "/api/corp/reports".to_owned(),
            format!("/api/corp/reports/{REPORT}"),
            format!("/api/corp/reports/{REPORT}/retry"),
        ] {
            let method = if path.ends_with("retry") {
                "POST"
            } else {
                "GET"
            };
            for (session, peer) in [
                (false, Some(EXIT)),
                (true, None),
                (true, Some("198.51.100.99")),
            ] {
                let response = f
                    .router
                    .clone()
                    .oneshot(request(
                        method,
                        &path,
                        session,
                        peer,
                        Some(CSRF),
                        Some(ORIGIN),
                    ))
                    .await
                    .unwrap();
                assert!(response.status().is_client_error());
            }
        }
        assert!(upstream.requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn retry_requires_origin_and_session_csrf_before_upstream() {
        let upstream = mock(
            StatusCode::ACCEPTED,
            json!({"schema":1,"state":"pending"}).to_string(),
        )
        .await;
        let f = fixture(Some(&upstream)).await;
        for (csrf, origin) in [
            (None, Some(ORIGIN)),
            (Some("forged"), Some(ORIGIN)),
            (Some(CSRF), None),
            (Some(CSRF), Some("https://evil.example")),
        ] {
            let response = f
                .router
                .clone()
                .oneshot(request(
                    "POST",
                    &format!("/api/corp/reports/{REPORT}/retry"),
                    true,
                    Some(EXIT),
                    csrf,
                    origin,
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }
        assert!(upstream.requests.lock().unwrap().is_empty());
        let response = f
            .router
            .clone()
            .oneshot(request(
                "POST",
                &format!("/api/corp/reports/{REPORT}/retry"),
                true,
                Some(EXIT),
                Some(CSRF),
                Some(ORIGIN),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(body(response).await, json!({"schema":1,"state":"pending"}));
        let requests = upstream.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].0,
            format!("/internal/corp-diagnostics/reports/{REPORT}/retry")
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&requests[0].2).unwrap(),
            json!({})
        );
    }

    #[tokio::test]
    async fn authenticated_list_forwards_only_service_capability_and_filters_unknown_fields() {
        let mut item = summary();
        item["raw_archive_url"] = json!(PRIVATE_MARKER);
        let upstream = mock(
            StatusCode::OK,
            json!({"schema":1,"reports":[item],"next_cursor":null,"credentials":PRIVATE_MARKER})
                .to_string(),
        )
        .await;
        let f = fixture(Some(&upstream)).await;
        let mut req = request(
            "GET",
            "/api/corp/reports?limit=1",
            true,
            Some(EXIT),
            None,
            None,
        );
        req.headers_mut().insert(
            "authorization",
            "Bearer browser-capability-must-not-forward"
                .parse()
                .unwrap(),
        );
        req.headers_mut()
            .insert("x-forwarded-for", "203.0.113.9".parse().unwrap());
        let response = f.router.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        let result = body(response).await;
        assert_eq!(
            result,
            json!({"schema":1,"reports":[summary()],"next_cursor":null})
        );
        let requests = upstream.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].0, "/internal/corp-diagnostics/reports?limit=1");
        assert_eq!(requests[0].1["authorization"], format!("Bearer {TOKEN}"));
        for header in ["cookie", "x-forwarded-for", "x-real-ip", "x-corp-csrf"] {
            assert!(!requests[0].1.contains_key(header));
        }
    }

    #[tokio::test]
    async fn authenticated_detail_has_safe_defined_dto_without_receipt_fields() {
        let mut item = summary();
        item["archive_path"] = json!(PRIVATE_MARKER);
        let upstream = mock(StatusCode::OK, json!({"schema":1,"report":item,"analysis":null,"provenance":null,"identity_sha256":PRIVATE_MARKER}).to_string()).await;
        let f = fixture(Some(&upstream)).await;
        let response = f
            .router
            .clone()
            .oneshot(request(
                "GET",
                &format!("/api/corp/reports/{REPORT}"),
                true,
                Some(EXIT),
                None,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            body(response).await,
            json!({"schema":1,"report":summary(),"analysis":null,"provenance":null})
        );
        assert_eq!(
            upstream.requests.lock().unwrap()[0].0,
            format!("/internal/corp-diagnostics/reports/{REPORT}")
        );
    }

    #[tokio::test]
    async fn malformed_ids_and_out_of_range_limits_never_reach_upstream() {
        let upstream = mock(StatusCode::OK, "{}".into()).await;
        let f = fixture(Some(&upstream)).await;
        for path in [
            "/api/corp/reports/not-an-id",
            "/api/corp/reports/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "/api/corp/reports?limit=0",
            "/api/corp/reports?limit=101",
            "/api/corp/reports?cursor=foreign",
        ] {
            let response = f
                .router
                .clone()
                .oneshot(request("GET", path, true, Some(EXIT), None, None))
                .await
                .unwrap();
            assert!(response.status().is_client_error(), "{path}");
        }
        assert!(upstream.requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn revoked_session_is_rechecked_before_each_upstream_request() {
        let upstream = mock(
            StatusCode::OK,
            json!({"schema":1,"reports":[],"next_cursor":null}).to_string(),
        )
        .await;
        let f = fixture(Some(&upstream)).await;
        let response = f
            .router
            .clone()
            .oneshot(request(
                "GET",
                "/api/corp/reports",
                true,
                Some(EXIT),
                None,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let status = f.inv.corp_record().await.unwrap().unwrap().status;
        f.inv
            .revoke_corp_sessions(status.config_version, "spec")
            .await
            .unwrap();
        let response = f
            .router
            .clone()
            .oneshot(request(
                "GET",
                "/api/corp/reports",
                true,
                Some(EXIT),
                None,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(upstream.requests.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn unavailable_configuration_and_upstream_failures_remain_safe() {
        let f = fixture(None).await;
        let response = f
            .router
            .clone()
            .oneshot(request(
                "GET",
                "/api/corp/reports",
                true,
                Some(EXIT),
                None,
                None,
            ))
            .await
            .unwrap();
        assert!(response.status().is_server_error());
        assert!(body(response).await["message"].is_string());
        for payload in [
            format!("{{\"private\":\"{PRIVATE_MARKER}\"}}"),
            format!("{}{}", PRIVATE_MARKER, "x".repeat(256 * 1024)),
        ] {
            let upstream = mock(StatusCode::OK, payload).await;
            let f = fixture(Some(&upstream)).await;
            let response = f
                .router
                .clone()
                .oneshot(request(
                    "GET",
                    "/api/corp/reports",
                    true,
                    Some(EXIT),
                    None,
                    None,
                ))
                .await
                .unwrap();
            assert!(response.status().is_server_error());
            let result = body(response).await;
            assert!(result["message"].is_string());
            let text = result.to_string();
            for secret in [PRIVATE_MARKER, TOKEN, upstream.url.as_str()] {
                assert!(!text.contains(secret));
            }
        }
    }
    #[tokio::test]
    async fn detail_provenance_is_a_defined_dto_not_an_arbitrary_receipt_object() {
        let safe = json!({
            "requested_model":"synthetic-model","returned_model":"synthetic-model",
            "prompt_sha256":"b".repeat(64),"input_sha256":"c".repeat(64),
            "run_id":"synthetic-run","started_utc":"2026-11-16T12:00:30Z",
            "completed_utc":"2026-11-16T12:01:00Z","prompt_version":"synthetic-v1","status":"ready"
        });
        let mut provenance = safe.clone();
        provenance["model_api_key"] = json!(PRIVATE_MARKER);
        provenance["raw_logs"] = json!([PRIVATE_MARKER]);
        let upstream = mock(
            StatusCode::OK,
            json!({"schema":1,"report":summary(),"analysis":null,"provenance":provenance})
                .to_string(),
        )
        .await;
        let f = fixture(Some(&upstream)).await;
        let response = f
            .router
            .clone()
            .oneshot(request(
                "GET",
                &format!("/api/corp/reports/{REPORT}"),
                true,
                Some(EXIT),
                None,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body(response).await["provenance"], safe);
    }

    #[tokio::test]
    async fn non_corp_host_cannot_reach_reports_and_denied_page_never_fetches_reports() {
        let upstream = mock(
            StatusCode::OK,
            json!({"schema":1,"reports":[],"next_cursor":null}).to_string(),
        )
        .await;
        let f = fixture(Some(&upstream)).await;
        for host in [
            "operator.example.com",
            "admin.corp.ninitux.com.evil.example",
        ] {
            let mut req = request("GET", "/api/corp/reports", true, Some(EXIT), None, None);
            req.headers_mut().insert("host", host.parse().unwrap());
            let response = f.router.clone().oneshot(req).await.unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }
        let response = f
            .router
            .clone()
            .oneshot(request(
                "GET",
                "/diagnostics",
                true,
                Some("198.51.100.99"),
                None,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(upstream.requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn upstream_redirect_is_not_followed_and_its_location_is_not_exposed() {
        let target = mock(
            StatusCode::OK,
            json!({"schema":1,"reports":[],"next_cursor":null}).to_string(),
        )
        .await;
        let location = format!("{}/private-redirect-target", target.url);
        let redirect = Router::new().fallback(any(move || {
            let location = location.clone();
            async move {
                Response::builder()
                    .status(StatusCode::FOUND)
                    .header("location", location)
                    .body(Body::empty())
                    .unwrap()
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let job = tokio::spawn(async move {
            axum::serve(listener, redirect).await.unwrap();
        });
        let upstream = Mock {
            url,
            requests: Arc::new(Mutex::new(Vec::new())),
            job,
        };
        let f = fixture(Some(&upstream)).await;
        let response = f
            .router
            .clone()
            .oneshot(request(
                "GET",
                "/api/corp/reports",
                true,
                Some(EXIT),
                None,
                None,
            ))
            .await
            .unwrap();
        assert!(response.status().is_server_error());
        assert!(!response.headers().contains_key("location"));
        let value = body(response).await;
        assert!(!value.to_string().contains(&target.url));
        assert!(target.requests.lock().unwrap().is_empty());
    }
    #[tokio::test]
    async fn rich_analysis_keeps_defined_evidence_and_strips_unknown_nested_fields() {
        let evidence = json!({"kind":"log","file":"app-01.txt","line":12});
        let safe = json!({
            "schema":"corp-diagnosis/1",
            "assessments":[{"scope":"client_runtime","verdict":"insufficient_data","confidence":"low","time_scope":"unknown","explanation_ru":"Свежих записей нет","evidence":[evidence.clone()]}],
            "confirmed":[{"statement":"Старая запись о завершении","time_scope":"historical","evidence":[evidence]}],
            "probable":[],"unknown":[],"chronology":[],
            "owner_explanation":"Недостаточно свежих данных", "next_steps_ru":["Отправьте новый отчёт через приложение"],
            "public_analysis":{"version":1,"state":"ready","message_ru":"Недостаточно свежих данных"}
        });
        let mut untrusted = safe.clone();
        untrusted["raw_archive"] = json!(PRIVATE_MARKER);
        untrusted["assessments"][0]["credentials"] = json!(PRIVATE_MARKER);
        untrusted["confirmed"][0]["evidence"][0]["private_path"] = json!(PRIVATE_MARKER);
        let upstream = mock(
            StatusCode::OK,
            json!({"schema":1,"report":summary(),"analysis":untrusted,"provenance":null})
                .to_string(),
        )
        .await;
        let f = fixture(Some(&upstream)).await;
        let response = f
            .router
            .clone()
            .oneshot(request(
                "GET",
                &format!("/api/corp/reports/{REPORT}"),
                true,
                Some(EXIT),
                None,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body(response).await["analysis"], safe);
    }

    #[tokio::test]
    async fn unknown_and_foreign_ids_have_identical_safe_not_found_responses() {
        let upstream = mock(
            StatusCode::NOT_FOUND,
            json!({"message":PRIVATE_MARKER,"archive_path":PRIVATE_MARKER}).to_string(),
        )
        .await;
        let f = fixture(Some(&upstream)).await;
        let mut replies = Vec::new();
        for id in ["d".repeat(64), "e".repeat(64)] {
            let response = f
                .router
                .clone()
                .oneshot(request(
                    "GET",
                    &format!("/api/corp/reports/{id}"),
                    true,
                    Some(EXIT),
                    None,
                    None,
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            let result = body(response).await;
            assert!(result["message"].is_string());
            assert!(!result.to_string().contains(PRIVATE_MARKER));
            replies.push(result);
        }
        assert_eq!(replies[0], replies[1]);
    }

    #[tokio::test]
    async fn retry_of_an_active_job_preserves_conflict_and_hides_upstream_error_details() {
        let upstream = mock(
            StatusCode::CONFLICT,
            json!({"message":PRIVATE_MARKER,"service_token":TOKEN}).to_string(),
        )
        .await;
        let f = fixture(Some(&upstream)).await;
        let response = f
            .router
            .clone()
            .oneshot(request(
                "POST",
                &format!("/api/corp/reports/{REPORT}/retry"),
                true,
                Some(EXIT),
                Some(CSRF),
                Some(ORIGIN),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let value = body(response).await;
        assert!(value["message"].is_string());
        assert!(!value.to_string().contains(PRIVATE_MARKER));
        assert!(!value.to_string().contains(TOKEN));
    }

    #[tokio::test]
    async fn received_report_allows_nullable_analysis_metadata_and_maximum_page_size() {
        let item = json!({"report_id":REPORT,"received_utc":"2026-11-16T12:00:00Z","bytes":0,"device_label":null,"analysis_state":"received","verdict":null,"summary_ru":null,"model":null,"updated_utc":null});
        let upstream = mock(
            StatusCode::OK,
            json!({"schema":1,"reports":[item.clone()],"next_cursor":REPORT}).to_string(),
        )
        .await;
        let f = fixture(Some(&upstream)).await;
        let path = format!("/api/corp/reports?limit=100&cursor={REPORT}");
        let response = f
            .router
            .clone()
            .oneshot(request("GET", &path, true, Some(EXIT), None, None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            body(response).await,
            json!({"schema":1,"reports":[item],"next_cursor":REPORT})
        );
        assert_eq!(
            upstream.requests.lock().unwrap()[0].0,
            format!("/internal/corp-diagnostics/reports?limit=100&cursor={REPORT}")
        );
    }
}
