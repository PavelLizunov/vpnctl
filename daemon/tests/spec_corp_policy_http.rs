// Independent request-level tests derived only from the Corp HTTP, wire and storage contracts.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod spec {
    use std::{
        collections::BTreeMap,
        net::{IpAddr, SocketAddr},
        sync::Arc,
    };

    use argon2::{
        Algorithm, Argon2, Params, Version,
        password_hash::{PasswordHasher, SaltString},
    };
    use axum::{
        Router,
        body::{Body, Bytes},
        extract::ConnectInfo,
        http::{HeaderMap, HeaderValue, Request, StatusCode},
    };
    use base64::{
        Engine as _,
        engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    };
    use http_body_util::BodyExt;
    use serde_json::{Value, json};
    use tempfile::TempDir;
    use tokio::task::JoinHandle;
    use tower::ServiceExt;
    use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
    use vpnctl_inventory::{
        CorpCredentials, CorpPublication, CorpReaderToken, CorpSetup, CorpSigningKey,
        CorpVerifiedEgress, SqliteInventory,
    };
    use vpnctld::{
        AppState, app,
        corp_policy::{PolicyPayload, PolicyRule, PolicySigningKey, seed_rules, verify_envelope},
        corp_portal::{eligibility::eligible_servers, resolve_client_ip},
    };

    const HOST: &str = "admin.corp.ninitux.com";
    const ORIGIN: &str = "https://admin.corp.ninitux.com";
    const PASSWORD: &str = "synthetic-corp-password";
    const READER: &str = "synthetic_reader_0123456789abcdef0123456789";
    const OBSERVED_IP: &str = "198.51.100.20";

    struct Fixture {
        _dir: TempDir,
        state: AppState,
        router: Router,
        job: JoinHandle<()>,
        credentials: CorpCredentials,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            self.job.abort();
        }
    }

    fn user() -> User {
        User {
            id: UserId("http-spec-user".to_owned()),
            uuid: "12345678-9abc-4def-8abc-123456789abc".to_owned(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        }
    }

    fn server() -> Server {
        Server {
            id: ServerId("http-spec-server".to_owned()),
            address: "192.0.2.10".to_owned(),
            ssh_port: 22,
            ssh_user: "root".to_owned(),
            kernels: vec![KernelId("sing-box".to_owned())],
            enabled_protocols: vec![ProtocolId("vless+reality".to_owned())],
            trusted_host_fingerprint: None,
            hoster: "synthetic".to_owned(),
            jump_via: None,
            usage_coefficient: 1.0,
        }
    }

    fn now() -> i64 {
        chrono::Utc::now().timestamp()
    }

    fn credentials() -> CorpCredentials {
        let key = PolicySigningKey::generate().unwrap();
        let salt = SaltString::encode_b64(b"0123456789abcdef").unwrap();
        let argon = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(8192, 1, 1, Some(32)).unwrap(),
        );
        CorpCredentials {
            password_phc: argon
                .hash_password(PASSWORD.as_bytes(), &salt)
                .unwrap()
                .to_string(),
            reader_tokens: vec![CorpReaderToken {
                id: "reader-1".to_owned(),
                token: READER.to_owned(),
            }],
            signing_keys: vec![CorpSigningKey {
                id: "key-1".to_owned(),
                pkcs8: STANDARD.encode(key.export_pkcs8_der().unwrap().as_bytes()),
                spki: key.spki_base64().unwrap(),
            }],
            active_key_id: "key-1".to_owned(),
        }
    }

    impl Fixture {
        async fn new(binding: bool, eligible: bool) -> Self {
            let dir = TempDir::new().unwrap();
            let inv = SqliteInventory::open(&dir.path().join("inventory.db"))
                .await
                .unwrap();
            inv.add_user(&user()).await.unwrap();
            let credentials = credentials();
            if binding {
                let created = inv
                    .create_corp(
                        &CorpSetup {
                            user_id: user().id,
                            policy_id: "http-spec-policy".to_owned(),
                            credentials: credentials.clone(),
                        },
                        "spec",
                    )
                    .await
                    .unwrap();
                inv.update_corp_security(created.config_version, true, &credentials, "spec")
                    .await
                    .unwrap();
            }
            let registry = Arc::new(vpnctl_kernels::build_registry().unwrap());
            let (state, job) = app::make_app_state_for_tests(inv, registry);
            if eligible {
                state.inv.add_server(&server()).await.unwrap();
                state.inv.grant(&user().id, &server().id).await.unwrap();
                state
                    .inv
                    .set_server_secret(
                        &server().id,
                        "vless.public_key",
                        &URL_SAFE_NO_PAD.encode([7_u8; 32]),
                    )
                    .await
                    .unwrap();
                state
                    .inv
                    .set_server_secret(&server().id, "vless.short_id", "12345678")
                    .await
                    .unwrap();
                state
                    .inv
                    .set_server_secret(&server().id, "vless.sni", "www.example.com")
                    .await
                    .unwrap();
                let candidates = eligible_servers(&state, &user().id).await.unwrap();
                assert_eq!(candidates.len(), 1);
                let status = state.inv.corp_record().await.unwrap().unwrap().status;
                state
                    .inv
                    .replace_corp_egress(
                        status.config_version,
                        &[CorpVerifiedEgress {
                            server_id: server().id,
                            ip: OBSERVED_IP.parse().unwrap(),
                            configuration_fingerprint: candidates[0]
                                .configuration_fingerprint
                                .clone(),
                            verified_at: now(),
                        }],
                        "spec",
                    )
                    .await
                    .unwrap();
            }
            let router = app::router(state.clone());
            Self {
                _dir: dir,
                state,
                router,
                job,
                credentials,
            }
        }

        async fn call(&self, request: Request<Body>) -> Response {
            let response = self.router.clone().oneshot(request).await.unwrap();
            let (parts, body) = response.into_parts();
            Response {
                status: parts.status,
                headers: parts.headers,
                bytes: body.collect().await.unwrap().to_bytes().to_vec(),
            }
        }

        async fn login(&self) -> (String, String) {
            let response = self
                .call(login_request(&format!("password={PASSWORD}")))
                .await;
            assert_eq!(response.status, StatusCode::SEE_OTHER);
            security_headers(&response);
            assert_eq!(response.headers["location"], "/");
            let cookie = response.headers["set-cookie"]
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .to_owned();
            let state = self
                .call(browser_request(
                    "GET",
                    "/api/corp/state",
                    Body::empty(),
                    Some(&cookie),
                    None,
                ))
                .await;
            assert_eq!(state.status, StatusCode::OK);
            let csrf = state.json()["csrf"].as_str().unwrap().to_owned();
            (cookie, csrf)
        }

        async fn publish_direct(&self, rules: Vec<PolicyRule>, apply: &str) -> Vec<u8> {
            let status = self.state.inv.corp_record().await.unwrap().unwrap().status;
            let key = PolicySigningKey::from_pkcs8_der(
                &STANDARD
                    .decode(&self.credentials.signing_keys[0].pkcs8)
                    .unwrap(),
            )
            .unwrap();
            let signed = key
                .sign(&PolicyPayload {
                    schema: 1,
                    policy_id: status.policy_id,
                    key_id: status.active_key_id.clone(),
                    revision: status.revision + 1,
                    published_at: u64::try_from(now()).unwrap(),
                    apply: apply.to_owned(),
                    rules,
                })
                .unwrap();
            self.state
                .inv
                .publish_corp_policy(
                    &CorpPublication {
                        expected_revision: status.revision,
                        expected_config_version: status.config_version,
                        key_id: status.active_key_id,
                        published_at: i64::try_from(signed.payload.published_at).unwrap(),
                        payload_sha256: signed.payload_sha256.to_ascii_lowercase(),
                        payload: signed.payload_bytes,
                        envelope: signed.envelope.clone(),
                    },
                    "spec",
                )
                .await
                .unwrap();
            signed.envelope
        }
    }

    struct Response {
        status: StatusCode,
        headers: HeaderMap,
        bytes: Vec<u8>,
    }

    impl Response {
        fn json(&self) -> Value {
            serde_json::from_slice(&self.bytes).unwrap()
        }
        fn text(&self) -> &str {
            std::str::from_utf8(&self.bytes).unwrap()
        }
    }

    fn request(method: &str, path: &str, host: Option<&str>, body: Body) -> Request<Body> {
        let mut builder = Request::builder().method(method).uri(path);
        if let Some(host) = host {
            builder = builder.header("host", host);
        }
        builder.body(body).unwrap()
    }

    fn browser_request(
        method: &str,
        path: &str,
        body: Body,
        cookie: Option<&str>,
        csrf: Option<&str>,
    ) -> Request<Body> {
        let mut request = request(method, path, Some(HOST), body);
        request.extensions_mut().insert(ConnectInfo(SocketAddr::new(
            OBSERVED_IP.parse().unwrap(),
            40123,
        )));
        if let Some(cookie) = cookie {
            request
                .headers_mut()
                .insert("cookie", HeaderValue::from_str(cookie).unwrap());
        }
        if let Some(csrf) = csrf {
            request
                .headers_mut()
                .insert("x-corp-csrf", HeaderValue::from_str(csrf).unwrap());
        }
        if method == "POST" {
            request
                .headers_mut()
                .insert("origin", HeaderValue::from_static(ORIGIN));
            request
                .headers_mut()
                .insert("content-type", HeaderValue::from_static("application/json"));
        }
        request
    }

    fn login_request(body: &str) -> Request<Body> {
        let mut request =
            browser_request("POST", "/login", Body::from(body.to_owned()), None, None);
        request.headers_mut().insert(
            "content-type",
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        request
    }

    fn reader_request(host: Option<&str>, token: Option<&str>) -> Request<Body> {
        let mut request = request("GET", "/api/v1/corp/policy", host, Body::empty());
        if let Some(token) = token {
            request.headers_mut().insert(
                "authorization",
                HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
            );
        }
        request
    }

    fn security_headers(response: &Response) {
        assert!(
            response.headers["cache-control"]
                .to_str()
                .unwrap()
                .contains("no-store")
        );
        assert_eq!(response.headers["x-content-type-options"], "nosniff");
        assert_eq!(response.headers["x-frame-options"], "DENY");
        let html = response
            .headers
            .get("content-type")
            .is_some_and(|value| value.to_str().unwrap().starts_with("text/html"));
        let expected_referrer = if html
            && !response.status.is_redirection()
            && !response.headers.contains_key("content-disposition")
        {
            "same-origin"
        } else {
            "no-referrer"
        };
        assert_eq!(response.headers["referrer-policy"], expected_referrer);
        let robots = response.headers["x-robots-tag"].to_str().unwrap();
        assert!(robots.contains("noindex") && robots.contains("nofollow"));
        let csp = response.headers["content-security-policy"]
            .to_str()
            .unwrap();
        assert!(!csp.contains("'unsafe-inline'") && !csp.contains("'unsafe-eval'"));
        let directives: BTreeMap<_, _> = csp
            .split(';')
            .filter_map(|directive| {
                let mut words = directive.split_whitespace();
                words.next().map(|name| (name, words.collect::<Vec<_>>()))
            })
            .collect();
        for name in ["script-src", "style-src", "connect-src", "form-action"] {
            let values = directives
                .get(name)
                .or_else(|| directives.get("default-src"))
                .unwrap();
            assert_eq!(values, &["'self'"], "CSP {name}");
        }
        for name in ["object-src", "frame-src"] {
            let values = directives
                .get(name)
                .or_else(|| directives.get("default-src"))
                .unwrap();
            assert_eq!(values, &["'none'"], "CSP {name}");
        }
        if let Some(fonts) = directives.get("font-src") {
            assert!(
                fonts
                    .iter()
                    .all(|value| ["'self'", "'none'"].contains(value))
            );
        }
    }

    fn russian_api_error(response: &Response) {
        let body = response.json();
        let message = body["message"].as_str().unwrap();
        assert!(
            message
                .chars()
                .any(|c| ('А'..='я').contains(&c) || c == 'ё' || c == 'Ё')
        );
        for private in [
            PASSWORD,
            READER,
            "SQLITE",
            "sqlite",
            "password_phc",
            "pkcs8",
        ] {
            assert!(!response.text().contains(private));
        }
        security_headers(response);
    }

    fn write_body(expected_revision: u64, apply: &str, confirmed: bool, rules: &Value) -> String {
        json!({"expected_revision": expected_revision, "apply": apply, "confirm_interrupt": confirmed, "rules": rules}).to_string()
    }

    #[test]
    fn client_ip_requires_a_peer_and_ignores_untrusted_forwarding_claims() {
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", HeaderValue::from_static("192.0.2.20"));
        headers.insert("x-forwarded-for", HeaderValue::from_static("192.0.2.21"));
        assert_eq!(resolve_client_ip(&headers, None, false), None);
        assert_eq!(resolve_client_ip(&headers, None, true), None);
        let peer = "198.51.100.10".parse::<IpAddr>().unwrap();
        assert_eq!(resolve_client_ip(&headers, Some(peer), false), Some(peer));
        headers.append("x-real-ip", HeaderValue::from_static("not-an-ip"));
        assert_eq!(resolve_client_ip(&headers, Some(peer), false), Some(peer));
    }

    #[test]
    fn trusted_peer_requires_exactly_one_valid_real_ip_and_never_falls_back_to_xff() {
        let peer = "192.0.2.10".parse::<IpAddr>().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("198.51.100.10"));
        assert_eq!(resolve_client_ip(&headers, Some(peer), true), None);
        for invalid in [
            "",
            "not-an-ip",
            "198.51.100.10, 198.51.100.11",
            "198.51.100.10:443",
            "[2001:db8::10]:443",
        ] {
            headers.insert("x-real-ip", HeaderValue::from_str(invalid).unwrap());
            assert_eq!(
                resolve_client_ip(&headers, Some(peer), true),
                None,
                "{invalid}"
            );
        }
        headers.insert("x-real-ip", HeaderValue::from_static("198.51.100.10"));
        assert_eq!(
            resolve_client_ip(&headers, Some(peer), true),
            Some("198.51.100.10".parse().unwrap())
        );
        headers.append("x-real-ip", HeaderValue::from_static("198.51.100.10"));
        assert_eq!(resolve_client_ip(&headers, Some(peer), true), None);
    }

    #[test]
    fn client_ip_normalizes_ipv4_mapped_ipv6_and_preserves_native_ipv6() {
        let mut headers = HeaderMap::new();
        let mapped = "::ffff:198.51.100.10".parse::<IpAddr>().unwrap();
        let ipv4 = "198.51.100.10".parse::<IpAddr>().unwrap();
        assert_eq!(resolve_client_ip(&headers, Some(mapped), false), Some(ipv4));
        headers.insert(
            "x-real-ip",
            HeaderValue::from_static("::ffff:198.51.100.10"),
        );
        assert_eq!(
            resolve_client_ip(&headers, Some("192.0.2.1".parse().unwrap()), true),
            Some(ipv4)
        );
        let ipv6 = "2001:db8::10".parse::<IpAddr>().unwrap();
        headers.insert("x-real-ip", HeaderValue::from_static("2001:db8::10"));
        assert_eq!(
            resolve_client_ip(&headers, Some("192.0.2.1".parse().unwrap()), true),
            Some(ipv6)
        );
        assert_eq!(
            resolve_client_ip(&HeaderMap::new(), Some(ipv6), false),
            Some(ipv6)
        );
    }

    #[tokio::test]
    async fn corp_host_is_case_insensitive_accepts_only_443_and_never_reaches_legacy_routes() {
        let fixture = Fixture::new(false, false).await;
        for host in [HOST, "ADMIN.CORP.NINITUX.COM", "admin.corp.ninitux.com:443"] {
            let response = fixture
                .call(request("GET", "/", Some(host), Body::empty()))
                .await;
            assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE);
            security_headers(&response);
            for path in ["/admin/", "/api/v1/health", "/sub/fake-token", "/unknown"] {
                let response = fixture
                    .call(request("GET", path, Some(host), Body::empty()))
                    .await;
                assert_eq!(response.status, StatusCode::NOT_FOUND, "{path}");
                security_headers(&response);
            }
        }
        for host in [
            "admin.corp.ninitux.com.",
            "admin.corp.ninitux.com:80",
            "admin.corp.ninitux.com:444",
            "admin.corp.ninitux.com:0443",
        ] {
            let response = fixture
                .call(request("GET", "/api/v1/health", Some(host), Body::empty()))
                .await;
            assert!(
                response.status.is_client_error(),
                "{host}: {}",
                response.status
            );
        }
        let mut duplicate = request("GET", "/api/v1/health", Some(HOST), Body::empty());
        duplicate
            .headers_mut()
            .append("host", HeaderValue::from_static(HOST));
        assert!(fixture.call(duplicate).await.status.is_client_error());
    }

    #[tokio::test]
    async fn absolute_authority_cannot_bypass_host_boundary_and_legacy_health_remains_available() {
        let fixture = Fixture::new(false, false).await;
        for host in [None, Some("operator.example")] {
            assert_eq!(
                fixture
                    .call(request("GET", "/api/v1/health", host, Body::empty()))
                    .await
                    .status,
                StatusCode::OK
            );
            assert_eq!(
                fixture
                    .call(reader_request(host, Some(READER)))
                    .await
                    .status,
                StatusCode::NOT_FOUND
            );
        }
        let agreed = fixture
            .call(request(
                "GET",
                "https://admin.corp.ninitux.com/",
                Some(HOST),
                Body::empty(),
            ))
            .await;
        assert_eq!(agreed.status, StatusCode::SERVICE_UNAVAILABLE);
        for (uri, host) in [
            ("https://admin.corp.ninitux.com/", None),
            (
                "https://admin.corp.ninitux.com/api/v1/health",
                Some("operator.example"),
            ),
            ("https://operator.example/api/v1/health", Some(HOST)),
        ] {
            assert!(
                fixture
                    .call(request("GET", uri, host, Body::empty()))
                    .await
                    .status
                    .is_client_error()
            );
        }
    }

    #[tokio::test]
    async fn unrelated_malformed_host_preserves_legacy_health_but_cannot_reach_corp_reader() {
        let fixture = Fixture::new(false, false).await;
        let host = "evil.com/bad#";
        assert_eq!(
            fixture
                .call(request("GET", "/api/v1/health", Some(host), Body::empty()))
                .await
                .status,
            StatusCode::OK
        );
        assert_eq!(
            fixture
                .call(reader_request(Some(host), Some(READER)))
                .await
                .status,
            StatusCode::NOT_FOUND
        );
        for host in [host, "other.example"] {
            assert!(
                fixture
                    .call(request(
                        "GET",
                        "https://operator.example/api/v1/health",
                        Some(host),
                        Body::empty(),
                    ))
                    .await
                    .status
                    .is_client_error(),
                "conflicting authority with Host {host}"
            );
        }
    }

    #[tokio::test]
    async fn malformed_corp_host_forms_cannot_reach_legacy_health_or_operator_routes() {
        let fixture = Fixture::new(false, false).await;
        for host in [
            "user@admin.corp.ninitux.com",
            "admin.corp.ninitux.com@evil.com",
            "evil.com/admin.corp.ninitux.com",
            "admin.corp.ninitux.com/bad#",
            "evil.com admin.corp.ninitux.com",
            "evil.com,admin.corp.ninitux.com",
        ] {
            for path in ["/api/v1/health", "/admin/"] {
                let response = fixture
                    .call(request("GET", path, Some(host), Body::empty()))
                    .await;
                assert!(
                    response.status.is_client_error(),
                    "Host {host} at {path}: {}",
                    response.status
                );
            }
        }
    }

    #[tokio::test]
    async fn fixed_assets_render_while_unconfigured_and_do_not_expose_operator_assets() {
        let fixture = Fixture::new(false, false).await;
        for path in ["/assets/corp.css", "/assets/corp.js"] {
            let response = fixture
                .call(request("GET", path, Some(HOST), Body::empty()))
                .await;
            assert_eq!(response.status, StatusCode::OK);
            assert!(!response.bytes.is_empty());
            security_headers(&response);
        }
        for path in [
            "/assets/admin.js",
            "/assets/../admin.js",
            "/%3Cscript%3Ealert(1)%3C/script%3E",
        ] {
            let response = fixture
                .call(request("GET", path, Some(HOST), Body::empty()))
                .await;
            assert_eq!(response.status, StatusCode::NOT_FOUND);
            assert!(!response.text().contains("<script>alert(1)</script>"));
            security_headers(&response);
        }
    }

    #[tokio::test]
    async fn reader_serves_exact_signed_envelope_without_peer_session_or_csrf() {
        let fixture = Fixture::new(true, false).await;
        let envelope = fixture
            .publish_direct(
                vec![PolicyRule {
                    domain: "example.com".to_owned(),
                    action: "direct".to_owned(),
                    comment: "Synthetic".to_owned(),
                }],
                "next_connection",
            )
            .await;
        let response = fixture.call(reader_request(Some(HOST), Some(READER))).await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.bytes, envelope);
        assert!(
            response.headers["content-type"]
                .to_str()
                .unwrap()
                .starts_with("application/json")
        );
        assert!(!response.headers.contains_key("location"));
        security_headers(&response);
        let keys = BTreeMap::from([(
            "key-1".to_owned(),
            fixture.credentials.signing_keys[0].spki.clone(),
        )]);
        assert_eq!(
            verify_envelope(&response.bytes, "http-spec-policy", &keys)
                .unwrap()
                .payload
                .revision,
            1
        );
        let mut unrelated_query = reader_request(Some(HOST), Some(READER));
        *unrelated_query.uri_mut() = "/api/v1/corp/policy?policy_id=other&token=wrong"
            .parse()
            .unwrap();
        let queried = fixture.call(unrelated_query).await;
        assert_eq!(queried.status, StatusCode::OK);
        assert_eq!(queried.bytes, envelope);
    }

    #[tokio::test]
    async fn reader_rejects_missing_wrong_duplicate_or_non_bearer_auth_and_query_credentials() {
        let fixture = Fixture::new(true, false).await;
        fixture.publish_direct(Vec::new(), "now").await;
        for token in [None, Some("wrong-token")] {
            let response = fixture.call(reader_request(Some(HOST), token)).await;
            assert_eq!(response.status, StatusCode::UNAUTHORIZED);
            russian_api_error(&response);
        }
        for auth in [
            format!("Basic {}", STANDARD.encode(format!("operator:{PASSWORD}"))),
            format!("Bearer {READER}, Bearer {READER}"),
            format!("Bearer {}", "a".repeat(513)),
        ] {
            let mut request = reader_request(Some(HOST), None);
            request
                .headers_mut()
                .insert("authorization", HeaderValue::from_str(&auth).unwrap());
            assert!(fixture.call(request).await.status.is_client_error());
        }
        let mut duplicate = reader_request(Some(HOST), Some(READER));
        duplicate.headers_mut().append(
            "authorization",
            HeaderValue::from_str(&format!("Bearer {READER}")).unwrap(),
        );
        assert!(fixture.call(duplicate).await.status.is_client_error());
        let mut query = reader_request(Some(HOST), None);
        *query.uri_mut() = format!("/api/v1/corp/policy?token={READER}")
            .parse()
            .unwrap();
        assert_eq!(fixture.call(query).await.status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn reader_handles_no_revision_disable_deletion_and_credential_rotation() {
        let fixture = Fixture::new(true, false).await;
        assert_eq!(
            fixture
                .call(reader_request(Some(HOST), Some(READER)))
                .await
                .status,
            StatusCode::NOT_FOUND
        );
        let envelope = fixture.publish_direct(Vec::new(), "now").await;
        let mut credentials = fixture.credentials.clone();
        let replacement = "replacement_reader_0123456789abcdef0123456789";
        credentials.reader_tokens[0].token = replacement.to_owned();
        let status = fixture
            .state
            .inv
            .corp_record()
            .await
            .unwrap()
            .unwrap()
            .status;
        let rotated = fixture
            .state
            .inv
            .update_corp_security(status.config_version, true, &credentials, "spec")
            .await
            .unwrap();
        assert_eq!(
            fixture
                .call(reader_request(Some(HOST), Some(READER)))
                .await
                .status,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            fixture
                .call(reader_request(Some(HOST), Some(replacement)))
                .await
                .bytes,
            envelope
        );
        let disabled = fixture
            .state
            .inv
            .update_corp_security(rotated.config_version, false, &credentials, "spec")
            .await
            .unwrap();
        assert_eq!(
            fixture
                .call(reader_request(Some(HOST), Some(replacement)))
                .await
                .status,
            StatusCode::SERVICE_UNAVAILABLE
        );
        fixture
            .state
            .inv
            .update_corp_security(disabled.config_version, true, &credentials, "spec")
            .await
            .unwrap();
        fixture.state.inv.remove_user(&user().id).await.unwrap();
        assert_eq!(
            fixture
                .call(reader_request(Some(HOST), Some(replacement)))
                .await
                .status,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test]
    async fn browser_needs_real_peer_and_verified_exit_not_inventory_address_or_forwarded_claim() {
        let fixture = Fixture::new(true, true).await;
        let missing = fixture
            .call(request("GET", "/", Some(HOST), Body::empty()))
            .await;
        assert_eq!(missing.status, StatusCode::FORBIDDEN);
        security_headers(&missing);
        assert!(missing.text().contains("VPN"));
        for peer in ["192.0.2.10", "198.51.100.99"] {
            let mut request = browser_request("GET", "/", Body::empty(), None, None);
            request
                .extensions_mut()
                .insert(ConnectInfo(SocketAddr::new(peer.parse().unwrap(), 40123)));
            request
                .headers_mut()
                .insert("x-real-ip", HeaderValue::from_static(OBSERVED_IP));
            request
                .headers_mut()
                .insert("x-forwarded-for", HeaderValue::from_static(OBSERVED_IP));
            let denied = fixture.call(request).await;
            assert_eq!(denied.status, StatusCode::FORBIDDEN);
            assert!(denied.text().contains(peer));
            assert!(denied.text().contains("VPN"));
            security_headers(&denied);
        }
        let page = fixture
            .call(browser_request("GET", "/", Body::empty(), None, None))
            .await;
        assert_eq!(page.status, StatusCode::OK);
        assert!(page.text().contains("password"));
        assert!(page.text().contains("https://admin.corp.ninitux.com/login"));
        security_headers(&page);
    }

    #[tokio::test]
    async fn login_cookie_is_fresh_secure_host_only_and_operator_or_reader_credentials_do_not_log_in()
     {
        let fixture = Fixture::new(true, true).await;
        let mut prior = None;
        for _ in 0..2 {
            let response = fixture
                .call(login_request(&format!("password={PASSWORD}")))
                .await;
            assert_eq!(response.status, StatusCode::SEE_OTHER);
            assert_eq!(response.headers["location"], "/");
            let cookie = response.headers["set-cookie"].to_str().unwrap();
            assert!(cookie.starts_with("__Host-vpnctl_corp="));
            for attribute in [
                "Path=/",
                "Secure",
                "HttpOnly",
                "SameSite=Strict",
                "Max-Age=28800",
            ] {
                assert!(cookie.contains(attribute));
            }
            assert!(!cookie.to_ascii_lowercase().contains("domain="));
            let token = cookie.split(';').next().unwrap().to_owned();
            if let Some(previous) = prior {
                assert_ne!(token, previous);
            }
            prior = Some(token);
        }
        for auth in [
            format!("Bearer {READER}"),
            format!("Basic {}", STANDARD.encode(format!("operator:{PASSWORD}"))),
        ] {
            let mut request = browser_request(
                "GET",
                "/api/corp/state",
                Body::empty(),
                Some("vpnctl_admin=synthetic-operator-session"),
                None,
            );
            request
                .headers_mut()
                .insert("authorization", HeaderValue::from_str(&auth).unwrap());
            assert_eq!(fixture.call(request).await.status, StatusCode::UNAUTHORIZED);
        }
    }

    #[tokio::test]
    async fn login_checks_origin_form_shape_and_rejects_duplicate_headers() {
        let fixture = Fixture::new(true, true).await;
        for origin in [
            None,
            Some("null"),
            Some("http://admin.corp.ninitux.com"),
            Some("https://evil.example"),
            Some("https://admin.corp.ninitux.com/"),
        ] {
            let mut request = login_request(&format!("password={PASSWORD}"));
            request.headers_mut().remove("origin");
            request.headers_mut().insert(
                "referer",
                HeaderValue::from_static("https://admin.corp.ninitux.com/"),
            );
            if let Some(origin) = origin {
                request
                    .headers_mut()
                    .insert("origin", HeaderValue::from_str(origin).unwrap());
            }
            assert_eq!(fixture.call(request).await.status, StatusCode::FORBIDDEN);
        }
        for name in ["origin", "content-type"] {
            let mut request = login_request(&format!("password={PASSWORD}"));
            let value = request.headers()[name].clone();
            request.headers_mut().append(name, value);
            let response = fixture.call(request).await;
            assert!(response.status.is_client_error());
            assert!(!response.headers.contains_key("set-cookie"));
        }
        for body in [
            format!("password={PASSWORD}&password={PASSWORD}"),
            format!("password={PASSWORD}&extra=1"),
            "password=".to_owned(),
            format!("password={}", "a".repeat(513)),
        ] {
            let response = fixture.call(login_request(&body)).await;
            assert!(response.status.is_client_error());
            assert!(!response.headers.contains_key("set-cookie"));
        }
    }

    #[tokio::test]
    async fn wrong_password_is_401_and_sixth_attempt_is_throttled_per_address() {
        let fixture = Fixture::new(true, true).await;
        for _ in 0..5 {
            let response = fixture.call(login_request("password=wrong")).await;
            assert_eq!(response.status, StatusCode::UNAUTHORIZED);
            assert!(!response.headers.contains_key("set-cookie"));
        }
        let response = fixture
            .call(login_request(&format!("password={PASSWORD}")))
            .await;
        assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS);
        assert!(
            response.headers["retry-after"]
                .to_str()
                .unwrap()
                .parse::<u64>()
                .unwrap()
                > 0
        );
        assert!(!response.headers.contains_key("set-cookie"));
        security_headers(&response);
    }

    #[tokio::test]
    async fn session_state_starts_with_seed_and_never_exposes_credentials_or_operator_data() {
        let fixture = Fixture::new(true, true).await;
        let (cookie, csrf) = fixture.login().await;
        let response = fixture
            .call(browser_request(
                "GET",
                "/api/corp/state",
                Body::empty(),
                Some(&cookie),
                None,
            ))
            .await;
        let state = response.json();
        assert_eq!(state["revision"], 0);
        assert_eq!(
            serde_json::from_value::<Vec<PolicyRule>>(state["rules"].clone()).unwrap(),
            seed_rules().unwrap()
        );
        assert_eq!(state["csrf"], csrf);
        assert_eq!(state.as_object().unwrap().len(), 3);
        for secret in [
            PASSWORD,
            READER,
            &fixture.credentials.password_phc,
            &fixture.credentials.signing_keys[0].pkcs8,
        ] {
            assert!(!response.text().contains(secret));
        }
        let editor = fixture
            .call(browser_request(
                "GET",
                "/",
                Body::empty(),
                Some(&cookie),
                None,
            ))
            .await;
        assert_eq!(editor.status, StatusCode::OK);
        for text in [
            "Корпоративные правила",
            "Сайт",
            "Как открывать",
            "Комментарий",
            "Без VPN",
            "Через VPN",
        ] {
            assert!(editor.text().contains(text), "{text}");
        }
        security_headers(&editor);
    }

    #[tokio::test]
    async fn normalize_requires_session_origin_and_csrf_and_rejects_protected_or_ambiguous_json() {
        let fixture = Fixture::new(true, true).await;
        let (cookie, csrf) = fixture.login().await;
        let body = r#"{"site":"https://EXAMPLE.com/path"}"#;
        let good = fixture
            .call(browser_request(
                "POST",
                "/api/corp/normalize",
                Body::from(body),
                Some(&cookie),
                Some(&csrf),
            ))
            .await;
        assert_eq!(good.status, StatusCode::OK);
        assert_eq!(good.json(), json!({"domain":"example.com"}));
        for invalid in [
            r#"{"site":"uiscom.ru"}"#,
            r#"{"site":"*.example.com"}"#,
            r#"{"site":"example.com","site":"example.org"}"#,
            r#"{"site":"example.com","extra":1}"#,
            r#"{"site":1}"#,
            "{}",
        ] {
            let response = fixture
                .call(browser_request(
                    "POST",
                    "/api/corp/normalize",
                    Body::from(invalid),
                    Some(&cookie),
                    Some(&csrf),
                ))
                .await;
            assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);
            russian_api_error(&response);
        }
        for bad_csrf in [None, Some("forged")] {
            assert_eq!(
                fixture
                    .call(browser_request(
                        "POST",
                        "/api/corp/normalize",
                        Body::from(body),
                        Some(&cookie),
                        bad_csrf
                    ))
                    .await
                    .status,
                StatusCode::FORBIDDEN
            );
        }
        for bad_cookie in [None, Some("__Host-vpnctl_corp=forged")] {
            assert_eq!(
                fixture
                    .call(browser_request(
                        "POST",
                        "/api/corp/normalize",
                        Body::from(body),
                        bad_cookie,
                        Some(&csrf)
                    ))
                    .await
                    .status,
                StatusCode::UNAUTHORIZED
            );
        }
        let mut no_origin = browser_request(
            "POST",
            "/api/corp/normalize",
            Body::from(body),
            Some(&cookie),
            Some(&csrf),
        );
        no_origin.headers_mut().remove("origin");
        assert_eq!(fixture.call(no_origin).await.status, StatusCode::FORBIDDEN);
        assert_eq!(
            fixture
                .state
                .inv
                .corp_record()
                .await
                .unwrap()
                .unwrap()
                .status
                .revision,
            0
        );
    }

    #[tokio::test]
    async fn duplicate_session_cookies_and_csrf_headers_cannot_authorize_mutations() {
        let fixture = Fixture::new(true, true).await;
        let (cookie, csrf) = fixture.login().await;
        for combined in [
            format!("{cookie}; {cookie}"),
            format!("{cookie}; __Host-vpnctl_corp=forged"),
        ] {
            assert_eq!(
                fixture
                    .call(browser_request(
                        "GET",
                        "/api/corp/state",
                        Body::empty(),
                        Some(&combined),
                        None
                    ))
                    .await
                    .status,
                StatusCode::UNAUTHORIZED
            );
        }
        let mut duplicate_cookie =
            browser_request("GET", "/api/corp/state", Body::empty(), Some(&cookie), None);
        duplicate_cookie
            .headers_mut()
            .append("cookie", HeaderValue::from_str(&cookie).unwrap());
        assert_eq!(
            fixture.call(duplicate_cookie).await.status,
            StatusCode::UNAUTHORIZED
        );
        let mut duplicate_csrf = browser_request(
            "POST",
            "/api/corp/normalize",
            Body::from(r#"{"site":"example.com"}"#),
            Some(&cookie),
            Some(&csrf),
        );
        duplicate_csrf
            .headers_mut()
            .append("x-corp-csrf", HeaderValue::from_str(&csrf).unwrap());
        assert_eq!(
            fixture.call(duplicate_csrf).await.status,
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn logout_revokes_session_and_expires_the_same_strict_cookie() {
        let fixture = Fixture::new(true, true).await;
        let (cookie, csrf) = fixture.login().await;
        let response = fixture
            .call(browser_request(
                "POST",
                "/logout",
                Body::empty(),
                Some(&cookie),
                Some(&csrf),
            ))
            .await;
        assert_eq!(response.status, StatusCode::SEE_OTHER);
        assert_eq!(response.headers["location"], "/");
        let expired = response.headers["set-cookie"].to_str().unwrap();
        for attribute in [
            "__Host-vpnctl_corp=",
            "Path=/",
            "Secure",
            "HttpOnly",
            "SameSite=Strict",
            "Max-Age=0",
        ] {
            assert!(expired.contains(attribute));
        }
        assert!(!expired.to_ascii_lowercase().contains("domain="));
        assert_eq!(
            fixture
                .call(browser_request(
                    "GET",
                    "/api/corp/state",
                    Body::empty(),
                    Some(&cookie),
                    None
                ))
                .await
                .status,
            StatusCode::UNAUTHORIZED
        );
        security_headers(&response);
    }

    #[tokio::test]
    async fn browser_rechecks_grant_protocol_suppression_user_and_config_after_login() {
        for change in [
            "grant",
            "hidden",
            "override",
            "suppressed",
            "secret",
            "user",
            "corp",
        ] {
            let fixture = Fixture::new(true, true).await;
            let (cookie, _) = fixture.login().await;
            match change {
                "grant" => fixture
                    .state
                    .inv
                    .revoke(&user().id, &server().id)
                    .await
                    .unwrap(),
                "hidden" => fixture
                    .state
                    .inv
                    .set_server_protocol_hidden(
                        &server().id,
                        &ProtocolId("vless+reality".to_owned()),
                        true,
                    )
                    .await
                    .unwrap(),
                "override" => fixture
                    .state
                    .inv
                    .set_grant_protocol_override(
                        &user().id,
                        &server().id,
                        &ProtocolId("vless+reality".to_owned()),
                        true,
                    )
                    .await
                    .unwrap(),
                "suppressed" => {
                    fixture
                        .state
                        .inv
                        .set_server_auto_suppress(&server().id, true)
                        .await
                        .unwrap();
                    fixture
                        .state
                        .inv
                        .set_server_suppressed(&server().id, true)
                        .await
                        .unwrap();
                }
                "secret" => fixture
                    .state
                    .inv
                    .set_server_secret(&server().id, "vless.short_id", "abcdef12")
                    .await
                    .unwrap(),
                "user" => {
                    fixture
                        .state
                        .inv
                        .set_user_disabled(&user().id, true)
                        .await
                        .unwrap();
                }
                _ => {
                    let status = fixture
                        .state
                        .inv
                        .corp_record()
                        .await
                        .unwrap()
                        .unwrap()
                        .status;
                    fixture
                        .state
                        .inv
                        .update_corp_security(
                            status.config_version,
                            false,
                            &fixture.credentials,
                            "spec",
                        )
                        .await
                        .unwrap();
                }
            }
            let response = fixture
                .call(browser_request(
                    "GET",
                    "/api/corp/state",
                    Body::empty(),
                    Some(&cookie),
                    None,
                ))
                .await;
            assert!(!response.status.is_success(), "{change}");
            russian_api_error(&response);
        }
    }

    #[tokio::test]
    async fn publication_signs_complete_lists_both_timings_empty_deletions_and_rejects_stale_revision()
     {
        let fixture = Fixture::new(true, true).await;
        let (cookie, csrf) = fixture.login().await;
        let rules = json!([{"domain":"example.com","action":"direct","comment":"Site"}]);
        let first = fixture
            .call(browser_request(
                "POST",
                "/api/corp/rules",
                Body::from(write_body(0, "next_connection", false, &rules)),
                Some(&cookie),
                Some(&csrf),
            ))
            .await;
        assert_eq!(first.status, StatusCode::OK);
        assert_eq!(first.json()["revision"], 1);
        assert!(first.json()["published_at"].as_u64().unwrap() > 0);
        let reader = fixture.call(reader_request(Some(HOST), Some(READER))).await;
        let keys = BTreeMap::from([(
            "key-1".to_owned(),
            fixture.credentials.signing_keys[0].spki.clone(),
        )]);
        let signed = verify_envelope(&reader.bytes, "http-spec-policy", &keys).unwrap();
        assert_eq!(signed.payload.apply, "next_connection");
        assert_eq!(signed.payload.rules.len(), 1);
        let stale = fixture
            .call(browser_request(
                "POST",
                "/api/corp/rules",
                Body::from(write_body(0, "next_connection", false, &json!([]))),
                Some(&cookie),
                Some(&csrf),
            ))
            .await;
        assert_eq!(stale.status, StatusCode::CONFLICT);
        russian_api_error(&stale);
        let unconfirmed = fixture
            .call(browser_request(
                "POST",
                "/api/corp/rules",
                Body::from(write_body(1, "now", false, &json!([]))),
                Some(&cookie),
                Some(&csrf),
            ))
            .await;
        assert_eq!(unconfirmed.status, StatusCode::UNPROCESSABLE_ENTITY);
        let removed = fixture
            .call(browser_request(
                "POST",
                "/api/corp/rules",
                Body::from(write_body(1, "now", true, &json!([]))),
                Some(&cookie),
                Some(&csrf),
            ))
            .await;
        assert_eq!(removed.status, StatusCode::OK);
        assert_eq!(removed.json()["revision"], 2);
        let reader = fixture.call(reader_request(Some(HOST), Some(READER))).await;
        let signed = verify_envelope(&reader.bytes, "http-spec-policy", &keys).unwrap();
        assert_eq!(signed.payload.apply, "now");
        assert!(signed.payload.rules.is_empty());
        let state = fixture
            .call(browser_request(
                "GET",
                "/api/corp/state",
                Body::empty(),
                Some(&cookie),
                None,
            ))
            .await;
        assert_eq!(state.json()["rules"], json!([]));
    }

    #[tokio::test]
    async fn rules_reject_unknown_duplicate_noninteger_and_unnormalized_input_without_publication()
    {
        let fixture = Fixture::new(true, true).await;
        let (cookie, csrf) = fixture.login().await;
        let normal = write_body(0, "next_connection", false, &json!([]));
        let invalid = [
            normal.replacen('{', "{\"unknown\":1,", 1),
            normal.replacen('{', "{\"expected_revision\":0,", 1),
            normal.replace("\"expected_revision\":0", "\"expected_revision\":0.0"),
            write_body(
                0,
                "next_connection",
                false,
                &json!([{"domain":"EXAMPLE.COM","action":"direct","comment":""}]),
            ),
            write_body(
                0,
                "next_connection",
                false,
                &json!([{"domain":"uiscom.ru","action":"direct","comment":""}]),
            ),
            write_body(0, "later", false, &json!([])),
            "{}".to_owned(),
        ];
        for body in invalid {
            let response = fixture
                .call(browser_request(
                    "POST",
                    "/api/corp/rules",
                    Body::from(body),
                    Some(&cookie),
                    Some(&csrf),
                ))
                .await;
            assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);
            russian_api_error(&response);
        }
        assert_eq!(
            fixture
                .state
                .inv
                .corp_record()
                .await
                .unwrap()
                .unwrap()
                .status
                .revision,
            0
        );
        assert!(
            fixture
                .state
                .inv
                .corp_history(100)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn history_and_restore_create_new_revision_instead_of_resetting_floor() {
        let fixture = Fixture::new(true, true).await;
        let (cookie, csrf) = fixture.login().await;
        fixture
            .publish_direct(
                vec![PolicyRule {
                    domain: "example.com".to_owned(),
                    action: "direct".to_owned(),
                    comment: "First".to_owned(),
                }],
                "next_connection",
            )
            .await;
        fixture.publish_direct(Vec::new(), "now").await;
        let history = fixture
            .call(browser_request(
                "GET",
                "/api/corp/history",
                Body::empty(),
                Some(&cookie),
                None,
            ))
            .await;
        assert_eq!(history.status, StatusCode::OK);
        let entries = history.json();
        assert_eq!(entries.as_array().unwrap().len(), 2);
        assert_eq!(entries[0]["revision"], 2);
        assert_eq!(entries[0]["rule_count"], 0);
        assert_eq!(entries[1]["revision"], 1);
        assert_eq!(entries[1]["apply"], "next_connection");
        for entry in entries.as_array().unwrap() {
            assert_eq!(entry.as_object().unwrap().len(), 4);
        }
        let absent = json!({"expected_revision":2,"revision":99,"apply":"next_connection","confirm_interrupt":false}).to_string();
        assert_eq!(
            fixture
                .call(browser_request(
                    "POST",
                    "/api/corp/restore",
                    Body::from(absent),
                    Some(&cookie),
                    Some(&csrf)
                ))
                .await
                .status,
            StatusCode::NOT_FOUND
        );
        let restore =
            json!({"expected_revision":2,"revision":1,"apply":"now","confirm_interrupt":true})
                .to_string();
        let restored = fixture
            .call(browser_request(
                "POST",
                "/api/corp/restore",
                Body::from(restore),
                Some(&cookie),
                Some(&csrf),
            ))
            .await;
        assert_eq!(restored.status, StatusCode::OK);
        assert_eq!(restored.json()["revision"], 3);
        let state = fixture
            .call(browser_request(
                "GET",
                "/api/corp/state",
                Body::empty(),
                Some(&cookie),
                None,
            ))
            .await;
        assert_eq!(state.json()["revision"], 3);
        assert_eq!(state.json()["rules"][0]["domain"], "example.com");
        assert_eq!(
            fixture
                .state
                .inv
                .corp_revision(2)
                .await
                .unwrap()
                .unwrap()
                .revision,
            2
        );
    }

    #[tokio::test]
    async fn corp_accepts_valid_bodies_above_legacy_limit_and_caps_streamed_body_at_65536() {
        let fixture = Fixture::new(true, true).await;
        let (cookie, csrf) = fixture.login().await;
        let rules: Vec<_> = (0..40).map(|i| json!({"domain":format!("site-{i}.example.com"),"action":"direct","comment":"a".repeat(240)})).collect();
        let body = write_body(0, "next_connection", false, &json!(rules));
        assert!(body.len() > 8192 && body.len() < 65536);
        assert_eq!(
            fixture
                .call(browser_request(
                    "POST",
                    "/api/corp/rules",
                    Body::from(body),
                    Some(&cookie),
                    Some(&csrf)
                ))
                .await
                .status,
            StatusCode::OK
        );
        let mut exact = br#"{"site":"example.com"}"#.to_vec();
        exact.resize(65_536, b' ');
        let response = fixture
            .call(browser_request(
                "POST",
                "/api/corp/normalize",
                Body::from(exact.clone()),
                Some(&cookie),
                Some(&csrf),
            ))
            .await;
        assert_eq!(response.status, StatusCode::OK);
        exact.push(b' ');
        let chunks: Vec<_> = exact
            .chunks(4096)
            .map(|chunk| Ok::<Bytes, std::io::Error>(Bytes::copy_from_slice(chunk)))
            .collect();
        let body = Body::from_stream(tokio_stream::iter(chunks));
        let response = fixture
            .call(browser_request(
                "POST",
                "/api/corp/normalize",
                body,
                Some(&cookie),
                Some(&csrf),
            ))
            .await;
        assert_eq!(response.status, StatusCode::PAYLOAD_TOO_LARGE);
        security_headers(&response);
    }

    #[tokio::test]
    async fn unsupported_argon_parameters_fail_closed_without_session_cookie() {
        for (from, to) in [
            ("m=8192", "m=8191"),
            ("m=8192", "m=65537"),
            ("t=1", "t=5"),
            ("p=1", "p=5"),
            ("v=19", "v=16"),
        ] {
            let fixture = Fixture::new(true, true).await;
            let mut credentials = fixture.credentials.clone();
            credentials.password_phc = credentials.password_phc.replace(from, to);
            let status = fixture
                .state
                .inv
                .corp_record()
                .await
                .unwrap()
                .unwrap()
                .status;
            fixture
                .state
                .inv
                .update_corp_security(status.config_version, true, &credentials, "spec")
                .await
                .unwrap();
            let response = fixture
                .call(login_request(&format!("password={PASSWORD}")))
                .await;
            assert_eq!(response.status, StatusCode::UNAUTHORIZED, "{to}");
            assert!(!response.headers.contains_key("set-cookie"));
            security_headers(&response);
        }
    }

    #[tokio::test]
    async fn expired_or_future_exit_observations_do_not_admit_browser() {
        let fixture = Fixture::new(true, true).await;
        let candidates = eligible_servers(&fixture.state, &user().id).await.unwrap();
        for observed_at in [now() - 86_401, now() + 3600] {
            let status = fixture
                .state
                .inv
                .corp_record()
                .await
                .unwrap()
                .unwrap()
                .status;
            fixture
                .state
                .inv
                .replace_corp_egress(
                    status.config_version,
                    &[CorpVerifiedEgress {
                        server_id: server().id,
                        ip: OBSERVED_IP.parse().unwrap(),
                        configuration_fingerprint: candidates[0].configuration_fingerprint.clone(),
                        verified_at: observed_at,
                    }],
                    "spec",
                )
                .await
                .unwrap();
            let response = fixture
                .call(browser_request("GET", "/", Body::empty(), None, None))
                .await;
            assert_eq!(response.status, StatusCode::FORBIDDEN);
            security_headers(&response);
        }
    }

    #[tokio::test]
    async fn explicit_revoke_all_invalidates_browser_session_and_its_csrf() {
        let fixture = Fixture::new(true, true).await;
        let (cookie, csrf) = fixture.login().await;
        let status = fixture
            .state
            .inv
            .corp_record()
            .await
            .unwrap()
            .unwrap()
            .status;
        fixture
            .state
            .inv
            .revoke_corp_sessions(status.config_version, "spec")
            .await
            .unwrap();
        let response = fixture
            .call(browser_request(
                "POST",
                "/api/corp/rules",
                Body::from(write_body(0, "next_connection", false, &json!([]))),
                Some(&cookie),
                Some(&csrf),
            ))
            .await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
        russian_api_error(&response);
        assert_eq!(
            fixture
                .state
                .inv
                .corp_record()
                .await
                .unwrap()
                .unwrap()
                .status
                .revision,
            0
        );
    }

    #[tokio::test]
    async fn mismatched_signer_spki_returns_generic_error_without_partial_publication() {
        let fixture = Fixture::new(true, true).await;
        let mut mismatched = fixture.credentials.clone();
        mismatched.signing_keys[0].spki =
            PolicySigningKey::generate().unwrap().spki_base64().unwrap();
        let status = fixture
            .state
            .inv
            .corp_record()
            .await
            .unwrap()
            .unwrap()
            .status;
        fixture
            .state
            .inv
            .update_corp_security(status.config_version, true, &mismatched, "spec")
            .await
            .unwrap();
        let (cookie, csrf) = fixture.login().await;
        let audit_before = fixture.state.inv.recent_audit(100).await.unwrap().len();
        let response = fixture
            .call(browser_request(
                "POST",
                "/api/corp/rules",
                Body::from(write_body(0, "next_connection", false, &json!([]))),
                Some(&cookie),
                Some(&csrf),
            ))
            .await;
        assert!(response.status.is_server_error());
        russian_api_error(&response);
        assert_eq!(
            fixture
                .state
                .inv
                .corp_record()
                .await
                .unwrap()
                .unwrap()
                .status
                .revision,
            0
        );
        assert!(
            fixture
                .state
                .inv
                .corp_history(100)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            fixture.state.inv.recent_audit(100).await.unwrap().len(),
            audit_before
        );
    }

    #[tokio::test]
    async fn concurrent_http_publications_have_one_success_one_conflict_and_one_revision() {
        let fixture = Fixture::new(true, true).await;
        let (cookie, csrf) = fixture.login().await;
        let first = browser_request(
            "POST",
            "/api/corp/rules",
            Body::from(write_body(0, "next_connection", false, &json!([]))),
            Some(&cookie),
            Some(&csrf),
        );
        let second = browser_request(
            "POST",
            "/api/corp/rules",
            Body::from(write_body(0, "now", true, &json!([]))),
            Some(&cookie),
            Some(&csrf),
        );
        let audit_before = fixture.state.inv.recent_audit(100).await.unwrap().len();
        let (first, second) = tokio::join!(fixture.call(first), fixture.call(second));
        let mut statuses = [first.status.as_u16(), second.status.as_u16()];
        statuses.sort_unstable();
        assert_eq!(statuses, [200, 409]);
        assert_eq!(
            fixture
                .state
                .inv
                .corp_record()
                .await
                .unwrap()
                .unwrap()
                .status
                .revision,
            1
        );
        assert_eq!(fixture.state.inv.corp_history(100).await.unwrap().len(), 1);
        assert_eq!(
            fixture.state.inv.recent_audit(100).await.unwrap().len(),
            audit_before + 1
        );
    }

    #[tokio::test]
    async fn normalization_is_read_only_and_unconfigured_reader_is_unavailable() {
        let unconfigured = Fixture::new(false, false).await;
        let unavailable = unconfigured
            .call(reader_request(Some(HOST), Some(READER)))
            .await;
        assert_eq!(unavailable.status, StatusCode::SERVICE_UNAVAILABLE);
        security_headers(&unavailable);
        let fixture = Fixture::new(true, true).await;
        let (cookie, csrf) = fixture.login().await;
        let before = fixture.state.inv.recent_audit(100).await.unwrap().len();
        let response = fixture
            .call(browser_request(
                "POST",
                "/api/corp/normalize",
                Body::from(r#"{"site":"https://bücher.example/path"}"#),
                Some(&cookie),
                Some(&csrf),
            ))
            .await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.json()["domain"], "xn--bcher-kva.example");
        assert_eq!(
            fixture.state.inv.recent_audit(100).await.unwrap().len(),
            before
        );
        assert_eq!(
            fixture
                .state
                .inv
                .corp_record()
                .await
                .unwrap()
                .unwrap()
                .status
                .revision,
            0
        );
    }

    #[tokio::test]
    async fn legacy_form_body_limit_remains_8192_bytes_and_does_not_create_user() {
        let fixture = Fixture::new(false, false).await;
        let body = format!("id=spec-limit-user&pad={}", "x".repeat(8192));
        let mut request = request(
            "POST",
            "/admin/users",
            Some("operator.example"),
            Body::from(body),
        );
        request.headers_mut().insert(
            "origin",
            HeaderValue::from_static("http://operator.example"),
        );
        request.headers_mut().insert(
            "content-type",
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        assert_eq!(
            fixture.call(request).await.status,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert!(
            fixture
                .state
                .inv
                .get_user(&UserId("spec-limit-user".to_owned()))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn corp_timeout_keeps_security_headers_and_russian_generic_error() {
        let fixture = Fixture::new(true, true).await;
        let (cookie, csrf) = fixture.login().await;
        let body = Body::from_stream(tokio_stream::pending::<Result<Bytes, std::io::Error>>());
        let request = browser_request(
            "POST",
            "/api/corp/normalize",
            body,
            Some(&cookie),
            Some(&csrf),
        );
        let response =
            tokio::time::timeout(std::time::Duration::from_secs(20), fixture.call(request))
                .await
                .unwrap();
        assert_eq!(response.status, StatusCode::REQUEST_TIMEOUT);
        russian_api_error(&response);
        assert_eq!(
            fixture
                .state
                .inv
                .corp_record()
                .await
                .unwrap()
                .unwrap()
                .status
                .revision,
            0
        );
    }

    #[tokio::test]
    async fn password_form_accepts_one_and_512_utf8_bytes_at_the_documented_boundaries() {
        for password in ["x".to_owned(), "é".repeat(256)] {
            let fixture = Fixture::new(true, true).await;
            let mut credentials = fixture.credentials.clone();
            let salt = SaltString::encode_b64(b"0123456789abcdef").unwrap();
            let argon = Argon2::new(
                Algorithm::Argon2id,
                Version::V0x13,
                Params::new(8192, 1, 1, Some(32)).unwrap(),
            );
            credentials.password_phc = argon
                .hash_password(password.as_bytes(), &salt)
                .unwrap()
                .to_string();
            let status = fixture
                .state
                .inv
                .corp_record()
                .await
                .unwrap()
                .unwrap()
                .status;
            fixture
                .state
                .inv
                .update_corp_security(status.config_version, true, &credentials, "spec")
                .await
                .unwrap();
            let encoded = percent_encoding::utf8_percent_encode(
                &password,
                percent_encoding::NON_ALPHANUMERIC,
            );
            let response = fixture
                .call(login_request(&format!("password={encoded}")))
                .await;
            assert_eq!(response.status, StatusCode::SEE_OTHER);
            assert!(response.headers.contains_key("set-cookie"));
        }
    }

    #[tokio::test]
    async fn synthetic_ui_pages_are_usable_and_optionally_exported_for_narrow_width_rendering() {
        let fixture = Fixture::new(true, true).await;
        let login = fixture
            .call(browser_request("GET", "/", Body::empty(), None, None))
            .await;
        assert_eq!(login.status, StatusCode::OK);
        let (cookie, csrf) = fixture.login().await;
        let editor = fixture
            .call(browser_request(
                "GET",
                "/",
                Body::empty(),
                Some(&cookie),
                None,
            ))
            .await;
        assert_eq!(editor.status, StatusCode::OK);
        let mut denied_request = browser_request("GET", "/", Body::empty(), None, None);
        denied_request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(
                "198.51.100.99".parse().unwrap(),
                40123,
            )));
        let denied = fixture.call(denied_request).await;
        assert_eq!(denied.status, StatusCode::FORBIDDEN);
        let unconfigured = Fixture::new(false, false).await;
        let unavailable = unconfigured
            .call(request("GET", "/", Some(HOST), Body::empty()))
            .await;
        assert_eq!(unavailable.status, StatusCode::SERVICE_UNAVAILABLE);
        let pages = [
            ("login.html", login),
            ("editor.html", editor),
            ("denied.html", denied),
            ("unavailable.html", unavailable),
        ];
        for (_, page) in &pages {
            security_headers(page);
            assert!(
                page.headers["content-type"]
                    .to_str()
                    .unwrap()
                    .starts_with("text/html")
            );
            for secret in [
                PASSWORD,
                READER,
                &fixture.credentials.password_phc,
                &fixture.credentials.signing_keys[0].pkcs8,
            ] {
                assert!(!page.text().contains(secret));
            }
        }
        if let Some(directory) = std::env::var_os("CORP_UI_OUTPUT_DIR") {
            let directory = std::path::PathBuf::from(directory);
            std::fs::create_dir_all(directory.join("assets")).unwrap();
            for (name, page) in pages {
                let token = cookie.split_once('=').unwrap().1;
                let sanitized = page
                    .text()
                    .replace(&csrf, "SYNTHETIC_CSRF_FOR_RENDERING")
                    .replace(token, "SYNTHETIC_COOKIE_FOR_RENDERING");
                std::fs::write(directory.join(name), sanitized).unwrap();
                let mut headers = serde_json::Map::new();
                for name in [
                    "content-type",
                    "cache-control",
                    "x-content-type-options",
                    "x-frame-options",
                    "referrer-policy",
                    "x-robots-tag",
                    "content-security-policy",
                ] {
                    headers.insert(name.to_owned(), json!(page.headers[name].to_str().unwrap()));
                }
                let metadata = json!({"status": page.status.as_u16(), "headers": headers});
                let metadata_name = format!("{}.json", name.trim_end_matches(".html"));
                std::fs::write(
                    directory.join(metadata_name),
                    serde_json::to_vec_pretty(&metadata).unwrap(),
                )
                .unwrap();
            }
            for name in ["corp.css", "corp.js"] {
                let asset = fixture
                    .call(request(
                        "GET",
                        &format!("/assets/{name}"),
                        Some(HOST),
                        Body::empty(),
                    ))
                    .await;
                assert_eq!(asset.status, StatusCode::OK);
                std::fs::write(directory.join("assets").join(name), asset.bytes).unwrap();
            }
        }
    }

    #[tokio::test]
    async fn login_and_editor_html_keep_same_origin_policy_while_redirect_api_and_reader_do_not() {
        let fixture = Fixture::new(true, true).await;
        let login_page = fixture
            .call(browser_request("GET", "/", Body::empty(), None, None))
            .await;
        assert_eq!(login_page.status, StatusCode::OK);
        assert!(
            login_page.headers["content-type"]
                .to_str()
                .unwrap()
                .starts_with("text/html")
        );
        assert_eq!(login_page.headers["referrer-policy"], "same-origin");
        security_headers(&login_page);
        let login = fixture
            .call(login_request(&format!("password={PASSWORD}")))
            .await;
        assert_eq!(login.status, StatusCode::SEE_OTHER);
        assert_eq!(login.headers["referrer-policy"], "no-referrer");
        security_headers(&login);
        let cookie = login.headers["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        let editor = fixture
            .call(browser_request(
                "GET",
                "/",
                Body::empty(),
                Some(cookie),
                None,
            ))
            .await;
        assert_eq!(editor.status, StatusCode::OK);
        assert_eq!(editor.headers["referrer-policy"], "same-origin");
        security_headers(&editor);
        let state = fixture
            .call(browser_request(
                "GET",
                "/api/corp/state",
                Body::empty(),
                Some(cookie),
                None,
            ))
            .await;
        assert_eq!(state.status, StatusCode::OK);
        assert_eq!(state.headers["referrer-policy"], "no-referrer");
        security_headers(&state);
        fixture.publish_direct(vec![], "next_connection").await;
        let reader = fixture.call(reader_request(Some(HOST), Some(READER))).await;
        assert_eq!(reader.status, StatusCode::OK);
        assert_eq!(reader.headers["referrer-policy"], "no-referrer");
        security_headers(&reader);
    }
}
