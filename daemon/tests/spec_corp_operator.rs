#![allow(clippy::unwrap_used, clippy::expect_used)]

// Independent request specifications: fixtures and assertions derive only from
// docs/specs/corp-policy-{operator,store,wire,http,eligibility}.md.
use std::sync::{
    Arc,
    atomic::{AtomicI64, Ordering},
};

use axum::{
    body::{Body, to_bytes},
    http::{HeaderMap, Method, Request, StatusCode},
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use tower::ServiceExt;
use vpnctl_core::{User, UserId};
use vpnctl_inventory::{CorpPublication, SqliteInventory};
use vpnctld::{
    app,
    corp_operator::OperatorConfig,
    corp_policy::{PolicyPayload, PolicySigningKey},
};

const ORIGIN: &str = "https://operator.example.test";
const HOST: &str = "operator.example.test";
const NOW: i64 = 1_800_000_000;
const PASSWORD: &str = "synthetic-operator-password";
const ROUTES: &[(&str, &str)] = &[
    ("/setup", "user_id=synthetic-user&confirm_binding=true"),
    (
        "/enabled",
        "expected_config_version=1&enabled=false&confirm=true",
    ),
    ("/password/rotate", "expected_config_version=1&confirm=true"),
    ("/readers/add", "expected_config_version=1"),
    (
        "/readers/remove",
        "expected_config_version=1&reader_id=missing&confirm=true",
    ),
    ("/signers/add", "expected_config_version=1"),
    (
        "/signers/activate",
        "expected_config_version=1&key_id=missing&confirm=true",
    ),
    (
        "/signers/remove",
        "expected_config_version=1&key_id=missing&confirm=true",
    ),
    ("/sessions/revoke", "expected_config_version=1&confirm=true"),
    ("/export", "expected_config_version=1&reader_id=missing"),
    ("/probe", "expected_config_version=1&server_id=missing"),
];

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}
impl Reply {
    fn csrf(&self) -> String {
        extract(&self.body, "name=\"csrf\" value=\"", "\"")
    }
    fn password(&self) -> String {
        extract(
            &self.body,
            "<code id=\"corp-generated-password\">",
            "</code>",
        )
    }
    fn hardened(&self) {
        for (name, value) in [
            ("cache-control", "no-store"),
            ("x-content-type-options", "nosniff"),
            ("x-frame-options", "DENY"),
            ("x-robots-tag", "noindex"),
        ] {
            assert!(
                self.headers
                    .get(name)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .contains(value),
                "{name}"
            );
        }
        let html = self
            .headers
            .get("content-type")
            .is_some_and(|value| value.to_str().unwrap().starts_with("text/html"));
        let expected_referrer = if html
            && !self.status.is_redirection()
            && !self.headers.contains_key("content-disposition")
        {
            "same-origin"
        } else {
            "no-referrer"
        };
        assert_eq!(self.headers["referrer-policy"], expected_referrer);
        let csp = self
            .headers
            .get("content-security-policy")
            .unwrap()
            .to_str()
            .unwrap();
        for directive in [
            "script-src 'self'",
            "style-src 'self'",
            "connect-src 'self'",
            "form-action 'self'",
        ] {
            assert!(csp.contains(directive), "{csp}");
        }
        assert!(!csp.contains("'unsafe-inline'"));
    }
}
fn extract(body: &str, prefix: &str, suffix: &str) -> String {
    body.split_once(prefix)
        .expect("required spec markup")
        .1
        .split_once(suffix)
        .unwrap()
        .0
        .to_owned()
}
fn auth() -> String {
    format!("Basic {}", STANDARD.encode(format!("operator:{PASSWORD}")))
}
fn config(clock: Arc<AtomicI64>) -> OperatorConfig {
    OperatorConfig::from_parts(
        Some("operator".into()),
        Some(PASSWORD.into()),
        Some(ORIGIN.into()),
        "synthetic-install-secret",
    )
    .with_clock(Arc::new(move || clock.load(Ordering::SeqCst)))
}
struct Fixture {
    state: vpnctld::AppState,
    router: axum::Router,
    clock: Arc<AtomicI64>,
    job: tokio::task::JoinHandle<()>,
    dir: tempfile::TempDir,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.job.abort();
    }
}
impl Fixture {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let inv = SqliteInventory::open(&dir.path().join("synthetic.db"))
            .await
            .unwrap();
        inv.add_user(&User {
            id: UserId("synthetic-user".into()),
            uuid: "00000000-0000-4000-8000-000000000001".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
        let (state, job) =
            app::make_app_state_for_tests(inv, Arc::new(vpnctl_kernels::build_registry().unwrap()));
        let clock = Arc::new(AtomicI64::new(NOW));
        let router = app::router_with_corp_operator(state.clone(), config(Arc::clone(&clock)));
        Self {
            state,
            router,
            clock,
            job,
            dir,
        }
    }
    async fn send(&self, method: Method, uri: &str, body: &str, headers: &[(&str, &str)]) -> Reply {
        self.send_router(self.router.clone(), method, uri, body, headers)
            .await
    }
    async fn send_router(
        &self,
        router: axum::Router,
        method: Method,
        uri: &str,
        body: &str,
        headers: &[(&str, &str)],
    ) -> Reply {
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::from(body.to_owned()))
            .unwrap();
        for (name, value) in headers {
            request.headers_mut().append(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        let response = router.oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = String::from_utf8(
            to_bytes(response.into_body(), 1_048_576)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        let reply = Reply {
            status,
            headers,
            body,
        };
        reply.hardened();
        reply
    }
    async fn page(&self) -> Reply {
        self.send(
            Method::GET,
            "/admin/corp",
            "",
            &[("host", HOST), ("authorization", &auth())],
        )
        .await
    }
    async fn post_token(&self, route: &str, fields: &str, token: &str) -> Reply {
        self.send(
            Method::POST,
            &format!("/admin/corp{route}"),
            &format!("{fields}&csrf={token}"),
            &[
                ("host", HOST),
                ("authorization", &auth()),
                ("origin", ORIGIN),
                ("content-type", "application/x-www-form-urlencoded"),
            ],
        )
        .await
    }
    async fn post(&self, route: &str, fields: &str) -> Reply {
        self.post_token(route, fields, &self.page().await.csrf())
            .await
    }
    async fn setup(&self) -> String {
        let reply = self
            .post("/setup", "user_id=synthetic-user&confirm_binding=true")
            .await;
        assert_eq!(reply.status, StatusCode::OK);
        reply.password()
    }
    async fn record(&self) -> vpnctl_inventory::CorpRecord {
        self.state.inv.corp_record().await.unwrap().unwrap()
    }
    async fn snapshot(&self) -> (u64, u64, u64, String, bool) {
        let r = self.record().await;
        (
            r.status.config_version,
            r.status.auth_generation,
            r.status.revision,
            r.status.policy_id,
            r.status.enabled,
        )
    }
    async fn version_fields(&self) -> String {
        format!(
            "expected_config_version={}",
            self.record().await.status.config_version
        )
    }
    async fn pool(&self) -> sqlx::SqlitePool {
        sqlx::SqlitePool::connect(&format!(
            "sqlite://{}",
            self.dir.path().join("synthetic.db").display()
        ))
        .await
        .unwrap()
    }
    async fn audits(&self) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_log")
            .fetch_one(&self.pool().await)
            .await
            .unwrap()
    }
    async fn publish(&self) -> Vec<u8> {
        let r = self.record().await;
        self.state
            .inv
            .update_corp_security(
                r.status.config_version,
                true,
                &r.credentials,
                "synthetic-fixture",
            )
            .await
            .unwrap();
        let r = self.record().await;
        let key = r
            .credentials
            .signing_keys
            .iter()
            .find(|k| k.id == r.status.active_key_id)
            .unwrap();
        let signer =
            PolicySigningKey::from_pkcs8_der(&STANDARD.decode(&key.pkcs8).unwrap()).unwrap();
        let signed = signer
            .sign(&PolicyPayload {
                schema: 1,
                policy_id: r.status.policy_id,
                key_id: key.id.clone(),
                revision: 1,
                published_at: NOW as u64,
                apply: "next_connection".into(),
                rules: vec![],
            })
            .unwrap();
        self.state
            .inv
            .publish_corp_policy(
                &CorpPublication {
                    expected_revision: 0,
                    expected_config_version: r.status.config_version,
                    key_id: key.id.clone(),
                    published_at: NOW,
                    payload_sha256: signed.payload_sha256.to_ascii_lowercase(),
                    payload: signed.payload_bytes,
                    envelope: signed.envelope.clone(),
                },
                "synthetic-fixture",
            )
            .await
            .unwrap();
        signed.envelope
    }
}

#[tokio::test]
async fn every_operator_route_requires_operator_authentication() {
    for (route, fields) in ROUTES {
        for credential in [
            None,
            Some("Basic invalid"),
            Some("Bearer synthetic-reader"),
            Some("Basic d3Jvbmc6d3Jvbmc="),
        ] {
            let f = Fixture::new().await;
            let mut h = vec![
                ("host", HOST),
                ("origin", ORIGIN),
                ("content-type", "application/x-www-form-urlencoded"),
            ];
            if let Some(value) = credential {
                h.push(("authorization", value));
            }
            let r = f
                .send(Method::POST, &format!("/admin/corp{route}"), fields, &h)
                .await;
            assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{route}");
            assert!(f.state.inv.corp_record().await.unwrap().is_none());
        }
    }
    let f = Fixture::new().await;
    assert_eq!(
        f.send(
            Method::GET,
            "/admin/corp",
            "",
            &[
                ("host", HOST),
                ("cookie", "__Host-vpnctl_corp=synthetic-session")
            ]
        )
        .await
        .status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn absent_or_malformed_operator_configuration_fails_closed() {
    for (user, password, origin) in [
        (None, Some(PASSWORD), Some(ORIGIN)),
        (Some("operator"), None, Some(ORIGIN)),
        (Some(""), Some(""), Some(ORIGIN)),
        (Some("operator"), Some(PASSWORD), None),
        (
            Some("operator"),
            Some(PASSWORD),
            Some("http://operator.example.test"),
        ),
        (
            Some("operator"),
            Some(PASSWORD),
            Some("https://operator.example.test/"),
        ),
        (
            Some("operator"),
            Some(PASSWORD),
            Some("https://admin.corp.ninitux.com"),
        ),
        (
            Some("operator"),
            Some(PASSWORD),
            Some("https://user@operator.example.test"),
        ),
    ] {
        let f = Fixture::new().await;
        let c = OperatorConfig::from_parts(
            user.map(str::to_owned),
            password.map(str::to_owned),
            origin.map(str::to_owned),
            "synthetic-install-secret",
        );
        let router = app::router_with_corp_operator(f.state.clone(), c);
        for (method, path) in [
            (Method::GET, "/admin/corp"),
            (Method::POST, "/admin/corp/setup"),
        ] {
            assert_eq!(
                f.send_router(
                    router.clone(),
                    method,
                    path,
                    "",
                    &[("host", HOST), ("authorization", &auth())]
                )
                .await
                .status,
                StatusCode::SERVICE_UNAVAILABLE
            );
        }
    }
}

#[tokio::test]
async fn corp_host_never_dispatches_to_operator_even_with_operator_credentials() {
    for path in ["/admin/corp", "/admin/corp/setup", "/admin/corp/unknown"] {
        let f = Fixture::new().await;
        assert_eq!(
            f.send(
                Method::GET,
                path,
                "",
                &[
                    ("host", "admin.corp.ninitux.com"),
                    ("authorization", &auth())
                ]
            )
            .await
            .status,
            StatusCode::NOT_FOUND
        );
        assert!(f.state.inv.corp_record().await.unwrap().is_none());
    }
}

#[tokio::test]
async fn host_and_absolute_uri_must_match_pinned_https_origin() {
    for (uri, host) in [
        ("/admin/corp", "evil.example.test"),
        ("/admin/corp", "operator.example.test:443"),
        ("https://evil.example.test/admin/corp", HOST),
        ("http://operator.example.test/admin/corp", HOST),
    ] {
        let f = Fixture::new().await;
        assert_eq!(
            f.send(
                Method::GET,
                uri,
                "",
                &[("host", host), ("authorization", &auth())]
            )
            .await
            .status,
            StatusCode::BAD_REQUEST
        );
    }
    let f = Fixture::new().await;
    assert_eq!(
        f.send(
            Method::GET,
            "/admin/corp",
            "",
            &[("authorization", &auth())]
        )
        .await
        .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        f.send(
            Method::GET,
            "/admin/corp",
            "",
            &[
                ("host", "OPERATOR.EXAMPLE.TEST"),
                ("authorization", &auth())
            ]
        )
        .await
        .status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn ambiguous_security_headers_fail_before_authentication() {
    for name in ["host", "authorization", "cookie", "origin"] {
        let f = Fixture::new().await;
        let val = match name {
            "host" => HOST,
            "authorization" => "Basic invalid",
            "cookie" => "synthetic=value",
            _ => ORIGIN,
        };
        let mut h = vec![("host", HOST)];
        if name == "host" {
            h.clear();
        }
        h.extend([(name, val), (name, val)]);
        assert_eq!(
            f.send(Method::GET, "/admin/corp", "", &h).await.status,
            StatusCode::BAD_REQUEST,
            "{name}"
        );
    }
}

#[tokio::test]
async fn post_origin_requires_exact_single_pinned_origin_without_referer_fallback() {
    for origin in [
        None,
        Some("null"),
        Some("http://operator.example.test"),
        Some("https://operator.example.test/"),
        Some("https://evil.example.test"),
    ] {
        let f = Fixture::new().await;
        let token = f.page().await.csrf();
        let authorization = auth();
        let mut h = vec![
            ("host", HOST),
            ("authorization", authorization.as_str()),
            ("content-type", "application/x-www-form-urlencoded"),
            ("referer", ORIGIN),
        ];
        if let Some(value) = origin {
            h.push(("origin", value));
        }
        assert_eq!(
            f.send(
                Method::POST,
                "/admin/corp/setup",
                &format!("user_id=synthetic-user&confirm_binding=true&csrf={token}"),
                &h
            )
            .await
            .status,
            StatusCode::FORBIDDEN
        );
    }
}

#[tokio::test]
async fn cross_site_fetch_metadata_is_denied() {
    let f = Fixture::new().await;
    assert_eq!(
        f.send(
            Method::GET,
            "/admin/corp",
            "",
            &[
                ("host", HOST),
                ("authorization", &auth()),
                ("sec-fetch-site", "cross-site")
            ]
        )
        .await
        .status,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn csrf_is_random_canonical_authenticated_and_expires_at_one_hour() {
    let f = Fixture::new().await;
    let token = f.page().await.csrf();
    assert_ne!(token, f.page().await.csrf());
    let parts: Vec<_> = token.split('.').collect();
    assert_eq!(parts.len(), 4);
    assert_eq!(parts[0], "v1");
    assert_eq!(parts[1], NOW.to_string());
    for part in &parts[2..] {
        let bytes = URL_SAFE_NO_PAD.decode(part).unwrap();
        assert_eq!(bytes.len(), 32);
        assert_eq!(URL_SAFE_NO_PAD.encode(bytes), *part);
    }
    for bad in [
        format!("{token}x"),
        format!("{token}.extra"),
        "corp-session-csrf".into(),
    ] {
        assert_eq!(
            f.post_token(
                "/setup",
                "user_id=synthetic-user&confirm_binding=true",
                &bad
            )
            .await
            .status,
            StatusCode::FORBIDDEN
        );
    }
    f.clock.store(NOW - 1, Ordering::SeqCst);
    assert_eq!(
        f.post_token(
            "/setup",
            "user_id=synthetic-user&confirm_binding=true",
            &token
        )
        .await
        .status,
        StatusCode::FORBIDDEN
    );
    f.clock.store(NOW + 3600, Ordering::SeqCst);
    assert_eq!(
        f.post_token(
            "/setup",
            "user_id=synthetic-user&confirm_binding=true",
            &token
        )
        .await
        .status,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn csrf_is_bound_to_install_secret_credentials_and_origin() {
    for (user, password, origin, secret) in [
        ("operator", PASSWORD, ORIGIN, "changed-secret"),
        ("changed-user", PASSWORD, ORIGIN, "synthetic-install-secret"),
        (
            "operator",
            "changed-password",
            ORIGIN,
            "synthetic-install-secret",
        ),
        (
            "operator",
            PASSWORD,
            "https://other.example.test",
            "synthetic-install-secret",
        ),
    ] {
        let f = Fixture::new().await;
        let token = f.page().await.csrf();
        let c = OperatorConfig::from_parts(
            Some(user.into()),
            Some(password.into()),
            Some(origin.into()),
            secret,
        )
        .with_clock(Arc::new(|| NOW));
        let a = format!("Basic {}", STANDARD.encode(format!("{user}:{password}")));
        let host = origin.strip_prefix("https://").unwrap();
        assert_eq!(
            f.send_router(
                app::router_with_corp_operator(f.state.clone(), c),
                Method::POST,
                "/admin/corp/setup",
                &format!("user_id=synthetic-user&confirm_binding=true&csrf={token}"),
                &[
                    ("host", host),
                    ("authorization", &a),
                    ("origin", origin),
                    ("content-type", "application/x-www-form-urlencoded")
                ]
            )
            .await
            .status,
            StatusCode::FORBIDDEN
        );
    }
}

#[tokio::test]
async fn every_post_route_rejects_unknown_duplicate_and_missing_form_fields() {
    for (route, fields) in ROUTES {
        for suffix in [
            "&unexpected=synthetic",
            "&csrf=duplicate",
            "&expected_config_version=1&expected_config_version=1",
        ] {
            let f = Fixture::new().await;
            f.setup().await;
            let before = f.snapshot().await;
            assert_eq!(
                f.post(route, &format!("{fields}{suffix}")).await.status,
                StatusCode::UNPROCESSABLE_ENTITY,
                "{route}"
            );
            assert_eq!(f.snapshot().await, before);
        }
        let f = Fixture::new().await;
        f.setup().await;
        assert_eq!(
            f.post(route, "").await.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{route}"
        );
    }
}

#[tokio::test]
async fn wrong_content_type_malformed_encoding_queries_and_body_cap_are_rejected() {
    for (uri, body, content_type, expected) in [
        ("/admin/corp/setup", "{}", "application/json", 422),
        (
            "/admin/corp/setup",
            "%ZZ",
            "application/x-www-form-urlencoded",
            422,
        ),
        (
            "/admin/corp?reader_id=synthetic",
            "",
            "application/x-www-form-urlencoded",
            422,
        ),
    ] {
        let f = Fixture::new().await;
        let method = if body.is_empty() {
            Method::GET
        } else {
            Method::POST
        };
        assert_eq!(
            f.send(
                method,
                uri,
                body,
                &[
                    ("host", HOST),
                    ("authorization", &auth()),
                    ("origin", ORIGIN),
                    ("content-type", content_type)
                ]
            )
            .await
            .status
            .as_u16(),
            expected
        );
    }
    let f = Fixture::new().await;
    assert_eq!(
        f.send(
            Method::POST,
            "/admin/corp/setup",
            &"x".repeat(8193),
            &[
                ("host", HOST),
                ("authorization", &auth()),
                ("origin", ORIGIN),
                ("content-type", "application/x-www-form-urlencoded")
            ]
        )
        .await
        .status,
        StatusCode::PAYLOAD_TOO_LARGE
    );
}

#[tokio::test]
async fn decimal_versions_and_identifiers_are_exact_and_bounded() {
    for value in ["-1", "01", "1.0", "1e0", "18446744073709551616", "%2B1", ""] {
        let f = Fixture::new().await;
        f.setup().await;
        assert_eq!(
            f.post(
                "/sessions/revoke",
                &format!("expected_config_version={value}&confirm=true")
            )
            .await
            .status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{value}"
        );
    }
    for id in ["bad%2Fid".to_owned(), "a".repeat(65)] {
        let f = Fixture::new().await;
        f.setup().await;
        assert_eq!(
            f.post(
                "/readers/remove",
                &format!("expected_config_version=1&reader_id={id}&confirm=true")
            )
            .await
            .status,
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }
}

#[tokio::test]
async fn setup_is_disabled_immutable_and_password_is_revealed_only_once() {
    let f = Fixture::new().await;
    let password = f.setup().await;
    assert_eq!(URL_SAFE_NO_PAD.decode(&password).unwrap().len(), 32);
    let r = f.record().await;
    assert!(!r.status.enabled);
    assert_eq!(r.status.revision, 0);
    assert_eq!(r.status.config_version, 1);
    assert_eq!(r.status.auth_generation, 1);
    assert_eq!(r.status.user_id, UserId("synthetic-user".into()));
    assert_eq!(r.credentials.reader_tokens.len(), 1);
    assert_eq!(r.credentials.signing_keys.len(), 1);
    assert_ne!(password, r.credentials.reader_tokens[0].token);
    assert!(
        r.credentials
            .password_phc
            .starts_with("$argon2id$v=19$m=19456,t=2,p=1$")
    );
    let page = f.page().await;
    assert!(!page.body.contains(&password));
    assert_eq!(
        f.post("/setup", "user_id=synthetic-user&confirm_binding=true")
            .await
            .status,
        StatusCode::CONFLICT
    );
    assert_eq!(f.record().await.status.policy_id, r.status.policy_id);
}

#[tokio::test]
async fn setup_rejects_missing_user_or_missing_confirmation_without_binding() {
    for (fields, expected) in [
        (
            "user_id=missing&confirm_binding=true",
            StatusCode::NOT_FOUND,
        ),
        (
            "user_id=synthetic-user&confirm_binding=false",
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
    ] {
        let f = Fixture::new().await;
        assert_eq!(f.post("/setup", fields).await.status, expected);
        assert!(f.state.inv.corp_record().await.unwrap().is_none());
    }
}

#[tokio::test]
async fn existing_binding_routes_reject_stale_versions_without_retry_or_mutation() {
    for (route, fields) in ROUTES.iter().filter(|(route, _)| *route != "/setup") {
        let f = Fixture::new().await;
        f.setup().await;
        let before = f.snapshot().await;
        let audits = f.audits().await;
        assert_eq!(
            f.post(
                route,
                &fields.replace("expected_config_version=1", "expected_config_version=0")
            )
            .await
            .status,
            StatusCode::CONFLICT,
            "{route}"
        );
        assert_eq!(f.snapshot().await, before);
        assert_eq!(f.audits().await, audits);
    }
}

#[tokio::test]
async fn enable_and_probe_remain_unavailable_and_preserve_all_evidence() {
    for (route, fields) in [
        (
            "/enabled",
            "expected_config_version=1&enabled=true&confirm=true",
        ),
        (
            "/probe",
            "expected_config_version=1&server_id=synthetic-server",
        ),
    ] {
        let f = Fixture::new().await;
        f.setup().await;
        let before = f.snapshot().await;
        let audits = f.audits().await;
        assert_eq!(
            f.post(route, fields).await.status,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(f.snapshot().await, before);
        assert_eq!(f.audits().await, audits);
        assert!(f.state.inv.corp_verified_egress().await.unwrap().is_empty());
    }
}

#[tokio::test]
async fn disable_is_available_and_identical_disable_has_no_audit() {
    let f = Fixture::new().await;
    f.setup().await;
    let before = f.snapshot().await;
    let audits = f.audits().await;
    let reply = f
        .post(
            "/enabled",
            "expected_config_version=1&enabled=false&confirm=true",
        )
        .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    assert_eq!(reply.headers["location"], "/admin/corp/company/legacy");
    assert_eq!(f.snapshot().await, before);
    assert_eq!(f.audits().await, audits);
}

#[tokio::test]
async fn password_rotation_changes_only_password_and_revokes_old_generation() {
    let f = Fixture::new().await;
    let old = f.setup().await;
    let before = f.record().await;
    let reply = f
        .post("/password/rotate", "expected_config_version=1&confirm=true")
        .await;
    assert_eq!(reply.status, StatusCode::OK);
    let new = reply.password();
    assert_ne!(old, new);
    let after = f.record().await;
    assert_ne!(
        before.credentials.password_phc,
        after.credentials.password_phc
    );
    assert_eq!(
        before.credentials.reader_tokens[0].token,
        after.credentials.reader_tokens[0].token
    );
    assert_eq!(
        before.credentials.signing_keys[0].pkcs8,
        after.credentials.signing_keys[0].pkcs8
    );
    assert_eq!(
        after.status.auth_generation,
        before.status.auth_generation + 1
    );
    assert!(!f.page().await.body.contains(&new));
    let stale = f
        .state
        .inv
        .issue_corp_session(
            before.status.auth_generation,
            &vpnctl_inventory::CorpSessionInput {
                token_hash: "a".repeat(64),
                csrf_token: "A".repeat(43),
                expires_at: NOW + 100,
            },
            NOW,
            "synthetic-fixture",
        )
        .await;
    assert!(stale.is_err());
}

#[tokio::test]
async fn reader_overlap_is_explicit_and_never_removes_last_reader() {
    let f = Fixture::new().await;
    f.setup().await;
    let first = f.record().await.credentials.reader_tokens[0].clone();
    assert_eq!(
        f.post(
            "/readers/remove",
            &format!(
                "expected_config_version=1&reader_id={}&confirm=true",
                first.id
            )
        )
        .await
        .status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        f.post("/readers/add", "expected_config_version=1")
            .await
            .status,
        StatusCode::SEE_OTHER
    );
    let r = f.record().await;
    assert_eq!(r.credentials.reader_tokens.len(), 2);
    assert!(
        r.credentials
            .reader_tokens
            .iter()
            .any(|x| x.id == first.id && x.token == first.token)
    );
    assert_eq!(
        f.post("/readers/add", &f.version_fields().await)
            .await
            .status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        f.post(
            "/readers/remove",
            &format!(
                "{}&reader_id={}&confirm=true",
                f.version_fields().await,
                first.id
            )
        )
        .await
        .status,
        StatusCode::SEE_OTHER
    );
    assert!(
        !f.record()
            .await
            .credentials
            .reader_tokens
            .iter()
            .any(|x| x.id == first.id)
    );
}

#[tokio::test]
async fn signer_overlap_requires_explicit_activation_and_has_four_key_limit() {
    let f = Fixture::new().await;
    f.setup().await;
    let initial = f.record().await.status.active_key_id;
    for _ in 0..3 {
        assert_eq!(
            f.post("/signers/add", &f.version_fields().await)
                .await
                .status,
            StatusCode::SEE_OTHER
        );
        assert_eq!(f.record().await.status.active_key_id, initial);
    }
    assert_eq!(
        f.post("/signers/add", &f.version_fields().await)
            .await
            .status,
        StatusCode::CONFLICT
    );
    let r = f.record().await;
    assert_eq!(r.credentials.signing_keys.len(), 4);
    let next = &r
        .credentials
        .signing_keys
        .iter()
        .find(|k| k.id != initial)
        .unwrap()
        .id;
    assert_eq!(
        f.post(
            "/signers/activate",
            &format!("{}&key_id={next}&confirm=true", f.version_fields().await)
        )
        .await
        .status,
        StatusCode::SEE_OTHER
    );
    assert_eq!(f.record().await.status.active_key_id, *next);
    assert_eq!(
        f.post(
            "/signers/remove",
            &format!("{}&key_id={next}&confirm=true", f.version_fields().await)
        )
        .await
        .status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        f.post(
            "/signers/remove",
            &format!("{}&key_id={initial}&confirm=true", f.version_fields().await)
        )
        .await
        .status,
        StatusCode::SEE_OTHER
    );
}

#[tokio::test]
async fn unknown_reader_signer_and_export_targets_are_not_found() {
    for (route, extra) in [
        ("/readers/remove", "reader_id=missing&confirm=true"),
        ("/signers/activate", "key_id=missing&confirm=true"),
        ("/signers/remove", "key_id=missing&confirm=true"),
        ("/export", "reader_id=missing"),
    ] {
        let f = Fixture::new().await;
        f.setup().await;
        assert_eq!(
            f.post(route, &format!("expected_config_version=1&{extra}"))
                .await
                .status,
            StatusCode::NOT_FOUND
        );
    }
}

#[tokio::test]
async fn protected_export_is_exact_client_capability_and_is_read_only() {
    let f = Fixture::new().await;
    let password = f.setup().await;
    let r = f.record().await;
    let audits = f.audits().await;
    let reply = f
        .post(
            "/export",
            &format!(
                "expected_config_version=1&reader_id={}",
                r.credentials.reader_tokens[0].id
            ),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert!(
        reply.headers["content-disposition"]
            .to_str()
            .unwrap()
            .contains("attachment;")
    );
    assert!(!reply.headers.contains_key("location"));
    let value: serde_json::Value = serde_json::from_str(&reply.body).unwrap();
    let object = value.as_object().unwrap();
    assert_eq!(object.len(), 4);
    assert_eq!(value["policy_id"], r.status.policy_id);
    assert_eq!(
        value["endpoint"],
        "https://admin.corp.ninitux.com/api/v1/corp/policy"
    );
    assert_eq!(value["read_token"], r.credentials.reader_tokens[0].token);
    let keys = value["keys"].as_array().unwrap();
    assert_eq!(keys.len(), r.credentials.signing_keys.len());
    for key in keys {
        assert_eq!(key.as_object().unwrap().len(), 2);
        let source = r
            .credentials
            .signing_keys
            .iter()
            .find(|s| s.id == key["id"])
            .unwrap();
        assert_eq!(key["spki"], source.spki);
    }
    for secret in [
        &password,
        &r.credentials.password_phc,
        &r.credentials.signing_keys[0].pkcs8,
    ] {
        assert!(!reply.body.contains(secret));
    }
    assert_eq!(f.audits().await, audits);
    assert_eq!(f.record().await.status.config_version, 1);
}

#[tokio::test]
async fn revoke_sessions_advances_both_generations_even_without_sessions() {
    let f = Fixture::new().await;
    f.setup().await;
    let before = f.record().await;
    assert_eq!(
        f.post("/sessions/revoke", "expected_config_version=1&confirm=true")
            .await
            .status,
        StatusCode::SEE_OTHER
    );
    let after = f.record().await;
    assert_eq!(
        after.status.auth_generation,
        before.status.auth_generation + 1
    );
    assert_eq!(
        after.status.config_version,
        before.status.config_version + 1
    );
    assert_eq!(after.status.policy_id, before.status.policy_id);
    assert_eq!(after.status.revision, 0);
}

#[tokio::test]
async fn retained_publication_key_cannot_be_retired_and_rotations_preserve_exact_envelope() {
    let f = Fixture::new().await;
    f.setup().await;
    let envelope = f.publish().await;
    let before = f.record().await;
    let original = before.status.active_key_id.clone();
    for route in [
        "/readers/add",
        "/signers/add",
        "/password/rotate",
        "/sessions/revoke",
    ] {
        let extra = if matches!(route, "/password/rotate" | "/sessions/revoke") {
            "&confirm=true"
        } else {
            ""
        };
        let reply = f
            .post(route, &format!("{}{extra}", f.version_fields().await))
            .await;
        assert!(matches!(
            reply.status,
            StatusCode::OK | StatusCode::SEE_OTHER
        ));
        let r = f.record().await;
        assert_eq!(r.status.policy_id, before.status.policy_id);
        assert_eq!(r.status.user_id, before.status.user_id);
        assert_eq!(r.status.revision, 1);
        assert_eq!(
            f.state
                .inv
                .corp_revision(1)
                .await
                .unwrap()
                .unwrap()
                .envelope,
            envelope
        );
    }
    let r = f.record().await;
    let next = &r
        .credentials
        .signing_keys
        .iter()
        .find(|k| k.id != original)
        .unwrap()
        .id;
    assert_eq!(
        f.post(
            "/signers/activate",
            &format!("{}&key_id={next}&confirm=true", f.version_fields().await)
        )
        .await
        .status,
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        f.post(
            "/signers/remove",
            &format!(
                "{}&key_id={original}&confirm=true",
                f.version_fields().await
            )
        )
        .await
        .status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        f.state
            .inv
            .corp_revision(1)
            .await
            .unwrap()
            .unwrap()
            .envelope,
        envelope
    );
}

#[tokio::test]
async fn audit_failure_rolls_back_operator_security_write_and_redacts_error() {
    let f = Fixture::new().await;
    f.setup().await;
    let before = f.record().await;
    let snapshot = f.snapshot().await;
    sqlx::query("CREATE TRIGGER synthetic_audit_failure BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT, 'synthetic-private-database-detail'); END").execute(&f.pool().await).await.unwrap();
    let reply = f
        .post("/password/rotate", "expected_config_version=1&confirm=true")
        .await;
    assert_eq!(reply.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(!reply.body.contains("synthetic-private-database-detail"));
    assert!(!reply.body.contains("corp-generated-password"));
    assert_eq!(f.snapshot().await, snapshot);
    assert_eq!(
        f.record().await.credentials.password_phc,
        before.credentials.password_phc
    );
}

#[tokio::test]
async fn sanitized_status_and_debug_never_reveal_recoverable_credentials() {
    let f = Fixture::new().await;
    let password = f.setup().await;
    let r = f.record().await;
    let page = f.page().await;
    assert_eq!(page.status, StatusCode::OK);
    let debug = format!("{r:?}");
    for secret in [
        &password,
        &r.credentials.password_phc,
        &r.credentials.reader_tokens[0].token,
        &r.credentials.signing_keys[0].pkcs8,
    ] {
        assert!(!page.body.contains(secret));
        assert!(!debug.contains(secret));
    }
    for safe in [
        &r.status.policy_id,
        &r.status.active_key_id,
        &r.credentials.reader_tokens[0].id,
    ] {
        assert!(page.body.contains(safe));
    }
    assert!(!page.body.contains("<script>"));
    assert!(!page.body.contains("SSH"));
}

#[tokio::test]
async fn reserved_subtree_unknown_paths_and_unsupported_methods_do_not_fall_through() {
    let f = Fixture::new().await;
    for path in ["/admin/corp/unknown", "/admin/corp/"] {
        assert_eq!(
            f.send(
                Method::GET,
                path,
                "",
                &[("host", HOST), ("authorization", &auth())]
            )
            .await
            .status,
            StatusCode::NOT_FOUND
        );
    }
    assert_eq!(
        f.send(
            Method::PUT,
            "/admin/corp",
            "",
            &[("host", HOST), ("authorization", &auth())]
        )
        .await
        .status,
        StatusCode::METHOD_NOT_ALLOWED
    );
}

#[tokio::test]
async fn optional_synthetic_ui_capture_contains_actual_router_responses() {
    let Some(output) = std::env::var_os("CORP_OPERATOR_UI_OUTPUT_DIR") else {
        return;
    };
    let f = Fixture::new().await;
    let output = std::path::PathBuf::from(output);
    std::fs::create_dir_all(&output).unwrap();
    fn save(output: &std::path::Path, name: &str, reply: &Reply) {
        std::fs::write(output.join(format!("{name}.html")), &reply.body).unwrap();
        let headers: serde_json::Map<String, serde_json::Value> = reply
            .headers
            .iter()
            .filter(|(k, _)| {
                matches!(
                    k.as_str(),
                    "cache-control"
                        | "referrer-policy"
                        | "x-content-type-options"
                        | "x-frame-options"
                        | "x-robots-tag"
                        | "content-security-policy"
                        | "content-type"
                )
            })
            .map(|(k, v)| {
                (
                    k.to_string(),
                    serde_json::Value::String(v.to_str().unwrap().into()),
                )
            })
            .collect();
        std::fs::write(
            output.join(format!("{name}.json")),
            serde_json::to_vec_pretty(
                &serde_json::json!({"status":reply.status.as_u16(),"headers":headers}),
            )
            .unwrap(),
        )
        .unwrap();
    }
    save(&output, "setup", &f.page().await);
    let reveal = f
        .post("/setup", "user_id=synthetic-user&confirm_binding=true")
        .await;
    assert_eq!(reveal.status, StatusCode::OK);
    assert!(reveal.body.contains("настройка диагностики не завершилась"));
    assert!(reveal.body.contains("Повторить настройку диагностики"));
    save(&output, "password-result", &reveal);
    assert_eq!(
        f.post("/readers/add", &f.version_fields().await)
            .await
            .status,
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        f.post("/signers/add", &f.version_fields().await)
            .await
            .status,
        StatusCode::SEE_OTHER
    );
    // An eligible but unverified synthetic endpoint supplies the per-server
    // probe form without any network access or claimed exit verification.
    let server_id = vpnctl_core::ServerId("synthetic-ui-server".into());
    f.state
        .inv
        .add_server(&vpnctl_core::Server {
            id: server_id.clone(),
            address: "192.0.2.10".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![vpnctl_core::KernelId("sing-box".into())],
            enabled_protocols: vec![vpnctl_core::ProtocolId("vless+reality".into())],
            trusted_host_fingerprint: None,
            hoster: "synthetic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    f.state
        .inv
        .grant(&UserId("synthetic-user".into()), &server_id)
        .await
        .unwrap();
    for (name, value) in [
        ("vless.public_key", URL_SAFE_NO_PAD.encode([7_u8; 32])),
        ("vless.short_id", "12345678".into()),
        ("vless.sni", "www.example.com".into()),
    ] {
        f.state
            .inv
            .set_server_secret(&server_id, name, &value)
            .await
            .unwrap();
    }
    let eligible = vpnctld::corp_portal::eligibility::eligible_servers(
        &f.state,
        &UserId("synthetic-user".into()),
    )
    .await
    .unwrap();
    assert!(eligible.iter().any(|server| server.server_id == server_id));
    assert!(f.state.inv.corp_verified_egress().await.unwrap().is_empty());
    let status = f.page().await;
    save(&output, "status", &status);
    let companies = f
        .send(
            Method::GET,
            "/admin/corp/companies",
            "",
            &[("host", HOST), ("authorization", &auth())],
        )
        .await;
    assert_eq!(companies.status, StatusCode::OK);
    save(&output, "company-list", &companies);
    let companies_ink = f
        .send(
            Method::GET,
            "/admin/corp/companies",
            "",
            &[
                ("host", HOST),
                ("authorization", &auth()),
                ("cookie", "vpnctl_theme=ink; vpnctl_accent=forest"),
            ],
        )
        .await;
    assert_eq!(companies_ink.status, StatusCode::OK);
    save(&output, "company-list-ink", &companies_ink);
    let selected = f
        .send(
            Method::GET,
            "/admin/corp/company/legacy",
            "",
            &[("host", HOST), ("authorization", &auth())],
        )
        .await;
    assert_eq!(selected.status, StatusCode::OK);
    save(&output, "company-selected", &selected);
    for (route, _) in ROUTES.iter().filter(|(r, _)| *r != "/setup") {
        assert!(
            status.body.contains(&format!("/admin/corp{route}")),
            "missing form {route}"
        );
    }
    let conflict = f
        .post("/sessions/revoke", "expected_config_version=1&confirm=true")
        .await;
    assert_eq!(conflict.status, StatusCode::CONFLICT);
    save(&output, "conflict", &conflict);
    let css = f
        .send(
            Method::GET,
            "/admin/corp/assets/operator.css",
            "",
            &[("host", HOST), ("authorization", &auth())],
        )
        .await;
    assert_eq!(css.status, StatusCode::OK);
    std::fs::create_dir_all(output.join("assets")).unwrap();
    std::fs::write(output.join("assets/operator.css"), css.body).unwrap();
}

#[tokio::test]
async fn verified_operator_cookie_authenticates_but_duplicate_cookie_names_are_rejected() {
    let f = Fixture::new().await;
    let page = f.page().await;
    let cookie = page
        .headers
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap())
        .find(|v| v.starts_with("vpnctl_admin_session="))
        .expect("successful Basic authentication issues operator cookie")
        .split(';')
        .next()
        .unwrap();
    assert_eq!(
        f.send(
            Method::GET,
            "/admin/corp",
            "",
            &[("host", HOST), ("cookie", cookie)]
        )
        .await
        .status,
        StatusCode::OK
    );
    assert_eq!(
        f.send(
            Method::GET,
            "/admin/corp",
            "",
            &[("host", HOST), ("cookie", &format!("{cookie}; {cookie}"))]
        )
        .await
        .status,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn deleted_user_cannot_be_rebound_and_disabled_binding_can_still_be_repaired() {
    let f = Fixture::new().await;
    f.setup().await;
    let original = f.record().await.status;
    f.state.inv.remove_user(&original.user_id).await.unwrap();
    assert_eq!(
        f.post("/setup", "user_id=synthetic-user&confirm_binding=true")
            .await
            .status,
        StatusCode::CONFLICT
    );
    assert_eq!(f.page().await.status, StatusCode::OK);
    assert_eq!(
        f.post(
            "/password/rotate",
            &format!("{}&confirm=true", f.version_fields().await)
        )
        .await
        .status,
        StatusCode::OK
    );
    assert_eq!(
        f.post(
            "/sessions/revoke",
            &format!("{}&confirm=true", f.version_fields().await)
        )
        .await
        .status,
        StatusCode::SEE_OTHER
    );
    let after = f.record().await.status;
    assert_eq!(after.user_id, original.user_id);
    assert_eq!(after.policy_id, original.policy_id);
    assert!(!after.enabled);
}

#[tokio::test]
async fn disabled_user_cannot_be_selected_for_setup() {
    let f = Fixture::new().await;
    let csrf = f.page().await.csrf();
    f.state
        .inv
        .set_user_disabled(&UserId("synthetic-user".into()), true)
        .await
        .unwrap();
    assert_eq!(
        f.post_token(
            "/setup",
            "user_id=synthetic-user&confirm_binding=true",
            &csrf
        )
        .await
        .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(f.state.inv.corp_record().await.unwrap().is_none());
}

#[tokio::test]
async fn password_rotation_accepts_only_new_password_and_uses_required_phc_parameters() {
    use argon2::{Argon2, PasswordHash, PasswordVerifier};
    let f = Fixture::new().await;
    let old = f.setup().await;
    let new = f
        .post("/password/rotate", "expected_config_version=1&confirm=true")
        .await
        .password();
    let record = f.record().await;
    let phc = PasswordHash::new(&record.credentials.password_phc).unwrap();
    assert!(
        Argon2::default()
            .verify_password(new.as_bytes(), &phc)
            .is_ok()
    );
    assert!(
        Argon2::default()
            .verify_password(old.as_bytes(), &phc)
            .is_err()
    );
    assert_eq!(
        phc.salt.unwrap().decode_b64(&mut [0_u8; 64]).unwrap().len(),
        16
    );
    assert_eq!(phc.hash.unwrap().as_bytes().len(), 32);
}

#[tokio::test]
async fn security_changes_revoke_existing_sessions_and_reject_in_flight_old_generation() {
    for route in [
        "/password/rotate",
        "/readers/add",
        "/signers/add",
        "/sessions/revoke",
        "/enabled",
    ] {
        let f = Fixture::new().await;
        f.setup().await;
        f.publish().await;
        let before = f.record().await;
        let digest = "a".repeat(64);
        let input = vpnctl_inventory::CorpSessionInput {
            token_hash: digest.clone(),
            csrf_token: "A".repeat(43),
            expires_at: NOW + 100,
        };
        f.state
            .inv
            .issue_corp_session(
                before.status.auth_generation,
                &input,
                NOW,
                "synthetic-fixture",
            )
            .await
            .unwrap();
        assert!(
            f.state
                .inv
                .corp_session(&digest, NOW)
                .await
                .unwrap()
                .is_some()
        );
        let extra = match route {
            "/enabled" => "&enabled=false&confirm=true",
            "/password/rotate" | "/sessions/revoke" => "&confirm=true",
            _ => "",
        };
        let reply = f
            .post(route, &format!("{}{extra}", f.version_fields().await))
            .await;
        assert!(matches!(
            reply.status,
            StatusCode::OK | StatusCode::SEE_OTHER
        ));
        assert!(
            f.state
                .inv
                .corp_session(&digest, NOW)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            f.state
                .inv
                .issue_corp_session(
                    before.status.auth_generation,
                    &input,
                    NOW,
                    "synthetic-fixture"
                )
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn reader_overlap_fetches_exact_envelope_until_explicit_removal() {
    let f = Fixture::new().await;
    f.setup().await;
    let envelope = f.publish().await;
    let old = f.record().await.credentials.reader_tokens[0].clone();
    assert_eq!(
        f.post("/readers/add", &f.version_fields().await)
            .await
            .status,
        StatusCode::SEE_OTHER
    );
    for reader in f.record().await.credentials.reader_tokens {
        let reply = f
            .send(
                Method::GET,
                "/api/v1/corp/policy",
                "",
                &[
                    ("host", "admin.corp.ninitux.com"),
                    ("authorization", &format!("Bearer {}", reader.token)),
                ],
            )
            .await;
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(reply.body.as_bytes(), envelope);
    }
    assert_eq!(
        f.post(
            "/readers/remove",
            &format!(
                "{}&reader_id={}&confirm=true",
                f.version_fields().await,
                old.id
            )
        )
        .await
        .status,
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        f.send(
            Method::GET,
            "/api/v1/corp/policy",
            "",
            &[
                ("host", "admin.corp.ninitux.com"),
                ("authorization", &format!("Bearer {}", old.token))
            ]
        )
        .await
        .status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn committed_rotation_survives_database_reopen() {
    let f = Fixture::new().await;
    f.setup().await;
    assert_eq!(
        f.post("/readers/add", "expected_config_version=1")
            .await
            .status,
        StatusCode::SEE_OTHER
    );
    let expected = f.record().await;
    let reopened = SqliteInventory::open(&f.dir.path().join("synthetic.db"))
        .await
        .unwrap();
    let actual = reopened.corp_record().await.unwrap().unwrap();
    assert_eq!(actual.status.policy_id, expected.status.policy_id);
    assert_eq!(actual.status.config_version, expected.status.config_version);
    assert_eq!(actual.credentials.reader_tokens.len(), 2);
    for reader in expected.credentials.reader_tokens {
        assert!(
            actual
                .credentials
                .reader_tokens
                .iter()
                .any(|r| r.id == reader.id && r.token == reader.token)
        );
    }
}

async fn corrupt_enabled_signer_pair(f: &Fixture) -> vpnctl_inventory::CorpRecord {
    f.setup().await;
    f.publish().await;
    let mut record = f.record().await;
    let unrelated = PolicySigningKey::generate().unwrap().spki_base64().unwrap();
    assert_ne!(record.credentials.signing_keys[0].spki, unrelated);
    record.credentials.signing_keys[0].spki = unrelated;
    f.state
        .inv
        .update_corp_security(
            record.status.config_version,
            true,
            &record.credentials,
            "synthetic-corrupt-pair-fixture",
        )
        .await
        .unwrap();
    f.record().await
}

fn assert_credentials_unchanged(
    actual: &vpnctl_inventory::CorpCredentials,
    expected: &vpnctl_inventory::CorpCredentials,
) {
    assert_eq!(actual.password_phc, expected.password_phc);
    assert_eq!(actual.active_key_id, expected.active_key_id);
    assert_eq!(actual.reader_tokens.len(), expected.reader_tokens.len());
    for (actual, expected) in actual.reader_tokens.iter().zip(&expected.reader_tokens) {
        assert_eq!(actual.id, expected.id);
        assert_eq!(actual.token, expected.token);
    }
    assert_eq!(actual.signing_keys.len(), expected.signing_keys.len());
    for (actual, expected) in actual.signing_keys.iter().zip(&expected.signing_keys) {
        assert_eq!(actual.id, expected.id);
        assert_eq!(actual.pkcs8, expected.pkcs8);
        assert_eq!(actual.spki, expected.spki);
    }
}

#[tokio::test]
async fn emergency_disable_preserves_mismatched_signer_pair_and_revokes_sessions_atomically() {
    let f = Fixture::new().await;
    let before = corrupt_enabled_signer_pair(&f).await;
    let envelope = f
        .state
        .inv
        .corp_revision(1)
        .await
        .unwrap()
        .unwrap()
        .envelope;
    let digest = "b".repeat(64);
    let session = vpnctl_inventory::CorpSessionInput {
        token_hash: digest.clone(),
        csrf_token: URL_SAFE_NO_PAD.encode([1_u8; 32]),
        expires_at: NOW + 100,
    };
    f.state
        .inv
        .issue_corp_session(
            before.status.auth_generation,
            &session,
            NOW,
            "synthetic-fixture",
        )
        .await
        .unwrap();
    assert!(
        f.state
            .inv
            .corp_session(&digest, NOW)
            .await
            .unwrap()
            .is_some()
    );
    let audits = f.audits().await;
    let reply = f
        .post(
            "/enabled",
            &format!(
                "expected_config_version={}&enabled=false&confirm=true",
                before.status.config_version
            ),
        )
        .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    assert_eq!(reply.headers["location"], "/admin/corp/company/legacy");
    let after = f.record().await;
    assert!(!after.status.enabled);
    assert_eq!(
        after.status.config_version,
        before.status.config_version + 1
    );
    assert_eq!(
        after.status.auth_generation,
        before.status.auth_generation + 1
    );
    assert_eq!(after.status.user_id, before.status.user_id);
    assert_eq!(after.status.policy_id, before.status.policy_id);
    assert_eq!(after.status.revision, before.status.revision);
    assert_credentials_unchanged(&after.credentials, &before.credentials);
    assert_eq!(
        f.state
            .inv
            .corp_revision(1)
            .await
            .unwrap()
            .unwrap()
            .envelope,
        envelope
    );
    assert_eq!(f.audits().await, audits + 1);
    assert!(
        f.state
            .inv
            .corp_session(&digest, NOW)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        f.state
            .inv
            .issue_corp_session(
                before.status.auth_generation,
                &session,
                NOW,
                "synthetic-fixture"
            )
            .await
            .is_err()
    );
    let audits = f.audits().await;
    let snapshot = f.snapshot().await;
    assert_eq!(
        f.post(
            "/enabled",
            &format!("{}&enabled=false&confirm=true", f.version_fields().await)
        )
        .await
        .status,
        StatusCode::SEE_OTHER
    );
    assert_eq!(f.snapshot().await, snapshot);
    assert_eq!(f.audits().await, audits);
    assert_credentials_unchanged(&f.record().await.credentials, &before.credentials);
}

#[tokio::test]
async fn emergency_disable_with_corrupt_pair_still_requires_current_config_version() {
    let f = Fixture::new().await;
    let before = corrupt_enabled_signer_pair(&f).await;
    let snapshot = f.snapshot().await;
    let audits = f.audits().await;
    let reply = f
        .post(
            "/enabled",
            &format!(
                "expected_config_version={}&enabled=false&confirm=true",
                before.status.config_version - 1
            ),
        )
        .await;
    assert_eq!(reply.status, StatusCode::CONFLICT);
    assert_eq!(f.snapshot().await, snapshot);
    assert_eq!(f.audits().await, audits);
    assert_credentials_unchanged(&f.record().await.credentials, &before.credentials);
}

#[tokio::test]
async fn emergency_disable_with_corrupt_pair_rolls_back_on_audit_failure() {
    let f = Fixture::new().await;
    let before = corrupt_enabled_signer_pair(&f).await;
    let session = vpnctl_inventory::CorpSessionInput {
        token_hash: "c".repeat(64),
        csrf_token: URL_SAFE_NO_PAD.encode([2_u8; 32]),
        expires_at: NOW + 100,
    };
    f.state
        .inv
        .issue_corp_session(
            before.status.auth_generation,
            &session,
            NOW,
            "synthetic-fixture",
        )
        .await
        .unwrap();
    let snapshot = f.snapshot().await;
    let audits = f.audits().await;
    sqlx::query("CREATE TRIGGER synthetic_disable_audit_failure BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT, 'synthetic-private-disable-detail'); END").execute(&f.pool().await).await.unwrap();
    let reply = f
        .post(
            "/enabled",
            &format!(
                "expected_config_version={}&enabled=false&confirm=true",
                before.status.config_version
            ),
        )
        .await;
    assert_eq!(reply.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(!reply.body.contains("synthetic-private-disable-detail"));
    assert_eq!(f.snapshot().await, snapshot);
    assert_eq!(f.audits().await, audits);
    assert_credentials_unchanged(&f.record().await.credentials, &before.credentials);
    assert!(
        f.state
            .inv
            .corp_session(&session.token_hash, NOW)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn emergency_disable_exception_does_not_authorize_credential_writes_or_enable() {
    for (route, extra) in [
        ("/readers/add", ""),
        ("/signers/add", ""),
        ("/password/rotate", "&confirm=true"),
        ("/enabled", "&enabled=true&confirm=true"),
    ] {
        let f = Fixture::new().await;
        let before = corrupt_enabled_signer_pair(&f).await;
        let snapshot = f.snapshot().await;
        let audits = f.audits().await;
        assert_eq!(
            f.post(
                route,
                &format!(
                    "expected_config_version={}{extra}",
                    before.status.config_version
                )
            )
            .await
            .status,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(f.snapshot().await, snapshot);
        assert_eq!(f.audits().await, audits);
        assert_credentials_unchanged(&f.record().await.credentials, &before.credentials);
    }
}

#[tokio::test]
async fn operator_html_preserves_same_origin_form_navigation_but_downloads_and_redirects_do_not() {
    let f = Fixture::new().await;
    let setup_page = f.page().await;
    assert_eq!(setup_page.status, StatusCode::OK);
    assert_eq!(setup_page.headers["referrer-policy"], "same-origin");
    assert!(
        setup_page.headers["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/html")
    );
    let reveal = f
        .post("/setup", "user_id=synthetic-user&confirm_binding=true")
        .await;
    assert_eq!(reveal.status, StatusCode::OK);
    assert_eq!(reveal.headers["referrer-policy"], "same-origin");
    let status = f.page().await;
    assert_eq!(status.headers["referrer-policy"], "same-origin");
    let reader = f.record().await.credentials.reader_tokens[0].id.clone();
    let download = f
        .post(
            "/export",
            &format!("expected_config_version=1&reader_id={reader}"),
        )
        .await;
    assert_eq!(download.status, StatusCode::OK);
    assert_eq!(download.headers["referrer-policy"], "no-referrer");
    let redirect = f
        .post("/sessions/revoke", "expected_config_version=1&confirm=true")
        .await;
    assert_eq!(redirect.status, StatusCode::SEE_OTHER);
    assert_eq!(redirect.headers["referrer-policy"], "no-referrer");
}
