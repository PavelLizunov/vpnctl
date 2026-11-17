// Request-level company isolation specifications; fixtures use the public API.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHasher, SaltString},
};
use axum::{
    body::{Body, to_bytes},
    extract::ConnectInfo,
    http::{HeaderMap, HeaderValue, Request, StatusCode},
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde_json::{Value, json};
use std::{net::SocketAddr, sync::Arc};
use tower::ServiceExt;
use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
use vpnctl_inventory::{
    CorpCredentials, CorpReaderToken, CorpSetup, CorpSigningKey, CorpVerifiedEgress,
    SqliteInventory,
};
use vpnctld::{app, corp_policy::PolicySigningKey, corp_portal::eligibility::eligible_servers};

const HOST: &str = "admin.corp.ninitux.com";
const ORIGIN: &str = "https://admin.corp.ninitux.com";
const IP: &str = "198.51.100.20";
const USERS: [&str; 2] = ["company-user-a", "company-user-b"];
const COMPANIES: [&str; 2] = ["company-a", "company-b"];
const POLICIES: [&str; 2] = ["policy.a", "policy-b"];
const PASSWORDS: [&str; 2] = ["synthetic-password-a", "synthetic-password-b"];
const READERS: [&str; 2] = [
    "synthetic_reader_a_0123456789abcdef012345",
    "synthetic_reader_b_0123456789abcdef012345",
];

struct Fixture {
    _dir: tempfile::TempDir,
    state: vpnctld::AppState,
    router: axum::Router,
    job: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.job.abort();
    }
}
fn credentials(index: usize, shared_reader: bool) -> CorpCredentials {
    let key = PolicySigningKey::generate().unwrap();
    let salt = SaltString::encode_b64(b"0123456789abcdef").unwrap();
    let argon = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(8192, 1, 1, Some(32)).unwrap(),
    );
    CorpCredentials {
        password_phc: argon
            .hash_password(PASSWORDS[index].as_bytes(), &salt)
            .unwrap()
            .to_string(),
        reader_tokens: vec![CorpReaderToken {
            id: "reader-1".into(),
            token: READERS[if shared_reader { 0 } else { index }].into(),
        }],
        signing_keys: vec![CorpSigningKey {
            id: "key-1".into(),
            pkcs8: STANDARD.encode(key.export_pkcs8_der().unwrap().as_bytes()),
            spki: key.spki_base64().unwrap(),
        }],
        active_key_id: "key-1".into(),
    }
}
impl Fixture {
    async fn new(shared_reader: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let inv = SqliteInventory::open(&dir.path().join("inventory.db"))
            .await
            .unwrap();
        let server = Server {
            id: ServerId("shared-exit".into()),
            address: "192.0.2.10".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![ProtocolId("vless+reality".into())],
            trusted_host_fingerprint: None,
            hoster: "fixture".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        };
        inv.add_server(&server).await.unwrap();
        for (key, value) in [
            ("vless.public_key", URL_SAFE_NO_PAD.encode([7_u8; 32])),
            ("vless.short_id", "12345678".into()),
            ("vless.sni", "www.example.com".into()),
        ] {
            inv.set_server_secret(&server.id, key, &value)
                .await
                .unwrap();
        }
        for i in 0..2 {
            let user = User {
                id: UserId(USERS[i].into()),
                uuid: format!("00000000-0000-4000-8000-{:012}", i + 1),
                tuic_password: None,
                wireguard_pubkey: None,
                wireguard_private: None,
                sub_token: None,
                vpn_router_device_id: None,
                disabled: false,
            };
            inv.add_user(&user).await.unwrap();
            inv.grant(&user.id, &server.id).await.unwrap();
            let company = inv.corp_for(COMPANIES[i]);
            let creds = credentials(i, shared_reader);
            let status = company
                .create_corp(
                    &CorpSetup {
                        user_id: user.id,
                        policy_id: POLICIES[i].into(),
                        credentials: creds.clone(),
                    },
                    "spec",
                )
                .await
                .unwrap();
            company
                .update_corp_security(status.config_version, true, &creds, "spec")
                .await
                .unwrap();
        }
        let (state, job) =
            app::make_app_state_for_tests(inv, Arc::new(vpnctl_kernels::build_registry().unwrap()));
        for i in 0..2 {
            let candidates = eligible_servers(&state, &UserId(USERS[i].into()))
                .await
                .unwrap();
            assert_eq!(candidates.len(), 1);
            let company = state.inv.corp_for(COMPANIES[i]);
            let status = company.corp_record().await.unwrap().unwrap().status;
            company
                .replace_corp_egress(
                    status.config_version,
                    &[CorpVerifiedEgress {
                        server_id: server.id.clone(),
                        ip: IP.parse().unwrap(),
                        configuration_fingerprint: candidates[0].configuration_fingerprint.clone(),
                        verified_at: chrono::Utc::now().timestamp(),
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
        }
    }
    async fn call(&self, req: Request<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
        let response = self.router.clone().oneshot(req).await.unwrap();
        let (parts, body) = response.into_parts();
        (
            parts.status,
            parts.headers,
            to_bytes(body, 1_048_576).await.unwrap().to_vec(),
        )
    }
    async fn login(&self, i: usize) -> (String, String) {
        let (status, headers, _) = self
            .call(login(&format!(
                "username={}&password={}",
                USERS[i], PASSWORDS[i]
            )))
            .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let cookie = headers["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let (status, _, body) = self
            .call(browser("GET", "/api/corp/state", "", Some(&cookie), None))
            .await;
        assert_eq!(status, StatusCode::OK);
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["company"]["username"], USERS[i]);
        (cookie, value["csrf"].as_str().unwrap().to_owned())
    }
}
fn browser(
    method: &str,
    path: &str,
    body: &str,
    cookie: Option<&str>,
    csrf: Option<&str>,
) -> Request<Body> {
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header("host", HOST)
        .body(Body::from(body.to_owned()))
        .unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::new(IP.parse().unwrap(), 40123)));
    if let Some(v) = cookie {
        req.headers_mut()
            .insert("cookie", HeaderValue::from_str(v).unwrap());
    }
    if let Some(v) = csrf {
        req.headers_mut()
            .insert("x-corp-csrf", HeaderValue::from_str(v).unwrap());
    }
    if method == "POST" {
        req.headers_mut()
            .insert("origin", HeaderValue::from_static(ORIGIN));
        req.headers_mut()
            .insert("content-type", HeaderValue::from_static("application/json"));
    }
    req
}
fn login(body: &str) -> Request<Body> {
    let mut req = browser("POST", "/login", body, None, None);
    req.headers_mut().insert(
        "content-type",
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    req
}
fn reader(token: &str) -> Request<Body> {
    Request::builder()
        .uri("/api/v1/corp/policy")
        .header("host", HOST)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn login_requires_exact_username_password_and_never_selects_by_shared_exit() {
    let f = Fixture::new(false).await;
    let (_, _, page) = f.call(browser("GET", "/", "", None, None)).await;
    let html = String::from_utf8(page).unwrap();
    assert!(html.contains("name=\"username\"") && html.contains("autocomplete=\"username\""));
    assert!(html.contains("name=\"password\""));
    assert!(!html.contains(USERS[0]) && !html.contains(USERS[1]));
    for form in [
        format!("password={}", PASSWORDS[0]),
        format!("username={}&password={}", USERS[0], PASSWORDS[1]),
        format!("username=unknown&password={}", PASSWORDS[0]),
        format!(
            "username={}&username={}&password={}",
            USERS[0], USERS[1], PASSWORDS[0]
        ),
        format!(
            "username={}&password={}&password={}",
            USERS[0], PASSWORDS[0], PASSWORDS[0]
        ),
        format!("username={}&password={}&extra=x", USERS[0], PASSWORDS[0]),
    ] {
        let (_, headers, body) = f.call(login(&form)).await;
        if let Some(value) = headers.get("set-cookie") {
            let cookie = value.to_str().unwrap().split(';').next().unwrap();
            assert_eq!(
                f.call(browser("GET", "/api/corp/state", "", Some(cookie), None))
                    .await
                    .0,
                StatusCode::UNAUTHORIZED
            );
        }
        assert!(!String::from_utf8_lossy(&body).contains(PASSWORDS[0]));
        assert!(!String::from_utf8_lossy(&body).contains(PASSWORDS[1]));
    }
    let f = Fixture::new(false).await;
    let (_, _, failure) = f
        .call(login(&format!(
            "username={}&password={}",
            USERS[0], PASSWORDS[1]
        )))
        .await;
    assert!(String::from_utf8_lossy(&failure).contains(USERS[0]));
    f.login(0).await;
    f.login(1).await;
}

#[tokio::test]
async fn sessions_rules_expected_company_and_csrf_are_scoped() {
    let f = Fixture::new(false).await;
    let (a, csrf_a) = f.login(0).await;
    let (b, csrf_b) = f.login(1).await;
    let rules = json!([{"domain":"a.example.com","action":"direct","comment":"A"}]);
    let body = json!({"expected_revision":0,"apply":"next_connection","confirm_interrupt":false,"rules":rules}).to_string();
    assert_eq!(
        f.call(browser(
            "POST",
            "/api/corp/rules",
            &body,
            Some(&a),
            Some(&csrf_b)
        ))
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        f.call(browser(
            "POST",
            "/api/corp/rules",
            &body,
            Some(&a),
            Some(&csrf_a)
        ))
        .await
        .0,
        StatusCode::OK
    );
    let (_, _, state_a) = f
        .call(browser("GET", "/api/corp/state", "", Some(&a), None))
        .await;
    let (_, _, state_b) = f
        .call(browser("GET", "/api/corp/state", "", Some(&b), None))
        .await;
    let state_a: Value = serde_json::from_slice(&state_a).unwrap();
    let state_b: Value = serde_json::from_slice(&state_b).unwrap();
    assert_eq!(state_a["rules"], rules);
    assert_ne!(state_b["rules"], rules);
    assert_eq!(state_b["revision"], 0);
    let mut stale = browser("GET", "/api/corp/state", "", Some(&a), None);
    stale.headers_mut().insert(
        "x-corp-expected-company",
        HeaderValue::from_static(USERS[1]),
    );
    assert_eq!(f.call(stale).await.0, StatusCode::UNAUTHORIZED);
    let mut forged = browser(
        "POST",
        "/api/corp/normalize",
        r#"{"site":"example.com"}"#,
        Some(&a),
        Some(&csrf_a),
    );
    forged
        .headers_mut()
        .insert("x-corp-company", HeaderValue::from_static(POLICIES[1]));
    let (status, headers, _) = f.call(forged).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["x-corp-company"], POLICIES[0]);
    assert_eq!(
        f.state
            .inv
            .corp_for(COMPANIES[1])
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
async fn reader_envelopes_are_company_scoped_and_ambiguous_tokens_are_rejected() {
    let f = Fixture::new(false).await;
    for i in 0..2 {
        let (cookie, csrf) = f.login(i).await;
        let body = json!({"expected_revision":0,"apply":"next_connection","confirm_interrupt":false,"rules":[{"domain":format!("{}.example.com", if i == 0 {"a"} else {"b"}),"action":"direct","comment":""}]}).to_string();
        assert_eq!(
            f.call(browser(
                "POST",
                "/api/corp/rules",
                &body,
                Some(&cookie),
                Some(&csrf)
            ))
            .await
            .0,
            StatusCode::OK
        );
    }
    let (sa, _, a) = f.call(reader(READERS[0])).await;
    let (sb, _, b) = f.call(reader(READERS[1])).await;
    assert_eq!(sa, StatusCode::OK);
    assert_eq!(sb, StatusCode::OK);
    assert_ne!(a, b);
    for (i, envelope) in [a, b].iter().enumerate() {
        let company = f.state.inv.corp_for(COMPANIES[i]);
        let record = company.corp_record().await.unwrap().unwrap();
        assert_eq!(
            *envelope,
            company
                .corp_current_policy(record.status.config_version)
                .await
                .unwrap()
                .unwrap()
                .envelope
        );
    }
    let ambiguous = Fixture::new(true).await;
    assert_eq!(
        ambiguous.call(reader(READERS[0])).await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn operator_lists_companies_and_controls_only_the_selected_company() {
    use vpnctld::corp_operator::OperatorConfig;
    let f = Fixture::new(false).await;
    let config = OperatorConfig::from_parts(
        Some("operator".into()),
        Some("synthetic-operator-password".into()),
        Some("https://operator.example.test".into()),
        "synthetic-install-secret",
    );
    let router = app::router_with_corp_operator(f.state.clone(), config);
    let auth = format!(
        "Basic {}",
        STANDARD.encode("operator:synthetic-operator-password")
    );
    async fn send(
        router: &axum::Router,
        auth: &str,
        method: &str,
        path: &str,
        body: &str,
    ) -> (StatusCode, String) {
        let req = Request::builder()
            .method(method)
            .uri(path)
            .header("host", "operator.example.test")
            .header("authorization", auth)
            .header("origin", "https://operator.example.test")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body.to_owned()))
            .unwrap();
        let res = router.clone().oneshot(req).await.unwrap();
        let status = res.status();
        (
            status,
            String::from_utf8(to_bytes(res.into_body(), 1_048_576).await.unwrap().to_vec())
                .unwrap(),
        )
    }
    let (status, list) = send(&router, &auth, "GET", "/admin/corp/companies", "").await;
    assert_eq!(status, StatusCode::OK);
    for id in COMPANIES {
        assert!(list.contains(&format!("/admin/corp/company/{id}")));
    }
    let (status, detail) = send(&router, &auth, "GET", "/admin/corp/company/company-a", "").await;
    assert_eq!(status, StatusCode::OK);
    let csrf = detail
        .split_once("name=\"csrf\" value=\"")
        .unwrap()
        .1
        .split_once('"')
        .unwrap()
        .0;
    let version = f
        .state
        .inv
        .corp_for(COMPANIES[0])
        .corp_record()
        .await
        .unwrap()
        .unwrap()
        .status
        .config_version;
    let body = format!(
        "company_id={}&expected_config_version={version}&enabled=false&confirm=true&csrf={csrf}",
        COMPANIES[0]
    );
    let (status, _) = send(&router, &auth, "POST", "/admin/corp/enabled", &body).await;
    assert!(status.is_success() || status.is_redirection());
    assert!(
        !f.state
            .inv
            .corp_for(COMPANIES[0])
            .corp_record()
            .await
            .unwrap()
            .unwrap()
            .status
            .enabled
    );
    assert!(
        f.state
            .inv
            .corp_for(COMPANIES[1])
            .corp_record()
            .await
            .unwrap()
            .unwrap()
            .status
            .enabled
    );
}

#[tokio::test]
async fn short_operator_entry_redirects_safe_reads_and_never_replays_form_posts() {
    let f = Fixture::new(false).await;
    let origin = "https://vpnctld.synthetic.ts.net";
    let router = app::router_with_corp_operator(
        f.state.clone(),
        vpnctld::corp_operator::OperatorConfig::from_parts(
            Some("owner".into()),
            Some("synthetic-operator-password".into()),
            Some(origin.into()),
            "synthetic-install-secret",
        ),
    );
    for path in ["/admin/", "/admin/corp", "/admin/corp/companies"] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header("host", "vpnctld")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(response.headers()["location"], format!("{origin}{path}"));
    }
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/corp/enabled")
                .header("host", "vpnctld")
                .body(Body::from("synthetic-form"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(!response.headers().contains_key("location"));
    let response = router
        .oneshot(
            Request::builder()
                .uri("/admin/corp/companies")
                .header("host", "arbitrary.invalid")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn another_company_exit_can_render_login_despite_an_unusable_existing_session() {
    let f = Fixture::new(false).await;
    let (cookie_a, _) = f.login(0).await;
    let store_b = f.state.inv.corp_for(COMPANIES[1]);
    let status = store_b.corp_record().await.unwrap().unwrap().status;
    let mut exits = store_b.corp_verified_egress().await.unwrap();
    exits[0].ip = "198.51.100.21".parse().unwrap();
    store_b
        .replace_corp_egress(status.config_version, &exits, "spec")
        .await
        .unwrap();
    let mut request = browser("GET", "/", "", Some(&cookie_a), None);
    request.extensions_mut().insert(ConnectInfo(
        "198.51.100.21:40123".parse::<SocketAddr>().unwrap(),
    ));
    let (status, _, body) = f.call(request).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        String::from_utf8(body)
            .unwrap()
            .contains("name=\"username\"")
    );
    let mut api = browser("GET", "/api/corp/state", "", Some(&cookie_a), None);
    api.extensions_mut().insert(ConnectInfo(
        "198.51.100.21:40123".parse::<SocketAddr>().unwrap(),
    ));
    assert_eq!(f.call(api).await.0, StatusCode::FORBIDDEN);
    for (username, password) in [
        (USERS[0], PASSWORDS[0]),
        (USERS[0], "wrong"),
        ("unknown-company", PASSWORDS[0]),
    ] {
        let mut request = login(&format!("username={username}&password={password}"));
        request.extensions_mut().insert(ConnectInfo(
            "198.51.100.21:40123".parse::<SocketAddr>().unwrap(),
        ));
        let (status, headers, body) = f.call(request).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(!headers.contains_key("set-cookie"));
        assert!(
            String::from_utf8(body)
                .unwrap()
                .contains("Неверный username или пароль компании.")
        );
    }
}
