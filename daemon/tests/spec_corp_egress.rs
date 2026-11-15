#![allow(clippy::unwrap_used, clippy::expect_used)]
// Independent tests derived from corp-policy-egress and its referenced contracts.
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::ConnectInfo,
    http::{Request, StatusCode},
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
};
use tokio::sync::{Mutex, mpsc, oneshot};
use tower::ServiceExt;
use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
use vpnctl_inventory::{
    CorpCredentials, CorpReaderToken, CorpSetup, CorpSigningKey, SqliteInventory,
};
use vpnctld::{
    AppState, app,
    corp_egress::{
        AttemptState, EgressController, ProbeError, ProbeRequest, ProbeRunner, ProbeTicket,
    },
    corp_operator::OperatorConfig,
    corp_policy::PolicySigningKey,
    corp_portal::eligibility::probe_plan,
};

const NOW: i64 = 1_800_000_000;
const PATH: &str = "/api/v1/corp/egress-observation";
const HOST: &str = "admin.corp.ninitux.com";
const OP_HOST: &str = "operator.example.test";
const OP_ORIGIN: &str = "https://operator.example.test";

struct Call {
    request: ProbeRequest,
    done: oneshot::Sender<Result<(), ProbeError>>,
}
struct FakeRunner {
    tx: mpsc::UnboundedSender<Call>,
}
impl std::fmt::Debug for FakeRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FakeRunner { .. }")
    }
}
#[async_trait::async_trait]
impl ProbeRunner for FakeRunner {
    fn available(&self) -> bool {
        true
    }
    async fn run(&self, request: ProbeRequest) -> Result<(), ProbeError> {
        let (done, result) = oneshot::channel();
        self.tx
            .send(Call { request, done })
            .map_err(|_| ProbeError::Failed)?;
        result.await.unwrap_or(Err(ProbeError::Failed))
    }
}
struct Fixture {
    dir: tempfile::TempDir,
    state: AppState,
    router: Router,
    calls: Mutex<mpsc::UnboundedReceiver<Call>>,
    clock: Arc<AtomicI64>,
    job: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.job.abort();
    }
}
fn user() -> User {
    User {
        id: UserId("egress-user".into()),
        uuid: "11111111-1111-4111-8111-111111111111".into(),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    }
}
fn sid() -> ServerId {
    ServerId("egress-node".into())
}
impl Fixture {
    async fn new(multi: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let inv = SqliteInventory::open(&dir.path().join("inventory.db"))
            .await
            .unwrap();
        inv.add_user(&user()).await.unwrap();
        let key = PolicySigningKey::generate().unwrap();
        let credentials = CorpCredentials {
            password_phc: "$argon2id$v=19$m=8192,t=1,p=1$c3ludGhldGljLXNhbHQxMg$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            reader_tokens: vec![CorpReaderToken { id: "reader".into(), token: "synthetic-reader-0123456789abcdef0123456789".into() }],
            signing_keys: vec![CorpSigningKey { id: "signer".into(), pkcs8: STANDARD.encode(key.export_pkcs8_der().unwrap().as_bytes()), spki: key.spki_base64().unwrap() }], active_key_id: "signer".into(),
        };
        inv.create_corp(
            &CorpSetup {
                user_id: user().id,
                policy_id: "egress-policy".into(),
                credentials,
            },
            "spec",
        )
        .await
        .unwrap();
        let protocols = if multi {
            vec![
                ProtocolId("vless+reality".into()),
                ProtocolId("vless-ws".into()),
            ]
        } else {
            vec![ProtocolId("vless+reality".into())]
        };
        inv.add_server(&Server {
            id: sid(),
            address: "192.0.2.10".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("xray".into())],
            enabled_protocols: protocols,
            trusted_host_fingerprint: None,
            hoster: "synthetic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
        inv.grant(&user().id, &sid()).await.unwrap();
        for (name, value) in [
            ("vless.public_key", URL_SAFE_NO_PAD.encode([7_u8; 32])),
            ("vless.short_id", "12345678".into()),
            ("vless.sni", "www.example.com".into()),
            ("vlessws.domain", "edge.example.test".into()),
            ("vlessws.path", "route123".into()),
        ] {
            inv.set_server_secret(&sid(), name, &value).await.unwrap();
        }
        let (mut state, job) =
            app::make_app_state_for_tests(inv, Arc::new(vpnctl_kernels::build_registry().unwrap()));
        let (tx, rx) = mpsc::unbounded_channel();
        let clock = Arc::new(AtomicI64::new(NOW));
        let c = Arc::clone(&clock);
        state.corp_egress = Arc::new(EgressController::new(
            Arc::new(FakeRunner { tx }),
            Arc::new(move || c.load(Ordering::SeqCst)),
        ));
        let c = Arc::clone(&clock);
        let config = OperatorConfig::from_parts(
            Some("operator".into()),
            Some("synthetic-password".into()),
            Some(OP_ORIGIN.into()),
            "synthetic-install-secret",
        )
        .with_clock(Arc::new(move || c.load(Ordering::SeqCst)));
        let router = app::router_with_corp_operator(state.clone(), config);
        Self {
            dir,
            state,
            router,
            calls: Mutex::new(rx),
            clock,
            job,
        }
    }
    async fn version(&self) -> u64 {
        self.state
            .inv
            .corp_record()
            .await
            .unwrap()
            .unwrap()
            .status
            .config_version
    }
    async fn queue(&self) -> ProbeTicket {
        self.state
            .corp_egress
            .queue_probe(self.state.clone(), self.version().await, sid())
            .await
            .unwrap()
    }
    async fn next(&self) -> Call {
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            self.calls.lock().await.recv(),
        )
        .await
        .unwrap()
        .unwrap()
    }
    async fn observe(&self, token: &str, ip: &str) -> axum::response::Response {
        self.http("POST", PATH, HOST, Some(token), Some(ip), "")
            .await
    }
    async fn http(
        &self,
        method: &str,
        uri: &str,
        host: &str,
        token: Option<&str>,
        peer: Option<&str>,
        body: &str,
    ) -> axum::response::Response {
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header("host", host);
        if let Some(token) = token {
            req = req.header("authorization", format!("Bearer {token}"));
        }
        let mut req = req.body(Body::from(body.to_owned())).unwrap();
        if let Some(peer) = peer {
            req.extensions_mut().insert(ConnectInfo(
                format!("{peer}:12345").parse::<SocketAddr>().unwrap(),
            ));
        }
        self.router.clone().oneshot(req).await.unwrap()
    }
    async fn succeed(&self, call: Call, ip: &str) {
        let reply = self.observe(&call.request.token, ip).await;
        assert_eq!(reply.status(), StatusCode::NO_CONTENT);
        assert_eq!(reply.headers()["x-corp-probe"], call.request.token.as_str());
        assert_eq!(reply.headers()["cache-control"], "no-store");
        assert_eq!(reply.headers()["referrer-policy"], "no-referrer");
        assert!(reply.headers().contains_key("content-security-policy"));
        assert!(to_bytes(reply.into_body(), 1024).await.unwrap().is_empty());
        call.done.send(Ok(())).unwrap();
    }
    async fn proof(&self, ip: &str) {
        let ticket = self.queue().await;
        self.succeed(self.next().await, ip).await;
        assert_eq!(ticket.wait().await, Ok(()));
    }
    async fn op(&self, route: Option<(&str, &str)>) -> (StatusCode, String) {
        let auth = format!("Basic {}", STANDARD.encode("operator:synthetic-password"));
        let page = self
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/admin/corp")
                    .header("host", OP_HOST)
                    .header("authorization", &auth)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = page.status();
        let body = String::from_utf8(
            to_bytes(page.into_body(), 1_048_576)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        let Some((route, fields)) = route else {
            return (status, body);
        };
        assert_eq!(status, StatusCode::OK);
        let csrf = body
            .split_once("name=\"csrf\" value=\"")
            .unwrap()
            .1
            .split('"')
            .next()
            .unwrap();
        let response = self
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/admin/corp{route}"))
                    .header("host", OP_HOST)
                    .header("authorization", auth)
                    .header("origin", OP_ORIGIN)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(format!("{fields}&csrf={csrf}")))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = String::from_utf8(
            to_bytes(response.into_body(), 1_048_576)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        (status, body)
    }
}

#[tokio::test]
async fn complete_selected_outbounds_are_unchanged_and_persist_only_after_all_cleanup() {
    let f = Fixture::new(true).await;
    let expected = probe_plan(&f.state, &user().id, &sid())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(expected.outbounds.len(), 2);
    let ticket = f.queue().await;
    let mut tokens = Vec::new();
    for outbound in expected.outbounds {
        let call = f.next().await;
        assert_eq!(call.request.outbound, outbound);
        assert_eq!(format!("{:?}", call.request), "ProbeRequest { .. }");
        assert_eq!(format!("{:#?}", call.request), "ProbeRequest { .. }");
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(call.request.token.as_bytes())
                .unwrap()
                .len(),
            32
        );
        tokens.push(call.request.token.to_string());
        assert!(f.state.inv.corp_verified_egress().await.unwrap().is_empty());
        f.succeed(call, "198.51.100.20").await;
    }
    assert_ne!(tokens[0], tokens[1]);
    assert_eq!(ticket.wait().await, Ok(()));
    let rows = f.state.inv.corp_verified_egress().await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].verified_at, NOW);
    assert_eq!(
        rows[0].configuration_fingerprint,
        expected.server.configuration_fingerprint
    );
    assert_eq!(
        f.state.corp_egress.attempt(&sid()).state,
        AttemptState::Verified
    );
    let reopened = SqliteInventory::open(&f.dir.path().join("inventory.db"))
        .await
        .unwrap();
    assert_eq!(
        reopened.corp_verified_egress().await.unwrap()[0].ip,
        rows[0].ip
    );
    for token in tokens {
        assert_eq!(
            f.observe(&token, "198.51.100.21").await.status(),
            StatusCode::UNAUTHORIZED
        );
    }
}

#[tokio::test]
async fn observer_rejects_wrong_replayed_and_malformed_credentials_without_consuming_real_token() {
    let f = Fixture::new(false).await;
    let ticket = f.queue().await;
    let call = f.next().await;
    for token in ["forged", "", &format!("{}=", call.request.token.as_str())] {
        assert_eq!(
            f.observe(token, "198.51.100.20").await.status(),
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        f.observe(&call.request.token, "198.51.100.20")
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        f.observe(&call.request.token, "198.51.100.21")
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    call.done.send(Ok(())).unwrap();
    assert_eq!(ticket.wait().await, Ok(()));
    assert_eq!(
        f.state.inv.corp_verified_egress().await.unwrap()[0]
            .ip
            .to_string(),
        "198.51.100.20"
    );
}

#[tokio::test]
async fn observer_fixed_host_method_body_query_and_actual_peer_boundaries() {
    let f = Fixture::new(false).await;
    let ticket = f.queue().await;
    let call = f.next().await;
    let token = call.request.token.as_str();
    for (method, uri, host, peer, body, status) in [
        (
            "GET",
            PATH,
            HOST,
            Some("198.51.100.20"),
            "",
            StatusCode::METHOD_NOT_ALLOWED,
        ),
        (
            "POST",
            "/api/v1/corp/egress-observation?ip=198.51.100.20",
            HOST,
            Some("198.51.100.20"),
            "",
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "POST",
            PATH,
            HOST,
            Some("198.51.100.20"),
            "{}",
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        ("POST", PATH, HOST, None, "", StatusCode::FORBIDDEN),
        (
            "POST",
            PATH,
            "elsewhere.example.test",
            Some("198.51.100.20"),
            "",
            StatusCode::NOT_FOUND,
        ),
    ] {
        assert_eq!(
            f.http(method, uri, host, Some(token), peer, body)
                .await
                .status(),
            status
        );
    }
    assert_eq!(
        f.http(
            "POST",
            PATH,
            HOST,
            Some(token),
            Some("198.51.100.20"),
            &"x".repeat(1025)
        )
        .await
        .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    f.succeed(call, "198.51.100.20").await;
    assert_eq!(ticket.wait().await, Ok(()));
}

#[tokio::test]
async fn invalid_observed_addresses_fail_and_mapped_ipv4_is_canonicalized() {
    let f = Fixture::new(false).await;
    for ip in [
        "0.0.0.0",
        "127.0.0.1",
        "10.1.2.3",
        "172.16.1.1",
        "192.168.1.1",
        "169.254.1.1",
        "255.255.255.255",
        "224.0.0.1",
        "2001:db8::1",
    ] {
        let ticket = f.queue().await;
        let call = f.next().await;
        assert_eq!(
            f.state
                .corp_egress
                .observe(&call.request.token, ip.parse().unwrap()),
            Err(ProbeError::Failed)
        );
        call.done.send(Ok(())).unwrap();
        assert_eq!(ticket.wait().await, Err(ProbeError::Failed));
        assert!(f.state.inv.corp_verified_egress().await.unwrap().is_empty());
    }
    let ticket = f.queue().await;
    let call = f.next().await;
    assert_eq!(
        f.state
            .corp_egress
            .observe(&call.request.token, "::ffff:198.51.100.20".parse().unwrap()),
        Ok(())
    );
    call.done.send(Ok(())).unwrap();
    assert_eq!(ticket.wait().await, Ok(()));
    assert!(
        f.state.inv.corp_verified_egress().await.unwrap()[0]
            .ip
            .is_ipv4()
    );
}

#[tokio::test]
async fn runner_success_without_callback_and_partial_failure_never_persist() {
    let f = Fixture::new(false).await;
    let ticket = f.queue().await;
    f.next().await.done.send(Ok(())).unwrap();
    assert_eq!(ticket.wait().await, Err(ProbeError::Failed));
    assert!(f.state.inv.corp_verified_egress().await.unwrap().is_empty());
    let f = Fixture::new(true).await;
    let ticket = f.queue().await;
    f.succeed(f.next().await, "198.51.100.20").await;
    f.next().await.done.send(Err(ProbeError::Failed)).unwrap();
    assert_eq!(ticket.wait().await, Err(ProbeError::Failed));
    assert!(f.state.inv.corp_verified_egress().await.unwrap().is_empty());
}

#[tokio::test]
async fn dropped_ticket_retains_global_permit_until_runner_cleanup_finishes() {
    let f = Fixture::new(false).await;
    let ticket = f.queue().await;
    let call = f.next().await;
    drop(ticket);
    assert_eq!(
        f.state.corp_egress.attempt(&sid()).state,
        AttemptState::Running
    );
    assert_eq!(
        f.state
            .corp_egress
            .queue_probe(f.state.clone(), f.version().await, sid())
            .await
            .unwrap_err(),
        ProbeError::Busy
    );
    let refresh = f.state.corp_egress.refresh_due(f.state.clone()).await;
    assert!(matches!(refresh, Ok(()) | Err(ProbeError::Busy)));
    assert!(f.calls.lock().await.try_recv().is_err());
    f.succeed(call, "198.51.100.20").await;
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while f.state.corp_egress.attempt(&sid()).state == AttemptState::Running {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        f.state.corp_egress.attempt(&sid()).state,
        AttemptState::Verified
    );
    assert_eq!(f.state.inv.corp_verified_egress().await.unwrap().len(), 1);
}

#[tokio::test]
async fn cleanup_failure_poison_blocks_future_jobs_and_enable() {
    let f = Fixture::new(false).await;
    f.proof("198.51.100.20").await;
    let ticket = f.queue().await;
    let call = f.next().await;
    assert_eq!(
        f.observe(&call.request.token, "198.51.100.21")
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    call.done.send(Err(ProbeError::CleanupFailed)).unwrap();
    assert_eq!(ticket.wait().await, Err(ProbeError::CleanupFailed));
    assert!(!f.state.corp_egress.available());
    assert_eq!(
        f.state
            .corp_egress
            .queue_probe(f.state.clone(), f.version().await, sid())
            .await
            .unwrap_err(),
        ProbeError::Unavailable
    );
    assert!(
        !f.state
            .corp_egress
            .ready_to_enable(&f.state, f.version().await)
            .await
            .unwrap_or(false)
    );
    assert_eq!(
        f.state.inv.corp_verified_egress().await.unwrap()[0]
            .ip
            .to_string(),
        "198.51.100.20"
    );
}

#[tokio::test]
async fn revalidation_rejects_changed_config_plan_disabled_user_and_backwards_clock() {
    for change in ["config", "plan", "user", "clock", "zero", "overflow"] {
        let f = Fixture::new(false).await;
        let ticket = f.queue().await;
        let call = f.next().await;
        match change {
            "config" => {
                f.state
                    .inv
                    .revoke_corp_sessions(f.version().await, "spec")
                    .await
                    .unwrap();
            }
            "plan" => {
                f.state
                    .inv
                    .set_server_secret(&sid(), "vless.sni", "changed.example.test")
                    .await
                    .unwrap();
            }
            "user" => {
                f.state
                    .inv
                    .set_user_disabled(&user().id, true)
                    .await
                    .unwrap();
            }
            "clock" => {
                f.clock.store(NOW - 1, Ordering::SeqCst);
            }
            "zero" => {
                f.clock.store(0, Ordering::SeqCst);
            }
            _ => {
                f.clock.store(253_402_300_800, Ordering::SeqCst);
            }
        }
        f.succeed(call, "198.51.100.20").await;
        assert!(ticket.wait().await.is_err(), "{change}");
        assert!(
            f.state.inv.corp_verified_egress().await.unwrap().is_empty(),
            "{change}"
        );
    }
}

#[tokio::test]
async fn readiness_requires_current_version_fingerprint_enabled_user_and_fresh_positive_time() {
    let f = Fixture::new(false).await;
    assert!(
        !f.state
            .corp_egress
            .ready_to_enable(&f.state, f.version().await)
            .await
            .unwrap()
    );
    f.proof("198.51.100.20").await;
    let version = f.version().await;
    assert!(
        f.state
            .corp_egress
            .ready_to_enable(&f.state, version)
            .await
            .unwrap()
    );
    assert_eq!(
        f.state
            .corp_egress
            .ready_to_enable(&f.state, version - 1)
            .await,
        Err(ProbeError::Conflict)
    );
    for (now, ready) in [
        (NOW - 1, false),
        (NOW + 86_400, true),
        (NOW + 86_401, false),
    ] {
        f.clock.store(now, Ordering::SeqCst);
        assert_eq!(
            f.state
                .corp_egress
                .ready_to_enable(&f.state, version)
                .await
                .unwrap(),
            ready
        );
    }
    f.clock.store(NOW, Ordering::SeqCst);
    f.state
        .inv
        .set_server_secret(&sid(), "vless.sni", "changed.example.test")
        .await
        .unwrap();
    assert!(
        !f.state
            .corp_egress
            .ready_to_enable(&f.state, version)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn audit_failure_rolls_back_new_proof_and_does_not_report_verified() {
    let f = Fixture::new(false).await;
    let pool = sqlx::SqlitePool::connect(&format!(
        "sqlite://{}",
        f.dir.path().join("inventory.db").display()
    ))
    .await
    .unwrap();
    sqlx::query("CREATE TRIGGER synthetic_probe_audit_failure BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT, 'synthetic-private-detail'); END").execute(&pool).await.unwrap();
    let ticket = f.queue().await;
    f.succeed(f.next().await, "198.51.100.20").await;
    let error = ticket.wait().await.unwrap_err();
    assert!(!error.to_string().contains("synthetic-private-detail"));
    assert!(f.state.inv.corp_verified_egress().await.unwrap().is_empty());
    assert_ne!(
        f.state.corp_egress.attempt(&sid()).state,
        AttemptState::Verified
    );
}

#[tokio::test]
async fn preflight_stale_version_missing_server_and_disabled_user_do_not_invoke_runner() {
    let f = Fixture::new(false).await;
    assert_eq!(
        f.state
            .corp_egress
            .queue_probe(f.state.clone(), 0, sid())
            .await
            .unwrap_err(),
        ProbeError::Conflict
    );
    assert_eq!(
        f.state
            .corp_egress
            .queue_probe(
                f.state.clone(),
                f.version().await,
                ServerId("missing".into())
            )
            .await
            .unwrap_err(),
        ProbeError::NotFound
    );
    f.state
        .inv
        .set_user_disabled(&user().id, true)
        .await
        .unwrap();
    assert_eq!(
        f.state
            .corp_egress
            .queue_probe(f.state.clone(), f.version().await, sid())
            .await
            .unwrap_err(),
        ProbeError::Unavailable
    );
    assert!(f.calls.lock().await.try_recv().is_err());
}

#[tokio::test]
async fn challenge_expires_at_thirty_seconds_without_real_sleep() {
    let f = Fixture::new(false).await;
    let ticket = f.queue().await;
    let call = f.next().await;
    tokio::time::pause();
    tokio::time::advance(std::time::Duration::from_secs(30)).await;
    assert_eq!(
        f.state
            .corp_egress
            .observe(&call.request.token, "198.51.100.20".parse().unwrap()),
        Err(ProbeError::Failed)
    );
    call.done.send(Ok(())).unwrap();
    tokio::time::resume();
    assert_eq!(ticket.wait().await, Err(ProbeError::Failed));
    assert!(f.state.inv.corp_verified_egress().await.unwrap().is_empty());
}

#[tokio::test]
async fn operator_probe_returns_immediately_and_enable_rechecks_saved_proof() {
    let f = Fixture::new(false).await;
    let version = f.version().await;
    assert_eq!(
        f.op(Some((
            "/enabled",
            &format!("expected_config_version={version}&enabled=true&confirm=true")
        )))
        .await
        .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        f.op(Some((
            "/probe",
            &format!("expected_config_version={version}&server_id=egress-node")
        )))
        .await
        .0,
        StatusCode::SEE_OTHER
    );
    let call = f.next().await;
    assert_eq!(
        f.op(Some((
            "/probe",
            &format!("expected_config_version={version}&server_id=egress-node")
        )))
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert!(f.op(None).await.1.contains("/admin/corp"));
    f.succeed(call, "198.51.100.20").await;
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while f.state.corp_egress.attempt(&sid()).state == AttemptState::Running {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        f.op(Some((
            "/enabled",
            &format!("expected_config_version={version}&enabled=true&confirm=true")
        )))
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        f.op(Some((
            "/enabled",
            &format!(
                "expected_config_version={}&enabled=true&confirm=true",
                f.version().await
            )
        )))
        .await
        .0,
        StatusCode::SEE_OTHER
    );
    assert!(
        f.state
            .inv
            .corp_record()
            .await
            .unwrap()
            .unwrap()
            .status
            .enabled
    );
}

#[tokio::test]
async fn renewal_preserves_sessions_and_generations_but_changed_ip_revokes() {
    let f = Fixture::new(false).await;
    f.proof("198.51.100.20").await;
    let record = f.state.inv.corp_record().await.unwrap().unwrap();
    f.state
        .inv
        .update_corp_security(
            record.status.config_version,
            true,
            &record.credentials,
            "spec",
        )
        .await
        .unwrap();
    let before = f.state.inv.corp_record().await.unwrap().unwrap().status;
    let session = vpnctl_inventory::CorpSessionInput {
        token_hash: "a".repeat(64),
        csrf_token: URL_SAFE_NO_PAD.encode([1_u8; 32]),
        expires_at: NOW + 1000,
    };
    f.state
        .inv
        .issue_corp_session(before.auth_generation, &session, NOW, "spec")
        .await
        .unwrap();
    f.clock.store(NOW + 60, Ordering::SeqCst);
    f.proof("198.51.100.20").await;
    let after = f.state.inv.corp_record().await.unwrap().unwrap().status;
    assert_eq!(after.config_version, before.config_version);
    assert_eq!(after.auth_generation, before.auth_generation);
    assert_eq!(after.revision, before.revision);
    assert_eq!(
        f.state.inv.corp_verified_egress().await.unwrap()[0].verified_at,
        NOW + 60
    );
    assert!(
        f.state
            .inv
            .corp_session(&session.token_hash, NOW + 60)
            .await
            .unwrap()
            .is_some()
    );
    f.clock.store(NOW + 120, Ordering::SeqCst);
    f.proof("198.51.100.21").await;
    assert!(
        f.state
            .inv
            .corp_session(&session.token_hash, NOW + 120)
            .await
            .unwrap()
            .is_none()
    );
    let changed = f.state.inv.corp_record().await.unwrap().unwrap().status;
    assert_eq!(changed.config_version, before.config_version + 1);
    assert_eq!(changed.auth_generation, before.auth_generation + 1);
    let rows = f.state.inv.corp_verified_egress().await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].ip.to_string(), "198.51.100.21");
}

#[tokio::test]
async fn refresh_skips_fresh_proof_and_renews_at_six_hours_without_advancing_authority() {
    let f = Fixture::new(false).await;
    f.proof("198.51.100.20").await;
    let version = f.version().await;
    f.clock.store(NOW + 21_599, Ordering::SeqCst);
    assert_eq!(
        f.state.corp_egress.refresh_due(f.state.clone()).await,
        Ok(())
    );
    assert!(f.calls.lock().await.try_recv().is_err());
    f.clock.store(NOW + 21_600, Ordering::SeqCst);
    let controller = Arc::clone(&f.state.corp_egress);
    let state = f.state.clone();
    let refresh = tokio::spawn(async move { controller.refresh_due(state).await });
    let call = f.next().await;
    assert_eq!(
        f.state
            .corp_egress
            .queue_probe(f.state.clone(), version, sid())
            .await
            .unwrap_err(),
        ProbeError::Busy
    );
    f.succeed(call, "198.51.100.20").await;
    assert_eq!(refresh.await.unwrap(), Ok(()));
    assert_eq!(f.version().await, version);
    assert_eq!(
        f.state.inv.corp_verified_egress().await.unwrap()[0].verified_at,
        NOW + 21_600
    );
}

#[tokio::test]
async fn failed_renewal_preserves_saved_ip_and_age_and_clears_callback() {
    let f = Fixture::new(false).await;
    f.proof("198.51.100.20").await;
    f.clock.store(NOW + 100, Ordering::SeqCst);
    let ticket = f.queue().await;
    let call = f.next().await;
    let token = call.request.token.to_string();
    assert_eq!(
        f.observe(&token, "198.51.100.21").await.status(),
        StatusCode::NO_CONTENT
    );
    call.done.send(Err(ProbeError::Failed)).unwrap();
    assert_eq!(ticket.wait().await, Err(ProbeError::Failed));
    let rows = f.state.inv.corp_verified_egress().await.unwrap();
    assert_eq!(rows[0].verified_at, NOW);
    assert_eq!(rows[0].ip.to_string(), "198.51.100.20");
    assert_eq!(
        f.observe(&token, "198.51.100.21").await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        f.state.corp_egress.attempt(&sid()).state,
        AttemptState::Failed
    );
}

#[tokio::test]
async fn sixty_second_total_budget_prevents_starting_another_endpoint_without_cancelling_runner() {
    let f = Fixture::new(true).await;
    let ticket = f.queue().await;
    let call = f.next().await;
    assert_eq!(
        f.observe(&call.request.token, "198.51.100.20")
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    tokio::time::pause();
    tokio::time::advance(std::time::Duration::from_secs(61)).await;
    assert_eq!(
        f.state.corp_egress.attempt(&sid()).state,
        AttemptState::Running
    );
    assert_eq!(
        f.state
            .corp_egress
            .queue_probe(f.state.clone(), f.version().await, sid())
            .await
            .unwrap_err(),
        ProbeError::Busy
    );
    call.done.send(Ok(())).unwrap();
    tokio::time::resume();
    assert_eq!(ticket.wait().await, Err(ProbeError::Failed));
    assert!(f.calls.lock().await.try_recv().is_err());
    assert!(f.state.inv.corp_verified_egress().await.unwrap().is_empty());
}

#[tokio::test]
async fn default_controllers_are_disabled_and_never_accept_unrelated_challenges() {
    let f = Fixture::new(false).await;
    let (other, job) = app::make_app_state_for_tests(
        f.state.inv.clone(),
        Arc::new(vpnctl_kernels::build_registry().unwrap()),
    );
    assert!(!other.corp_egress.available());
    assert_eq!(
        other
            .corp_egress
            .queue_probe(other.clone(), f.version().await, sid())
            .await
            .unwrap_err(),
        ProbeError::Unavailable
    );
    let ticket = f.queue().await;
    let call = f.next().await;
    assert_eq!(
        other
            .corp_egress
            .observe(&call.request.token, "198.51.100.20".parse().unwrap()),
        Err(ProbeError::Failed)
    );
    f.succeed(call, "198.51.100.20").await;
    assert_eq!(ticket.wait().await, Ok(()));
    job.abort();
}

#[tokio::test]
async fn observer_ambiguous_host_auth_and_untrusted_claimed_ip_do_not_supply_proof() {
    let f = Fixture::new(false).await;
    let ticket = f.queue().await;
    let call = f.next().await;
    for header in ["host", "authorization"] {
        let request = Request::builder()
            .method("POST")
            .uri(PATH)
            .header("host", HOST)
            .header(
                "authorization",
                format!("Bearer {}", call.request.token.as_str()),
            )
            .header(
                header,
                if header == "host" {
                    HOST
                } else {
                    "Bearer forged"
                },
            )
            .extension(ConnectInfo(
                "198.51.100.20:12345".parse::<SocketAddr>().unwrap(),
            ))
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            f.router.clone().oneshot(request).await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );
    }
    let request = Request::builder()
        .method("POST")
        .uri(PATH)
        .header("host", HOST)
        .header(
            "authorization",
            format!("Bearer {}", call.request.token.as_str()),
        )
        .header("x-real-ip", "198.51.100.20")
        .header("x-forwarded-for", "198.51.100.20")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        f.router.clone().oneshot(request).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let request = Request::builder()
        .method("POST")
        .uri(PATH)
        .header("host", HOST)
        .header(
            "authorization",
            format!("Bearer {}", call.request.token.as_str()),
        )
        .header("x-real-ip", "198.51.100.99")
        .extension(ConnectInfo(
            "198.51.100.20:12345".parse::<SocketAddr>().unwrap(),
        ))
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        f.router.clone().oneshot(request).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );
    call.done.send(Ok(())).unwrap();
    assert_eq!(ticket.wait().await, Ok(()));
    assert_eq!(
        f.state.inv.corp_verified_egress().await.unwrap()[0]
            .ip
            .to_string(),
        "198.51.100.20"
    );
}

impl Fixture {
    async fn export_operator_page(&self, name: &str) {
        let Ok(output) = std::env::var("CORP_OPERATOR_UI_OUTPUT_DIR") else {
            return;
        };
        let output = std::path::PathBuf::from(output);
        std::fs::create_dir_all(output.join("assets")).unwrap();
        let auth = format!("Basic {}", STANDARD.encode("operator:synthetic-password"));
        let response = self
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/admin/corp")
                    .header("host", OP_HOST)
                    .header("authorization", &auth)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let mut headers = serde_json::Map::new();
        for name in [
            "cache-control",
            "content-type",
            "content-security-policy",
            "referrer-policy",
            "x-content-type-options",
            "x-frame-options",
            "x-robots-tag",
        ] {
            headers.insert(
                name.into(),
                response.headers()[name].to_str().unwrap().into(),
            );
        }
        let metadata =
            serde_json::json!({"status": response.status().as_u16(), "headers": headers});
        let body = to_bytes(response.into_body(), 1_048_576).await.unwrap();
        std::fs::write(output.join(format!("{name}.html")), body).unwrap();
        std::fs::write(
            output.join(format!("{name}.json")),
            serde_json::to_vec_pretty(&metadata).unwrap(),
        )
        .unwrap();
        let css = self
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/admin/corp/assets/operator.css")
                    .header("host", OP_HOST)
                    .header("authorization", auth)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(css.status(), StatusCode::OK);
        std::fs::write(
            output.join("assets/operator.css"),
            to_bytes(css.into_body(), 1_048_576).await.unwrap(),
        )
        .unwrap();
    }
}

#[tokio::test]
async fn export_synthetic_operator_egress_states_for_browser_verification() {
    let f = Fixture::new(false).await;
    f.proof("198.51.100.20").await;
    assert!(
        !f.state
            .inv
            .corp_record()
            .await
            .unwrap()
            .unwrap()
            .status
            .enabled
    );
    assert!(
        f.state
            .corp_egress
            .ready_to_enable(&f.state, f.version().await)
            .await
            .unwrap()
    );
    f.export_operator_page("egress-ready").await;
    let ticket = f.queue().await;
    let call = f.next().await;
    assert_eq!(
        f.state.corp_egress.attempt(&sid()).state,
        AttemptState::Running
    );
    f.export_operator_page("egress-running").await;
    call.done.send(Err(ProbeError::Failed)).unwrap();
    assert_eq!(ticket.wait().await, Err(ProbeError::Failed));
    assert!(
        f.state
            .corp_egress
            .ready_to_enable(&f.state, f.version().await)
            .await
            .unwrap()
    );
    f.export_operator_page("egress-failed").await;
    assert_eq!(
        f.op(Some((
            "/enabled",
            &format!(
                "expected_config_version={}&enabled=true&confirm=true",
                f.version().await
            )
        )))
        .await
        .0,
        StatusCode::SEE_OTHER
    );
    assert!(
        f.state
            .inv
            .corp_record()
            .await
            .unwrap()
            .unwrap()
            .status
            .enabled
    );
    f.export_operator_page("egress-enabled").await;
}

impl Fixture {
    async fn add_extra_server(&self, id: &str, address: &str) -> ServerId {
        let id = ServerId(id.into());
        self.state
            .inv
            .add_server(&Server {
                id: id.clone(),
                address: address.into(),
                ssh_port: 22,
                ssh_user: "root".into(),
                kernels: vec![KernelId("xray".into())],
                enabled_protocols: vec![ProtocolId("vless+reality".into())],
                trusted_host_fingerprint: None,
                hoster: "synthetic".into(),
                jump_via: None,
                usage_coefficient: 1.0,
            })
            .await
            .unwrap();
        self.state.inv.grant(&user().id, &id).await.unwrap();
        for (name, value) in [
            ("vless.public_key", URL_SAFE_NO_PAD.encode([7_u8; 32])),
            ("vless.short_id", "12345678".into()),
            ("vless.sni", "www.example.com".into()),
        ] {
            self.state
                .inv
                .set_server_secret(&id, name, &value)
                .await
                .unwrap();
        }
        id
    }
}

#[tokio::test]
async fn refreshing_one_server_preserves_every_other_servers_saved_rows() {
    let f = Fixture::new(false).await;
    let other = f.add_extra_server("other-node", "192.0.2.11").await;
    let ticket = f
        .state
        .corp_egress
        .queue_probe(f.state.clone(), f.version().await, other.clone())
        .await
        .unwrap();
    f.succeed(f.next().await, "198.51.100.30").await;
    assert_eq!(ticket.wait().await, Ok(()));
    f.proof("198.51.100.20").await;
    f.clock.store(NOW + 60, Ordering::SeqCst);
    f.proof("198.51.100.21").await;
    let rows = f.state.inv.corp_verified_egress().await.unwrap();
    assert_eq!(rows.len(), 2);
    let preserved = rows.iter().find(|row| row.server_id == other).unwrap();
    assert_eq!(preserved.verified_at, NOW);
    assert_eq!(preserved.ip.to_string(), "198.51.100.30");
    let refreshed = rows.iter().find(|row| row.server_id == sid()).unwrap();
    assert_eq!(refreshed.verified_at, NOW + 60);
    assert_eq!(refreshed.ip.to_string(), "198.51.100.21");
}

#[tokio::test]
async fn bounded_refresh_rotates_past_failed_early_servers() {
    let f = Fixture::new(false).await;
    for (id, address) in [
        ("extra-a", "192.0.2.11"),
        ("extra-b", "192.0.2.12"),
        ("extra-c", "192.0.2.13"),
        ("extra-d", "192.0.2.14"),
    ] {
        f.add_extra_server(id, address).await;
    }
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..5 {
        let controller = Arc::clone(&f.state.corp_egress);
        let state = f.state.clone();
        let mut refresh = tokio::spawn(async move { controller.refresh_due(state).await });
        let mut scanned = std::collections::BTreeSet::new();
        loop {
            tokio::select! {
                result = &mut refresh => { let _ = result.unwrap(); break; }
                call = f.next() => {
                    let host = call.request.outbound["server"].as_str().unwrap().to_owned();
                    assert!(scanned.insert(host.clone()), "must not retry a failed server within one scan");
                    assert!(scanned.len() <= 4);
                    seen.insert(host);
                    call.done.send(Err(ProbeError::Failed)).unwrap();
                }
            }
        }
        assert!(!scanned.is_empty());
        if seen.len() == 5 {
            break;
        }
    }
    assert_eq!(
        seen.len(),
        5,
        "failed early servers must not starve later ones"
    );
    assert!(f.state.inv.corp_verified_egress().await.unwrap().is_empty());
}

struct PanickingRunner {
    tx: mpsc::UnboundedSender<Call>,
}
impl std::fmt::Debug for PanickingRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("synthetic-private-runner-detail")
    }
}
#[async_trait::async_trait]
impl ProbeRunner for PanickingRunner {
    fn available(&self) -> bool {
        true
    }
    #[allow(clippy::panic, reason = "fault injection verifies owned-job unwinding")]
    async fn run(&self, request: ProbeRequest) -> Result<(), ProbeError> {
        let (done, result) = oneshot::channel();
        self.tx
            .send(Call { request, done })
            .unwrap_or_else(|_| panic!("test receiver missing"));
        let _ = result.await;
        panic!("synthetic-private-runner-panic");
    }
}

#[tokio::test]
async fn unexpected_runner_panic_clears_challenge_and_never_commits_proof() {
    let mut f = Fixture::new(false).await;
    let (tx, rx) = mpsc::unbounded_channel();
    let clock = Arc::clone(&f.clock);
    f.state.corp_egress = Arc::new(EgressController::new(
        Arc::new(PanickingRunner { tx }),
        Arc::new(move || clock.load(Ordering::SeqCst)),
    ));
    f.calls = Mutex::new(rx);
    assert!(!format!("{:?}", f.state.corp_egress).contains("synthetic-private-runner-detail"));
    let ticket = f.queue().await;
    let call = f.next().await;
    let token = call.request.token.to_string();
    assert!(!format!("{ticket:?}").contains(&token));
    assert_eq!(
        f.state
            .corp_egress
            .observe(&token, "198.51.100.20".parse().unwrap()),
        Ok(())
    );
    call.done.send(Ok(())).unwrap();
    let result = tokio::time::timeout(std::time::Duration::from_secs(10), ticket.wait())
        .await
        .unwrap();
    assert!(result.is_err());
    assert_ne!(
        f.state.corp_egress.attempt(&sid()).state,
        AttemptState::Running
    );
    assert_eq!(
        f.state
            .corp_egress
            .observe(&token, "198.51.100.20".parse().unwrap()),
        Err(ProbeError::Failed)
    );
    assert!(f.state.inv.corp_verified_egress().await.unwrap().is_empty());
}

#[tokio::test]
async fn a_concurrent_newer_renewal_is_not_overwritten_by_an_older_completion_clock() {
    let f = Fixture::new(false).await;
    f.proof("198.51.100.20").await;
    f.clock.store(NOW + 60, Ordering::SeqCst);
    let ticket = f.queue().await;
    let call = f.next().await;
    let previous = f.state.inv.corp_verified_egress().await.unwrap();
    let mut newer = previous.clone();
    newer[0].verified_at = NOW + 120;
    f.state
        .inv
        .refresh_corp_egress(f.version().await, &previous, &newer, "spec-concurrent")
        .await
        .unwrap();
    f.succeed(call, "198.51.100.20").await;
    assert!(ticket.wait().await.is_err());
    assert_eq!(
        f.state.inv.corp_verified_egress().await.unwrap()[0].verified_at,
        NOW + 120
    );
}

#[tokio::test]
async fn absent_binding_fails_before_starting_any_probe() {
    let mut f = Fixture::new(false).await;
    f.state.inv = SqliteInventory::open(&f.dir.path().join("unbound.db"))
        .await
        .unwrap();
    assert_eq!(
        f.state
            .corp_egress
            .queue_probe(f.state.clone(), 1, sid())
            .await
            .unwrap_err(),
        ProbeError::NotFound
    );
    assert!(f.calls.lock().await.try_recv().is_err());
}

#[tokio::test]
async fn callback_from_previous_endpoint_cannot_satisfy_the_next_endpoint() {
    let f = Fixture::new(true).await;
    let ticket = f.queue().await;
    let first = f.next().await;
    let old = first.request.token.to_string();
    f.succeed(first, "198.51.100.20").await;
    let second = f.next().await;
    assert_eq!(
        f.observe(&old, "198.51.100.21").await.status(),
        StatusCode::UNAUTHORIZED
    );
    second.done.send(Ok(())).unwrap();
    assert_eq!(ticket.wait().await, Err(ProbeError::Failed));
    assert!(f.state.inv.corp_verified_egress().await.unwrap().is_empty());
}
