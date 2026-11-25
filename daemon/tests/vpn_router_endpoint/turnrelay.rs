use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use http_body_util::BodyExt;
use serde_json::Value;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{KernelId, ProtocolId, RenderCtx, Server, ServerId, User, UserId};
use vpnctl_inventory::SqliteInventory;
use vpnctl_protocols::turnrelay_applied_digest;
use vpnctld::{AppState, router};

use super::common::TEST_DEVICE_ID;

const RAW_UA: &str = "VPNRouter/2.4.1 v2rayN/6.62";
const LEGACY_UA: &str = "v2rayN/6.62";
const BUSINESS: &str = "VPNRouterBusiness/2.52.0";
const CAPABILITY: &str = "turnrelay-v1";
const FINGERPRINT: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const CORE: &str = "1.14.4-vpnctl.3";

struct Fixture {
    _dir: TempDir,
    state: AppState,
}

impl Fixture {
    async fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let inv = SqliteInventory::open(&dir.path().join("inv.db"))
            .await
            .unwrap();
        let registry = vpnctl_kernels::build_registry().unwrap();
        let (mut state, _writer) = vpnctld::make_app_state_for_tests(inv, Arc::new(registry));
        state.rate_limiter = Arc::new(vpnctld::rate_limit::RateLimiter::new(
            100.0,
            0.0,
            Duration::from_secs(60),
        ));
        for (sid, address, label, relay) in [
            ("de", "192.0.2.10", "Germany", true),
            ("is", "192.0.2.11", "Iceland", false),
            ("nl", "192.0.2.12", "Netherlands", false),
        ] {
            let mut protocols = vec![ProtocolId("vless+reality".into())];
            let mut kernels = vec![KernelId("sing-box".into())];
            if relay {
                protocols.push(ProtocolId("turnrelay".into()));
                kernels.push(KernelId("turnrelay".into()));
            }
            let server = Server {
                id: ServerId(sid.into()),
                address: address.into(),
                ssh_port: 22,
                ssh_user: "root".into(),
                kernels,
                enabled_protocols: protocols,
                trusted_host_fingerprint: None,
                hoster: "generic".into(),
                jump_via: None,
                usage_coefficient: 1.0,
            };
            state.inv.add_server(&server).await.unwrap();
            state
                .inv
                .set_server_display_name(&server.id, Some(label))
                .await
                .unwrap();
            state
                .inv
                .set_server_secret(&server.id, "vless.public_key", &format!("PUB_{sid}"))
                .await
                .unwrap();
            state
                .inv
                .set_server_secret(&server.id, "vless.short_id", "12345678")
                .await
                .unwrap();
        }
        let user = User {
            id: UserId("tester-1".into()),
            uuid: "11111111-2222-3333-4444-555555555555".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        };
        state.inv.add_user(&user).await.unwrap();
        state
            .inv
            .set_vpn_router_device_id(&user.id, TEST_DEVICE_ID)
            .await
            .unwrap();
        for server in ["de", "is", "nl"] {
            state
                .inv
                .grant(&user.id, &ServerId(server.into()))
                .await
                .unwrap();
        }
        Self { _dir: dir, state }
    }

    async fn configure_relay(&self, publish_targets: &str) {
        let sid = ServerId("de".into());
        let server = self.state.inv.get_server(&sid).await.unwrap().unwrap();
        let mut secrets = self.state.inv.list_server_secrets(&sid).await.unwrap();
        for (key, value) in [
            ("turnrelay.turn_server", "turn.example.org:3478"),
            ("turnrelay.turn_username", "turn-user"),
            ("turnrelay.turn_password", "turn-pass"),
            ("turnrelay.password", "exit-secret"),
            ("turnrelay.publish", "vless+reality"),
            ("turnrelay.publish_targets", publish_targets),
        ] {
            secrets.insert(key.into(), value.into());
            self.state
                .inv
                .set_server_secret(&sid, key, value)
                .await
                .unwrap();
        }
        let digest = turnrelay_applied_digest(&RenderCtx::new(&server, &secrets)).unwrap();
        self.state
            .inv
            .set_server_secret(&sid, "observed.turnrelay.applied", &digest)
            .await
            .unwrap();
        self.state
            .inv
            .set_server_secret(&sid, "observed.turnrelay.cert_sha256", FINGERPRINT)
            .await
            .unwrap();
    }
}

fn expected_vless(address: &str, pbk: &str, label: &str) -> String {
    format!(
        "vless://11111111-2222-3333-4444-555555555555@{address}:443?encryption=none&type=tcp&security=reality&pbk={pbk}&fp=randomized&sni=yahoo.com&sid=12345678&spx=%2F&flow=xtls-rprx-vision&packetEncoding=xudp#{label}"
    )
}

fn baseline_lines() -> Vec<String> {
    vec![
        expected_vless("192.0.2.10", "PUB_de", "Germany%20VLESS%20~tester-1"),
        expected_vless("192.0.2.11", "PUB_is", "Iceland%20VLESS%20~tester-1"),
        expected_vless("192.0.2.12", "PUB_nl", "Netherlands%20VLESS%20~tester-1"),
    ]
}

fn baseline_blob() -> String {
    STANDARD.encode(baseline_lines().join("\n"))
}

async fn request(
    state: &AppState,
    user_agent: &str,
    capability: Option<&str>,
    platform: Option<&str>,
    core: Option<&str>,
) -> axum::http::Response<axum::body::Body> {
    let mut builder = Request::builder()
        .uri(format!("/api/v1/app/config/{TEST_DEVICE_ID}"))
        .header("user-agent", user_agent);
    if let Some(capability) = capability {
        builder = builder.header("X-VPNRouter-Capabilities", capability);
    }
    if let Some(platform) = platform {
        builder = builder.header("X-VPNRouter-Platform", platform);
    }
    if let Some(core) = core {
        builder = builder.header("X-VPNRouter-Core-Version", core);
    }
    router(state.clone())
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

async fn body(state: &AppState, user_agent: &str, capability: Option<&str>) -> Vec<u8> {
    let response = request(state, user_agent, capability, None, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec()
}

fn decode_lines(bytes: &[u8]) -> Vec<String> {
    let text = std::str::from_utf8(bytes).unwrap();
    let encoded = if text.trim_start().starts_with('{') {
        let value: Value = serde_json::from_slice(bytes).unwrap();
        value["config"].as_str().unwrap_or_default().to_owned()
    } else {
        text.to_owned()
    };
    if encoded.is_empty() {
        return Vec::new();
    }
    String::from_utf8(STANDARD.decode(encoded).unwrap())
        .unwrap()
        .split('\n')
        .map(str::to_owned)
        .collect()
}

fn turnrelay_profiles(lines: &[String]) -> Vec<&String> {
    lines
        .iter()
        .filter(|line| line.starts_with("turnrelay://"))
        .collect()
}

fn decode_profile(line: &str) -> Value {
    let payload = line
        .strip_prefix("turnrelay://")
        .unwrap()
        .split_once('#')
        .unwrap()
        .0;
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
}

#[tokio::test]
async fn adding_turnrelay_settings_does_not_change_capability_less_bytes() {
    let fixture = Fixture::new().await;
    let before = body(&fixture.state, RAW_UA, None).await;
    assert_eq!(before, baseline_blob().as_bytes());

    fixture.configure_relay("").await;
    assert_eq!(body(&fixture.state, RAW_UA, None).await, before);
    assert_eq!(
        body(&fixture.state, RAW_UA, Some("turnrelay-v10")).await,
        before
    );
    assert_eq!(
        body(&fixture.state, LEGACY_UA, Some(CAPABILITY)).await,
        before
    );
}

#[tokio::test]
async fn repeated_capability_header_is_accepted_and_non_vpnrouter_ua_is_ignored() {
    let fixture = Fixture::new().await;
    fixture.configure_relay("").await;
    let response = router(fixture.state.clone())
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/app/config/{TEST_DEVICE_ID}"))
                .header("user-agent", RAW_UA)
                .header("X-VPNRouter-Capabilities", "future-v1")
                .header("X-VPNRouter-Capabilities", CAPABILITY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let lines = decode_lines(&bytes);
    assert_eq!(turnrelay_profiles(&lines).len(), 1);
}

#[tokio::test]
async fn same_server_emits_one_relayed_vless_duplicate_and_one_profile() {
    let fixture = Fixture::new().await;
    fixture.configure_relay("").await;
    let lines = decode_lines(&body(&fixture.state, RAW_UA, Some(CAPABILITY)).await);
    assert_eq!(&lines[..3], baseline_lines().as_slice());

    let relayed = lines
        .iter()
        .find(|line| line.contains("outbound=vless-turnrelay-de&detour=turnrelay-de"))
        .expect("same-server relayed VLESS duplicate");
    assert!(!relayed.contains("-via-"));
    assert!(relayed.ends_with("#Germany%20VLESS%20%C2%B7%20TurnRelay%20~tester-1"));

    let profiles = turnrelay_profiles(&lines);
    assert_eq!(
        profiles.len(),
        1,
        "one deduplicated hop per exit: {lines:?}"
    );
    assert!(profiles[0].ends_with("#Germany%20TurnRelay%20~tester-1"));
    let profile = decode_profile(profiles[0]);
    assert_eq!(profile["id"], "turnrelay-de");
    assert_eq!(profile["provider"], "static");
    assert_eq!(profile["server_type"], "exit");
    assert_eq!(profile["server"], "192.0.2.10");
    assert_eq!(profile["server_port"], 53492);
    assert_eq!(profile["turn_server"], "turn.example.org:3478");
    assert_eq!(profile["turn_username"], "turn-user");
    assert_eq!(profile["turn_password"], "turn-pass");
    assert_eq!(profile["password"], "exit-secret");
    assert_eq!(profile["server_fingerprint"], FINGERPRINT);
    assert_eq!(profile["connections"], 2);
    assert_eq!(profile["mode"], "dtls");
    assert_eq!(profile["udp"], true);
}

#[tokio::test]
async fn cross_server_targets_use_standard_outbound_and_detour_params() {
    let fixture = Fixture::new().await;
    fixture.configure_relay("is,nl").await;
    let lines = decode_lines(&body(&fixture.state, RAW_UA, Some(CAPABILITY)).await);
    assert_eq!(&lines[..3], baseline_lines().as_slice());

    let same = lines
        .iter()
        .find(|line| line.contains("outbound=vless-turnrelay-de&detour=turnrelay-de"))
        .expect("same-server duplicate");
    assert!(same.ends_with("#Germany%20VLESS%20%C2%B7%20TurnRelay%20~tester-1"));

    let via_is = lines
        .iter()
        .find(|line| line.contains("outbound=vless-turnrelay-is-via-de&detour=turnrelay-de"))
        .expect("cross-server target is");
    assert!(via_is.ends_with("#Iceland%20VLESS%20%C2%B7%20TurnRelay%20%28Germany%29%20~tester-1"));

    let via_nl = lines
        .iter()
        .filter(|line| line.contains("outbound=vless-turnrelay-nl-via-de&detour=turnrelay-de"))
        .count();
    assert_eq!(via_nl, 1);
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.contains("detour=turnrelay-de"))
            .count(),
        3,
        "same-server + two cross-server duplicates: {lines:?}"
    );
    assert_eq!(turnrelay_profiles(&lines).len(), 1);
}

#[tokio::test]
async fn wildcard_publish_targets_select_every_other_eligible_server() {
    let fixture = Fixture::new().await;
    fixture.configure_relay("*").await;
    let lines = decode_lines(&body(&fixture.state, RAW_UA, Some(CAPABILITY)).await);
    for target in ["is", "nl"] {
        assert!(
            lines.iter().any(|line| line.contains(&format!(
                "outbound=vless-turnrelay-{target}-via-de&detour=turnrelay-de"
            ))),
            "missing wildcard target {target}: {lines:?}"
        );
    }
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.contains("detour=turnrelay-de"))
            .count(),
        3
    );
    assert_eq!(turnrelay_profiles(&lines).len(), 1);
}

async fn assert_no_turnrelay(state: &AppState, case: &str) {
    let lines = decode_lines(&body(state, RAW_UA, Some(CAPABILITY)).await);
    assert!(
        !lines.iter().any(|line| line.contains("turnrelay")),
        "TurnRelay must be omitted for {case}: {lines:?}"
    );
}

#[tokio::test]
async fn hidden_suppressed_revoked_detoured_and_unapplied_states_are_omitted() {
    {
        let fixture = Fixture::new().await;
        fixture.configure_relay("").await;
        fixture
            .state
            .inv
            .set_server_protocol_hidden(
                &ServerId("de".into()),
                &ProtocolId("turnrelay".into()),
                true,
            )
            .await
            .unwrap();
        assert_no_turnrelay(&fixture.state, "hidden").await;
    }
    {
        let fixture = Fixture::new().await;
        fixture.configure_relay("").await;
        fixture
            .state
            .inv
            .set_server_auto_suppress(&ServerId("de".into()), true)
            .await
            .unwrap();
        fixture
            .state
            .inv
            .set_server_suppressed(&ServerId("de".into()), true)
            .await
            .unwrap();
        assert_no_turnrelay(&fixture.state, "suppressed").await;
    }
    {
        let fixture = Fixture::new().await;
        fixture.configure_relay("").await;
        fixture
            .state
            .inv
            .revoke(&UserId("tester-1".into()), &ServerId("de".into()))
            .await
            .unwrap();
        assert_no_turnrelay(&fixture.state, "revoked").await;
    }
    {
        let fixture = Fixture::new().await;
        fixture.configure_relay("").await;
        fixture
            .state
            .inv
            .set_client_detour_via_as("test", &ServerId("de".into()), Some(&ServerId("is".into())))
            .await
            .unwrap();
        assert_no_turnrelay(&fixture.state, "detoured").await;
    }
    {
        let fixture = Fixture::new().await;
        fixture.configure_relay("").await;
        fixture
            .state
            .inv
            .set_server_secret(&ServerId("de".into()), "observed.turnrelay.applied", "")
            .await
            .unwrap();
        assert_no_turnrelay(&fixture.state, "undeployed").await;
    }
    {
        let fixture = Fixture::new().await;
        fixture.configure_relay("").await;
        fixture
            .state
            .inv
            .set_server_secret(&ServerId("de".into()), "observed.turnrelay.cert_sha256", "")
            .await
            .unwrap();
        assert_no_turnrelay(&fixture.state, "missing certificate").await;
    }
    {
        let fixture = Fixture::new().await;
        fixture.configure_relay("").await;
        fixture
            .state
            .inv
            .set_server_secret(&ServerId("de".into()), "turnrelay.password", "rotated")
            .await
            .unwrap();
        assert_no_turnrelay(&fixture.state, "rotated exit password").await;
    }
    {
        let fixture = Fixture::new().await;
        fixture.configure_relay("").await;
        fixture
            .state
            .inv
            .set_server_secret(&ServerId("de".into()), "turnrelay.turn_password", "rotated")
            .await
            .unwrap();
        assert_no_turnrelay(&fixture.state, "rotated TURN password").await;
    }
    {
        let fixture = Fixture::new().await;
        fixture.configure_relay("").await;
        fixture
            .state
            .inv
            .set_server_secret(&ServerId("de".into()), "turnrelay.publish", "")
            .await
            .unwrap();
        assert_no_turnrelay(&fixture.state, "publish disabled").await;
    }
}

#[tokio::test]
async fn desktop_core_pin_is_honored_only_for_supported_desktop_platforms() {
    let fixture = Fixture::new().await;
    fixture.configure_relay("").await;
    let full = body(&fixture.state, RAW_UA, Some(CAPABILITY)).await;
    let full_lines = decode_lines(&full);
    assert_eq!(turnrelay_profiles(&full_lines).len(), 1);

    // Android and other unsupported platforms are capability-only: with no
    // desktop pin they receive the same profile as a desktop client.
    let android_before_pin = request(
        &fixture.state,
        "VPNRouter/2.4.1",
        Some(CAPABILITY),
        Some("android"),
        None,
    )
    .await;
    let android_lines = decode_lines(
        &android_before_pin
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes(),
    );
    assert_eq!(android_lines, full_lines);

    fixture
        .state
        .inv
        .set_desktop_subscription_core(&ServerId("de".into()), Some(CORE))
        .await
        .unwrap();
    let unrestricted = body(&fixture.state, RAW_UA, Some(CAPABILITY)).await;
    let unrestricted_lines = decode_lines(&unrestricted);
    assert!(
        !unrestricted_lines
            .iter()
            .any(|line| line.contains("192.0.2.10"))
    );
    assert!(
        !unrestricted_lines
            .iter()
            .any(|line| line.contains("turnrelay"))
    );

    let pinned_off = request(
        &fixture.state,
        BUSINESS,
        Some(CAPABILITY),
        Some("windows"),
        Some("1.14.4-vpnctl.2"),
    )
    .await;
    let pinned_lines = decode_lines(&pinned_off.into_body().collect().await.unwrap().to_bytes());
    assert_eq!(pinned_lines, unrestricted_lines);

    for (ua, platform) in [
        (BUSINESS, "windows"),
        ("VPNRouter/2.4.1", "windows"),
        ("VPNRouter/2.4.1", "macos"),
        ("VPNRouter/2.4.1", "linux"),
    ] {
        let response = request(
            &fixture.state,
            ua,
            Some(CAPABILITY),
            Some(platform),
            Some(CORE),
        )
        .await;
        let lines = decode_lines(&response.into_body().collect().await.unwrap().to_bytes());
        assert_eq!(
            lines, full_lines,
            "{ua} {platform} with the exact core must keep the exit"
        );
    }

    for (ua, platform) in [
        ("VPNRouter/2.4.1", "android"),
        ("VPNRouterBusiness/2.52.0", "android"),
        ("VPNRouterBusiness/2.52.0", "macos"),
        ("VPNRouterBusiness/2.52.0", "linux"),
    ] {
        let response = request(
            &fixture.state,
            ua,
            Some(CAPABILITY),
            Some(platform),
            Some(CORE),
        )
        .await;
        let lines = decode_lines(&response.into_body().collect().await.unwrap().to_bytes());
        assert_eq!(
            lines, unrestricted_lines,
            "{ua} {platform} ignores the core header and keeps the desktop-pinned server hidden"
        );
    }
}

#[tokio::test]
async fn generic_subscription_and_sub_route_never_gain_turnrelay() {
    let fixture = Fixture::new().await;
    fixture.configure_relay("*").await;
    let generic = decode_lines(&body(&fixture.state, LEGACY_UA, Some(CAPABILITY)).await);
    assert_eq!(generic, baseline_lines());

    let user = fixture
        .state
        .inv
        .get_user(&UserId("tester-1".into()))
        .await
        .unwrap()
        .unwrap();
    let token = user.sub_token.unwrap();
    let response = router(fixture.state.clone())
        .oneshot(
            Request::builder()
                .uri(format!("/sub/{token}"))
                .header("user-agent", RAW_UA)
                .header("X-VPNRouter-Capabilities", CAPABILITY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    assert!(!String::from_utf8_lossy(&bytes).contains("turnrelay"));
}
