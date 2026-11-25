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

use vpnctl_core::{KernelId, Protocol, ProtocolId, Registry, RenderCtx, Server, ServerId, UserId};
use vpnctl_kernels::{DnsttKernel, SingBox};
use vpnctl_protocols::{Dnstt, VlessReality};
use vpnctld::{AppState, router};

use super::common::{TEST_DEVICE_ID, seed_state};

const VPN_ROUTER_UA: &str = "VPNRouter/2.4.1";
const VPN_ROUTER_RAW_UA: &str = "VPNRouter/2.4.1 v2rayN/6.62";
const LEGACY_UA: &str = "v2rayN/6.62";
const DNS_CAPABILITY: &str = "dnstt-v1";
const DNS_DOMAIN: &str = "t.example.com";
const DNS_RESOLVER: &str = "192.0.2.53";

// Public test vectors and synthetic key material, independent of real nodes.
const NOISE_PRIVATE: &str = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo";
const NOISE_PUBLIC: &str = "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo";
const NOISE_PUBLIC_HEX: &str = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
const SSH_SEED: &str = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA";
const SSH_HOST_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHm1Vi6P5lT5QHixEuipi6eQH4U65pW+1+DjkQutBJZk";

const LEGACY_LINKS: &str = concat!(
    "vless://11111111-2222-3333-4444-555555555555@de.example.com:443?encryption=none&type=tcp&security=reality&pbk=PUB_de&fp=randomized&sni=yahoo.com&sid=12345678&spx=%2F&flow=xtls-rprx-vision&packetEncoding=xudp#Germany%20VLESS%20~tester-1\n",
    "vless://11111111-2222-3333-4444-555555555555@is.example.com:443?encryption=none&type=tcp&security=reality&pbk=PUB_is&fp=randomized&sni=yahoo.com&sid=12345678&spx=%2F&flow=xtls-rprx-vision&packetEncoding=xudp#Iceland%20VLESS%20~tester-1",
);

async fn seed_dnstt_registry(dir: &TempDir) -> AppState {
    let mut state = seed_state(dir).await;
    let mut registry = Registry::new();
    registry.register_kernel(Box::new(SingBox::new())).unwrap();
    registry.register_kernel(Box::new(DnsttKernel)).unwrap();
    registry
        .register_protocol(Box::new(VlessReality::new()))
        .unwrap();
    registry.register_protocol(Box::new(Dnstt)).unwrap();
    state.registry = Arc::new(registry);
    state.rate_limiter = Arc::new(vpnctld::rate_limit::RateLimiter::new(
        100.0,
        0.0,
        Duration::from_secs(60),
    ));
    state
}

async fn add_dnstt_server(state: &AppState, name: &str) -> ServerId {
    let id = ServerId(name.into());
    state
        .inv
        .add_server(&Server {
            id: id.clone(),
            address: "192.0.2.77".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("dnstt".into())],
            enabled_protocols: vec![ProtocolId("dnstt".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    let applied = format!("{DNS_DOMAIN}+{DNS_RESOLVER}+{NOISE_PUBLIC}");
    for (key, value) in [
        ("dnstt.domain", DNS_DOMAIN),
        ("dnstt.resolver", DNS_RESOLVER),
        ("dnstt.private_key", NOISE_PRIVATE),
        ("dnstt.public_key", NOISE_PUBLIC),
        ("dnstt.ssh_seed", SSH_SEED),
        ("observed.dnstt.ssh_host_key", SSH_HOST_KEY),
        ("observed.dnstt.applied", applied.as_str()),
    ] {
        state.inv.set_server_secret(&id, key, value).await.unwrap();
    }
    state
        .inv
        .grant(&UserId("tester-1".into()), &id)
        .await
        .unwrap();
    simulate_apply(state, &id).await;
    id
}

async fn simulate_apply(state: &AppState, id: &ServerId) {
    let server = state.inv.get_server(id).await.unwrap().unwrap();
    let secrets = state.inv.list_server_secrets(id).await.unwrap();
    let users = state
        .inv
        .users_for_server_protocol(id, &ProtocolId("dnstt".into()))
        .await
        .unwrap();
    let rendered = Dnstt
        .server_inbound(&RenderCtx::new(&server, &secrets), &users)
        .unwrap();
    let keys = rendered["authorized_keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|key| key.as_str().unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    state
        .inv
        .set_server_secret(id, "observed.dnstt.authorized_keys", &keys)
        .await
        .unwrap();
}

async fn get(
    state: &AppState,
    path: &str,
    ua: &str,
    capability: Option<&str>,
) -> (String, Vec<u8>) {
    let mut request = Request::builder().uri(path).header("user-agent", ua);
    if let Some(value) = capability {
        request = request.header("X-VPNRouter-Capabilities", value);
    }
    get_request(state, request).await
}

async fn get_request(state: &AppState, request: axum::http::request::Builder) -> (String, Vec<u8>) {
    let response = router(state.clone())
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let content_type = response.headers()["content-type"]
        .to_str()
        .unwrap()
        .to_owned();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (content_type, bytes.to_vec())
}

async fn get_opted_in_config(state: &AppState) -> String {
    let path = format!("/api/v1/app/config/{TEST_DEVICE_ID}");
    let (content_type, body) = get(state, &path, VPN_ROUTER_UA, Some(DNS_CAPABILITY)).await;
    assert!(content_type.starts_with("application/json"));
    let wrapper: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(wrapper["status"], "ok");
    assert_eq!(wrapper["app"], "vpn-router");
    String::from_utf8(
        STANDARD
            .decode(wrapper["config"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap()
}

fn dnstt_profile(config: &str) -> Value {
    let entry = config.strip_prefix(LEGACY_LINKS).unwrap();
    let entry = entry.strip_prefix("\ndnstt://").unwrap();
    assert!(!entry.contains('\n'), "exactly one DNSTT entry expected");
    let (encoded, label) = entry.split_once('#').unwrap();
    assert!(!encoded.contains('='));
    assert!(!label.is_empty() && !label.contains(char::is_whitespace));
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).unwrap()).unwrap()
}

fn take_ssh_string<'a>(fields: &mut &'a [u8]) -> &'a [u8] {
    let (length_bytes, tail) = fields.split_at(4);
    let length = u32::from_be_bytes(length_bytes.try_into().unwrap()) as usize;
    let (value, remaining) = tail.split_at(length);
    *fields = remaining;
    value
}

fn ssh_public_identity(profile: &Value) -> Vec<u8> {
    let mut lines = profile["ssh_private_key"].as_str().unwrap().lines();
    let key_kind = "OPENSSH PRIVATE KEY";
    assert_eq!(
        lines.next(),
        Some(format!("-----BEGIN {key_kind}-----").as_str())
    );
    assert_eq!(
        lines.next_back(),
        Some(format!("-----END {key_kind}-----").as_str())
    );
    let bytes = STANDARD.decode(lines.collect::<String>()).unwrap();
    let mut fields = bytes.strip_prefix(b"openssh-key-v1\0").unwrap();
    assert_eq!(take_ssh_string(&mut fields), b"none");
    assert_eq!(take_ssh_string(&mut fields), b"none");
    assert!(take_ssh_string(&mut fields).is_empty());
    let (count_bytes, mut fields) = fields.split_at(4);
    assert_eq!(u32::from_be_bytes(count_bytes.try_into().unwrap()), 1);
    let mut public_key = take_ssh_string(&mut fields);
    assert!(!take_ssh_string(&mut fields).is_empty());
    assert_eq!(take_ssh_string(&mut public_key), b"ssh-ed25519");
    let identity = take_ssh_string(&mut public_key);
    assert_eq!(identity.len(), 32);
    assert!(public_key.is_empty());
    identity.to_vec()
}

#[tokio::test]
async fn windows_business_app_config_respects_the_exact_core_grant_and_dnstt_capability() {
    const BUSINESS: &str = "VPNRouterBusiness/2.52.0";
    const CORE: &str = "1.14.4-vpnctl.3";
    let dir = TempDir::new().unwrap();
    let state = seed_dnstt_registry(&dir).await;
    let dns = add_dnstt_server(&state, "dns-fixture").await;
    let reality = ServerId("de".into());
    let full = get_opted_in_config(&state).await;
    assert_eq!(dnstt_profile(&full)["id"], "dns-fixture");
    for server in [&reality, &dns] {
        state
            .inv
            .set_desktop_subscription_core(server, Some(CORE))
            .await
            .unwrap();
    }
    let unrestricted = LEGACY_LINKS.split_once('\n').unwrap().1;
    let path = format!("/api/v1/app/config/{TEST_DEVICE_ID}");
    let request = |ua: &str, platform: &str, core: &str, capabilities: &str| {
        Request::builder()
            .uri(path.as_str())
            .header("User-Agent", ua)
            .header("X-VPNRouter-Platform", platform)
            .header("X-VPNRouter-Core-Version", core)
            .header("X-VPNRouter-Capabilities", capabilities)
    };
    async fn check(state: &AppState, request: axum::http::request::Builder, expected: &str) {
        let (content_type, body) = get_request(state, request).await;
        assert!(content_type.starts_with("application/json"));
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "ok");
        assert_eq!(json["config"], STANDARD.encode(expected));
    }
    for (ua, platform, core, capabilities, expected) in [
        (
            BUSINESS,
            "windows",
            CORE,
            "detour-v1, dnstt-v1",
            full.as_str(),
        ),
        (BUSINESS, "windows", CORE, "detour-v1", LEGACY_LINKS),
        (BUSINESS, "windows", CORE, "dnstt-v10", LEGACY_LINKS),
        (
            BUSINESS,
            "windows",
            "1.14.4-vpnctl.2",
            DNS_CAPABILITY,
            unrestricted,
        ),
        (BUSINESS, "linux", CORE, DNS_CAPABILITY, unrestricted),
        (BUSINESS, "macos", CORE, DNS_CAPABILITY, unrestricted),
        (BUSINESS, "android", CORE, DNS_CAPABILITY, unrestricted),
        (
            "OtherVPNRouterBusiness",
            "windows",
            CORE,
            DNS_CAPABILITY,
            unrestricted,
        ),
    ] {
        check(&state, request(ua, platform, core, capabilities), expected).await;
    }
    let business_request = || request(BUSINESS, "windows", CORE, DNS_CAPABILITY);
    check(
        &state,
        business_request().header("User-Agent", BUSINESS),
        unrestricted,
    )
    .await;
    let user = UserId("tester-1".into());
    for server in [&reality, &dns] {
        state.inv.revoke(&user, server).await.unwrap();
    }
    check(&state, business_request(), unrestricted).await;
}

#[tokio::test]
async fn dnstt_preserves_legacy_config_and_generic_subscription_bytes() {
    let dir = TempDir::new().unwrap();
    let state = seed_dnstt_registry(&dir).await;
    let user = UserId("tester-1".into());
    let token = state
        .inv
        .get_user(&user)
        .await
        .unwrap()
        .unwrap()
        .sub_token
        .unwrap();
    let app_path = format!("/api/v1/app/config/{TEST_DEVICE_ID}");
    let sub_path = format!("/sub/{token}");
    let requests = [
        (app_path.as_str(), VPN_ROUTER_RAW_UA, None),
        (app_path.as_str(), VPN_ROUTER_RAW_UA, Some("dnstt-v10")),
        (app_path.as_str(), LEGACY_UA, Some(DNS_CAPABILITY)),
        (sub_path.as_str(), VPN_ROUTER_RAW_UA, Some(DNS_CAPABILITY)),
    ];
    let mut baseline = Vec::new();
    for (path, ua, capabilities) in requests {
        let response = get(&state, path, ua, capabilities).await;
        assert!(response.0.starts_with("text/plain"));
        baseline.push(response);
    }
    let frozen = STANDARD.encode(LEGACY_LINKS);
    for response in &baseline[..3] {
        assert_eq!(response.1, frozen.as_bytes());
    }
    assert!(
        STANDARD
            .decode(&baseline[3].1)
            .unwrap()
            .starts_with(b"vless://")
    );

    add_dnstt_server(&state, "dns-fixture").await;

    for ((path, ua, capabilities), expected) in requests.into_iter().zip(baseline) {
        assert_eq!(get(&state, path, ua, capabilities).await, expected);
    }
}

#[tokio::test]
async fn dnstt_appends_one_profile_and_keeps_ssh_identity_stable_per_grant() {
    let dir = TempDir::new().unwrap();
    let state = seed_dnstt_registry(&dir).await;
    let user = UserId("tester-1".into());
    let server = add_dnstt_server(&state, "dns-fixture").await;

    let profile = dnstt_profile(&get_opted_in_config(&state).await);
    assert_eq!(profile["id"], "dns-fixture");
    assert_eq!(profile["resolver"], DNS_RESOLVER);
    assert_eq!(profile["port"], 53);
    assert_eq!(profile["domain"], DNS_DOMAIN);
    assert_eq!(profile["noise_key"], NOISE_PUBLIC_HEX);
    assert_eq!(profile["ssh_host_key"], SSH_HOST_KEY);

    let identity = ssh_public_identity(&profile);
    let repeated = dnstt_profile(&get_opted_in_config(&state).await);
    assert_eq!(ssh_public_identity(&repeated), identity);
    state
        .inv
        .set_grant_client_uuid(&user, &server, "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
        .await
        .unwrap();
    assert_eq!(
        get_opted_in_config(&state).await,
        LEGACY_LINKS,
        "rotated but unapplied"
    );
    simulate_apply(&state, &server).await;
    let changed_grant = dnstt_profile(&get_opted_in_config(&state).await);
    assert_ne!(ssh_public_identity(&changed_grant), identity);
}

#[tokio::test]
async fn dnstt_omits_profiles_with_missing_or_invalid_managed_settings() {
    let dir = TempDir::new().unwrap();
    let state = seed_dnstt_registry(&dir).await;
    for (index, (key, invalid)) in [
        ("dnstt.domain", "not a domain"),
        ("dnstt.resolver", "invalid resolver"),
        ("dnstt.private_key", "invalid-base64!"),
        ("dnstt.public_key", "AQID"),
        ("dnstt.ssh_seed", "AQID"),
        ("observed.dnstt.ssh_host_key", "ssh-ed25519 invalid!"),
        ("observed.dnstt.applied", "other.example.com+192.0.2.53"),
        ("observed.dnstt.authorized_keys", "unrecognized public key"),
    ]
    .into_iter()
    .enumerate()
    {
        let server = add_dnstt_server(&state, &format!("dns-missing-{index}")).await;
        let db =
            sqlx::SqlitePool::connect(&format!("sqlite:{}", dir.path().join("inv.db").display()))
                .await
                .unwrap();
        sqlx::query("DELETE FROM server_secrets WHERE server_id = ? AND key = ?")
            .bind(&server.0)
            .bind(key)
            .execute(&db)
            .await
            .unwrap();
        assert_eq!(
            get_opted_in_config(&state).await,
            LEGACY_LINKS,
            "missing {key}"
        );
        state
            .inv
            .set_server_secret(&server, key, invalid)
            .await
            .unwrap();
        assert_eq!(
            get_opted_in_config(&state).await,
            LEGACY_LINKS,
            "invalid {key}"
        );
    }
}

#[tokio::test]
async fn dnstt_omits_ungranted_hidden_suppressed_detoured_and_revoked_nodes() {
    let dir = TempDir::new().unwrap();
    let state = seed_dnstt_registry(&dir).await;
    let user = UserId("tester-1".into());
    let server = add_dnstt_server(&state, "dns-fixture").await;
    let protocol = ProtocolId("dnstt".into());

    state.inv.revoke(&user, &server).await.unwrap();
    assert_eq!(get_opted_in_config(&state).await, LEGACY_LINKS, "ungranted");
    state.inv.grant(&user, &server).await.unwrap();
    let _ = dnstt_profile(&get_opted_in_config(&state).await);

    state
        .inv
        .set_server_protocol_hidden(&server, &protocol, true)
        .await
        .unwrap();
    assert_eq!(get_opted_in_config(&state).await, LEGACY_LINKS, "hidden");
    state
        .inv
        .set_server_protocol_hidden(&server, &protocol, false)
        .await
        .unwrap();

    state
        .inv
        .set_server_auto_suppress(&server, true)
        .await
        .unwrap();
    state
        .inv
        .set_server_suppressed(&server, true)
        .await
        .unwrap();
    assert_eq!(
        get_opted_in_config(&state).await,
        LEGACY_LINKS,
        "suppressed"
    );
    state
        .inv
        .set_server_suppressed(&server, false)
        .await
        .unwrap();

    let via = ServerId("de".into());
    state
        .inv
        .set_client_detour_via_as("test", &server, Some(&via))
        .await
        .unwrap();
    assert_eq!(get_opted_in_config(&state).await, LEGACY_LINKS, "detoured");
    state
        .inv
        .set_client_detour_via_as("test", &server, None)
        .await
        .unwrap();
    let _ = dnstt_profile(&get_opted_in_config(&state).await);

    state.inv.revoke(&user, &server).await.unwrap();
    assert_eq!(get_opted_in_config(&state).await, LEGACY_LINKS, "revoked");
}
