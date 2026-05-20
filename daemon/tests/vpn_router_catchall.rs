//! Spec tests for the `/api/v1/app/config/*` catchall handler — the
//! defence-in-depth layer that stops the admin realm
//! (`WWW-Authenticate: Basic realm="vpnctl admin"`) from leaking when
//! a probe hits any path under `/api/v1/app/config/*` that is NOT a
//! valid single-segment device_id route.
//!
//! INDEPENDENCE: written from the spec alone, not the impl. If a test
//! fails, the impl is wrong or the spec is ambiguous — do not weaken.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{KernelId, ProtocolId, Registry, Server, ServerId, User, UserId};
use vpnctl_inventory::SqliteInventory;
use vpnctl_kernels::SingBox;
use vpnctl_protocols::VlessReality;
use vpnctld::{AppState, router};

const TEST_DEVICE_ID: &str = "a92b915032b48a2ed45ef72f4171e5f4";

/// Each MUST land on the catchall (not on `{device_id}`).
const CATCHALL_PATHS: &[&str] = &[
    "/api/v1/app/config",
    "/api/v1/app/config/",
    "/api/v1/app/config/foo",
    "/api/v1/app/config/foo/bar",
    "/api/v1/app/config/abc/def/ghi",
];

/// All 16 keywords from the existing classifier, mixed casing included
/// so the case-insensitive rule is exercised in the same table. Note:
/// `VPNRouter` is DELIBERATELY NOT in the VPN-client list — verified
/// against live subscription-server which returns the JSON wrapper for
/// `User-Agent: VPNRouter` (probed at https://ninitux.com 2026-05-19).
/// The non-VPN-client classification of VPNRouter is pinned by
/// `non_vpn_client_uas_are_rejected` in the module-level `#[cfg(test)]`
/// block of `vpn_router.rs`.
const VPN_CLIENT_UAS: &[&str] = &[
    "Streisand/1.0",
    "v2rayN/6.62",
    "V2RAYNG/1.8",
    "Shadowrocket/2.2",
    "Quantumult/X",
    "Surge/4.0",
    "cLaSh/Verge",
    "Sing-Box/1.10",
    "HIDDIFY/1.5",
    "NekoRay/3.21",
    "NekoBox/1.3",
    "v2Box/1.0",
    "FoxRay/2.0",
    "Matsuri/1.6",
    "SagerNet/1.0",
    "Karing/1.0",
];

/// Extra UAs that look VPN-router-ish but MUST be classified as
/// non-VPN (browser-style JSON wrapper). VPNRouter is the canonical
/// case — verified against live ninitux 2026-05-19.
const NON_VPN_LOOKALIKES: &[&str] = &["VPNRouter/2.4.1", "VPNRouter", "VpnRouter/1.0"];

const NON_VPN_UAS: &[Option<&str>] = &[
    Some("Mozilla/5.0 Firefox/138.0"),
    Some("curl/8.5.0"),
    Some("Wget/1.21"),
    None,
];

async fn seed_state(dir: &TempDir) -> AppState {
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    let mut reg = Registry::new();
    reg.register_kernel(Box::new(SingBox::new())).unwrap();
    reg.register_protocol(Box::new(VlessReality::new()))
        .unwrap();
    vpnctld::make_app_state_for_tests(inv, Arc::new(reg)).0
}

/// One server + one granted user with `TEST_DEVICE_ID` pinned — required
/// for rule-5 (load-bearing) + rule-6 (multi-segment hex prefix).
async fn seed_state_with_user(dir: &TempDir) -> AppState {
    let state = seed_state(dir).await;
    let sid = ServerId("vps-de-01".into());
    state
        .inv
        .add_server(&Server {
            id: sid.clone(),
            address: "vps-de-01.example.com".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![ProtocolId("vless+reality".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    state
        .inv
        .set_server_secret(&sid, "vless.public_key", "PUB_de01")
        .await
        .unwrap();
    state
        .inv
        .set_server_secret(&sid, "vless.short_id", "12345678")
        .await
        .unwrap();
    let uid = UserId("tester-1".into());
    state
        .inv
        .add_user(&User {
            id: uid.clone(),
            uuid: "11111111-2222-3333-4444-555555555555".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
        })
        .await
        .unwrap();
    state
        .inv
        .set_vpn_router_device_id(&uid, TEST_DEVICE_ID)
        .await
        .unwrap();
    state.inv.grant(&uid, &sid).await.unwrap();
    state
}

async fn fetch(
    app: Router,
    path: &str,
    ua: Option<&str>,
) -> (StatusCode, Vec<(String, String)>, Vec<u8>) {
    let mut req = Request::builder().uri(path);
    if let Some(u) = ua {
        req = req.header("user-agent", u);
    }
    let resp = app.oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
    let status = resp.status();
    let headers = resp
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_ascii_lowercase(),
                v.to_str().unwrap_or("").to_string(),
            )
        })
        .collect();
    let body = resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, headers, body)
}

fn h<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

// Rule 1: every catchall path returns 200 regardless of UA.
#[tokio::test]
async fn catchall_returns_200_for_every_unmatched_path_regardless_of_ua() {
    let dir = TempDir::new().unwrap();
    let app = router(seed_state(&dir).await);
    let uas: &[Option<&str>] = &[Some("Mozilla/5.0"), None, Some("v2rayN/6.62")];
    for path in CATCHALL_PATHS {
        for ua in uas {
            let (status, _, _) = fetch(app.clone(), path, *ua).await;
            assert_eq!(status, StatusCode::OK, "path={path} ua={ua:?}");
        }
    }
}

// Rule 2: any VPN-client keyword (case-insensitive) → 0-byte text/plain.
#[tokio::test]
async fn catchall_returns_empty_text_plain_body_for_every_vpn_client_keyword() {
    let dir = TempDir::new().unwrap();
    let app = router(seed_state(&dir).await);
    for ua in VPN_CLIENT_UAS {
        for path in CATCHALL_PATHS {
            let (status, headers, body) = fetch(app.clone(), path, Some(ua)).await;
            assert_eq!(status, StatusCode::OK, "ua={ua} path={path}");
            assert!(body.is_empty(), "ua={ua} path={path} body={body:?}");
            assert_eq!(
                h(&headers, "content-type").unwrap_or(""),
                "text/plain; charset=utf-8",
                "ua={ua} path={path}",
            );
        }
    }
}

// Rule 3: any non-VPN UA → canonical JSON wrapper in COMPACT form
// with keys in DECLARED order. Asserted via substring positions, NOT
// parsed-JSON equality (parsing would lose the order signal).
#[tokio::test]
async fn catchall_returns_canonical_compact_ordered_json_for_non_vpn_uas() {
    let dir = TempDir::new().unwrap();
    let app = router(seed_state(&dir).await);
    let keys = [
        "\"status\"",
        "\"app\"",
        "\"version\"",
        "\"update_available\"",
        "\"config\"",
        "\"check_interval\"",
        "\"timestamp\"",
    ];
    for ua in NON_VPN_UAS {
        for path in CATCHALL_PATHS {
            let (status, headers, body) = fetch(app.clone(), path, *ua).await;
            assert_eq!(status, StatusCode::OK, "ua={ua:?} path={path}");
            assert!(
                h(&headers, "content-type")
                    .unwrap_or("")
                    .starts_with("application/json"),
                "ua={ua:?} path={path}",
            );
            let s = std::str::from_utf8(&body).unwrap();
            for needle in [
                r#""status":"device_not_registered""#,
                r#""app":"vpn-router""#,
                r#""version":"2.4.1""#,
                r#""update_available":false"#,
                r#""config":null"#,
                r#""check_interval":3600"#,
                r#""timestamp":"#,
            ] {
                assert!(s.contains(needle), "missing {needle} in {s}");
            }
            let positions: Vec<_> = keys
                .iter()
                .map(|k| s.find(k).unwrap_or_else(|| panic!("missing {k} in {s}")))
                .collect();
            for w in positions.windows(2) {
                assert!(w[0] < w[1], "keys out of order {positions:?}: {s}");
            }
            // Compact form — no whitespace after `:` or `,`.
            assert!(
                !s.contains(": ") && !s.contains(", "),
                "compact expected: {s}"
            );
        }
    }
}

// Rule 4: no admin-realm signal — neither header nor `vpnctl admin`
// substring in the body. Combined: same leak surface, same shape.
#[tokio::test]
async fn catchall_does_not_leak_admin_realm_header_or_body_on_any_route_variant() {
    let dir = TempDir::new().unwrap();
    let app = router(seed_state(&dir).await);
    let uas: &[Option<&str>] = &[Some("Mozilla/5.0"), Some("v2rayN/6.62"), None];
    for path in CATCHALL_PATHS {
        for ua in uas {
            let (status, headers, body) = fetch(app.clone(), path, *ua).await;
            assert_eq!(status, StatusCode::OK, "path={path} ua={ua:?}");
            assert!(
                h(&headers, "www-authenticate").is_none(),
                "WWW-Authenticate leak — path={path} ua={ua:?} headers={headers:?}",
            );
            let s = String::from_utf8_lossy(&body);
            assert!(
                !s.contains("vpnctl admin"),
                "`vpnctl admin` in body — path={path} ua={ua:?} body={s}",
            );
        }
    }
}

// Rule 5 (load-bearing): single-segment `{device_id}` MUST still win
// for a registered 32-hex device. If matchit ever flips priority so
// `{*tail}` shadows `{device_id}`, every registered device silently
// turns into `device_not_registered` — this is the regression net.
#[tokio::test]
async fn single_segment_valid_device_id_route_is_not_shadowed_by_catchall() {
    let dir = TempDir::new().unwrap();
    let app = router(seed_state_with_user(&dir).await);
    let (status, headers, body) = fetch(
        app,
        &format!("/api/v1/app/config/{TEST_DEVICE_ID}"),
        Some("Mozilla/5.0"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        h(&headers, "content-type")
            .unwrap_or("")
            .starts_with("application/json")
    );
    let s = std::str::from_utf8(&body).unwrap();
    assert!(s.contains(r#""status":"ok""#), "expected ok: {s}");
    assert!(
        !s.contains(r#""config":null"#),
        "expected non-null config: {s}"
    );
    // Catchall has no inventory access — a real base64 vless:// blob
    // can ONLY come from the registered handler.
    let needle = r#""config":""#;
    let start = s.find(needle).unwrap() + needle.len();
    let rest = &s[start..];
    let end = rest.find('"').unwrap();
    let decoded = BASE64_STANDARD.decode(&rest[..end]).unwrap();
    assert!(
        std::str::from_utf8(&decoded)
            .unwrap()
            .starts_with("vless://"),
        "blob must start with vless://",
    );
}

// Rule 6: 32-hex prefix + trailing segment MUST land on the wildcard
// catchall — proves multi-segment never bleeds into the named route.
#[tokio::test]
async fn valid_hex_device_id_with_trailing_segment_lands_on_catchall() {
    let dir = TempDir::new().unwrap();
    let app = router(seed_state_with_user(&dir).await);
    let path = format!("/api/v1/app/config/{TEST_DEVICE_ID}/extra");
    let (status, headers, body) = fetch(app, &path, Some("Mozilla/5.0")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        h(&headers, "content-type")
            .unwrap_or("")
            .starts_with("application/json")
    );
    let s = std::str::from_utf8(&body).unwrap();
    assert!(
        s.contains(r#""status":"device_not_registered""#),
        "hit catchall: {s}"
    );
    assert!(s.contains(r#""config":null"#), "null config: {s}");
}

// Review-agent finding #2: percent-encoded slash `%2F` in tail gets
// decoded by `Path<String>` extractor before the `contains('/')`
// gate fires. Confirms multi-segment dispatch covers this case
// rather than the request landing on the device_id-shape gate.
#[tokio::test]
async fn percent_encoded_slash_in_tail_lands_on_catchall() {
    let dir = TempDir::new().unwrap();
    let app = router(seed_state(&dir).await);
    for path in [
        "/api/v1/app/config/foo%2Fbar",
        "/api/v1/app/config/%2F",
        "/api/v1/app/config/abc%2Fdef%2Fghi",
    ] {
        let (status, headers, body) = fetch(app.clone(), path, Some("Mozilla/5.0")).await;
        assert_eq!(status, StatusCode::OK, "path={path}");
        assert!(h(&headers, "www-authenticate").is_none(), "path={path}");
        let s = std::str::from_utf8(&body).unwrap();
        assert!(
            s.contains(r#""status":"device_not_registered""#),
            "path={path} body={s}"
        );
    }
}

// Review-agent finding #6: non-ASCII bytes in the tail must NOT
// leak the admin realm and must return the canonical shape.
#[tokio::test]
async fn non_ascii_tail_does_not_leak_admin_realm() {
    let dir = TempDir::new().unwrap();
    let app = router(seed_state(&dir).await);
    // Cyrillic "тест", URL-encoded.
    let path = "/api/v1/app/config/%D1%82%D0%B5%D1%81%D1%82";
    let (status, headers, body) = fetch(app, path, Some("Mozilla/5.0")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(h(&headers, "www-authenticate").is_none());
    let s = String::from_utf8_lossy(&body);
    assert!(!s.contains("vpnctl admin"), "leaked: {s}");
    assert!(s.contains(r#""status":"device_not_registered""#));
}

// Review-agent finding #6: a registered-but-NOT-PRESENT 32-hex
// device_id (single segment, valid shape, but no row in users)
// must ALSO not leak `WWW-Authenticate`. The bug class isn't tied
// to multi-segment paths only.
#[tokio::test]
async fn unregistered_single_segment_hex_does_not_leak_admin_realm() {
    let dir = TempDir::new().unwrap();
    // Seed WITHOUT users so the device_id is unregistered.
    let app = router(seed_state(&dir).await);
    let path = "/api/v1/app/config/00000000000000000000000000000000";
    for ua in [
        Some("Mozilla/5.0"),
        Some("v2rayN/6.62"),
        Some("VPNRouter"),
        None,
    ] {
        let (status, headers, body) = fetch(app.clone(), path, ua).await;
        assert_eq!(status, StatusCode::OK, "ua={ua:?}");
        assert!(
            h(&headers, "www-authenticate").is_none(),
            "leaked www-authenticate for ua={ua:?}"
        );
        let s = String::from_utf8_lossy(&body);
        assert!(
            !s.contains("vpnctl admin"),
            "leaked body for ua={ua:?}: {s}"
        );
    }
}

// VPN-router-lookalike UAs (e.g. `VPNRouter/2.4.1`) MUST be classified
// as non-VPN-client and receive the JSON wrapper, NOT the raw base64.
// Pinned because the live `VPNRouter` UA arrives in production
// (visible in nginx access logs) and ninitux returns JSON for it.
#[tokio::test]
async fn lookalike_uas_get_json_wrapper_not_raw() {
    let dir = TempDir::new().unwrap();
    let app = router(seed_state(&dir).await);
    for ua in NON_VPN_LOOKALIKES {
        for path in CATCHALL_PATHS {
            let (status, headers, body) = fetch(app.clone(), path, Some(ua)).await;
            assert_eq!(status, StatusCode::OK, "ua={ua} path={path}");
            assert!(
                h(&headers, "content-type")
                    .unwrap_or("")
                    .starts_with("application/json"),
                "ua={ua} path={path} headers={headers:?}",
            );
            let s = std::str::from_utf8(&body).unwrap();
            assert!(
                s.contains(r#""status":"device_not_registered""#),
                "ua={ua} path={path} body={s}",
            );
        }
    }
}

// Rule 7: Content-Length matches body for BOTH UA classes (155 JSON / 0
// raw), and two requests with the same UA + path differ ONLY in the
// `timestamp` field.
#[tokio::test]
async fn catchall_content_length_matches_body_and_is_deterministic_modulo_timestamp() {
    let dir = TempDir::new().unwrap();
    let app = router(seed_state(&dir).await);

    // JSON: exactly 155 bytes (10-digit unix ts; holds through 2286).
    let (_, headers, b1) = fetch(app.clone(), "/api/v1/app/config/foo", Some("Mozilla/5.0")).await;
    assert_eq!(
        b1.len(),
        155,
        "got {}: {}",
        b1.len(),
        String::from_utf8_lossy(&b1)
    );
    let cl: usize = h(&headers, "content-length").unwrap().parse().unwrap();
    assert_eq!(cl, b1.len());

    let (_, _, b2) = fetch(app.clone(), "/api/v1/app/config/foo", Some("Mozilla/5.0")).await;
    let strip_ts = |b: &[u8]| -> String {
        let s = std::str::from_utf8(b).unwrap();
        let n = r#""timestamp":"#;
        let start = s.find(n).unwrap() + n.len();
        let rest = &s[start..];
        let end = rest.find('}').unwrap();
        format!("{}<TS>{}", &s[..start], &rest[end..])
    };
    assert_eq!(strip_ts(&b1), strip_ts(&b2), "non-timestamp drift");

    // Raw path: 0 bytes.
    let (_, headers, body) = fetch(app, "/api/v1/app/config/foo", Some("v2rayN/6.62")).await;
    assert_eq!(body.len(), 0);
    let cl: usize = h(&headers, "content-length").unwrap().parse().unwrap();
    assert_eq!(cl, 0);
}
