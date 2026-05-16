//! Spec-driven security tests for the `vpnctld` HTTP surface. INDEPENDENT
//! of the daemon impl: encodes the public contract. Mirrors `sub_endpoint.rs`'s
//! oneshot+shim-router pattern (handlers are `pub(crate)`). If a test fails,
//! the implementation is wrong — do not weaken the test.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{KernelId, ProtocolId, Registry, Server, ServerId, User, UserId};
use vpnctl_inventory::SqliteInventory;
use vpnctl_kernels::SingBox;
use vpnctl_protocols::{TuicV5, VlessReality};

const SECRET_FP: &str = "sha256:DEADBEEFCAFEBABE0123456789ABCDEF";

#[derive(Clone)]
struct AppState {
    inv: SqliteInventory,
    registry: Arc<Registry>,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState").finish_non_exhaustive()
    }
}

// Shape per spec: health JSON; sub → 404/500 plaintext or 200 sing-box JSON
// with selector→servers→direct→block + route + log.
fn router(state: AppState) -> axum::Router {
    use axum::extract::{Path, State};
    use axum::http::StatusCode as Sc;
    use axum::response::IntoResponse;
    use axum::routing::get;
    use vpnctl_core::RenderCtx;

    async fn health() -> impl IntoResponse {
        let body = json!({"status":"ok","version":env!("CARGO_PKG_VERSION")}).to_string();
        (Sc::OK, [("content-type", "application/json")], body)
    }
    fn plain(c: Sc, m: &'static str) -> axum::response::Response {
        (c, [("content-type", "text/plain; charset=utf-8")], m).into_response()
    }
    async fn sub(State(s): State<AppState>, Path(token): Path<String>) -> axum::response::Response {
        let user = match s.inv.find_user_by_sub_token(&token).await {
            Ok(Some(u)) => u,
            Ok(None) => return plain(Sc::NOT_FOUND, "not found\n"),
            Err(_) => return plain(Sc::INTERNAL_SERVER_ERROR, "internal error\n"),
        };
        let servers = match s.inv.servers_for_user(&user.id).await {
            Ok(v) => v,
            Err(_) => return plain(Sc::INTERNAL_SERVER_ERROR, "internal error\n"),
        };
        let (mut srv_outs, mut tags): (Vec<Value>, Vec<String>) = (vec![], vec![]);
        for srv in &servers {
            let Ok(secrets) = s.inv.list_server_secrets(&srv.id).await else {
                continue;
            };
            let ctx = RenderCtx::new(srv, &secrets);
            for pid in &srv.enabled_protocols {
                let Some(p) = s.registry.protocol(pid) else {
                    continue;
                };
                let Ok(mut v) = p.client_config(&ctx, &user) else {
                    continue;
                };
                let tag = format!("{}-{}", srv.id.0, pid.0);
                if let Some(o) = v.as_object_mut() {
                    o.insert("tag".into(), Value::String(tag.clone()));
                }
                srv_outs.push(v);
                tags.push(tag);
            }
        }
        let mut outs: Vec<Value> = vec![];
        if !tags.is_empty() {
            outs.push(json!({"type":"selector","tag":"proxy",
                "outbounds": tags, "default": tags.first().cloned()}));
        }
        outs.extend(srv_outs);
        outs.push(json!({"type":"direct","tag":"direct"}));
        outs.push(json!({"type":"block","tag":"block"}));
        let body = json!({"log": {"level":"info"}, "outbounds": outs,
            "route": {"final": if tags.is_empty() {"direct"} else {"proxy"},
                "auto_detect_interface": true}});
        (
            Sc::OK,
            [("content-type", "application/json")],
            body.to_string(),
        )
            .into_response()
    }
    axum::Router::new()
        .route("/api/v1/health", get(health))
        .route("/sub/{token}", get(sub))
        .with_state(state)
}

fn mk_server(id: &str, addr: &str, fp: Option<&str>, protos: &[&str]) -> Server {
    Server {
        id: ServerId(id.into()),
        address: addr.into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: protos.iter().map(|p| ProtocolId((*p).into())).collect(),
        trusted_host_fingerprint: fp.map(String::from),
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}
fn mk_user(id: &str, uuid: &str, pw: Option<&str>) -> User {
    User {
        id: UserId(id.into()),
        uuid: uuid.into(),
        tuic_password: pw.map(String::from),
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
    }
}
async fn open_inv(dir: &TempDir) -> SqliteInventory {
    SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap()
}
fn full_registry() -> Arc<Registry> {
    let mut r = Registry::new();
    r.register_kernel(Box::new(SingBox::new())).unwrap();
    r.register_protocol(Box::new(VlessReality::new())).unwrap();
    r.register_protocol(Box::new(TuicV5::new())).unwrap();
    Arc::new(r)
}
async fn token_for(inv: &SqliteInventory, id: &UserId) -> String {
    inv.get_user(id).await.unwrap().unwrap().sub_token.unwrap()
}

// Happy-path seed: 1 server (vless+tuic, fp set), 1 user granted.
async fn seed_full(dir: &TempDir) -> (SqliteInventory, Arc<Registry>, String) {
    let inv = open_inv(dir).await;
    let srv = mk_server(
        "srv",
        "10.0.0.1",
        Some(SECRET_FP),
        &["vless+reality", "tuic-v5"],
    );
    inv.add_server(&srv).await.unwrap();
    inv.set_server_secret(&srv.id, "vless.public_key", "PUB_TEST")
        .await
        .unwrap();
    inv.set_server_secret(&srv.id, "vless.short_id", "12345678")
        .await
        .unwrap();
    inv.set_server_secret(&srv.id, "vless.private_key", "PRIV_REALITY_SECRET")
        .await
        .unwrap();
    let user = mk_user("alice", "uuid-alice-2026", Some("tuic-pw-alice"));
    inv.add_user(&user).await.unwrap();
    inv.grant(&user.id, &srv.id).await.unwrap();
    let token = token_for(&inv, &user.id).await;
    (inv, full_registry(), token)
}

fn body_string(b: &[u8]) -> String {
    b.iter().copied().map(char::from).collect()
}

async fn get(app: axum::Router, uri: &str) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let resp = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, headers, body)
}

fn ct(h: &axum::http::HeaderMap) -> String {
    h.get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

// ── tests ───────────────────────────────────────────────────────────────

async fn full_app() -> (axum::Router, String, TempDir) {
    let dir = TempDir::new().unwrap();
    let (inv, registry, token) = seed_full(&dir).await;
    (router(AppState { inv, registry }), token, dir)
}

#[tokio::test]
async fn t1_health_returns_ok_status_with_json_content_type() {
    let (app, _, _d) = full_app().await;
    let (status, headers, body) = get(app, "/api/v1/health").await;
    assert_eq!(status, StatusCode::OK);
    let c = ct(&headers);
    assert!(
        c.starts_with("application/json"),
        "expected json, got {c:?}"
    );
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["status"], "ok");
    assert!(v["version"].is_string(), "version must be a string");
}

#[tokio::test]
async fn t2_unknown_token_returns_404_plaintext_without_echoing_token() {
    let (app, _, _d) = full_app().await;
    let probe = "ENUM-PROBE-TOKEN-DEADBEEF";
    let (status, headers, body) = get(app, &format!("/sub/{probe}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let c = ct(&headers);
    assert!(
        !c.starts_with("application/json"),
        "404 must NOT be JSON (got {c:?}); JSON encourages enumeration tooling"
    );
    let s = body_string(&body);
    assert!(
        !s.contains(probe),
        "404 body MUST NOT echo probed token (anti-enumeration); body={s:?}"
    );
}

#[tokio::test]
async fn t3_response_does_not_leak_sub_token() {
    let (app, token, _d) = full_app().await;
    let (status, _h, body) = get(app, &format!("/sub/{token}")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !body_string(&body).contains(&token),
        "rendered config MUST NOT contain the user's sub_token"
    );
}

#[tokio::test]
async fn t4_response_does_not_leak_reality_private_key() {
    let (app, token, _d) = full_app().await;
    let (status, _h, body) = get(app, &format!("/sub/{token}")).await;
    assert_eq!(status, StatusCode::OK);
    let raw = body_string(&body);
    assert!(
        !raw.contains("private_key"),
        "client config MUST NOT mention 'private_key' (REALITY privkey is server-side)"
    );
    assert!(
        !raw.contains("PRIV_REALITY_SECRET"),
        "REALITY private_key value leaked into client config"
    );
}

#[tokio::test]
async fn t5_response_does_not_leak_trusted_host_fingerprint() {
    let (app, token, _d) = full_app().await;
    let (status, _h, body) = get(app, &format!("/sub/{token}")).await;
    assert_eq!(status, StatusCode::OK);
    let raw = body_string(&body);
    assert!(
        !raw.contains(SECRET_FP),
        "trusted_host_fingerprint leaked into client config: body={raw}"
    );
}

#[tokio::test]
async fn t6_response_has_selector_proxy_with_all_tags_plus_direct_and_block() {
    let (app, token, _d) = full_app().await;
    let (status, _h, body) = get(app, &format!("/sub/{token}")).await;
    assert_eq!(status, StatusCode::OK);
    let v: Value = serde_json::from_slice(&body).unwrap();
    let outs = v["outbounds"].as_array().expect("outbounds must be array");
    let first = outs.first().expect("at least the selector");
    assert_eq!(first["type"], "selector", "first outbound is selector");
    assert_eq!(first["tag"], "proxy", "selector tag must be 'proxy'");
    let sel: Vec<String> = first["outbounds"]
        .as_array()
        .expect("selector.outbounds is array")
        .iter()
        .map(|t| t.as_str().unwrap_or("").to_string())
        .collect();
    assert!(
        sel.iter().any(|t| t == "srv-vless+reality"),
        "selector must list vless tag, got {sel:?}"
    );
    assert!(
        sel.iter().any(|t| t == "srv-tuic-v5"),
        "selector must list tuic tag, got {sel:?}"
    );
    let n = outs.len();
    assert!(n >= 2, "need at least direct+block");
    assert_eq!(outs[n - 2]["type"], "direct", "second-to-last is direct");
    assert_eq!(outs[n - 1]["type"], "block", "last is block");
    assert!(v["route"].is_object(), "route object missing");
    assert!(v["route"].get("final").is_some(), "route.final missing");
    assert!(
        v["route"].get("auto_detect_interface").is_some(),
        "route.auto_detect_interface missing"
    );
    assert!(v["log"].is_object(), "log object missing");
}

#[tokio::test]
async fn t7_unknown_protocol_in_grants_is_skipped_not_crashed() {
    let dir = TempDir::new().unwrap();
    let inv = open_inv(&dir).await;
    // Registry with ONLY tuic-v5; vless+reality intentionally absent.
    let mut reg = Registry::new();
    reg.register_kernel(Box::new(SingBox::new())).unwrap();
    reg.register_protocol(Box::new(TuicV5::new())).unwrap();
    let srv = mk_server("srv", "10.0.0.2", None, &["vless+reality", "tuic-v5"]);
    inv.add_server(&srv).await.unwrap();
    let user = mk_user("bob", "uuid-bob", Some("pw-bob"));
    inv.add_user(&user).await.unwrap();
    inv.grant(&user.id, &srv.id).await.unwrap();
    let token = token_for(&inv, &user.id).await;
    let (status, _h, body) = get(
        router(AppState {
            inv,
            registry: Arc::new(reg),
        }),
        &format!("/sub/{token}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "must not crash on unknown protocol");
    let v: Value = serde_json::from_slice(&body).unwrap();
    let tags: Vec<&str> = v["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|o| o.get("tag").and_then(Value::as_str))
        .collect();
    assert!(
        tags.contains(&"srv-tuic-v5"),
        "tuic outbound must still be present, got {tags:?}"
    );
    assert!(
        !tags.contains(&"srv-vless+reality"),
        "vless outbound must be skipped (no impl in registry), got {tags:?}"
    );
}

#[tokio::test]
async fn t8_user_with_no_grants_yields_only_direct_and_block_no_selector() {
    let dir = TempDir::new().unwrap();
    let inv = open_inv(&dir).await;
    let user = mk_user("solo", "uuid-solo", Some("pw"));
    inv.add_user(&user).await.unwrap();
    let token = token_for(&inv, &user.id).await;
    let (status, _h, body) = get(
        router(AppState {
            inv,
            registry: full_registry(),
        }),
        &format!("/sub/{token}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let v: Value = serde_json::from_slice(&body).unwrap();
    let outs = v["outbounds"].as_array().unwrap();
    assert_eq!(outs.len(), 2, "expected only direct+block, got {outs:?}");
    assert_eq!(outs[0]["type"], "direct");
    assert_eq!(outs[1]["type"], "block");
    assert!(
        !outs.iter().any(|o| o["type"] == "selector"),
        "no selector when nothing to select between"
    );
}
