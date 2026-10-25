use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
use vpnctld::router;

use crate::common::*;

#[tokio::test]
async fn admin_user_detail_wireguard_section_shows_pubkey_and_rotate_button() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    let app = router(s);
    let resp = app
        .clone()
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("id=carol"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let pk = inv
        .get_user(&UserId("carol".into()))
        .await
        .unwrap()
        .unwrap()
        .wireguard_pubkey
        .unwrap();

    let html = fetch_html(app, "/admin/users/carol/delivery").await;
    assert!(html.contains("WireGuard keypair"), "section heading");
    assert!(
        html.contains(pk.as_str()),
        "pubkey must render verbatim — operator wants to see what's deployed"
    );
    assert!(
        html.contains("/admin/users/carol/wireguard/regenerate"),
        "rotate-keypair form must POST to the regenerate route"
    );
    let keypair = html.split_once("WireGuard keypair</div>").unwrap().1;
    let private = keypair
        .split_once(">private </span>")
        .unwrap()
        .1
        .split_once("</div>")
        .unwrap()
        .0;
    assert!(
        private.contains(r#"<use href="/admin/assets/icons.svg#check""#),
        "private-key marker must carry its own check icon"
    );
    assert_eq!(
        private.split_once("</svg>").unwrap().1,
        "stored — served via /sub/&lt;token&gt; only</span>",
        "private must be marker-only, never the value itself"
    );
    let priv_ = inv
        .get_user(&UserId("carol".into()))
        .await
        .unwrap()
        .unwrap()
        .wireguard_private
        .unwrap();
    assert!(
        !html.contains(priv_.as_str()),
        "PRIVATE LEAK: detail HTML contains the raw private bytes"
    );
    assert!(
        html.contains("Flow A — Hiddify / Sing-box"),
        "user-detail must teach the sing-box/Hiddify recipient flow"
    );
    assert!(
        html.contains("Flow B — official WireGuard app / Hiddify"),
        "Flow B label must NOT claim AmneziaVPN — that's Flow C now"
    );
    assert!(
        html.contains("Flow C — AmneziaVPN"),
        "user-detail must teach the AmneziaVPN-native recipient flow"
    );
    assert!(
        html.contains("No servers granted to this user yet"),
        "case A empty-state (no grants) copy missing"
    );
    assert!(
        !html.contains("scans the QR in the"),
        "Flow A must not reference 'above' anymore — it has its own QR"
    );
    assert!(
        html.contains("Recommended default — one URL covers everything"),
        "Flow A footnote (Recommended default) missing — copy regressed"
    );
}

#[tokio::test]
async fn admin_user_detail_wireguard_flow_b_empty_state_case_b_grants_no_wg() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    let app = router(s);

    inv.add_server(&Server {
        id: ServerId("nowg".into()),
        address: "203.0.113.7".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![
            ProtocolId("vless+reality".into()),
            ProtocolId("tuic-v5".into()),
        ],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();

    app.clone()
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("id=brat"))
            .unwrap(),
        )
        .await
        .unwrap();
    inv.grant(&UserId("brat".into()), &ServerId("nowg".into()))
        .await
        .unwrap();

    let html = fetch_html(app, "/admin/users/brat/delivery").await;
    assert!(
        !html.contains("No servers granted to this user yet"),
        "case A wording leaked into case B — user IS granted but to a non-WG server"
    );
    assert!(
        html.contains("Keys exist, but no granted server runs WireGuard"),
        "case B headline missing — operator won't understand why no QR"
    );
    assert!(
        html.contains("nowg"),
        "case B body must name the actually-granted servers"
    );
    assert!(
        html.contains("Settings page"),
        "case B must point at the server's Settings page when inventory has zero WG-capable nodes"
    );
    assert!(
        !html.contains("vpnctl server add"),
        "case B must not instruct a CLI command"
    );
}

#[tokio::test]
async fn admin_user_detail_wireguard_flow_b_namedrops_other_wg_servers() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    let app = router(s);

    inv.add_server(&Server {
        id: ServerId("nowg".into()),
        address: "203.0.113.7".into(),
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
    inv.add_server(&Server {
        id: ServerId("wg-de-01".into()),
        address: "198.51.100.5".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("amneziawg".into())],
        enabled_protocols: vec![ProtocolId("wireguard".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();
    app.clone()
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("id=brat"))
            .unwrap(),
        )
        .await
        .unwrap();
    inv.grant(&UserId("brat".into()), &ServerId("nowg".into()))
        .await
        .unwrap();

    let html = fetch_html(app, "/admin/users/brat/delivery").await;
    assert!(
        html.contains("WG-capable servers in the inventory you could grant"),
        "suggestion line missing"
    );
    assert!(
        html.contains("wg-de-01"),
        "the WG-capable server id must be name-dropped: {html:.300}"
    );
}

#[tokio::test]
async fn admin_user_regen_wireguard_rotates_pair_and_audits() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    let app = router(s);
    app.clone()
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("id=dave"))
            .unwrap(),
        )
        .await
        .unwrap();
    inv.add_server(&Server {
        id: ServerId("wg-regen-node".into()),
        address: "203.0.113.41".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![],
        enabled_protocols: vec![],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();
    inv.grant(&UserId("dave".into()), &ServerId("wg-regen-node".into()))
        .await
        .unwrap();
    inv.audit("admin", "server.deploy", Some("wg-regen-node"), None)
        .await
        .unwrap();
    let before = inv.get_user(&UserId("dave".into())).await.unwrap().unwrap();

    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users/dave/wireguard/regenerate"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let after = inv.get_user(&UserId("dave".into())).await.unwrap().unwrap();
    assert_ne!(
        before.wireguard_pubkey, after.wireguard_pubkey,
        "pubkey must change on rotate"
    );
    assert_ne!(
        before.wireguard_private, after.wireguard_private,
        "private must change on rotate"
    );
    let audit = inv.recent_audit(5).await.unwrap();
    let row = audit
        .iter()
        .find(|a| a.action == "user.wireguard.regen")
        .expect("audit row for wireguard.regen");
    let payload = row
        .payload
        .as_ref()
        .map(|v| v.to_string())
        .unwrap_or_default();
    assert!(payload.contains("server-generated"));
    assert!(payload.contains(after.wireguard_pubkey.as_deref().unwrap()));
    let rows = wait_for_autodeploy_rows(&inv, 1).await;
    assert!(rows.iter().any(|row| {
        row.target.as_deref() == Some("dave")
            && row
                .payload
                .as_ref()
                .and_then(|p| p.get("trigger"))
                .and_then(|v| v.as_str())
                == Some("user.wireguard.regen")
    }));
    assert_eq!(
        inv.servers_pending_deploy_for_user(
            &UserId("dave".into()),
            &[ServerId("wg-regen-node".into())],
        )
        .await
        .unwrap(),
        vec![ServerId("wg-regen-node".into())],
        "failed auto-deploy must leave the regenerated key pending",
    );
}

async fn wireguard_download_state(dir: &TempDir, kernel: &str) -> vpnctld::AppState {
    let s = state(dir).await;
    let inv = s.inv.clone();
    inv.add_server(&Server {
        id: ServerId("dlsrv".into()),
        address: "203.0.113.11".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId(kernel.into())],
        enabled_protocols: vec![ProtocolId("wireguard".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();
    inv.set_server_secret(
        &ServerId("dlsrv".into()),
        "wireguard.server_public_key",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    )
    .await
    .unwrap();
    inv.set_server_secret(
        &ServerId("dlsrv".into()),
        "wireguard.server_private_key",
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
    )
    .await
    .unwrap();
    inv.add_user(&User {
        id: UserId("dltest".into()),
        uuid: "55555555-5555-5555-5555-555555555555".into(),
        tuic_password: Some("tp".into()),
        wireguard_pubkey: Some("qXFvJL5KLmM3Of9hVo5GmJ4n0LB9rWYfV4ZE1XGZJks=".into()),
        wireguard_private: Some("0000000000000000000000000000000000000000000=".into()),
        sub_token: Some("st-dltest".into()),
        vpn_router_device_id: None,
        disabled: false,
    })
    .await
    .unwrap();
    inv.grant(&UserId("dltest".into()), &ServerId("dlsrv".into()))
        .await
        .unwrap();

    s
}

#[tokio::test]
async fn admin_user_wireguard_conf_download_serves_attachment() {
    let dir = TempDir::new().unwrap();
    let s = wireguard_download_state(&dir, "sing-box").await;
    let app = router(s);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/users/dltest/wireguard/conf/dlsrv")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let cd = resp
        .headers()
        .get("content-disposition")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        cd.contains("attachment") && cd.contains("dltest-dlsrv.conf"),
        "Content-Disposition must declare attachment with the <user>-<server>.conf filename, got {cd:?}"
    );
    let cc = resp
        .headers()
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(
        cc, "no-store",
        "Cache-Control must be no-store for wireguard conf download, got {cc:?}"
    );
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.starts_with("text/plain"),
        "Content-Type should be text/plain for .conf, got {ct:?}"
    );
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = std::str::from_utf8(&body).unwrap();
    assert_eq!(text.as_bytes(), WIREGUARD_DOWNLOAD_BYTES.as_bytes());
    assert!(
        text.contains("[Interface]"),
        ".conf must contain [Interface]"
    );
    assert!(text.contains("[Peer]"), ".conf must contain [Peer]");
    assert!(
        text.contains("Endpoint = 203.0.113.11:51820"),
        ".conf must reference the right server endpoint"
    );
    assert!(
        text.contains("PrivateKey = 0000000000000000000000000000000000000000000="),
        ".conf must inline the user's private key (server-generated default)"
    );
}

#[tokio::test]
async fn admin_user_wireguard_conf_download_refuses_disabled_user() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    inv.add_server(&Server {
        id: ServerId("dlsrv".into()),
        address: "203.0.113.11".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("wireguard".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();
    inv.set_server_secret(
        &ServerId("dlsrv".into()),
        "wireguard.server_public_key",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    )
    .await
    .unwrap();
    inv.set_server_secret(
        &ServerId("dlsrv".into()),
        "wireguard.server_private_key",
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
    )
    .await
    .unwrap();
    inv.add_user(&User {
        id: UserId("dltest".into()),
        uuid: "55555555-5555-5555-5555-555555555555".into(),
        tuic_password: Some("tp".into()),
        wireguard_pubkey: Some("qXFvJL5KLmM3Of9hVo5GmJ4n0LB9rWYfV4ZE1XGZJks=".into()),
        wireguard_private: Some("0000000000000000000000000000000000000000000=".into()),
        sub_token: Some("st-dltest".into()),
        vpn_router_device_id: None,
        disabled: false,
    })
    .await
    .unwrap();
    inv.grant(&UserId("dltest".into()), &ServerId("dlsrv".into()))
        .await
        .unwrap();

    inv.set_user_disabled(&UserId("dltest".into()), true)
        .await
        .unwrap();

    let app = router(s);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/users/dltest/wireguard/conf/dlsrv")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8_lossy(&body);
    assert!(text.starts_with("vpnctl admin: "), "got {text:?}");
    assert!(text.contains("disabled"), "got {text:?}");
}

#[tokio::test]
async fn admin_user_wireguard_conf_download_404_on_unknown_user() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/users/nope/wireguard/conf/whatever")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn admin_user_wireguard_conf_download_404_on_unknown_server_when_user_exists() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_user(&User {
            id: UserId("u".into()),
            uuid: "00000000-0000-0000-0000-000000000000".into(),
            tuic_password: None,
            wireguard_pubkey: Some("qXFvJL5KLmM3Of9hVo5GmJ4n0LB9rWYfV4ZE1XGZJks=".into()),
            wireguard_private: Some("0000000000000000000000000000000000000000000=".into()),
            sub_token: Some("st".into()),
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    let app = router(s);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/users/u/wireguard/conf/nosuch")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(
        text.contains("no such server 'nosuch'"),
        "expected canonical 'no such server' body, got {text:?}"
    );
}

#[tokio::test]
async fn admin_user_wireguard_conf_download_refuses_when_user_not_granted_server() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    inv.add_server(&Server {
        id: ServerId("ungranted-srv".into()),
        address: "203.0.113.200".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("wireguard".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();
    inv.set_server_secret(
        &ServerId("ungranted-srv".into()),
        "wireguard.server_public_key",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    )
    .await
    .unwrap();
    inv.add_user(&User {
        id: UserId("ungranted-user".into()),
        uuid: "88888888-8888-8888-8888-888888888888".into(),
        tuic_password: None,
        wireguard_pubkey: Some("qXFvJL5KLmM3Of9hVo5GmJ4n0LB9rWYfV4ZE1XGZJks=".into()),
        wireguard_private: Some("0000000000000000000000000000000000000000000=".into()),
        sub_token: Some("st".into()),
        vpn_router_device_id: None,
        disabled: false,
    })
    .await
    .unwrap();

    let app = router(s);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/users/ungranted-user/wireguard/conf/ungranted-srv")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "ungranted (user, server) pair must 404, not serve the .conf"
    );
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(
        text.contains("not granted on server"),
        "expected canonical 'not granted' body, got {text:?}"
    );
}

#[tokio::test]
async fn admin_user_wg_conf_peer_octet_differs_per_user_index() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    inv.add_server(&Server {
        id: ServerId("multi".into()),
        address: "203.0.113.150".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("wireguard".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();
    inv.set_server_secret(
        &ServerId("multi".into()),
        "wireguard.server_public_key",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    )
    .await
    .unwrap();
    for (uid, uuid, pubk) in [
        (
            "alex",
            "11111111-1111-1111-1111-111111111111",
            "qXFvJL5KLmM3Of9hVo5GmJ4n0LB9rWYfV4ZE1XGZJks=",
        ),
        (
            "bob",
            "22222222-2222-2222-2222-222222222222",
            "AbcDefGhIjKlMnOpQrStUvWxYz0123456789AbCdEf=",
        ),
    ] {
        inv.add_user(&User {
            id: UserId(uid.into()),
            uuid: uuid.into(),
            tuic_password: None,
            wireguard_pubkey: Some(pubk.into()),
            wireguard_private: Some("0000000000000000000000000000000000000000000=".into()),
            sub_token: Some(format!("st-{uid}")),
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
        inv.grant(&UserId(uid.into()), &ServerId("multi".into()))
            .await
            .unwrap();
    }

    let app = router(s);
    let alex_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/users/alex/wireguard/conf/multi")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bob_resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/users/bob/wireguard/conf/multi")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(alex_resp.status(), StatusCode::OK);
    assert_eq!(bob_resp.status(), StatusCode::OK);
    let alex_conf = std::str::from_utf8(&alex_resp.into_body().collect().await.unwrap().to_bytes())
        .unwrap()
        .to_string();
    let bob_conf = std::str::from_utf8(&bob_resp.into_body().collect().await.unwrap().to_bytes())
        .unwrap()
        .to_string();
    assert!(
        alex_conf.contains("Address = 10.66.0.2/32"),
        "alex (index 0) must claim 10.66.0.2; got: {alex_conf}"
    );
    assert!(
        bob_conf.contains("Address = 10.66.0.3/32"),
        "bob (index 1) must claim 10.66.0.3 (NOT 10.66.0.2 — that's the regression); got: {bob_conf}"
    );
}

#[tokio::test]
async fn admin_user_wireguard_conf_download_400_when_server_lacks_wg_protocol() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    inv.add_server(&Server {
        id: ServerId("nowg2".into()),
        address: "203.0.113.99".into(),
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
    inv.add_user(&User {
        id: UserId("u1".into()),
        uuid: "66666666-6666-6666-6666-666666666666".into(),
        tuic_password: Some("tp".into()),
        wireguard_pubkey: Some("qXFvJL5KLmM3Of9hVo5GmJ4n0LB9rWYfV4ZE1XGZJks=".into()),
        wireguard_private: Some("0000000000000000000000000000000000000000000=".into()),
        sub_token: Some("st-u1".into()),
        vpn_router_device_id: None,
        disabled: false,
    })
    .await
    .unwrap();
    let app = router(s);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/users/u1/wireguard/conf/nowg2")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(
        text.contains("does not enable the 'wireguard' protocol"),
        "expected the canonical 'wireguard protocol not enabled' message, got {text:?}"
    );
}

#[tokio::test]
async fn admin_destructive_user_actions_ask_for_confirmation() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    s.inv
        .add_user(&User {
            id: UserId("keyed".into()),
            uuid: "66666666-6666-6666-6666-666666666666".into(),
            tuic_password: Some("tp".into()),
            wireguard_pubkey: Some("qXFvJL5KLmM3Of9hVo5GmJ4n0LB9rWYfV4ZE1XGZJks=".into()),
            wireguard_private: Some("0000000000000000000000000000000000000000000=".into()),
            sub_token: Some("st-keyed".into()),
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    let app = router(s);
    let overview = fetch_html(app.clone(), "/admin/users/u0/overview").await;
    let delivery = fetch_html(app.clone(), "/admin/users/keyed/delivery").await;
    let first_key = fetch_html(app.clone(), "/admin/users/u0/delivery").await;
    let access = fetch_html(app, "/admin/users/u0/access").await;
    let at = first_key.find("/wireguard/regenerate\"").unwrap();
    let head = &first_key[first_key[..at].rfind("<form").unwrap()..at + 200];
    assert!(
        !head.contains("data-confirm="),
        "minting the first key breaks nothing and must not ask"
    );
    for (page, action) in [
        (&overview, "/sub-token/regenerate\""),
        (&delivery, "/wireguard/regenerate\""),
        (&access, "/revoke\""),
    ] {
        let at = page
            .find(action)
            .unwrap_or_else(|| panic!("{action} form missing"));
        let form_start = page[..at].rfind("<form").unwrap();
        let form_head = &page[form_start..at + 400.min(page.len() - at)];
        assert!(
            form_head.contains("data-confirm="),
            "{action} must ask for confirmation"
        );
    }
}

const WIREGUARD_DOWNLOAD_BYTES: &str = concat!(
    "# vpnctl-rendered AmneziaWG client config.\n",
    "# Private key was server-generated for dltest — import this file as-is.\n\n",
    "[Interface]\n",
    "PrivateKey = 0000000000000000000000000000000000000000000=\n",
    "Address = 10.66.0.2/32\n",
    "DNS = 1.1.1.1\n\n",
    "[Peer]\n",
    "PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
    "Endpoint = 203.0.113.11:51820\n",
    "AllowedIPs = 0.0.0.0/0, ::/0\n",
    "PersistentKeepalive = 25\n",
);

#[tokio::test]
async fn admin_wireguard_download_visibility_refusal_and_restore_byte_equal() {
    for kernel in ["sing-box", "amneziawg"] {
        for gate in [
            "hidden",
            "override",
            "suppressed",
            "detour",
            "detour-granted",
        ] {
            let dir = TempDir::new().unwrap();
            let s = wireguard_download_state(&dir, kernel).await;
            let sid = ServerId("dlsrv".into());
            let uid = UserId("dltest".into());
            let pid = ProtocolId("wireguard".into());
            let app = router(s.clone());
            match gate {
                "hidden" => s
                    .inv
                    .set_server_protocol_hidden(&sid, &pid, true)
                    .await
                    .unwrap(),
                "override" => s
                    .inv
                    .set_grant_protocol_override(&uid, &sid, &pid, true)
                    .await
                    .unwrap(),
                "suppressed" => {
                    s.inv.set_server_auto_suppress(&sid, true).await.unwrap();
                    s.inv.set_server_suppressed(&sid, true).await.unwrap();
                }
                "detour" | "detour-granted" => {
                    let mut entry = s.inv.get_server(&sid).await.unwrap().unwrap();
                    entry.id = ServerId("entry".into());
                    s.inv.add_server(&entry).await.unwrap();
                    if gate == "detour-granted" {
                        s.inv.grant(&uid, &entry.id).await.unwrap();
                    }
                    s.inv
                        .set_client_detour_via_as("test", &sid, Some(&entry.id))
                        .await
                        .unwrap();
                }
                _ => unreachable!(),
            }
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/admin/users/dltest/wireguard/conf/dlsrv")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{gate}");
            assert!(response.headers().get("content-disposition").is_none());
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let expected = concat!(
                "vpnctl admin: This WireGuard download is unavailable because the subscription ",
                "does not offer this server as a direct configuration. Review user access and ",
                "the server's visibility, availability, and routing settings in the admin UI.\n",
            );
            assert_eq!(body.as_ref(), expected.as_bytes(), "{gate}");
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/sub/st-dltest")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let config: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert!(
                config["outbounds"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|outbound| {
                        outbound["tag"] != "DLSRV WireGuard ~dltest"
                            || outbound["detour"].is_string()
                    })
            );
            match gate {
                "hidden" => s
                    .inv
                    .set_server_protocol_hidden(&sid, &pid, false)
                    .await
                    .unwrap(),
                "override" => s
                    .inv
                    .set_grant_protocol_override(&uid, &sid, &pid, false)
                    .await
                    .unwrap(),
                "suppressed" => {
                    s.inv.set_server_suppressed(&sid, false).await.unwrap();
                }
                "detour" | "detour-granted" => s
                    .inv
                    .set_client_detour_via_as("test", &sid, None)
                    .await
                    .unwrap(),
                _ => unreachable!(),
            }
            let response = app
                .oneshot(
                    Request::builder()
                        .uri("/admin/users/dltest/wireguard/conf/dlsrv")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{gate}");
            let body = response.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(body.as_ref(), WIREGUARD_DOWNLOAD_BYTES.as_bytes(), "{gate}");
        }
    }
}
