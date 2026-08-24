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
    // Create via the new auto-gen path.
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

    // Detail page must show that pubkey verbatim + a rotate form.
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
    // Private value MUST NOT leak into the HTML — only the marker.
    // maud escapes `<` → `&lt;` in attribute-free text, so check
    // the unambiguous substring before the escape.
    assert!(
        html.contains("✓ stored — served via /sub/"),
        "private must be marker-only ('✓ stored'), never the value itself"
    );
    // Hard assertion: actual private bytes are NEVER in the HTML.
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
    // Distribution-panel guidance for THREE client personas.
    // Pavel's \"Flow A / Flow B / Flow C\" pattern: ALWAYS show all
    // three labels even when no WG-enabled server is granted, so the
    // operator knows every option exists + sees why B/C are empty.
    // 2026-05-17: Flow B + Flow C split — pre-split Flow B claimed
    // to cover both AmneziaVPN and the WG app, but AmneziaVPN rejects
    // `wireguard://?conf=` with ErrorCode 900. Honest labels now.
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
    // No grants → Case A empty state (\"grant a server\"). Pinned
    // so the no-grant message can't drift into the case-B/C wording.
    assert!(
        html.contains("No servers granted to this user yet"),
        "case A empty-state (no grants) copy missing"
    );
    // 2026-05-17 — Pavel: «Flow A не показывает QR-код, говорит
    // про \"above\"». Symmetric `share_link_card` is the fix: Flow A
    // now renders its OWN QR + readonly copy textarea. The old
    // \"Recipient scans the QR in the Subscription block above\"
    // wording must be GONE.
    assert!(
        !html.contains("scans the QR in the"),
        "Flow A must not reference 'above' anymore — it has its own QR"
    );
    // The Flow A card renders the sub URL inside a readonly textarea
    // with the click-to-select-all hook.
    assert!(
        html.contains("Recommended default — one URL covers everything"),
        "Flow A footnote (Recommended default) missing — copy regressed"
    );
}

// ────────────────────────────────────────────────────────────────────────
// Pavel's \"main-brat\" confusion: user HAS WG keys, granted to a server
// that does NOT declare wireguard → empty-state must say so explicitly
// rather than the misleading \"grant a server with WG\" wording.

#[tokio::test]
async fn admin_user_detail_wireguard_flow_b_empty_state_case_b_grants_no_wg() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    let app = router(s);

    // Seed: a server that explicitly does NOT run wireguard (mimics
    // vps-is-01 post-bash-import: vless+reality, tuic-v5, hysteria2
    // only).
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

    // Create user via the auto-gen path → WG keypair populated.
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
    // Grant to the non-WG server.
    inv.grant(&UserId("brat".into()), &ServerId("nowg".into()))
        .await
        .unwrap();

    let html = fetch_html(app, "/admin/users/brat/delivery").await;
    // The misleading message MUST NOT appear (case A copy).
    assert!(
        !html.contains("No servers granted to this user yet"),
        "case A wording leaked into case B — user IS granted but to a non-WG server"
    );
    // The actually-correct case-B explanation MUST be present.
    assert!(
        html.contains("Keys exist, but no granted server runs WireGuard"),
        "case B headline missing — operator won't understand why no QR"
    );
    // The granted server's id must be name-dropped so the operator
    // knows WHICH server needs the protocol added.
    assert!(
        html.contains("nowg"),
        "case B body must name the actually-granted servers"
    );
    // No WG-capable server in inventory either → tail message points
    // at the web workaround (operator-action policy: no CLI in copy).
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

    // Two servers: one without WG (granted), one WITH WG (not granted).
    // Case-B copy should point at the second as a suggestion.
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
    // Seed via creation.
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

    // Rotate.
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
    // Audit row exists with the new pubkey + provenance marker.
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

#[tokio::test]
async fn admin_user_wireguard_conf_download_serves_attachment() {
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
    assert!(
        text.contains("[Interface]"),
        ".conf must contain [Interface]"
    );
    assert!(text.contains("[Peer]"), ".conf must contain [Peer]");
    assert!(
        text.contains("Endpoint = 203.0.113.11:51820"),
        ".conf must reference the right server endpoint"
    );
    // Private bytes MUST be inlined in the .conf so the operator's
    // recipient can import without a second action.
    assert!(
        text.contains("PrivateKey = 0000000000000000000000000000000000000000000="),
        ".conf must inline the user's private key (server-generated default)"
    );
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
    // Both user and server exist; server has wireguard enabled; but
    // there's NO grant linking them. The endpoint must 404, not leak
    // the .conf — otherwise a stale browser tab keeps working past
    // a revoke (review-agent 2026-05-17).
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
    // NB: NO grant.

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
    // Two users granted to the same WG server. Their .conf files
    // must claim different /32 addresses (10.66.0.2 + 10.66.0.3).
    // Pre-fix both claimed 10.66.0.2 — review-agent 2026-05-17.
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
    // Two users — `alex` < `bob` by lex sort (matches the
    // inv.users_for_server ORDER BY id).
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
    // Server that doesn't declare wireguard.
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
