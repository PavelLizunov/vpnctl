use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

use vpnctl_core::{User, UserId};
use vpnctld::router;

use super::common::*;

#[tokio::test]
async fn admin_users_empty_state_quotes_cli() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let html = fetch_html(app, "/admin/users").await;

    assert!(
        html.contains("0 <em>users</em>"),
        "page header should announce 0 users"
    );
    assert!(html.contains("No users yet"), "empty-state copy missing");
    assert!(
        html.contains("grant server access"),
        "empty-state should hint the web grant workflow"
    );
    assert!(
        !html.contains(r#"class="ed-server""#),
        "no row-articles when there are no users"
    );
}

#[tokio::test]
async fn admin_users_populated_renders_rows_and_masks_secrets() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 3, &[(0, 0), (1, 0), (2, 0)]).await;

    let u0 = s.inv.get_user(&UserId("u0".into())).await.unwrap().unwrap();
    let token = u0.sub_token.expect("backfill should mint a sub_token");
    assert!(token.len() > 16, "sub_token unexpectedly short: {token:?}");

    let html = fetch_html(router(s), "/admin/users").await;

    assert_eq!(
        html.matches(r#"class="ed-grid__id""#).count(),
        3,
        "expected 3 user rows"
    );
    assert!(html.contains("3 <em>users</em>"));
    for id in ["u0", "u1", "u2"] {
        let href = format!(r#"href="/admin/users/{id}""#);
        assert!(
            html.contains(&href),
            "missing detail link for {id} ({href})"
        );
    }
    let head: String = token.chars().take(4).collect();
    let tail: String = token.chars().skip(token.len() - 4).collect();
    assert!(
        html.contains(&format!("{head}…{tail}")),
        "masked token preview should appear (first 4 + last 4)"
    );
    assert!(
        !html.contains(&token),
        "FULL sub_token leaked into the list page"
    );
    assert_eq!(
        html.matches(r#"<td class="num"><b>1</b></td>"#).count(),
        3,
        "each user row should show one granted server"
    );
}

#[tokio::test]
async fn admin_users_href_url_encodes_special_chars() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    s.inv
        .add_user(&User {
            id: UserId("weird/id?x=1 #frag".into()),
            uuid: "00000000-0000-0000-0000-000000000099".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();

    let html = fetch_html(router(s), "/admin/users").await;

    assert!(
        html.contains("href=\"/admin/users/weird%2Fid%3Fx%3D1%20%23frag\""),
        "href must percent-encode `/`, `?`, `=`, ` `, `#` (snippet around href: {:?})",
        html.split("ed-server__cta").next().unwrap_or("?")
    );
    assert!(
        !html.contains("href=\"/admin/users/weird/id?x=1 #frag\""),
        "raw, unescaped id leaked into href"
    );
}

#[tokio::test]
async fn admin_users_list_deck_mentions_ninitux_endpoint() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await;

    let html = fetch_html(router(s), "/admin/users").await;
    assert!(
        html.contains("ninitux.com/api/v1/app/config/&lt;device_id&gt;")
            || html.contains("ninitux.com/api/v1/app/config/<device_id>"),
        "users-list deck must mention the production ninitux URL shape"
    );
}

#[tokio::test]
async fn admin_users_renders_search_form_before_add_user_form() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    st.inv
        .add_user(&vpnctl_core::User {
            id: vpnctl_core::UserId("seed".into()),
            uuid: "11111111-1111-1111-1111-111111111111".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: Some("seed-token".into()),
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    let app = router(st);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/users")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();

    let search_idx = html
        .find(r#"method="get" action="/admin/users""#)
        .expect("search form (method=get) missing");
    let add_idx = html
        .find(r#"method="post" action="/admin/users""#)
        .expect("add-user form (method=post) missing");
    assert!(
        search_idx < add_idx,
        "search form (at {search_idx}) must appear BEFORE add-user form (at {add_idx}) — \
         else accidental Enter from search-flow creates a user (Pavel-2026-05-19 bug)"
    );
    assert!(
        html.contains("border-left: 1px dashed var(--accent)"),
        "add-user form must use a dashed accent divider"
    );
}

#[tokio::test]
async fn admin_user_create_happy_path() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    assert_eq!(s.inv.list_users().await.unwrap().len(), 0);

    let inv = s.inv.clone();
    let app = router(s);

    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("id=alice"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "expected 303 redirect after create, got {:?}",
        resp.status()
    );
    assert_eq!(
        resp.headers().get("location").unwrap().to_str().unwrap(),
        "/admin/users/alice",
        "redirect target must be the new user's detail page"
    );

    let user = inv
        .get_user(&UserId("alice".into()))
        .await
        .unwrap()
        .expect("user must be in inventory after create");
    assert_eq!(user.uuid.len(), 36, "uuid must be standard 36 chars");
    assert!(user.tuic_password.is_some(), "tuic_password must be minted");
    assert!(user.sub_token.is_some(), "sub_token backfilled by add_user");

    let entries = inv.recent_audit(10).await.unwrap();
    let add = entries
        .iter()
        .find(|e| e.action == "user.add")
        .expect("audit row for user.add missing");
    assert_eq!(add.actor, "admin");
    assert_eq!(add.target.as_deref(), Some("alice"));
    let payload = add.payload.as_ref().expect("payload must contain uuid");
    assert_eq!(
        payload["uuid"],
        serde_json::Value::String(user.uuid.clone())
    );
}

#[tokio::test]
async fn admin_user_create_rejects_bad_id() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);

    for bad in [
        "alice with space",
        "alice/slash",
        "alice?query",
        "",
        "русский",
        "..",
        "user..name",
        ".leadingdot",
        "trailingdot.",
        "-leadingdash",
        "trailingdash-",
        "_leadingunderscore",
        "trailingunderscore_",
    ] {
        let body = format!("id={}", bad.replace(' ', "+"));
        let resp = app
            .clone()
            .oneshot(
                add_same_origin(
                    Request::builder()
                        .method("POST")
                        .uri("/admin/users")
                        .header("content-type", "application/x-www-form-urlencoded"),
                )
                .body(Body::from(body))
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "id {bad:?} must be rejected, got {:?}",
            resp.status()
        );
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(
            text.starts_with("vpnctl admin: invalid user id"),
            "400 body must start with the unified prefix, got: {text:?}"
        );
    }
}

#[tokio::test]
async fn admin_user_create_rejects_duplicate_id() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await;
    let app = router(s);

    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("id=u0"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "duplicate id must be 400, got {:?}",
        resp.status()
    );
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(
        text.contains("already exists"),
        "duplicate body should mention 'already exists', got: {text:?}"
    );
    assert!(
        text.contains("pick a different id"),
        "duplicate body should suggest the fix, got: {text:?}"
    );
}

#[tokio::test]
async fn admin_users_page_renders_create_form() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let html = fetch_html(app, "/admin/users").await;
    assert!(
        html.contains(r#"action="/admin/users""#),
        "form must POST to /admin/users"
    );
    assert!(
        html.contains(r#"name="id""#),
        "form must have a name=id input"
    );
    assert!(
        html.contains(">create<"),
        "submit button label drifted from 'create'"
    );
    assert!(
        html.contains("all keys are auto-generated"),
        "form helper drifted — should promise auto-gen so the operator doesn't go hunting"
    );
}

#[tokio::test]
async fn admin_user_delete_confirm_renders_form_with_match_id() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await;
    let app = router(s);
    let html = fetch_html(app, "/admin/users/u0/delete-confirm").await;
    assert!(
        html.contains("delete forever"),
        "submit button label drifted"
    );
    assert!(
        html.contains(r#"action="/admin/users/u0/delete""#),
        "confirm form must POST to /admin/users/u0/delete"
    );
    assert!(html.contains(r#"name="confirm""#), "confirm input missing");
    assert!(html.contains(">u0<"), "operator must see what to type");
}

#[tokio::test]
async fn admin_user_delete_confirm_unknown_404() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let body = body_of(
        app,
        "GET",
        "/admin/users/no-such/delete-confirm",
        None,
        None,
    )
    .await;
    assert_eq!(body, "vpnctl admin: no such user 'no-such'\n");
}

#[tokio::test]
async fn admin_user_delete_happy_path() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    s.inv
        .log_sub_access(&UserId("u0".into()), "1.1.1.1", None, 200, 100)
        .await
        .unwrap();
    let inv = s.inv.clone();
    let app = router(s);

    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users/u0/delete")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("confirm=u0"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        resp.headers().get("location").unwrap().to_str().unwrap(),
        "/admin/users",
        "redirect after delete must land on the users list"
    );

    assert!(
        inv.get_user(&UserId("u0".into())).await.unwrap().is_none(),
        "user must be removed"
    );
    assert_eq!(
        inv.servers_for_user(&UserId("u0".into()))
            .await
            .unwrap()
            .len(),
        0
    );
    let entries = inv.recent_audit(10).await.unwrap();
    assert!(
        entries
            .iter()
            .any(|e| e.action == "user.remove" && e.target.as_deref() == Some("u0")),
        "user.remove audit row missing"
    );
    let n = inv
        .distinct_ips_for_user(&UserId("u0".into()), 24)
        .await
        .unwrap();
    assert_eq!(
        n, 0,
        "deleted user's distinct IPs query returns 0 (FK was SET NULL — row survives orphaned)"
    );
}

#[tokio::test]
async fn admin_user_delete_mismatch_400() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 0, 1, &[]).await;
    let inv = s.inv.clone();
    let app = router(s);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users/u0/delete")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("confirm=u1"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(inv.get_user(&UserId("u0".into())).await.unwrap().is_some());
}

#[tokio::test]
async fn admin_user_create_always_mints_server_generated_wireguard_pair() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    let app = router(s);
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from("id=alice"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let u = inv
        .get_user(&UserId("alice".into()))
        .await
        .unwrap()
        .unwrap();
    let pk = u.wireguard_pubkey.as_deref().expect("pubkey auto-set");
    let priv_ = u.wireguard_private.as_deref().expect("private auto-set");
    assert_eq!(pk.len(), 44, "pubkey must be 44-char standard b64: {pk}");
    assert_eq!(priv_.len(), 44, "private must be 44-char standard b64");
    assert!(pk.ends_with('='));
    assert!(priv_.ends_with('='));
    assert_ne!(pk, priv_, "pub and priv must differ");
}

#[tokio::test]
async fn admin_user_create_ignores_stale_wireguard_pubkey_field() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    let inv = s.inv.clone();
    let app = router(s);
    let attacker_pubkey = "AttackerKkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkAB=";
    let body = format!(
        "id=bob&wireguard_pubkey={}",
        attacker_pubkey.replace('=', "%3D")
    );
    let resp = app
        .oneshot(
            add_same_origin(
                Request::builder()
                    .method("POST")
                    .uri("/admin/users")
                    .header("content-type", "application/x-www-form-urlencoded"),
            )
            .body(Body::from(body))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let u = inv.get_user(&UserId("bob".into())).await.unwrap().unwrap();
    let pk = u.wireguard_pubkey.as_deref().unwrap();
    assert_ne!(
        pk, attacker_pubkey,
        "stale form field MUST be ignored; got {pk}"
    );
    assert!(u.wireguard_private.is_some(), "server-generated pair");
}

#[tokio::test]
async fn admin_users_page_form_is_one_field_one_button() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let html = fetch_html(app, "/admin/users").await;
    assert!(
        !html.contains(r#"name="wireguard_pubkey""#),
        "wireguard_pubkey input MUST NOT be in the creation form"
    );
    assert!(
        !html.contains(r#"name="gen_wireguard""#),
        "gen_wireguard checkbox MUST NOT be in the creation form"
    );
    assert!(
        html.contains("all keys are auto-generated"),
        "form helper must promise auto-gen so the operator doesn't go hunting for missing options"
    );
}

#[tokio::test]
async fn admin_users_search_filters_by_id_substring() {
    use vpnctl_core::{User, UserId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    for uid in ["alice", "bob", "alicia", "carol"] {
        s.inv
            .add_user(&User {
                id: UserId(uid.into()),
                uuid: format!("uuid-{uid}"),
                tuic_password: None,
                wireguard_pubkey: None,
                wireguard_private: None,
                sub_token: None,
                vpn_router_device_id: None,
                disabled: false,
            })
            .await
            .unwrap();
    }
    let app = router(s);
    let html = fetch_html(app, "/admin/users?q=ali").await;
    assert!(html.contains(">alice<"), "alice should appear");
    assert!(html.contains(">alicia<"), "alicia should appear");
    assert!(!html.contains(">bob<"), "bob must be filtered out");
    assert!(!html.contains(">carol<"), "carol must be filtered out");
    assert!(html.contains("showing 2 of 4"), "subset counter missing");
}

#[tokio::test]
async fn admin_users_sort_servers_orders_by_grants_count_ascending() {
    use vpnctl_core::{KernelId, Server, ServerId, User, UserId};
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    for sid in ["s1", "s2", "s3"] {
        s.inv
            .add_server(&Server {
                id: ServerId(sid.into()),
                address: "203.0.113.7".into(),
                ssh_port: 22,
                ssh_user: "root".into(),
                kernels: vec![KernelId("sing-box".into())],
                enabled_protocols: vec![],
                trusted_host_fingerprint: None,
                hoster: "generic".into(),
                jump_via: None,
                usage_coefficient: 1.0,
            })
            .await
            .unwrap();
    }
    for uid in ["alice", "bob", "carol"] {
        s.inv
            .add_user(&User {
                id: UserId(uid.into()),
                uuid: format!("uuid-{uid}"),
                tuic_password: None,
                wireguard_pubkey: None,
                wireguard_private: None,
                sub_token: None,
                vpn_router_device_id: None,
                disabled: false,
            })
            .await
            .unwrap();
    }
    for sid in ["s1", "s2", "s3"] {
        s.inv
            .grant(&UserId("alice".into()), &ServerId(sid.into()))
            .await
            .unwrap();
    }
    s.inv
        .grant(&UserId("bob".into()), &ServerId("s1".into()))
        .await
        .unwrap();

    let html = fetch_html(router(s.clone()), "/admin/users?sort=servers").await;
    let pos_alice = html.find(">alice<").expect("alice rendered");
    let pos_bob = html.find(">bob<").expect("bob rendered");
    let pos_carol = html.find(">carol<").expect("carol rendered");
    assert!(
        pos_carol < pos_bob && pos_bob < pos_alice,
        "sort=servers (ascending) must render carol<bob<alice; got positions a={pos_alice} b={pos_bob} c={pos_carol}"
    );

    let html_desc = fetch_html(router(s), "/admin/users?sort=servers-desc").await;
    let pos_alice = html_desc.find(">alice<").expect("alice rendered");
    let pos_bob = html_desc.find(">bob<").expect("bob rendered");
    let pos_carol = html_desc.find(">carol<").expect("carol rendered");
    assert!(
        pos_alice < pos_bob && pos_bob < pos_carol,
        "sort=servers-desc (descending) must render alice<bob<carol; got positions a={pos_alice} b={pos_bob} c={pos_carol}"
    );
}

#[tokio::test]
async fn user_disable_then_enable_round_trip_flips_flag_and_audits() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    st.inv
        .add_user(&User {
            id: UserId("toggleable".into()),
            uuid: "00000000-0000-0000-0000-000000000061".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
    let app = router(st.clone());

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/users/toggleable/disable")
                .header("Origin", "http://127.0.0.1")
                .header("Host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let u = st
        .inv
        .get_user(&UserId("toggleable".into()))
        .await
        .unwrap()
        .unwrap();
    assert!(
        u.disabled,
        "disabled flag must be true after POST .../disable"
    );
    let audit = st.inv.recent_audit(10).await.unwrap();
    assert!(
        audit.iter().any(|e| e.action == "user.disable"),
        "audit must contain user.disable row"
    );

    let pre = st.inv.recent_audit(10).await.unwrap().len();
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/users/toggleable/disable")
                .header("Origin", "http://127.0.0.1")
                .header("Host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let post = st.inv.recent_audit(10).await.unwrap().len();
    assert_eq!(
        pre, post,
        "no-op re-disable must NOT write audit (audit-on-actual-mutation contract)"
    );

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/users/toggleable/enable")
                .header("Origin", "http://127.0.0.1")
                .header("Host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let u = st
        .inv
        .get_user(&UserId("toggleable".into()))
        .await
        .unwrap()
        .unwrap();
    assert!(
        !u.disabled,
        "disabled flag must be false after POST .../enable"
    );
    let audit = st.inv.recent_audit(20).await.unwrap();
    assert!(
        audit.iter().any(|e| e.action == "user.enable"),
        "audit must contain user.enable row after the flip"
    );
}

#[tokio::test]
async fn user_create_audit_payload_includes_wg_keypair_provenance_and_pubkey_set() {
    let dir = TempDir::new().unwrap();
    let st = state(&dir).await;
    let app = router(st.clone());
    let _ = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/users")
                .header("Origin", "http://127.0.0.1")
                .header("Host", "127.0.0.1")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("id=alice"))
                .unwrap(),
        )
        .await
        .unwrap();
    let audit = st.inv.recent_audit(20).await.unwrap();
    let row = audit
        .iter()
        .find(|e| e.action == "user.add" && e.target.as_deref() == Some("alice"))
        .expect("user.add audit row must exist for alice");
    let payload = row.payload.as_ref().expect("payload required");
    assert!(
        payload.get("uuid").is_some(),
        "audit payload must include uuid; got: {payload}"
    );
    assert_eq!(
        payload.get("wg_pubkey_set").and_then(|v| v.as_bool()),
        Some(true),
        "web-create must report wg_pubkey_set=true (always generates a pair)"
    );
    assert_eq!(
        payload
            .get("wg_keypair_provenance")
            .and_then(|v| v.as_str()),
        Some("server-generated"),
        "web-create must report wg_keypair_provenance=server-generated"
    );
}

#[tokio::test]
async fn user_disable_unknown_user_returns_404() {
    let dir = TempDir::new().unwrap();
    let app = router(state(&dir).await);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/users/no-such/disable")
                .header("Origin", "http://127.0.0.1")
                .header("Host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn sharing_page_lists_all_flagged_users_and_filters() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 7, &[(0, 0)]).await;
    for i in 0..7 {
        s.inv
            .record_user_ip_concurrency(&[(UserId(format!("u{i}")), if i == 0 { 4 } else { 3 })])
            .await
            .unwrap();
    }
    let app = router(s);

    let all = fetch_html(app.clone(), "/admin/sharing").await;
    assert!(all.contains("Sharing-risk review"), "{all}");
    assert!(
        all.contains("heuristic, not a probability"),
        "the score must not be presented as a probability: {all}"
    );
    assert!(
        all.contains(r#"id="fleet-at-a-glance""#)
            && all.contains(r#"ed-tab--on" href="/admin/sharing""#)
            && all.contains(r#"href="/admin/overview""#)
            && all.contains(r#"href="/admin/activity""#),
        "sharing review must use the dashboard chrome and tab navigation: {all}"
    );
    for i in 0..7 {
        assert!(
            all.contains(&format!("/admin/users/u{i}/activity#source-ips")),
            "u{i} missing from full sharing page"
        );
    }

    let high = fetch_html(app.clone(), "/admin/sharing?level=high").await;
    assert!(
        high.contains("/admin/users/u0/activity#source-ips"),
        "{high}"
    );
    assert!(
        !high.contains("/admin/users/u1/activity#source-ips"),
        "{high}"
    );

    let search = fetch_html(app, "/admin/sharing?q=u3&min_score=40").await;
    assert!(
        search.contains("/admin/users/u3/activity#source-ips"),
        "{search}"
    );
    assert!(
        !search.contains("/admin/users/u2/activity#source-ips"),
        "{search}"
    );
}

#[tokio::test]
async fn sharing_page_invalid_or_empty_filters_stay_readable() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;
    s.inv
        .record_user_ip_concurrency(&[(UserId("u0".into()), 3)])
        .await
        .unwrap();
    let app = router(s);

    let invalid = fetch_html(app.clone(), "/admin/sharing?level=wat&min_score=wat").await;
    assert!(
        invalid.contains("/admin/users/u0/activity#source-ips"),
        "{invalid}"
    );

    let empty = fetch_html(app, "/admin/sharing?q=missing").await;
    assert!(
        empty.contains("No flagged users match these filters."),
        "{empty}"
    );
}
