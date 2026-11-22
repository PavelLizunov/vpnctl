#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::common::*;
use tempfile::TempDir;
use vpnctl_core::{ServerId, UserId};

const ROUTES: [&str; 6] = [
    "/admin/",
    "/admin/servers",
    "/admin/servers/s0/setup",
    "/admin/users/u0",
    "/admin/users/u0/access",
    "/admin/users/u0/delivery",
];

async fn seed_delivery_secrets(st: &vpnctld::AppState, ids: &[&str]) {
    for id in ids {
        let id = ServerId((*id).to_owned());
        st.inv
            .set_server_secret(&id, "vless.public_key", "fixture-public")
            .await
            .unwrap();
        st.inv
            .set_server_secret(&id, "vless.short_id", "12345678")
            .await
            .unwrap();
    }
}

// Locate the identity element without assuming its tag, classes, or nesting.
fn assert_identity(html: &str, id: &str, escaped_name: &str) {
    let marker = format!("data-server-id=\"{id}\"");
    let mut found = 0;
    for (position, _) in html.match_indices(&marker) {
        let start = html[..position].rfind('<').unwrap();
        let opening_end = start + html[start..].find('>').unwrap() + 1;
        let opening = &html[start..opening_end];
        if !opening.contains("data-server-name=") {
            continue;
        }
        assert!(opening.contains(&format!("data-server-name=\"{escaped_name}\"")));
        let tag = html[start + 1..opening_end - 1]
            .split_whitespace()
            .next()
            .unwrap();
        let mut depth = 1;
        let mut end = opening_end;
        while depth != 0 {
            let next = end + html[end..].find('<').expect("identity closing tag");
            end = next + html[next..].find('>').unwrap() + 1;
            let token = html[next + 1..end - 1].trim();
            if token.strip_prefix('/') == Some(tag) {
                depth -= 1;
            } else if token.split_whitespace().next() == Some(tag) && !token.ends_with('/') {
                depth += 1;
            }
        }
        let mut inside_tag = false;
        let text: String = html[opening_end..end]
            .chars()
            .filter(|character| match character {
                '<' => {
                    inside_tag = true;
                    false
                }
                '>' => {
                    inside_tag = false;
                    false
                }
                _ => !inside_tag,
            })
            .collect();
        let visible = text.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(visible.contains(escaped_name), "primary label for {id}");
        assert!(
            visible.contains(&format!("ID: {id}")),
            "visible ID for {id}"
        );
        found += 1;
    }
    assert!(found > 0, "identity markup for {id}");
}

#[tokio::test]
async fn custom_server_name_and_technical_id_appear_on_all_operator_surfaces() {
    let directory = TempDir::new().unwrap();
    let st = state(&directory).await;
    seed_verified(&st.inv, 1, 1, &[(0, 0)]).await;
    seed_delivery_secrets(&st, &["s0"]).await;
    st.inv
        .set_server_display_name(&ServerId("s0".into()), Some("BitFolk"))
        .await
        .unwrap();

    for route in ROUTES {
        let html = fetch_html(vpnctld::router(st.clone()), route).await;
        assert_identity(&html, "s0", "BitFolk");
    }
}

#[tokio::test]
async fn presence_pending_notice_and_lower_access_list_use_escaped_names_and_ids() {
    let directory = TempDir::new().unwrap();
    let st = state(&directory).await;
    seed_verified(&st.inv, 2, 1, &[(0, 0)]).await;
    for id in ["s0", "s1"] {
        let sid = ServerId(id.into());
        st.inv
            .set_server_display_name(&sid, Some("Twin <&> Node"))
            .await
            .unwrap();
        let mut connection = pr_user_conn("198.51.100.12", "40000");
        connection.metadata.user = Some("u0".into());
        st.snapshot_cache.store(
            sid,
            vpnctld::clash_api::Snapshot {
                upload_total: connection.upload,
                download_total: connection.download,
                connections: vec![connection],
            },
        );
    }
    st.inv
        .audit("admin", "user.grant", Some("u0"), None)
        .await
        .unwrap();
    for route in [
        "/admin/users/u0",
        "/admin/users/u0/access",
        "/admin/users/u0/delivery",
    ] {
        let html = fetch_html(vpnctld::router(st.clone()), route).await;
        let heading = html.split("class=\"ed-headrow__actions\"").next().unwrap();
        assert!(heading.contains("2 conns across"));
        for id in ["s0", "s1"] {
            assert_identity(heading, id, "Twin &lt;&amp;&gt; Node");
        }
        let notice = html
            .split_once("Config not yet deployed to:")
            .unwrap()
            .1
            .split("data-sse-url=")
            .next()
            .unwrap();
        assert_identity(notice, "s0", "Twin &lt;&amp;&gt; Node");
        assert!(notice.contains("href=\"/admin/servers/s0#deploy-button\""));
        if route.ends_with("/access") {
            let lower_list = html.split_once("id=\"server-access\"").unwrap().1;
            for id in ["s0", "s1"] {
                assert_identity(lower_list, id, "Twin &lt;&amp;&gt; Node");
            }
            assert!(lower_list.contains("action=\"/admin/users/u0/grants/s0/revoke\""));
            assert!(lower_list.contains("action=\"/admin/users/u0/grants/s1\""));
        }
    }
}

#[tokio::test]
async fn duplicate_escaped_names_keep_visible_ids_and_technical_grant_paths() {
    let directory = TempDir::new().unwrap();
    let st = state(&directory).await;
    seed_verified(&st.inv, 2, 1, &[(0, 0)]).await;
    seed_delivery_secrets(&st, &["s0", "s1"]).await;
    let grant = "action=\"/admin/users/u0/grants/s1\"";
    let revoke = "action=\"/admin/users/u0/grants/s0/revoke\"";
    let before = fetch_html(vpnctld::router(st.clone()), "/admin/users/u0/access").await;
    assert!(before.contains(grant));
    assert!(before.contains(revoke));
    for id in ["s0", "s1"] {
        st.inv
            .set_server_display_name(&ServerId(id.into()), Some("Twin <&> Node"))
            .await
            .unwrap();
    }

    let servers = fetch_html(vpnctld::router(st.clone()), "/admin/servers").await;
    let access = fetch_html(vpnctld::router(st.clone()), "/admin/users/u0/access").await;
    for id in ["s0", "s1"] {
        assert_identity(&servers, id, "Twin &lt;&amp;&gt; Node");
        assert_identity(&access, id, "Twin &lt;&amp;&gt; Node");
        assert!(servers.contains(&format!("href=\"/admin/servers/{id}\"")));
    }
    assert!(access.contains(grant));
    assert!(access.contains(revoke));
}

#[tokio::test]
async fn unset_names_use_display_fallbacks_and_admin_gets_leave_inventory_unchanged() {
    let directory = TempDir::new().unwrap();
    let st = state(&directory).await;
    seed_verified(&st.inv, 1, 1, &[(0, 0)]).await;
    seed_delivery_secrets(&st, &["s0"]).await;
    let server_id = ServerId("s0".into());
    let user_id = UserId("u0".into());
    st.inv
        .set_server_display_name(&server_id, Some("Temporary"))
        .await
        .unwrap();
    st.inv
        .set_server_display_name(&server_id, None)
        .await
        .unwrap();
    let mut country_server = st.inv.get_server(&server_id).await.unwrap().unwrap();
    country_server.id = ServerId("de".into());
    country_server.address = "198.51.100.88".into();
    st.inv.add_server(&country_server).await.unwrap();

    let before_server = st.inv.get_server(&server_id).await.unwrap().unwrap();
    let before_user = st.inv.get_user(&user_id).await.unwrap().unwrap();
    let before_secrets = st.inv.list_server_secrets(&server_id).await.unwrap();
    let mut before_grants: Vec<_> = st
        .inv
        .users_for_server(&server_id)
        .await
        .unwrap()
        .into_iter()
        .map(|user| user.id.0)
        .collect();
    before_grants.sort();
    let before_audit = st.inv.recent_audit(1000).await.unwrap().len();

    for route in ROUTES {
        let html = fetch_html(vpnctld::router(st.clone()), route).await;
        assert_identity(&html, "s0", "S0");
        if matches!(route, "/admin/" | "/admin/servers") {
            assert_identity(&html, "de", "Germany");
        }
    }

    let after_server = st.inv.get_server(&server_id).await.unwrap().unwrap();
    let after_user = st.inv.get_user(&user_id).await.unwrap().unwrap();
    let mut after_grants: Vec<_> = st
        .inv
        .users_for_server(&server_id)
        .await
        .unwrap()
        .into_iter()
        .map(|user| user.id.0)
        .collect();
    after_grants.sort();
    assert_eq!(
        (
            before_server.id,
            before_server.address,
            before_server.ssh_port,
            before_server.ssh_user
        ),
        (
            after_server.id,
            after_server.address,
            after_server.ssh_port,
            after_server.ssh_user
        )
    );
    assert_eq!(
        (
            before_user.id,
            before_user.uuid,
            before_user.sub_token,
            before_user.disabled
        ),
        (
            after_user.id,
            after_user.uuid,
            after_user.sub_token,
            after_user.disabled
        )
    );
    assert_eq!(before_grants, after_grants);
    assert_eq!(
        before_secrets,
        st.inv.list_server_secrets(&server_id).await.unwrap()
    );
    assert_eq!(before_audit, st.inv.recent_audit(1000).await.unwrap().len());
    assert_eq!(
        st.inv
            .get_server(&ServerId("de".into()))
            .await
            .unwrap()
            .unwrap()
            .id
            .0,
        "de"
    );
}
