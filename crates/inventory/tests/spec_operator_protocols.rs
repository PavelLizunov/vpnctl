#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use tempfile::TempDir;
use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
use vpnctl_inventory::{SqliteInventory, SqliteInventoryError};

async fn open(dir: &TempDir) -> SqliteInventory {
    SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .expect("open inventory db")
}

fn srv(id: &str, protocols: &[&str]) -> Server {
    Server {
        id: ServerId(id.into()),
        address: format!("{id}.example.com"),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: protocols.iter().map(|p| ProtocolId((*p).into())).collect(),
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

fn usr(id: &str) -> User {
    User {
        id: UserId(id.into()),
        uuid: format!("global-uuid-of-{id}"),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    }
}

async fn count_audit_by_action(inv: &SqliteInventory, action: &str) -> usize {
    inv.recent_audit(1000)
        .await
        .unwrap()
        .into_iter()
        .filter(|a| a.action == action)
        .count()
}

#[tokio::test]
async fn server_protocol_hidden_noop_audit_and_visibility() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    let server_id = ServerId("srv-node".into());
    let proto_vless = ProtocolId("vless+reality".into());
    let proto_tuic = ProtocolId("tuic-v5".into());
    let user_id = UserId("alice".into());

    inv.add_server(&srv("srv-node", &["vless+reality", "tuic-v5"]))
        .await
        .unwrap();
    inv.add_user(&usr("alice")).await.unwrap();
    inv.grant(&user_id, &server_id).await.unwrap();

    assert!(
        !inv.is_server_protocol_hidden(&server_id, &proto_vless)
            .await
            .unwrap()
    );
    assert!(
        !inv.is_server_protocol_hidden(&server_id, &proto_tuic)
            .await
            .unwrap()
    );

    let vis = inv
        .visible_protocols_for_subscription(&user_id, &server_id)
        .await
        .unwrap();
    assert_eq!(vis, vec![proto_tuic.clone(), proto_vless.clone()]);

    inv.set_server_protocol_hidden(&server_id, &proto_vless, false)
        .await
        .unwrap();
    assert_eq!(
        count_audit_by_action(&inv, "server.protocol.set_hidden").await,
        0
    );

    inv.set_server_protocol_hidden(&server_id, &proto_vless, true)
        .await
        .unwrap();
    assert_eq!(
        count_audit_by_action(&inv, "server.protocol.set_hidden").await,
        1
    );
    assert!(
        inv.is_server_protocol_hidden(&server_id, &proto_vless)
            .await
            .unwrap()
    );

    let recent = inv.recent_audit(10).await.unwrap();
    let entry = recent
        .iter()
        .find(|a| a.action == "server.protocol.set_hidden")
        .expect("audit row found");
    assert_eq!(entry.actor, "admin");
    assert_eq!(entry.target.as_deref(), Some("srv-node"));
    let payload = entry.payload.as_ref().unwrap();
    assert_eq!(payload["server_id"], serde_json::json!("srv-node"));
    assert_eq!(payload["protocol_id"], serde_json::json!("vless+reality"));
    assert_eq!(payload["old_hidden"], serde_json::json!(false));
    assert_eq!(payload["new_hidden"], serde_json::json!(true));

    let vis_after_hide = inv
        .visible_protocols_for_subscription(&user_id, &server_id)
        .await
        .unwrap();
    assert_eq!(vis_after_hide, vec![proto_tuic.clone()]);

    let per_server = inv
        .list_server_protocols_with_hidden(&server_id)
        .await
        .unwrap();
    assert_eq!(per_server.get(&proto_vless).copied(), Some(true));
    assert_eq!(per_server.get(&proto_tuic).copied(), Some(false));

    let all_servers = inv.list_all_server_protocols_with_hidden().await.unwrap();
    assert_eq!(
        all_servers
            .get(&(server_id.clone(), proto_vless.clone()))
            .copied(),
        Some(true)
    );
    assert_eq!(
        all_servers
            .get(&(server_id.clone(), proto_tuic.clone()))
            .copied(),
        Some(false)
    );

    inv.set_server_protocol_hidden(&server_id, &proto_vless, true)
        .await
        .unwrap();
    assert_eq!(
        count_audit_by_action(&inv, "server.protocol.set_hidden").await,
        1
    );

    inv.set_server_protocol_hidden(&server_id, &proto_vless, false)
        .await
        .unwrap();
    assert_eq!(
        count_audit_by_action(&inv, "server.protocol.set_hidden").await,
        2
    );
    assert!(
        !inv.is_server_protocol_hidden(&server_id, &proto_vless)
            .await
            .unwrap()
    );

    let vis_restored = inv
        .visible_protocols_for_subscription(&user_id, &server_id)
        .await
        .unwrap();
    assert_eq!(vis_restored, vec![proto_tuic.clone(), proto_vless.clone()]);

    let not_enabled = ProtocolId("shadowsocks-2022".into());
    let err = inv
        .set_server_protocol_hidden(&server_id, &not_enabled, true)
        .await
        .unwrap_err();
    match err {
        SqliteInventoryError::Invalid(msg) => {
            assert!(
                msg.contains("no such server_protocols row"),
                "unexpected err: {msg}"
            );
        }
        other => panic!("expected Invalid, got {other:?}"),
    }
}

#[tokio::test]
async fn grant_protocol_override_noop_audit_and_isolation() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    let server_id = ServerId("srv-node".into());
    let user_a = UserId("alice".into());
    let user_b = UserId("bob".into());
    let proto_vless = ProtocolId("vless+reality".into());
    let proto_tuic = ProtocolId("tuic-v5".into());

    inv.add_server(&srv("srv-node", &["vless+reality", "tuic-v5"]))
        .await
        .unwrap();
    inv.add_user(&usr("alice")).await.unwrap();
    inv.add_user(&usr("bob")).await.unwrap();
    inv.grant(&user_a, &server_id).await.unwrap();
    inv.grant(&user_b, &server_id).await.unwrap();

    inv.set_grant_protocol_override(&user_a, &server_id, &proto_vless, false)
        .await
        .unwrap();
    assert_eq!(
        count_audit_by_action(&inv, "grant.protocol.set_override").await,
        0
    );

    inv.set_grant_protocol_override(&user_a, &server_id, &proto_vless, true)
        .await
        .unwrap();
    assert_eq!(
        count_audit_by_action(&inv, "grant.protocol.set_override").await,
        1
    );

    let alice_vis = inv
        .visible_protocols_for_subscription(&user_a, &server_id)
        .await
        .unwrap();
    assert_eq!(alice_vis, vec![proto_tuic.clone()]);
    let bob_vis = inv
        .visible_protocols_for_subscription(&user_b, &server_id)
        .await
        .unwrap();
    assert_eq!(bob_vis, vec![proto_tuic.clone(), proto_vless.clone()]);

    let alice_overrides = inv.list_protocol_overrides_for_user(&user_a).await.unwrap();
    assert_eq!(
        alice_overrides
            .get(&(server_id.clone(), proto_vless.clone()))
            .copied(),
        Some(true)
    );

    inv.set_grant_protocol_override(&user_a, &server_id, &proto_vless, true)
        .await
        .unwrap();
    assert_eq!(
        count_audit_by_action(&inv, "grant.protocol.set_override").await,
        1
    );

    inv.set_grant_protocol_override(&user_a, &server_id, &proto_vless, false)
        .await
        .unwrap();
    assert_eq!(
        count_audit_by_action(&inv, "grant.protocol.set_override").await,
        2
    );

    let alice_vis_restored = inv
        .visible_protocols_for_subscription(&user_a, &server_id)
        .await
        .unwrap();
    assert_eq!(
        alice_vis_restored,
        vec![proto_tuic.clone(), proto_vless.clone()]
    );

    let user_no_grant = UserId("charlie".into());
    inv.add_user(&usr("charlie")).await.unwrap();
    let err = inv
        .set_grant_protocol_override(&user_no_grant, &server_id, &proto_vless, true)
        .await
        .unwrap_err();
    match err {
        SqliteInventoryError::Invalid(msg) => {
            assert!(msg.contains("no grant for"), "unexpected err: {msg}");
        }
        other => panic!("expected Invalid, got {other:?}"),
    }
}
