#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;

#[test]
fn parse_bash_inventory_env_real_fixture() {
    let s = include_str!("../../tests/fixtures/bash_migration/198.51.100.93.env");
    let inv = parse_bash_inventory_env(s).unwrap();
    assert_eq!(inv.server_ip, "198.51.100.93");
    assert_eq!(inv.ssh_port, 2222);
    assert_eq!(
        inv.reality_public,
        "FixturePublicKeyAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    );
    assert_eq!(inv.short_id, "0123456789abcdef");
    assert_eq!(inv.users.len(), 20);
    assert_eq!(inv.users[0], "main-brat");
}

#[test]
fn parse_bash_inventory_env_example_template() {
    let s = include_str!("../../tests/fixtures/bash_migration/example_inv.env");
    let inv = parse_bash_inventory_env(s).unwrap();
    assert_eq!(inv.server_ip, "1.2.3.4");
    assert_eq!(inv.ssh_port, 2222);
    assert_eq!(inv.users, vec!["user1", "user2", "user3"]);
}

#[test]
fn parse_bash_inventory_env_rejects_malformed_line() {
    let bad = "SERVER_IP=1.2.3.4\nbroken-no-equals\n";
    let err = parse_bash_inventory_env(bad).unwrap_err();
    assert!(err.contains("KEY=VALUE"), "wrong error: {err}");
}

#[test]
fn parse_bash_inventory_env_rejects_missing_required() {
    let no_ip = "SHORT_ID=abc\nREALITY_PUBLIC=xyz\n";
    let err = parse_bash_inventory_env(no_ip).unwrap_err();
    assert!(err.contains("SERVER_IP"), "wrong error: {err}");
}

#[test]
fn parse_bash_singbox_real_fixture_counts() {
    let cfg = include_str!("../../tests/fixtures/bash_migration/config.json");
    let keys = include_str!("../../tests/fixtures/bash_migration/keys.env");
    let data = parse_bash_singbox(cfg, keys).unwrap();
    assert_eq!(
        data.vless_users.len(),
        23,
        "expected 23 VLESS users from the migration fixture"
    );
    assert_eq!(data.tuic_users.len(), 9, "expected 9 TUIC users");
    assert!(
        data.reality_private
            .as_deref()
            .unwrap_or("")
            .starts_with("EXAMPLE_REDACTED")
    );
}

#[test]
fn parse_bash_singbox_skips_non_vless_non_tuic_inbounds() {
    let cfg = r#"{"inbounds": [{"type":"socks", "tag":"socks-in"}]}"#;
    let data = parse_bash_singbox(cfg, "").unwrap();
    assert!(data.vless_users.is_empty());
    assert!(data.tuic_users.is_empty());
    assert!(data.reality_private.is_none());
}

#[test]
fn parse_bash_singbox_rejects_invalid_json() {
    let err = parse_bash_singbox("not json", "").unwrap_err();
    assert!(err.contains("valid JSON"));
}

fn fake_token(name: &str) -> String {
    format!("subtoken-{name}-deadbeef")
}

fn fake_inv() -> BashInventoryEnv {
    BashInventoryEnv {
        server_ip: "203.0.113.7".into(),
        ssh_port: 22,
        reality_public: "PUBKEY_ABCDEFGHIJKL".into(),
        short_id: "deadbeefdeadbeef".into(),
        users: vec!["alex".into(), "bob".into()],
    }
}

#[test]
fn build_plan_unifies_vless_and_tuic_user_on_matching_uuid() {
    let inv = fake_inv();
    let data = BashSingboxData {
        vless_users: vec![
            BashVlessUser {
                name: "alex".into(),
                uuid: "u-alex".into(),
                flow: Some("xtls-rprx-vision".into()),
            },
            BashVlessUser {
                name: "bob".into(),
                uuid: "u-bob".into(),
                flow: Some("xtls-rprx-vision".into()),
            },
        ],
        tuic_users: vec![BashTuicUser {
            name: "alex".into(),
            uuid: "u-alex".into(),
            password: "pw-alex".into(),
        }],
        reality_private: Some("priv".into()),
    };
    let plan = build_migration_plan(None, &inv, &data, fake_token).unwrap();
    assert_eq!(plan.users_to_import.len(), 2);
    let alex = plan
        .users_to_import
        .iter()
        .find(|u| u.id.0 == "alex")
        .unwrap();
    assert_eq!(alex.tuic_password.as_deref(), Some("pw-alex"));
    let bob = plan
        .users_to_import
        .iter()
        .find(|u| u.id.0 == "bob")
        .unwrap();
    assert_eq!(bob.tuic_password, None);
    let pids: Vec<&str> = plan
        .server
        .enabled_protocols
        .iter()
        .map(|p| p.0.as_str())
        .collect();
    assert!(pids.contains(&"vless+reality"));
    assert!(pids.contains(&"tuic-v5"));
}

#[test]
fn build_plan_drops_tuic_v5_protocol_when_no_user_has_password() {
    let inv = fake_inv();
    let data = BashSingboxData {
        vless_users: vec![BashVlessUser {
            name: "alex".into(),
            uuid: "u".into(),
            flow: None,
        }],
        tuic_users: vec![],
        reality_private: None,
    };
    let plan = build_migration_plan(None, &inv, &data, fake_token).unwrap();
    let pids: Vec<&str> = plan
        .server
        .enabled_protocols
        .iter()
        .map(|p| p.0.as_str())
        .collect();
    assert!(pids.contains(&"vless+reality"));
    assert!(!pids.contains(&"tuic-v5"));
}

#[test]
fn build_plan_skips_tuic_only_legacy_users_with_clear_reason() {
    let inv = fake_inv();
    let data = BashSingboxData {
        vless_users: vec![BashVlessUser {
            name: "alex".into(),
            uuid: "u-alex".into(),
            flow: None,
        }],
        tuic_users: vec![
            BashTuicUser {
                name: "alex".into(),
                uuid: "u-alex".into(),
                password: "pw".into(),
            },
            BashTuicUser {
                name: "legacy-pc".into(),
                uuid: "u-legacy".into(),
                password: "pw2".into(),
            },
        ],
        reality_private: None,
    };
    let plan = build_migration_plan(None, &inv, &data, fake_token).unwrap();
    let skipped_names: Vec<&str> = plan.skipped.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(skipped_names, vec!["legacy-pc"]);
    assert!(plan.skipped[0].reason.contains("TUIC-only"));
    assert!(plan.users_to_import.iter().all(|u| u.id.0 != "legacy-pc"));
    assert!(plan.grants.iter().all(|(uid, _)| uid.0 != "legacy-pc"));
}

#[test]
fn build_plan_warns_on_vless_tuic_uuid_split_identity_imports_vless_only() {
    let inv = fake_inv();
    let data = BashSingboxData {
        vless_users: vec![
            BashVlessUser {
                name: "alex".into(),
                uuid: "u-alex-vless-aaaaaaaa".into(),
                flow: None,
            },
            BashVlessUser {
                name: "bob".into(),
                uuid: "u-bob-shared-bbbbbbbb".into(),
                flow: None,
            },
        ],
        tuic_users: vec![
            BashTuicUser {
                name: "alex".into(),
                uuid: "u-alex-tuic-cccccccc".into(),
                password: "pw-alex".into(),
            },
            BashTuicUser {
                name: "bob".into(),
                uuid: "u-bob-shared-bbbbbbbb".into(),
                password: "pw-bob".into(),
            },
        ],
        reality_private: None,
    };
    let plan = build_migration_plan(None, &inv, &data, fake_token).unwrap();

    let alex = plan
        .users_to_import
        .iter()
        .find(|u| u.id.0 == "alex")
        .unwrap();
    assert_eq!(alex.uuid, "u-alex-vless-aaaaaaaa");
    assert_eq!(alex.tuic_password, None);

    let bob = plan
        .users_to_import
        .iter()
        .find(|u| u.id.0 == "bob")
        .unwrap();
    assert_eq!(bob.uuid, "u-bob-shared-bbbbbbbb");
    assert_eq!(bob.tuic_password.as_deref(), Some("pw-bob"));

    let warning = plan
        .warnings
        .iter()
        .find(|w| w.contains("alex"))
        .expect("expected split-identity warning for alex");
    assert!(warning.contains("differs"), "warning was: {warning}");
    assert!(
        warning.contains("u-alex-v"),
        "expected VLESS uuid prefix 'u-alex-v', got: {warning}"
    );
    assert!(
        warning.contains("u-alex-t"),
        "expected TUIC uuid prefix 'u-alex-t', got: {warning}"
    );

    let split_skipped = plan
        .skipped
        .iter()
        .find(|s| s.name == "alex")
        .expect("expected SkippedUser entry for split-identity TUIC half");
    assert!(
        split_skipped.reason.contains("split-identity"),
        "skip reason was: {}",
        split_skipped.reason
    );

    let pids: Vec<&str> = plan
        .server
        .enabled_protocols
        .iter()
        .map(|p| p.0.as_str())
        .collect();
    assert!(pids.contains(&"tuic-v5"));
}

#[test]
fn build_plan_warns_on_stale_inventory_user_not_in_config() {
    let mut inv = fake_inv();
    inv.users.push("ghost".into());
    let data = BashSingboxData {
        vless_users: vec![BashVlessUser {
            name: "alex".into(),
            uuid: "u-alex".into(),
            flow: None,
        }],
        tuic_users: vec![],
        reality_private: Some("priv".into()),
    };
    let plan = build_migration_plan(None, &inv, &data, fake_token).unwrap();
    assert!(
        plan.warnings
            .iter()
            .any(|w| w.contains("'ghost'") && w.contains("stale"))
    );
}

#[test]
fn build_plan_warns_on_missing_reality_private() {
    let inv = fake_inv();
    let data = BashSingboxData {
        vless_users: vec![BashVlessUser {
            name: "alex".into(),
            uuid: "u-alex".into(),
            flow: None,
        }],
        tuic_users: vec![],
        reality_private: None,
    };
    let plan = build_migration_plan(None, &inv, &data, fake_token).unwrap();
    assert!(plan.warnings.iter().any(|w| w.contains("REALITY_PRIVATE")));
    assert!(!plan.server_secrets.contains_key("vless.private_key"));
    assert!(plan.server_secrets.contains_key("vless.public_key"));
    assert!(plan.server_secrets.contains_key("vless.short_id"));
}

#[test]
fn build_plan_assigns_sub_tokens_via_closure() {
    let inv = fake_inv();
    let data = BashSingboxData {
        vless_users: vec![
            BashVlessUser {
                name: "alex".into(),
                uuid: "u-a".into(),
                flow: None,
            },
            BashVlessUser {
                name: "bob".into(),
                uuid: "u-b".into(),
                flow: None,
            },
        ],
        tuic_users: vec![],
        reality_private: None,
    };
    let plan = build_migration_plan(None, &inv, &data, fake_token).unwrap();
    let alex = plan
        .users_to_import
        .iter()
        .find(|u| u.id.0 == "alex")
        .unwrap();
    let bob = plan
        .users_to_import
        .iter()
        .find(|u| u.id.0 == "bob")
        .unwrap();
    assert_eq!(alex.sub_token.as_deref(), Some("subtoken-alex-deadbeef"));
    assert_eq!(bob.sub_token.as_deref(), Some("subtoken-bob-deadbeef"));
}

#[test]
fn derive_server_id_keeps_ipv4_unchanged() {
    assert_eq!(derive_server_id_from_ip("198.51.100.93"), "198.51.100.93");
}

#[test]
fn derive_server_id_replaces_ipv6_colons_with_hyphens() {
    assert_eq!(derive_server_id_from_ip("2001:db8::1"), "2001-db8--1");
}

async fn open_test_inv() -> crate::SqliteInventory {
    let dir = tempfile::tempdir().unwrap();
    std::mem::forget(dir);
    let db = std::env::temp_dir().join(format!(
        "vpnctl-migrate-test-{}.db",
        vpnctl_crypto::gen_password(8).unwrap_or_else(|_| "fallback".into())
    ));
    crate::SqliteInventory::open(&db).await.unwrap()
}

fn plan_with_one_user(server_id: &str, user_name: &str, user_uuid: &str) -> MigrationPlan {
    let inv = BashInventoryEnv {
        server_ip: "203.0.113.1".into(),
        ssh_port: 22,
        reality_public: "PUB".into(),
        short_id: "SID".into(),
        users: vec![user_name.into()],
    };
    let data = BashSingboxData {
        vless_users: vec![BashVlessUser {
            name: user_name.into(),
            uuid: user_uuid.into(),
            flow: None,
        }],
        tuic_users: vec![],
        reality_private: Some("priv".into()),
    };
    build_migration_plan(Some(server_id.into()), &inv, &data, |n| format!("tok-{n}")).unwrap()
}

#[tokio::test]
async fn apply_writes_audit_row_with_summary_payload() {
    let inv = open_test_inv().await;
    let plan = plan_with_one_user("srv-a", "alice", "uuid-A");
    let _ = apply_migration_plan(&inv, &plan, false).await.unwrap();
    let rows = inv.recent_audit(10).await.unwrap();
    let audit = rows
        .iter()
        .find(|r| r.action == "migrate.from_bash")
        .expect("migrate.from_bash audit row must be written");
    let payload = audit.payload.as_ref().unwrap();
    assert_eq!(payload["server_created"], serde_json::json!(true));
    assert_eq!(payload["users_created"], serde_json::json!(1));
    assert_eq!(payload["grants_made"], serde_json::json!(1));
}

#[tokio::test]
async fn migration_audit_payloads_omit_user_and_grant_uuids() {
    let inv = open_test_inv().await;
    let original_uuid = "00000000-0000-0000-0000-000000000001";
    let imported_uuid = "00000000-0000-0000-0000-000000000002";
    let original = plan_with_one_user("srv-a", "alice", original_uuid);
    apply_migration_plan(&inv, &original, false).await.unwrap();
    let changed = plan_with_one_user("srv-a", "alice", imported_uuid);
    apply_migration_plan(&inv, &changed, false).await.unwrap();
    let rows = inv.recent_audit(100).await.unwrap();
    for row in &rows {
        let payload = serde_json::to_string(&row.payload).unwrap();
        assert!(!payload.contains(original_uuid));
        assert!(!payload.contains(imported_uuid));
    }
    let created = rows.iter().find(|row| row.action == "user.add").unwrap();
    assert_eq!(created.payload.as_ref().unwrap()["uuid_set"], true);
    let changed = rows
        .iter()
        .find(|row| row.action == "grant.set_client_uuid")
        .unwrap();
    assert_eq!(changed.target.as_deref(), Some("alice"));
    let payload = changed.payload.as_ref().unwrap();
    assert_eq!(payload["server_id"], "srv-a");
    assert_eq!(payload["old_client_uuid_set"], false);
    assert_eq!(payload["new_client_uuid_set"], true);
}

#[tokio::test]
async fn apply_with_overwrite_replaces_existing_user_uuid() {
    use vpnctl_core::{User, UserId};
    let inv = open_test_inv().await;
    inv.add_user(&User {
        id: UserId("alice".into()),
        uuid: "00000000-0000-0000-0000-000000000001".into(),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: Some("stale".into()),
        vpn_router_device_id: None,
        disabled: false,
    })
    .await
    .unwrap();

    let plan = plan_with_one_user("srv-b", "alice", "00000000-0000-0000-0000-000000000002");
    let outcome = apply_migration_plan(&inv, &plan, false).await.unwrap();
    assert_eq!(outcome.users_skipped_existing, vec!["alice".to_string()]);
    let after_no_overwrite = inv
        .get_user(&UserId("alice".into()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        after_no_overwrite.uuid,
        "00000000-0000-0000-0000-000000000001"
    );
    let outcome = apply_migration_plan(&inv, &plan, true).await.unwrap();
    assert_eq!(outcome.users_overwritten, vec!["alice".to_string()]);
    let after_overwrite = inv
        .get_user(&UserId("alice".into()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after_overwrite.uuid, "00000000-0000-0000-0000-000000000002");
}

#[tokio::test]
async fn apply_with_overwrite_preserves_user_grants_on_other_servers() {
    use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
    let inv = open_test_inv().await;
    inv.add_server(&Server {
        id: ServerId("existing-other".into()),
        address: "198.51.100.99".into(),
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
        id: UserId("alice".into()),
        uuid: "OLD-uuid".into(),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: Some("stale".into()),
        vpn_router_device_id: None,
        disabled: false,
    })
    .await
    .unwrap();
    inv.grant(&UserId("alice".into()), &ServerId("existing-other".into()))
        .await
        .unwrap();

    let plan = plan_with_one_user("srv-bash", "alice", "NEW-uuid");
    let outcome = apply_migration_plan(&inv, &plan, true).await.unwrap();

    let servers = inv.servers_for_user(&UserId("alice".into())).await.unwrap();
    let ids: std::collections::HashSet<String> = servers.iter().map(|s| s.id.0.clone()).collect();
    assert!(
        ids.contains("existing-other"),
        "alice's grant on existing-other MUST survive overwrite — got: {ids:?}"
    );
    assert!(
        ids.contains("srv-bash"),
        "alice should ALSO be granted on the newly-migrated bash server"
    );
    assert_eq!(
        outcome.other_server_grants_preserved,
        vec!["alice|existing-other".to_string()],
        "outcome must report the preserved grant for audit visibility"
    );
}

#[tokio::test]
async fn apply_with_overwrite_updates_existing_server_address() {
    use vpnctl_core::{KernelId, ProtocolId, Server, ServerId};
    let inv = open_test_inv().await;
    inv.add_server(&Server {
        id: ServerId("srv-bash".into()),
        address: "1.2.3.4".into(),
        ssh_port: 9999,
        ssh_user: "old-user".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("vless+reality".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();

    let plan = plan_with_one_user("srv-bash", "alice", "uuid-x");
    let outcome = apply_migration_plan(&inv, &plan, true).await.unwrap();
    assert!(outcome.server_already_existed);
    assert!(
        outcome.server_address_updated,
        "address must be updated under --overwrite-existing"
    );

    let after = inv
        .get_server(&ServerId("srv-bash".into()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.address, "203.0.113.1");
    assert_eq!(after.ssh_port, 22);
    assert_eq!(after.ssh_user, "root");
}

#[test]
fn build_plan_real_fixture_end_to_end() {
    let inv = parse_bash_inventory_env(include_str!(
        "../../tests/fixtures/bash_migration/198.51.100.93.env"
    ))
    .unwrap();
    let data = parse_bash_singbox(
        include_str!("../../tests/fixtures/bash_migration/config.json"),
        include_str!("../../tests/fixtures/bash_migration/keys.env"),
    )
    .unwrap();
    let plan = build_migration_plan(Some("vps-is-01".into()), &inv, &data, fake_token).unwrap();
    assert_eq!(plan.server.id.0, "vps-is-01");
    assert_eq!(plan.users_to_import.len(), 23);
    assert_eq!(plan.skipped.len(), 9);
    assert!(
        plan.users_to_import
            .iter()
            .all(|u| u.tuic_password.is_none())
    );
    let pids: Vec<&str> = plan
        .server
        .enabled_protocols
        .iter()
        .map(|p| p.0.as_str())
        .collect();
    assert_eq!(pids, vec!["vless+reality"]);
    assert!(plan.server_secrets.contains_key("vless.public_key"));
    assert!(plan.server_secrets.contains_key("vless.short_id"));
    assert!(plan.server_secrets.contains_key("vless.private_key"));
    assert_eq!(plan.grants.len(), 23);
}

#[tokio::test]
async fn overwrite_uuid_conflict_preserves_user_and_grants_atomically() {
    use vpnctl_core::UserId;
    let inv = open_test_inv().await;
    let original = plan_with_one_user("srv-a", "alice", "uuid-alice");
    apply_migration_plan(&inv, &original, false).await.unwrap();
    let bob = plan_with_one_user("srv-b", "bob", "uuid-bob");
    apply_migration_plan(&inv, &bob, false).await.unwrap();
    let before: Vec<(String, Option<String>, String, Option<String>)> = sqlx::query_as(
        "SELECT server_id, client_uuid, created_at, granted_at FROM grants WHERE user_id = 'alice'",
    )
    .fetch_all(&inv.pool)
    .await
    .unwrap();
    let audit_before = inv.recent_audit(100).await.unwrap().len();
    let mut conflicting = original.clone();
    conflicting.users_to_import[0].uuid = "uuid-bob".into();
    assert!(
        apply_migration_plan(&inv, &conflicting, true)
            .await
            .is_err()
    );
    let alice = inv
        .get_user(&UserId("alice".into()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(alice.uuid, "uuid-alice");
    assert_eq!(alice.sub_token, original.users_to_import[0].sub_token);
    let after: Vec<(String, Option<String>, String, Option<String>)> = sqlx::query_as(
        "SELECT server_id, client_uuid, created_at, granted_at FROM grants WHERE user_id = 'alice'",
    )
    .fetch_all(&inv.pool)
    .await
    .unwrap();
    assert_eq!(before, after);
    assert_eq!(inv.recent_audit(100).await.unwrap().len(), audit_before);
}

#[tokio::test]
async fn sequential_plans_preserve_each_servers_effective_uuid() {
    for overwrite in [false, true] {
        let inv = open_test_inv().await;
        let first = plan_with_one_user("srv-a", "alice", "00000000-0000-0000-0000-000000000001");
        let second = plan_with_one_user("srv-b", "alice", "00000000-0000-0000-0000-000000000002");
        apply_migration_plan(&inv, &first, overwrite).await.unwrap();
        apply_migration_plan(&inv, &second, overwrite)
            .await
            .unwrap();
        for plan in [&first, &second] {
            let users = inv.users_for_server(&plan.server.id).await.unwrap();
            assert_eq!(users.len(), 1);
            assert_eq!(users[0].uuid, plan.users_to_import[0].uuid);
        }
    }
}

#[tokio::test]
async fn conflicting_imported_grant_leaves_no_global_uuid_grant_or_audit() {
    let inv = open_test_inv().await;
    let alice = plan_with_one_user("srv-a", "alice", "00000000-0000-0000-0000-000000000001");
    let bob = plan_with_one_user("srv-b", "bob", "00000000-0000-0000-0000-000000000002");
    apply_migration_plan(&inv, &alice, false).await.unwrap();
    apply_migration_plan(&inv, &bob, false).await.unwrap();
    let conflicting = plan_with_one_user("srv-b", "alice", &bob.users_to_import[0].uuid);
    let audit_before = inv.recent_audit(100).await.unwrap().len();
    assert!(
        apply_migration_plan(&inv, &conflicting, false)
            .await
            .is_err()
    );
    assert_eq!(
        inv.client_uuid_for(&alice.users_to_import[0].id, &bob.server.id)
            .await
            .unwrap(),
        None
    );
    assert_eq!(inv.recent_audit(100).await.unwrap().len(), audit_before);
}

#[tokio::test]
async fn imported_grant_checks_imported_uuid_instead_of_global_uuid() {
    let inv = open_test_inv().await;
    let alice = plan_with_one_user("srv-a", "alice", "00000000-0000-0000-0000-000000000001");
    let bob = plan_with_one_user("srv-b", "bob", "00000000-0000-0000-0000-000000000002");
    apply_migration_plan(&inv, &alice, false).await.unwrap();
    apply_migration_plan(&inv, &bob, false).await.unwrap();
    inv.set_grant_client_uuid(
        &bob.users_to_import[0].id,
        &bob.server.id,
        &alice.users_to_import[0].uuid,
    )
    .await
    .unwrap();
    let imported = plan_with_one_user("srv-b", "alice", "00000000-0000-0000-0000-000000000003");
    apply_migration_plan(&inv, &imported, false).await.unwrap();
    assert_eq!(
        inv.client_uuid_for(&alice.users_to_import[0].id, &bob.server.id)
            .await
            .unwrap(),
        Some(imported.users_to_import[0].uuid.clone())
    );
    let audit_before = inv.recent_audit(100).await.unwrap().len();
    apply_migration_plan(&inv, &imported, false).await.unwrap();
    assert_eq!(inv.recent_audit(100).await.unwrap().len(), audit_before);
}

#[tokio::test]
async fn existing_secrets_require_overwrite_and_noop_import_is_not_audited() {
    let inv = open_test_inv().await;
    let mut plan = plan_with_one_user("srv-a", "alice", "uuid-alice");
    apply_migration_plan(&inv, &plan, false).await.unwrap();
    let original = inv.list_server_secrets(&plan.server.id).await.unwrap();
    for value in plan.server_secrets.values_mut() {
        *value = "replacement".into();
    }
    let audit_before = inv.recent_audit(100).await.unwrap().len();
    let outcome = apply_migration_plan(&inv, &plan, false).await.unwrap();
    assert_eq!(outcome.secrets_set, 0);
    assert_eq!(
        inv.list_server_secrets(&plan.server.id).await.unwrap(),
        original
    );
    assert_eq!(inv.recent_audit(100).await.unwrap().len(), audit_before);
    let outcome = apply_migration_plan(&inv, &plan, true).await.unwrap();
    assert_eq!(outcome.secrets_set, plan.server_secrets.len());
    assert_eq!(
        inv.list_server_secrets(&plan.server.id).await.unwrap(),
        plan.server_secrets
    );
}

#[tokio::test]
async fn import_without_overwrite_keeps_an_existing_pinned_grant_uuid() {
    let inv = open_test_inv().await;
    let first = plan_with_one_user("srv-a", "alice", "00000000-0000-0000-0000-000000000001");
    apply_migration_plan(&inv, &first, false).await.unwrap();
    let user = &first.users_to_import[0].id;
    let pinned = "00000000-0000-0000-0000-00000000000b";
    inv.set_grant_client_uuid(user, &first.server.id, pinned)
        .await
        .unwrap();
    let audit_before = inv.recent_audit(100).await.unwrap().len();
    let stale = plan_with_one_user("srv-a", "alice", "00000000-0000-0000-0000-00000000000c");
    apply_migration_plan(&inv, &stale, false).await.unwrap();
    assert_eq!(
        inv.client_uuid_for(user, &first.server.id).await.unwrap(),
        Some(pinned.to_string()),
        "the live node accepts the pinned UUID; an import must not replace it"
    );
    assert_eq!(inv.recent_audit(100).await.unwrap().len(), audit_before);
}
