#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;

// ── Parser tests ────────────────────────────────────────────────

#[test]
fn parse_bash_inventory_env_real_fixture() {
    let s = include_str!("../../tests/fixtures/bash_migration/104.194.156.93.env");
    let inv = parse_bash_inventory_env(s).unwrap();
    assert_eq!(inv.server_ip, "104.194.156.93");
    assert_eq!(inv.ssh_port, 2222);
    assert_eq!(
        inv.reality_public,
        "gDawCMB0X6iGXZkG8nZIFW5TaaW29x0DMzWijN-gc2A"
    );
    assert_eq!(inv.short_id, "d86e92a0c6dd2271");
    // 20 names in the production .env at recon time.
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
    // 23 VLESS, 9 TUIC, names don't overlap — recon-confirmed
    // shape from production 104.194.156.93 (sanitised).
    assert_eq!(
        data.vless_users.len(),
        23,
        "expected 23 VLESS users from 104 fixture"
    );
    assert_eq!(data.tuic_users.len(), 9, "expected 9 TUIC users");
    // REALITY_PRIVATE present (sanitised to EXAMPLE_REDACTED).
    assert!(
        data.reality_private
            .as_deref()
            .unwrap_or("")
            .starts_with("EXAMPLE_REDACTED")
    );
    // The first VLESS inbound (port 443) is picked, NOT the
    // secondary `vless-reality-2083` — both have 23 users so
    // the count alone wouldn't catch a bug; we'd need a uuid
    // check. Both inbounds happen to mirror users so we don't
    // need to discriminate further here (planner's warning
    // covers the "second inbound exists" diagnostic).
}

#[test]
fn parse_bash_singbox_skips_non_vless_non_tuic_inbounds() {
    // A config with ONLY a socks5 inbound returns empty vlessv +
    // tuic lists, not an error.
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

// ── Planner tests ───────────────────────────────────────────────

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
    // alex got both protocols, bob only VLESS.
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
    // Protocol list contains tuic-v5 because at least one user has it.
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
    // 'legacy-pc' must NOT be in the import set OR have a grant.
    assert!(plan.users_to_import.iter().all(|u| u.id.0 != "legacy-pc"));
    assert!(plan.grants.iter().all(|(uid, _)| uid.0 != "legacy-pc"));
}

#[test]
fn build_plan_warns_on_vless_tuic_uuid_split_identity_imports_vless_only() {
    // 2026-05-17 policy update: split-identity (same name,
    // different uuids per protocol) is no longer fatal — bash
    // 93.95.226.167 has this shape historically. The planner
    // imports VLESS and warns about the TUIC mismatch. The
    // fixture deliberately mixes a split-identity user ('alex')
    // with a happy-path user ('bob', matching uuids) so the
    // assertions distinguish "tuic_password dropped for THIS
    // user" from "tuic_password dropped for everyone" (the
    // inverted-impl trap the original test was vulnerable to).
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

    // alex IS imported (with VLESS uuid + NO tuic_password) — the
    // split-identity branch must NOT silently merge.
    let alex = plan
        .users_to_import
        .iter()
        .find(|u| u.id.0 == "alex")
        .unwrap();
    assert_eq!(alex.uuid, "u-alex-vless-aaaaaaaa");
    assert_eq!(alex.tuic_password, None);

    // bob IS imported with tuic_password Some(...) — positive
    // control that the happy-path merge still works. Without
    // this, a bug that dropped tuic_password for ALL users
    // would not be caught.
    let bob = plan
        .users_to_import
        .iter()
        .find(|u| u.id.0 == "bob")
        .unwrap();
    assert_eq!(bob.uuid, "u-bob-shared-bbbbbbbb");
    assert_eq!(bob.tuic_password.as_deref(), Some("pw-bob"));

    // The split-identity is surfaced AS A WARNING, exposing the
    // 8-char prefixes (pin the new slicing path):
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

    // AND mirrored into `skipped` so dry-run's per-user table
    // lists every non-imported entity in one place.
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

    // tuic-v5 IS still enabled (bob has a working tuic_password).
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
    inv.users.push("ghost".into()); // not in vless_users below
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
    // vless.private_key NOT in secrets when missing.
    assert!(!plan.server_secrets.contains_key("vless.private_key"));
    // Public half + short_id ARE present (we have those from inv).
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
    assert_eq!(derive_server_id_from_ip("104.194.156.93"), "104.194.156.93");
}

#[test]
fn derive_server_id_replaces_ipv6_colons_with_hyphens() {
    assert_eq!(derive_server_id_from_ip("2001:db8::1"), "2001-db8--1");
}

// ── Apply tests ─────────────────────────────────────────────────
//
// Spec-test the actual mutation path, not just the planner.
// Each test uses a fresh tempdir SqliteInventory so audit + grant
// + user state is reset between cases.

async fn open_test_inv() -> crate::SqliteInventory {
    let dir = tempfile::tempdir().unwrap();
    std::mem::forget(dir); // leak for the test process lifetime
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
async fn apply_with_overwrite_replaces_existing_user_uuid() {
    use vpnctl_core::{User, UserId};
    let inv = open_test_inv().await;
    // Pre-seed a user with a DIFFERENT uuid than the migration
    // plan brings. Without overwrite the migration must keep
    // the existing uuid; WITH overwrite it must replace it.
    inv.add_user(&User {
        id: UserId("alice".into()),
        uuid: "OLD-uuid-1234".into(),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: Some("stale".into()),
        vpn_router_device_id: None,
        disabled: false,
    })
    .await
    .unwrap();

    let plan = plan_with_one_user("srv-b", "alice", "NEW-uuid-9999");
    // Without overwrite: existing uuid wins.
    let outcome = apply_migration_plan(&inv, &plan, false).await.unwrap();
    assert_eq!(outcome.users_skipped_existing, vec!["alice".to_string()]);
    let after_no_overwrite = inv
        .get_user(&UserId("alice".into()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after_no_overwrite.uuid, "OLD-uuid-1234");
    // With overwrite: bash uuid wins.
    let outcome = apply_migration_plan(&inv, &plan, true).await.unwrap();
    assert_eq!(outcome.users_overwritten, vec!["alice".to_string()]);
    let after_overwrite = inv
        .get_user(&UserId("alice".into()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after_overwrite.uuid, "NEW-uuid-9999");
}

#[tokio::test]
async fn apply_with_overwrite_preserves_user_grants_on_other_servers() {
    // The bug that caused real grant loss on production
    // (review-agent 2026-05-17 critical). `alice` is granted to
    // server `existing-other`; the bash migration imports a
    // DIFFERENT server `srv-bash`. After overwrite-apply alice
    // must STILL be granted on `existing-other` + newly on
    // `srv-bash`.
    use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
    let inv = open_test_inv().await;
    // Seed the OTHER server + user + grant first.
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

    // alice still on existing-other (was preserved).
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
    // Pre-seed `srv-bash` with WRONG address (mimics the real
    // production issue: a wizard-test row with stale IP).
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
    // Reads the sanitised 104.194.156.93 fixtures and builds a
    // plan. Pins the expected counts so a regression in either
    // the parser OR the planner would surface.
    let inv = parse_bash_inventory_env(include_str!(
        "../../tests/fixtures/bash_migration/104.194.156.93.env"
    ))
    .unwrap();
    let data = parse_bash_singbox(
        include_str!("../../tests/fixtures/bash_migration/config.json"),
        include_str!("../../tests/fixtures/bash_migration/keys.env"),
    )
    .unwrap();
    let plan = build_migration_plan(Some("vps-is-01".into()), &inv, &data, fake_token).unwrap();
    // Server id override honoured.
    assert_eq!(plan.server.id.0, "vps-is-01");
    // 23 VLESS users imported (modern scheme).
    assert_eq!(plan.users_to_import.len(), 23);
    // 9 TUIC-only legacy users skipped.
    assert_eq!(plan.skipped.len(), 9);
    // None of the 23 imported users got a tuic_password
    // (names don't overlap with TUIC inbound on 104).
    assert!(
        plan.users_to_import
            .iter()
            .all(|u| u.tuic_password.is_none())
    );
    // → protocol list excludes tuic-v5.
    let pids: Vec<&str> = plan
        .server
        .enabled_protocols
        .iter()
        .map(|p| p.0.as_str())
        .collect();
    assert_eq!(pids, vec!["vless+reality"]);
    // Secrets cover vless public/short_id + private (sanitised).
    assert!(plan.server_secrets.contains_key("vless.public_key"));
    assert!(plan.server_secrets.contains_key("vless.short_id"));
    assert!(plan.server_secrets.contains_key("vless.private_key"));
    // 23 grants (one per imported user × server).
    assert_eq!(plan.grants.len(), 23);
}
