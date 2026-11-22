#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashSet;

use tempfile::TempDir;
use vpnctl_core::{KernelId, Server, ServerId, User, UserId};
use vpnctl_inventory::SqliteInventory;

async fn open(dir: &TempDir) -> SqliteInventory {
    SqliteInventory::open(&dir.path().join("inventory.db"))
        .await
        .expect("open")
}

fn srv(id: &str) -> Server {
    Server {
        id: ServerId(id.into()),
        address: "203.0.113.1".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

fn user(id: &str, n: u32) -> User {
    User {
        id: UserId(id.into()),
        uuid: format!("00000000-0000-0000-0000-{n:012}"),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    }
}

#[tokio::test]
async fn empty_granted_list_returns_empty() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let got = inv
        .servers_pending_deploy_for_user(&UserId("anybody".into()), &[])
        .await
        .unwrap();
    assert!(got.is_empty(), "empty input → empty output");
}

#[tokio::test]
async fn back_to_back_mutation_after_deploy_is_pending_without_clock_delay() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let sid = ServerId("fast".into());
    let uid = UserId("fast-user".into());
    inv.audit("admin", "server.deploy", Some(&sid.0), None)
        .await
        .unwrap();
    inv.audit("admin", "user.wireguard.regen", Some(&uid.0), None)
        .await
        .unwrap();
    assert_eq!(
        inv.servers_pending_deploy_for_user(&uid, std::slice::from_ref(&sid))
            .await
            .unwrap(),
        vec![sid]
    );
}

#[tokio::test]
async fn user_with_zero_audit_rows_returns_empty() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("legacy", 1)).await.unwrap();
    inv.add_server(&srv("alpha")).await.unwrap();
    inv.grant(&UserId("legacy".into()), &ServerId("alpha".into()))
        .await
        .unwrap();
    let got = inv
        .servers_pending_deploy_for_user(&UserId("legacy".into()), &[ServerId("alpha".into())])
        .await
        .unwrap();
    assert!(
        got.is_empty(),
        "user with zero audit rows must NOT surface as pending"
    );
}

#[tokio::test]
async fn server_with_no_deploy_row_is_pending_when_user_has_any_mutation() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("alice", 2)).await.unwrap();
    inv.audit("admin", "user.add", Some("alice"), None)
        .await
        .unwrap();
    let got = inv
        .servers_pending_deploy_for_user(
            &UserId("alice".into()),
            &[ServerId("never-deployed".into())],
        )
        .await
        .unwrap();
    assert_eq!(got.len(), 1, "no-deploy server must be flagged as pending");
    assert_eq!(got[0].0, "never-deployed");
}

#[tokio::test]
async fn server_deployed_after_user_mutation_is_not_pending() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("bob", 3)).await.unwrap();
    inv.audit("admin", "user.add", Some("bob"), None)
        .await
        .unwrap();
    inv.audit("admin", "server.deploy", Some("beta"), None)
        .await
        .unwrap();
    let got = inv
        .servers_pending_deploy_for_user(&UserId("bob".into()), &[ServerId("beta".into())])
        .await
        .unwrap();
    assert!(
        got.is_empty(),
        "deploy newer than user mutation → not pending; got: {got:?}"
    );
}

#[tokio::test]
async fn server_deployed_before_user_mutation_is_pending() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("carol", 4)).await.unwrap();
    inv.audit("admin", "server.deploy", Some("gamma"), None)
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    inv.audit("admin", "user.add", Some("carol"), None)
        .await
        .unwrap();
    let got = inv
        .servers_pending_deploy_for_user(&UserId("carol".into()), &[ServerId("gamma".into())])
        .await
        .unwrap();
    assert_eq!(got.len(), 1, "user.add after deploy → pending");
    assert_eq!(got[0].0, "gamma");
}

#[tokio::test]
async fn mixed_servers_returns_only_the_pending_ones() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("dave", 5)).await.unwrap();
    inv.audit("admin", "server.deploy", Some("old"), None)
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    inv.audit("admin", "user.add", Some("dave"), None)
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    inv.audit("admin", "server.deploy", Some("fresh"), None)
        .await
        .unwrap();
    let got = inv
        .servers_pending_deploy_for_user(
            &UserId("dave".into()),
            &[
                ServerId("old".into()),
                ServerId("fresh".into()),
                ServerId("nodeploy".into()),
            ],
        )
        .await
        .unwrap();
    let ids: Vec<&str> = got.iter().map(|s| s.0.as_str()).collect();
    assert!(ids.contains(&"old"), "old deploy → pending");
    assert!(ids.contains(&"nodeploy"), "no deploy ever → pending");
    assert!(!ids.contains(&"fresh"), "fresh deploy → NOT pending");
}

#[tokio::test]
async fn enable_disable_count_as_user_mutations() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("eve", 6)).await.unwrap();
    inv.audit("admin", "user.add", Some("eve"), None)
        .await
        .unwrap();
    inv.audit("admin", "server.deploy", Some("srv"), None)
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    inv.audit("admin", "user.disable", Some("eve"), None)
        .await
        .unwrap();
    let got = inv
        .servers_pending_deploy_for_user(&UserId("eve".into()), &[ServerId("srv".into())])
        .await
        .unwrap();
    assert_eq!(
        got.len(),
        1,
        "user.disable after deploy must mark server pending"
    );
}

#[tokio::test]
async fn server_side_detector_tracks_membership_vs_deploy() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;

    assert!(
        !inv.server_pending_deploy(&ServerId("srv".into()))
            .await
            .unwrap()
    );

    inv.audit(
        "admin",
        "user.grant",
        Some("alice"),
        Some(&serde_json::json!({ "server": "srv", "source": "test" })),
    )
    .await
    .unwrap();
    assert!(
        inv.server_pending_deploy(&ServerId("srv".into()))
            .await
            .unwrap()
    );

    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    inv.audit("admin", "server.deploy", Some("srv"), None)
        .await
        .unwrap();
    assert!(
        !inv.server_pending_deploy(&ServerId("srv".into()))
            .await
            .unwrap()
    );

    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    inv.audit(
        "admin",
        "user.revoke",
        Some("alice"),
        Some(&serde_json::json!({ "server": "srv", "source": "test" })),
    )
    .await
    .unwrap();
    assert!(
        inv.server_pending_deploy(&ServerId("srv".into()))
            .await
            .unwrap()
    );

    assert!(
        !inv.server_pending_deploy(&ServerId("other".into()))
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn failed_deploy_row_does_not_clear_user_side_pending() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("frank", 7)).await.unwrap();
    inv.audit("admin", "user.grant", Some("frank"), None)
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    inv.audit(
        "admin",
        "server.deploy.failed",
        Some("srv"),
        Some(&serde_json::json!({
            "ssh_errors": ["sing-box: apply_config failed: node unreachable"],
            "ssh_skip_reason": null,
        })),
    )
    .await
    .unwrap();
    let got = inv
        .servers_pending_deploy_for_user(&UserId("frank".into()), &[ServerId("srv".into())])
        .await
        .unwrap();
    assert_eq!(
        got.len(),
        1,
        "a FAILED deploy must not count as a baseline — server stays pending"
    );

    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    inv.audit(
        "admin",
        "server.deploy",
        Some("srv"),
        Some(&serde_json::json!({
            "ssh_errors": [],
            "ssh_skip_reason": null,
        })),
    )
    .await
    .unwrap();
    let got = inv
        .servers_pending_deploy_for_user(&UserId("frank".into()), &[ServerId("srv".into())])
        .await
        .unwrap();
    assert!(got.is_empty(), "successful deploy clears pending");
}

#[tokio::test]
async fn skipped_deploy_row_does_not_clear_user_side_pending() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("grace", 8)).await.unwrap();
    inv.audit("admin", "user.grant", Some("grace"), None)
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    inv.audit(
        "admin",
        "server.deploy.skipped",
        Some("srv"),
        Some(&serde_json::json!({
            "ssh_errors": [],
            "ssh_skip_reason": "deploy key absent; see /admin/settings",
        })),
    )
    .await
    .unwrap();
    let got = inv
        .servers_pending_deploy_for_user(&UserId("grace".into()), &[ServerId("srv".into())])
        .await
        .unwrap();
    assert_eq!(
        got.len(),
        1,
        "a SKIPPED deploy must not count as a baseline — server stays pending"
    );
}

#[tokio::test]
async fn failed_deploy_row_does_not_clear_server_side_pending() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.audit(
        "admin",
        "user.revoke",
        Some("alice"),
        Some(&serde_json::json!({ "server": "srv", "source": "test" })),
    )
    .await
    .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    inv.audit(
        "admin",
        "server.deploy.failed",
        Some("srv"),
        Some(&serde_json::json!({
            "ssh_errors": ["sing-box: apply_config failed: refusing to REMOVE 1 user UUID(s)"],
            "ssh_skip_reason": null,
        })),
    )
    .await
    .unwrap();
    assert!(
        inv.server_pending_deploy(&ServerId("srv".into()))
            .await
            .unwrap(),
        "failed deploy must leave the server-side pending flag up"
    );

    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    inv.audit(
        "admin",
        "server.deploy",
        Some("srv"),
        Some(&serde_json::json!({ "ssh_errors": [], "ssh_skip_reason": null })),
    )
    .await
    .unwrap();
    assert!(
        !inv.server_pending_deploy(&ServerId("srv".into()))
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn legacy_baseline_rows_without_payload_fields_still_count_as_success() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("henry", 9)).await.unwrap();
    inv.audit("admin", "user.grant", Some("henry"), None)
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    inv.audit("admin", "server.deploy", Some("srv"), None)
        .await
        .unwrap();
    let got = inv
        .servers_pending_deploy_for_user(&UserId("henry".into()), &[ServerId("srv".into())])
        .await
        .unwrap();
    assert!(
        got.is_empty(),
        "payload-less baseline must count as success"
    );

    inv.add_user(&user("iris", 10)).await.unwrap();
    inv.audit("admin", "user.grant", Some("iris"), None)
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    inv.audit(
        "admin",
        "server.deploy",
        Some("wiz"),
        Some(&serde_json::json!({ "kernels": ["sing-box"], "via": "wizard-bootstrap" })),
    )
    .await
    .unwrap();
    let got = inv
        .servers_pending_deploy_for_user(&UserId("iris".into()), &[ServerId("wiz".into())])
        .await
        .unwrap();
    assert!(
        got.is_empty(),
        "wizard-bootstrap success row must count as a baseline"
    );
}

#[tokio::test]
async fn grant_scoped_by_payload_server_does_not_flag_other_servers() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("brat", 7)).await.unwrap();
    for sid in ["old-node", "new-node"] {
        inv.add_server(&srv(sid)).await.unwrap();
        inv.grant(&UserId("brat".into()), &ServerId(sid.into()))
            .await
            .unwrap();
    }
    for sid in ["old-node", "new-node"] {
        inv.audit(
            "admin",
            "server.deploy",
            Some(sid),
            Some(&serde_json::json!({ "ssh_errors": [], "ssh_skip_reason": null })),
        )
        .await
        .unwrap();
    }
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    inv.audit(
        "admin",
        "user.grant",
        Some("brat"),
        Some(&serde_json::json!({ "server": "new-node", "source": "test" })),
    )
    .await
    .unwrap();
    let got = inv
        .servers_pending_deploy_for_user(
            &UserId("brat".into()),
            &[ServerId("old-node".into()), ServerId("new-node".into())],
        )
        .await
        .unwrap();
    assert_eq!(
        got,
        vec![ServerId("new-node".into())],
        "only the server named by payload.server may go pending"
    );
}

#[tokio::test]
async fn server_agnostic_mutation_still_flags_all_servers() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("pausa", 8)).await.unwrap();
    for sid in ["n1", "n2"] {
        inv.add_server(&srv(sid)).await.unwrap();
        inv.grant(&UserId("pausa".into()), &ServerId(sid.into()))
            .await
            .unwrap();
        inv.audit(
            "admin",
            "server.deploy",
            Some(sid),
            Some(&serde_json::json!({ "ssh_errors": [], "ssh_skip_reason": null })),
        )
        .await
        .unwrap();
    }
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    inv.audit("admin", "user.disable", Some("pausa"), None)
        .await
        .unwrap();
    let got = inv
        .servers_pending_deploy_for_user(
            &UserId("pausa".into()),
            &[ServerId("n1".into()), ServerId("n2".into())],
        )
        .await
        .unwrap();
    assert_eq!(got.len(), 2, "disable must flag every granted server");
}

#[tokio::test]
async fn boosty_bridge_flips_count_as_user_mutations() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("sub", 11)).await.unwrap();
    inv.add_server(&srv("node")).await.unwrap();
    inv.grant(&UserId("sub".into()), &ServerId("node".into()))
        .await
        .unwrap();
    inv.audit(
        "admin",
        "server.deploy",
        Some("node"),
        Some(&serde_json::json!({ "ssh_errors": [], "ssh_skip_reason": null })),
    )
    .await
    .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;

    inv.audit("boosty-bridge", "boosty.enable", Some("sub"), None)
        .await
        .unwrap();
    let got = inv
        .servers_pending_deploy_for_user(&UserId("sub".into()), &[ServerId("node".into())])
        .await
        .unwrap();
    assert_eq!(got.len(), 1, "boosty.enable after deploy → pending");

    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    inv.audit(
        "admin",
        "server.deploy",
        Some("node"),
        Some(&serde_json::json!({ "ssh_errors": [], "ssh_skip_reason": null })),
    )
    .await
    .unwrap();
    let got = inv
        .servers_pending_deploy_for_user(&UserId("sub".into()), &[ServerId("node".into())])
        .await
        .unwrap();
    assert!(got.is_empty(), "deploy after the flip clears pending");

    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    inv.audit("boosty-bridge", "boosty.disable", Some("sub"), None)
        .await
        .unwrap();
    let got = inv
        .servers_pending_deploy_for_user(&UserId("sub".into()), &[ServerId("node".into())])
        .await
        .unwrap();
    assert_eq!(got.len(), 1, "boosty.disable after deploy → pending");
}

#[tokio::test]
async fn wireguard_regen_counts_as_user_mutation() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("wg", 20)).await.unwrap();
    inv.add_server(&srv("node")).await.unwrap();
    inv.grant(&UserId("wg".into()), &ServerId("node".into()))
        .await
        .unwrap();
    inv.audit(
        "admin",
        "server.deploy",
        Some("node"),
        Some(&serde_json::json!({ "ssh_errors": [] })),
    )
    .await
    .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;

    inv.audit("admin", "user.wireguard.regen", Some("wg"), None)
        .await
        .unwrap();
    let got = inv
        .servers_pending_deploy_for_user(&UserId("wg".into()), &[ServerId("node".into())])
        .await
        .unwrap();
    assert_eq!(got.len(), 1, "wireguard.regen after deploy → pending");

    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    inv.audit(
        "admin",
        "server.deploy",
        Some("node"),
        Some(&serde_json::json!({ "ssh_errors": [] })),
    )
    .await
    .unwrap();
    let got = inv
        .servers_pending_deploy_for_user(&UserId("wg".into()), &[ServerId("node".into())])
        .await
        .unwrap();
    assert!(got.is_empty(), "deploy after regen clears pending");
}

#[tokio::test]
async fn tuic_mint_counts_as_user_mutation() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    inv.add_user(&user("tuic", 21)).await.unwrap();
    inv.add_server(&srv("node")).await.unwrap();
    inv.grant(&UserId("tuic".into()), &ServerId("node".into()))
        .await
        .unwrap();
    inv.audit(
        "admin",
        "server.deploy",
        Some("node"),
        Some(&serde_json::json!({ "ssh_errors": [] })),
    )
    .await
    .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;

    inv.audit("admin", "user.mint_tuic_password", Some("tuic"), None)
        .await
        .unwrap();
    let got = inv
        .servers_pending_deploy_for_user(&UserId("tuic".into()), &[ServerId("node".into())])
        .await
        .unwrap();
    assert_eq!(got.len(), 1, "mint_tuic_password after deploy → pending");
}

#[tokio::test]
async fn protocol_kernel_mutations_raise_server_pending_deploy() {
    let actions = [
        "server.protocol.enable",
        "server.protocol.disable",
        "server.kernel.enable",
        "server.kernel.disable",
    ];
    for action in actions {
        let dir = TempDir::new().unwrap();
        let inv = open(&dir).await;
        inv.add_server(&srv("srv")).await.unwrap();
        inv.audit(
            "admin",
            "server.deploy",
            Some("srv"),
            Some(&serde_json::json!({ "ssh_errors": [] })),
        )
        .await
        .unwrap();
        assert!(
            !inv.server_pending_deploy(&ServerId("srv".into()))
                .await
                .unwrap(),
            "{action}: baseline deploy → not pending"
        );
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;

        inv.audit("admin", action, Some("srv"), None).await.unwrap();
        assert!(
            inv.server_pending_deploy(&ServerId("srv".into()))
                .await
                .unwrap(),
            "{action}: mutation after deploy → pending"
        );

        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        inv.audit(
            "admin",
            "server.deploy",
            Some("srv"),
            Some(&serde_json::json!({ "ssh_errors": [] })),
        )
        .await
        .unwrap();
        assert!(
            !inv.server_pending_deploy(&ServerId("srv".into()))
                .await
                .unwrap(),
            "{action}: deploy after mutation clears pending"
        );
    }
}

// servers_deployed_since_grant: current grants (created_at, ms) covered by a
// later successful server.deploy on that exact node; fixture timestamps pinned.

const G0: &str = "2026-01-02T03:04:05.000Z"; // grant creation instant
const D0: &str = "2026-01-02T03:04:06.000Z"; // ordinary later deploy
const R0: &str = "2026-01-02T03:04:07.000Z"; // revoke
const G1: &str = "2026-01-02T03:04:08.000Z"; // regrant / later grant
const D1: &str = "2026-01-02T03:04:09.000Z"; // deploy after regrant
const MUT: &str = "2026-01-02T03:04:10.000Z"; // later user mutation
const T_OLD: &str = "2025-12-30T00:00:00.000Z"; // previous grant cycle
const NODES: &str = "happy idle failed skipped stale shared regrant-stale \
                     regrant-fresh tie-ordered tie-reversed legacy-tie imported";

struct DeployFixture {
    _dir: TempDir,
    inv: SqliteInventory,
    db: sqlx::sqlite::SqlitePool,
}

impl DeployFixture {
    async fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let inv = open(&dir).await;
        let dsn = format!("sqlite://{}", dir.path().join("inventory.db").display());
        let db = sqlx::sqlite::SqlitePool::connect(&dsn).await.unwrap();
        Self { _dir: dir, inv, db }
    }

    async fn grant_at(&self, uid: &str, sid: &str, at: &str) {
        let (uid, sid) = (UserId(uid.into()), ServerId(sid.into()));
        self.inv.grant(&uid, &sid).await.unwrap();
        sqlx::query("UPDATE grants SET created_at=?1 WHERE user_id=?2 AND server_id=?3")
            .bind(at)
            .bind(&uid.0)
            .bind(&sid.0)
            .execute(&self.db)
            .await
            .unwrap();
    }

    async fn audit_at(&self, at: &str, action: &str, target: &str, payload: Option<&str>) {
        sqlx::query(
            "INSERT INTO audit_log(ts,actor,action,target,payload) VALUES(?1,'admin',?2,?3,?4)",
        )
        .bind(at)
        .bind(action)
        .bind(target)
        .bind(payload)
        .execute(&self.db)
        .await
        .unwrap();
    }

    async fn deploy(&self, at: &str, sid: &str) {
        self.audit_at(at, "server.deploy", sid, None).await;
    }

    async fn grant_audit(&self, at: &str, sid: &str) {
        let p = format!(r#"{{"server":"{sid}"}}"#);
        self.audit_at(at, "user.grant", "alice", Some(&p)).await;
    }

    async fn deployed_since(&self, uid: &str) -> HashSet<ServerId> {
        let uid = UserId(uid.into());
        self.inv.servers_deployed_since_grant(&uid).await.unwrap()
    }

    fn assert_ids(got: &HashSet<ServerId>, want: &str) {
        let mut ids: Vec<&str> = got.iter().map(|s| s.0.as_str()).collect();
        ids.sort_unstable();
        assert_eq!(ids.join(" "), want);
    }
}

async fn seeded() -> DeployFixture {
    let f = DeployFixture::new().await;
    for (uid, n) in [("alice", 60), ("bob", 61), ("carol", 62)] {
        f.inv.add_user(&user(uid, n)).await.unwrap();
    }
    for sid in NODES.split_whitespace().chain(["undeployed", "neighbour"]) {
        f.inv.add_server(&srv(sid)).await.unwrap();
    }
    for sid in NODES.split_whitespace() {
        f.grant_at("alice", sid, G0).await;
    }
    f.grant_at("bob", "shared", G0).await;
    f.grant_at("bob", "neighbour", G0).await;

    // The current grant postdates its only deploy.
    f.deploy(D0, "undeployed").await;
    f.grant_at("alice", "undeployed", G1).await;
    for sid in ["happy", "shared", "imported"] {
        f.deploy(D0, sid).await;
    }
    f.audit_at(D0, "server.deploy.failed", "failed", None).await;
    f.audit_at(D0, "server.deploy.skipped", "skipped", None)
        .await;
    f.audit_at(D0, "server.deploy.stale", "stale", None).await;

    // Revoke/regrant: the old deploy is historical; a newer one re-qualifies.
    for sid in ["regrant-stale", "regrant-fresh"] {
        f.deploy(D0, sid).await;
        let uid = UserId("alice".into());
        f.inv.revoke(&uid, &ServerId(sid.into())).await.unwrap();
        f.grant_at("alice", sid, G1).await;
    }
    let q = "UPDATE audit_log SET ts=?1 WHERE action='user.revoke'";
    sqlx::query(q).bind(R0).execute(&f.db).await.unwrap();
    f.deploy(D1, "regrant-fresh").await;

    // Same-millisecond ties: a matching grant audit ordered first is evidence.
    f.grant_audit(G0, "tie-ordered").await;
    f.deploy(G0, "tie-ordered").await;
    f.deploy(G0, "tie-reversed").await;
    f.grant_audit(G0, "tie-reversed").await;
    f.deploy(G0, "legacy-tie").await;
    f.grant_audit(T_OLD, "legacy-tie").await;

    // Imported grant: no grant audit and no granted_at display date.
    let q = "UPDATE grants SET granted_at=NULL WHERE user_id='alice' AND server_id='imported'";
    sqlx::query(q).execute(&f.db).await.unwrap();
    f
}

#[tokio::test]
async fn deployed_since_grant_returns_only_qualified_current_grants() {
    let f = seeded().await;
    let changed = f
        .inv
        .grant_audited(
            &UserId("alice".into()),
            &ServerId("happy".into()),
            "admin",
            "test",
        )
        .await
        .unwrap();
    assert!(
        !changed,
        "a no-op grant must preserve the existing deploy evidence"
    );
    DeployFixture::assert_ids(
        &f.deployed_since("alice").await,
        "happy imported regrant-fresh shared tie-ordered",
    );
}

#[tokio::test]
async fn deploy_evidence_is_scoped_to_each_users_own_grants() {
    assert!(
        DeployFixture::new()
            .await
            .deployed_since("alice")
            .await
            .is_empty()
    );
    let f = seeded().await;
    DeployFixture::assert_ids(&f.deployed_since("bob").await, "shared");
    assert!(f.deployed_since("carol").await.is_empty());
    assert!(f.deployed_since("ghost").await.is_empty());
}

#[tokio::test]
async fn same_millisecond_ties_need_an_ordered_grant_audit() {
    let f = seeded().await;
    let got = f.deployed_since("alice").await;
    assert!(got.contains(&ServerId("tie-ordered".into())));
    assert!(!got.contains(&ServerId("tie-reversed".into())));
    assert!(!got.contains(&ServerId("legacy-tie".into())));
    f.deploy(D1, "legacy-tie").await;
    let got = f.deployed_since("alice").await;
    assert!(got.contains(&ServerId("legacy-tie".into())));
}

#[tokio::test]
async fn deploy_since_grant_ignores_later_user_mutations() {
    let f = seeded().await;
    let before = f.deployed_since("alice").await;
    f.audit_at(MUT, "user.wireguard.regen", "alice", None).await;
    let sid = ServerId("happy".into());
    let uid = UserId("alice".into());
    let one = std::slice::from_ref(&sid);
    let pending = f
        .inv
        .servers_pending_deploy_for_user(&uid, one)
        .await
        .unwrap();
    assert_eq!(pending, vec![sid]);
    assert_eq!(f.deployed_since("alice").await, before);
}
