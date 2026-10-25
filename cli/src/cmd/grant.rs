use crate::ui;
use std::path::PathBuf;
use vpnctl_core::{ProtocolId, ServerId, UserId};
use vpnctl_inventory::SqliteInventory;

pub(crate) async fn run_grant(
    user: &str,
    server: &str,
    db_flag: Option<PathBuf>,
) -> anyhow::Result<()> {
    let db_path = ui::resolve_db_path(db_flag)?;
    let inv = SqliteInventory::open(&db_path).await?;

    let uid = UserId(user.to_string());
    let sid = ServerId(server.to_string());

    if inv.get_user(&uid).await?.is_none() {
        return Err(anyhow::anyhow!("no such user: {user}"));
    }
    if inv.get_server(&sid).await?.is_none() {
        return Err(anyhow::anyhow!("no such server: {server}"));
    }

    inv.grant_audited(&uid, &sid, "cli", "cli").await?;
    println!("granted '{user}' access to '{server}'");
    Ok(())
}

pub(crate) async fn run_revoke(
    user: &str,
    server: &str,
    db_flag: Option<PathBuf>,
) -> anyhow::Result<()> {
    let db_path = ui::resolve_db_path(db_flag)?;
    let inv = SqliteInventory::open(&db_path).await?;

    let uid = UserId(user.to_string());
    let sid = ServerId(server.to_string());
    inv.revoke_audited(&uid, &sid, "cli", "cli").await?;
    println!("revoked '{user}' from '{server}'");
    Ok(())
}

pub(crate) async fn run_protocol_disable(
    user: &str,
    server: &str,
    protocol: &str,
    db_flag: Option<PathBuf>,
) -> anyhow::Result<()> {
    let db_path = ui::resolve_db_path(db_flag)?;
    let inv = SqliteInventory::open(&db_path).await?;

    let uid = UserId(user.to_string());
    let sid = ServerId(server.to_string());
    let pid = ProtocolId(protocol.to_string());

    if inv.get_user(&uid).await?.is_none() {
        return Err(anyhow::anyhow!("no such user: {user}"));
    }
    if inv.get_server(&sid).await?.is_none() {
        return Err(anyhow::anyhow!("no such server: {server}"));
    }

    inv.set_grant_protocol_override(&uid, &sid, &pid, true)
        .await?;
    println!("disabled protocol '{protocol}' for '{user}' on '{server}'");
    Ok(())
}

pub(crate) async fn run_protocol_enable(
    user: &str,
    server: &str,
    protocol: &str,
    db_flag: Option<PathBuf>,
) -> anyhow::Result<()> {
    let db_path = ui::resolve_db_path(db_flag)?;
    let inv = SqliteInventory::open(&db_path).await?;

    let uid = UserId(user.to_string());
    let sid = ServerId(server.to_string());
    let pid = ProtocolId(protocol.to_string());

    if inv.get_user(&uid).await?.is_none() {
        return Err(anyhow::anyhow!("no such user: {user}"));
    }
    if inv.get_server(&sid).await?.is_none() {
        return Err(anyhow::anyhow!("no such server: {server}"));
    }

    inv.set_grant_protocol_override(&uid, &sid, &pid, false)
        .await?;
    println!("enabled protocol '{protocol}' for '{user}' on '{server}'");
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {

    use super::*;
    use tempfile::TempDir;
    use vpnctl_core::{KernelId, ProtocolId, Server, User};

    async fn seeded_inv(dir: &TempDir) -> SqliteInventory {
        let inv = SqliteInventory::open(&dir.path().join("inv.db"))
            .await
            .unwrap();
        inv.add_server(&Server {
            id: ServerId("s1".into()),
            address: "203.0.113.5".into(),
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
            uuid: "uuid-alice".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
        inv
    }

    #[tokio::test]
    async fn cli_grant_writes_canonical_user_grant_row_and_marks_pending() {
        let dir = TempDir::new().unwrap();
        let inv = seeded_inv(&dir).await;
        inv.audit("cli", "server.deploy", Some("s1"), None)
            .await
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));

        run_grant("alice", "s1", Some(dir.path().join("inv.db")))
            .await
            .unwrap();

        let entries = inv.recent_audit(10).await.unwrap();
        let g = entries
            .iter()
            .find(|e| e.action == "user.grant")
            .expect("CLI grant must write a user.grant row");
        assert_eq!(g.actor, "cli");
        assert_eq!(g.target.as_deref(), Some("alice"));
        assert_eq!(g.payload.as_ref().unwrap()["server"], "s1");
        assert_eq!(g.payload.as_ref().unwrap()["source"], "cli");

        let pending = inv
            .servers_pending_deploy_for_user(&UserId("alice".into()), &[ServerId("s1".into())])
            .await
            .unwrap();
        assert_eq!(
            pending,
            vec![ServerId("s1".into())],
            "CLI grant must mark the server pending-deploy"
        );
    }

    #[tokio::test]
    async fn cli_revoke_writes_canonical_user_revoke_row_only_on_actual_revoke() {
        let dir = TempDir::new().unwrap();
        let inv = seeded_inv(&dir).await;
        inv.grant(&UserId("alice".into()), &ServerId("s1".into()))
            .await
            .unwrap();
        let db = dir.path().join("inv.db");

        run_revoke("alice", "s1", Some(db.clone())).await.unwrap();
        let entries = inv.recent_audit(10).await.unwrap();
        let r = entries
            .iter()
            .find(|e| e.action == "user.revoke")
            .expect("CLI revoke must write a user.revoke row");
        assert_eq!(r.actor, "cli");
        assert_eq!(r.target.as_deref(), Some("alice"));
        assert_eq!(r.payload.as_ref().unwrap()["server"], "s1");
        assert_eq!(r.payload.as_ref().unwrap()["source"], "cli");

        let before = entries.iter().filter(|e| e.action == "user.revoke").count();
        run_revoke("alice", "s1", Some(db)).await.unwrap();
        let after = inv
            .recent_audit(10)
            .await
            .unwrap()
            .iter()
            .filter(|e| e.action == "user.revoke")
            .count();
        assert_eq!(before, after, "no-op re-revoke must not write a row");
    }

    #[tokio::test]
    async fn cli_protocol_override_requires_grant() {
        let dir = TempDir::new().unwrap();
        let _inv = seeded_inv(&dir).await;
        let db = dir.path().join("inv.db");

        let res_dis = run_protocol_disable("alice", "s1", "vless+reality", Some(db.clone())).await;
        assert!(res_dis.is_err(), "protocol-disable without grant must fail");

        let res_en = run_protocol_enable("alice", "s1", "vless+reality", Some(db)).await;
        assert!(res_en.is_err(), "protocol-enable without grant must fail");
    }

    #[tokio::test]
    async fn cli_protocol_override_no_duplicate_audit_on_noop() {
        let dir = TempDir::new().unwrap();
        let inv = seeded_inv(&dir).await;
        inv.grant(&UserId("alice".into()), &ServerId("s1".into()))
            .await
            .unwrap();
        let db = dir.path().join("inv.db");

        run_protocol_disable("alice", "s1", "vless+reality", Some(db.clone()))
            .await
            .unwrap();
        let entries = inv.recent_audit(20).await.unwrap();
        let overrides: Vec<_> = entries
            .iter()
            .filter(|e| e.action == "grant.protocol.set_override")
            .collect();
        assert_eq!(overrides.len(), 1, "first disable must write 1 audit row");
        assert_eq!(overrides[0].target.as_deref(), Some("alice"));
        assert_eq!(overrides[0].payload.as_ref().unwrap()["disabled"], true);

        run_protocol_disable("alice", "s1", "vless+reality", Some(db.clone()))
            .await
            .unwrap();
        let entries2 = inv.recent_audit(20).await.unwrap();
        let count_noop = entries2
            .iter()
            .filter(|e| e.action == "grant.protocol.set_override")
            .count();
        assert_eq!(
            count_noop, 1,
            "no-op disable must not write duplicate audit"
        );

        run_protocol_enable("alice", "s1", "vless+reality", Some(db.clone()))
            .await
            .unwrap();
        let entries3 = inv.recent_audit(20).await.unwrap();
        let count_enable = entries3
            .iter()
            .filter(|e| e.action == "grant.protocol.set_override")
            .count();
        assert_eq!(count_enable, 2, "enable must write 1 audit row");

        run_protocol_enable("alice", "s1", "vless+reality", Some(db.clone()))
            .await
            .unwrap();
        let entries4 = inv.recent_audit(20).await.unwrap();
        let count_enable_noop = entries4
            .iter()
            .filter(|e| e.action == "grant.protocol.set_override")
            .count();
        assert_eq!(
            count_enable_noop, 2,
            "no-op enable must not write duplicate audit"
        );
    }

    #[tokio::test]
    async fn cli_protocol_override_affects_visibility() {
        let dir = TempDir::new().unwrap();
        let inv = seeded_inv(&dir).await;
        let uid = UserId("alice".into());
        let sid = ServerId("s1".into());
        inv.grant(&uid, &sid).await.unwrap();
        let db = dir.path().join("inv.db");

        let visible = inv
            .visible_protocols_for_subscription(&uid, &sid)
            .await
            .unwrap();
        assert_eq!(visible, vec![ProtocolId("vless+reality".into())]);

        run_protocol_disable("alice", "s1", "vless+reality", Some(db.clone()))
            .await
            .unwrap();
        let visible_after_disable = inv
            .visible_protocols_for_subscription(&uid, &sid)
            .await
            .unwrap();
        assert!(
            visible_after_disable.is_empty(),
            "disabled protocol must not be visible"
        );

        run_protocol_enable("alice", "s1", "vless+reality", Some(db.clone()))
            .await
            .unwrap();
        let visible_after_enable = inv
            .visible_protocols_for_subscription(&uid, &sid)
            .await
            .unwrap();
        assert_eq!(
            visible_after_enable,
            vec![ProtocolId("vless+reality".into())],
            "enabled protocol must be visible again"
        );
    }
}
