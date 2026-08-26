use crate::ui;
use serde_json::json;
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

    // Membership BEFORE the grant — the audit row below is written only
    // for a NEW grant. An idempotent re-grant must not write a fresh
    // mutation row (it would falsely re-mark the server pending-deploy
    // until a no-op redeploy).
    let was_granted = inv
        .servers_for_user(&uid)
        .await?
        .iter()
        .any(|s| s.id == sid);
    inv.grant(&uid, &sid).await?;
    // Per-user `user.grant` row with target = USER id — the canonical
    // grant-audit shape every grant path emits (2026-06-04 unification).
    // The pending-deploy detector (`servers_pending_deploy_for_user`)
    // keys on `action = 'user.grant' AND target = <user>`; the previous
    // `action="grant", target=<server>` shape was invisible to it, so a
    // CLI grant after the server's first deploy never raised the
    // «config not yet deployed» banner.
    if !was_granted {
        inv.audit(
            "cli",
            "user.grant",
            Some(user),
            Some(&json!({ "server": server, "source": "cli" })),
        )
        .await?;
    }
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
    // Membership BEFORE the revoke — write the canonical per-user
    // `user.revoke` row (target = USER id) only for an ACTUAL revoke,
    // mirroring `run_grant`. The old `action="revoke", target=<server>`
    // shape was invisible to the pending-deploy detector, so a revoked
    // UUID stayed live on the node with no warning.
    let was_granted = inv
        .servers_for_user(&uid)
        .await?
        .iter()
        .any(|s| s.id == sid);
    inv.revoke(&uid, &sid).await?;
    if was_granted {
        inv.audit(
            "cli",
            "user.revoke",
            Some(user),
            Some(&json!({ "server": server, "source": "cli" })),
        )
        .await?;
    }
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
    //! REGRESSION (review 2026-06-04): the CLI grant must write the
    //! canonical per-user `user.grant` audit row (target = USER id) —
    //! the shape the daemon's pending-deploy detector keys on. The old
    //! `action="grant", target=<server>` row was invisible to it, so a
    //! CLI grant after the server's first deploy never raised the
    //! «config not yet deployed» banner.

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
        // Deploy baseline FIRST — the regression only bites once a
        // server.deploy row exists. (Seeded user has zero audit rows,
        // so the only user-mutation ts is what run_grant writes.)
        inv.audit("cli", "server.deploy", Some("s1"), None)
            .await
            .unwrap();
        // std sleep (not tokio::time) — the cli crate's tokio doesn't
        // enable the `time` feature; 10 ms blocking in a test is fine.
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
        // Mirror of the grant contract (audit 2026-06-10): revoke writes
        // a per-user `user.revoke` row (target = USER id) — and ONLY for
        // an actual revoke; a no-op re-revoke writes nothing.
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

        // Idempotent re-revoke → no new row.
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

        // alice is NOT granted s1 yet
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

        // Initial disable -> 1 audit row
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

        // Second disable (no-op) -> still 1 audit row
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

        // Enable -> 2nd audit row
        run_protocol_enable("alice", "s1", "vless+reality", Some(db.clone()))
            .await
            .unwrap();
        let entries3 = inv.recent_audit(20).await.unwrap();
        let count_enable = entries3
            .iter()
            .filter(|e| e.action == "grant.protocol.set_override")
            .count();
        assert_eq!(count_enable, 2, "enable must write 1 audit row");

        // Second enable (no-op) -> still 2 audit rows
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

        // Initially visible
        let visible = inv
            .visible_protocols_for_subscription(&uid, &sid)
            .await
            .unwrap();
        assert_eq!(visible, vec![ProtocolId("vless+reality".into())]);

        // Disable protocol -> excluded from visible
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

        // Re-enable protocol -> visible again
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
