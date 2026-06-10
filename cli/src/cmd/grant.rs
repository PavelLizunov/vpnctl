use crate::ui;
use serde_json::json;
use std::path::PathBuf;
use vpnctl_core::{ServerId, UserId};
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

    inv.revoke(&UserId(user.to_string()), &ServerId(server.to_string()))
        .await?;
    inv.audit(
        "cli",
        "revoke",
        Some(server),
        Some(&json!({ "user": user })),
    )
    .await?;
    println!("revoked '{user}' from '{server}'");
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
}
