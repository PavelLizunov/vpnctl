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

    inv.grant(&uid, &sid).await?;
    inv.audit("cli", "grant", Some(server), Some(&json!({ "user": user })))
        .await?;
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
