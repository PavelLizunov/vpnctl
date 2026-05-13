//! `vpnctl sub <user>` — собирает share-link'и для всех серверов, на которые
//! у юзера есть grant. По одной строке на (server, protocol).

use crate::{OutputFormat, ui};
use serde::Serialize;
use std::path::PathBuf;
use vpnctl_core::{RenderCtx, UserId};
use vpnctl_inventory::SqliteInventory;

#[derive(Serialize)]
struct LinkEntry {
    server: String,
    protocol: String,
    link: String,
}

pub(crate) async fn run(
    user_id: &str,
    db_flag: Option<PathBuf>,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let db_path = ui::resolve_db_path(db_flag)?;
    let inv = SqliteInventory::open(&db_path).await?;

    let uid = UserId(user_id.to_string());
    let user = inv
        .get_user(&uid)
        .await?
        .ok_or_else(|| anyhow::anyhow!("no such user: {user_id}"))?;

    let servers = inv.servers_for_user(&uid).await?;
    let registry = crate::registry::build()?;

    let mut entries: Vec<LinkEntry> = Vec::new();
    for server in &servers {
        let secrets = inv.list_server_secrets(&server.id).await?;
        let ctx = RenderCtx::new(server, &secrets);
        for pid in &server.enabled_protocols {
            let Some(proto) = registry.protocol(pid) else {
                eprintln!("warn: protocol '{pid}' not registered, skipping");
                continue;
            };
            match proto.share_link(&ctx, &user) {
                Ok(link) => entries.push(LinkEntry {
                    server: server.id.0.clone(),
                    protocol: pid.0.clone(),
                    link,
                }),
                Err(e) => eprintln!("warn: cannot build link for {}/{}: {e}", server.id.0, pid.0),
            }
        }
    }

    ui::print(format, &entries, |entries| {
        if entries.is_empty() {
            println!("(no grants for user '{user_id}')");
            return Ok(());
        }
        for e in entries {
            println!("# {} via {}", e.server, e.protocol);
            println!("{}", e.link);
            println!();
        }
        Ok(())
    })
}
