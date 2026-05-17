//! `vpnctl sub <user>` — собирает share-link'и для всех серверов, на которые
//! у юзера есть grant. По одной строке на (server, protocol). С `--qr` —
//! ASCII QR-код под каждым линком, удобно сканировать с телефона.

use crate::{OutputFormat, ui};
use qrcode::QrCode;
use qrcode::render::unicode;
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
    qr: bool,
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
        // WireGuard's share_link reads `ctx.peers` to assign the right
        // /32 per user — pass the granted-users list. Other protocols
        // ignore the field.
        let peers = inv.users_for_server(&server.id).await?;
        let ctx = RenderCtx::with_peers(server, &secrets, &peers);
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
            if qr {
                render_qr(&e.link, &e.server, &e.protocol);
            }
            println!();
        }
        Ok(())
    })
}

/// Render the link as a Unicode-block QR sized to fit a normal terminal.
/// Best-effort: oversized URLs (>~2.5 KB) overflow QR capacity — we
/// warn but don't bail (the link itself is still printed above).
fn render_qr(link: &str, server: &str, protocol: &str) {
    match QrCode::new(link.as_bytes()) {
        Ok(code) => {
            // Dense1x2 packs one QR module into half a terminal cell —
            // good readability without dominating the screen. We invert
            // dark/light because most terminals are dark-on-light:
            // contrasting "filled" blocks make the camera scan reliably.
            let image = code
                .render::<unicode::Dense1x2>()
                .dark_color(unicode::Dense1x2::Light)
                .light_color(unicode::Dense1x2::Dark)
                .quiet_zone(true)
                .build();
            println!("{image}");
        }
        Err(err) => {
            eprintln!("warn: QR generation failed for {server}/{protocol}: {err}");
        }
    }
}
