//! `vpnctl render <server>` — render the kernel config for a server
//! and print it to stdout WITHOUT SSH'ing anywhere.
//!
//! Closes the methodology TODO from `docs/PROTOCOL_TESTING.md` layer 5:
//! "until we ship `vpnctl render-server-config`, hand-construct the
//! JSON and unit-test the equivalence." This command IS that helper.
//!
//! Use cases:
//!   - Reviewing what a `vpnctl deploy <server>` WOULD push, without
//!     actually SSH'ing (offline confidence-check)
//!   - Live-staging tests — pipe through `sing-box check` on the node
//!     to fast-loop config drafts without re-implementing the render
//!     in Python
//!   - Diffing: render twice with different secrets, diff the outputs
//!
//! Output: kernel-native format (JSON for sing-box, INI for
//! AmneziaWG). Goes to stdout — pipe to file, less, or another
//! tool.
//!
//! Exit codes:
//!   * 0 — rendered successfully
//!   * non-zero (via `anyhow`) — server unknown, secrets missing,
//!     protocol mismatch with kernel, etc.

use std::path::PathBuf;

use crate::registry;
use crate::ui;
use vpnctl_core::{Protocol, RenderCtx, ServerId};
use vpnctl_inventory::SqliteInventory;

pub(crate) async fn run(server: &str, db_flag: Option<PathBuf>) -> anyhow::Result<()> {
    let db_path = ui::resolve_db_path(db_flag)?;
    let inv = SqliteInventory::open(&db_path).await?;
    let reg = registry::build()?;

    let sid = ServerId(server.to_string());
    let server_row = inv
        .get_server(&sid)
        .await?
        .ok_or_else(|| anyhow::anyhow!("server not in inventory: {server}"))?;

    let kernel = reg
        .kernel(&server_row.kernel)
        .ok_or_else(|| anyhow::anyhow!("kernel not registered: {}", server_row.kernel))?;
    // Same protocol-vs-kernel validation `deploy` does pre-SSH — fail
    // here too so operators don't get a surprise from `sing-box check`
    // on the rendered output.
    reg.validate_server(&server_row)?;

    let mut protocols: Vec<&dyn Protocol> = Vec::with_capacity(server_row.enabled_protocols.len());
    for pid in &server_row.enabled_protocols {
        let p = reg
            .protocol(pid)
            .ok_or_else(|| anyhow::anyhow!("protocol not registered: {pid}"))?;
        protocols.push(p);
    }
    let users = inv.users_for_server(&sid).await?;
    let secrets = inv.list_server_secrets(&sid).await?;
    let ctx = RenderCtx::new(&server_row, &secrets);
    let bytes = kernel.render_config(&ctx, &users, &protocols)?;
    // Stdout, write-all to avoid Unicode-boundary truncation if the
    // output has non-ASCII (AmneziaWG header uses an em-dash).
    use std::io::Write;
    std::io::stdout().write_all(&bytes)?;
    // Trailing newline only if the kernel didn't include one — keep
    // consumers like `wc -l` and pipe-into-jq happy.
    if !bytes.ends_with(b"\n") {
        println!();
    }
    Ok(())
}
