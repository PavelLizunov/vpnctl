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

    // Same protocol-vs-kernel validation `deploy` does pre-SSH — fail
    // here too so operators don't get a surprise from `sing-box check`
    // on the rendered output.
    reg.validate_server(&server_row)?;

    let users = inv.users_for_server(&sid).await?;
    let secrets = inv.list_server_secrets(&sid).await?;
    let ctx = RenderCtx::new(&server_row, &secrets);

    // Multi-kernel: render each declared kernel's config separately,
    // delimited by a kernel-id header line so the operator can tell
    // them apart when piping through `less`. Single-kernel servers
    // (the historic 1:1 case) get a single block with the same header
    // — keeps the output shape uniform.
    use std::io::Write;
    for kid in &server_row.kernels {
        let kernel = reg
            .kernel(kid)
            .ok_or_else(|| anyhow::anyhow!("kernel not registered: {kid}"))?;
        let supported = kernel.supported_protocols();
        let protocols: Vec<&dyn Protocol> = server_row
            .enabled_protocols
            .iter()
            .filter(|pid| supported.contains(pid))
            .map(|pid| {
                reg.protocol(pid)
                    .ok_or_else(|| anyhow::anyhow!("protocol not registered: {pid}"))
            })
            .collect::<anyhow::Result<_>>()?;
        if protocols.is_empty() {
            // Kernel declared but no protocols for it — still print a
            // header so the operator notices the dead kernel.
            writeln!(
                std::io::stdout(),
                "# === kernel: {kid} (no enabled_protocols this kernel can render — skipped) ==="
            )?;
            continue;
        }
        writeln!(std::io::stdout(), "# === kernel: {kid} ===")?;
        let bytes = kernel.render_config(&ctx, &users, &protocols)?;
        std::io::stdout().write_all(&bytes)?;
        if !bytes.ends_with(b"\n") {
            println!();
        }
    }
    Ok(())
}
