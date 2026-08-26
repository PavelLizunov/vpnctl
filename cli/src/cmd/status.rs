use crate::{OutputFormat, ui};
use std::path::PathBuf;
use vpnctl_core::ServerId;
use vpnctl_inventory::SqliteInventory;
use vpnctl_ssh::SubprocessSshTransport;

pub(crate) async fn run(
    server_id: &str,
    ssh_key: Option<PathBuf>,
    db_flag: Option<PathBuf>,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let db_path = ui::resolve_db_path(db_flag)?;
    let inv = SqliteInventory::open(&db_path).await?;

    let sid = ServerId(server_id.to_string());
    let server = inv
        .get_server(&sid)
        .await?
        .ok_or_else(|| anyhow::anyhow!("no such server: {server_id}"))?;

    let registry = crate::registry::build()?;
    if server.kernels.is_empty() {
        anyhow::bail!("server '{}' has no kernels declared", server.id);
    }
    let kernels: Vec<&dyn vpnctl_core::Kernel> = server
        .kernels
        .iter()
        .map(|kid| {
            registry
                .kernel(kid)
                .ok_or_else(|| anyhow::anyhow!("kernel not registered: {kid}"))
        })
        .collect::<anyhow::Result<_>>()?;

    let key_path = crate::cmd::deploy::resolve_key_path(ssh_key)?;
    let jump = inv.resolve_jump_host(&server).await?;
    let ssh = SubprocessSshTransport::new(&server.address, &server.ssh_user, key_path)
        .port(server.ssh_port)
        .trusted_fingerprint(server.trusted_host_fingerprint.clone())
        .with_jump(jump);

    // Multi-kernel: query each declared kernel's status and emit a
    // block per kernel. The JSON variant returns an array of statuses
    // (instead of a single object) so machine consumers can iterate.
    let mut all_statuses = Vec::with_capacity(kernels.len());
    for k in &kernels {
        let st = k.status(&ssh).await?;
        all_statuses.push((k.id().0.clone(), st));
    }

    ui::print(format, &all_statuses, |list| {
        println!(
            "server   : {} ({}:{})",
            server.id.0, server.address, server.ssh_port
        );
        for (kid, s) in list {
            println!("kernel   : {kid}");
            println!("  active : {}", s.active);
            println!("  version: {}", s.version.as_deref().unwrap_or("(unknown)"));
            println!(
                "  uptime : {}",
                s.uptime_seconds
                    .map_or_else(|| "(unknown)".to_string(), |u| format!("{u}s"))
            );
        }
        Ok(())
    })
}
