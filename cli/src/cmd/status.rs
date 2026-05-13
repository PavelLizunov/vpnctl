use crate::{OutputFormat, ui};
use std::path::PathBuf;
use vpnctl_core::ServerId;
use vpnctl_inventory::SqliteInventory;
use vpnctl_ssh::RusshTransportBuilder;

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
    let kernel = registry
        .kernel(&server.kernel)
        .ok_or_else(|| anyhow::anyhow!("kernel not registered: {}", server.kernel))?;

    let key_path = crate::cmd::deploy::resolve_key_path(ssh_key)?;
    let mut builder =
        RusshTransportBuilder::new(server.address.clone(), server.ssh_user.clone(), key_path)
            .port(server.ssh_port);
    if let Some(fp) = server.trusted_host_fingerprint.as_deref() {
        builder = builder.trusted_fingerprint(fp);
    }
    let ssh = builder.connect().await?;

    let status = kernel.status(&ssh).await?;

    ui::print(format, &status, |s| {
        println!(
            "server   : {} ({}:{})",
            server.id.0, server.address, server.ssh_port
        );
        println!("kernel   : {}", kernel.id());
        println!("active   : {}", s.active);
        println!("version  : {}", s.version.as_deref().unwrap_or("(unknown)"));
        println!(
            "uptime   : {}",
            s.uptime_seconds
                .map_or_else(|| "(unknown)".to_string(), |u| format!("{u}s"))
        );
        Ok(())
    })
}
