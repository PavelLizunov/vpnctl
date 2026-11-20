pub(crate) use vpnctl_kernels::build_registry as build;

pub(crate) fn validate_new_server(
    registry: &vpnctl_core::Registry,
    server: &vpnctl_core::Server,
) -> anyhow::Result<()> {
    for protocol in &server.enabled_protocols {
        if registry
            .protocol(protocol)
            .is_some_and(|entry| entry.is_retired())
        {
            anyhow::bail!("protocol '{protocol}' is retired");
        }
    }
    registry.validate_server_support(server)?;
    Ok(())
}
