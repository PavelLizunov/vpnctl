mod amnezia_wg;
mod caddy;
mod registry;
mod sing_box;
mod xray;

pub use amnezia_wg::AmneziaWg;
pub use caddy::Caddy;
pub use registry::build_registry;
pub use sing_box::{
    SING_BOX_AMD64_SHA256, SING_BOX_ARM64_SHA256, SING_BOX_ARMV7_SHA256, SING_BOX_MIN_VERSION,
    SING_BOX_VPNCTL_VERSION, SingBox,
};
pub use xray::Xray;

/// Destination ranges user traffic must never reach on a node, beyond what a
/// kernel's own "private" matcher covers (e.g. CGNAT, used by Tailscale).
pub const USER_TRAFFIC_DENIED_CIDRS: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "::/128",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
    "fec0::/10",
    "ff00::/8",
];

pub use sing_box::validate_config_excludes_ports;

pub use sing_box::live_config_user_uuids;

async fn apply_staged_config(
    ssh: &dyn vpnctl_core::SshTransport,
    path: &str,
    config: &[u8],
    script: &str,
) -> vpnctl_core::Result<()> {
    let parent = std::path::Path::new(path)
        .parent()
        .and_then(std::path::Path::to_str)
        .filter(|parent| !parent.is_empty())
        .ok_or_else(|| vpnctl_core::CoreError::Transport("staging path has no directory".into()))?;
    let directory = vpnctl_core::shell::single_quote(parent);
    let quoted = vpnctl_core::shell::single_quote(path);
    // Revoke service write access before replacing any stale link. The directory
    // stays protected across the separate SSH upload and apply calls.
    ssh.exec(&format!(
        "set -eu\ntest ! -L {directory}\nchown root {directory}\nchmod go-w {directory}\n\
         rm -f -- {quoted}\ninstall -o root -g root -m 0600 /dev/null {quoted}"
    ))
    .await?;
    let result = async {
        ssh.upload(path, config).await?;
        ssh.exec(script).await?;
        Ok(())
    }
    .await;
    if result.is_err() {
        let _ = ssh.exec(&format!("rm -f -- {quoted}")).await;
    }
    result
}

/// Stop and disable retired kernels and enabled kernels with no enabled protocols.
/// Kernels vpnctl never managed on this server stay untouched.
pub async fn reconcile_disabled_kernels(
    registry: &vpnctl_core::Registry,
    server: &vpnctl_core::Server,
    retired: &[vpnctl_core::KernelId],
    ssh: &dyn vpnctl_core::SshTransport,
) -> vpnctl_core::Result<()> {
    let mut script = String::from("set -eu\n");
    for kid in server
        .kernels
        .iter()
        .chain(retired.iter().filter(|kid| !server.kernels.contains(kid)))
    {
        let Some(kernel) = registry.kernel(kid) else {
            continue;
        };
        let supported = kernel.supported_protocols();
        if server.kernels.contains(kid)
            && server
                .enabled_protocols
                .iter()
                .any(|pid| supported.contains(pid))
        {
            continue;
        }
        if kernel.service_units().is_empty() {
            return Err(vpnctl_core::CoreError::Transport(format!(
                "kernel '{kid}' does not declare its service units"
            )));
        }
        for unit in kernel.service_units() {
            let unit = vpnctl_core::shell::single_quote(unit);
            script.push_str(&format!(
                "state=$(systemctl show --property=LoadState --value -- {unit}) || [ \"$state\" = not-found ]\n\
                 if [ \"$state\" != not-found ]; then systemctl disable --now -- {unit}; fi\n"
            ));
        }
    }
    if script != "set -eu\n" {
        ssh.exec(&script).await?;
    }
    Ok(())
}

#[cfg(test)]
mod staging_tests;
