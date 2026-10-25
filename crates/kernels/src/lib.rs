mod amnezia_wg;
mod caddy;
mod sing_box;
mod xray;

pub use amnezia_wg::AmneziaWg;
pub use caddy::Caddy;
pub use sing_box::{
    SING_BOX_AMD64_SHA256, SING_BOX_ARM64_SHA256, SING_BOX_ARMV7_SHA256, SING_BOX_MIN_VERSION,
    SING_BOX_VPNCTL_VERSION, SingBox,
};
pub use xray::Xray;

pub use sing_box::validate_config_excludes_ports;

pub use sing_box::live_config_user_uuids;

/// Stop and disable services of `retired` kernels (ones the operator disabled
/// on this server) that are not enabled again. Kernels vpnctl never managed on
/// the server are not in `retired`, so unrelated node services stay untouched.
pub async fn reconcile_disabled_kernels(
    registry: &vpnctl_core::Registry,
    server: &vpnctl_core::Server,
    retired: &[vpnctl_core::KernelId],
    ssh: &dyn vpnctl_core::SshTransport,
) -> vpnctl_core::Result<()> {
    let mut script = String::from("set -eu\n");
    for kid in retired {
        if server.kernels.contains(kid) {
            continue;
        }
        let Some(kernel) = registry.kernel(kid) else {
            continue;
        };
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
