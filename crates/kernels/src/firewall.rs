use std::collections::BTreeSet;
use std::fmt::Write;

use vpnctl_core::{CoreError, Kernel, Registry, RenderCtx, Result, SshTransport};

use crate::Caddy;

pub(crate) fn ufw_function() -> String {
    format!(
        "vpnctl_ufw() {{\n\
         command -v ufw >/dev/null 2>&1 || return 0\n\
         LC_ALL=C /usr/bin/python3 -I - \"$@\" <<'VPNCTL_UFW_PY'\n{}\nVPNCTL_UFW_PY\n}}\n",
        include_str!("firewall/ufw.py"),
    )
}

fn append_ports(script: &mut String, ports: BTreeSet<(&str, u16)>) {
    for (transport, port) in ports {
        let _ = write!(script, " {transport}:{port}");
    }
    script.push('\n');
}

pub(crate) fn firewall_open_script(ports: &[(&str, u16)]) -> Option<String> {
    if ports.is_empty() {
        return None;
    }
    let mut script = format!("set -eu\n{}vpnctl_ufw allow", ufw_function());
    append_ports(&mut script, ports.iter().copied().collect());
    Some(script)
}

pub(crate) fn firewall_open_dnstt(address: std::net::Ipv4Addr) -> String {
    format!(
        "set -eu\n{}vpnctl_ufw allow-dnstt {address}\n",
        ufw_function()
    )
}

/// Remove stale owned ingress rules after a successful deploy and report unused unmarked allowances.
pub async fn reconcile_firewall(
    ssh: &dyn SshTransport,
    registry: &Registry,
    ctx: &RenderCtx<'_>,
) -> Result<Option<String>> {
    let server = ctx.server;
    let mut protected = BTreeSet::from([("tcp", server.ssh_port)]);
    for id in &server.enabled_protocols {
        let protocol = registry
            .protocol(id)
            .ok_or_else(|| CoreError::Render(format!("protocol not registered: {id}")))?;
        protected.extend(protocol.effective_listen_ports(ctx.secrets));
    }

    let caddy = Caddy::new();
    if server.kernels.contains(&caddy.id())
        && caddy
            .supported_protocols()
            .iter()
            .any(|id| server.enabled_protocols.contains(id))
    {
        protected.insert(("tcp", 80));
    }

    let mut script = format!("set -eu\n{}vpnctl_ufw cleanup", ufw_function());
    append_ports(&mut script, protected);
    let output = ssh.exec(&script).await?;
    let ports: Vec<_> = output
        .split_whitespace()
        .filter_map(|entry| {
            let (protocol, port) = entry.split_once(':')?;
            let port = port.parse::<u16>().ok()?;
            matches!(protocol, "tcp" | "udp").then(|| format!("{port}/{protocol}"))
        })
        .collect();
    Ok((!ports.is_empty()).then(|| {
        format!(
            "UFW retained unmarked allowances with no public listener: {}",
            ports.join(", ")
        )
    }))
}
