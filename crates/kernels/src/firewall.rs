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

fn append_ports(script: &mut String, ports: &BTreeSet<(&str, u16)>) {
    for &(transport, port) in ports {
        if matches!(transport, "tcp" | "udp") && port != 0 {
            let _ = write!(script, " {transport}:{port}");
        }
    }
}

pub(crate) fn firewall_open_script(ports: &[(&str, u16)]) -> Option<String> {
    if ports.is_empty() {
        return None;
    }
    let mut script = format!("set -eu\n{}vpnctl_ufw allow", ufw_function());
    append_ports(&mut script, &ports.iter().copied().collect());
    script.push('\n');
    Some(script)
}

pub(crate) fn firewall_open_dnstt(address: std::net::Ipv4Addr) -> String {
    format!(
        "set -eu\n{}vpnctl_ufw allow-dnstt {address}\n",
        ufw_function()
    )
}

fn protected_ports(
    registry: &Registry,
    ctx: &RenderCtx<'_>,
    reserved: &[u16],
) -> Result<BTreeSet<(&'static str, u16)>> {
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

    for &port in reserved {
        protected.extend([("tcp", port), ("udp", port)]);
    }
    Ok(protected)
}

fn parse_port(entry: &str) -> Option<(&str, u16)> {
    let (protocol, port) = entry.split_once(':')?;
    if !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let port = port.parse::<u16>().ok().filter(|port| *port != 0)?;

    Some((protocol, port))
}

/// Remove stale owned ingress rules after a successful deploy and report unused unmarked allowances.
pub async fn reconcile_firewall(
    ssh: &dyn SshTransport,
    registry: &Registry,
    ctx: &RenderCtx<'_>,
    reserved: &[u16],
) -> Result<Option<String>> {
    let protected = protected_ports(registry, ctx, reserved)?;
    let mut script = format!("set -eu\n{}vpnctl_ufw cleanup", ufw_function());
    append_ports(&mut script, &protected);
    script.push('\n');
    let output = ssh.exec(&script).await?;
    let ports: Vec<_> = output
        .split_whitespace()
        .filter_map(parse_port)
        .filter(|(protocol, _)| matches!(*protocol, "tcp" | "udp"))
        .map(|(protocol, port)| format!("{port}/{protocol}"))
        .collect();
    Ok((!ports.is_empty()).then(|| {
        format!(
            "UFW retained unmarked allowances with no public listener: {}",
            ports.join(", ")
        )
    }))
}

/// Sweep results identify the address family as `tcp4`, `tcp6`, `udp4`, or `udp6`.
#[derive(Debug, Default)]
pub struct FirewallSweep {
    pub idle_unmarked: BTreeSet<(&'static str, u16)>,
    pub removed: BTreeSet<(&'static str, u16)>,
    pub failed: Option<(&'static str, u16)>,
}

/// Remove eligible idle ingress and return observations for the next scheduled sweep.
pub async fn sweep_firewall(
    ssh: &dyn SshTransport,
    registry: &Registry,
    ctx: &RenderCtx<'_>,
    reserved: &[u16],
    previous_idle: &BTreeSet<(&'static str, u16)>,
) -> Result<FirewallSweep> {
    let protected = protected_ports(registry, ctx, reserved)?;
    let mut script = format!("set -eu\n{}vpnctl_ufw sweep", ufw_function());
    append_ports(&mut script, &protected);
    script.push_str(" --");
    for &(transport, port) in previous_idle {
        if matches!(transport, "tcp4" | "tcp6" | "udp4" | "udp6") && port != 0 {
            let _ = write!(script, " {transport}:{port}");
        }
    }
    script.push('\n');

    let mut sweep = FirewallSweep::default();
    for line in ssh.exec(&script).await?.lines() {
        let Some((action, value)) = line.split_once(' ') else {
            continue;
        };
        let Some((transport, port)) = parse_port(value) else {
            continue;
        };
        let transport = match transport {
            "tcp4" => "tcp4",
            "tcp6" => "tcp6",
            "udp4" => "udp4",
            "udp6" => "udp6",
            _ => continue,
        };
        let port = (transport, port);
        match action {
            "idle" => {
                sweep.idle_unmarked.insert(port);
            }
            "removed" => {
                sweep.removed.insert(port);
            }
            "failed" => sweep.failed = Some(port),
            _ => {}
        }
    }
    Ok(sweep)
}
