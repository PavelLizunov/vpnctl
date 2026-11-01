//! Network boundary: inventory-only targets and a fixed, pinned SSH probe.
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use chrono::Utc;
use vpnctl_core::Server;

use super::{Outcome, ResultRow, Source, Target};
use crate::AppState;

pub(super) async fn targets(state: &AppState, servers: &[Server]) -> anyhow::Result<Vec<Target>> {
    let mut targets = Vec::new();
    for server in servers {
        let secrets = state.inv.list_server_secrets(&server.id).await?;
        let ip = match server.address.parse::<IpAddr>() {
            Ok(ip) => Some(ip),
            Err(_) => state
                .inv
                .resolved_ips_for_server(&server.id)
                .await?
                .into_iter()
                .next(),
        };
        for protocol in &server.enabled_protocols {
            let ports = state
                .registry
                .protocol(protocol)
                .map(|p| p.effective_listen_ports(&secrets))
                .unwrap_or_default();
            let ports: Vec<_> = if ports.is_empty() {
                vec![("unknown", None)]
            } else {
                ports
                    .into_iter()
                    .map(|(transport, port)| (transport, Some(port)))
                    .collect()
            };
            for (transport, port) in ports {
                targets.push(Target {
                    server: server.id.0.clone(),
                    address: server.address.clone(),
                    ip,
                    protocol: protocol.0.clone(),
                    transport: transport.into(),
                    port,
                });
            }
        }
    }
    Ok(targets)
}

fn skipped(target: &Target) -> Option<Outcome> {
    if target.transport == "udp" {
        Some(Outcome::UdpNotChecked)
    } else if target.transport != "tcp" || !target.port.is_some_and(|p| p != 0) {
        Some(Outcome::Unsupported)
    } else if target.ip.is_none() {
        Some(Outcome::NoAddress)
    } else {
        None
    }
}

pub(super) async fn local(target: &Target) -> Outcome {
    if let Some(outcome) = skipped(target) {
        return outcome;
    }
    let (Some(ip), Some(port)) = (target.ip, target.port) else {
        return Outcome::NoAddress;
    };
    let start = Instant::now();
    match tokio::time::timeout(
        Duration::from_secs(2),
        tokio::net::TcpStream::connect(SocketAddr::new(ip, port)),
    )
    .await
    {
        Ok(Ok(_)) => Outcome::Reachable(start.elapsed().as_millis()),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => Outcome::Refused,
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::TimedOut => Outcome::Timeout,
        Ok(Err(_)) => Outcome::Failed,
        Err(_) => Outcome::Timeout,
    }
}

// No inventory values are interpolated into this shell command.
const REMOTE_PROBE: &str = r#"python3 -c 'import concurrent.futures, errno, json, signal, socket, sys, time
signal.alarm(15)
items = json.load(sys.stdin)
def probe(item):
    ip, port = item
    start = time.monotonic()
    try:
        with socket.create_connection((ip, port), timeout=2):
            return ["ok", int((time.monotonic() - start) * 1000)]
    except (socket.timeout, TimeoutError):
        return ["timeout", 0]
    except OSError as e:
        return ["refused" if e.errno == errno.ECONNREFUSED else "failed", 0]
with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
    print(json.dumps(list(pool.map(probe, items))))'"#;

fn parse_remote(bytes: &[u8], expected: usize) -> Option<Vec<Outcome>> {
    if bytes.len() > 4096 {
        return None;
    }
    let entries: Vec<(String, u64)> = serde_json::from_slice(bytes).ok()?;
    if entries.len() != expected {
        return None;
    }
    entries
        .into_iter()
        .map(|(status, ms)| match (status.as_str(), ms) {
            ("ok", 0..=15000) => Some(Outcome::Reachable(u128::from(ms))),
            ("timeout", 0) => Some(Outcome::Timeout),
            ("refused", 0) => Some(Outcome::Refused),
            ("failed", 0) => Some(Outcome::Failed),
            _ => None,
        })
        .collect()
}

fn remote_skip(target: &Target, source: &Server, ips: &HashSet<IpAddr>) -> Option<Outcome> {
    skipped(target).or_else(|| {
        if target.server == source.id.0 || target.ip.is_some_and(|ip| ips.contains(&ip)) {
            Some(Outcome::SelfCheck)
        } else if ips.is_empty() {
            Some(Outcome::SourceUnavailable)
        } else {
            None
        }
    })
}

pub(super) async fn remote(
    state: &AppState,
    targets: &[Target],
    source: &Server,
) -> Vec<ResultRow> {
    let resolved = state.inv.resolved_ips_for_server(&source.id).await;
    let resolution_ok = resolved.is_ok();
    let mut ips: HashSet<IpAddr> = resolved.unwrap_or_default().into_iter().collect();
    if resolution_ok && let Ok(ip) = source.address.parse() {
        ips.insert(ip);
    }
    let input: Vec<_> = targets
        .iter()
        .filter(|t| remote_skip(t, source, &ips).is_none())
        .filter_map(|t| Some((t.ip?.to_string(), t.port?)))
        .collect();
    let results = async {
        if input.is_empty() {
            return Some(Vec::new());
        }
        // None would select accept-new in the shared transport: require a pin.
        let fingerprint = source.trusted_host_fingerprint.as_ref()?;
        if fingerprint.is_empty() {
            return None;
        }
        let jump = state.inv.resolve_jump_host(source).await.ok()?;
        let ssh = crate::ssh_subprocess::SubprocessSshTransport::new(
            source.address.clone(),
            source.ssh_user.clone(),
            crate::app::deploy_key_path(),
        )
        .port(source.ssh_port)
        .trusted_fingerprint(source.trusted_host_fingerprint.clone())
        .with_jump(jump)
        .timeout(Duration::from_secs(20));
        let bytes = ssh
            .exec_with_stdin(REMOTE_PROBE, serde_json::to_vec(&input).ok()?)
            .await
            .ok()?;
        parse_remote(&bytes, input.len())
    }
    .await;
    let mut results = results.as_ref().into_iter().flatten();
    targets
        .iter()
        .map(|target| ResultRow {
            source: Source::Server(source.id.0.clone()),
            target: target.clone(),
            time: Utc::now(),
            outcome: remote_skip(target, source, &ips).unwrap_or_else(|| {
                results
                    .next()
                    .cloned()
                    .unwrap_or(Outcome::SourceUnavailable)
            }),
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    fn target(port: u16, transport: &str) -> Target {
        Target {
            server: "test".into(),
            address: "127.0.0.1".into(),
            ip: Some("127.0.0.1".parse().unwrap()),
            protocol: "test".into(),
            transport: transport.into(),
            port: Some(port),
        }
    }
    #[test]
    fn parser_requires_complete_bounded_results() {
        assert_eq!(
            parse_remote(br#"[["ok",12],["refused",0],["timeout",0]]"#, 3),
            Some(vec![
                Outcome::Reachable(12),
                Outcome::Refused,
                Outcome::Timeout
            ])
        );
        for bytes in [
            br#"[["ok",12]]"#.as_slice(),
            br#"[["ok",15001],["failed",0]]"#,
            br#"[["refused",1],["failed",0]]"#,
            b"invalid",
        ] {
            assert_eq!(parse_remote(bytes, 2), None);
        }
        assert_eq!(parse_remote(&vec![b' '; 4097], 0), None);
    }
    #[tokio::test]
    async fn local_tcp_and_udp_semantics() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(matches!(
            local(&target(port, "tcp")).await,
            Outcome::Reachable(_)
        ));
        assert_eq!(local(&target(port, "udp")).await, Outcome::UdpNotChecked);
        drop(listener);
        assert_eq!(local(&target(port, "tcp")).await, Outcome::Refused);
        let mut missing = target(port, "tcp");
        missing.ip = None;
        assert_eq!(local(&missing).await, Outcome::NoAddress);
    }
    #[test]
    fn self_and_unavailable_source_are_not_target_failures() {
        let source = Server {
            id: vpnctl_core::ServerId("test".into()),
            address: "127.0.0.1".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![],
            enabled_protocols: vec![],
            trusted_host_fingerprint: None,
            hoster: "test".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        };
        let ips = HashSet::from(["127.0.0.1".parse().unwrap()]);
        assert_eq!(
            remote_skip(&target(443, "tcp"), &source, &ips),
            Some(Outcome::SelfCheck)
        );
        assert_eq!(
            remote_skip(&target(443, "udp"), &source, &ips),
            Some(Outcome::UdpNotChecked)
        );
        let mut other = target(443, "tcp");
        other.server = "other".into();
        assert_eq!(
            remote_skip(&other, &source, &HashSet::new()),
            Some(Outcome::SourceUnavailable)
        );
    }
}
