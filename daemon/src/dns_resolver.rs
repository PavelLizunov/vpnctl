use std::process::Command;
use std::time::Duration;

use vpnctl_core::ServerId;
use vpnctl_inventory::SqliteInventory;

use crate::snapshot_cache::SnapshotCache;

pub const DEFAULT_INTERVAL_SECS: u64 = 5 * 60;
pub const LOOKUP_TIMEOUT_SECS: u64 = 3;
pub const MAX_LOOKUPS_PER_TICK: usize = 50;

pub fn spawn_dns_resolver(
    inv: SqliteInventory,
    snapshot_cache: SnapshotCache,
) -> tokio::task::JoinHandle<()> {
    use tokio::time::{MissedTickBehavior, interval};

    let interval_secs = crate::config::parse_positive_secs(
        "VPNCTLD_DNS_RESOLVER_INTERVAL_SECS",
        DEFAULT_INTERVAL_SECS,
    );

    tokio::spawn(async move {
        let mut tick = interval(Duration::from_secs(interval_secs));
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        tick.tick().await;
        loop {
            tick.tick().await;
            if let Err(e) = resolve_one_tick(&inv, &snapshot_cache).await {
                tracing::warn!(
                    target = "vpnctld::dns_resolver",
                    error = %e,
                    "dns resolver tick failed; will retry next tick"
                );
            }
        }
    })
}

pub async fn resolve_one_tick(
    inv: &SqliteInventory,
    snapshot_cache: &SnapshotCache,
) -> anyhow::Result<()> {
    let servers = inv.list_servers().await?;
    let mut all_ips: std::collections::HashSet<String> = std::collections::HashSet::new();
    for s in &servers {
        if let Some(snap) = snapshot_cache.get(&ServerId(s.id.0.clone())) {
            for c in &snap.snapshot.connections {
                if c.metadata.host.is_empty() && !c.metadata.destination_ip.is_empty() {
                    all_ips.insert(c.metadata.destination_ip.clone());
                }
            }
        }
    }
    if all_ips.is_empty() {
        tracing::debug!(
            target = "vpnctld::dns_resolver",
            "no destination IPs to resolve this tick"
        );
        return Ok(());
    }

    let ips_vec: Vec<String> = all_ips.iter().cloned().collect();
    let cached = inv.lookup_dns_ptr_bulk(&ips_vec).await?;
    let unresolved: Vec<String> = ips_vec
        .into_iter()
        .filter(|ip| !cached.contains_key(ip))
        .take(MAX_LOOKUPS_PER_TICK)
        .collect();
    if unresolved.is_empty() {
        tracing::debug!(
            target = "vpnctld::dns_resolver",
            "all destination IPs already cached"
        );
        return Ok(());
    }

    let attempt = unresolved.len();
    let mut resolved_count: usize = 0;
    for ip in &unresolved {
        let host = resolve_one(ip).await;
        if host.is_some() {
            resolved_count += 1;
        }
        if let Err(e) = inv.upsert_dns_ptr(ip, host.as_deref()).await {
            tracing::warn!(
                target = "vpnctld::dns_resolver",
                ip = %ip,
                error = %e,
                "dns_ptr_cache upsert failed"
            );
        }
    }
    tracing::info!(
        target = "vpnctld::dns_resolver",
        attempted = attempt,
        resolved = resolved_count,
        "dns resolver tick: {resolved_count}/{attempt} returned a hostname"
    );
    Ok(())
}

pub async fn resolve_one(ip: &str) -> Option<String> {
    if !ip
        .chars()
        .all(|c| c.is_ascii_digit() || matches!(c, '.' | ':' | 'a'..='f' | 'A'..='F'))
    {
        return None;
    }
    let ip_owned = ip.to_string();
    tokio::task::spawn_blocking(move || resolve_blocking(&ip_owned))
        .await
        .ok()?
}

fn resolve_blocking(ip: &str) -> Option<String> {
    let mut child = Command::new("getent")
        .arg("hosts")
        .arg(ip)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .ok()?;

    let deadline = std::time::Instant::now() + Duration::from_secs(LOOKUP_TIMEOUT_SECS);
    loop {
        match child.try_wait().ok()? {
            Some(_) => break,
            None => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }

    let out = child.wait_with_output().ok()?;
    if !out.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    parse_getent_hosts_line(&stdout)
}

pub fn parse_getent_hosts_line(stdout: &str) -> Option<String> {
    let first_line = stdout.lines().next()?;
    let mut parts = first_line.split_whitespace();
    let _ip = parts.next()?;
    let hostname = parts.next()?;
    if hostname.is_empty() {
        return None;
    }
    Some(hostname.to_string())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parse_getent_returns_hostname_from_canonical_line() {
        let out = "8.8.8.8         dns.google\n";
        assert_eq!(parse_getent_hosts_line(out), Some("dns.google".into()));
    }

    #[test]
    fn parse_getent_handles_multiple_hostnames_returns_first() {
        let out = "1.1.1.1         one.one.one.one cloudflare-dns.com\n";
        assert_eq!(parse_getent_hosts_line(out), Some("one.one.one.one".into()));
    }

    #[test]
    fn parse_getent_handles_ipv6_address() {
        let out = "2606:4700:4700::1111 one.one.one.one\n";
        assert_eq!(parse_getent_hosts_line(out), Some("one.one.one.one".into()));
    }

    #[test]
    fn parse_getent_empty_stdout_returns_none() {
        assert_eq!(parse_getent_hosts_line(""), None);
    }

    #[test]
    fn parse_getent_only_ip_no_hostname_returns_none() {
        let out = "1.2.3.4\n";
        assert_eq!(parse_getent_hosts_line(out), None);
    }

    #[tokio::test]
    async fn resolve_one_rejects_non_ip_input_without_spawning() {
        assert!(resolve_one("attacker.example.com").await.is_none());
        assert!(resolve_one("rm -rf /").await.is_none());
        assert!(resolve_one("foo bar").await.is_none());
    }
}
