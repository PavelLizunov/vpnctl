//! Low-load native service-path quality sampling. No Prometheus agent or
//! external monitor: vpnctld connects directly to the TCP ingress ports
//! declared by each enabled protocol and stores one compact SQLite batch.

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::{Instant, MissedTickBehavior, interval, timeout};
use vpnctl_core::{Registry, Server, ServerId};
use vpnctl_inventory::{
    QUALITY_MIN_SAMPLES, ServiceQualitySample, ServiceQualityScore, SqliteInventory,
};

const DEFAULT_INTERVAL_SECS: u64 = 5 * 60;
const ATTEMPTS_PER_TARGET: u32 = 3;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const QUALITY_ALERT_LOW: u8 = 60;
const QUALITY_ALERT_RECOVER: u8 = 75;
const QUALITY_ALERT_TICKS: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QualityTransition {
    NoChange,
    Degraded,
    StillDegraded,
    Recovered,
}

#[derive(Debug, Default)]
struct QualityAlertState {
    low: HashMap<ServerId, u8>,
    high: HashMap<ServerId, u8>,
    degraded: HashMap<ServerId, bool>,
    healthy_confirmed: HashMap<ServerId, bool>,
}

impl QualityAlertState {
    fn observe(&mut self, server_id: &ServerId, score: Option<u8>) -> QualityTransition {
        let Some(score) = score else {
            self.low.insert(server_id.clone(), 0);
            self.high.insert(server_id.clone(), 0);
            self.healthy_confirmed.insert(server_id.clone(), false);
            return QualityTransition::NoChange;
        };
        let is_degraded = self.degraded.get(server_id).copied().unwrap_or(false);
        if score < QUALITY_ALERT_LOW {
            self.high.insert(server_id.clone(), 0);
            self.healthy_confirmed.insert(server_id.clone(), false);
            let low = self.low.entry(server_id.clone()).or_insert(0);
            *low = low.saturating_add(1);
            if *low >= QUALITY_ALERT_TICKS {
                if is_degraded {
                    QualityTransition::StillDegraded
                } else {
                    self.degraded.insert(server_id.clone(), true);
                    QualityTransition::Degraded
                }
            } else {
                QualityTransition::NoChange
            }
        } else if score >= QUALITY_ALERT_RECOVER {
            self.low.insert(server_id.clone(), 0);
            let high = self.high.entry(server_id.clone()).or_insert(0);
            *high = high.saturating_add(1);
            let already_confirmed = self
                .healthy_confirmed
                .get(server_id)
                .copied()
                .unwrap_or(false);
            if *high >= QUALITY_ALERT_TICKS && (is_degraded || !already_confirmed) {
                self.degraded.insert(server_id.clone(), false);
                self.healthy_confirmed.insert(server_id.clone(), true);
                QualityTransition::Recovered
            } else {
                QualityTransition::NoChange
            }
        } else {
            // Hysteresis band: preserve degraded state, but a partial
            // recovery/failure does not count toward either edge.
            self.low.insert(server_id.clone(), 0);
            self.high.insert(server_id.clone(), 0);
            self.healthy_confirmed.insert(server_id.clone(), false);
            QualityTransition::NoChange
        }
    }

    fn prune(&mut self, live: &std::collections::HashSet<ServerId>) {
        self.low.retain(|id, _| live.contains(id));
        self.high.retain(|id, _| live.contains(id));
        self.degraded.retain(|id, _| live.contains(id));
        self.healthy_confirmed.retain(|id, _| live.contains(id));
    }
}

pub fn spawn_quality_poller(
    inv: SqliteInventory,
    registry: Arc<Registry>,
) -> tokio::task::JoinHandle<()> {
    let interval_secs =
        crate::config::parse_positive_secs("VPNCTLD_QUALITY_INTERVAL_SECS", DEFAULT_INTERVAL_SECS);
    tokio::spawn(async move {
        let mut tick = interval(Duration::from_secs(interval_secs));
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        tick.tick().await;
        let mut alert_state = QualityAlertState::default();
        loop {
            tick.tick().await;
            let servers = match inv.list_servers().await {
                Ok(servers) => servers,
                Err(e) => {
                    tracing::warn!(target = "vpnctld::quality", error = %e, "list_servers failed");
                    continue;
                }
            };
            let live = servers.iter().map(|s| s.id.clone()).collect();
            alert_state.prune(&live);
            for server in &servers {
                if crate::wizard_bootstrap::DeployGuard::is_active(&server.id.0) {
                    tracing::debug!(target = "vpnctld::quality", server = %server.id.0, "quality tick skipped during deploy/update");
                    continue;
                }
                match sample_server(&inv, &registry, server).await {
                    Ok(Some(score)) => {
                        dispatch_quality_alert(&inv, server, &score, &mut alert_state).await;
                    }
                    Ok(None) => {}
                    Err(e) => tracing::warn!(
                        target = "vpnctld::quality",
                        server = %server.id.0,
                        error = %e,
                        "quality sample failed"
                    ),
                }
            }
        }
    })
}

fn declared_tcp_ports(
    registry: &Registry,
    server: &Server,
    secrets: &HashMap<String, String>,
) -> BTreeSet<u16> {
    server
        .enabled_protocols
        .iter()
        .filter_map(|pid| registry.protocol(pid))
        .flat_map(|protocol| protocol.effective_listen_ports(secrets))
        .filter_map(|(transport, port)| transport.eq_ignore_ascii_case("tcp").then_some(port))
        .collect()
}

async fn sample_server(
    inv: &SqliteInventory,
    registry: &Registry,
    server: &Server,
) -> Result<Option<ServiceQualityScore>, anyhow::Error> {
    let secrets = inv.list_server_secrets(&server.id).await?;
    let ports = declared_tcp_ports(registry, server, &secrets);
    let ips = inv.resolved_ips_for_server(&server.id).await?;
    if ips.is_empty() {
        tracing::info!(target = "vpnctld::quality", server = %server.id.0, "no resolved target IP; quality remains unknown");
        return Ok(None);
    }
    let service_targets: Vec<SocketAddr> = ips
        .iter()
        .copied()
        .flat_map(|ip: IpAddr| ports.iter().map(move |port| SocketAddr::new(ip, *port)))
        .collect();
    let control_targets: Vec<SocketAddr> = ips
        .iter()
        .copied()
        .map(|ip| SocketAddr::new(ip, server.ssh_port))
        .collect();

    // Optional secondary signal. `ping` may be absent or forbidden by
    // the host sandbox; either case yields NULL ICMP fields while the
    // TCP service score remains complete.
    let mut ping_jobs = JoinSet::new();
    for ip in ips {
        ping_jobs.spawn_blocking(move || ping_ip(ip));
    }

    let (service, control) = tokio::join!(
        probe_tcp_targets(&service_targets),
        probe_tcp_targets(&control_targets)
    );
    let service = service?;
    let control = control?;
    let mut icmp_attempts = 0u32;
    let mut icmp_successes = 0u32;
    let mut icmp_rtts = Vec::new();
    let mut icmp_available = false;
    while let Some(result) = ping_jobs.join_next().await {
        if let Ok(Some(result)) = result {
            icmp_available = true;
            icmp_attempts = icmp_attempts.saturating_add(result.attempts);
            icmp_successes = icmp_successes.saturating_add(result.successes);
            icmp_rtts.extend(result.rtts);
        }
    }
    let vantage = std::env::var("VPNCTLD_QUALITY_VANTAGE")
        .unwrap_or_else(|_| "192.168.0.236 · vpnctld control host".to_string());
    let sample = ServiceQualitySample {
        ts: Utc::now(),
        server_id: server.id.clone(),
        vantage,
        target_count: service.target_count,
        available_targets: service.available_targets,
        attempts: service.attempts,
        successes: service.successes,
        tcp_rtt_ms: service.rtts,
        control_attempts: control.attempts,
        control_successes: control.successes,
        control_rtt_ms: control.rtts,
        icmp_attempts: icmp_available.then_some(icmp_attempts),
        icmp_successes: icmp_available.then_some(icmp_successes),
        icmp_rtt_ms: icmp_available.then_some(icmp_rtts),
    };
    inv.record_service_quality_sample(&sample).await?;
    let score = inv
        .service_quality_for_server(&server.id, 24, QUALITY_MIN_SAMPLES)
        .await?;
    Ok(Some(score))
}

#[derive(Debug)]
struct TcpBatch {
    target_count: u32,
    available_targets: u32,
    attempts: u32,
    successes: u32,
    rtts: Vec<u32>,
}

async fn probe_tcp_targets(targets: &[SocketAddr]) -> Result<TcpBatch, tokio::task::JoinError> {
    let mut jobs = JoinSet::new();
    for target in targets {
        for _ in 0..ATTEMPTS_PER_TARGET {
            let target = *target;
            jobs.spawn(async move {
                let started = Instant::now();
                let ok = timeout(CONNECT_TIMEOUT, TcpStream::connect(target))
                    .await
                    .is_ok_and(|result| result.is_ok());
                let rtt = ok.then(|| {
                    u32::try_from(started.elapsed().as_millis())
                        .unwrap_or(u32::MAX)
                        .max(1)
                });
                (target, ok, rtt)
            });
        }
    }

    let mut target_up: HashMap<SocketAddr, bool> = targets
        .iter()
        .copied()
        .map(|target| (target, false))
        .collect();
    let mut successes = 0u32;
    let mut rtts = Vec::new();
    while let Some(result) = jobs.join_next().await {
        let (target, ok, rtt) = result?;
        if ok {
            successes = successes.saturating_add(1);
            target_up.insert(target, true);
        }
        if let Some(rtt) = rtt {
            rtts.push(rtt);
        }
    }
    rtts.sort_unstable();
    let target_count = u32::try_from(targets.len()).unwrap_or(u32::MAX);
    Ok(TcpBatch {
        target_count,
        available_targets: u32::try_from(target_up.values().filter(|up| **up).count())
            .unwrap_or(u32::MAX),
        attempts: target_count.saturating_mul(ATTEMPTS_PER_TARGET),
        successes,
        rtts,
    })
}

#[derive(Debug, PartialEq, Eq)]
struct IcmpResult {
    attempts: u32,
    successes: u32,
    rtts: Vec<u32>,
}

fn ping_ip(ip: IpAddr) -> Option<IcmpResult> {
    let ip = ip.to_string();
    let output = Command::new("ping")
        .env("LC_ALL", "C")
        .args(["-n", "-c", "3", "-W", "2", ip.as_str()])
        .output()
        .ok()?;
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    parse_ping_output(&text)
}

fn parse_ping_output(output: &str) -> Option<IcmpResult> {
    let summary = output
        .lines()
        .find(|line| line.contains("packets transmitted"))?;
    let mut fields = summary.split(',');
    let attempts: u32 = fields.next()?.split_whitespace().next()?.parse().ok()?;
    let successes: u32 = fields.next()?.split_whitespace().next()?.parse().ok()?;
    let rtts = output
        .lines()
        .filter_map(|line| line.split_once("time=").map(|(_, tail)| tail))
        .filter_map(|tail| tail.split_whitespace().next())
        .filter_map(|value| value.parse::<f64>().ok())
        .map(|value| value.round().clamp(0.0, f64::from(u32::MAX)) as u32)
        .collect();
    Some(IcmpResult {
        attempts,
        successes: successes.min(attempts),
        rtts,
    })
}

async fn dispatch_quality_alert(
    inv: &SqliteInventory,
    server: &Server,
    score: &ServiceQualityScore,
    state: &mut QualityAlertState,
) {
    match state.observe(&server.id, score.score) {
        QualityTransition::Degraded | QualityTransition::StillDegraded => {
            let summary = format!(
                "service-path quality {} / 100 from {} (availability {:.1}%, loss {:.1}%, p95 {} ms)",
                score.score.unwrap_or(0),
                score.vantage.as_deref().unwrap_or("unknown vantage"),
                score.availability_pct.unwrap_or(0.0),
                score.packet_loss_pct.unwrap_or(100.0),
                score
                    .p95_rtt_ms
                    .map_or_else(|| "—".to_string(), |v| v.to_string()),
            );
            let payload = serde_json::json!({
                "score": score.score,
                "availability_pct": score.availability_pct,
                "packet_loss_pct": score.packet_loss_pct,
                "p95_rtt_ms": score.p95_rtt_ms,
                "jitter_ms": score.jitter_ms,
                "samples": score.sample_count,
                "vantage": score.vantage,
                "low_threshold": QUALITY_ALERT_LOW,
                "recover_threshold": QUALITY_ALERT_RECOVER,
            });
            let payload_json = payload.to_string();
            if let Ok(Some(id)) = inv
                .insert_alert_if_no_unacked(
                    "server.quality.degraded",
                    Some(&server.id),
                    "warning",
                    &summary,
                    Some(&payload_json),
                )
                .await
            {
                crate::node_probe_poller::audit_alert_fire(
                    inv,
                    &server.id,
                    id,
                    "server.quality.degraded",
                    &summary,
                )
                .await;
                let subject = crate::node_probe_poller::server_subject(inv, &server.id).await;
                crate::node_probe_poller::push_alert(
                    inv,
                    "server.quality.degraded",
                    "warning",
                    &subject,
                    &payload,
                    Some(id),
                )
                .await;
            }
        }
        QualityTransition::Recovered => {
            crate::node_probe_poller::auto_ack(
                inv,
                &server.id,
                "server.quality.degraded",
                "service-path score stayed above the recovery threshold",
            )
            .await;
        }
        QualityTransition::NoChange => {}
    }
}

pub async fn purge_old(
    inv: &SqliteInventory,
    days: u32,
) -> Result<u64, vpnctl_inventory::SqliteInventoryError> {
    inv.purge_service_quality_older_than(days).await
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn sampling_budget_stays_low_load() {
        assert_eq!(DEFAULT_INTERVAL_SECS, 300);
        assert_eq!(ATTEMPTS_PER_TARGET, 3);
        assert_eq!(CONNECT_TIMEOUT, Duration::from_secs(2));
    }

    #[test]
    fn service_targets_follow_secret_driven_listen_ports() {
        let mut registry = Registry::new();
        registry
            .register_protocol(Box::new(vpnctl_protocols::VlessReality::new()))
            .expect("register vless");
        let server = Server {
            id: ServerId("de".into()),
            address: "203.0.113.10".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![],
            enabled_protocols: vec![vpnctl_core::ProtocolId("vless+reality".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        };
        let secrets = HashMap::from([("vless.listen_port".into(), "8443".into())]);
        assert_eq!(
            declared_tcp_ports(&registry, &server, &secrets),
            BTreeSet::from([8443])
        );
    }

    #[test]
    fn quality_alert_uses_three_bad_ticks_and_a_separate_recovery_threshold() {
        let id = ServerId("de".into());
        let mut state = QualityAlertState::default();
        assert_eq!(state.observe(&id, Some(59)), QualityTransition::NoChange);
        assert_eq!(state.observe(&id, Some(40)), QualityTransition::NoChange);
        assert_eq!(state.observe(&id, Some(10)), QualityTransition::Degraded);
        assert_eq!(state.observe(&id, Some(65)), QualityTransition::NoChange);
        assert_eq!(state.observe(&id, Some(75)), QualityTransition::NoChange);
        assert_eq!(state.observe(&id, Some(90)), QualityTransition::NoChange);
        assert_eq!(state.observe(&id, Some(80)), QualityTransition::Recovered);
    }

    #[test]
    fn unknown_score_never_becomes_a_false_degraded_state() {
        let id = ServerId("fresh".into());
        let mut state = QualityAlertState::default();
        for _ in 0..10 {
            assert_eq!(state.observe(&id, None), QualityTransition::NoChange);
        }
    }

    #[test]
    fn stable_health_reconciles_a_stale_persisted_alert_once_after_restart() {
        let id = ServerId("de".into());
        let mut state = QualityAlertState::default();
        assert_eq!(state.observe(&id, Some(90)), QualityTransition::NoChange);
        assert_eq!(state.observe(&id, Some(90)), QualityTransition::NoChange);
        assert_eq!(state.observe(&id, Some(90)), QualityTransition::Recovered);
        assert_eq!(state.observe(&id, Some(90)), QualityTransition::NoChange);
    }

    #[test]
    fn parses_linux_ping_as_optional_secondary_signal() {
        let output = "64 bytes from 203.0.113.1: icmp_seq=1 ttl=51 time=23.4 ms\n\
64 bytes from 203.0.113.1: icmp_seq=2 ttl=51 time=25.6 ms\n\
3 packets transmitted, 2 received, 33.3333% packet loss, time 2003ms\n";
        assert_eq!(
            parse_ping_output(output),
            Some(IcmpResult {
                attempts: 3,
                successes: 2,
                rtts: vec![23, 26],
            })
        );
        assert_eq!(parse_ping_output("ping: operation not permitted"), None);
    }
}
