//! Per-protocol assurance on top of the existing quality cadence.
//!
//! Built-in checks never claim a protocol handshake: render, listener and TCP
//! reachability are classified locally. Full client handshakes are delegated to
//! an optional operator-owned runner (`VPNCTLD_PROTOCOL_ASSURANCE_RUNNER`).
//! The runner receives JSON on stdin; its stdout must be one small JSON result.

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::net::{TcpStream, lookup_host};
use tokio::time::{MissedTickBehavior, interval, timeout};
use vpnctl_core::{Protocol, Registry, RenderCtx, Server};
use vpnctl_inventory::{
    AssuranceStage, AssuranceState, ProtocolAssuranceSample, SqliteInventory,
};

const DEFAULT_INTERVAL_SECS: u64 = 10 * 60;
const TCP_TIMEOUT: Duration = Duration::from_secs(3);
const RUNNER_TIMEOUT: Duration = Duration::from_secs(30);
const NODE_HEALTH_MAX_AGE: chrono::Duration = chrono::Duration::minutes(20);
const CLIENT_KIND: &str = "vpnctl-builtin";

#[derive(Debug, Serialize)]
struct RunnerRequest<'a> {
    server: &'a str,
    protocol: &'a str,
    ports: &'a [(&'a str, u16)],
}

#[derive(Debug, Deserialize)]
struct RunnerResult {
    stage: AssuranceStage,
    state: AssuranceState,
    latency_ms: Option<u64>,
    failure_code: Option<String>,
    #[serde(default = "runner_client_kind")]
    client_kind: String,
}

fn runner_client_kind() -> String {
    "external-runner".into()
}

enum RunnerAttempt {
    NotConfigured,
    Result(RunnerResult),
    Failed(&'static str),
}

pub fn spawn_protocol_assurance_poller(
    inv: SqliteInventory,
    registry: Arc<Registry>,
) -> tokio::task::JoinHandle<()> {
    let seconds = crate::config::parse_positive_secs(
        "VPNCTLD_PROTOCOL_ASSURANCE_INTERVAL_SECS",
        DEFAULT_INTERVAL_SECS,
    );
    tokio::spawn(async move {
        let mut tick = interval(Duration::from_secs(seconds));
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        tick.tick().await;
        loop {
            tick.tick().await;
            let servers = match inv.list_servers().await {
                Ok(servers) => servers,
                Err(error) => {
                    tracing::warn!(target = "vpnctld::assurance", %error, "list_servers failed");
                    continue;
                }
            };
            let mut jobs = tokio::task::JoinSet::new();
            let permits = Arc::new(tokio::sync::Semaphore::new(4));
            for server in servers {
                if crate::wizard_bootstrap::DeployGuard::is_active(&server.id.0) {
                    continue;
                }
                let inv = inv.clone();
                let registry = Arc::clone(&registry);
                let permits = Arc::clone(&permits);
                jobs.spawn(async move {
                    let Ok(_permit) = permits.acquire_owned().await else {
                        return;
                    };
                    for protocol_id in &server.enabled_protocols {
                        let Some(protocol) = registry.protocol(protocol_id) else {
                            continue;
                        };
                        match sample_protocol(&inv, &server, protocol).await {
                            Ok(sample) => {
                                if let Err(error) = persist_and_alert(&inv, &sample).await {
                                    tracing::warn!(target = "vpnctld::assurance", server = %server.id.0, protocol = %protocol_id.0, %error, "persist/alert failed");
                                }
                            }
                            Err(error) => tracing::warn!(target = "vpnctld::assurance", server = %server.id.0, protocol = %protocol_id.0, %error, "protocol sample failed"),
                        }
                    }
                });
            }
            while let Some(result) = jobs.join_next().await {
                if let Err(error) = result {
                    tracing::warn!(target = "vpnctld::assurance", %error, "server assurance task failed");
                }
            }
        }
    })
}

async fn sample_protocol(
    inv: &SqliteInventory,
    server: &Server,
    protocol: &dyn Protocol,
) -> anyhow::Result<ProtocolAssuranceSample> {
    let secrets = inv.list_server_secrets(&server.id).await?;
    let users = inv.users_for_server(&server.id).await?;
    let ctx = RenderCtx::with_peers(server, &secrets, &users);
    let client_render_ok = users
        .iter()
        .filter(|user| !user.disabled)
        .any(|user| protocol.client_config(&ctx, user).is_ok());
    if protocol.server_inbound(&ctx, &users).is_err() {
        return Ok(sample(
            server,
            protocol,
            CLIENT_KIND,
            AssuranceStage::Render,
            AssuranceState::Blocked,
            None,
            Some("render_failed"),
        ));
    }
    let ports = protocol.effective_listen_ports(&secrets);
    let expected: HashSet<String> = ports
        .iter()
        .map(|(transport, port)| format!("{}/{port}", transport.to_ascii_lowercase()))
        .collect();
    let Some(health) = inv.latest_node_health(&server.id).await? else {
        return Ok(sample(
            server,
            protocol,
            CLIENT_KIND,
            AssuranceStage::Listener,
            AssuranceState::Unknown,
            None,
            Some("probe_data_unavailable"),
        ));
    };
    if Utc::now().signed_duration_since(health.ts) > NODE_HEALTH_MAX_AGE {
        return Ok(sample(
            server,
            protocol,
            CLIENT_KIND,
            AssuranceStage::Listener,
            AssuranceState::Unknown,
            None,
            Some("probe_data_stale"),
        ));
    }
    let Some(live_json) = health.listening_ports_json else {
        return Ok(sample(
            server,
            protocol,
            CLIENT_KIND,
            AssuranceStage::Listener,
            AssuranceState::Unknown,
            None,
            Some("probe_data_unavailable"),
        ));
    };
    let live: HashSet<String> = serde_json::from_str(&live_json).unwrap_or_default();
    if !expected.is_empty() && !expected.is_subset(&live) {
        return Ok(sample(
            server,
            protocol,
            CLIENT_KIND,
            AssuranceStage::Listener,
            AssuranceState::Blocked,
            None,
            Some("listener_missing"),
        ));
    }

    match run_external_runner(server, protocol, &ports).await? {
        RunnerAttempt::Result(result) => {
            let failure_code = result
                .failure_code
                .as_deref()
                .filter(|value| {
                    !value.is_empty()
                        && value.len() <= 64
                        && value
                            .chars()
                            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
                })
                .or(result.failure_code.as_ref().map(|_| "runner_invalid_failure_code"));
            return Ok(sample(
                server,
                protocol,
                &result.client_kind,
                result.stage,
                result.state,
                result.latency_ms,
                failure_code,
            ));
        }
        RunnerAttempt::Failed(code) => {
            return Ok(sample(
                server,
                protocol,
                "external-runner",
                AssuranceStage::Handshake,
                AssuranceState::Unknown,
                None,
                Some(code),
            ));
        }
        RunnerAttempt::NotConfigured => {}
    }

    let tcp_ports: Vec<u16> = ports
        .iter()
        .filter_map(|(transport, port)| transport.eq_ignore_ascii_case("tcp").then_some(*port))
        .collect();
    if tcp_ports.is_empty() {
        return Ok(sample(
            server,
            protocol,
            CLIENT_KIND,
            AssuranceStage::ExternalPath,
            AssuranceState::Unknown,
            None,
            Some("udp_path_unverified"),
        ));
    }
    let started = Instant::now();
    for port in tcp_ports {
        let targets: Vec<SocketAddr> = match timeout(
            TCP_TIMEOUT,
            lookup_host((server.address.as_str(), port)),
        )
        .await
        {
            Ok(Ok(targets)) => targets.collect(),
            _ => {
                return Ok(sample(
                    server,
                    protocol,
                    CLIENT_KIND,
                    AssuranceStage::ExternalPath,
                    AssuranceState::Blocked,
                    None,
                    Some("dns_lookup_failed"),
                ));
            }
        };
        let mut connected = false;
        for target in targets {
            if timeout(TCP_TIMEOUT, TcpStream::connect(target))
                .await
                .is_ok_and(|result| result.is_ok())
            {
                connected = true;
                break;
            }
        }
        if !connected {
            return Ok(sample(
                server,
                protocol,
                CLIENT_KIND,
                AssuranceStage::ExternalPath,
                AssuranceState::Blocked,
                None,
                Some("tcp_connect_failed"),
            ));
        }
    }
    Ok(sample(
        server,
        protocol,
        CLIENT_KIND,
        AssuranceStage::ExternalPath,
        AssuranceState::Unknown,
        Some(started.elapsed().as_millis() as u64),
        Some(if client_render_ok {
            "tcp_path_only"
        } else {
            "no_probe_identity"
        }),
    ))
}

fn sample(
    server: &Server,
    protocol: &dyn Protocol,
    client_kind: &str,
    stage: AssuranceStage,
    state: AssuranceState,
    latency_ms: Option<u64>,
    failure_code: Option<&str>,
) -> ProtocolAssuranceSample {
    ProtocolAssuranceSample {
        ts: Utc::now(),
        server_id: server.id.clone(),
        protocol_id: protocol.id(),
        client_kind: sanitize_client_kind(client_kind),
        stage,
        state,
        latency_ms,
        failure_code: failure_code.map(|value| value.chars().take(128).collect()),
    }
}

async fn run_external_runner(
    server: &Server,
    protocol: &dyn Protocol,
    ports: &[(&str, u16)],
) -> anyhow::Result<RunnerAttempt> {
    let Ok(runner) = std::env::var("VPNCTLD_PROTOCOL_ASSURANCE_RUNNER") else {
        return Ok(RunnerAttempt::NotConfigured);
    };
    let runner = std::path::PathBuf::from(runner.trim());
    if !runner.is_absolute() {
        tracing::warn!(target = "vpnctld::assurance", "runner path must be absolute");
        return Ok(RunnerAttempt::Failed("runner_invalid_path"));
    }
    if std::fs::symlink_metadata(&runner).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        tracing::warn!(target = "vpnctld::assurance", "runner path must not be a symlink");
        return Ok(RunnerAttempt::Failed("runner_unsafe_path"));
    }
    let runner = match std::fs::canonicalize(&runner) {
        Ok(path) => path,
        Err(error) => {
            tracing::warn!(target = "vpnctld::assurance", %error, "runner canonicalization failed");
            return Ok(RunnerAttempt::Failed("runner_unavailable"));
        }
    };
    let metadata = match std::fs::metadata(&runner) {
        Ok(metadata) => metadata,
        Err(error) => {
            tracing::warn!(target = "vpnctld::assurance", %error, "runner metadata unavailable");
            return Ok(RunnerAttempt::Failed("runner_unavailable"));
        }
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 || metadata.mode() & 0o111 == 0 {
            tracing::warn!(target = "vpnctld::assurance", "runner must be root-owned, executable and not group/world writable");
            return Ok(RunnerAttempt::Failed("runner_unsafe_permissions"));
        }
        for parent in runner.ancestors().skip(1).take_while(|path| !path.as_os_str().is_empty()) {
            if let Ok(parent_meta) = std::fs::metadata(parent) {
                if parent_meta.uid() != 0 || parent_meta.mode() & 0o022 != 0 {
                    tracing::warn!(target = "vpnctld::assurance", "runner parent directory is not trusted");
                    return Ok(RunnerAttempt::Failed("runner_unsafe_path"));
                }
            }
        }
    }
    let request = serde_json::to_vec(&RunnerRequest {
        server: &server.address,
        protocol: &protocol.id().0,
        ports,
    })?;
    if request.len() > 64 * 1024 {
        tracing::warn!(target = "vpnctld::assurance", "runner request exceeds 64 KiB");
        return Ok(RunnerAttempt::Failed("runner_request_too_large"));
    }
    match tokio::task::spawn_blocking(move || run_runner_process(&runner, &request)).await {
        Ok(Ok(Some(result))) => Ok(RunnerAttempt::Result(result)),
        Ok(Ok(None)) => Ok(RunnerAttempt::Failed("runner_invalid_result")),
        Ok(Err(error)) => {
            tracing::warn!(target = "vpnctld::assurance", %error, "external assurance runner failed");
            Ok(RunnerAttempt::Failed("runner_failed"))
        }
        Err(error) => {
            tracing::warn!(target = "vpnctld::assurance", %error, "external assurance runner task failed");
            Ok(RunnerAttempt::Failed("runner_task_failed"))
        }
    }
}

fn run_runner_process(
    runner: &std::path::Path,
    request: &[u8],
) -> anyhow::Result<Option<RunnerResult>> {
    run_runner_process_with_timeout(runner, request, RUNNER_TIMEOUT)
}

fn run_runner_process_with_timeout(
    runner: &std::path::Path,
    request: &[u8],
    runner_timeout: Duration,
) -> anyhow::Result<Option<RunnerResult>> {
    let mut child = {
        let mut last_error = None;
        let mut child = None;
        for _ in 0..3 {
            match Command::new(runner)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
            {
                Ok(spawned) => {
                    child = Some(spawned);
                    break;
                }
                Err(error) if error.raw_os_error() == Some(26) => {
                    last_error = Some(error);
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error.into()),
            }
        }
        match (child, last_error) {
            (Some(child), _) => child,
            (None, Some(error)) => return Err(error.into()),
            (None, None) => anyhow::bail!("runner spawn produced no result"),
        }
    };
    let request = request.to_vec();
    let mut writer = child.stdin.take().map(|mut stdin| {
        std::thread::spawn(move || {
            let _ = stdin.write_all(&request);
        })
    });
    let stdout = child.stdout.take();
    let mut reader = stdout.map(|mut stdout| {
        std::thread::spawn(move || {
            let mut kept = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let read = stdout.read(&mut buf).unwrap_or(0);
                if read == 0 {
                    break;
                }
                if kept.len() <= 4096 {
                    let remaining = 4097usize.saturating_sub(kept.len());
                    kept.extend_from_slice(&buf[..read.min(remaining)]);
                }
            }
            kept
        })
    });
    let deadline = Instant::now() + runner_timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            if let Some(writer) = writer.take() {
                let _ = writer.join();
            }
            let output = reader.take().and_then(|reader| reader.join().ok()).unwrap_or_default();
            if !status.success() || output.len() > 4096 {
                return Ok(None);
            }
            return Ok(Some(serde_json::from_slice(&output)?));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            if let Some(writer) = writer.take() {
                let _ = writer.join();
            }
            if let Some(reader) = reader.take() {
                let _ = reader.join();
            }
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn sanitize_client_kind(value: &str) -> String {
    let value: String = value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .take(64)
        .collect();
    if value.is_empty() {
        "external-runner".into()
    } else {
        value
    }
}

fn assurance_alert_kind(protocol: &str) -> String {
    format!("protocol.assurance.failed.{protocol}")
}

async fn persist_and_alert(
    inv: &SqliteInventory,
    sample: &ProtocolAssuranceSample,
) -> anyhow::Result<()> {
    let previous = inv.latest_protocol_assurance_for_server(&sample.server_id).await?;
    let previous_builtin_failed = previous.iter().any(|row| {
        row.protocol_id == sample.protocol_id
            && row.client_kind == CLIENT_KIND
            && matches!(row.state, AssuranceState::Blocked | AssuranceState::Degraded)
    });
    let kind = assurance_alert_kind(&sample.protocol_id.0);
    let has_open = inv
        .has_unacked_alert(&kind, Some(&sample.server_id))
        .await
        .unwrap_or(false);
    inv.record_protocol_assurance_sample(sample).await?;
    let failed = matches!(sample.state, AssuranceState::Blocked | AssuranceState::Degraded);
    if failed {
        let payload = serde_json::json!({
            "protocol": sample.protocol_id.0,
            "client_kind": sample.client_kind,
            "stage": sample.stage.as_str(),
            "state": sample.state.as_str(),
            "failure_code": sample.failure_code,
        });
        let summary = format!(
            "protocol {} assurance failed at {}",
            sample.protocol_id.0,
            sample.stage.as_str()
        );
        if let Some(id) = inv
            .insert_alert_if_no_unacked(
                &kind,
                Some(&sample.server_id),
                "warning",
                &summary,
                Some(&payload.to_string()),
            )
            .await?
        {
            crate::node_probe_poller::audit_alert_fire(
                inv,
                &sample.server_id,
                id,
                &kind,
                &summary,
            )
            .await;
            let subject = crate::node_probe_poller::server_subject(inv, &sample.server_id).await;
            crate::node_probe_poller::push_alert(
                inv,
                &kind,
                "warning",
                &subject,
                &payload,
                Some(id),
            )
            .await;
        }
    } else if has_open
        && (sample.state == AssuranceState::Verified
            || (previous_builtin_failed
                && sample.client_kind == CLIENT_KIND
                && sample.state == AssuranceState::Unknown
                && matches!(
                    sample.failure_code.as_deref(),
                    Some("tcp_path_only" | "udp_path_unverified" | "no_probe_identity")
                )))
    {
        let payload = serde_json::json!({
            "protocol": sample.protocol_id.0,
            "client_kind": sample.client_kind,
            "stage": sample.stage.as_str(),
            "state": sample.state.as_str(),
            "latency_ms": sample.latency_ms,
        });
        let subject = crate::node_probe_poller::server_subject(inv, &sample.server_id).await;
        crate::node_probe_poller::recover_alert(
            inv,
            &kind,
            &kind,
            &subject,
            &payload,
            Some(&sample.server_id),
            None,
        )
        .await;
        crate::node_probe_poller::auto_ack(
            inv,
            &sample.server_id,
            &kind,
            "protocol assurance recovered",
        )
        .await;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn script(body: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("runner.sh");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&path, permissions).unwrap();
        (dir, path)
    }

    #[test]
    fn alert_kind_is_canonical_per_protocol() {
        assert_eq!(
            assurance_alert_kind("hysteria2"),
            "protocol.assurance.failed.hysteria2"
        );
    }

    #[test]
    fn client_kind_is_bounded_and_sanitized() {
        assert_eq!(sanitize_client_kind("xray client!?"), "xrayclient");
        assert_eq!(sanitize_client_kind("!?"), "external-runner");
    }

    #[test]
    fn runner_parses_bounded_sanitized_result() {
        let (_dir, runner) = script("cat >/dev/null; printf '%s' '{\"stage\":\"transfer\",\"state\":\"verified\",\"latency_ms\":12,\"failure_code\":null,\"client_kind\":\"xray\"}'");
        let result = run_runner_process_with_timeout(
            &runner,
            b"{}",
            Duration::from_secs(1),
        )
        .unwrap()
        .unwrap();
        assert_eq!(result.stage, AssuranceStage::Transfer);
        assert_eq!(result.state, AssuranceState::Verified);
        assert_eq!(result.client_kind, "xray");
    }

    #[test]
    fn runner_timeout_is_unknown_not_verified() {
        let (_dir, runner) = script("sleep 2");
        let result = run_runner_process_with_timeout(
            &runner,
            b"{}",
            Duration::from_millis(50),
        )
        .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn oversized_runner_output_is_rejected() {
        let (_dir, runner) = script("cat >/dev/null; head -c 5000 /dev/zero");
        let result = run_runner_process_with_timeout(
            &runner,
            b"{}",
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(result.is_none());
    }
}

pub async fn purge_old(
    inv: &SqliteInventory,
    days: u32,
) -> Result<u64, vpnctl_inventory::SqliteInventoryError> {
    inv.purge_protocol_assurance_older_than(days).await
}
