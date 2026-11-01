use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::response::{IntoResponse, Redirect, Response};
use chrono::{DateTime, Utc};
use maud::{Markup, html};
use tokio::sync::Mutex;

use crate::AppState;
use crate::handlers::admin::helpers::{internal_error, render_page, theme_accent_lang};
use crate::i18n::{Locale, tr};

#[derive(Clone, Debug, PartialEq, Eq)]
struct Target {
    server: String,
    address: String,
    ip: Option<IpAddr>,
    protocol: String,
    transport: String,
    port: Option<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Outcome {
    Reachable(u128),
    Failed,
    Refused,
    Timeout,
    Unavailable,
    UdpNotChecked,
}

#[derive(Clone, Debug)]
struct ResultRow {
    source: String,
    target: Target,
    outcome: Outcome,
    time: DateTime<Utc>,
}

#[derive(Default)]
pub(crate) struct PrivateChecks {
    running: Arc<Mutex<()>>,
    rows: Mutex<Vec<ResultRow>>,
    failed: AtomicBool,
    target_offset: AtomicUsize,
    source_offset: AtomicUsize,
}

async fn targets(state: &AppState) -> Result<Vec<Target>, Response> {
    let servers = state
        .inv
        .list_servers()
        .await
        .map_err(|e| internal_error(e.into()))?;
    let mut out = Vec::new();
    for server in servers {
        let secrets = state
            .inv
            .list_server_secrets(&server.id)
            .await
            .map_err(|e| internal_error(e.into()))?;
        let ip = match server.address.parse::<IpAddr>() {
            Ok(ip) => Some(ip),
            Err(_) => state
                .inv
                .resolved_ips_for_server(&server.id)
                .await
                .map_err(|e| internal_error(e.into()))?
                .into_iter()
                .next(),
        };
        for pid in &server.enabled_protocols {
            let ports = state
                .registry
                .protocol(pid)
                .map(|p| p.effective_listen_ports(&secrets))
                .unwrap_or_default();
            if ports.is_empty() {
                out.push(Target {
                    server: server.id.0.clone(),
                    address: server.address.clone(),
                    ip,
                    protocol: pid.0.clone(),
                    transport: "unknown".into(),
                    port: None,
                });
            }
            for (transport, port) in ports {
                out.push(Target {
                    server: server.id.0.clone(),
                    address: server.address.clone(),
                    ip,
                    protocol: pid.0.clone(),
                    transport: transport.into(),
                    port: Some(port),
                });
            }
        }
    }
    Ok(out)
}

async fn probe(target: &Target) -> Outcome {
    if target.transport == "udp" {
        return Outcome::UdpNotChecked;
    }
    let (Some(ip), Some(port)) = (target.ip, target.port) else {
        return Outcome::Unavailable;
    };
    if target.transport != "tcp" || port == 0 {
        return Outcome::Unavailable;
    }
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

// Fixed code only; the SSH command never contains an inventory value.
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
const MAX_TARGETS: usize = 32;
const MAX_SOURCES: usize = 4;
const CONTROLLER_CONCURRENCY: usize = 8;

// A short final batch wraps to zero; nested target/source rotation covers pairs.
fn rotating_batch<T: Clone>(
    items: &[T],
    limit: usize,
    offset: &AtomicUsize,
    advance: bool,
) -> Vec<T> {
    if items.is_empty() || limit == 0 {
        offset.store(0, Ordering::Relaxed);
        return Vec::new();
    }
    let start = offset.load(Ordering::Relaxed) % items.len();
    let end = start.saturating_add(limit).min(items.len());
    let batch = items[start..end].to_vec();
    if advance {
        offset.store(if end == items.len() { 0 } else { end }, Ordering::Relaxed);
    }
    batch
}

fn remote_outcome(
    target: &Target,
    eligible: bool,
    results: Option<&mut std::slice::Iter<'_, Outcome>>,
) -> Outcome {
    if target.transport == "udp" {
        Outcome::UdpNotChecked
    } else if eligible && target.transport == "tcp" && target.port.is_some_and(|p| p != 0) {
        results
            .and_then(Iterator::next)
            .cloned()
            .unwrap_or(Outcome::Unavailable)
    } else {
        Outcome::Unavailable
    }
}

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

async fn remote_rows(
    state: &AppState,
    targets: &[Target],
    source: &vpnctl_core::Server,
) -> Vec<ResultRow> {
    let resolved = state.inv.resolved_ips_for_server(&source.id).await;
    let resolution_ok = resolved.is_ok();
    let mut ips: HashSet<IpAddr> = resolved.unwrap_or_default().into_iter().collect();
    if let Ok(ip) = source.address.parse() {
        ips.insert(ip);
    }
    // If the source address cannot be established, no target is independent.
    let source_known = resolution_ok && !ips.is_empty();
    let eligible = |target: &Target| {
        source_known
            && target.server != source.id.0
            && target.ip.is_some_and(|ip| !ips.contains(&ip))
    };
    let probes: Vec<_> = targets
        .iter()
        .filter(|t| eligible(t) && t.transport == "tcp" && t.port.is_some_and(|p| p != 0))
        .collect();
    let input: Vec<_> = probes
        .iter()
        .filter_map(|t| Some((t.ip?.to_string(), t.port?)))
        .collect();
    let results = async {
        // Do not allow accept-new host keys for probes carrying inventory addresses.
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
    let mut result_iter = results.as_ref().map(|results| results.iter());
    targets
        .iter()
        .map(|target| {
            let outcome = remote_outcome(target, eligible(target), result_iter.as_mut());
            ResultRow {
                source: format!("server: {}", source.id.0),
                target: target.clone(),
                outcome,
                time: Utc::now(),
            }
        })
        .collect()
}

pub(crate) async fn private_checks_run(State(state): State<AppState>) -> Response {
    if let Ok(guard) = Arc::clone(&state.private_checks.running).try_lock_owned() {
        state.private_checks.failed.store(false, Ordering::Release);
        tokio::spawn(async move {
            let _guard = guard;
            state.private_checks.rows.lock().await.clear();
            let work = async {
                let mut all_targets = targets(&state).await.map_err(|_| ())?;
                all_targets.sort_by(|a, b| {
                    (
                        &a.server,
                        &a.protocol,
                        &a.transport,
                        a.port,
                        &a.address,
                        a.ip,
                    )
                        .cmp(&(
                            &b.server,
                            &b.protocol,
                            &b.transport,
                            b.port,
                            &b.address,
                            b.ip,
                        ))
                });
                let targets = rotating_batch(
                    &all_targets,
                    MAX_TARGETS,
                    &state.private_checks.target_offset,
                    true,
                );
                let mut all_sources = state.inv.list_servers().await.map_err(|_| ())?;
                all_sources.sort_by(|a, b| a.id.0.cmp(&b.id.0));
                let sources = rotating_batch(
                    &all_sources,
                    MAX_SOURCES,
                    &state.private_checks.source_offset,
                    state.private_checks.target_offset.load(Ordering::Relaxed) == 0,
                );
                let mut rows = Vec::new();
                // Each group has at most eight two-second TCP attempts, so every
                // selected target gets its full timeout without an early deadline.
                for group in targets.chunks(CONTROLLER_CONCURRENCY) {
                    let mut tasks = tokio::task::JoinSet::new();
                    for target in group.iter().cloned() {
                        tasks.spawn(async move {
                            let outcome = probe(&target).await;
                            ResultRow {
                                source: "controller".into(),
                                target,
                                outcome,
                                time: Utc::now(),
                            }
                        });
                    }
                    while let Some(result) = tasks.join_next().await {
                        rows.push(result.map_err(|_| ())?);
                    }
                }
                // Run at most four sources in parallel. Await every transport worker:
                // dropping one would leave its SSH subprocess running after unlock.
                let mut remote_tasks = tokio::task::JoinSet::new();
                for source in sources {
                    let state = state.clone();
                    let targets = targets.clone();
                    remote_tasks.spawn(async move { remote_rows(&state, &targets, &source).await });
                }
                let mut remote_failed = false;
                while let Some(result) = remote_tasks.join_next().await {
                    match result {
                        Ok(remote) => rows.extend(remote),
                        Err(_) => remote_failed = true,
                    }
                }
                if remote_failed {
                    return Err(());
                }
                *state.private_checks.rows.lock().await = rows;
                Ok::<(), ()>(())
            };
            if work.await.is_err() {
                state.private_checks.rows.lock().await.clear();
                state.private_checks.failed.store(true, Ordering::Release);
            }
        });
    }
    Redirect::to("/admin/monitoring/private-checks").into_response()
}

pub(crate) async fn private_checks_page(
    headers: axum::http::HeaderMap,
    State(state): State<AppState>,
) -> Result<Markup, Response> {
    let (theme, accent, lang) = theme_accent_lang(&headers);
    let targets = targets(&state).await?;
    let rows = state.private_checks.rows.lock().await.clone();
    let running = state.private_checks.running.try_lock().is_err();
    let now = Utc::now();
    let body = html! {
        h1 { (tr(lang, "Private network checks", "Приватные сетевые проверки")) }
        p { (tr(lang, "TCP reachability only: not a VPN handshake or a censorship test. UDP is not checked. No third-party service is used.", "Только доступность TCP: это не VPN handshake и не проверка блокировки. UDP не проверяется. Сторонние сервисы не используются.")) }
        p { (tr(lang, "Results are kept in memory until restart; hostname checks use the first inventory-resolved IP. Each run checks a rotating batch of up to 32 targets and 4 server sources; repeat runs to cover the rest. Only the latest batch is shown. Server sources are controls, not residential networks.", "Результаты хранятся в памяти до перезапуска; для имени используется первый IP из инвентаря. Каждый запуск проверяет очередную группу до 32 целей и 4 серверов-источников; повторите запуск для остальных. Показаны только результаты последней группы. Серверы — контрольные точки, не домашние сети.")) }
        form method="post" action="/admin/monitoring/private-checks" { button class="ed-abtn ed-abtn--secondary" style="min-height:44px;" type="submit" disabled[running] { (tr(lang, "Run checks", "Запустить проверку")) } }
        @if running { p { (tr(lang, "Check in progress. Refresh this page for results.", "Проверка выполняется. Обновите страницу для результатов.")) } }
        @if state.private_checks.failed.load(Ordering::Acquire) { p { (tr(lang, "The last sweep failed or timed out; no results are available.", "Последний обход завершился ошибкой или по тайм-ауту; результаты недоступны.")) } }
        @if targets.is_empty() { p { (tr(lang, "No servers with configured protocols; no results yet.", "Нет серверов с настроенными протоколами; результатов пока нет.")) } }
        @else {
            div style="overflow-x:auto;" { table.ed-grid { thead { tr { th { (tr(lang, "Server", "Сервер")) } th { (tr(lang, "Protocol / port", "Протокол / порт")) } th { (tr(lang, "Source", "Источник")) } th { (tr(lang, "Result", "Результат")) } th { (tr(lang, "Time / latency", "Время / задержка")) } } } tbody {
                @for target in &targets {
                    @let row = rows.iter().find(|r| r.source == "controller" && r.target == *target);
                    tr { td { (&target.server) } td { (&target.protocol) " · " (&target.transport) " / " (target.port.map(|p| p.to_string()).unwrap_or_else(|| "—".into())) } td { "controller" @if let Some(ip) = target.ip { " → " (ip) } } td {
                        @if let Some(row) = row {
                            (outcome_text(&row.outcome, lang))
                            @if now.signed_duration_since(row.time) > chrono::Duration::hours(1) { " · " (tr(lang, "stale", "устарело")) }
                        } @else if target.transport == "udp" { (tr(lang, "UDP not checked", "UDP не проверен")) } @else { (tr(lang, "Not checked", "Не проверено")) }
                    } td { @if let Some(row) = row { (row.time.format("%Y-%m-%d %H:%M:%S UTC")) @if let Outcome::Reachable(ms) = row.outcome { " · " (ms) " ms" } } @else { "—" } } }
                }
                @for row in rows.iter().filter(|r| r.source != "controller" && targets.contains(&r.target)) {
                    tr { td { (&row.target.server) } td { (&row.target.protocol) " · " (&row.target.transport) " / " (row.target.port.map(|p| p.to_string()).unwrap_or_else(|| "—".into())) } td { (&row.source) @if let Some(ip) = row.target.ip { " → " (ip) } } td { (outcome_text(&row.outcome, lang)) @if now.signed_duration_since(row.time) > chrono::Duration::hours(1) { " · " (tr(lang, "stale", "устарело")) } } td { (row.time.format("%Y-%m-%d %H:%M:%S UTC")) @if let Outcome::Reachable(ms) = row.outcome { " · " (ms) " ms" } } }
                }
            } } }
        }
    };
    Ok(render_page(&state, "monitoring", &theme, &accent, lang, body).await)
}

fn outcome_text(outcome: &Outcome, lang: Locale) -> &'static str {
    match outcome {
        Outcome::Reachable(_) => tr(lang, "TCP reachable", "TCP доступен"),
        Outcome::Failed => tr(lang, "TCP connection failed", "Ошибка TCP-соединения"),
        Outcome::Refused => tr(lang, "TCP connection refused", "TCP-соединение отклонено"),
        Outcome::Timeout => tr(lang, "TCP connection timed out", "Тайм-аут TCP-соединения"),
        Outcome::Unavailable => tr(
            lang,
            "Unavailable / not checked",
            "Недоступно / не проверено",
        ),
        Outcome::UdpNotChecked => tr(lang, "UDP not checked", "UDP не проверен"),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
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
    fn remote_parser_rejects_incomplete_and_untrusted_results() {
        assert_eq!(
            parse_remote(
                br#"[["ok",12],["timeout",0],["refused",0],["failed",0]]"#,
                4
            ),
            Some(vec![
                Outcome::Reachable(12),
                Outcome::Timeout,
                Outcome::Refused,
                Outcome::Failed
            ])
        );
        assert_eq!(parse_remote(br#"[["ok",12]]"#, 2), None);
        assert_eq!(parse_remote(br#"[["ok",15001]]"#, 1), None);
        assert_eq!(parse_remote(br#"[["refused",1]]"#, 1), None);
        assert_eq!(parse_remote(b"invalid", 1), None);
    }
    #[test]
    fn rotating_batches_cover_all_source_target_pairs() {
        let target_offset = AtomicUsize::new(0);
        let source_offset = AtomicUsize::new(0);
        let targets: Vec<_> = (0..65).collect();
        let sources: Vec<_> = (0..9).collect();
        let mut pairs = HashSet::new();
        for _ in 0..9 {
            let batch = rotating_batch(&targets, 32, &target_offset, true);
            let sources = rotating_batch(
                &sources,
                4,
                &source_offset,
                target_offset.load(Ordering::Relaxed) == 0,
            );
            for target in batch {
                for source in &sources {
                    pairs.insert((target, *source));
                }
            }
        }
        assert_eq!(pairs.len(), targets.len() * sources.len());
        assert!(rotating_batch::<u8>(&[], 32, &target_offset, true).is_empty());
    }

    #[test]
    fn remote_udp_is_not_checked_regardless_of_source_or_ssh() {
        let udp = target(8444, "udp");
        let tcp = target(443, "tcp");
        assert_eq!(remote_outcome(&udp, false, None), Outcome::UdpNotChecked);
        assert_eq!(remote_outcome(&udp, true, None), Outcome::UdpNotChecked);
        assert_eq!(remote_outcome(&tcp, false, None), Outcome::Unavailable);
        assert_eq!(remote_outcome(&tcp, true, None), Outcome::Unavailable);
        let values = [Outcome::Reachable(3)];
        let mut iter = values.iter();
        assert_eq!(
            remote_outcome(&udp, false, Some(&mut iter)),
            Outcome::UdpNotChecked
        );
        assert_eq!(
            remote_outcome(&tcp, true, Some(&mut iter)),
            Outcome::Reachable(3)
        );
    }

    #[tokio::test]
    async fn tcp_and_udp_semantics() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(matches!(
            probe(&target(port, "tcp")).await,
            Outcome::Reachable(_)
        ));
        assert_eq!(probe(&target(port, "udp")).await, Outcome::UdpNotChecked);
        drop(listener);
        assert_eq!(probe(&target(port, "tcp")).await, Outcome::Refused);
        let mut missing = target(port, "tcp");
        missing.ip = None;
        assert_eq!(probe(&missing).await, Outcome::Unavailable);
    }
}
