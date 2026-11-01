use std::net::{IpAddr, SocketAddr};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
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
    Timeout,
    Unavailable,
    UdpNotChecked,
}

#[derive(Clone, Debug)]
struct ResultRow {
    target: Target,
    outcome: Outcome,
    time: DateTime<Utc>,
}

#[derive(Default)]
pub(crate) struct PrivateChecks {
    running: Arc<Mutex<()>>,
    rows: Mutex<Vec<ResultRow>>,
    failed: AtomicBool,
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
        Ok(Err(_)) => Outcome::Failed,
        Err(_) => Outcome::Timeout,
    }
}

pub(crate) async fn private_checks_run(State(state): State<AppState>) -> Response {
    if let Ok(guard) = Arc::clone(&state.private_checks.running).try_lock_owned() {
        state.private_checks.failed.store(false, Ordering::Release);
        tokio::spawn(async move {
            let _guard = guard;
            state.private_checks.rows.lock().await.clear();
            // ponytail: one sequential sweep with a deadline; add parallelism only if needed.
            let work = async {
                let targets = targets(&state).await.map_err(|_| ())?;
                let mut rows = Vec::with_capacity(targets.len());
                let deadline = Instant::now() + Duration::from_secs(60);
                for target in targets {
                    let outcome = if target.transport == "udp" {
                        Outcome::UdpNotChecked
                    } else if Instant::now() >= deadline {
                        Outcome::Unavailable
                    } else {
                        tokio::time::timeout_at(
                            tokio::time::Instant::from_std(deadline),
                            probe(&target),
                        )
                        .await
                        .unwrap_or(Outcome::Unavailable)
                    };
                    rows.push(ResultRow {
                        target,
                        outcome,
                        time: Utc::now(),
                    });
                }
                *state.private_checks.rows.lock().await = rows;
                Ok::<(), ()>(())
            };
            if !matches!(
                tokio::time::timeout(Duration::from_secs(65), work).await,
                Ok(Ok(()))
            ) {
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
        h1 { (tr(lang, "Private controller checks", "Приватная проверка с контроллера")) }
        p { (tr(lang, "TCP reachability only: not a VPN handshake or a censorship test. UDP is not checked. No third-party service is used.", "Только доступность TCP: это не VPN handshake и не проверка блокировки. UDP не проверяется. Сторонние сервисы не используются.")) }
        p { (tr(lang, "Results are kept in memory until restart; hostname checks use the first inventory-resolved IP.", "Результаты хранятся в памяти до перезапуска; для имени используется первый IP из инвентаря.")) }
        form method="post" action="/admin/monitoring/private-checks" { button class="ed-abtn ed-abtn--secondary" style="min-height:44px;" type="submit" disabled[running] { (tr(lang, "Run checks", "Запустить проверку")) } }
        @if running { p { (tr(lang, "Check in progress. Refresh this page for results.", "Проверка выполняется. Обновите страницу для результатов.")) } }
        @if state.private_checks.failed.load(Ordering::Acquire) { p { (tr(lang, "The last sweep failed or timed out; no results are available.", "Последний обход завершился ошибкой или по тайм-ауту; результаты недоступны.")) } }
        @if targets.is_empty() { p { (tr(lang, "No servers with configured protocols; no results yet.", "Нет серверов с настроенными протоколами; результатов пока нет.")) } }
        @else {
            div style="overflow-x:auto;" { table.ed-grid { thead { tr { th { (tr(lang, "Server", "Сервер")) } th { (tr(lang, "Protocol / port", "Протокол / порт")) } th { (tr(lang, "Source", "Источник")) } th { (tr(lang, "Result", "Результат")) } th { (tr(lang, "Time / latency", "Время / задержка")) } } } tbody {
                @for target in &targets {
                    @let row = rows.iter().find(|r| r.target == *target);
                    tr { td { (&target.server) } td { (&target.protocol) " · " (&target.transport) " / " (target.port.map(|p| p.to_string()).unwrap_or_else(|| "—".into())) } td { "controller" @if let Some(ip) = target.ip { " → " (ip) } } td {
                        @if let Some(row) = row {
                            (outcome_text(&row.outcome, lang))
                            @if now.signed_duration_since(row.time) > chrono::Duration::hours(1) { " · " (tr(lang, "stale", "устарело")) }
                        } @else if target.transport == "udp" { (tr(lang, "UDP not checked", "UDP не проверен")) } @else { (tr(lang, "Not checked", "Не проверено")) }
                    } td { @if let Some(row) = row { (row.time.format("%Y-%m-%d %H:%M:%S UTC")) @if let Outcome::Reachable(ms) = row.outcome { " · " (ms) " ms" } } @else { "—" } } }
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
        assert_eq!(probe(&target(port, "tcp")).await, Outcome::Failed);
        let mut missing = target(port, "tcp");
        missing.ip = None;
        assert_eq!(probe(&missing).await, Outcome::Unavailable);
    }
}
