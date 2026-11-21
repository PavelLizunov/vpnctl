use std::convert::Infallible;
use std::future::Future;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use serde_json::json;
use tokio_stream::wrappers::ReceiverStream;
use vpnctl_core::{ProtocolId, ServerId};
use vpnctl_inventory::{AssuranceState, ProtocolAssuranceSample};

use crate::AppState;
use crate::handlers::admin::helpers::{error_resp, internal_error, not_found};
use crate::i18n::{Locale, tr};

pub(crate) async fn dnstt_check(
    Path(id): Path<String>,
    uri: Uri,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Response {
    if let Some(response) = super::sse_ticket::refuse_without_ticket(&uri) {
        return response;
    }
    let lang = Locale::from_request(&headers);
    let Some(runner) = state.dnstt_check_runner.clone() else {
        return not_found(tr(
            lang,
            "DNSTT transfer check is not configured.",
            "Проверка DNSTT не настроена.",
        ));
    };
    let sid = ServerId(id);
    let server = match state.inv.get_server(&sid).await {
        Ok(Some(server)) => server,
        Ok(None) => return not_found(tr(lang, "VPN server not found.", "VPN-сервер не найден.")),
        Err(error) => return internal_error(error.into()),
    };
    let protocol = ProtocolId("dnstt".into());
    if !server.enabled_protocols.contains(&protocol) {
        return error_resp(
            StatusCode::BAD_REQUEST,
            tr(
                lang,
                "DNSTT is disabled on this server.",
                "DNSTT выключен на этом сервере.",
            ),
        );
    }
    let Some(guard) = crate::wizard_bootstrap::DeployGuard::try_acquire(&sid.0) else {
        return error_resp(
            StatusCode::CONFLICT,
            tr(
                lang,
                "An operation is already running on this server.",
                "На сервере уже выполняется операция.",
            ),
        );
    };
    let (sender, receiver) = tokio::sync::mpsc::channel(1);
    tokio::spawn(async move {
        let sample = async {
            let registered = state
                .registry
                .protocol(&protocol)
                .ok_or_else(|| anyhow::anyhow!("DNSTT is not registered"))?;
            crate::protocol_assurance_poller::sample_dnstt_on_demand(&server, registered, runner)
                .await
        };
        let event = match run_check(&state, &server, &protocol, sample, lang).await {
            Ok(event) => event,
            Err(error) => {
                tracing::warn!(target: "vpnctld::assurance", server = %sid, %error, "manual DNSTT check could not be recorded");
                Event::default().event("error").data(json!({
                    "message": tr(lang, "Could not record the DNSTT check.", "Не удалось сохранить результат проверки DNSTT."),
                }).to_string())
            }
        };
        drop(guard);
        let _ = sender.send(Ok::<_, Infallible>(event)).await;
    });
    Sse::new(ReceiverStream::new(receiver))
        .keep_alive(KeepAlive::default())
        .into_response()
}

async fn run_check(
    state: &AppState,
    server: &vpnctl_core::Server,
    protocol_id: &ProtocolId,
    sample: impl Future<Output = anyhow::Result<ProtocolAssuranceSample>>,
    lang: Locale,
) -> anyhow::Result<Event> {
    let sid = &server.id;
    let revision = state.inv.deploy_input_revision(sid).await?;
    let current = state.inv.get_server(sid).await?;
    anyhow::ensure!(
        current.is_some_and(|current| current.address == server.address
            && current.enabled_protocols.contains(protocol_id)),
        "DNSTT check target changed"
    );
    let sample = sample.await?;
    anyhow::ensure!(
        state.inv.deploy_input_revision(sid).await? == revision,
        "DNSTT check inputs changed"
    );
    state.inv.record_protocol_assurance_sample(&sample).await?;
    if let Err(error) = state
        .inv
        .audit(
            "admin",
            "server.dnstt.check",
            Some(&sid.0),
            Some(&json!({
                "stage": sample.stage.as_str(),
                "state": sample.state.as_str(),
                "failure_code": sample.failure_code,
            })),
        )
        .await
    {
        tracing::warn!(target: "vpnctld::assurance", server = %sid, %error, "manual DNSTT audit write failed");
    }
    let message = match sample.state {
        AssuranceState::Verified => tr(
            lang,
            "DNSTT transfer verified.",
            "Передача через DNSTT подтверждена.",
        ),
        AssuranceState::Blocked | AssuranceState::Degraded => tr(
            lang,
            "The DNSTT transfer check failed.",
            "Проверка передачи через DNSTT завершилась ошибкой.",
        ),
        _ => tr(
            lang,
            "The DNSTT check could not verify a transfer.",
            "Проверка не смогла подтвердить передачу через DNSTT.",
        ),
    };
    Ok(Event::default().event("ok").data(
        json!({
            "message": message,
        })
        .to_string(),
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::sync::Arc;

    use axum::Router;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, header};
    use tower::ServiceExt;
    use vpnctl_core::{KernelId, Server};
    use vpnctl_inventory::{AssuranceStage, SqliteInventory};

    use super::*;

    const ID: &str = "dnstt-on-demand-fixture";
    const CHECK: &str = "/admin/servers/dnstt-on-demand-fixture/dnstt-check/sse";
    const STATUS: &str = "/admin/servers/dnstt-on-demand-fixture/status";

    async fn fixture() -> (tempfile::TempDir, AppState) {
        let dir = tempfile::tempdir().unwrap();
        let inv = SqliteInventory::open(&dir.path().join("fixture.db"))
            .await
            .unwrap();
        inv.add_server(&Server {
            id: ServerId(ID.into()),
            address: "192.0.2.17".into(),
            ssh_port: 22,
            ssh_user: "fixture".into(),
            kernels: vec![KernelId("dnstt".into())],
            enabled_protocols: vec![ProtocolId("dnstt".into())],
            trusted_host_fingerprint: None,
            hoster: "fixture".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
        let (mut state, _) = crate::app::make_app_state_for_tests(
            inv,
            Arc::new(vpnctl_kernels::build_registry().unwrap()),
        );
        state.dnstt_check_runner = Some("fixture-untrusted-relative-runner".into());
        (dir, state)
    }

    async fn get(app: &Router, uri: &str) -> Response {
        app.clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header(header::HOST, "test.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    async fn ticket(app: &Router, origin: &str) -> Response {
        app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/sse-ticket")
                    .header(header::HOST, "test.example")
                    .header(header::ORIGIN, origin)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(format!("path={CHECK}")))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    async fn body(response: Response) -> String {
        String::from_utf8(
            to_bytes(response.into_body(), 1_048_576)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn ticket_is_required_and_untrusted_runner_is_recorded_as_unknown() {
        let (_dir, state) = fixture().await;
        let app = crate::app::router(state.clone());
        let sid = ServerId(ID.into());
        assert_eq!(get(&app, CHECK).await.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            ticket(&app, "https://foreign.example").await.status(),
            StatusCode::FORBIDDEN
        );
        assert!(
            state
                .inv
                .latest_protocol_assurance_for_server(&sid)
                .await
                .unwrap()
                .is_empty()
        );

        let start = ticket(&app, "https://test.example").await;
        assert_eq!(start.status(), StatusCode::OK);
        let url = format!("{CHECK}?ticket={}", body(start).await);
        let response = get(&app, &url).await;
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "text/event-stream"
        );
        let stream = body(response).await;
        assert!(stream.contains("event: ok"));
        assert!(!stream.contains("fixture-untrusted-relative-runner"));
        assert_eq!(get(&app, &url).await.status(), StatusCode::FORBIDDEN);

        let entries = state
            .inv
            .latest_protocol_assurance_for_server(&sid)
            .await
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].stage, AssuranceStage::ClientImport);
        assert_eq!(entries[0].state, AssuranceState::Unknown);
        assert_eq!(
            entries[0].failure_code.as_deref(),
            Some("runner_invalid_path")
        );
        assert!(
            state
                .inv
                .recent_audit(10)
                .await
                .unwrap()
                .iter()
                .any(|row| row.action == "server.dnstt.check" && row.target.as_deref() == Some(ID))
        );
    }

    #[tokio::test]
    async fn adapter_transfer_is_recorded_and_visible_in_fleet_and_server_availability() {
        let (_dir, state) = fixture().await;
        let app = crate::app::router(state.clone());
        assert!(body(get(&app, STATUS).await).await.contains(CHECK));
        let sid = ServerId(ID.into());
        let protocol = ProtocolId("dnstt".into());
        let server = state.inv.get_server(&sid).await.unwrap().unwrap();
        let registered = state.registry.protocol(&protocol).unwrap();
        run_check(
            &state,
            &server,
            &protocol,
            async { crate::protocol_assurance_poller::sample_dnstt_fixture(&server, registered) },
            Locale::En,
        )
        .await
        .unwrap();
        let entries = state
            .inv
            .latest_protocol_assurance_for_server(&sid)
            .await
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].stage, AssuranceStage::Transfer);
        assert_eq!(entries[0].state, AssuranceState::Verified);
        assert_eq!(entries[0].client_kind, "dnstt-on-demand");
        assert_eq!(entries[0].latency_ms, Some(1234));
        for path in [STATUS, "/admin/servers"] {
            assert!(
                body(get(&app, path).await)
                    .await
                    .contains("data-path-status=\"udp_verified\"")
            );
        }
    }
}
