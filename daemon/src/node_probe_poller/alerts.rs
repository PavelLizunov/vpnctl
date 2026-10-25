use vpnctl_core::ServerId;
use vpnctl_inventory::SqliteInventory;

use super::{FailState, ProbeOutcome, UnreachableTransition};

pub async fn dispatch_alerts(
    inv: &SqliteInventory,
    server: &vpnctl_core::Server,
    outcome: &ProbeOutcome,
    fail_state: &mut FailState,
) {
    let mut transition = fail_state.observe(&server.id, outcome);
    if matches!(outcome, ProbeOutcome::Ok(_)) {
        match inv
            .has_unacked_alert("server.unreachable", Some(&server.id))
            .await
        {
            Ok(true) => transition = UnreachableTransition::Recovered,
            Ok(false) => {}
            Err(e) => tracing::warn!(
                target = "vpnctld::node_probe",
                server = %server.id.0,
                error = %e,
                "could not read open server.unreachable alert"
            ),
        }
    }
    match transition {
        UnreachableTransition::BecameUnreachable {
            consecutive_failures,
            threshold,
        }
        | UnreachableTransition::StillUnreachable {
            consecutive_failures,
            threshold,
        } => {
            let reason = match outcome {
                ProbeOutcome::SshFailed(msg) => msg.as_str(),
                _ => "unknown",
            };
            let payload_val = serde_json::json!({
                "consecutive_failures": consecutive_failures,
                "threshold": threshold,
                "last_ssh_error": reason,
                "ssh_user": server.ssh_user,
                "ssh_port": server.ssh_port,
                "ip": server.address,
            });
            let payload = payload_val.to_string();
            let subject = server_subject(inv, &server.id).await;
            let summary = format!(
                "{consecutive_failures} consecutive SSH probes failed — host may be down, key revoked, or sshd port changed"
            );
            match inv
                .insert_alert_if_no_unacked(
                    "server.unreachable",
                    Some(&server.id),
                    "warning",
                    &summary,
                    Some(&payload),
                )
                .await
            {
                Ok(Some(id)) => {
                    audit_alert_fire(inv, &server.id, id, "server.unreachable", &summary).await;
                    push_alert(
                        inv,
                        "server.unreachable",
                        "warning",
                        &subject,
                        &payload_val,
                        Some(id),
                    )
                    .await;
                }
                Ok(None) => {}
                Err(e) => tracing::warn!(
                    target = "vpnctld::node_probe",
                    server = %server.id.0,
                    error = %e,
                    "insert server.unreachable alert failed"
                ),
            }
            match inv.server_auto_suppress_state(&server.id).await {
                Ok((true, _)) => {
                    if let Err(e) = inv.set_server_suppressed(&server.id, true).await {
                        tracing::warn!(
                            target = "vpnctld::node_probe",
                            server = %server.id.0,
                            error = %e,
                            "auto-suppress set failed"
                        );
                    }
                }
                Ok((false, _)) => {}
                Err(e) => tracing::warn!(
                    target = "vpnctld::node_probe",
                    server = %server.id.0,
                    error = %e,
                    "auto-suppress state read failed"
                ),
            }
        }
        UnreachableTransition::Recovered => {
            let subject = server_subject(inv, &server.id).await;
            recover_alert(
                inv,
                "server.unreachable",
                "server.unreachable",
                &subject,
                &serde_json::json!({ "ip": server.address }),
                Some(&server.id),
                None,
            )
            .await;
            auto_ack(
                inv,
                &server.id,
                "server.unreachable",
                "probe succeeded after consecutive failures",
            )
            .await;
        }
        UnreachableTransition::NoChange => {}
    }

    if matches!(outcome, ProbeOutcome::Ok(_))
        && let Err(e) = inv.set_server_suppressed(&server.id, false).await
    {
        tracing::warn!(
            target = "vpnctld::node_probe",
            server = %server.id.0,
            error = %e,
            "auto-restore (clear suppressed) failed"
        );
    }

    if let ProbeOutcome::Ok(probe) = outcome {
        match probe.fail2ban_self_banned {
            Some(true) => {
                let banned_list = probe.fail2ban_banned_ips.clone().unwrap_or_default();
                let our_ip = probe.probe_source_ip.clone().unwrap_or_default();
                let ban_count_other = banned_list.len().saturating_sub(1);
                let payload_val = serde_json::json!({
                    "our_ip": our_ip,
                    "fail2ban_banned_ips": banned_list,
                    "ban_count_other": ban_count_other,
                });
                let payload = payload_val.to_string();
                let subject = server_subject(inv, &server.id).await;
                let summary = format!(
                    "daemon's outbound IP {our_ip} is in fail2ban's banned list for sshd. \
                     Daemon can't self-recover — use the hoster's console / KVM to run \
                     `fail2ban-client set sshd unbanip {our_ip}` (the next probe \
                     auto-clears this alert)."
                );
                match inv
                    .insert_alert_if_no_unacked(
                        "server.fail2ban.banned_self",
                        Some(&server.id),
                        "critical",
                        &summary,
                        Some(&payload),
                    )
                    .await
                {
                    Ok(Some(id)) => {
                        audit_alert_fire(
                            inv,
                            &server.id,
                            id,
                            "server.fail2ban.banned_self",
                            &summary,
                        )
                        .await;
                        push_alert(
                            inv,
                            "server.fail2ban.banned_self",
                            "critical",
                            &subject,
                            &payload_val,
                            Some(id),
                        )
                        .await;
                    }
                    Ok(None) => {}
                    Err(e) => tracing::warn!(
                        target = "vpnctld::node_probe",
                        server = %server.id.0,
                        error = %e,
                        "insert server.fail2ban.banned_self alert failed"
                    ),
                }
            }
            Some(false) => {
                auto_ack(
                    inv,
                    &server.id,
                    "server.fail2ban.banned_self",
                    "outbound IP no longer in fail2ban-client status sshd banned list",
                )
                .await;
            }
            None => {}
        }
    }
}

pub(crate) async fn audit_alert_fire(
    inv: &SqliteInventory,
    server_id: &ServerId,
    alert_id: i64,
    kind: &str,
    summary: &str,
) {
    if let Err(e) = inv
        .audit(
            "vpnctld",
            "alert.fire",
            Some(&server_id.0),
            Some(&serde_json::json!({
                "alert_id": alert_id,
                "kind": kind,
                "summary": summary,
            })),
        )
        .await
    {
        tracing::warn!(
            target = "vpnctld::node_probe",
            kind = kind,
            server = %server_id.0,
            error = %e,
            "audit_log row for alert.fire failed; alert row is still in admin_alerts"
        );
    }
}

pub(crate) async fn push_alert(
    inv: &SqliteInventory,
    kind: &str,
    severity: &str,
    subject: &str,
    payload: &serde_json::Value,
    alert_id: Option<i64>,
) {
    let loc = match inv.get_telegram_config().await {
        Ok(Some(cfg)) => crate::i18n::Locale::from_lang_code(cfg.language.as_deref()),
        _ => crate::i18n::Locale::En,
    };
    let rendered = crate::alert_text::render_alert(kind, severity, subject, payload, loc);
    let time_local =
        crate::handlers::admin::format_local_with_pattern(chrono::Utc::now(), "%d.%m %H:%M");
    let text = crate::alert_text::to_telegram_html(&rendered, loc, &time_local, false);
    let silent = crate::alert_text::is_silent(severity);

    let sink = match build_alert_sink(inv).await {
        Ok(Some(s)) => s,
        Ok(None) => return,
        Err(e) => {
            tracing::warn!(
                target = "vpnctld::alert_sink",
                error = %e,
                "build_alert_sink failed; skipping push for this alert"
            );
            return;
        }
    };

    if let Some(id) = alert_id {
        match inv
            .claim_alert_telegram_delivery(id, chrono::Utc::now(), false)
            .await
        {
            Ok(Some(_)) => {}
            Ok(None) => return,
            Err(error) => {
                tracing::warn!(target = "vpnctld::alert_sink", %error, "could not reserve alert delivery");
                return;
            }
        }
    }

    let kind = kind.to_string();
    let severity = severity.to_string();
    let inv = inv.clone();
    tokio::spawn(async move {
        let sink_name = sink.name();
        let result = send_with_retry(
            sink.as_ref(),
            &kind,
            &severity,
            &text,
            silent,
            std::time::Duration::from_secs(30),
        )
        .await;
        if result.is_ok() {
            tracing::info!(target = "vpnctld::alert_sink", %kind, "pushed via {}", sink_name);
        }
        if let Some(aid) = alert_id {
            if let Err(error) =
                record_delivery_result(&inv, aid, 1, &result, chrono::Utc::now()).await
            {
                tracing::warn!(target = "vpnctld::alert_sink", %error, "failed to record alert delivery result");
            }
        } else if let Err(error) = result {
            tracing::warn!(target = "vpnctld::alert_sink", %kind, %error, "push to {} failed", sink_name);
        }
    });
}

fn telegram_retry_delay(attempts: i64) -> chrono::Duration {
    let exponent = attempts.saturating_sub(1).clamp(0, 6) as u32;
    chrono::Duration::seconds((60_i64 << exponent).min(3600))
}

async fn record_delivery_result(
    inv: &SqliteInventory,
    alert_id: i64,
    attempts: i64,
    result: &Result<Option<String>, crate::alert_sink::AlertSinkError>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), vpnctl_inventory::SqliteInventoryError> {
    match result {
        Ok(message_id) => {
            inv.record_alert_telegram_delivery(alert_id, message_id.as_deref())
                .await
        }
        Err(error) => {
            tracing::warn!(target = "vpnctld::alert_sink", alert_id, %error, "alert delivery failed; retry scheduled");
            inv.defer_alert_telegram_delivery(alert_id, now + telegram_retry_delay(attempts))
                .await
        }
    }
}

pub(crate) async fn retry_alert_deliveries(inv: &SqliteInventory) -> anyhow::Result<()> {
    let sink = build_alert_sink(inv).await?;
    retry_alert_deliveries_with_sink(inv, sink.as_deref(), chrono::Utc::now()).await
}

async fn retry_alert_deliveries_with_sink(
    inv: &SqliteInventory,
    sink: Option<&dyn crate::alert_sink::AlertSink>,
    now: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<()> {
    let Some(cfg) = inv
        .get_telegram_config()
        .await?
        .filter(|cfg| cfg.is_enabled())
    else {
        return Ok(());
    };
    let expired = inv.expire_alert_telegram_deliveries(now).await?;
    if expired > 0 {
        tracing::warn!(
            target = "vpnctld::alert_sink",
            expired,
            "gave up undelivered alerts after 24 hours"
        );
    }
    let Some(sink) = sink else {
        return Ok(());
    };
    let loc = crate::i18n::Locale::from_lang_code(cfg.language.as_deref());
    for alert in inv.pending_alert_telegram_deliveries(now).await? {
        let Some(attempts) = inv
            .claim_alert_telegram_delivery(alert.id, now, true)
            .await?
        else {
            continue;
        };
        let subject = if let Some(sid) = &alert.server_id {
            server_subject(inv, sid).await
        } else if let Some((_, suffix)) = alert.kind.split_once(':') {
            suffix.to_string()
        } else {
            String::new()
        };
        let payload = alert
            .payload_json
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or(serde_json::Value::Null);
        let rendered =
            crate::alert_text::render_alert(&alert.kind, &alert.severity, &subject, &payload, loc);
        let time_local =
            crate::handlers::admin::format_local_with_pattern(alert.created_at, "%d.%m %H:%M");
        let text = crate::alert_text::to_telegram_html(&rendered, loc, &time_local, false);
        let result = sink
            .send_text(
                &alert.kind,
                &alert.severity,
                &text,
                crate::alert_text::is_silent(&alert.severity),
            )
            .await;
        record_delivery_result(inv, alert.id, attempts, &result, now).await?;
    }
    Ok(())
}

async fn send_with_retry(
    sink: &dyn crate::alert_sink::AlertSink,
    kind: &str,
    severity: &str,
    text: &str,
    silent: bool,
    retry_delay: std::time::Duration,
) -> Result<Option<String>, crate::alert_sink::AlertSinkError> {
    let mut retries_left = 2;
    loop {
        match sink.send_text(kind, severity, text, silent).await {
            Err(error) if retries_left > 0 => {
                retries_left -= 1;
                tracing::warn!(
                    target = "vpnctld::alert_sink",
                    kind,
                    retries_left,
                    %error,
                    "alert push failed; retrying after delay"
                );
                tokio::time::sleep(retry_delay).await;
            }
            result => return result,
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn recover_alert(
    inv: &SqliteInventory,
    recovery_kind: &str,
    resolves_kind: &str,
    subject: &str,
    payload: &serde_json::Value,
    server_id: Option<&vpnctl_core::ServerId>,
    fallback_alert_id: Option<i64>,
) {
    let loc = match inv.get_telegram_config().await {
        Ok(Some(cfg)) => crate::i18n::Locale::from_lang_code(cfg.language.as_deref()),
        _ => crate::i18n::Locale::En,
    };
    let rendered = crate::alert_text::render_alert(recovery_kind, "info", subject, payload, loc);
    let time_local =
        crate::handlers::admin::format_local_with_pattern(chrono::Utc::now(), "%d.%m %H:%M");
    let text = crate::alert_text::to_telegram_html(&rendered, loc, &time_local, false);

    let message_id = match inv.latest_alert_message_id(resolves_kind, server_id).await {
        Ok(mid) => mid,
        Err(e) => {
            tracing::warn!(
                target = "vpnctld::alert_sink",
                resolves = %resolves_kind,
                error = %e,
                "latest_alert_message_id failed; sending a fresh recovery message"
            );
            None
        }
    };

    let Some(mid) = message_id else {
        push_alert(
            inv,
            recovery_kind,
            "info",
            subject,
            payload,
            fallback_alert_id,
        )
        .await;
        return;
    };

    let sink = match build_alert_sink(inv).await {
        Ok(Some(s)) => s,
        Ok(None) => return,
        Err(e) => {
            tracing::warn!(
                target = "vpnctld::alert_sink",
                error = %e,
                "build_alert_sink failed; skipping recovery edit"
            );
            return;
        }
    };
    let recovery_kind = recovery_kind.to_string();
    tokio::spawn(async move {
        let sink_name = sink.name();
        if let Err(e) = sink.edit_text(&mid, &text).await {
            tracing::warn!(
                target = "vpnctld::alert_sink",
                kind = %recovery_kind,
                error = %e,
                "edit-on-recover via {} failed; sending a fresh recovery message",
                sink_name
            );
            let _ = sink.send_text(&recovery_kind, "info", &text, true).await;
        } else {
            tracing::info!(
                target = "vpnctld::alert_sink",
                kind = %recovery_kind,
                "edited original alert message to recovered via {}",
                sink_name
            );
        }
    });
}

pub(crate) async fn server_subject(inv: &SqliteInventory, sid: &vpnctl_core::ServerId) -> String {
    let custom = inv.server_display_name(sid).await.ok().flatten();
    crate::handlers::vpn_router::server_display_label(&sid.0, custom.as_deref())
}

pub(crate) async fn send_digest(inv: &SqliteInventory) -> anyhow::Result<bool> {
    let Some(sink) = build_alert_sink(inv).await? else {
        return Ok(false);
    };
    let loc = match inv.get_telegram_config().await? {
        Some(cfg) => crate::i18n::Locale::from_lang_code(cfg.language.as_deref()),
        None => crate::i18n::Locale::En,
    };
    let open = inv.recent_alerts(50, false).await?;
    let servers = inv.list_servers().await?.len();
    let mut titles = Vec::with_capacity(open.len());
    for a in &open {
        let subject = if let Some(sid) = &a.server_id {
            server_subject(inv, sid).await
        } else if let Some((_, suffix)) = a.kind.split_once(':') {
            suffix.to_string()
        } else {
            String::new()
        };
        let payload: serde_json::Value = a
            .payload_json
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or(serde_json::Value::Null);
        let r = crate::alert_text::render_alert(&a.kind, &a.severity, &subject, &payload, loc);
        titles.push(format!("{} {}", r.icon, r.title));
    }
    let time_local =
        crate::handlers::admin::format_local_with_pattern(chrono::Utc::now(), "%d.%m %H:%M");
    let messages =
        crate::alert_text::digest::render_digest_messages(loc, servers, &titles, &time_local);
    for text in &messages {
        sink.send_text("digest", "info", text, true).await?;
    }
    tracing::info!(
        target = "vpnctld::alert_sink",
        open = open.len(),
        "sent fleet digest"
    );
    Ok(true)
}

pub async fn build_alert_sink(
    inv: &SqliteInventory,
) -> Result<Option<Box<dyn crate::alert_sink::AlertSink>>, vpnctl_inventory::SqliteInventoryError> {
    use crate::alert_sink::TelegramSink;

    let cfg = match inv.get_telegram_config().await? {
        Some(c) if c.is_enabled() => c,
        _ => return Ok(None),
    };

    let (token, chat_id) = match (cfg.token, cfg.chat_id) {
        (Some(t), Some(c)) => (t, c),
        _ => return Ok(None),
    };

    let mut sink = match TelegramSink::from_env(token, chat_id) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                target = "vpnctld::alert_sink",
                error = %e,
                "TelegramSink construction failed despite is_enabled gate; transport disabled"
            );
            return Ok(None);
        }
    };

    if let Some(server_id_str) = cfg.proxy_via_server_id.as_deref() {
        let server_id = vpnctl_core::ServerId(server_id_str.to_string());
        match inv.list_servers().await {
            Ok(servers) => {
                if let Some(server) = servers.iter().find(|s| s.id == server_id) {
                    let jump = match inv.resolve_jump_host(server).await {
                        Ok(value) => value,
                        Err(error) => {
                            tracing::warn!(target = "vpnctld::alert_sink", %error, "Telegram proxy jump validation failed; transport disabled");
                            return Ok(None);
                        }
                    };
                    let key_path = crate::app::deploy_key_path();
                    let ssh = crate::ssh_subprocess::SubprocessSshTransport::new(
                        server.address.clone(),
                        server.ssh_user.clone(),
                        key_path,
                    )
                    .port(server.ssh_port)
                    .trusted_fingerprint(server.trusted_host_fingerprint.clone())
                    .with_jump(jump);
                    sink = sink.with_via_ssh(ssh);
                } else {
                    tracing::warn!(
                        target = "vpnctld::alert_sink",
                        server_id = %server_id_str,
                        "configured proxy_via_server_id no longer in inventory; \
                         transport DISABLED (operator must pick a different proxy \
                         server on /admin/settings or unset the field)"
                    );
                    return Ok(None);
                }
            }
            Err(e) => {
                tracing::warn!(
                    target = "vpnctld::alert_sink",
                    error = %e,
                    "list_servers failed while resolving proxy_via_server_id"
                );
                return Err(e);
            }
        }
    }

    Ok(Some(Box::new(sink)))
}

pub(crate) async fn auto_ack(
    inv: &SqliteInventory,
    server_id: &ServerId,
    kind: &str,
    reason: &str,
) {
    match inv.ack_open_alerts(kind, Some(server_id)).await {
        Ok(0) => {}
        Ok(n) => {
            if let Err(e) = inv
                .audit(
                    "vpnctld",
                    "alert.auto_ack",
                    Some(&server_id.0),
                    Some(&serde_json::json!({
                        "kind": kind,
                        "rows_acked": n,
                        "reason": reason,
                    })),
                )
                .await
            {
                tracing::warn!(
                    target = "vpnctld::node_probe",
                    kind = kind,
                    server = %server_id.0,
                    error = %e,
                    "audit for alert.auto_ack failed"
                );
            }
        }
        Err(e) => tracing::warn!(
            target = "vpnctld::node_probe",
            kind = kind,
            server = %server_id.0,
            error = %e,
            "ack_open_alerts failed"
        ),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct FlakySink {
        calls: AtomicUsize,
        failures: usize,
    }

    #[async_trait::async_trait]
    impl crate::alert_sink::AlertSink for FlakySink {
        async fn send_text(
            &self,
            _kind: &str,
            _severity: &str,
            _text: &str,
            _silent: bool,
        ) -> Result<Option<String>, crate::alert_sink::AlertSinkError> {
            if self.calls.fetch_add(1, Ordering::SeqCst) < self.failures {
                Err(crate::alert_sink::AlertSinkError::Misconfigured)
            } else {
                Ok(Some("123".into()))
            }
        }

        async fn edit_text(
            &self,
            _message_id: &str,
            _text: &str,
        ) -> Result<(), crate::alert_sink::AlertSinkError> {
            Ok(())
        }

        fn name(&self) -> &'static str {
            "flaky"
        }
    }

    #[tokio::test]
    async fn failed_push_retries_and_returns_message_id() {
        for failures in 0..=2 {
            let sink = FlakySink {
                calls: AtomicUsize::new(0),
                failures,
            };
            let message_id = send_with_retry(
                &sink,
                "test",
                "warning",
                "test alert",
                false,
                std::time::Duration::ZERO,
            )
            .await
            .unwrap();
            assert_eq!(message_id.as_deref(), Some("123"));
            assert_eq!(sink.calls.load(Ordering::SeqCst), failures + 1);
        }
    }

    #[tokio::test]
    async fn failed_push_stops_after_three_attempts() {
        let sink = FlakySink {
            calls: AtomicUsize::new(0),
            failures: usize::MAX,
        };
        assert!(
            send_with_retry(
                &sink,
                "test",
                "warning",
                "test alert",
                false,
                std::time::Duration::ZERO,
            )
            .await
            .is_err()
        );
        assert_eq!(sink.calls.load(Ordering::SeqCst), 3);
    }

    async fn pending_delivery() -> (
        tempfile::TempDir,
        SqliteInventory,
        i64,
        chrono::DateTime<chrono::Utc>,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let inv = SqliteInventory::open(&dir.path().join("inv.db"))
            .await
            .unwrap();
        inv.set_telegram_config(Some("test-token"), Some("42"), None)
            .await
            .unwrap();
        let id = inv
            .insert_alert("test", None, "warning", "test alert", None)
            .await
            .unwrap();
        let now = chrono::Utc::now();
        assert_eq!(
            inv.claim_alert_telegram_delivery(id, now, false)
                .await
                .unwrap(),
            Some(1)
        );
        (dir, inv, id, now)
    }

    #[test]
    fn telegram_backoff_doubles_from_one_minute_and_caps_at_one_hour() {
        for (attempts, seconds) in [
            (1, 60),
            (2, 120),
            (3, 240),
            (4, 480),
            (5, 960),
            (6, 1920),
            (7, 3600),
            (8, 3600),
            (i64::MAX, 3600),
        ] {
            assert_eq!(telegram_retry_delay(attempts).num_seconds(), seconds);
        }
    }

    #[tokio::test]
    async fn failed_delivery_is_retried_after_reopen_and_marked_delivered() {
        let (dir, inv, id, now) = pending_delivery().await;
        let sink = FlakySink {
            calls: AtomicUsize::new(0),
            failures: 3,
        };
        let result = send_with_retry(
            &sink,
            "test",
            "warning",
            "test alert",
            false,
            std::time::Duration::ZERO,
        )
        .await;
        assert!(result.is_err());
        record_delivery_result(&inv, id, 1, &result, now)
            .await
            .unwrap();
        assert!(
            inv.pending_alert_telegram_deliveries(now)
                .await
                .unwrap()
                .is_empty()
        );
        drop(inv);
        let inv = SqliteInventory::open(&dir.path().join("inv.db"))
            .await
            .unwrap();
        retry_alert_deliveries_with_sink(&inv, Some(&sink), now + chrono::Duration::seconds(59))
            .await
            .unwrap();
        assert_eq!(sink.calls.load(Ordering::SeqCst), 3);
        retry_alert_deliveries_with_sink(&inv, Some(&sink), now + chrono::Duration::seconds(60))
            .await
            .unwrap();
        assert_eq!(sink.calls.load(Ordering::SeqCst), 4);
        assert_eq!(
            inv.latest_alert_message_id("test", None)
                .await
                .unwrap()
                .as_deref(),
            Some("123")
        );
        retry_alert_deliveries_with_sink(&inv, Some(&sink), now + chrono::Duration::hours(2))
            .await
            .unwrap();
        assert_eq!(sink.calls.load(Ordering::SeqCst), 4);
        assert!(
            inv.claim_alert_telegram_delivery(id, now, false)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn failed_delivery_backs_off_and_gives_up_after_24_hours() {
        let (_dir, inv, id, now) = pending_delivery().await;
        let sink = FlakySink {
            calls: AtomicUsize::new(0),
            failures: usize::MAX,
        };
        let failure = Err(crate::alert_sink::AlertSinkError::Misconfigured);
        record_delivery_result(&inv, id, 1, &failure, now)
            .await
            .unwrap();
        retry_alert_deliveries_with_sink(&inv, Some(&sink), now + chrono::Duration::seconds(60))
            .await
            .unwrap();
        assert_eq!(sink.calls.load(Ordering::SeqCst), 1);
        retry_alert_deliveries_with_sink(&inv, Some(&sink), now + chrono::Duration::seconds(179))
            .await
            .unwrap();
        assert_eq!(sink.calls.load(Ordering::SeqCst), 1);
        retry_alert_deliveries_with_sink(&inv, Some(&sink), now + chrono::Duration::seconds(180))
            .await
            .unwrap();
        assert_eq!(sink.calls.load(Ordering::SeqCst), 2);
        retry_alert_deliveries_with_sink(&inv, None, now + chrono::Duration::hours(24))
            .await
            .unwrap();
        assert_eq!(sink.calls.load(Ordering::SeqCst), 2);
        assert!(
            inv.pending_alert_telegram_deliveries(now + chrono::Duration::hours(25))
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            inv.expire_alert_telegram_deliveries(now + chrono::Duration::hours(25))
                .await
                .unwrap(),
            0
        );
        // Once recorded, expiry remains final even if wall-clock time moves backwards.
        assert!(
            inv.claim_alert_telegram_delivery(id, now + chrono::Duration::hours(1), true)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(inv.unacked_alert_count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn disabled_telegram_does_not_send_or_change_pending_delivery() {
        let (_dir, inv, id, now) = pending_delivery().await;
        inv.defer_alert_telegram_delivery(id, now).await.unwrap();
        inv.set_telegram_config(None, None, None).await.unwrap();
        let sink = FlakySink {
            calls: AtomicUsize::new(0),
            failures: 0,
        };
        retry_alert_deliveries(&inv).await.unwrap();
        retry_alert_deliveries_with_sink(&inv, Some(&sink), now + chrono::Duration::hours(25))
            .await
            .unwrap();
        assert_eq!(sink.calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            inv.pending_alert_telegram_deliveries(now)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            inv.claim_alert_telegram_delivery(id, now, true)
                .await
                .unwrap(),
            Some(2)
        );
    }
}
