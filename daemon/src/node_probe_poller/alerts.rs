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

    if matches!(outcome, ProbeOutcome::Ok(_)) {
        if let Err(e) = inv.set_server_suppressed(&server.id, false).await {
            tracing::warn!(
                target = "vpnctld::node_probe",
                server = %server.id.0,
                error = %e,
                "auto-restore (clear suppressed) failed"
            );
        }
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

    let kind = kind.to_string();
    let severity = severity.to_string();
    let inv = inv.clone();
    tokio::spawn(async move {
        let sink_name = sink.name();
        match send_with_retry(
            sink.as_ref(),
            &kind,
            &severity,
            &text,
            silent,
            std::time::Duration::from_secs(30),
        )
        .await
        {
            Ok(message_id) => {
                tracing::info!(
                    target = "vpnctld::alert_sink",
                    kind = %kind,
                    "pushed via {}",
                    sink_name
                );
                if let (Some(aid), Some(mid)) = (alert_id, message_id) {
                    if let Err(e) = inv.set_alert_telegram_message_id(aid, &mid).await {
                        tracing::warn!(
                            target = "vpnctld::alert_sink",
                            kind = %kind,
                            error = %e,
                            "failed to record telegram_message_id; edit-on-recover will fall back"
                        );
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    target = "vpnctld::alert_sink",
                    kind = %kind,
                    error = %e,
                    "push to {} failed; alert row still in admin_alerts",
                    sink_name
                );
            }
        }
    });
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
}
