use vpnctl_core::ServerId;
use vpnctl_inventory::SqliteInventory;

use super::{FailState, ProbeOutcome, UnreachableTransition};

/// Translate one [`ProbeOutcome`] into the appropriate inventory-
/// level alert writes (fire / ack). Pulled out as a free function
/// so admin_smoke can drive it with a hand-built outcome without
/// having to mock SSH + interval clock.
pub async fn dispatch_alerts(
    inv: &SqliteInventory,
    server: &vpnctl_core::Server,
    outcome: &ProbeOutcome,
    fail_state: &mut FailState,
) {
    // ─── server.unreachable (state-machine over outcomes) ─────
    match fail_state.observe(&server.id, outcome) {
        // First fire AND every subsequent still-down tick run the SAME
        // idempotent insert: while the alert is open + unacked the
        // partial-UNIQUE index makes it a no-op (Ok(None)); after the
        // operator acks a still-down server, the next tick's insert
        // re-opens it (Ok(Some) → audit + push). This is the kg
        // 2026-05-31 fix — an ack no longer permanently silences a
        // server that's still failing.
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
            // Payload is operationally-relevant numbers + the redacted
            // SSH stderr. Per `insert_alert_if_no_unacked` doc: no
            // secrets.
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
                    // Row freshly inserted. Honour migration 0011's
                    // contract: «audit_log row is STILL written for
                    // every alert with action='alert.fire'». Bug-
                    // hunt agent 2026-05-18 caught this — chunk 2
                    // detectors skipped it, breaking /admin/audit.
                    audit_alert_fire(inv, &server.id, id, "server.unreachable", &summary).await;
                    // Then push to the configured sink (best-effort). The
                    // row id is threaded so the message id is recorded for
                    // edit-on-recover.
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
                Ok(None) => {
                    // Duplicate suppressed by the partial-UNIQUE
                    // index — same condition already raised + unacked.
                }
                Err(e) => tracing::warn!(
                    target = "vpnctld::node_probe",
                    server = %server.id.0,
                    error = %e,
                    "insert server.unreachable alert failed"
                ),
            }
            // Auto-suppress (migration 0030): if the operator opted this
            // server in, flag it suppressed so the subscription render
            // stops handing clients a dead URI. Idempotent — only the
            // first crossing actually writes + audits; later still-down
            // ticks are no-ops. Gated on the per-server opt-in (default
            // off → unchanged behaviour, server stays in the sub).
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
                Ok((false, _)) => {} // opt-in off — leave it in the sub.
                Err(e) => tracing::warn!(
                    target = "vpnctld::node_probe",
                    server = %server.id.0,
                    error = %e,
                    "auto-suppress state read failed"
                ),
            }
        }
        UnreachableTransition::Recovered => {
            // Edit-on-recover: flip the original 🔴 «недоступна» message
            // to 🟢 «снова доступна» BEFORE acking (the ack clears the
            // row but the message id is read from the most-recent
            // unreachable row regardless of ack state).
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

    // Auto-restore (migration 0030): clear suppression on ANY successful
    // probe — NOT only the `Recovered` transition. The in-memory
    // FailState resets on a daemon restart (routine — every redeploy),
    // so a server suppressed before the restart would otherwise stay
    // suppressed forever if it recovered within fewer than `threshold`
    // failed probes (recover() emits `Recovered` only when it had a
    // fired state to clear → otherwise NoChange → the clear never ran).
    // Tying the clear to the Ok OUTCOME — idempotent no-op when not
    // suppressed — makes restore restart-safe. (review-agent critical.)
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

    // ─── server.fail2ban.banned_self (per-probe-snapshot verdict) ─
    //
    // Only inspectable when the probe succeeded AND the parser
    // produced a verdict (both SSH_CLIENT_IP and fail2ban-client
    // output were parseable). The `None` case is no-signal and
    // intentionally does NOT touch the alert state — operator-clear
    // requires explicit `Some(false)`.
    if let ProbeOutcome::Ok(probe) = outcome {
        match probe.fail2ban_self_banned {
            Some(true) => {
                let banned_list = probe.fail2ban_banned_ips.clone().unwrap_or_default();
                let our_ip = probe.probe_source_ip.clone().unwrap_or_default();
                let ban_count_other = banned_list.len().saturating_sub(1);
                // Daemon is LOCKED OUT — by definition it can't
                // self-recover (it tried to SSH and got banned).
                // The remediation must:
                //   (a) substitute the actual IP literally (the
                //       previous «<our_ip>» placeholder was a real
                //       regression — review-agent caught it),
                //   (b) live in `summary` (rendered by `alerts_table`),
                //       NOT in `payload_json` (which `/admin/alerts`
                //       never displays — only kind + summary + severity
                //       are surfaced).
                let payload_val = serde_json::json!({
                    "our_ip": our_ip,
                    "fail2ban_banned_ips": banned_list,
                    "ban_count_other": ban_count_other,
                });
                let payload = payload_val.to_string();
                let subject = server_subject(inv, &server.id).await;
                // Summary IS rendered; bake the unban command + the
                // «hoster console» hint right into it so the operator
                // sees it on /admin/alerts without drilling into the
                // (currently un-rendered) payload.
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
                        // Honour 0011's audit_log contract — same
                        // fix as server.unreachable above.
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
            None => {} // no signal → no action
        }
    }
}

/// Push one freshly-inserted alert via the configured AlertSink.
/// Fire-and-forget — spawns a tokio task so the curl call (up to
/// 20s with the default timeout) doesn't block the next server's
/// probe. Reads the Telegram config from inventory each call (cheap
/// SQLite roundtrip, ~µs) so a config change via /admin/settings
/// takes effect on the very next alert without a daemon restart.
///
/// Sink-side errors are LOGGED at warn but never returned — the
/// alert is already persisted in `admin_alerts`, push is the
/// best-effort secondary delivery. If the operator wants to find
/// out why a Telegram message didn't arrive, the journal carries
/// the full curl-stderr context.
/// Write the `alert.fire` audit_log row that migration 0011's
/// schema doc-comment mandates for every newly-inserted alert.
/// Same shape as `health_monitor.rs::insert_alert`'s audit call,
/// extracted as a free fn so both `dispatch_alerts` detector
/// branches share one source of truth. Bug-hunt agent finding
/// 2026-05-18.
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

/// Push one alert to the configured transport, rendered localized +
/// pretty. `subject` is the human display-name (country label for server
/// alerts, user id for user alerts); `payload` is the structured event
/// fields — the message TEXT is produced HERE in the operator's language
/// (`notification_settings.language`), so the same event speaks Russian
/// to the operator while the dashboard can render any locale.
/// `alert_id` (when known) is the `admin_alerts` row id; on a successful
/// push the transport's `message_id` is recorded against it so a later
/// recovery can EDIT this exact 🔴 message to 🟢 (see [`recover_alert`]).
pub(crate) async fn push_alert(
    inv: &SqliteInventory,
    kind: &str,
    severity: &str,
    subject: &str,
    payload: &serde_json::Value,
    alert_id: Option<i64>,
) {
    // Resolve the operator's notification language (best-effort — fall
    // back to En on any read failure rather than dropping the alert).
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
        Ok(None) => return, // transport not configured — no-op
        Err(e) => {
            tracing::warn!(
                target = "vpnctld::alert_sink",
                error = %e,
                "build_alert_sink failed; skipping push for this alert"
            );
            return;
        }
    };

    // Owned clones for the spawn — these are short strings.
    let kind = kind.to_string();
    let severity = severity.to_string();
    let inv = inv.clone();
    tokio::spawn(async move {
        // Track sink name BEFORE the move-into-await so we can log
        // it on success without resurrecting a borrow from `sink`locked.
        let sink_name = sink.name();
        match sink.send_text(&kind, &severity, &text, silent).await {
            Ok(message_id) => {
                tracing::info!(
                    target = "vpnctld::alert_sink",
                    kind = %kind,
                    "pushed via {}",
                    sink_name
                );
                // Record the Telegram message id against the alert row so
                // a later recovery edits THIS message instead of posting a
                // second one. Best-effort — failure just means recovery
                // falls back to a fresh 🟢 message.
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

/// Recovery push (edit-on-recover): instead of sending a SECOND message
/// when a condition clears, EDIT the original 🔴 alert message in place
/// to 🟢. Looks up the `resolves_kind`'s most-recent
/// `telegram_message_id` for `server_id`; if found, edits that message
/// with the localized recovery text; if not (transport was off when the
/// condition fired, or it predates this feature) falls back to a fresh
/// recovery message via [`push_alert`]. Recovery is always rendered as
/// the silent 🟢 info variant.
///
/// Eventual-consistency note: the condition's message id is written by a
/// spawned task inside [`push_alert`]. Recovery normally happens a probe
/// interval (≥10 min) later, so the write has long landed; a sub-second
/// flap across two back-to-back ticks could miss it and send a fresh 🟢
/// rather than editing — graceful degradation, not a bug.
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
        // No original message to edit → fresh 🟢 (carries its own row id).
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
            // The original message is gone (operator deleted it, or it
            // aged past Telegram's 48h edit window). Don't lose the
            // recovery — send a fresh 🟢 instead.
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

/// Resolve a server's human label for an alert subject: operator's
/// custom `display_name` → country map → uppercased id. Same precedence
/// as the `/sub` + `/api/v1/app/config` render, so an alert names a node
/// exactly as the operator sees it elsewhere (e.g. `cdn` → «Latvia»).
/// Best-effort — a DB read failure degrades to the country/id resolution.
pub(crate) async fn server_subject(inv: &SqliteInventory, sid: &vpnctl_core::ServerId) -> String {
    let custom = inv.server_display_name(sid).await.ok().flatten();
    crate::handlers::vpn_router::server_display_label(&sid.0, custom.as_deref())
}

/// Build + send a fleet digest to the configured transport: «all clear»
/// 🟢 when there are no open alerts, otherwise a 🔴 list of every open
/// problem (each rendered + localized). Drives the daily scheduler + the
/// on-demand /admin/settings button. Best-effort — logs + returns on any
/// storage/transport failure. Sent silently (a routine summary).
pub(crate) async fn send_digest(inv: &SqliteInventory) {
    let loc = match inv.get_telegram_config().await {
        Ok(Some(cfg)) => crate::i18n::Locale::from_lang_code(cfg.language.as_deref()),
        _ => crate::i18n::Locale::En,
    };
    let open = inv.recent_alerts(50, false).await.unwrap_or_default();
    let servers = inv.list_servers().await.map(|s| s.len()).unwrap_or(0);
    let mut titles = Vec::with_capacity(open.len());
    for a in &open {
        // server_id wins over a `:`-suffix (server alerts can carry a
        // suffix where it's the raw id; we want the country label). The
        // suffix is the subject only for user-scoped alerts.
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
    let text = crate::alert_text::render_digest_html(loc, servers, &titles, &time_local);

    let sink = match build_alert_sink(inv).await {
        Ok(Some(s)) => s,
        Ok(None) => return, // transport not configured — no-op
        Err(e) => {
            tracing::warn!(
                target = "vpnctld::alert_sink",
                error = %e,
                "build_alert_sink failed; skipping digest"
            );
            return;
        }
    };
    if let Err(e) = sink.send_text("digest", "info", &text, true).await {
        tracing::warn!(target = "vpnctld::alert_sink", error = %e, "digest push failed");
    } else {
        tracing::info!(
            target = "vpnctld::alert_sink",
            open = open.len(),
            "sent fleet digest"
        );
    }
}

/// Build the appropriate `AlertSink` from the current
/// `notification_settings` row. Returns `Ok(None)` when the
/// operator hasn't configured a transport (transport is then a
/// no-op — alert still in `admin_alerts` for the pull view). Returns
/// `Err` only on storage-layer failures the caller should log.
///
/// Pulled out as a free fn so both `push_alert` (fire-and-forget)
/// and the synchronous test-send handler share the same construction
/// logic — no risk of the two paths drifting on which server the
/// proxy uses, which proxy env var wins, etc.
pub async fn build_alert_sink(
    inv: &SqliteInventory,
) -> Result<Option<Box<dyn crate::alert_sink::AlertSink>>, vpnctl_inventory::SqliteInventoryError> {
    use crate::alert_sink::TelegramSink;

    let cfg = match inv.get_telegram_config().await? {
        Some(c) if c.is_enabled() => c,
        // Either no row OR not enabled.
        _ => return Ok(None),
    };

    // `is_enabled()` proved both halves Some, but the workspace
    // forbids `expect()` even in this provably-infallible position.
    // Defensive `match` returns Ok(None) in the impossible None arm
    // — equivalent to «transport not configured», which is the
    // operator-visible behaviour we'd want anyway.
    let (token, chat_id) = match (cfg.token, cfg.chat_id) {
        (Some(t), Some(c)) => (t, c),
        _ => return Ok(None),
    };

    // Build the base direct-mode sink first; then chain via-ssh if
    // the operator picked a proxy server.
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
        // Look up the server. Removed-from-inventory case: we log
        // + fall back to direct mode (operator-friendlier than
        // silently disabling — they'll see the «proxy server gone»
        // warning in the journal AND get the message from a working
        // direct path if their network allows; if direct ALSO fails
        // the operator gets the «port 443 timeout» curl error which
        // is the natural next step).
        let server_id = vpnctl_core::ServerId(server_id_str.to_string());
        match inv.list_servers().await {
            Ok(servers) => {
                if let Some(server) = servers.iter().find(|s| s.id == server_id) {
                    let key_path = crate::app::deploy_key_path();
                    let ssh = crate::ssh_subprocess::SubprocessSshTransport::new(
                        server.address.clone(),
                        server.ssh_user.clone(),
                        key_path,
                    )
                    .port(server.ssh_port);
                    sink = sink.with_via_ssh(ssh);
                } else {
                    // Operator explicitly chose proxy_via_server_id;
                    // silently downgrading to direct mode re-enables
                    // the network path they deliberately disabled
                    // (e.g. РФ DPI scenario where api.telegram.org
                    // is blocked from the daemon host). Per migration
                    // 0015's «losing the transport silently is worse
                    // than a loud failure» policy + bug-hunt finding
                    // 2026-05-18 — return None so push becomes a
                    // no-op AND the test-send button surfaces a
                    // clear error to the operator.
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
                // Storage-layer failure — propagate, don't silently
                // downgrade. Caller (test-send) will surface 500;
                // production push-loop will log+swallow as before.
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

/// Helper: bulk-ack any open (kind, server_id) alerts and write the
/// matching `alert.auto_ack` audit row when the ack actually moved
/// state. Centralises the «ok_with_rows → audit, ok_with_zero →
/// silent, err → warn-and-swallow» policy across every detector
/// recovery path in [`dispatch_alerts`].
///
/// Returns nothing — all errors fold into trace/warn logs because
/// the caller's tick loop must continue regardless of audit-write
/// failures (an audit failure should not block the next server's
/// probe).
pub(crate) async fn auto_ack(
    inv: &SqliteInventory,
    server_id: &ServerId,
    kind: &str,
    reason: &str,
) {
    match inv.ack_open_alerts(kind, Some(server_id)).await {
        Ok(0) => {} // no open row — nothing to log
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
